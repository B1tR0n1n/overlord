#!/usr/bin/env python3
"""OVERLORD — transactional execution for agent processes.

The keystone primitive of an agent hypervisor: snapshot, execute, inspect,
commit or roll back.

    overlord run   -t <dir> [--trace] -- <any command>
    overlord shell -t <dir>
    overlord sessions
    overlord diff <session>
    overlord log <session>
    overlord commit <session> [--force]
    overlord rollback <session>
    overlord doctor

A wrapped command runs against an overlay of the target directory. Every write
lands in the session's upper layer; the real tree is untouched until an
explicit commit. Rollback is deletion of the upper layer. Commit verifies the
real tree has not drifted since the snapshot (conflict detection) and refuses
to clobber external changes unless forced.

Backends:
  kernel  overlayfs inside an unprivileged user namespace. The overlay is
          mounted OVER the target's own path inside the namespace, so even
          absolute-path writes into the target are contained. Requires userns
          capability grants (on Ubuntu 24.04+ install the AppArmor profile
          shipped in packaging/).
  fuse    fuse-overlayfs, no privileges needed. Cooperative containment only:
          the command runs with cwd inside the overlay, but absolute-path
          writes to the real target are NOT intercepted.
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import uuid

OVERLORD_HOME = os.environ.get("OVERLORD_HOME", os.path.expanduser("~/.overlord"))
SESSIONS_DIR = os.path.join(OVERLORD_HOME, "sessions")

# ---------------------------------------------------------------- backends


def _kernel_backend_available():
    probe = subprocess.run(
        ["unshare", "--map-root-user", "--mount", "true"], capture_output=True
    )
    return probe.returncode == 0


def _fuse_backend_available():
    return bool(shutil.which("fuse-overlayfs")) and bool(shutil.which("fusermount3"))


def detect_backend():
    if _kernel_backend_available():
        return "kernel"
    if _fuse_backend_available():
        return "fuse"
    return None


def _check_mount_path(path, name):
    if ":" in path or "," in path:
        raise SystemExit(
            f"error: {name} path contains ':' or ',' — unsupported in overlay mount options: {path}"
        )


def run_kernel(target, upper, work, merged, cmd):
    """Mount the overlay over the target's own path inside a private mount ns.

    Absolute references to the target resolve into the overlay; the real tree
    is untouched. `merged` is unused by this backend.
    """
    _check_mount_path(target, "target")
    _check_mount_path(upper, "session")
    opts = f"lowerdir={target},upperdir={upper},workdir={work},userxattr"
    inner = (
        f"mount -t overlay overlay -o {shlex.quote(opts)} {shlex.quote(target)} "
        f"&& cd {shlex.quote(target)} && exec {shlex.join(cmd)}"
    )
    proc = subprocess.run(["unshare", "--map-root-user", "--mount", "bash", "-c", inner])
    return proc.returncode


def run_fuse(target, upper, work, merged, cmd):
    _check_mount_path(target, "target")
    _check_mount_path(upper, "session")
    opts = f"lowerdir={target},upperdir={upper},workdir={work}"
    mnt = subprocess.run(
        ["fuse-overlayfs", "-o", opts, merged], capture_output=True, text=True
    )
    if mnt.returncode != 0:
        raise SystemExit(f"error: fuse-overlayfs mount failed: {mnt.stderr.strip()}")
    try:
        return subprocess.run(cmd, cwd=merged).returncode
    finally:
        subprocess.run(["fusermount3", "-u", merged], capture_output=True)


BACKENDS = {"kernel": run_kernel, "fuse": run_fuse}

# ---------------------------------------------------------------- sessions


def new_session_id():
    return time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]


def session_path(sid):
    return os.path.join(SESSIONS_DIR, sid)


def load_meta(sid):
    path = os.path.join(session_path(sid), "meta.json")
    if not os.path.isfile(path):
        raise SystemExit(f"error: no such session: {sid}")
    with open(path) as f:
        return json.load(f)


def save_meta(sid, meta):
    with open(os.path.join(session_path(sid), "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)


def list_sessions():
    if not os.path.isdir(SESSIONS_DIR):
        return []
    return sorted(
        d for d in os.listdir(SESSIONS_DIR)
        if os.path.isfile(os.path.join(SESSIONS_DIR, d, "meta.json"))
    )


# ---------------------------------------------------------------- snapshot


def snapshot_manifest(target):
    """Fast fingerprint of every file in the target: rel -> [size, mtime_ns]."""
    manifest = {}
    for root, _dirs, files in os.walk(target):
        for name in files:
            path = os.path.join(root, name)
            rel = os.path.relpath(path, target)
            st = os.lstat(path)
            manifest[rel] = [st.st_size, st.st_mtime_ns]
    return manifest


def _fingerprint(path):
    st = os.lstat(path)
    return [st.st_size, st.st_mtime_ns]


# ---------------------------------------------------------------- diffing

WHITEOUT_PREFIX = ".wh."


def is_whiteout(path):
    st = os.lstat(path)
    if stat.S_ISCHR(st.st_mode) and st.st_rdev == 0:
        return True
    if os.path.basename(path).startswith(WHITEOUT_PREFIX):
        return True
    for xa in ("user.overlay.whiteout", "user.fuseoverlayfs.whiteout"):
        try:
            os.getxattr(path, xa, follow_symlinks=False)
            return True
        except OSError:
            pass
    return False


def whiteout_victim(path):
    base = os.path.basename(path)
    if base.startswith(WHITEOUT_PREFIX):
        return os.path.join(os.path.dirname(path), base[len(WHITEOUT_PREFIX):])
    return path


def is_opaque_dir(path):
    for xa in ("user.overlay.opaque", "trusted.overlay.opaque", "user.fuseoverlayfs.opaque"):
        try:
            if os.getxattr(path, xa, follow_symlinks=False) in (b"y", b"1"):
                return True
        except OSError:
            pass
    return False


def compute_diff(upper, target):
    """Classify upper-layer entries: sorted list of (kind, relpath).

    kinds: added, modified, deleted, replaced-dir. Added dirs get a '/' suffix.
    """
    changes = []
    for root, dirs, files in os.walk(upper):
        for d in list(dirs):
            dpath = os.path.join(root, d)
            rel = os.path.relpath(dpath, upper)
            if is_opaque_dir(dpath):
                changes.append(("replaced-dir", rel))
                dirs.remove(d)
            elif not os.path.isdir(os.path.join(target, rel)):
                changes.append(("added", rel + "/"))
        for name in files:
            fpath = os.path.join(root, name)
            rel = os.path.relpath(fpath, upper)
            if is_whiteout(fpath):
                victim = os.path.relpath(whiteout_victim(fpath), upper)
                changes.append(("deleted", victim))
            elif os.path.lexists(os.path.join(target, rel)):
                changes.append(("modified", rel))
            else:
                changes.append(("added", rel))
    return sorted(changes, key=lambda c: c[1])


# ---------------------------------------------------------------- conflicts


def find_conflicts(changes, manifest, target):
    """Paths where the real tree drifted after the snapshot. List of (reason, rel)."""
    conflicts = []
    for kind, rel in changes:
        tpath = os.path.join(target, rel.rstrip("/"))
        if kind == "added":
            if rel.endswith("/"):
                continue  # mkdir -p semantics: pre-existing dir is benign
            if rel in manifest or os.path.lexists(tpath):
                conflicts.append(("created-externally", rel))
        elif kind in ("modified", "deleted"):
            if rel not in manifest:
                conflicts.append(("appeared-after-snapshot", rel))
            elif not os.path.lexists(tpath):
                conflicts.append(("deleted-externally", rel))
            elif _fingerprint(tpath) != manifest[rel]:
                conflicts.append(("modified-externally", rel))
        elif kind == "replaced-dir":
            prefix = rel + os.sep
            for mrel, fp in manifest.items():
                if mrel.startswith(prefix):
                    mpath = os.path.join(target, mrel)
                    if not os.path.lexists(mpath) or _fingerprint(mpath) != fp:
                        conflicts.append(("modified-externally", mrel))
    return conflicts


# ---------------------------------------------------------------- provenance


def _sha256(path):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        return "symlink:" + os.readlink(path)
    if not stat.S_ISREG(st.st_mode):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_provenance(changes, upper, target):
    """Transaction-level flight record: hashes before (lower) and after (upper)."""
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    records = []
    for kind, rel in changes:
        rec = {"ts": ts, "kind": kind, "path": rel}
        clean = rel.rstrip("/")
        if kind in ("modified", "deleted"):
            tpath = os.path.join(target, clean)
            if os.path.lexists(tpath):
                rec["before_sha256"] = _sha256(tpath)
        if kind in ("added", "modified") and not rel.endswith("/"):
            upath = os.path.join(upper, clean)
            rec["after_sha256"] = _sha256(upath)
            rec["after_size"] = os.lstat(upath).st_size
        records.append(rec)
    return records


# strace line: "PID  TS syscall(args) = ret"
_STRACE_RE = re.compile(r"^(\d+)\s+([\d.]+)\s+(\w+)\((.*)\)\s*=\s*(-?\d+|\?)")
_QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
_TRACED = {
    "openat", "open", "creat", "unlink", "unlinkat", "rename", "renameat",
    "renameat2", "execve", "mkdir", "mkdirat", "rmdir", "chmod", "fchmodat",
    "symlinkat", "linkat", "connect",
}


def parse_strace(raw_path):
    events = []
    with open(raw_path, errors="replace") as f:
        for line in f:
            m = _STRACE_RE.match(line)
            if not m or m.group(3) not in _TRACED:
                continue
            pid, ts, syscall, args, ret = m.groups()
            paths = _QUOTED_RE.findall(args)
            events.append({
                "pid": int(pid),
                "ts": float(ts),
                "syscall": syscall,
                "paths": paths[:2],
                "write": syscall != "connect" and (
                    syscall not in ("openat", "open")
                    or any(fl in args for fl in _WRITE_FLAGS)
                ),
                "ret": ret,
            })
    return events


# ---------------------------------------------------------------- commit


def _copy_entry(src, dst):
    st = os.lstat(src)
    if stat.S_ISLNK(st.st_mode):
        if os.path.lexists(dst):
            os.remove(dst)
        os.symlink(os.readlink(src), dst)
    elif stat.S_ISDIR(st.st_mode):
        os.makedirs(dst, exist_ok=True)
        shutil.copystat(src, dst)
    else:
        if os.path.isdir(dst) and not os.path.islink(dst):
            shutil.rmtree(dst)
        shutil.copy2(src, dst, follow_symlinks=False)


def _force_rmtree(path):
    """rmtree that survives mode-000 entries (overlayfs creates work/work as 000)."""
    if not os.path.isdir(path):
        if os.path.lexists(path):
            os.remove(path)
        return
    for root, dirs, _files in os.walk(path):
        for d in dirs:
            try:
                os.chmod(os.path.join(root, d), 0o700)
            except OSError:
                pass
    shutil.rmtree(path)


def _remove_target(path):
    if not os.path.lexists(path):
        return
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        os.remove(path)


def apply_upper(upper, target):
    """Replay the upper layer onto the real tree. Returns change count."""
    applied = 0
    for root, dirs, files in os.walk(upper):
        for d in list(dirs):
            dpath = os.path.join(root, d)
            rel = os.path.relpath(dpath, upper)
            tpath = os.path.join(target, rel)
            if is_opaque_dir(dpath):
                _remove_target(tpath)
                shutil.copytree(dpath, tpath, symlinks=True)
                dirs.remove(d)
                applied += 1
            elif not os.path.isdir(tpath):
                _remove_target(tpath)
                os.makedirs(tpath, exist_ok=True)
                applied += 1
        for name in files:
            fpath = os.path.join(root, name)
            rel = os.path.relpath(fpath, upper)
            if is_whiteout(fpath):
                victim = os.path.relpath(whiteout_victim(fpath), upper)
                _remove_target(os.path.join(target, victim))
            else:
                _copy_entry(fpath, os.path.join(target, rel))
            applied += 1
    return applied


# ---------------------------------------------------------------- execution


def execute_session(target, cmd, backend=None, trace=False):
    """Core transactional run. Returns (sid, exit_code, changes)."""
    target = os.path.realpath(target)
    if not os.path.isdir(target):
        raise SystemExit(f"error: target is not a directory: {target}")
    backend = backend or detect_backend()
    if backend is None:
        raise SystemExit(
            "error: no overlay backend available.\n"
            "  kernel: userns capability grants restricted (install packaging/apparmor profile)\n"
            "  fuse:   install fuse-overlayfs (sudo apt install fuse-overlayfs)"
        )
    sid = new_session_id()
    sdir = session_path(sid)
    upper, work, merged = (os.path.join(sdir, d) for d in ("upper", "work", "merged"))
    for d in (upper, work, merged):
        os.makedirs(d)

    manifest = snapshot_manifest(target)
    with open(os.path.join(sdir, "manifest.json"), "w") as f:
        json.dump(manifest, f)

    raw_trace = os.path.join(sdir, "raw.strace")
    if trace:
        if not shutil.which("strace"):
            raise SystemExit("error: --trace requires strace (sudo apt install strace)")
        cmd = ["strace", "-f", "-qq", "-ttt", "-e",
               "trace=%file,%process,%network", "-o", raw_trace] + cmd

    meta = {
        "id": sid, "target": target, "cmd": cmd, "backend": backend,
        "trace": trace, "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "status": "running",
    }
    save_meta(sid, meta)

    rc = BACKENDS[backend](target, upper, work, merged, cmd)

    changes = compute_diff(upper, target)
    provenance = build_provenance(changes, upper, target)
    with open(os.path.join(sdir, "provenance.jsonl"), "w") as f:
        for rec in provenance:
            f.write(json.dumps(rec) + "\n")
    if trace and os.path.isfile(raw_trace):
        with open(os.path.join(sdir, "syscalls.jsonl"), "w") as f:
            for ev in parse_strace(raw_trace):
                f.write(json.dumps(ev) + "\n")

    meta.update(exit_code=rc, status="pending",
                finished=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    save_meta(sid, meta)
    return sid, rc, changes


# ---------------------------------------------------------------- commands


def cmd_run(args):
    sid, rc, changes = execute_session(args.target, args.cmd, args.backend, args.trace)
    backend = load_meta(sid)["backend"]
    print(f"\nsession {sid}  exit={rc}  backend={backend}  changes={len(changes)}")
    for kind, rel in changes[:20]:
        print(f"  {kind:12s} {rel}")
    if len(changes) > 20:
        print(f"  ... {len(changes) - 20} more (overlord diff {sid})")
    print(f"\n  inspect:  overlord diff {sid}   |   overlord log {sid}")
    print(f"  commit:   overlord commit {sid}")
    print(f"  rollback: overlord rollback {sid}")
    return rc


def cmd_shell(args):
    shell = os.environ.get("SHELL", "/bin/bash")
    print(f"overlord: transactional shell over {args.target} — exit to close", file=sys.stderr)
    sid, rc, changes = execute_session(args.target, [shell], args.backend, False)
    print(f"\nsession {sid}  exit={rc}  changes={len(changes)}")
    print(f"  commit:   overlord commit {sid}")
    print(f"  rollback: overlord rollback {sid}")
    return rc


def cmd_sessions(args):
    rows = list_sessions()
    if not rows:
        print("no sessions")
        return 0
    for sid in rows:
        m = load_meta(sid)
        print(f"{sid}  {m.get('status', '?'):9s} exit={m.get('exit_code', '-')}  "
              f"{m.get('target', '')}  :: {shlex.join(m.get('cmd', []))}")
    return 0


def cmd_diff(args):
    m = load_meta(args.session)
    upper = os.path.join(session_path(args.session), "upper")
    if not os.path.isdir(upper):
        raise SystemExit(f"error: session is {m.get('status')}; layers discarded")
    changes = compute_diff(upper, m["target"])
    for kind, rel in changes:
        print(f"{kind:12s} {rel}")
    if not changes:
        print("no changes")
    return 0


def cmd_log(args):
    sdir = session_path(args.session)
    load_meta(args.session)
    prov = os.path.join(sdir, "provenance.jsonl")
    if not os.path.isfile(prov):
        print("no provenance recorded")
        return 0
    with open(prov) as f:
        for line in f:
            rec = json.loads(line)
            before = (rec.get("before_sha256") or "-")[:12]
            after = (rec.get("after_sha256") or "-")[:12]
            print(f"{rec['kind']:12s} {rec['path']:40s} {before} -> {after}")
    sc = os.path.join(sdir, "syscalls.jsonl")
    if os.path.isfile(sc):
        with open(sc) as f:
            n = sum(1 for _ in f)
        print(f"\nsyscall trace: {n} events in {sc}")
    return 0


def cmd_commit(args):
    m = load_meta(args.session)
    if m.get("status") != "pending":
        raise SystemExit(f"error: session is {m.get('status')}, not pending")
    sdir = session_path(args.session)
    upper = os.path.join(sdir, "upper")
    with open(os.path.join(sdir, "manifest.json")) as f:
        manifest = json.load(f)
    changes = compute_diff(upper, m["target"])
    conflicts = find_conflicts(changes, manifest, m["target"])
    if conflicts and not args.force:
        print("error: target drifted since snapshot — refusing to commit:", file=sys.stderr)
        for reason, rel in conflicts:
            print(f"  {reason:22s} {rel}", file=sys.stderr)
        print("override with: overlord commit --force " + args.session, file=sys.stderr)
        return 1
    n = apply_upper(upper, m["target"])
    m.update(status="committed", committed=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
             forced=bool(conflicts))
    save_meta(args.session, m)
    for sub in ("upper", "work", "merged", "manifest.json", "raw.strace"):
        p = os.path.join(sdir, sub)
        try:
            _force_rmtree(p)
        except OSError:
            pass
    print(f"committed {n} changes to {m['target']}")
    return 0


def cmd_rollback(args):
    m = load_meta(args.session)
    if m.get("status") == "committed":
        raise SystemExit("error: session already committed; nothing to roll back")
    _force_rmtree(session_path(args.session))
    print(f"rolled back {args.session} — target untouched: {m['target']}")
    return 0


def cmd_doctor(args):
    checks = []
    checks.append(("python", sys.version.split()[0], True))
    k = _kernel_backend_available()
    checks.append(("kernel backend (userns overlay, full containment)",
                   "available" if k else "blocked", k))
    fu = _fuse_backend_available()
    checks.append(("fuse backend (fuse-overlayfs, cooperative)",
                   "available" if fu else "missing", fu))
    st_ = bool(shutil.which("strace"))
    checks.append(("syscall trace (--trace, strace)",
                   "available" if st_ else "missing", st_))
    try:
        with open("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") as f:
            restr = f.read().strip()
        checks.append(("apparmor userns restriction", restr, True))
    except OSError:
        pass
    ok = True
    for name, val, good in checks:
        mark = "ok " if good else "!! "
        ok = ok and (good or name.startswith("apparmor"))
        print(f"  {mark} {name}: {val}")
    if not (k or fu):
        print("\n  NO BACKEND AVAILABLE — run packaging/install.sh")
        return 1
    print(f"\n  active backend: {'kernel' if k else 'fuse'}")
    return 0


# ---------------------------------------------------------------- main


def main(argv=None):
    p = argparse.ArgumentParser(prog="overlord", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)

    pr = sub.add_parser("run", help="run a command transactionally against a target dir")
    pr.add_argument("-t", "--target", required=True)
    pr.add_argument("--backend", choices=list(BACKENDS))
    pr.add_argument("--trace", action="store_true", help="record syscall provenance (strace)")
    pr.add_argument("cmd", nargs=argparse.REMAINDER, metavar="-- CMD")
    pr.set_defaults(fn=cmd_run)

    ps = sub.add_parser("shell", help="interactive transactional shell over a target dir")
    ps.add_argument("-t", "--target", required=True)
    ps.add_argument("--backend", choices=list(BACKENDS))
    ps.set_defaults(fn=cmd_shell)

    sub.add_parser("sessions", help="list sessions").set_defaults(fn=cmd_sessions)
    sub.add_parser("doctor", help="environment diagnostics").set_defaults(fn=cmd_doctor)

    for name, fn in (("diff", cmd_diff), ("log", cmd_log), ("rollback", cmd_rollback)):
        sp = sub.add_parser(name)
        sp.add_argument("session")
        sp.set_defaults(fn=fn)

    pc = sub.add_parser("commit")
    pc.add_argument("session")
    pc.add_argument("--force", action="store_true",
                    help="commit even if the target drifted since snapshot")
    pc.set_defaults(fn=cmd_commit)

    args = p.parse_args(argv)
    if getattr(args, "cmd", None) is not None:
        if args.cmd and args.cmd[0] == "--":
            args.cmd = args.cmd[1:]
        if not args.cmd:
            p.error("run requires a command after --")
    os.makedirs(SESSIONS_DIR, exist_ok=True)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
