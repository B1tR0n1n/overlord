#!/usr/bin/env python3
"""OVERLORD — an agent hypervisor: transactional, scoped, recorded execution.

    overlord run   -t <dir> [grants] [--trace[=strace|ebpf]] -- <any command>
    overlord shell -t <dir> [grants]
    overlord sessions
    overlord diff <session>
    overlord log <session>
    overlord commit <session> [--merge] [--force]
    overlord rollback <session>
    overlord doctor

A wrapped command runs against an overlay of the target directory. Every write
lands in the session's upper layer; the real tree is untouched until an
explicit commit. Commit verifies the real tree has not drifted since the
snapshot and refuses to clobber external changes (or three-way merges them
with --merge when the session kept a base copy).

Grants (the capability manifest, via flags or --manifest file):
    --jail          pivot_root jail: the process sees system dirs + the target
                    and nothing else — $HOME and the rest of the fs don't exist
    --net none      private network namespace: no network, not even loopback
                    to host services
    --timeout N     hard wall-clock limit; the process group is killed
    --merge-base    keep a base copy of the target to enable commit --merge

Backends:
  kernel  overlayfs in an unprivileged user namespace; overlay is mounted over
          the target's own path (or into the jail), so absolute-path writes
          are contained. jail/net grants require this backend. On Ubuntu
          24.04+ install packaging/ (AppArmor profile grants userns to the
          overlord launcher only).
  fuse    fuse-overlayfs, no privileges. Cooperative containment: cwd is
          inside the overlay, absolute-path writes are NOT intercepted.
"""

import argparse
import fcntl
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
LOCKS_DIR = os.path.join(OVERLORD_HOME, "locks")
EBPF_SCRIPT = "/usr/local/lib/overlord/provenance.bt"
TIMEOUT_RC = 124

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


def _jail_script(target, opts, sdir, cmd):
    """Inner script for the pivot_root jail: tmpfs root, system dirs bound,
    overlay at the target's path, private /proc. $HOME and the rest of the
    real filesystem do not exist inside."""
    tgt_rel = target.lstrip("/")
    jail = os.path.join(sdir, "jail")
    return f"""set -e
mount --make-rprivate /
J={shlex.quote(jail)}
mount -t tmpfs tmpfs "$J"
cd "$J"
mkdir -p oldroot proc tmp dev .overlord
chmod 1777 tmp
for d in usr bin sbin lib lib64 lib32 etc opt; do
  if [ -L "/$d" ]; then ln -s "$(readlink "/$d")" "$d"
  elif [ -d "/$d" ]; then mkdir -p "$d"; mount --rbind "/$d" "$d"; fi
done
for n in null zero full random urandom tty; do
  if [ -e "/dev/$n" ]; then touch "dev/$n"; mount --bind "/dev/$n" "dev/$n"; fi
done
ln -s /proc/self/fd dev/fd
RESOLV="$(readlink -f /etc/resolv.conf 2>/dev/null || true)"
if [ -n "$RESOLV" ] && [ "${{RESOLV#/run/}}" != "$RESOLV" ] && [ -f "$RESOLV" ]; then
  mkdir -p "$(dirname "${{RESOLV#/}}")"; cp "$RESOLV" "${{RESOLV#/}}"
fi
mount --bind {shlex.quote(sdir)} .overlord
mkdir -p {shlex.quote(tgt_rel)}
mount -t overlay overlay -o {shlex.quote(opts)} "$J/{tgt_rel}"
mount -t proc proc proc
pivot_root . oldroot
cd /
umount -l /oldroot 2>/dev/null || true
export HOME=/{shlex.quote(tgt_rel)} TMPDIR=/tmp
cd /{shlex.quote(tgt_rel)}
exec {shlex.join(cmd)}
"""


def prepare_kernel(target, sdir, cmd, grants):
    """Returns (argv, cwd, cleanup) for the kernel backend."""
    upper, work = os.path.join(sdir, "upper"), os.path.join(sdir, "work")
    _check_mount_path(target, "target")
    _check_mount_path(sdir, "session")
    opts = f"lowerdir={target},upperdir={upper},workdir={work},userxattr"
    argv = ["unshare", "--map-root-user", "--mount"]
    if grants.get("net") == "none":
        argv.append("--net")
    if grants.get("jail"):
        argv += ["--pid", "--fork"]
        os.makedirs(os.path.join(sdir, "jail"), exist_ok=True)
        inner = _jail_script(target, opts, sdir, cmd)
    else:
        inner = (
            f"mount -t overlay overlay -o {shlex.quote(opts)} {shlex.quote(target)} "
            f"&& cd {shlex.quote(target)} && exec {shlex.join(cmd)}"
        )
    return argv + ["bash", "-c", inner], None, None


def prepare_fuse(target, sdir, cmd, grants):
    """Returns (argv, cwd, cleanup) for the fuse backend."""
    for grant in ("jail", "net"):
        if grants.get(grant) and grants[grant] != "host":
            raise SystemExit(
                f"error: --{grant} requires the kernel backend "
                "(install packaging/apparmor profile)"
            )
    upper, work = os.path.join(sdir, "upper"), os.path.join(sdir, "work")
    merged = os.path.join(sdir, "merged")
    _check_mount_path(target, "target")
    _check_mount_path(sdir, "session")
    opts = f"lowerdir={target},upperdir={upper},workdir={work}"
    mnt = subprocess.run(
        ["fuse-overlayfs", "-o", opts, merged], capture_output=True, text=True
    )
    if mnt.returncode != 0:
        raise SystemExit(f"error: fuse-overlayfs mount failed: {mnt.stderr.strip()}")

    def cleanup():
        subprocess.run(["fusermount3", "-u", merged], capture_output=True)

    return cmd, merged, cleanup


PREPARE = {"kernel": prepare_kernel, "fuse": prepare_fuse}

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


def pending_sessions_for(target):
    hits = []
    for sid in list_sessions():
        m = load_meta(sid)
        if m.get("status") == "pending" and m.get("target") == target:
            hits.append(sid)
    return hits


def acquire_target_lock(target, wait):
    """Arbitration: one executing session per target. Returns held lock fd."""
    os.makedirs(LOCKS_DIR, exist_ok=True)
    name = hashlib.sha256(target.encode()).hexdigest()[:24] + ".lock"
    fd = open(os.path.join(LOCKS_DIR, name), "w")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
    except BlockingIOError:
        raise SystemExit(
            f"error: another session is executing against {target} (use --wait to queue)"
        )
    return fd


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


def try_merge(conflicts, sdir, target):
    """Three-way merge modified-externally conflicts using the session's base
    copy. Merged content is written into the upper layer, so a subsequent
    apply replays it. Returns (resolved, unresolved)."""
    base_dir = os.path.join(sdir, "base")
    upper = os.path.join(sdir, "upper")
    if not os.path.isdir(base_dir):
        raise SystemExit(
            "error: --merge needs a base copy — session was not run with --merge-base"
        )
    resolved, unresolved = [], []
    for reason, rel in conflicts:
        ours = os.path.join(upper, rel)       # session's version
        base = os.path.join(base_dir, rel)    # common ancestor
        theirs = os.path.join(target, rel)    # external version
        if reason != "modified-externally" or not all(
            os.path.isfile(p) and not os.path.islink(p) for p in (ours, base, theirs)
        ):
            unresolved.append((reason, rel))
            continue
        r = subprocess.run(
            ["git", "merge-file", "-p", "-L", "session", "-L", "base", "-L",
             "external", ours, base, theirs],
            capture_output=True,
        )
        if r.returncode == 0:
            with open(ours, "wb") as f:
                f.write(r.stdout)
            resolved.append(rel)
        else:
            unresolved.append(("merge-conflict", rel))
    return resolved, unresolved


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
            events.append({
                "pid": int(pid),
                "ts": float(ts),
                "syscall": syscall,
                "paths": _QUOTED_RE.findall(args)[:2],
                "write": syscall != "connect" and (
                    syscall not in ("openat", "open")
                    or any(fl in args for fl in _WRITE_FLAGS)
                ),
                "ret": ret,
            })
    return events


def start_ebpf(pid, sdir):
    """Attach the bpftrace flight recorder to a process tree. Root-only."""
    script = EBPF_SCRIPT if os.path.isfile(EBPF_SCRIPT) else os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "packaging", "ebpf", "provenance.bt"
    )
    if not os.path.isfile(script):
        raise SystemExit("error: ebpf recorder script not found")
    argv = ["bpftrace", "-o", os.path.join(sdir, "ebpf.log"), script, str(pid)]
    if os.geteuid() != 0:
        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
            raise SystemExit(
                "error: --trace ebpf needs root (or passwordless sudo for bpftrace)"
            )
        argv = ["sudo", "-n"] + argv
    return subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


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


def load_grants(args):
    """Capability manifest: --manifest file defaults, CLI flags override."""
    grants = {"net": "host", "jail": False, "timeout": None, "merge_base": False}
    manifest_file = getattr(args, "manifest", None)
    if manifest_file:
        with open(manifest_file) as f:
            declared = json.load(f)
        unknown = set(declared) - set(grants)
        if unknown:
            raise SystemExit(f"error: unknown manifest keys: {', '.join(sorted(unknown))}")
        grants.update(declared)
    if getattr(args, "net", None):
        grants["net"] = args.net
    if getattr(args, "jail", False):
        grants["jail"] = True
    if getattr(args, "timeout", None):
        grants["timeout"] = args.timeout
    if getattr(args, "merge_base", False):
        grants["merge_base"] = True
    return grants


def execute_session(target, cmd, backend, grants, trace=None, wait=False, stack=False):
    """Core transactional run. Returns (sid, exit_code, changes)."""
    target = os.path.realpath(target)
    if not os.path.isdir(target):
        raise SystemExit(f"error: target is not a directory: {target}")
    backend = backend or detect_backend()
    if backend is None:
        raise SystemExit(
            "error: no overlay backend available.\n"
            "  kernel: userns capability grants restricted (install packaging/)\n"
            "  fuse:   install fuse-overlayfs (sudo apt install fuse-overlayfs)"
        )
    pending = pending_sessions_for(target)
    if pending and not stack:
        raise SystemExit(
            f"error: {len(pending)} pending session(s) already exist for {target}: "
            f"{', '.join(pending)}\ncommit or roll back first, or pass --stack"
        )
    lock = acquire_target_lock(target, wait)

    sid = new_session_id()
    sdir = session_path(sid)
    for d in ("upper", "work", "merged"):
        os.makedirs(os.path.join(sdir, d))

    manifest = snapshot_manifest(target)
    with open(os.path.join(sdir, "manifest.json"), "w") as f:
        json.dump(manifest, f)
    if grants.get("merge_base"):
        subprocess.run(
            ["cp", "-a", "--reflink=auto", target, os.path.join(sdir, "base")],
            check=True,
        )

    raw_trace = os.path.join(sdir, "raw.strace")
    if trace == "strace":
        if not shutil.which("strace"):
            raise SystemExit("error: --trace requires strace (sudo apt install strace)")
        strace_out = "/.overlord/raw.strace" if grants.get("jail") else raw_trace
        cmd = ["strace", "-f", "-qq", "-ttt", "-e",
               "trace=%file,%process,%network", "-o", strace_out] + cmd

    meta = {
        "id": sid, "target": target, "cmd": cmd, "backend": backend,
        "grants": grants, "trace": trace,
        "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "status": "running",
    }
    save_meta(sid, meta)

    argv, cwd, cleanup = PREPARE[backend](target, sdir, cmd, grants)
    ebpf = None
    try:
        proc = subprocess.Popen(argv, cwd=cwd, start_new_session=True)
        if trace == "ebpf":
            ebpf = start_ebpf(proc.pid, sdir)
        try:
            rc = proc.wait(timeout=grants.get("timeout"))
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, 9)
            proc.wait()
            rc = TIMEOUT_RC
            meta["timed_out"] = True
    finally:
        if cleanup:
            cleanup()
        if ebpf:
            ebpf.terminate()
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()

    upper = os.path.join(sdir, "upper")
    changes = compute_diff(upper, target)
    with open(os.path.join(sdir, "provenance.jsonl"), "w") as f:
        for rec in build_provenance(changes, upper, target):
            f.write(json.dumps(rec) + "\n")
    if trace == "strace" and os.path.isfile(raw_trace):
        with open(os.path.join(sdir, "syscalls.jsonl"), "w") as f:
            for ev in parse_strace(raw_trace):
                f.write(json.dumps(ev) + "\n")

    meta.update(exit_code=rc, status="pending",
                finished=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    save_meta(sid, meta)
    return sid, rc, changes


# ---------------------------------------------------------------- commands


def _print_session_footer(sid, rc, backend, changes):
    print(f"\nsession {sid}  exit={rc}  backend={backend}  changes={len(changes)}")
    for kind, rel in changes[:20]:
        print(f"  {kind:12s} {rel}")
    if len(changes) > 20:
        print(f"  ... {len(changes) - 20} more (overlord diff {sid})")
    print(f"\n  inspect:  overlord diff {sid}   |   overlord log {sid}")
    print(f"  commit:   overlord commit {sid}")
    print(f"  rollback: overlord rollback {sid}")


def cmd_run(args):
    grants = load_grants(args)
    sid, rc, changes = execute_session(
        args.target, args.cmd, args.backend, grants,
        trace=args.trace, wait=args.wait, stack=args.stack,
    )
    _print_session_footer(sid, rc, load_meta(sid)["backend"], changes)
    return rc


def cmd_shell(args):
    grants = load_grants(args)
    shell = os.environ.get("SHELL", "/bin/bash")
    print(f"overlord: transactional shell over {args.target} — exit to close",
          file=sys.stderr)
    sid, rc, changes = execute_session(
        args.target, [shell], args.backend, grants,
        wait=args.wait, stack=args.stack,
    )
    _print_session_footer(sid, rc, load_meta(sid)["backend"], changes)
    return rc


def cmd_sessions(args):
    rows = list_sessions()
    if not rows:
        print("no sessions")
        return 0
    for sid in rows:
        m = load_meta(sid)
        g = m.get("grants", {})
        tags = "".join(
            f" [{t}]" for t, on in
            (("jail", g.get("jail")), ("net:none", g.get("net") == "none"),
             ("timed-out", m.get("timed_out"))) if on
        )
        print(f"{sid}  {m.get('status', '?'):9s} exit={m.get('exit_code', '-')}{tags}  "
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
    for name, label in (("syscalls.jsonl", "syscall trace"), ("ebpf.log", "ebpf trace")):
        p = os.path.join(sdir, name)
        if os.path.isfile(p):
            with open(p, errors="replace") as f:
                n = sum(1 for _ in f)
            print(f"\n{label}: {n} events in {p}")
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
    merged = []
    if conflicts and args.merge:
        merged, conflicts = try_merge(conflicts, sdir, m["target"])
    if conflicts and not args.force:
        print("error: target drifted since snapshot — refusing to commit:", file=sys.stderr)
        for reason, rel in conflicts:
            print(f"  {reason:22s} {rel}", file=sys.stderr)
        hint = "--merge (needs --merge-base session) or --force" if not args.merge else "--force"
        print(f"override with: overlord commit {hint} {args.session}", file=sys.stderr)
        return 1
    n = apply_upper(upper, m["target"])
    m.update(status="committed", committed=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
             forced=bool(conflicts), merged_paths=merged)
    save_meta(args.session, m)
    for sub in ("upper", "work", "merged", "base", "jail", "manifest.json", "raw.strace"):
        try:
            _force_rmtree(os.path.join(sdir, sub))
        except OSError:
            pass
    msg = f"committed {n} changes to {m['target']}"
    if merged:
        msg += f" ({len(merged)} three-way merged)"
    print(msg)
    return 0


def cmd_rollback(args):
    m = load_meta(args.session)
    if m.get("status") == "committed":
        raise SystemExit("error: session already committed; nothing to roll back")
    _force_rmtree(session_path(args.session))
    print(f"rolled back {args.session} — target untouched: {m['target']}")
    return 0


def cmd_doctor(args):
    k = _kernel_backend_available()
    fu = _fuse_backend_available()
    checks = [
        ("python", sys.version.split()[0], True),
        ("kernel backend (userns overlay; jail + net grants)",
         "available" if k else "blocked", k),
        ("fuse backend (fuse-overlayfs, cooperative)",
         "available" if fu else "missing", fu),
        ("syscall trace (--trace, strace)",
         "available" if shutil.which("strace") else "missing",
         bool(shutil.which("strace"))),
        ("ebpf trace (--trace ebpf, bpftrace, root-only)",
         "available" if shutil.which("bpftrace") else "missing",
         bool(shutil.which("bpftrace"))),
        ("three-way merge (git merge-file)",
         "available" if shutil.which("git") else "missing",
         bool(shutil.which("git"))),
    ]
    try:
        with open("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") as f:
            checks.append(("apparmor userns restriction", f.read().strip(), True))
    except OSError:
        pass
    for name, val, good in checks:
        print(f"  {'ok ' if good else '!! '} {name}: {val}")
    if not (k or fu):
        print("\n  NO BACKEND AVAILABLE — run: sudo bash packaging/install.sh")
        return 1
    print(f"\n  active backend: {'kernel' if k else 'fuse'}")
    return 0


# ---------------------------------------------------------------- main


def _add_exec_flags(parser):
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("--backend", choices=list(PREPARE))
    parser.add_argument("--manifest", help="capability manifest JSON (flags override)")
    parser.add_argument("--jail", action="store_true",
                        help="pivot_root jail: only system dirs + target exist")
    parser.add_argument("--net", choices=["host", "none"],
                        help="network grant (none = private empty netns)")
    parser.add_argument("--timeout", type=float, metavar="SECS",
                        help="hard wall-clock limit; kills the process group")
    parser.add_argument("--merge-base", action="store_true",
                        help="keep a base copy enabling commit --merge")
    parser.add_argument("--wait", action="store_true",
                        help="queue behind an executing session instead of failing")
    parser.add_argument("--stack", action="store_true",
                        help="allow a new session while others are pending on this target")


def main(argv=None):
    p = argparse.ArgumentParser(prog="overlord", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)

    pr = sub.add_parser("run", help="run a command transactionally against a target dir")
    _add_exec_flags(pr)
    pr.add_argument("--trace", nargs="?", const="strace", choices=["strace", "ebpf"],
                    help="record syscall provenance")
    pr.add_argument("cmd", nargs=argparse.REMAINDER, metavar="-- CMD")
    pr.set_defaults(fn=cmd_run)

    ps = sub.add_parser("shell", help="interactive transactional shell over a target dir")
    _add_exec_flags(ps)
    ps.set_defaults(fn=cmd_shell)

    sub.add_parser("sessions", help="list sessions").set_defaults(fn=cmd_sessions)
    sub.add_parser("doctor", help="environment diagnostics").set_defaults(fn=cmd_doctor)

    for name, fn in (("diff", cmd_diff), ("log", cmd_log), ("rollback", cmd_rollback)):
        sp = sub.add_parser(name)
        sp.add_argument("session")
        sp.set_defaults(fn=fn)

    pc = sub.add_parser("commit")
    pc.add_argument("session")
    pc.add_argument("--merge", action="store_true",
                    help="three-way merge external drift (session needs --merge-base)")
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
