#!/usr/bin/env python3
"""OVERLORD v0 — transactional execution for agent processes.

The keystone primitive: snapshot, execute, inspect, commit or roll back.

    overlord run -t /path/to/target -- <any command>
    overlord sessions
    overlord diff <session>
    overlord commit <session>
    overlord rollback <session>

An agent command runs against an overlay of the target directory. Every write
lands in the session's upper layer; the real tree is untouched until an
explicit commit. Rollback is deletion of the upper layer.

Backends: kernel overlayfs inside an unprivileged user namespace (preferred),
fuse-overlayfs where userns capability grants are restricted (e.g. Ubuntu
with kernel.apparmor_restrict_unprivileged_userns=1).
"""

import argparse
import json
import os
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
    """True if we can create a capability-bearing user namespace."""
    probe = subprocess.run(
        ["unshare", "--map-root-user", "--mount", "true"],
        capture_output=True,
    )
    return probe.returncode == 0


def _fuse_backend_available():
    return shutil.which("fuse-overlayfs") is not None and shutil.which("fusermount3") is not None


def detect_backend():
    if _kernel_backend_available():
        return "kernel"
    if _fuse_backend_available():
        return "fuse"
    return None


def _check_mount_path(path, name):
    """Overlay mount options cannot encode ':' or ',' in paths."""
    if ":" in path or "," in path:
        raise SystemExit(f"error: {name} path contains ':' or ',' — unsupported by overlay mount options: {path}")


def run_kernel(target, upper, work, merged, cmd):
    for p, n in ((target, "target"), (upper, "session")):
        _check_mount_path(p, n)
    opts = f"lowerdir={target},upperdir={upper},workdir={work},userxattr"
    inner = (
        f"mount -t overlay overlay -o {shlex.quote(opts)} {shlex.quote(merged)} "
        f"&& cd {shlex.quote(merged)} && exec {shlex.join(cmd)}"
    )
    proc = subprocess.run(["unshare", "--map-root-user", "--mount", "bash", "-c", inner])
    return proc.returncode


def run_fuse(target, upper, work, merged, cmd):
    for p, n in ((target, "target"), (upper, "session")):
        _check_mount_path(p, n)
    opts = f"lowerdir={target},upperdir={upper},workdir={work}"
    mnt = subprocess.run(["fuse-overlayfs", "-o", opts, merged], capture_output=True, text=True)
    if mnt.returncode != 0:
        raise SystemExit(f"error: fuse-overlayfs mount failed: {mnt.stderr.strip()}")
    try:
        proc = subprocess.run(cmd, cwd=merged)
        return proc.returncode
    finally:
        subprocess.run(["fusermount3", "-u", merged], capture_output=True)


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
    return sorted(os.listdir(SESSIONS_DIR))


# ---------------------------------------------------------------- diffing

WHITEOUT_PREFIX = ".wh."


def is_whiteout(path):
    """Whiteout = deletion marker in the upper layer.

    Kernel overlayfs and privileged fuse-overlayfs: char device 0:0.
    Unprivileged fuse-overlayfs: xattr-marked empty file or .wh.-prefixed name.
    """
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
    """The target-relative name a whiteout deletes."""
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
    """Classify upper-layer entries: list of (kind, relpath).

    kinds: added, modified, deleted, replaced-dir
    """
    changes = []
    for root, dirs, files in os.walk(upper):
        pruned = []
        for d in list(dirs):
            dpath = os.path.join(root, d)
            rel = os.path.relpath(dpath, upper)
            if is_opaque_dir(dpath):
                changes.append(("replaced-dir", rel))
                dirs.remove(d)
                pruned.append(d)
                continue
            if not os.path.isdir(os.path.join(target, rel)):
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
        # symlinks-to-dirs appear in dirs on some walks; lstat-check files covers rest
        _ = pruned
    return sorted(changes, key=lambda c: c[1])


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
        if os.path.lexists(dst) and os.path.isdir(dst) and not os.path.islink(dst):
            shutil.rmtree(dst)
        shutil.copy2(src, dst, follow_symlinks=False)


def _remove_target(path):
    if not os.path.lexists(path):
        return
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        os.remove(path)


def apply_upper(upper, target):
    """Replay the upper layer onto the real target tree. Returns change count."""
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
            else:
                if not os.path.isdir(tpath):
                    _remove_target(tpath)
                    os.makedirs(tpath, exist_ok=True)
                    applied += 1
        for name in files:
            fpath = os.path.join(root, name)
            rel = os.path.relpath(fpath, upper)
            if is_whiteout(fpath):
                victim_rel = os.path.relpath(whiteout_victim(fpath), upper)
                _remove_target(os.path.join(target, victim_rel))
            else:
                _copy_entry(fpath, os.path.join(target, rel))
            applied += 1
    return applied


# ---------------------------------------------------------------- commands


def cmd_run(args):
    target = os.path.realpath(args.target)
    if not os.path.isdir(target):
        raise SystemExit(f"error: target is not a directory: {target}")
    backend = args.backend or detect_backend()
    if backend is None:
        raise SystemExit(
            "error: no overlay backend available.\n"
            "  kernel: userns capability grants are restricted on this host\n"
            "  fuse:   install fuse-overlayfs (apt install fuse-overlayfs)"
        )
    sid = new_session_id()
    sdir = session_path(sid)
    upper = os.path.join(sdir, "upper")
    work = os.path.join(sdir, "work")
    merged = os.path.join(sdir, "merged")
    for d in (upper, work, merged):
        os.makedirs(d)

    meta = {
        "id": sid,
        "target": target,
        "cmd": args.cmd,
        "backend": backend,
        "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "status": "running",
    }
    save_meta(sid, meta)

    runner = run_kernel if backend == "kernel" else run_fuse
    rc = runner(target, upper, work, merged, args.cmd)

    meta["exit_code"] = rc
    meta["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    meta["status"] = "pending"
    save_meta(sid, meta)

    changes = compute_diff(upper, target)
    print(f"\nsession {sid}  exit={rc}  backend={backend}  changes={len(changes)}")
    for kind, rel in changes[:20]:
        print(f"  {kind:12s} {rel}")
    if len(changes) > 20:
        print(f"  ... {len(changes) - 20} more (overlord diff {sid})")
    print(f"\n  commit:   overlord commit {sid}")
    print(f"  rollback: overlord rollback {sid}")
    return rc


def cmd_sessions(args):
    rows = list_sessions()
    if not rows:
        print("no sessions")
        return 0
    for sid in rows:
        try:
            m = load_meta(sid)
        except SystemExit:
            continue
        print(f"{sid}  {m.get('status', '?'):9s} exit={m.get('exit_code', '-')}  "
              f"{m.get('target', '')}  :: {shlex.join(m.get('cmd', []))}")
    return 0


def cmd_diff(args):
    m = load_meta(args.session)
    upper = os.path.join(session_path(args.session), "upper")
    changes = compute_diff(upper, m["target"])
    for kind, rel in changes:
        print(f"{kind:12s} {rel}")
    if not changes:
        print("no changes")
    return 0


def cmd_commit(args):
    m = load_meta(args.session)
    if m.get("status") != "pending":
        raise SystemExit(f"error: session is {m.get('status')}, not pending")
    upper = os.path.join(session_path(args.session), "upper")
    n = apply_upper(upper, m["target"])
    m["status"] = "committed"
    m["committed"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    save_meta(args.session, m)
    for sub in ("upper", "work", "merged"):
        shutil.rmtree(os.path.join(session_path(args.session), sub), ignore_errors=True)
    print(f"committed {n} changes to {m['target']}")
    return 0


def cmd_rollback(args):
    m = load_meta(args.session)
    if m.get("status") == "committed":
        raise SystemExit("error: session already committed; nothing to roll back")
    shutil.rmtree(session_path(args.session))
    print(f"rolled back {args.session} — target untouched: {m['target']}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="overlord", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)

    pr = sub.add_parser("run", help="run a command transactionally against a target dir")
    pr.add_argument("-t", "--target", required=True)
    pr.add_argument("--backend", choices=["kernel", "fuse"])
    pr.add_argument("cmd", nargs=argparse.REMAINDER, metavar="-- CMD")
    pr.set_defaults(fn=cmd_run)

    sub.add_parser("sessions", help="list sessions").set_defaults(fn=cmd_sessions)

    for name, fn in (("diff", cmd_diff), ("commit", cmd_commit), ("rollback", cmd_rollback)):
        sp = sub.add_parser(name)
        sp.add_argument("session")
        sp.set_defaults(fn=fn)

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
