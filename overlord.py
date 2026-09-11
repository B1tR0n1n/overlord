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
    overlord agent -t <dir> [grants] [--provider anthropic|openai] "<task>"
    overlord keys <provider> <key>

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
          INTO THE TARGET are contained. Paths outside it (/tmp, $HOME, /etc)
          are the real filesystem unless --jail, which is why `agent` jails by
          default. jail/net grants require this backend. On Ubuntu
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


def _jail_script(target, opts, sdir, cmd, bind_trace=False):
    """Inner script for the pivot_root jail: tmpfs root, system dirs bound,
    overlay at the target's path, private /proc. $HOME and the rest of the
    real filesystem do not exist inside. Session records (meta, manifest,
    provenance) are NEVER exposed — only an isolated trace/ subdir is bound,
    and only when strace needs somewhere to write (red team finding A3)."""
    tgt_rel = target.lstrip("/")
    jail = os.path.join(sdir, "jail")
    trace_bind = ""
    if bind_trace:
        trace_bind = (
            f'mkdir -p .overlord\nmount --bind {shlex.quote(os.path.join(sdir, "trace"))} .overlord\n'
        )
    return f"""set -e
mount --make-rprivate /
J={shlex.quote(jail)}
mount -t tmpfs tmpfs "$J"
cd "$J"
mkdir -p oldroot proc tmp dev
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
{trace_bind}mkdir -p {shlex.quote(tgt_rel)}
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
        argv += ["--pid", "--fork", "--uts", "--ipc"]
        os.makedirs(os.path.join(sdir, "jail"), exist_ok=True)
        inner = _jail_script(target, opts, sdir, cmd,
                             bind_trace=grants.get("_bind_trace", False))
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
    """The one place a session id becomes a filesystem path.

    Ids arrive from outside — the daemon socket, the UI's URL path — so this
    resolves the join and refuses anything that does not land exactly one
    level inside SESSIONS_DIR: `..`, an absolute path, an empty id, a symlink
    that points out. Every caller gets the resolved, checked path."""
    base = os.path.realpath(SESSIONS_DIR)
    resolved = os.path.realpath(os.path.join(base, str(sid)))
    if not resolved.startswith(base + os.sep) or os.path.dirname(resolved) != base:
        raise SystemExit(f"error: not a session id: {sid!r}")
    return resolved


def load_meta(sid):
    path = os.path.join(session_path(sid), "meta.json")
    if not os.path.isfile(path):
        raise SystemExit(f"error: no such session: {sid}")
    with open(path) as f:
        meta = json.load(f)
    return reconcile_session(sid, meta)


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
        if m.get("status") in ("pending", "open") and m.get("target") == target:
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


# ---------------------------------------------------------------- live sessions
#
# A live session keeps the overlay mounted (and the jail/netns alive) for as
# long as its holder process runs, so N commands can execute inside one
# transaction. The holder is a tiny executor loop (python, inline source —
# nothing from the session dir is exposed to the jail) that speaks JSON lines
# over an inherited socketpair: run / kill / close. It exits on EOF, so a
# dead opener always tears the namespace down; the session dir is then
# reconciled to "pending" by whoever loads it next.

_EXECUTOR_SRC = r"""
import base64, json, os, signal, socket, subprocess, sys, threading
sock = socket.socket(fileno=int(sys.argv[1]))
rf = sock.makefile("rb")
wl = threading.Lock()
procs = {}
def send(o):
    with wl:
        sock.sendall((json.dumps(o) + "\n").encode())
def run(req):
    rid, cmd = req["id"], req["cmd"]
    cwd = os.path.join(os.getcwd(), req["cwd"]) if req.get("cwd") else None
    kw = {}
    if req.get("capture", True):
        kw = dict(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        p = subprocess.Popen(cmd, cwd=cwd, start_new_session=True, **kw)
    except OSError as e:
        send({"id": rid, "exit": 127, "error": str(e)}); return
    procs[rid] = p
    if p.stdout is not None:
        while True:
            chunk = p.stdout.read1(65536)
            if not chunk: break
            send({"id": rid, "out": base64.b64encode(chunk).decode()})
    rc = p.wait()
    procs.pop(rid, None)
    send({"id": rid, "exit": rc})
def killall():
    for p in list(procs.values()):
        try: os.killpg(p.pid, signal.SIGKILL)
        except OSError: pass
send({"ready": True, "pid": os.getpid()})
for line in rf:
    try: req = json.loads(line)
    except ValueError: continue
    if req.get("op") == "run":
        threading.Thread(target=run, args=(req,), daemon=True).start()
    elif req.get("op") == "kill":
        p = procs.get(req.get("id"))
        if p:
            try: os.killpg(p.pid, signal.SIGKILL)
            except OSError: pass
    elif req.get("op") == "close":
        break
killall()
os._exit(0)
"""


class LiveSession:
    """An open transaction: overlay mounted, holder alive, commands accepted."""

    def __init__(self, sid, meta, proc, sock, lock, cleanup, ebpf, trace_inside):
        import queue
        import socket as _socket
        import threading
        self.sid, self.meta, self.proc = sid, meta, proc
        self.sdir = session_path(sid)
        self._sock, self._lock, self._cleanup, self._ebpf = sock, lock, cleanup, ebpf
        self._trace_inside = trace_inside
        self._q = {}
        self._qlock = threading.Lock()
        self._wlock = threading.Lock()
        self._queue = queue
        self.expired = False
        self.closed = False
        self._ready = threading.Event()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self._deadline = None
        t = meta["grants"].get("timeout")
        if t:
            self._deadline = threading.Timer(t, self._expire)
            self._deadline.daemon = True
            self._deadline.start()
        if not self._ready.wait(30):
            self._kill()
            raise SystemExit("error: session holder did not start (backend failure?)")

    # -- transport
    def _read_loop(self):
        rf = self._sock.makefile("rb")
        for line in rf:
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if msg.get("ready"):
                self._ready.set()
                continue
            with self._qlock:
                q = self._q.get(msg.get("id"))
            if q:
                q.put(msg)
        # EOF: holder is gone — release every waiter
        with self._qlock:
            for q in self._q.values():
                q.put({"exit": TIMEOUT_RC if self.expired else 137, "eof": True})

    def _send(self, obj):
        with self._wlock:
            try:
                self._sock.sendall((json.dumps(obj) + "\n").encode())
            except OSError:
                pass

    def _kill(self):
        try:
            os.killpg(self.proc.pid, 9)
        except OSError:
            pass

    def _expire(self):
        self.expired = True
        self.meta["timed_out"] = True
        self._kill()

    # -- api
    def exec(self, cmd, timeout=None, capture=True, cwd=None, on_output=None,
             label=None):
        """Run one command inside the transaction. Returns (rc, output_bytes)."""
        import threading
        if self.closed or self.expired:
            raise SystemExit("error: session is closed" if self.closed else
                             "error: session expired (timeout grant)")
        rid = uuid.uuid4().hex[:8]
        q = self._queue.Queue()
        with self._qlock:
            self._q[rid] = q
        real_cmd = list(cmd)
        if self._trace_inside:
            real_cmd = ["strace", "-f", "-qq", "-ttt", "-e",
                        "trace=%file,%process,%network", "-o",
                        f"{self._trace_inside}/raw.{rid}.strace"] + real_cmd
        rec = {"id": rid, "cmd": list(cmd), "label": label,
               "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        self.meta.setdefault("execs", []).append(rec)
        if not self.meta.get("cmd"):
            self.meta["cmd"] = list(cmd)
        save_meta(self.sid, self.meta)
        self._send({"op": "run", "id": rid, "cmd": real_cmd, "capture": capture,
                    "cwd": cwd})
        timer = None
        timed_out = [False]
        if timeout:
            def _kill_exec():
                timed_out[0] = True
                self._send({"op": "kill", "id": rid})
            timer = threading.Timer(timeout, _kill_exec)
            timer.daemon = True
            timer.start()
        out = bytearray()
        outlog = open(os.path.join(self.sdir, "output.log"), "ab") if capture else None
        try:
            while True:
                msg = q.get()
                if "out" in msg:
                    import base64
                    chunk = base64.b64decode(msg["out"])
                    out += chunk
                    if outlog:
                        outlog.write(chunk)
                        outlog.flush()
                    if on_output:
                        on_output(chunk)
                if "exit" in msg:
                    rc = msg["exit"]
                    if msg.get("error") and outlog:
                        outlog.write((msg["error"] + "\n").encode())
                    break
        finally:
            if timer:
                timer.cancel()
            if outlog:
                outlog.close()
            with self._qlock:
                self._q.pop(rid, None)
        if timed_out[0] or (self.expired and rc in (137, TIMEOUT_RC)):
            rc = TIMEOUT_RC
            rec["timed_out"] = True
        rec.update(exit_code=rc, finished=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        save_meta(self.sid, self.meta)
        return rc, bytes(out)

    def changes(self):
        return compute_diff(os.path.join(self.sdir, "upper"), self.meta["target"])

    def close(self):
        """Tear the namespace down and finalize the session as pending.
        Returns (sid, changes)."""
        if self.closed:
            return self.sid, self.changes()
        self.closed = True
        if self._deadline:
            self._deadline.cancel()
        self._send({"op": "close"})
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._kill()
            self.proc.wait()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._cleanup:
            self._cleanup()
        if self._ebpf:
            self._ebpf.terminate()
        fcntl.flock(self._lock, fcntl.LOCK_UN)
        self._lock.close()
        changes = _finalize_session(self.sid, self.meta)
        return self.sid, changes


def _finalize_session(sid, meta):
    """Compute diff + provenance, parse traces, mark pending. Idempotent."""
    sdir = session_path(sid)
    upper = os.path.join(sdir, "upper")
    changes = compute_diff(upper, meta["target"]) if os.path.isdir(upper) else []
    attribution = {}
    apath = os.path.join(sdir, "attribution.json")
    if os.path.isfile(apath):
        with open(apath) as f:
            attribution = json.load(f)
    with open(os.path.join(sdir, "provenance.jsonl"), "w") as f:
        for rec in build_provenance(changes, upper, meta["target"]):
            if rec["path"] in attribution:
                rec["caused_by"] = attribution[rec["path"]]   # agent tool call
            f.write(json.dumps(rec) + "\n")
    tdir = os.path.join(sdir, "trace")
    if meta.get("trace") == "strace" and os.path.isdir(tdir):
        raws = sorted(p for p in os.listdir(tdir) if p.endswith(".strace"))
        raw = os.path.join(sdir, "raw.strace")
        with open(raw, "wb") as out:
            for p in raws:
                with open(os.path.join(tdir, p), "rb") as f:
                    shutil.copyfileobj(f, out)
        with open(os.path.join(sdir, "syscalls.jsonl"), "w") as f:
            for ev in parse_strace(raw):
                f.write(json.dumps(ev) + "\n")
    execs = meta.get("execs") or []
    rc = execs[-1].get("exit_code") if execs else None
    if any(e.get("timed_out") for e in execs) or meta.get("timed_out"):
        meta["timed_out"] = True
        if rc is None or rc == 0:
            rc = TIMEOUT_RC
    meta.update(exit_code=rc, status="pending",
                finished=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    meta.pop("holder_pid", None)
    save_meta(sid, meta)
    return changes


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def reconcile_session(sid, meta):
    """An 'open' session whose holder is gone (opener crashed) becomes pending."""
    if meta.get("status") == "open":
        pid = meta.get("holder_pid")
        if not pid or not _pid_alive(pid):
            _finalize_session(sid, meta)
    return meta


def open_session(target, backend, grants, trace=None, wait=False, stack=False,
                 capture=False, agent=None):
    """Snapshot the target, mount the overlay, start the holder. Returns LiveSession."""
    import socket
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

    grants = dict(grants)
    trace_inside = None
    if trace == "strace":
        if not shutil.which("strace"):
            raise SystemExit("error: --trace requires strace (sudo apt install strace)")
        os.makedirs(os.path.join(sdir, "trace"), exist_ok=True)
        if grants.get("jail"):
            # red team finding A3: never expose session records to the jail —
            # strace gets an isolated trace/ subdir bound at /.overlord
            grants["_bind_trace"] = True
            trace_inside = "/.overlord"
        else:
            trace_inside = os.path.join(sdir, "trace")

    meta = {
        "id": sid, "target": target, "cmd": [], "execs": [], "backend": backend,
        "grants": {k: v for k, v in grants.items() if not k.startswith("_")},
        "trace": trace, "agent": agent,
        "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "status": "open",
    }

    parent_sock, child_sock = socket.socketpair()
    py = sys.executable if (sys.executable or "").startswith("/usr/") else "python3"
    executor = [py, "-c", _EXECUTOR_SRC, str(child_sock.fileno())]
    argv, cwd, cleanup = PREPARE[backend](target, sdir, executor, grants)
    popen_kw = {"pass_fds": (child_sock.fileno(),)}
    if capture:
        outfile = open(os.path.join(sdir, "output.log"), "ab")
        popen_kw.update(stdout=outfile, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    try:
        proc = subprocess.Popen(argv, cwd=cwd, start_new_session=True, **popen_kw)
    except OSError:
        if cleanup:
            cleanup()
        raise
    finally:
        child_sock.close()
        if capture:
            outfile.close()
    meta["holder_pid"] = proc.pid
    save_meta(sid, meta)
    ebpf = start_ebpf(proc.pid, sdir) if trace == "ebpf" else None
    return LiveSession(sid, meta, proc, parent_sock, lock, cleanup, ebpf, trace_inside)


def execute_session(target, cmd, backend, grants, trace=None, wait=False,
                    stack=False, capture=False):
    """One-shot transactional run (open, exec, close). Returns (sid, exit_code, changes)."""
    live = open_session(target, backend, grants, trace=trace, wait=wait,
                        stack=stack, capture=capture)
    try:
        rc, _ = live.exec(cmd, capture=capture)
    finally:
        sid, changes = live.close()
    if live.expired:
        rc = TIMEOUT_RC
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
        execs = m.get("execs") or []
        what = shlex.join(m.get("cmd") or [])
        if len(execs) > 1:
            what = f"{len(execs)} commands, first: {what}"
        if m.get("agent"):
            what = f"agent {m['agent']} — {what}"
        print(f"{sid}  {m.get('status', '?'):9s} exit={m.get('exit_code', '-')}{tags}  "
              f"{m.get('target', '')}  :: {what}")
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
            cause = rec.get("caused_by")
            if cause:
                print(f"{'':12s}   caused_by: turn {cause.get('turn')} "
                      f"{cause.get('tool')}({cause.get('summary', '')}) "
                      f"[{cause.get('tool_call_id')}]")
    for name, label in (("syscalls.jsonl", "syscall trace"), ("ebpf.log", "ebpf trace")):
        p = os.path.join(sdir, name)
        if os.path.isfile(p):
            with open(p, errors="replace") as f:
                n = sum(1 for _ in f)
            print(f"\n{label}: {n} events in {p}")
    return 0


def commit_session(sid, merge=False, force=False):
    """Core commit. Returns a result dict; never prints."""
    m = load_meta(sid)
    if m.get("status") != "pending":
        raise SystemExit(f"error: session is {m.get('status')}, not pending")
    sdir = session_path(sid)
    upper = os.path.join(sdir, "upper")
    with open(os.path.join(sdir, "manifest.json")) as f:
        manifest = json.load(f)
    changes = compute_diff(upper, m["target"])
    conflicts = find_conflicts(changes, manifest, m["target"])
    merged = []
    if conflicts and merge:
        merged, conflicts = try_merge(conflicts, sdir, m["target"])
    if conflicts and not force:
        return {"committed": False, "conflicts": conflicts, "merged": merged,
                "target": m["target"]}
    n = apply_upper(upper, m["target"])
    m.update(status="committed", committed=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
             forced=bool(conflicts), merged_paths=merged)
    save_meta(sid, m)
    for sub in ("upper", "work", "merged", "base", "jail", "trace", "manifest.json", "raw.strace"):
        try:
            _force_rmtree(os.path.join(sdir, sub))
        except OSError:
            pass
    return {"committed": True, "applied": n, "merged": merged, "target": m["target"]}


def rollback_session(sid):
    """Core rollback. Returns the untouched target path."""
    m = load_meta(sid)
    if m.get("status") == "committed":
        raise SystemExit("error: session already committed; nothing to roll back")
    if m.get("status") == "open" and m.get("holder_pid"):
        try:
            os.killpg(m["holder_pid"], 9)
        except OSError:
            pass
        for _ in range(50):
            if not _pid_alive(m["holder_pid"]):
                break
            time.sleep(0.1)
    _force_rmtree(session_path(sid))
    return m["target"]


def cmd_commit(args):
    res = commit_session(args.session, merge=args.merge, force=args.force)
    if not res["committed"]:
        print("error: target drifted since snapshot — refusing to commit:", file=sys.stderr)
        for reason, rel in res["conflicts"]:
            print(f"  {reason:22s} {rel}", file=sys.stderr)
        hint = "--merge (needs --merge-base session) or --force" if not args.merge else "--force"
        print(f"override with: overlord commit {hint} {args.session}", file=sys.stderr)
        return 1
    msg = f"committed {res['applied']} changes to {res['target']}"
    if res["merged"]:
        msg += f" ({len(res['merged'])} three-way merged)"
    print(msg)
    return 0


def cmd_rollback(args):
    target = rollback_session(args.session)
    print(f"rolled back {args.session} — target untouched: {target}")
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


# ---------------------------------------------------------------- daemon

VERSION = "0.3.0"
DEFAULT_SOCKET = os.path.join(OVERLORD_HOME, "overlordd.sock")
POLICY_FILE = os.path.join(OVERLORD_HOME, "policy.json")


def load_policy():
    """Policy is re-read per request so edits apply without a restart."""
    if not os.path.isfile(POLICY_FILE):
        return None
    with open(POLICY_FILE) as f:
        return json.load(f)


def _policy_rule(policy, target):
    """Longest-prefix match under 'targets', else 'default'. None = refused."""
    best, best_len = None, -1
    for prefix, rule in policy.get("targets", {}).items():
        p = prefix.rstrip("/")
        if (target == p or target.startswith(p + "/")) and len(p) > best_len:
            best, best_len = rule, len(p)
    if best is not None:
        return best
    return policy.get("default")


def resolve_policy(target, requested):
    """Broker authority: the effective grant is never looser than policy.

    Policy can force jail on, force net off, and cap the timeout. With no
    policy file, requested grants pass through (direct-CLI semantics)."""
    policy = load_policy()
    if policy is None:
        return dict(requested), None
    rule = _policy_rule(policy, target)
    if rule is None:
        raise SystemExit(f"error: policy refuses target: {target}")
    eff = dict(requested)
    if rule.get("jail"):
        eff["jail"] = True
    if rule.get("net") == "none":
        eff["net"] = "none"
    cap = rule.get("timeout")
    if cap is not None:
        eff["timeout"] = min(cap, eff.get("timeout") or cap)
    return eff, rule


def _api_run(req):
    target = os.path.realpath(req["target"])
    requested = {"net": "host", "jail": False, "timeout": None, "merge_base": False}
    requested.update(req.get("grants") or {})
    grants, _rule = resolve_policy(target, requested)
    sid, rc, changes = execute_session(
        target, list(req["cmd"]), req.get("backend"), grants,
        trace=req.get("trace"), wait=bool(req.get("wait")),
        stack=bool(req.get("stack")), capture=True,
    )
    out_path = os.path.join(session_path(sid), "output.log")
    tail = ""
    if os.path.isfile(out_path):
        with open(out_path, errors="replace") as f:
            tail = "".join(f.readlines()[-50:])
    return {"sid": sid, "exit_code": rc, "changes": changes,
            "grants": grants, "output_tail": tail}


def _api_commit(req):
    m = load_meta(req["sid"])
    policy = load_policy()
    if policy is not None and req.get("force"):
        rule = _policy_rule(policy, m["target"]) or {}
        if not rule.get("allow_force", False):
            raise SystemExit("error: policy forbids --force commits on this target")
    return commit_session(req["sid"], merge=bool(req.get("merge")),
                          force=bool(req.get("force")))


def _api_log(req):
    prov = os.path.join(session_path(req["sid"]), "provenance.jsonl")
    load_meta(req["sid"])
    records = []
    if os.path.isfile(prov):
        with open(prov) as f:
            records = [json.loads(line) for line in f]
    return {"provenance": records}


# live sessions brokered by this daemon process: sid -> LiveSession
LIVE = {}
LIVE_LOCK = None  # created lazily (threading) in cmd_daemon


def _live(sid):
    ls = LIVE.get(sid)
    if ls is None:
        raise SystemExit(f"error: session {sid} is not open in this daemon")
    return ls


def _api_open(req):
    target = os.path.realpath(req["target"])
    requested = {"net": "host", "jail": False, "timeout": None, "merge_base": False}
    requested.update(req.get("grants") or {})
    grants, _rule = resolve_policy(target, requested)
    ls = open_session(target, req.get("backend"), grants, trace=req.get("trace"),
                      wait=bool(req.get("wait")), stack=bool(req.get("stack")),
                      capture=True, agent=req.get("agent"))
    LIVE[ls.sid] = ls
    return {"sid": ls.sid, "grants": grants, "backend": ls.meta["backend"]}


def _api_exec(req, emit):
    """Streaming op: emits {"event":"out","data":...} lines, then the final result."""
    ls = _live(req["sid"])
    import base64
    rc, out = ls.exec(list(req["cmd"]), timeout=req.get("timeout"), cwd=req.get("cwd"),
                      label=req.get("label"),
                      on_output=lambda chunk: emit(
                          {"ok": True, "event": "out",
                           "data": base64.b64encode(chunk).decode()}))
    return {"exit_code": rc, "output": out.decode(errors="replace"),
            "changes": ls.changes()}


def _api_close(req):
    ls = LIVE.pop(req["sid"], None)
    if ls is None:
        m = load_meta(req["sid"])  # may reconcile an orphan
        return {"sid": req["sid"], "status": m.get("status"), "changes": []}
    sid, changes = ls.close()
    m = load_meta(sid)
    out_path = os.path.join(session_path(sid), "output.log")
    tail = ""
    if os.path.isfile(out_path):
        with open(out_path, errors="replace") as f:
            tail = "".join(f.readlines()[-50:])
    return {"sid": sid, "exit_code": m.get("exit_code"), "changes": changes,
            "grants": m.get("grants"), "output_tail": tail}


def _api_rollback(req):
    ls = LIVE.pop(req["sid"], None)
    if ls is not None:
        ls.close()
    return {"target": rollback_session(req["sid"])}


AGENT_CANCEL = set()


def _api_agent(req, emit):
    """Streaming op: open a session, run the built-in agent, close it. Emits
    transcript events as they happen; returns the sealed session."""
    import agent as agent_mod
    target = os.path.realpath(req["target"])
    requested = {"net": "host", "jail": False, "timeout": None, "merge_base": False}
    requested.update(req.get("grants") or {})
    grants, _rule = resolve_policy(target, requested)
    provider = agent_mod.make_provider(req.get("provider", "anthropic"), req.get("model"))
    ls = open_session(target, req.get("backend"), grants, trace=req.get("trace"),
                      wait=bool(req.get("wait")), stack=bool(req.get("stack")),
                      capture=True, agent=f"{provider.name}:{provider.model}")
    LIVE[ls.sid] = ls
    emit({"ok": True, "event": "session", "sid": ls.sid, "grants": grants,
          "backend": ls.meta["backend"]})
    final = ""
    try:
        final = agent_mod.run_agent(
            ls, provider, req["task"], max_turns=int(req.get("max_turns") or
                                                    agent_mod.DEFAULT_MAX_TURNS),
            emit=lambda ev: emit({"ok": True, "event": "agent", **ev}),
            should_stop=lambda: ls.sid in AGENT_CANCEL)
    except SystemExit as e:
        emit({"ok": True, "event": "agent", "type": "error", "text": str(e)})
    finally:
        AGENT_CANCEL.discard(ls.sid)
        LIVE.pop(ls.sid, None)
        sid, changes = ls.close()
    m = load_meta(sid)
    return {"sid": sid, "final": final, "changes": changes, "grants": m.get("grants"),
            "usage": m.get("usage"), "exit_code": m.get("exit_code")}


def _api_agent_cancel(req):
    if req["sid"] not in LIVE:
        raise SystemExit(f"error: no running agent session {req['sid']}")
    AGENT_CANCEL.add(req["sid"])
    return {"sid": req["sid"], "cancelling": True}


def _api_transcript(req):
    path = os.path.join(session_path(req["sid"]), "transcript.jsonl")
    load_meta(req["sid"])
    events = []
    if os.path.isfile(path):
        with open(path) as f:
            events = [json.loads(line) for line in f]
    return {"transcript": events}


DAEMON_OPS = {
    "ping": lambda req: {"version": VERSION, "pid": os.getpid()},
    "run": _api_run,
    "open": _api_open,
    "close": _api_close,
    "diff": lambda req: {"changes": compute_diff(
        os.path.join(session_path(req["sid"]), "upper"), load_meta(req["sid"])["target"])},
    "log": _api_log,
    "commit": _api_commit,
    "rollback": _api_rollback,
    "sessions": lambda req: {"sessions": [load_meta(s) for s in list_sessions()]},
    "agent_cancel": _api_agent_cancel,
    "transcript": _api_transcript,
}
STREAMING_OPS = {"exec": _api_exec, "agent": _api_agent}


def cmd_daemon(args):
    import socketserver

    sock_path = args.socket or DEFAULT_SOCKET
    os.makedirs(os.path.dirname(sock_path), exist_ok=True)
    if os.path.exists(sock_path):
        os.remove(sock_path)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            def emit(obj):
                self.wfile.write((json.dumps(obj) + "\n").encode())
                self.wfile.flush()

            for line in self.rfile:
                try:
                    req = json.loads(line)
                    op = req.get("op")
                    if op in STREAMING_OPS:
                        resp = {"ok": True, **STREAMING_OPS[op](req, emit)}
                    elif op in DAEMON_OPS:
                        resp = {"ok": True, **DAEMON_OPS[op](req)}
                    else:
                        raise ValueError(f"unknown op: {op}")
                except SystemExit as e:
                    resp = {"ok": False, "error": str(e)}
                except Exception as e:  # daemon must survive any request
                    resp = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                self.wfile.write((json.dumps(resp) + "\n").encode())
                self.wfile.flush()

    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True

    with Server(sock_path, Handler) as server:
        os.chmod(sock_path, 0o600)
        print(f"overlordd {VERSION} listening on {sock_path}"
              + (" (policy active)" if os.path.isfile(POLICY_FILE) else " (no policy file)"),
              file=sys.stderr)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            for ls in list(LIVE.values()):
                try:
                    ls.close()
                except Exception:
                    pass
    return 0


def cmd_ui(args):
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
    import ui
    return ui.serve(args.port)


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
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
    import agent as agent_mod
    agent_mod.add_agent_parser(sub, _add_exec_flags)
    sub.add_parser("doctor", help="environment diagnostics").set_defaults(fn=cmd_doctor)

    pd = sub.add_parser("daemon", help="resident broker: unix socket + policy enforcement")
    pd.add_argument("--socket", help=f"socket path (default {DEFAULT_SOCKET})")
    pd.set_defaults(fn=cmd_daemon)

    pu = sub.add_parser("ui", help="mission control: localhost web UI for session review")
    pu.add_argument("--port", type=int, default=7777)
    pu.set_defaults(fn=cmd_ui)

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
