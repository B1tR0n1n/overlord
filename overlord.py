#!/usr/bin/env python3
"""OVERLORD — an agent hypervisor: transactional, scoped, recorded execution.

    overlord run   -t <dir> [grants] [--trace[=strace|ebpf]] -- <any command>
    overlord shell -t <dir> [grants]
    overlord sessions
    overlord diff <session>
    overlord log <session>
    overlord savepoints <session>
    overlord rewind <session> --to <savepoint>
    overlord resume <session> [--note "..."] | [-- <cmd>]
    overlord fork <session> [--at <savepoint>]
    overlord compare <session-a> <session-b>
    overlord review <session> [--provider ...] [--model M]
    overlord check <session>
    overlord commit <session> [--merge] [--force] [--only SEL] [--drop SEL] [--countersigned]
    overlord rollback <session>
    overlord revert <session> [--commit] [--force] [--stack]
    overlord blame <path> [--json]
    overlord doctor
    overlord agent -t <dir> [grants] [--provider anthropic|openai] "<task>"
    overlord keys <provider> <key>

A wrapped command runs against an overlay of the target directory. Every write
lands in the session's upper layer; the real tree is untouched until an
explicit commit. Commit verifies the real tree has not drifted since the
snapshot and refuses to clobber external changes (or three-way merges them
with --merge when the session kept a base copy).

Savepoints: a session's upper layer is a *stack*, one layer per command that
wrote something (for the agent, per tool call). Each command runs in its own
mount namespace over the current stack, so a new layer costs one mount and
nothing is copied. That makes three things possible:
    rewind   drop the layers above a savepoint; the tree is as it was after
             that command, and an agent session's transcript is cut to match,
             so `resume` continues the model from a world it believes in.
    commit --only / --drop
             replay only the layers a selector names (layer:N, turn:N,
             tool:NAME, call:ID); undo a decision, not a path.
    blame    committed provenance plus retained content answer, per line,
             which session, turn, tool call and instruction put it there.
    fork     copy the stack up to a savepoint into a new pending session, so
             two continuations of one moment can be compared before either
             is committed (compare).
    review   a second model countersigns the diff (review.py); a fresh
             rejection blocks commit, --countersigned demands a fresh
             approval, and policy can require it per target.
    revert   undo a COMMITTED session: its inverse — added files removed,
             modified and deleted files restored from retained before-content
             — is staged as a NEW pending session over the same target, so it
             is reviewed and committed like any other change. (rollback is the
             pre-commit half: it discards a pending session; the tree was
             never touched.) A removed directory is rebuilt from the files
             retained beneath it at commit. File modes are not restored.
    check    dry-run the content policy gate before committing: a policy rule's
             "checks" scan the diff for secrets, compiled binaries, dependency-
             manifest changes and oversized diffs; each finding is block (refuse
             like a conflict; --force overrides), countersign (demand a fresh
             approval) or warn (record and allow). commit runs the same gate.

Grants (the capability manifest, via flags or --manifest file):
    --jail          pivot_root jail: the process sees system dirs + the target
                    and nothing else — $HOME and the rest of the fs don't exist
    --net none      private network namespace: no network, not even loopback
    --net proxy     empty netns whose only egress is a recording, allowlisting
                    proxy — every connection is on the session's record
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

# Inside a jail HOME is the working folder, so the default state dir would
# land in the project tree (and in its diff); state written from inside a
# jail goes to the jail's private /tmp instead and vanishes with it.
OVERLORD_HOME = os.environ.get("OVERLORD_HOME") or (
    "/tmp/overlord-in-jail" if os.environ.get("OVERLORD_JAIL") else os.path.expanduser("~/.overlord"))
SESSIONS_DIR = os.path.join(OVERLORD_HOME, "sessions")
LOCKS_DIR = os.path.join(OVERLORD_HOME, "locks")
# content-addressed copies of every committed file version (before and after),
# so `blame` can attribute lines, not just files. Capped per file.
OBJECTS_DIR = os.path.join(OVERLORD_HOME, "objects")
OBJECT_MAX = int(os.environ.get("OVERLORD_OBJECT_MAX", 4 << 20))
EBPF_SCRIPT = "/usr/local/lib/overlord/provenance.bt"
TIMEOUT_RC = 124
ENTER_RC = 125          # the namespace-entry wrapper failed before exec

# layer stack: layer 0 is <session>/upper (unchanged on-disk contract), layer
# N>0 is <session>/layers/N/upper. The legacy mount(2) data page is 4 KiB and
# every layer adds a path to lowerdir=, so layers are named relative to the
# session dir and the stack is capped; past the cap the top layer keeps
# absorbing writes (savepoints get coarser, nothing is lost).
LAYERS_DIR = "layers"
MAX_LAYERS = 200

# session record file names
META_FILE = "meta.json"
MANIFEST_FILE = "manifest.json"
PROVENANCE_FILE = "provenance.jsonl"
SYSCALLS_FILE = "syscalls.jsonl"
RAW_TRACE_FILE = "raw.strace"
OUTPUT_FILE = "output.log"
TS_FORMAT = "%Y-%m-%dT%H:%M:%S%z"

# session ids are minted by new_session_id(); anything else is rejected before
# it can be joined onto a path (ids arrive from argv, the daemon socket, the UI)
_SESSION_ID_RE = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")


class OverlordError(Exception):
    """A user-facing failure. The CLI prints it and exits 1; the daemon and UI
    turn it into an error response. Library code raises this, never SystemExit,
    so embedding callers keep control of the process."""


def _now():
    return time.strftime(TS_FORMAT)

# ---------------------------------------------------------------- backends


def _kernel_backend_available():
    try:
        probe = subprocess.run(
            ["unshare", "--map-root-user", "--mount", "true"], capture_output=True
        )
    except OSError:                       # no unshare(1) on this host at all
        return False
    return probe.returncode == 0


def _fuse_backend_reason():
    """Why the fuse backend cannot mount here, or None when it can. The
    binaries on PATH are not the backend: a mount needs /dev/fuse, which a
    container started without --device /dev/fuse lacks, and a jail never
    has (found by an agent running the suite inside its own jail: doctor
    said available, every session died on the mount)."""
    for tool in ("fuse-overlayfs", "fusermount3"):
        if not shutil.which(tool):
            return f"missing {tool}"
    if not os.path.exists("/dev/fuse"):
        return "no /dev/fuse" + (" (inside a jail)" if in_jail()
                                 else " (a container needs --device /dev/fuse)")
    if not os.access("/dev/fuse", os.R_OK | os.W_OK):
        return "/dev/fuse not accessible to this user"
    return None


def _fuse_backend_available():
    return _fuse_backend_reason() is None


def in_jail():
    """True when this process runs inside an OVERLORD jail."""
    return bool(os.environ.get("OVERLORD_JAIL"))


def detect_backend():
    if _kernel_backend_available():
        return "kernel"
    if _fuse_backend_available():
        return "fuse"
    return None


def _check_mount_path(path, name):
    if ":" in path or "," in path:
        raise OverlordError(
            f"error: {name} path contains ':' or ',' — unsupported in overlay mount options: {path}"
        )


def layer_upper_rel(i):
    """Upper dir of layer i, relative to the session dir."""
    return "upper" if i == 0 else f"{LAYERS_DIR}/{i}/upper"


def layer_work_rel(i):
    return "work" if i == 0 else f"{LAYERS_DIR}/{i}/work"


def layer_uppers(sdir, meta):
    """Absolute upper dirs of every layer, bottom (0) to top."""
    n = len(meta.get("layers") or ()) or 1
    return [os.path.join(sdir, layer_upper_rel(i)) for i in range(n)]


def overlay_opts(target, n_layers, kernel=True, sdir=None):
    """Mount options for a stack of n_layers over target. Kernel mounts are
    made with cwd = session dir and layer paths relative to it (the mount
    data page is 4 KiB); fuse-overlayfs daemonizes, so it gets absolute ones."""
    def up(i):
        return layer_upper_rel(i) if sdir is None else os.path.join(sdir, layer_upper_rel(i))

    def wk(i):
        return layer_work_rel(i) if sdir is None else os.path.join(sdir, layer_work_rel(i))
    lowers = [up(i) for i in range(n_layers - 2, -1, -1)] + [target]
    opts = f"lowerdir={':'.join(lowers)},upperdir={up(n_layers - 1)},workdir={wk(n_layers - 1)}"
    return opts + ",userxattr" if kernel else opts


# Per-command namespace entry for the kernel backend. The session holder (the
# executor loop below) lives in the session's user/mount(/net/pid/uts/ipc)
# namespaces with the real root still visible, and every command it runs
# passes through this wrapper: a fresh private mount namespace, the overlay
# mounted over the *current* layer stack, then (with the jail grant) a tmpfs
# root with system dirs bound, private /proc, pivot_root, and the old root
# detached. Layers are addressed relative to the session dir; mount(2) is
# called directly so no mount(8) option-length policy gets between the stack
# and the kernel. Session records (meta, manifest, provenance, layers) are
# NEVER exposed to the jail — only the isolated trace/ subdir is bound, and
# only when strace needs somewhere to write (red team finding A3), plus the
# session's own tmp/ so /tmp survives from one command to the next.
_ENTER_SRC = r"""
import ctypes, json, os, platform, subprocess, sys
spec = json.loads(sys.argv[1])
libc = ctypes.CDLL(None, use_errno=True)
MS_RDONLY, MS_NOSUID, MS_NODEV, MS_BIND, MS_REC, MS_PRIVATE = 1, 2, 4, 4096, 16384, 1 << 18
MNT_DETACH, CLONE_NEWNS = 2, 0x20000
def die(what):
    e = ctypes.get_errno()
    sys.stderr.write("overlord: %s: %s\n" % (what, os.strerror(e) if e else "failed"))
    sys.exit(125)
def mount(src, tgt, fstype, flags, data=None):
    if libc.mount(src.encode(), tgt.encode(), fstype.encode() if fstype else None,
                  ctypes.c_ulong(flags), data.encode() if data else None) != 0:
        die("mount " + tgt)
if libc.unshare(CLONE_NEWNS) != 0:
    die("unshare mount namespace")
mount("none", "/", None, MS_REC | MS_PRIVATE)
sdir, target, cmd = spec["sdir"], spec["target"], spec["cmd"]
cwd = spec.get("cwd") or ""
if spec.get("jail"):
    tgt_rel = target.lstrip("/")
    J = os.path.join(sdir, "jail")
    mount("tmpfs", J, "tmpfs", 0)
    os.chdir(J)
    for d in ("oldroot", "proc", "tmp", "dev"):
        os.mkdir(d)
    mount(os.path.join(sdir, "tmp"), "tmp", None, MS_BIND)
    HOST_DIRS = ("usr", "bin", "sbin", "lib", "lib64", "lib32", "etc", "opt")
    for d in HOST_DIRS:
        if os.path.islink("/" + d):
            os.symlink(os.readlink("/" + d), d)
        elif os.path.isdir("/" + d):
            os.mkdir(d)
            mount("/" + d, d, None, MS_BIND | MS_REC)
    # red team A12: a bind mount is read-write by default, so a jailed command
    # could write the host's /etc, /usr and /opt. Every host bind and each of
    # its submounts is remounted read-only, keeping the flags a user namespace
    # locks (nosuid, nodev, noexec, atime) or the kernel refuses the remount.
    MS_REMOUNT, MS_NOEXEC = 32, 8
    LOCKED = {"nosuid": MS_NOSUID, "nodev": MS_NODEV, "noexec": MS_NOEXEC, "noatime": 1024,
              "nodiratime": 2048, "relatime": 1 << 21, "strictatime": 1 << 24}
    def remount_ro(binds):
        with open("/proc/self/mountinfo") as f:
            for line in f:
                r = line.split()
                mp = r[4].replace("\\040", " ")
                if not any(mp == b or mp.startswith(b + "/") for b in binds):
                    continue
                flags = MS_REMOUNT | MS_BIND | MS_RDONLY
                for opt in r[5].split(","):
                    flags |= LOCKED.get(opt, 0)
                mount("none", mp, None, flags)
    remount_ro([os.path.join(J, d) for d in HOST_DIRS])
    # Names, when the network is granted. On WSL2 and systemd-resolved hosts
    # /etc/resolv.conf is a symlink out of /etc (/mnt/wsl/resolv.conf,
    # /run/systemd/resolve/stub-resolv.conf); those trees are not bound, so
    # inside the jail the link dangled: a net=host command had a network and
    # no DNS. The real file is bound at its real path, read-only, so the link
    # in the bound /etc resolves. With net=none there is nothing to resolve.
    if spec.get("net") == "host":
        real = os.path.realpath(spec.get("resolv") or "/etc/resolv.conf")
        top = real.lstrip("/").split("/", 1)[0]
        if os.path.isfile(real) and top not in HOST_DIRS and top not in ("proc", "dev", "tmp"):
            rel = real.lstrip("/")
            os.makedirs(os.path.dirname(rel), exist_ok=True)
            open(rel, "w").close()
            mount(real, rel, None, MS_BIND)
            remount_ro([os.path.join(J, rel)])
    for n in ("null", "zero", "full", "random", "urandom", "tty"):
        if os.path.exists("/dev/" + n):
            open("dev/" + n, "w").close()
            mount("/dev/" + n, "dev/" + n, None, MS_BIND)
    os.symlink("/proc/self/fd", "dev/fd")
    try:
        resolv = os.path.realpath("/etc/resolv.conf")
        if resolv.startswith("/run/") and os.path.isfile(resolv):
            os.makedirs(os.path.dirname(resolv.lstrip("/")), exist_ok=True)
            with open(resolv, "rb") as f, open(resolv.lstrip("/"), "wb") as g:
                g.write(f.read())
    except OSError:
        pass
    if spec.get("trace_bind"):
        os.mkdir(".overlord")
        mount(os.path.join(sdir, "trace"), ".overlord", None, MS_BIND)
    os.makedirs(tgt_rel, exist_ok=True)
    os.chdir(sdir)
    mount("overlay", os.path.join(J, tgt_rel), "overlay", 0, spec["opts"])
    os.chdir(J)
    mount("proc", "proc", "proc", 0)
    nr = {"x86_64": 155, "aarch64": 41, "riscv64": 41, "i686": 217, "i386": 217,
          "armv7l": 218, "ppc64le": 203, "s390x": 217}.get(platform.machine())
    if nr is None or libc.syscall(nr, b".", b"oldroot") != 0:
        subprocess.run(["pivot_root", ".", "oldroot"], check=True)
    os.chdir("/")
    libc.umount2(b"/oldroot", MNT_DETACH)
    os.environ["HOME"] = "/" + tgt_rel
    os.environ["TMPDIR"] = "/tmp"
    os.environ["OVERLORD_JAIL"] = "1"       # so a command can tell where it is
    os.chdir(os.path.join("/", tgt_rel, cwd))
    # red team A14: inside the user namespace the command held every
    # capability (over the namespace's own resources) with no seccomp policy
    # and NoNewPrivs off — far more surface than a build needs. Mounts are
    # done, so: ambient caps cleared, the bounding set dropped, NoNewPrivs
    # set, a seccomp filter installed, then every capability set zeroed.
    PR_CAPBSET_DROP, PR_SET_NO_NEW_PRIVS, PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL = 24, 38, 47, 4
    PR_SET_SECCOMP, SECCOMP_MODE_FILTER = 22, 2
    libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
    for cap in range(64):
        if libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0:
            break                                   # EINVAL past the last capability
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        die("no_new_privs")
    DENY = {"x86_64": [165, 166, 155, 272, 308, 246, 320, 169, 175, 313, 176, 250, 248, 249, 321, 298,
                       323, 304, 425, 426, 427, 428, 429, 430, 431, 432, 433, 442, 167, 168, 163, 164,
                       227, 305, 159, 103, 312, 180, 153, 171, 170, 172, 173, 179, 212, 256, 279],
            "aarch64": [40, 39, 41, 97, 268, 104, 294, 142, 105, 273, 106, 219, 217, 218, 280, 241,
                        282, 265, 425, 426, 427, 428, 429, 430, 431, 432, 433, 442, 224, 225, 89, 170,
                        112, 266, 171, 116, 272, 42, 58, 162, 161, 60, 18, 238, 239]}
    PTRACE = {"x86_64": [101, 310, 311], "aarch64": [117, 270, 271]}
    ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}
    m = platform.machine()
    if m in DENY:
        deny = list(DENY[m]) + ([] if spec.get("trace_bind") else PTRACE[m])
        class SockFilter(ctypes.Structure):
            _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8),
                        ("k", ctypes.c_uint32)]
        class SockFprog(ctypes.Structure):
            _fields_ = [("len", ctypes.c_uint16), ("filter", ctypes.POINTER(SockFilter))]
        LD_ABS, JEQ, JGE, RET = 0x20, 0x15, 0x35, 0x06
        KILL, ALLOW, EPERM_RET = 0x80000000, 0x7FFF0000, 0x00050001
        prog = [(LD_ABS, 0, 0, 4), (JEQ, 1, 0, ARCH[m]), (RET, 0, 0, KILL),      # wrong ABI: kill
                (LD_ABS, 0, 0, 0), (JGE, 0, 1, 0x40000000), (RET, 0, 0, KILL)]    # x32 numbers: kill
        for nr in deny:
            prog += [(JEQ, 0, 1, nr), (RET, 0, 0, EPERM_RET)]
        prog.append((RET, 0, 0, ALLOW))
        arr = (SockFilter * len(prog))(*[SockFilter(*p) for p in prog])
        fprog = SockFprog(len(prog), arr)
        if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0) != 0:
            die("seccomp")
    class CapHdr(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
    class CapData(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                    ("inheritable", ctypes.c_uint32)]
    hdr, data = CapHdr(0x20080522, 0), (CapData * 2)()
    capset_nr = {"x86_64": 126, "aarch64": 91}.get(m)
    if capset_nr is not None and libc.syscall(capset_nr, ctypes.byref(hdr), ctypes.byref(data)) != 0:
        die("capset")
else:
    os.chdir(sdir)
    mount("overlay", target, "overlay", 0, spec["opts"])
    os.chdir(os.path.join(target, cwd))
try:
    os.execvp(cmd[0], cmd)
except OSError as e:
    sys.stderr.write("overlord: exec %s: %s\n" % (cmd[0], e.strerror))
    sys.exit(127)
"""


def prepare_kernel(target, sdir, grants):
    """Holder launch prefix for the kernel backend: the executor lives in the
    session's namespaces with the real root visible; every command it runs
    enters its own mount namespace over the current layer stack (_ENTER_SRC).
    Returns (argv_prefix, cleanup)."""
    _check_mount_path(target, "target")
    _check_mount_path(sdir, "session")
    argv = ["unshare", "--map-root-user", "--mount"]
    if grants.get("net") in ("none", "proxy"):
        # proxy egress runs in an EMPTY namespace with no route out; the only
        # path is the in-namespace proxy front (netproxy), so a direct connect
        # is refused by the kernel, not by cooperation
        argv.append("--net")
    if grants.get("jail"):
        # private pid, uts and ipc namespaces: a jailed process must not see
        # host processes, nor reach host-wide kernel state such as the
        # hostname (red team finding A4 when overlord itself runs as root)
        argv += ["--pid", "--fork", "--uts", "--ipc"]
        os.makedirs(os.path.join(sdir, "jail"), exist_ok=True)
    return argv, None


def prepare_fuse(target, sdir, grants):
    """Holder launch prefix for the fuse backend: no namespaces; the parent
    process mounts fuse-overlayfs at <session>/merged and remounts it when the
    stack grows. Returns (argv_prefix, cleanup)."""
    for grant in ("jail", "net"):
        if grants.get(grant) and grants[grant] != "host":
            raise OverlordError(
                f"error: --{grant} requires the kernel backend "
                "(install packaging/apparmor profile)"
            )
    _check_mount_path(target, "target")
    _check_mount_path(sdir, "session")
    merged = os.path.join(sdir, "merged")

    def cleanup():
        _fuse_unmount(merged)

    return [], cleanup


def _fuse_mount(target, sdir, n_layers):
    merged = os.path.join(sdir, "merged")
    opts = overlay_opts(target, n_layers, kernel=False, sdir=sdir)
    mnt = subprocess.run(["fuse-overlayfs", "-o", opts, merged],
                         capture_output=True, text=True)
    if mnt.returncode != 0:
        raise OverlordError(f"error: fuse-overlayfs mount failed: {mnt.stderr.strip()}")


def _fuse_unmount(merged):
    """True when merged is no longer mounted."""
    if not os.path.ismount(merged):
        return True
    r = subprocess.run(["fusermount3", "-u", merged], capture_output=True)
    return r.returncode == 0 and not os.path.ismount(merged)


PREPARE = {"kernel": prepare_kernel, "fuse": prepare_fuse}

# ---------------------------------------------------------------- sessions


def new_session_id():
    return time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]


def validate_session_id(sid):
    """Return sid if it has the minted shape; otherwise refuse. This is the one
    gate between externally supplied ids and the filesystem, so the message
    deliberately does not echo the rejected value."""
    if not isinstance(sid, str) or not _SESSION_ID_RE.match(sid):
        raise OverlordError("error: invalid session id")
    return sid


def session_path(sid):
    return os.path.join(SESSIONS_DIR, validate_session_id(sid))


def session_file(sid, name):
    """Path of a record file (meta, manifest, ...) inside a validated session."""
    return os.path.join(session_path(sid), name)


def _safe_join(base, rel):
    """Join rel onto base, refusing any result that escapes base. Relative
    paths here come from walking an overlay upper layer that an untrusted
    process wrote to, so a crafted name must never resolve outside the tree
    it is being replayed into.

    normpath alone stops lexical `..`, but not a symlink drifted into an
    existing path component: if the target grew `dir -> /outside` after the
    snapshot, replaying `dir/file` would write through it. So the deepest
    component that already exists on disk is resolved with realpath and must
    still sit inside base. This runs on the write path, so --force cannot
    bypass it."""
    base_abs = os.path.abspath(base)
    path = os.path.normpath(os.path.join(base_abs, rel))
    if path != base_abs and not path.startswith(base_abs + os.sep):
        raise OverlordError(f"error: path escapes its tree: {rel}")
    real_base = os.path.realpath(base_abs)
    probe = path
    while probe != base_abs and not os.path.lexists(probe):
        probe = os.path.dirname(probe)
    real_probe = os.path.realpath(probe)
    if real_probe != real_base and not real_probe.startswith(real_base + os.sep):
        raise OverlordError(f"error: path escapes its tree via a symlink: {rel}")
    return path


def load_meta(sid):
    path = session_file(sid, META_FILE)
    if not os.path.isfile(path):
        raise OverlordError(f"error: no such session: {sid}")
    with open(path) as f:
        meta = json.load(f)
    return reconcile_session(sid, meta)


def save_meta(sid, meta):
    # atomic: a reader (the UI polling during a live run, a second session,
    # the daemon) must never see a truncated meta.json mid-write
    path = session_file(sid, META_FILE)
    tmp = f"{path}.{uuid.uuid4().hex[:8]}.tmp"
    with open(tmp, "w") as f:
        json.dump(meta, f, indent=2)
    os.replace(tmp, path)


def list_sessions():
    if not os.path.isdir(SESSIONS_DIR):
        return []
    return sorted(
        d for d in os.listdir(SESSIONS_DIR)
        if _SESSION_ID_RE.match(d)
        and os.path.isfile(os.path.join(SESSIONS_DIR, d, META_FILE))
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
        raise OverlordError(
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


def is_whiteout(path, backend=None):
    """Kernel overlayfs marks a delete with a 0:0 char device (or the
    user.overlay.whiteout xattr under userxattr). The `.wh.` name prefix is
    fuse-overlayfs's convention; on the kernel backend a file called
    `.wh.foo` is a file called `.wh.foo`, and reading it as a whiteout would
    delete the user's `foo` on commit."""
    st = os.lstat(path)
    if stat.S_ISCHR(st.st_mode) and st.st_rdev == 0:
        return True
    if backend != "kernel" and os.path.basename(path).startswith(WHITEOUT_PREFIX):
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


# fuse-overlayfs keeps its opaque bookkeeping as entries inside the directory
# it marks; they are not the workload's and must never reach the tree
_FUSE_MARKERS = {".wh..opq", ".wh..wh..opq"}


def _layer_entries(upper, target, backend=None):
    """Walk one layer: yields (kind, rel, opaque).

    kinds: added, modified, deleted, replaced-dir. Added dirs get a '/'
    suffix. A directory marked opaque over something the target has is a
    replaced-dir and is not descended (it is replayed wholesale); one marked
    opaque over nothing (fuse-overlayfs marks every new directory) is simply
    an added directory, descended like any other — but its opacity still
    matters to a stack, where it hides whatever lower layers put beneath."""
    for root, dirs, files in os.walk(upper):
        skip = []
        for d in dirs:
            dpath = os.path.join(root, d)
            rel = os.path.relpath(dpath, upper)
            opaque = is_opaque_dir(dpath)
            tdir = _safe_join(target, rel)
            if opaque and os.path.lexists(tdir):
                yield ("replaced-dir", rel, True)
                skip.append(d)
            elif not os.path.isdir(tdir):
                yield ("added", rel + "/", opaque)
        dirs[:] = [d for d in dirs if d not in skip]  # don't descend replaced dirs
        for name in files:
            if backend != "kernel" and name in _FUSE_MARKERS:
                continue
            fpath = os.path.join(root, name)
            rel = os.path.relpath(fpath, upper)
            if is_whiteout(fpath, backend):
                try:
                    yield ("deleted", _victim_rel(fpath, upper), False)
                except OverlordError:
                    # names its own tree root; recorded so diff/log show it,
                    # refused by commit_session before anything is replayed
                    yield ("invalid-whiteout", rel, False)
            elif os.path.lexists(_safe_join(target, rel)):
                yield ("modified", rel, False)
            else:
                yield ("added", rel, False)


def compute_diff(upper, target, backend=None):
    """Classify upper-layer entries: sorted list of (kind, relpath)."""
    return sorted(((k, r) for k, r, _o in _layer_entries(upper, target, backend)),
                  key=lambda c: c[1])


def _victim_rel(whiteout_path, upper):
    """Relative path a whiteout entry deletes, proven to stay inside the tree
    (a file literally named '.wh...' would otherwise name the parent dir)."""
    victim = os.path.relpath(whiteout_victim(whiteout_path), upper)
    if victim in ("", os.curdir) or victim.startswith(os.pardir + os.sep):
        # a file literally named '.wh.' / '.wh..' resolves to the parent dir;
        # left unchecked, apply_upper would _remove_target(<tree root>).
        raise OverlordError(f"error: whiteout names its own tree: {whiteout_path}")
    _safe_join(upper, victim)
    return victim


def _drop_subtree(merged, clean):
    prefix = clean + os.sep
    for key in [k for k in merged if k == clean or k.startswith(prefix)]:
        del merged[key]


def stack_diff(uppers, target, backend=None):
    """Flatten a layer stack the way the kernel would present it.

    Returns (changes, origin, touched):
      changes  sorted [(kind, rel)] — the net effect of the whole stack on the
               target, same shape as compute_diff
      origin   rel -> index into uppers of the layer that holds the final
               content (the topmost layer mentioning the path)
      touched  every per-layer entry a sequential replay would act on. This
               is the set conflict detection must check: a file a lower
               layer created and a higher one deleted is absent from
               `changes`, yet replay still writes it, so a same-named file
               that appeared externally would be destroyed unnoticed.
    Whiteouts of paths the target never had cancel lower-layer entries and
    are not replayed against the target, so they are excluded from touched."""
    merged = {}     # clean rel -> [kind, layer, display rel]
    touched = set()
    for k, upper in enumerate(uppers):
        for kind, rel, opaque in sorted(_layer_entries(upper, target, backend),
                                        key=lambda c: c[1]):
            clean = rel.rstrip("/")
            if kind == "deleted":
                _drop_subtree(merged, clean)
                if os.path.lexists(_safe_join(target, clean)):
                    merged[clean] = ["deleted", k, rel]
                    touched.add((kind, rel))
                continue
            if opaque:
                _drop_subtree(merged, clean)
            merged[clean] = [kind, k, rel]
            touched.add((kind, rel))
    changes = sorted(((v[0], v[2]) for v in merged.values()), key=lambda c: c[1])
    origin = {v[2]: v[1] for v in merged.values()}
    return changes, origin, sorted(touched, key=lambda c: c[1])


def session_stack(sid, meta=None, layers=None):
    """(changes, origin, touched, uppers) for a session's stack, or a subset
    of its layers (indices, ascending). Empty when the layers are gone."""
    meta = meta or load_meta(sid)
    sdir = session_path(sid)
    uppers = layer_uppers(sdir, meta)
    if layers is not None:
        uppers = [uppers[i] for i in layers]
    uppers = [u for u in uppers if os.path.isdir(u)]
    if not uppers:
        return [], {}, [], []
    changes, origin, touched = stack_diff(uppers, meta["target"], meta.get("backend"))
    return changes, origin, touched, uppers


# ---------------------------------------------------------------- conflicts


def find_conflicts(changes, manifest, target):
    """Paths where the real tree drifted after the snapshot. List of (reason, rel)."""
    conflicts = []
    for kind, rel in changes:
        if kind == "added":
            conflicts.extend(_added_conflicts(rel, manifest, target))
        elif kind in ("modified", "deleted"):
            conflicts.extend(_touched_conflicts(rel, manifest, target))
        elif kind == "replaced-dir":
            conflicts.extend(_replaced_dir_conflicts(rel, manifest, target))
        elif kind == "invalid-whiteout":
            conflicts.append(("invalid-whiteout", rel))
    return conflicts


def _added_conflicts(rel, manifest, target):
    tpath = _safe_join(target, rel.rstrip("/"))
    if rel.endswith("/"):
        # mkdir -p semantics: a pre-existing *directory* here is benign, but an
        # external regular file or symlink is not — apply_upper would delete it.
        if os.path.lexists(tpath) and not (os.path.isdir(tpath) and not os.path.islink(tpath)):
            return [("created-externally", rel)]
        return []
    if rel in manifest or os.path.lexists(tpath):
        return [("created-externally", rel)]
    return []


def _touched_conflicts(rel, manifest, target):
    """A file the session modified or deleted must still be as snapshotted."""
    if rel not in manifest:
        # the manifest holds files, so a deleted DIRECTORY is not in it: it is
        # validated as a subtree, like a replaced dir — every snapshotted file
        # beneath it intact and nothing new beneath it — since replay rmtrees it
        tpath = _safe_join(target, rel)
        if os.path.isdir(tpath) and not os.path.islink(tpath):
            return _replaced_dir_conflicts(rel, manifest, target)
        return [("appeared-after-snapshot", rel)]
    tpath = _safe_join(target, rel)
    if not os.path.lexists(tpath):
        return [("deleted-externally", rel)]
    if _fingerprint(tpath) != manifest[rel]:
        return [("modified-externally", rel)]
    return []


def _replaced_dir_conflicts(rel, manifest, target):
    """A wholesale-replaced dir is removed and rewritten on commit, so nothing
    live under it may be lost: every snapshotted file must be intact AND no
    descendant may have appeared after the snapshot."""
    prefix = rel + os.sep
    found = []
    for mrel, fp in manifest.items():
        if not mrel.startswith(prefix):
            continue
        mpath = _safe_join(target, mrel)
        if not os.path.lexists(mpath) or _fingerprint(mpath) != fp:
            found.append(("modified-externally", mrel))
    tdir = _safe_join(target, rel)
    if os.path.isdir(tdir) and not os.path.islink(tdir):
        for root, _dirs, files in os.walk(tdir):
            for name in files:
                drel = os.path.relpath(os.path.join(root, name), target)
                if drel not in manifest:
                    found.append(("appeared-after-snapshot", drel))
    return found


def try_merge(conflicts, sdir, target, locate=None):
    """Three-way merge modified-externally conflicts using the session's base
    copy. Merged content is written into the layer that holds the session's
    version (locate(rel) — the top of the stack by default), so a subsequent
    replay applies it. Returns (resolved, unresolved)."""
    base_dir = os.path.join(sdir, "base")
    upper = os.path.join(sdir, "upper")
    locate = locate or (lambda rel: _safe_join(upper, rel))
    if not os.path.isdir(base_dir):
        raise OverlordError(
            "error: --merge needs a base copy — session was not run with --merge-base"
        )
    resolved, unresolved = [], []
    for reason, rel in conflicts:
        ours = locate(rel)                  # session's version
        base = _safe_join(base_dir, rel)    # common ancestor
        theirs = _safe_join(target, rel)    # external version
        if reason != "modified-externally" or not all(
            os.path.isfile(p) and not os.path.islink(p) for p in (ours, base, theirs)
        ):
            unresolved.append((reason, rel))
            continue
        # all three operands are validated regular files inside their trees;
        # git receives them as positional args after "--", never as options
        r = subprocess.run(
            ["git", "merge-file", "-p", "-L", "session", "-L", "base", "-L",
             "external", "--", ours, base, theirs],
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


def build_provenance(changes, upper, target, origin=None, uppers=None):
    """Transaction-level flight record: hashes before (lower) and after (upper).
    With a stack, origin maps each path to the layer (index into uppers) that
    holds its final content, and the record names that layer."""
    ts = _now()
    records = []
    for kind, rel in changes:
        rec = {"ts": ts, "kind": kind, "path": rel}
        clean = rel.rstrip("/")
        if origin is not None and rel in origin:
            rec["layer"] = origin[rel]
        if kind in ("modified", "deleted"):
            tpath = _safe_join(target, clean)
            if os.path.lexists(tpath):
                rec["before_sha256"] = _sha256(tpath)
        if kind in ("added", "modified") and not rel.endswith("/"):
            layer_dir = uppers[origin[rel]] if origin is not None and uppers else upper
            upath = _safe_join(layer_dir, clean)
            rec["after_sha256"] = _sha256(upath)
            rec["after_size"] = os.lstat(upath).st_size
        records.append(rec)
    return records


def store_object(path):
    """Retain a copy of a regular file under objects/<sha256> for blame.
    Returns the hash, or None when the file is not retained (symlink,
    special, or over OBJECT_MAX)."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_size > OBJECT_MAX:
        return None
    digest = _sha256(path)
    os.makedirs(OBJECTS_DIR, exist_ok=True)
    dst = os.path.join(OBJECTS_DIR, digest)
    if not os.path.exists(dst):
        tmp = dst + f".{uuid.uuid4().hex[:8]}.tmp"
        shutil.copyfile(path, tmp)
        os.replace(tmp, dst)
    return digest


def load_object(digest):
    """Retained content for a hash, or None."""
    if not digest or "/" in digest:
        return None
    path = os.path.join(OBJECTS_DIR, digest)
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as f:
        return f.read()


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
        raise OverlordError("error: ebpf recorder script not found")
    if not shutil.which("bpftrace"):
        raise OverlordError("error: --trace ebpf needs bpftrace (sudo apt install bpftrace)")
    argv = ["bpftrace", "-o", os.path.join(sdir, "ebpf.log"), script, str(pid)]
    if os.geteuid() != 0:
        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
            raise OverlordError(
                "error: --trace ebpf needs root (or passwordless sudo for bpftrace)"
            )
        argv = ["sudo", "-n"] + argv
    return subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ---------------------------------------------------------------- commit


def _copy_entry(src, dst):
    st = os.lstat(src)
    if os.path.islink(dst):
        os.remove(dst)
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


def apply_upper(upper, target, backend=None):
    """Replay the upper layer onto the real tree. Returns change count."""
    applied = 0
    # Validate every destination first (the same strict join used below, which
    # already refuses a symlinked ancestor), so a rejection leaves nothing
    # half-replayed rather than mutating up to the offending entry.
    for root, dirs, files in os.walk(upper):
        for d in dirs:
            _safe_join(target, os.path.relpath(os.path.join(root, d), upper))
        for name in files:
            if backend != "kernel" and name in _FUSE_MARKERS:
                continue
            fpath = os.path.join(root, name)
            rel = _victim_rel(fpath, upper) if is_whiteout(fpath, backend) \
                else os.path.relpath(fpath, upper)
            _safe_join(target, rel)
    for root, dirs, files in os.walk(upper):
        for d in dirs:
            dpath = os.path.join(root, d)
            tpath = _safe_join(target, os.path.relpath(dpath, upper))
            if is_opaque_dir(dpath):
                # wholesale replacement: clear, recreate, then the walk below
                # fills it entry by entry (which also keeps fuse's markers out)
                _remove_target(tpath)
                os.makedirs(tpath)
                shutil.copystat(dpath, tpath)
                applied += 1
            elif not (os.path.isdir(tpath) and not os.path.islink(tpath)):
                _remove_target(tpath)
                os.makedirs(tpath, exist_ok=True)
                applied += 1
        for name in files:
            if backend != "kernel" and name in _FUSE_MARKERS:
                continue
            fpath = os.path.join(root, name)
            if is_whiteout(fpath, backend):
                _remove_target(_safe_join(target, _victim_rel(fpath, upper)))
            else:
                _copy_entry(fpath, _safe_join(target, os.path.relpath(fpath, upper)))
            applied += 1
    return applied


def apply_layers(uppers, target, backend=None):
    """Replay a stack bottom-up. Each layer's entries are complete (overlayfs
    copies a whole file up on first write), so sequential replay of any
    ascending subset of layers yields exactly the state the topmost selected
    layer describes for every path it mentions."""
    for upper in uppers:
        apply_upper(upper, target, backend)


# ---------------------------------------------------------------- execution


# resource grants: what a session may consume of the machine. Enforced by
# rlimits in every command (both backends) and, where the host allows, a
# cgroup around the whole session; the disk figure is measured per layer.
DEFAULT_LIMITS = {"memory_mb": 4096, "pids": 512, "cpu_pct": 200, "disk_mb": 8192,
                  "fsize_mb": 4096, "nofile": 4096}
LIMIT_KEYS = tuple(DEFAULT_LIMITS)
DISK_RC = 122            # a command's exit code when the session crossed its disk grant


def parse_limits(pairs, base=None):
    """--limit key=value (repeatable) over defaults; 0 means unlimited."""
    limits = dict(base or DEFAULT_LIMITS)
    for pair in pairs or []:
        k, sep, v = str(pair).partition("=")
        if not sep or k not in LIMIT_KEYS:
            raise OverlordError(f"error: --limit takes one of {', '.join(LIMIT_KEYS)}=N")
        try:
            limits[k] = max(0, int(v))
        except ValueError:
            raise OverlordError(f"error: --limit {k} must be a whole number")
    return limits


def effective_limits(grants):
    return {k: int(v) for k, v in (grants.get("limits") or DEFAULT_LIMITS).items() if k in LIMIT_KEYS}


def load_grants(args):
    """Capability manifest: --manifest file defaults, CLI flags override."""
    grants = {"net": "host", "jail": False, "timeout": None, "merge_base": False}
    optional = {"connectors": list, "connector_approval": str, "limits": dict,
                "connector_shell": bool, "net_allow": list}
    manifest_file = getattr(args, "manifest", None)
    if manifest_file:
        with open(manifest_file) as f:
            declared = json.load(f)
        unknown = set(declared) - set(grants) - set(optional)
        if unknown:
            raise OverlordError(f"error: unknown manifest keys: {', '.join(sorted(unknown))}")
        for k, typ in optional.items():
            if k in declared and not isinstance(declared[k], typ):
                raise OverlordError(f"error: manifest key {k} must be a {typ.__name__}")
        grants.update(declared)
    if getattr(args, "net", None):
        grants["net"] = args.net
    if getattr(args, "net_allow", None):
        grants["net_allow"] = list(args.net_allow)
    if getattr(args, "jail", False):
        grants["jail"] = True
    if getattr(args, "timeout", None):
        grants["timeout"] = args.timeout
    if getattr(args, "merge_base", False):
        grants["merge_base"] = True
    if getattr(args, "limit", None):
        grants["limits"] = parse_limits(args.limit, grants.get("limits"))
    if getattr(args, "connector_shell", False):
        grants["connector_shell"] = True
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
import base64, fcntl, json, os, signal, socket, struct, subprocess, sys, threading
# red team A11: the executor inherits the holder's environment, which is the
# operator's — provider keys, OVERLORD_HOME, whatever `overlord ui` was
# started with. Nothing a sandboxed command runs may read those, so the
# environment is cut to what a build needs before the first command.
_KEEP = ("PATH", "HOME", "TMPDIR", "LANG", "LANGUAGE", "TERM", "USER", "LOGNAME", "SHELL",
         "TZ", "COLUMNS", "LINES", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE")
for _k in list(os.environ):
    if _k not in _KEEP and not _k.startswith("LC_"):
        del os.environ[_k]
os.environ.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
# net=proxy: this process holds an EMPTY network namespace. Bring loopback up
# and run a front that hands every client socket to the back (the parent, in
# the host namespace) over the passed control fd. The agent's tools reach the
# world only through http://127.0.0.1:PORT — a direct connect has no route.
_pfd = int(sys.argv[2]) if len(sys.argv) > 2 else -1
_pport = int(sys.argv[3]) if len(sys.argv) > 3 else 0
if _pfd >= 0:
    def _lo_up():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            cur = struct.unpack("16sh", fcntl.ioctl(s, 0x8913, struct.pack("16sh", b"lo", 0)))[1]
            fcntl.ioctl(s, 0x8914, struct.pack("16sh", b"lo", cur | 0x1))
        finally:
            s.close()
    def _front(ctrlfd, port):
        ctrl = socket.socket(fileno=ctrlfd)
        try: _lo_up()
        except OSError: pass
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port)); srv.listen(64)
        while True:
            try: cl, _ = srv.accept()
            except OSError: break
            try: ctrl.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", cl.fileno()))])
            except OSError: pass
            cl.close()
    threading.Thread(target=_front, args=(_pfd, _pport), daemon=True).start()
    _url = "http://127.0.0.1:%d" % _pport
    os.environ.update(HTTP_PROXY=_url, HTTPS_PROXY=_url, http_proxy=_url,
                      https_proxy=_url, NO_PROXY="", no_proxy="")
sock = socket.socket(fileno=int(sys.argv[1]))
rf = sock.makefile("rb")
wl = threading.Lock()
procs = {}
def send(o):
    with wl:
        sock.sendall((json.dumps(o) + "\n").encode())
def _limits_hook(lim):
    # rlimits in the child, before exec: the process count, the size of any
    # one file, open files, and — when no cgroup surrounds the session — the
    # data segment as a coarse memory line. Inherited by everything below.
    import resource
    def hook():
        MB = 1 << 20
        for key, res in (("pids", resource.RLIMIT_NPROC), ("nofile", resource.RLIMIT_NOFILE)):
            v = int(lim.get(key) or 0)
            if v > 0:
                try: resource.setrlimit(res, (v, v))
                except (ValueError, OSError): pass
        v = int(lim.get("fsize_mb") or 0)
        if v > 0:
            try: resource.setrlimit(resource.RLIMIT_FSIZE, (v * MB, v * MB))
            except (ValueError, OSError): pass
        v = int(lim.get("memory_mb") or 0)
        if v > 0 and lim.get("rlimit_memory"):
            try: resource.setrlimit(resource.RLIMIT_DATA, (v * MB, v * MB))
            except (ValueError, OSError): pass
    return hook
def run(req):
    rid, cmd = req["id"], req["cmd"]
    cwd = req.get("cwd") or None
    kw = {}
    if req.get("capture", True):
        kw = dict(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if req.get("limits"):
        kw["preexec_fn"] = _limits_hook(req["limits"])
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


def _dir_nonempty(path):
    try:
        with os.scandir(path) as it:
            return next(it, None) is not None
    except OSError:
        return False


def _check_rel_cwd(cwd):
    """A working directory for exec is relative to the target and stays in it."""
    if not cwd:
        return ""
    p = os.path.normpath(cwd)
    if os.path.isabs(p) or p == os.pardir or p.startswith(os.pardir + os.sep):
        raise OverlordError(f"error: cwd must be relative to the target: {cwd}")
    return "" if p == os.curdir else p


class LiveSession:
    """An open transaction: holder alive, commands accepted, each one run over
    the current layer stack. A command that wrote something seals its layer:
    the next command starts a new one (a savepoint)."""

    def __init__(self, sid, meta, proc, sock, lock, cleanup, ebpf, trace_inside):
        import queue
        import threading
        self.sid, self.meta, self.proc = sid, meta, proc
        self.sdir = session_path(sid)
        self._sock, self._lock, self._cleanup, self._ebpf = sock, lock, cleanup, ebpf
        self._trace_inside = trace_inside
        self._q = {}
        self._qlock = threading.Lock()
        self._wlock = threading.Lock()
        self._layer_lock = threading.Lock()
        self._active = 0
        self._fuse_layers = 0      # fuse: how many layers the live mount stacks
        self._queue = queue
        self.expired = False
        self.closed = False
        self._proxy = None
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
            raise OverlordError("error: session holder did not start (backend failure?)")

    # -- layers
    @property
    def layers(self):
        return self.meta.setdefault("layers", [{"n": 0, "started": self.meta.get("started")}])

    @property
    def current_layer(self):
        return len(self.layers) - 1

    def _ensure_layer(self):
        """Start a new layer if the top one holds writes. Returns the index the
        next command will write into."""
        layers = self.layers
        top = os.path.join(self.sdir, layer_upper_rel(len(layers) - 1))
        if not _dir_nonempty(top):
            return len(layers) - 1
        if len(layers) >= MAX_LAYERS:
            self.meta["layer_cap_hit"] = True
            return len(layers) - 1
        if self.meta.get("backend") == "fuse" and not _fuse_unmount(
                os.path.join(self.sdir, "merged")):
            # a lingering process pins the mount; keep writing to this layer
            self.meta["layer_reuse"] = self.meta.get("layer_reuse", 0) + 1
            return len(layers) - 1
        n = len(layers)
        for sub in (layer_upper_rel(n), layer_work_rel(n)):
            os.makedirs(os.path.join(self.sdir, sub))
        layers.append({"n": n, "started": _now()})
        return n

    def _wrap(self, cmd, cwd):
        """(argv, cwd) that runs cmd over the current stack on this backend."""
        n = len(self.layers)
        target = self.meta["target"]
        if self.meta.get("backend") == "fuse":
            merged = os.path.join(self.sdir, "merged")
            if not os.path.ismount(merged):
                _fuse_mount(target, self.sdir, n)
                self._fuse_layers = n
            return list(cmd), os.path.join(merged, cwd) if cwd else merged
        jail = bool(self.meta["grants"].get("jail"))
        spec = {"sdir": self.sdir, "target": target, "cmd": list(cmd), "cwd": cwd,
                "jail": jail, "opts": overlay_opts(target, n, kernel=True),
                "net": self.meta["grants"].get("net", "none"),
                # the resolver file the jail is given names from; a test points
                # it at a symlink chain of its own to prove the dangling case
                "resolv": os.environ.get("OVERLORD_RESOLV") or "/etc/resolv.conf",
                "trace_bind": jail and self._trace_inside == "/.overlord"}
        py = sys.executable if (sys.executable or "").startswith("/usr/") else "python3"
        return [py, "-c", _ENTER_SRC, json.dumps(spec)], None

    def rewind(self, to):
        """Drop every layer above savepoint `to` while the session stays open.
        Refused while a command is running (its mount would pin the layers)."""
        with self._layer_lock:
            if self._active:
                raise OverlordError("error: cannot rewind while a command is running")
            if self.meta.get("backend") == "fuse" and not _fuse_unmount(
                    os.path.join(self.sdir, "merged")):
                raise OverlordError("error: cannot rewind: the fuse mount is busy")
            return _rewind_layers(self.sid, self.meta, to)

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
             label=None, cause=None):
        """Run one command inside the transaction. Returns (rc, output_bytes).
        `cause` (an agent's tool call, say) is stamped on the layer the
        command writes into, which is how provenance names its reason."""
        import threading
        if self.closed or self.expired:
            raise OverlordError("error: session is closed" if self.closed else
                             "error: session expired (timeout grant)")
        if getattr(self, "over_disk", False):
            raise OverlordError("error: session exceeded its disk grant; commit or discard it")
        cwd = _check_rel_cwd(cwd)
        rid = uuid.uuid4().hex[:8]
        q = self._queue.Queue()
        with self._qlock:
            self._q[rid] = q
        real_cmd = list(cmd)
        if self._trace_inside:
            real_cmd = ["strace", "-f", "-qq", "-ttt", "-e",
                        "trace=%file,%process,%network", "-o",
                        f"{self._trace_inside}/raw.{rid}.strace"] + real_cmd
        with self._layer_lock:
            layer = self._ensure_layer()
            self._active += 1
            lrec = self.layers[layer]
            lrec.update(exec=rid, label=label, cmd=list(cmd))
            if cause is not None:
                lrec["cause"] = cause
            wrapped, run_cwd = self._wrap(real_cmd, cwd)
        rec = {"id": rid, "cmd": list(cmd), "label": label, "layer": layer,
               "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        self.meta.setdefault("execs", []).append(rec)
        if not self.meta.get("cmd"):
            self.meta["cmd"] = list(cmd)
        save_meta(self.sid, self.meta)
        lim = dict(effective_limits(self.meta.get("grants") or {}))
        if (self.meta.get("cgroup") or {}).get("kind") in (None, "none"):
            lim["rlimit_memory"] = True          # no cgroup: the data segment is the memory line
        self._send({"op": "run", "id": rid, "cmd": wrapped, "capture": capture,
                    "cwd": run_cwd, "limits": lim})
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
            with self._layer_lock:
                self._active -= 1
        if timed_out[0] or (self.expired and rc in (137, TIMEOUT_RC)):
            rc = TIMEOUT_RC
            rec["timed_out"] = True
        # the disk grant: this layer's upper is measured after the command; the
        # session's total is the sum over layers, and a crossing ends the session's
        # ability to run anything else — what was written stays for review
        disk_mb = int(effective_limits(self.meta.get("grants") or {}).get("disk_mb") or 0)
        if disk_mb:
            try:
                lrec["bytes"] = _tree_bytes(os.path.join(self.sdir, layer_upper_rel(layer)))
            except OSError:
                pass
            total = sum(int(lr.get("bytes") or 0) for lr in self.layers)
            self.meta["disk_bytes"] = total
            if total > disk_mb << 20:
                self.over_disk = True
                rec["disk_exceeded"] = True
                note = f"\noverlord: session exceeded its disk grant ({total >> 20} MiB > {disk_mb} MiB)\n"
                out += note.encode()
                if rc == 0:
                    rc = DISK_RC
        rec.update(exit_code=rc, finished=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        save_meta(self.sid, self.meta)
        return rc, bytes(out)

    def changes(self):
        return session_stack(self.sid, self.meta)[0]

    def stack(self):
        """(changes, origin, touched, uppers) of the live stack."""
        return session_stack(self.sid, self.meta)

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
        if self._proxy:
            self._proxy["stop"].set()
            try:
                self._proxy["sock"].close()
            except OSError:
                pass
        if self._cleanup:
            self._cleanup()
        if self._ebpf:
            self._ebpf.terminate()
        _cgroup_release(self.meta.get("cgroup"))
        fcntl.flock(self._lock, fcntl.LOCK_UN)
        self._lock.close()
        changes = _finalize_session(self.sid, self.meta)
        if self.meta.get("agent") and changes:
            # an agent's work is waiting for a person: the act a webhook tells the team about
            _audit("session.needs_review", sid=self.sid, target=self.meta.get("target"),
                   owner=self.meta.get("owner"), agent=self.meta.get("agent"),
                   files=len(changes), task=(self.meta.get("task") or "")[:200])
        return self.sid, changes


def _write_provenance(sid, meta, layers=None):
    """Provenance for the stack (or a subset of its layers): hashes before and
    after, the layer holding each final version, and caused_by — the cause
    stamped on that layer (an agent's tool call) — so every path names its
    reason structurally, which survives rewind. Returns the changes."""
    sdir = session_path(sid)
    changes, origin, _touched, uppers = session_stack(sid, meta, layers)
    idx = layers if layers is not None else list(range(len(uppers)))
    lrecs = meta.get("layers") or []
    with open(os.path.join(sdir, PROVENANCE_FILE), "w") as f:
        for rec in build_provenance(changes, None, meta["target"], origin, uppers):
            if "layer" in rec:
                rec["layer"] = idx[rec["layer"]]     # index into the session's stack
                if rec["layer"] < len(lrecs) and lrecs[rec["layer"]].get("cause"):
                    rec["caused_by"] = lrecs[rec["layer"]]["cause"]
            f.write(json.dumps(rec) + "\n")
    return changes


def _finalize_session(sid, meta):
    """Compute diff + provenance, parse traces, mark pending. Idempotent."""
    sdir = session_path(sid)
    changes = _write_provenance(sid, meta)
    tdir = os.path.join(sdir, "trace")
    if meta.get("trace") == "strace" and os.path.isdir(tdir):
        raws = sorted(p for p in os.listdir(tdir) if p.endswith(".strace"))
        raw = os.path.join(sdir, RAW_TRACE_FILE)
        with open(raw, "wb") as out:
            for p in raws:
                with open(os.path.join(tdir, p), "rb") as f:
                    shutil.copyfileobj(f, out)
        with open(os.path.join(sdir, SYSCALLS_FILE), "w") as f:
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
                 capture=False, agent=None, owner=None):
    """Snapshot the target, mount the overlay, start the holder. Returns LiveSession.
    owner: the account that opened it (accounts on); who may act on it."""
    target = os.path.realpath(target)
    if not os.path.isdir(target):
        raise OverlordError(f"error: target is not a directory: {target}")
    backend = backend or detect_backend()
    if backend is None:
        raise OverlordError(
            "error: no overlay backend available.\n"
            "  kernel: userns capability grants restricted (install packaging/)\n"
            "  fuse:   install fuse-overlayfs (sudo apt install fuse-overlayfs)"
        )
    pending = pending_sessions_for(target)
    if pending and not stack:
        raise OverlordError(
            f"error: {len(pending)} pending session(s) already exist for {target}: "
            f"{', '.join(pending)}\ncommit or roll back first, or pass --stack"
        )
    lock = acquire_target_lock(target, wait)

    sid = new_session_id()
    sdir = session_path(sid)
    for d in ("upper", "work", "merged", "tmp"):
        os.makedirs(os.path.join(sdir, d))
    os.chmod(os.path.join(sdir, "tmp"), 0o1777)

    manifest = snapshot_manifest(target)
    with open(os.path.join(sdir, MANIFEST_FILE), "w") as f:
        json.dump(manifest, f)
    if grants.get("merge_base"):
        subprocess.run(
            ["cp", "-a", "--reflink=auto", target, os.path.join(sdir, "base")],
            check=True,
        )

    if trace == "strace" and not shutil.which("strace"):
        raise OverlordError("error: --trace requires strace (sudo apt install strace)")
    meta = {
        "id": sid, "target": target, "cmd": [], "execs": [], "backend": backend,
        "grants": {k: v for k, v in grants.items() if not k.startswith("_")},
        "trace": trace, "agent": agent, "owner": owner,
        "layers": [{"n": 0, "started": _now()}],
        "started": _now(), "status": "open",
    }
    return _launch_holder(sid, meta, lock, capture, fresh=True)


def reopen_session(sid, wait=False, capture=False):
    """Bring a pending session back to life on its existing layer stack, so
    more commands (or a resumed agent) run on top of it — the mechanism
    behind `resume`. The snapshot manifest is kept: commit still verifies the
    tree against the moment the session began."""
    m = load_meta(sid)
    if m.get("status") != "pending":
        raise OverlordError(f"error: session is {m.get('status')}, not pending")
    sdir = session_path(sid)
    if not os.path.isdir(os.path.join(sdir, "upper")):
        raise OverlordError("error: session layers are gone; nothing to resume")
    target = m["target"]
    if not os.path.isdir(target):
        raise OverlordError(f"error: target is not a directory: {target}")
    if m.get("backend") not in PREPARE or (
            m["backend"] == "kernel" and not _kernel_backend_available()) or (
            m["backend"] == "fuse" and not _fuse_backend_available()):
        raise OverlordError(f"error: backend {m.get('backend')} is not available now")
    lock = acquire_target_lock(target, wait)
    os.makedirs(os.path.join(sdir, "tmp"), exist_ok=True)
    if m.get("backend") == "kernel" and m["grants"].get("jail"):
        os.makedirs(os.path.join(sdir, "jail"), exist_ok=True)
    m.setdefault("layers", [{"n": 0, "started": m.get("started")}])
    m.setdefault("resumed", []).append(_now())
    m["status"] = "open"
    for k in ("finished", "exit_code"):
        m.pop(k, None)
    return _launch_holder(sid, m, lock, capture, fresh=False)


def _systemd_user_ok():
    """Is `systemd-run --user` actually usable here? On WSL2 (and other setups
    without a user D-Bus session) it fails at launch with 'Failed to connect to
    bus: No medium found', which would otherwise stall every session. The probe
    runs a trivial scope AND fails when it cannot reach the bus, so a stale
    yes cannot leak through. OVERLORD_NO_SYSTEMD=1 forces it off."""
    if os.environ.get("OVERLORD_NO_SYSTEMD"):
        return False
    try:
        with open("/proc/sys/kernel/osrelease") as f:
            if "microsoft" in f.read().lower():     # WSL: user bus is unreliable
                return False
    except OSError:
        pass
    if not shutil.which("systemd-run"):
        return False
    try:
        r = subprocess.run(["systemd-run", "--user", "--scope", "-q", "-p", "TasksMax=64", "--", "true"],
                           capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    err = (r.stderr or b"").decode(errors="replace").lower()
    return r.returncode == 0 and "bus" not in err and "failed" not in err


def _cgroup_prefix(limits):
    """systemd-run --user --scope with the limits, when a user manager is
    really there to delegate a cgroup (desktops). Skipped on WSL2 and wherever
    the user bus is missing — sessions then use rlimits (and a direct cgroup if
    delegated) instead of stalling. Probed once."""
    if _cgroup_prefix.cache is not None:
        return list(_cgroup_prefix.cache)
    prefix = ["systemd-run", "--user", "--scope", "-q"] if _systemd_user_ok() else []
    _cgroup_prefix.cache = prefix
    return list(prefix)


_cgroup_prefix.cache = None


def _systemd_props(limits):
    props = []
    if limits.get("memory_mb"):
        props += ["-p", f"MemoryMax={int(limits['memory_mb'])}M"]
    if limits.get("pids"):
        props += ["-p", f"TasksMax={int(limits['pids'])}"]
    if limits.get("cpu_pct"):
        props += ["-p", f"CPUQuota={int(limits['cpu_pct'])}%"]
    return props


def _cgroup_create(sid, limits):
    """Make a cgroup with the limits BEFORE the holder is launched: the child
    joins it in its own pre-exec hook, so every process below it is born
    inside. (Joining after Popen missed the executor that `unshare --fork`
    had already forked.) Tries cgroup v2 directly (root, or a delegated
    tree), then v1 controllers. Returns {"kind", "paths"}; "none" = rlimits only."""
    def w(path, val):
        with open(path, "w") as f:
            f.write(str(val))
    base = "/sys/fs/cgroup"
    if os.path.isfile(os.path.join(base, "cgroup.controllers")):
        for parent in (base, _own_cgroup_dir()):
            if not parent:
                continue
            d = os.path.join(parent, "overlord", sid) if parent == base else os.path.join(parent, f"overlord-{sid}")
            try:
                os.makedirs(os.path.dirname(d), exist_ok=True)
                try:
                    w(os.path.join(os.path.dirname(d), "cgroup.subtree_control"), "+memory +pids +cpu")
                except OSError:
                    pass
                os.makedirs(d, exist_ok=True)
                if limits.get("memory_mb"):
                    w(os.path.join(d, "memory.max"), int(limits["memory_mb"]) << 20)
                if limits.get("pids"):
                    w(os.path.join(d, "pids.max"), int(limits["pids"]))
                if limits.get("cpu_pct"):
                    w(os.path.join(d, "cpu.max"), f"{int(limits['cpu_pct']) * 1000} 100000")
                return {"kind": "v2", "paths": [d]}
            except OSError:
                try:
                    os.rmdir(d)
                except OSError:
                    pass
                continue
        return {"kind": "none", "paths": []}
    paths = []
    for ctl, files in (("memory", {"memory.limit_in_bytes": (int(limits.get("memory_mb") or 0) << 20) or None}),
                       ("pids", {"pids.max": int(limits.get("pids") or 0) or None}),
                       ("cpu", {"cpu.cfs_quota_us": (int(limits.get("cpu_pct") or 0) * 1000) or None,
                                "cpu.cfs_period_us": 100000 if limits.get("cpu_pct") else None})):
        root = os.path.join(base, ctl)
        if not os.path.isdir(root) or not any(v for v in files.values()):
            continue
        d = os.path.join(root, f"overlord-{sid}")
        try:
            os.makedirs(d, exist_ok=True)
            for fn, val in files.items():
                if val is not None:
                    w(os.path.join(d, fn), val)
            paths.append(d)
        except OSError:
            try:
                os.rmdir(d)
            except OSError:
                pass
    return {"kind": "v1" if paths else "none", "paths": paths}


def _cgroup_joiner(info):
    """The child's pre-exec hook: write its own pid into every cgroup made
    for the session, before it forks anything."""
    paths = list((info or {}).get("paths") or [])

    def join():
        pid = str(os.getpid())
        for d in paths:
            try:
                with open(os.path.join(d, "cgroup.procs"), "w") as f:
                    f.write(pid)
            except OSError:
                pass
    return join


def _own_cgroup_dir():
    try:
        with open("/proc/self/cgroup") as f:
            for line in f:
                if line.startswith("0::"):
                    return "/sys/fs/cgroup" + line.strip()[3:]
    except OSError:
        pass
    return None


def _cgroup_release(info):
    for d in reversed((info or {}).get("paths") or []):
        for _ in range(20):
            try:
                os.rmdir(d)
                break
            except OSError:
                time.sleep(0.05)


def limits_backend():
    """For doctor: how a session's limits are enforced on this host."""
    if _cgroup_prefix(DEFAULT_LIMITS):
        return "cgroup v2 via systemd-run --user --scope (+ rlimits)"
    if os.path.isfile("/sys/fs/cgroup/cgroup.controllers"):
        probe = os.path.join("/sys/fs/cgroup", "overlord", "probe")
        try:
            os.makedirs(probe, exist_ok=True)
            os.rmdir(probe)
            return "cgroup v2, direct (+ rlimits)"
        except OSError:
            return "rlimits only (cgroup v2 not delegated; systemd --user unavailable — normal on WSL2)"
    if os.path.isdir("/sys/fs/cgroup/pids"):
        try:
            os.makedirs("/sys/fs/cgroup/pids/overlord-probe", exist_ok=True)
            os.rmdir("/sys/fs/cgroup/pids/overlord-probe")
            return "cgroup v1 (+ rlimits)"
        except OSError:
            pass
    return "rlimits only"


SANDBOX_ENV_KEEP = ("PATH", "HOME", "TMPDIR", "LANG", "LANGUAGE", "TERM", "USER", "LOGNAME",
                    "SHELL", "TZ", "COLUMNS", "LINES", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE")


def sandbox_env():
    """What a sandboxed command may inherit: never the operator's keys,
    tokens or OVERLORD_HOME (red team A11)."""
    env = {k: v for k, v in os.environ.items()
           if k in SANDBOX_ENV_KEEP or k.startswith("LC_")}
    env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    return env


def _tree_bytes(path):
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


def _launch_holder(sid, meta, lock, capture, fresh):
    """Start the holder process for a session record and hand back the live
    handle. On any failure a fresh session vanishes entirely (_abort_launch);
    a reopened one is put back to pending untouched."""
    import socket
    sdir, target, backend = session_path(sid), meta["target"], meta["backend"]
    grants, trace = dict(meta["grants"]), meta.get("trace")
    trace_inside = None
    if trace == "strace":
        os.makedirs(os.path.join(sdir, "trace"), exist_ok=True)
        if grants.get("jail"):
            # red team finding A3: never expose session records to the jail —
            # strace gets an isolated trace/ subdir bound at /.overlord
            trace_inside = "/.overlord"
        else:
            trace_inside = os.path.join(sdir, "trace")

    def abort(parent_sock, cleanup, proc=None):
        if fresh:
            _abort_launch(sid, lock, cleanup, parent_sock, proc)
            return
        if proc is not None:
            try:
                os.killpg(proc.pid, 9)
            except OSError:
                pass
        parent_sock.close()
        if cleanup:
            cleanup()
        meta.pop("holder_pid", None)
        meta["status"] = "pending"
        save_meta(sid, meta)
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()

    try:
        prefix, cleanup = PREPARE[backend](target, sdir, grants)
    except OverlordError:
        if fresh:
            _force_rmtree(sdir)
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()
        raise
    parent_sock, child_sock = socket.socketpair()
    py = sys.executable if (sys.executable or "").startswith("/usr/") else "python3"
    limits = effective_limits(grants)
    want_cg = any(limits.get(k) for k in ("memory_mb", "pids", "cpu_pct"))
    sd = _cgroup_prefix(limits) if want_cg else []
    if sd:
        cg = {"kind": "systemd", "paths": []}
    elif want_cg:
        cg = _cgroup_create(sid, limits)
    else:
        cg = {"kind": "none", "paths": []}
    proxy_parent = proxy_child = None
    proxy_fd, proxy_port = -1, 0
    if grants.get("net") == "proxy":
        import netproxy as _np
        proxy_parent, proxy_child = socket.socketpair()
        proxy_fd, proxy_port = proxy_child.fileno(), _np.PROXY_PORT
    argv = (sd + _systemd_props(limits) + ["--"] if sd else []) + prefix + \
        [py, "-c", _EXECUTOR_SRC, str(child_sock.fileno()), str(proxy_fd), str(proxy_port)]
    # red team A11: the environment is cut BEFORE the process exists. Unsetting
    # variables inside it is cosmetic — /proc/<pid>/environ reads the original
    # block, so a jailed `cat /proc/1/environ` would still show the keys.
    pass_fds = (child_sock.fileno(),) + ((proxy_child.fileno(),) if proxy_child else ())
    popen_kw = {"pass_fds": pass_fds, "env": sandbox_env()}
    if cg.get("paths"):
        popen_kw["preexec_fn"] = _cgroup_joiner(cg)
    if capture:
        outfile = open(os.path.join(sdir, "output.log"), "ab")
        popen_kw.update(stdout=outfile, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    try:
        proc = subprocess.Popen(argv, start_new_session=True, **popen_kw)
    except OSError:
        abort(parent_sock, cleanup)
        raise
    finally:
        child_sock.close()
        if proxy_child:
            proxy_child.close()
        if capture:
            outfile.close()
    meta["holder_pid"] = proc.pid
    meta["limits"] = limits
    meta["cgroup"] = cg
    save_meta(sid, meta)
    proxy = None
    if grants.get("net") == "proxy":
        import netproxy as _np
        import threading as _threading
        allow = _np.Allow(grants.get("net_allow"))
        rec = _np.Recorder(path=os.path.join(sdir, "egress.jsonl"))
        stop = _threading.Event()
        back = _threading.Thread(target=_np.run_backend, args=(proxy_parent, allow, rec, stop), daemon=True)
        back.start()
        proxy = {"sock": proxy_parent, "stop": stop, "thread": back, "rec": rec, "allow": allow}
    ebpf = None
    if trace == "ebpf":
        try:
            ebpf = start_ebpf(proc.pid, sdir)
        except Exception:
            # the workload is already live and the recorder is not
            abort(parent_sock, cleanup, proc)
            raise
    try:
        live = LiveSession(sid, meta, proc, parent_sock, lock, cleanup, ebpf, trace_inside)
        live._proxy = proxy
    except OverlordError:
        if proxy:
            proxy["stop"].set()
            proxy["sock"].close()
        abort(parent_sock, cleanup, proc)
        raise
    _audit("session.open" if fresh else "session.reopen", sid=sid, target=target,
           owner=meta.get("owner"), backend=backend, agent=meta.get("agent"),
           jail=bool(grants.get("jail")), net=grants.get("net"),
           net_allow=grants.get("net_allow") or None,
           connectors=grants.get("connectors") or None)
    return live


def _audit(action, **fields):
    """The machine-wide record (audit.py); never allowed to fail the work."""
    try:
        import audit as audit_mod
        audit_mod.record(action, **fields)
    except Exception as e:      # noqa: BLE001 — a broken audit path is reported, not fatal
        print(f"audit: {e}", file=sys.stderr)


# ---------------------------------------------------------------- savepoints


def _rewind_layers(sid, meta, to):
    """Drop layers above `to` on disk and in meta; cut an agent transcript to
    match. The dropped tail is archived (meta['rewinds'], transcript.rewound.N)
    because a rewind is itself an act with provenance. Returns meta."""
    layers = meta.get("layers") or [{"n": 0}]
    if not isinstance(to, int) or not 0 <= to < len(layers):
        raise OverlordError(f"error: no savepoint {to} (session has 0..{len(layers) - 1})")
    if to == len(layers) - 1:
        return meta
    sdir = session_path(sid)
    execs = meta.get("execs") or []
    archived = {"at": _now(), "to": to, "layers": layers[to + 1:],
                "execs": [e for e in execs if e.get("layer", 0) > to]}
    for i in range(to + 1, len(layers)):
        _force_rmtree(os.path.join(sdir, LAYERS_DIR, str(i)))
    meta["layers"] = layers[:to + 1]
    meta["execs"] = [e for e in execs if e.get("layer", 0) <= to]
    rewinds = meta.setdefault("rewinds", [])
    tpath = os.path.join(sdir, "transcript.jsonl")
    if os.path.isfile(tpath):
        with open(tpath) as f:
            events = [json.loads(line) for line in f if line.strip()]
        cut = 0
        for i, ev in enumerate(events):
            if ev.get("type") == "tool_result" and ev.get("layer", 0) <= to:
                cut = i + 1
            elif ev.get("type") in ("task", "rewind", "resume"):
                cut = max(cut, i + 1)
        tail = events[cut:]
        n = len(rewinds) + 1
        with open(os.path.join(sdir, f"transcript.rewound.{n}.jsonl"), "w") as f:
            for ev in tail:
                f.write(json.dumps(ev) + "\n")
        with open(tpath, "w") as f:
            for ev in events[:cut]:
                f.write(json.dumps(ev) + "\n")
            f.write(json.dumps({"ts": _now(), "type": "rewind", "to": to,
                                "dropped_events": len(tail)}) + "\n")
        archived["transcript_events"] = len(tail)
    rewinds.append(archived)
    save_meta(sid, meta)
    return meta


def rewind_session(sid, to):
    """Rewind a pending session to savepoint `to` and re-derive its
    provenance. Returns the remaining changes."""
    m = load_meta(sid)
    if m.get("status") != "pending":
        raise OverlordError(f"error: session is {m.get('status')}, not pending"
                            + (" (rewind it through the daemon that holds it)"
                               if m.get("status") == "open" else ""))
    _rewind_layers(sid, m, to)
    _audit("session.rewind", sid=sid, owner=m.get("owner"), to=to)
    return _write_provenance(sid, m)


def _copy_tree(src, dst):
    """cp -a --reflink=auto: keeps whiteouts (0:0 char devices; unprivileged
    since Linux 5.8) and the overlay xattrs a layer depends on."""
    r = subprocess.run(["cp", "-a", "--reflink=auto", src, dst], capture_output=True, text=True)
    if r.returncode != 0:
        raise OverlordError(f"error: could not copy {src}: {r.stderr.strip()}")


def fork_session(sid, at=None):
    """Copy a pending session's stack up to savepoint `at` (default: the top)
    into a new pending session on the same target and snapshot, transcript
    cut to match. Two continuations of one moment can then be compared
    (compare_sessions) before either is committed; committing one makes the
    other's snapshot stale, which conflict detection reports as usual.
    Returns the new session id."""
    m = load_meta(sid)
    if m.get("status") != "pending":
        raise OverlordError(f"error: session is {m.get('status')}, not pending")
    src = session_path(sid)
    if not os.path.isdir(os.path.join(src, "upper")):
        raise OverlordError("error: session layers are gone; nothing to fork")
    layers = m.get("layers") or [{"n": 0}]
    at = len(layers) - 1 if at is None else at
    if not isinstance(at, int) or not 0 <= at < len(layers):
        raise OverlordError(f"error: no savepoint {at} (session has 0..{len(layers) - 1})")
    new = new_session_id()
    while os.path.exists(session_path(new)):
        new = new_session_id()
    dst = session_path(new)
    os.makedirs(dst)
    try:
        for name in ("upper", "work", "base", "tmp", MANIFEST_FILE, "transcript.jsonl"):
            p = os.path.join(src, name)
            if os.path.lexists(p):
                _copy_tree(p, os.path.join(dst, name))
        if at > 0:
            os.makedirs(os.path.join(dst, LAYERS_DIR))
            for i in range(1, at + 1):
                _copy_tree(os.path.join(src, LAYERS_DIR, str(i)),
                           os.path.join(dst, LAYERS_DIR, str(i)))
        os.makedirs(os.path.join(dst, "merged"), exist_ok=True)
        fm = json.loads(json.dumps(m))
        fm.update(id=new, status="pending", started=_now(), trace=None,
                  forked_from={"session": sid, "at": at, "ts": _now()},
                  layers=json.loads(json.dumps(layers)))
        for k in ("holder_pid", "reviews", "rewinds", "resumed", "exit_code", "finished",
                  "timed_out", "layer_cap_hit", "layer_reuse", "forks"):
            fm.pop(k, None)
        fm["execs"] = [e for e in (m.get("execs") or []) if e.get("layer", 0) <= at]
        save_meta(new, fm)
        if at < len(layers) - 1:
            # same cut as a rewind, applied to the copy: layers above `at`
            # were never copied, so only the record and transcript need it
            _rewind_layers(new, fm, at)
            fm.pop("rewinds", None)
            save_meta(new, fm)
        _write_provenance(new, fm)
    except BaseException:
        _force_rmtree(dst)
        raise
    m.setdefault("forks", []).append({"session": new, "at": at, "ts": _now()})
    save_meta(sid, m)
    _audit("session.fork", sid=sid, owner=m.get("owner"), new=new, at=at)
    return new


def compare_sessions(a, b):
    """Where two stacks over the same target diverge: per path, 'same',
    'differ', 'only-a' or 'only-b', by kind and after-hash."""
    ma, mb = load_meta(a), load_meta(b)
    if ma.get("target") != mb.get("target"):
        raise OverlordError("error: sessions have different targets")

    def view(sid, m):
        changes, origin, _t, uppers = session_stack(sid, m)
        if not uppers:
            raise OverlordError(f"error: session {sid} is {m.get('status')}; layers discarded")
        recs = build_provenance(changes, None, m["target"], origin, uppers)
        return {r["path"]: (r["kind"], r.get("after_sha256")) for r in recs}
    va, vb = view(a, ma), view(b, mb)
    rows = []
    for rel in sorted(set(va) | set(vb)):
        if rel in va and rel in vb:
            rows.append({"path": rel, "state": "same" if va[rel] == vb[rel] else "differ",
                         "a": va[rel][0], "b": vb[rel][0]})
        elif rel in va:
            rows.append({"path": rel, "state": "only-a", "a": va[rel][0], "b": None})
        else:
            rows.append({"path": rel, "state": "only-b", "a": None, "b": vb[rel][0]})
    return rows


def session_savepoints(sid, meta=None):
    """One entry per layer: what ran, what it was for, what it changed."""
    meta = meta or load_meta(sid)
    sdir = session_path(sid)
    out = []
    for i, lrec in enumerate(meta.get("layers") or [{"n": 0}]):
        upper = os.path.join(sdir, layer_upper_rel(i))
        entries = (compute_diff(upper, meta["target"], meta.get("backend"))
                   if os.path.isdir(upper) else [])
        out.append({"n": i, "started": lrec.get("started"), "label": lrec.get("label"),
                    "cmd": lrec.get("cmd"), "cause": lrec.get("cause"),
                    "paths": [list(c) for c in entries]})
    return out


_SEL_RE = re.compile(r"^(layer|turn|tool|call)?:?(.+)$")


def select_layers(meta, only=None, drop=None):
    """Resolve --only / --drop selectors to ascending layer indices.

    Selectors, comma-separated: layer:N, layer:A-B, turn:N, turn:A-B,
    tool:NAME, call:TOOL_CALL_ID; a bare N or A-B means layer. turn/tool/call
    match the cause stamped on a layer (an agent's tool call)."""
    layers = meta.get("layers") or [{"n": 0}]
    n = len(layers)

    def parse_range(text, what):
        try:
            if "-" in text:
                a, b = text.split("-", 1)
                return int(a), int(b)
            return int(text), int(text)
        except ValueError:
            raise OverlordError(f"error: bad {what} selector: {text}")

    def matches(sel):
        m = _SEL_RE.match(sel.strip())
        kind, arg = (m.group(1) or "layer"), m.group(2)
        if sel.strip() and ":" not in sel:
            kind, arg = "layer", sel.strip()
        hits = set()
        if kind == "layer":
            a, b = parse_range(arg, "layer")
            hits = {i for i in range(n) if a <= i <= b}
        elif kind == "turn":
            a, b = parse_range(arg, "turn")
            hits = {i for i, l in enumerate(layers)
                    if (l.get("cause") or {}).get("turn") is not None
                    and a <= l["cause"]["turn"] <= b}
        elif kind == "tool":
            hits = {i for i, l in enumerate(layers) if (l.get("cause") or {}).get("tool") == arg}
        elif kind == "call":
            hits = {i for i, l in enumerate(layers)
                    if (l.get("cause") or {}).get("tool_call_id") == arg}
        if not hits:
            raise OverlordError(f"error: selector matches no layer: {sel.strip()}")
        return hits

    def expand(spec):
        out = set()
        for part in (spec or "").split(","):
            if part.strip():
                out |= matches(part)
        return out

    selected = expand(only) if only else set(range(n))
    selected -= expand(drop) if drop else set()
    if not selected:
        raise OverlordError("error: selection leaves no layer to commit")
    return sorted(selected)


def _abort_launch(sid, lock, cleanup, parent_sock, proc=None):
    """A launch that fails after the session record exists must leave nothing:
    not a running holder (a daemon would keep it alive, unrecorded, after the
    caller was told the session failed), not an `open` orphan that blocks the
    target for every later run, and not the target lock (held by the daemon
    process until it dies). The session never happened."""
    if proc is not None:
        try:
            os.killpg(proc.pid, 9)
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    parent_sock.close()
    if cleanup:
        cleanup()
    _force_rmtree(session_path(sid))
    fcntl.flock(lock, fcntl.LOCK_UN)
    lock.close()


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


def _session_row(sid, m):
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
    if m.get("forked_from"):
        what = f"fork of {m['forked_from']['session']}@{m['forked_from']['at']} — {what}"
    rev = (m.get("reviews") or [None])[-1]
    if rev:
        verdict = {"approve": "approved", "reject": "rejected"}.get(rev.get("verdict"), "no-verdict")
        tags += f" [{verdict}]"
    return (f"{sid}  {m.get('status', '?'):9s} exit={m.get('exit_code', '-')}{tags}  "
            f"{m.get('target', '')}  :: {what}")


def cmd_sessions(args):
    rows = list_sessions()
    if not rows:
        print("no sessions")
        return 0
    for sid in rows:
        print(_session_row(sid, load_meta(sid)))
    return 0


def cmd_diff(args):
    m = load_meta(args.session)
    upper = session_file(args.session, "upper")
    if not os.path.isdir(upper):
        raise OverlordError(f"error: session is {m.get('status')}; layers discarded")
    changes, origin, _t, _u = session_stack(args.session, m)
    for kind, rel in changes:
        tag = f"  @{origin[rel]}" if len(m.get("layers") or ()) > 1 else ""
        print(f"{kind:12s} {rel}{tag}")
    if not changes:
        print("no changes")
    return 0


def _describe_cause(cause):
    return (f"turn {cause.get('turn')} {cause.get('tool')}({cause.get('summary', '')}) "
            f"[{cause.get('tool_call_id')}]")


def cmd_log(args):
    load_meta(args.session)
    prov = session_file(args.session, PROVENANCE_FILE)
    if not os.path.isfile(prov):
        print("no provenance recorded")
        return 0
    with open(prov) as f:
        for line in f:
            rec = json.loads(line)
            before = (rec.get("before_sha256") or "-")[:12]
            after = (rec.get("after_sha256") or "-")[:12]
            layer = f"  @{rec['layer']}" if "layer" in rec else ""
            print(f"{rec['kind']:12s} {rec['path']:40s} {before} -> {after}{layer}")
            cause = rec.get("caused_by")
            if cause:
                print(f"{'':12s}   caused_by: {_describe_cause(cause)}")
    for name, label in ((SYSCALLS_FILE, "syscall trace"), ("ebpf.log", "ebpf trace")):
        p = session_file(args.session, name)
        if os.path.isfile(p):
            with open(p, errors="replace") as f:
                n = sum(1 for _ in f)
            print(f"\n{label}: {n} events in {p}")
    return 0


def commit_session(sid, merge=False, force=False, only=None, drop=None,
                   countersigned=False):
    """Core commit. Returns a result dict; never prints.

    only/drop select layers (see select_layers): the replay applies just
    those, in order, so a decision — a tool call, a turn — can be undone
    while everything after it that stands on its own is kept. Conflict
    detection covers every path the selected layers would touch on replay,
    not only the net diff. Content before and after is retained for blame."""
    m = load_meta(sid)
    if m.get("status") != "pending":
        raise OverlordError(f"error: session is {m.get('status')}, not pending")
    sdir = session_path(sid)
    with open(os.path.join(sdir, MANIFEST_FILE)) as f:
        manifest = json.load(f)
    all_layers = list(range(len(m.get("layers") or [{"n": 0}])))
    selected = select_layers(m, only, drop) if (only or drop) else all_layers
    changes, origin, touched, uppers = session_stack(sid, m, selected)
    # countersignature: a verdict binds to a fingerprint of exactly what would
    # be replayed; a fresh rejection stands unless forced, and --countersigned
    # (or policy) demands a fresh approval
    import review as review_mod
    rev, fresh = review_mod.review_state(sid, m, selected if (only or drop) else None)
    # protected paths: a policy list, or the harness's own modules when the
    # target is OVERLORD's source. Touching one needs a fresh, complete
    # countersignature and can never be forced past a rejection or conflict.
    protected = protected_hits(m["target"], changes)
    if protected:
        if force:
            raise OverlordError("error: --force is refused: the diff touches protected paths: "
                                + ", ".join(protected[:8]))
        countersigned = True
    # content gate: findings whose action is "countersign" demand a fresh
    # approval (handled just below); "block" findings refuse the commit like a
    # conflict (force overrides); "warn" findings only ride the audit record.
    policy_findings = policy_gate(m["target"], changes, origin, uppers)
    if any(f["action"] == "countersign" for f in policy_findings):
        countersigned = True
    policy_block = [f for f in policy_findings if f["action"] == "block"]
    if countersigned and not (rev and fresh and rev.get("verdict") == "approve"
                              and not rev.get("truncated")):
        why = ("no review recorded" if rev is None else
               "the last review is stale — the diff changed since it was signed" if not fresh
               else "the reviewer did not see the whole diff (dossier truncated) — fail closed"
               if rev.get("verdict") == "approve" and rev.get("truncated")
               else f"the last review {rev.get('verdict')}ed")
        raise OverlordError(f"error: commit needs a fresh countersignature ({why}): "
                            f"overlord review {sid}" + (f" — protected: {', '.join(protected[:5])}"
                                                        if protected else ""))
    if rev and fresh and rev.get("verdict") == "reject" and not force:
        _audit("session.commit_refused", sid=sid, owner=m.get("owner"), target=m["target"],
               why="rejected by review", reviewer=rev.get("reviewer"))
        return {"committed": False, "conflicts": [], "merged": [], "target": m["target"],
                "layers": selected, "rejected": rev}
    bad = [rel for kind, rel in changes if kind == "invalid-whiteout"]
    if bad:  # would _remove_target(<tree root>); no --force for this one
        raise OverlordError("error: refusing to commit — whiteout entry names its own "
                            f"tree root: {', '.join(bad)} (roll the session back)")
    if policy_block and not force:
        import policycheck
        _audit("session.commit_refused", sid=sid, owner=m.get("owner"), target=m["target"],
               why="policy", findings=policycheck.summarize(policy_findings))
        return {"committed": False, "conflicts": [], "merged": [],
                "target": m["target"], "layers": selected, "policy": policy_findings}
    conflicts = list(dict.fromkeys(find_conflicts(touched, manifest, m["target"])))
    merged = []
    if conflicts and merge:
        merged, conflicts = try_merge(
            conflicts, sdir, m["target"],
            locate=lambda rel: _safe_join(uppers[origin[rel]], rel) if rel in origin
            else _safe_join(uppers[-1], rel))
    if conflicts and not force:
        _audit("session.commit_refused", sid=sid, owner=m.get("owner"), target=m["target"],
               why="conflicts", conflicts=len(conflicts))
        return {"committed": False, "conflicts": conflicts, "merged": merged,
                "target": m["target"], "layers": selected}
    # provenance is derived while the tree still holds the "before" state
    _write_provenance(sid, m, selected)
    # retain content for blame: the tree's version before replay, then the
    # session's version after it (both content-addressed, so nothing repeats)
    retained = {}
    # a deleted DIRECTORY is one whiteout in the layer, but reversibility needs
    # what was beneath it: retain every regular file under it and record each,
    # so blame can answer for them and revert can rebuild the directory
    expanded = {}
    for kind, rel in changes:
        if kind in ("modified", "deleted"):
            tpath = _safe_join(m["target"], rel)
            if kind == "deleted" and os.path.isdir(tpath) and not os.path.islink(tpath):
                subs = []
                for root, _dirs, files in os.walk(tpath):
                    for name in files:
                        fp = os.path.join(root, name)
                        sha = store_object(fp)
                        if sha:
                            subs.append((os.path.relpath(fp, m["target"]), sha))
                expanded[rel] = subs
                continue
            if store_object(tpath):
                retained.setdefault(rel, set()).add("before")
    apply_layers(uppers, m["target"], m.get("backend"))
    for kind, rel in changes:
        if kind in ("added", "modified") and not rel.endswith("/"):
            if store_object(_safe_join(m["target"], rel)):
                retained.setdefault(rel, set()).add("after")
    dropped = [i for i in all_layers if i not in selected]
    m.update(status="committed", committed=_now(), committed_ns=time.time_ns(),
             forced=bool(conflicts), merged_paths=merged,
             layers_applied=selected, layers_dropped=dropped,
             countersigned=bool(rev and fresh and rev.get("verdict") == "approve"),
             overrode_rejection=bool(rev and fresh and rev.get("verdict") == "reject"))
    save_meta(sid, m)
    with open(os.path.join(sdir, PROVENANCE_FILE)) as f:
        records = [json.loads(line) for line in f]
    with open(os.path.join(sdir, PROVENANCE_FILE), "w") as f:
        for rec in records:
            for side in retained.get(rec["path"], ()):
                rec[f"{side}_retained"] = True
            subs = expanded.get(rec["path"]) if rec.get("kind") == "deleted" else None
            if subs is not None:
                rec["expanded"] = len(subs)      # the records that follow are its files
            f.write(json.dumps(rec) + "\n")
            for sub_rel, sha in subs or ():
                f.write(json.dumps({**{k: rec[k] for k in ("ts", "layer", "caused_by") if k in rec},
                                    "kind": "deleted", "path": sub_rel, "under": rec["path"],
                                    "before_sha256": sha, "before_retained": True}) + "\n")
    for sub in ("upper", "work", "merged", "base", "jail", "trace", "tmp", LAYERS_DIR,
                MANIFEST_FILE, RAW_TRACE_FILE):
        try:
            _force_rmtree(os.path.join(sdir, sub))
        except OSError:
            pass
    if m.get("agent"):
        # the folder's journal: what was done here, from the record, for the
        # next conversation's memory
        import memory as memory_mod
        try:
            memory_mod.journal_record(m)
        except OSError:
            pass
    import policycheck
    _audit("session.commit", sid=sid, owner=m.get("owner"), target=m["target"],
           files=len(changes), forced=bool(conflicts), merged=len(merged) or None,
           only=only, drop=drop, countersigned=m.get("countersigned") or None,
           overrode_rejection=m.get("overrode_rejection") or None,
           policy=policycheck.summarize(policy_findings) or None,
           policy_forced=bool(policy_block and force) or None, usage=m.get("usage"))
    return {"committed": True, "applied": len(changes), "merged": merged,
            "target": m["target"], "layers": selected, "dropped": dropped,
            "policy": policy_findings}


HARNESS_FILES = ("overlord.py", "agent.py", "providers.py", "review.py", "mcp.py", "memory.py",
                 "auth.py", "vault.py", "oidc.py", "notify.py", "cost.py", "audit.py", "bundle.py",
                 "skills.py", "retention.py", "ui.py", "chatui.py", "packaging/*", "Dockerfile")


def protected_patterns(target):
    """The policy rule's "protect" globs; with no rule, the harness's own
    modules when the folder is OVERLORD's source."""
    pol = load_policy()
    rule = _policy_rule(pol, os.path.realpath(target)) if pol else None
    if rule is not None and "protect" in rule:
        return [str(p) for p in (rule.get("protect") or [])]
    if os.path.isfile(os.path.join(target, "overlord.py")):
        return list(HARNESS_FILES)
    return []


def protected_hits(target, changes):
    import fnmatch
    pats = protected_patterns(target)
    if not pats:
        return []
    return [rel for _k, rel in changes
            if any(fnmatch.fnmatch(rel.rstrip("/"), p) or fnmatch.fnmatch(rel, p + "/*") for p in pats)]


def policy_gate(target, changes, origin, uppers):
    """Content checks for the pending diff, per the target's policy rule:
    secrets, compiled binaries, dependency-manifest changes, oversized diffs.
    Returns a list of findings (each {check, path, detail, action}), empty when
    the rule declares no `checks`. The findings' actions — block / countersign
    / warn — are applied by commit_session, not here."""
    pol = load_policy()
    rule = _policy_rule(pol, os.path.realpath(target)) if pol else None
    checks = rule.get("checks") if isinstance(rule, dict) else None
    if not checks:
        return []
    import policycheck

    def locate(rel):
        try:
            i = origin[rel] if rel in origin else -1
            return _safe_join(uppers[i], rel)
        except Exception:            # noqa: BLE001 — an unreadable path just isn't scanned
            return None

    return policycheck.evaluate(changes, locate, checks)


def rollback_session(sid):
    """Core rollback. Returns the untouched target path."""
    m = load_meta(sid)
    if m.get("status") == "committed":
        raise OverlordError("error: session already committed; nothing to roll back")
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
    _audit("session.rollback", sid=sid, owner=m.get("owner"), target=m["target"],
           was=m.get("status"), usage=m.get("usage"))
    return m["target"]


# ---------------------------------------------------------------- revert
#
# rollback discards a PENDING session: the tree was never touched. revert is
# the other half of reversibility — undoing a COMMITTED session's file changes
# — and it is itself a transaction: the inverse is replayed into a fresh
# session from the provenance record and the retained before-content, so the
# operator reviews a diff and commits it like any other. Nothing here reaches
# the tree directly.

_REVERT_SCRIPT = r'''
import json, os, shutil, sys
ops, objs = json.loads(sys.argv[1]), sys.argv[2]
bad, dirs = [], []
for op in ops:
    kind, rel = op[0], op[1]
    if kind == "rm":
        try:
            os.remove(rel)
        except FileNotFoundError:
            pass
        except OSError:
            bad.append(rel)
    elif kind == "rmdir":
        dirs.append(rel)
    elif kind == "mkdir":
        os.makedirs(rel, exist_ok=True)
    elif kind == "restore":
        if os.path.islink(rel) or os.path.isdir(rel):
            bad.append(rel)
            continue
        d = os.path.dirname(rel)
        if d:
            os.makedirs(d, exist_ok=True)
        try:
            shutil.copyfile(os.path.join(objs, op[2]), rel)
        except OSError:
            bad.append(rel)
for d in sorted(dirs, key=len, reverse=True):
    try:
        os.rmdir(d)
    except OSError:
        pass
print("REVERT-RESULT " + json.dumps(bad))
'''


def revert_plan(sid, meta=None):
    """The inverse of a committed session, read from its provenance:
    (ops, unrecoverable). ops are ("rm", rel) for an added file, ("rmdir", rel)
    for an added directory, ("restore", rel, sha256) for a modified or deleted
    file whose before-content was retained. unrecoverable lists (rel, why)."""
    m = meta or load_meta(sid)
    prov = session_file(sid, PROVENANCE_FILE)
    if not os.path.isfile(prov):
        raise OverlordError(f"error: session {sid} has no provenance record to invert")
    with open(prov) as f:
        records = [json.loads(line) for line in f if line.strip()]
    ops, bad = [], []
    for rec in records:
        rel, kind = rec.get("path", ""), rec.get("kind")
        clean = rel.rstrip("/")
        if not clean or os.path.isabs(clean) or ".." in clean.split("/"):
            bad.append((rel, "unsafe path"))
            continue
        if kind == "added":
            ops.append(("rmdir", clean) if rel.endswith("/") else ("rm", clean))
        elif kind == "deleted" and "expanded" in rec:
            # a deleted directory: its files follow as their own records and
            # restore it; an empty one is simply recreated
            if rec["expanded"] == 0:
                ops.append(("mkdir", clean))
        elif kind in ("modified", "deleted"):
            sha = rec.get("before_sha256")
            if not (sha and rec.get("before_retained")
                    and os.path.isfile(os.path.join(OBJECTS_DIR, sha))):
                bad.append((rel, "before-content not retained"))
                continue
            ops.append(("restore", clean, sha))
        else:
            bad.append((rel, f"cannot invert {kind}"))
    return ops, bad


def revert_session(sid, backend=None, force=False, stack=False, commit=False, wait=False):
    """Stage the inverse of committed session `sid` as a new pending session
    over the same target and return {sid, reverted, changes, skipped, failed,
    committed}. With commit=True the revert is committed at once. A path with
    no retained before-content refuses the whole revert unless force=True,
    which skips it (listed under `skipped`). File modes are not restored —
    provenance records content, not metadata."""
    m = load_meta(sid)
    if m.get("status") != "committed":
        raise OverlordError(f"error: session {sid} is {m.get('status')}, not committed — "
                            "revert undoes a committed session; rollback discards a pending one")
    ops, bad = revert_plan(sid, m)
    if bad and not force:
        raise OverlordError("error: revert cannot restore every path (--force skips them):\n"
                            + "\n".join(f"  {r}: {why}" for r, why in bad[:20]))
    if not ops:
        raise OverlordError(f"error: nothing to revert in {sid}")
    # no jail: the command must read the objects store; no network, ever
    grants = {"net": "none", "jail": False, "timeout": None, "merge_base": False}
    live = open_session(m["target"], backend or m.get("backend"), grants, wait=wait,
                        stack=stack, capture=True, owner=m.get("owner"))
    try:
        rc, out = live.exec(["python3", "-c", _REVERT_SCRIPT, json.dumps(ops), OBJECTS_DIR],
                            label=f"revert {sid}", cause={"revert_of": sid})
    finally:
        new_sid, changes = live.close()
    failed = []
    for line in out.decode(errors="replace").splitlines():
        if line.startswith("REVERT-RESULT "):
            failed = json.loads(line[len("REVERT-RESULT "):])
    if rc != 0:
        rollback_session(new_sid)
        raise OverlordError(f"error: revert command failed (exit {rc}): {out[-300:]!r}")
    nm = load_meta(new_sid)
    nm["revert_of"] = sid
    save_meta(new_sid, nm)
    _audit("session.revert", sid=new_sid, of=sid, owner=m.get("owner"), target=m["target"],
           files=len(changes), skipped=len(bad) or None, failed=failed or None)
    res = {"sid": new_sid, "reverted": sid, "changes": changes, "skipped": bad,
           "failed": failed, "committed": False}
    if commit:
        cres = commit_session(new_sid)
        res["committed"] = bool(cres.get("committed"))
        res["commit"] = cres
    return res


def cmd_commit(args):
    res = commit_session(args.session, merge=args.merge, force=args.force,
                         only=args.only, drop=args.drop, countersigned=args.countersigned)
    if not res["committed"] and res.get("rejected"):
        r = res["rejected"]
        print(f"error: refusing to commit — rejected by {r.get('reviewer')}: {r.get('reason')}",
              file=sys.stderr)
        print(f"override with: overlord commit --force {args.session}", file=sys.stderr)
        return 1
    if not res["committed"] and res.get("policy") is not None and not res.get("conflicts"):
        import policycheck
        print("error: policy gate blocked the commit:", file=sys.stderr)
        for line in policycheck.summarize(res["policy"]):
            print(f"  {line}", file=sys.stderr)
        print(f"inspect the diff, then roll back: overlord rollback {args.session}", file=sys.stderr)
        print(f"or override (audited): overlord commit --force {args.session}", file=sys.stderr)
        return 1
    if not res["committed"]:
        print("error: target drifted since snapshot — refusing to commit:", file=sys.stderr)
        for reason, rel in res["conflicts"]:
            print(f"  {reason:22s} {rel}", file=sys.stderr)
        hint = "--merge (needs --merge-base session) or --force" if not args.merge else "--force"
        print(f"override with: overlord commit {hint} {args.session}", file=sys.stderr)
        return 1
    warns = [f for f in (res.get("policy") or []) if f["action"] == "warn"]
    if warns:
        import policycheck
        print("policy warnings (committed anyway):", file=sys.stderr)
        for line in policycheck.summarize(warns):
            print(f"  {line}", file=sys.stderr)
    msg = f"committed {res['applied']} changes to {res['target']}"
    if res["merged"]:
        msg += f" ({len(res['merged'])} three-way merged)"
    if res.get("dropped"):
        msg += (f" — layers {', '.join(map(str, res['layers']))} applied, "
                f"{', '.join(map(str, res['dropped']))} dropped")
    m = load_meta(args.session)
    if m.get("countersigned"):
        msg += " (countersigned)"
    elif m.get("overrode_rejection"):
        msg += " (forced past a rejection)"
    print(msg)
    return 0


def cmd_rollback(args):
    target = rollback_session(args.session)
    print(f"rolled back {args.session} — target untouched: {target}")
    return 0


def cmd_revert(args):
    res = revert_session(args.session, force=args.force, stack=args.stack, commit=args.commit)
    print(f"revert of {args.session} staged as session {res['sid']}: "
          f"{len(res['changes'])} change(s)")
    for kind, rel in res["changes"][:20]:
        print(f"  {kind:12s} {rel}")
    if len(res["changes"]) > 20:
        print(f"  ... {len(res['changes']) - 20} more (overlord diff {res['sid']})")
    if res["skipped"]:
        print(f"  skipped {len(res['skipped'])} path(s) with no retained before-content")
    if res["failed"]:
        print(f"  failed inside the session: {', '.join(res['failed'][:10])}", file=sys.stderr)
    if args.commit:
        print("committed" if res["committed"] else
              f"NOT committed — resolve with: overlord commit {res['sid']}")
    else:
        print(f"\n  inspect:  overlord diff {res['sid']}\n  commit:   overlord commit {res['sid']}"
              f"\n  discard:  overlord rollback {res['sid']}")
    return 1 if res["failed"] else 0


def cmd_check(args):
    """Dry-run the pre-commit policy gate against a pending session: report
    what would block, require countersignature, or warn — without committing."""
    import policycheck
    m = load_meta(args.session)
    if m.get("status") != "pending":
        print(f"error: session is {m.get('status')}, not pending", file=sys.stderr)
        return 2
    changes, origin, touched, uppers = session_stack(args.session, m)
    findings = policy_gate(m["target"], changes, origin, uppers)
    if not findings:
        pol = load_policy()
        rule = _policy_rule(pol, os.path.realpath(m["target"])) if pol else None
        active = isinstance(rule, dict) and rule.get("checks")
        print("no policy findings" + ("" if active else " (no checks configured for this target)"))
        return 0
    for line in policycheck.summarize(findings):
        print(f"  {line}")
    top = policycheck.worst(findings)
    verdict = {"block": "commit would be BLOCKED (override: --force)",
               "countersign": "commit would REQUIRE a fresh countersignature",
               "warn": "commit would be allowed with warnings"}.get(top, "")
    print(verdict)
    return 1 if top == "block" else 0


def _savepoint_line(sp):
    what = ""
    if sp.get("cause"):
        c = sp["cause"]
        what = f"turn {c.get('turn')} {c.get('tool')}({c.get('summary', '')})"
    elif sp.get("cmd"):
        what = shlex.join(sp["cmd"])
    n = len(sp["paths"])
    return f"@{sp['n']:<3d} {n:3d} path{'s' if n != 1 else ' '}  {what}"


def cmd_savepoints(args):
    m = load_meta(args.session)
    if not os.path.isdir(session_file(args.session, "upper")):
        raise OverlordError(f"error: session is {m.get('status')}; layers discarded")
    for sp in session_savepoints(args.session, m):
        print(_savepoint_line(sp))
        if args.paths:
            for kind, rel in sp["paths"]:
                print(f"      {kind:12s} {rel}")
    if m.get("rewinds"):
        for rw in m["rewinds"]:
            print(f"rewound to @{rw['to']} at {rw['at']}: "
                  f"{len(rw['layers'])} layer(s) discarded")
    if m.get("layer_cap_hit"):
        print(f"note: layer cap ({MAX_LAYERS}) reached; later writes share the top layer")
    return 0


def cmd_rewind(args):
    changes = rewind_session(args.session, args.to)
    print(f"rewound {args.session} to savepoint @{args.to}: {len(changes)} change(s) remain")
    for kind, rel in changes[:20]:
        print(f"  {kind:12s} {rel}")
    print(f"\n  resume:   overlord resume {args.session} [--note \"...\"]")
    return 0


def cmd_fork(args):
    new = fork_session(args.session, args.at)
    m = load_meta(new)
    print(f"forked {args.session} at savepoint @{m['forked_from']['at']} -> {new}")
    print(f"\n  continue:  overlord resume {new} [--note \"...\"]")
    print(f"  compare:   overlord compare {args.session} {new}")
    return 0


def cmd_compare(args):
    rows = compare_sessions(args.a, args.b)
    if not rows:
        print("neither session changed anything")
        return 0
    for r in rows:
        print(f"{r['state']:8s} {r['path']:40s} a={r['a'] or '-':12s} b={r['b'] or '-'}")
    return 0


def cmd_resume(args):
    m = load_meta(args.session)
    if m.get("agent") and not args.cmd:
        import agent as agent_mod
        return agent_mod.cmd_resume(args, m)
    if not args.cmd:
        raise OverlordError("error: resume needs a command after -- for a non-agent session")
    live = reopen_session(args.session, wait=args.wait)
    try:
        rc, _ = live.exec(args.cmd, capture=False)
    finally:
        sid, changes = live.close()
    if live.expired:
        rc = TIMEOUT_RC
    _print_session_footer(sid, rc, m["backend"], changes)
    return rc


# ---------------------------------------------------------------- blame


def _sessions_for_path(real):
    """Committed sessions whose target contains the path, oldest commit first."""
    hits = []
    for sid in list_sessions():
        m = load_meta(sid)
        t = m.get("target") or ""
        if m.get("status") == "committed" and (real == t or real.startswith(t + os.sep)):
            hits.append(m)
    # committed_ns orders commits that share a second; the wall-clock string
    # keeps records from before it was written in their place
    return sorted(hits, key=lambda m: (m.get("committed") or "", m.get("committed_ns") or 0))


def _turn_text(sid, turn):
    """What the model said in the turn that issued a tool call."""
    path = session_file(sid, "transcript.jsonl")
    if turn is None or not os.path.isfile(path):
        return None
    with open(path) as f:
        for line in f:
            ev = json.loads(line)
            if ev.get("type") == "assistant" and ev.get("turn") == turn:
                return ev.get("text")
    return None


def blame_path(path):
    """Attribute a file — and, where content was retained, each of its
    lines — to the committed session, turn, tool call and instruction that
    produced it. Returns a dict (see cmd_blame for the rendering)."""
    real = os.path.realpath(path)
    versions = []
    for m in _sessions_for_path(real):
        rel = os.path.relpath(real, m["target"])
        prov = session_file(m["id"], PROVENANCE_FILE)
        if not os.path.isfile(prov):
            continue
        with open(prov) as f:
            for line in f:
                rec = json.loads(line)
                if rec["path"] != rel:
                    continue
                cause = rec.get("caused_by") or {}
                versions.append({
                    "sid": m["id"], "committed": m.get("committed"),
                    "agent": m.get("agent"), "task": m.get("task"),
                    "kind": rec["kind"], "layer": rec.get("layer"), "cause": cause,
                    "before_sha256": rec.get("before_sha256"),
                    "after_sha256": rec.get("after_sha256"),
                    "said": _turn_text(m["id"], cause.get("turn")) if cause else None,
                })
    out = {"path": real, "versions": versions, "lines": None, "state": "unrecorded"}
    if not versions:
        return out
    current = _sha256(real) if os.path.lexists(real) else None
    last = versions[-1]
    if last["kind"] == "deleted":
        out["state"] = "deleted" if current is None else "recreated-outside"
    elif current == last["after_sha256"]:
        out["state"] = "current"
    else:
        out["state"] = "drifted"
    # line attribution: walk the retained content chain
    if not os.path.isfile(real) or os.path.islink(real):
        return out
    with open(real, "rb") as f:
        raw = f.read()
    try:
        cur_lines = raw.decode().splitlines()
    except UnicodeDecodeError:
        out["state_note"] = "binary"
        return out
    attr = None            # per-line owner, None = chain broken (content not retained)
    prev = None
    first_before = load_object(versions[0].get("before_sha256"))
    if first_before is not None:
        try:
            prev = first_before.decode().splitlines()
            attr = ["origin"] * len(prev)
        except UnicodeDecodeError:
            prev = None
    for i, v in enumerate(versions):
        content = load_object(v.get("after_sha256")) if v["kind"] != "deleted" else b""
        if content is None:
            attr, prev = None, None
            continue
        try:
            new = content.decode().splitlines()
        except UnicodeDecodeError:
            attr, prev = None, None
            continue
        attr = _attribute_lines(prev, attr, new, i)
        prev = new
    if attr is None or prev is None:
        out["lines_note"] = "content not retained for every version; line blame unavailable"
        return out
    if cur_lines != prev:
        attr = _attribute_lines(prev, attr, cur_lines, "drift")
    out["lines"] = [{"n": n + 1, "owner": owner, "text": text}
                    for n, (owner, text) in enumerate(zip(attr, cur_lines))]
    return out


def _attribute_lines(prev, attr, new, owner):
    """Carry ownership across equal lines; everything inserted or replaced
    belongs to `owner`."""
    import difflib
    if prev is None or attr is None:
        return [owner] * len(new)
    out = []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, prev, new, autojunk=False).get_opcodes():
        if op == "equal":
            out.extend(attr[i1:i2])
        elif op in ("insert", "replace"):
            out.extend([owner] * (j2 - j1))
    return out


def cmd_blame(args):
    res = blame_path(args.path)
    if args.json:
        print(json.dumps(res, indent=2))
        return 0
    vs = res["versions"]
    if not vs:
        print(f"{res['path']}: no committed overlord session recorded this path")
        return 1
    state = {"current": "current content matches the last commit",
             "drifted": "content has changed OUTSIDE overlord since the last commit",
             "deleted": "deleted by the last commit",
             "recreated-outside": "deleted by the last commit, recreated outside overlord",
             }.get(res["state"], res["state"])
    print(f"{res['path']} — {len(vs)} recorded version(s); {state}")
    for i, v in enumerate(vs):
        who = f"agent {v['agent']}" if v.get("agent") else "command"
        print(f"  [{i}] {v['sid']}  committed {v.get('committed')}  {who}  ({v['kind']})")
        if v.get("task"):
            print(f"      task:   {v['task']}")
        if v.get("cause"):
            print(f"      cause:  {_describe_cause(v['cause'])}")
        if v.get("said"):
            said = " ".join(v["said"].split())
            print(f"      model:  \"{said[:240]}{'…' if len(said) > 240 else ''}\"")
    if res.get("lines") is None:
        if res.get("lines_note"):
            print(f"  ({res['lines_note']})")
        return 0
    print()
    for ln in res["lines"]:
        owner = ln["owner"]
        if isinstance(owner, int):
            v = vs[owner]
            c = v.get("cause") or {}
            tag = (f"[{owner}] t{c.get('turn')} {c.get('tool')}" if c
                   else f"[{owner}] {v['sid'][-6:]}")
        else:
            tag = owner
        print(f"{ln['n']:5d}  {tag:26s} │ {ln['text']}")
    return 0


def _policy_gate_summary():
    """One line for doctor: whether policy.json configures content checks."""
    pol = load_policy()
    if not pol:
        return "always available; no policy file, so no checks run"
    rules = list(pol.get("targets", {}).values()) + ([pol["default"]] if pol.get("default") else [])
    names = sorted({k for r in rules if isinstance(r, dict) and isinstance(r.get("checks"), dict)
                    for k, v in r["checks"].items() if not str(k).startswith("max_")})
    return ("checks configured: " + ", ".join(names)) if names else "no checks configured"


def cmd_doctor(args):
    if in_jail():
        print("inside an OVERLORD jail: no capabilities, no new privileges, a seccomp policy — a\n"
              "nested session cannot be opened here by design, so the backends below read as\n"
              "blocked. That is this jail holding, not a missing backend; the host's own\n"
              "`overlord doctor` and red-team suite are the view that counts.\n")
    k = _kernel_backend_available()
    fu = _fuse_backend_available()
    checks = [
        ("python", sys.version.split()[0], True),
        ("kernel backend (userns overlay; jail + net grants)",
         "available" if k else "blocked", k),
        ("fuse backend (fuse-overlayfs, cooperative)",
         "available" if fu else _fuse_backend_reason(), fu),
        ("recorded egress (--net proxy: empty netns + in-process proxy)",
         "available" if k else "needs the kernel backend", k),
        ("syscall trace (--trace, strace)",
         "available" if shutil.which("strace") else "missing",
         bool(shutil.which("strace"))),
        ("ebpf trace (--trace ebpf, bpftrace, root-only)",
         "available" if shutil.which("bpftrace") else "missing",
         bool(shutil.which("bpftrace"))),
        ("three-way merge (git merge-file)",
         "available" if shutil.which("git") else "missing",
         bool(shutil.which("git"))),
        ("savepoints (one overlay layer per writing command; rewind / commit --only)",
         "kernel: exact" if k else ("fuse: best effort (remount between commands)"
                                    if fu else "no backend"), k or fu),
        ("commit policy gate (secrets / binaries / deps / size)",
         _policy_gate_summary(), True),
    ]
    try:
        with open("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") as f:
            checks.append(("apparmor userns restriction", f.read().strip(), True))
    except OSError:
        pass
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
    import auth as auth_mod
    import audit as audit_mod
    import retention as retention_mod
    users = auth_mod.list_users()
    checks.append(("accounts (web UI sign-in)",
                   f"{len(users)} account(s): sign-in required" if users
                   else "none: loopback only, the local person is the operator", True))
    tls_dir = os.path.join(OVERLORD_HOME, "tls")
    has_tls = os.path.isfile(os.path.join(tls_dir, "cert.pem"))
    checks.append(("tls material (~/.overlord/tls)",
                   "cert.pem present" if has_tls else "none (overlord tls selfsign, or bring your own)",
                   True))
    _w = audit_mod.config().get("witness") or {}
    checks.append(("audit witness (off-box head)",
                   (_w.get("url") + (" (auto)" if _w.get("auto") else "")) if _w.get("url") else "not set",
                   bool(_w.get("url"))))
    v = audit_mod.verify()
    checks.append(("audit chain", (f"intact, {v['entries']} entries, "
                                    + ("signed" if v.get("keyed") else "UNSIGNED")) if v["ok"]
                   else f"BROKEN at line {v['broken_at']}: {v['reason']}", v["ok"]))
    checks.append(("resource limits (memory / pids / cpu per session)", limits_backend(), True))
    du = retention_mod.usage()
    rc = retention_mod.load_config()
    checks.append(("records on disk",
                   f"{du['sessions']} session(s) {du['sessions_bytes'] >> 20} MiB, "
                   f"{du['objects']} object(s) {du['objects_bytes'] >> 20} MiB; "
                   f"gc keeps {rc['keep_days']} days / newest {rc['keep_last']}", True))
    for name, val, good in checks:
        print(f"  {'ok ' if good else '!! '} {name}: {val}")
    if not (k or fu):
        print("\n  NO BACKEND AVAILABLE — run: sudo bash packaging/install.sh")
        return 1
    print(f"\n  active backend: {'kernel' if k else 'fuse'}")
    return 0


# ---------------------------------------------------------------- daemon

VERSION = "0.30.0"
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
        raise OverlordError(f"error: policy refuses target: {target}")
    eff = dict(requested)
    if rule.get("jail"):
        eff["jail"] = True
    if rule.get("net") == "none":
        eff["net"] = "none"
    cap = rule.get("timeout")
    if cap is not None:
        eff["timeout"] = min(cap, eff.get("timeout") or cap)
    if isinstance(rule.get("limits"), dict):
        # a policy limit is a ceiling: the smaller of the two wins, 0 = unlimited on either side
        lim = effective_limits(eff)
        for k, v in rule["limits"].items():
            if k in LIMIT_KEYS:
                lim[k] = int(v) if not lim.get(k) else (int(v) if not int(v) else min(lim[k], int(v)))
        eff["limits"] = lim
    if not rule.get("connector_shell", False):
        eff.pop("connector_shell", None)
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
    out_path = session_file(sid, OUTPUT_FILE)
    tail = ""
    if os.path.isfile(out_path):
        with open(out_path, errors="replace") as f:
            tail = "".join(f.readlines()[-50:])
    return {"sid": sid, "exit_code": rc, "changes": changes,
            "grants": grants, "output_tail": tail}


def _api_commit(req):
    m = load_meta(req["sid"])
    policy = load_policy()
    countersigned = bool(req.get("countersigned"))
    if policy is not None:
        rule = _policy_rule(policy, m["target"]) or {}
        if req.get("force") and not rule.get("allow_force", False):
            raise OverlordError("error: policy forbids --force commits on this target")
        if rule.get("require_review"):
            countersigned = True     # policy: no commit without a fresh approval
    return commit_session(req["sid"], merge=bool(req.get("merge")),
                          force=bool(req.get("force")),
                          only=req.get("only"), drop=req.get("drop"),
                          countersigned=countersigned)


def _api_review(req, emit):
    """Streaming op: a second model countersigns a pending session."""
    import agent as agent_mod
    import review as review_mod
    provider = agent_mod.make_provider(req.get("provider", "anthropic"), req.get("model"),
                                       script_env=review_mod.SCRIPT_ENV)
    rec = review_mod.run_review(
        req["sid"], provider, max_turns=int(req.get("max_turns") or review_mod.DEFAULT_MAX_TURNS),
        emit=lambda ev: emit({"ok": True, "event": "review", **ev}),
        allow_same=bool(req.get("same_model")))
    return {"sid": req["sid"], "review": rec}


def _api_rewind(req):
    """Rewind a session this daemon holds open, or a pending one."""
    ls = LIVE.get(req["sid"])
    to = req.get("to")
    if not isinstance(to, int):
        raise OverlordError("error: rewind needs an integer savepoint")
    if ls is not None:
        ls.rewind(to)
        return {"sid": ls.sid, "to": to, "changes": ls.changes(), "open": True}
    return {"sid": req["sid"], "to": to, "changes": rewind_session(req["sid"], to),
            "open": False}


def _api_savepoints(req):
    ls = LIVE.get(req["sid"])
    return {"savepoints": session_savepoints(req["sid"], ls.meta if ls else None)}


def _api_resume(req, emit):
    """Streaming op: reopen a pending agent session and let the model carry
    on from its restored transcript (after a rewind, typically), with an
    optional operator note; then seal it again."""
    import agent as agent_mod
    m = load_meta(req["sid"])
    if not m.get("agent"):
        raise OverlordError("error: not an agent session; use open/exec on it instead")
    provider = agent_mod.provider_for(m, req.get("provider"), req.get("model"))
    ls = reopen_session(req["sid"], wait=bool(req.get("wait")), capture=True)
    LIVE[ls.sid] = ls
    emit({"ok": True, "event": "session", "sid": ls.sid, "grants": ls.meta["grants"],
          "backend": ls.meta["backend"]})
    final = ""
    try:
        final = agent_mod.run_agent(
            ls, provider, m.get("task", ""), max_turns=int(req.get("max_turns") or
                                                        agent_mod.DEFAULT_MAX_TURNS),
            emit=lambda ev: emit({"ok": True, "event": "agent", **ev}),
            should_stop=lambda: ls.sid in AGENT_CANCEL,
            resume=True, note=req.get("note"))
    except SystemExit as e:
        emit({"ok": True, "event": "agent", "type": "error", "text": str(e)})
    finally:
        AGENT_CANCEL.discard(ls.sid)
        LIVE.pop(ls.sid, None)
        sid, changes = ls.close()
    m = load_meta(sid)
    return {"sid": sid, "final": final, "changes": changes, "grants": m.get("grants"),
            "usage": m.get("usage"), "exit_code": m.get("exit_code")}


def _api_log(req):
    load_meta(req["sid"])
    prov = session_file(req["sid"], PROVENANCE_FILE)
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
        raise OverlordError(f"error: session {sid} is not open in this daemon")
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
                      label=req.get("label"), cause=req.get("cause"),
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


def _policy_connectors(rule, requested):
    """Policy caps the connectors a brokered session may be granted: a rule
    lists names (or "*"); no rule means none through the daemon."""
    if not requested:
        return []
    allowed = (rule or {}).get("connectors")
    if allowed == "*":
        return list(requested)
    allowed = set(allowed or [])
    refused = [c for c in requested if c not in allowed]
    if refused:
        raise OverlordError(f"error: policy does not grant connector(s): {', '.join(refused)}")
    return list(requested)


def _api_agent(req, emit):
    """Streaming op: open a session, run the built-in agent, close it. Emits
    transcript events as they happen; returns the sealed session."""
    import agent as agent_mod
    target = os.path.realpath(req["target"])
    requested = {"net": "host", "jail": False, "timeout": None, "merge_base": False}
    requested.update(req.get("grants") or {})
    grants, rule = resolve_policy(target, requested)
    connectors = list(req.get("connectors") or [])
    if load_policy() is not None:
        connectors = _policy_connectors(rule, connectors)
    if connectors:
        grants["connectors"] = connectors
    provider = agent_mod.make_provider(
        req.get("provider", "anthropic"), req.get("model"), base_url=req.get("base_url"),
        headers=req.get("headers"), config=req.get("config"),
        azure_api_version=req.get("azure_api_version"))
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
            should_stop=lambda: ls.sid in AGENT_CANCEL,
            connectors=connectors or None,
            # brokered runs have no terminal: an action is auto-approved only
            # when the caller asked for it AND policy did not say readonly
            approval=req.get("connector_approval") or None,
            approve=(lambda r: bool(req.get("approve_all"))))
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
        raise OverlordError(f"error: no running agent session {req['sid']}")
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


def _api_revert(req):
    return revert_session(req["sid"], force=bool(req.get("force")), stack=bool(req.get("stack")),
                          commit=bool(req.get("commit")))


# an external system (a console, an executor) may append its own events —
# receipts, plans, findings, approvals — to the keyed audit chain through the
# broker, so they inherit the chain's tamper evidence and off-box witness. The
# namespace keeps them apart from the engine's own record; `via` marks them.
_EXT_AUDIT = re.compile(r"^(ext|receipt|plan|finding|approval)\.[a-z0-9_.]{1,64}$")
_RESERVED_AUDIT = {"ts", "action", "seq", "prev", "hash", "v", "via"}


def _api_audit(req):
    action = str(req.get("action") or "")
    if not _EXT_AUDIT.match(action):
        raise OverlordError("error: external audit actions must be namespaced "
                            "ext.|receipt.|plan.|finding.|approval. (lowercase, dots, underscores)")
    fields = req.get("fields") or {}
    if not isinstance(fields, dict):
        raise OverlordError("error: audit fields must be an object")
    clash = _RESERVED_AUDIT & set(fields)
    if clash:
        raise OverlordError(f"error: reserved audit field(s): {', '.join(sorted(clash))}")
    if len(json.dumps(fields)) > 65536:
        raise OverlordError("error: audit fields exceed 64 KiB")
    import audit as audit_mod
    return {"entry": audit_mod.record(action, via="daemon", **fields)}


def _api_complete(req):
    """One tool-less model call through the engine's providers and key store —
    for a planner that must only *propose*. Audited with prompt and output
    hashes, so a plan is traceable to the exact call that produced it."""
    import hashlib
    import agent as agent_mod
    prompt = req.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise OverlordError("error: complete needs a non-empty prompt")
    system = req.get("system") or ""
    provider = agent_mod.make_provider(req.get("provider", "anthropic"), req.get("model"),
                                       base_url=req.get("base_url"), headers=req.get("headers"),
                                       azure_api_version=req.get("azure_api_version"))
    reply = provider.complete(system, [{"role": "user", "content": prompt}], tools=None)
    text = reply.text or ""
    sha = lambda s: hashlib.sha256(s.encode()).hexdigest()   # noqa: E731
    model = getattr(provider, "model", None) or req.get("model")
    res = {"text": text, "stop": reply.stop, "usage": reply.usage, "refusal": reply.refusal,
           "provider": getattr(provider, "name", req.get("provider")), "model": model,
           "prompt_sha256": sha(system + "\n" + prompt), "output_sha256": sha(text)}
    _audit("model.complete", provider=res["provider"], model=model, purpose=req.get("purpose"),
           prompt_sha256=res["prompt_sha256"], output_sha256=res["output_sha256"],
           stop=reply.stop, usage=reply.usage)
    return res


DAEMON_OPS = {
    "ping": lambda req: {"version": VERSION, "pid": os.getpid()},
    "revert": _api_revert,
    "audit": _api_audit,
    "audit_head": lambda req: {"head": __import__("audit").head()},
    "complete": _api_complete,
    "run": _api_run,
    "open": _api_open,
    "close": _api_close,
    "diff": lambda req: {"changes": (LIVE[req["sid"]].changes() if req["sid"] in LIVE
                                     else session_stack(req["sid"])[0])},
    "log": _api_log,
    "commit": _api_commit,
    "rollback": _api_rollback,
    "sessions": lambda req: {"sessions": [load_meta(s) for s in list_sessions()]},
    "agent_cancel": _api_agent_cancel,
    "transcript": _api_transcript,
    "savepoints": _api_savepoints,
    "rewind": _api_rewind,
    "blame": lambda req: blame_path(req["path"]),
    "fork": lambda req: {"sid": fork_session(req["sid"], req.get("at")),
                         "forked_from": req["sid"]},
    "models": lambda req: {"models": __import__("agent").list_models(
        req.get("provider", "anthropic"), base_url=req.get("base_url"),
        headers=req.get("headers"), azure_api_version=req.get("azure_api_version"))},
    "compare": lambda req: {"rows": compare_sessions(req["a"], req["b"])},
}
STREAMING_OPS = {"exec": _api_exec, "agent": _api_agent, "resume": _api_resume,
                 "review": _api_review}


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
                except (OverlordError, SystemExit) as e:
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
    return ui.serve(args.port, bind=args.bind, tls_cert=args.tls_cert, tls_key=args.tls_key,
                    hosts=args.host, log_json=args.log_json, rate_limit=args.rate_limit)


# ---------------------------------------------------------------- main


def _add_exec_flags(parser):
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("--backend", choices=list(PREPARE))
    parser.add_argument("--manifest", help="capability manifest JSON (flags override)")
    parser.add_argument("--jail", action="store_true",
                        help="pivot_root jail: only system dirs + target exist")
    parser.add_argument("--net", choices=["host", "none", "proxy"],
                        help="network grant (none = empty netns; proxy = recorded egress via an allowlisting proxy)")
    parser.add_argument("--net-allow", action="append", metavar="HOST",
                        help="with --net proxy: a host or *.suffix the agent may reach "
                             "(repeatable; none given = record every connection, allow all)")
    parser.add_argument("--limit", action="append", metavar="KEY=N",
                        help=f"a resource grant: {', '.join(LIMIT_KEYS)} (0 = unlimited)")
    parser.add_argument("--connector-shell", action="store_true",
                        help="offer connector tools that look like a shell (withheld by default)")
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

    pu = sub.add_parser("ui", help="the workspace and mission control (web UI)")
    pu.add_argument("--port", type=int, default=7777)
    pu.add_argument("--bind", default="127.0.0.1",
                    help="address to listen on; anything but loopback needs accounts + TLS")
    pu.add_argument("--tls-cert", help="PEM certificate chain (serve https)")
    pu.add_argument("--tls-key", help="PEM private key")
    pu.add_argument("--host", action="append",
                    help="a hostname browsers will use (Host header allowlist); repeatable")
    pu.add_argument("--log-json", action="store_true", help="one JSON line per request on stderr")
    pu.add_argument("--rate-limit", type=int, default=3000,
                    help="requests per minute per address (0 = off)")
    pu.set_defaults(fn=cmd_ui)
    sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
    import auth as auth_mod
    import cost as cost_mod
    import audit as audit_mod
    import retention as retention_mod
    import skills as skills_mod
    import oidc as oidc_mod
    import notify as notify_mod
    import vault as vault_mod
    import bundle as bundle_mod
    vault_mod.add_vault_parser(sub)
    bundle_mod.add_bundle_parsers(sub)
    skills_mod.add_skills_parser(sub)
    oidc_mod.add_sso_parser(sub)
    notify_mod.add_webhooks_parser(sub)
    auth_mod.add_auth_parsers(sub)
    cost_mod.add_cost_parser(sub)
    audit_mod.add_audit_parser(sub)
    retention_mod.add_gc_parser(sub)

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
    pc.add_argument("--only", metavar="SEL",
                    help="replay only these layers: layer:N, layer:A-B, turn:N, "
                         "tool:NAME, call:ID (comma-separated)")
    pc.add_argument("--drop", metavar="SEL",
                    help="replay everything except these layers (same selectors)")
    pc.add_argument("--countersigned", action="store_true",
                    help="refuse unless a second model's fresh approval is on record "
                         "(overlord review)")
    pc.set_defaults(fn=cmd_commit)

    pch = sub.add_parser("check", help="dry-run the pre-commit policy gate on a pending session")
    pch.add_argument("session")
    pch.set_defaults(fn=cmd_check)

    prv = sub.add_parser("revert", help="undo a COMMITTED session's file changes as a new "
                                        "reviewable session (rollback discards a pending one)")
    prv.add_argument("session")
    prv.add_argument("--commit", action="store_true", help="commit the revert at once")
    prv.add_argument("--force", action="store_true",
                     help="skip paths whose before-content was not retained instead of refusing")
    prv.add_argument("--stack", action="store_true",
                     help="open over existing pending sessions on the target")
    prv.set_defaults(fn=cmd_revert)

    pf = sub.add_parser("fork", help="copy the stack up to a savepoint into a new session")
    pf.add_argument("session")
    pf.add_argument("--at", type=int, metavar="N", help="savepoint to fork at (default: top)")
    pf.set_defaults(fn=cmd_fork)

    pcmp = sub.add_parser("compare", help="where two sessions' stacks diverge, per path")
    pcmp.add_argument("a")
    pcmp.add_argument("b")
    pcmp.set_defaults(fn=cmd_compare)

    import review as review_mod
    review_mod.add_review_parser(sub)
    import mcp as mcp_mod
    mcp_mod.add_mcp_parser(sub)
    import memory as memory_mod
    memory_mod.add_memory_parser(sub)

    psv = sub.add_parser("savepoints", help="the layer stack: one savepoint per writing command")
    psv.add_argument("session")
    psv.add_argument("--paths", action="store_true", help="list each savepoint's paths")
    psv.set_defaults(fn=cmd_savepoints)

    prw = sub.add_parser("rewind", help="discard every layer above a savepoint")
    prw.add_argument("session")
    prw.add_argument("--to", type=int, required=True, metavar="N",
                     help="savepoint to return to (see `overlord savepoints`)")
    prw.set_defaults(fn=cmd_rewind)

    prs = sub.add_parser("resume", help="reopen a pending session: continue the agent, "
                                         "or run another command on its stack")
    prs.add_argument("session")
    prs.add_argument("--note", help="operator note the resumed model reads first")
    prs.add_argument("--provider", choices=["anthropic", "openai", "scripted"],
                     help="override the session's recorded provider")
    prs.add_argument("--model")
    prs.add_argument("--max-turns", type=int)
    prs.add_argument("--wait", action="store_true",
                     help="queue behind an executing session instead of failing")
    prs.add_argument("cmd", nargs="*", metavar="-- CMD",
                     help="non-agent sessions: the command to run on the stack "
                          "(after --)")
    prs.set_defaults(fn=cmd_resume)

    pb = sub.add_parser("blame", help="which session, turn, tool call and instruction "
                                       "put each line of a file there")
    pb.add_argument("path")
    pb.add_argument("--json", action="store_true")
    pb.set_defaults(fn=cmd_blame)

    args = p.parse_args(argv)
    if getattr(args, "cmd", None) is not None and args.command != "resume":
        if args.cmd and args.cmd[0] == "--":
            args.cmd = args.cmd[1:]
        if not args.cmd:
            p.error("run requires a command after --")
    os.makedirs(SESSIONS_DIR, exist_ok=True)
    try:
        return args.fn(args)
    except OverlordError as e:
        print(e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    # submodules `import overlord`; without this alias they would load a
    # second copy of the engine whose OverlordError is a different class,
    # and main() would show a traceback instead of the error line
    sys.modules.setdefault("overlord", sys.modules[__name__])
    sys.exit(main())
