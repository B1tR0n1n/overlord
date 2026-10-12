#!/usr/bin/env python3
"""Hardening: session ids match exactly; session records are owner-only;
--expose is validated (absolute, existing, jail + kernel, never overlapping
the target or OVERLORD_HOME) and policy-brokered for API callers; profiles
fold their exposes and env in; the syscall trace is capped. Under the kernel
backend: commands run as the invoking user (un-root), the jail masks the
host's identity, and exposed paths appear read-only (or read-write with
--expose-rw) at their real path."""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = os.path.join(HOME, ".overlord")

import overlord as ov      # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


def refused(fn, *a, contains=""):
    try:
        fn(*a)
    except ov.OverlordError as e:
        if contains and contains not in str(e):
            fail(f"refused for the wrong reason: {e}")
        return True
    return False


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


target = tempfile.mkdtemp()
outside = tempfile.mkdtemp()
with open(os.path.join(target, "lib.py"), "w") as f:
    f.write("x = 1\n")
cfg_dir = os.path.join(outside, "agentcfg")
os.makedirs(cfg_dir)
with open(os.path.join(cfg_dir, "settings"), "w") as f:
    f.write("theme=dark\n")
cfg_file = os.path.join(outside, "agent.json")
with open(cfg_file, "w") as f:
    f.write("{}\n")
rw_dir = os.path.join(outside, "state")
os.makedirs(rw_dir)

try:
    # 1. session ids: fullmatch, so a trailing newline is not a valid id
    good = ov.new_session_id()
    if ov.validate_session_id(good) != good:
        fail("a minted id must validate")
    if not refused(ov.validate_session_id, good + "\n", contains="invalid session id"):
        fail("an id with a trailing newline must be refused")
    ok("session ids match exactly (a trailing newline is refused)")

    # 2. --expose validation
    jail = {"jail": True}
    r = ov.resolve_expose({**jail, "expose": [cfg_dir, cfg_file], "expose_rw": [rw_dir]},
                          "kernel", target)
    if r["expose"] != [os.path.realpath(cfg_dir), os.path.realpath(cfg_file)] or \
            r["expose_rw"] != [os.path.realpath(rw_dir)]:
        fail(f"expose not resolved: {r}")
    if ov.resolve_expose({"jail": False}, "fuse", target) != {"jail": False}:
        fail("no expose grant must pass through untouched")
    cases = [
        ({**jail, "expose": [cfg_dir]}, "fuse", "kernel backend"),
        ({"jail": False, "expose": [cfg_dir]}, "kernel", "requires --jail"),
        ({**jail, "expose": ["relative/path"]}, "kernel", "absolute"),
        ({**jail, "expose": [os.path.join(outside, "nope")]}, "kernel", "does not exist"),
        ({**jail, "expose": ["/"]}, "kernel", "overlaps"),
        ({**jail, "expose": [target]}, "kernel", "overlaps"),
        ({**jail, "expose": [os.path.dirname(target)]}, "kernel", "overlaps"),
        ({**jail, "expose_rw": [HOME]}, "kernel", "overlaps"),            # parent of OVERLORD_HOME
    ]
    os.makedirs(ov.OVERLORD_HOME, exist_ok=True)
    for g, backend, why in cases:
        if not refused(ov.resolve_expose, g, backend, target, contains=why):
            fail(f"expose should be refused ({why}): {g}")
    ok("--expose: absolute + existing, kernel + jail only, never the target, / or OVERLORD_HOME")

    # 3. policy brokers expose for API callers: only under a path the rule lists
    req = {"net": "host", "jail": False, "timeout": None, "merge_base": False,
           "expose": [cfg_dir, cfg_file], "expose_rw": [rw_dir]}
    eff, rule = ov.resolve_policy(target, req)
    if rule is not None or eff["expose"] != req["expose"]:
        fail("with no policy file, grants pass through (direct-CLI semantics)")
    with open(ov.POLICY_FILE, "w") as f:
        json.dump({"default": {"jail": True}}, f)
    eff, _r = ov.resolve_policy(target, req)
    if "expose" in eff or "expose_rw" in eff:
        fail(f"a rule without an expose list must drop exposes: {eff}")
    with open(ov.POLICY_FILE, "w") as f:
        json.dump({"default": {"jail": True, "expose": [cfg_dir]}}, f)
    eff, _r = ov.resolve_policy(target, req)
    if eff.get("expose") != [cfg_dir] or "expose_rw" in eff:
        fail(f"only the listed path (read-only) may pass: {eff}")
    os.unlink(ov.POLICY_FILE)
    ok("policy: exposes kept only under paths the rule lists; none by default")

    # 4. profiles fold in exposes (skipping missing paths) and env, and imply --jail
    if not refused(ov.load_profile, "x", contains="no profiles defined"):
        fail("no profiles.json must be a clear error")
    with open(os.path.join(ov.OVERLORD_HOME, "profiles.json"), "w") as f:
        json.dump({"cli": {"expose": [cfg_dir, os.path.join(outside, "missing")],
                           "expose_rw": [rw_dir], "env": {"IS_SANDBOX": "1"}}}, f)
    g, cmd = ov.apply_profile("cli", {"jail": False, "expose": [cfg_file]}, ["agentcli", "-p"])
    if not g["jail"] or g["expose"] != [cfg_file, cfg_dir] or g["expose_rw"] != [rw_dir]:
        fail(f"profile grants: {g}")
    if cmd != ["env", "IS_SANDBOX=1", "agentcli", "-p"]:
        fail(f"profile env: {cmd}")
    if not refused(ov.load_profile, "other", contains="no such profile"):
        fail("an unknown profile must be refused")
    ok("profiles: exposes (missing paths skipped) + env, --jail implied")

    BACKEND = ov.detect_backend()
    if BACKEND is None:
        print("PASS: hardening (no sandbox backend here; session checks skipped)")
        sys.exit(0)

    # 5. owner-only records, retrofitted onto a world-readable install
    os.chmod(ov.OVERLORD_HOME, 0o755)
    os.makedirs(ov.SESSIONS_DIR, exist_ok=True)
    os.chmod(ov.SESSIONS_DIR, 0o755)
    ov.ensure_private_dirs()
    live = ov.open_session(target, BACKEND, {"net": "host", "jail": False, "timeout": None,
                                              "merge_base": False}, capture=True)
    live.exec(["sh", "-c", "echo hi > out.txt"], timeout=60)
    sid, _ = live.close()
    for p in (ov.OVERLORD_HOME, ov.SESSIONS_DIR, ov.LOCKS_DIR, ov.session_path(sid)):
        if mode(p) != 0o700:
            fail(f"{p} is {oct(mode(p))}, want 0700")
    if mode(ov.session_file(sid, ov.META_FILE)) != 0o600:
        fail(f"meta.json is {oct(mode(ov.session_file(sid, ov.META_FILE)))}, want 0600")
    ov.rollback_session(sid)
    ok("OVERLORD_HOME, sessions/, locks/, the session dir 0700; meta.json 0600")

    # 6. the syscall trace is capped: past trace_mb the command is killed
    if shutil.which("strace"):
        lim = {**ov.DEFAULT_LIMITS, "trace_mb": 1}
        live = ov.open_session(target, BACKEND, {"net": "host", "jail": False, "timeout": None,
                                                  "merge_base": False, "limits": lim},
                               trace="strace", capture=True)
        rc, _out = live.exec(["python3", "-c",
                              "import os\nwhile True:\n    os.stat('.')"], timeout=60)
        rec = live.meta["execs"][-1]
        sid, _ = live.close()
        if not rec.get("trace_truncated") or rc == 0:
            fail(f"trace cap not enforced: rc={rc} rec={rec}")
        ov.rollback_session(sid)
        ok("a command whose syscall trace passes trace_mb is killed; the record says truncated")
    else:
        print("  skip: trace cap (no strace)")

    if BACKEND != "kernel":
        print("PASS: hardening (fuse backend; un-root, identity mask and --expose need the kernel backend)")
        sys.exit(0)

    # 7. kernel: un-root, identity mask, expose ro / rw
    uid, gid = os.getuid(), os.getgid()
    live = ov.open_session(
        target, "kernel",
        {"net": "none", "jail": True, "timeout": None, "merge_base": False,
         "expose": [cfg_dir, cfg_file], "expose_rw": [rw_dir]}, capture=True)
    script = (
        f"id -u; id -g; hostname; cat /etc/hostname; wc -c < /etc/machine-id; "
        f"cut -d: -f1 /etc/passwd | tr '\\n' ,; echo; "
        f"cat {cfg_dir}/settings; cat {cfg_file}; "
        f"(echo x > {cfg_dir}/new) 2>/dev/null && echo RO-BROKEN || echo RO-HELD; "
        f"echo written > {rw_dir}/from-jail && echo RW-OK; echo HOME=$HOME")
    rc, out = live.exec(["sh", "-c", script], timeout=60)
    sid, _ = live.close()
    lines = out.decode(errors="replace").split("\n")
    expect = {0: str(uid), 1: str(gid), 2: "sandbox", 3: "sandbox", 4: "0"}
    for i, want in expect.items():
        if uid == 0 and i < 2:
            continue                       # overlord itself runs as root: nothing to drop to
        if lines[i].strip() != want:
            fail(f"jail line {i}: {lines[i]!r}, want {want!r}\n{out.decode(errors='replace')}")
    accounts = set(filter(None, lines[5].split(",")))
    if not accounts <= {"root", "agent"}:
        fail(f"host accounts visible in the jail: {sorted(accounts)}")
    body = "\n".join(lines[6:])
    if "theme=dark" not in body or "{}" not in body:
        fail(f"exposed dir/file not readable in the jail:\n{body}")
    if "RO-HELD" not in body or os.path.exists(os.path.join(cfg_dir, "new")):
        fail("a read-only expose was writable")
    if "RW-OK" not in body or not os.path.isfile(os.path.join(rw_dir, "from-jail")):
        fail("an --expose-rw path did not take the write on the host")
    if f"HOME={os.environ.get('HOME', '/')}" not in body:
        fail("with exposes the real $HOME is kept")
    ov.rollback_session(sid)
    ok("kernel: runs as the invoking user; hostname/machine-id/passwd masked; "
       "exposes read-only (dir and single file), --expose-rw writes through")

    print("PASS: hardening")
finally:
    subprocess.run(["rm", "-rf", HOME, target, outside])
