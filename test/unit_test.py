#!/usr/bin/env python3
"""Engine unit tests: the pure path-handling and whiteout-classification
functions, driven against synthetic upper layers. No backend required.

These pin down the boundary between an untrusted upper layer (written by the
wrapped process) and the real tree it is replayed into."""

import json
import os
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import overlord as core  # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


def raises(fn, *a):
    try:
        fn(*a)
    except core.OverlordError:
        return True
    return False


def touch(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w"):
        pass


def try_mknod_whiteout(path):
    """0/0 char device, the kernel-native whiteout. Unprivileged creation has
    been allowed since Linux 5.8; return False where the host refuses."""
    try:
        os.mknod(path, stat.S_IFCHR | 0o600, 0)
        return True
    except PermissionError:
        return False


def make_tree(files):
    root = tempfile.mkdtemp()
    for rel in files:
        touch(os.path.join(root, rel))
    return root


# --- 1. session ids: only the minted shape reaches the filesystem
good = core.new_session_id()
if core.validate_session_id(good) != good:
    fail("minted session id rejected")
for bad in ("", "../etc", "20260911-132207-72DDCE", "20260911-132207-72ddce/x",
            "x", None, 42, "20260911-132207-72ddce\n"):
    if not raises(core.validate_session_id, bad):
        fail(f"session id accepted: {bad!r}")
if not raises(core.session_path, "../escape"):
    fail("session_path joined an unvalidated id")
ok("session id validation")

# --- 2. _safe_join: nothing resolves outside its base
base = tempfile.mkdtemp()
if core._safe_join(base, "a/b") != os.path.join(base, "a", "b"):
    fail("safe_join mangled an ordinary path")
if core._safe_join(base, ".") != base:
    fail("safe_join refused the base itself")
for esc in ("..", "../x", "a/../../x", "/etc/passwd"):
    if not raises(core._safe_join, base, esc):
        fail(f"safe_join allowed escape: {esc}")
ok("safe_join containment")

# --- 3. whiteout recognition is per backend
up = make_tree([".wh.foo", "plain"])
if not core.is_whiteout(os.path.join(up, ".wh.foo"), "fuse"):
    fail("fuse: .wh. marker not recognised")
if core.is_whiteout(os.path.join(up, ".wh.foo"), "kernel"):
    fail("kernel: regular file named .wh.foo misread as a whiteout")
if core.is_whiteout(os.path.join(up, "plain"), "fuse"):
    fail("plain file read as whiteout")
if core._victim_rel(os.path.join(up, ".wh.foo"), up) != "foo":
    fail("fuse: wrong whiteout victim")
if try_mknod_whiteout(os.path.join(up, "gone")):
    for b in ("fuse", "kernel"):
        if not core.is_whiteout(os.path.join(up, "gone"), b):
            fail(f"{b}: 0/0 char device not recognised as whiteout")
        if core._victim_rel(os.path.join(up, "gone"), up) != "gone":
            fail(f"{b}: char-device whiteout victim wrong")
    ok("whiteout recognition per backend (incl. char-device whiteouts)")
else:
    ok("whiteout recognition per backend (char-device mknod refused here; skipped)")

# --- 4. a bare '.wh.' entry must never resolve to its parent directory
up = make_tree([".wh.", "sub/.wh.", "sub/.wh.."])
for rel in (".wh.", "sub/.wh.", "sub/.wh.."):
    if not raises(core._victim_rel, os.path.join(up, rel), up):
        fail(f"fuse: bare marker {rel!r} accepted (would delete its parent)")
# under kernel the same names are ordinary files and stay ordinary
if core.is_whiteout(os.path.join(up, ".wh."), "kernel"):
    fail("kernel: bare .wh. misread as whiteout")
ok("bare .wh. marker refused")

# --- 5. compute_diff: same upper, backend decides added vs deleted
target = make_tree(["keep.txt", "sub/n.txt"])
up = make_tree([".wh.keep.txt"])
if core.compute_diff(up, target, "kernel") != [("added", ".wh.keep.txt")]:
    fail(f"kernel diff: {core.compute_diff(up, target, 'kernel')}")
if core.compute_diff(up, target, "fuse") != [("deleted", "keep.txt")]:
    fail(f"fuse diff: {core.compute_diff(up, target, 'fuse')}")
ok("compute_diff classifies .wh. names per backend")

# --- 6. apply_upper: kernel replays the file; fuse refuses a bare marker
target = make_tree(["keep.txt", "sub/n.txt"])
up = make_tree([".wh.keep.txt"])
core.apply_upper(up, target, "kernel")
if not (os.path.isfile(os.path.join(target, "keep.txt"))
        and os.path.isfile(os.path.join(target, ".wh.keep.txt"))):
    fail("kernel apply: .wh.-named file did not replay as a plain file")
target = make_tree(["keep.txt", "sub/n.txt"])
up = make_tree(["sub/.wh."])
if not raises(core.apply_upper, up, target, "fuse"):
    fail("fuse apply: bare marker in sub/ was replayed")
if not os.path.isfile(os.path.join(target, "sub", "n.txt")):
    fail("fuse apply: refused marker still deleted sub/")
ok("apply_upper honours backend and refuses bare markers")

# --- 7. diff never escapes: crafted relpaths in the upper are impossible to
# walk into, but the join guard is exercised directly by the victim path
up = make_tree([".wh.x"])
os.rename(os.path.join(up, ".wh.x"), os.path.join(up, ".wh..."))
if not raises(core._victim_rel, os.path.join(up, ".wh..."), up):
    fail("victim '..' escaped the upper tree")
ok("whiteout victim cannot escape the tree")

# --- 8. profile: forces jail, wraps the env, exposes only paths that exist
with open(os.path.join(os.environ["OVERLORD_HOME"], "profiles.json"), "w") as f:
    json.dump({"cli": {"expose": [base, "/nonexistent-xyzzy-12345"],
                       "env": {"IS_SANDBOX": "1"}}}, f)
g, c = core.apply_profile("cli", {"jail": False, "expose": []}, ["cli", "-p", "hi"])
if g["jail"] is not True:
    fail("profile did not force --jail")
if c[:2] != ["env", "IS_SANDBOX=1"] or c[-3:] != ["cli", "-p", "hi"]:
    fail(f"profile mangled the command: {c}")
if g["expose"] != [base]:
    fail(f"profile exposed a non-existent path: {g['expose']}")
if not raises(core.apply_profile, "nope", {}, ["x"]):
    fail("unknown profile accepted")
ok("profile (jail + env wrap + extant exposes)")

# --- 9. expose validation: absolute + existing + kernel + jail, never the
# target or OVERLORD_HOME (ro and rw alike)
tgt = tempfile.mkdtemp()
def expose(paths, jail=True, backend="kernel", key="expose"):
    return core.resolve_expose({key: paths, "jail": jail}, backend, tgt)
for key in ("expose", "expose_rw"):
    for bad, kw in ((["relative/path"], {}), (["/nonexistent-xyzzy-12345"], {}),
                    ([base], {"jail": False}), ([base], {"backend": "fuse"}),
                    ([tgt], {}), ([os.environ["OVERLORD_HOME"]], {}), (["/"], {})):
        if not raises(lambda: expose(bad, key=key, **kw)):
            fail(f"{key} accepted {bad} {kw}")
    if expose([base], key=key)[key] != [os.path.realpath(base)]:
        fail(f"{key} mangled a valid path")
ok("expose path validation (ro/rw share it)")

print("PASS: engine unit tests")
