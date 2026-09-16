#!/usr/bin/env python3
"""Commit-time replay safety. Master's `_safe_join` already refuses a
destination whose deepest existing component resolves outside the tree (a
symlinked ancestor, or a leaf symlink pointing out), so those escapes are
rejected. This suite pins the two behaviours added on top of that:

  - a rejection leaves NOTHING half-replayed (validate before mutating);
  - replay never writes THROUGH a leaf symlink that points back inside the
    tree, which `_safe_join` allows — it would otherwise clobber the target.

Context: PR #4 (coderabbitai) proposed the same intent; most of it was
already independently hardened on master, so only these pieces were taken."""

import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import overlord as ov      # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


def _tree():
    work = tempfile.mkdtemp()
    upper = os.path.join(work, "upper")
    target = os.path.join(work, "target")
    outside = os.path.join(work, "outside")
    os.makedirs(upper)
    os.makedirs(target)
    os.makedirs(outside)
    return work, upper, target, outside


try:
    # 1. a symlinked ancestor pointing out of the tree is refused, and because
    #    validation precedes any write, nothing is replayed
    work, upper, target, outside = _tree()
    os.makedirs(os.path.join(upper, "escape"))
    with open(os.path.join(upper, "before.txt"), "w") as f:
        f.write("must not be replayed")
    with open(os.path.join(upper, "escape", "payload.txt"), "w") as f:
        f.write("outside")
    os.symlink(outside, os.path.join(target, "escape"))
    try:
        ov.apply_upper(upper, target)
        fail("apply_upper replayed through a symlinked ancestor")
    except ov.OverlordError:
        pass
    if os.path.exists(os.path.join(outside, "payload.txt")):
        fail("a file was written outside the tree through the symlink")
    if os.path.exists(os.path.join(target, "before.txt")):
        fail("the replay was partial — validation must precede any mutation")
    shutil.rmtree(work)
    ok("a symlinked ancestor is refused before anything is written; no partial replay")

    # 2. a leaf symlink that points BACK INSIDE the tree is replaced, not
    #    written through — the file it points at is left untouched
    work, upper, target, outside = _tree()
    with open(os.path.join(target, "real.txt"), "w") as f:
        f.write("KEEP")
    os.symlink(os.path.join(target, "real.txt"), os.path.join(target, "link.txt"))
    with open(os.path.join(upper, "link.txt"), "w") as f:
        f.write("REPLAYED")
    ov.apply_upper(upper, target)
    if os.path.islink(os.path.join(target, "link.txt")):
        fail("the leaf symlink was not replaced")
    if open(os.path.join(target, "link.txt")).read() != "REPLAYED":
        fail("the replayed file did not land at the link's path")
    if open(os.path.join(target, "real.txt")).read() != "KEEP":
        fail("replay wrote through the leaf symlink and clobbered its target")
    shutil.rmtree(work)
    ok("a leaf symlink pointing inside the tree is unlinked and replaced, its target untouched")

    # 3. ordinary replay — nested file plus a whiteout delete — is unaffected
    work, upper, target, outside = _tree()
    os.makedirs(os.path.join(upper, "sub"))
    with open(os.path.join(upper, "sub", "a.txt"), "w") as f:
        f.write("A")
    with open(os.path.join(target, "gone.txt"), "w") as f:
        f.write("old")
    open(os.path.join(upper, ".wh.gone.txt"), "w").close()
    ov.apply_upper(upper, target)
    if open(os.path.join(target, "sub", "a.txt")).read() != "A":
        fail("a normal file+subdir replay regressed")
    if os.path.exists(os.path.join(target, "gone.txt")):
        fail("a whiteout no longer deletes its victim")
    shutil.rmtree(work)
    ok("ordinary replay — nested file and whiteout delete — is unaffected")

    print("PASS: replay_safety")
except Exception as e:                       # noqa: BLE001
    fail(f"unexpected: {e}")
