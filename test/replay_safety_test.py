#!/usr/bin/env python3
"""Focused regressions for safe upper-layer replay and drift checks."""

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import overlord


class ReplaySafetyTest(unittest.TestCase):
    def test_apply_upper_rejects_symlink_escape_before_replay(self):
        with tempfile.TemporaryDirectory() as work:
            upper = os.path.join(work, "upper")
            target = os.path.join(work, "target")
            outside = os.path.join(work, "outside")
            os.makedirs(os.path.join(upper, "escape"))
            os.makedirs(target)
            os.makedirs(outside)
            with open(os.path.join(upper, "before.txt"), "w") as f:
                f.write("must not be replayed")
            with open(os.path.join(upper, "escape", "payload.txt"), "w") as f:
                f.write("outside")
            os.symlink(outside, os.path.join(target, "escape"))

            with self.assertRaises(overlord.OverlordError):
                overlord.apply_upper(upper, target)

            self.assertFalse(os.path.exists(os.path.join(target, "before.txt")))
            self.assertFalse(os.path.exists(os.path.join(outside, "payload.txt")))

    def test_root_whiteout_is_rejected(self):
        with tempfile.TemporaryDirectory() as upper:
            with self.assertRaises(overlord.OverlordError):
                overlord._victim_rel(os.path.join(upper, ".wh."), upper)

    def test_apply_upper_replaces_leaf_symlink_without_following_it(self):
        with tempfile.TemporaryDirectory() as work:
            upper = os.path.join(work, "upper")
            target = os.path.join(work, "target")
            outside = os.path.join(work, "outside.txt")
            os.makedirs(upper)
            os.makedirs(target)
            with open(outside, "w") as f:
                f.write("outside")
            with open(os.path.join(upper, "leaf.txt"), "w") as f:
                f.write("replayed")
            os.symlink(outside, os.path.join(target, "leaf.txt"))

            overlord.apply_upper(upper, target)

            self.assertFalse(os.path.islink(os.path.join(target, "leaf.txt")))
            with open(os.path.join(target, "leaf.txt")) as f:
                self.assertEqual("replayed", f.read())
            with open(outside) as f:
                self.assertEqual("outside", f.read())

    def test_added_directory_conflicts_with_regular_file(self):
        with tempfile.TemporaryDirectory() as target:
            with open(os.path.join(target, "new-dir"), "w") as f:
                f.write("external")
            self.assertEqual(
                [("created-externally", "new-dir/")],
                overlord._added_conflicts("new-dir/", {}, target),
            )

    def test_replaced_directory_detects_new_descendant(self):
        with tempfile.TemporaryDirectory() as target:
            replaced = os.path.join(target, "replaced")
            os.makedirs(replaced)
            original = os.path.join(replaced, "original.txt")
            with open(original, "w") as f:
                f.write("original")
            manifest = {"replaced/original.txt": overlord._fingerprint(original)}
            with open(os.path.join(replaced, "external.txt"), "w") as f:
                f.write("external")

            self.assertIn(
                ("appeared-after-snapshot", "replaced/external.txt"),
                overlord._replaced_dir_conflicts("replaced", manifest, target),
            )


if __name__ == "__main__":
    unittest.main()
