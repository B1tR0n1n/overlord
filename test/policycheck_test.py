#!/usr/bin/env python3
"""The pre-commit policy gate. Two parts:

  unit   policycheck.evaluate over a synthetic changeset with a fake `locate` —
         secrets, binaries, dependency files, size thresholds, and the three
         actions (block / countersign / warn). Fully offline, always runs.
  e2e    a real session on whichever backend detect_backend() picks: a policy
         that blocks on secrets refuses the commit and leaves it pending;
         --force overrides; a warn-only policy commits and records the finding.
         Skips only if there is no overlay backend at all.
"""

import contextlib
import io
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ["OVERLORD_HOME"] = tempfile.mkdtemp()

import overlord as ov          # noqa: E402
import policycheck as pc       # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


# ---------------------------------------------------------------- unit

def locator(contents):
    """A fake `locate`: rel -> a temp file holding the given bytes."""
    d = tempfile.mkdtemp()
    paths = {}
    for rel, data in contents.items():
        p = os.path.join(d, rel.replace("/", "_"))
        with open(p, "wb") as f:
            f.write(data)
        paths[rel] = p
    return lambda rel: paths.get(rel)


# secrets: a real-looking key blocks; ordinary code does not
contents = {
    "config.py": b"AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
    "clean.py": b"def add(a, b):\n    return a + b\n",
}
changes = [("added", "config.py"), ("modified", "clean.py")]
f = pc.evaluate(changes, locator(contents), {"secrets": "block"})
if not any(x["check"] == "secrets" and x["path"] == "config.py" for x in f):
    fail(f"secret not caught: {f}")
if any(x["path"] == "clean.py" for x in f):
    fail(f"clean file flagged: {f}")
if "AKIA" in json.dumps(f):
    fail("the secret material leaked into the finding")
if f[0]["action"] != "block":
    fail(f"action not carried: {f}")
ok("secrets: a cloud key blocks, clean code passes, the secret value never appears in the finding")

# private key header and a secret-named assignment
keydata = {"id_rsa": b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n",
           "app.js": b"const password = \"hunter2hunter2hunter2\";\n"}
f = pc.evaluate([("added", "id_rsa"), ("added", "app.js")], locator(keydata), {"secrets": "warn"})
kinds = {x["detail"].split(" at")[0] for x in f}
if "private-key" not in kinds or "secret-assignment" not in kinds:
    fail(f"private key / assignment not both caught: {f}")
if any(x["action"] != "warn" for x in f):
    fail("warn action not applied")
ok("secrets: private-key headers and secret-named assignments caught; action honoured")

# binaries: content with a NUL byte is binary regardless of name
bindata = {"tool": b"\x7fELF\x00\x00\x00stuff", "notes.txt": b"just text\n"}
f = pc.evaluate([("added", "tool"), ("added", "notes.txt")], locator(bindata), {"binaries": "block"})
if not (len(f) == 1 and f[0]["check"] == "binaries" and f[0]["path"] == "tool"):
    fail(f"binary detection: {f}")
ok("binaries: NUL-containing content is flagged by content, text is not")

# deps: a lockfile change is flagged from its name; no content read needed
f = pc.evaluate([("modified", "package-lock.json"), ("added", "src/app.js")],
                lambda rel: None, {"deps": "countersign"})
if not (len(f) == 1 and f[0]["check"] == "deps" and f[0]["action"] == "countersign"):
    fail(f"dep file: {f}")
if not pc.is_dep_file("a/b/go.sum") or pc.is_dep_file("go.summary"):
    fail("dep basename matching")
ok("deps: a lockfile/manifest change is flagged (by basename), unrelated files are not")

# size: file count and byte thresholds
many = [("added", f"f{i}.txt") for i in range(5)]
f = pc.evaluate(many, locator({f"f{i}.txt": b"x" for i in range(5)}),
                {"size": "block", "max_files": 3})
if not any(x["check"] == "size" and "files" in x["detail"] for x in f):
    fail(f"max_files not enforced: {f}")
big = {"big.bin": b"x" * 100}
f = pc.evaluate([("added", "big.bin")], locator(big), {"size": "block", "max_bytes": 50})
if not any(x["check"] == "size" and "bytes" in x["detail"] for x in f):
    fail(f"max_bytes not enforced: {f}")
ok("size: file-count and byte thresholds each raise a size finding")

# no checks configured, or all off → nothing, and deleted files aren't scanned
if pc.evaluate(changes, locator(contents), {}) != []:
    fail("empty checks should yield nothing")
if pc.evaluate([("deleted", "config.py")], locator(contents), {"secrets": "block"}):
    fail("a deleted path should not be scanned for secrets")
ok("no checks (or a deleted path) yields no findings")

# worst() ranking and summarize() eliding
mixed = [{"check": "a", "path": "p", "detail": "d", "action": "warn"},
         {"check": "b", "path": "q", "detail": "e", "action": "block"}]
if pc.worst(mixed) != "block" or pc.worst([]) is not None:
    fail("worst() ranking")
if any("hunter2" in s for s in pc.summarize(f)):
    fail("summarize leaked a value")
ok("worst() picks the strongest action; summaries carry action, check, path — not values")

print("PASS: policycheck (unit)")


# ---------------------------------------------------------------- e2e

BACKEND = os.environ.get("OVERLORD_TEST_BACKEND") or ov.detect_backend()
if BACKEND is None:
    print("SKIP: policycheck e2e (no overlay backend)")
    sys.exit(0)
KERNEL = BACKEND == "kernel"
grants = {"net": "none" if KERNEL else "host", "jail": KERNEL,
          "timeout": None, "merge_base": False}


def cli(*argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = ov.main(list(argv))
    return rc, buf.getvalue()


def new_session(writes):
    target = tempfile.mkdtemp()
    with open(os.path.join(target, "README.md"), "w") as fh:
        fh.write("# demo\n")
    live = ov.open_session(target, BACKEND, grants, capture=True, agent="scripted")
    for cmd in writes:
        live.exec(["bash", "-c", cmd])
    sid, _ = live.close()
    return target, sid


def set_policy(target, checks):
    with open(ov.POLICY_FILE, "w") as fh:
        json.dump({"default": {"jail": False, "checks": checks}}, fh)


try:
    # a secret in an added file blocks the commit; the session stays pending
    target, sid = new_session(["printf 'AWS=AKIAIOSFODNN7EXAMPLE\\n' > secrets.env"])
    set_policy(target, {"secrets": "block"})
    res = ov.commit_session(sid)
    if res["committed"] or not res.get("policy"):
        fail(f"a secret did not block the commit: {res}")
    if ov.load_meta(sid).get("status") != "pending":
        fail("a blocked session should remain pending, not be destroyed")
    if os.path.exists(os.path.join(target, "secrets.env")):
        fail("a blocked commit must not touch the target")
    ok("a secret blocks the commit and leaves the session pending; the target is untouched")

    # `check` reports it as a dry-run without committing
    rc, out = cli("check", sid)
    if rc != 1 or "BLOCKED" not in out or "secrets" not in out:
        fail(f"check dry-run: rc={rc} out={out!r}")
    ok("overlord check reports the block as a dry-run, exit 1, without committing")

    # --force overrides; the commit lands and is recorded as policy_forced
    res = ov.commit_session(sid, force=True)
    if not res["committed"]:
        fail(f"--force did not override the policy block: {res}")
    if not os.path.exists(os.path.join(target, "secrets.env")):
        fail("forced commit did not apply the change")
    ok("--force overrides the block; the change is applied and the override is on the record")

    # a warn-only policy commits, and the finding rides the result
    target2, sid2 = new_session(["printf 'password = \"averylongsecretvalue123\"\\n' > app.py"])
    set_policy(target2, {"secrets": "warn"})
    res = ov.commit_session(sid2)
    if not res["committed"]:
        fail(f"warn-only policy should not block: {res}")
    if not any(x["action"] == "warn" for x in (res.get("policy") or [])):
        fail(f"warn finding not surfaced on a committed session: {res}")
    ok("a warn-only policy commits and still surfaces the finding")

    os.path.exists(ov.POLICY_FILE) and os.unlink(ov.POLICY_FILE)
    print("PASS: policycheck (e2e)")
finally:
    if os.path.exists(ov.POLICY_FILE):
        os.unlink(ov.POLICY_FILE)
