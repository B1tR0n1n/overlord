#!/usr/bin/env python3
"""The executor-facing surface an external orchestrator (a console, a
remediation loop) drives OVERLORD through:

  revert     a COMMITTED session's inverse is staged as a new reviewable
             session, from provenance + retained before-content; committing
             it makes the tree byte-identical to before. Refuses (or, with
             force, skips) a path whose before-content was not retained.
  cause      an exec's `cause` object rides the daemon/SDK and lands as
             `caused_by` on provenance — a plan step names itself.
  grants     net_allow / limits pass through the SDK to the broker.
  audit      namespaced external events join the keyed chain via the daemon;
             engine namespaces and reserved fields are refused.
  complete   one tool-less model call, audited with prompt/output hashes.

Runs on whichever backend detect_backend() picks; skips with none."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "sdk"))
HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = HOME
os.environ.pop("OVERLORD_NO_SYSTEMD", None)

import overlord as ov                                   # noqa: E402
import audit as audit_mod                               # noqa: E402
from overlord_client import OverlordClient, OverlordError  # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


def read(p):
    with open(p) as f:
        return f.read()


def write(p, text):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(text)


BACKEND = os.environ.get("OVERLORD_TEST_BACKEND") or ov.detect_backend()
if BACKEND is None:
    print("SKIP: executor (no overlay backend)")
    sys.exit(0)
KERNEL = BACKEND == "kernel"
grants = {"net": "none" if KERNEL else "host", "jail": KERNEL, "timeout": None, "merge_base": False}


def session(target, cmds):
    live = ov.open_session(target, BACKEND, grants, capture=True)
    for c in cmds:
        live.exec(["bash", "-c", c])
    sid, _ = live.close()
    return sid


# ---------------------------------------------------------------- revert (in-process)

target = tempfile.mkdtemp()
write(f"{target}/a.txt", "A\n")
write(f"{target}/b.txt", "B\n")
write(f"{target}/sub/c.txt", "C\n")
before = {"a.txt": "A\n", "b.txt": "B\n", "sub/c.txt": "C\n"}

sid = session(target, ["echo A2 > a.txt", "rm b.txt", "echo N > new.txt",
                       "mkdir newdir && echo X > newdir/x.txt"])
if not ov.commit_session(sid)["committed"]:
    fail("setup commit")
if read(f"{target}/a.txt") != "A2\n" or os.path.exists(f"{target}/b.txt") \
        or not os.path.exists(f"{target}/newdir/x.txt"):
    fail("setup did not land")

# a pending session cannot be reverted, only rolled back
pend = session(target, ["echo tmp > tmp.txt"])
try:
    ov.revert_session(pend)
    fail("revert accepted a pending session")
except ov.OverlordError as e:
    if "not committed" not in str(e):
        fail(f"wrong refusal: {e}")
ov.rollback_session(pend)
ok("revert refuses a pending session (that is rollback's job)")

res = ov.revert_session(sid)
kinds = {rel: kind for kind, rel in res["changes"]}
if ov.load_meta(res["sid"]).get("status") != "pending":
    fail("the revert is not staged as a pending session")
if kinds.get("a.txt") != "modified" or kinds.get("b.txt") != "added" \
        or kinds.get("new.txt") != "deleted" \
        or not (kinds.get("newdir") == "deleted" or kinds.get("newdir/x.txt") == "deleted"):
    fail(f"inverse diff is wrong: {res['changes']}")
if read(f"{target}/a.txt") != "A2\n":
    fail("staging the revert touched the tree")
if ov.load_meta(res["sid"]).get("revert_of") != sid:
    fail("revert session does not name what it reverts")
ok("revert stages the exact inverse as a pending session; the tree is untouched until commit")

# the layer carries the cause; provenance says why each path changed
prov = [json.loads(x) for x in open(ov.session_file(res["sid"], ov.PROVENANCE_FILE))]
layered = [r for r in prov if "layer" in r]
if not layered or not all(r.get("caused_by") == {"revert_of": sid} for r in layered):
    fail(f"revert provenance lacks caused_by: {prov}")
ok("every reverted path's provenance is caused_by {revert_of: <sid>}")

if not ov.commit_session(res["sid"])["committed"]:
    fail("committing the revert failed")
after = {}
for root, _d, files in os.walk(target):
    for fn in files:
        p = os.path.join(root, fn)
        after[os.path.relpath(p, target)] = read(p)
if after != before:
    fail(f"tree after revert != before: {after}")
if os.path.isdir(f"{target}/newdir"):
    fail("an added directory survived the revert")
ok("committing the revert makes the tree byte-identical to before; added dirs are removed")

acts = [e["action"] for e in audit_mod.entries(n=50)]
if "session.revert" not in acts:
    fail(f"no session.revert on the audit chain: {acts}")
ok("session.revert is on the audit chain")

# a before-object that was never retained (over OBJECT_MAX) refuses, force skips
write(f"{target}/big.txt", "x" * 64)
saved = ov.OBJECT_MAX
ov.OBJECT_MAX = 16
try:
    sid2 = session(target, ["echo small > a.txt", "echo y > big.txt"])
    ov.commit_session(sid2)
finally:
    ov.OBJECT_MAX = saved
try:
    ov.revert_session(sid2)
    fail("revert proceeded with an unrecoverable path")
except ov.OverlordError as e:
    if "big.txt" not in str(e):
        fail(f"refusal does not name the path: {e}")
res = ov.revert_session(sid2, force=True, commit=True)
if not res["committed"] or [r for r, _w in res["skipped"]] != ["big.txt"]:
    fail(f"forced revert: {res}")
if read(f"{target}/a.txt") != "A\n" or read(f"{target}/big.txt") != "y\n":
    fail("forced revert restored the wrong set")
ok("a path with no retained before-content refuses the revert; --force skips it and --commit lands the rest")

# engine: removing a directory is committable (the manifest holds files, so a
# deleted dir is validated as a subtree, like a replaced dir); a file that
# appeared beneath it after the snapshot is a conflict, not silently lost
write(f"{target}/old/one.txt", "1\n")
write(f"{target}/old/two.txt", "2\n")
s3 = session(target, ["rm -r old"])
if not ov.commit_session(s3)["committed"] or os.path.exists(f"{target}/old"):
    fail("rm -r of a directory did not commit")
# ...and it is reversible: every file beneath the deleted dir was retained and
# recorded, so revert rebuilds it; an emptied directory comes back too
prov3 = [json.loads(x) for x in open(ov.session_file(s3, ov.PROVENANCE_FILE))]
subs = sorted(r["path"] for r in prov3 if r.get("under") == "old")
if subs != ["old/one.txt", "old/two.txt"] or not all(r.get("before_retained") for r in prov3 if "under" in r):
    fail(f"files under a deleted dir were not retained/recorded: {prov3}")
os.makedirs(f"{target}/emptyd")
s3b = session(target, ["rmdir emptyd"])
ov.commit_session(s3b)
r3 = ov.revert_session(s3, commit=True)
r3b = ov.revert_session(s3b, commit=True)
if not (r3["committed"] and r3b["committed"]) or read(f"{target}/old/one.txt") != "1\n" \
        or read(f"{target}/old/two.txt") != "2\n" or not os.path.isdir(f"{target}/emptyd"):
    fail(f"revert of a deleted directory: {r3} {r3b}")
ok("rm -r of a directory is reversible: its files are retained at commit and revert rebuilds it (empty dirs too)")
write(f"{target}/gone/keep.txt", "k\n")
s4 = session(target, ["rm -r gone"])
write(f"{target}/gone/late.txt", "late\n")          # appears after the snapshot
r4 = ov.commit_session(s4)
if r4["committed"] or ("appeared-after-snapshot", "gone/late.txt") not in [tuple(c) for c in r4["conflicts"]]:
    fail(f"external file under a deleted dir was not a conflict: {r4}")
ov.rollback_session(s4)
ok("removing a directory commits; a file that appeared beneath it after the snapshot is a conflict")

print("PASS: executor (revert)")


# ---------------------------------------------------------------- daemon surface

SOCK = os.path.join(HOME, "d.sock")
script = os.path.join(HOME, "script.json")
with open(script, "w") as f:
    json.dump([{"text": "PLAN: restart_service app-1", "usage": {"in": 7, "out": 3}}], f)
env = dict(os.environ, OVERLORD_AGENT_SCRIPT=script)
daemon = subprocess.Popen([sys.executable, os.path.join(HERE, "overlord.py"), "daemon",
                           "--socket", SOCK], env=env, stderr=subprocess.DEVNULL)
try:
    cli = OverlordClient(SOCK, timeout=60)
    for _ in range(100):
        if os.path.exists(SOCK):
            break
        time.sleep(0.1)
    cli.ping()

    # grants pass through to the broker and come back effective
    t2 = tempfile.mkdtemp()
    write(f"{t2}/README.md", "hi\n")
    ls = cli.open(t2, jail=KERNEL, net="none" if KERNEL else "host",
                  net_allow=["example.com", "*.pypi.org"], limits={"pids": 50})
    if ls.grants.get("net_allow") != ["example.com", "*.pypi.org"] \
            or (ls.grants.get("limits") or {}).get("pids") != 50:
        fail(f"grants did not pass through: {ls.grants}")
    ok("net_allow and limits pass through the SDK to the broker's effective grants")

    # cause rides exec and lands on provenance
    cause = {"plan_id": "plan-1", "step_id": "s1", "action_id": "restart_service"}
    rc, out, _ = ls.exec(["bash", "-c", "echo done > step.txt"], label="plan-1/s1", cause=cause)
    if rc != 0:
        fail(f"exec: {rc} {out}")
    sess = ls.close()
    prov = cli._call("log", sid=sess.sid)["provenance"]
    rec = next((r for r in prov if r["path"] == "step.txt"), None)
    if not rec or rec.get("caused_by") != cause:
        fail(f"cause did not reach provenance: {prov}")
    ok("an exec's cause object lands as caused_by on the path's provenance record")

    # external events join the keyed chain; engine namespaces and reserved fields are refused
    entry = cli.audit("receipt.step", plan_id="plan-1", step_id="s1", status="ok")
    if entry.get("action") != "receipt.step" or entry.get("via") != "daemon" \
            or not entry.get("hash") or not entry.get("seq"):
        fail(f"audit entry: {entry}")
    for bad in (("session.commit", {}), ("receipt.step", {"hash": "z"}), ("Receipt.Step", {})):
        try:
            cli.audit(bad[0], **bad[1])
            fail(f"audit accepted {bad}")
        except OverlordError:
            pass
    head = cli.audit_head()
    if head["seq"] < entry["seq"] or not head["hash"]:
        fail(f"head: {head}")
    v = audit_mod.verify()
    if not v.get("ok") or not v.get("keyed"):
        fail(f"chain broken after external append: {v}")
    ok("receipt.* events append to the keyed chain via the daemon; engine names and reserved fields refused; chain verifies")

    # one tool-less model call, audited with hashes
    r = cli.complete("Propose a plan for finding F1", system="You only propose.",
                     provider="scripted", purpose="planner")
    if r["text"] != "PLAN: restart_service app-1" or r["provider"] != "scripted":
        fail(f"complete: {r}")
    if r["output_sha256"] != hashlib.sha256(r["text"].encode()).hexdigest():
        fail("output hash mismatch")
    mc = [e for e in audit_mod.entries(n=50, action="model.complete")]
    if not mc or mc[-1].get("purpose") != "planner" or mc[-1].get("output_sha256") != r["output_sha256"]:
        fail(f"model.complete not audited with hashes: {mc[-1:] }")
    ok("complete() runs one tool-less model call and audits it with prompt/output hashes")

    # revert over the socket (settle the pending step session first)
    if not sess.commit()["committed"]:
        fail("could not commit the step session")
    s = cli.run(t2, ["bash", "-c", "echo v2 > README.md"], jail=KERNEL,
                net="none" if KERNEL else "host")
    s.commit()
    rv = cli.revert(s.sid)
    if ov.load_meta(rv["sid"]).get("status") != "pending" or rv["reverted"] != s.sid:
        fail(f"daemon revert: {rv}")
    cli._call("rollback", sid=rv["sid"])
    ok("revert is brokered over the socket and returns the staged session")

    print("PASS: executor (daemon)")
finally:
    daemon.terminate()
    try:
        daemon.wait(timeout=10)
    except subprocess.TimeoutExpired:
        daemon.kill()
    subprocess.run(["rm", "-rf", HOME, target])
