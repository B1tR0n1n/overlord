#!/usr/bin/env python3
"""Countersignature + forks e2e: a second model reviews a pending session's
diff through a read-only tool and signs it approve/reject; the verdict is
bound to a fingerprint of the diff, so rewind or a selective commit makes it
stale; a fresh rejection blocks commit and --countersigned demands a fresh
approval; the reviewer must be a different model; policy can require it
through the daemon. Forks copy a stack up to a savepoint into a new pending
session (whiteouts and transcript cut intact); compare shows where two
continuations diverge; committing one leaves the other conflicting."""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "sdk"))
os.environ["OVERLORD_HOME"] = tempfile.mkdtemp()

import overlord as ov          # noqa: E402
import agent                   # noqa: E402
import review                  # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


def cli(*argv):
    buf, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
        rc = ov.main(list(argv))
    return rc, buf.getvalue() + err.getvalue()


def read(path):
    with open(path) as f:
        return f.read()


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def scripted(script, model="scripted"):
    p = agent.ScriptedProvider(script)
    p.model = model
    return p


def events_of(sid, name="transcript.jsonl"):
    with open(os.path.join(ov.session_path(sid), name)) as f:
        return [json.loads(line) for line in f if line.strip()]


BACKEND = os.environ.get("OVERLORD_TEST_BACKEND") or ov.detect_backend()
if BACKEND is None:
    print("SKIP: review_fork (no sandbox backend here — see `overlord doctor`)")
    sys.exit(0)
KERNEL = BACKEND == "kernel"
if BACKEND is None:
    print("SKIP: no overlay backend")
    sys.exit(0)
grants = {"net": "none" if KERNEL else "host", "jail": KERNEL,
          "timeout": None, "merge_base": False}
home = os.environ["OVERLORD_HOME"]
target = tempfile.mkdtemp()
write(f"{target}/lib.py", "def a():\n    return 1\n")
write(f"{target}/README.md", "# demo\n")

LIB2 = "def a():\n    return 1\n\n\ndef greet():\n    return 'hi'\n"
REJECT = [{"tool_calls": [{"name": "read_file", "input": {"path": "lib.py"}},
                          {"name": "read_file", "input": {"path": "/etc/passwd"}}]},
          {"text": "The agent wrote a credential file.", "tool_calls": [
              {"name": "reject", "input": {"reason": ".env holds a secret the task never asked for",
                                           "paths": [".env"]}}]}]
APPROVE = [{"tool_calls": [{"name": "read_file", "input": {"path": "."}}]},
           {"tool_calls": [{"name": "approve", "input": {"reason": "greet() as asked"}}]}]

try:
    # ------------------------------------------------------------ session A
    script = [
        {"text": "Adding greet.", "tool_calls": [{"name": "write_file",
                                                  "input": {"path": "lib.py", "content": LIB2}}]},
        {"tool_calls": [{"name": "shell", "input": {"command": "echo secret > .env; rm README.md"}}]},
        {"text": "Done."}]
    live = ov.open_session(target, BACKEND, grants, capture=True, agent="scripted")
    agent.run_agent(live, scripted(script), "add greet()", max_turns=5)
    A, changes_a = live.close()
    if set(changes_a) != {("modified", "lib.py"), ("added", ".env"), ("deleted", "README.md")}:
        fail(f"session A: {changes_a}")

    # ------------------------------------------------------------ forks first (A must stay pending)
    B = ov.fork_session(A, 0)
    C = ov.fork_session(A)
    mb, mc, ma = ov.load_meta(B), ov.load_meta(C), ov.load_meta(A)
    if mb["forked_from"] != {"session": A, "at": 0, "ts": mb["forked_from"]["ts"]} or \
            len(mb["layers"]) != 1 or [e["layer"] for e in mb["execs"]] != [0]:
        fail(f"fork B record: {mb.get('forked_from')} {len(mb['layers'])} {mb['execs']}")
    if ov.session_stack(B)[0] != [("modified", "lib.py")]:
        fail(f"fork B stack: {ov.session_stack(B)[0]}")
    kinds = [e["type"] for e in events_of(B)]
    if kinds.count("tool_result") != 1 or "rewind" not in kinds or \
            any(e.get("turn", 0) > 1 for e in events_of(B) if e["type"] != "rewind"):
        fail(f"fork B transcript: {kinds}")
    if set(ov.session_stack(C)[0]) != set(changes_a) or mc["forked_from"]["at"] != 1:
        fail("full fork C does not reproduce A's stack (whiteouts included)")
    if len(ma["layers"]) != 2 or [f["session"] for f in ma["forks"]] != [B, C] or \
            [e["type"] for e in events_of(A)].count("tool_result") != 2:
        fail("forking altered the original")
    if read(os.path.join(ov.session_path(B), "manifest.json")) != \
            read(os.path.join(ov.session_path(A), "manifest.json")):
        fail("fork did not inherit the snapshot manifest")
    try:
        ov.fork_session(A, 5)
        fail("fork past the stack accepted")
    except ov.OverlordError:
        pass
    ok("fork: stack copied to a savepoint, transcript cut, snapshot shared, original untouched")

    # ------------------------------------------------------------ review A: independence
    try:
        review.run_review(A, scripted(REJECT))          # scripted:scripted == the agent
        fail("same-model reviewer accepted")
    except ov.OverlordError as e:
        if "second model" not in str(e):
            fail(f"independence error text: {e}")
    rec = review.run_review(A, scripted(REJECT), allow_same=True)
    if not rec["same_model"] or rec["verdict"] != "reject":
        fail(f"--same-model override: {rec}")
    ok("reviewer must be a different model; --same-model overrides and is recorded")

    # ------------------------------------------------------------ review A: reject binds
    p = scripted(REJECT, model="reviewer-1")
    rec = review.run_review(A, p)
    dossier = p.seen[0][0]["content"]
    for needle in ("TASK: add greet()", "+def greet", ".env", "GRANTS:", "MANIFEST (3",
                   "turn 2 shell: echo secret", "-# demo"):
        if needle not in dossier:
            fail(f"dossier lacks {needle!r}:\n{dossier[:1500]}")
    tool_msgs = [m for m in p.seen[1] if m["role"] == "tool"]
    if "def greet" not in tool_msgs[0]["content"] or "relative" not in tool_msgs[1]["content"]:
        fail(f"read_file results: {[m['content'][:60] for m in tool_msgs]}")
    if rec["verdict"] != "reject" or rec["paths"] != [".env"] or rec["reviewer"] != "scripted:reviewer-1":
        fail(f"reject record: {rec}")
    rl = events_of(A, "review.jsonl")
    if [e["type"] for e in rl][-1] != "verdict" or rl[-1]["fingerprint"] != rec["fingerprint"]:
        fail("review.jsonl incomplete")
    if len(ov.load_meta(A)["reviews"]) != 2:
        fail("every verdict must be kept")
    res = ov.commit_session(A)
    if res["committed"] or res.get("rejected", {}).get("reviewer") != "scripted:reviewer-1":
        fail(f"fresh rejection did not block commit: {res}")
    try:
        ov.commit_session(A, countersigned=True)
        fail("--countersigned accepted a rejection")
    except ov.OverlordError as e:
        if "rejected" not in str(e):
            fail(f"countersigned error text: {e}")
    rc, out = cli("commit", A)
    if rc != 1 or "rejected by scripted:reviewer-1" not in out:
        fail(f"commit CLI refusal: {rc} {out}")
    rc, out = cli("sessions")
    if f"{A}" not in out or "[rejected]" not in out:
        fail(f"sessions row lacks the verdict: {out}")
    ok("reject: the dossier shows the diff, read_file is read-only, a fresh rejection blocks commit")

    # ------------------------------------------------------------ review A: approve via CLI, stale by selection
    spath = os.path.join(home, "approve.json")
    with open(spath, "w") as f:
        json.dump(APPROVE, f)
    env = dict(os.environ, OVERLORD_REVIEW_SCRIPT=spath)
    base = [sys.executable, os.path.join(HERE, "overlord.py")]
    r = subprocess.run(base + ["review", A, "--provider", "scripted", "--model", "reviewer-2"],
                       env=env, capture_output=True, text=True)
    if r.returncode != 0 or "APPROVED by scripted:reviewer-2" not in r.stdout or \
            "greet() as asked" not in r.stdout:
        fail(f"review CLI: {r.returncode} {r.stdout} {r.stderr}")
    rev, fresh = review.review_state(A)
    if rev["verdict"] != "approve" or not fresh:
        fail("approval not fresh right after signing")
    try:
        ov.commit_session(A, drop="1", countersigned=True)
        fail("a selective commit reused a signature over the full diff")
    except ov.OverlordError as e:
        if "stale" not in str(e):
            fail(f"stale error text: {e}")
    r = subprocess.run(base + ["commit", "--countersigned", A], env=env,
                       capture_output=True, text=True)
    if r.returncode != 0 or "(countersigned)" not in r.stdout:
        fail(f"countersigned commit CLI: {r.stdout} {r.stderr}")
    ma = ov.load_meta(A)
    if not ma["countersigned"] or read(f"{target}/lib.py") != LIB2 or os.path.exists(f"{target}/README.md"):
        fail("countersigned commit did not apply")
    ok("approve: fresh signature commits with --countersigned; a different selection is stale")

    # ------------------------------------------------------------ fork B continues, compare, stale by rewind
    cont = [{"tool_calls": [{"name": "write_file", "input": {
                "path": "lib.py", "content": LIB2 + "\n\ndef bye():\n    return 'bye'\n"}}]},
            {"text": "done"}]
    live = ov.reopen_session(B, capture=True)
    agent.run_agent(live, scripted(cont), "add greet()", max_turns=5, resume=True, note="add bye()")
    sid, changes_b = live.close()
    if sid != B or changes_b != [("modified", "lib.py")] or len(ov.load_meta(B)["layers"]) != 2:
        fail(f"resume on the fork: {changes_b}")
    rows = {r["path"]: r["state"] for r in ov.compare_sessions(B, C)}
    # A's commit already removed README.md, so C's whiteout of it is now a no-op
    if rows != {"lib.py": "differ", ".env": "only-b"}:
        fail(f"compare B C: {rows}")
    rc, out = cli("compare", B, C)
    if rc != 0 or "differ   lib.py" not in out or "only-b   .env" not in out:
        fail(f"compare CLI: {out}")
    try:
        ov.compare_sessions(A, B)
        fail("compare accepted a committed session")
    except ov.OverlordError:
        pass
    rec = review.run_review(B, scripted(APPROVE, model="reviewer-2"))
    if rec["verdict"] != "approve" or not review.review_state(B)[1]:
        fail("fork B approval")
    ov.rewind_session(B, 0)
    rev, fresh = review.review_state(B)
    if fresh:
        fail("approval survived a rewind")
    try:
        ov.commit_session(B, countersigned=True)
        fail("stale approval satisfied --countersigned")
    except ov.OverlordError as e:
        if "stale" not in str(e):
            fail(f"stale-after-rewind text: {e}")
    res = ov.commit_session(B)
    if res["committed"] or ("modified-externally", "lib.py") not in res["conflicts"]:
        fail(f"committing a fork after its origin committed must conflict: {res}")
    if read(f"{target}/lib.py") != LIB2:
        fail("refused fork commit touched the tree")
    ov.rollback_session(B)
    ov.rollback_session(C)
    ok("forks continue independently; compare shows divergence; the loser's commit conflicts")

    # ------------------------------------------------------------ daemon: policy require_review, fork, compare
    from overlord_client import OverlordClient, OverlordError
    with open(ov.POLICY_FILE, "w") as f:
        json.dump({"default": {"require_review": True, "allow_force": False}}, f)
    agent_script = os.path.join(home, "agent.json")
    with open(agent_script, "w") as f:
        json.dump([{"tool_calls": [{"name": "write_file",
                                    "input": {"path": "d.txt", "content": "d\n"}}]},
                   {"text": "done"}], f)
    env = dict(os.environ, OVERLORD_AGENT_SCRIPT=agent_script, OVERLORD_REVIEW_SCRIPT=spath)
    sock = os.path.join(home, "overlordd.sock")
    daemon = subprocess.Popen(base + ["daemon", "--socket", sock], env=env,
                              stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if os.path.exists(sock):
                break
            time.sleep(0.1)
        c = OverlordClient(sock, timeout=60)
        kw = {"jail": KERNEL, "net": "none" if KERNEL else "host"}
        s = c.agent(target, "write d", provider="scripted", **kw)
        try:
            s.commit()
            fail("policy require_review did not bind")
        except OverlordError as e:
            if "countersignature" not in str(e):
                fail(f"policy refusal text: {e}")
        try:
            s.review(provider="scripted")            # same model as the agent
            fail("daemon accepted a same-model reviewer")
        except OverlordError:
            pass
        e = c.fork(s.sid)
        if e.sid == s.sid or set(e.changes) != {("added", "d.txt")}:
            fail(f"sdk fork: {e}")
        if [r["state"] for r in c.compare(s.sid, e.sid)] != ["same"]:
            fail("sdk compare of an untouched fork")
        seen = []
        rec = s.review(provider="scripted", model="reviewer-2", on_event=seen.append)
        if rec["verdict"] != "approve" or "verdict" not in [x.get("type") for x in seen]:
            fail(f"sdk review: {rec} {[x.get('type') for x in seen]}")
        res = s.commit()
        if not res["committed"] or read(f"{target}/d.txt") != "d\n":
            fail("policy-required review, once fresh, did not let the commit through")
        e.rollback()
        ok("daemon: policy require_review binds; review, fork and compare over the socket")
    finally:
        daemon.terminate()
        daemon.wait()

    print(f"PASS: countersignature + forks ({BACKEND} backend)")
finally:
    subprocess.run(["rm", "-rf", home, target])
