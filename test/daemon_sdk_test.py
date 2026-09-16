#!/usr/bin/env python3
"""Daemon + SDK + policy e2e: broker a full session lifecycle over the socket,
prove policy caps bind, prove unlisted targets are refused."""

import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(HERE, "sdk"))

OVERLORD_HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = OVERLORD_HOME
SOCK = os.path.join(OVERLORD_HOME, "overlordd.sock")

from overlord_client import OverlordClient, OverlordError  # noqa: E402
sys.path.insert(1, HERE)
import overlord as _core  # noqa: E402
if _core.detect_backend() is None:
    print("SKIP: daemon_sdk (no sandbox backend here — see `overlord doctor`)")
    sys.exit(0)


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


target = tempfile.mkdtemp()
with open(os.path.join(target, "app.conf"), "w") as f:
    f.write("v1\n")

daemon = subprocess.Popen(
    [sys.executable, os.path.join(HERE, "overlord.py"), "daemon", "--socket", SOCK],
    env=os.environ.copy(), stderr=subprocess.DEVNULL,
)
try:
    ov = OverlordClient(SOCK, timeout=60)
    for _ in range(50):
        if os.path.exists(SOCK):
            break
        time.sleep(0.1)

    # 1. ping
    if "version" not in ov.ping():
        fail("ping")
    ok("ping")

    # 2. brokered transactional run: changes visible, target untouched
    s = ov.run(target, ["bash", "-c", "echo v2 > app.conf; echo hello-sdk"])
    if s.exit_code != 0 or ("modified", "app.conf") not in s.changes:
        fail(f"run: exit={s.exit_code} changes={s.changes}")
    if "hello-sdk" not in s.output_tail:
        fail("captured output missing")
    if open(os.path.join(target, "app.conf")).read() != "v1\n":
        fail("target mutated before commit")
    ok("brokered run + output capture + isolation")

    # 3. provenance over the wire
    if not any(r["path"] == "app.conf" and r.get("after_sha256") for r in s.log()):
        fail("provenance over socket")
    ok("provenance over socket")

    # 4. commit through the SDK
    s.commit()
    if open(os.path.join(target, "app.conf")).read() != "v2\n":
        fail("commit did not apply")
    ok("sdk commit")

    # 5. policy: timeout cap binds even when the caller asks for none
    with open(os.path.join(OVERLORD_HOME, "policy.json"), "w") as f:
        json.dump({"default": {"timeout": 1}}, f)
    s = ov.run(target, ["sleep", "30"])
    if s.exit_code != 124:
        fail(f"policy timeout not enforced (exit={s.exit_code})")
    if s.grants.get("timeout") != 1:
        fail("effective grants do not show policy cap")
    s.rollback()
    ok("policy timeout cap")

    # 6. policy: unlisted target refused when no default rule exists
    with open(os.path.join(OVERLORD_HOME, "policy.json"), "w") as f:
        json.dump({"targets": {"/nonexistent/allowed": {}}}, f)
    try:
        ov.run(target, ["true"])
        fail("policy did not refuse unlisted target")
    except OverlordError as e:
        if "policy refuses" not in str(e):
            fail(f"wrong refusal: {e}")
    ok("policy deny-by-default")

    # 7. policy: force commit forbidden unless allow_force
    with open(os.path.join(OVERLORD_HOME, "policy.json"), "w") as f:
        json.dump({"default": {}}, f)
    s = ov.run(target, ["bash", "-c", "echo v3 > app.conf"])
    time.sleep(0.01)
    with open(os.path.join(target, "app.conf"), "w") as f:
        f.write("external\n")   # drift
    try:
        s.commit(force=True)
        fail("policy allowed forbidden force commit")
    except OverlordError as e:
        if "forbids" not in str(e):
            fail(f"wrong force refusal: {e}")
    s.rollback()
    ok("policy forbids force")

    # 8. sessions listing over the wire
    if not isinstance(ov.sessions(), list):
        fail("sessions op")
    ok("sessions over socket")

    # --- a session id off the socket must not become a path outside the store
    for op in ("diff", "log", "transcript", "commit", "rollback"):
        for bad in ("..", "../..", "/etc", "x/../../y"):
            try:
                ov._call(op, sid=bad)
                fail(f"daemon op {op!r} accepted session id {bad!r}")
            except OverlordError as e:
                if "invalid session id" not in str(e):
                    fail(f"{op} {bad!r}: wrong refusal: {e}")
    ok("daemon refuses traversal in session ids")

    # --- a launch that fails inside the daemon must release the target ---
    # (kill the holder, drop the session record, unlock) — the daemon process
    # outlives the failure, so a leaked flock would block the target for good
    import shutil as _sh
    if _sh.which("bpftrace") is None:
        try:
            ov._call("run", target=target, cmd=["bash", "-c", "sleep 2"], trace="ebpf")
            fail("ebpf run succeeded with no recorder available")
        except OverlordError as e:
            if "bpftrace" not in str(e):
                fail(f"unexpected launch error: {e}")
        s = ov.run(target, ["true"])          # must not be blocked or locked
        s.rollback()
        ok("failed launch releases the target (no orphan, no held lock)")
    else:
        print("  skip: failed-launch test (bpftrace present)")

    # 9. live session: many commands, one transaction, streamed output
    with open(os.path.join(OVERLORD_HOME, "policy.json"), "w") as f:
        json.dump({"default": {}}, f)
    with open(os.path.join(target, "app.conf"), "w") as f:
        f.write("v1\n")
    live = ov.open(target, agent="test")
    chunks = []
    rc, out, ch = live.shell("echo step-one; echo a > a.txt",
                             on_output=lambda b: chunks.append(b))
    if rc != 0 or "step-one" not in out or b"step-one" not in b"".join(chunks):
        fail(f"live exec 1: rc={rc} out={out!r} chunks={chunks!r}")
    if ("added", "a.txt") not in ch:
        fail(f"live exec 1 changes: {ch}")
    rc, out, ch = live.shell("cat a.txt > b.txt; rm a.txt; echo v2 > app.conf")
    if rc != 0 or ("added", "b.txt") not in ch or ("modified", "app.conf") not in ch:
        fail(f"live exec 2 changes: {ch}")
    if open(os.path.join(target, "app.conf")).read() != "v1\n":
        fail("live session mutated target before close/commit")
    ok("live session: multi-exec + streaming + cumulative diff")

    # 10. live session cannot be committed until closed; close seals it
    try:
        Session = type(s)
        Session(ov, live.sid, 0, [], {}).commit()
        fail("committed an open session")
    except OverlordError as e:
        if "not pending" not in str(e):
            fail(f"wrong open-commit refusal: {e}")
    sealed = live.close()
    if sealed.exit_code != 0 or ("added", "b.txt") not in sealed.changes:
        fail(f"close: {sealed}")
    metas = {m["id"]: m for m in ov.sessions()}
    if metas[sealed.sid]["status"] != "pending" or len(metas[sealed.sid]["execs"]) != 2:
        fail(f"sealed meta: {metas[sealed.sid]}")
    sealed.commit()
    if open(os.path.join(target, "b.txt")).read() != "a\n":
        fail("live session commit did not apply")
    ok("live session: open blocks commit, close seals, commit applies")

    # 11. per-exec timeout kills only that command; session survives
    live = ov.open(target)
    rc, _, _ = live.exec(["sleep", "30"], timeout=1)
    if rc != 124:
        fail(f"exec timeout rc={rc}")
    rc, out, _ = live.shell("echo still-alive")
    if rc != 0 or "still-alive" not in out:
        fail("session died with the timed-out command")
    ok("live session: per-exec timeout")

    # 12. rollback while open tears the holder down
    live.rollback()
    if any(m["id"] == live.sid for m in ov.sessions()):
        fail("open session survived rollback")
    try:
        live.shell("true")
        fail("exec succeeded on a rolled-back session")
    except OverlordError:
        pass
    ok("live session: rollback while open")

    # 13. session-level timeout grant expires the whole transaction
    live = ov.open(target, timeout=1)
    rc, _, _ = live.exec(["sleep", "30"])
    if rc != 124:
        fail(f"session timeout rc={rc}")
    try:
        live.shell("true")
        fail("exec succeeded after session expiry")
    except OverlordError as e:
        if "expired" not in str(e):
            fail(f"wrong expiry error: {e}")
    sealed = live.close()
    if not {m["id"]: m for m in ov.sessions()}[sealed.sid].get("timed_out"):
        fail("expired session not marked timed_out")
    sealed.rollback()
    ok("live session: timeout grant expiry")

    # 14. built-in agent over the wire: events stream, session sealed, cancel op
    script = os.path.join(OVERLORD_HOME, "script.json")
    with open(script, "w") as f:
        json.dump([{"text": "hello", "tool_calls": [
                        {"name": "write_file", "input": {"path": "agent.txt", "content": "x\n"}}]},
                   {"text": "finished"}], f)
    os.environ["OVERLORD_AGENT_SCRIPT"] = script
    daemon.terminate(); daemon.wait()
    os.remove(SOCK)
    daemon = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "overlord.py"), "daemon", "--socket", SOCK],
        env=os.environ.copy(), stderr=subprocess.DEVNULL)
    for _ in range(50):
        if os.path.exists(SOCK):
            break
        time.sleep(0.1)
    evs = []
    s = ov.agent(target, "do it", provider="scripted", on_event=evs.append)
    types = [e["type"] for e in evs]
    if types[0] != "session" or "tool_call" not in types or types[-1] != "done":
        fail(f"agent events: {types}")
    if s.final != "finished" or ("added", "agent.txt") not in s.changes:
        fail(f"agent result: {s} final={s.final!r}")
    if not any(t["type"] == "tool_result" for t in ov.transcript(s.sid)):
        fail("transcript op")
    prov = [r for r in s.log() if r["path"] == "agent.txt"]
    if not prov or prov[0].get("caused_by", {}).get("tool") != "write_file":
        fail(f"agent provenance over socket: {prov}")
    s.rollback()
    ok("agent over socket: streamed events, sealed session, linked provenance")

    # 15. orphan reconcile: a dead opener leaves a pending session, not a wedged one
    orphan = ov.open(target)
    orphan.shell("echo orphan > o.txt")
    daemon.kill(); daemon.wait()               # daemon dies hard with a session open
    import importlib.util
    spec = importlib.util.spec_from_file_location("ov", os.path.join(HERE, "overlord.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    for _ in range(50):
        if mod.load_meta(orphan.sid).get("status") == "pending":
            break
        time.sleep(0.1)
    m = mod.load_meta(orphan.sid)
    if m.get("status") != "pending" or ("added", "o.txt") not in [tuple(c) for c in mod.compute_diff(
            os.path.join(mod.session_path(orphan.sid), "upper"), target)]:
        fail(f"orphan not reconciled: {m}")
    mod.rollback_session(orphan.sid)
    ok("orphan session reconciled to pending")

    print("PASS: daemon + sdk + policy + live sessions")
finally:
    daemon.terminate()
    daemon.wait()
    subprocess.run(["rm", "-rf", OVERLORD_HOME, target])
