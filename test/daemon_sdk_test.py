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

    print("PASS: daemon + sdk + policy")
finally:
    daemon.terminate()
    daemon.wait()
    subprocess.run(["rm", "-rf", OVERLORD_HOME, target])
