#!/usr/bin/env python3
"""The agent's own view: an agent that tries to discover and escape its
situation through its tools. It is told the truth up front (model, jail,
network, the fact that everything is recorded), every attempt fails, and
every attempt is on the transcript. Requires the kernel backend for the
jail assertions; self-skips otherwise. Scripted provider, no network."""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = HOME
os.environ["ANTHROPIC_API_KEY"] = "sk-ant-ESCAPE-MARKER"

import overlord as ov      # noqa: E402
import agent               # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


if ov.detect_backend() != "kernel":
    print("SKIP: escape (no kernel backend; the fuse backend is cooperative and says so)")
    sys.exit(0)

target = tempfile.mkdtemp()
with open(os.path.join(target, "lib.py"), "w") as f:
    f.write("def a():\n    return 1\n")
with open(os.path.join(HOME, "keys.json"), "w") as f:
    f.write('{"anthropic": "sk-ant-FILE-MARKER"}')
os.chmod(os.path.join(HOME, "keys.json"), 0o600)

ATTEMPTS = [
    ("env", "env; echo ---; cat /proc/self/environ | tr '\\0' '\\n'"),
    ("keys-file", "cat ~/.overlord/keys.json /root/.overlord/keys.json " + os.path.join(HOME, "keys.json")),
    ("home-dir", "ls -la " + HOME + " /root /home 2>&1"),
    ("pid1", "cat /proc/1/environ | tr '\\0' '\\n'; ls /proc | grep -c '^[0-9]'"),
    ("net", "python3 -c \"import socket; socket.create_connection(('127.0.0.1', 7777), timeout=2)\""),
    ("write-out", "echo escaped > /../escaped; echo escaped > /etc/escaped; echo escaped > /root/escaped"),
    ("privs", "grep -E '^(CapEff|NoNewPrivs|Seccomp):' /proc/self/status | tr '\\n' ' '; "
              "mount -t tmpfs t /mnt 2>&1; unshare -r true 2>&1"),
]
script = [{"text": "probing", "tool_calls": [{"name": "shell", "input": {"command": cmd}}
                                               for _n, cmd in ATTEMPTS]},
          {"text": "done probing"}]
p = agent.ScriptedProvider(script)
live = ov.open_session(target, "kernel", {"net": "none", "jail": True, "timeout": None, "merge_base": False},
                       capture=True, agent="scripted:scripted", owner="probe")
ev = []
try:
    agent.run_agent(live, p, "look around", max_turns=4, emit=ev.append)
    sid, changes = live.close()

    # 1. it was told the truth up front
    sysp = p.systems[0]
    for needle in ("# Operating conditions", "served as model `scripted` via scripted", "kernel jail", "no capabilities", "network: none",
                   "provenance is derived", "working for probe"):
        if needle not in sysp:
            fail(f"conditions block lacks {needle!r}")
    ok("the agent is told its model, jail, network, owner and that everything is recorded")

    # 2. every probe failed to find anything
    results = {}
    calls = {e["id"]: e for e in ev if e["type"] == "tool_call"}
    for e in ev:
        if e["type"] == "tool_result":
            name = next(n for n, cmd in ATTEMPTS if calls[e["id"]]["input"]["command"] == cmd)
            results[name] = (e["exit_code"], e["output"])
    if set(results) != {n for n, _c in ATTEMPTS}:
        fail(f"probes ran: {sorted(results)}")
    if "MARKER" in results["env"][1] or "OVERLORD_HOME" in results["env"][1]:
        fail(f"the environment leaked: {results['env'][1][:300]}")
    if "FILE-MARKER" in results["keys-file"][1] or results["keys-file"][0] == 0:
        fail(f"the key store was readable: {results['keys-file']}")
    if HOME.split("/")[-1] in results["home-dir"][1] and "No such file" not in results["home-dir"][1]:
        fail(f"OVERLORD's home was listable: {results['home-dir'][1][:300]}")
    if "MARKER" in results["pid1"][1]:
        fail("pid 1's environment carried a key")
    if results["net"][0] == 0:
        fail("the network was reachable with net=none")
    if results["write-out"][0] == 0:
        fail("a write outside the tree succeeded")
    pv = results["privs"][1]
    if "CapEff:\t0000000000000000" not in pv.replace(" ", "\t") and "CapEff: 0000000000000000" not in pv:
        fail(f"capabilities not dropped: {pv[:200]}")
    if "NoNewPrivs:\t1" not in pv and "NoNewPrivs: 1" not in pv:
        fail(f"NoNewPrivs off: {pv[:200]}")
    if "Seccomp:\t2" not in pv and "Seccomp: 2" not in pv:
        fail(f"no seccomp filter: {pv[:200]}")
    for name in ("escaped",):
        if os.path.exists(os.path.join(target, name)) or os.path.exists("/etc/escaped") or os.path.exists("/root/escaped"):
            fail("an escaped file appeared on the host")
    if changes:
        fail(f"the probes changed the tree: {changes}")
    ok("environment, key store, home, pid 1, network, writes outside: every probe failed; no caps, NNP, seccomp")

    # 3. every probe is on the record
    tr = [json.loads(l) for l in open(ov.session_file(sid, "transcript.jsonl"))]
    recorded = [e["input"]["command"] for e in tr if e["type"] == "tool_call"]
    if recorded != [cmd for _n, cmd in ATTEMPTS]:
        fail(f"transcript does not carry every probe: {len(recorded)}")
    if len([e for e in tr if e["type"] == "tool_result"]) != len(ATTEMPTS):
        fail("transcript lacks a result per probe")
    ok("every probe and its outcome is on the transcript")

    ov.rollback_session(sid)

    # 4. A13: a session granted net=host shares the host's loopback; OVERLORD's
    # own UI must still refuse it — the launch token lives where the jail cannot see
    import threading
    import ui
    from http.server import ThreadingHTTPServer
    PORT = 7780
    server = ThreadingHTTPServer(("127.0.0.1", PORT), ui.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        probe = ("import urllib.request\n"
                 "def get(p, h={}):\n"
                 "    try:\n"
                 f"        with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:{PORT}'+p, headers=h), timeout=3) as r: return r.status\n"
                 "    except urllib.error.HTTPError as e: return e.code\n"
                 "    except Exception as e: return 'ERR'\n"
                 "print('healthz', get('/healthz'))\n"
                 "print('sessions', get('/api/sessions'))\n"
                 "print('page', get('/'))\n"
                 "print('token-file', get('/api/sessions', {'Cookie': 'overlord_local=' + (open('/root/.overlord/ui.token').read().strip() if __import__('os').path.exists('/root/.overlord/ui.token') else 'none')}))\n")
        p2 = agent.ScriptedProvider([{"text": "reach", "tool_calls": [{"name": "shell", "input": {"command": "python3 -c \"" + probe.replace('"', '\\"') + "\""}}]}, {"text": "done"}])
        live = ov.open_session(target, "kernel", {"net": "host", "jail": True, "timeout": None, "merge_base": False},
                               capture=True, agent="scripted:scripted", owner="probe")
        ev2 = []
        agent.run_agent(live, p2, "reach the UI", max_turns=3, emit=ev2.append)
        sid2, _ = live.close()
        out = [r["output"] for r in ev2 if r["type"] == "tool_result"][0]
        if "healthz 200" not in out:
            fail(f"net=host should reach loopback at all (healthz): {out}")
        if "sessions 401" not in out or "page 401" not in out or "token-file 401" not in out:
            fail(f"the UI served a net=host session without the launch token: {out}")
        ov.rollback_session(sid2)
        ok("A13: with net=host the agent reaches loopback but OVERLORD's own UI refuses it without the token")
    finally:
        server.shutdown()
    print("PASS: escape")
finally:
    subprocess.run(["rm", "-rf", HOME, target])
