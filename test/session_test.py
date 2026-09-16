#!/usr/bin/env python3
"""Long conversations and long-lived servers: when a call uses three
quarters of the context window the agent writes a handover note, older
turns are dropped and the cut is on the transcript (summary, what was
kept) so a resume rebuilds the same view; the note's call is on the
ledger; the window is a setting; logins outlive a restart (hashed at
rest); a per-address rate limit answers 429. Scripted provider, no network."""

import json
import os
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = HOME

import overlord as ov      # noqa: E402
import agent               # noqa: E402
import providers as P      # noqa: E402
import cost                # noqa: E402
import auth                # noqa: E402
import chatui              # noqa: E402
import ui                  # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


BACKEND = ov.detect_backend()
if BACKEND is None:
    print("SKIP: session (no sandbox backend here — see `overlord doctor`)")
    sys.exit(0)
KERNEL = BACKEND == "kernel"
grants = {"net": "none" if KERNEL else "host", "jail": KERNEL, "timeout": None, "merge_base": False}
target = tempfile.mkdtemp()
with open(os.path.join(target, "lib.py"), "w") as f:
    f.write("def a():\n    return 1\n")


def roles(msgs):
    return [m["role"] for m in msgs]


try:
    # 1. compaction: triggered by the last call's prompt size, recorded, priced
    script = [{"text": "one", "usage": {"in": 800, "out": 10},
               "tool_calls": [{"name": "shell", "input": {"command": "echo a > a.txt"}}]},
              {"text": "HANDOVER: made a.txt; next make b.txt; tests: none.", "usage": {"in": 900, "out": 40}},
              {"text": "two", "usage": {"in": 300, "out": 10},
               "tool_calls": [{"name": "shell", "input": {"command": "echo b > b.txt"}}]},
              {"text": "done", "usage": {"in": 320, "out": 5}}]
    p = agent.ScriptedProvider(script)
    p.config = P.ModelConfig(context_limit=1000)
    live = ov.open_session(target, BACKEND, grants, capture=True, agent="scripted:scripted")
    ev = []
    agent.run_agent(live, p, "do it", max_turns=6, emit=ev.append)
    sid, changes = live.close()
    if len(p.seen) != 4:
        fail(f"expected 4 model calls (turn, handover, turn, turn): {len(p.seen)}")
    handover_ask = p.seen[1]
    if handover_ask[-1]["role"] != "user" or "handover note" not in handover_ask[-1]["content"] \
            or roles(handover_ask[:-1]) != ["user", "assistant", "tool"]:
        fail(f"handover request: {roles(handover_ask)} {handover_ask[-1]['content'][:60]}")
    after = p.seen[2]
    if roles(after) != ["user", "assistant", "tool"] or "TASK: do it" not in after[0]["content"] \
            or "HANDOVER: made a.txt" not in after[0]["content"] or after[1]["content"] != "one":
        fail(f"compacted view: {roles(after)} {after[0]['content'][:120]}")
    if p.seen[3][0]["content"] != after[0]["content"] or roles(p.seen[3]) != ["user", "assistant", "tool",
                                                                              "assistant", "tool"]:
        fail(f"the turn after compaction builds on the compacted view: {roles(p.seen[3])}")
    tr = [json.loads(l) for l in open(ov.session_file(sid, "transcript.jsonl"))]
    comp = [e for e in tr if e["type"] == "compaction"]
    if len(comp) != 1 or comp[0]["turn"] != 1 or comp[0]["before_tokens"] != 800 or comp[0]["kept"] != 2 \
            or "HANDOVER" not in comp[0]["summary"] or comp[0]["usage"]["in"] != 900:
        fail(f"compaction event: {comp}")
    m = ov.load_meta(sid)
    if m["usage"]["in"] != 800 + 900 + 300 + 320 or m.get("compactions") != [{"turn": 1, "before_tokens": 800}]:
        fail(f"meta after compaction: {m['usage']} {m.get('compactions')}")
    rows = [r for r in cost.ledger_rows() if r["kind"] == "compaction"]
    if len(rows) != 1 or rows[0]["in"] != 900:
        fail(f"ledger: {rows}")
    if sorted(changes) != [("added", "a.txt"), ("added", "b.txt")]:
        fail(f"work across the compaction: {changes}")
    notes = [x for x in chatui.messages_from_transcript(sid) if x["type"] == "note" and "compacted" in x["text"]]
    if len(notes) != 1 or "kept its last 2" not in notes[0]["text"]:
        fail(f"workspace note: {notes}")
    ok("compaction: handover written by the model, older turns dropped, recorded, priced, work intact")

    # 2. a resume replays the same cut
    p2 = agent.ScriptedProvider([{"text": "resumed", "usage": {"in": 10, "out": 1}}])
    live = ov.reopen_session(sid, capture=True)
    agent.run_agent(live, p2, "do it", max_turns=3, emit=lambda e: None, resume=True, note="carry on")
    live.close()
    replay = p2.seen[0]
    for msg in replay:
        msg.pop("_turn", None)
    # compacted head, turn 1's kept tail, turn 2, the closing "done", the operator's note
    if roles(replay) != ["user", "assistant", "tool", "assistant", "tool", "assistant", "user"] \
            or replay[0]["content"] != after[0]["content"] \
            or replay[1]["content"] != "one" or replay[3]["content"] != "two" \
            or replay[5]["content"] != "done" \
            or replay[2]["tool_call_id"] != p.seen[3][2]["tool_call_id"] \
            or "carry on" not in replay[-1]["content"]:
        fail(f"resume replay: {roles(replay)} {replay[0]['content'][:80]}")
    ov.rollback_session(sid)
    ok("a resume rebuilds exactly the compacted view, then the operator note")

    # 3. the window is a setting
    spath = os.path.join(HOME, "script.json")
    with open(spath, "w") as f:
        json.dump([{"text": "hi"}], f)
    os.environ["OVERLORD_AGENT_SCRIPT"] = spath
    chatui.save_settings({"provider": "scripted", "workdir": target, "gen": {"context_limit": "50000"}})
    s = chatui.load_settings()
    if s["gen"]["context_limit"] != 50000 or chatui.build_provider(s).config.context_limit != 50000:
        fail(f"context_limit setting: {s['gen']}")
    try:
        chatui.save_settings({"gen": {"context_limit": "lots"}})
        fail("bad context_limit accepted")
    except ov.OverlordError:
        pass
    chatui.save_settings({"gen": {"context_limit": ""}})
    if chatui.build_provider(chatui.load_settings()).config.context_limit != P.ModelConfig.DEFAULT_CONTEXT:
        fail("blank context_limit should mean the default")
    ok("context window is a generation setting; blank means the default")

    # 4. logins outlive a restart; the file never holds a usable cookie
    auth.add_user("alice", "correct horse", "admin")
    tok, _p = auth.login("alice", "correct horse", "127.0.0.1")
    if os.stat(auth.SESSIONS_FILE).st_mode & 0o077 or tok in open(auth.SESSIONS_FILE).read():
        fail("sessions file not private, or holds the raw cookie")
    auth._SESSIONS.clear()                       # a restart
    auth._load_sessions()
    who = auth.authenticate({"Cookie": f"{auth.COOKIE}={tok}"})
    if not who or who["user"] != "alice":
        fail(f"login lost across restart: {who}")
    auth.logout(tok)
    auth._SESSIONS.clear()
    auth._load_sessions()
    if auth.authenticate({"Cookie": f"{auth.COOKIE}={tok}"}):
        fail("logout not durable")
    os.unlink(auth.USERS_FILE)
    ok("logins survive a restart, hashed at rest; logout is durable")

    # 5. a per-address rate limit
    PORT = 7788
    server = ui.make_server(PORT, rate_limit=5)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    codes = []
    for _ in range(7):
        try:
            with urllib.request.urlopen(urllib.request.Request(
                    f"http://127.0.0.1:{PORT}/api/me", headers={"Host": f"127.0.0.1:{PORT}", "Cookie": ui.local_cookie()}), timeout=5) as r:
                codes.append(r.status)
        except urllib.error.HTTPError as e:
            codes.append(e.code)
    server.shutdown()
    if codes[:5] != [200] * 5 or codes[5:] != [429, 429]:
        fail(f"rate limit: {codes}")
    ok("rate limit: the sixth request in a minute from one address is refused")

    print("PASS: sessions")
finally:
    subprocess.run(["rm", "-rf", HOME, target])
