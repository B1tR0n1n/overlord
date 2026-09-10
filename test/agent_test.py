#!/usr/bin/env python3
"""Agent e2e: a scripted model drives real tool calls inside a live session
(jail + net:none when the kernel backend allows); provenance is linked to the
tool call that caused each change; the transcript is complete; the turn
budget binds; both provider adapters produce/parse the right wire shapes
without touching the network."""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ["OVERLORD_HOME"] = tempfile.mkdtemp()

import overlord as ov          # noqa: E402
import agent                   # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


target = tempfile.mkdtemp()
with open(os.path.join(target, "README.md"), "w") as f:
    f.write("# demo\n")
with open(os.path.join(target, "old.txt"), "w") as f:
    f.write("stale\n")

kernel = ov._kernel_backend_available()
grants = {"net": "none" if kernel else "host", "jail": bool(kernel),
          "timeout": None, "merge_base": False}
try:
    # --- 1. scripted agent run: read, write, shell, delete; then stop
    script = [
        {"text": "Looking around.", "tool_calls": [
            {"name": "list_dir", "input": {"path": "."}},
            {"name": "read_file", "input": {"path": "README.md"}}]},
        {"tool_calls": [
            {"name": "write_file", "input": {"path": "src/hello.py",
                                             "content": "print('hi')\n"}}]},
        {"tool_calls": [
            {"name": "shell", "input": {"command": "python3 src/hello.py && rm old.txt"}}]},
        {"tool_calls": [
            {"name": "shell", "input": {"command": "cat /etc/hostname; ls /home 2>&1; "
                                                   "curl -s -m 2 http://example.com >/dev/null "
                                                   "&& echo NET-OPEN || echo NET-CLOSED"}}]},
        {"tool_calls": [
            {"name": "read_file", "input": {"path": "/etc/passwd"}}]},
        {"text": "Done: added src/hello.py, removed old.txt."},
    ]
    provider = agent.ScriptedProvider(script)
    provider.model = "scripted"
    live = ov.open_session(target, None, grants, capture=True, agent="scripted")
    events = []
    final = agent.run_agent(live, provider, "make hello", max_turns=10, emit=events.append)
    sid, changes = live.close()
    if "Done:" not in final:
        fail(f"final text: {final!r}")
    if set(changes) != {("added", "src/"), ("added", "src/hello.py"), ("deleted", "old.txt")}:
        fail(f"changes: {changes}")
    if open(os.path.join(target, "old.txt")).read() != "stale\n":
        fail("agent mutated the real tree")
    ok("scripted agent: tools acted inside the transaction, target untouched")

    # --- 2. tool results fed back to the model are real
    results = {e["id"]: e for e in events if e["type"] == "tool_result"}
    calls = {e["id"]: e for e in events if e["type"] == "tool_call"}
    by_tool = {}
    for cid, e in calls.items():
        by_tool.setdefault(e["tool"], []).append(results[cid])
    if "README.md" not in by_tool["list_dir"][0]["output"]:
        fail("list_dir output")
    if by_tool["read_file"][0]["output"] != "# demo\n":
        fail("read_file output")
    if by_tool["shell"][0]["exit_code"] != 0 or "hi" not in by_tool["shell"][0]["output"]:
        fail(f"shell output: {by_tool['shell'][0]}")
    if by_tool["read_file"][1]["exit_code"] == 0 or "relative" not in by_tool["read_file"][1]["output"]:
        fail("absolute path was not refused")
    if kernel:
        probe = by_tool["shell"][1]["output"]
        if "NET-CLOSED" not in probe or "No such file" not in probe:
            fail(f"grants did not bind for the agent's hands: {probe!r}")
        ok("agent's hands are jailed and offline (model side keeps network)")
    ok("tool results are real and refusals are explicit")

    # --- 3. provenance is linked to the tool call that caused each change
    prov = [json.loads(l) for l in open(os.path.join(ov.session_path(sid), "provenance.jsonl"))]
    by_path = {r["path"]: r for r in prov}
    w = by_path["src/hello.py"].get("caused_by") or {}
    d = by_path["old.txt"].get("caused_by") or {}
    if w.get("tool") != "write_file" or w.get("turn") != 2 or w.get("summary") != "src/hello.py":
        fail(f"write attribution: {w}")
    if d.get("tool") != "shell" or d.get("turn") != 3 or "rm old.txt" not in d.get("summary", ""):
        fail(f"delete attribution: {d}")
    if w["tool_call_id"] not in calls or d["tool_call_id"] not in calls:
        fail("caused_by ids do not resolve to transcript tool calls")
    ok("provenance: every change names its tool call, turn, and instruction")

    # --- 4. transcript + meta are complete records
    tpath = os.path.join(ov.session_path(sid), "transcript.jsonl")
    trans = [json.loads(l) for l in open(tpath)]
    kinds = [t["type"] for t in trans]
    if kinds[0] != "task" or kinds[-1] != "done" or kinds.count("tool_call") != 6:
        fail(f"transcript shape: {kinds}")
    m = ov.load_meta(sid)
    if m["agent"] != "scripted:scripted" or m["task"] != "make hello" or len(m["execs"]) != 5:   # the refused absolute read never ran
        fail(f"meta: {m}")
    if not all(e.get("label", "").startswith("turn") for e in m["execs"]):
        fail("execs not labelled with turn/tool id")
    # the model saw its own tool results in order
    last = provider.seen[-1]
    if last[-1]["role"] != "tool" or "relative" not in last[-1]["content"]:
        fail("message history not threaded back to the model")
    ok("transcript, meta, and message threading")
    ov.commit_session(sid)
    if not os.path.isfile(os.path.join(target, "src/hello.py")) or os.path.exists(
            os.path.join(target, "old.txt")):
        fail("commit of agent session")
    ok("agent session commits like any other")

    # --- 5. turn budget binds; cancel binds
    looper = agent.ScriptedProvider(
        [{"tool_calls": [{"name": "shell", "input": {"command": "echo loop"}}]}] * 50)
    looper.model = "scripted"
    live = ov.open_session(target, None, grants, capture=True)
    ev = []
    agent.run_agent(live, looper, "loop", max_turns=3, emit=ev.append)
    if ev[-1]["type"] != "done" or ev[-1]["reason"] != "max_turns" or looper.i != 3:
        fail(f"budget: {ev[-1]} calls={looper.i}")
    sid, _ = live.close()
    ov.rollback_session(sid)
    looper = agent.ScriptedProvider(
        [{"tool_calls": [{"name": "shell", "input": {"command": "echo loop"}}]}] * 50)
    looper.model = "scripted"
    live = ov.open_session(target, None, grants, capture=True)
    n = {"turns": 0}

    def stop():
        n["turns"] += 1
        return n["turns"] > 2
    ev = []
    agent.run_agent(live, looper, "loop", max_turns=50, emit=ev.append, should_stop=stop)
    if ev[-1]["reason"] != "cancelled" or looper.i != 2:
        fail(f"cancel: {ev[-1]} calls={looper.i}")
    sid, _ = live.close()
    ov.rollback_session(sid)
    ok("turn budget and cancellation bind")

    # --- 6. provider adapters: wire format out, reply parsing in (no network)
    neutral = [
        {"role": "user", "content": "task"},
        {"role": "assistant", "content": "thinking", "tool_calls": [
            {"id": "c1", "name": "shell", "input": {"command": "ls"}},
            {"id": "c2", "name": "read_file", "input": {"path": "a"}}]},
        {"role": "tool", "tool_call_id": "c1", "content": "out1"},
        {"role": "tool", "tool_call_id": "c2", "content": "out2"},
    ]
    captured = {}

    def fake_post(url, headers, body, timeout=600):
        captured["url"], captured["headers"], captured["body"] = url, headers, body
        if "anthropic" in url:
            return {"content": [{"type": "text", "text": "hi"},
                                {"type": "tool_use", "id": "t1", "name": "shell",
                                 "input": {"command": "pwd"}}],
                    "stop_reason": "tool_use",
                    "usage": {"input_tokens": 10, "output_tokens": 5}}
        return {"choices": [{"finish_reason": "tool_calls", "message": {
                    "content": None, "tool_calls": [{"id": "t1", "type": "function",
                    "function": {"name": "shell", "arguments": "{\"command\": \"pwd\"}"}}]}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5}}
    agent._post = fake_post

    a = agent.AnthropicProvider("m", "k")
    r = a.complete("sys", neutral)
    b = captured["body"]
    if captured["headers"]["x-api-key"] != "k" or b["system"] != "sys" or b["tools"] != agent.TOOLS:
        fail("anthropic request")
    if b["messages"][1]["content"][1]["type"] != "tool_use":
        fail("anthropic assistant tool_use blocks")
    if (b["messages"][2]["role"] != "user" or len(b["messages"][2]["content"]) != 2
            or b["messages"][2]["content"][1]["tool_use_id"] != "c2"):
        fail("anthropic tool_result merging")
    if r.text != "hi" or r.tool_calls[0]["input"] != {"command": "pwd"} or r.usage["in"] != 10:
        fail("anthropic reply parse")

    o = agent.OpenAIProvider("m", "k")
    r = o.complete("sys", neutral)
    b = captured["body"]
    if captured["headers"]["Authorization"] != "Bearer k" or b["messages"][0]["role"] != "system":
        fail("openai request")
    if b["tools"][0]["function"]["name"] != "list_dir" or b["tools"][0]["function"]["parameters"]["type"] != "object":
        fail("openai tools")
    tc = b["messages"][2]["tool_calls"][0]
    if tc["type"] != "function" or json.loads(tc["function"]["arguments"]) != {"command": "ls"}:
        fail("openai assistant tool_calls")
    if b["messages"][3]["role"] != "tool" or b["messages"][4]["tool_call_id"] != "c2":
        fail("openai tool messages")
    if r.tool_calls[0]["name"] != "shell" or r.tool_calls[0]["input"] != {"command": "pwd"} or r.usage["out"] != 5:
        fail("openai reply parse")
    ok("anthropic + openai adapters: wire shapes and reply parsing")

    # --- 7. keys: env wins; file must be 0600
    os.environ["ANTHROPIC_API_KEY"] = "env-key"
    if agent.load_key("anthropic") != "env-key":
        fail("env key")
    del os.environ["ANTHROPIC_API_KEY"]
    agent.save_key("openai", "file-key")
    kp = os.path.join(ov.OVERLORD_HOME, "keys.json")
    if oct(os.stat(kp).st_mode & 0o777) != "0o600" or agent.load_key("openai") != "file-key":
        fail("key file")
    os.chmod(kp, 0o644)
    try:
        agent.load_key("openai")
        fail("world-readable key file accepted")
    except SystemExit:
        pass
    ok("key handling")

    print("PASS: agent" + (" (jail + net:none)" if kernel else " (no kernel backend: unjailed)"))
finally:
    subprocess.run(["rm", "-rf", os.environ["OVERLORD_HOME"], target])
