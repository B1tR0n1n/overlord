#!/usr/bin/env python3
"""Workspace e2e: the chat front door served by `overlord ui`. Settings round
-trip with the API key never echoed; a conversation is one transaction — the
first message opens a sandboxed session and runs the agent, the inspector
shows the live diff and a Commit control, a follow-up message resumes the same
transaction, Commit applies it and Discard leaves the folder untouched; the
model runs in-process (no daemon); a missing key and a second conversation on
a busy folder both fail friendly. Uses the scripted provider — no network."""

import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
OVERLORD_HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = OVERLORD_HOME
PORT = 7796
BASE = f"http://127.0.0.1:{PORT}"

import overlord as core        # noqa: E402
import agent                   # noqa: E402
import ui                      # noqa: E402
import chatui                  # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


def req(path, data=None, method=None, headers=None):
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(BASE + path, data=body, method=method,
                               headers={"Host": f"127.0.0.1:{PORT}", "Cookie": ui.local_cookie(),
                                        **(headers or {})})
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def set_script(steps):
    p = os.path.join(OVERLORD_HOME, "script.json")
    with open(p, "w") as f:
        json.dump(steps, f)
    os.environ["OVERLORD_AGENT_SCRIPT"] = p


def wait_idle(sid, timeout=30):
    frm, deadline = 0, time.time() + timeout
    seen = []
    while time.time() < deadline:
        code, d = req(f"/api/chats/{sid}/events?from={frm}")
        if code != 200:
            fail(f"events {code}: {d}")
        frm = d["next"]
        seen += d["events"]
        if not d["running"]:
            return seen, d["inspector"]
        time.sleep(0.05)
    fail("agent did not finish")


target = tempfile.mkdtemp()
with open(os.path.join(target, "lib.py"), "w") as f:
    f.write("def a():\n    return 1\n")
KERNEL = core.detect_backend() == "kernel"
if core.detect_backend() is None:
    print("SKIP: chat (no sandbox backend here — see `overlord doctor`)")
    sys.exit(0)

server = None
try:
    from http.server import ThreadingHTTPServer
    server = ThreadingHTTPServer(("127.0.0.1", PORT), ui.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # 1. missing key: the workspace will not start a run it cannot serve
    chatui.save_settings({"provider": "anthropic", "workdir": target,
                          "jail": KERNEL, "net": "none" if KERNEL else "host"})
    code, sp = req("/api/settings")
    if code != 200 or sp["provider"] != "anthropic" or sp["provider_ready"] not in (True, False):
        fail(f"settings: {sp}")
    if sp.get("keys", {}).get("anthropic"):
        # a stray key in the test env; not our concern, just skip the assertion
        pass
    elif sp["provider_ready"]:
        fail("provider_ready true without a key")
    ok("settings served; provider readiness reported")

    # 2. settings round-trip; an API key is stored but never echoed
    code, sp = req("/api/settings", {"provider": "openai", "key": "sk-secret-123",
                                     "workdir": target, "max_turns": 7}, "PUT")
    if code != 200:
        fail(f"settings PUT: {sp}")
    if "sk-secret" in json.dumps(sp):
        fail("the API key was echoed back to the client")
    if not sp["keys"]["openai"] or sp["max_turns"] != 7:
        fail(f"settings not applied: {sp}")
    if agent.load_key("openai") != "sk-secret-123":
        fail("the key did not reach the engine key store")
    # the second model's key lands under the reviewer's provider, not the agent's
    code, sp = req("/api/settings", {"review_provider": "gemini", "review_model": "gemini-2.5-flash",
                                     "review_key": "gm-review-456"}, "PUT")
    if code != 200 or sp["review_provider"] != "gemini" or sp["review_model"] != "gemini-2.5-flash" \
            or not sp["keys"]["gemini"] or "gm-review" in json.dumps(sp):
        fail(f"reviewer settings: {code} {sp.get('review_provider')} {sp.get('keys')}")
    if agent.load_key("gemini") != "gm-review-456" or agent.load_key("openai") != "sk-secret-123":
        fail("the reviewer's key went to the wrong store")
    code, sp = req("/api/settings", {"review_provider": "nope"}, "PUT")
    if code != 400:
        fail("bad reviewer provider accepted")
    req("/api/settings", {"review_provider": "", "review_model": ""}, "PUT")
    ok("settings round-trip; API key stored in the engine, never echoed; the reviewer's key under its provider")

    # 3. switch to the scripted provider and start a conversation
    set_script([
        {"text": "I'll add a greeting.", "tool_calls": [
            {"name": "read_file", "input": {"path": "lib.py"}}]},
        {"tool_calls": [{"name": "write_file", "input": {
            "path": "lib.py", "content": "def a():\n    return 1\n\n\ndef greet():\n    return 'hi'\n"}}]},
        {"text": "Added greet()."}])
    chatui.save_settings({"provider": "scripted", "workdir": target,
                          "jail": KERNEL, "net": "none" if KERNEL else "host"})
    code, r = req("/api/chats", {"message": "add a greet function", "target": target}, "POST")
    if code != 200 or "sid" not in r:
        fail(f"start chat: {code} {r}")
    sid = r["sid"]
    events, inspector = wait_idle(sid)
    types = [e["type"] for e in events]
    if "assistant" not in types or "tool_result" not in types or types[-1] != "idle":
        fail(f"stream types: {types}")
    if "greet" not in json.dumps(events):
        fail("the tool call the agent made is not in the stream")
    if core.load_meta(sid)["status"] != "pending" or \
            open(os.path.join(target, "lib.py")).read() == "" or "greet" in open(
                os.path.join(target, "lib.py")).read():
        fail("the real folder changed before commit")
    ok("a message opens a sandboxed transaction and streams the agent's work")

    # 4. the conversation view rebuilds from disk; inspector offers Commit
    code, conv = req(f"/api/chats/{sid}")
    roles = [m["type"] for m in conv["messages"]]
    if roles[0] != "user" or "assistant" not in roles or "tool_result" not in roles:
        fail(f"conversation messages: {roles}")
    if conv["meta"]["title"] != "add a greet function":
        fail(f"title: {conv['meta']}")
    if "Commit changes" not in conv["inspector"] or "lib.py" not in conv["inspector"]:
        fail("inspector lacks the diff or the commit control")
    code, chats = req("/api/chats")
    if not any(c["sid"] == sid and c["title"] == "add a greet function"
               for c in chats["conversations"]):
        fail("conversation not listed")
    ok("conversation rebuilds from disk; inspector shows the diff and Commit; it is listed")

    # 5. a second folder-mate conversation is refused with a friendly message
    code, r = req("/api/chats", {"message": "another", "target": target}, "POST")
    if code != 400 or "already has an open conversation" not in r.get("error", ""):
        fail(f"pending-guard message: {code} {r}")
    ok("a second conversation on the same folder is refused clearly")

    # 6. a follow-up message resumes the SAME transaction
    set_script([
        {"tool_calls": [{"name": "write_file", "input": {
            "path": "NOTES.md", "content": "# notes\n"}}]},
        {"text": "Added NOTES.md."}])
    code, r = req(f"/api/chats/{sid}/message", {"message": "also add a NOTES.md"}, "POST")
    if code != 200:
        fail(f"follow-up: {code} {r}")
    wait_idle(sid)
    code, conv = req(f"/api/chats/{sid}")
    users = [m["text"] for m in conv["messages"] if m["type"] == "user"]
    if users != ["add a greet function", "also add a NOTES.md"]:
        fail(f"both human messages: {users}")
    if "lib.py" not in conv["inspector"] or "NOTES.md" not in conv["inspector"]:
        fail("the resumed transaction lost the earlier change")
    ok("a follow-up message resumes the same transaction; both changes accumulate")

    # 7. Commit applies via the shared engine endpoint; folder now changed
    code, res = req(f"/api/session/{sid}/commit", {}, "POST")
    if code != 200 or not res.get("committed"):
        fail(f"commit: {res}")
    if "greet" not in open(os.path.join(target, "lib.py")).read() or \
            not os.path.exists(os.path.join(target, "NOTES.md")):
        fail("commit did not apply the accumulated changes")
    code, conv = req(f"/api/chats/{sid}")
    if "Committed" not in conv["inspector"]:
        fail("committed state not shown")
    ok("Commit applies the whole conversation to the real folder")

    # 8. Discard leaves the folder untouched
    set_script([{"tool_calls": [{"name": "shell", "input": {"command": "rm lib.py"}}]},
                {"text": "removed it"}])
    code, r = req("/api/chats", {"message": "delete lib.py", "target": target}, "POST")
    sid2 = r["sid"]
    wait_idle(sid2)
    before = open(os.path.join(target, "lib.py")).read()
    code, res = req(f"/api/session/{sid2}/rollback", {}, "POST")
    if code != 200 or not os.path.exists(os.path.join(target, "lib.py")) or \
            open(os.path.join(target, "lib.py")).read() != before:
        fail("discard did not leave the folder byte-identical")
    ok("Discard throws the sandbox away; the folder is untouched")

    # 9. sending to a committed conversation is refused clearly
    code, r = req(f"/api/chats/{sid}/message", {"message": "more"}, "POST")
    if code != 400 or "closed" not in r.get("error", ""):
        fail(f"message to a closed conversation: {code} {r}")
    ok("a message to a committed conversation is refused clearly")

    # 10. cross-origin POST is refused (shared guard covers the chat routes)
    code, r = req("/api/chats", {"message": "x", "target": target}, "POST",
                  headers={"Origin": "https://evil.example"})
    if code != 403:
        fail(f"cross-origin chat start: expected 403, got {code}")
    code, r = req("/api/settings", {"provider": "openai"}, "PUT",
                  headers={"Sec-Fetch-Site": "cross-site"})
    if code != 403:
        fail(f"cross-origin settings write: expected 403, got {code}")
    ok("the chat and settings routes sit behind the same origin guard as the console")

    # 11. model configuration: provider profiles, generation knobs, validation, live listing
    code, sp = req("/api/settings", {"provider": "openai-compatible",
                                     "provider_opts": {"model": "llama3", "base_url": "http://127.0.0.1:11434/v1",
                                                       "headers": '{"X-Team": "a"}'},
                                     "gen": {"max_tokens": 2048, "effort": "high", "temperature": "0.3",
                                             "stop": "END, STOP", "stream": False, "api": "responses"}}, "PUT")
    if code != 200 or sp["provider_opts"]["model"] != "llama3" or sp["provider_opts"]["headers"] != {"X-Team": "a"} \
            or sp["gen"]["max_tokens"] != 2048 or sp["gen"]["temperature"] != 0.3 or sp["gen"]["stream"] is not False \
            or sp["gen"]["api"] != "responses" or chatui.build_provider(chatui.load_settings()).api != "responses":
        fail(f"model settings round-trip: {code} {sp}")
    if not sp["provider_ready"]:
        fail("a keyless provider must count as ready")
    ids = [p["id"] for p in sp["providers_available"]]
    if ids != ["anthropic", "openai", "azure", "openai-compatible", "gemini"]:
        fail(f"providers listed: {ids}")
    code, sp = req("/api/settings", {"net": "host"}, "PUT")
    if code != 200 or sp["net"] != "host" or chatui.load_settings()["net"] != "host":
        fail(f"net setting round-trip: {code} {sp.get('net')}")
    req("/api/settings", {"net": "none"}, "PUT")
    for bad in ({"gen": {"effort": "extreme"}}, {"gen": {"temperature": "hot"}}, {"gen": {"api": "grpc"}}, {"net": "vpn"},
                {"provider_opts": {"headers": "not json"}}, {"provider_opts": {"base_url": "ftp://x"}}):
        code, r = req("/api/settings", bad, "PUT")
        if code != 400:
            fail(f"bad setting accepted: {bad}")
    # switching provider keeps the other profile
    code, sp = req("/api/settings", {"provider": "scripted"}, "PUT")
    if sp["providers"]["openai-compatible"]["model"] != "llama3":
        fail("provider profile lost on switch")
    code, m = req("/api/models?provider=scripted")
    if code != 200 or [x["id"] for x in m["models"]] != ["scripted"]:
        fail(f"models endpoint: {code} {m}")
    code, m = req("/api/models?provider=anthropic")
    if code != 400 or "API key" not in m.get("error", ""):
        fail(f"models without a key should fail clearly: {code} {m}")
    ok("model configuration: per-provider profiles, generation knobs validated, live listing")

    # 12. streaming: assistant text arrives as deltas before the final message; a
    #     per-conversation provider/model override is recorded on the session
    chatui.save_settings({"provider": "scripted", "workdir": target, "gen": {"stream": True},
                          "jail": KERNEL, "net": "none" if KERNEL else "host"})
    set_script([{"text": "Streamed reply for you.", "tool_calls": []}])
    code, r = req("/api/chats", {"message": "say hi", "target": target,
                                 "provider": "scripted", "model": "scripted-v2"}, "POST")
    if code != 200:
        fail(f"start with override: {r}")
    sid3 = r["sid"]
    events, _ = wait_idle(sid3)
    types = [e["type"] for e in events]
    deltas = [e["text"] for e in events if e["type"] == "assistant_delta"]
    if len(deltas) < 2 or "".join(deltas) != "Streamed reply for you." or \
            types.index("assistant_delta") < types.index("assistant") is False:
        fail(f"streaming deltas: {types} {deltas}")
    if types.index("assistant") < types.index("assistant_delta"):
        fail("final assistant message arrived before its deltas")
    m = core.load_meta(sid3)
    if m["agent"] != "scripted:scripted-v2" or not m.get("model_config") or "provider_opts" not in m:
        fail(f"per-conversation model not recorded: {m.get('agent')} {m.get('model_config')}")
    code, conv = req(f"/api/chats/{sid3}")
    if [x["type"] for x in conv["messages"]].count("assistant_delta"):
        fail("deltas must not be persisted as messages")
    req(f"/api/session/{sid3}/rollback", {}, "POST")
    ok("streaming deltas precede the final message; per-conversation model recorded")

    # 13. "/audit [focus]" starts the containment-audit preset — the authorized
    #     framing as the task, flagged on the session, refused without a jail
    set_script([{"text": "Every claim holds.", "tool_calls": []}])
    if KERNEL:
        code, r = req("/api/chats", {"message": "/audit seccomp only", "target": target}, "POST")
        if code != 200:
            fail(f"/audit start: {r}")
        sid4 = r["sid"]
        events, _ = wait_idle(sid4)
        m = core.load_meta(sid4)
        if m.get("audit") is not True or not m["task"].startswith("Authorized containment audit") \
                or "Focus for this run: seccomp only" not in m["task"]:
            fail(f"/audit task/meta: {m.get('audit')} {m['task'][:60]!r}")
        users = [e["text"] for e in events if e["type"] == "user"]
        notes = [e["text"] for e in events if e["type"] == "note"]
        if users != ["/audit seccomp only"] or not any("Containment audit" in n for n in notes):
            fail(f"/audit bubble/note: {users} {notes}")
        req(f"/api/session/{sid4}/rollback", {}, "POST")
    chatui.save_settings({"jail": False, "net": "host"})
    code, r = req("/api/chats", {"message": "/audit", "target": target}, "POST")
    if code != 400 or "nothing to audit" not in r.get("error", ""):
        fail(f"/audit without a jail accepted: {code} {r}")
    chatui.save_settings({"jail": KERNEL, "net": "none" if KERNEL else "host"})
    ok("/audit presets the containment audit in the workspace; jailed only")

    print("PASS: workspace")
finally:
    if server:
        server.shutdown()
    import subprocess
    subprocess.run(["rm", "-rf", OVERLORD_HOME, target])
