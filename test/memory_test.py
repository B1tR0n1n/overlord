#!/usr/bin/env python3
"""Memory e2e: project notes (OVERLORD.md), user notes (~/.overlord/memory.md)
and the folder journal are injected into the system prompt, capped; the
`remember` tool writes project notes INSIDE the transaction (a reviewed file
change with a savepoint) and only proposes user notes, which a person accepts;
commit journals an agent session from the engine's records and the next run
sees it; the CLI and the workspace expose all of it. Scripted provider, no
network."""

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
import memory              # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


def run(script, target, task="do it"):
    p = agent.ScriptedProvider(script)
    p.model = "scripted"
    live = ov.open_session(target, BACKEND, grants, capture=True, agent="scripted")
    ev = []
    agent.run_agent(live, p, task, max_turns=6, emit=ev.append)
    sid, changes = live.close()
    return sid, changes, ev, p


BACKEND = ov.detect_backend()
if BACKEND is None:
    print("SKIP: memory (no sandbox backend here — see `overlord doctor`)")
    sys.exit(0)
KERNEL = BACKEND == "kernel"
grants = {"net": "none" if KERNEL else "host", "jail": KERNEL, "timeout": None, "merge_base": False}
target = tempfile.mkdtemp()
with open(os.path.join(target, "lib.py"), "w") as f:
    f.write("def a():\n    return 1\n")

try:
    # 1. nothing to inject: the system prompt is the bare one, remember is offered
    sid, _, _, p = run([{"text": "hi"}], target)
    if "# Memory" in p.systems[0] or "remember" not in p.toolsets[0]:
        fail("empty memory injected, or remember tool missing")
    ov.rollback_session(sid)
    text, summary = memory.build_context(target)
    if text or summary:
        fail("build_context not empty for an empty folder")
    ok("no memory: nothing injected; the remember tool is always offered")

    # 2. project + user memory reach the model, capped and labelled
    with open(os.path.join(target, "OVERLORD.md"), "w") as f:
        f.write("# Project notes\n\n- Tests run with `python3 -m pytest`.\n- Never touch vendor/.\n")
    memory.set_user_memory("Prefers short commit messages.\n")
    sid, _, _, p = run([{"text": "hi"}], target)
    sysp = p.systems[0]
    for needle in ("## Project notes", "python3 -m pytest", "## About the person", "short commit"):
        if needle not in sysp:
            fail(f"memory block lacks {needle!r}")
    m = ov.load_meta(sid)
    if m.get("memory", {}).get("project_chars") is None or m["memory"].get("user_chars") is None:
        fail(f"what the model was told is not recorded: {m.get('memory')}")
    ov.rollback_session(sid)
    big = "x" * (memory.PROJECT_CAP + 500)
    with open(os.path.join(target, "OVERLORD.md"), "w") as f:
        f.write(big)
    t, trunc = memory.project_memory(target)
    if not trunc or "more characters not shown" not in t or len(t) > memory.PROJECT_CAP + 100:
        fail("project memory not capped")
    with open(os.path.join(target, "OVERLORD.md"), "w") as f:
        f.write("# Project notes\n\n- Tests run with `python3 -m pytest`.\n")
    ok("project and user memory injected and labelled; oversized notes are capped")

    # 3. remember(project) is a transactional file change; remember(user) only proposes
    script = [{"text": "Noting.", "tool_calls": [
                  {"name": "remember", "input": {"scope": "project", "text": "lib.py is the core module"}},
                  {"name": "remember", "input": {"scope": "user", "text": "Likes tabs over spaces"}},
                  {"name": "remember", "input": {"scope": "project", "text": ""}}]},
              {"text": "done"}]
    sid, changes, ev, _ = run(script, target)
    if changes != [("modified", "OVERLORD.md")]:
        fail(f"project note should be a modified OVERLORD.md in the diff: {changes}")
    upper = os.path.join(ov.session_path(sid), "upper", "OVERLORD.md")
    text = open(upper).read()
    if not text.endswith("- lib.py is the core module\n") or "python3 -m pytest" not in text:
        fail(f"project note not appended cleanly:\n{text}")
    if open(os.path.join(target, "OVERLORD.md")).read().count("core module"):
        fail("project note reached the real folder before commit")
    results = {e["id"]: e for e in ev if e["type"] == "tool_result"}
    outs = [e["output"] for e in ev if e["type"] == "tool_result"]
    if "suggestion" not in outs[1] or outs[2].startswith("error") is False:
        fail(f"remember outputs: {outs}")
    subs = memory.suggestions(sid)
    if len(subs) != 1 or subs[0]["text"] != "Likes tabs over spaces" or subs[0]["accepted"]:
        fail(f"user suggestion not recorded: {subs}")
    if "tabs" in memory.user_memory()[0]:
        fail("a user-scope note was written without a person")
    prov = {json.loads(l)["path"]: json.loads(l) for l in open(ov.session_file(sid, "provenance.jsonl"))}
    if prov["OVERLORD.md"]["caused_by"]["tool"] != "remember":
        fail("the note is not attributed to the remember call")
    ok("remember: project scope is a reviewed, attributed file change; user scope only proposes")

    # 4. a person accepts the suggestion; acceptance is recorded, idempotent
    memory.accept_suggestion(sid, subs[0]["id"])
    if "Likes tabs over spaces" not in memory.user_memory()[0]:
        fail("acceptance did not write user memory")
    memory.accept_suggestion(sid, subs[0]["id"])
    if memory.user_memory()[0].count("Likes tabs") != 1 or not memory.suggestions(sid)[0]["accepted"]:
        fail("acceptance not idempotent / not recorded")
    try:
        memory.accept_suggestion(sid, "nope")
        fail("unknown suggestion accepted")
    except ov.OverlordError:
        pass
    ok("a person accepts a proposed note; recorded in the transcript, idempotent")

    # 5. commit journals the session; the next run is told about it
    ov.commit_session(sid)
    rows = memory.journal_entries(target)
    if len(rows) != 1 or rows[0]["session"] != sid or rows[0]["changed"] != ["OVERLORD.md"] \
            or rows[0]["outcome"] != "done" or rows[0]["task"] != "do it":
        fail(f"journal entry: {rows}")
    if "core module" not in open(os.path.join(target, "OVERLORD.md")).read():
        fail("committed note not in the folder")
    sid2, _, _, p = run([{"text": "again"}], target, task="second")
    if "## Recent committed work" not in p.systems[0] or "task: do it" not in p.systems[0] \
            or "core module" not in p.systems[0]:
        fail("the next run does not see the journal and the committed note")
    ov.rollback_session(sid2)
    # a rolled-back session is not journaled; a plain (non-agent) commit is not either
    if len(memory.journal_entries(target)) != 1:
        fail("rollback journaled")
    live = ov.open_session(target, BACKEND, grants, capture=True)
    live.exec(["bash", "-c", "echo x > plain.txt"])
    sid3, _ = live.close()
    ov.commit_session(sid3)
    if len(memory.journal_entries(target)) != 1:
        fail("a non-agent session was journaled")
    ok("commit journals agent sessions from the record; the next conversation is told")

    # 6. CLI
    base = [sys.executable, os.path.join(HERE, "overlord.py")]
    r = subprocess.run(base + ["memory", "show", "-t", target], capture_output=True, text=True, env=os.environ)
    if r.returncode != 0 or "Project notes" not in r.stdout or "Recent committed work" not in r.stdout:
        fail(f"memory show: {r.stdout} {r.stderr}")
    r = subprocess.run(base + ["memory", "user", "--add", "Works nights."], capture_output=True, text=True, env=os.environ)
    if "Works nights." not in memory.user_memory()[0]:
        fail("memory user --add")
    r = subprocess.run(base + ["memory", "journal", "-t", target], capture_output=True, text=True, env=os.environ)
    if sid not in r.stdout:
        fail(f"memory journal: {r.stdout}")
    r = subprocess.run(base + ["memory", "accept", sid], capture_output=True, text=True, env=os.environ)
    if "accepted" not in r.stdout:
        fail(f"memory accept listing: {r.stdout}")
    ok("CLI: show, user --add, journal, accept")

    # 7. workspace API
    import ui
    import chatui
    PORT = 7793
    from http.server import ThreadingHTTPServer
    server = ThreadingHTTPServer(("127.0.0.1", PORT), ui.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    BASE = f"http://127.0.0.1:{PORT}"

    def req(path, data=None, method=None):
        body = json.dumps(data).encode() if data is not None else None
        r = urllib.request.Request(BASE + path, data=body, method=method,
                                   headers={"Host": f"127.0.0.1:{PORT}", "Cookie": ui.local_cookie()})
        try:
            with urllib.request.urlopen(r, timeout=20) as resp:
                return resp.status, json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or "{}")

    try:
        chatui.save_settings({"provider": "scripted", "workdir": target, "jail": KERNEL,
                              "net": "none" if KERNEL else "host"})
        code, mem = req("/api/memory")
        if code != 200 or "Works nights." not in mem["user"] or "core module" not in mem["project"] \
                or len(mem["journal"]) != 1:
            fail(f"memory GET: {code} {mem}")
        code, r = req("/api/memory", {"user": "Only this line.\n"}, "PUT")
        if code != 200 or memory.user_memory()[0] != "Only this line.\n":
            fail(f"memory PUT: {code} {r}")
        code, r = req("/api/memory", {"user": 5}, "PUT")
        if code != 400:
            fail("bad memory PUT accepted")
        # a conversation proposes a note; the workspace shows and accepts it
        spath = os.path.join(HOME, "script.json")
        with open(spath, "w") as f:
            json.dump([{"text": "Noting you.", "tool_calls": [
                           {"name": "remember", "input": {"scope": "user", "text": "Uses zsh"}}]},
                       {"text": "ok"}], f)
        os.environ["OVERLORD_AGENT_SCRIPT"] = spath
        code, r = req("/api/chats", {"message": "remember my shell", "target": target}, "POST")
        sid4 = r["sid"]
        import time
        frm, sug = 0, None
        for _ in range(100):
            code, d = req(f"/api/chats/{sid4}/events?from={frm}")
            frm = d["next"]
            sug = next((e for e in d["events"] if e["type"] == "memory_suggestion"), sug)
            if not d["running"]:
                break
            time.sleep(0.05)
        if not sug or sug["text"] != "Uses zsh":
            fail(f"suggestion event: {sug}")
        code, conv = req(f"/api/chats/{sid4}")
        cards = [m for m in conv["messages"] if m["type"] == "memory_suggestion"]
        if len(cards) != 1 or cards[0]["accepted"]:
            fail(f"conversation view suggestion: {cards}")
        code, r = req(f"/api/chats/{sid4}/remember", {"id": sug["id"]}, "POST")
        if code != 200 or "Uses zsh" not in memory.user_memory()[0]:
            fail(f"accept via API: {code} {r}")
        code, conv = req(f"/api/chats/{sid4}")
        if not [m for m in conv["messages"] if m["type"] == "memory_suggestion"][0]["accepted"]:
            fail("accepted state not reflected")
        req(f"/api/session/{sid4}/rollback", {}, "POST")
        ok("workspace: memory read and written; a proposed note is shown and accepted")
    finally:
        server.shutdown()

    print("PASS: memory")
finally:
    subprocess.run(["rm", "-rf", HOME, target])
