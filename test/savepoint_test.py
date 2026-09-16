#!/usr/bin/env python3
"""Savepoints e2e: every writing tool call seals its own overlay layer; the
flattened stack is what diff/commit see; rewind cuts layers and transcript
together; resume restores the model's memory and continues on the stack;
commit --only/--drop replays a selection of layers; conflict detection covers
paths a dropped-or-cancelled layer would still touch; blame attributes lines
to the session, turn, tool call and instruction that produced them.

Runs on whichever backend detect_backend() picks; OVERLORD_TEST_BACKEND=fuse
forces the cooperative backend (no jail, no /tmp carry-over assertion)."""

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


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


def cli(*argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = ov.main(list(argv))
    return rc, buf.getvalue()


def read(path):
    with open(path) as f:
        return f.read()


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def scripted(script):
    p = agent.ScriptedProvider(script)
    p.model = "scripted"
    return p


def events_of(sid):
    with open(os.path.join(ov.session_path(sid), "transcript.jsonl")) as f:
        return [json.loads(line) for line in f if line.strip()]


BACKEND = os.environ.get("OVERLORD_TEST_BACKEND") or ov.detect_backend()
if BACKEND is None:
    print("SKIP: savepoint (no sandbox backend here — see `overlord doctor`)")
    sys.exit(0)
KERNEL = BACKEND == "kernel"
if BACKEND is None:
    print("SKIP: no overlay backend")
    sys.exit(0)
grants = {"net": "none" if KERNEL else "host", "jail": KERNEL,
          "timeout": None, "merge_base": False}

target = tempfile.mkdtemp()
write(f"{target}/README.md", "# demo\n")
write(f"{target}/lib.py", "def a():\n    return 1\n")
write(f"{target}/old.txt", "stale\n")

try:
    # ------------------------------------------------------------ A. layers
    carry_out = "echo x > /tmp/carry" if KERNEL else "true"
    carry_in = "cat /tmp/carry" if KERNEL else "echo x"
    script = [
        {"text": "Looking.", "tool_calls": [
            {"name": "list_dir", "input": {"path": "."}},
            {"name": "read_file", "input": {"path": "lib.py"}}]},
        {"tool_calls": [{"name": "write_file",
                         "input": {"path": "src/hello.py", "content": "print('hi')\n"}}]},
        {"tool_calls": [{"name": "shell",
                         "input": {"command": f"echo tmp > scratch.txt; {carry_out}"}}]},
        {"tool_calls": [{"name": "shell", "input": {"command": "rm scratch.txt; rm old.txt"}}]},
        {"text": "Bumping a.", "tool_calls": [{"name": "write_file",
                         "input": {"path": "lib.py", "content": "def a():\n    return 2\n"}}]},
        {"tool_calls": [{"name": "shell", "input": {"command": carry_in}}]},
        {"text": "Done."},
    ]
    live = ov.open_session(target, BACKEND, grants, capture=True, agent="scripted")
    ev = []
    agent.run_agent(live, scripted(script), "make hello", max_turns=10, emit=ev.append)
    sid1, changes = live.close()
    m = ov.load_meta(sid1)
    layers = m["layers"]
    causes = [(l.get("cause") or {}).get("turn") for l in layers]
    tools = [(l.get("cause") or {}).get("tool") for l in layers]
    if len(layers) != 5 or causes != [2, 3, 4, 5, 6] or tools != [
            "write_file", "shell", "shell", "write_file", "shell"]:
        fail(f"layers: {[(l.get('n'), l.get('cause')) for l in layers]}")
    sps = ov.session_savepoints(sid1)
    paths = [sorted(tuple(p) for p in sp["paths"]) for sp in sps]
    if paths[1] != [("added", "scratch.txt")] or paths[2] != [
            ("deleted", "old.txt"), ("deleted", "scratch.txt")] or paths[4] != []:
        fail(f"savepoint paths: {paths}")
    ok("one layer per writing tool call; reads ride the next empty layer")

    expect = {("added", "src/"), ("added", "src/hello.py"), ("deleted", "old.txt"),
              ("modified", "lib.py")}
    if set(changes) != expect:
        fail(f"flattened changes: {changes}")
    prov = {r["path"]: r for r in map(json.loads, open(
        os.path.join(ov.session_path(sid1), "provenance.jsonl")))}
    if prov["lib.py"]["layer"] != 3 or prov["lib.py"]["caused_by"]["turn"] != 5:
        fail(f"lib.py provenance: {prov['lib.py']}")
    if prov["old.txt"]["layer"] != 2 or prov["old.txt"]["caused_by"]["turn"] != 4:
        fail(f"old.txt provenance: {prov['old.txt']}")
    if "scratch.txt" in prov:
        fail("a path created and deleted inside the stack leaked into provenance")
    if read(f"{target}/old.txt") != "stale\n" or os.path.exists(f"{target}/src"):
        fail("target mutated before commit")
    results = [e for e in ev if e["type"] == "tool_result"]
    if [e.get("layer") for e in results] != [0, 0, 0, 1, 2, 3, 4]:
        fail(f"tool_result layers: {[e.get('layer') for e in results]}")
    if KERNEL and "x" not in results[-1]["output"]:
        fail(f"/tmp did not carry across tool calls: {results[-1]['output']!r}")
    ok("stack flattens like the kernel: cancelled paths vanish, provenance names the layer")

    rc, out = cli("savepoints", sid1, "--paths")
    if rc != 0 or "@1" not in out or "turn 3 shell" not in out or "scratch.txt" not in out:
        fail(f"savepoints CLI: {out}")
    rc, out = cli("diff", sid1)
    if "lib.py  @3" not in out:
        fail(f"diff CLI layer tag: {out}")
    ok("savepoints and diff CLI")

    # ------------------------------------------------------------ B. rewind
    remaining = ov.rewind_session(sid1, 1)
    if set(remaining) != {("added", "src/"), ("added", "src/hello.py"), ("added", "scratch.txt")}:
        fail(f"after rewind: {remaining}")
    m = ov.load_meta(sid1)
    sdir = ov.session_path(sid1)
    if len(m["layers"]) != 2 or os.path.isdir(os.path.join(sdir, "layers", "2")):
        fail("layers not dropped")
    if [e["layer"] for e in m["execs"]] != [0, 0, 0, 1] or len(m["rewinds"]) != 1:
        fail(f"execs after rewind: {m['execs']}")
    evs = events_of(sid1)
    kinds = [e["type"] for e in evs]
    if kinds[-1] != "rewind" or kinds.count("tool_result") != 4 or any(
            e.get("turn", 0) > 3 for e in evs if e["type"] != "rewind"):
        fail(f"transcript after rewind: {kinds}")
    archived = os.path.join(sdir, "transcript.rewound.1.jsonl")
    if not os.path.isfile(archived) or "return 2" not in read(archived):
        fail("dropped transcript tail not archived")
    try:
        ov.rewind_session(sid1, 7)
        fail("rewind past the stack accepted")
    except ov.OverlordError:
        pass
    rc, out = cli("log", sid1)
    if "lib.py" in out or "old.txt" in out:
        fail(f"provenance not re-derived after rewind: {out}")
    ok("rewind drops layers, execs and transcript together; the tail is archived")

    # ------------------------------------------------------------ C. resume
    cont = [
        {"tool_calls": [{"name": "shell", "input": {"command": "ls; cat scratch.txt"}}]},
        {"text": "Bumping a to 3.", "tool_calls": [{"name": "write_file",
                         "input": {"path": "lib.py", "content": "def a():\n    return 3\n"}}]},
        {"text": "Resumed and done."},
    ]
    p2 = scripted(cont)
    live = ov.reopen_session(sid1, capture=True)
    ev = []
    final = agent.run_agent(live, p2, "make hello", max_turns=10, emit=ev.append,
                            resume=True, note="keep scratch.txt, and make a() return 3")
    sid, changes = live.close()
    if sid != sid1 or "Resumed" not in final:
        fail(f"resume: {sid} {final!r}")
    seen = p2.seen[0]
    if seen[0] != {"role": "user", "content": "make hello"}:
        fail(f"restored history does not start with the task: {seen[0]}")
    ids = [tc["id"] for msg in seen if msg["role"] == "assistant" for tc in msg["tool_calls"]]
    answered = [msg["tool_call_id"] for msg in seen if msg["role"] == "tool"]
    if ids != answered or len(ids) != 4:
        fail(f"restored tool pairing: {ids} vs {answered}")
    if seen[-1]["role"] != "user" or "OPERATOR" not in seen[-1]["content"] or \
            "keep scratch.txt" not in seen[-1]["content"]:
        fail(f"operator note missing: {seen[-1]}")
    if any("return 2" in json.dumps(msg) for msg in seen):
        fail("rewound turn leaked into the restored history")
    turns = [e["turn"] for e in ev if e["type"] == "tool_result"]
    if turns != [4, 5]:
        fail(f"resumed turns: {turns}")
    if "tmp" not in [e for e in ev if e["type"] == "tool_result"][0]["output"]:
        fail("resumed model does not see the rewound world (scratch.txt)")
    m = ov.load_meta(sid1)
    if len(m["layers"]) != 3 or m["layers"][2]["cause"]["turn"] != 5 or len(m["resumed"]) != 1:
        fail(f"layers after resume: {m['layers']}")
    if set(changes) != {("added", "src/"), ("added", "src/hello.py"),
                        ("added", "scratch.txt"), ("modified", "lib.py")}:
        fail(f"changes after resume: {changes}")
    kinds = [e["type"] for e in events_of(sid1)]
    if "resume" not in kinds or kinds[-1] != "done":
        fail(f"transcript after resume: {kinds}")
    ok("resume: the model's memory and world are cut at the same savepoint; it carries on")

    # ------------------------------------------------------------ D. commit by cause
    for bad in ({"only": "tool:nope"}, {"drop": "0-2"}, {"only": "layer:9"}, {"only": "x:1"}):
        try:
            ov.commit_session(sid1, **bad)
            fail(f"bad selector accepted: {bad}")
        except ov.OverlordError:
            pass
    if ov.select_layers(m, only="turn:2-5", drop="tool:shell") != [0, 2]:
        fail("selector algebra")
    res = ov.commit_session(sid1, drop="tool:shell")
    if not res["committed"] or res["layers"] != [0, 2] or res["dropped"] != [1] or res["applied"] != 3:
        fail(f"partial commit result: {res}")
    if read(f"{target}/src/hello.py") != "print('hi')\n" or read(f"{target}/lib.py") != \
            "def a():\n    return 3\n":
        fail("selected layers not applied")
    if os.path.exists(f"{target}/scratch.txt") or read(f"{target}/old.txt") != "stale\n":
        fail("dropped layer leaked into the tree")
    m = ov.load_meta(sid1)
    prov = {r["path"]: r for r in map(json.loads, open(
        os.path.join(ov.session_path(sid1), "provenance.jsonl")))}
    if "scratch.txt" in prov or m["layers_dropped"] != [1] or not prov["lib.py"].get("after_retained"):
        fail(f"post-commit record: {list(prov)} {m.get('layers_dropped')}")
    if os.path.isdir(os.path.join(ov.session_path(sid1), "layers")):
        fail("layers not cleaned up after commit")
    ok("commit --drop tool:shell: the decision is undone, later work that stands alone is kept")

    # ------------------------------------------------------------ E. conflicts across layers
    live = ov.open_session(target, BACKEND, grants, capture=True)
    live.exec(["bash", "-c", "echo a > ghost.txt"])
    live.exec(["bash", "-c", "rm ghost.txt; echo b > README.md"])
    sid2, changes = live.close()
    if set(changes) != {("modified", "README.md")} or len(ov.load_meta(sid2)["layers"]) != 2:
        fail(f"plain session stack: {changes}")
    write(f"{target}/ghost.txt", "external\n")
    res = ov.commit_session(sid2)
    if res["committed"] or "ghost.txt" not in [p for _r, p in res["conflicts"]] or \
            len(res["conflicts"]) != len(set(res["conflicts"])):
        fail(f"cancelled path not guarded: {res}")
    if read(f"{target}/ghost.txt") != "external\n":
        fail("external file destroyed by a refused commit")
    os.remove(f"{target}/ghost.txt")
    res = ov.commit_session(sid2, drop="1")
    if not res["committed"] or read(f"{target}/ghost.txt") != "a\n" or read(f"{target}/README.md") != "# demo\n":
        fail(f"drop of the cancelling layer: {res}")
    os.remove(f"{target}/ghost.txt")
    ok("conflict detection covers what replay touches, not just the net diff")

    # ------------------------------------------------------------ F. blame
    live = ov.open_session(target, BACKEND, grants, capture=True, agent="scripted")
    bump = [{"text": "Adding b.", "tool_calls": [{"name": "write_file", "input": {
                "path": "lib.py",
                "content": "def a():\n    return 3\n\ndef b():\n    return 0\n"}}]},
            {"text": "ok"}]
    agent.run_agent(live, scripted(bump), "add b()", max_turns=5)
    sid3, _ = live.close()
    ov.commit_session(sid3)
    res = ov.blame_path(f"{target}/lib.py")
    vs = res["versions"]
    if [v["sid"] for v in vs] != [sid1, sid3] or res["state"] != "current":
        fail(f"blame versions: {[(v['sid'], v['kind']) for v in vs]} {res['state']}")
    if vs[0]["task"] != "make hello" or vs[0]["cause"]["turn"] != 5 or vs[1]["said"] != "Adding b.":
        fail(f"blame legend: {vs}")
    owners = [ln["owner"] for ln in res["lines"]]
    if owners != ["origin", 0, 1, 1, 1]:
        fail(f"line owners: {owners}")
    with open(f"{target}/lib.py", "a") as f:
        f.write("# drift\n")
    res = ov.blame_path(f"{target}/lib.py")
    if res["state"] != "drifted" or [ln["owner"] for ln in res["lines"]][-1] != "drift":
        fail(f"drift not detected: {res['state']} {res['lines'][-1]}")
    rc, out = cli("blame", f"{target}/lib.py")
    if rc != 0 or "task:   make hello" not in out or "t5 write_file" not in out or \
            "OUTSIDE overlord" not in out:
        fail(f"blame CLI: {out}")
    rc, out = cli("blame", f"{target}/README.md")
    if rc != 1 or "no committed" not in out:
        fail(f"blame of an unrecorded path: {rc} {out}")
    res = ov.blame_path(f"{target}/old.txt")
    if res["versions"]:
        fail("a path from a dropped layer was blamed")
    ok("blame: each line names its session, turn, tool call and instruction; drift shows")

    # ------------------------------------------------------------ G. CLI resume + rewind
    home = os.environ["OVERLORD_HOME"]
    spath = os.path.join(home, "script.json")
    with open(spath, "w") as f:
        json.dump([{"tool_calls": [{"name": "write_file",
                                    "input": {"path": "x.txt", "content": "x\n"}}]},
                   {"tool_calls": [{"name": "write_file",
                                    "input": {"path": "y.txt", "content": "y\n"}}]},
                   {"text": "done"}], f)
    env = dict(os.environ, OVERLORD_AGENT_SCRIPT=spath)
    base = [sys.executable, os.path.join(HERE, "overlord.py")]
    extra = [] if KERNEL else ["--no-jail", "--backend", BACKEND]
    r = subprocess.run(base + ["agent", "--provider", "scripted", *extra, "-t", target, "xy"],
                       env=env, capture_output=True, text=True)
    sid4 = [l for l in r.stdout.splitlines() if l.startswith("session ")][0].split()[1]
    r = subprocess.run(base + ["rewind", sid4, "--to", "0"], env=env, capture_output=True, text=True)
    if r.returncode != 0 or "1 change(s) remain" not in r.stdout:
        fail(f"rewind CLI: {r.stdout} {r.stderr}")
    r = subprocess.run(base + ["resume", sid4, "--note", "again"], env=env,
                       capture_output=True, text=True)
    if r.returncode != 0 or "resumed at savepoint @0" not in r.stdout:
        fail(f"resume CLI: {r.stdout} {r.stderr}")
    m = ov.load_meta(sid4)
    if m["status"] != "pending" or len(m["layers"]) != 3:   # 0: x, 1: x again, 2: y
        fail(f"resumed session record: {m['status']} {len(m['layers'])}")
    r = subprocess.run(base + ["commit", sid4, "--only", "turn:2-3"], env=env,
                       capture_output=True, text=True)
    if r.returncode != 0 or "0 dropped" not in r.stdout or not os.path.exists(f"{target}/y.txt"):
        fail(f"commit --only CLI: {r.stdout} {r.stderr}")
    ok("CLI: rewind, resume with a note, commit --only")

    # ------------------------------------------------------------ H. daemon + SDK
    from overlord_client import OverlordClient, OverlordError
    sock = os.path.join(home, "overlordd.sock")
    daemon = subprocess.Popen(base + ["daemon", "--socket", sock], env=env,
                              stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if os.path.exists(sock):
                break
            time.sleep(0.1)
        c = OverlordClient(sock, timeout=60)
        kw = {} if KERNEL else {"jail": False}
        ls = c.open(target, jail=KERNEL, net="none" if KERNEL else "host")
        ls.exec(["bash", "-c", "echo 1 > d1.txt"])
        ls.exec(["bash", "-c", "echo 2 > d2.txt"])
        sps = ls.savepoints()
        if [len(s["paths"]) for s in sps] != [1, 1]:
            fail(f"sdk savepoints: {sps}")
        res = ls.rewind(0)
        if set(map(tuple, res["changes"])) != {("added", "d1.txt")} or not res["open"]:
            fail(f"sdk live rewind: {res}")
        ls.exec(["bash", "-c", "echo 3 > d3.txt"])
        s = ls.close()
        if set(s.changes) != {("added", "d1.txt"), ("added", "d3.txt")}:
            fail(f"after live rewind + exec: {s.changes}")
        if [len(x["paths"]) for x in s.savepoints()] != [1, 1]:
            fail("pending savepoints over the socket")
        s.rewind(0)
        s.commit(only="layer:0")
        if not os.path.exists(f"{target}/d1.txt") or os.path.exists(f"{target}/d3.txt"):
            fail("sdk rewind/commit(only=)")
        b = c.blame(f"{target}/d1.txt")
        if b["state"] != "current" or len(b["versions"]) != 1:
            fail(f"sdk blame: {b}")
        # agent over the socket, then rewind + resume over the socket
        seen = []
        s = c.agent(target, "xy", provider="scripted", on_event=seen.append, **kw)
        c.rewind(s.sid, 0)
        seen = []
        s2 = c.resume(s.sid, note="once more", provider="scripted", on_event=seen.append)
        if s2.sid != s.sid or "resume" not in [e.get("type") for e in seen] or \
                "done" not in s2.final:
            fail(f"sdk resume: {[e.get('type') for e in seen]} {s2.final!r}")
        s2.rollback()
        try:
            c.rewind(s.sid, 0)
            fail("rewind of a rolled-back session accepted")
        except OverlordError:
            pass
        ok("daemon + SDK: savepoints, rewind (live and pending), commit(only=), blame, resume")
    finally:
        daemon.terminate()
        daemon.wait()

    print(f"PASS: savepoints ({BACKEND} backend)")
finally:
    subprocess.run(["rm", "-rf", os.environ["OVERLORD_HOME"], target])
