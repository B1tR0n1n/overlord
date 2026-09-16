#!/usr/bin/env python3
"""Skills e2e: a catalogue (project skills in .overlord/skills/, machine
skills in ~/.overlord/skills/) reaches the model up front; the `skill`
tool loads one on demand — a project skill through the jail, a machine
skill host-side, supporting files included, traversal refused — and every
load is a transcript event; an agent may author a project skill INSIDE the
transaction (a reviewed diff) and the next conversation is offered it;
policy caps the machine skills a folder sees; CLI and workspace manage
them. Scripted provider, no network."""

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
import skills              # noqa: E402
import audit               # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


def cli(*args):
    return subprocess.run([sys.executable, os.path.join(HERE, "overlord.py"), *args],
                          capture_output=True, text=True, env=os.environ)


BACKEND = ov.detect_backend()
if BACKEND is None:
    print("SKIP: skills (no sandbox backend here — see `overlord doctor`)")
    sys.exit(0)
KERNEL = BACKEND == "kernel"
grants = {"net": "none" if KERNEL else "host", "jail": KERNEL, "timeout": None, "merge_base": False}
target = tempfile.mkdtemp()
with open(os.path.join(target, "lib.py"), "w") as f:
    f.write("def a():\n    return 1\n")


def run(script, task="do it"):
    p = agent.ScriptedProvider(script)
    live = ov.open_session(target, BACKEND, grants, capture=True, agent="scripted:scripted")
    ev = []
    agent.run_agent(live, p, task, max_turns=8, emit=ev.append)
    sid, changes = live.close()
    return sid, changes, ev, p


def results(ev):
    return [e for e in ev if e["type"] == "tool_result"]


try:
    # 1. parsing and the catalogue: project skills win a name clash
    meta, body = skills.parse("---\nname: x\ndescription: 'Does x'\nwhen: always\n---\n# X\nbody\n")
    if meta != {"name": "x", "description": "Does x", "when": "always"} or not body.startswith("# X"):
        fail(f"parse: {meta} {body!r}")
    if cli("skills", "add", os.path.join(HERE, "skills", "python-testing")).returncode != 0:
        fail("skills add")
    if cli("skills", "add", os.path.join(HERE, "skills", "conventional-commits")).returncode != 0:
        fail("skills add 2")
    r = cli("skills", "add", os.path.join(HERE, "skills", "python-testing"))
    if r.returncode == 0:
        fail("a duplicate machine skill was installed")
    pdir = os.path.join(target, skills.PROJECT_DIR, "house-style")
    os.makedirs(pdir)
    with open(os.path.join(pdir, "SKILL.md"), "w") as f:
        f.write("---\nname: house-style\ndescription: This project's own conventions.\n---\n"
                "# House style\nTabs. Docstrings on everything.\n")
    os.makedirs(os.path.join(target, skills.PROJECT_DIR, "python-testing"))
    with open(os.path.join(target, skills.PROJECT_DIR, "python-testing", "SKILL.md"), "w") as f:
        f.write("---\ndescription: The project's own pytest notes (override).\n---\nrun `pytest -x`\n")
    cat = skills.catalogue(target)
    by = {s["name"]: s for s in cat}
    if set(by) != {"house-style", "python-testing", "conventional-commits"} \
            or by["python-testing"]["source"] != "project" or by["house-style"]["source"] != "project" \
            or by["conventional-commits"]["source"] != "machine":
        fail(f"catalogue: {[(s['name'], s['source']) for s in cat]}")
    out = cli("skills", "list", "-t", target).stdout
    if "house-style" not in out or "conventional-commits" not in out:
        fail(f"skills list:\n{out}")
    if "override" not in cli("skills", "show", "python-testing", "-t", target).stdout:
        fail("skills show did not pick the project one")
    ok("catalogue: machine skills installed, project skills found, a project skill wins a name clash")

    # 2. the model is told the catalogue; the tool loads project (jailed) and machine (host) skills
    script = [{"text": "loading", "tool_calls": [
                  {"name": "skill", "input": {"name": "house-style"}},
                  {"name": "skill", "input": {"name": "conventional-commits"}},
                  {"name": "skill", "input": {"name": "python-testing"}},
                  {"name": "skill", "input": {"name": "nope"}},
                  {"name": "skill", "input": {"name": "conventional-commits", "file": "../SKILL.md"}},
                  {"name": "skill", "input": {"name": "Bad Name"}}]},
              {"text": "done"}]
    sid, changes, ev, p = run(script)
    sysp = p.systems[0]
    for needle in ("# Skills", "house-style (project)", "conventional-commits (machine)",
                   "python-testing (project)"):
        if needle not in sysp:
            fail(f"system prompt lacks {needle!r}")
    if "skill" not in p.toolsets[0]:
        fail("skill tool not offered")
    outs = [(r["exit_code"], r["output"]) for r in results(ev)]
    if outs[0][0] != 0 or "Tabs. Docstrings" not in outs[0][1]:
        fail(f"project skill via the jail: {outs[0]}")
    if outs[1][0] != 0 or "Conventional commits" not in outs[1][1]:
        fail(f"machine skill host-side: {outs[1]}")
    if outs[2][0] != 0 or "pytest -x" not in outs[2][1]:
        fail(f"project override should be served: {outs[2]}")
    if outs[3][0] == 0 or "no skill named nope" not in outs[3][1]:
        fail(f"unknown skill: {outs[3]}")
    if outs[4][0] == 0 or outs[5][0] == 0:
        fail(f"traversal / bad name accepted: {outs[4]} {outs[5]}")
    tr = [json.loads(l) for l in open(ov.session_file(sid, "transcript.jsonl"))]
    offered = [e for e in tr if e["type"] == "skills"]
    uses = [(e["name"], e["source"]) for e in tr if e["type"] == "skill_use"]
    if len(offered) != 1 or len(offered[0]["offered"]) != 3:
        fail(f"skills offered event: {offered}")
    if uses != [("house-style", "project"), ("conventional-commits", "machine"), ("python-testing", "project")]:
        fail(f"skill_use events: {uses}")
    if ov.load_meta(sid).get("skills") != ["project:house-style", "project:python-testing",
                                            "machine:conventional-commits"]:
        fail(f"meta skills: {ov.load_meta(sid).get('skills')}")
    if changes:
        fail(f"loading skills changed the tree: {changes}")
    ov.rollback_session(sid)
    ok("catalogue in the prompt; loads through the jail / host-side; refusals; every load on the transcript")

    # 3. supporting files; an agent authors a project skill inside the transaction
    script = [{"text": "author", "tool_calls": [
                  {"name": "skill", "input": {"name": "python-testing", "file": "checklist.md"}},
                  {"name": "write_file", "input": {
                      "path": ".overlord/skills/release/SKILL.md",
                      "content": "---\nname: release\ndescription: How we cut a release here.\n---\n"
                                 "# Release\n1. bump VERSION\n2. tag\n"}},
                  {"name": "skill", "input": {"name": "release"}}]},
              {"text": "done"}]
    sid, changes, ev, p = run(script)
    outs = [(r["exit_code"], r["output"]) for r in results(ev)]
    # python-testing is shadowed by the project's override, which has no checklist.md,
    # and the machine copy is not consulted for a project name
    if outs[0][0] == 0:
        fail(f"a project override should not fall through to the machine copy's files: {outs[0]}")
    if outs[2][0] != 0 or "bump VERSION" not in outs[2][1]:
        fail(f"a skill written this session is loadable: {outs[2]}")
    if ("added", ".overlord/skills/release/SKILL.md") not in changes \
            or any(not p.startswith(".overlord/skills/release") for _k, p in changes):
        fail(f"the authored skill is a reviewed diff: {changes}")
    tr = [json.loads(l) for l in open(ov.session_file(sid, "transcript.jsonl"))]
    if [(e["name"], e["source"], e["file"]) for e in tr if e["type"] == "skill_use"] \
            != [("release", "project", "SKILL.md")]:
        fail("skill_use for the authored skill")
    ov.commit_session(sid)
    if "release" not in {s["name"] for s in skills.catalogue(target)}:
        fail("committed skill not in the next catalogue")
    sid, changes, ev, p = run([{"text": "hi"}])
    if "release (project): How we cut a release here." not in p.systems[0]:
        fail("the next conversation is not offered the authored skill")
    ov.rollback_session(sid)
    # the machine copy's supporting file is reachable when it is not shadowed
    os.rename(os.path.join(target, skills.PROJECT_DIR, "python-testing"),
              os.path.join(target, skills.PROJECT_DIR, "python-testing.off"))
    sid, changes, ev, p = run([{"text": "x", "tool_calls": [
        {"name": "skill", "input": {"name": "python-testing", "file": "checklist.md"}}]}, {"text": "done"}])
    r0 = results(ev)[0]
    if r0["exit_code"] != 0 or "Before you stop" not in r0["output"]:
        fail(f"machine supporting file: {r0}")
    ov.rollback_session(sid)
    ok("supporting files; an agent authors a project skill inside the transaction; the next run sees it")

    # 4. policy caps the machine skills a folder sees; project skills unaffected
    with open(ov.POLICY_FILE, "w") as f:
        json.dump({"default": {"skills": ["python-testing"]}}, f)
    names = [(s["name"], s["source"]) for s in skills.catalogue(target)]
    if ("conventional-commits", "machine") in names or ("house-style", "project") not in names \
            or ("python-testing", "machine") not in names:
        fail(f"policy cap: {names}")
    with open(ov.POLICY_FILE, "w") as f:
        json.dump({"default": {"skills": []}}, f)
    if any(s["source"] == "machine" for s in skills.catalogue(target)):
        fail("policy [] still offered machine skills")
    with open(ov.POLICY_FILE, "w") as f:
        json.dump({"default": {"skills": "*"}}, f)
    if ("conventional-commits", "machine") not in [(s["name"], s["source"]) for s in skills.catalogue(target)]:
        fail("policy * withheld a machine skill")
    os.unlink(ov.POLICY_FILE)
    ok("policy: a folder's rule lists the machine skills it may see; project skills unaffected")

    # 5. CLI new / rm; audit
    r = cli("skills", "new", "notes", "--description", "Scratch notes", "-t", target)
    if r.returncode != 0 or not os.path.isfile(os.path.join(target, skills.PROJECT_DIR, "notes", "SKILL.md")):
        fail(f"skills new -t: {r.stdout} {r.stderr}")
    r = cli("skills", "new", "global-notes", "--description", "Machine-wide notes")
    if r.returncode != 0 or "global-notes" not in cli("skills", "list", "-t", target).stdout:
        fail("skills new (machine)")
    if cli("skills", "rm", "global-notes").returncode != 0 or os.path.isdir(os.path.join(skills.MACHINE_DIR, "global-notes")):
        fail("skills rm")
    if cli("skills", "rm", "house-style").returncode == 0:
        fail("rm reached a project skill")
    ops = [(e.get("op"), e.get("skill")) for e in audit.entries(action="skills.config")]
    for want in (("add", "python-testing"), ("create", "global-notes"), ("remove", "global-notes")):
        if want not in ops:
            fail(f"audit lacks {want}: {ops}")
    ok("CLI new (project and machine), rm (machine only); changes audited")

    # 6. workspace API
    import ui
    from http.server import ThreadingHTTPServer
    PORT = 7792
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
        code, d = req(f"/api/skills?target={urllib.request.quote(target)}")
        names = {s["name"]: s["source"] for s in d["skills"]}
        if code != 200 or names.get("house-style") != "project" or names.get("conventional-commits") != "machine":
            fail(f"skills GET: {code} {names}")
        code, d = req("/api/skills", {"name": "ui-made", "description": "Made in the UI", "body": "# UI\nsteps"}, "POST")
        if code != 200 or d["source"] != "machine":
            fail(f"skills POST create: {code} {d}")
        code, d = req("/api/skills", {"path": os.path.join(HERE, "skills", "python-testing"), "name": "pt2"}, "POST")
        if code != 200:
            fail(f"skills POST install: {code} {d}")
        code, d = req("/api/skills/ui-made/remove", {}, "POST")
        code, d = req("/api/skills/pt2/remove", {}, "POST")
        code, d = req("/api/skills/house-style/remove", {}, "POST")
        if code != 400:
            fail("a project skill was removable from the workspace")
        ok("workspace: list, create, install, remove machine skills; project skills are the tree's")
    finally:
        server.shutdown()

    print("PASS: skills")
finally:
    subprocess.run(["rm", "-rf", HOME, target])
