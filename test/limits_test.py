#!/usr/bin/env python3
"""Resource limits and deterministic gates: rlimits bound process count,
file size and open files in every command; a cgroup surrounds the session
where the host allows and is released after; the disk grant is measured
per layer and a crossing ends the session's ability to run — the agent
loop stops with reason "limit"; policy limits are ceilings; a harness
file touched needs a fresh, complete countersignature and cannot be
forced; a truncated reviewer dossier fails closed; shell-shaped connector
tools are withheld unless granted. Scripted provider, no network."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = HOME

import overlord as ov      # noqa: E402
import agent               # noqa: E402
import review              # noqa: E402
import audit               # noqa: E402
import mcp as mcp_mod      # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


BACKEND = ov.detect_backend()
if BACKEND is None:
    print("SKIP: limits (no sandbox backend here — see `overlord doctor`)")
    sys.exit(0)
if BACKEND != "kernel":
    print("SKIP: limits (rlimits are not enforced for a privileged user outside the jail)")
    sys.exit(0)
target = tempfile.mkdtemp()
with open(os.path.join(target, "lib.py"), "w") as f:
    f.write("def a():\n    return 1\n")


def grants(**lim):
    g = {"net": "none", "jail": True, "timeout": None, "merge_base": False}
    if lim:
        g["limits"] = {**ov.DEFAULT_LIMITS, **lim}
    return g


def run(cmd, **lim):
    live = ov.open_session(target, "kernel", grants(**lim), capture=True)
    rc, out = live.exec(["bash", "-c", cmd], timeout=60)
    meta = dict(live.meta)
    sid, changes = live.close()
    return rc, out.decode(errors="replace"), meta, sid


try:
    # 1. rlimits inside the jail: processes, file size, open files
    rc, out, meta, sid = run(
        "python3 - <<'EOF'\n"
        "import subprocess, sys\n"
        "ps, failed = [], 0\n"
        "for i in range(40):\n"
        "    try: ps.append(subprocess.Popen(['sleep', '3']))\n"
        "    except (OSError, BlockingIOError): failed += 1\n"
        "print('spawn-failed', failed)\n"
        "for p in ps: p.kill()\n"
        "EOF", pids=16)
    if "spawn-failed 0" in out or "spawn-failed" not in out:
        fail(f"pids limit not enforced: {out[-300:]}")
    ov.rollback_session(sid)
    rc, out, meta, sid = run("dd if=/dev/zero of=big bs=1M count=20 2>&1; ls -l big | awk '{print $5}'", fsize_mb=8)
    size = int(out.strip().splitlines()[-1] or 0)
    if size > 8 << 20:
        fail(f"fsize limit not enforced: {size} bytes")
    ov.rollback_session(sid)
    rc, out, meta, sid = run("python3 -c \"import os\nfs=[]\ntry:\n    [fs.append(open('/dev/null')) for _ in range(200)]\n    print('opened', len(fs))\nexcept OSError as e:\n    print('nofile-hit', len(fs))\"", nofile=64)
    if "nofile-hit" not in out:
        fail(f"nofile limit not enforced: {out[-200:]}")
    if meta["limits"]["nofile"] != 64:
        fail(f"limits not recorded on the session: {meta.get('limits')}")
    ov.rollback_session(sid)
    ok("rlimits in every command: process count, file size, open files; recorded on the session")

    # 2. a cgroup surrounds the session where the host allows, and is released
    live = ov.open_session(target, "kernel", grants(pids=33), capture=True)
    cg = live.meta.get("cgroup") or {}
    kind = cg.get("kind")
    if kind not in ("v1", "v2", "systemd", "none"):
        fail(f"cgroup kind: {cg}")
    if kind in ("v1", "v2"):
        pidsfile = next((os.path.join(p, "pids.max") for p in cg["paths"] if os.path.isfile(os.path.join(p, "pids.max"))), None)
        if not pidsfile or open(pidsfile).read().strip() != "33":
            fail(f"cgroup pids.max not set: {cg}")
        procs = next((os.path.join(p, "cgroup.procs") for p in cg["paths"]), None)
        if str(live.meta["holder_pid"]) not in open(procs).read().split():
            fail("holder not in the cgroup")
    rc, out = live.exec(["bash", "-c", "grep -E '^(pids|memory|cpu)' /proc/self/cgroup /proc/self/status 2>/dev/null | head -3; echo ran"])
    sid, _ = live.close()
    if kind in ("v1", "v2") and any(os.path.exists(p) for p in cg["paths"]):
        fail("cgroup not released after close")
    ov.rollback_session(sid)
    ok(f"a cgroup surrounds the session ({kind} on this host) and is released after close")

    # 3. the disk grant: measured per layer; a crossing ends the session's commands; the agent stops
    live = ov.open_session(target, "kernel", grants(disk_mb=1), capture=True)
    rc, out = live.exec(["bash", "-c", "dd if=/dev/zero of=fill bs=1M count=2 2>/dev/null; echo wrote"])
    if rc != ov.DISK_RC or "exceeded its disk grant" not in out.decode():
        fail(f"disk grant not enforced: rc={rc} {out[-200:]}")
    try:
        live.exec(["true"])
        fail("commands still run after the disk grant was crossed")
    except ov.OverlordError:
        pass
    sid, changes = live.close()
    if ("added", "fill") not in changes or ov.load_meta(sid)["disk_bytes"] < (1 << 20):
        fail(f"what was written should stay for review: {changes} {ov.load_meta(sid).get('disk_bytes')}")
    ov.rollback_session(sid)
    p = agent.ScriptedProvider([{"text": "fill", "tool_calls": [{"name": "shell", "input": {"command": "dd if=/dev/zero of=fill bs=1M count=2 2>/dev/null"}}]},
                                {"text": "more", "tool_calls": [{"name": "shell", "input": {"command": "echo again > more.txt"}}]},
                                {"text": "done"}])
    live = ov.open_session(target, "kernel", grants(disk_mb=1), capture=True, agent="scripted:scripted")
    ev = []
    agent.run_agent(live, p, "fill the disk", max_turns=5, emit=ev.append)
    sid, changes = live.close()
    done = [e for e in ev if e["type"] == "done"][-1]
    if done["reason"] != "limit" or len(p.seen) != 1:
        fail(f"the agent should stop at the disk line after one call: {done['reason']} calls={len(p.seen)}")
    if not any(e["action"] == "limit.stop" and e.get("sid") == sid for e in audit.entries(n=0)):
        fail("limit stop not audited")
    if "disk_mb" not in p.systems[0] or "Resource grants" not in p.systems[0]:
        fail("the agent is not told its resource grants")
    ov.rollback_session(sid)
    ok("disk grant: measured per layer, a crossing ends commands, the agent stops with reason limit, audited")

    # 4. policy limits are ceilings; --limit parses; the CLI carries it
    with open(ov.POLICY_FILE, "w") as f:
        json.dump({"default": {"limits": {"pids": 8, "memory_mb": 512}}}, f)
    eff, _rule = ov.resolve_policy(target, grants(pids=500, memory_mb=0))
    if eff["limits"]["pids"] != 8 or eff["limits"]["memory_mb"] != 512:
        fail(f"policy ceiling: {eff['limits']}")
    eff, _rule = ov.resolve_policy(target, grants(pids=4))
    if eff["limits"]["pids"] != 4:
        fail("a tighter request should win")
    os.unlink(ov.POLICY_FILE)
    ns = argparse.Namespace(manifest=None, net=None, jail=True, timeout=None, merge_base=False,
                            limit=["pids=12", "disk_mb=0"], connector_shell=False)
    g = ov.load_grants(ns)
    if g["limits"]["pids"] != 12 or g["limits"]["disk_mb"] != 0 or g["limits"]["nofile"] != ov.DEFAULT_LIMITS["nofile"]:
        fail(f"--limit parsing: {g['limits']}")
    try:
        ov.parse_limits(["cores=2"])
        fail("unknown limit key accepted")
    except ov.OverlordError:
        pass
    r = subprocess.run([sys.executable, os.path.join(HERE, "overlord.py"), "run", "--jail", "--limit", "fsize_mb=1",
                        "-t", target, "--", "bash", "-c", "dd if=/dev/zero of=x bs=1M count=3 2>&1 | tail -1; ls -l x | awk '{print $5}'"],
                       capture_output=True, text=True, env=os.environ)
    sizes = [int(w) for w in r.stdout.split() if w.isdigit() and int(w) > 4096]   # the ls -l size column
    if not sizes or max(sizes) > (1 << 20):
        fail(f"CLI --limit: sizes={sizes}\n{r.stdout}\n{r.stderr}")
    sid_cli = next((w for w in r.stdout.split() if w.startswith("2")), None)
    if sid_cli:
        ov.rollback_session(sid_cli)
    ok("policy limits are ceilings; --limit parses; the CLI carries it")

    # 5. gates: protected paths need a complete countersignature and cannot be forced
    harness = tempfile.mkdtemp()
    for n in ("overlord.py", "auth.py", "README.md"):
        with open(os.path.join(harness, n), "w") as f:
            f.write(f"# {n}\nx = 1\n")
    live = ov.open_session(harness, "kernel", grants(), capture=True, agent="scripted:scripted")
    live.exec(["bash", "-c", "echo 'x = 2  # weaker' >> auth.py; echo note >> README.md"])
    sid, changes = live.close()
    if sorted(ov.protected_hits(harness, changes)) != ["auth.py"]:
        fail(f"protected hits: {ov.protected_hits(harness, changes)}")
    try:
        ov.commit_session(sid)
        fail("a harness file was committed without a countersignature")
    except ov.OverlordError as e:
        if "protected" not in str(e) or "countersignature" not in str(e):
            fail(f"wrong refusal: {e}")
    try:
        ov.commit_session(sid, force=True)
        fail("--force reached a protected path")
    except ov.OverlordError as e:
        if "refused" not in str(e):
            fail(f"wrong force refusal: {e}")
    # a truncated dossier: the reviewer approves what it did not see -> fail closed
    saved = review.MAX_DIFF_CHARS
    review.MAX_DIFF_CHARS = 40
    rp = agent.ScriptedProvider([{"tool_calls": [{"name": "approve", "input": {"reason": "looks fine"}}]}])
    rp.model = "reviewer-x"
    rec = review.run_review(sid, rp)
    review.MAX_DIFF_CHARS = saved
    if not rec["truncated"] or not rec["omitted"] or "NOT seen the whole diff" not in rp.seen[0][0]["content"]:
        fail(f"truncation not recorded / not told: {rec.get('truncated')} {rec.get('omitted')}")
    try:
        ov.commit_session(sid, countersigned=True)
        fail("an approval on a truncated dossier countersigned a commit")
    except ov.OverlordError as e:
        if "whole diff" not in str(e):
            fail(f"wrong truncation refusal: {e}")
    rp = agent.ScriptedProvider([{"tool_calls": [{"name": "approve", "input": {"reason": "read it all"}}]}])
    rp.model = "reviewer-x"
    rec = review.run_review(sid, rp)
    if rec["truncated"]:
        fail("a full dossier marked truncated")
    res = ov.commit_session(sid)
    if not res["committed"] or "weaker" not in open(os.path.join(harness, "auth.py")).read():
        fail(f"a complete countersignature should commit: {res}")
    # policy may name its own protected set (or none)
    with open(ov.POLICY_FILE, "w") as f:
        json.dump({"default": {"protect": []}}, f)
    live = ov.open_session(harness, "kernel", grants(), capture=True)
    live.exec(["bash", "-c", "echo more >> auth.py"])
    sid2, changes = live.close()
    if ov.protected_hits(harness, changes):
        fail("policy protect: [] should disable the harness default")
    ov.rollback_session(sid2)
    with open(ov.POLICY_FILE, "w") as f:
        json.dump({"default": {"protect": ["*.md", "secrets/*"]}}, f)
    live = ov.open_session(harness, "kernel", grants(), capture=True)
    live.exec(["bash", "-c", "mkdir -p secrets; echo k > secrets/key; echo doc >> README.md; echo z >> auth.py"])
    sid3, changes = live.close()
    if sorted(ov.protected_hits(harness, changes)) != ["README.md", "secrets/key"]:
        fail(f"policy protect globs: {ov.protected_hits(harness, changes)}")
    ov.rollback_session(sid3)
    os.unlink(ov.POLICY_FILE)
    shutil.rmtree(harness)
    ok("protected paths: countersignature required, --force refused, truncated review fails closed, policy globs")

    # 6. shell-shaped connector tools are withheld unless granted
    mcp_mod.add_server("fake", command=sys.executable, args=[os.path.join(HERE, "test", "fake_mcp_server.py")])
    reg = mcp_mod.Registry(["fake"])
    names = [t["name"] for t in reg.tools()]
    if "mcp__fake__run_shell" in names or reg.withheld != ["mcp__fake__run_shell"] or "mcp__fake__send" not in names:
        fail(f"shell tool not withheld: {names} {reg.withheld}")
    reg2 = mcp_mod.Registry(["fake"], allow_shell=True)
    if "mcp__fake__run_shell" not in [t["name"] for t in reg2.tools()]:
        fail("connector_shell grant did not offer the tool")
    p = agent.ScriptedProvider([{"text": "hi"}])
    live = ov.open_session(target, "kernel", {**grants(), "connectors": ["fake"]}, capture=True, agent="scripted:scripted")
    agent.run_agent(live, p, "x", max_turns=2, emit=lambda e: None, connectors=["fake"], approval="auto")
    sid, _ = live.close()
    tr = [json.loads(l) for l in open(ov.session_file(sid, "transcript.jsonl"))]
    conn = [e for e in tr if e["type"] == "connectors"][0]
    if conn["withheld"] != ["mcp__fake__run_shell"] or "mcp__fake__run_shell" in p.toolsets[0]:
        fail(f"withheld not recorded / tool offered: {conn}")
    ov.rollback_session(sid)
    with open(ov.POLICY_FILE, "w") as f:
        json.dump({"default": {"connectors": "*"}}, f)
    eff, _r = ov.resolve_policy(target, {**grants(), "connector_shell": True})
    if eff.get("connector_shell"):
        fail("policy without connector_shell should drop the grant")
    with open(ov.POLICY_FILE, "w") as f:
        json.dump({"default": {"connectors": "*", "connector_shell": True}}, f)
    eff, _r = ov.resolve_policy(target, {**grants(), "connector_shell": True})
    if not eff.get("connector_shell"):
        fail("policy connector_shell: true should keep the grant")
    os.unlink(ov.POLICY_FILE)
    ok("shell-shaped connector tools withheld by default; offered only with the connector_shell grant, policy-gated")

    print("PASS: limits")
finally:
    subprocess.run(["rm", "-rf", HOME, target])
