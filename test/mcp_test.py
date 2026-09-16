#!/usr/bin/env python3
"""Connectors (MCP) e2e: stdio and streamable-HTTP transports against local
servers; a session must be granted a connector by name; its tools reach the
model namespaced and a call is routed back to the server; non-read-only
tools pass the approval gate (ask / auto / readonly) and every decision is
in the transcript and the reviewer's dossier; the daemon caps connectors by
policy; the workspace configures connectors, grants them per conversation and
answers approvals over its API. No network: the fake servers run in-process."""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "sdk"))
HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = HOME

import overlord as ov      # noqa: E402
import audit               # noqa: E402
import agent               # noqa: E402
import mcp                 # noqa: E402
import review              # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


def events_of(sid):
    with open(ov.session_file(sid, "transcript.jsonl")) as f:
        return [json.loads(line) for line in f if line.strip()]


BACKEND = ov.detect_backend()
if BACKEND is None:
    print("SKIP: mcp (no sandbox backend here — see `overlord doctor`)")
    sys.exit(0)
KERNEL = BACKEND == "kernel"
grants = {"net": "none" if KERNEL else "host", "jail": KERNEL, "timeout": None, "merge_base": False}
FAKE = os.path.join(HERE, "test", "fake_mcp_server.py")
LOG = os.path.join(HOME, "sent.log")
target = tempfile.mkdtemp()
with open(os.path.join(target, "a.txt"), "w") as f:
    f.write("a\n")


# a streamable-HTTP MCP server: JSON for most calls, SSE for tools/call, a session id
class HttpMCP(BaseHTTPRequestHandler):
    calls = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        req = json.loads(self.rfile.read(n) or b"{}")
        HttpMCP.calls.append((req.get("method"), self.headers.get("Mcp-Session-Id"),
                              self.headers.get("Authorization")))
        method, rid = req.get("method"), req.get("id")
        if rid is None:                      # a notification
            self.send_response(202)
            self.end_headers()
            return
        if method == "initialize":
            body = {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "http-mcp", "version": "2"}}}
            self._json(body, session="sess-42")
        elif method == "tools/list":
            self._json({"jsonrpc": "2.0", "id": rid, "result": {"tools": [
                {"name": "lookup", "description": "look something up",
                 "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
                 "annotations": {"readOnlyHint": True}}]}})
        elif method == "tools/call":
            q = (req.get("params") or {}).get("arguments", {}).get("q")
            # streamed: a stray event first, then the answer
            body = (b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"
                    + b"event: message\ndata: " + json.dumps({"jsonrpc": "2.0", "id": rid, "result": {
                        "content": [{"type": "text", "text": f"found {q}"}]}}).encode() + b"\n\n")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._json({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "nope"}})

    def _json(self, obj, session=None):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if session:
            self.send_header("Mcp-Session-Id", session)
        self.end_headers()
        self.wfile.write(body)


httpd = ThreadingHTTPServer(("127.0.0.1", 0), HttpMCP)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
HTTP_URL = f"http://127.0.0.1:{httpd.server_address[1]}/mcp"

try:
    # ------------------------------------------------------------ config + transports
    mcp.add_server("fake", command=sys.executable, args=[FAKE], env={"MCP_FAKE_LOG": LOG})
    mcp.add_server("web", url=HTTP_URL, headers={"Authorization": "Bearer t0k"})
    for bad in (dict(name="x y", command="true"), dict(name="both", command="true", url="http://x"),
                dict(name="none"), dict(name="ftp", url="ftp://x")):
        try:
            mcp.add_server(**bad)
            fail(f"bad connector accepted: {bad}")
        except mcp.MCPError:
            pass
    pub = mcp.public_config()
    if pub["servers"]["fake"]["env"] != ["MCP_FAKE_LOG"] or "MCP_FAKE_LOG" in json.dumps(pub["servers"]["fake"].get("env_values", "")) \
            or pub["servers"]["web"]["headers"] != ["Authorization"] or "t0k" in json.dumps(pub):
        fail(f"public config leaks values: {pub}")
    ok("connector config: validation, secrets masked in the public view")

    reg = mcp.Registry(["fake", "web"]).connect()
    names = sorted(t["name"] for t in reg.tools())
    if names != ["mcp__fake__echo", "mcp__fake__send", "mcp__web__lookup"]:
        fail(f"namespaced tools: {names}")
    if reg.describe("mcp__fake__send")["read_only"] or not reg.describe("mcp__web__lookup")["read_only"]:
        fail("readOnlyHint not honoured")
    if reg.call("mcp__fake__echo", {"text": "hi"}) != ("hi", False):
        fail("stdio call")
    out, err = reg.call("mcp__web__lookup", {"q": "cats"})
    if out != "found cats" or err:
        fail(f"http call over SSE: {out!r} {err}")
    sess = [s for m, s, _a in HttpMCP.calls if m == "tools/call"]
    auth = {a for _m, _s, a in HttpMCP.calls}
    if sess != ["sess-42"] or auth != {"Bearer t0k"}:
        fail(f"http session id / headers: {sess} {auth}")
    reg.close()
    try:
        mcp.Registry(["nope"])
        fail("unknown connector accepted")
    except mcp.MCPError:
        pass
    ok("stdio (paginated tools/list) and streamable HTTP (JSON + SSE, session id, headers)")

    # ------------------------------------------------------------ agent: grant + approval modes
    def run(script, connectors, approval=None, approve=None):
        p = agent.ScriptedProvider(script)
        p.model = "scripted"
        live = ov.open_session(target, BACKEND, grants, capture=True, agent="scripted")
        ev = []
        agent.run_agent(live, p, "use connectors", max_turns=6, emit=ev.append,
                        connectors=connectors, approval=approval, approve=approve)
        sid, changes = live.close()
        return sid, ev, p

    def tool_outputs(ev):
        return {e["tool"]: e for e in ev if e["type"] == "tool_result"}

    SCRIPT = [{"text": "Using tools.", "tool_calls": [
                  {"name": "mcp__fake__echo", "input": {"text": "ping"}},
                  {"name": "mcp__fake__send", "input": {"to": "alice", "body": "hi"}},
                  {"name": "write_file", "input": {"path": "note.txt", "content": "n\n"}}]},
              {"text": "done"}]

    # no grant: the tools are not even offered
    sid, ev, p = run(SCRIPT, None)
    if any(t["name"].startswith("mcp__") for t in []) or "mcp__fake__echo" in json.dumps(p.seen[0]):
        fail("connector tools offered without a grant")
    res = tool_outputs(ev)
    if "unknown tool" not in res["mcp__fake__echo"]["output"]:
        fail(f"ungranted connector tool should be unknown: {res['mcp__fake__echo']['output']}")
    ov.rollback_session(sid)

    # ask mode with a denying approver: read-only runs, the action is refused, files still work
    if os.path.exists(LOG):
        os.remove(LOG)
    asked = []
    sid, ev, _ = run(SCRIPT, ["fake"], approval="ask", approve=lambda r: asked.append(r) and False)
    res = tool_outputs(ev)
    if res["mcp__fake__echo"]["output"] != "ping" or res["mcp__fake__echo"]["exit_code"] != 0:
        fail(f"read-only connector tool did not run: {res['mcp__fake__echo']}")
    if "denied" not in res["mcp__fake__send"]["output"] or res["mcp__fake__send"]["exit_code"] != 1:
        fail(f"denied action not refused: {res['mcp__fake__send']}")
    if os.path.exists(LOG):
        fail("a denied action still ran")
    if len(asked) != 1 or asked[0]["server"] != "fake" or asked[0]["tool"] != "send" or asked[0]["read_only"]:
        fail(f"approver was not asked correctly: {asked}")
    if "n\n" != open(os.path.join(ov.session_path(sid), "upper", "note.txt")).read():
        fail("file tool did not run alongside connector tools")
    evs = events_of(sid)
    kinds = [e["type"] for e in evs]
    if "connectors" not in kinds or "approval" not in kinds:
        fail(f"transcript lacks connector/approval records: {kinds}")
    decisions = {(e["tool"], e["decision"]) for e in evs if e["type"] == "approval_decision"}
    if decisions != {("echo", "read-only"), ("send", "denied")}:
        fail(f"decisions: {decisions}")
    calls = [e for e in evs if e["type"] == "tool_call" and e.get("external")]
    if len(calls) != 2 or calls[0]["connector"] != "fake":
        fail("external tool calls not marked in the transcript")
    m = ov.load_meta(sid)
    if m["grants"].get("connectors") != ["fake"] or m["grants"].get("connector_approval") != "ask":
        fail(f"grant not recorded: {m['grants']}")
    dossier, _ = review.build_dossier(sid)
    if "EXTERNAL ACTIONS" not in dossier or "fake.send: denied" not in dossier:
        fail("reviewer dossier does not surface external actions")
    prov = [json.loads(l) for l in open(ov.session_file(sid, "provenance.jsonl"))]
    if [r["path"] for r in prov] != ["note.txt"]:
        fail("connector calls must not appear as file provenance")
    # every connector call, its decision and its result are bound into the keyed
    # audit chain, the call by a fingerprint of exactly what it is
    aud = [e for e in audit.entries(n=0) if e.get("sid") == sid and e["action"].startswith("connector.")]
    call = [e for e in aud if e["action"] == "connector.call" and e["tool"] == "send"][0]
    fp = mcp.call_fingerprint("fake", "send", {"to": "alice", "body": "hi"})
    if call["fingerprint"] != fp:
        fail(f"connector.call fingerprint does not bind the arguments: {call}")
    dec = [e for e in aud if e["action"] == "connector.decision" and e["tool"] == "send"][0]
    if dec["fingerprint"] != fp or dec["decision"] != "denied" or dec.get("approved_by"):
        fail(f"connector.decision not bound to the call / a denial has no approver: {dec}")
    res = [e for e in aud if e["action"] == "connector.result" and e["tool"] == "echo"][0]
    if res["fingerprint"] != mcp.call_fingerprint("fake", "echo", {"text": "ping"}) \
            or res["bytes"] <= 0 or "result_sha256" not in res:
        fail(f"connector.result not recorded with a hash and size: {res}")
    if not audit.verify()["ok"] or not audit.verify()["keyed"]:
        fail("the connector records did not extend the signed audit chain")
    ov.rollback_session(sid)
    ok("ask mode: read-only runs, the action waits, a denial never runs; call/decision/result signed into the audit chain")

    # ask mode with no approver: denied; auto mode: runs; readonly mode: denied by policy
    sid, ev, _ = run(SCRIPT, ["fake"], approval="ask", approve=None)
    if "no one is available" not in tool_outputs(ev)["mcp__fake__send"]["output"]:
        fail("no approver should mean denial")
    ov.rollback_session(sid)
    sid, ev, _ = run(SCRIPT, ["fake"], approval="auto")
    if tool_outputs(ev)["mcp__fake__send"]["output"] != "sent: alice" or not os.path.exists(LOG):
        fail(f"auto mode did not run the action: {tool_outputs(ev)['mcp__fake__send']}")
    autodec = [e for e in audit.entries(n=0) if e.get("sid") == sid
               and e["action"] == "connector.decision" and e["tool"] == "send"][0]
    if autodec["decision"] != "auto-approved" or "fingerprint" not in autodec:
        fail(f"auto-approved decision not bound: {autodec}")
    if [json.loads(l)["to"] for l in open(LOG)] != ["alice"]:
        fail("the server did not receive the action")
    ov.rollback_session(sid)
    os.remove(LOG)
    sid, ev, _ = run(SCRIPT, ["fake"], approval="readonly", approve=lambda r: True)
    if "readonly" not in tool_outputs(ev)["mcp__fake__send"]["output"] or os.path.exists(LOG):
        fail("readonly mode ran an action")
    ov.rollback_session(sid)
    # a server-side tool error reaches the model as an error result
    sid, ev, _ = run([{"tool_calls": [{"name": "mcp__fake__boom", "input": {}}]}, {"text": "x"}],
                     ["fake"], approval="auto")
    out = tool_outputs(ev)
    if out and "mcp__fake__boom" in out and out["mcp__fake__boom"]["exit_code"] == 0:
        fail("isError result not surfaced")
    ov.rollback_session(sid)
    ok("no approver denies; auto runs; readonly refuses; server errors surface")

    # ------------------------------------------------------------ daemon: policy caps connectors
    from overlord_client import OverlordClient, OverlordError
    with open(ov.POLICY_FILE, "w") as f:
        json.dump({"default": {"connectors": ["fake"]}}, f)
    spath = os.path.join(HOME, "script.json")
    with open(spath, "w") as f:
        json.dump([{"tool_calls": [{"name": "mcp__fake__echo", "input": {"text": "via daemon"}}]},
                   {"text": "done"}], f)
    env = dict(os.environ, OVERLORD_AGENT_SCRIPT=spath)
    sock = os.path.join(HOME, "overlordd.sock")
    daemon = subprocess.Popen([sys.executable, os.path.join(HERE, "overlord.py"), "daemon", "--socket", sock],
                              env=env, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if os.path.exists(sock):
                break
            time.sleep(0.1)
        c = OverlordClient(sock, timeout=60)
        seen = []
        s = c._call("agent", on_event=seen.append, target=target, task="t", provider="scripted",
                    grants={"jail": KERNEL, "net": "none" if KERNEL else "host", "timeout": None,
                            "merge_base": False}, connectors=["fake"])
        outs = [e for e in seen if e.get("type") == "tool_result"]
        if not outs or outs[0]["output"] != "via daemon":
            fail(f"connector over the daemon: {outs}")
        c.rollback(s["sid"]) if hasattr(c, "rollback") else c._call("rollback", sid=s["sid"])
        try:
            c._call("agent", target=target, task="t", provider="scripted",
                    grants={"jail": KERNEL, "net": "none" if KERNEL else "host", "timeout": None,
                            "merge_base": False}, connectors=["web"])
            fail("policy let an ungranted connector through")
        except OverlordError as e:
            if "policy does not grant" not in str(e):
                fail(f"policy refusal text: {e}")
        ok("daemon: policy lists the connectors a brokered session may be granted")
    finally:
        daemon.terminate()
        daemon.wait()
    os.remove(ov.POLICY_FILE)

    # ------------------------------------------------------------ workspace API
    import ui
    import chatui
    PORT = 7794
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
        os.environ["OVERLORD_AGENT_SCRIPT"] = spath
        chatui.save_settings({"provider": "scripted", "workdir": target, "jail": KERNEL,
                              "net": "none" if KERNEL else "host"})
        code, cfg = req("/api/connectors")
        if code != 200 or sorted(cfg["servers"]) != ["fake", "web"] or "t0k" in json.dumps(cfg):
            fail(f"connectors listing: {cfg}")
        code, r = req("/api/connectors", {"name": "fake2", "command": sys.executable, "args": [FAKE],
                                          "env": {"MCP_FAKE_LOG": LOG}}, "POST")
        if code != 200 or r.get("transport") != "stdio":
            fail(f"add via API: {code} {r}")
        code, r = req("/api/connectors/fake2/test", {}, "POST")
        if code != 200 or [t["name"] for t in r["tools"]] != ["echo", "run_shell", "send"]:
            fail(f"test via API: {r}")
        code, r = req("/api/connectors/fake2/remove", {}, "POST")
        code, r = req("/api/connectors/approval", {"mode": "auto"}, "POST")
        if code != 200 or mcp.load_config()["approval"] != "auto":
            fail("approval mode via API")
        req("/api/connectors/approval", {"mode": "ask"}, "POST")
        # a conversation granted a connector; an action pauses for approval
        with open(spath, "w") as f:
            json.dump([{"text": "Sending.", "tool_calls": [
                           {"name": "mcp__fake__send", "input": {"to": "carol"}}]},
                       {"text": "sent"}], f)
        if os.path.exists(LOG):
            os.remove(LOG)
        code, r = req("/api/chats", {"message": "send carol a note", "target": target,
                                     "connectors": ["fake"]}, "POST")
        if code != 200:
            fail(f"chat with connector: {r}")
        sid = r["sid"]
        pending, frm = None, 0
        for _ in range(100):
            code, d = req(f"/api/chats/{sid}/events?from={frm}")
            frm = d["next"]
            pending = next((e for e in d["events"] if e["type"] == "approval"), pending)
            if pending:
                break
            time.sleep(0.05)
        if not pending or pending["server"] != "fake" or pending["tool"] != "send":
            fail(f"approval never surfaced: {pending}")
        code, d = req(f"/api/chats/{sid}/events?from={frm}")
        if not d["running"]:
            fail("the run should be paused, waiting for a decision")
        code, r = req(f"/api/chats/{sid}/approve", {"id": "wrong", "allow": True}, "POST")
        if code != 400:
            fail("a mismatched approval id was accepted")
        code, r = req(f"/api/chats/{sid}/approve", {"id": pending["id"], "allow": True}, "POST")
        if code != 200:
            fail(f"approve: {r}")
        for _ in range(100):
            code, d = req(f"/api/chats/{sid}/events?from={frm}")
            frm = d["next"]
            if not d["running"]:
                break
            time.sleep(0.05)
        if not os.path.exists(LOG) or json.loads(open(LOG).read())["to"] != "carol":
            fail("approved action did not run")
        # the approval is bound to who gave it and to the exact call
        dec = [e for e in audit.entries(n=0) if e.get("sid") == sid
               and e["action"] == "connector.decision" and e["tool"] == "send"][0]
        if dec["decision"] != "approved" or not dec.get("approved_by") \
                or dec["fingerprint"] != mcp.call_fingerprint("fake", "send", {"to": "carol"}):
            fail(f"workspace approval not bound to approver and call: {dec}")
        code, conv = req(f"/api/chats/{sid}")
        kinds = [m["type"] for m in conv["messages"]]
        if "approval_decision" not in kinds or not any(m.get("external") for m in conv["messages"]
                                                       if m["type"] == "tool_call"):
            fail(f"conversation view lacks the external action record: {kinds}")
        if ov.load_meta(sid)["grants"].get("connectors") != ["fake"]:
            fail("conversation grant not recorded")
        req(f"/api/session/{sid}/rollback", {}, "POST")
        code, r = req("/api/chats", {"message": "x", "target": target, "connectors": ["ghost"]}, "POST")
        if code != 400 or "no connector named" not in r.get("error", ""):
            fail(f"unknown connector on a chat: {code} {r}")
        ok("workspace: connectors configured and tested over the API; a granted action pauses for approval")
    finally:
        server.shutdown()

    print("PASS: connectors")
finally:
    httpd.shutdown()
    subprocess.run(["rm", "-rf", HOME, target])
