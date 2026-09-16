#!/usr/bin/env python3
"""Webhooks e2e against a local receiver: hooks subscribe to audit actions;
an agent session finishing with changes, an external action waiting at
the approval gate and a budget stop each reach the receiver (slack text
and signed json, with a link when a base URL is set); a failing endpoint
is retried three times, a 4xx once; `webhooks test`; the API. Scripted
provider and a fake MCP server, no network."""

import hashlib
import hmac
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
HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = HOME
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

import overlord as ov      # noqa: E402
import agent               # noqa: E402
import notify              # noqa: E402
import audit               # noqa: E402
import mcp as mcp_mod      # noqa: E402
import chatui              # noqa: E402

RX_PORT = 7787
GOT = []                   # (path, headers, body) per delivery
BEHAVE = {"/ok": 200, "/flaky": 500, "/gone": 404}


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


class Receiver(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        GOT.append((self.path, dict(self.headers), body))
        code = BEHAVE.get(self.path, 200)
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()


def deliveries(path=None, action=None):
    out = []
    for p, h, b in GOT:
        if path and p != path:
            continue
        if action and h.get("X-Overlord-Event") != action:
            continue
        out.append((p, h, b))
    return out


def wait_for(pred, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


def cli(*args, stdin=None):
    return subprocess.run([sys.executable, os.path.join(HERE, "overlord.py"), *args],
                          capture_output=True, text=True, env=os.environ, input=stdin)


BACKEND = ov.detect_backend()
if BACKEND is None:
    print("SKIP: webhook (no sandbox backend here — see `overlord doctor`)")
    sys.exit(0)
KERNEL = BACKEND == "kernel"
grants = {"net": "none" if KERNEL else "host", "jail": KERNEL, "timeout": None, "merge_base": False}
target = tempfile.mkdtemp()
with open(os.path.join(target, "lib.py"), "w") as f:
    f.write("def a():\n    return 1\n")
rx = ThreadingHTTPServer(("127.0.0.1", RX_PORT), Receiver)
threading.Thread(target=rx.serve_forever, daemon=True).start()
RX = f"http://127.0.0.1:{RX_PORT}"


def run(script, owner=None, **kw):
    p = agent.ScriptedProvider(script)
    live = ov.open_session(target, BACKEND, grants, capture=True, agent="scripted:scripted", owner=owner)
    ev = []
    agent.run_agent(live, p, "do it", max_turns=6, emit=ev.append, **kw)
    sid, changes = live.close()
    return sid, changes, ev


try:
    # 1. configured by the CLI: a slack hook and a signed json hook, a base URL for links
    r = cli("webhooks", "add", "team", RX + "/ok")
    if r.returncode != 0 or "session.needs_review" not in r.stdout:
        fail(f"webhooks add: {r.stdout} {r.stderr}")
    r = cli("webhooks", "add", "siem", RX + "/ok", "--format", "json", "--secret-stdin",
            "--event", "session.needs_review", "--event", "budget.stop", "--event", "connector.approval_requested",
            "--event", "session.commit", stdin="hush-hush\n")
    if r.returncode != 0:
        fail(f"webhooks add json: {r.stderr}")
    cli("webhooks", "base-url", "https://overlord.example.lan:7777/")
    out = cli("webhooks", "list").stdout
    if "team" not in out or "signed" not in out or "overlord.example.lan" not in out or "hush" in out:
        fail(f"webhooks list:\n{out}")
    if os.stat(notify.CONFIG_FILE).st_mode & 0o077:
        fail("webhooks.json not private")
    if cli("webhooks", "add", "team", RX + "/ok").returncode == 0:
        fail("duplicate hook accepted")
    ok("hooks added by the CLI: slack text, signed json, base URL; config private")

    # 2. an agent finishes with changes -> session.needs_review reaches both hooks
    sid, changes, ev = run([{"text": "w", "tool_calls": [{"name": "shell", "input": {"command": "echo a > a.txt"}}]},
                           {"text": "done"}], owner="bob")
    if not wait_for(lambda: len(deliveries("/ok", "session.needs_review")) >= 2):
        fail(f"needs_review not delivered: {[(p, h.get('X-Overlord-Event')) for p, h, b in GOT]}")
    slack = [b for p, h, b in deliveries("/ok", "session.needs_review") if b"\"text\"" in b and b"\"seq\"" not in b]
    signed = [(h, b) for p, h, b in deliveries("/ok", "session.needs_review") if "X-Overlord-Signature" in h]
    if len(slack) != 1 or len(signed) != 1:
        fail(f"one slack and one signed delivery expected: {len(slack)} {len(signed)}")
    text = json.loads(slack[0])["text"]
    if "bob" not in text or "waiting for review" not in text or f"https://overlord.example.lan:7777/?sid={sid}" not in text:
        fail(f"slack text: {text}")
    h, b = signed[0]
    want = "sha256=" + hmac.new(b"hush-hush", b, hashlib.sha256).hexdigest()
    body = json.loads(b)
    if h["X-Overlord-Signature"] != want or body["action"] != "session.needs_review" or body["sid"] != sid \
            or body["files"] != 1 or body["owner"] != "bob" or "hash" in body or body["link"].endswith(sid) is False:
        fail(f"signed json: {h.get('X-Overlord-Signature')} {body}")
    if not any(e["action"] == "session.needs_review" and e["sid"] == sid for e in audit.entries(n=0)):
        fail("needs_review not on the audit log itself")
    ov.rollback_session(sid)
    ok("an agent's finished work notifies: slack text with a link, signed json with the facts")

    # 3. a connector action waiting at the approval gate; a budget stop
    mcp_mod.add_server("fake", command=sys.executable, args=[os.path.join(HERE, "test", "fake_mcp_server.py")])
    decided = []

    def approve(req):
        decided.append(req["tool"])
        return False

    sid, changes, ev = run([{"text": "send", "tool_calls": [{"name": "mcp__fake__send", "input": {"to": "x"}}]},
                           {"text": "done"}], owner="bob", connectors=["fake"], approval="ask", approve=approve)
    if not wait_for(lambda: deliveries("/ok", "connector.approval_requested")):
        fail("approval_requested not delivered")
    b = [b for p, h, b in deliveries("/ok", "connector.approval_requested") if b"\"seq\"" in b][0]
    body = json.loads(b)
    if body["server"] != "fake" or body["tool"] != "send" or "waiting for approval" not in body["text"]:
        fail(f"approval payload: {body}")
    if decided != ["send"]:
        fail(f"the gate still asked: {decided}")
    ov.rollback_session(sid)
    with open(ov.POLICY_FILE, "w") as f:
        json.dump({"default": {"budget": {"session_tokens": 100}}}, f)
    sid, changes, ev = run([{"text": "x", "usage": {"in": 500, "out": 5},
                             "tool_calls": [{"name": "shell", "input": {"command": "true"}}]}, {"text": "done"}])
    os.unlink(ov.POLICY_FILE)
    if not wait_for(lambda: deliveries("/ok", "budget.stop")):
        fail("budget.stop not delivered")
    if "budget stop" not in json.loads([b for p, h, b in deliveries("/ok", "budget.stop")][0])["text"]:
        fail("budget text")
    ov.rollback_session(sid)
    # a commit reaches only the hook subscribed to it
    before = len(deliveries("/ok", "session.commit"))
    sid, changes, ev = run([{"text": "w", "tool_calls": [{"name": "shell", "input": {"command": "echo c > c.txt"}}]},
                           {"text": "done"}])
    ov.commit_session(sid)
    if not wait_for(lambda: len(deliveries("/ok", "session.commit")) == before + 1):
        fail("commit not delivered exactly once (json hook only)")
    if any(b"\"seq\"" not in b for p, h, b in deliveries("/ok", "session.commit")):
        fail("the slack hook (not subscribed) got a commit")
    ok("approval gate and budget stop notify; each hook gets only the events it asked for")

    # 4. retries: a 500 is tried three times, a 404 once; failures are counted, never raised
    cli("webhooks", "add", "flaky", RX + "/flaky", "--event", "webhook.test")
    cli("webhooks", "add", "gone", RX + "/gone", "--event", "webhook.test")
    GOT.clear()
    r = cli("webhooks", "test", "flaky")
    if r.returncode == 0 or "3 attempt" not in r.stderr + r.stdout:
        fail(f"flaky test should fail after 3 attempts: {r.stdout} {r.stderr}")
    if len(deliveries("/flaky")) != 3:
        fail(f"500 should be retried 3 times: {len(deliveries('/flaky'))}")
    r = cli("webhooks", "test", "gone")
    if r.returncode == 0 or len(deliveries("/gone")) != 1 or "1 attempt" not in r.stderr + r.stdout:
        fail(f"404 should not be retried: {len(deliveries('/gone'))} {r.stderr}")
    r = cli("webhooks", "test", "team")
    if r.returncode != 0 or "delivery works" not in json.loads(deliveries("/ok")[-1][2])["text"]:
        fail(f"webhooks test: {r.stdout} {r.stderr}")
    # a failing hook in the background: the caller's work is untouched, stats say so
    GOT.clear()
    notify.dispatch({"action": "webhook.test", "hook": "flaky", "ts": "now", "actor": "t"})
    notify.wait_idle(15)
    # both test-subscribed hooks were tried; either may be the last error named
    if notify._STATS["failed"] < 2 or not any(x in (notify._STATS["last_error"] or "") for x in ("flaky", "gone")):
        fail(f"stats: {notify._STATS}")
    cli("webhooks", "rm", "flaky")
    cli("webhooks", "rm", "gone")
    ops = [(e.get("op"), e.get("hook")) for e in audit.entries(action="webhook.config")]
    if ("add", "team") not in ops or ("remove", "flaky") not in ops:
        fail(f"webhook config audited: {ops}")
    ok("retries: 500 x3, 404 x1; a failing hook never fails the work; config audited")

    # 5. the API and the deep link
    import ui
    PORT = 7786
    server = ThreadingHTTPServer(("127.0.0.1", PORT), ui.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    BASE = f"http://127.0.0.1:{PORT}"

    def req(path, data=None, method=None):
        body = json.dumps(data).encode() if data is not None else None
        r = urllib.request.Request(BASE + path, data=body, method=method, headers={"Host": f"127.0.0.1:{PORT}", "Cookie": ui.local_cookie()})
        try:
            with urllib.request.urlopen(r, timeout=20) as resp:
                return resp.status, json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or "{}")

    try:
        code, d = req("/api/webhooks")
        names = {h["name"]: h for h in d["hooks"]}
        if code != 200 or set(names) != {"team", "siem"} or not names["siem"]["has_secret"] \
                or "secret" in names["siem"] or d["base_url"] != "https://overlord.example.lan:7777":
            fail(f"webhooks GET: {code} {d}")
        code, d = req("/api/webhooks", {"name": "ui", "url": RX + "/ok", "events": ["gc"]}, "POST")
        if code != 200 or d.get("added") != "ui":
            fail(f"webhooks POST: {code} {d}")
        code, d = req("/api/webhooks", {"name": "bad", "url": "ftp://x"}, "POST")
        if code != 400:
            fail("bad URL accepted")
        code, d = req("/api/webhooks/ui/test", {}, "POST")
        if code != 200:
            fail(f"api test: {code} {d}")
        code, d = req("/api/webhooks/ui/remove", {}, "POST")
        if code != 200 or "ui" in {h["name"] for h in req("/api/webhooks")[1]["hooks"]}:
            fail("remove via API")
        if "get('sid')" not in chatui.chat_shell("n"):
            fail("workspace lacks the ?sid= deep link")
        ok("API: list without secrets, add, test, remove; the workspace honours ?sid= links")
    finally:
        server.shutdown()

    print("PASS: webhooks")
finally:
    rx.shutdown()
    subprocess.run(["rm", "-rf", HOME, target])
