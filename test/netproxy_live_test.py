#!/usr/bin/env python3
"""net=proxy end to end on the kernel backend: a jailed session whose only
route out is the recording proxy. A direct connect from inside has no route;
the proxy reaches an allowed upstream and records it; a denied host is
refused. The upstream is a local HTTP server in the parent's namespace, so
no real network is needed. Self-skips without the kernel backend."""

import http.server
import json
import os
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = HOME

import overlord as ov      # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


if ov.detect_backend() != "kernel":
    print("SKIP: netproxy_live (no kernel backend)")
    sys.exit(0)


class Upstream(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"REACHED-UPSTREAM"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
UPORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

target = tempfile.mkdtemp()
with open(os.path.join(target, "f.txt"), "w") as f:
    f.write("x\n")

try:
    grants = {"net": "proxy", "jail": True, "timeout": None, "merge_base": False,
              "net_allow": ["127.0.0.1"]}
    live = ov.open_session(target, "kernel", grants, capture=True, agent="scripted:probe")

    # 1. the namespace is empty: no route to any non-loopback address, and the
    #    parent's upstream (on the parent's own loopback) is not reachable directly
    rc, out = live.exec(["python3", "-c",
                         "import socket; s=socket.socket(); s.settimeout(4); s.connect(('10.255.255.1', 80))"])
    if rc == 0 or (b"unreachable" not in out.lower() and b"101" not in out):
        fail(f"a non-loopback address was not unreachable inside net=proxy: {rc} {out[-200:]!r}")
    rc, out = live.exec(["python3", "-c",
                         f"import socket; s=socket.socket(); s.settimeout(4); s.connect(('127.0.0.1',{UPORT}))"])
    if rc == 0:
        fail("the parent's upstream was reachable directly — the netns is not isolated")
    ok("inside net=proxy the namespace is empty: no route to any host, the upstream only exists via the proxy")

    # 2. the same host is reachable THROUGH the proxy, and recorded
    prog = ("import os,socket\n"
            "p=os.environ['HTTP_PROXY'].split('//')[-1]; ph,pp=p.split(':')\n"
            "s=socket.create_connection((ph,int(pp)),timeout=5)\n"
            f"s.sendall(b'GET http://127.0.0.1:{UPORT}/ok HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nConnection: close\\r\\n\\r\\n')\n"
            "d=b''\n"
            "while True:\n"
            " c=s.recv(4096)\n"
            " if not c: break\n"
            " d+=c\n"
            "print(d.decode('latin1'))\n")
    rc, out = live.exec(["python3", "-c", prog])
    if rc != 0 or b"REACHED-UPSTREAM" not in out:
        fail(f"the allowed upstream was not reachable through the proxy: {rc} {out[-300:]!r}")
    ok("the allowed host is reachable only through the proxy, which the agent is told is its route")

    # 3. HTTP_PROXY is set inside the jail
    rc, out = live.exec(["sh", "-c", "echo $HTTP_PROXY"])
    if b"127.0.0.1:" not in out:
        fail(f"HTTP_PROXY not set in the jail: {out!r}")
    ok("the proxy is wired into the jail's environment (HTTP_PROXY/HTTPS_PROXY)")

    sid, _ = live.close()

    # 4. every connection is on the session's egress record
    egress = os.path.join(ov.session_path(sid), "egress.jsonl")
    rows = [json.loads(x) for x in open(egress)]
    allowed = [r for r in rows if r.get("allowed") and r["host"] == "127.0.0.1" and r["port"] == UPORT]
    if not allowed or allowed[-1]["down"] <= 0:
        fail(f"the allowed connection was not recorded with bytes: {rows}")
    ok("every egress connection is recorded with its destination and byte counts")

    ov.rollback_session(sid)

    # 5. a host outside the allowlist is refused by the proxy
    grants = {"net": "proxy", "jail": True, "timeout": None, "merge_base": False,
              "net_allow": ["example.invalid"]}
    live = ov.open_session(target, "kernel", grants, capture=True, agent="scripted:probe")
    rc, out = live.exec(["python3", "-c", prog])
    if b"403" not in out and b"REACHED-UPSTREAM" in out:
        fail(f"a denied host was reachable: {out[-200:]!r}")
    sid, _ = live.close()
    rows = [json.loads(x) for x in open(os.path.join(ov.session_path(sid), "egress.jsonl"))]
    if not any(r.get("allowed") is False for r in rows):
        fail(f"the denied connection was not recorded as blocked: {rows}")
    ok("a host outside --net-allow is refused by the proxy and logged as blocked")
    ov.rollback_session(sid)

    print("PASS: netproxy_live")
finally:
    srv.shutdown()
    import subprocess
    subprocess.run(["rm", "-rf", HOME, target])
