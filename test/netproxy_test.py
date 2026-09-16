#!/usr/bin/env python3
"""netproxy e2e, offline: the recording/allowlisting proxy against a local
upstream. The front is simulated by passing an accepted client socket to the
back over a control socketpair, exactly as it happens across the empty
namespace boundary. No jail, no network beyond loopback."""

import http.server
import os
import socket
import sys
import threading
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import netproxy as np      # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


# a local upstream that both a tunnel (CONNECT) and a plain proxied GET reach
class Upstream(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"UPSTREAM {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
UPORT = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()


def run_back(allow, rec):
    """A back loop over a fresh control socketpair; returns (front_ctrl, stop)."""
    front_ctrl, back_ctrl = socket.socketpair()
    stop = threading.Event()
    threading.Thread(target=np.run_backend, args=(back_ctrl, allow, rec, stop), daemon=True).start()
    return front_ctrl, stop


def proxied(allow, rec, request, read_reply=True):
    """Simulate the front for one client: a real client connects to a local
    listener; we accept it and pass the fd to the back, then the client speaks
    `request` (a callable given its socket) and we return what it read."""
    front_ctrl, stop = run_back(allow, rec)
    lst = socket.socket(); lst.bind(("127.0.0.1", 0)); lst.listen(1)
    port = lst.getsockname()[1]
    out = {}

    def client():
        c = socket.create_connection(("127.0.0.1", port)); c.settimeout(5)
        try:
            out["reply"] = request(c)
        finally:
            c.close()

    ct = threading.Thread(target=client); ct.start()
    conn, _ = lst.accept()
    np.send_fd(front_ctrl, conn.fileno())
    conn.close()
    ct.join(10)
    time.sleep(0.05)
    stop.set(); front_ctrl.close(); lst.close()
    return out.get("reply")


try:
    # 1. the allowlist: deny-by-default with patterns, record-all without
    a = np.Allow(["github.com", "*.pypi.org"])
    if not a.allows("github.com") or not a.allows("files.pypi.org") or not a.allows("pypi.org") \
            or a.allows("evil.com") or a.allows("github.com.evil.com"):
        fail("allowlist matching")
    if a.record_only or not np.Allow([]).record_only or not np.Allow(["*"]).record_only:
        fail("record-only detection")
    ok("allowlist: exact and *.suffix match, deny by default; empty or * is record-only")

    # 2. a CONNECT tunnel to an allowed host carries bytes and is recorded
    rec = np.Recorder()

    def do_connect(c):
        c.sendall(f"CONNECT 127.0.0.1:{UPORT} HTTP/1.1\r\n\r\n".encode())
        head = c.recv(4096)
        if b"200" not in head.split(b"\r\n")[0]:
            return b"NO-TUNNEL: " + head
        c.sendall(b"GET /tunneled HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            chunk = c.recv(4096)
            if not chunk:
                break
            data += chunk
        return data

    reply = proxied(np.Allow(["127.0.0.1"]), rec, do_connect)
    if not reply or b"UPSTREAM /tunneled" not in reply:
        fail(f"CONNECT tunnel did not reach the upstream: {reply!r}")
    row = [r for r in rec.rows if r["method"] == "CONNECT"][-1]
    if not row["allowed"] or row["host"] != "127.0.0.1" or row["port"] != UPORT or row["up"] <= 0 or row["down"] <= 0:
        fail(f"CONNECT not recorded with bytes: {row}")
    ok("CONNECT tunnel: bytes flow to the upstream; destination and byte counts recorded")

    # 3. a denied host is refused with 403 and recorded as blocked, no upstream reached
    rec = np.Recorder()

    def do_connect_denied(c):
        c.sendall(f"CONNECT 127.0.0.1:{UPORT} HTTP/1.1\r\n\r\n".encode())
        return c.recv(4096)

    reply = proxied(np.Allow(["only-this.example"]), rec, do_connect_denied)
    if b"403" not in reply:
        fail(f"a denied CONNECT was not refused: {reply!r}")
    row = rec.rows[-1]
    if row["allowed"] or row["up"] != 0 or row["down"] != 0:
        fail(f"denied connection not recorded as blocked: {row}")
    ok("a host outside the allowlist gets 403 and is logged as blocked; nothing dialled")

    # 4. an absolute-form plain-HTTP GET is proxied and recorded
    rec = np.Recorder()

    def do_get(c):
        c.sendall(f"GET http://127.0.0.1:{UPORT}/plain HTTP/1.1\r\nHost: 127.0.0.1:{UPORT}\r\n"
                  f"Connection: close\r\n\r\n".encode())
        data = b""
        while True:
            chunk = c.recv(4096)
            if not chunk:
                break
            data += chunk
        return data

    reply = proxied(np.Allow(["127.0.0.1"]), rec, do_get)
    if not reply or b"UPSTREAM /plain" not in reply:
        fail(f"absolute-form GET not proxied: {reply!r}")
    row = rec.rows[-1]
    if row["method"] != "GET" or not row["allowed"] or row["host"] != "127.0.0.1":
        fail(f"absolute-form GET not recorded: {row}")
    ok("absolute-form plain HTTP is proxied to the upstream and recorded")

    # 5. the recorder writes one JSON line per connection to the session file
    import json
    import tempfile
    p = os.path.join(tempfile.mkdtemp(), "netlog.jsonl")
    rec = np.Recorder(path=p)
    proxied(np.Allow(["127.0.0.1"]), rec, do_get)
    lines = [json.loads(x) for x in open(p)]
    if len(lines) != 1 or lines[0]["host"] != "127.0.0.1" or "ts" not in lines[0]:
        fail(f"recorder file: {lines}")
    ok("every connection is one JSON line on the session's egress log")

    print("PASS: netproxy")
finally:
    srv.shutdown()
