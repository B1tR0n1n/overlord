#!/usr/bin/env python3
"""OVERLORD egress mediation — a recording, allowlisting proxy.

`net=host` gives a jailed command the host's network and records nothing:
the diff shows what the agent wrote, never what it sent. `net=proxy` closes
that gap. The command runs in an EMPTY network namespace — no route out at
all, enforced by the kernel — and its one path to the world is an HTTP proxy
this module runs. Every connection names its destination and its byte counts
on the session's record, and an allowlist can turn recording into refusal.

The proxy is split so the lock holds without any userspace network stack
(no slirp4netns, no passt, no root on the host):

  front   a tiny accept loop INSIDE the empty namespace, bound to
          127.0.0.1:PROXY_PORT. It owns no connectivity; it only hands each
          accepted client socket to the back over a control socket (SCM_RIGHTS).
  back    runs in the PARENT's network namespace, which has the real network.
          It speaks the HTTP proxy protocol on each passed socket, checks the
          allowlist, logs the destination and bytes, and makes the real
          outbound connection. A socket keeps its own namespace, so the back
          can service a client that was accepted in the empty namespace.

Because the command's namespace has no other route, the proxy is the only way
out — cooperation is not required, a direct connect() returns ENETUNREACH.
The proxy does not intercept TLS: for a CONNECT tunnel it records host, port
and byte counts, which is what a tunnel honestly exposes, not the plaintext.
"""

import fcntl
import json
import select
import socket
import struct
import threading
import time

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8071                     # inside the empty netns, so never contended
_BUF = 65536


# ---------------------------------------------------------------- allowlist


class Allow:
    """Deny-by-default when patterns are given; record-all when they are not.
    A pattern is an exact host, a `*.suffix` wildcard, or `*` for everything."""

    def __init__(self, patterns=None):
        self.patterns = [p.strip().lower() for p in (patterns or []) if p and p.strip()]
        self.record_only = not self.patterns or "*" in self.patterns

    def allows(self, host):
        if self.record_only:
            return True
        h = (host or "").lower().rstrip(".")
        for p in self.patterns:
            if p == h:
                return True
            if p.startswith("*.") and (h == p[2:] or h.endswith(p[1:])):
                return True
        return False

    def describe(self):
        return "record only" if self.record_only else ", ".join(self.patterns)


# ---------------------------------------------------------------- log


class Recorder:
    """One JSON line per connection, appended under the session dir; an
    optional callback puts the same fact on the live transcript."""

    def __init__(self, path=None, emit=None):
        self.path = path
        self.emit = emit
        self._lock = threading.Lock()
        self.rows = []

    def note(self, **entry):
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **entry}
        with self._lock:
            self.rows.append(entry)
            if self.path:
                try:
                    with open(self.path, "a") as f:
                        f.write(json.dumps(entry) + "\n")
                except OSError:
                    pass
        if self.emit:
            try:
                self.emit(entry)
            except Exception:            # noqa: BLE001 — never on the connection's path
                pass
        return entry


# ---------------------------------------------------------------- HTTP proxy


def _read_head(sock, acc):
    """Read a full request head (request line + headers + the blank line),
    leaving any spillover — early tunnel bytes — in acc."""
    while b"\r\n\r\n" not in acc:
        chunk = sock.recv(_BUF)
        if not chunk:
            break
        acc.extend(chunk)
    i = acc.find(b"\r\n\r\n")
    if i < 0:
        head, rest = bytes(acc), b""
    else:
        head, rest = bytes(acc[:i + 4]), bytes(acc[i + 4:])
    acc[:] = rest
    return head


def _host_port(authority, default_port):
    authority = authority.strip()
    if authority.startswith("[") and "]" in authority:          # IPv6 literal
        host, _, rest = authority[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
    elif ":" in authority:
        host, _, port = authority.rpartition(":")
    else:
        host, port = authority, ""
    try:
        return host, int(port) if port else default_port
    except ValueError:
        return host, default_port


def _splice(a, b, counters):
    """Pump a<->b until either side closes; counters[0]=a→b, counters[1]=b→a."""
    fds = {a.fileno(): (a, b, 0), b.fileno(): (b, a, 1)}
    open_fds = {a.fileno(), b.fileno()}
    try:
        while open_fds:
            r, _, _ = select.select(list(open_fds), [], [], 300)
            if not r:
                break
            for fd in r:
                src, dst, idx = fds[fd]
                try:
                    data = src.recv(_BUF)
                except OSError:
                    data = b""
                if not data:
                    open_fds.discard(fd)
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                counters[idx] += len(data)
                try:
                    dst.sendall(data)
                except OSError:
                    open_fds.discard(fd)
    finally:
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass


def _connect(host, port, timeout=30):
    return socket.create_connection((host, port), timeout=timeout)


def handle_client(client, allow, rec):
    """Serve one proxied connection on `client` (a socket in the caller's
    network namespace). Records the destination and bytes either way."""
    client.settimeout(60)
    acc = bytearray()
    try:
        head = _read_head(client, acc)
        first = head.split(b"\r\n", 1)[0]
        parts = first.split(b" ")
        if len(parts) < 3:
            return
        method, target = parts[0].decode("latin1"), parts[1].decode("latin1")
        if method == "CONNECT":
            host, port = _host_port(target, 443)
            if not allow.allows(host):
                client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                rec.note(host=host, port=port, method="CONNECT", allowed=False, up=0, down=0)
                return
            try:
                upstream = _connect(host, port)
            except OSError as e:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                rec.note(host=host, port=port, method="CONNECT", allowed=True, error=str(e), up=0, down=0)
                return
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if acc:
                upstream.sendall(bytes(acc))      # bytes the client already sent
            counters = [len(acc), 0]
            client.settimeout(None)
            _splice(client, upstream, counters)
            rec.note(host=host, port=port, method="CONNECT", allowed=True,
                     up=counters[0], down=counters[1])
            return
        # absolute-form request (plain HTTP): GET http://host/path HTTP/1.1
        if "://" in target:
            authority = target.split("://", 1)[1].split("/", 1)[0]
            host, port = _host_port(authority, 80)
        else:
            host, port = _host_port(_header(head, b"host") or "", 80)
        if not allow.allows(host):
            client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            rec.note(host=host, port=port, method=method, allowed=False, up=0, down=0)
            return
        try:
            upstream = _connect(host, port)
        except OSError as e:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            rec.note(host=host, port=port, method=method, allowed=True, error=str(e), up=0, down=0)
            return
        # rewrite the head to origin-form for the upstream (strip scheme+authority)
        if "://" in target:
            after = target.split("://", 1)[1]
            path = "/" + after.split("/", 1)[1] if "/" in after else "/"
            rest = head.split(b"\r\n", 1)[1] if b"\r\n" in head else b"\r\n"
            head = f"{method} {path} {parts[2].decode('latin1')}\r\n".encode() + rest
        upstream.sendall(head + bytes(acc))
        counters = [len(head) + len(acc), 0]
        client.settimeout(None)
        _splice(client, upstream, counters)
        rec.note(host=host, port=port, method=method, allowed=True,
                 up=counters[0], down=counters[1])
    except OSError:
        pass
    finally:
        try:
            client.close()
        except OSError:
            pass


def _header(head, name):
    for line in head.split(b"\r\n"):
        if b":" in line:
            k, _, v = line.partition(b":")
            if k.strip().lower() == name:
                return v.strip().decode("latin1")
    return None


# ---------------------------------------------------------------- back (host netns)


def run_backend(ctrl, allow, rec, stop):
    """Loop in the parent's network namespace: receive client sockets passed
    from the front over `ctrl` and serve each. Returns when `stop` is set or
    the control socket closes."""
    ctrl.setblocking(False)
    while not stop.is_set():
        r, _, _ = select.select([ctrl], [], [], 0.5)
        if not r:
            continue
        try:
            fds = _recv_fds(ctrl)
        except (BlockingIOError, InterruptedError):
            continue
        except OSError:
            break
        if fds is None:
            break
        for fd in fds:
            client = socket.socket(fileno=fd)
            threading.Thread(target=handle_client, args=(client, allow, rec), daemon=True).start()


def _recv_fds(sock, maxfds=8):
    msg, anc, _flags, _addr = sock.recvmsg(1, socket.CMSG_LEN(maxfds * 4))
    if not msg:
        return None
    fds = []
    for level, typ, data in anc:
        if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
            fds += list(struct.unpack("%di" % (len(data) // 4), data[:len(data) // 4 * 4]))
    return fds


# ---------------------------------------------------------------- front (empty netns)


def lo_up():
    """Bring loopback up without `ip` — an ioctl available with CAP_NET_ADMIN,
    which a process holds in a network namespace it created."""
    SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        cur = struct.unpack("16sh", fcntl.ioctl(s, SIOCGIFFLAGS, struct.pack("16sh", b"lo", 0)))[1]
        fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sh", b"lo", cur | IFF_UP))
    finally:
        s.close()


def send_fd(ctrl, fd):
    ctrl.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", fd))])


def run_frontend(ctrl, host=PROXY_HOST, port=PROXY_PORT):
    """Accept loop inside the empty namespace: bind, then hand every client
    socket to the back. Never touches the network itself."""
    lo_up()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)
    while True:
        try:
            client, _ = srv.accept()
        except OSError:
            break
        try:
            send_fd(ctrl, client.fileno())
        except OSError:
            pass
        client.close()          # the back holds its own copy now
