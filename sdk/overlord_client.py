"""OVERLORD Python SDK — embed transactional agent execution in any harness.

    from overlord_client import OverlordClient

    ov = OverlordClient()                      # connects to overlordd socket
    s = ov.run("/srv/app", ["python3", "agent.py"], jail=True, net="none")
    for kind, path in s.changes:
        print(kind, path)
    if s.exit_code == 0 and input("commit? ") == "y":
        s.commit()
    else:
        s.rollback()

All authority flows through the daemon: grants are brokered against the
policy file, so an embedded caller can never obtain a looser scope than the
operator allows. Requires `overlord daemon` to be running.
"""

import json
import os
import socket

DEFAULT_SOCKET = os.path.join(
    os.environ.get("OVERLORD_HOME", os.path.expanduser("~/.overlord")),
    "overlordd.sock",
)


class OverlordError(RuntimeError):
    pass


class Session:
    """Handle to one pending transactional session."""

    def __init__(self, client, sid, exit_code, changes, grants, output_tail=""):
        self._client = client
        self.sid = sid
        self.exit_code = exit_code
        self.changes = [tuple(c) for c in changes]
        self.grants = grants
        self.output_tail = output_tail

    def diff(self):
        return [tuple(c) for c in self._client._call("diff", sid=self.sid)["changes"]]

    def log(self):
        return self._client._call("log", sid=self.sid)["provenance"]

    def commit(self, merge=False, force=False):
        """Returns the commit result dict; raises on conflict refusal."""
        res = self._client._call("commit", sid=self.sid, merge=merge, force=force)
        if not res.get("committed"):
            raise OverlordError(
                "commit refused — target drifted: "
                + ", ".join(f"{r}:{p}" for r, p in res.get("conflicts", []))
            )
        return res

    def rollback(self):
        return self._client._call("rollback", sid=self.sid)["target"]

    def __repr__(self):
        return (f"<overlord.Session {self.sid} exit={self.exit_code} "
                f"changes={len(self.changes)}>")


class OverlordClient:
    def __init__(self, socket_path=None, timeout=None):
        self.socket_path = socket_path or DEFAULT_SOCKET
        self.timeout = timeout

    def _call(self, op, **kw):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall((json.dumps({"op": op, **kw}) + "\n").encode())
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = sock.recv(1 << 16)
                    if not chunk:
                        break
                    buf += chunk
        except OSError as e:
            raise OverlordError(
                f"cannot reach overlordd at {self.socket_path}: {e} "
                "(is `overlord daemon` running?)"
            ) from e
        resp = json.loads(buf)
        if not resp.get("ok"):
            raise OverlordError(resp.get("error", "unknown daemon error"))
        return resp

    def ping(self):
        return self._call("ping")

    def run(self, target, cmd, jail=False, net="host", timeout=None,
            merge_base=False, trace=None, wait=False, stack=False):
        """Execute cmd transactionally against target. Returns a Session."""
        res = self._call(
            "run", target=str(target), cmd=list(cmd),
            grants={"jail": jail, "net": net, "timeout": timeout,
                    "merge_base": merge_base},
            trace=trace, wait=wait, stack=stack,
        )
        return Session(self, res["sid"], res["exit_code"], res["changes"],
                       res["grants"], res.get("output_tail", ""))

    def sessions(self):
        return self._call("sessions")["sessions"]
