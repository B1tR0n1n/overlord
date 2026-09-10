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

    def _call(self, op, on_event=None, **kw):
        """One request, one final response. Streaming ops send intermediate
        {"event": ...} lines first; each is passed to on_event."""
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall((json.dumps({"op": op, **kw}) + "\n").encode())
                rf = sock.makefile("rb")
                for line in rf:
                    resp = json.loads(line)
                    if resp.get("ok") and "event" in resp:
                        if on_event:
                            on_event(resp)
                        continue
                    break
                else:
                    raise OSError("connection closed before a response")
        except OSError as e:
            raise OverlordError(
                f"cannot reach overlordd at {self.socket_path}: {e} "
                "(is `overlord daemon` running?)"
            ) from e
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

    def open(self, target, jail=False, net="host", timeout=None, merge_base=False,
             trace=None, wait=False, stack=False, agent=None):
        """Open a live transaction: many commands, one commit. Returns LiveSession."""
        res = self._call(
            "open", target=str(target),
            grants={"jail": jail, "net": net, "timeout": timeout,
                    "merge_base": merge_base},
            trace=trace, wait=wait, stack=stack, agent=agent,
        )
        return LiveSession(self, res["sid"], res["grants"], res["backend"])

    def sessions(self):
        return self._call("sessions")["sessions"]


class LiveSession:
    """A session that is still open on the daemon. exec() as many times as
    needed, then close() to get the reviewable Session (or rollback())."""

    def __init__(self, client, sid, grants, backend):
        self._c, self.sid, self.grants, self.backend = client, sid, grants, backend

    def exec(self, cmd, timeout=None, cwd=None, label=None, on_output=None):
        """Run cmd inside the transaction. Streams output chunks to on_output.
        Returns (exit_code, output, changes_so_far)."""
        import base64

        def _ev(ev):
            if on_output and ev.get("event") == "out":
                on_output(base64.b64decode(ev["data"]))
        res = self._c._call("exec", on_event=_ev, sid=self.sid, cmd=list(cmd),
                            timeout=timeout, cwd=cwd, label=label)
        return res["exit_code"], res["output"], [tuple(c) for c in res["changes"]]

    def shell(self, script, **kw):
        return self.exec(["bash", "-c", script], **kw)

    def diff(self):
        return [tuple(c) for c in self._c._call("diff", sid=self.sid)["changes"]]

    def close(self):
        """Seal the transaction; returns a Session to inspect/commit/rollback."""
        res = self._c._call("close", sid=self.sid)
        return Session(self._c, self.sid, res.get("exit_code"),
                       [tuple(c) for c in res["changes"]], res.get("grants"),
                       res.get("output_tail", ""))

    def rollback(self):
        return self._c._call("rollback", sid=self.sid)["target"]

    def __repr__(self):
        return f"<LiveSession {self.sid} open>"
