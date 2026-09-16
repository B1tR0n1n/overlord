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

    def commit(self, merge=False, force=False, only=None, drop=None, countersigned=False):
        """Returns the commit result dict; raises on refusal.
        only/drop select layers to replay: "layer:N", "layer:A-B", "turn:N",
        "tool:NAME", "call:ID", comma-separated — undo a decision, keep the
        rest. countersigned=True (or policy "require_review") demands a fresh
        approval from review(); a fresh rejection refuses unless force."""
        res = self._client._call("commit", sid=self.sid, merge=merge, force=force,
                                 only=only, drop=drop, countersigned=countersigned)
        if not res.get("committed"):
            if res.get("rejected"):
                r = res["rejected"]
                raise OverlordError(f"commit refused — rejected by {r.get('reviewer')}: "
                                    f"{r.get('reason')}")
            raise OverlordError(
                "commit refused — target drifted: "
                + ", ".join(f"{r}:{p}" for r, p in res.get("conflicts", []))
            )
        return res

    def review(self, provider="anthropic", model=None, max_turns=None, same_model=False,
               on_event=None):
        """Put this session's diff before a second model. Returns the review
        record: verdict (approve / reject / abstain), reason, reviewer,
        fingerprint of what was signed."""
        return self._client.review(self.sid, provider=provider, model=model,
                                   max_turns=max_turns, same_model=same_model,
                                   on_event=on_event)

    def fork(self, at=None):
        """Copy this session's stack up to savepoint `at` into a new pending
        session. Returns its Session handle."""
        return self._client.fork(self.sid, at)

    def rollback(self):
        return self._client._call("rollback", sid=self.sid)["target"]

    def savepoints(self):
        """One entry per layer: n, cause (tool call) or cmd, and its paths."""
        return self._client._call("savepoints", sid=self.sid)["savepoints"]

    def rewind(self, to):
        """Discard every layer above savepoint `to`. Returns the daemon's
        result (remaining changes); self.changes is refreshed."""
        res = self._client._call("rewind", sid=self.sid, to=int(to))
        self.changes = [tuple(c) for c in res["changes"]]
        return res

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

    def agent(self, target, task, provider="anthropic", model=None, max_turns=None,
              jail=False, net="host", timeout=None, merge_base=False, trace=None,
              wait=False, stack=False, on_event=None):
        """Run the built-in agent against target inside a live session, then
        seal it. on_event receives transcript events (assistant, tool_call,
        tool_result, done, error) and one initial {"type": "session", "sid"}.
        Returns a Session plus the agent's final text."""
        def _ev(ev):
            if not on_event:
                return
            if ev.get("event") == "session":
                on_event({"type": "session", "sid": ev["sid"], "grants": ev["grants"]})
            elif ev.get("event") == "agent":
                on_event({k: v for k, v in ev.items() if k not in ("ok", "event")})
        res = self._call(
            "agent", on_event=_ev, target=str(target), task=task, provider=provider,
            model=model, max_turns=max_turns,
            grants={"jail": jail, "net": net, "timeout": timeout, "merge_base": merge_base},
            trace=trace, wait=wait, stack=stack,
        )
        s = Session(self, res["sid"], res.get("exit_code"), res["changes"], res.get("grants"))
        s.final, s.usage = res.get("final", ""), res.get("usage")
        return s

    def agent_cancel(self, sid):
        return self._call("agent_cancel", sid=sid)

    def resume(self, sid, note=None, provider=None, model=None, max_turns=None,
               wait=False, on_event=None):
        """Reopen a pending agent session (after a rewind, typically) and let
        the model continue from its restored transcript, reading `note` as an
        operator message first. Returns a Session plus the agent's final text."""
        def _ev(ev):
            if not on_event:
                return
            if ev.get("event") == "session":
                on_event({"type": "session", "sid": ev["sid"], "grants": ev["grants"]})
            elif ev.get("event") == "agent":
                on_event({k: v for k, v in ev.items() if k not in ("ok", "event")})
        res = self._call("resume", on_event=_ev, sid=sid, note=note, provider=provider,
                         model=model, max_turns=max_turns, wait=wait)
        s = Session(self, res["sid"], res.get("exit_code"), res["changes"], res.get("grants"))
        s.final, s.usage = res.get("final", ""), res.get("usage")
        return s

    def savepoints(self, sid):
        return self._call("savepoints", sid=sid)["savepoints"]

    def review(self, sid, provider="anthropic", model=None, max_turns=None,
               same_model=False, on_event=None):
        """Countersignature: a second model approves or rejects a pending
        session's diff. on_event receives the reviewer's transcript events."""
        def _ev(ev):
            if on_event and ev.get("event") == "review":
                on_event({k: v for k, v in ev.items() if k not in ("ok", "event")})
        return self._call("review", on_event=_ev, sid=sid, provider=provider, model=model,
                          max_turns=max_turns, same_model=same_model)["review"]

    def fork(self, sid, at=None):
        """Fork a pending session at a savepoint (default: its top). Returns a
        Session for the new pending copy."""
        res = self._call("fork", sid=sid, at=at)
        new = res["sid"]
        return Session(self, new, None, self._call("diff", sid=new)["changes"], None)

    def compare(self, a, b):
        """Per-path divergence of two pending stacks on one target:
        [{"path", "state": same|differ|only-a|only-b, "a", "b"}]."""
        return self._call("compare", a=a, b=b)["rows"]

    def rewind(self, sid, to):
        """Rewind a pending session (or one this daemon holds open)."""
        return self._call("rewind", sid=sid, to=int(to))

    def blame(self, path):
        """Which committed session, turn, tool call and instruction produced
        the file at path — per line where content was retained."""
        return self._call("blame", path=str(path))

    def transcript(self, sid):
        return self._call("transcript", sid=sid)["transcript"]

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

    def savepoints(self):
        return self._c._call("savepoints", sid=self.sid)["savepoints"]

    def rewind(self, to):
        """Drop every layer above savepoint `to` while the session stays open
        (refused while a command is running). Returns the daemon's result."""
        return self._c._call("rewind", sid=self.sid, to=int(to))

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
