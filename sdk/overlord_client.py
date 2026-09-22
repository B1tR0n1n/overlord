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
        return self._client.commit(self.sid, merge=merge, force=force, only=only,
                                   drop=drop, countersigned=countersigned)

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

    def revert(self, commit=False, force=False, stack=False):
        """Once committed: stage this session's inverse as a new pending
        session (see OverlordClient.revert)."""
        return self._client.revert(self.sid, commit=commit, force=force, stack=stack)

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

    @staticmethod
    def _grants(jail, net, timeout, merge_base, net_allow=None, limits=None):
        g = {"jail": jail, "net": net, "timeout": timeout, "merge_base": merge_base}
        if net_allow:
            g["net_allow"] = list(net_allow)      # with net="proxy": hosts / *.suffix
        if limits:
            g["limits"] = dict(limits)            # cpu / mem / pids / disk ceilings
        return g

    def run(self, target, cmd, jail=False, net="host", timeout=None,
            merge_base=False, trace=None, wait=False, stack=False,
            net_allow=None, limits=None):
        """Execute cmd transactionally against target. Returns a Session."""
        res = self._call(
            "run", target=str(target), cmd=list(cmd),
            grants=self._grants(jail, net, timeout, merge_base, net_allow, limits),
            trace=trace, wait=wait, stack=stack,
        )
        return Session(self, res["sid"], res["exit_code"], res["changes"],
                       res["grants"], res.get("output_tail", ""))

    def open(self, target, jail=False, net="host", timeout=None, merge_base=False,
             trace=None, wait=False, stack=False, agent=None, net_allow=None, limits=None):
        """Open a live transaction: many commands, one commit. Returns LiveSession.
        The daemon applies policy: the effective grants are never looser than
        the target's rule, and are returned on the LiveSession."""
        res = self._call(
            "open", target=str(target),
            grants=self._grants(jail, net, timeout, merge_base, net_allow, limits),
            trace=trace, wait=wait, stack=stack, agent=agent,
        )
        return LiveSession(self, res["sid"], res["grants"], res["backend"])

    def agent(self, target, task, provider="anthropic", model=None, max_turns=None,
              jail=False, net="host", timeout=None, merge_base=False, trace=None,
              wait=False, stack=False, on_event=None, base_url=None, headers=None,
              config=None, azure_api_version=None, connectors=None,
              connector_approval=None, approve_all=False):
        """Run the built-in agent against target inside a live session, then
        seal it. on_event receives transcript events (assistant_delta while
        text streams, then assistant, tool_call, tool_result, done, error) and
        one initial {"type": "session", "sid"}. provider is one of anthropic,
        openai, azure, openai-compatible, gemini; base_url/headers reach a
        gateway or a local server; config is a dict of generation knobs
        (max_tokens, temperature, top_p, stop, effort, thinking, system_extra,
        stream, fallbacks) — blank knobs are not sent. connectors grants MCP
        servers by name (policy may cap them; they run on the daemon host,
        outside the transaction); connector_approval is ask|auto|readonly and
        approve_all=True answers "ask" with yes for this run — a brokered run
        has no terminal, so the default answer is no. Returns a Session plus
        the agent's final text."""
        def _ev(ev):
            if not on_event:
                return
            if ev.get("event") == "session":
                on_event({"type": "session", "sid": ev["sid"], "grants": ev["grants"]})
            elif ev.get("event") == "agent":
                on_event({k: v for k, v in ev.items() if k not in ("ok", "event")})
        res = self._call(
            "agent", on_event=_ev, target=str(target), task=task, provider=provider,
            model=model, max_turns=max_turns, base_url=base_url, headers=headers,
            config=config, azure_api_version=azure_api_version,
            connectors=connectors, connector_approval=connector_approval,
            approve_all=approve_all,
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

    def models(self, provider="anthropic", base_url=None, headers=None, azure_api_version=None):
        """The models a provider serves right now: [{id, name, context, max_output}]."""
        return self._call("models", provider=provider, base_url=base_url, headers=headers,
                          azure_api_version=azure_api_version)["models"]

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

    def commit(self, sid, merge=False, force=False, only=None, drop=None, countersigned=False):
        """Commit a pending session by id (see Session.commit). Raises on
        refusal, naming why: a reviewer's rejection, the policy gate's
        findings, or external drift."""
        res = self._call("commit", sid=sid, merge=merge, force=force,
                         only=only, drop=drop, countersigned=countersigned)
        if not res.get("committed"):
            if res.get("rejected"):
                r = res["rejected"]
                raise OverlordError(f"commit refused — rejected by {r.get('reviewer')}: "
                                    f"{r.get('reason')}")
            if res.get("policy") and not res.get("conflicts"):
                raise OverlordError(
                    "commit refused — policy gate: "
                    + "; ".join(f"[{f.get('action')}] {f.get('check')} {f.get('path') or '(diff)'}"
                                f" — {f.get('detail')}" for f in res["policy"]))
            raise OverlordError(
                "commit refused — target drifted: "
                + ", ".join(f"{r}:{p}" for r, p in res.get("conflicts", []))
            )
        return res

    def revert(self, sid, commit=False, force=False, stack=False):
        """Undo a COMMITTED session's file changes as a NEW reviewable session
        over the same target. Returns {sid, reverted, changes, skipped, failed,
        committed}. A path with no retained before-content refuses the revert
        unless force=True, which skips it. rollback() is the pre-commit half."""
        return self._call("revert", sid=sid, commit=commit, force=force, stack=stack)

    def audit(self, action, **fields):
        """Append one event to the engine's keyed, witnessed audit chain.
        `action` must be namespaced ext.|receipt.|plan.|finding.|approval.;
        the entry is marked via="daemon". Returns the entry ({seq, hash, ...})
        — a receipt can cite its `hash` as its chain reference."""
        return self._call("audit", action=action, fields=fields)["entry"]

    def audit_head(self):
        """{seq, hash, keyed}: the chain head right now."""
        return self._call("audit_head")["head"]

    def complete(self, prompt, system="", provider="anthropic", model=None, purpose=None,
                 base_url=None, headers=None):
        """One tool-less model call through the engine's providers and key
        store — for a planner that only proposes. Returns {text, stop, usage,
        provider, model, prompt_sha256, output_sha256, refusal}; the call is
        audited as model.complete with those hashes."""
        return self._call("complete", prompt=prompt, system=system, provider=provider,
                          model=model, purpose=purpose, base_url=base_url, headers=headers)

    def sessions(self):
        return self._call("sessions")["sessions"]


class LiveSession:
    """A session that is still open on the daemon. exec() as many times as
    needed, then close() to get the reviewable Session (or rollback())."""

    def __init__(self, client, sid, grants, backend):
        self._c, self.sid, self.grants, self.backend = client, sid, grants, backend

    def exec(self, cmd, timeout=None, cwd=None, label=None, on_output=None, cause=None):
        """Run cmd inside the transaction. Streams output chunks to on_output.
        `cause` (any JSON object — e.g. {"plan_id", "step_id", "action_id"}) is
        stamped on the layer this command writes into and surfaces as
        `caused_by` on every affected path's provenance record.
        Returns (exit_code, output, changes_so_far)."""
        import base64

        def _ev(ev):
            if on_output and ev.get("event") == "out":
                on_output(base64.b64decode(ev["data"]))
        res = self._c._call("exec", on_event=_ev, sid=self.sid, cmd=list(cmd),
                            timeout=timeout, cwd=cwd, label=label, cause=cause)
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
