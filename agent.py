#!/usr/bin/env python3
"""OVERLORD agent — the reference harness: a model thinks on the host, its
hands act inside a live transactional session.

    overlord agent -t <dir> [grants] [--provider anthropic|openai]
                   [--model M] [--max-turns N] [--no-jail] "<task>"

The model loop runs in the overlord process with network access to the
provider API. Every tool it calls (list_dir / read_file / write_file / shell)
executes through LiveSession.exec inside the overlay, jail, and netns the
grants describe.

The agent is jailed by default — `run` and `shell` are not. The overlay covers
the target's path, not the filesystem, so an unjailed `shell` tool writing to
/tmp or $HOME hits the real thing: outside the transaction, absent from the
diff, no provenance, nothing to roll back, and the session still reports
changes=0. Jailed, the model sees system dirs and the target and nothing else,
and the guarantee holds: nothing it does touches anything until commit.
--no-jail drops that and says so on stderr.

Provenance is structural: every tool call that writes seals its own overlay
layer (a savepoint), stamped with the call that caused it, so each changed
path names its turn, tool and instruction in provenance.jsonl (`caused_by`)
next to the transcript (transcript.jsonl). Because the layer stack and the
transcript are cut at the same savepoint, `overlord rewind` followed by
`overlord resume` puts the model back in a world that matches what it
remembers, with an optional operator note injected at that point.

Providers are stdlib-only (urllib). Keys come from the environment
(ANTHROPIC_API_KEY / OPENAI_API_KEY) or ~/.overlord/keys.json (mode 0600):
    {"anthropic": "sk-ant-...", "openai": "sk-..."}
"""

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

import overlord as ov

# Checked 2026-09-11. claude-sonnet-5 is current. gpt-5 was the alias for the
# gpt-5-2025-08-07 snapshot, deprecated 2026-06-11 and removed 2026-12-11;
# gpt-5.5 is the replacement OpenAI published for it, served on the Chat
# Completions endpoint this client uses. Newer families exist (gpt-5.6, and
# gpt-6-astra as flagship) — re-check with `GET /v1/models` before bumping, and
# do not guess an id from a release announcement.
DEFAULT_MODELS = {"anthropic": "claude-sonnet-5", "openai": "gpt-5.5"}
MAX_TOOL_OUTPUT = 32_000       # chars fed back to the model per tool result
DEFAULT_MAX_TURNS = 40

SYSTEM_PROMPT = """You are an autonomous engineering agent operating inside OVERLORD, \
a transactional sandbox. Your working directory is the project root. Every \
change you make lands in an overlay that a human reviews and commits or rolls \
back afterwards, so act decisively: inspect, edit, run tests, verify.

Use the tools to do the work; do not describe changes you have not made. \
Prefer small, verifiable steps. When the task is complete, reply with a short \
summary of what changed and how you verified it, then stop calling tools."""

TOOLS = [
    {"name": "list_dir",
     "description": "List a directory (relative to the project root). Shows type and size.",
     "input_schema": {"type": "object",
                      "properties": {"path": {"type": "string", "default": "."}},
                      "required": []}},
    {"name": "read_file",
     "description": "Read a text file (relative to the project root).",
     "input_schema": {"type": "object",
                      "properties": {"path": {"type": "string"}},
                      "required": ["path"]}},
    {"name": "write_file",
     "description": "Create or overwrite a text file with the given content. "
                    "Parent directories are created.",
     "input_schema": {"type": "object",
                      "properties": {"path": {"type": "string"},
                                     "content": {"type": "string"}},
                      "required": ["path", "content"]}},
    {"name": "shell",
     "description": "Run a bash command in the project root and return its "
                    "combined output and exit code. Use for builds, tests, "
                    "git, grep, sed, and anything else.",
     "input_schema": {"type": "object",
                      "properties": {"command": {"type": "string"},
                                     "timeout": {"type": "number",
                                                 "description": "seconds (default 300)"}},
                      "required": ["command"]}},
]


# ---------------------------------------------------------------- keys


def load_key(provider):
    env = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}[provider]
    if os.environ.get(env):
        return os.environ[env]
    path = os.path.join(ov.OVERLORD_HOME, "keys.json")
    if os.path.isfile(path):
        mode = os.stat(path).st_mode & 0o777
        if mode & 0o077:
            raise ov.OverlordError(f"error: {path} is mode {mode:03o}; chmod 600 it")
        with open(path) as f:
            key = json.load(f).get(provider)
        if key:
            return key
    raise ov.OverlordError(f"error: no API key for {provider}: set {env} or add it to {path}")


def save_key(provider, key):
    path = os.path.join(ov.OVERLORD_HOME, "keys.json")
    os.makedirs(ov.OVERLORD_HOME, exist_ok=True)
    keys = {}
    if os.path.isfile(path):
        with open(path) as f:
            keys = json.load(f)
    keys[provider] = key
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(keys, f)
    os.chmod(path, 0o600)


# ---------------------------------------------------------------- providers
#
# Neutral message form (what the loop keeps):
#   {"role": "user", "content": str}
#   {"role": "assistant", "content": str, "tool_calls": [{"id", "name", "input"}]}
#   {"role": "tool", "tool_call_id": str, "content": str}
# Each provider translates to its wire format and back to a Reply.


class Reply:
    def __init__(self, text, tool_calls, stop, usage):
        self.text, self.tool_calls, self.stop, self.usage = text, tool_calls, stop, usage


def _post(url, headers, body, timeout=600):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:2000]
        raise ov.OverlordError(f"error: provider HTTP {e.code}: {detail}")
    except urllib.error.URLError as e:
        raise ov.OverlordError(f"error: provider unreachable: {e.reason}")


class AnthropicProvider:
    name = "anthropic"
    url = "https://api.anthropic.com/v1/messages"

    def __init__(self, model, key):
        self.model, self.key = model, key

    def _wire(self, messages):
        out = []
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                blocks = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": m["content"]})
                for tc in m.get("tool_calls", []):
                    blocks.append({"type": "tool_use", "id": tc["id"],
                                   "name": tc["name"], "input": tc["input"]})
                out.append({"role": "assistant", "content": blocks})
            elif m["role"] == "tool":
                block = {"type": "tool_result", "tool_use_id": m["tool_call_id"],
                         "content": m["content"]}
                # consecutive tool results merge into one user turn
                if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block]})
        return out

    def complete(self, system, messages):
        body = {"model": self.model, "max_tokens": 8192, "system": system,
                "messages": self._wire(messages), "tools": TOOLS}
        data = _post(self.url, {"x-api-key": self.key,
                                "anthropic-version": "2023-06-01"}, body)
        text, calls = "", []
        for block in data.get("content", []):
            if block["type"] == "text":
                text += block["text"]
            elif block["type"] == "tool_use":
                calls.append({"id": block["id"], "name": block["name"],
                              "input": block.get("input") or {}})
        u = data.get("usage", {})
        return Reply(text, calls, data.get("stop_reason"),
                     {"in": u.get("input_tokens", 0), "out": u.get("output_tokens", 0)})


class OpenAIProvider:
    name = "openai"
    url = "https://api.openai.com/v1/chat/completions"

    def __init__(self, model, key):
        self.model, self.key = model, key

    def _wire(self, system, messages):
        out = [{"role": "system", "content": system}]
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                msg = {"role": "assistant", "content": m.get("content") or None}
                if m.get("tool_calls"):
                    msg["tool_calls"] = [
                        {"id": tc["id"], "type": "function",
                         "function": {"name": tc["name"],
                                      "arguments": json.dumps(tc["input"])}}
                        for tc in m["tool_calls"]]
                out.append(msg)
            elif m["role"] == "tool":
                out.append({"role": "tool", "tool_call_id": m["tool_call_id"],
                            "content": m["content"]})
        return out

    def complete(self, system, messages):
        tools = [{"type": "function",
                  "function": {"name": t["name"], "description": t["description"],
                               "parameters": t["input_schema"]}} for t in TOOLS]
        body = {"model": self.model, "messages": self._wire(system, messages),
                "tools": tools}
        data = _post(self.url, {"Authorization": f"Bearer {self.key}"}, body)
        choice = data["choices"][0]
        msg = choice["message"]
        calls = []
        for tc in msg.get("tool_calls") or []:
            try:
                args = json.loads(tc["function"].get("arguments") or "{}")
            except ValueError:
                args = {"_raw": tc["function"].get("arguments")}
            calls.append({"id": tc["id"], "name": tc["function"]["name"], "input": args})
        u = data.get("usage", {})
        return Reply(msg.get("content") or "", calls, choice.get("finish_reason"),
                     {"in": u.get("prompt_tokens", 0), "out": u.get("completion_tokens", 0)})


class ScriptedProvider:
    """Deterministic stand-in for tests: replays a list of Reply-like dicts."""
    name = "scripted"

    def __init__(self, script):
        self.script, self.i, self.seen = list(script), 0, []

    def complete(self, system, messages):
        self.seen.append(json.loads(json.dumps(messages)))
        if self.i >= len(self.script):
            return Reply("(script exhausted)", [], "end_turn", {"in": 0, "out": 0})
        step = self.script[self.i]
        self.i += 1
        calls = [{"id": f"call_{self.i}_{n}", "name": c["name"], "input": c["input"]}
                 for n, c in enumerate(step.get("tool_calls", []))]
        return Reply(step.get("text", ""), calls,
                     "tool_use" if calls else "end_turn", {"in": 0, "out": 0})


def make_provider(provider, model=None, key=None):
    if provider == "anthropic":
        return AnthropicProvider(model or DEFAULT_MODELS[provider], key or load_key(provider))
    if provider == "openai":
        return OpenAIProvider(model or DEFAULT_MODELS[provider], key or load_key(provider))
    if provider == "scripted":      # tests: OVERLORD_AGENT_SCRIPT=<json file of replies>
        path = os.environ.get("OVERLORD_AGENT_SCRIPT")
        if not path:
            raise ov.OverlordError("error: scripted provider needs OVERLORD_AGENT_SCRIPT")
        with open(path) as f:
            p = ScriptedProvider(json.load(f))
        p.model = model or "scripted"
        return p
    raise ov.OverlordError(f"error: unknown provider: {provider}")


# ---------------------------------------------------------------- tools → session


def _rel_ok(path):
    """Tools take paths relative to the project root. Absolute paths and
    parent traversal are refused here for clarity — the jail would contain
    them anyway, but the model should get a clear error, not a silent tmpfs."""
    p = (path or ".").strip()
    if p.startswith("/") or ".." in p.split("/"):
        return None
    return p or "."


class ToolRunner:
    def __init__(self, live):
        self.live = live
        self._cause = None

    def run(self, name, inp, label, cause=None):
        fn = getattr(self, f"t_{name}", None)
        if fn is None:
            return f"error: unknown tool {name}", 1
        self._cause = cause
        try:
            return fn(inp, label)
        except (ov.OverlordError, SystemExit) as e:
            return f"error: {e}", 1

    def _exec(self, cmd, timeout, label):
        # the cause rides along so the layer this command writes into is
        # stamped with the tool call — that is what provenance reports
        rc, out = self.live.exec(cmd, timeout=timeout, label=label, cause=self._cause)
        return out.decode(errors="replace"), rc

    def t_list_dir(self, inp, label):
        p = _rel_ok(inp.get("path", "."))
        if p is None:
            return "error: path must be relative to the project root", 1
        return self._exec(["ls", "-lA", "--", p], 30, label)

    def t_read_file(self, inp, label):
        p = _rel_ok(inp.get("path"))
        if p is None:
            return "error: path must be relative to the project root", 1
        return self._exec(["cat", "--", p], 30, label)

    def t_write_file(self, inp, label):
        p = _rel_ok(inp.get("path"))
        if p is None:
            return "error: path must be relative to the project root", 1
        b64 = base64.b64encode(inp.get("content", "").encode()).decode()
        code = ("import base64,os,sys; p=sys.argv[1]; d=os.path.dirname(p); "
                "d and os.makedirs(d, exist_ok=True); "
                "open(p,'wb').write(base64.b64decode(sys.argv[2])); "
                "print('wrote', p, os.path.getsize(p), 'bytes')")
        return self._exec(["python3", "-c", code, p, b64], 30, label)

    def t_shell(self, inp, label):
        cmd = inp.get("command", "")
        timeout = float(inp.get("timeout") or 300)
        return self._exec(["bash", "-c", cmd], timeout, label)


# ---------------------------------------------------------------- provenance link


class Attribution:
    """Re-hash the flattened stack after each tool call to report which paths
    that call touched (for the transcript and the operator's eyes). The
    durable attribution is the cause stamped on each layer by the engine."""

    def __init__(self, live):
        self.live = live
        self.state = self._snapshot()

    def _snapshot(self):
        changes, origin, _t, uppers = self.live.stack()
        recs = ov.build_provenance(changes, None, self.live.meta["target"], origin, uppers)
        return {r["path"]: (r["kind"], r.get("after_sha256")) for r in recs}

    def attribute(self, cause):
        now = self._snapshot()
        touched = [p for p, v in now.items() if self.state.get(p) != v]
        touched += [p for p in self.state if p not in now]   # reverted
        self.state = now
        return touched


# ---------------------------------------------------------------- the loop


def _restore_messages(events):
    """Rebuild the neutral message list from a transcript, exactly as the
    model saw it. A turn cut short by a rewind keeps only the tool calls
    that still have results, so every provider's pairing rule holds."""
    messages, turn = [], 0
    for ev in events:
        t = ev.get("type")
        if t == "task":
            messages.append({"role": "user", "content": ev.get("text", "")})
        elif t == "assistant":
            turn = max(turn, ev.get("turn", 0))
            messages.append({"role": "assistant", "content": ev.get("text", ""),
                             "tool_calls": [], "_turn": ev.get("turn")})
        elif t == "tool_call":
            turn = max(turn, ev.get("turn", 0))
            if not (messages and messages[-1]["role"] == "assistant"
                    and messages[-1].get("_turn") == ev.get("turn")):
                messages.append({"role": "assistant", "content": "", "tool_calls": [],
                                 "_turn": ev.get("turn")})
            messages[-1]["tool_calls"].append(
                {"id": ev["id"], "name": ev["tool"], "input": ev.get("input") or {}})
        elif t == "tool_result":
            out = ev.get("output", "")
            if len(out) > MAX_TOOL_OUTPUT:
                out = (out[:MAX_TOOL_OUTPUT // 2] + "\n...[truncated]...\n"
                       + out[-MAX_TOOL_OUTPUT // 2:])
            rc = ev.get("exit_code", 0)
            content = out if rc == 0 else f"{out}\n[exit code {rc}]"
            messages.append({"role": "tool", "tool_call_id": ev["id"],
                             "content": content or "(no output)"})
        elif t == "resume" and ev.get("note"):
            messages.append({"role": "user", "content": ev["note"]})
    answered = {m["tool_call_id"] for m in messages if m["role"] == "tool"}
    for m in messages:
        if m["role"] == "assistant":
            m["tool_calls"] = [tc for tc in m["tool_calls"] if tc["id"] in answered]
            m.pop("_turn", None)
    # a tool message must follow the assistant message that asked for it
    out = []
    for m in messages:
        if m["role"] == "tool" and not any(
                p["role"] == "assistant" and any(tc["id"] == m["tool_call_id"]
                                                 for tc in p["tool_calls"]) for p in out):
            continue
        out.append(m)
    return out, turn


def _operator_note(live, note):
    layers = live.meta.get("layers") or []
    top = layers[-1] if layers else {}
    where = ""
    if top.get("cause"):
        c = top["cause"]
        where = f" after turn {c.get('turn')} {c.get('tool')}({c.get('summary', '')})"
    text = (f"OPERATOR: this session was paused{where} and is now resumed. The "
            f"project tree is exactly as it was at that point; anything you did "
            f"after it was undone.")
    if note:
        text += f"\nOperator note: {note}"
    return text + "\nContinue the task from here."


def run_agent(live, provider, task, max_turns=DEFAULT_MAX_TURNS, emit=None,
              should_stop=None, resume=False, note=None):
    """Drive the model against an open LiveSession until it stops calling
    tools, hits max_turns, or should_stop() is true. Emits events:
      assistant / tool_call / tool_result / done / error
    With resume=True the transcript already on disk (as cut by rewind) is
    the model's memory; an operator note is delivered as the next user turn.
    Returns the final assistant text."""
    emit = emit or (lambda e: None)
    tpath = os.path.join(live.sdir, "transcript.jsonl")
    start_turn = 1
    messages = [{"role": "user", "content": task}]
    if resume:
        events = []
        if os.path.isfile(tpath):
            with open(tpath) as f:
                events = [json.loads(line) for line in f if line.strip()]
        messages, last_turn = _restore_messages(events)
        if not messages:
            messages = [{"role": "user", "content": task}]
        start_turn = last_turn + 1
    transcript = open(tpath, "a")

    def record(ev):
        ev = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **ev}
        transcript.write(json.dumps(ev) + "\n")
        transcript.flush()
        emit(ev)

    live.meta["agent"] = f"{provider.name}:{getattr(provider, 'model', '-')}"
    live.meta["task"] = task
    live.meta.setdefault("usage", {"in": 0, "out": 0})
    ov.save_meta(live.sid, live.meta)

    tools = ToolRunner(live)
    attribution = Attribution(live)
    if resume:
        text = _operator_note(live, note)
        messages.append({"role": "user", "content": text})
        record({"type": "resume", "note": text, "turn": start_turn - 1,
                "layer": live.current_layer})
    else:
        record({"type": "task", "text": task, "agent": live.meta["agent"]})
    final = ""
    try:
        for turn in range(start_turn, start_turn + max_turns):
            if should_stop and should_stop():
                record({"type": "done", "reason": "cancelled", "turn": turn})
                return final
            reply = provider.complete(SYSTEM_PROMPT, messages)
            live.meta["usage"]["in"] += reply.usage.get("in", 0)
            live.meta["usage"]["out"] += reply.usage.get("out", 0)
            ov.save_meta(live.sid, live.meta)
            messages.append({"role": "assistant", "content": reply.text,
                             "tool_calls": reply.tool_calls})
            if reply.text:
                final = reply.text
                record({"type": "assistant", "turn": turn, "text": reply.text})
            if not reply.tool_calls:
                record({"type": "done", "reason": reply.stop or "end_turn",
                        "turn": turn, "usage": live.meta["usage"]})
                return final
            for tc in reply.tool_calls:
                record({"type": "tool_call", "turn": turn, "id": tc["id"],
                        "tool": tc["name"], "input": tc["input"]})
                label = f"turn{turn}:{tc['id']}:{tc['name']}"
                cause = {"turn": turn, "tool_call_id": tc["id"], "tool": tc["name"],
                         "summary": _summarize(tc)}
                out, rc = tools.run(tc["name"], tc["input"], label, cause)
                touched = attribution.attribute(cause)
                if len(out) > MAX_TOOL_OUTPUT:
                    out = (out[:MAX_TOOL_OUTPUT // 2] + "\n...[truncated]...\n"
                           + out[-MAX_TOOL_OUTPUT // 2:])
                content = out if rc == 0 else f"{out}\n[exit code {rc}]"
                messages.append({"role": "tool", "tool_call_id": tc["id"],
                                 "content": content or "(no output)"})
                record({"type": "tool_result", "turn": turn, "id": tc["id"],
                        "tool": tc["name"], "exit_code": rc, "output": out,
                        "touched": touched, "layer": live.current_layer})
        record({"type": "done", "reason": "max_turns", "turn": start_turn + max_turns - 1,
                "usage": live.meta["usage"]})
        return final
    except (ov.OverlordError, SystemExit) as e:
        record({"type": "error", "text": str(e)})
        raise
    finally:
        transcript.close()


def _summarize(tc):
    i = tc["input"]
    if tc["name"] == "shell":
        return i.get("command", "")[:200]
    if tc["name"] in ("read_file", "write_file", "list_dir"):
        return i.get("path", "")
    return json.dumps(i)[:200]


# ---------------------------------------------------------------- CLI


def cmd_agent(args):
    grants = ov.load_grants(args)
    # The agent is jailed by default, unlike `run` and `shell`.
    #
    # Those take a command the operator typed; this takes commands a model
    # chooses. Without the jail the overlay covers only the target's own path,
    # so `bash -c "echo x > /tmp/f"` writes to the real /tmp: outside the
    # transaction, absent from the diff, with no provenance and nothing to roll
    # back — and the session still reports changes=0, which reads as "the agent
    # did nothing" rather than "the agent went somewhere we are not recording".
    # A reviewer cannot approve what was never shown to them, so the containment
    # has to be the default and leaving it has to be deliberate.
    if not args.no_jail:
        grants["jail"] = True
    else:
        print("warning: --no-jail — the model's tools can write anywhere this "
              "user can. Writes outside the target land on the real filesystem, "
              "outside the transaction, and cannot be rolled back.",
              file=sys.stderr)
    provider = make_provider(args.provider, args.model)
    live = ov.open_session(args.target, args.backend, grants, trace=args.trace,
                           wait=args.wait, stack=args.stack, capture=True,
                           agent=f"{provider.name}:{provider.model}")
    print(f"overlord agent: {provider.name}/{provider.model} over {live.meta['target']}"
          f"  [session {live.sid}]", file=sys.stderr)

    try:
        run_agent(live, provider, args.task, max_turns=args.max_turns, emit=_show)
    finally:
        sid, changes = live.close()
    ov._print_session_footer(sid, ov.load_meta(sid).get("exit_code"),
                             ov.load_meta(sid)["backend"], changes)
    return 0


def provider_for(meta, provider=None, model=None):
    """The provider a session ran with (meta['agent'] is 'name:model'),
    unless overridden."""
    recorded = (meta.get("agent") or ":").split(":", 1)
    name = provider or recorded[0] or "anthropic"
    if not provider and not model and len(recorded) > 1 and recorded[1] not in ("", "-"):
        model = recorded[1] if name != "scripted" else None
    return make_provider(name, model)


def cmd_resume(args, meta):
    """`overlord resume <sid>` for an agent session: reopen the stack, restore
    the transcript, hand the model the operator's note, run until it stops."""
    provider = provider_for(meta, args.provider, args.model)
    live = ov.reopen_session(args.session, wait=args.wait, capture=True)
    print(f"overlord resume: {provider.name}/{provider.model} over {live.meta['target']}"
          f"  [session {live.sid}, savepoint @{live.current_layer}]", file=sys.stderr)
    try:
        run_agent(live, provider, meta.get("task", ""),
                  max_turns=args.max_turns or DEFAULT_MAX_TURNS, emit=_show,
                  resume=True, note=args.note)
    finally:
        sid, changes = live.close()
    ov._print_session_footer(sid, ov.load_meta(sid).get("exit_code"),
                             ov.load_meta(sid)["backend"], changes)
    return 0


def _show(ev):
    t = ev["type"]
    if t == "assistant":
        print(f"\n{ev['text']}\n")
    elif t == "tool_call":
        print(f"  → {ev['tool']}  {_summarize({'name': ev['tool'], 'input': ev['input']})}")
    elif t == "tool_result":
        tail = ev["output"].strip().splitlines()[-3:]
        for line in tail:
            print(f"      {line[:160]}")
        print(f"    exit={ev['exit_code']}"
              + (f"  touched={len(ev['touched'])}  @{ev.get('layer')}" if ev["touched"] else ""))
    elif t == "resume":
        print(f"  ↺ resumed at savepoint @{ev.get('layer')}")
    elif t == "done":
        print(f"\n[{ev['reason']} after {ev['turn']} turn(s), "
              f"tokens in/out {ev.get('usage', {}).get('in', 0)}/"
              f"{ev.get('usage', {}).get('out', 0)}]")
    elif t == "error":
        print(f"\n[error] {ev['text']}", file=sys.stderr)


def add_agent_parser(sub, add_exec_flags):
    pa = sub.add_parser("agent", help="run a model as an agent inside a live session")
    add_exec_flags(pa)
    pa.add_argument("--no-jail", action="store_true",
                    help="run the agent's tools unjailed — they can then write "
                         "anywhere you can, outside the transaction and unrecorded")
    pa.add_argument("--provider", choices=["anthropic", "openai", "scripted"],
                    default="anthropic")
    pa.add_argument("--model", help=f"model id (defaults: {DEFAULT_MODELS})")
    pa.add_argument("--max-turns", type=int, default=DEFAULT_MAX_TURNS,
                    help="budget: model turns before the loop stops")
    pa.add_argument("--trace", nargs="?", const="strace", choices=["strace", "ebpf"])
    pa.add_argument("task", help="what the agent should do")
    pa.set_defaults(fn=cmd_agent)

    pk = sub.add_parser("keys", help="store a provider API key (mode 0600)")
    pk.add_argument("provider", choices=["anthropic", "openai"])
    pk.add_argument("key")
    pk.set_defaults(fn=lambda a: (save_key(a.provider, a.key),
                                  print(f"stored {a.provider} key"))[1] or 0)
