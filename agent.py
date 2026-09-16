#!/usr/bin/env python3
"""OVERLORD agent — the reference harness: a model thinks on the host, its
hands act inside a live transactional session.

    overlord agent -t <dir> [grants] [--provider anthropic|openai|azure|
                   openai-compatible|gemini] [--model M] [--base-url URL]
                   [--effort E] [--max-tokens N] [--max-turns N] [--no-jail] "<task>"
    overlord models [--provider P] [--base-url URL]

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

Providers (providers.py) are stdlib-only (urllib): anthropic, openai, azure,
openai-compatible, gemini — each behind a base URL with extra headers, each
streaming. Keys come from the environment (ANTHROPIC_API_KEY, OPENAI_API_KEY,
AZURE_OPENAI_API_KEY, GEMINI_API_KEY) or ~/.overlord/keys.json (mode 0600):
    {"anthropic": "sk-ant-...", "openai": "sk-..."}
"""

import base64
import json
import os
import sys
import time

import overlord as ov
import memory as memory_mod
import cost as cost_mod
import audit as audit_mod

import providers as _providers_defaults  # noqa: E402
DEFAULT_MODELS = _providers_defaults.DEFAULT_MODELS
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
    memory_mod.REMEMBER_TOOL,
]


# ---------------------------------------------------------------- keys


def load_key(provider):
    import providers as _p
    env = _p.KEY_ENV.get(provider)
    if env is None:
        raise ov.OverlordError(f"error: unknown provider: {provider}")
    if os.environ.get(env):
        return os.environ[env]
    # the person's own key store first (accounts on), then the machine's
    # shared one — an admin can provision a key for everyone
    shared = os.path.join(ov.OVERLORD_HOME, "keys.json")
    for path in dict.fromkeys((_keys_file(), shared)):
        if os.path.isfile(path):
            mode = os.stat(path).st_mode & 0o777
            if mode & 0o077:
                raise ov.OverlordError(f"error: {path} is mode {mode:03o}; chmod 600 it")
            with open(path) as f:
                key = json.load(f).get(provider)
            if key:
                return key
    raise ov.OverlordError(f"error: no API key for {provider}: set {env} or add it to {shared}")


def _keys_file():
    import auth
    return auth.user_path("keys.json", os.path.join(ov.OVERLORD_HOME, "keys.json"))


def save_key(provider, key):
    path = _keys_file()
    os.makedirs(os.path.dirname(path), exist_ok=True)
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
# The adapters live in providers.py (anthropic, openai, azure, openai-compatible,
# gemini, scripted). These names stay importable here for callers and tests.

import providers as _providers  # noqa: E402

Reply = _providers.Reply
ModelConfig = _providers.ModelConfig
AnthropicProvider = _providers.AnthropicProvider
OpenAIProvider = _providers.OpenAIProvider
AzureOpenAIProvider = _providers.AzureOpenAIProvider
GeminiProvider = _providers.GeminiProvider
ScriptedProvider = _providers.ScriptedProvider
PROVIDERS = _providers.PROVIDERS


def make_provider(provider, model=None, key=None, script_env="OVERLORD_AGENT_SCRIPT",
                  base_url=None, headers=None, config=None, azure_api_version=None):
    """Build a provider; stored keys come from the engine's 0600 key store
    when no key is given and the environment has none."""
    try:
        return _providers.make(provider, model=model, key=key, base_url=base_url,
                               headers=headers, config=config,
                               azure_api_version=azure_api_version, script_env=script_env,
                               key_loader=_stored_key)
    except _providers.ProviderError as e:
        raise ov.OverlordError(str(e))


def _stored_key(provider):
    try:
        return load_key(provider)
    except (ov.OverlordError, SystemExit):
        return None


def list_models(provider, base_url=None, headers=None, azure_api_version=None):
    try:
        return _providers.list_models(provider, base_url=base_url, headers=headers,
                                      azure_api_version=azure_api_version,
                                      key_loader=_stored_key)
    except _providers.ProviderError as e:
        raise ov.OverlordError(str(e))


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
        self.suggestions = []       # user-scope notes proposed this run

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

    def t_remember(self, inp, label):
        """Project scope appends to OVERLORD.md inside the transaction (a
        reviewed file change like any other); user scope only proposes."""
        text = " ".join(str(inp.get("text") or "").split())
        if not text:
            return "error: nothing to remember", 1
        if inp.get("scope") == "user":
            sug = {"id": f"mem_{len(self.suggestions) + 1}", "text": text}
            self.suggestions.append(sug)
            return ("noted as a suggestion; the person decides whether it is kept "
                    f"[{sug['id']}]"), 0
        b64 = base64.b64encode(("- " + text + "\n").encode()).decode()
        code = ("import base64,os,sys\n"
                "p, line = sys.argv[1], base64.b64decode(sys.argv[2])\n"
                "cur = open(p, 'rb').read() if os.path.exists(p) else b'# Project notes\\n\\n'\n"
                "if cur and not cur.endswith(b'\\n'): cur += b'\\n'\n"
                "open(p, 'wb').write(cur + line)\n"
                "print('remembered in', p)\n")
        return self._exec(["python3", "-c", code, memory_mod.PROJECT_FILE, b64], 30, label)


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
              should_stop=None, resume=False, note=None, connectors=None,
              approval=None, approve=None):
    """Drive the model against an open LiveSession until it stops calling
    tools, hits max_turns, or should_stop() is true. Emits events:
      assistant_delta / assistant / tool_call / tool_result / approval / done / error
    With resume=True the transcript already on disk (as cut by rewind) is
    the model's memory; an operator note is delivered as the next user turn.

    connectors: MCP server names this session is granted (default: the
    session's recorded grant). Their tools are offered next to the built-ins;
    a call runs on the host, outside the transaction, and is recorded with
    the server that served it. Non-read-only connector tools pass through the
    approval gate: `approval` is ask|auto|readonly (default from mcp.json) and
    `approve(request) -> bool` is asked under "ask" — no approver means deny.
    Returns the final assistant text."""
    import mcp as mcp_mod
    emit = emit or (lambda e: None)
    grants = live.meta.setdefault("grants", {})
    if connectors is None:
        connectors = list(grants.get("connectors") or [])
    registry = None
    if connectors:
        registry = mcp_mod.Registry(connectors)
        grants["connectors"] = list(connectors)
    mode = approval or (registry.approval if registry else "ask")
    if mode not in mcp_mod.APPROVAL_MODES:
        raise ov.OverlordError(f"error: connector approval must be one of {mcp_mod.APPROVAL_MODES}")
    if connectors:
        grants["connector_approval"] = mode
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
    cfg = getattr(provider, "config", None)
    if cfg is not None and "model_config" not in live.meta:
        live.meta["model_config"] = cfg.to_dict()
    if "provider_opts" not in live.meta:
        live.meta["provider_opts"] = {
            "base_url": getattr(provider, "base_url", None),
            "headers": getattr(provider, "headers", None) or {},
            "azure_api_version": getattr(provider, "api_version", None)}
    ov.save_meta(live.sid, live.meta)

    tools = ToolRunner(live)
    attribution = Attribution(live)
    mem_text, mem_summary = memory_mod.build_context(live.meta["target"], live.meta.get("owner"))
    system_prompt = SYSTEM_PROMPT + mem_text
    if mem_summary:
        live.meta["memory"] = mem_summary
        ov.save_meta(live.sid, live.meta)
    all_tools = list(TOOLS)
    if registry:
        try:
            all_tools += registry.tools()
        except ov.OverlordError as e:
            record({"type": "error", "text": str(e)})
            raise
        record({"type": "connectors", "servers": list(connectors), "approval": mode,
                "tools": [t["name"] for t in all_tools[len(TOOLS):]]})
    if resume:
        text = _operator_note(live, note)
        messages.append({"role": "user", "content": text})
        record({"type": "resume", "note": text, "turn": start_turn - 1,
                "layer": live.current_layer})
    else:
        record({"type": "task", "text": task, "agent": live.meta["agent"]})
    final = ""
    recorded_suggestions = 0
    try:
        for turn in range(start_turn, start_turn + max_turns):
            if should_stop and should_stop():
                record({"type": "done", "reason": "cancelled", "turn": turn})
                return final
            try:
                cost_mod.check(live.meta)          # before the money is spent
            except cost_mod.BudgetExceeded as e:
                record({"type": "error", "turn": turn, "text": str(e)})
                record({"type": "done", "reason": "budget", "turn": turn,
                        "usage": live.meta["usage"]})
                audit_mod.record("budget.stop", sid=live.sid, owner=live.meta.get("owner"),
                                 reason=str(e))
                return final
            reply = provider.complete(
                system_prompt, messages, tools=all_tools,
                on_delta=lambda t, _turn=turn: emit({"type": "assistant_delta",
                                                     "turn": _turn, "text": t}))
            live.meta["usage"]["in"] += reply.usage.get("in", 0)
            live.meta["usage"]["out"] += reply.usage.get("out", 0)
            model_name = getattr(provider, "model", "") or ""
            usd = cost_mod.cost_of(model_name, reply.usage)
            if usd is not None:
                live.meta["usage"]["usd"] = round((live.meta["usage"].get("usd") or 0) + usd, 6)
            cost_mod.ledger_append(live.sid, live.meta.get("owner"), model_name, reply.usage, usd)
            ov.save_meta(live.sid, live.meta)
            messages.append({"role": "assistant", "content": reply.text,
                             "tool_calls": reply.tool_calls})
            if reply.text:
                final = reply.text
                record({"type": "assistant", "turn": turn, "text": reply.text})
            if reply.stop == "refusal":
                # a safety decline: the turn's tool calls are never run
                record({"type": "error", "turn": turn,
                        "text": "the model declined this request"
                                + (f" ({reply.refusal.get('category')})"
                                   if isinstance(reply.refusal, dict) and reply.refusal.get("category")
                                   else "")})
                record({"type": "done", "reason": "refusal", "turn": turn,
                        "usage": live.meta["usage"]})
                return final
            if not reply.tool_calls:
                record({"type": "done", "reason": reply.stop or "end_turn",
                        "turn": turn, "usage": live.meta["usage"]})
                return final
            if reply.stop == "max_tokens":
                # a cut-off can truncate a tool input into a valid-looking
                # partial object; never run those — stop and say so
                record({"type": "error", "turn": turn,
                        "text": "the reply was cut off at max_tokens before its tool "
                                "calls completed; raise Max tokens in Settings"})
                record({"type": "done", "reason": "max_tokens", "turn": turn,
                        "usage": live.meta["usage"]})
                return final
            for tc in reply.tool_calls:
                ev = {"type": "tool_call", "turn": turn, "id": tc["id"],
                      "tool": tc["name"], "input": tc["input"]}
                if registry and registry.owns(tc["name"]):
                    ev.update(external=True, **{"connector": registry.describe(tc["name"])["server"]})
                record(ev)
                label = f"turn{turn}:{tc['id']}:{tc['name']}"
                cause = {"turn": turn, "tool_call_id": tc["id"], "tool": tc["name"],
                         "summary": _summarize(tc)}
                if tc.get("invalid_json"):
                    # streamed tool input that did not parse strictly: hand it
                    # back as an error so the model can retry, never run it
                    out, rc = json.dumps({"INVALID_JSON": tc["invalid_json"][:4000]}), 1
                    touched = []
                elif registry and registry.owns(tc["name"]):
                    out, rc = _connector_call(registry, mode, approve, tc, turn, record,
                                              sid=live.sid, owner=live.meta.get("owner"))
                    touched = []
                else:
                    out, rc = tools.run(tc["name"], tc["input"], label, cause)
                    touched = attribution.attribute(cause)
                if len(out) > MAX_TOOL_OUTPUT:
                    out = (out[:MAX_TOOL_OUTPUT // 2] + "\n...[truncated]...\n"
                           + out[-MAX_TOOL_OUTPUT // 2:])
                content = out if rc == 0 else f"{out}\n[exit code {rc}]"
                messages.append({"role": "tool", "tool_call_id": tc["id"],
                                 "content": content or "(no output)",
                                 "is_error": bool(tc.get("invalid_json"))})
                record({"type": "tool_result", "turn": turn, "id": tc["id"],
                        "tool": tc["name"], "exit_code": rc, "output": out,
                        "touched": touched, "layer": live.current_layer})
                for sug in tools.suggestions[recorded_suggestions:]:
                    record({"type": "memory_suggestion", "turn": turn, "id": sug["id"],
                            "text": sug["text"]})
                recorded_suggestions = len(tools.suggestions)
        record({"type": "done", "reason": "max_turns", "turn": start_turn + max_turns - 1,
                "usage": live.meta["usage"]})
        return final
    except (ov.OverlordError, SystemExit) as e:
        record({"type": "error", "text": str(e)})
        raise
    finally:
        transcript.close()
        if registry:
            registry.close()


def _connector_call(registry, mode, approve, tc, turn, record, sid=None, owner=None):
    """A connector tool: outside the jail and the transaction, so gated.
    Returns (output, rc) for the model; every decision is in the transcript."""
    desc = registry.describe(tc["name"])
    req = {"id": tc["id"], "turn": turn, "tool": desc["tool"], "server": desc["server"],
           "name": tc["name"], "input": tc["input"], "read_only": desc["read_only"]}
    decision = "read-only" if desc["read_only"] else None
    if not desc["read_only"]:
        if mode == "readonly":
            decision = "denied-by-policy"
        elif mode == "auto":
            decision = "auto-approved"
        else:
            record({"type": "approval", **req})
            allowed = bool(approve(req)) if approve else False
            decision = "approved" if allowed else ("denied" if approve else "denied-no-approver")
    record({"type": "approval_decision", "id": tc["id"], "turn": turn, "decision": decision,
            "server": desc["server"], "tool": desc["tool"]})
    audit_mod.record("connector.decision", sid=sid, owner=owner, server=desc["server"],
                     tool=desc["tool"], decision=decision)
    if decision.startswith("denied"):
        why = {"denied-by-policy": "connector approval mode is readonly",
               "denied-no-approver": "no one is available to approve external actions",
               "denied": "the operator denied this action"}[decision]
        return f"error: {desc['server']}.{desc['tool']} was not run: {why}", 1
    try:
        out, is_error = registry.call(tc["name"], tc["input"])
    except ov.OverlordError as e:
        return f"error: {e}", 1
    return out, (1 if is_error else 0)


def cli_approve(req):
    """The CLI's approval gate: ask on a terminal, deny without one."""
    if not sys.stdin.isatty():
        print(f"  [connector] {req['server']}.{req['tool']} needs approval and there is "
              "no terminal to ask — denied", file=sys.stderr)
        return False
    print(f"\n  [connector] {req['server']}.{req['tool']} wants to run with:", file=sys.stderr)
    print("    " + json.dumps(req["input"])[:600], file=sys.stderr)
    try:
        ans = input("  allow this external action? [y/N] ")
    except EOFError:
        return False
    return ans.strip().lower() in ("y", "yes")


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
    provider = make_provider(args.provider, args.model, base_url=args.base_url,
                             headers=_headers_arg(args.header),
                             config=config_from_args(args),
                             azure_api_version=args.azure_api_version)
    live = ov.open_session(args.target, args.backend, grants, trace=args.trace,
                           wait=args.wait, stack=args.stack, capture=True,
                           agent=f"{provider.name}:{provider.model}")
    print(f"overlord agent: {provider.name}/{provider.model} over {live.meta['target']}"
          f"  [session {live.sid}]", file=sys.stderr)

    try:
        run_agent(live, provider, args.task, max_turns=args.max_turns, emit=_show,
                  connectors=args.connector or None, approval=args.connector_approval,
                  approve=cli_approve)
    finally:
        sid, changes = live.close()
    ov._print_session_footer(sid, ov.load_meta(sid).get("exit_code"),
                             ov.load_meta(sid)["backend"], changes)
    return 0


def provider_for(meta, provider=None, model=None):
    """The provider a session ran with (meta['agent'] is 'name:model', and
    meta['model_config'] / meta['provider_opts'] carry the knobs and the
    endpoint it used), unless overridden."""
    recorded = (meta.get("agent") or ":").split(":", 1)
    name = provider or recorded[0] or "anthropic"
    if not provider and not model and len(recorded) > 1 and recorded[1] not in ("", "-"):
        model = recorded[1] if name != "scripted" else None
    opts = meta.get("provider_opts") or {}
    return make_provider(name, model, base_url=opts.get("base_url"),
                         headers=opts.get("headers"), config=meta.get("model_config"),
                         azure_api_version=opts.get("azure_api_version"))


def cmd_models(args):
    rows = list_models(args.provider, base_url=args.base_url,
                       headers=_headers_arg(args.header),
                       azure_api_version=args.azure_api_version)
    if not rows:
        print("no models listed")
        return 1
    for m in rows:
        ctx = f"  ctx {m['context']:,}" if m.get("context") else ""
        out = f"  out {m['max_output']:,}" if m.get("max_output") else ""
        print(f"{m['id']:40s} {m.get('name') or ''}{ctx}{out}")
    return 0


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
                  resume=True, note=args.note, approve=cli_approve)
    finally:
        sid, changes = live.close()
    ov._print_session_footer(sid, ov.load_meta(sid).get("exit_code"),
                             ov.load_meta(sid)["backend"], changes)
    return 0


_STREAMED = {"n": 0}


def _show(ev):
    t = ev["type"]
    if t == "assistant_delta":
        if _STREAMED["n"] == 0:
            print()
        print(ev["text"], end="", flush=True)
        _STREAMED["n"] += len(ev["text"])
        return
    if t == "assistant":
        if _STREAMED["n"]:
            print("\n")          # the text already streamed; close the paragraph
        else:
            print(f"\n{ev['text']}\n")
        _STREAMED["n"] = 0
        return
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
    elif t == "connectors":
        print(f"  ⇄ connectors {', '.join(ev['servers'])} ({ev['approval']}): "
              f"{len(ev['tools'])} tool(s)")
    elif t == "memory_suggestion":
        print(f"  ✎ proposed for your memory [{ev['id']}]: {ev['text']}  "
              f"(overlord memory accept <session> --id {ev['id']})")
    elif t == "approval_decision":
        print(f"    {ev['server']}.{ev['tool']}: {ev['decision']}")
    elif t == "done":
        print(f"\n[{ev['reason']} after {ev['turn']} turn(s), "
              f"tokens in/out {ev.get('usage', {}).get('in', 0)}/"
              f"{ev.get('usage', {}).get('out', 0)}]")
    elif t == "error":
        print(f"\n[error] {ev['text']}", file=sys.stderr)


def _headers_arg(items):
    out = {}
    for h in items or []:
        if ":" not in h:
            raise ov.OverlordError(f"error: --header wants 'Name: value', got {h!r}")
        k, v = h.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def config_from_args(args):
    return ModelConfig.from_dict({
        "max_tokens": getattr(args, "max_tokens", None),
        "temperature": getattr(args, "temperature", None),
        "top_p": getattr(args, "top_p", None),
        "stop": getattr(args, "stop", None),
        "effort": getattr(args, "effort", None),
        "thinking": getattr(args, "thinking", None),
        "system_extra": getattr(args, "system", None),
        "stream": not getattr(args, "no_stream", False),
        "fallbacks": not getattr(args, "no_fallbacks", False)})


def add_model_flags(p):
    """The model-configuration surface, shared by agent / resume / review."""
    p.add_argument("--provider", choices=PROVIDERS + ["scripted"], default=None)
    p.add_argument("--model", help=f"model id (defaults: {DEFAULT_MODELS})")
    p.add_argument("--base-url", help="endpoint override: a gateway, a proxy, a local server")
    p.add_argument("--header", action="append", metavar="'Name: value'",
                   help="extra request header (repeatable)")
    p.add_argument("--azure-api-version", help="azure only (default 2024-10-21)")
    p.add_argument("--max-tokens", type=int)
    p.add_argument("--temperature", type=float,
                   help="sent only when given; the current Claude family rejects it")
    p.add_argument("--top-p", type=float)
    p.add_argument("--stop", action="append", help="stop sequence (repeatable)")
    p.add_argument("--effort", choices=[e for e in _providers.EFFORTS if e],
                   help="reasoning depth (anthropic output_config.effort / openai reasoning_effort)")
    p.add_argument("--thinking", choices=["summarized", "off"],
                   help="anthropic: stream a thinking summary, or disable thinking")
    p.add_argument("--system", help="text appended to the system prompt")
    p.add_argument("--no-stream", action="store_true", help="one-shot responses instead of SSE")
    p.add_argument("--no-fallbacks", action="store_true",
                   help="anthropic native: do not opt into server-side refusal fallbacks")
    p.add_argument("--connector", action="append", metavar="NAME",
                   help="grant an MCP connector's tools to this session (repeatable; "
                        "they run on the host, outside the transaction)")
    p.add_argument("--connector-approval", choices=["ask", "auto", "readonly"],
                   help="gate for non-read-only connector tools (default from mcp.json)")


def add_agent_parser(sub, add_exec_flags):
    pa = sub.add_parser("agent", help="run a model as an agent inside a live session")
    add_exec_flags(pa)
    pa.add_argument("--no-jail", action="store_true",
                    help="run the agent's tools unjailed — they can then write "
                         "anywhere you can, outside the transaction and unrecorded")
    add_model_flags(pa)
    pa.set_defaults(provider="anthropic")
    pa.add_argument("--max-turns", type=int, default=DEFAULT_MAX_TURNS,
                    help="budget: model turns before the loop stops")
    pa.add_argument("--trace", nargs="?", const="strace", choices=["strace", "ebpf"])
    pa.add_argument("task", help="what the agent should do")
    pa.set_defaults(fn=cmd_agent)

    pm = sub.add_parser("models", help="list the models a provider serves right now")
    pm.add_argument("--provider", choices=PROVIDERS, default="anthropic")
    pm.add_argument("--base-url")
    pm.add_argument("--header", action="append")
    pm.add_argument("--azure-api-version")
    pm.set_defaults(fn=cmd_models)

    pk = sub.add_parser("keys", help="store a provider API key (mode 0600)")
    pk.add_argument("provider", choices=PROVIDERS)
    pk.add_argument("key")
    pk.set_defaults(fn=lambda a: (save_key(a.provider, a.key),
                                  print(f"stored {a.provider} key"))[1] or 0)
