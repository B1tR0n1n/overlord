#!/usr/bin/env python3
"""OVERLORD model providers — every way a model can be reached, stdlib only.

    anthropic          Claude, native Messages API (streaming, adaptive thinking,
                       effort, refusal handling, server-side fallbacks)
    openai             OpenAI Chat Completions (streaming, reasoning effort)
    azure              Azure OpenAI deployments (endpoint + deployment + api-version)
    openai-compatible  anything that speaks the Chat Completions shape behind a
                       base URL: Ollama, vLLM, LiteLLM, Groq, Together, a gateway
    gemini             Google Gemini REST (streaming, function calling)
    scripted           deterministic replay for tests (no network)

One contract: `complete(system, messages, tools, on_delta) -> Reply`, where
messages are the neutral form the agent loop keeps

    {"role": "user", "content": str}
    {"role": "assistant", "content": str, "tool_calls": [{"id", "name", "input"}]}
    {"role": "tool", "tool_call_id": str, "content": str}

and on_delta(text) fires as text streams in. Each adapter translates to its
wire format and back. Generation knobs live in a ModelConfig and are applied
only when set: the current Claude family rejects temperature/top_p outright
and takes depth from `output_config.effort`, so nothing is sent blindly.

Every request goes through urllib against a configurable base URL with
optional extra headers, which is what makes gateways and proxies work.
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request

# Checked 2026-09-16 against the API reference bundled with this session:
# claude-opus-5 is the current default recommendation; claude-sonnet-5 the
# cheaper current-generation option; claude-fable-5-1 the most capable.
# OpenAI: gpt-5.5 serves the Chat Completions endpoint this client uses.
# Gemini id left generic — the live list (`overlord models`) is authoritative.
DEFAULT_MODELS = {
    "anthropic": "claude-opus-5",
    "openai": "gpt-5.5",
    "azure": "",                      # the deployment name is the model
    "openai-compatible": "",          # whatever the server lists
    "gemini": "gemini-2.5-pro",
    "scripted": "scripted",
}
DEFAULT_BASE_URLS = {
    "anthropic": "https://api.anthropic.com",
    "openai": "https://api.openai.com/v1",
    "azure": "",                      # https://<resource>.openai.azure.com
    "openai-compatible": "http://127.0.0.1:11434/v1",
    "gemini": "https://generativelanguage.googleapis.com",
}
KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY",
           "azure": "AZURE_OPENAI_API_KEY", "openai-compatible": "OPENAI_COMPAT_API_KEY",
           "gemini": "GEMINI_API_KEY"}
NEEDS_KEY = {"anthropic": True, "openai": True, "azure": True,
             "openai-compatible": False, "gemini": True, "scripted": False}
PROVIDERS = ["anthropic", "openai", "azure", "openai-compatible", "gemini"]
EFFORTS = ["", "low", "medium", "high", "xhigh", "max"]
ANTHROPIC_VERSION = "2023-06-01"
# opt-in refusal fallbacks on the native endpoint (routes by refusal category)
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class ProviderError(RuntimeError):
    pass


class Reply:
    def __init__(self, text, tool_calls, stop, usage, thinking="", refusal=None):
        self.text, self.tool_calls, self.stop, self.usage = text, tool_calls, stop, usage
        self.thinking, self.refusal = thinking, refusal


class ModelConfig:
    """Generation knobs. None means 'do not send' — every adapter applies only
    what is set, so a knob a model rejects is never on the wire by default."""
    FIELDS = ("max_tokens", "temperature", "top_p", "stop", "effort", "thinking",
              "system_extra", "stream", "fallbacks", "timeout", "context_limit", "api")
    DEFAULT_CONTEXT = 128_000     # tokens; compaction runs at 75% of this

    def __init__(self, max_tokens=None, temperature=None, top_p=None, stop=None,
                 effort=None, thinking=None, system_extra=None, stream=True,
                 fallbacks=True, timeout=600, context_limit=None, api=None):
        self.api = api or None                # OpenAI: None | "responses" | "chat"
        self.context_limit = int(context_limit) if context_limit else self.DEFAULT_CONTEXT
        self.max_tokens = int(max_tokens) if max_tokens else None
        self.temperature = float(temperature) if temperature not in (None, "") else None
        self.top_p = float(top_p) if top_p not in (None, "") else None
        self.stop = [s for s in (stop or []) if s]
        self.effort = effort or None          # low|medium|high|xhigh|max
        self.thinking = thinking or None      # None | "summarized" | "off"
        self.system_extra = system_extra or ""
        self.stream = bool(stream)
        self.fallbacks = bool(fallbacks)
        self.timeout = float(timeout or 600)

    @classmethod
    def from_dict(cls, d):
        d = d or {}
        stop = d.get("stop")
        if isinstance(stop, str):
            stop = [s.strip() for s in stop.split(",") if s.strip()]
        return cls(max_tokens=d.get("max_tokens"), temperature=d.get("temperature"),
                   top_p=d.get("top_p"), stop=stop, effort=d.get("effort"),
                   thinking=d.get("thinking"), system_extra=d.get("system_extra"),
                   stream=d.get("stream", True), fallbacks=d.get("fallbacks", True),
                   timeout=d.get("timeout") or 600, context_limit=d.get("context_limit"),
                   api=d.get("api"))

    def to_dict(self):
        return {k: getattr(self, k) for k in self.FIELDS}


# ---------------------------------------------------------------- transport


# Called with (url, response headers) after every provider reply, including
# an error reply: the rate-limit headers are the provider's own statement of
# how much headroom is left. Set by the engine (cost.note_ratelimit).
RESPONSE_HOOK = None


def _notify(url, headers):
    if RESPONSE_HOOK is None or headers is None:
        return
    try:
        RESPONSE_HOOK(url, headers)
    except Exception:                    # noqa: BLE001 — never on the call's path
        pass


def _open(url, headers, body, timeout, method="POST"):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "overlord/0.9", **headers})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        _notify(url, e.headers)
        detail = e.read().decode(errors="replace")[:2000]
        raise ProviderError(f"error: provider HTTP {e.code}: {detail}")
    except urllib.error.URLError as e:
        raise ProviderError(f"error: provider unreachable: {e.reason}")
    _notify(url, resp.headers)
    return resp


def _post(url, headers, body, timeout=600):
    with _open(url, headers, body, timeout) as r:
        return json.load(r)


def _get(url, headers, timeout=60):
    with _open(url, headers, None, timeout, method="GET") as r:
        return json.load(r)


def _sse(resp):
    """Yield (event, data) pairs from a Server-Sent Events response."""
    event, data = None, []
    for raw in resp:
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        if not line:
            if data:
                yield event, "\n".join(data)
            event, data = None, []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].lstrip())
    if data:
        yield event, "\n".join(data)


def _strict_json(text):
    """Tool input that streamed in must parse strictly; a tolerant parse
    would hand the tool a silently truncated object."""
    try:
        return json.loads(text) if text.strip() else {}, None
    except ValueError:
        return {"_raw": text}, text


# ---------------------------------------------------------------- anthropic


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model, key, base_url=None, headers=None, config=None):
        self.model, self.key = model, key
        self.base_url = (base_url or DEFAULT_BASE_URLS["anthropic"]).rstrip("/")
        self.headers = dict(headers or {})
        self.config = config or ModelConfig()

    @property
    def native(self):
        return self.base_url == DEFAULT_BASE_URLS["anthropic"]

    def _headers(self, betas=()):
        h = {"x-api-key": self.key, "anthropic-version": ANTHROPIC_VERSION, **self.headers}
        if betas:
            h["anthropic-beta"] = ",".join(betas)
        return h

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
                if blocks:
                    out.append({"role": "assistant", "content": blocks})
            elif m["role"] == "tool":
                block = {"type": "tool_result", "tool_use_id": m["tool_call_id"],
                         "content": m["content"]}
                if m.get("is_error"):
                    block["is_error"] = True
                # consecutive tool results merge into one user turn
                if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block]})
        return out

    def _body(self, system, messages, tools, stream):
        c = self.config
        body = {"model": self.model, "max_tokens": c.max_tokens or 16000,
                "system": system + (("\n\n" + c.system_extra) if c.system_extra else ""),
                "messages": self._wire(messages)}
        if tools:
            wire_tools = []
            for t in tools:
                wt = {"name": t["name"], "description": t["description"],
                      "input_schema": t["input_schema"]}
                if stream and self.native:
                    wt["eager_input_streaming"] = True
                wire_tools.append(wt)
            body["tools"] = wire_tools
        if c.temperature is not None:
            body["temperature"] = c.temperature
        if c.top_p is not None:
            body["top_p"] = c.top_p
        if c.stop:
            body["stop_sequences"] = c.stop
        if c.effort:
            body["output_config"] = {"effort": c.effort}
        if c.thinking == "summarized":
            body["thinking"] = {"type": "adaptive", "display": "summarized"}
        elif c.thinking == "off":
            body["thinking"] = {"type": "disabled"}
        if stream:
            body["stream"] = True
        return body

    def complete(self, system, messages, tools=None, on_delta=None):
        stream = self.config.stream
        body = self._body(system, messages, tools, stream)
        betas = []
        if self.config.fallbacks and self.native:
            body["fallbacks"] = "default"
            betas.append(FALLBACK_BETA)
        url = f"{self.base_url}/v1/messages"
        if not stream:
            return self._parse(_post(url, self._headers(betas), body, self.config.timeout))
        with _open(url, self._headers(betas), body, self.config.timeout) as resp:
            return self._consume(resp, on_delta)

    def _parse(self, data):
        text, calls, thinking = "", [], ""
        for block in data.get("content", []):
            if block["type"] == "text":
                text += block["text"]
            elif block["type"] == "tool_use":
                calls.append({"id": block["id"], "name": block["name"],
                              "input": block.get("input") or {}})
            elif block["type"] == "thinking":
                thinking += block.get("thinking") or ""
        u = data.get("usage", {})
        stop = data.get("stop_reason")
        refusal = data.get("stop_details") if stop == "refusal" else None
        return Reply(text, [] if stop == "refusal" else calls, stop, _usage(u),
                     thinking=thinking, refusal=refusal)

    def _consume(self, resp, on_delta):
        text, thinking, calls, blocks = "", "", [], {}
        usage, stop, refusal = {}, None, None
        for event, data in _sse(resp):
            try:
                ev = json.loads(data)
            except ValueError:
                continue
            t = ev.get("type")
            if t == "message_start":
                usage.update(ev.get("message", {}).get("usage") or {})
            elif t == "content_block_start":
                cb = ev.get("content_block") or {}
                blocks[ev.get("index")] = {"type": cb.get("type"), "id": cb.get("id"),
                                           "name": cb.get("name"), "json": ""}
            elif t == "content_block_delta":
                d = ev.get("delta") or {}
                if d.get("type") == "text_delta":
                    text += d.get("text", "")
                    if on_delta:
                        on_delta(d.get("text", ""))
                elif d.get("type") == "input_json_delta":
                    blocks.setdefault(ev.get("index"), {"json": ""})["json"] += d.get("partial_json", "")
                elif d.get("type") == "thinking_delta":
                    thinking += d.get("thinking", "")
            elif t == "content_block_stop":
                b = blocks.get(ev.get("index")) or {}
                if b.get("type") == "tool_use":
                    inp, bad = _strict_json(b.get("json", ""))
                    calls.append({"id": b.get("id"), "name": b.get("name"), "input": inp,
                                  "invalid_json": bad})
            elif t == "message_delta":
                stop = (ev.get("delta") or {}).get("stop_reason") or stop
                if stop == "refusal":
                    refusal = (ev.get("delta") or {}).get("stop_details") or {"type": "refusal"}
                usage.update(ev.get("usage") or {})
            elif t == "error":
                err = ev.get("error") or {}
                raise ProviderError(f"error: provider stream error: {err.get('message') or data}")
        if stop in ("refusal", "max_tokens") and calls:
            # a refusal or a cut-off can truncate a tool input mid-stream; never run those
            calls = [] if stop == "refusal" else calls
        return Reply(text, calls, stop, _usage(usage), thinking=thinking, refusal=refusal)

    def models(self):
        data = _get(f"{self.base_url}/v1/models?limit=100", self._headers(), 30)
        return [{"id": m.get("id"), "name": m.get("display_name") or m.get("id"),
                 "context": m.get("max_input_tokens"), "max_output": m.get("max_tokens")}
                for m in data.get("data", [])]


def _usage(u):
    return {"in": u.get("input_tokens", 0) or 0, "out": u.get("output_tokens", 0) or 0,
            "cache_read": u.get("cache_read_input_tokens", 0) or 0,
            "cache_write": u.get("cache_creation_input_tokens", 0) or 0}


# ---------------------------------------------------------------- openai family


class OpenAIProvider:
    """OpenAI. Two wire shapes behind one contract:

      responses   /v1/responses — OpenAI's current API and the only one where a
                  reasoning model may use function tools with a reasoning
                  effort (GPT-5.5 rejects the pair on chat completions). The
                  default for the `openai` provider. Nothing is stored server
                  side (`store: false`); the model's encrypted reasoning is
                  carried across the tool calls of one run so it does not have
                  to think everything through again every turn.
      chat        /v1/chat/completions — the shape Ollama, vLLM, LiteLLM, Groq
                  and most gateways speak (`openai-compatible`, any base URL)
                  and what Azure deployments serve.

    `ModelConfig.api` overrides the choice: `chat` for a gateway that fronts
    api.openai.com but only speaks the old shape, `responses` for a compatible
    server that has grown the new one."""
    name = "openai"
    RESPONSES, CHAT = "responses", "chat"
    STOP = {"length": "max_tokens", "max_output_tokens": "max_tokens",
            "content_filter": "refusal"}       # to the vocabulary agent.py checks

    def __init__(self, model, key, base_url=None, headers=None, config=None, name=None):
        self.model, self.key = model, key
        self.name = name or "openai"
        self.base_url = (base_url or DEFAULT_BASE_URLS.get(self.name)
                         or DEFAULT_BASE_URLS["openai"]).rstrip("/")
        self.headers = dict(headers or {})
        self.config = config or ModelConfig()
        self._reasoning = {}          # first tool-call id of a turn → its reasoning items

    @property
    def api(self):
        c = getattr(self.config, "api", None)
        if self.name == "azure":              # deployments serve chat completions
            return self.CHAT
        if c in (self.RESPONSES, self.CHAT):
            return c
        return self.RESPONSES if self.name == "openai" else self.CHAT

    def _headers(self):
        h = dict(self.headers)
        if self.key:
            h["Authorization"] = f"Bearer {self.key}"
        return h

    def _url(self, path):
        return f"{self.base_url}/{path}"

    def _system(self, system):
        c = self.config
        return system + (("\n\n" + c.system_extra) if c.system_extra else "")

    def _effort(self):
        return {"xhigh": "high", "max": "high"}.get(self.config.effort, self.config.effort)

    def complete(self, system, messages, tools=None, on_delta=None):
        stream = self.config.stream
        if self.api == self.RESPONSES:
            body = self._body_responses(system, messages, tools, stream)
            url = self._url("responses")
            if not stream:
                return self._parse_response(_post(url, self._headers(), body, self.config.timeout))
            with _open(url, self._headers(), body, self.config.timeout) as resp:
                return self._consume_responses(resp, on_delta)
        body = self._body(system, messages, tools, stream)
        url = self._url("chat/completions")
        if not stream:
            return self._parse(_post(url, self._headers(), body, self.config.timeout))
        with _open(url, self._headers(), body, self.config.timeout) as resp:
            return self._consume(resp, on_delta)

    # ------------------------------------------------------------ responses

    def _wire_responses(self, messages):
        out = []
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                if m.get("content"):
                    out.append({"role": "assistant", "content": m["content"]})
                calls = m.get("tool_calls") or []
                if calls:
                    # a reasoning item must be followed by the calls it produced
                    out.extend(self._reasoning.get(calls[0]["id"], []))
                for tc in calls:
                    out.append({"type": "function_call", "call_id": tc["id"], "name": tc["name"],
                                "arguments": json.dumps(tc["input"])})
            elif m["role"] == "tool":
                out.append({"type": "function_call_output", "call_id": m["tool_call_id"],
                            "output": m["content"]})
        return out

    def _body_responses(self, system, messages, tools, stream):
        c = self.config
        body = {"model": self.model, "instructions": self._system(system),
                "input": self._wire_responses(messages), "store": False,
                "include": ["reasoning.encrypted_content"]}
        if tools:
            body["tools"] = [{"type": "function", "name": t["name"],
                              "description": t["description"], "parameters": t["input_schema"]}
                             for t in tools]
        if c.max_tokens:
            body["max_output_tokens"] = c.max_tokens
        if c.temperature is not None:
            body["temperature"] = c.temperature
        if c.top_p is not None:
            body["top_p"] = c.top_p
        if c.effort:
            body["reasoning"] = {"effort": self._effort()}
        if stream:
            body["stream"] = True
        return body

    def _finish(self, text, calls, reasoning, status, detail, usage, refusal):
        if calls:
            self._reasoning[calls[0]["id"]] = reasoning
        if status == "failed":
            raise ProviderError(f"error: provider reply failed: {detail or 'no detail'}")
        if refusal is not None:
            stop = "refusal"
        elif status == "incomplete":
            stop = self.STOP.get(detail or "", detail or "incomplete")
        else:
            stop = "tool_calls" if calls else "stop"
        return Reply(text, calls, stop,
                     {"in": usage.get("input_tokens", 0), "out": usage.get("output_tokens", 0)},
                     refusal={"category": refusal} if refusal is not None else None)

    def _item(self, item, acc):
        """Fold one output item into the accumulator."""
        t = item.get("type")
        if t == "function_call":
            inp, bad = _strict_json(item.get("arguments") or "{}")
            acc["calls"].append({"id": item.get("call_id") or item.get("id") or f"call_{len(acc['calls'])}",
                                 "name": item.get("name"), "input": inp, "invalid_json": bad})
        elif t == "reasoning":
            keep = {k: item[k] for k in ("type", "id", "encrypted_content", "summary") if k in item}
            if keep.get("encrypted_content"):
                acc["reasoning"].append(keep)
        elif t == "message":
            for part in item.get("content") or []:
                if part.get("type") == "output_text":
                    acc["item_text"] += part.get("text") or ""
                elif part.get("type") == "refusal":
                    acc["refusal"] = part.get("refusal") or ""

    def _parse_response(self, data):
        acc = {"calls": [], "reasoning": [], "item_text": "", "refusal": None}
        for item in data.get("output") or []:
            self._item(item, acc)
        inc = data.get("incomplete_details") or {}
        err = data.get("error") or {}
        return self._finish(acc["item_text"], acc["calls"], acc["reasoning"], data.get("status"),
                            inc.get("reason") or err.get("message"), data.get("usage") or {},
                            acc["refusal"])

    def _consume_responses(self, resp, on_delta):
        acc = {"calls": [], "reasoning": [], "item_text": "", "refusal": None}
        text, status, detail, usage = "", None, None, {}
        for event, data in _sse(resp):
            try:
                ev = json.loads(data)
            except ValueError:
                continue
            kind = ev.get("type") or event
            if kind == "response.output_text.delta":
                text += ev.get("delta") or ""
                if on_delta and ev.get("delta"):
                    on_delta(ev["delta"])
            elif kind == "response.output_item.done":
                self._item(ev.get("item") or {}, acc)
            elif kind in ("response.completed", "response.incomplete", "response.failed"):
                r = ev.get("response") or {}
                usage = r.get("usage") or usage
                status = r.get("status") or kind.rsplit(".", 1)[-1]
                detail = (r.get("incomplete_details") or {}).get("reason") \
                    or (r.get("error") or {}).get("message")
            elif kind == "error":
                e = ev.get("error") if isinstance(ev.get("error"), dict) else ev
                raise ProviderError(f"error: provider stream error: {e.get('message') or data[:300]}")
        return self._finish(text or acc["item_text"], acc["calls"], acc["reasoning"], status,
                            detail, usage, acc["refusal"])

    # ------------------------------------------------------------ chat completions

    def _wire(self, system, messages):
        out = [{"role": "system", "content": self._system(system)}]
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

    def _body(self, system, messages, tools, stream):
        c = self.config
        body = {"model": self.model, "messages": self._wire(system, messages)}
        if tools:
            body["tools"] = [{"type": "function",
                              "function": {"name": t["name"], "description": t["description"],
                                           "parameters": t["input_schema"]}} for t in tools]
        if c.max_tokens:
            # OpenAI's newer models take max_completion_tokens; compatible
            # servers mostly still read max_tokens
            body["max_completion_tokens" if self.name == "openai" else "max_tokens"] = c.max_tokens
        if c.temperature is not None:
            body["temperature"] = c.temperature
        if c.top_p is not None:
            body["top_p"] = c.top_p
        if c.stop:
            body["stop"] = c.stop
        if c.effort and self.name in ("openai", "azure"):
            body["reasoning_effort"] = self._effort()
        if stream:
            body["stream"] = True
            body["stream_options"] = {"include_usage": True}
        return body

    def _parse(self, data):
        choice = data["choices"][0]
        msg = choice["message"]
        calls = []
        for tc in msg.get("tool_calls") or []:
            inp, bad = _strict_json(tc["function"].get("arguments") or "{}")
            calls.append({"id": tc["id"], "name": tc["function"]["name"], "input": inp,
                          "invalid_json": bad})
        u = data.get("usage") or {}
        stop = choice.get("finish_reason")
        return Reply(msg.get("content") or "", calls, self.STOP.get(stop, stop),
                     {"in": u.get("prompt_tokens", 0), "out": u.get("completion_tokens", 0)})

    def _consume(self, resp, on_delta):
        text, partial, stop, usage = "", {}, None, {}
        for _event, data in _sse(resp):
            if data.strip() == "[DONE]":
                break
            try:
                ev = json.loads(data)
            except ValueError:
                continue
            if ev.get("usage"):
                usage = ev["usage"]
            for ch in ev.get("choices") or []:
                d = ch.get("delta") or {}
                if d.get("content"):
                    text += d["content"]
                    if on_delta:
                        on_delta(d["content"])
                for tc in d.get("tool_calls") or []:
                    slot = partial.setdefault(tc.get("index", 0), {"id": None, "name": "", "args": ""})
                    if tc.get("id"):
                        slot["id"] = tc["id"]
                    fn = tc.get("function") or {}
                    if fn.get("name"):
                        slot["name"] += fn["name"]
                    if fn.get("arguments"):
                        slot["args"] += fn["arguments"]
                if ch.get("finish_reason"):
                    stop = ch["finish_reason"]
        calls = []
        for i in sorted(partial):
            s = partial[i]
            inp, bad = _strict_json(s["args"] or "{}")
            calls.append({"id": s["id"] or f"call_{i}", "name": s["name"], "input": inp,
                          "invalid_json": bad})
        return Reply(text, calls, self.STOP.get(stop, stop),
                     {"in": usage.get("prompt_tokens", 0), "out": usage.get("completion_tokens", 0)})

    def models(self):
        data = _get(self._url("models"), self._headers(), 30)
        return [{"id": m.get("id"), "name": m.get("id"), "context": None, "max_output": None}
                for m in data.get("data", [])]


class AzureOpenAIProvider(OpenAIProvider):
    """Azure OpenAI: the model is a deployment; auth is the api-key header."""
    name = "azure"

    def __init__(self, model, key, base_url=None, headers=None, config=None,
                 api_version="2024-10-21"):
        if not base_url:
            raise ProviderError("error: azure needs a base URL (https://<resource>.openai.azure.com)")
        super().__init__(model, key, base_url, headers, config, name="azure")
        self.api_version = api_version

    def _headers(self):
        return {"api-key": self.key, **self.headers}

    def _url(self, path):
        if path == "models":
            return f"{self.base_url}/openai/models?api-version={self.api_version}"
        return (f"{self.base_url}/openai/deployments/{urllib.parse.quote(self.model)}/"
                f"{path}?api-version={self.api_version}")


# ---------------------------------------------------------------- gemini


class GeminiProvider:
    name = "gemini"

    def __init__(self, model, key, base_url=None, headers=None, config=None):
        self.model, self.key = model, key
        self.base_url = (base_url or DEFAULT_BASE_URLS["gemini"]).rstrip("/")
        self.headers = dict(headers or {})
        self.config = config or ModelConfig()

    def _headers(self):
        return {"x-goog-api-key": self.key, **self.headers}

    def _wire(self, messages):
        out, names = [], {}
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "parts": [{"text": m["content"]}]})
            elif m["role"] == "assistant":
                parts = []
                if m.get("content"):
                    parts.append({"text": m["content"]})
                for tc in m.get("tool_calls", []):
                    names[tc["id"]] = tc["name"]
                    parts.append({"functionCall": {"name": tc["name"], "args": tc["input"]}})
                if parts:
                    out.append({"role": "model", "parts": parts})
            elif m["role"] == "tool":
                part = {"functionResponse": {"name": names.get(m["tool_call_id"], "tool"),
                                             "response": {"result": m["content"]}}}
                if out and out[-1]["role"] == "user" and "functionResponse" in out[-1]["parts"][0]:
                    out[-1]["parts"].append(part)
                else:
                    out.append({"role": "user", "parts": [part]})
        return out

    def _body(self, system, messages, tools):
        c = self.config
        body = {"system_instruction": {"parts": [{"text": system + (
            ("\n\n" + c.system_extra) if c.system_extra else "")}]},
                "contents": self._wire(messages)}
        if tools:
            body["tools"] = [{"functionDeclarations": [
                {"name": t["name"], "description": t["description"],
                 "parameters": _gemini_schema(t["input_schema"])} for t in tools]}]
        gen = {}
        if c.max_tokens:
            gen["maxOutputTokens"] = c.max_tokens
        if c.temperature is not None:
            gen["temperature"] = c.temperature
        if c.top_p is not None:
            gen["topP"] = c.top_p
        if c.stop:
            gen["stopSequences"] = c.stop
        if gen:
            body["generationConfig"] = gen
        return body

    def complete(self, system, messages, tools=None, on_delta=None):
        body = self._body(system, messages, tools)
        model = urllib.parse.quote(self.model)
        if not self.config.stream:
            url = f"{self.base_url}/v1beta/models/{model}:generateContent"
            return self._parse(_post(url, self._headers(), body, self.config.timeout))
        url = f"{self.base_url}/v1beta/models/{model}:streamGenerateContent?alt=sse"
        text, calls, usage, stop, n = "", [], {}, None, 0
        with _open(url, self._headers(), body, self.config.timeout) as resp:
            for _event, data in _sse(resp):
                try:
                    ev = json.loads(data)
                except ValueError:
                    continue
                usage = ev.get("usageMetadata") or usage
                for cand in ev.get("candidates") or []:
                    stop = cand.get("finishReason") or stop
                    for part in (cand.get("content") or {}).get("parts") or []:
                        if part.get("text"):
                            text += part["text"]
                            if on_delta:
                                on_delta(part["text"])
                        if part.get("functionCall"):
                            n += 1
                            fc = part["functionCall"]
                            calls.append({"id": f"gemini_{n}", "name": fc.get("name"),
                                          "input": fc.get("args") or {}})
        return Reply(text, calls, _gemini_stop(stop),
                     {"in": usage.get("promptTokenCount", 0), "out": usage.get("candidatesTokenCount", 0)})

    def _parse(self, data):
        text, calls, n = "", [], 0
        cand = (data.get("candidates") or [{}])[0]
        for part in (cand.get("content") or {}).get("parts") or []:
            if part.get("text"):
                text += part["text"]
            if part.get("functionCall"):
                n += 1
                fc = part["functionCall"]
                calls.append({"id": f"gemini_{n}", "name": fc.get("name"), "input": fc.get("args") or {}})
        u = data.get("usageMetadata") or {}
        return Reply(text, calls, _gemini_stop(cand.get("finishReason")),
                     {"in": u.get("promptTokenCount", 0), "out": u.get("candidatesTokenCount", 0)})

    def models(self):
        data = _get(f"{self.base_url}/v1beta/models?pageSize=100", self._headers(), 30)
        out = []
        for m in data.get("models", []):
            if "generateContent" not in (m.get("supportedGenerationMethods") or ["generateContent"]):
                continue
            out.append({"id": (m.get("name") or "").replace("models/", ""),
                        "name": m.get("displayName") or m.get("name"),
                        "context": m.get("inputTokenLimit"), "max_output": m.get("outputTokenLimit")})
        return out


def _gemini_stop(reason):
    return {"STOP": "end_turn", "MAX_TOKENS": "max_tokens", "SAFETY": "refusal"}.get(reason, reason)


def _gemini_schema(schema):
    """Gemini's function schemas are an OpenAPI subset: drop keys it rejects."""
    if not isinstance(schema, dict):
        return schema
    out = {}
    for k, v in schema.items():
        if k in ("default", "additionalProperties", "$schema"):
            continue
        if k == "properties" and isinstance(v, dict):
            out[k] = {pk: _gemini_schema(pv) for pk, pv in v.items()}
        elif k == "items":
            out[k] = _gemini_schema(v)
        else:
            out[k] = v
    return out


# ---------------------------------------------------------------- scripted


class ScriptedProvider:
    """Deterministic stand-in for tests: replays a list of Reply-like dicts.
    Text is delivered as deltas in two halves so streaming paths get exercised."""
    name = "scripted"

    def __init__(self, script):
        self.script, self.i, self.seen, self.systems, self.toolsets = list(script), 0, [], [], []
        self.model = "scripted"
        self.config = ModelConfig()

    def complete(self, system, messages, tools=None, on_delta=None):
        self.seen.append(json.loads(json.dumps(messages)))
        self.systems.append(system)
        self.toolsets.append([t["name"] for t in (tools or [])])
        if self.i >= len(self.script):
            return Reply("(script exhausted)", [], "end_turn", {"in": 0, "out": 0})
        step = self.script[self.i]
        self.i += 1
        text = step.get("text", "")
        if on_delta and text:
            half = max(1, len(text) // 2)
            on_delta(text[:half])
            on_delta(text[half:])
        calls = [{"id": f"call_{self.i}_{n}", "name": c["name"], "input": c["input"]}
                 for n, c in enumerate(step.get("tool_calls", []))]
        usage = {"in": 0, "out": 0, **(step.get("usage") or {})}   # a step may price itself
        return Reply(text, calls, "tool_use" if calls else "end_turn", usage)

    def models(self):
        return [{"id": "scripted", "name": "scripted", "context": None, "max_output": None}]


# ---------------------------------------------------------------- factory


def make(provider, model=None, key=None, base_url=None, headers=None, config=None,
         azure_api_version=None, script_env="OVERLORD_AGENT_SCRIPT", key_loader=None):
    """Build a provider. key_loader(provider) supplies a stored key when none
    is given (the engine's 0600 key store); env vars come first."""
    config = config if isinstance(config, ModelConfig) else ModelConfig.from_dict(config)
    model = model or DEFAULT_MODELS.get(provider) or ""
    if provider == "scripted":
        path = os.environ.get(script_env)
        if not path:
            raise ProviderError(f"error: scripted provider needs {script_env}")
        with open(path) as f:
            p = ScriptedProvider(json.load(f))
        p.model = model or "scripted"
        p.config = config
        return p
    if provider not in PROVIDERS:
        raise ProviderError(f"error: unknown provider: {provider}")
    if not key:
        key = os.environ.get(KEY_ENV[provider]) or (key_loader(provider) if key_loader else None)
    if not key and NEEDS_KEY[provider]:
        raise ProviderError(f"error: no API key for {provider}: set {KEY_ENV[provider]} "
                            "or add it in Settings")
    if not model and provider in ("azure", "openai-compatible"):
        raise ProviderError(f"error: {provider} needs a model "
                            f"({'deployment name' if provider == 'azure' else 'as the server lists it'})")
    if provider == "anthropic":
        return AnthropicProvider(model, key, base_url, headers, config)
    if provider == "openai":
        return OpenAIProvider(model, key, base_url, headers, config)
    if provider == "openai-compatible":
        return OpenAIProvider(model, key or "", base_url, headers, config, name="openai-compatible")
    if provider == "azure":
        return AzureOpenAIProvider(model, key, base_url, headers, config,
                                   api_version=azure_api_version or "2024-10-21")
    return GeminiProvider(model, key, base_url, headers, config)


def list_models(provider, key=None, base_url=None, headers=None, azure_api_version=None,
                key_loader=None):
    """Live model catalog for a provider (no model needed to ask)."""
    if provider == "scripted":
        return ScriptedProvider([]).models()
    p = make(provider, model=DEFAULT_MODELS.get(provider) or "-", key=key, base_url=base_url,
             headers=headers, azure_api_version=azure_api_version, key_loader=key_loader)
    return p.models()
