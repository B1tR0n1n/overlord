#!/usr/bin/env python3
"""Provider adapters, wire-exact and offline: every provider's request body
and headers for the neutral message form, streaming parsed from canned SSE
(text deltas, tool inputs assembled from fragments, usage, stop reasons,
refusal), strict tool-input validation, model-aware generation knobs (nothing
sent unless set; effort mapped per provider), base URL / headers / Azure
routing, model listing, and the factory's key rules. No network."""

import io
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ["OVERLORD_HOME"] = tempfile.mkdtemp()

import providers as P    # noqa: E402
import agent             # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


NEUTRAL = [
    {"role": "user", "content": "task"},
    {"role": "assistant", "content": "thinking", "tool_calls": [
        {"id": "c1", "name": "shell", "input": {"command": "ls"}},
        {"id": "c2", "name": "read_file", "input": {"path": "a"}}]},
    {"role": "tool", "tool_call_id": "c1", "content": "out1"},
    {"role": "tool", "tool_call_id": "c2", "content": "out2", "is_error": True},
]
CAPTURED = {}


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def fake_open(url, headers, body, timeout, method="POST"):
    CAPTURED.update(url=url, headers=headers, body=body, method=method)
    return FakeResp(CAPTURED.get("stream", b""))


_ORIG_OPEN = P._open                      # the genuine transport, for the hook test
P._open = fake_open

# ------------------------------------------------------------ the response hook
# every reply's headers reach RESPONSE_HOOK, an error reply's too (that is
# where retry-after lives); the hook never breaks the call
import email.message  # noqa: E402
import urllib.error  # noqa: E402
import urllib.request  # noqa: E402
seen = []


class HdrResp(FakeResp):
    headers = {"anthropic-ratelimit-tokens-remaining": "7"}


def fake_urlopen(req, timeout=None):
    if "fail" in req.full_url:
        h = email.message.Message(); h["retry-after"] = "9"
        raise urllib.error.HTTPError(req.full_url, 429, "slow down", h, io.BytesIO(b'{"error":"rl"}'))
    return HdrResp(b"{}")


P._open = _ORIG_OPEN
urllib.request.urlopen, P.RESPONSE_HOOK = fake_urlopen, lambda url, h: seen.append((url, dict(h.items()) if hasattr(h, "items") else h))
P._post("https://x/ok", {}, {})
try:
    P._post("https://x/fail", {}, {})
    fail("429 did not raise")
except P.ProviderError as e:
    if "429" not in str(e):
        fail(f"429 message: {e}")
if seen != [("https://x/ok", {"anthropic-ratelimit-tokens-remaining": "7"}), ("https://x/fail", {"retry-after": "9"})]:
    fail(f"response hook calls: {seen}")
P.RESPONSE_HOOK = lambda url, h: 1 / 0
P._post("https://x/ok", {}, {})                       # a broken hook is not the call's problem
P.RESPONSE_HOOK = None
P._open = fake_open                                    # restore for the streaming tests below
ok("response hook: every reply's headers, error replies included; never on the call's path")

# ------------------------------------------------------------ anthropic streaming
sse = b"""event: message_start
data: {"type":"message_start","message":{"usage":{"input_tokens":12,"cache_read_input_tokens":4}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hel"}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"lo"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: content_block_start
data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"write_file","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\\"path\\": \\"a.txt\\", "}}

event: content_block_delta
data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\\"content\\": \\"x\\\\ny\\"}"}}

event: content_block_stop
data: {"type":"content_block_stop","index":1}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":9}}

event: message_stop
data: {"type":"message_stop"}

"""
CAPTURED["stream"] = sse
a = P.AnthropicProvider("claude-opus-5", "k", config=P.ModelConfig(effort="high", thinking="summarized"))
deltas = []
r = a.complete("sys", NEUTRAL, tools=agent.TOOLS, on_delta=deltas.append)
b = CAPTURED["body"]
if CAPTURED["url"] != "https://api.anthropic.com/v1/messages" or CAPTURED["headers"]["x-api-key"] != "k":
    fail(f"anthropic url/headers: {CAPTURED['url']} {CAPTURED['headers']}")
if b["system"] != "sys" or b["stream"] is not True or b["max_tokens"] != 16000:
    fail(f"anthropic body basics: {b}")
if b["output_config"] != {"effort": "high"} or b["thinking"] != {"type": "adaptive", "display": "summarized"}:
    fail(f"effort/thinking mapping: {b.get('output_config')} {b.get('thinking')}")
if "temperature" in b or "top_p" in b:
    fail("sampling knobs were sent without being set")
if b["fallbacks"] != "default" or P.FALLBACK_BETA not in CAPTURED["headers"].get("anthropic-beta", ""):
    fail("server-side refusal fallbacks not opted in on the native endpoint")
if not all(t.get("eager_input_streaming") for t in b["tools"]) or b["tools"][0]["name"] != "list_dir":
    fail(f"tool wire shape: {b['tools'][0]}")
if b["messages"][1]["content"][1]["type"] != "tool_use" or \
        b["messages"][2]["content"][1] != {"type": "tool_result", "tool_use_id": "c2",
                                            "content": "out2", "is_error": True}:
    fail(f"anthropic message translation: {b['messages']}")
if deltas != ["Hel", "lo"] or r.text != "Hello" or r.stop != "tool_use":
    fail(f"streamed text: {deltas} {r.text!r} {r.stop}")
if r.tool_calls != [{"id": "toolu_1", "name": "write_file",
                     "input": {"path": "a.txt", "content": "x\ny"}, "invalid_json": None}]:
    fail(f"tool input assembled from fragments: {r.tool_calls}")
if r.usage != {"in": 12, "out": 9, "cache_read": 4, "cache_write": 0}:
    fail(f"usage: {r.usage}")
ok("anthropic: streaming text + fragmented tool input, effort/thinking, fallbacks, no stray knobs")

# refusal mid-stream: text kept, tool calls dropped
CAPTURED["stream"] = b"""event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"shell","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"command\\": \\"rm"}}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber"}},"usage":{"output_tokens":1}}

"""
r = a.complete("sys", NEUTRAL, tools=agent.TOOLS)
if r.stop != "refusal" or r.tool_calls or r.refusal.get("category") != "cyber":
    fail(f"refusal handling: {r.stop} {r.tool_calls} {r.refusal}")
# invalid streamed JSON is flagged, never parsed leniently
CAPTURED["stream"] = b"""event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"shell","input":{}}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"command\\": \\"ls"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{}}

"""
r = a.complete("sys", NEUTRAL, tools=agent.TOOLS)
if not r.tool_calls[0].get("invalid_json") or "_raw" not in r.tool_calls[0]["input"]:
    fail(f"invalid streamed JSON not flagged: {r.tool_calls}")
ok("anthropic: a refusal drops the turn's tool calls; malformed streamed input is flagged")

# non-streaming, gateway base URL, extra headers: no eager flag, no fallbacks
CAPTURED.clear()
P._post = lambda url, headers, body, timeout=600: (CAPTURED.update(url=url, headers=headers, body=body) or {
    "content": [{"type": "text", "text": "hi"}], "stop_reason": "end_turn",
    "usage": {"input_tokens": 1, "output_tokens": 1}})
g = P.AnthropicProvider("claude-opus-5", "k", base_url="https://gw.example/anthropic",
                        headers={"X-Org": "t"},
                        config=P.ModelConfig(stream=False, temperature=0.2, stop=["END"],
                                             max_tokens=500, system_extra="Be brief."))
r = g.complete("sys", NEUTRAL, tools=agent.TOOLS)
b = CAPTURED["body"]
if CAPTURED["url"] != "https://gw.example/anthropic/v1/messages" or CAPTURED["headers"]["X-Org"] != "t":
    fail("gateway base URL / headers")
if "fallbacks" in b or "anthropic-beta" in CAPTURED["headers"] or any("eager_input_streaming" in t for t in b["tools"]):
    fail("native-only options leaked to a gateway request")
if b["temperature"] != 0.2 or b["stop_sequences"] != ["END"] or b["max_tokens"] != 500 or \
        not b["system"].endswith("\n\nBe brief.") or "stream" in b:
    fail(f"knobs when set: {b}")
if r.text != "hi":
    fail("non-streaming parse")
ok("anthropic: gateway base URL + headers; knobs sent only when set; non-streaming path")

# ------------------------------------------------------------ openai: responses
# the default for `openai`: /v1/responses, the only place a reasoning model
# may hold function tools and a reasoning effort at once
P._open = fake_open
CAPTURED.clear()
CAPTURED["stream"] = b"""event: response.created
data: {"type":"response.created","response":{"id":"resp_1"}}

event: response.output_item.done
data: {"type":"response.output_item.done","item":{"type":"reasoning","id":"rs_1","encrypted_content":"ENC","summary":[]}}

event: response.output_text.delta
data: {"type":"response.output_text.delta","delta":"He"}

event: response.output_text.delta
data: {"type":"response.output_text.delta","delta":"y"}

event: response.output_item.done
data: {"type":"response.output_item.done","item":{"type":"message","content":[{"type":"output_text","text":"Hey"}]}}

event: response.output_item.done
data: {"type":"response.output_item.done","item":{"type":"function_call","id":"fc_1","call_id":"call_9","name":"shell","arguments":"{\\"command\\": \\"pwd\\"}"}}

event: response.completed
data: {"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":10,"output_tokens":5}}}
"""
o = P.OpenAIProvider("gpt-5.5", "k", config=P.ModelConfig(effort="xhigh", max_tokens=300))
deltas = []
r = o.complete("sys", NEUTRAL, tools=agent.TOOLS, on_delta=deltas.append)
b = CAPTURED["body"]
if CAPTURED["url"] != "https://api.openai.com/v1/responses" or \
        CAPTURED["headers"]["Authorization"] != "Bearer k":
    fail(f"openai responses url/auth: {CAPTURED['url']}")
if b["instructions"] != "sys" or b["store"] is not False or "reasoning.encrypted_content" not in b["include"]:
    fail(f"openai responses envelope: {b}")
items = b["input"]
if items[0] != {"role": "user", "content": NEUTRAL[0]["content"]} or \
        items[1] != {"role": "assistant", "content": NEUTRAL[1]["content"]} or \
        [i for i in items if i.get("type") == "function_call"][0]["call_id"] != NEUTRAL[1]["tool_calls"][0]["id"] or \
        [i for i in items if i.get("type") == "function_call_output"][-1]["call_id"] != "c2":
    fail(f"openai responses input translation: {items}")
if b["tools"][0] != {"type": "function", "name": "list_dir", "description": agent.TOOLS[0]["description"],
                     "parameters": agent.TOOLS[0]["input_schema"]}:
    fail(f"openai responses tools: {b['tools'][0]}")
if b["reasoning"] != {"effort": "high"} or b["max_output_tokens"] != 300 or "reasoning_effort" in b \
        or "max_completion_tokens" in b or b.get("stream") is not True:
    fail(f"openai responses knobs: {b}")
if deltas != ["He", "y"] or r.text != "Hey" or r.stop != "tool_calls" or \
        r.tool_calls[0]["input"] != {"command": "pwd"} or r.tool_calls[0]["id"] != "call_9" or \
        r.usage != {"in": 10, "out": 5}:
    fail(f"openai responses stream parse: {deltas} {r.text!r} {r.tool_calls} {r.usage}")
ok("openai: /v1/responses by default — reasoning + function tools, streamed text and calls")

# the next turn replays the model's encrypted reasoning ahead of the calls it
# produced, then the tool's output; a reply cut off maps to max_tokens
CAPTURED.clear()
CAPTURED["stream"] = b"""event: response.incomplete
data: {"type":"response.incomplete","response":{"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"usage":{"input_tokens":20,"output_tokens":300}}}
"""
msgs = NEUTRAL + [{"role": "assistant", "content": r.text, "tool_calls": r.tool_calls},
                  {"role": "tool", "tool_call_id": "call_9", "content": "/work"}]
r2 = o.complete("sys", msgs, tools=agent.TOOLS)
items = CAPTURED["body"]["input"]
i = [n for n, it in enumerate(items) if it.get("type") == "function_call" and it["call_id"] == "call_9"][0]
if items[i - 1] != {"type": "reasoning", "id": "rs_1", "encrypted_content": "ENC", "summary": []} or \
        items[i - 2] != {"role": "assistant", "content": "Hey"} or \
        items[i + 1] != {"type": "function_call_output", "call_id": "call_9", "output": "/work"}:
    fail(f"reasoning carry-over: {items[i-2:i+2]}")
if r2.stop != "max_tokens" or r2.tool_calls or r2.usage != {"in": 20, "out": 300}:
    fail(f"incomplete reply: {r2.stop} {r2.tool_calls} {r2.usage}")
# a failed response is an error, a refusal drops the turn's calls, non-streaming parses the same
CAPTURED["stream"] = b"""event: response.failed
data: {"type":"response.failed","response":{"status":"failed","error":{"message":"server melted"}}}
"""
try:
    o.complete("sys", NEUTRAL, tools=agent.TOOLS)
    fail("failed response not raised")
except P.ProviderError as e:
    if "server melted" not in str(e):
        fail(f"failed response message: {e}")
P._post = lambda url, headers, body, timeout=600: (CAPTURED.update(url=url, body=body) or {
    "status": "completed", "output": [
        {"type": "message", "content": [{"type": "refusal", "refusal": "no"}]},
        {"type": "function_call", "call_id": "call_x", "name": "shell", "arguments": "{}"}],
    "usage": {"input_tokens": 3, "output_tokens": 1}})
ns = P.OpenAIProvider("gpt-5.5", "k", config=P.ModelConfig(stream=False))
r3 = ns.complete("sys", NEUTRAL, tools=agent.TOOLS)
if "stream" in CAPTURED["body"] or r3.stop != "refusal" or r3.refusal != {"category": "no"} or not r3.tool_calls:
    fail(f"non-streaming responses / refusal: {r3.stop} {r3.refusal}")
ok("openai: encrypted reasoning replayed before its calls; max_tokens, failure and refusal mapped")

# ------------------------------------------------------------ openai: chat completions
# `api: chat` keeps the old shape for a gateway that fronts api.openai.com
CAPTURED.clear()
CAPTURED["stream"] = b"""data: {"choices":[{"delta":{"content":"He"},"finish_reason":null}]}

data: {"choices":[{"delta":{"content":"y"},"finish_reason":null}]}

data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_9","function":{"name":"shell","arguments":"{\\"comm"}}]},"finish_reason":null}]}

data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"and\\": \\"pwd\\"}"}}]},"finish_reason":"tool_calls"}]}

data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5}}

data: [DONE]
"""
o = P.OpenAIProvider("gpt-5.5", "k", config=P.ModelConfig(effort="xhigh", max_tokens=300, api="chat"))
deltas = []
r = o.complete("sys", NEUTRAL, tools=agent.TOOLS, on_delta=deltas.append)
b = CAPTURED["body"]
if CAPTURED["url"] != "https://api.openai.com/v1/chat/completions" or \
        CAPTURED["headers"]["Authorization"] != "Bearer k":
    fail("openai url/auth")
if b["messages"][0]["role"] != "system" or b["messages"][2]["tool_calls"][0]["type"] != "function" or \
        b["messages"][4]["tool_call_id"] != "c2":
    fail(f"openai message translation: {b['messages']}")
if b["tools"][0]["function"]["name"] != "list_dir" or b["stream_options"] != {"include_usage": True}:
    fail("openai tools/stream options")
if b["reasoning_effort"] != "high" or b["max_completion_tokens"] != 300 or "max_tokens" in b:
    fail(f"openai effort/max mapping: {b}")
if deltas != ["He", "y"] or r.text != "Hey" or r.stop != "tool_calls" or \
        r.tool_calls[0]["input"] != {"command": "pwd"} or r.tool_calls[0]["id"] != "call_9" or \
        r.usage != {"in": 10, "out": 5}:
    fail(f"openai stream parse: {deltas} {r.text!r} {r.tool_calls} {r.usage}")
CAPTURED["stream"] = b"""data: {"choices":[{"delta":{"content":"x"},"finish_reason":"length"}]}

data: [DONE]
"""
if o.complete("sys", NEUTRAL, tools=agent.TOOLS).stop != "max_tokens":
    fail("chat finish_reason length not mapped to max_tokens")
ok("openai: api=chat keeps chat completions — reasoning_effort, max_completion_tokens, length→max_tokens")

# openai-compatible: no key needed, max_tokens, no reasoning_effort, custom base
CAPTURED.clear()
CAPTURED["stream"] = b"data: [DONE]\n"
c = P.OpenAIProvider("llama3", "", base_url="http://127.0.0.1:11434/v1", name="openai-compatible",
                     config=P.ModelConfig(effort="high", max_tokens=100))
c.complete("sys", NEUTRAL, tools=agent.TOOLS)
b = CAPTURED["body"]
if CAPTURED["url"] != "http://127.0.0.1:11434/v1/chat/completions" or "Authorization" in CAPTURED["headers"]:
    fail("openai-compatible routing/auth")
if b.get("max_tokens") != 100 or "reasoning_effort" in b or "max_completion_tokens" in b:
    fail(f"openai-compatible knob mapping: {b}")
ok("openai-compatible: keyless, custom base URL, max_tokens, no OpenAI-only params")

# azure: deployment URL + api-key header
CAPTURED.clear()
CAPTURED["stream"] = b"data: [DONE]\n"
az = P.AzureOpenAIProvider("my-deploy", "k", base_url="https://res.openai.azure.com",
                           api_version="2024-10-21")
az.complete("sys", NEUTRAL)
if CAPTURED["url"] != "https://res.openai.azure.com/openai/deployments/my-deploy/chat/completions?api-version=2024-10-21" \
        or CAPTURED["headers"].get("api-key") != "k" or "Authorization" in CAPTURED["headers"]:
    fail(f"azure routing: {CAPTURED['url']} {CAPTURED['headers']}")
try:
    P.AzureOpenAIProvider("d", "k", base_url="")
    fail("azure without a base URL accepted")
except P.ProviderError:
    pass
ok("azure: deployment path, api-version, api-key header")

# ------------------------------------------------------------ gemini
CAPTURED.clear()
CAPTURED["stream"] = b"""data: {"candidates":[{"content":{"parts":[{"text":"Sure"}]}}]}

data: {"candidates":[{"content":{"parts":[{"functionCall":{"name":"read_file","args":{"path":"a"}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":7,"candidatesTokenCount":3}}

"""
gm = P.GeminiProvider("gemini-2.5-pro", "k", config=P.ModelConfig(max_tokens=64, temperature=0.5))
deltas = []
r = gm.complete("sys", NEUTRAL, tools=agent.TOOLS, on_delta=deltas.append)
b = CAPTURED["body"]
if not CAPTURED["url"].endswith("/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse") or \
        CAPTURED["headers"].get("x-goog-api-key") != "k":
    fail(f"gemini routing: {CAPTURED['url']}")
if b["system_instruction"]["parts"][0]["text"] != "sys" or b["contents"][0]["role"] != "user" or \
        b["contents"][1]["role"] != "model" or "functionCall" not in b["contents"][1]["parts"][1] or \
        b["contents"][2]["parts"][0]["functionResponse"]["name"] != "shell" or \
        len(b["contents"][2]["parts"]) != 2:
    fail(f"gemini contents: {json.dumps(b['contents'])[:400]}")
decl = b["tools"][0]["functionDeclarations"][0]
if decl["name"] != "list_dir" or "default" in json.dumps(decl["parameters"]):
    fail(f"gemini schema cleanup: {decl}")
if b["generationConfig"] != {"maxOutputTokens": 64, "temperature": 0.5}:
    fail(f"gemini generationConfig: {b['generationConfig']}")
if deltas != ["Sure"] or r.tool_calls[0]["name"] != "read_file" or r.stop != "end_turn" or \
        r.usage != {"in": 7, "out": 3}:
    fail(f"gemini parse: {deltas} {r.tool_calls} {r.stop} {r.usage}")
ok("gemini: system_instruction, contents roles, function declarations, streaming parse")

# ------------------------------------------------------------ model listing
P._get = lambda url, headers, timeout=60: (CAPTURED.update(url=url) or {
    "data": [{"id": "claude-opus-5", "display_name": "Claude Opus 5",
              "max_input_tokens": 1000000, "max_tokens": 128000}],
    "models": [{"name": "models/gemini-2.5-pro", "displayName": "G",
                "supportedGenerationMethods": ["generateContent"], "inputTokenLimit": 1048576},
               {"name": "models/embedding-001", "supportedGenerationMethods": ["embedContent"]}]})
rows = a.models()
if rows != [{"id": "claude-opus-5", "name": "Claude Opus 5", "context": 1000000, "max_output": 128000}] \
        or not CAPTURED["url"].startswith("https://api.anthropic.com/v1/models"):
    fail(f"anthropic models: {rows}")
rows = gm.models()
if [m["id"] for m in rows] != ["gemini-2.5-pro"]:
    fail(f"gemini models filter: {rows}")
rows = az.models()
if not CAPTURED["url"].endswith("/openai/models?api-version=2024-10-21"):
    fail("azure models url")
ok("model listing per provider, non-chat Gemini models filtered out")

# ------------------------------------------------------------ factory + keys
os.environ.pop("ANTHROPIC_API_KEY", None)
try:
    P.make("anthropic")
    fail("anthropic without a key accepted")
except P.ProviderError as e:
    if "ANTHROPIC_API_KEY" not in str(e):
        fail(f"key error text: {e}")
p = P.make("openai-compatible", model="llama3", base_url="http://x:1/v1")
if p.name != "openai-compatible" or p.key != "":
    fail("openai-compatible needs no key")
try:
    P.make("openai-compatible")
    fail("openai-compatible without a model accepted")
except P.ProviderError:
    pass
p = P.make("anthropic", key_loader=lambda prov: "stored-key")
if p.key != "stored-key" or p.model != "claude-opus-5":
    fail("stored key loader / default model")
os.environ["GEMINI_API_KEY"] = "env-key"
p = P.make("gemini", config={"effort": "low", "temperature": "", "stop": "a, b"})
if p.key != "env-key" or p.config.effort != "low" or p.config.temperature is not None or \
        p.config.stop != ["a", "b"]:
    fail(f"env key / config from dict: {p.config.to_dict()}")
try:
    P.make("nope")
    fail("unknown provider accepted")
except P.ProviderError:
    pass
# the agent-level wrapper turns provider errors into engine errors
try:
    agent.make_provider("anthropic")
    fail("agent.make_provider did not surface the missing key")
except Exception as e:
    if e.__class__.__name__ != "OverlordError":
        fail(f"wrong error class: {e.__class__.__name__}")
ok("factory: env key > stored key, keyless providers, required models, config from dict")

# scripted provider streams its text in halves
sp = P.ScriptedProvider([{"text": "abcdef"}])
deltas = []
r = sp.complete("s", [], on_delta=deltas.append)
if deltas != ["abc", "def"] or r.text != "abcdef":
    fail(f"scripted deltas: {deltas}")
ok("scripted provider exercises the streaming path")

print("PASS: providers")
