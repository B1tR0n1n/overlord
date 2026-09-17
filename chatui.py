#!/usr/bin/env python3
"""OVERLORD workspace — the friendly face of the agent hypervisor.

A chat window, like the assistants people already know, with one difference
that is the whole point: the agent's hands are jailed inside a transaction,
and nothing it does touches your files until you press Commit.

    overlord ui            # http://127.0.0.1:7777  — this workspace at /
                           #                          the console at /console

One conversation is one transaction. The first message opens a sandboxed,
offline copy of a folder and sets the agent to work; every later message
resumes it on the same copy; the panel on the right shows the running diff.
Commit replays it onto the real folder; Discard throws the copy away and the
folder is byte-identical. Conversations are listed on the left and selectable;
Settings holds the model, the API key, the folder, and the sandbox grants.

This module is the workspace: the runtime that runs a model in-process (so no
daemon is needed — `overlord ui` is the whole product), the settings store,
and the page. Security (loopback bind, origin guard, nonce CSP) lives in ui.py
and is shared; the console and every engine primitive it drives are unchanged.
"""

import json
import os
import threading
import time

import overlord as core
import agent as agent_mod
import providers as prov
import mcp as mcp_mod
import memory as memory_mod
import auth
import cost as cost_mod
import skills as skills_mod
import notify as notify_mod

LAUNCH_CWD = os.getcwd()
SETTINGS_FILE = os.path.join(core.OVERLORD_HOME, "ui.json")
DEFAULT_SETTINGS = {"provider": "anthropic", "model": "", "jail": True,
                    "net": "none", "net_allow": [], "max_turns": 40, "workdir": "",
                    # the second model that countersigns: blank provider = the agent's
                    # provider, in which case the model must differ from the agent's
                    "review_provider": "", "review_model": "",
                    # per-provider endpoint + model, kept when you switch providers
                    "providers": {},
                    # generation knobs; blank means "do not send"
                    "gen": {"max_tokens": 16000, "temperature": "", "top_p": "", "stop": "",
                            "effort": "", "thinking": "", "system_extra": "",
                            "stream": True, "fallbacks": True, "context_limit": "", "api": ""}}
GEN_KEYS = ("max_tokens", "temperature", "top_p", "stop", "effort", "thinking",
            "system_extra", "stream", "fallbacks", "context_limit", "api")
PROVIDER_KEYS = ("model", "base_url", "headers", "azure_api_version")
GLYPH = {"added": "+", "modified": "~", "deleted": "−", "replaced-dir": "±"}
MAX_TAIL = 1200                   # chars of a tool's output shown in the stream


def _esc(s):
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


# ---------------------------------------------------------------- settings


def _settings_file():
    """Each account has its own settings once accounts exist."""
    return auth.user_path("ui.json", SETTINGS_FILE)


def load_settings():
    s = json.loads(json.dumps(DEFAULT_SETTINGS))
    try:
        with open(_settings_file()) as f:
            saved = json.load(f)
        for k, v in saved.items():
            if k == "gen" and isinstance(v, dict):
                s["gen"].update({gk: gv for gk, gv in v.items() if gk in GEN_KEYS})
            elif k == "providers" and isinstance(v, dict):
                s["providers"] = {p: {pk: pv for pk, pv in (o or {}).items() if pk in PROVIDER_KEYS}
                                  for p, o in v.items() if isinstance(o, dict)}
            elif k in DEFAULT_SETTINGS:
                s[k] = v
    except (OSError, ValueError):
        pass
    if not s.get("workdir"):
        s["workdir"] = LAUNCH_CWD
    return s


def provider_opts(s, provider=None):
    """Endpoint + model for a provider: the saved profile, else defaults."""
    p = provider or s["provider"]
    o = dict(s.get("providers", {}).get(p) or {})
    o.setdefault("model", s.get("model") or "")
    o.setdefault("base_url", "")
    o.setdefault("headers", {})
    o.setdefault("azure_api_version", "")
    return o


def build_provider(s, provider=None, model=None, script_env="OVERLORD_AGENT_SCRIPT"):
    """The model the workspace talks to, from settings (or an override)."""
    p = provider or s["provider"]
    o = provider_opts(s, p)
    return agent_mod.make_provider(
        p, model or o.get("model") or None,
        base_url=o.get("base_url") or None, headers=o.get("headers") or None,
        config=prov.ModelConfig.from_dict(s.get("gen")),
        azure_api_version=o.get("azure_api_version") or None, script_env=script_env)


def build_review_provider(s, provider=None, model=None):
    """The second model, from Settings → Countersignature (or an override).
    It must not be the agent's own model: a countersignature by the same
    mind is a signature, not a second one."""
    import review as review_mod
    p = provider or s.get("review_provider") or s["provider"]
    m = model or s.get("review_model") or None
    if p == "scripted":
        return agent_mod.make_provider("scripted", m, script_env=review_mod.SCRIPT_ENV)
    agent_model = provider_opts(s, s["provider"]).get("model") or prov.DEFAULT_MODELS.get(s["provider"], "")
    if not m:
        m = prov.DEFAULT_MODELS.get(p, "")
    if p == s["provider"] and m == agent_model:
        raise core.OverlordError("error: the second model is the agent's own model — choose a different "
                                 "model or provider under Settings → Countersignature")
    return build_provider(s, p, m, script_env=review_mod.SCRIPT_ENV)


def save_settings(incoming):
    """Persist the workspace settings. An API key (if present) is handed to
    the engine's 0600 key store and never written here or echoed back."""
    s = load_settings()
    key = incoming.get("key")
    provider = incoming.get("provider") or s["provider"]
    for k in DEFAULT_SETTINGS:
        if k in ("gen", "providers"):
            continue
        if k in incoming and incoming[k] is not None:
            s[k] = incoming[k]
    s["provider"] = provider
    if s.get("provider") not in prov.PROVIDERS + ["scripted"]:
        raise core.OverlordError(f"error: provider must be one of {', '.join(prov.PROVIDERS)}")
    # a provider profile: model, endpoint, headers (JSON object), azure version
    po = incoming.get("provider_opts")
    if isinstance(po, dict):
        cur = dict(s["providers"].get(provider) or {})
        for k in PROVIDER_KEYS:
            if k in po and po[k] is not None:
                cur[k] = po[k]
        hdrs = cur.get("headers")
        if isinstance(hdrs, str):
            try:
                hdrs = json.loads(hdrs) if hdrs.strip() else {}
            except ValueError:
                raise core.OverlordError("error: headers must be a JSON object")
        if hdrs is not None and not isinstance(hdrs, dict):
            raise core.OverlordError("error: headers must be a JSON object")
        cur["headers"] = {str(k): str(v) for k, v in (hdrs or {}).items()}
        for k in ("model", "base_url", "azure_api_version"):
            cur[k] = str(cur.get(k) or "").strip()
        if cur["base_url"] and not cur["base_url"].startswith(("http://", "https://")):
            raise core.OverlordError("error: base URL must start with http:// or https://")
        s["providers"][provider] = cur
    gen = incoming.get("gen")
    if isinstance(gen, dict):
        g = dict(s["gen"])
        for k in GEN_KEYS:
            if k in gen:
                g[k] = gen[k]
        for k in ("temperature", "top_p"):
            v = g.get(k)
            if v in (None, ""):
                g[k] = ""
            else:
                try:
                    g[k] = float(v)
                except (TypeError, ValueError):
                    raise core.OverlordError(f"error: {k} must be a number or blank")
        try:
            g["max_tokens"] = int(g.get("max_tokens") or 16000)
        except (TypeError, ValueError):
            raise core.OverlordError("error: max_tokens must be a whole number")
        if g.get("effort") not in prov.EFFORTS:
            raise core.OverlordError("error: effort must be low, medium, high, xhigh, max or blank")
        if g.get("thinking") not in ("", None, "summarized", "off"):
            raise core.OverlordError("error: thinking must be summarized, off or blank")
        g["thinking"] = g.get("thinking") or ""
        if g.get("api") not in ("", None, "responses", "chat"):
            raise core.OverlordError("error: api must be responses, chat or blank")
        g["api"] = g.get("api") or ""
        g["stop"] = str(g.get("stop") or "")
        g["system_extra"] = str(g.get("system_extra") or "")
        g["stream"] = bool(g.get("stream", True))
        g["fallbacks"] = bool(g.get("fallbacks", True))
        cl = g.get("context_limit")
        if cl in (None, ""):
            g["context_limit"] = ""
        else:
            try:
                g["context_limit"] = max(8000, int(cl))
            except (TypeError, ValueError):
                raise core.OverlordError("error: context window must be a whole number of tokens or blank")
        s["gen"] = g
    if s.get("net") not in ("none", "host", "proxy"):
        raise core.OverlordError("error: net must be none, host or proxy")
    na = s.get("net_allow")
    if na is not None:
        if isinstance(na, str):
            na = [h.strip() for h in na.replace(",", " ").split() if h.strip()]
        if not isinstance(na, list) or any(not isinstance(h, str) for h in na):
            raise core.OverlordError("error: net_allow must be a list of hosts")
        s["net_allow"] = na
    rp = str(s.get("review_provider") or "")
    if rp and rp not in prov.PROVIDERS + ["scripted"]:
        raise core.OverlordError("error: the second model's provider must be one of "
                                 + ", ".join(prov.PROVIDERS) + " (or blank for the agent's)")
    s["review_provider"] = rp
    s["review_model"] = str(s.get("review_model") or "").strip()
    try:
        s["max_turns"] = max(1, min(200, int(s.get("max_turns") or 40)))
    except (TypeError, ValueError):
        s["max_turns"] = 40
    s["jail"] = bool(s.get("jail"))
    wd = s.get("workdir") or LAUNCH_CWD
    if not os.path.isdir(os.path.expanduser(wd)):
        raise core.OverlordError(f"error: not a folder: {wd}")
    s["workdir"] = os.path.realpath(os.path.expanduser(wd))
    path = _settings_file()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(s, f, indent=2)
    if key:
        if provider not in prov.PROVIDERS:
            raise core.OverlordError("error: a key can only be set for a real provider")
        agent_mod.save_key(provider, key.strip())
    rkey = incoming.get("review_key")
    if rkey:
        rprov = s.get("review_provider") or provider
        if rprov not in prov.PROVIDERS:
            raise core.OverlordError("error: the reviewer's key can only be set for a real provider")
        agent_mod.save_key(rprov, rkey.strip())
    return s


def _has_key(provider):
    try:
        agent_mod.load_key(provider)
        return True
    except (core.OverlordError, SystemExit):
        return False


def settings_public():
    s = load_settings()
    backend = core.detect_backend()
    p = s["provider"]
    if p == "scripted":
        ready = bool(os.environ.get("OVERLORD_AGENT_SCRIPT"))
    else:
        ready = _has_key(p) or not prov.NEEDS_KEY.get(p, True)
    return {**s,
            "backend": backend or "none",
            "jail_available": backend == "kernel",
            "keys": {q: _has_key(q) for q in prov.PROVIDERS},
            "provider_ready": ready,
            "provider_opts": provider_opts(s),
            "default_model": prov.DEFAULT_MODELS.get(p, ""),
            "models": prov.DEFAULT_MODELS,
            "providers_available": [
                {"id": q, "needs_key": prov.NEEDS_KEY[q], "key_env": prov.KEY_ENV[q],
                 "default_base_url": prov.DEFAULT_BASE_URLS.get(q, ""),
                 "default_model": prov.DEFAULT_MODELS.get(q, "")} for q in prov.PROVIDERS],
            "efforts": [e for e in prov.EFFORTS if e]}


_MODEL_CACHE = {}


def models_for(provider=None, refresh=False):
    """Live model catalog for a provider, cached five minutes per endpoint."""
    s = load_settings()
    p = provider or s["provider"]
    o = provider_opts(s, p)
    key = (p, o.get("base_url") or "")
    hit = _MODEL_CACHE.get(key)
    if hit and not refresh and time.time() - hit[0] < 300:
        return {"provider": p, "models": hit[1], "cached": True}
    rows = agent_mod.list_models(p, base_url=o.get("base_url") or None,
                                 headers=o.get("headers") or None,
                                 azure_api_version=o.get("azure_api_version") or None)
    _MODEL_CACHE[key] = (time.time(), rows)
    return {"provider": p, "models": rows, "cached": False}


# ---------------------------------------------------------------- runtime
#
# One worker thread runs the model loop for a conversation while it "thinks".
# Events are appended to an in-memory buffer the browser polls; the durable
# copy is transcript.jsonl on disk (written by run_agent), so a page reload —
# or a restart of `overlord ui` — reconstructs the whole conversation. The
# buffer only carries the live tail.

_RUNS = {}
_REG_LOCK = threading.Lock()


def _conv(sid):
    with _REG_LOCK:
        c = _RUNS.get(sid)
        if c is None:
            c = _RUNS[sid] = {"events": [], "running": False, "error": None,
                              "cancel": threading.Event(), "lock": threading.Lock(),
                              "pending": None}
        return c


APPROVAL_WAIT = 600     # seconds a run waits for a person to decide


def _approver(sid):
    """The workspace's approval gate: publish the request as an event, block
    the worker until the browser answers (or the wait expires — a no answer
    is a no), and record what happened."""
    c = _conv(sid)

    def approve(req):
        gate = {"id": req["id"], "decided": threading.Event(), "allow": False, "who": None}
        with c["lock"]:
            c["pending"] = gate
        _emit(sid, {"type": "approval", "id": req["id"], "server": req["server"],
                    "tool": req["tool"], "input": req["input"], "turn": req.get("turn"),
                    "fingerprint": req.get("fingerprint")})
        gate["decided"].wait(APPROVAL_WAIT)
        with c["lock"]:
            c["pending"] = None
        allowed = bool(gate["allow"]) if gate["decided"].is_set() else False
        if allowed:
            req["approved_by"] = gate.get("who") or "workspace"
        return allowed
    return approve


def decide(sid, approval_id, allow, approver=None):
    c = _conv(sid)
    with c["lock"]:
        gate = c["pending"]
        if not gate or gate["id"] != approval_id:
            raise core.OverlordError("error: nothing is waiting for that approval")
        gate["allow"] = bool(allow)
        gate["who"] = approver
        gate["decided"].set()
    _emit(sid, {"type": "approval_decision", "id": approval_id,
                "decision": "approved" if allow else "denied",
                "approved_by": approver if allow else None})
    return {"ok": True}


def _emit(sid, ev):
    c = _conv(sid)
    with c["lock"]:
        c["events"].append(ev)


def _grants_for(settings, backend):
    """The sandbox the agent's hands run in. Jail + offline need the kernel
    backend; on fuse they are refused rather than faked, so the workspace
    drops them and says so."""
    if backend == "kernel":
        g = {"net": settings.get("net", "none"), "jail": bool(settings.get("jail", True)),
             "timeout": None, "merge_base": False}
        if g["net"] == "proxy" and settings.get("net_allow"):
            g["net_allow"] = list(settings["net_allow"])
        return g, None
    note = ("Cooperative backend (fuse-overlayfs): the agent works in an overlay, "
            "but the jail and offline grants need the kernel backend, so they are off. "
            "Writes outside the folder are not contained.")
    return {"net": "host", "jail": False, "timeout": None, "merge_base": False}, note


def _record_user(sid, text):
    """The human's message, written where both the reload path and the model's
    own resume history can see it (transcript.jsonl carries it as an inert
    'user' line; run_agent's resume rebuild ignores unknown types)."""
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "type": "user", "text": text}
    with open(core.session_file(sid, "transcript.jsonl"), "a") as f:
        f.write(json.dumps(rec) + "\n")
    _emit(sid, rec)


def _map_event(ev):
    """run_agent's transcript event -> a structured chat event. Text is never
    HTML; the browser renders it with textContent."""
    t = ev.get("type")
    if t == "assistant_delta":
        return {"type": "assistant_delta", "text": ev.get("text", "")}
    if t == "assistant":
        return {"type": "assistant", "text": ev.get("text", "")}
    if t == "tool_call":
        return {"type": "tool_call", "id": ev.get("id"), "tool": ev.get("tool"),
                "external": bool(ev.get("external")), "connector": ev.get("connector"),
                "summary": agent_mod._summarize(
                    {"name": ev.get("tool"), "input": ev.get("input") or {}})}
    if t == "tool_result":
        out = ev.get("output", "") or ""
        if len(out) > MAX_TAIL:
            out = out[-MAX_TAIL:]
        return {"type": "tool_result", "id": ev.get("id"), "tool": ev.get("tool"),
                "exit": ev.get("exit_code"), "touched": ev.get("touched") or [],
                "output": out}
    if t == "done":
        return {"type": "done", "reason": ev.get("reason"), "turn": ev.get("turn"),
                "usage": ev.get("usage")}
    if t == "connectors":
        return {"type": "note", "text": "Connectors: " + ", ".join(ev.get("servers") or [])
                + f" ({ev.get('approval')} mode, {len(ev.get('tools') or [])} tools)"}
    if t == "memory_suggestion":
        return {"type": "memory_suggestion", "id": ev.get("id"), "text": ev.get("text", ""),
                "accepted": False}
    if t == "skills":
        return {"type": "note", "text": "Skills offered: " + ", ".join(
            s["name"] for s in ev.get("offered") or [])}
    if t == "compaction":
        return {"type": "note", "text": f"Context compacted at step {ev.get('turn')}: the agent wrote a "
                f"handover note and kept its last {ev.get('kept')} messages "
                f"({ev.get('before_tokens')} tokens in the previous call)."}
    if t == "skill_use":
        return {"type": "note", "text": f"Loaded skill {ev.get('name')} ({ev.get('source')})"
                + (f" — {ev.get('file')}" if ev.get("file") not in (None, "SKILL.md") else "")}
    if t == "approval_decision":
        return {"type": "approval_decision", "id": ev.get("id"), "decision": ev.get("decision"),
                "server": ev.get("server"), "tool": ev.get("tool")}
    if t == "error":
        return {"type": "error", "text": ev.get("text", "")}
    return None


def _run(sid, live, provider, message, first, max_turns, connectors=None):
    c = _conv(sid)
    c["running"], c["error"] = True, None
    c["cancel"].clear()

    def emit(ev):
        mapped = _map_event(ev)
        if mapped:
            _emit(sid, mapped)

    try:
        task = message if first else (live.meta.get("task") or message)
        agent_mod.run_agent(live, provider, task, max_turns=max_turns, emit=emit,
                            should_stop=c["cancel"].is_set,
                            resume=not first, note=None if first else message,
                            connectors=connectors, approve=_approver(sid))
    except (core.OverlordError, SystemExit) as e:
        c["error"] = str(e)
        _emit(sid, {"type": "error", "text": str(e)})
    except Exception as e:                       # a worker must never take the server down
        c["error"] = f"{type(e).__name__}: {e}"
        _emit(sid, {"type": "error", "text": c["error"]})
    finally:
        try:
            live.close()
        except Exception:
            pass
        c["running"] = False
        _emit(sid, {"type": "idle"})


def start_conversation(message, target=None, provider=None, model=None, connectors=None):
    """Open a fresh transaction and set the agent to work. Returns its sid.
    connectors: MCP server names to grant this conversation (host-side tools)."""
    auth.require("use")
    s = load_settings()
    connectors = [str(c) for c in (connectors or []) if c]
    if connectors:
        mcp_mod.Registry(connectors)        # validates the names before anything opens
    target = os.path.realpath(os.path.expanduser(target or s["workdir"]))
    if not os.path.isdir(target):
        raise core.OverlordError(f"error: not a folder: {target}")
    if not (message or "").strip():
        raise core.OverlordError("error: a message is needed to start")
    backend = core.detect_backend()
    if backend is None:
        raise core.OverlordError(
            "error: no sandbox backend available — run `overlord doctor`")
    if provider and provider not in prov.PROVIDERS + ["scripted"]:
        raise core.OverlordError(f"error: unknown provider: {provider}")
    provider = build_provider(s, provider or None, model or None)
    grants, note = _grants_for(s, backend)
    if connectors:
        grants["connectors"] = connectors
    # "/audit [focus]" is the containment-audit preset (`overlord agent --audit`):
    # the same authorized framing, and only ever against a real jail
    audit = message.strip().split(None, 1)[0].lower() == "/audit"
    task = message
    if audit:
        if not grants.get("jail"):
            raise core.OverlordError("error: /audit needs the jail (Settings → Jail + offline, kernel "
                                     "backend); there is nothing to audit without it")
        task = agent_mod.audit_task(message.strip()[len("/audit"):])
    pend = core.pending_sessions_for(target)
    if pend:
        raise core.OverlordError(
            "error: this folder already has an open conversation. Commit or discard it "
            "first, or pick another folder in Settings.")
    live = core.open_session(target, backend, grants, capture=True,
                             agent=f"{provider.name}:{provider.model}", owner=auth.current_user())
    sid = live.sid
    _conv(sid)
    if audit:
        live.meta["audit"] = True
        core.save_meta(sid, live.meta)
        _emit(sid, {"type": "note", "text": "Containment audit: the agent is asked to check every "
                    "claim about its jail against reality and write each gap as a failing red-team check."})
    if note:
        _emit(sid, {"type": "note", "text": note})
    _record_user(sid, message)
    threading.Thread(target=_run, args=(sid, live, provider, task, True,
                                        int(s["max_turns"]), connectors or None),
                     daemon=True).start()
    return sid


def send_message(sid, message):
    """Resume a conversation with another message on the same transaction."""
    c = _conv(sid)
    if c["running"]:
        raise core.OverlordError("error: the agent is still working — wait for it to finish")
    if not (message or "").strip():
        raise core.OverlordError("error: empty message")
    meta = core.load_meta(sid)
    auth.require("act", meta)
    if meta.get("status") != "pending":
        raise core.OverlordError(
            "error: this conversation is closed (its changes were committed or discarded). "
            "Start a new conversation.")
    provider = agent_mod.provider_for(meta)
    live = core.reopen_session(sid, capture=True)
    _record_user(sid, message)
    threading.Thread(target=_run, args=(sid, live, provider, message, False,
                                        int(load_settings()["max_turns"])),
                     daemon=True).start()
    return sid


def cancel(sid):
    auth.require("act", core.load_meta(sid))
    _conv(sid)["cancel"].set()
    return {"cancelling": True}


def events_since(sid, frm):
    c = _conv(sid)
    with c["lock"]:
        tail = c["events"][frm:]
        nxt = len(c["events"])
        running = c["running"]
    return {"events": tail, "next": nxt, "running": running,
            "inspector": render_inspector(sid)}


# ---------------------------------------------------------------- reading


def messages_from_transcript(sid):
    """Rebuild the whole conversation from disk: human messages, what the model
    said, and each tool call with its result. The internal 'task'/'resume'
    lines are the model's own scaffolding and are not shown."""
    path = core.session_file(sid, "transcript.jsonl")
    msgs, calls = [], {}
    if not os.path.isfile(path):
        return msgs
    with open(path) as f:
        for line in f:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            t = ev.get("type")
            if t == "user":
                msgs.append({"type": "user", "text": ev.get("text", "")})
            elif t == "assistant":
                msgs.append({"type": "assistant", "text": ev.get("text", "")})
            elif t == "tool_call":
                calls[ev.get("id")] = agent_mod._summarize(
                    {"name": ev.get("tool"), "input": ev.get("input") or {}})
                msgs.append({"type": "tool_call", "id": ev.get("id"),
                             "tool": ev.get("tool"), "summary": calls.get(ev.get("id"), ""),
                             "external": bool(ev.get("external")), "connector": ev.get("connector")})
            elif t == "approval_decision":
                msgs.append({"type": "approval_decision", "id": ev.get("id"),
                             "decision": ev.get("decision"), "server": ev.get("server"),
                             "tool": ev.get("tool")})
            elif t == "connectors":
                msgs.append({"type": "note", "text": "Connectors: " + ", ".join(ev.get("servers") or [])
                             + f" ({ev.get('approval')} mode)"})
            elif t == "memory_suggestion":
                msgs.append({"type": "memory_suggestion", "id": ev.get("id"),
                             "text": ev.get("text", ""), "accepted": False})
            elif t == "skills":
                msgs.append({"type": "note", "text": "Skills offered: " + ", ".join(
                    s["name"] for s in ev.get("offered") or [])})
            elif t == "compaction":
                msgs.append({"type": "note", "text": f"Context compacted at step {ev.get('turn')}: the agent "
                             f"wrote a handover note and kept its last {ev.get('kept')} messages."})
            elif t == "skill_use":
                msgs.append({"type": "note", "text": f"Loaded skill {ev.get('name')} ({ev.get('source')})"
                             + (f" — {ev.get('file')}" if ev.get("file") not in (None, "SKILL.md") else "")})
            elif t == "memory_accepted":
                for m in msgs:
                    if m.get("type") == "memory_suggestion" and m.get("id") == ev.get("id"):
                        m["accepted"] = True
            elif t == "tool_result":
                out = ev.get("output", "") or ""
                if len(out) > MAX_TAIL:
                    out = out[-MAX_TAIL:]
                msgs.append({"type": "tool_result", "id": ev.get("id"),
                             "tool": ev.get("tool"), "exit": ev.get("exit_code"),
                             "touched": ev.get("touched") or [], "output": out})
            elif t == "rewind":
                msgs.append({"type": "note", "text": f"Rewound to savepoint @{ev.get('to')}."})
            elif t == "error":
                msgs.append({"type": "error", "text": ev.get("text", "")})
            elif t == "done" and ev.get("reason") in ("max_turns", "cancelled"):
                reason = "reached its step limit" if ev["reason"] == "max_turns" else "was stopped"
                msgs.append({"type": "note", "text": f"The agent {reason}."})
    return msgs


def _title(meta):
    return (meta.get("task") or " ".join(meta.get("cmd") or []) or "conversation")[:80]


def conversations():
    """Every chat (agent session), newest first, for the left rail."""
    out = []
    for sid in core.list_sessions():
        m = core.load_meta(sid)
        if not m.get("agent") or not auth.visible(m):
            continue
        out.append({"sid": sid, "title": _title(m), "status": m.get("status"), "owner": m.get("owner"),
                    "target": m.get("target"), "updated": m.get("finished") or m.get("started"),
                    "thinking": _conv(sid)["running"]})
    out.sort(key=lambda c: c["updated"] or "", reverse=True)
    return out


def conversation(sid):
    core.validate_session_id(sid)
    meta = core.load_meta(sid)
    auth.require("read", meta)
    c = _conv(sid)
    with c["lock"]:
        event_count = len(c["events"])
    return {"meta": {"id": meta["id"], "title": _title(meta), "status": meta.get("status"),
                     "target": meta.get("target"), "agent": meta.get("agent"),
                     "grants": meta.get("grants"), "owner": meta.get("owner"),
                     "may_act": auth.may("act", meta), "cost": cost_mod.summary(meta)},
            "messages": messages_from_transcript(sid),
            "running": c["running"], "event_count": event_count,
            "inspector": render_inspector(sid)}


# ---------------------------------------------------------------- inspector


def _grant_chips(g):
    out = []
    if g.get("jail"):
        out.append("sandboxed")
    out.append("offline" if g.get("net") == "none" else "online")
    if g.get("timeout"):
        out.append(f"{g['timeout']}s limit")
    return "".join(f'<span class="chip">{_esc(x)}</span>' for x in out)


def render_inspector(sid):
    """The right panel: the transaction as it stands — what would change, and
    the controls to accept or throw it away. Server-rendered and escaped."""
    try:
        m = core.load_meta(sid)
    except core.OverlordError:
        return '<div class="ins-empty">No conversation selected.</div>'
    live = os.path.isdir(core.session_file(sid, "upper"))
    h = ['<div class="ins-head"><div class="ins-k">Working folder</div>'
         f'<div class="ins-v">{_esc(m.get("target"))}</div>'
         f'<div class="chips">{_grant_chips(m.get("grants") or {})}</div></div>']

    # While the agent is mid-run the overlay is being written under us, so a
    # walk of it can race a file that appears and vanishes. The diff is also
    # still changing, so there is nothing stable to show: report progress and
    # compute the real manifest on the next poll, once the run has stopped.
    if _conv(sid)["running"]:
        h.append('<div class="ins-note mt16">The agent is working. '
                 'The changes it makes will appear here when it pauses.</div>')
        return "".join(h)
    try:
        return "".join(h) + _inspector_body(sid, m, live)
    except OSError:
        h.append('<div class="ins-note mt16">Reading the changes…</div>')
        return "".join(h)


def _ktok(n):
    return f"{n / 1000:.1f}k" if n >= 1000 else str(n)


def _inspector_body(sid, m, live):
    h = []

    if m.get("status") == "committed":
        h.append('<div class="ins-state ok">Committed to the folder.</div>')
    elif m.get("status") in ("rolled-back",) or (not live and m.get("status") != "pending"):
        h.append('<div class="ins-state">Discarded. The folder was left untouched.</div>')

    u = m.get("usage") or {}
    if u.get("in") or u.get("out"):
        usd = u.get("usd")
        h.append('<div class="ins-cost">'
                 f'{_esc(_ktok(u.get("in", 0)))} in &middot; {_esc(_ktok(u.get("out", 0)))} out'
                 + (f' &middot; ${usd:.4f}' if usd is not None else ' &middot; unpriced model')
                 + '</div>')
    changes = core.session_stack(sid, m)[0] if live else []
    h.append(f'<div class="ins-k mt18">Changes '
             f'<span class="count">{len(changes)}</span></div>')
    if changes:
        rows = "".join(
            f'<div class="chg"><span class="g g-{_esc(k)}">{GLYPH.get(k, "&middot;")}</span>'
            f'<span class="cp">{_esc(p)}</span></div>' for k, p in changes[:200])
        h.append(f'<div class="chg-list">{rows}</div>')
    else:
        h.append('<div class="ins-note">Nothing changed yet.</div>')

    if live:
        sps = core.session_savepoints(sid, m)
        wrote = [s for s in sps if s["paths"]]
        if wrote:
            h.append(f'<div class="ins-k mt16">Steps '
                     f'<span class="count">{len(wrote)}</span></div><div class="sp-mini">')
            for s in sps:
                if not s["paths"]:
                    continue
                c = s.get("cause") or {}
                label = (f'{_esc(c.get("tool"))}' if c else "step")
                h.append(f'<div class="spm"><span class="spn">@{s["n"]}</span>'
                         f'<span>{label} &middot; {len(s["paths"])} file(s)</span></div>')
            h.append('</div>')

    if live and m.get("status") == "pending":
        import review as review_mod
        rev, fresh = review_mod.review_state(sid, m)
        sig = ""
        if rev and fresh:
            v = {"approve": "approved", "reject": "rejected"}.get(rev.get("verdict"), "reviewed")
            cls = rev.get("verdict") if rev.get("verdict") in ("approve", "reject") else ""
            sig = (f'<div class="sig-line stamp-{cls}">Second model {v}'
                   + (f': {_esc(rev.get("reason"))}' if rev.get("reason") else "") + '</div>')
        elif rev:
            sig = '<div class="sig-line">Earlier review is stale — the diff changed.</div>'
        h.append('<div class="ins-actions">'
                 f'{sig}'
                 f'<button class="act act-commit" data-commit="{_esc(sid)}">Commit changes</button>'
                 f'<button class="act act-discard" data-discard="{_esc(sid)}">Discard</button>'
                 f'<button class="act act-review" data-review="{_esc(sid)}">Second-model check</button>'
                 f'<a class="act act-discard" href="/api/session/{_esc(sid)}/export" download>Export</a>'
                 '<div class="act-msg" id="actmsg"></div></div>')
    elif m.get("imported"):
        i = m["imported"]
        h.append(f'<div class="ins-note">Imported from {_esc(i.get("from"))} ({_esc(i.get("exported"))}); '
                 + ("signature verified" if i.get("verified") else "signature not verified") + '.</div>')
    if m.get("status") == "committed" or m.get("imported"):
        h.append(f'<div class="ins-actions"><a class="act act-discard" href="/api/session/{_esc(sid)}/export" '
                 'download>Export</a></div>')
    return "".join(h)


# ---------------------------------------------------------------- the page

CHAT_CSS = """
:root{
  --bg:#0a0908;--bg2:#0f0e0b;--bg3:#161410;--panel:#1a1814;
  --border:#2a2620;--border-lt:#3d362c;
  --text:#c8bda0;--dim:#7a7060;--bright:#ede5d0;
  --accent:#c9a227;--accent-dim:#8b7320;--glow:rgba(201,162,39,.12);
  --red:#a63d2f;--green:#4a7a45;--blue:#5a7a9a;
  --serif:Georgia,'Times New Roman',serif;
  --mono:'SF Mono',ui-monospace,Consolas,monospace;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--text);font-family:var(--mono);
  font-size:13px;line-height:1.55;overflow:hidden}
button{font-family:inherit;cursor:pointer}
.app{display:grid;grid-template-columns:250px 1fr 320px;height:100vh}
.app>*{min-height:0}
@media(max-width:900px){.app{grid-template-columns:1fr}
  .rail,.inspect{display:none}.app.show-rail .rail{display:flex;position:fixed;z-index:20;
    width:250px;height:100%}.app.show-ins .inspect{display:flex;position:fixed;right:0;z-index:20;
    width:320px;height:100%}}

/* left rail */
.rail{background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column}
.brand{padding:16px 16px 12px;border-bottom:1px solid var(--border)}
.brand .name{font-family:var(--mono);font-size:15px;letter-spacing:5px;color:var(--bright);font-weight:600}
.brand .sub{font-family:var(--serif);font-style:italic;font-size:12px;color:var(--dim);margin-top:2px}
.newbtn{margin:12px;padding:10px;background:transparent;border:1px solid var(--border-lt);
  color:var(--text);letter-spacing:2px;text-transform:uppercase;font-size:10px;transition:.2s}
.newbtn:hover{border-color:var(--accent);color:var(--accent)}
.convs{flex:1;min-height:0;overflow-y:auto;padding:4px 8px}
.conv{padding:10px 10px;border-radius:2px;cursor:pointer;border-left:2px solid transparent}
.conv:hover{background:var(--bg3)}
.conv.sel{background:var(--glow);border-left-color:var(--accent)}
.conv .t{color:var(--bright);font-family:var(--serif);font-size:14px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.conv .m{font-size:10px;color:var(--dim);margin-top:3px;display:flex;gap:8px;align-items:center}
.dot{width:6px;height:6px;border-radius:50%;display:inline-block}
.dot.pending{background:var(--accent)}.dot.committed{background:var(--green)}
.dot.thinking{background:var(--accent);animation:pulse 1s infinite}
@keyframes pulse{50%{opacity:.3}}
.meters{border-top:1px solid var(--border);padding:10px 12px;display:flex;flex-direction:column;gap:9px}
.meter .lbl{display:flex;justify-content:space-between;gap:8px;font-size:9px;letter-spacing:1.5px;text-transform:uppercase;color:var(--dim)}
.meter .val{color:var(--text);letter-spacing:0;text-transform:none;font-size:10px;white-space:nowrap}
.meter .track{height:5px;margin-top:4px;border-radius:3px;background:var(--glow);overflow:hidden}
.meter .fill{height:100%;border-radius:3px;background:var(--accent);transition:width .35s}
.meter.warn .fill{background:#b5702a}.meter.crit .fill{background:var(--red)}
.meter.warn .track{background:rgba(181,112,42,.18)}.meter.crit .track{background:rgba(166,61,47,.2)}
.meter .note{font-size:9px;color:var(--dim);margin-top:2px;letter-spacing:.5px}
.meter.crit .note,.meter.warn .note{color:var(--text)}
.railfoot{border-top:1px solid var(--border);padding:10px 12px;display:flex;flex-direction:column;align-items:flex-start;gap:6px}
.railnav{display:flex;flex-direction:column;align-items:flex-start;gap:8px}
.railnav .gear,.railnav .consolelink{display:block;text-align:left}
.railfoot .backend{white-space:nowrap}
.gear{background:none;border:0;padding:0;color:var(--dim);font-size:11px;letter-spacing:2px;text-transform:uppercase;cursor:pointer}
.gear:hover{color:var(--accent)}
.backend{font-size:9px;color:var(--dim);letter-spacing:1px}

/* center */
.chat{display:flex;flex-direction:column;min-width:0;background:var(--bg)}
.chat-head{padding:14px 22px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px}
.chat-head .h-t{font-family:var(--serif);font-size:17px;color:var(--bright);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.chat-head .h-s{margin-left:auto;font-size:10px;color:var(--dim);letter-spacing:2px;text-transform:uppercase}
.iconbtn{display:none;background:none;border:1px solid var(--border-lt);color:var(--dim);
  padding:5px 9px;font-size:11px}
@media(max-width:900px){.iconbtn{display:inline-block}}
.stream{flex:1;min-height:0;overflow-y:auto;padding:26px 22px 8px}
.msg{max-width:760px;margin:0 auto 20px}
.msg .who{font-size:9px;letter-spacing:3px;text-transform:uppercase;color:var(--dim);margin-bottom:6px}
.msg.user .bub{background:var(--bg3);border:1px solid var(--border);border-left:2px solid var(--accent);
  padding:12px 16px;white-space:pre-wrap;color:var(--bright)}
.msg.assistant .bub{font-family:var(--mono);font-size:12.5px;line-height:1.55;color:var(--text);
  background:var(--bg);border:1px solid var(--border);border-left:2px solid var(--green);
  padding:11px 14px;overflow-x:auto}
.msg.assistant .bub.live{white-space:pre-wrap}
.bub>*:first-child{margin-top:0}.bub>*:last-child{margin-bottom:0}
.bub p{margin:0 0 9px}
.bub strong{color:var(--bright);font-weight:600}
.bub em{color:var(--text);font-style:italic}
.bub code{background:var(--bg3);border:1px solid var(--border);border-radius:3px;
  padding:0 4px;font-size:11.5px;color:var(--accent)}
.bub pre{background:var(--bg3);border:1px solid var(--border);border-radius:4px;
  padding:9px 11px;overflow-x:auto;margin:0 0 9px;line-height:1.45}
.bub pre code{background:none;border:0;padding:0;color:var(--text);font-size:11.5px}
.bub ul,.bub ol{margin:0 0 9px;padding-left:20px}
.bub li{margin:2px 0}
.bub li::marker{color:var(--accent-dim)}
.bub h1,.bub h2,.bub h3{font-size:11px;color:var(--bright);margin:0 0 7px;
  letter-spacing:1.5px;text-transform:uppercase;font-weight:600}
.bub a{color:var(--blue);text-decoration:underline}
.tool{max-width:760px;margin:0 auto 10px;border:1px solid var(--border);background:var(--bg2)}
.tool .th{padding:8px 14px;font-size:11px;display:flex;gap:10px;align-items:center;cursor:pointer}
.tool .th .arrow{color:var(--accent-dim)}
.tool .th .tl{color:var(--bright)}.tool .th .sm{color:var(--dim);white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis;flex:1}
.tool .th .tag{font-size:9px;letter-spacing:1px;color:var(--dim)}
.tool .th .tag.bad{color:var(--red)}
.tool .body{display:none;border-top:1px solid var(--border);padding:10px 14px;
  font-size:11px;white-space:pre-wrap;color:var(--dim);max-height:280px;overflow:auto}
.tool.open .body{display:block}
.tool .touched{padding:6px 14px;border-top:1px solid var(--border);font-size:10px;color:var(--dim)}
.note{max-width:760px;margin:0 auto 16px;text-align:center;font-family:var(--serif);
  font-style:italic;font-size:13px;color:var(--dim)}
.note.err{color:var(--red);font-style:normal;font-family:var(--mono);font-size:12px}
.thinking{max-width:760px;margin:0 auto 20px;color:var(--dim);font-size:12px}
.thinking .d{animation:pulse 1.2s infinite}

/* welcome / empty */
.welcome{max-width:620px;margin:8vh auto 0;text-align:center;padding:0 20px}
.welcome h1{font-family:var(--serif);font-size:30px;color:var(--bright);font-weight:600;margin:0 0 10px}
.welcome p{color:var(--dim);font-size:14px;line-height:1.7;margin:0 auto 22px;max-width:52ch}
.folder-row{display:flex;gap:8px;max-width:560px;margin:0 auto 12px;text-align:left}
.folder-row label{font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--dim);
  align-self:center}
.folder-row input{flex:1;background:var(--bg2);border:1px solid var(--border);color:var(--text);
  font-family:var(--mono);font-size:12px;padding:8px 10px}

/* composer */
.composer{border-top:1px solid var(--border);padding:14px 22px 18px}
.composer .box{max-width:760px;margin:0 auto;border:1px solid var(--border-lt);background:var(--bg2);
  display:flex;align-items:flex-end;gap:8px;padding:8px 8px 8px 14px}
.composer.busy .box{opacity:.6}
.composer textarea{flex:1;background:none;border:0;color:var(--bright);font-family:var(--mono);
  font-size:14px;resize:none;max-height:180px;padding:6px 0;outline:none}
.send{background:var(--accent);color:var(--bg);border:0;padding:9px 18px;font-size:11px;
  letter-spacing:2px;text-transform:uppercase;font-weight:600}
.send:disabled{background:var(--border-lt);color:var(--dim)}
.stopbtn{background:transparent;border:1px solid var(--border-lt);color:var(--dim);
  padding:9px 14px;font-size:11px;letter-spacing:1px;text-transform:uppercase}
.hint{max-width:760px;margin:8px auto 0;font-size:10px;color:var(--dim);text-align:center}
.hint b{color:var(--text);font-weight:400}

/* inspector */
.inspect{background:var(--bg2);border-left:1px solid var(--border);display:flex;flex-direction:column}
.ins-t{padding:14px 18px;border-bottom:1px solid var(--border);font-size:10px;letter-spacing:3px;
  text-transform:uppercase;color:var(--dim)}
.ins-body{flex:1;min-height:0;overflow-y:auto;padding:16px 18px}
.ins-empty{color:var(--dim);font-family:var(--serif);font-style:italic;padding:20px 0}
.ins-k{font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--dim)}
.ins-v{color:var(--text);font-size:11px;margin-top:4px;word-break:break-all}
.chips{margin-top:8px;display:flex;gap:6px;flex-wrap:wrap}
.chip{font-size:9px;letter-spacing:1px;text-transform:uppercase;color:var(--accent-dim);
  border:1px solid var(--border-lt);padding:2px 7px}
.count{color:var(--accent);font-family:var(--mono)}
.ins-note{color:var(--dim);font-style:italic;font-family:var(--serif);margin-top:6px}
.ins-state{margin-top:12px;font-size:11px;color:var(--dim);border:1px solid var(--border);padding:8px 10px}
.ins-state.ok{color:var(--green);border-color:var(--green)}
.chg-list{margin-top:8px;display:flex;flex-direction:column;gap:3px}
.chg{display:flex;gap:8px;font-size:11px;align-items:baseline}
.chg .g{font-family:var(--mono);width:10px}
.g-added{color:var(--green)}.g-modified{color:var(--accent)}.g-deleted{color:var(--red)}
.chg .cp{color:var(--text);word-break:break-all}
.sp-mini{margin-top:8px;display:flex;flex-direction:column;gap:4px}
.spm{font-size:10px;color:var(--dim);display:flex;gap:8px}
.spm .spn{color:var(--accent);font-family:var(--mono)}
.ins-actions{margin-top:22px;display:flex;flex-direction:column;gap:9px}
.sig-line{font-size:11px;color:var(--dim);border:1px solid var(--border);padding:7px 9px;margin-bottom:2px}
.sig-line.stamp-approve{color:var(--green);border-color:var(--green)}
.sig-line.stamp-reject{color:var(--red);border-color:var(--red)}
.act{padding:11px;border:1px solid;font-size:11px;letter-spacing:2px;text-transform:uppercase;
  background:none;transition:.2s}
.act-commit{background:var(--accent);color:var(--bg);border-color:var(--accent);font-weight:600}
.act-commit:hover{background:transparent;color:var(--accent)}
.act-discard{color:var(--dim);border-color:var(--border-lt)}
.act-discard:hover{color:var(--red);border-color:var(--red)}
.act-review{color:var(--blue);border-color:var(--border-lt);font-size:10px}
.act-review:hover{border-color:var(--blue)}
.act-msg{font-size:11px;color:var(--dim);min-height:14px}
.act-msg.bad{color:var(--red)}.act-msg.ok{color:var(--green)}

/* modal */
.modal{position:fixed;inset:0;background:rgba(0,0,0,.6);display:none;z-index:40;
  align-items:center;justify-content:center}
.modal.open{display:flex}
.sheet2{background:var(--bg2);border:1px solid var(--border-lt);width:min(520px,92vw);
  max-height:88vh;overflow-y:auto;padding:24px 26px}
.sheet2 h2{font-family:var(--serif);font-size:22px;color:var(--bright);margin:0 0 4px}
.sheet2 .lead{color:var(--dim);font-size:12px;margin-bottom:18px}
.field{margin-bottom:16px}
.field label{display:block;font-size:9px;letter-spacing:2px;text-transform:uppercase;
  color:var(--dim);margin-bottom:6px}
.field input,.field select{width:100%;background:var(--bg);border:1px solid var(--border);
  color:var(--text);font-family:var(--mono);font-size:12px;padding:9px 10px}
.field .desc{font-size:11px;color:var(--dim);margin-top:5px;font-style:italic;font-family:var(--serif)}
.row2{display:flex;gap:14px}.row2>.field{flex:1}
.toggle{display:flex;align-items:center;gap:9px;font-size:12px;color:var(--text)}
.toggle input{width:auto}
.keystate{font-size:10px;letter-spacing:1px;text-transform:uppercase}
.linkbtn{background:none;border:0;color:var(--accent-dim);font-size:9px;letter-spacing:1px;
  text-transform:uppercase;cursor:pointer;margin-left:8px}
.linkbtn:hover{color:var(--accent)}
.adv{border:1px solid var(--border);padding:10px 12px;margin-bottom:16px}
.adv summary{cursor:pointer;font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--dim)}
.adv[open] summary{margin-bottom:12px}
.field textarea{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);
  font-family:var(--mono);font-size:12px;padding:9px 10px;resize:vertical}
#f-azure.hide{display:none}
.msg.assistant .bub.live::after{content:"▍";color:var(--accent);animation:pulse 1s infinite}
.tool.external{border-color:var(--blue)}
.tool.external .arrow{color:var(--blue)}
.conn-row{display:flex;gap:12px;align-items:center;flex-wrap:wrap;max-width:560px;margin:0 auto 6px;text-align:left}
.conn-row label:first-child{font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--dim)}
.conn-opt{display:inline-flex;gap:6px;align-items:center;font-size:12px;color:var(--text);cursor:pointer}
.conn-hint{font-size:10px;color:var(--dim);max-width:560px;margin:0 auto 12px;text-align:left;font-style:italic;font-family:var(--serif)}
.approval{max-width:760px;margin:0 auto 16px;border:1px solid var(--blue);background:var(--bg3);padding:14px 16px}
.approval.done{border-color:var(--border);opacity:.85}
.ap-t{font-size:9px;letter-spacing:3px;text-transform:uppercase;color:var(--blue);margin-bottom:6px}
.ap-w{color:var(--bright);font-size:13px}
.ap-in{font-size:11px;color:var(--dim);white-space:pre-wrap;margin:8px 0;max-height:200px;overflow:auto}
.ap-acts{display:flex;gap:10px;align-items:center;margin-top:8px}
.ap-acts .act{padding:8px 16px}
.ap-res{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--dim);margin-top:6px}
.memsug{max-width:760px;margin:0 auto 16px;border:1px solid var(--accent-dim);background:var(--bg3);padding:12px 16px}
.memsug.done{border-color:var(--border);opacity:.85}
.ins-cost{font-family:var(--mono);font-size:10px;color:var(--dim);letter-spacing:.5px;margin-top:6px}
.memview{background:var(--bg);border:1px solid var(--border);color:var(--dim);font-size:11px;
  padding:9px 10px;max-height:160px;overflow:auto;white-space:pre-wrap;margin:0}
.memview .jr{margin-bottom:6px}.memview .jr b{color:var(--text);font-weight:400}
.conn-list{display:flex;flex-direction:column;gap:6px;margin-bottom:14px}
.conn-item{display:flex;gap:10px;align-items:center;font-size:11px;border:1px solid var(--border);padding:7px 10px}
.conn-item .cn{color:var(--bright)}.conn-item .cw{color:var(--dim);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.conn-item .linkbtn{margin-left:4px}
#c-http.hide,#c-stdio.hide{display:none}
.keystate.set{color:var(--green)}.keystate.unset{color:var(--red)}
.modal-acts{display:flex;gap:10px;justify-content:flex-end;margin-top:22px}
.savebtn{background:var(--accent);color:var(--bg);border:0;padding:10px 22px;font-size:11px;
  letter-spacing:2px;text-transform:uppercase;font-weight:600}
.closebtn{background:none;border:1px solid var(--border-lt);color:var(--dim);padding:10px 18px;
  font-size:11px;letter-spacing:2px;text-transform:uppercase}
.consolelink{color:var(--dim);text-decoration:none;font-size:11px;letter-spacing:2px;text-transform:uppercase}
.consolelink:hover{color:var(--accent)}
.mt16{margin-top:16px}.mt18{margin-top:18px}.right-auto{margin-right:auto}
.stopbtn.hide{display:none}
.hint.bad{color:var(--red)}
"""


def chat_shell(nonce):
    return CHAT_SHELL.replace("__CSS__", CHAT_CSS).replace("__NONCE__", nonce)


CHAT_SHELL = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OVERLORD — workspace</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' fill='%230a0908'/%3E%3Crect x='10' y='10' width='12' height='12' fill='none' stroke='%23c9a227' stroke-width='2'/%3E%3Crect x='15' y='0' width='2' height='8' fill='%23c9a227'/%3E%3C/svg%3E">
<style nonce="__NONCE__">__CSS__</style></head><body>
<div class="app" id="app">
  <nav class="rail">
    <div class="brand"><div class="name">OVERLORD</div>
      <div class="sub">agent workspace</div></div>
    <button class="newbtn" id="new">+ New conversation</button>
    <div class="convs" id="convs"></div>
    <div class="meters" id="meters" title="What is left: the provider's own rate-limit headers from its last reply, and your spend against the budget lines you set"></div>
    <div class="railfoot">
      <div class="railnav">
        <button class="gear" id="opensettings">Settings</button>
        <a class="consolelink" href="/console">Console</a>
        <button class="gear hide" id="logout">Sign out</button>
      </div>
      <span class="backend" id="backend"></span>
      <span class="backend" id="whoami"></span>
    </div>
  </nav>
  <main class="chat">
    <div class="chat-head">
      <button class="iconbtn" id="togglerail">&#9776;</button>
      <div class="h-t" id="title">New conversation</div>
      <div class="h-s" id="hstatus"></div>
      <button class="iconbtn" id="toggleins">Changes</button>
    </div>
    <div class="stream" id="stream"></div>
    <div class="composer" id="composer">
      <div class="box">
        <textarea id="input" rows="1" placeholder="Tell the agent what to do… (/audit checks its own jail)"></textarea>
        <button class="stopbtn hide" id="stop">Stop</button>
        <button class="send" id="send">Send</button>
      </div>
      <div class="hint" id="hint"></div>
    </div>
  </main>
  <aside class="inspect">
    <div class="ins-t">Transaction</div>
    <div class="ins-body" id="inspector"><div class="ins-empty">No conversation selected.</div></div>
  </aside>
</div>

<div class="modal" id="settings">
  <div class="sheet2">
    <h2>Settings</h2>
    <div class="lead">The model does the thinking on this machine; only its hands run in the sandbox.</div>
    <div class="row2">
      <div class="field"><label>Model provider</label>
        <select id="s-provider">
          <option value="anthropic">Anthropic (Claude)</option>
          <option value="openai">OpenAI</option>
          <option value="azure">Azure OpenAI</option>
          <option value="openai-compatible">OpenAI-compatible (Ollama, vLLM, LiteLLM, gateway)</option>
          <option value="gemini">Google Gemini</option></select></div>
      <div class="field"><label>Model <button type="button" class="linkbtn" id="s-models-refresh">refresh list</button></label>
        <input id="s-model" type="text" list="s-models" placeholder="default" autocomplete="off">
        <datalist id="s-models"></datalist>
        <div class="desc" id="s-models-note"></div></div>
    </div>
    <div class="field"><label>API key <span class="keystate" id="keystate"></span></label>
      <input id="s-key" type="password" placeholder="paste to set — never shown again">
      <div class="desc" id="keydesc">Stored on this machine only, in ~/.overlord/keys.json (mode 600).</div></div>
    <div class="row2">
      <div class="field"><label>Endpoint (base URL)</label>
        <input id="s-baseurl" type="text" placeholder="default">
        <div class="desc">A gateway, a proxy, a local server. Blank uses the provider's own.</div></div>
      <div class="field" id="f-azure"><label>Azure API version</label>
        <input id="s-azurever" type="text" placeholder="2024-10-21"></div>
    </div>
    <div class="field"><label>Extra headers (JSON object)</label>
      <input id="s-headers" type="text" placeholder='{"X-Org": "team-a"}'></div>
    <details class="adv"><summary>Generation</summary>
    <div class="row2">
      <div class="field"><label>Max tokens</label><input id="g-maxtokens" type="number" min="1"></div>
      <div class="field"><label>Effort</label>
        <select id="g-effort"><option value="">model default</option><option>low</option>
          <option>medium</option><option>high</option><option>xhigh</option><option>max</option></select>
        <div class="desc">Reasoning depth. Claude: output_config.effort; OpenAI: reasoning.effort.</div></div>
    </div>
    <div class="row2">
      <div class="field"><label>OpenAI API</label>
        <select id="g-api"><option value="">provider default</option>
          <option value="responses">responses</option><option value="chat">chat completions</option></select>
        <div class="desc">Which wire shape an OpenAI-style endpoint gets. Reasoning models only take function tools with an effort on /v1/responses, so <code>openai</code> uses it; <code>openai-compatible</code> servers get chat completions. Set this for a gateway that differs.</div></div>
    </div>
    <div class="row2">
      <div class="field"><label>Thinking (Claude)</label>
        <select id="g-thinking"><option value="">model default</option>
          <option value="summarized">show a summary</option><option value="off">off</option></select></div>
      <div class="field"><label>Stop sequences (comma-separated)</label><input id="g-stop" type="text"></div>
    </div>
    <div class="row2">
      <div class="field"><label>Temperature</label><input id="g-temperature" type="text" placeholder="not sent">
        <div class="desc">Sent only when set. The current Claude family rejects it.</div></div>
      <div class="field"><label>Top-p</label><input id="g-topp" type="text" placeholder="not sent"></div>
    </div>
    <div class="field"><label>Added system instructions</label>
      <textarea id="g-system" rows="3" placeholder="Appended to the agent's system prompt."></textarea></div>
    <div class="row2">
      <div class="field"><label class="toggle"><input type="checkbox" id="g-stream"> Stream replies</label></div>
      <div class="field"><label class="toggle"><input type="checkbox" id="g-fallbacks"> Refusal fallbacks (Claude native)</label>
        <div class="desc">If Claude declines, the API retries on a fallback model in the same call.</div></div>
    </div>
    <div class="field"><label>Context window (tokens)</label>
      <input id="g-context" type="number" min="8000" step="1000" placeholder="128000">
      <div class="desc">When a call uses three quarters of this, the agent writes a handover note and older turns are dropped; the note is on the transcript.</div></div>
    </details>
    <details class="adv" id="review-section"><summary>Countersignature (second model)</summary>
    <div class="desc">The model that reviews a diff before it can be countersigned. It must not be the agent's own model — a signature by the same mind is not a second one. Blank provider means the agent's provider with a different model.</div>
    <div class="row2">
      <div class="field"><label>Reviewer provider</label>
        <select id="r-provider"><option value="">same as the agent</option>
          <option value="anthropic">Anthropic (Claude)</option><option value="openai">OpenAI</option>
          <option value="azure">Azure OpenAI</option><option value="openai-compatible">OpenAI-compatible</option>
          <option value="gemini">Google Gemini</option></select></div>
      <div class="field"><label>Reviewer model</label>
        <input id="r-model" type="text" placeholder="that provider's default" autocomplete="off"></div>
    </div>
    <div class="field"><label>API key for the reviewer's provider <span class="keystate" id="rkeystate"></span></label>
      <input id="r-key" type="password" placeholder="paste to set — never shown again" autocomplete="off">
      <div class="desc">Stored in the same key store as the agent's key, under the reviewer's provider. If the reviewer uses the agent's provider, its key is already in place. Endpoint and headers come from that provider's profile above.</div></div>
    <div class="desc">A review with a truncated diff never countersigns; harness files (and any policy-protected path) need a complete one.</div>
    </details>
    <div class="field"><label>Working folder</label>
      <input id="s-workdir" type="text">
      <div class="desc">The agent works on a sandboxed copy of this folder. Nothing changes until you Commit.</div></div>
    <div class="row2">
      <div class="field"><label>Sandbox</label>
        <label class="toggle"><input type="checkbox" id="s-jail"> Jail (kernel backend)</label>
        <select id="s-net"><option value="none">Network: offline</option><option value="proxy">Network: recorded (proxy)</option><option value="host">Network: host</option></select>
        <input id="s-netallow" type="text" placeholder="allow (recorded proxy): github.com, *.pypi.org — blank records all">
        <div class="desc" id="jailnote"></div></div>
      <div class="field"><label>Max steps per message</label>
        <input id="s-maxturns" type="number" min="1" max="200"></div>
    </div>
    <details class="adv" id="mem-section"><summary>Memory</summary>
    <div class="desc">What the agent is told before your first message. Project notes live in OVERLORD.md inside the folder (the agent may add to them, inside the transaction, so you review the change). Your own notes live here and only you write them.</div>
    <div class="field"><label>About you (~/.overlord/memory.md)</label>
      <textarea id="m-user" rows="5" placeholder="Prefer pytest. Keep commit messages short. I work in UTC+1."></textarea></div>
    <div class="ap-acts"><button class="act act-review" id="m-save">Save my notes</button>
      <span class="act-msg" id="m-msg"></span></div>
    <div class="field"><label>Project notes in the working folder</label>
      <pre class="memview" id="m-project"></pre></div>
    <div class="field"><label>Recent committed work here</label>
      <div class="memview" id="m-journal"></div></div>
    </details>
    <details class="adv" id="conn-section"><summary>Connectors (MCP)</summary>
    <div class="desc">Tools from MCP servers, offered to the agent next to the built-ins. They run on this machine, outside the sandbox and the transaction, so each conversation must be granted them and non-read-only actions ask you first.</div>
    <div class="field"><label>Approval for actions</label>
      <select id="c-approval"><option value="ask">ask me each time</option>
        <option value="auto">allow automatically</option><option value="readonly">read-only tools only</option></select></div>
    <div id="conn-list" class="conn-list"></div>
    <div class="row2">
      <div class="field"><label>Name</label><input id="c-name" type="text" placeholder="github"></div>
      <div class="field"><label>Transport</label><select id="c-transport"><option value="stdio">command (stdio)</option><option value="http">url (http)</option></select></div>
    </div>
    <div class="field" id="c-stdio"><label>Command and arguments</label>
      <input id="c-command" type="text" placeholder="npx -y @modelcontextprotocol/server-github">
      <div class="desc">Environment for it (JSON object, e.g. tokens):</div>
      <input id="c-env" type="text" placeholder='{"GITHUB_TOKEN": "…"}'></div>
    <div class="field hide" id="c-http"><label>URL</label>
      <input id="c-url" type="text" placeholder="https://host/mcp">
      <div class="desc">Headers (JSON object):</div>
      <input id="c-headers" type="text" placeholder='{"Authorization": "Bearer …"}'></div>
    <div class="ap-acts"><button class="act act-review" id="c-add">Add connector</button>
      <span class="act-msg" id="c-msg"></span></div>
    </details>
    <details class="adv" id="skills-section"><summary>Skills</summary>
    <div class="desc">Packaged know-how the agent loads when its description fits the task. Project skills live in .overlord/skills/ inside the working folder — the agent may write or improve one, and that change is reviewed with everything else. Machine skills are installed here for every conversation.</div>
    <div id="skills-list" class="conn-list"></div>
    <div class="field"><label>Install a machine skill from a folder on this machine</label>
      <input id="sk-path" type="text" placeholder="/path/to/skill-folder (with a SKILL.md)"></div>
    <div class="row2">
      <div class="field"><label>…or create one: name</label><input id="sk-name" type="text" placeholder="release-checklist"></div>
      <div class="field"><label>Description (when it fits)</label><input id="sk-desc" type="text" placeholder="Steps for cutting a release"></div>
    </div>
    <div class="field"><label>SKILL.md body</label><textarea id="sk-body" rows="4" placeholder="# Release checklist&#10;1. …"></textarea></div>
    <div class="ap-acts"><button class="act act-review" id="sk-add">Add skill</button>
      <span class="act-msg" id="sk-msg"></span></div>
    </details>
    <details class="adv hide" id="hooks-section"><summary>Notifications</summary>
    <div class="desc">Tell a chat channel or a service when something needs a person: an agent finished and its changes wait for review, an external action waits for approval, a budget stopped a conversation. Slack-compatible incoming webhooks work as they are.</div>
    <div class="field"><label>Workspace URL for links</label><input id="wh-base" type="text" placeholder="https://overlord.example.lan:7777"></div>
    <div id="wh-list" class="conn-list"></div>
    <div class="row2">
      <div class="field"><label>Name</label><input id="wh-name" type="text" placeholder="team"></div>
      <div class="field"><label>Format</label><select id="wh-format"><option value="slack">slack (text)</option><option value="json">json (signed)</option></select></div>
    </div>
    <div class="field"><label>URL</label><input id="wh-url" type="text" placeholder="https://hooks.slack.com/services/…"></div>
    <div class="field"><label>Events (comma-separated; blank = needs review, approval requested, budget stop)</label>
      <input id="wh-events" type="text" placeholder="session.needs_review, connector.approval_requested, budget.stop"></div>
    <div class="ap-acts"><button class="act act-review" id="wh-add">Add webhook</button>
      <span class="act-msg" id="wh-msg"></span></div>
    </details>
    <details class="adv" id="cost-section"><summary>Cost</summary>
    <div class="desc">Every model call is priced from the table in ~/.overlord/cost.json and written to a ledger. A conversation stops before the call that would cross a budget line.</div>
    <div class="field"><label>Spend</label><div class="memview" id="cost-spend"></div></div>
    <div class="row2" id="cost-budget-row">
      <div class="field"><label>Session limit (tokens)</label><input id="b-tokens" type="number" min="0" placeholder="none"></div>
      <div class="field"><label>Session limit (USD)</label><input id="b-session" type="number" min="0" step="0.01" placeholder="none"></div>
    </div>
    <div class="row2" id="cost-day-row">
      <div class="field"><label>Daily limit for the machine (USD)</label><input id="b-day" type="number" min="0" step="0.01" placeholder="none"></div>
      <div class="field"><label>Monthly limit (USD)</label><input id="b-month" type="number" min="0" step="1" placeholder="none">
        <div class="desc">Set this to your provider's monthly spend cap. The API never reports the cap, so the meter measures against the number you give it.</div></div>
    </div>
    <div class="ap-acts" id="cost-acts"><button class="act act-review" id="b-save">Save budget</button>
      <span class="act-msg" id="b-msg"></span></div>
    </details>
    <details class="adv hide" id="audit-section"><summary>Audit</summary>
    <div class="desc">The machine-wide, hash-chained record of consequential acts: opens, commits, discards, rewinds, reviews, connector decisions, sign-ins, account and policy changes.</div>
    <div class="field"><label>Chain <span class="keystate" id="audit-chain"></span></label>
      <div class="memview" id="audit-list"></div></div>
    </details>
    <details class="adv hide" id="account-section"><summary>My account</summary>
    <div class="desc">Your conversations, keys, settings and notes are yours alone; an admin sees every record.</div>
    <div class="field"><label>New password (8+ characters)</label>
      <input id="a-pass" type="password" autocomplete="new-password"></div>
    <div class="ap-acts"><button class="act act-review" id="a-passwd">Change password</button>
      <span class="act-msg" id="a-msg"></span></div>
    <div class="field"><label>Bearer token for scripts</label>
      <div class="desc">Minted once, shown once; send it as an Authorization: Bearer header.</div>
      <pre class="memview" id="a-token"></pre></div>
    <div class="ap-acts"><button class="act act-review" id="a-mint">New token</button></div>
    </details>
    <details class="adv hide" id="users-section"><summary>Accounts</summary>
    <div class="desc">Who may sign in, and as what. Operators work in their own conversations; viewers read everything and change nothing; admins run the machine (accounts, policy, connectors).</div>
    <div id="u-list" class="conn-list"></div>
    <div class="row2">
      <div class="field"><label>Name</label><input id="u-name" type="text" placeholder="alice" autocomplete="off"></div>
      <div class="field"><label>Role</label><select id="u-role"><option value="operator">operator</option>
        <option value="admin">admin</option><option value="viewer">viewer</option></select></div>
    </div>
    <div class="field"><label>Password (8+ characters)</label>
      <input id="u-pass" type="password" autocomplete="new-password"></div>
    <div class="ap-acts"><button class="act act-review" id="u-add">Add account</button>
      <span class="act-msg" id="u-msg"></span></div>
    </details>
    <div class="modal-acts">
      <span class="act-msg right-auto" id="setmsg"></span>
      <button class="closebtn" id="closesettings">Close</button>
      <button class="savebtn" id="savesettings">Save</button>
    </div>
  </div>
</div>

<script nonce="__NONCE__">
const $ = id => document.getElementById(id);
const j = (u, o) => fetch(u, o).then(r => {
  if(r.status===401){ location.href='/login?next='+encodeURIComponent(location.pathname); return new Promise(()=>{}); }
  return r.json(); });
let SEL = null, FROM = 0, POLL = null, RUNNING = false, READONLY = false, SETTINGS = {}, CONNECTORS = {servers:{}};
let ME = {auth:false, user:null, role:'admin'};
const isAdmin = () => !ME.auth || ME.role==='admin';

function el(tag, cls, text){ const e=document.createElement(tag); if(cls)e.className=cls;
  if(text!=null)e.textContent=text; return e; }

async function loadSettings(){ SETTINGS = await j('/api/settings');
  try { ME = await j('/api/me'); } catch(e) {}
  $('backend').textContent = SETTINGS.backend + ' backend';
  $('whoami').textContent = ME.auth ? (ME.user+' \u00b7 '+ME.role) : '';
  $('logout').classList.toggle('hide', !ME.auth);
  try { CONNECTORS = await j('/api/connectors'); } catch(e) { CONNECTORS = {servers:{}}; }
  return SETTINGS; }

async function loadConvs(){
  const d = await j('/api/chats');
  const box = $('convs'); box.innerHTML='';
  d.conversations.forEach(c => {
    const e = el('div','conv'+(c.sid===SEL?' sel':''));
    e.appendChild(el('div','t', c.title));
    const m = el('div','m');
    const dot = el('span','dot '+(c.thinking?'thinking':(c.status||'')));
    m.appendChild(dot);
    m.appendChild(el('span',null,(c.thinking?'working':c.status||'')+' · '+(c.target||'').split('/').pop()));
    e.appendChild(m);
    e.addEventListener('click',()=>select(c.sid));
    box.appendChild(e);
  });
}

let LIVE = null;   // the assistant bubble currently receiving streamed text
// Render markdown into an element by BUILDING DOM NODES — never innerHTML of
// model text, so nothing the model writes can inject markup. Handles
// paragraphs, headings, bullet/numbered lists, fenced and inline code, bold,
// italic and safe links. This is what turns the raw ** and - the model emits
// into a clean, CLI-styled transcript.
function mdSafeHref(u){ return /^(https?:|mailto:)/i.test(u) ? u : null; }
function mdInline(container, text){
  const re=/(\*\*([^*]+)\*\*|__([^_]+)__|\*([^*\n]+)\*|`([^`]+)`|\[([^\]]+)\]\(([^)\s]+)\))/g;
  let last=0, m;
  while((m=re.exec(text))){
    if(m.index>last) container.appendChild(document.createTextNode(text.slice(last,m.index)));
    if(m[2]!=null||m[3]!=null){ const b=document.createElement('strong'); b.textContent=m[2]!=null?m[2]:m[3]; container.appendChild(b); }
    else if(m[4]!=null){ const e=document.createElement('em'); e.textContent=m[4]; container.appendChild(e); }
    else if(m[5]!=null){ const co=document.createElement('code'); co.textContent=m[5]; container.appendChild(co); }
    else if(m[6]!=null){ const href=mdSafeHref(m[7]);
      if(href){ const a=document.createElement('a'); a.textContent=m[6]; a.href=href; a.target='_blank'; a.rel='noopener noreferrer'; container.appendChild(a); }
      else container.appendChild(document.createTextNode(m[6])); }
    last=re.lastIndex;
  }
  if(last<text.length) container.appendChild(document.createTextNode(text.slice(last)));
}
function mdRender(el2, text){
  el2.textContent='';
  const lines=(text||'').replace(/\r\n?/g,'\n').split('\n');
  let i=0, list=null, listType=null, para=[];
  function flushList(){ if(list){ el2.appendChild(list); list=null; listType=null; } }
  function flushPara(){ if(para.length){ const p=document.createElement('p'); mdInline(p, para.join(' ')); el2.appendChild(p); para=[]; } }
  while(i<lines.length){
    const line=lines[i];
    if(/^\s*```/.test(line)){
      flushPara(); flushList(); const buf=[]; i++;
      while(i<lines.length && !/^\s*```/.test(lines[i])){ buf.push(lines[i]); i++; }
      i++;
      const pre=document.createElement('pre'), code=document.createElement('code');
      code.textContent=buf.join('\n'); pre.appendChild(code); el2.appendChild(pre); continue;
    }
    const h=line.match(/^(#{1,3})\s+(.*)$/);
    if(h){ flushPara(); flushList(); const hd=document.createElement('h3'); mdInline(hd, h[2]); el2.appendChild(hd); i++; continue; }
    const ul=line.match(/^\s*[-*]\s+(.*)$/), ol=line.match(/^\s*\d+[.)]\s+(.*)$/);
    if(ul||ol){
      flushPara(); const t=ul?'ul':'ol';
      if(list && listType!==t) flushList();
      if(!list){ list=document.createElement(t); listType=t; }
      const li=document.createElement('li'); mdInline(li, ul?ul[1]:ol[1]); list.appendChild(li); i++; continue;
    }
    if(line.trim()===''){ flushPara(); flushList(); i++; continue; }
    flushList(); para.push(line.trim()); i++;
  }
  flushPara(); flushList();
}
function renderMsg(m){
  const s = $('stream');
  if(m.type==='assistant_delta'){
    if(!LIVE){ const w = el('div','msg assistant'); w.appendChild(el('div','who','agent'));
      LIVE = el('div','bub live'); w.appendChild(LIVE); s.appendChild(w); }
    LIVE.textContent += m.text||'';
  } else if(m.type==='assistant' && LIVE){
    mdRender(LIVE, m.text||''); LIVE.classList.remove('live'); LIVE = null;
  } else if(m.type==='user'||m.type==='assistant'){
    LIVE = null;
    const w = el('div','msg '+m.type);
    w.appendChild(el('div','who', m.type==='user'?'you':'agent'));
    const bub = el('div','bub');
    if(m.type==='assistant') mdRender(bub, m.text||''); else bub.textContent = m.text||'';
    w.appendChild(bub);
    s.appendChild(w);
  } else if(m.type==='tool_call'){
    LIVE = null;
    const t = el('div','tool'); t.dataset.id = m.id||'';
    const th = el('div','th');
    th.appendChild(el('span','arrow', m.external ? '⇄' : '↳'));
    if(m.external) t.classList.add('external');
    th.appendChild(el('span','tl', m.external ? (m.connector+' · '+m.tool.replace(/^mcp__[^_]+(?:-[^_]+)*__/,'')) : m.tool));
    th.appendChild(el('span','sm', m.summary||''));
    th.appendChild(el('span','tag','·'));
    th.addEventListener('click',()=>t.classList.toggle('open'));
    t.appendChild(th); s.appendChild(t);
  } else if(m.type==='tool_result'){
    const t = [...s.querySelectorAll('.tool')].reverse().find(x=>x.dataset.id===(m.id||''))
              || (()=>{const x=el('div','tool');s.appendChild(x);return x;})();
    const tag = t.querySelector('.tag');
    if(tag){ tag.textContent = 'exit '+m.exit; if(m.exit)tag.classList.add('bad'); }
    if(m.output){ const b=el('div','body', m.output); t.appendChild(b); }
    if(m.touched && m.touched.length){
      t.appendChild(el('div','touched','changed: '+m.touched.join(', '))); }
  } else if(m.type==='approval'){
    LIVE = null;
    const card = el('div','approval'); card.dataset.id = m.id;
    card.appendChild(el('div','ap-t','External action needs your approval'));
    card.appendChild(el('div','ap-w', m.server+' · '+m.tool));
    card.appendChild(el('pre','ap-in', JSON.stringify(m.input||{}, null, 1).slice(0,1500)));
    const acts = el('div','ap-acts');
    const allow = el('button','act act-commit','Allow'); allow.dataset.approve='1';
    const deny = el('button','act act-discard','Deny'); deny.dataset.approve='0';
    acts.appendChild(allow); acts.appendChild(deny); card.appendChild(acts);
    s.appendChild(card);
  } else if(m.type==='approval_decision'){
    const card = [...s.querySelectorAll('.approval')].reverse().find(x=>x.dataset.id===(m.id||''));
    if(card){ card.classList.add('done'); const a=card.querySelector('.ap-acts'); if(a) a.remove();
      card.appendChild(el('div','ap-res', m.decision)); }
    else if(m.decision && m.decision!=='read-only'){ s.appendChild(el('div','note', (m.server||'')+'.'+(m.tool||'')+': '+m.decision)); }
  } else if(m.type==='memory_suggestion'){
    const card = el('div','memsug'); card.dataset.id = m.id;
    card.appendChild(el('div','ap-t','Proposed for your memory'));
    card.appendChild(el('div','ap-w', m.text));
    if(m.accepted){ card.classList.add('done'); card.appendChild(el('div','ap-res','saved')); }
    else { const acts = el('div','ap-acts'); const b = el('button','act act-review','Save to my memory');
      b.dataset.remember = m.id; acts.appendChild(b); card.appendChild(acts); }
    s.appendChild(card);
  } else if(m.type==='note'){
    s.appendChild(el('div','note', m.text));
  } else if(m.type==='error'){
    s.appendChild(el('div','note err', m.text));
  }
}

function setThinking(on){
  RUNNING = on;
  $('send').disabled = on || READONLY;
  $('stop').classList.toggle('hide', !on);
  $('composer').classList.toggle('busy', on);
  let ind = $('ind');
  if(on && !ind){ ind = el('div','thinking'); ind.id='ind';
    ind.innerHTML='<span class="d">the agent is working…</span>'; $('stream').appendChild(ind); }
  if(!on && ind) ind.remove();
  $('hstatus').textContent = on ? 'working' : (SEL?'ready':'');
}

function scroll(){ const s=$('stream'); s.scrollTop = s.scrollHeight; }

async function select(sid){
  stopPoll(); SEL = sid;
  const d = await j('/api/chats/'+encodeURIComponent(sid));
  $('title').textContent = d.meta.title || 'conversation';
  const s = $('stream'); s.innerHTML=''; showComposer(true);
  READONLY = d.meta.may_act === false;
  $('input').disabled = READONLY;
  if(READONLY) $('input').placeholder = 'Read-only: this conversation belongs to '+(d.meta.owner||'someone else');
  d.messages.forEach(renderMsg);
  $('inspector').innerHTML = d.inspector;
  FROM = d.event_count||0;
  setThinking(d.running);
  loadConvs();
  scroll();
  if(d.running) startPoll();
}

function showComposer(on){ $('input').placeholder = SEL ? 'Reply, or ask for a change…' : 'Tell the agent what to do…'; }

function newChat(){ READONLY=false; $('input').disabled=false;
  stopPoll(); SEL=null; FROM=0;
  $('title').textContent='New conversation';
  $('hstatus').textContent='';
  $('inspector').innerHTML='<div class="ins-empty">The transaction will appear here once the agent starts.</div>';
  const s=$('stream'); s.innerHTML='';
  const w = el('div','welcome');
  w.appendChild(el('h1','','What should the agent build?'));
  const p = el('p'); p.textContent='It works on a sandboxed copy of your folder. Nothing on disk changes until you press Commit — so you can let it run, then read the diff and decide.';
  w.appendChild(p);
  const fr = el('div','folder-row');
  fr.appendChild(el('label',null,'Folder'));
  const fi = el('input'); fi.id='folder'; fi.value = SETTINGS.workdir||''; fr.appendChild(fi);
  w.appendChild(fr);
  const names = Object.keys((CONNECTORS.servers)||{});
  if(names.length){
    const cr = el('div','conn-row'); cr.appendChild(el('label',null,'Connectors'));
    names.forEach(n=>{ const l=el('label','conn-opt'); const cb=el('input'); cb.type='checkbox';
      cb.value=n; cb.className='conn-cb'; l.appendChild(cb); l.appendChild(el('span',null,n)); cr.appendChild(l); });
    const hint = el('div','conn-hint','Connector tools run on this machine, outside the sandbox — each action asks you first.');
    w.appendChild(cr); w.appendChild(hint);
  }
  s.appendChild(w);
  setThinking(false);
  loadConvs();
  $('input').focus();
}

async function send(){
  const inp = $('input'); const text = inp.value.trim();
  if(!text || RUNNING) return;
  if(!SEL){
    if(!SETTINGS.provider_ready){
      openSettings('Add your '+SETTINGS.provider+' API key to begin.'); return; }
    const folder = ($('folder')||{}).value || SETTINGS.workdir;
    const connectors = [...document.querySelectorAll('.conn-cb:checked')].map(x=>x.value);
    inp.value=''; autosize();
    const r = await j('/api/chats',{method:'POST',body:JSON.stringify({message:text,target:folder,connectors})});
    if(r.error){ flashHint(r.error,true); return; }
    await select(r.sid);
    startPoll();
  } else {
    inp.value=''; autosize();
    setThinking(true);
    const r = await j('/api/chats/'+encodeURIComponent(SEL)+'/message',
                      {method:'POST',body:JSON.stringify({message:text})});
    if(r.error){ setThinking(false); inp.value=text; flashHint(r.error,true); return; }
    // the server recorded the message and emits it as the next event: the
    // poll renders it once (an optimistic bubble here showed it twice)
    await poll(); startPoll();
  }
}

function flashHint(t,bad){ const h=$('hint'); h.textContent=t; h.classList.toggle('bad',!!bad);
  setTimeout(()=>{h.textContent='';h.classList.remove('bad');},5000); }

function startPoll(){ stopPoll(); POLL=setInterval(poll,650); }
function stopPoll(){ if(POLL){clearInterval(POLL);POLL=null;} }

async function poll(){
  if(!SEL){ stopPoll(); return; }
  const d = await j('/api/chats/'+encodeURIComponent(SEL)+'/events?from='+FROM);
  if(d.error){ stopPoll(); return; }
  FROM = d.next;
  let idle=false;
  d.events.forEach(e=>{ if(e.type==='idle'){idle=true;} else renderMsg(e); });
  if(d.inspector) $('inspector').innerHTML = d.inspector;
  scroll();
  if(!d.running){ setThinking(false); stopPoll(); loadConvs(); loadMeters(); }
}

function stop(){ if(SEL) fetch('/api/chats/'+encodeURIComponent(SEL)+'/cancel',{method:'POST',body:'{}'}); }

async function insAction(url, body){
  const msg = $('actmsg');
  const r = await j(url,{method:'POST',body:JSON.stringify(body||{})});
  if(r.error||r.committed===false){
    let t = r.error || 'refused';
    if(r.rejected) t='rejected: '+r.rejected.reason;
    else if(r.conflicts) t='the folder changed underneath — refused';
    if(msg){msg.textContent=t;msg.className='act-msg bad';}
    return;
  }
  if(msg){msg.textContent='done';msg.className='act-msg ok';}
  await select(SEL);
}

// inspector + review delegation
document.addEventListener('click', async e=>{
  const rm = e.target.closest('[data-remember]');
  if(rm && SEL){ const card = rm.closest('.memsug');
    const r = await j('/api/chats/'+encodeURIComponent(SEL)+'/remember',{method:'POST',
      body:JSON.stringify({id:card.dataset.id})});
    if(!r.error){ card.classList.add('done'); const a=card.querySelector('.ap-acts'); if(a) a.remove();
      card.appendChild(el('div','ap-res','saved')); }
    return; }
  const ap = e.target.closest('[data-approve]');
  if(ap && SEL){ const card = ap.closest('.approval');
    await j('/api/chats/'+encodeURIComponent(SEL)+'/approve',{method:'POST',
      body:JSON.stringify({id:card.dataset.id, allow: ap.dataset.approve==='1'})});
    return; }
  const b = e.target.closest('[data-commit],[data-discard],[data-review]');
  if(!b) return;
  if(b.dataset.commit!==undefined) return insAction('/api/session/'+encodeURIComponent(b.dataset.commit)+'/commit');
  if(b.dataset.discard!==undefined) return insAction('/api/session/'+encodeURIComponent(b.dataset.discard)+'/rollback');
  if(b.dataset.review!==undefined){ const m=$('actmsg'); if(m){m.textContent='asking a second model…';m.className='act-msg';}
    // the second model comes from Settings → Countersignature; the server refuses
    // the agent's own model, so a blank setting fails loudly instead of guessing
    return insAction('/api/session/'+encodeURIComponent(b.dataset.review)+'/review',
                     {provider: SETTINGS.review_provider||null, model: SETTINGS.review_model||null}); }
});

// settings modal
function providerInfo(p){ return (SETTINGS.providers_available||[]).find(x=>x.id===p)||{}; }
function fillProvider(p){
  const o = (SETTINGS.providers||{})[p] || {};
  const info = providerInfo(p);
  $('s-model').value = o.model || '';
  $('s-model').placeholder = info.default_model || 'as the server lists it';
  $('s-baseurl').value = o.base_url || '';
  $('s-baseurl').placeholder = info.default_base_url || 'required';
  $('s-headers').value = o.headers && Object.keys(o.headers).length ? JSON.stringify(o.headers) : '';
  $('s-azurever').value = o.azure_api_version || '';
  $('f-azure').classList.toggle('hide', p!=='azure');
  keystate();
  loadModels(false);
}
async function loadModels(refresh){
  const p = $('s-provider').value, note = $('s-models-note'), dl = $('s-models');
  note.textContent = 'listing models…';
  const r = await j('/api/models?provider='+encodeURIComponent(p)+(refresh?'&refresh=1':''));
  dl.innerHTML = '';
  if(r.error){ note.textContent = 'could not list models: '+r.error; return; }
  (r.models||[]).forEach(m=>{ const o=document.createElement('option'); o.value=m.id;
    o.label = m.name && m.name!==m.id ? m.name : ''; dl.appendChild(o); });
  note.textContent = (r.models||[]).length + ' models available' + (r.cached?' (cached)':'');
}
async function openSettings(msg){
  await loadSettings();
  $('s-provider').value = SETTINGS.provider;
  $('s-workdir').value = SETTINGS.workdir||'';
  const g = SETTINGS.gen || {};
  $('g-maxtokens').value = g.max_tokens || 16000;
  $('g-effort').value = g.effort || '';
  $('g-thinking').value = g.thinking || '';
  $('g-api').value = g.api || '';
  $('g-stop').value = g.stop || '';
  $('g-temperature').value = (g.temperature===''||g.temperature==null) ? '' : g.temperature;
  $('g-topp').value = (g.top_p===''||g.top_p==null) ? '' : g.top_p;
  $('g-system').value = g.system_extra || '';
  $('g-stream').checked = g.stream !== false;
  $('g-fallbacks').checked = g.fallbacks !== false;
  $('g-context').value = g.context_limit || '';
  $('r-provider').value = SETTINGS.review_provider || '';
  $('r-model').value = SETTINGS.review_model || '';
  rkeystate();
  fillProvider(SETTINGS.provider);
  renderConnectors();
  loadMemory();
  $('account-section').classList.toggle('hide', !ME.auth);
  loadCost();
  setInterval(loadMeters, 20000);
  loadSkills();
  $('hooks-section').classList.toggle('hide', !isAdmin());
  if(isAdmin()) loadHooks();
  $('audit-section').classList.toggle('hide', !(isAdmin() || ME.role==='viewer'));
  if(isAdmin() || ME.role==='viewer') loadAudit();
  $('users-section').classList.toggle('hide', !(ME.auth && ME.role==='admin'));
  if(ME.auth && ME.role==='admin') loadUsers();
  $('c-add').disabled = !isAdmin(); $('c-approval').disabled = !isAdmin();
  $('keydesc').textContent = ME.auth
    ? 'Stored for your account only (mode 600). If you set none, the machine\'s shared key is used. A secret://NAME reference is resolved through your vault.'
    : 'Stored on this machine only, in ~/.overlord/keys.json (mode 600). A secret://NAME reference is resolved through your vault (overlord secrets).';
  $('s-jail').checked = !!SETTINGS.jail;
  $('s-jail').disabled = !SETTINGS.jail_available;
  $('s-net').value = SETTINGS.net || 'none';
  $('s-net').disabled = !SETTINGS.jail_available;
  $('s-netallow').value = (SETTINGS.net_allow||[]).join(', ');
  $('s-netallow').disabled = !SETTINGS.jail_available;
  $('jailnote').textContent = SETTINGS.jail_available
    ? 'Jail: namespaces, no capabilities, seccomp, the host tree read-only. Network: with host access the agent can fetch packages and call APIs; every connection it makes is on the record, and OVERLORD\'s own UI still needs the launch token.'
    : 'This machine has the cooperative backend; the jail and the offline grant are unavailable.';
  $('s-maxturns').value = SETTINGS.max_turns;
  keystate();
  $('setmsg').textContent = msg||''; $('setmsg').className='act-msg'+(msg?' bad':'');
  $('settings').classList.add('open');
}
function rkeystate(){ const p = $('r-provider').value || $('s-provider').value;
  const has = p==='scripted' || (SETTINGS.keys && SETTINGS.keys[p]) || (SETTINGS.providers_available||[]).some(x=>x.id===p && !x.needs_key);
  const k=$('rkeystate'); k.textContent = has?'set':'not set'; k.className='keystate '+(has?'set':'unset'); }
function keystate(){ const has = SETTINGS.keys && SETTINGS.keys[$('s-provider').value];
  const k=$('keystate'); k.textContent = has?'set':'not set'; k.className='keystate '+(has?'set':'unset'); }
async function saveSettings(){
  const body = {provider:$('s-provider').value,
    review_provider:$('r-provider').value, review_model:$('r-model').value.trim(),
    workdir:$('s-workdir').value.trim(), jail:$('s-jail').checked, net:$('s-net').value,
    net_allow:$('s-netallow').value.split(/[\s,]+/).filter(Boolean),
    max_turns:Number($('s-maxturns').value)||40,
    provider_opts:{model:$('s-model').value.trim(), base_url:$('s-baseurl').value.trim(),
      headers:$('s-headers').value.trim(), azure_api_version:$('s-azurever').value.trim()},
    gen:{max_tokens:Number($('g-maxtokens').value)||16000, effort:$('g-effort').value,
      thinking:$('g-thinking').value, stop:$('g-stop').value,
      temperature:$('g-temperature').value.trim(), top_p:$('g-topp').value.trim(),
      system_extra:$('g-system').value, stream:$('g-stream').checked,
      fallbacks:$('g-fallbacks').checked, context_limit:$('g-context').value.trim(),
      api:$('g-api').value}};
  const key = $('s-key').value.trim(); if(key) body.key=key;
  const rkey = $('r-key').value.trim(); if(rkey) body.review_key=rkey;
  const r = await j('/api/settings',{method:'PUT',body:JSON.stringify(body)});
  if(r.error){ $('setmsg').textContent=r.error; $('setmsg').className='act-msg bad'; return; }
  $('s-key').value=''; $('r-key').value=''; SETTINGS=r; await loadSettings(); keystate(); rkeystate();
  $('setmsg').textContent='saved'; $('setmsg').className='act-msg ok';
  $('backend').textContent = SETTINGS.backend+' backend';
  if(!SEL) newChat();
}

async function loadMemory(){
  const r = await j('/api/memory');
  if(r.error) return;
  $('m-user').value = r.user || '';
  $('m-project').textContent = (r.project||'').trim() ? r.project : '(no OVERLORD.md in this folder yet)';
  const jl = $('m-journal'); jl.innerHTML = '';
  if(!(r.journal||[]).length){ jl.textContent = '(nothing committed here yet)'; return; }
  r.journal.slice().reverse().forEach(e=>{ const d = el('div','jr');
    const b = el('b', null, (e.ts||'').slice(0,10)+' — '+(e.task||'')); d.appendChild(b);
    if(e.outcome){ d.appendChild(el('div', null, e.outcome.slice(0,200))); }
    jl.appendChild(d); });
}
async function saveMemory(){
  const r = await j('/api/memory',{method:'PUT',body:JSON.stringify({user:$('m-user').value})});
  const m = $('m-msg'); m.textContent = r.error ? r.error : 'saved'; m.className = 'act-msg '+(r.error?'bad':'ok');
}
function renderConnectors(){
  const list = $('conn-list'); list.innerHTML='';
  $('c-approval').value = CONNECTORS.approval || 'ask';
  const names = Object.keys(CONNECTORS.servers||{});
  if(!names.length){ list.appendChild(el('div','desc','No connectors yet.')); return; }
  names.forEach(n=>{ const sv = CONNECTORS.servers[n];
    const row = el('div','conn-item'); row.appendChild(el('span','cn', n));
    row.appendChild(el('span','cw', sv.transport==='http' ? sv.url : [sv.command].concat(sv.args||[]).join(' ')));
    const t = el('button','linkbtn','test'); t.addEventListener('click', async()=>{
      t.textContent='testing…'; const r = await j('/api/connectors/'+encodeURIComponent(n)+'/test',{method:'POST',body:'{}'});
      t.textContent = r.error ? 'failed' : (r.tools||[]).length+' tools'; if(r.error) $('c-msg').textContent = r.error; });
    const rm = el('button','linkbtn','remove'); rm.addEventListener('click', async()=>{
      await j('/api/connectors/'+encodeURIComponent(n)+'/remove',{method:'POST',body:'{}'});
      CONNECTORS = await j('/api/connectors'); renderConnectors(); });
    row.appendChild(t); if(isAdmin()) row.appendChild(rm); list.appendChild(row); });
}
async function loadUsers(){
  const r = await j('/api/users'); const list = $('u-list'); list.innerHTML='';
  if(r.error){ list.appendChild(el('div','desc',r.error)); return; }
  r.users.forEach(u=>{ const row = el('div','conn-item'); row.appendChild(el('span','cn',u.name));
    const sel = document.createElement('select');
    r.roles.forEach(x=>{ const o=document.createElement('option'); o.value=x; o.textContent=x; sel.appendChild(o); });
    sel.value = u.role;
    sel.addEventListener('change', async()=>{ const q = await j('/api/users/'+encodeURIComponent(u.name)+'/role',
      {method:'POST',body:JSON.stringify({role:sel.value})}); $('u-msg').textContent = q.error||''; loadUsers(); });
    row.appendChild(sel);
    row.appendChild(el('span','cw',(u.tokens||[]).length+' token(s)'));
    const rm = el('button','linkbtn','remove'); rm.addEventListener('click', async()=>{
      const q = await j('/api/users/'+encodeURIComponent(u.name)+'/remove',{method:'POST',body:'{}'});
      $('u-msg').textContent = q.error||''; loadUsers(); });
    row.appendChild(rm); list.appendChild(row); });
}
async function addUser(){
  const r = await j('/api/users',{method:'POST',body:JSON.stringify({name:$('u-name').value.trim(),
    password:$('u-pass').value, role:$('u-role').value})});
  const m=$('u-msg'); m.textContent = r.error||'added'; m.className='act-msg '+(r.error?'bad':'ok');
  if(!r.error){ $('u-name').value=''; $('u-pass').value=''; loadUsers(); }
}
async function changePassword(){
  const r = await j('/api/users/'+encodeURIComponent(ME.user)+'/passwd',{method:'POST',
    body:JSON.stringify({password:$('a-pass').value})});
  const m=$('a-msg'); m.textContent = r.error||'changed \u2014 sign in again'; m.className='act-msg '+(r.error?'bad':'ok');
  if(!r.error) $('a-pass').value='';
}
async function mintToken(){
  const r = await j('/api/users/'+encodeURIComponent(ME.user)+'/token',{method:'POST',body:JSON.stringify({label:'workspace'})});
  $('a-token').textContent = r.error||r.token;
}
async function loadHooks(){
  const r = await j('/api/webhooks'); const list = $('wh-list'); list.innerHTML='';
  if(r.error){ list.appendChild(el('div','desc',r.error)); return; }
  $('wh-base').value = r.base_url||'';
  if(!r.hooks.length) list.appendChild(el('div','desc','No webhooks yet.'));
  r.hooks.forEach(h=>{ const row = el('div','conn-item'); row.appendChild(el('span','cn', h.name));
    row.appendChild(el('span','cw', '['+h.format+(h.has_secret?', signed':'')+'] '+h.url+' — '+h.events.join(', ')));
    const t = el('button','linkbtn','test'); t.addEventListener('click', async()=>{ t.textContent='sending…';
      const q = await j('/api/webhooks/'+encodeURIComponent(h.name)+'/test',{method:'POST',body:'{}'});
      t.textContent = q.error ? 'failed' : 'delivered'; if(q.error) $('wh-msg').textContent = q.error; });
    const rm = el('button','linkbtn','remove'); rm.addEventListener('click', async()=>{
      await j('/api/webhooks/'+encodeURIComponent(h.name)+'/remove',{method:'POST',body:'{}'}); loadHooks(); });
    row.appendChild(t); row.appendChild(rm); list.appendChild(row); });
  if(r.stats && (r.stats.sent||r.stats.failed)) list.appendChild(el('div','desc',
    `delivered ${r.stats.sent}, failed ${r.stats.failed}`+(r.stats.last_error?' — last error: '+r.stats.last_error:'')));
}
async function addHook(){
  const events = $('wh-events').value.split(',').map(s=>s.trim()).filter(Boolean);
  const r = await j('/api/webhooks',{method:'POST',body:JSON.stringify({name:$('wh-name').value.trim(),
    url:$('wh-url').value.trim(), format:$('wh-format').value, events})});
  const m=$('wh-msg'); m.textContent = r.error||('added '+r.added); m.className='act-msg '+(r.error?'bad':'ok');
  if(!r.error){ $('wh-name').value=''; $('wh-url').value=''; $('wh-events').value=''; loadHooks(); }
}
async function saveBase(){ await j('/api/webhooks',{method:'POST',body:JSON.stringify({base_url:$('wh-base').value.trim()})}); }
async function loadSkills(){
  const r = await j('/api/skills'); const list = $('skills-list'); list.innerHTML='';
  if(r.error){ list.appendChild(el('div','desc',r.error)); return; }
  if(!r.skills.length){ list.appendChild(el('div','desc','No skills yet. Two examples ship in the repo: overlord skills add skills/python-testing')); }
  r.skills.forEach(s=>{ const row = el('div','conn-item'); row.appendChild(el('span','cn', s.name));
    row.appendChild(el('span','cw', '['+s.source+'] '+s.description+(s.files.length?' (+'+s.files.length+' files)':'')));
    if(s.source==='machine' && isAdmin()){ const rm = el('button','linkbtn','remove'); rm.addEventListener('click', async()=>{
      const q = await j('/api/skills/'+encodeURIComponent(s.name)+'/remove',{method:'POST',body:'{}'});
      $('sk-msg').textContent = q.error||''; loadSkills(); }); row.appendChild(rm); }
    list.appendChild(row); });
  ['sk-path','sk-name','sk-desc','sk-body','sk-add'].forEach(id=>{ $(id).disabled = !isAdmin(); });
}
async function addSkill(){
  const body = $('sk-path').value.trim() ? {path:$('sk-path').value.trim()}
    : {name:$('sk-name').value.trim(), description:$('sk-desc').value.trim(), body:$('sk-body').value};
  const r = await j('/api/skills',{method:'POST',body:JSON.stringify(body)});
  const m=$('sk-msg'); m.textContent = r.error||('added '+r.added); m.className='act-msg '+(r.error?'bad':'ok');
  if(!r.error){ ['sk-path','sk-name','sk-desc','sk-body'].forEach(id=>{ $(id).value=''; }); loadSkills(); }
}
function money(v){ return v==null ? '—' : '$'+Number(v).toFixed(4); }
async function loadCost(){
  const r = await j('/api/cost'); if(r.error){ $('cost-spend').textContent = r.error; return; }
  const t = r.today, m = r.month;
  $('cost-spend').textContent = `today (${r.scope}): ${t.calls} call(s), ${t.in} in / ${t.out} out, ${money(t.usd)}\n`
    + `last 30 days: ${m.calls} call(s), ${m.in} in / ${m.out} out, ${money(m.usd)}`
    + (m.unpriced ? ` (${m.unpriced} on unpriced models)` : '')
    + (Object.keys(r.limits||{}).length ? `\nlimits in effect: ${Object.entries(r.limits).map(([k,v])=>k+'='+v).join(', ')}` : '');
  const b = r.budget||{};
  $('b-tokens').value = b.session_tokens||''; $('b-session').value = b.session_usd||''; $('b-day').value = b.day_usd||'';
  $('b-month').value = b.month_usd||'';
  const ro = !isAdmin(); ['b-tokens','b-session','b-day','b-month','b-save'].forEach(id=>{ $(id).disabled = ro; });
  renderMeters(r);
}
// ---- the usage meter: what is left, from two real sources ----------------
// 1. the provider's rate-limit headers on its last reply (tokens and requests
//    per minute: limit, remaining, refill time). A lower bound between calls.
// 2. spend from the ledger against the budget lines in effect (today, month).
function fmtK(n){ if(n==null) return '—'; n=Number(n); return n>=1e6 ? (n/1e6).toFixed(n>=1e7?0:1)+'M' : n>=1e3 ? Math.round(n/1e3)+'k' : String(Math.round(n)); }
function meterRow(box, title, used, limit, valueText, note){
  const left = limit>0 ? Math.max(0, 1 - used/limit) : null;
  const d = el('div', 'meter' + (left==null ? '' : left < .1 ? ' crit' : left < .25 ? ' warn' : ''));
  const l = el('div','lbl'); l.appendChild(el('span', null, title)); l.appendChild(el('span','val', valueText)); d.appendChild(l);
  if(limit>0){ const t = el('div','track'); const f = el('div','fill'); f.style.width = Math.min(100, Math.max(0, used/limit*100)).toFixed(1)+'%'; t.appendChild(f); d.appendChild(t); }
  const n = note + (left==null ? '' : left < .1 ? ' · nearly exhausted' : left < .25 ? ' · running low' : '');
  if(n) d.appendChild(el('div','note', n));
  box.appendChild(d);
}
function untilText(reset, now){
  if(!reset) return '';
  const t = Date.parse(reset); if(isNaN(t)) return 'refills in '+reset;
  const s = Math.round((t - now*1000)/1000); return s <= 0 ? 'refilled' : 'refills in '+(s>=60? Math.floor(s/60)+'m'+(s%60)+'s' : s+'s');
}
function renderMeters(r){
  const box = $('meters'); if(!box) return; box.innerHTML='';
  const prov = SETTINGS.provider, rate = (r.rate||{})[prov];
  if(rate){
    const age = Math.max(0, Math.round((r.now||Date.now()/1000) - (rate.seen||0)));
    const stale = age > 90 ? ' · as of '+(age>=3600? Math.floor(age/3600)+'h' : Math.floor(age/60)+'m')+' ago' : '';
    const tk = rate.tokens || rate.input_tokens;
    if(tk && tk.limit) meterRow(box, 'tokens / min · '+prov, tk.limit - (tk.remaining||0), tk.limit,
      fmtK(tk.remaining)+' of '+fmtK(tk.limit)+' left', untilText(tk.reset, r.now) + stale);
    if(rate.output_tokens && rate.output_tokens.limit && tk !== rate.output_tokens) meterRow(box, 'output / min', rate.output_tokens.limit - (rate.output_tokens.remaining||0), rate.output_tokens.limit,
      fmtK(rate.output_tokens.remaining)+' of '+fmtK(rate.output_tokens.limit)+' left', untilText(rate.output_tokens.reset, r.now));
    if(rate.requests && rate.requests.limit) meterRow(box, 'requests / min', rate.requests.limit - (rate.requests.remaining||0), rate.requests.limit,
      fmtK(rate.requests.remaining)+' of '+fmtK(rate.requests.limit)+' left', untilText(rate.requests.reset, r.now));
    if(rate.retry_after) meterRow(box, 'rate limited', 1, 1, 'retry in '+rate.retry_after+'s', 'the provider refused the last call');
  } else if(prov && prov!=='scripted') {
    meterRow(box, 'rate limit · '+prov, 0, 0, 'no reply yet', 'the provider states its headroom on every reply; send a message');
  }
  const lim = r.limits||{}, t = r.today||{}, m = r.mtd||{};
  if(lim.day_usd) meterRow(box, 'today', t.usd||0, lim.day_usd, '$'+(t.usd||0).toFixed(2)+' of $'+lim.day_usd.toFixed(2), (t.calls||0)+' call(s)');
  else meterRow(box, 'today', 0, 0, '$'+(t.usd||0).toFixed(2), (t.calls||0)+' call(s) · no daily limit set');
  if(lim.month_usd) meterRow(box, 'this month', m.usd||0, lim.month_usd, '$'+(m.usd||0).toFixed(2)+' of $'+lim.month_usd.toFixed(0), fmtK(m.in)+' in / '+fmtK(m.out)+' out');
  else meterRow(box, 'this month', 0, 0, '$'+(m.usd||0).toFixed(2), 'set a monthly limit in Settings → Cost to meter against your provider\'s cap');
  if(r.month && r.month.unpriced) box.appendChild(el('div','note', r.month.unpriced+' call(s) on unpriced models are not in the dollars'));
}
async function loadMeters(){ try { const r = await j('/api/cost'); if(!r.error) renderMeters(r); } catch(e) {} }
async function saveBudget(){
  const body = {budget:{session_tokens:$('b-tokens').value||0, session_usd:$('b-session').value||0, day_usd:$('b-day').value||0, month_usd:$('b-month').value||0}};
  const r = await j('/api/cost',{method:'PUT',body:JSON.stringify(body)});
  const m=$('b-msg'); m.textContent = r.error||'saved'; m.className='act-msg '+(r.error?'bad':'ok');
  if(!r.error) loadCost();
}
async function loadAudit(){
  const r = await j('/api/audit?n=40&verify=1'); const box = $('audit-list'); box.innerHTML='';
  if(r.error){ box.textContent = r.error; return; }
  const ch = $('audit-chain'); ch.textContent = r.chain && r.chain.ok ? 'intact · '+r.chain.entries : 'BROKEN';
  ch.className = 'keystate '+(r.chain && r.chain.ok ? 'set' : 'unset');
  r.entries.slice().reverse().forEach(e=>{ const d = el('div','jr');
    const extra = Object.entries(e).filter(([k])=>!['ts','action','actor','seq','prev','hash'].includes(k))
      .map(([k,v])=>k+'='+(typeof v==='string'?v:JSON.stringify(v))).join(' ');
    d.appendChild(el('b', null, (e.ts||'').slice(0,19)+'  '+(e.actor||'')+'  '+e.action));
    if(extra) d.appendChild(el('div', null, extra.slice(0,200)));
    box.appendChild(d); });
}
async function signOut(){ await j('/api/logout',{method:'POST',body:'{}'}); location.href='/login'; }
async function addConnector(){
  const transport = $('c-transport').value, msg = $('c-msg');
  const body = {name: $('c-name').value.trim()};
  try {
    if(transport==='stdio'){
      const parts = $('c-command').value.trim().split(/\s+/).filter(Boolean);
      body.command = parts[0]; body.args = parts.slice(1);
      body.env = $('c-env').value.trim() ? JSON.parse($('c-env').value) : {};
    } else {
      body.url = $('c-url').value.trim();
      body.headers = $('c-headers').value.trim() ? JSON.parse($('c-headers').value) : {};
    }
  } catch(e){ msg.textContent = 'env/headers must be a JSON object'; msg.className='act-msg bad'; return; }
  const r = await j('/api/connectors',{method:'POST',body:JSON.stringify(body)});
  if(r.error){ msg.textContent = r.error; msg.className='act-msg bad'; return; }
  msg.textContent = 'added'; msg.className='act-msg ok';
  $('c-name').value=''; $('c-command').value=''; $('c-env').value=''; $('c-url').value=''; $('c-headers').value='';
  CONNECTORS = await j('/api/connectors'); renderConnectors();
}
function autosize(){ const t=$('input'); t.style.height='auto'; t.style.height=Math.min(180,t.scrollHeight)+'px'; }

$('send').addEventListener('click',send);
$('stop').addEventListener('click',stop);
$('new').addEventListener('click',newChat);
$('opensettings').addEventListener('click',()=>openSettings());
$('closesettings').addEventListener('click',()=>$('settings').classList.remove('open'));
$('savesettings').addEventListener('click',saveSettings);
$('s-provider').addEventListener('change',()=>{ fillProvider($('s-provider').value); rkeystate(); });
$('r-provider').addEventListener('change',rkeystate);
$('s-models-refresh').addEventListener('click',()=>loadModels(true));
$('c-transport').addEventListener('change',()=>{ const h=$('c-transport').value==='http';
  $('c-http').classList.toggle('hide',!h); $('c-stdio').classList.toggle('hide',h); });
$('c-add').addEventListener('click',addConnector);
$('m-save').addEventListener('click',saveMemory);
$('u-add').addEventListener('click',addUser);
$('a-passwd').addEventListener('click',changePassword);
$('a-mint').addEventListener('click',mintToken);
$('b-save').addEventListener('click',saveBudget);
$('sk-add').addEventListener('click',addSkill);
$('wh-add').addEventListener('click',addHook);
$('wh-base').addEventListener('change',saveBase);
$('logout').addEventListener('click',signOut);
$('c-approval').addEventListener('change',async()=>{ await j('/api/connectors/approval',{method:'POST',
  body:JSON.stringify({mode:$('c-approval').value})}); CONNECTORS = await j('/api/connectors'); });
$('togglerail').addEventListener('click',()=>$('app').classList.toggle('show-rail'));
$('toggleins').addEventListener('click',()=>$('app').classList.toggle('show-ins'));
$('input').addEventListener('input',autosize);
$('input').addEventListener('keydown',e=>{ if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send();} });

(async ()=>{ await loadSettings(); await loadConvs();
  const want = new URLSearchParams(location.search).get('sid');   // a notification's deep link
  if(want && /^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$/.test(want)){ try { await select(want); return; } catch(e) {} }
  if(!SETTINGS.provider_ready) openSettings('Add your API key to begin.');
  newChat();
})();
</script></body></html>"""


# ---------------------------------------------------------------- dispatch
#
# ui.py owns the socket, the loopback bind, the origin guard and the nonce CSP.
# It calls these after the guard passes; they use handler._send exactly as the
# console routes do, so the whole surface shares one security perimeter.


def handle_get(handler, path, query):
    if path == "/api/settings":
        handler._send(settings_public())
        return True
    if path == "/api/connectors":
        handler._send(mcp_mod.public_config())
        return True
    if path == "/api/webhooks":
        auth.require("admin")
        handler._send(notify_mod.public())
        return True
    if path == "/api/skills":
        s = load_settings()
        wd = os.path.realpath(os.path.expanduser((query.get("target") or [s["workdir"]])[0]))
        handler._send({"skills": skills_mod.public(wd if os.path.isdir(wd) else None),
                       "project_dir": os.path.join(wd, skills_mod.PROJECT_DIR),
                       "machine_dir": skills_mod.MACHINE_DIR})
        return True
    if path == "/api/memory":
        s = load_settings()
        wd = (query.get("target") or [s["workdir"]])[0]
        wd = os.path.realpath(os.path.expanduser(wd))
        user_text, _u = memory_mod.user_memory()
        proj_text, ptrunc = memory_mod.project_memory(wd) if os.path.isdir(wd) else ("", False)
        handler._send({"user": user_text, "user_file": memory_mod.user_file(),
                       "project": proj_text, "project_file": os.path.join(wd, memory_mod.PROJECT_FILE),
                       "project_truncated": ptrunc,
                       "journal": memory_mod.journal_entries(wd) if os.path.isdir(wd) else []})
        return True
    if path == "/api/models":
        handler._send(models_for((query.get("provider") or [None])[0] or None,
                                 refresh=bool((query.get("refresh") or [""])[0])))
        return True
    if path == "/api/chats":
        s = load_settings()
        handler._send({"conversations": conversations(),
                       "backend": core.detect_backend() or "none",
                       "workdir": s["workdir"]})
        return True
    if path.startswith("/api/chats/"):
        rest = path[len("/api/chats/"):]
        sid = core.validate_session_id(rest.split("/")[0])
        if rest.endswith("/events"):
            auth.require("read", core.load_meta(sid))
            frm = 0
            try:
                frm = max(0, int((query.get("from") or ["0"])[0]))
            except ValueError:
                frm = 0
            handler._send(events_since(sid, frm))
            return True
        handler._send(conversation(sid))
        return True
    return False


def handle_post(handler, parts, req):
    # parts is self.path.strip('/').split('/')
    if parts == ["api", "chats"]:
        sid = start_conversation(req.get("message", ""), req.get("target") or None,
                                 provider=req.get("provider") or None,
                                 model=req.get("model") or None,
                                 connectors=req.get("connectors") or None)
        handler._send({"sid": sid})
        return True
    if len(parts) == 4 and parts[:2] == ["api", "chats"]:
        sid, action = core.validate_session_id(parts[2]), parts[3]
        if action == "message":
            send_message(sid, req.get("message", ""))
            handler._send({"ok": True})
            return True
        if action == "cancel":
            handler._send(cancel(sid))
            return True
        if action == "approve":
            auth.require("act", core.load_meta(sid))
            _p = auth.current()
            _who = (f"{_p['user']}@{_p['via']}" if _p else "workspace")
            handler._send(decide(sid, str(req.get("id") or ""), bool(req.get("allow")), _who))
            return True
        if action == "remember":
            auth.require("act", core.load_meta(sid))
            handler._send(memory_mod.accept_suggestion(sid, str(req.get("id") or "")))
            return True
    if parts == ["api", "webhooks"]:
        auth.require("admin")
        if "base_url" in req and len(req) == 1:
            notify_mod.set_base_url(str(req.get("base_url") or ""))
            handler._send({"base_url": notify_mod.load_config()["base_url"]})
            return True
        h = notify_mod.add_hook(str(req.get("name") or ""), str(req.get("url") or ""),
                                [str(e) for e in (req.get("events") or [])] or None,
                                str(req.get("format") or "slack"), str(req.get("secret") or ""))
        handler._send({"added": h["name"]})
        return True
    if len(parts) == 4 and parts[:2] == ["api", "webhooks"]:
        auth.require("admin")
        if parts[3] == "remove":
            notify_mod.remove_hook(parts[2])
            handler._send({"removed": parts[2]})
            return True
        if parts[3] == "test":
            handler._send({"status": notify_mod.send_test(parts[2])})
            return True
    if parts == ["api", "skills"]:
        auth.require("admin")
        if req.get("path"):
            e = skills_mod.install(str(req["path"]), req.get("name") or None)
        else:
            e = skills_mod.create(str(req.get("name") or ""), str(req.get("description") or ""),
                                  str(req.get("body") or ""), when=str(req.get("when") or ""))
        handler._send({"added": e["name"], "source": e["source"]})
        return True
    if len(parts) == 4 and parts[:2] == ["api", "skills"] and parts[3] == "remove":
        auth.require("admin")
        skills_mod.remove(parts[2])
        handler._send({"removed": parts[2]})
        return True
    if parts == ["api", "connectors"]:
        auth.require("admin")
        env = req.get("env") or {}
        headers = req.get("headers") or {}
        if not isinstance(env, dict) or not isinstance(headers, dict):
            raise core.OverlordError("error: env and headers must be JSON objects")
        entry = mcp_mod.add_server(str(req.get("name") or ""), command=req.get("command") or None,
                                   args=[str(a) for a in (req.get("args") or [])], env=env,
                                   cwd=req.get("cwd") or None, url=req.get("url") or None,
                                   headers=headers)
        handler._send({"added": req.get("name"), "transport": entry["transport"]})
        return True
    if len(parts) == 3 and parts[:2] == ["api", "connectors"]:
        name = parts[2]
        if name == "approval":
            auth.require("admin")
            mcp_mod.set_approval(str(req.get("mode") or ""))
            handler._send({"approval": req.get("mode")})
            return True
        raise core.OverlordError("error: unknown connector action")
    if len(parts) == 4 and parts[:2] == ["api", "connectors"]:
        name, action = parts[2], parts[3]
        auth.require("admin")
        if action == "remove":
            mcp_mod.remove_server(name)
            handler._send({"removed": name})
            return True
        if action == "test":
            handler._send(mcp_mod.test_server(name))
            return True
    return False


def handle_put(handler, path, body_text):
    auth.require("use")
    if path == "/api/memory":
        try:
            incoming = json.loads(body_text or "{}")
        except ValueError:
            raise core.OverlordError("error: memory must be JSON")
        text = incoming.get("user")
        if not isinstance(text, str):
            raise core.OverlordError("error: memory.user must be a string")
        if len(text) > 200_000:
            raise core.OverlordError("error: user memory is too large (200k chars)")
        memory_mod.set_user_memory(text)
        handler._send({"saved": True, "chars": len(text)})
        return True
    if path == "/api/settings":
        try:
            incoming = json.loads(body_text or "{}")
        except ValueError:
            raise core.OverlordError("error: settings must be JSON")
        save_settings(incoming)
        handler._send(settings_public())
        return True
    return False
