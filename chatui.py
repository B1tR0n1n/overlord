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

LAUNCH_CWD = os.getcwd()
SETTINGS_FILE = os.path.join(core.OVERLORD_HOME, "ui.json")
DEFAULT_SETTINGS = {"provider": "anthropic", "model": "", "jail": True,
                    "net": "none", "max_turns": 40, "workdir": ""}
GLYPH = {"added": "+", "modified": "~", "deleted": "−", "replaced-dir": "±"}
MAX_TAIL = 1200                   # chars of a tool's output shown in the stream


def _esc(s):
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


# ---------------------------------------------------------------- settings


def load_settings():
    s = dict(DEFAULT_SETTINGS)
    try:
        with open(SETTINGS_FILE) as f:
            s.update({k: v for k, v in json.load(f).items() if k in DEFAULT_SETTINGS})
    except (OSError, ValueError):
        pass
    if not s.get("workdir"):
        s["workdir"] = LAUNCH_CWD
    return s


def save_settings(incoming):
    """Persist the workspace settings. An API key (if present) is handed to
    the engine's 0600 key store and never written here or echoed back."""
    s = load_settings()
    key = incoming.get("key")
    provider = incoming.get("provider") or s["provider"]
    for k in DEFAULT_SETTINGS:
        if k in incoming and incoming[k] is not None:
            s[k] = incoming[k]
    s["provider"] = provider
    if s.get("provider") not in ("anthropic", "openai", "scripted"):
        raise core.OverlordError("error: provider must be anthropic or openai")
    if s.get("net") not in ("none", "host"):
        raise core.OverlordError("error: net must be none or host")
    try:
        s["max_turns"] = max(1, min(200, int(s.get("max_turns") or 40)))
    except (TypeError, ValueError):
        s["max_turns"] = 40
    s["jail"] = bool(s.get("jail"))
    wd = s.get("workdir") or LAUNCH_CWD
    if not os.path.isdir(os.path.expanduser(wd)):
        raise core.OverlordError(f"error: not a folder: {wd}")
    s["workdir"] = os.path.realpath(os.path.expanduser(wd))
    os.makedirs(core.OVERLORD_HOME, exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(s, f, indent=2)
    if key:
        if provider not in ("anthropic", "openai"):
            raise core.OverlordError("error: a key can only be set for anthropic or openai")
        agent_mod.save_key(provider, key.strip())
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
    if s["provider"] == "scripted":
        ready = bool(os.environ.get("OVERLORD_AGENT_SCRIPT"))
    else:
        ready = _has_key(s["provider"])
    return {**s,
            "backend": backend or "none",
            "jail_available": backend == "kernel",
            "keys": {p: _has_key(p) for p in ("anthropic", "openai")},
            "provider_ready": ready,
            "default_model": agent_mod.DEFAULT_MODELS.get(s["provider"], ""),
            "models": agent_mod.DEFAULT_MODELS}


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
                              "cancel": threading.Event(), "lock": threading.Lock()}
        return c


def _emit(sid, ev):
    c = _conv(sid)
    with c["lock"]:
        c["events"].append(ev)


def _grants_for(settings, backend):
    """The sandbox the agent's hands run in. Jail + offline need the kernel
    backend; on fuse they are refused rather than faked, so the workspace
    drops them and says so."""
    if backend == "kernel":
        return {"net": settings.get("net", "none"), "jail": bool(settings.get("jail", True)),
                "timeout": None, "merge_base": False}, None
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
    if t == "assistant":
        return {"type": "assistant", "text": ev.get("text", "")}
    if t == "tool_call":
        return {"type": "tool_call", "id": ev.get("id"), "tool": ev.get("tool"),
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
    if t == "error":
        return {"type": "error", "text": ev.get("text", "")}
    return None


def _run(sid, live, provider, message, first, max_turns):
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
                            resume=not first, note=None if first else message)
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


def start_conversation(message, target=None):
    """Open a fresh transaction and set the agent to work. Returns its sid."""
    s = load_settings()
    target = os.path.realpath(os.path.expanduser(target or s["workdir"]))
    if not os.path.isdir(target):
        raise core.OverlordError(f"error: not a folder: {target}")
    if not (message or "").strip():
        raise core.OverlordError("error: a message is needed to start")
    backend = core.detect_backend()
    if backend is None:
        raise core.OverlordError(
            "error: no sandbox backend available — run `overlord doctor`")
    provider = agent_mod.make_provider(s["provider"], s["model"] or None)
    grants, note = _grants_for(s, backend)
    pend = core.pending_sessions_for(target)
    if pend:
        raise core.OverlordError(
            "error: this folder already has an open conversation. Commit or discard it "
            "first, or pick another folder in Settings.")
    live = core.open_session(target, backend, grants, capture=True,
                             agent=f"{provider.name}:{provider.model}")
    sid = live.sid
    _conv(sid)
    if note:
        _emit(sid, {"type": "note", "text": note})
    _record_user(sid, message)
    threading.Thread(target=_run, args=(sid, live, provider, message, True,
                                        int(s["max_turns"])), daemon=True).start()
    return sid


def send_message(sid, message):
    """Resume a conversation with another message on the same transaction."""
    c = _conv(sid)
    if c["running"]:
        raise core.OverlordError("error: the agent is still working — wait for it to finish")
    if not (message or "").strip():
        raise core.OverlordError("error: empty message")
    meta = core.load_meta(sid)
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
                             "tool": ev.get("tool"), "summary": calls.get(ev.get("id"), "")})
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
        if not m.get("agent"):
            continue
        out.append({"sid": sid, "title": _title(m), "status": m.get("status"),
                    "target": m.get("target"), "updated": m.get("finished") or m.get("started"),
                    "thinking": _conv(sid)["running"]})
    out.sort(key=lambda c: c["updated"] or "", reverse=True)
    return out


def conversation(sid):
    core.validate_session_id(sid)
    meta = core.load_meta(sid)
    c = _conv(sid)
    with c["lock"]:
        event_count = len(c["events"])
    return {"meta": {"id": meta["id"], "title": _title(meta), "status": meta.get("status"),
                     "target": meta.get("target"), "agent": meta.get("agent"),
                     "grants": meta.get("grants")},
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


def _inspector_body(sid, m, live):
    h = []

    if m.get("status") == "committed":
        h.append('<div class="ins-state ok">Committed to the folder.</div>')
    elif m.get("status") in ("rolled-back",) or (not live and m.get("status") != "pending"):
        h.append('<div class="ins-state">Discarded. The folder was left untouched.</div>')

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
                 '<div class="act-msg" id="actmsg"></div></div>')
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
.convs{flex:1;overflow-y:auto;padding:4px 8px}
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
.railfoot{border-top:1px solid var(--border);padding:10px 12px;display:flex;gap:10px;align-items:center}
.gear{background:none;border:0;color:var(--dim);font-size:11px;letter-spacing:2px;text-transform:uppercase}
.gear:hover{color:var(--accent)}
.backend{margin-left:auto;font-size:9px;color:var(--dim);letter-spacing:1px}

/* center */
.chat{display:flex;flex-direction:column;min-width:0;background:var(--bg)}
.chat-head{padding:14px 22px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px}
.chat-head .h-t{font-family:var(--serif);font-size:17px;color:var(--bright);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.chat-head .h-s{margin-left:auto;font-size:10px;color:var(--dim);letter-spacing:2px;text-transform:uppercase}
.iconbtn{display:none;background:none;border:1px solid var(--border-lt);color:var(--dim);
  padding:5px 9px;font-size:11px}
@media(max-width:900px){.iconbtn{display:inline-block}}
.stream{flex:1;overflow-y:auto;padding:26px 22px 8px}
.msg{max-width:760px;margin:0 auto 20px}
.msg .who{font-size:9px;letter-spacing:3px;text-transform:uppercase;color:var(--dim);margin-bottom:6px}
.msg.user .bub{background:var(--bg3);border:1px solid var(--border);border-left:2px solid var(--accent);
  padding:12px 16px;white-space:pre-wrap;color:var(--bright)}
.msg.assistant .bub{font-family:var(--serif);font-size:16px;line-height:1.6;color:var(--text);
  white-space:pre-wrap}
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
.ins-body{flex:1;overflow-y:auto;padding:16px 18px}
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
.keystate.set{color:var(--green)}.keystate.unset{color:var(--red)}
.modal-acts{display:flex;gap:10px;justify-content:flex-end;margin-top:22px}
.savebtn{background:var(--accent);color:var(--bg);border:0;padding:10px 22px;font-size:11px;
  letter-spacing:2px;text-transform:uppercase;font-weight:600}
.closebtn{background:none;border:1px solid var(--border-lt);color:var(--dim);padding:10px 18px;
  font-size:11px;letter-spacing:2px;text-transform:uppercase}
.consolelink{color:var(--dim);text-decoration:none;font-size:10px;letter-spacing:2px;text-transform:uppercase}
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
    <div class="railfoot">
      <button class="gear" id="opensettings">Settings</button>
      <a class="consolelink" href="/console">Console</a>
      <span class="backend" id="backend"></span>
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
        <textarea id="input" rows="1" placeholder="Tell the agent what to do…"></textarea>
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
        <select id="s-provider"><option value="anthropic">Anthropic (Claude)</option>
          <option value="openai">OpenAI</option></select></div>
      <div class="field"><label>Model</label>
        <input id="s-model" type="text" placeholder="default"></div>
    </div>
    <div class="field"><label>API key <span class="keystate" id="keystate"></span></label>
      <input id="s-key" type="password" placeholder="paste to set — never shown again">
      <div class="desc">Stored on this machine only, in ~/.overlord/keys.json (mode 600).</div></div>
    <div class="field"><label>Working folder</label>
      <input id="s-workdir" type="text">
      <div class="desc">The agent works on a sandboxed copy of this folder. Nothing changes until you Commit.</div></div>
    <div class="row2">
      <div class="field"><label>Sandbox</label>
        <label class="toggle"><input type="checkbox" id="s-jail"> Jail + offline (kernel backend)</label>
        <div class="desc" id="jailnote"></div></div>
      <div class="field"><label>Max steps per message</label>
        <input id="s-maxturns" type="number" min="1" max="200"></div>
    </div>
    <div class="modal-acts">
      <span class="act-msg right-auto" id="setmsg"></span>
      <button class="closebtn" id="closesettings">Close</button>
      <button class="savebtn" id="savesettings">Save</button>
    </div>
  </div>
</div>

<script nonce="__NONCE__">
const $ = id => document.getElementById(id);
const j = (u, o) => fetch(u, o).then(r => r.json());
let SEL = null, FROM = 0, POLL = null, RUNNING = false, SETTINGS = {};

function el(tag, cls, text){ const e=document.createElement(tag); if(cls)e.className=cls;
  if(text!=null)e.textContent=text; return e; }

async function loadSettings(){ SETTINGS = await j('/api/settings');
  $('backend').textContent = SETTINGS.backend + ' backend';
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

function renderMsg(m){
  const s = $('stream');
  if(m.type==='user'||m.type==='assistant'){
    const w = el('div','msg '+m.type);
    w.appendChild(el('div','who', m.type==='user'?'you':'agent'));
    w.appendChild(el('div','bub', m.text||''));
    s.appendChild(w);
  } else if(m.type==='tool_call'){
    const t = el('div','tool'); t.dataset.id = m.id||'';
    const th = el('div','th');
    th.appendChild(el('span','arrow','↳'));
    th.appendChild(el('span','tl', m.tool));
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
  } else if(m.type==='note'){
    s.appendChild(el('div','note', m.text));
  } else if(m.type==='error'){
    s.appendChild(el('div','note err', m.text));
  }
}

function setThinking(on){
  RUNNING = on;
  $('send').disabled = on;
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
  d.messages.forEach(renderMsg);
  $('inspector').innerHTML = d.inspector;
  FROM = d.event_count||0;
  setThinking(d.running);
  loadConvs();
  scroll();
  if(d.running) startPoll();
}

function showComposer(on){ $('input').placeholder = SEL ? 'Reply, or ask for a change…' : 'Tell the agent what to do…'; }

function newChat(){
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
    inp.value=''; autosize();
    const r = await j('/api/chats',{method:'POST',body:JSON.stringify({message:text,target:folder})});
    if(r.error){ flashHint(r.error,true); return; }
    await select(r.sid);
    startPoll();
  } else {
    inp.value=''; autosize();
    const st=$('stream'); const wm=el('div','msg user');
    wm.appendChild(el('div','who','you')); wm.appendChild(el('div','bub',text)); st.appendChild(wm); scroll();
    const r = await j('/api/chats/'+encodeURIComponent(SEL)+'/message',
                      {method:'POST',body:JSON.stringify({message:text})});
    if(r.error){ flashHint(r.error,true); return; }
    setThinking(true); startPoll();
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
  if(!d.running){ setThinking(false); stopPoll(); loadConvs(); }
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
document.addEventListener('click', e=>{
  const b = e.target.closest('[data-commit],[data-discard],[data-review]');
  if(!b) return;
  if(b.dataset.commit!==undefined) return insAction('/api/session/'+encodeURIComponent(b.dataset.commit)+'/commit');
  if(b.dataset.discard!==undefined) return insAction('/api/session/'+encodeURIComponent(b.dataset.discard)+'/rollback');
  if(b.dataset.review!==undefined){ const m=$('actmsg'); if(m){m.textContent='asking a second model…';m.className='act-msg';}
    return insAction('/api/session/'+encodeURIComponent(b.dataset.review)+'/review',
                     {provider: SETTINGS.provider==='openai'?'anthropic':'openai'}); }
});

// settings modal
async function openSettings(msg){
  await loadSettings();
  $('s-provider').value = SETTINGS.provider;
  $('s-model').value = SETTINGS.model||'';
  $('s-model').placeholder = SETTINGS.default_model||'default';
  $('s-workdir').value = SETTINGS.workdir||'';
  $('s-jail').checked = !!SETTINGS.jail;
  $('s-jail').disabled = !SETTINGS.jail_available;
  $('jailnote').textContent = SETTINGS.jail_available ? 'Full containment is available.'
    : 'This machine has the cooperative backend; the jail is unavailable.';
  $('s-maxturns').value = SETTINGS.max_turns;
  keystate();
  $('setmsg').textContent = msg||''; $('setmsg').className='act-msg'+(msg?' bad':'');
  $('settings').classList.add('open');
}
function keystate(){ const has = SETTINGS.keys && SETTINGS.keys[$('s-provider').value];
  const k=$('keystate'); k.textContent = has?'set':'not set'; k.className='keystate '+(has?'set':'unset'); }
async function saveSettings(){
  const body = {provider:$('s-provider').value, model:$('s-model').value.trim(),
    workdir:$('s-workdir').value.trim(), jail:$('s-jail').checked,
    max_turns:Number($('s-maxturns').value)||40};
  const key = $('s-key').value.trim(); if(key) body.key=key;
  const r = await j('/api/settings',{method:'PUT',body:JSON.stringify(body)});
  if(r.error){ $('setmsg').textContent=r.error; $('setmsg').className='act-msg bad'; return; }
  $('s-key').value=''; SETTINGS=r; await loadSettings(); keystate();
  $('setmsg').textContent='saved'; $('setmsg').className='act-msg ok';
  $('backend').textContent = SETTINGS.backend+' backend';
  if(!SEL) newChat();
}

function autosize(){ const t=$('input'); t.style.height='auto'; t.style.height=Math.min(180,t.scrollHeight)+'px'; }

$('send').addEventListener('click',send);
$('stop').addEventListener('click',stop);
$('new').addEventListener('click',newChat);
$('opensettings').addEventListener('click',()=>openSettings());
$('closesettings').addEventListener('click',()=>$('settings').classList.remove('open'));
$('savesettings').addEventListener('click',saveSettings);
$('s-provider').addEventListener('change',()=>{ $('s-model').placeholder=(SETTINGS.models||{})[$('s-provider').value]||'default'; keystate(); });
$('togglerail').addEventListener('click',()=>$('app').classList.toggle('show-rail'));
$('toggleins').addEventListener('click',()=>$('app').classList.toggle('show-ins'));
$('input').addEventListener('input',autosize);
$('input').addEventListener('keydown',e=>{ if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();send();} });

(async ()=>{ await loadSettings(); await loadConvs();
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
        sid = start_conversation(req.get("message", ""), req.get("target") or None)
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
    return False


def handle_put(handler, path, body_text):
    if path == "/api/settings":
        try:
            incoming = json.loads(body_text or "{}")
        except ValueError:
            raise core.OverlordError("error: settings must be JSON")
        save_settings(incoming)
        handler._send(settings_public())
        return True
    return False
