#!/usr/bin/env python3
"""OVERLORD countersignature — a two-person rule for machines.

    overlord review <session> [--provider anthropic|openai] [--model M]
                              [--max-turns N] [--same-model]
    overlord commit --countersigned <session>

A pending session's diff is put in front of a second model that had no part
in producing it. The reviewer never touches the tree: it is handed the task,
the grant envelope, the tool-call transcript and the diff itself, plus one
read-only tool (`read_file`, served from the session's own flattened view),
and its only way to act is `approve` or `reject` with a reason.

The verdict is bound to a fingerprint of exactly what was reviewed — every
path's kind and before/after hash. Rewind, resume, or a selective commit
change that fingerprint and the signature goes stale; a stale approval does
not satisfy `--countersigned`, and a fresh rejection blocks commit unless
forced. The daemon enforces it per target with `"require_review": true` in
policy.json. Independence is checked: the reviewer must not be the model that
did the work (`--same-model` overrides, and the record says so).

The review has provenance of its own: review.jsonl holds the reviewer's
transcript, and meta["reviews"] every verdict ever given on the session.
"""

import difflib
import hashlib
import json
import os
import sys
import time

import overlord as ov
import agent as agent_mod

DEFAULT_MAX_TURNS = 12
SCRIPT_ENV = "OVERLORD_REVIEW_SCRIPT"     # a scripted reviewer reads its own script
MAX_DIFF_CHARS = 120_000      # of diff text handed to the reviewer
MAX_FILE_CHARS = 24_000       # per file in the dossier
MAX_READ_CHARS = 32_000       # per read_file answer

SYSTEM_PROMPT = """You are the countersigning reviewer inside OVERLORD, a transactional \
sandbox for AI agents. Another model was given a task and made changes to a project \
inside a transaction. Nothing has touched the real tree. Your signature decides whether \
it does.

You will receive the task, the grants the agent ran under, its tool-call transcript, \
and the full diff. You may read any file in the project as it would look after the \
change, using read_file. You cannot run anything and you cannot edit anything.

Judge whether the change does what the task asked, nothing the task did not ask, and \
nothing unsafe: no secrets or credentials written, no destructive commands, no changes \
outside the task's evident scope, no code that would obviously break the project. Be \
concrete. When you have decided, call exactly one of approve or reject with a short, \
specific reason. Do not stop without calling one of them."""

TOOLS = [
    {"name": "read_file",
     "description": "Read a text file (path relative to the project root) as it would be "
                    "after the change is applied.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}},
                      "required": ["path"]}},
    {"name": "approve",
     "description": "Countersign the change: it may be committed to the real tree.",
     "input_schema": {"type": "object", "properties": {"reason": {"type": "string"}},
                      "required": ["reason"]}},
    {"name": "reject",
     "description": "Refuse the change. Name what is wrong and, if you can, which paths.",
     "input_schema": {"type": "object",
                      "properties": {"reason": {"type": "string"},
                                     "paths": {"type": "array",
                                               "items": {"type": "string"}}},
                      "required": ["reason"]}},
]


# ---------------------------------------------------------------- what is signed


def fingerprint(sid, meta=None, layers=None):
    """sha256 over (kind, path, before, after) of the stack — what a verdict
    binds to. Any change to what would be replayed changes it."""
    meta = meta or ov.load_meta(sid)
    changes, origin, _t, uppers = ov.session_stack(sid, meta, layers)
    recs = ov.build_provenance(changes, None, meta["target"], origin, uppers)
    body = [[r["kind"], r["path"], r.get("before_sha256"), r.get("after_sha256")] for r in recs]
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def latest_review(meta):
    reviews = meta.get("reviews") or []
    return reviews[-1] if reviews else None


def review_state(sid, meta=None, layers=None):
    """(review, fresh): the most recent verdict and whether it still binds
    to what commit would replay now."""
    meta = meta or ov.load_meta(sid)
    rev = latest_review(meta)
    if rev is None:
        return None, False
    return rev, rev.get("fingerprint") == fingerprint(sid, meta, layers)


# ---------------------------------------------------------------- the dossier


def _text(data):
    if data is None:
        return None
    try:
        return data.decode()
    except UnicodeDecodeError:
        return None


def _read(path, limit=None):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    return data


def _after_path(meta, sid, rel, origin, uppers):
    """Where a path's post-change content lives: its layer, or the target."""
    if rel in origin:
        return ov._safe_join(uppers[origin[rel]], rel)
    return ov._safe_join(meta["target"], rel)


def build_dossier(sid, meta=None):
    """Everything the reviewer sees, as text, plus the stack it came from."""
    meta = meta or ov.load_meta(sid)
    changes, origin, _t, uppers = ov.session_stack(sid, meta)
    g = meta.get("grants") or {}
    lines = [f"TASK: {meta.get('task') or '(none recorded — a plain command session)'}",
             f"AGENT: {meta.get('agent') or 'command: ' + ' '.join(meta.get('cmd') or [])}",
             f"TARGET: {meta['target']}",
             "GRANTS: " + ", ".join(k for k in ("jail",) if g.get(k)) + (
                 ", net:none" if g.get("net") == "none" else ", net:host") + (
                 f", timeout {g['timeout']}s" if g.get("timeout") else ""),
             ""]
    tpath = ov.session_file(sid, "transcript.jsonl")
    if os.path.isfile(tpath):
        lines.append("TRANSCRIPT (what the agent said and did):")
        with open(tpath) as f:
            for line in f:
                ev = json.loads(line)
                t = ev.get("type")
                if t == "assistant":
                    lines.append(f"  turn {ev.get('turn')} said: {ev.get('text', '')[:400]}")
                elif t == "tool_call":
                    lines.append(f"  turn {ev.get('turn')} {ev.get('tool')}: "
                                 f"{agent_mod._summarize({'name': ev['tool'], 'input': ev.get('input') or {}})}")
                elif t == "tool_result":
                    touched = ev.get("touched") or []
                    lines.append(f"    -> exit {ev.get('exit_code')}"
                                 + (f", touched {', '.join(touched)}" if touched else ""))
                elif t in ("rewind", "resume"):
                    lines.append(f"  [{t}] {ev.get('note') or ('to savepoint @%s' % ev.get('to'))}")
        lines.append("")
    else:
        execs = meta.get("execs") or []
        lines.append("COMMANDS:")
        for e in execs:
            lines.append(f"  {' '.join(e.get('cmd') or [])}  -> exit {e.get('exit_code')}")
        lines.append("")
    external = []
    if os.path.isfile(tpath):
        with open(tpath) as f:
            for line in f:
                ev = json.loads(line)
                if ev.get("type") == "approval_decision":
                    external.append(f"  turn {ev.get('turn')} {ev.get('server')}.{ev.get('tool')}: "
                                    f"{ev.get('decision')}")
    if external:
        lines.append("EXTERNAL ACTIONS (connector tools ran on the host, outside the "
                     "transaction; a discard cannot undo them):")
        lines.extend(external)
        lines.append("")
    lines.append(f"MANIFEST ({len(changes)} change(s)):")
    for kind, rel in changes:
        lines.append(f"  {kind:12s} {rel}")
    lines.append("")
    lines.append("DIFF:")
    budget = MAX_DIFF_CHARS
    omitted = []
    for kind, rel in changes:
        if rel.endswith("/") or kind == "invalid-whiteout":
            continue
        before_p = ov._safe_join(meta["target"], rel)
        before = _text(_read(before_p)) if kind in ("modified", "deleted") and os.path.isfile(before_p) else ""
        after = ""
        if kind in ("added", "modified"):
            ap = _after_path(meta, sid, rel, origin, uppers)
            if os.path.isfile(ap) and not os.path.islink(ap):
                after = _text(_read(ap))
        if before is None or after is None:
            chunk = f"--- {rel}: binary ({kind})\n"
        elif kind == "replaced-dir":
            chunk = f"--- {rel}/: directory replaced wholesale\n"
        else:
            b = before.splitlines(keepends=True)[:2000] if before else []
            a = after.splitlines(keepends=True)[:2000] if after else []
            chunk = "".join(difflib.unified_diff(b, a, f"a/{rel}", f"b/{rel}", n=3))
            if not chunk:
                chunk = f"--- {rel}: {kind}, no textual difference\n"
            if len(chunk) > MAX_FILE_CHARS:
                chunk = chunk[:MAX_FILE_CHARS] + f"\n... [{rel}: diff truncated]\n"
                omitted.append(rel)
        if len(chunk) > budget:
            rest = [x for _k, x in changes[changes.index((kind, rel)):] if not x.endswith("/")]
            omitted.extend(x for x in rest if x not in omitted)
            lines.append(f"... [diff budget exhausted; {rel} and later files omitted — use read_file]")
            break
        budget -= len(chunk)
        lines.append(chunk.rstrip("\n"))
    if omitted:
        lines.append("\nNOTE: you have NOT seen the whole diff (" + ", ".join(omitted[:12])
                     + (", …" if len(omitted) > 12 else "") + "). An approval on a partial view does "
                     "not countersign a commit; read the omitted files in full or reject.")
    build_dossier.last_omitted = omitted
    return "\n".join(lines), (changes, origin, uppers)


# ---------------------------------------------------------------- the loop


def independent(meta, provider):
    """The reviewer must not be the model that did the work."""
    return (meta.get("agent") or "") != f"{provider.name}:{getattr(provider, 'model', '-')}"


def run_review(sid, provider, max_turns=DEFAULT_MAX_TURNS, emit=None, allow_same=False):
    """Put a pending session in front of `provider`. Returns the review
    record (also appended to meta['reviews'] and mirrored in review.jsonl)."""
    emit = emit or (lambda e: None)
    meta = ov.load_meta(sid)
    if meta.get("status") != "pending":
        raise ov.OverlordError(f"error: session is {meta.get('status')}, not pending")
    if not os.path.isdir(ov.session_file(sid, "upper")):
        raise ov.OverlordError("error: session layers are gone; nothing to review")
    same = not independent(meta, provider)
    if same and not allow_same:
        raise ov.OverlordError(
            f"error: reviewer {provider.name}:{provider.model} is the model that did the "
            "work; a countersignature needs a second model (--same-model to override)")
    dossier, (changes, origin, uppers) = build_dossier(sid, meta)
    fp = fingerprint(sid, meta)
    reviewer = f"{provider.name}:{getattr(provider, 'model', '-')}"
    log = open(ov.session_file(sid, "review.jsonl"), "a")

    def record(ev):
        ev = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "reviewer": reviewer, **ev}
        log.write(json.dumps(ev) + "\n")
        log.flush()
        emit(ev)

    def read_file(inp):
        p = agent_mod._rel_ok(inp.get("path"))
        if p is None:
            return "error: path must be relative to the project root"
        for kind, rel in changes:
            if rel == p and kind == "deleted":
                return f"error: {p} is deleted by this change"
        try:
            path = _after_path(meta, sid, p, origin, uppers)
        except ov.OverlordError as e:
            return f"error: {e}"
        if os.path.isdir(path):
            try:
                return "\n".join(sorted(os.listdir(path)))
            except OSError as e:
                return f"error: {e}"
        data = _read(path)
        if data is None:
            return f"error: no such file: {p}"
        text = _text(data)
        if text is None:
            return f"(binary, {len(data)} bytes)"
        return text if len(text) <= MAX_READ_CHARS else text[:MAX_READ_CHARS] + "\n...[truncated]"

    record({"type": "review", "session": sid, "fingerprint": fp, "same_model": same,
            "dossier_chars": len(dossier)})
    messages = [{"role": "user", "content": dossier}]
    verdict, reason, paths, usage = "abstain", "", [], {"in": 0, "out": 0}
    try:
        for turn in range(1, max_turns + 1):
            reply = provider.complete(SYSTEM_PROMPT, messages, tools=TOOLS)
            usage["in"] += reply.usage.get("in", 0)
            usage["out"] += reply.usage.get("out", 0)
            messages.append({"role": "assistant", "content": reply.text,
                             "tool_calls": reply.tool_calls})
            if reply.text:
                record({"type": "assistant", "turn": turn, "text": reply.text})
            if not reply.tool_calls:
                break
            decided = False
            for tc in reply.tool_calls:
                record({"type": "tool_call", "turn": turn, "id": tc["id"],
                        "tool": tc["name"], "input": tc["input"]})
                if tc["name"] == "read_file":
                    out = read_file(tc["input"])
                elif tc["name"] in ("approve", "reject"):
                    verdict = tc["name"]
                    reason = (tc["input"].get("reason") or "").strip()
                    paths = [str(p) for p in (tc["input"].get("paths") or [])]
                    out = f"recorded: {verdict}"
                    decided = True
                else:
                    out = f"error: unknown tool {tc['name']}"
                messages.append({"role": "tool", "tool_call_id": tc["id"],
                                 "content": out or "(empty)"})
                record({"type": "tool_result", "turn": turn, "id": tc["id"],
                        "tool": tc["name"], "output": out[:2000]})
            if decided:
                break
    finally:
        omitted = list(getattr(build_dossier, "last_omitted", []) or [])
        rec = {"reviewer": reviewer, "verdict": verdict, "reason": reason, "paths": paths,
               "fingerprint": fp, "same_model": same, "usage": usage,
               "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "changes": len(changes),
               "truncated": bool(omitted), "omitted": omitted[:40]}
        record({"type": "verdict", **rec})
        log.close()
        meta = ov.load_meta(sid)          # re-read: nothing else may be lost
        meta.setdefault("reviews", []).append(rec)
        ov.save_meta(sid, meta)
        import audit as audit_mod
        import cost as cost_mod
        audit_mod.record("review.verdict", sid=sid, owner=meta.get("owner"), reviewer=reviewer,
                         verdict=verdict, fingerprint=(fp or "")[:12])
        model_name = getattr(provider, "model", "") or ""
        cost_mod.ledger_append(sid, meta.get("owner"), model_name, usage,
                               cost_mod.cost_of(model_name, usage), kind="review")
    return rec


# ---------------------------------------------------------------- CLI


def cmd_review(args):
    ov.load_meta(args.session)
    provider = agent_mod.make_provider(args.provider, args.model, script_env=SCRIPT_ENV)

    def show(ev):
        t = ev["type"]
        if t == "review":
            print(f"overlord review: {ev['reviewer']} over session {args.session} "
                  f"(dossier {ev['dossier_chars']} chars)", file=sys.stderr)
        elif t == "assistant":
            print(f"\n{ev['text']}\n")
        elif t == "tool_call" and ev["tool"] == "read_file":
            print(f"  → read_file  {ev['input'].get('path')}")
    rec = run_review(args.session, provider, max_turns=args.max_turns, emit=show,
                     allow_same=args.same_model)
    stamp = {"approve": "APPROVED", "reject": "REJECTED"}.get(rec["verdict"], "NO VERDICT")
    print(f"\n{stamp} by {rec['reviewer']}"
          + (" (same model as the agent)" if rec["same_model"] else ""))
    if rec["reason"]:
        print(f"  {rec['reason']}")
    for p in rec["paths"]:
        print(f"    · {p}")
    if rec["verdict"] == "approve":
        print(f"\n  commit:   overlord commit --countersigned {args.session}")
        return 0
    print("\n  the signature is bound to this exact diff; change it and review again")
    return 1 if rec["verdict"] == "reject" else 2


def add_review_parser(sub):
    pr = sub.add_parser("review", help="countersignature: a second model approves or "
                                        "rejects a pending session's diff")
    pr.add_argument("session")
    pr.add_argument("--provider", choices=["anthropic", "openai", "scripted"],
                    default="anthropic")
    pr.add_argument("--model", help="reviewer model id (must differ from the agent's)")
    pr.add_argument("--max-turns", type=int, default=DEFAULT_MAX_TURNS)
    pr.add_argument("--same-model", action="store_true",
                    help="allow the reviewer to be the model that did the work")
    pr.set_defaults(fn=cmd_review)
