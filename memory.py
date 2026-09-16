#!/usr/bin/env python3
"""OVERLORD memory — what the agent knows before the first message, and how
that knowledge is allowed to change.

Three sources, all injected into the system prompt, all capped:

  project memory   OVERLORD.md at the root of the working folder. Notes about
                   this codebase: conventions, commands, things learned. The
                   agent may extend it with the `remember` tool — INSIDE the
                   transaction, so the change shows in the diff, carries a
                   savepoint and a cause, and is committed or discarded with
                   everything else. Memory is a file the person reviews.
  user memory      ~/.overlord/memory.md. Notes about the person and their
                   preferences, across every folder. The agent cannot write
                   it: `remember` with scope "user" only proposes, and the
                   person accepts the suggestion (workspace button, or
                   `overlord memory accept`). Nothing outside a transaction
                   changes without a human hand.
  journal          ~/.overlord/journal/<folder-hash>.jsonl. One line per
                   committed agent session in a folder: the task, what the
                   model said it did, which files changed. Derived from the
                   engine's own records at commit time, never written by the
                   model, so "recent work in this folder" is always true.

    overlord memory show [-t <dir>]        # what the agent would be told
    overlord memory user                   # print user memory
    overlord memory user --set-file F      # replace it
    overlord memory accept <sid> [--all]   # accept a session's suggestions
    overlord memory journal [-t <dir>]     # recent committed work here
"""

import hashlib
import json
import os
import time

import overlord as core

PROJECT_FILE = "OVERLORD.md"
USER_FILE = os.path.join(core.OVERLORD_HOME, "memory.md")
JOURNAL_DIR = os.path.join(core.OVERLORD_HOME, "journal")
PROJECT_CAP = 12_000       # chars of project memory shown to the model
USER_CAP = 4_000
JOURNAL_ENTRIES = 8
JOURNAL_CAP = 4_000

REMEMBER_TOOL = {
    "name": "remember",
    "description": ("Write a durable note. scope 'project' appends to OVERLORD.md in the "
                    "project root (part of this transaction — reviewed and committed with "
                    "your other changes); scope 'user' proposes a note about the person's "
                    "preferences, which they must accept. Keep notes short and factual."),
    "input_schema": {"type": "object",
                     "properties": {"scope": {"type": "string", "enum": ["project", "user"]},
                                    "text": {"type": "string"}},
                     "required": ["scope", "text"]},
}


def _read(path, cap):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return "", False
    if len(text) > cap:
        return text[:cap] + f"\n… [{len(text) - cap} more characters not shown]", True
    return text, False


def project_memory(target):
    """(text, truncated) from OVERLORD.md in the folder, if any."""
    return _read(os.path.join(target, PROJECT_FILE), PROJECT_CAP)


def user_file(owner=None):
    """Whose notes: a named account's, else the person serving this request
    (accounts on), else the shared file."""
    import auth
    if owner:
        return os.path.join(auth.user_dir(owner), "memory.md")
    return auth.user_path("memory.md", USER_FILE)


def user_memory(owner=None):
    return _read(user_file(owner), USER_CAP)


def set_user_memory(text, owner=None):
    path = user_file(owner)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def append_user_memory(line, owner=None):
    cur, _ = _read(user_file(owner), 10**9)
    text = cur.rstrip("\n") + ("\n" if cur.strip() else "") + line.strip() + "\n"
    set_user_memory(text, owner)


# ---------------------------------------------------------------- journal


def _journal_path(target):
    h = hashlib.sha256(os.path.realpath(target).encode()).hexdigest()[:16]
    return os.path.join(JOURNAL_DIR, f"{h}.jsonl")


def journal_entries(target, n=JOURNAL_ENTRIES):
    path = _journal_path(target)
    if not os.path.isfile(path):
        return []
    with open(path) as f:
        rows = [json.loads(line) for line in f if line.strip()]
    return rows[-n:]


def journal_record(meta, final=None):
    """Append a committed agent session to its folder's journal. Called by
    commit; derived from the engine's records, never from the model."""
    if not meta.get("agent") or not meta.get("target"):
        return None
    sid = meta["id"]
    if final is None:
        final = _last_assistant_text(sid)
    changed = []
    prov = core.session_file(sid, core.PROVENANCE_FILE)
    if os.path.isfile(prov):
        with open(prov) as f:
            changed = [json.loads(line)["path"] for line in f if line.strip()]
    entry = {"ts": meta.get("committed") or time.strftime(core.TS_FORMAT), "session": sid,
             "task": (meta.get("task") or "")[:300], "agent": meta.get("agent"),
             "outcome": " ".join((final or "").split())[:400], "changed": changed[:40]}
    os.makedirs(JOURNAL_DIR, exist_ok=True)
    with open(_journal_path(meta["target"]), "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def _last_assistant_text(sid):
    path = core.session_file(sid, "transcript.jsonl")
    if not os.path.isfile(path):
        return ""
    last = ""
    with open(path) as f:
        for line in f:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("type") == "assistant" and ev.get("text"):
                last = ev["text"]
    return last


# ---------------------------------------------------------------- suggestions


def suggestions(sid):
    """User-scope notes a session proposed, with whether each was accepted."""
    path = core.session_file(sid, "transcript.jsonl")
    out, accepted = [], set()
    if not os.path.isfile(path):
        return out
    with open(path) as f:
        for line in f:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("type") == "memory_suggestion":
                out.append({"id": ev.get("id"), "text": ev.get("text", ""), "turn": ev.get("turn")})
            elif ev.get("type") == "memory_accepted":
                accepted.add(ev.get("id"))
    for s in out:
        s["accepted"] = s["id"] in accepted
    return out


def accept_suggestion(sid, suggestion_id):
    """A person accepts a proposed user-memory note: it is appended to user
    memory and the acceptance is recorded in the session's transcript."""
    for s in suggestions(sid):
        if s["id"] == suggestion_id:
            if s["accepted"]:
                return s
            owner = core.load_meta(sid).get("owner")
            append_user_memory(s["text"], owner=owner)
            import audit
            audit.record("memory.accept", sid=sid, owner=owner, suggestion=suggestion_id)
            with open(core.session_file(sid, "transcript.jsonl"), "a") as f:
                f.write(json.dumps({"ts": time.strftime(core.TS_FORMAT), "type": "memory_accepted",
                                    "id": suggestion_id}) + "\n")
            s["accepted"] = True
            return s
    raise core.OverlordError("error: no such memory suggestion")


# ---------------------------------------------------------------- context


def build_context(target, owner=None):
    """The memory block appended to the system prompt, and a summary of
    what went into it (recorded on the session so the record shows what
    the model was told). owner: whose notes, when accounts are on."""
    parts, summary = [], {}
    pm, ptrunc = project_memory(target)
    if pm.strip():
        parts.append(f"## Project notes (OVERLORD.md in the project root)\n{pm.strip()}")
        summary["project_chars"] = len(pm)
    um, utrunc = user_memory(owner)
    if um.strip():
        parts.append("## About the person you are working for (their notes; do not "
                     f"contradict them)\n{um.strip()}")
        summary["user_chars"] = len(um)
    rows = journal_entries(target)
    if rows:
        lines = []
        for r in rows:
            lines.append(f"- {r.get('ts', '')[:10]} — task: {r.get('task', '')}"
                         + (f" — outcome: {r.get('outcome', '')[:160]}" if r.get("outcome") else "")
                         + (f" — changed: {', '.join(r.get('changed', [])[:6])}" if r.get("changed") else ""))
        block = "\n".join(lines)
        if len(block) > JOURNAL_CAP:
            block = block[:JOURNAL_CAP] + "\n…"
        parts.append("## Recent committed work in this folder (from the engine's records)\n" + block)
        summary["journal_entries"] = len(rows)
    if not parts:
        return "", summary
    text = ("\n\n# Memory\nUse the `remember` tool for durable notes: scope 'project' "
            "for facts about this codebase (they land in OVERLORD.md inside this "
            "transaction), scope 'user' to propose a note about the person (they decide).\n\n"
            + "\n\n".join(parts))
    return text, summary


# ---------------------------------------------------------------- CLI


def cmd_memory(args):
    if args.mem_cmd == "show":
        target = os.path.realpath(args.target or os.getcwd())
        text, summary = build_context(target)
        print(text.strip() if text else "(no memory: no OVERLORD.md here, no user notes, no journal)")
        return 0
    if args.mem_cmd == "user":
        if args.set_file:
            with open(args.set_file, encoding="utf-8") as f:
                set_user_memory(f.read())
            print(f"user memory replaced from {args.set_file}")
            return 0
        if args.add:
            append_user_memory(args.add)
            print("noted")
            return 0
        text, _ = user_memory()
        print(text.rstrip() if text.strip() else f"(empty — {user_file()})")
        return 0
    if args.mem_cmd == "journal":
        target = os.path.realpath(args.target or os.getcwd())
        rows = journal_entries(target, n=args.n)
        if not rows:
            print("no committed agent sessions recorded for this folder")
            return 0
        for r in rows:
            print(f"{r.get('ts', '')}  {r.get('session', '')}  {r.get('task', '')}")
            if r.get("outcome"):
                print(f"    {r['outcome'][:200]}")
            if r.get("changed"):
                print(f"    changed: {', '.join(r['changed'][:8])}")
        return 0
    if args.mem_cmd == "accept":
        core.load_meta(args.session)
        subs = suggestions(args.session)
        if not subs:
            print("no memory suggestions in that session")
            return 0
        chosen = subs if args.all else [s for s in subs if s["id"] in (args.id or [])]
        if not chosen:
            for s in subs:
                print(f"  [{s['id']}] {'accepted ' if s['accepted'] else 'proposed '} {s['text']}")
            print("pass --all or --id <id> to accept")
            return 0
        for s in chosen:
            accept_suggestion(args.session, s["id"])
            print(f"accepted: {s['text']}")
        return 0
    raise core.OverlordError("error: unknown memory subcommand")


def add_memory_parser(sub):
    pm = sub.add_parser("memory", help="what the agent is told up front, and how it may change")
    ms = pm.add_subparsers(dest="mem_cmd", required=True)
    ps = ms.add_parser("show", help="the memory block for a folder")
    ps.add_argument("-t", "--target")
    pu = ms.add_parser("user", help="user memory (~/.overlord/memory.md)")
    pu.add_argument("--set-file", help="replace user memory with this file's contents")
    pu.add_argument("--add", help="append a line")
    pj = ms.add_parser("journal", help="recent committed agent sessions in a folder")
    pj.add_argument("-t", "--target")
    pj.add_argument("-n", type=int, default=JOURNAL_ENTRIES)
    pa = ms.add_parser("accept", help="accept a session's proposed user-memory notes")
    pa.add_argument("session")
    pa.add_argument("--all", action="store_true")
    pa.add_argument("--id", action="append")
    pm.set_defaults(fn=cmd_memory)
