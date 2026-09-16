#!/usr/bin/env python3
"""OVERLORD audit — one tamper-evident line per consequential act.

Sessions already keep their own records (meta, transcript, provenance).
This is the machine-wide index of who did what: every open, commit,
rollback, rewind, fork, review verdict, connector decision, memory
acceptance, policy or connector-config change, sign-in (and failure),
account change, budget stop and gc run — from the CLI, the daemon or the
web UI alike, since they all go through the same engine calls.

  ~/.overlord/audit.jsonl   append-only. Each line carries the hash of the
                            line before it (sha256 over prev + the entry),
                            so a removed, altered or reordered line breaks
                            the chain from that point on.

    overlord audit [-n N] [--action prefix] [--json]
    overlord audit verify           # walks the chain; names the first break

The actor is the signed-in account when there is one, else the session's
owner for work done on its behalf, else the OS user running the command.
"""

import getpass
import hashlib
import json
import os
import threading
import time

import overlord as core

AUDIT_FILE = os.path.join(core.OVERLORD_HOME, "audit.jsonl")
GENESIS = "0" * 64
_LOCK = threading.Lock()
_STATE = {"seq": None, "hash": None, "size": None}


def _canon(entry):
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash(prev, entry):
    return hashlib.sha256((prev + "\n" + _canon(entry)).encode()).hexdigest()


def _tail():
    """(seq, hash) of the last line, reading only the end of the file."""
    try:
        size = os.path.getsize(AUDIT_FILE)
    except OSError:
        return 0, GENESIS
    if _STATE["size"] == size and _STATE["hash"]:
        return _STATE["seq"], _STATE["hash"]
    with open(AUDIT_FILE, "rb") as f:
        back = min(size, 65536)
        f.seek(size - back)
        chunk = f.read().splitlines()
    for line in reversed(chunk):
        if line.strip():
            try:
                last = json.loads(line)
                return int(last["seq"]), str(last["hash"])
            except (ValueError, KeyError, TypeError):
                break
    return 0, GENESIS


def actor_name(owner=None):
    try:
        import auth
        p = auth.current()
        if p:
            return f"{p['user']}@{p['via']}"
    except ImportError:
        pass
    if owner:
        return f"{owner}@session"
    try:
        return f"os:{getpass.getuser()}"
    except (KeyError, OSError):
        return "os:?"


def record(action, **fields):
    """Append one entry. Never raises into the caller's work: an audit line
    that cannot be written is reported on stderr, not allowed to fail a commit."""
    entry = {"ts": time.strftime(core.TS_FORMAT), "action": action,
             "actor": fields.pop("actor", None) or actor_name(fields.get("owner"))}
    entry.update({k: v for k, v in fields.items() if v is not None})
    try:
        os.makedirs(core.OVERLORD_HOME, exist_ok=True)
        with _LOCK:
            seq, prev = _tail()
            entry["seq"] = seq + 1
            entry["prev"] = prev
            entry["hash"] = _hash(prev, entry)
            with open(AUDIT_FILE, "a") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                f.flush()
            _STATE.update(seq=entry["seq"], hash=entry["hash"], size=os.path.getsize(AUDIT_FILE))
    except OSError as e:
        import sys
        print(f"audit: could not write {AUDIT_FILE}: {e}", file=sys.stderr)
    return entry


def entries(n=50, action=None, since=None):
    if not os.path.isfile(AUDIT_FILE):
        return []
    out = []
    with open(AUDIT_FILE) as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                out.append({"seq": None, "action": "?corrupt", "raw": line.strip()[:200]})
                continue
            if action and not str(e.get("action", "")).startswith(action):
                continue
            if since and (e.get("ts") or "") < since:
                continue
            out.append(e)
    return out[-n:] if n else out


def verify():
    """Walk the whole chain. {'ok', 'entries', 'broken_at', 'reason'}."""
    if not os.path.isfile(AUDIT_FILE):
        return {"ok": True, "entries": 0, "broken_at": None, "reason": "no audit log yet"}
    prev, n = GENESIS, 0
    with open(AUDIT_FILE) as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except ValueError:
                return {"ok": False, "entries": n, "broken_at": lineno, "reason": "unparseable line"}
            h = e.get("hash")
            body = {k: v for k, v in e.items() if k != "hash"}
            if e.get("seq") != n + 1:
                return {"ok": False, "entries": n, "broken_at": lineno,
                        "reason": f"sequence jumps to {e.get('seq')} (expected {n + 1})"}
            if e.get("prev") != prev:
                return {"ok": False, "entries": n, "broken_at": lineno, "reason": "previous hash mismatch"}
            if _hash(prev, body) != h:
                return {"ok": False, "entries": n, "broken_at": lineno, "reason": "entry hash mismatch"}
            prev, n = h, n + 1
    return {"ok": True, "entries": n, "broken_at": None, "reason": None}


# ---------------------------------------------------------------- cli


def cmd_audit(args):
    if args.audit_cmd == "verify":
        v = verify()
        if v["ok"]:
            print(f"audit chain intact: {v['entries']} entries")
            return 0
        print(f"AUDIT CHAIN BROKEN at line {v['broken_at']} ({v['reason']}); "
              f"{v['entries']} entries verified before it")
        return 1
    rows = entries(args.n, args.action)
    if not rows:
        print("no audit entries")
        return 0
    for e in rows:
        if args.json:
            print(json.dumps(e))
            continue
        extra = {k: v for k, v in e.items()
                 if k not in ("ts", "action", "actor", "seq", "prev", "hash")}
        print(f"{e.get('seq', '?'):>6}  {e.get('ts', '')}  {str(e.get('actor', '')):18} "
              f"{e.get('action', ''):22} " + " ".join(f"{k}={_short(v)}" for k, v in extra.items()))
    return 0


def _short(v):
    s = json.dumps(v) if not isinstance(v, str) else v
    return s if len(s) <= 60 else s[:57] + "..."


def add_audit_parser(sub):
    pa = sub.add_parser("audit", help="the tamper-evident log of consequential acts")
    asub = pa.add_subparsers(dest="audit_cmd")
    asub.add_parser("verify", help="walk the hash chain")
    pa.add_argument("-n", type=int, default=50)
    pa.add_argument("--action", help="only actions with this prefix (session., auth., users. ...)")
    pa.add_argument("--json", action="store_true")
    pa.set_defaults(fn=cmd_audit)
