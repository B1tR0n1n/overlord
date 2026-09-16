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
import hmac
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.request

import overlord as core

AUDIT_FILE = os.path.join(core.OVERLORD_HOME, "audit.jsonl")
# The chain's signing key. An unkeyed hash chain is tamper-EVIDENT only to
# someone who did not also rewrite it: the owner of the file can recompute
# every hash and forge a clean chain. Keying each link with a MAC means a
# forger needs this key too, so a rewrite by anyone without it is caught.
# The key is a local anchor: it defends against a reader who has the log but
# not the key, and (with `audit checkpoint`) lets the head be witnessed
# off-box so even the key holder cannot silently truncate or roll back.
KEY_FILE = os.path.join(core.OVERLORD_HOME, "audit.key")
GENESIS = "0" * 64
_LOCK = threading.Lock()
_STATE = {"seq": None, "hash": None, "size": None}


def audit_key(create=True):
    """The chain key (bytes), generated 0600 on first use. None if absent and
    not creating, or if it cannot be written (then the chain falls back to a
    bare hash and `verify` says the log is unsigned)."""
    try:
        with open(KEY_FILE) as f:
            return bytes.fromhex(f.read().strip())
    except (OSError, ValueError):
        if not create:
            return None
    try:
        os.makedirs(core.OVERLORD_HOME, exist_ok=True)
        key = secrets.token_bytes(32)
        fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key.hex())
        return key
    except OSError:
        return None


def _canon(entry):
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _link(prev, entry, key):
    """One chain link. A v2 entry is MAC'd with the key; a legacy entry (no
    'v') keeps the bare sha256 so old logs still verify."""
    msg = (prev + "\n" + _canon(entry)).encode()
    if key is not None and entry.get("v") == 2:
        return hmac.new(key, msg, hashlib.sha256).hexdigest()
    return hashlib.sha256(msg).hexdigest()


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
            key = audit_key()
            seq, prev = _tail()
            entry["seq"] = seq + 1
            entry["prev"] = prev
            if key is not None:
                entry["v"] = 2
            entry["hash"] = _link(prev, entry, key)
            with open(AUDIT_FILE, "a") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                f.flush()
            _STATE.update(seq=entry["seq"], hash=entry["hash"], size=os.path.getsize(AUDIT_FILE))
    except OSError as e:
        import sys
        print(f"audit: could not write {AUDIT_FILE}: {e}", file=sys.stderr)
    try:
        import notify
        notify.dispatch(entry)          # webhooks subscribe to audit actions
    except Exception as e:              # noqa: BLE001 — never on the caller's path
        import sys
        print(f"audit: webhook dispatch: {e}", file=sys.stderr)
    try:
        maybe_auto_checkpoint(action)   # off-box witness of the head, when configured
    except Exception as e:              # noqa: BLE001 — never on the caller's path
        import sys
        print(f"audit: witness: {e}", file=sys.stderr)
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
    """Walk the whole chain. {'ok', 'entries', 'broken_at', 'reason', 'keyed'}.
    `keyed` is true when the newest entry is MAC-signed. A signed entry with
    no key present, or an unsigned entry after signing has begun (a downgrade),
    breaks the chain."""
    if not os.path.isfile(AUDIT_FILE):
        return {"ok": True, "entries": 0, "broken_at": None, "reason": "no audit log yet", "keyed": False}
    key = audit_key(create=False)
    prev, n, signed_started, last_signed = GENESIS, 0, False, False
    with open(AUDIT_FILE) as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except ValueError:
                return {"ok": False, "entries": n, "broken_at": lineno, "reason": "unparseable line", "keyed": last_signed}
            h = e.get("hash")
            body = {k: v for k, v in e.items() if k != "hash"}
            if e.get("seq") != n + 1:
                return {"ok": False, "entries": n, "broken_at": lineno,
                        "reason": f"sequence jumps to {e.get('seq')} (expected {n + 1})", "keyed": last_signed}
            if e.get("prev") != prev:
                return {"ok": False, "entries": n, "broken_at": lineno, "reason": "previous hash mismatch", "keyed": last_signed}
            signed = e.get("v") == 2
            if signed:
                if key is None:
                    return {"ok": False, "entries": n, "broken_at": lineno,
                            "reason": "entry is signed but the audit key is missing", "keyed": last_signed}
                signed_started = True
            elif signed_started:
                return {"ok": False, "entries": n, "broken_at": lineno,
                        "reason": "unsigned entry after signing began (downgrade)", "keyed": last_signed}
            if _link(prev, body, key) != h:
                return {"ok": False, "entries": n, "broken_at": lineno,
                        "reason": "entry signature mismatch" if signed else "entry hash mismatch", "keyed": last_signed}
            prev, n, last_signed = h, n + 1, signed
    return {"ok": True, "entries": n, "broken_at": None, "reason": None, "keyed": last_signed}


def head():
    """The chain head to witness off-box: {seq, hash, keyed}. Empty at seq 0."""
    seq, h = _tail()
    return {"seq": seq, "hash": None if seq == 0 else h, "keyed": verify().get("keyed", False)}


def check_pin(pinned):
    """Does the live chain still carry the witnessed head? Catches a truncation
    or rewrite at or below the pinned point even by the key holder. `pinned` is
    a prior head(): {'seq', 'hash'}."""
    want_seq, want_hash = pinned.get("seq"), pinned.get("hash")
    if not want_seq or not want_hash:
        return {"ok": True, "reason": "empty pin"}
    for e in entries(n=0):
        if e.get("seq") == want_seq:
            if e.get("hash") == want_hash:
                return {"ok": True, "reason": None}
            return {"ok": False, "reason": f"entry {want_seq} was rewritten since the pin"}
    return {"ok": False, "reason": f"entry {want_seq} is gone — the log was truncated below the pin"}


# ---------------------------------------------------------------- witness
# A local key stops a forger who lacks it; it does not stop the key's holder.
# For that, send each checkpoint to an append-only witness the host does not
# control. Verifying against the witness catches a truncation or rewrite even
# by the key holder, because the witness keeps the higher sequence they would
# have to retract — and a MAC over the head proves it came from this OVERLORD,
# so a third party who can write to the witness cannot plant a head we accept.

CONFIG_FILE = os.path.join(core.OVERLORD_HOME, "audit.json")
_SENT = {"at": 0.0}                    # throttle for automatic checkpoints


def config():
    try:
        with open(CONFIG_FILE) as f:
            c = json.load(f)
        return c if isinstance(c, dict) else {}
    except (OSError, ValueError):
        return {}


def save_config(c):
    os.makedirs(core.OVERLORD_HOME, exist_ok=True)
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(c, f, indent=2)
    os.replace(tmp, CONFIG_FILE)


def signed_head():
    """The head plus a MAC over it, keyed by the audit key: what we send to a
    witness. Without the key the MAC is absent and the head is unsigned."""
    h = head()
    key = audit_key(create=False)
    if key is not None and h["hash"]:
        h["mac"] = hmac.new(key, f"{h['seq']}:{h['hash']}".encode(), hashlib.sha256).hexdigest()
    h["ts"] = time.strftime(core.TS_FORMAT)
    return h


def _witness_url(url=None):
    return url or (config().get("witness") or {}).get("url")


def send_checkpoint(url=None, headers=None, timeout=15):
    """POST the signed head to the witness. Best-effort: returns a result dict,
    never raises. Records the send locally so `witness --show` can report it."""
    w = config().get("witness") or {}
    url = url or w.get("url")
    if not url:
        return {"ok": False, "reason": "no witness configured (overlord audit witness <url>)"}
    body = json.dumps(signed_head()).encode()
    hdrs = {"Content-Type": "application/json", **(w.get("header") or {}), **(headers or {})}
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read()
            code = r.status
    except urllib.error.HTTPError as e:
        return {"ok": False, "reason": f"witness HTTP {e.code}"}
    except (urllib.error.URLError, OSError) as e:
        return {"ok": False, "reason": f"witness unreachable: {getattr(e, 'reason', e)}"}
    c = config()
    c["last_sent"] = {**signed_head(), "code": code}
    save_config(c)
    return {"ok": True, "seq": c["last_sent"]["seq"], "code": code}


def fetch_witness(url=None, headers=None, timeout=15):
    """GET the latest head the witness holds: {'seq','hash'[, 'mac']}."""
    w = config().get("witness") or {}
    url = url or w.get("url")
    if not url:
        raise core.OverlordError("error: no witness configured")
    hdrs = {**(w.get("header") or {}), **(headers or {})}
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode() or "{}")


def verify_against_witness(url=None):
    """Check the live log still carries the head the witness holds, and that
    that head was signed by this OVERLORD's key."""
    try:
        remote = fetch_witness(url)
    except (urllib.error.URLError, OSError, ValueError, core.OverlordError) as e:
        return {"ok": False, "reason": f"witness fetch failed: {getattr(e, 'reason', e)}"}
    key = audit_key(create=False)
    mac = remote.get("mac")
    if key is not None and remote.get("hash") and mac is not None:
        want = hmac.new(key, f"{remote['seq']}:{remote['hash']}".encode(), hashlib.sha256).hexdigest()
        if mac != want:
            return {"ok": False, "reason": "witnessed head is not signed by this audit key"}
    p = check_pin(remote)
    return {"ok": p["ok"], "reason": p["reason"], "seq": remote.get("seq")}


def maybe_auto_checkpoint(action):
    """Fire-and-forget checkpoint after a consequential act, throttled; only
    when a witness is configured with auto. Never on the caller's path."""
    w = config().get("witness") or {}
    if not (w.get("url") and w.get("auto")):
        return
    if not action.split(".", 1)[0] in ("session", "users", "auth", "policy", "connector", "cost"):
        return
    now = time.time()
    if now - _SENT["at"] < float(w.get("min_interval", 20)):
        return
    _SENT["at"] = now
    threading.Thread(target=send_checkpoint, daemon=True).start()


# ---------------------------------------------------------------- cli


def cmd_audit(args):
    if args.audit_cmd == "verify":
        v = verify()
        if not v["ok"]:
            print(f"AUDIT CHAIN BROKEN at line {v['broken_at']} ({v['reason']}); "
                  f"{v['entries']} entries verified before it")
            return 1
        state = "signed" if v.get("keyed") else "UNSIGNED (no key — tamper-evident only to a reader without the log)"
        print(f"audit chain intact: {v['entries']} entries, {state}")
        pin = getattr(args, "pin", None)
        if pin:
            try:
                with open(pin) as f:
                    pinned = json.load(f)
            except (OSError, ValueError) as e:
                print(f"pin unreadable: {e}")
                return 1
            p = check_pin(pinned)
            if not p["ok"]:
                print(f"PIN MISMATCH: {p['reason']}")
                return 1
            print(f"pin ok: head still carries witnessed entry {pinned.get('seq')}")
        if getattr(args, "witness", False):
            w = verify_against_witness()
            if not w["ok"]:
                print(f"WITNESS MISMATCH: {w['reason']}")
                return 1
            print(f"witness ok: the log still carries the head the witness holds (entry {w.get('seq')})")
        return 0
    if args.audit_cmd == "checkpoint":
        if getattr(args, "send", False):
            r = send_checkpoint()
            if not r["ok"]:
                print(f"checkpoint not sent: {r['reason']}")
                return 1
            print(f"checkpoint sent to the witness: entry {r['seq']} (HTTP {r['code']})")
            return 0
        h = head()
        text = json.dumps(h)
        dest = getattr(args, "file", None)
        if dest:
            with open(dest, "w") as f:
                f.write(text + "\n")
            print(f"checkpoint written: entry {h['seq']} → {dest} (store it off-box to witness the head)")
        else:
            print(text)
        return 0
    if args.audit_cmd == "witness":
        if getattr(args, "off", False):
            c = config(); c.pop("witness", None); save_config(c)
            print("witness cleared")
            return 0
        if args.url:
            headers = {}
            for h in args.header or []:
                if ":" not in h:
                    raise core.OverlordError(f"error: --header wants 'Name: value', got {h!r}")
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
            c = config()
            c["witness"] = {"url": args.url, "header": headers, "auto": bool(args.auto)}
            save_config(c)
            print(f"witness set: {args.url}" + (" (auto)" if args.auto else ""))
            return 0
        w = config().get("witness") or {}
        if not w:
            print("no witness configured (overlord audit witness <url> [--auto])")
            return 0
        print(f"witness: {w.get('url')}" + (" (auto)" if w.get("auto") else ""))
        last = config().get("last_sent")
        if last:
            print(f"  last sent: entry {last.get('seq')} at {last.get('ts')}")
        return 0
    if args.audit_cmd == "key":
        k = audit_key(create=False)
        print(f"audit key: {KEY_FILE}" + ("" if k else " (none yet — created on the first recorded act)"))
        print("copy it off-box: a rewrite of the log needs this key, and off-box it survives a host compromise")
        return 0
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
    pv = asub.add_parser("verify", help="walk the signed chain; optionally check a witnessed head")
    pv.add_argument("--pin", metavar="FILE", help="a prior `audit checkpoint` file to check the head against")
    pv.add_argument("--witness", action="store_true", help="also check the live log against the configured witness")
    pc = asub.add_parser("checkpoint", help="print the chain head to witness off-box (or write/send it)")
    pc.add_argument("file", nargs="?", help="write the head here instead of stdout")
    pc.add_argument("--send", action="store_true", help="POST the signed head to the configured witness")
    pw = asub.add_parser("witness", help="an append-only endpoint that holds the head off-box")
    pw.add_argument("url", nargs="?", help="set the witness URL (omit to show the current one)")
    pw.add_argument("--header", action="append", metavar="'Name: value'", help="a header sent to the witness")
    pw.add_argument("--auto", action="store_true", help="send a checkpoint after each consequential act")
    pw.add_argument("--off", action="store_true", help="clear the witness")
    asub.add_parser("key", help="where the chain-signing key lives; copy it off-box")
    pa.add_argument("-n", type=int, default=50)
    pa.add_argument("--action", help="only actions with this prefix (session., auth., users. ...)")
    pa.add_argument("--json", action="store_true")
    pa.set_defaults(fn=cmd_audit)
