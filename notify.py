#!/usr/bin/env python3
"""OVERLORD webhooks — tell the team when something needs a person.

A webhook subscribes to audit actions (audit.py is the machine's index of
consequential acts, so nothing new has to be invented to notify about
one). Two acts exist because of this module: `session.needs_review`, when
an agent session finishes with changes waiting for a person, and
`connector.approval_requested`, when an external action waits at the
approval gate — a gate nobody is told about is a gate that stalls.

  ~/.overlord/webhooks.json   {"base_url": "https://overlord.example",
                               "hooks": [{"name", "url", "events": [...],
                                          "format": "slack"|"json", "secret"}]}

Delivery is a JSON POST from a background thread, three attempts with
backoff, never on the caller's path. `format: slack` sends {"text": …}
that Slack-compatible incoming webhooks (Slack, Mattermost, Discord's
/slack endpoint, Teams via a flow) render; `json` sends the audit entry
with a `text` line and, when a secret is set, `X-Overlord-Signature:
sha256=<hmac of the body>` so the receiver can check it came from here.

    overlord webhooks add team https://hooks.slack.com/… --event session.needs_review \\
        --event connector.approval_requested --event budget.stop
    overlord webhooks list | test <name> | rm <name>
"""

import hashlib
import hmac
import json
import os
import queue
import sys
import threading
import time
import urllib.error
import urllib.request

import overlord as core

CONFIG_FILE = os.path.join(core.OVERLORD_HOME, "webhooks.json")
FORMATS = ("slack", "json")
DEFAULT_EVENTS = ["session.needs_review", "connector.approval_requested", "budget.stop"]
KNOWN_EVENTS = DEFAULT_EVENTS + ["session.commit", "session.commit_refused", "session.rollback",
                                 "review.verdict", "auth.login_failed", "auth.sso_refused", "gc"]
ATTEMPTS = 3
_Q = queue.Queue()
_WORKER = {"thread": None}
_LOCK = threading.Lock()
_STATS = {"sent": 0, "failed": 0, "last_error": None}


# ---------------------------------------------------------------- config


def load_config():
    try:
        with open(CONFIG_FILE) as f:
            c = json.load(f)
    except (OSError, ValueError):
        return {"base_url": "", "hooks": []}
    hooks = []
    for h in c.get("hooks") or []:
        if isinstance(h, dict) and h.get("name") and h.get("url"):
            hooks.append({"name": str(h["name"]), "url": str(h["url"]),
                          "events": [str(e) for e in (h.get("events") or DEFAULT_EVENTS)],
                          "format": h.get("format") if h.get("format") in FORMATS else "slack",
                          "secret": h.get("secret") or ""})
    return {"base_url": str(c.get("base_url") or "").rstrip("/"), "hooks": hooks}


def save_config(c):
    os.makedirs(core.OVERLORD_HOME, exist_ok=True)
    tmp = CONFIG_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(c, f, indent=2)
    os.replace(tmp, CONFIG_FILE)


def public():
    c = load_config()
    return {"base_url": c["base_url"], "known_events": KNOWN_EVENTS,
            "hooks": [{k: v for k, v in h.items() if k != "secret"} | {"has_secret": bool(h["secret"])}
                      for h in c["hooks"]], "stats": dict(_STATS)}


def add_hook(name, url, events=None, fmt="slack", secret=""):
    name = (name or "").strip()
    if not name or len(name) > 40:
        raise core.OverlordError("error: a webhook needs a short name")
    if not (url or "").startswith(("https://", "http://")):
        raise core.OverlordError("error: the webhook URL must be http(s)")
    if fmt not in FORMATS:
        raise core.OverlordError(f"error: format must be one of {', '.join(FORMATS)}")
    events = [e for e in (events or DEFAULT_EVENTS) if e]
    c = load_config()
    if any(h["name"] == name for h in c["hooks"]):
        raise core.OverlordError(f"error: webhook exists: {name}")
    c["hooks"].append({"name": name, "url": url, "events": events, "format": fmt, "secret": secret or ""})
    save_config(c)
    import audit
    audit.record("webhook.config", op="add", hook=name, events=events)
    return c["hooks"][-1]


def remove_hook(name):
    c = load_config()
    if not any(h["name"] == name for h in c["hooks"]):
        raise core.OverlordError(f"error: no webhook named {name}")
    c["hooks"] = [h for h in c["hooks"] if h["name"] != name]
    save_config(c)
    import audit
    audit.record("webhook.config", op="remove", hook=name)


def set_base_url(url):
    c = load_config()
    c["base_url"] = (url or "").rstrip("/")
    save_config(c)


# ---------------------------------------------------------------- text


def text_for(entry, base_url=""):
    """One human line for an audit entry, with a link when we know the host."""
    a = entry.get("action", "")
    sid = entry.get("sid")
    who = entry.get("owner") or entry.get("user") or entry.get("actor") or "someone"
    link = f" {base_url}/?sid={sid}" if (base_url and sid) else (f" [{sid}]" if sid else "")
    t = entry.get("target")
    where = f" in {t}" if t else ""
    if a == "session.needs_review":
        return (f"OVERLORD: {who}'s agent finished{where} — {entry.get('files', '?')} file(s) changed, "
                f"waiting for review.{link}")
    if a == "connector.approval_requested":
        return (f"OVERLORD: {who}'s agent wants to run {entry.get('server')}.{entry.get('tool')} "
                f"(an external action) — waiting for approval.{link}")
    if a == "budget.stop":
        return f"OVERLORD: budget stop for {who}: {entry.get('reason', '')}{link}"
    if a == "session.commit":
        return f"OVERLORD: {who} committed {entry.get('files', '?')} file(s){where}.{link}"
    if a == "session.commit_refused":
        return f"OVERLORD: a commit{where} was refused ({entry.get('why')}).{link}"
    if a == "session.rollback":
        return f"OVERLORD: {who} discarded a session{where}.{link}"
    if a == "review.verdict":
        return (f"OVERLORD: second model {entry.get('reviewer')} {entry.get('verdict')}ed "
                f"a session.{link}")
    if a == "auth.login_failed":
        return f"OVERLORD: failed sign-in for {entry.get('user')} from {entry.get('remote')}."
    if a == "auth.sso_refused":
        return f"OVERLORD: SSO sign-in refused for {entry.get('user')}: {entry.get('reason')}."
    if a == "gc":
        return (f"OVERLORD: gc removed {entry.get('sessions')} record(s), "
                f"{entry.get('objects')} object(s).")
    if a == "webhook.test":
        return f"OVERLORD: test message for webhook {entry.get('hook')} — delivery works."
    extra = {k: v for k, v in entry.items()
             if k not in ("ts", "action", "actor", "seq", "prev", "hash")}
    return f"OVERLORD: {a} by {entry.get('actor')} " + json.dumps(extra)[:300]


# ---------------------------------------------------------------- delivery


def dispatch(entry):
    """Called by audit.record for every entry. Queues; never blocks."""
    c = load_config()
    if not c["hooks"]:
        return 0
    n = 0
    for h in c["hooks"]:
        if entry.get("action") in h["events"]:
            _Q.put((h, entry, c["base_url"]))
            n += 1
    if n:
        _ensure_worker()
    return n


def _ensure_worker():
    with _LOCK:
        t = _WORKER["thread"]
        if t is None or not t.is_alive():
            t = threading.Thread(target=_worker, name="overlord-webhooks", daemon=True)
            _WORKER["thread"] = t
            t.start()
            if not _WORKER.get("atexit"):
                import atexit
                atexit.register(wait_idle, 8)      # a CLI command must not exit mid-delivery
                _WORKER["atexit"] = True


def _worker():
    while True:
        try:
            hook, entry, base_url = _Q.get(timeout=30)
        except queue.Empty:
            return
        try:
            deliver(hook, entry, base_url)
            _STATS["sent"] += 1
        except Exception as e:      # noqa: BLE001 — a webhook must never take the server down
            _STATS["failed"] += 1
            _STATS["last_error"] = f"{hook['name']}: {e}"
            print(f"webhook {hook['name']}: {e}", file=sys.stderr)
        finally:
            _Q.task_done()


def payload_for(hook, entry, base_url):
    text = text_for(entry, base_url)
    if hook["format"] == "slack":
        return json.dumps({"text": text}).encode()
    body = {k: v for k, v in entry.items() if k not in ("prev", "hash")}
    body["text"] = text
    if base_url and entry.get("sid"):
        body["link"] = f"{base_url}/?sid={entry['sid']}"
    return json.dumps(body).encode()


def signature(hook, body):
    import vault as vault_mod
    secret = vault_mod.resolve(hook["secret"])        # may be a secret:// reference
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def deliver(hook, entry, base_url="", attempts=ATTEMPTS):
    body = payload_for(hook, entry, base_url)
    headers = {"Content-Type": "application/json", "User-Agent": f"overlord/{core.VERSION}",
               "X-Overlord-Event": entry.get("action", "")}
    if hook.get("secret"):
        headers["X-Overlord-Signature"] = signature(hook, body)
    last, tries = None, 0
    for i in range(attempts):
        tries += 1
        try:
            req = urllib.request.Request(hook["url"], data=body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10) as r:
                if 200 <= r.status < 300:
                    return r.status
                last = f"status {r.status}"
        except urllib.error.HTTPError as e:
            last = f"status {e.code}"
            if 400 <= e.code < 500 and e.code != 429:
                break                    # our fault or theirs; retrying will not help
        except (urllib.error.URLError, OSError) as e:
            last = str(e)
        if i < attempts - 1:
            time.sleep(0.5 * (2 ** i))
    raise core.OverlordError(f"delivery failed after {tries} attempt(s): {last}")


def wait_idle(timeout=10):
    """For tests and `webhooks test`: block until the queue drains."""
    end = time.time() + timeout
    while time.time() < end:
        if _Q.unfinished_tasks == 0:
            return True
        time.sleep(0.05)
    return False


def send_test(name):
    c = load_config()
    hook = next((h for h in c["hooks"] if h["name"] == name), None)
    if not hook:
        raise core.OverlordError(f"error: no webhook named {name}")
    entry = {"ts": time.strftime(core.TS_FORMAT), "action": "webhook.test", "actor": "test",
             "hook": name}
    return deliver(hook, entry, c["base_url"])


# ---------------------------------------------------------------- cli


def cmd_webhooks(args):
    c = args.wh_cmd
    if c == "add":
        secret = sys.stdin.readline().rstrip("\n") if args.secret_stdin else ""
        h = add_hook(args.name, args.url, args.event, args.format, secret)
        print(f"added webhook {h['name']} ({h['format']}): " + ", ".join(h["events"]))
        return 0
    if c == "list":
        cfg = load_config()
        if cfg["base_url"]:
            print(f"links point at {cfg['base_url']}")
        if not cfg["hooks"]:
            print("no webhooks; events available: " + ", ".join(KNOWN_EVENTS))
            return 0
        for h in cfg["hooks"]:
            print(f"  {h['name']:16} {h['format']:6} {'signed ' if h['secret'] else ''}{h['url']}")
            print(f"  {'':16} {', '.join(h['events'])}")
        return 0
    if c == "rm":
        remove_hook(args.name)
        print(f"removed webhook {args.name}")
        return 0
    if c == "test":
        status = send_test(args.name)
        print(f"delivered a test message to {args.name} (status {status})")
        return 0
    if c == "base-url":
        set_base_url(args.url)
        print(f"links will point at {load_config()['base_url'] or '(no base URL)'}")
        return 0
    raise core.OverlordError("error: unknown webhooks subcommand")


def add_webhooks_parser(sub):
    pw = sub.add_parser("webhooks", help="tell a chat channel or a service when something needs a person")
    ws = pw.add_subparsers(dest="wh_cmd", required=True)
    pa = ws.add_parser("add")
    pa.add_argument("name")
    pa.add_argument("url")
    pa.add_argument("--event", action="append", help=f"an audit action; default {', '.join(DEFAULT_EVENTS)}")
    pa.add_argument("--format", choices=FORMATS, default="slack")
    pa.add_argument("--secret-stdin", action="store_true", help="HMAC-sign deliveries (json format)")
    ws.add_parser("list")
    ws.add_parser("rm").add_argument("name")
    ws.add_parser("test").add_argument("name")
    ws.add_parser("base-url", help="the workspace URL links should point at").add_argument("url")
    pw.set_defaults(fn=cmd_webhooks)
