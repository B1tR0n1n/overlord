#!/usr/bin/env python3
"""OVERLORD auth — who is at the keyboard, and what they may do.

By default `overlord ui` binds loopback with no accounts: the person at the
machine is the operator, as before. The moment accounts exist
(`overlord users add`), every request must carry a login cookie or a
bearer token, and each person has their own conversations, keys, settings
and notes. Binding anything but loopback requires both accounts and TLS;
the server refuses to start otherwise.

  roles    admin     everything: accounts, policy, connector config, every
                     record on the machine
           operator  their own conversations (start, commit, discard,
                     rewind, fork, review), their own settings, keys and
                     notes; connectors may be used, not configured
           viewer    read-only across every record (an auditor)

  storage  ~/.overlord/users.json        mode 600: scrypt password hashes,
                                         hashed bearer tokens
           ~/.overlord/users/<name>/     that person's ui.json, keys.json,
                                         memory.md (mode 700)

  overlord users add <name> [--role r]      # prompts for a password
  overlord users passwd <name>
  overlord users role <name> <role>
  overlord users rm <name>
  overlord users list
  overlord users token <name> --name ci     # a bearer token, printed once
  overlord users tokens <name>
  overlord users untoken <token-id>
  overlord tls selfsign [--host h ...]      # a self-signed cert via openssl

Login sessions live in memory: a restart of `overlord ui` logs everyone
out. Tokens are for scripts (`Authorization: Bearer ovl_…`), hashed at
rest, revocable one by one.
"""

import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time

import overlord as core
import audit

USERS_FILE = os.path.join(core.OVERLORD_HOME, "users.json")
USERS_DIR = os.path.join(core.OVERLORD_HOME, "users")
ROLES = ("admin", "operator", "viewer")
COOKIE = "overlord_session"
SESSION_TTL = 12 * 3600          # absolute lifetime of a login
LOGIN_WINDOW = 300               # failures counted over this many seconds
LOGIN_FAILS = 5                  # ... and this many of them
LOGIN_LOCK = 60                  # ... lock the (address, name) pair this long
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
_SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)

SESSIONS_FILE = os.path.join(core.OVERLORD_HOME, "sessions.json")
_LOCK = threading.Lock()
_SESSIONS = {}                   # sha256(cookie token) -> {user, role, created}
_FAILS = {}                      # (remote, user) -> [timestamps]
_LOCAL = threading.local()       # the principal of the request being served


class Forbidden(core.OverlordError):
    """The caller is known but may not do this (HTTP 403)."""


class LoginFailed(core.OverlordError):
    """Wrong user or password (HTTP 401)."""


class TooMany(core.OverlordError):
    """Login attempts locked for a while (HTTP 429)."""


# ---------------------------------------------------------------- store


def _load():
    try:
        with open(USERS_FILE) as f:
            db = json.load(f)
    except (OSError, ValueError):
        return {"users": {}, "tokens": {}}
    db.setdefault("users", {})
    db.setdefault("tokens", {})
    return db


def _save(db):
    os.makedirs(core.OVERLORD_HOME, exist_ok=True)
    tmp = USERS_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(db, f, indent=2)
    os.replace(tmp, USERS_FILE)


def enabled():
    """Accounts exist — or single sign-on is configured — so the UI demands
    a login."""
    if _load()["users"]:
        return True
    import oidc
    return oidc.configured()


def hash_password(password):
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return f"scrypt${salt.hex()}${h.hex()}"


def verify_password(password, stored):
    try:
        algo, salt, h = (stored or "").split("$")
        if algo != "scrypt":
            return False
        cand = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), **_SCRYPT)
        return hmac.compare_digest(cand, bytes.fromhex(h))
    except (ValueError, TypeError):
        return False


def _check_name(name):
    if not _NAME_RE.match(name or ""):
        raise core.OverlordError("error: user names are 1-32 chars of a-z 0-9 . _ - (lowercase)")
    return name


def _check_role(role):
    if role not in ROLES:
        raise core.OverlordError(f"error: role must be one of {', '.join(ROLES)}")
    return role


def add_user(name, password, role="operator"):
    _check_name(name)
    _check_role(role)
    if len(password or "") < 8:
        raise core.OverlordError("error: passwords are at least 8 characters")
    with _LOCK:
        db = _load()
        if name in db["users"]:
            raise core.OverlordError(f"error: user exists: {name}")
        db["users"][name] = {"hash": hash_password(password), "role": role,
                             "created": time.strftime(core.TS_FORMAT), "disabled": False}
        _save(db)
    os.makedirs(user_dir(name), mode=0o700, exist_ok=True)
    audit.record("users.add", user=name, role=role)
    return public_user(name, db["users"][name])


def set_password(name, password):
    if len(password or "") < 8:
        raise core.OverlordError("error: passwords are at least 8 characters")
    with _LOCK:
        db = _load()
        if name not in db["users"]:
            raise core.OverlordError(f"error: no such user: {name}")
        db["users"][name]["hash"] = hash_password(password)
        _save(db)
    _drop_sessions(name)
    audit.record("users.passwd", user=name)


def set_role(name, role):
    _check_role(role)
    with _LOCK:
        db = _load()
        if name not in db["users"]:
            raise core.OverlordError(f"error: no such user: {name}")
        if role != "admin" and db["users"][name]["role"] == "admin" \
                and not any(u["role"] == "admin" and not u.get("disabled")
                            for n, u in db["users"].items() if n != name):
            raise core.OverlordError("error: that would leave no admin")
        db["users"][name]["role"] = role
        _save(db)
    _drop_sessions(name)
    audit.record("users.role", user=name, role=role)


def remove_user(name):
    with _LOCK:
        db = _load()
        if name not in db["users"]:
            raise core.OverlordError(f"error: no such user: {name}")
        if db["users"][name]["role"] == "admin" \
                and not any(u["role"] == "admin" and not u.get("disabled")
                            for n, u in db["users"].items() if n != name):
            raise core.OverlordError("error: that would remove the last admin")
        del db["users"][name]
        db["tokens"] = {t: v for t, v in db["tokens"].items() if v.get("user") != name}
        _save(db)
    _drop_sessions(name)
    audit.record("users.rm", user=name)


def public_user(name, u):
    return {"name": name, "role": u.get("role"), "created": u.get("created"),
            "disabled": bool(u.get("disabled")), "budget": u.get("budget") or {},
            "sso": u.get("sso")}


_EXT_RE = re.compile(r"^[a-z0-9][a-z0-9._@+-]{0,127}$")


def external_login(ident, role, issuer):
    """An identity the provider vouched for: provision the account on first
    sign-in (no password — the provider is the password), keep its role in
    step with the mapping, and open a login session. Returns the principal."""
    ident = (ident or "").lower()
    if not _EXT_RE.match(ident):
        raise core.OverlordError("error: unusable identity from the provider")
    _check_role(role)
    with _LOCK:
        db = _load()
        u = db["users"].get(ident)
        if u is None:
            u = {"hash": None, "role": role, "sso": issuer, "disabled": False,
                 "created": time.strftime(core.TS_FORMAT)}
            db["users"][ident] = u
            created = True
        else:
            created = False
            if u.get("disabled"):
                raise core.OverlordError(f"error: {ident} is disabled")
            if u.get("sso") and u["role"] != role:
                u["role"] = role
        _save(db)
    os.makedirs(os.path.join(USERS_DIR, ident), mode=0o700, exist_ok=True)
    tok = _open_session(ident, u["role"])
    audit.record("auth.sso_login", actor=f"{ident}@sso", user=ident, role=u["role"],
                 provisioned=created or None, issuer=issuer)
    return tok, {"user": ident, "role": u["role"], "via": "sso"}


def user_budget(name):
    """The account's own spending limits (see cost.py), {} if none."""
    return (_load()["users"].get(name) or {}).get("budget") or {}


def set_budget(name, budget):
    import cost
    clean = cost._clean_budget(budget or {})
    with _LOCK:
        db = _load()
        if name not in db["users"]:
            raise core.OverlordError(f"error: no such user: {name}")
        if clean:
            db["users"][name]["budget"] = clean
        else:
            db["users"][name].pop("budget", None)
        _save(db)
    audit.record("users.budget", user=name, budget=clean)
    return clean


def list_users():
    db = _load()
    return [public_user(n, u) for n, u in sorted(db["users"].items())]


def user_dir(name):
    if not _EXT_RE.match(name or ""):
        _check_name(name)
    path = os.path.join(USERS_DIR, name)
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


# ---------------------------------------------------------------- tokens


def create_token(name, label=""):
    """A bearer token for scripts. Returned once; only its hash is kept."""
    with _LOCK:
        db = _load()
        if name not in db["users"]:
            raise core.OverlordError(f"error: no such user: {name}")
        raw = "ovl_" + secrets.token_urlsafe(32)
        tid = hashlib.sha256(raw.encode()).hexdigest()
        db["tokens"][tid] = {"user": name, "label": label or "",
                             "created": time.strftime(core.TS_FORMAT)}
        _save(db)
    audit.record("users.token", user=name, token=tid[:12], label=label or "")
    return raw, tid[:12]


def tokens_for(name):
    db = _load()
    return [{"id": t[:12], "label": v.get("label", ""), "created": v.get("created")}
            for t, v in db["tokens"].items() if v.get("user") == name]


def revoke_token(prefix, owner=None):
    """Revoke by id prefix; with owner, only that account's tokens count."""
    with _LOCK:
        db = _load()
        hits = [t for t, v in db["tokens"].items() if t.startswith(prefix)
                and (owner is None or v.get("user") == owner)]
        if len(hits) != 1:
            raise core.OverlordError("error: no such token" if not hits else "error: ambiguous token id")
        rec = db["tokens"].pop(hits[0])
        _save(db)
    audit.record("users.untoken", user=rec.get("user"), token=hits[0][:12])


# ---------------------------------------------------------------- sessions
#
# Logins outlive a restart of `overlord ui`: the table is written to a
# mode-600 file keyed by the cookie's hash, so the file never holds a
# usable cookie. Loaded once at import; every change writes through.


def _sid(tok):
    return hashlib.sha256((tok or "").encode()).hexdigest()


def _load_sessions():
    try:
        with open(SESSIONS_FILE) as f:
            saved = json.load(f)
    except (OSError, ValueError):
        return
    now = time.time()
    with _LOCK:
        _SESSIONS.clear()
        for k, s in (saved or {}).items():
            if isinstance(s, dict) and now - float(s.get("created", 0)) <= SESSION_TTL:
                _SESSIONS[k] = s


def _save_sessions():
    """Call with _LOCK held."""
    try:
        os.makedirs(core.OVERLORD_HOME, exist_ok=True)
        tmp = SESSIONS_FILE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(_SESSIONS, f)
        os.replace(tmp, SESSIONS_FILE)
    except OSError:
        pass


def _open_session(name, role):
    tok = secrets.token_urlsafe(32)
    with _LOCK:
        _SESSIONS[_sid(tok)] = {"user": name, "role": role, "created": time.time()}
        _save_sessions()
    return tok


def _drop_sessions(name):
    with _LOCK:
        for tok in [t for t, s in _SESSIONS.items() if s["user"] == name]:
            del _SESSIONS[tok]
        _save_sessions()


def _locked(remote, name, now):
    fails = [t for t in _FAILS.get((remote, name), []) if now - t < LOGIN_WINDOW]
    _FAILS[(remote, name)] = fails
    return len(fails) >= LOGIN_FAILS and now - fails[-1] < LOGIN_LOCK


def login(name, password, remote="?"):
    """Check a password; returns (cookie token, principal). Five failures in
    five minutes lock that (address, name) pair for a minute — a slow brute
    force is the realistic attack on a small team's password file."""
    name = str(name or "")
    now = time.time()
    with _LOCK:
        if _locked(remote, name, now):
            raise TooMany("error: too many attempts; try again in a minute")
    db = _load()
    u = db["users"].get(name)
    if u and u.get("sso") and not u.get("hash"):
        raise LoginFailed("error: this account signs in through single sign-on")
    good = bool(u) and not u.get("disabled") and verify_password(str(password or ""), u["hash"])
    if not good:
        with _LOCK:
            _FAILS.setdefault((remote, name), []).append(now)
        audit.record("auth.login_failed", actor=f"{name or '?'}@{remote}", user=name, remote=remote)
        raise LoginFailed("error: wrong user or password")
    with _LOCK:
        _FAILS.pop((remote, name), None)
    tok = _open_session(name, u["role"])
    audit.record("auth.login", actor=f"{name}@cookie", user=name, role=u["role"], remote=remote)
    return tok, {"user": name, "role": u["role"], "via": "cookie"}


def logout(tok):
    with _LOCK:
        s = _SESSIONS.pop(_sid(tok), None)
        if s:
            _save_sessions()
    if s:
        audit.record("auth.logout", actor=f"{s['user']}@cookie", user=s["user"])


def _cookie(headers):
    for part in (headers.get("Cookie") or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == COOKIE:
            return v
    return None


def authenticate(headers, remote="?"):
    """The principal behind a request, or None: a bearer token first, then
    the login cookie."""
    authz = headers.get("Authorization") or ""
    if authz.startswith("Bearer "):
        raw = authz[7:].strip()
        tid = hashlib.sha256(raw.encode()).hexdigest()
        db = _load()
        rec = db["tokens"].get(tid)
        if rec:
            u = db["users"].get(rec["user"])
            if u and not u.get("disabled"):
                return {"user": rec["user"], "role": u["role"], "via": "token"}
        return None
    tok = _cookie(headers)
    if not tok:
        return None
    now = time.time()
    with _LOCK:
        s = _SESSIONS.get(_sid(tok))
        if not s:
            return None
        if now - s["created"] > SESSION_TTL:
            del _SESSIONS[_sid(tok)]
            _save_sessions()
            return None
    u = _load()["users"].get(s["user"])
    if not u or u.get("disabled"):
        return None
    return {"user": s["user"], "role": u["role"], "via": "cookie"}


# ---------------------------------------------------------------- principal


def set_current(principal):
    _LOCAL.principal = principal


def current():
    return getattr(_LOCAL, "principal", None)


def current_user():
    p = current()
    return p["user"] if p else None


def user_path(filename, default):
    """Where a per-person file lives for the request being served; the
    shared file when no one is logged in (accounts off)."""
    p = current()
    if not p:
        return default
    return os.path.join(user_dir(p["user"]), filename)


def visible(meta, principal=None):
    """May this principal see this session at all?"""
    p = principal if principal is not None else current()
    if not p or p["role"] in ("admin", "viewer"):
        return True
    return meta.get("owner") == p["user"]


def may(action, meta=None, principal=None):
    """action: read (a record) | act (mutate a record) | use (start work,
    edit own settings/notes) | admin (accounts, policy, connector config)."""
    p = principal if principal is not None else current()
    if not p:
        return True
    role = p["role"]
    if role == "admin":
        return True
    if role == "viewer":
        return action in ("read", "audit")
    if action in ("admin", "audit"):
        return False
    if action == "use":
        return True
    if meta is None:
        return action == "read"
    return meta.get("owner") == p["user"]


def require(action, meta=None):
    if not may(action, meta):
        p = current()
        who = f"{p['user']} ({p['role']})" if p else "anonymous"
        raise Forbidden(f"error: {who} may not {action} this")


def me():
    p = current()
    return {"auth": enabled(), "user": p["user"] if p else None,
            "role": p["role"] if p else "admin", "via": p["via"] if p else None}


# ---------------------------------------------------------------- tls


def selfsign(out_dir, hosts):
    """A self-signed certificate for a private deployment, via openssl.
    Returns (cert_path, key_path)."""
    exe = shutil.which("openssl")
    if not exe:
        raise core.OverlordError("error: openssl is not installed; bring your own certificate")
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    cert, key = os.path.join(out_dir, "cert.pem"), os.path.join(out_dir, "key.pem")
    hosts = list(hosts or []) or ["localhost"]
    sans = []
    for h in hosts:
        kind = "IP" if re.match(r"^[\d.]+$|^[0-9a-fA-F:]+$", h) else "DNS"
        sans.append(f"{kind}:{h}")
    if "IP:127.0.0.1" not in sans:
        sans.append("IP:127.0.0.1")
    cmd = [exe, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
           "-nodes", "-keyout", key, "-out", cert, "-days", "397", "-subj", f"/CN={hosts[0]}",
           "-addext", "subjectAltName=" + ",".join(sans)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise core.OverlordError(f"error: openssl failed: {r.stderr.strip()[-400:]}")
    os.chmod(key, 0o600)
    return cert, key


# ---------------------------------------------------------------- cli


def _read_password(args, confirm=True):
    if getattr(args, "password_stdin", False):
        return sys.stdin.readline().rstrip("\n")
    pw = getpass.getpass("password: ")
    if confirm and getpass.getpass("again: ") != pw:
        raise core.OverlordError("error: passwords differ")
    return pw


def cmd_users(args):
    c = args.users_cmd
    if c == "add":
        u = add_user(args.name, _read_password(args), args.role)
        print(f"added {u['name']} ({u['role']}); the UI now requires a login")
        return 0
    if c == "passwd":
        set_password(args.name, _read_password(args))
        print(f"password changed for {args.name}")
        return 0
    if c == "role":
        set_role(args.name, args.role)
        print(f"{args.name} is now {args.role}")
        return 0
    if c == "rm":
        remove_user(args.name)
        print(f"removed {args.name}")
        return 0
    if c == "list":
        rows = list_users()
        if not rows:
            print("no accounts: the UI is open to whoever reaches it (loopback only)")
            return 0
        for u in rows:
            b = ", ".join(f"{k}={v}" for k, v in (u.get("budget") or {}).items())
            print(f"{u['name']:28} {u['role']:9} {'disabled' if u['disabled'] else ''}"
                  f"{'sso ' if u.get('sso') else ''}{len(tokens_for(u['name']))} token(s)"
                  + (f"  budget {b}" if b else ""))
        return 0
    if c == "token":
        raw, tid = create_token(args.name, args.label or "")
        print(f"token {tid} for {args.name} — shown once:\n{raw}")
        return 0
    if c == "tokens":
        for t in tokens_for(args.name):
            print(f"{t['id']}  {t['created']}  {t['label']}")
        return 0
    if c == "untoken":
        revoke_token(args.token_id, owner=args.user)
        print("revoked")
        return 0
    if c == "budget":
        cur = user_budget(args.name)
        for k in ("session_tokens", "session_usd", "day_usd"):
            v = getattr(args, k)
            if v is not None:
                if v == 0:
                    cur.pop(k, None)
                else:
                    cur[k] = v
        clean = set_budget(args.name, cur)
        print(f"{args.name} budget: " + (", ".join(f"{k}={v}" for k, v in clean.items()) or "none"))
        return 0
    raise core.OverlordError("error: unknown users subcommand")


def cmd_tls(args):
    if args.tls_cmd == "selfsign":
        cert, key = selfsign(args.out, args.host)
        print(f"certificate: {cert}\nkey:         {key}\n"
              f"start with:  overlord ui --bind <addr> --tls-cert {cert} --tls-key {key}")
        return 0
    raise core.OverlordError("error: unknown tls subcommand")


def add_auth_parsers(sub):
    pu = sub.add_parser("users", help="accounts for the web UI (admin / operator / viewer)")
    us = pu.add_subparsers(dest="users_cmd", required=True)
    pa = us.add_parser("add")
    pa.add_argument("name")
    pa.add_argument("--role", default="operator", choices=ROLES)
    pa.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    pp = us.add_parser("passwd")
    pp.add_argument("name")
    pp.add_argument("--password-stdin", action="store_true")
    pr = us.add_parser("role")
    pr.add_argument("name")
    pr.add_argument("role", choices=ROLES)
    us.add_parser("rm").add_argument("name")
    us.add_parser("list")
    pt = us.add_parser("token", help="mint a bearer token for scripts")
    pt.add_argument("name")
    pt.add_argument("--name", dest="label", default="")
    us.add_parser("tokens").add_argument("name")
    pun = us.add_parser("untoken")
    pun.add_argument("token_id")
    pun.add_argument("--user", help="only this account's tokens")
    pb = us.add_parser("budget", help="an account's spending limits (0 clears one)")
    pb.add_argument("name")
    pb.add_argument("--session-tokens", dest="session_tokens", type=int)
    pb.add_argument("--session-usd", dest="session_usd", type=float)
    pb.add_argument("--day-usd", dest="day_usd", type=float)
    pu.set_defaults(fn=cmd_users)

    pt = sub.add_parser("tls", help="certificates for `overlord ui --bind`")
    ts = pt.add_subparsers(dest="tls_cmd", required=True)
    ps = ts.add_parser("selfsign", help="a self-signed certificate (openssl)")
    ps.add_argument("--out", default=os.path.join(core.OVERLORD_HOME, "tls"))
    ps.add_argument("--host", action="append", help="a name or address the cert covers")
    pt.set_defaults(fn=cmd_tls)


_load_sessions()
