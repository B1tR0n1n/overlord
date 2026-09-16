#!/usr/bin/env python3
"""OVERLORD single sign-on — OpenID Connect, authorization code + PKCE.

    overlord sso set --issuer https://login.example.com --client-id … \\
        --client-secret-stdin --domain example.com --admin alice@example.com
    overlord sso show | test | off

Sign-in: /auth/login sends the browser to the provider with state, nonce
and a PKCE challenge; /auth/callback trades the code for tokens over TLS at
the provider's token endpoint, then asks the provider's userinfo endpoint
who this is. The account is provisioned on first sign-in when its e-mail
domain is allowed; its role comes from `roles` (e-mails per role), or from
a groups claim through `role_map`, else `default_role`. SSO accounts have
no password: the password form refuses them.

What the trust rests on, stated plainly: the TLS channel to the provider's
token and userinfo endpoints, plus the state / nonce / PKCE round-trip.
The ID token's claims (iss, aud, nonce, exp) are checked; its signature is
not, because the standard library has no RSA — the same identity is
confirmed by userinfo directly from the provider. Set OVERLORD_OIDC_INSECURE=1
only for a test provider on plain http.

  ~/.overlord/oidc.json   mode 600 (the client secret lives here)
"""

import base64
import hashlib
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import overlord as core

CONFIG_FILE = os.path.join(core.OVERLORD_HOME, "oidc.json")
STATE_TTL = 600
_LOCK = threading.Lock()
_STATES = {}          # state -> {verifier, nonce, next, created}
_DISCOVERY = {}       # issuer -> (fetched_at, doc)


class SSOError(core.OverlordError):
    pass


# ---------------------------------------------------------------- config


def load_config():
    try:
        with open(CONFIG_FILE) as f:
            c = json.load(f)
    except (OSError, ValueError):
        return None
    if not c.get("issuer") or not c.get("client_id"):
        return None
    c.setdefault("scopes", "openid email profile")
    c.setdefault("claim", "email")
    c.setdefault("allowed_domains", [])
    c.setdefault("default_role", "operator")
    c.setdefault("roles", {})
    c.setdefault("role_claim", "")
    c.setdefault("role_map", {})
    c.setdefault("name", "single sign-on")
    return c


def save_config(c):
    os.makedirs(core.OVERLORD_HOME, exist_ok=True)
    tmp = CONFIG_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(c, f, indent=2)
    os.replace(tmp, CONFIG_FILE)


def configured():
    return load_config() is not None


def public():
    c = load_config()
    if not c:
        return {"configured": False}
    return {"configured": True, "name": c["name"], "issuer": c["issuer"],
            "allowed_domains": c["allowed_domains"], "default_role": c["default_role"]}


def _insecure_ok(url):
    if url.startswith("https://"):
        return
    if os.environ.get("OVERLORD_OIDC_INSECURE") == "1":
        return
    raise SSOError(f"error: the provider must be https ({url}); OVERLORD_OIDC_INSECURE=1 for a test one")


# ---------------------------------------------------------------- provider


def _get_json(url, headers=None, data=None, timeout=15):
    _insecure_ok(url)
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:300]
        raise SSOError(f"error: provider returned {e.code} for {url}: {body}")
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise SSOError(f"error: could not reach the provider at {url}: {e}")


def discovery(issuer, refresh=False):
    hit = _DISCOVERY.get(issuer)
    if hit and not refresh and time.time() - hit[0] < 3600:
        return hit[1]
    doc = _get_json(issuer.rstrip("/") + "/.well-known/openid-configuration")
    for k in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint"):
        if not doc.get(k):
            raise SSOError(f"error: the provider's discovery document lacks {k}")
    if doc.get("issuer") and doc["issuer"].rstrip("/") != issuer.rstrip("/"):
        raise SSOError(f"error: discovery names issuer {doc['issuer']}, config says {issuer}")
    _DISCOVERY[issuer] = (time.time(), doc)
    return doc


def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def begin(redirect_uri, next_path="/"):
    """The URL to send the browser to. State is remembered server-side."""
    c = load_config()
    if not c:
        raise SSOError("error: single sign-on is not configured")
    doc = discovery(c["issuer"])
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    now = time.time()
    with _LOCK:
        for k in [k for k, v in _STATES.items() if now - v["created"] > STATE_TTL]:
            del _STATES[k]
        _STATES[state] = {"verifier": verifier, "nonce": nonce, "next": next_path,
                          "created": now, "redirect_uri": redirect_uri}
    q = {"response_type": "code", "client_id": c["client_id"], "redirect_uri": redirect_uri,
         "scope": c["scopes"], "state": state, "nonce": nonce,
         "code_challenge": challenge, "code_challenge_method": "S256"}
    sep = "&" if "?" in doc["authorization_endpoint"] else "?"
    return doc["authorization_endpoint"] + sep + urllib.parse.urlencode(q)


def _jwt_claims(tok):
    try:
        payload = tok.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload).decode())
    except (IndexError, ValueError, TypeError):
        return {}


def finish(code, state):
    """Exchange the code, confirm the identity with userinfo, provision or
    look up the account. Returns (cookie token, principal, next path)."""
    c = load_config()
    if not c:
        raise SSOError("error: single sign-on is not configured")
    with _LOCK:
        st = _STATES.pop(state or "", None)
    if not st or time.time() - st["created"] > STATE_TTL:
        raise SSOError("error: sign-in expired or was not started here; try again")
    doc = discovery(c["issuer"])
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": st["redirect_uri"],
            "client_id": c["client_id"], "code_verifier": st["verifier"]}
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    if c.get("client_secret"):
        import vault as vault_mod
        cs = vault_mod.resolve(c["client_secret"])
        basic = base64.b64encode(f"{c['client_id']}:{cs}".encode()).decode()
        headers["Authorization"] = f"Basic {basic}"
    tokens = _get_json(doc["token_endpoint"], headers, urllib.parse.urlencode(form).encode())
    access = tokens.get("access_token")
    if not access:
        raise SSOError("error: the provider returned no access token")
    claims = _jwt_claims(tokens.get("id_token") or "")
    if claims:
        aud = claims.get("aud")
        if (claims.get("iss") or "").rstrip("/") != c["issuer"].rstrip("/") \
                or (aud != c["client_id"] and not (isinstance(aud, list) and c["client_id"] in aud)) \
                or claims.get("nonce") != st["nonce"] \
                or (claims.get("exp") and claims["exp"] < time.time()):
            raise SSOError("error: the ID token is not for this sign-in")
    info = _get_json(doc["userinfo_endpoint"], {"Authorization": f"Bearer {access}"})
    if claims and info.get("sub") and claims.get("sub") and info["sub"] != claims["sub"]:
        raise SSOError("error: userinfo and the ID token disagree on the subject")
    ident = str(info.get(c["claim"]) or claims.get(c["claim"]) or "").strip().lower()
    if not ident:
        raise SSOError(f"error: the provider gave no {c['claim']} claim")
    domain = ident.rsplit("@", 1)[-1] if "@" in ident else ""
    if c["allowed_domains"] and domain not in [d.lower() for d in c["allowed_domains"]]:
        import audit
        audit.record("auth.sso_refused", actor=f"{ident}@sso", user=ident, reason="domain not allowed")
        raise SSOError(f"error: {ident} is not in an allowed domain")
    role = _role_for(c, ident, info, claims)
    import auth
    tok, principal = auth.external_login(ident, role, c["issuer"])
    return tok, principal, st["next"]


def _role_for(c, ident, info, claims):
    for role, members in (c.get("roles") or {}).items():
        if ident in [m.lower() for m in (members or [])]:
            return role
    rc = c.get("role_claim")
    if rc:
        groups = info.get(rc) if info.get(rc) is not None else claims.get(rc)
        groups = groups if isinstance(groups, list) else ([groups] if groups else [])
        for g in groups:
            if str(g) in (c.get("role_map") or {}):
                return c["role_map"][str(g)]
    return c.get("default_role") or "operator"


# ---------------------------------------------------------------- cli


def cmd_sso(args):
    c = args.sso_cmd
    if c == "set":
        cur = load_config() or {}
        cur.update(issuer=args.issuer or cur.get("issuer"), client_id=args.client_id or cur.get("client_id"),
                   name=args.name or cur.get("name") or "single sign-on")
        if args.client_secret_stdin:
            cur["client_secret"] = sys.stdin.readline().rstrip("\n")
        if args.domain:
            cur["allowed_domains"] = args.domain
        if args.default_role:
            cur["default_role"] = args.default_role
        if args.admin is not None:
            cur.setdefault("roles", {})["admin"] = args.admin
        if args.viewer is not None:
            cur.setdefault("roles", {})["viewer"] = args.viewer
        if args.role_claim is not None:
            cur["role_claim"] = args.role_claim
        if args.role_map:
            m = {}
            for pair in args.role_map:
                g, _, r = pair.partition("=")
                m[g] = r
            cur["role_map"] = m
        if args.scopes:
            cur["scopes"] = args.scopes
        if not cur.get("issuer") or not cur.get("client_id"):
            raise SSOError("error: --issuer and --client-id are required")
        save_config(cur)
        import audit
        audit.record("auth.sso_config", op="set", issuer=cur["issuer"])
        print(f"single sign-on set: {cur['issuer']} (client {cur['client_id']}); "
              f"domains {cur.get('allowed_domains') or 'any'}; default role {cur.get('default_role', 'operator')}")
        print("the provider's redirect URI is https://<your host>/auth/callback")
        return 0
    if c == "show":
        cfg = load_config()
        if not cfg:
            print("single sign-on is not configured")
            return 0
        shown = dict(cfg)
        if shown.get("client_secret"):
            shown["client_secret"] = "••••" + shown["client_secret"][-3:]
        print(json.dumps(shown, indent=2))
        return 0
    if c == "test":
        cfg = load_config()
        if not cfg:
            raise SSOError("error: single sign-on is not configured")
        doc = discovery(cfg["issuer"], refresh=True)
        print(f"provider ok: authorize {doc['authorization_endpoint']}\n"
              f"             token     {doc['token_endpoint']}\n"
              f"             userinfo  {doc['userinfo_endpoint']}")
        return 0
    if c == "off":
        if os.path.isfile(CONFIG_FILE):
            os.unlink(CONFIG_FILE)
        import audit
        audit.record("auth.sso_config", op="off")
        print("single sign-on off; local accounts only")
        return 0
    raise SSOError("error: unknown sso subcommand")


def add_sso_parser(sub):
    ps = sub.add_parser("sso", help="single sign-on (OpenID Connect) for the web UI")
    ss = ps.add_subparsers(dest="sso_cmd", required=True)
    p = ss.add_parser("set")
    p.add_argument("--issuer")
    p.add_argument("--client-id")
    p.add_argument("--client-secret-stdin", action="store_true")
    p.add_argument("--name", help="what the sign-in button says")
    p.add_argument("--domain", action="append", help="an allowed e-mail domain; repeatable")
    p.add_argument("--default-role", choices=("admin", "operator", "viewer"))
    p.add_argument("--admin", action="append", help="an e-mail that signs in as admin; repeatable")
    p.add_argument("--viewer", action="append", help="an e-mail that signs in as viewer; repeatable")
    p.add_argument("--role-claim", help="a claim listing groups (e.g. groups)")
    p.add_argument("--role-map", action="append", help="group=role; repeatable")
    p.add_argument("--scopes")
    ss.add_parser("show")
    ss.add_parser("test")
    ss.add_parser("off")
    ps.set_defaults(fn=cmd_sso)
