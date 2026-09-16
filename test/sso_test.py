#!/usr/bin/env python3
"""Single sign-on e2e against a fake OpenID provider: discovery, the
authorize redirect with state / nonce / PKCE, the code exchange with the
verifier and client secret, identity from userinfo, accounts provisioned
on first sign-in with roles from the e-mail list or a groups claim,
domains enforced, forged state refused, SSO accounts refusing passwords,
the sign-in page offering the button, everything audited. No network:
the provider is a local http server allowed by OVERLORD_OIDC_INSECURE."""

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = HOME
os.environ["OVERLORD_OIDC_INSECURE"] = "1"
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

import auth                # noqa: E402
import audit               # noqa: E402
import oidc                # noqa: E402
import ui                  # noqa: E402

IDP_PORT, UI_PORT = 7789, 7790
ISSUER = f"http://127.0.0.1:{IDP_PORT}"
CLIENT, SECRET = "overlord-ui", "s3cret-s3cret"
IDP = {"codes": {}, "tokens": {}, "who": {"sub": "u-1", "email": "Alice@Example.com", "groups": []},
       "seen_authorize": [], "seen_token": []}


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class IdP(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        if u.path == "/.well-known/openid-configuration":
            self._json({"issuer": ISSUER, "authorization_endpoint": ISSUER + "/authorize",
                        "token_endpoint": ISSUER + "/token", "userinfo_endpoint": ISSUER + "/userinfo"})
        elif u.path == "/authorize":
            IDP["seen_authorize"].append(q)
            code = "code-" + b64url(os.urandom(8))
            IDP["codes"][code] = q
            self.send_response(302)
            self.send_header("Location", q["redirect_uri"] + "?" + urllib.parse.urlencode(
                {"code": code, "state": q["state"]}))
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif u.path == "/userinfo":
            tok = (self.headers.get("Authorization") or "").replace("Bearer ", "")
            if tok not in IDP["tokens"]:
                self._json({"error": "invalid_token"}, 401)
            else:
                self._json(IDP["who"])
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        form = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode()).items()}
        IDP["seen_token"].append((dict(self.headers), form))
        if self.path != "/token":
            return self._json({"error": "not found"}, 404)
        basic = (self.headers.get("Authorization") or "").replace("Basic ", "")
        if base64.b64decode(basic).decode() != f"{CLIENT}:{SECRET}":
            return self._json({"error": "invalid_client"}, 401)
        req = IDP["codes"].pop(form.get("code"), None)
        if not req:
            return self._json({"error": "invalid_grant"}, 400)
        if b64url(hashlib.sha256(form.get("code_verifier", "").encode()).digest()) != req["code_challenge"]:
            return self._json({"error": "invalid_grant", "error_description": "pkce"}, 400)
        access = "at-" + b64url(os.urandom(8))
        IDP["tokens"][access] = req
        hdr = b64url(json.dumps({"alg": "none"}).encode())
        claims = {"iss": ISSUER, "aud": CLIENT, "sub": IDP["who"]["sub"], "nonce": req["nonce"],
                  "exp": 4102444800, "email": IDP["who"]["email"]}
        id_token = f"{hdr}.{b64url(json.dumps(claims).encode())}."
        self._json({"access_token": access, "token_type": "Bearer", "id_token": id_token})


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def get(url, cookie=None, headers=None):
    h = {"Host": f"127.0.0.1:{UI_PORT}"}
    if cookie:
        h["Cookie"] = f"{auth.COOKIE}={cookie}"
    h.update(headers or {})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(urllib.request.Request(url, headers=h), timeout=20) as r:
            return r.status, r.read().decode(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), e.headers


def post(url, data, cookie=None):
    h = {"Host": f"127.0.0.1:{UI_PORT}"}
    if cookie:
        h["Cookie"] = f"{auth.COOKIE}={cookie}"
    r = urllib.request.Request(url, data=json.dumps(data).encode(), headers=h, method="POST")
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}"), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}"), e.headers


def sign_in(next_path="/"):
    """Drive the browser's part: /auth/login -> provider -> /auth/callback."""
    BASE = f"http://127.0.0.1:{UI_PORT}"
    code, body, h = get(BASE + "/auth/login?next=" + urllib.parse.quote(next_path, safe=""))
    if code != 302:
        fail(f"/auth/login: {code} {body}")
    loc = h["Location"]
    code, body, h = get(loc, headers={"Host": f"127.0.0.1:{IDP_PORT}"})
    if code != 302:
        fail(f"provider authorize: {code}")
    cb = h["Location"]
    if not cb.startswith(BASE + "/auth/callback?"):
        fail(f"callback uri: {cb}")
    return get(cb)


def cli(*args, stdin=None):
    return subprocess.run([sys.executable, os.path.join(HERE, "overlord.py"), *args],
                          capture_output=True, text=True, env=os.environ, input=stdin)


idp = ThreadingHTTPServer(("127.0.0.1", IDP_PORT), IdP)
threading.Thread(target=idp.serve_forever, daemon=True).start()
server = ui.make_server(UI_PORT)
threading.Thread(target=server.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{UI_PORT}"

try:
    # 1. configured by the CLI; configuration alone turns sign-in on
    if auth.enabled():
        fail("auth on before anything is configured")
    r = cli("sso", "set", "--issuer", ISSUER, "--client-id", CLIENT, "--client-secret-stdin",
            "--domain", "example.com", "--admin", "alice@example.com", "--role-claim", "groups",
            "--role-map", "auditors=viewer", "--name", "Example SSO", stdin=SECRET + "\n")
    if r.returncode != 0 or "auth/callback" not in r.stdout:
        fail(f"sso set: {r.stdout} {r.stderr}")
    if os.stat(oidc.CONFIG_FILE).st_mode & 0o077:
        fail("oidc.json not private")
    if SECRET in cli("sso", "show").stdout:
        fail("sso show printed the secret")
    if cli("sso", "test").returncode != 0:
        fail("sso test")
    if not auth.enabled():
        fail("SSO configured but sign-in not required")
    code, body, h = get(BASE + "/api/chats")
    if code != 401:
        fail("API open with SSO configured")
    code, body, h = get(BASE + "/login")
    if code != 200 or "Sign in with Example SSO" not in body or "/auth/login?next=" not in body:
        fail("login page lacks the SSO button")
    ok("configured by the CLI (secret private, masked); sign-in required; the page offers the button")

    # 2. the round trip: state, nonce, PKCE, client secret, userinfo; admin by e-mail list
    code, body, h = sign_in("/console")
    if code != 302 or h["Location"] != "/console" or auth.COOKIE not in (h.get("Set-Cookie") or ""):
        fail(f"callback: {code} {h.get('Location')} {h.get('Set-Cookie')}")
    cookie = h["Set-Cookie"].split("=")[1].split(";")[0]
    code, me, h2 = get(BASE + "/api/me", cookie=cookie)
    me = json.loads(me)
    if me != {"auth": True, "user": "alice@example.com", "role": "admin", "via": "cookie"}:
        fail(f"me after SSO: {me}")
    a = IDP["seen_authorize"][-1]
    if a["code_challenge_method"] != "S256" or len(a["state"]) < 20 or len(a["nonce"]) < 20 \
            or a["redirect_uri"] != BASE + "/auth/callback" or "openid" not in a["scope"]:
        fail(f"authorize request: {a}")
    hdrs, form = IDP["seen_token"][-1]
    if form["grant_type"] != "authorization_code" or "code_verifier" not in form \
            or not hdrs.get("Authorization", "").startswith("Basic "):
        fail(f"token request: {form} {hdrs.get('Authorization')}")
    users = {u["name"]: u for u in auth.list_users()}
    if users["alice@example.com"]["role"] != "admin" or users["alice@example.com"]["sso"] != ISSUER:
        fail(f"provisioned account: {users}")
    if not os.path.isdir(os.path.join(auth.USERS_DIR, "alice@example.com")):
        fail("no per-account folder")
    ok("state + nonce + PKCE + client secret; identity from userinfo; provisioned as admin from the list")

    # 3. a second identity: groups claim -> viewer; domain enforced; forged state refused
    IDP["who"] = {"sub": "u-2", "email": "carl@example.com", "groups": ["auditors"]}
    code, body, h = sign_in()
    c2 = h["Set-Cookie"].split("=")[1].split(";")[0]
    me = json.loads(get(BASE + "/api/me", cookie=c2)[1])
    if me["user"] != "carl@example.com" or me["role"] != "viewer":
        fail(f"groups mapping: {me}")
    IDP["who"] = {"sub": "u-3", "email": "mallory@evil.example", "groups": []}
    code, body, h = sign_in()
    if code != 400 or "allowed domain" not in body or "mallory@evil.example" in [u["name"] for u in auth.list_users()]:
        fail(f"domain not enforced: {code} {body[:120]}")
    code, body, h = get(BASE + "/auth/callback?code=x&state=forged")
    if code != 400 or "expired or was not started" not in body:
        fail(f"forged state: {code} {body[:120]}")
    IDP["who"] = {"sub": "u-4", "email": "dana@example.com", "groups": []}
    code, body, h = sign_in()
    me = json.loads(get(BASE + "/api/me", cookie=h["Set-Cookie"].split("=")[1].split(";")[0])[1])
    if me["role"] != "operator":
        fail(f"default role: {me}")
    ok("groups claim maps a role; default role; domain enforced; forged state refused")

    # 4. SSO accounts have no password; the password form refuses them; local accounts still work
    code, d, h = post(BASE + "/api/login", {"user": "alice@example.com", "password": "anything!"})
    if code != 401 or "single sign-on" not in d.get("error", ""):
        fail(f"password login for an SSO account: {code} {d}")
    cli("users", "add", "local", "--role", "operator", "--password-stdin", stdin="local-password\n")
    code, d, h = post(BASE + "/api/login", {"user": "local", "password": "local-password"})
    if code != 200:
        fail("local account cannot sign in alongside SSO")
    out = cli("users", "list").stdout
    if "alice@example.com" not in out or "sso" not in out:
        fail(f"users list: {out}")
    # an admin can still change an SSO account's role between sign-ins; the mapping wins on the next
    cli("users", "role", "dana@example.com", "viewer")
    IDP["who"] = {"sub": "u-4", "email": "dana@example.com", "groups": []}
    code, body, h = sign_in()
    me = json.loads(get(BASE + "/api/me", cookie=h["Set-Cookie"].split("=")[1].split(";")[0])[1])
    if me["role"] != "operator":
        fail("the provider's mapping should win on sign-in")
    ok("SSO accounts refuse passwords; local accounts coexist; the mapping decides the role at sign-in")

    # 5. audited; sso off restores local-only
    acts = [(e["action"], e.get("user")) for e in audit.entries(n=0)]
    for want in (("auth.sso_config", None), ("auth.sso_login", "alice@example.com"),
                 ("auth.sso_refused", "mallory@evil.example")):
        if want not in acts:
            fail(f"audit lacks {want}: {acts}")
    prov = [e for e in audit.entries(action="auth.sso_login") if e.get("provisioned")]
    if len(prov) != 3:
        fail(f"provisioning audited: {prov}")
    if cli("sso", "off").returncode != 0 or oidc.configured():
        fail("sso off")
    code, body, h = get(BASE + "/login")
    if "Sign in with" in body:
        fail("button shown after sso off")
    code, body, h = get(BASE + "/auth/login")
    if code != 400:
        fail(f"/auth/login after off: {code}")
    ok("sign-ins, refusals, provisioning and configuration audited; sso off")

    print("PASS: sso")
finally:
    server.shutdown()
    idp.shutdown()
    subprocess.run(["rm", "-rf", HOME])
