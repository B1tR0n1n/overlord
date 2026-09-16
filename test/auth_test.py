#!/usr/bin/env python3
"""Auth e2e: with no accounts the UI is open on loopback as before; the
first account turns sign-in on (cookie, bearer token, lockout after
repeated failures); roles — an operator sees and acts on their own
conversations only, a viewer reads everything and changes nothing, an
admin runs the machine; settings, keys and notes are per account; the
owner is recorded on the session; --bind beyond loopback is refused
without accounts and TLS; TLS is served from `overlord tls selfsign`
with a Host allowlist and a Secure cookie. Scripted provider, no network."""

import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = HOME
PORT, TLS_PORT = 7794, 7795

import overlord as ov      # noqa: E402
import auth                # noqa: E402
import ui                  # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Client:
    """One person's browser or script: a cookie or a bearer token."""

    def __init__(self, base, ctx=None):
        self.base, self.cookie, self.token, self.ctx = base, None, None, ctx

    def req(self, path, data=None, method=None, headers=None, raw=False):
        body = json.dumps(data).encode() if data is not None else None
        h = {"Host": self.base.split("://", 1)[1]}
        cookies = [ui.local_cookie()]                 # open mode's credential; ignored once accounts exist
        if self.cookie:
            cookies.append(f"{auth.COOKIE}={self.cookie}")
        h["Cookie"] = "; ".join(cookies)
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        h.update(headers or {})
        r = urllib.request.Request(self.base + path, data=body,
                                   method=method or ("POST" if body is not None else "GET"), headers=h)
        opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=self.ctx))
        try:
            with opener.open(r, timeout=20) as resp:
                text = resp.read().decode()
                return resp.status, (text if raw else json.loads(text or "{}")), resp.headers
        except urllib.error.HTTPError as e:
            text = e.read().decode()
            try:
                parsed = text if raw else json.loads(text or "{}")
            except ValueError:
                parsed = text
            return e.code, parsed, e.headers

    def login(self, user, pw):
        code, d, hdrs = self.req("/api/login", {"user": user, "password": pw})
        if code == 200:
            self.cookie = (hdrs.get("Set-Cookie") or "").split(f"{auth.COOKIE}=")[1].split(";")[0]
        return code, d, hdrs


def cli(*args, stdin=None):
    return subprocess.run([sys.executable, os.path.join(HERE, "overlord.py"), *args],
                          capture_output=True, text=True, env=os.environ, input=stdin)


def wait_done(c, sid):
    frm, last = 0, None
    for _ in range(300):
        code, d, _h = c.req(f"/api/chats/{sid}/events?from={frm}")
        if code != 200:
            fail(f"events: {code} {d}")
        frm = d["next"]
        last = d
        if not d["running"]:
            return
        time.sleep(0.05)
    fail(f"conversation never finished: {last}")


BACKEND = ov.detect_backend()
if BACKEND is None:
    print("SKIP: auth (no sandbox backend here — see `overlord doctor`)")
    sys.exit(0)
KERNEL = BACKEND == "kernel"
target = tempfile.mkdtemp()
with open(os.path.join(target, "lib.py"), "w") as f:
    f.write("def a():\n    return 1\n")
script = os.path.join(HOME, "script.json")
with open(script, "w") as f:
    json.dump([{"text": "Noting.", "tool_calls": [
                   {"name": "remember", "input": {"scope": "user", "text": "Bob uses vim"}}]},
               {"text": "done"}], f)
os.environ["OVERLORD_AGENT_SCRIPT"] = script
SCRIPTED = {"provider": "scripted", "workdir": target, "jail": KERNEL, "net": "none" if KERNEL else "host"}

server = ui.make_server(PORT)
threading.Thread(target=server.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{PORT}"
tls_server = None

try:
    # 1. no accounts: open on loopback, refused beyond it
    anon = Client(BASE)
    code, me, _h = anon.req("/api/me")
    if code != 200 or me["auth"] or me["role"] != "admin":
        fail(f"open mode: {code} {me}")
    code, d, _h = anon.req("/api/chats")
    if code != 200:
        fail("open mode refused the chat list")
    try:
        ui.make_server(0, bind="0.0.0.0")
        fail("bound beyond loopback with no accounts")
    except ov.OverlordError as e:
        if "accounts" not in str(e):
            fail(f"wrong refusal: {e}")
    ok("no accounts: the local person is the operator; --bind beyond loopback refused")

    # 2. the first account turns sign-in on
    r = cli("users", "add", "alice", "--role", "admin", "--password-stdin", stdin="correct horse\n")
    if r.returncode != 0 or "requires a login" not in r.stdout:
        fail(f"users add: {r.stdout} {r.stderr}")
    if "alice" not in cli("users", "list").stdout:
        fail("users list")
    mode = os.stat(auth.USERS_FILE).st_mode & 0o777
    if mode != 0o600 or "correct horse" in open(auth.USERS_FILE).read():
        fail(f"users file: mode {mode:o}, or the password is stored in clear")
    code, d, _h = anon.req("/api/chats")
    if code != 401 or d.get("login") != "/login":
        fail(f"api without login: {code} {d}")
    code, body, hdrs = anon.req("/", raw=True)
    if code != 302 or not (hdrs.get("Location") or "").startswith("/login"):
        fail(f"page without login: {code} {hdrs.get('Location')}")
    code, body, _h = anon.req("/login", raw=True)
    if code != 200 or "sign in" not in body or "Content-Security-Policy" not in str(_h):
        fail("login page")
    alice = Client(BASE)
    code, d, _h = alice.login("alice", "wrong")
    if code != 401:
        fail(f"wrong password: {code} {d}")
    for _ in range(4):
        alice.login("alice", "wrong")
    code, d, _h = alice.login("alice", "correct horse")
    if code != 429:
        fail(f"no lockout after repeated failures: {code} {d}")
    auth._FAILS.clear()
    code, d, hdrs = alice.login("alice", "correct horse")
    sc = hdrs.get("Set-Cookie") or ""
    if code != 200 or d["user"] != "alice" or "HttpOnly" not in sc or "SameSite=Strict" not in sc:
        fail(f"login: {code} {d} {sc}")
    code, me, _h = alice.req("/api/me")
    if me != {"auth": True, "user": "alice", "role": "admin", "via": "cookie"}:
        fail(f"me: {me}")
    try:
        ui.make_server(0, bind="0.0.0.0")
        fail("bound beyond loopback without TLS")
    except ov.OverlordError as e:
        if "TLS" not in str(e):
            fail(f"wrong refusal: {e}")
    code, d, _h = alice.req("/api/logout", {})
    code, d, _h = alice.req("/api/me")
    if code != 401:
        fail("logout did not end the session")
    alice.login("alice", "correct horse")
    ok("first account: sign-in required, lockout after failures, HttpOnly strict cookie, logout")

    # 3. accounts and roles via the API; per-account settings, keys, notes
    for name, role in (("bob", "operator"), ("carol", "viewer"), ("dave", "operator")):
        code, d, _h = alice.req("/api/users", {"name": name, "password": f"{name}-password", "role": role})
        if code != 200:
            fail(f"add {name}: {code} {d}")
    code, d, _h = alice.req("/api/users", {"name": "Eve!", "password": "x" * 8})
    if code != 400:
        fail("bad user name accepted")
    bob, carol, dave = Client(BASE), Client(BASE), Client(BASE)
    bob.login("bob", "bob-password")
    carol.login("carol", "carol-password")
    dave.login("dave", "dave-password")
    code, d, _h = bob.req("/api/users")
    if code != 403:
        fail("an operator listed the accounts")
    code, d, _h = bob.req("/api/settings", SCRIPTED, "PUT")
    if code != 200:
        fail(f"bob settings: {code} {d}")
    code, d, _h = bob.req("/api/settings", {"provider": "anthropic", "key": "sk-bob-test"}, "PUT")
    code, d, _h = bob.req("/api/settings", {"provider": "scripted"}, "PUT")
    kf = os.path.join(auth.USERS_DIR, "bob", "keys.json")
    if not os.path.isfile(kf) or os.stat(kf).st_mode & 0o077 or os.path.isfile(os.path.join(HOME, "keys.json")):
        fail("bob's key did not land in his own 0600 store")
    if not os.path.isfile(os.path.join(auth.USERS_DIR, "bob", "ui.json")):
        fail("bob's settings did not land in his own folder")
    code, a_s, _h = alice.req("/api/settings")
    if a_s["provider"] != "anthropic" or a_s["keys"]["anthropic"]:
        fail(f"alice sees bob's settings or key: {a_s['provider']} {a_s['keys']}")
    code, d, _h = bob.req("/api/memory", {"user": "Bob prefers tabs.\n"}, "PUT")
    if code != 200 or not os.path.isfile(os.path.join(auth.USERS_DIR, "bob", "memory.md")):
        fail("bob's notes did not land in his own folder")
    code, d, _h = alice.req("/api/memory")
    if d["user"]:
        fail("alice sees bob's notes")
    code, d, _h = carol.req("/api/settings", SCRIPTED, "PUT")
    if code != 403:
        fail("a viewer changed settings")
    ok("accounts via the API; settings, keys and notes are per account")

    # 4. ownership: who sees and who acts
    code, d, _h = bob.req("/api/chats", {"message": "remember my editor", "target": target})
    if code != 200:
        fail(f"bob start: {code} {d}")
    sid = d["sid"]
    wait_done(bob, sid)
    if ov.load_meta(sid).get("owner") != "bob":
        fail("owner not recorded on the session")
    who_sees = {n: [c["sid"] for c in cl.req("/api/chats")[1]["conversations"]]
                for n, cl in (("alice", alice), ("bob", bob), ("carol", carol), ("dave", dave))}
    if sid not in who_sees["alice"] or sid not in who_sees["bob"] or sid not in who_sees["carol"] \
            or sid in who_sees["dave"]:
        fail(f"visibility: {who_sees}")
    code, d, _h = dave.req(f"/api/chats/{sid}")
    if code != 403:
        fail("another operator read bob's conversation")
    code, d, _h = dave.req(f"/api/session/{sid}/rollback", {})
    if code != 403:
        fail("another operator discarded bob's session")
    code, d, _h = dave.req(f"/api/chats/{sid}/message", {"message": "hi"})
    if code != 403:
        fail("another operator wrote into bob's conversation")
    code, conv, _h = carol.req(f"/api/chats/{sid}")
    if code != 200 or conv["meta"]["may_act"] is not False or conv["meta"]["owner"] != "bob":
        fail(f"viewer read: {code} {conv.get('meta')}")
    for path, body in ((f"/api/session/{sid}/rollback", {}), ("/api/chats", {"message": "x", "target": target})):
        code, d, _h = carol.req(path, body)
        if code != 403:
            fail(f"a viewer changed something: {path} {code}")
    code, d, _h = carol.req("/api/policy", {"default": {}}, "PUT", headers={"Content-Type": "application/json"})
    if code != 403:
        fail("a viewer wrote policy")
    code, d, _h = bob.req("/api/policy", {"default": {}}, "PUT")
    if code != 403:
        fail("an operator wrote policy")
    code, d, _h = bob.req("/api/connectors", {"name": "x", "command": "true"})
    if code != 403:
        fail("an operator configured connectors")
    code, conv, _h = bob.req(f"/api/chats/{sid}")
    sug = [m for m in conv["messages"] if m["type"] == "memory_suggestion"]
    if len(sug) != 1 or conv["meta"]["may_act"] is not True:
        fail(f"bob's own view: {conv['meta']} {sug}")
    code, d, _h = bob.req(f"/api/chats/{sid}/remember", {"id": sug[0]["id"]})
    if code != 200 or "Bob uses vim" not in open(os.path.join(auth.USERS_DIR, "bob", "memory.md")).read():
        fail("accepted note did not go to bob's own notes")
    if os.path.isfile(os.path.join(HOME, "memory.md")):
        fail("a note reached the shared file")
    code, d, _h = alice.req("/api/sessions")
    if sid not in [m["id"] for m in d["sessions"]]:
        fail("admin console lacks the session")
    code, d, _h = dave.req("/api/sessions")
    if sid in [m["id"] for m in d["sessions"]]:
        fail("console shows another operator's session")
    code, d, _h = alice.req(f"/api/session/{sid}/rollback", {})
    if code != 200:
        fail(f"admin could not act on bob's session: {code} {d}")
    ok("owner recorded; operators act on their own, viewers read, admins act on all")

    # 5. own password and tokens; admin-only account changes; last-admin guard
    code, d, _h = bob.req("/api/users/bob/passwd", {"password": "bob-password-2"})
    if code != 200:
        fail(f"own password change: {code} {d}")
    code, d, _h = bob.req("/api/me")
    if code != 401:
        fail("a password change kept the old session alive")
    bob.login("bob", "bob-password-2")
    code, d, _h = bob.req("/api/users/dave/passwd", {"password": "pwned-pwned"})
    if code != 403:
        fail("an operator changed someone else's password")
    r = cli("users", "token", "alice", "--name", "ci")
    raw = [w for w in r.stdout.split() if w.startswith("ovl_")]
    if r.returncode != 0 or len(raw) != 1:
        fail(f"users token: {r.stdout} {r.stderr}")
    tid = r.stdout.split("token ")[1].split()[0]
    scripted = Client(BASE)
    scripted.token = raw[0]
    code, me, _h = scripted.req("/api/me")
    if me != {"auth": True, "user": "alice", "role": "admin", "via": "token"}:
        fail(f"bearer token: {me}")
    if raw[0] in open(auth.USERS_FILE).read():
        fail("a token is stored in clear")
    code, d, _h = bob.req("/api/users/bob/token", {"label": "mine"})
    if code != 200 or not d.get("token", "").startswith("ovl_"):
        fail(f"own token: {code} {d}")
    code, d2, _h = bob.req("/api/users/bob/untoken", {"id": tid})
    if code == 200:
        fail("an operator revoked an admin's token")
    if cli("users", "untoken", tid).returncode != 0:
        fail("untoken")
    code, me, _h = scripted.req("/api/me")
    if code != 401:
        fail("revoked token still works")
    r = cli("users", "role", "alice", "operator")
    if r.returncode == 0:
        fail("the last admin was demoted")
    if cli("users", "rm", "dave").returncode != 0 or "dave" in cli("users", "list").stdout:
        fail("users rm")
    ok("own password + tokens; tokens hashed, revocable; last admin guarded")

    # 6. TLS beyond loopback: self-signed cert, Host allowlist, Secure cookie, HSTS
    r = cli("tls", "selfsign", "--out", os.path.join(HOME, "tls"), "--host", "127.0.0.1", "--host", "overlord.test")
    if r.returncode != 0:
        fail(f"tls selfsign: {r.stderr}")
    cert, key = os.path.join(HOME, "tls", "cert.pem"), os.path.join(HOME, "tls", "key.pem")
    if os.stat(key).st_mode & 0o077:
        fail("key not private")
    try:
        ui.make_server(0, bind="0.0.0.0", tls_cert=cert)
        fail("cert without key accepted")
    except ov.OverlordError:
        pass
    tls_server = ui.make_server(TLS_PORT, bind="0.0.0.0", tls_cert=cert, tls_key=key, hosts=["overlord.test"])
    threading.Thread(target=tls_server.serve_forever, daemon=True).start()
    ctx = ssl.create_default_context(cafile=cert)
    TBASE = f"https://127.0.0.1:{TLS_PORT}"
    tc = Client(TBASE, ctx)
    code, d, hdrs = tc.login("alice", "correct horse")
    sc = hdrs.get("Set-Cookie") or ""
    if code != 200 or "Secure" not in sc or "Strict-Transport-Security" not in str(hdrs):
        fail(f"tls login: {code} {sc} hsts={hdrs.get('Strict-Transport-Security')}")
    code, me, _h = tc.req("/api/me")
    if me.get("user") != "alice":
        fail(f"tls me: {me}")
    code, d, _h = tc.req("/api/me", headers={"Host": "overlord.test"})
    if code != 200:
        fail(f"allowed host refused: {code}")
    code, d, _h = tc.req("/api/me", headers={"Host": "attacker.example"})
    if code != 421:
        fail(f"unknown host served: {code}")
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{TLS_PORT}/api/me", timeout=5)
        fail("plain http served on the TLS port")
    except (urllib.error.URLError, ConnectionError, OSError):
        pass
    code, me, _h = tc.req("/api/me")
    if code != 200:
        fail("server unhealthy after a plain-http probe")
    ok("TLS: self-signed via openssl, Secure cookie, HSTS, Host allowlist, plain-http probe shrugged off")

    # 7. the CLI and the daemon are unaffected: an ownerless session is the admin's to see
    live = ov.open_session(target, BACKEND, {"net": "none" if KERNEL else "host", "jail": KERNEL,
                                             "timeout": None, "merge_base": False}, capture=True)
    live.exec(["bash", "-c", "echo x > plain.txt"])
    sid2, _ = live.close()
    code, d, _h = alice.req("/api/sessions")
    code2, d2, _h = bob.req("/api/sessions")
    if sid2 not in [m["id"] for m in d["sessions"]] or sid2 in [m["id"] for m in d2["sessions"]]:
        fail("ownerless session visibility")
    ov.rollback_session(sid2)
    ok("CLI sessions carry no owner: admins see them, operators do not")

    print("PASS: auth")
finally:
    server.shutdown()
    if tls_server:
        tls_server.shutdown()
    subprocess.run(["rm", "-rf", HOME, target])
