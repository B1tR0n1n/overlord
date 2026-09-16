#!/usr/bin/env python3
"""Audit, retention and deployment e2e: every consequential act — open,
commit, refused commit, rollback, rewind, fork, review, connector config,
sign-in and failure, account and policy changes — lands on one hash-chained
log with an actor; `overlord audit verify` walks the chain and names the
first altered line; `overlord gc` prunes old finished records, orphan
objects and stale locks but never a pending session or the newest
committed ones; /healthz answers without a login; --log-json emits one
JSON line per request. Scripted provider, no network."""

import fcntl
import json
import os
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

import overlord as ov      # noqa: E402
import audit               # noqa: E402
import retention           # noqa: E402
import mcp as mcp_mod      # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


def cli(*args, stdin=None):
    return subprocess.run([sys.executable, os.path.join(HERE, "overlord.py"), *args],
                          capture_output=True, text=True, env=os.environ, input=stdin)


def actions():
    return [e["action"] for e in audit.entries(n=0)]


BACKEND = ov.detect_backend()
if BACKEND is None:
    print("SKIP: audit (no sandbox backend here — see `overlord doctor`)")
    sys.exit(0)
KERNEL = BACKEND == "kernel"
grants = {"net": "none" if KERNEL else "host", "jail": KERNEL, "timeout": None, "merge_base": False}
target = tempfile.mkdtemp()
with open(os.path.join(target, "f.txt"), "w") as f:
    f.write("v1\n")


def session(cmd):
    live = ov.open_session(target, BACKEND, grants, capture=True, stack=True)
    live.exec(["bash", "-c", cmd])
    sid, _ = live.close()
    return sid


try:
    # 1. the engine's acts are chained with an actor
    s1 = session("echo v2 > f.txt")
    s2 = session("echo x > g.txt; echo y > h.txt")
    ov.rewind_session(s2, 0)
    f2 = ov.fork_session(s1)
    ov.commit_session(s1)
    res = ov.commit_session(f2)                       # f2's snapshot is stale → conflict → refused
    if res.get("committed"):
        fail("stale fork committed")
    ov.rollback_session(f2)
    ov.rollback_session(s2)
    seen = actions()
    for a in ("session.open", "session.rewind", "session.fork", "session.commit",
              "session.commit_refused", "session.rollback"):
        if a not in seen:
            fail(f"missing audit action {a}: {seen}")
    rows = audit.entries(n=0)
    if any(not e.get("actor", "").startswith("os:") for e in rows):
        fail(f"actor missing: {[e.get('actor') for e in rows]}")
    commit = [e for e in rows if e["action"] == "session.commit"][0]
    if commit["sid"] != s1 or commit["files"] != 1 or commit["target"] != target:
        fail(f"commit entry: {commit}")
    refused = [e for e in rows if e["action"] == "session.commit_refused"][0]
    if refused["why"] != "conflicts" or refused["sid"] != f2:
        fail(f"refused entry: {refused}")
    v = audit.verify()
    if not v["ok"] or v["entries"] != len(rows):
        fail(f"verify: {v}")
    r = cli("audit", "verify")
    if r.returncode != 0 or "intact" not in r.stdout:
        fail(f"audit verify: {r.stdout}")
    out = cli("audit", "--action", "session.").stdout
    if s1 not in out or "session.commit " not in out:
        fail(f"audit listing:\n{out}")
    if not v.get("keyed") or "signed" not in cli("audit", "verify").stdout:
        fail(f"chain is not signed: {v} / {cli('audit', 'verify').stdout!r}")
    if oct(os.stat(audit.KEY_FILE).st_mode)[-3:] != "600":
        fail("audit key is not mode 0600")
    # the head can be witnessed off-box and a pin binds the live log to it
    pin = os.path.join(HOME, "pin.json")
    if cli("audit", "checkpoint", pin).returncode != 0:
        fail("checkpoint failed")
    with open(pin) as f:
        h = json.load(f)
    if h["seq"] != len(rows) or not h["hash"] or not h["keyed"]:
        fail(f"checkpoint head: {h}")
    if cli("audit", "verify", "--pin", pin).returncode != 0:
        fail("verify --pin should pass against a fresh checkpoint")
    if not audit.check_pin(h)["ok"] or audit.check_pin({"seq": 1, "hash": "deadbeef"})["ok"]:
        fail("check_pin does not bind to the witnessed hash")
    ok("open, rewind, fork, commit, refused commit, rollback: chained, signed, with actor and facts")

    # 1b. keying is the anchor: a rewrite without the key is caught, a downgrade
    #     to an unsigned entry is caught, and a truncation below a pin is caught
    keyed_lines = open(audit.AUDIT_FILE).read().splitlines()
    import hashlib as _h
    def bare(entry):
        b = {k: v for k, v in entry.items() if k != "hash"}
        return _h.sha256((entry["prev"] + "\n" + json.dumps(b, sort_keys=True, separators=(",", ":"), ensure_ascii=False)).encode()).hexdigest()
    # forge the last entry keeping its signed marker: the MAC will not match
    forged = list(keyed_lines)
    e = json.loads(forged[-1]); e["target"] = "/tmp/evil"; e["hash"] = bare(e)
    forged[-1] = json.dumps(e, ensure_ascii=False)
    open(audit.AUDIT_FILE, "w").write("\n".join(forged) + "\n")
    audit._STATE.update(seq=None, hash=None, size=None)
    vd = audit.verify()
    if vd["ok"] or "signature mismatch" not in vd["reason"]:
        fail(f"a keyless rewrite of a signed entry was not caught: {vd}")
    # strip the signed marker to fake an unsigned entry: a downgrade after signing
    forged = list(keyed_lines)
    e = json.loads(forged[-1]); e.pop("v", None); e["target"] = "/tmp/evil"; e["hash"] = bare(e)
    forged[-1] = json.dumps(e, ensure_ascii=False)
    open(audit.AUDIT_FILE, "w").write("\n".join(forged) + "\n")
    audit._STATE.update(seq=None, hash=None, size=None)
    vd = audit.verify()
    if vd["ok"] or "downgrade" not in vd["reason"]:
        fail(f"a downgrade to an unsigned entry was not caught: {vd}")
    # with the key deleted, a signed entry can no longer be validated at all
    open(audit.AUDIT_FILE, "w").write("\n".join(keyed_lines) + "\n")
    saved = open(audit.KEY_FILE).read(); os.unlink(audit.KEY_FILE)
    audit._STATE.update(seq=None, hash=None, size=None)
    vd = audit.verify()
    if vd["ok"] or "key is missing" not in vd["reason"]:
        fail(f"a signed chain with no key should not verify: {vd}")
    open(audit.KEY_FILE, "w").write(saved); os.chmod(audit.KEY_FILE, 0o600)
    # a truncation below the pin is caught even though the shortened chain is self-consistent
    open(audit.AUDIT_FILE, "w").write("\n".join(keyed_lines[:2]) + "\n")
    audit._STATE.update(seq=None, hash=None, size=None)
    if audit.verify()["ok"] is not True:
        fail("a clean prefix of a signed chain should still verify on its own")
    if audit.check_pin(h)["ok"] or cli("audit", "verify", "--pin", pin).returncode != 1:
        fail("a truncation below the pinned head was not caught")
    open(audit.AUDIT_FILE, "w").write("\n".join(keyed_lines) + "\n")
    audit._STATE.update(seq=None, hash=None, size=None)
    ok("the chain is keyed: a keyless rewrite, a downgrade and a truncation below a witnessed pin are all caught")

    # 2. an altered line breaks the chain from that point on
    with open(audit.AUDIT_FILE) as f:
        lines = f.readlines()
    bad = json.loads(lines[2])
    bad["files"] = 99 if "files" in bad else 1
    bad["target"] = "/elsewhere"
    lines[2] = json.dumps(bad) + "\n"
    with open(audit.AUDIT_FILE, "w") as f:
        f.writelines(lines)
    v = audit.verify()
    if v["ok"] or v["broken_at"] != 3 or v["entries"] != 2:
        fail(f"tamper not detected: {v}")
    if cli("audit", "verify").returncode != 1:
        fail("audit verify should exit 1 on a broken chain")
    del lines[2]                                       # a removed line breaks it too
    with open(audit.AUDIT_FILE, "w") as f:
        f.writelines(lines)
    if audit.verify()["broken_at"] != 3:
        fail("removed line not detected")
    os.unlink(audit.AUDIT_FILE)
    audit._STATE.update(seq=None, hash=None, size=None)
    ok("an altered or removed line breaks the chain at that line; doctor and verify say so")

    # 3. connector config, sign-ins, accounts, policy, review: all on the log
    mcp_mod.add_server("echo", command="true")
    mcp_mod.set_approval("readonly")
    mcp_mod.remove_server("echo")
    import ui
    import auth
    from http.server import ThreadingHTTPServer
    PORT = 7797
    server = ThreadingHTTPServer(("127.0.0.1", PORT), ui.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    BASE = f"http://127.0.0.1:{PORT}"

    def req(path, data=None, method=None, headers=None, raw_body=None):
        body = raw_body.encode() if raw_body is not None else (json.dumps(data).encode() if data is not None else None)
        h = {"Host": f"127.0.0.1:{PORT}", "Cookie": ui.local_cookie()}
        h.update(headers or {})
        r = urllib.request.Request(BASE + path, data=body, method=method, headers=h)
        try:
            with urllib.request.urlopen(r, timeout=20) as resp:
                return resp.status, json.loads(resp.read().decode() or "{}"), resp.headers
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or "{}"), e.headers

    try:
        code, d, h = req("/api/policy", method="PUT", raw_body='{"default": {}}')
        if code != 200:
            fail(f"policy write: {code} {d}")
        cli("users", "add", "alice", "--role", "admin", "--password-stdin", stdin="correct horse\n")
        code, d, h = req("/api/login", {"user": "alice", "password": "nope"})
        code, d, h = req("/api/login", {"user": "alice", "password": "correct horse"})
        cookie = (h.get("Set-Cookie") or "").split("=")[1].split(";")[0]
        code, d, h = req("/api/users", {"name": "carol", "password": "carol-pass", "role": "viewer"},
                         headers={"Cookie": f"{auth.COOKIE}={cookie}"})
        code, d, h = req("/api/users/carol/role", {"role": "operator"},
                         headers={"Cookie": f"{auth.COOKIE}={cookie}"})
        seen = actions()
        for a in ("connector.config", "policy.write", "auth.login_failed", "auth.login",
                  "users.add", "users.role"):
            if a not in seen:
                fail(f"missing {a}: {seen}")
        adds = [e for e in audit.entries(n=0) if e["action"] == "users.add" and e["user"] == "carol"]
        if not adds or adds[0]["actor"] != "alice@cookie":
            fail(f"actor should be the signed-in admin: {adds}")
        # the audit API: viewers and admins read it, operators do not
        code, d, h = req("/api/audit?n=5&verify=1", headers={"Cookie": f"{auth.COOKIE}={cookie}"})
        if code != 200 or len(d["entries"]) != 5 or not d["chain"]["ok"]:
            fail(f"audit API: {code} {d}")
        code, d, h = req("/api/login", {"user": "carol", "password": "carol-pass"})
        ccookie = (h.get("Set-Cookie") or "").split("=")[1].split(";")[0]
        code, d, h = req("/api/audit", headers={"Cookie": f"{auth.COOKIE}={ccookie}"})
        if code != 403:
            fail("an operator read the audit log")
        # /healthz needs no login; a bad Host is still refused
        code, d, h = req("/healthz")
        if code != 200 or not d["ok"] or d["version"] != ov.VERSION or d["auth"] is not True:
            fail(f"healthz: {code} {d}")
        code, d, h = req("/healthz", headers={"Host": "attacker.example"})
        if code != 421:
            fail("healthz served for an unknown host")
        ok("connector config, policy, sign-ins, accounts audited with the signed-in actor; healthz open")
    finally:
        server.shutdown()
    os.unlink(auth.USERS_FILE)

    # 4. gc: old finished records, orphan objects, stale locks — never pending or the newest
    old = session("echo o > old.txt")
    ov.commit_session(old)
    mid = session("echo m > mid.txt")
    ov.commit_session(mid)
    new = session("echo n > new.txt")
    ov.commit_session(new)
    pend = session("echo p > pend.txt")
    long_ago = time.strftime(ov.TS_FORMAT, time.localtime(time.time() - 40 * 86400))
    for sid, ns in ((old, 1), (mid, 2)):
        m = ov.load_meta(sid)
        m["committed"], m["committed_ns"] = long_ago, ns
        ov.save_meta(sid, m)
    m = ov.load_meta(pend)
    m["started"] = long_ago
    ov.save_meta(pend, m)
    orphan = os.path.join(ov.OBJECTS_DIR, "0" * 64)
    with open(orphan, "w") as f:
        f.write("nobody refers to me")
    referenced = set()
    for sid in (new,):
        with open(ov.session_file(sid, ov.PROVENANCE_FILE)) as f:
            for line in f:
                r = json.loads(line)
                referenced.update(x for x in (r.get("before_sha256"), r.get("after_sha256")) if x)
    if not referenced:
        fail("no retained objects to protect")
    os.makedirs(ov.LOCKS_DIR, exist_ok=True)
    stale = os.path.join(ov.LOCKS_DIR, "stale.lock")
    open(stale, "w").close()
    held = open(os.path.join(ov.LOCKS_DIR, "held.lock"), "w")
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    # the two removed records' own retained objects become orphans in the
    # same pass (3 with the fake); the folder's released lock is stale too (2)
    r = cli("gc", "--dry-run", "--keep-days", "30", "--keep-last", "1")
    if r.returncode != 0 or "would remove: 2 record(s)" not in r.stdout or "3 orphan object" not in r.stdout \
            or "2 stale lock" not in r.stdout:
        fail(f"gc dry-run: {r.stdout} {r.stderr}")
    if not os.path.isdir(ov.session_path(old)):
        fail("dry run removed something")
    r = cli("gc", "--keep-days", "30", "--keep-last", "1")
    if r.returncode != 0 or "removed: 2 record(s)" not in r.stdout:
        fail(f"gc: {r.stdout} {r.stderr}")
    if os.path.isdir(ov.session_path(old)) or os.path.isdir(ov.session_path(mid)):
        fail("old committed records not removed")
    if not os.path.isdir(ov.session_path(new)) or not os.path.isdir(ov.session_path(pend)):
        fail("the newest committed record or the pending session was removed")
    if os.path.exists(orphan) or not all(os.path.isfile(os.path.join(ov.OBJECTS_DIR, x)) for x in referenced):
        fail("orphan kept or referenced object removed")
    if os.path.exists(stale) or not os.path.exists(held.name):
        fail("stale lock kept or a held lock removed")
    held.close()
    if "gc" not in actions():
        fail("gc not audited")
    # keep_last protects the newest committed record whatever its age
    m = ov.load_meta(new)
    m["committed"], m["committed_ns"] = long_ago, time.time_ns() + 1
    ov.save_meta(new, m)
    r = cli("gc", "--keep-days", "1", "--keep-last", "1")
    if not os.path.isdir(ov.session_path(new)):
        fail("keep_last did not protect the newest committed record")
    r = cli("gc", "--set-keep-days", "7")
    if retention.load_config()["keep_days"] != 7 or "keep_days=7" not in r.stdout:
        fail("retention config")
    ov.rollback_session(pend)
    ok("gc: old finished records, orphan objects and stale locks go; pending and newest stay; configurable")

    # 5. --log-json: one JSON line per request on stderr; doctor shows the chain
    PORT2 = 7799
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, "overlord.py"), "ui", "--port", str(PORT2),
                             "--log-json"], env=os.environ, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT2}/healthz", timeout=2).read()
                break
            except (urllib.error.URLError, ConnectionError, OSError):
                time.sleep(0.1)
        urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{PORT2}/api/sessions",
                                                      headers={"Cookie": ui.local_cookie()}), timeout=5).read()
    finally:
        proc.terminate()
        _out, err = proc.communicate(timeout=10)
    lines = [json.loads(line) for line in err.decode().splitlines() if line.startswith("{")]
    paths = [ln["path"] for ln in lines]
    if "/healthz" not in paths or "/api/sessions" not in paths \
            or any(ln["status"] != 200 or "ms" not in ln or ln["method"] != "GET" for ln in lines):
        fail(f"log-json lines: {err.decode()[:400]}")
    out = cli("doctor").stdout
    if "audit chain: intact" not in out or "records on disk" not in out or "accounts" not in out:
        fail(f"doctor:\n{out}")
    ok("--log-json request lines; doctor reports accounts, TLS, the audit chain and disk")

    # 6. the fuse probe checks the device a mount needs, not just the binaries:
    #    doctor names the reason, and detect_backend never offers a backend that
    #    cannot mount (found by an agent running the suite inside its jail)
    from unittest import mock
    with mock.patch.object(ov.shutil, "which", lambda t: "/usr/bin/" + t), \
            mock.patch.object(ov.os.path, "exists", lambda p: p != "/dev/fuse"):
        if ov._fuse_backend_reason() != "no /dev/fuse (a container needs --device /dev/fuse)" or ov._fuse_backend_available():
            fail(f"fuse probe without /dev/fuse: {ov._fuse_backend_reason()!r}")
        with mock.patch.dict(ov.os.environ, {"OVERLORD_JAIL": "1"}):
            if "inside a jail" not in ov._fuse_backend_reason():
                fail("fuse probe inside a jail does not say so")
    with mock.patch.object(ov.shutil, "which", lambda t: None):
        if ov._fuse_backend_reason() != "missing fuse-overlayfs":
            fail(f"fuse probe without the binary: {ov._fuse_backend_reason()!r}")
    ok("fuse backend counts as available only with /dev/fuse; doctor says which piece is missing")

    # 7. the off-box witness: a signed checkpoint sent to an append-only endpoint,
    #    verified back, catching a truncation the key holder could otherwise hide
    import http.server as _hs
    import threading as _th
    HELD = []
    class Witness(_hs.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            HELD.append(json.loads(self.rfile.read(n) or b"{}"))
            self.send_response(200); self.end_headers()
        def do_GET(self):
            body = json.dumps(HELD[-1] if HELD else {}).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a):
            pass
    wsrv = _hs.ThreadingHTTPServer(("127.0.0.1", 0), Witness)
    WPORT = wsrv.server_address[1]
    _th.Thread(target=wsrv.serve_forever, daemon=True).start()
    try:
        # rebuild a clean signed chain (earlier steps left it broken/removed)
        for i in range(5):
            audit.record("session.commit", sid=f"s{i}", files=1)
        r = cli("audit", "witness", f"http://127.0.0.1:{WPORT}/hook")
        if r.returncode != 0 or (audit.config().get("witness") or {}).get("url") != f"http://127.0.0.1:{WPORT}/hook":
            fail(f"witness set: {r.stdout} {r.stderr}")
        r = cli("audit", "checkpoint", "--send")
        if r.returncode != 0 or not HELD or HELD[-1]["seq"] != audit.head()["seq"] or "mac" not in HELD[-1]:
            fail(f"checkpoint --send did not deliver a signed head: {r.stdout} {HELD[-1:]}")
        if cli("audit", "verify", "--witness").returncode != 0:
            fail("verify --witness should pass against a fresh checkpoint")
        witnessed_seq = HELD[-1]["seq"]
        # more acts, then a truncation BELOW the witnessed head — self-consistent, but the witness catches it
        for i in range(3):
            audit.record("session.rollback", sid=f"r{i}")
        lines = open(audit.AUDIT_FILE).read().splitlines()
        open(audit.AUDIT_FILE, "w").write("\n".join(lines[:witnessed_seq - 1]) + "\n")
        audit._STATE.update(seq=None, hash=None, size=None)
        if audit.verify()["ok"] is not True:
            fail("the truncated prefix should still verify on its own — that is why a witness is needed")
        w = audit.verify_against_witness()
        if w["ok"] or "truncated" not in w["reason"]:
            fail(f"the witness did not catch the truncation below its head: {w}")
        # a head not signed by our key is rejected even if the witness serves it
        HELD.append({"seq": 99, "hash": "f" * 64, "mac": "0" * 64})
        if audit.verify_against_witness()["ok"] or "not signed" not in audit.verify_against_witness()["reason"]:
            fail("a witnessed head with a bad MAC was accepted")
        # auto: with auto on, a consequential act sends a checkpoint on its own
        HELD.clear()
        open(audit.AUDIT_FILE, "w").write("\n".join(lines) + "\n")
        audit._STATE.update(seq=None, hash=None, size=None)
        cli("audit", "witness", f"http://127.0.0.1:{WPORT}/hook", "--auto")
        audit._SENT["at"] = 0
        audit.record("session.commit", sid="auto1", files=1)
        for _ in range(50):
            if HELD:
                break
            time.sleep(0.05)
        if not HELD or "mac" not in HELD[-1]:
            fail(f"auto witness did not send a signed checkpoint after a commit: {HELD}")
        ok("off-box witness: a signed checkpoint is sent and verified; a truncation below it and a bad MAC are caught; auto sends on commit")
    finally:
        wsrv.shutdown()

    print("PASS: audit")
finally:
    subprocess.run(["rm", "-rf", HOME, target])
