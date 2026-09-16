#!/usr/bin/env python3
"""Mission control e2e: page renders, sessions list, detail with provenance,
rollback via POST, policy round-trip with invalid-JSON rejection."""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OVERLORD_HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = OVERLORD_HOME
PORT = 7791
BASE = f"http://127.0.0.1:{PORT}"


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


def req(path, data=None, method=None):
    r = urllib.request.Request(
        BASE + path, data=data.encode() if data else None, method=method
    )
    with urllib.request.urlopen(r, timeout=10) as resp:
        return resp.read().decode()


target = tempfile.mkdtemp()
with open(os.path.join(target, "f.txt"), "w") as f:
    f.write("v1\n")

env = os.environ.copy()
run = subprocess.run(
    [sys.executable, os.path.join(HERE, "overlord.py"), "run", "-t", target,
     "--", "bash", "-c", "echo v2 > f.txt"],
    env=env, capture_output=True, text=True,
)
sid = next((w for w in run.stdout.split() if w.startswith("2")), None) or fail("no session")

server = subprocess.Popen(
    [sys.executable, os.path.join(HERE, "overlord.py"), "ui", "--port", str(PORT)],
    env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
try:
    for _ in range(50):
        try:
            req("/api/sessions")
            break
        except OSError:
            time.sleep(0.1)

    if "OVERLORD" not in req("/") or "mission control" not in req("/"):
        fail("page render")
    ok("page renders")

    sessions = json.loads(req("/api/sessions"))["sessions"]
    if not any(m["id"] == sid for m in sessions):
        fail("session missing from list")
    ok("sessions list")

    detail = json.loads(req(f"/api/session/{sid}"))
    if ["modified", "f.txt"] not in detail["changes"]:
        fail(f"detail changes: {detail['changes']}")
    if not any(r["path"] == "f.txt" and r.get("after_sha256") for r in detail["provenance"]):
        fail("detail provenance")
    ok("session detail + provenance")

    res = json.loads(req(f"/api/session/{sid}/commit", data="{}", method="POST"))
    if not res.get("committed"):
        fail(f"ui commit: {res}")
    if open(os.path.join(target, "f.txt")).read() != "v2\n":
        fail("ui commit did not apply")
    ok("commit via UI")

    res = json.loads(req("/api/policy", data='{"default": {"timeout": 5}}', method="PUT"))
    if not res.get("saved"):
        fail("policy save")
    if "timeout" not in json.loads(req("/api/policy"))["text"]:
        fail("policy round-trip")
    try:
        req("/api/policy", data="not json {", method="PUT")
        fail("invalid policy accepted")
    except urllib.error.HTTPError as e:
        if e.code != 400:
            fail(f"wrong invalid-policy status: {e.code}")
    ok("policy editor + validation")

    # --- a cross-origin page must not be able to apply an agent's changes ---
    run2 = subprocess.run(
        [sys.executable, os.path.join(HERE, "overlord.py"), "run", "-t", target,
         "--", "bash", "-c", "echo v3 > f.txt"],
        env=env, capture_output=True, text=True)
    sid2 = next((w for w in run2.stdout.split() if w.startswith("2")), None) or fail("no session")

    def raw(path, data=None, method=None, headers=None):
        r = urllib.request.Request(BASE + path, data=data.encode() if data else None,
                                   method=method, headers=headers or {})
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.read().decode()

    for hdrs in ({"Origin": "https://evil.example"},
                 {"Origin": "http://127.0.0.1:1"},
                 {"Sec-Fetch-Site": "cross-site"}):
        try:
            raw(f"/api/session/{sid2}/commit", data="{}", method="POST", headers=hdrs)
            fail(f"cross-origin commit accepted with {hdrs}")
        except urllib.error.HTTPError as e:
            if e.code != 403:
                fail(f"cross-origin commit: expected 403, got {e.code} for {hdrs}")
    if open(os.path.join(target, "f.txt")).read() != "v2\n":
        fail("a cross-origin request changed the target")

    try:
        raw("/api/policy", data='{"default": {}}', method="PUT",
            headers={"Origin": "https://evil.example"})
        fail("cross-origin policy write accepted")
    except urllib.error.HTTPError as e:
        if e.code != 403:
            fail(f"cross-origin policy write: expected 403, got {e.code}")
    ok("cross-origin state changes refused")

    # --- DNS rebinding: a non-loopback Host must not be served ---
    try:
        raw("/api/sessions", headers={"Host": "attacker.example"})
        fail("non-loopback Host served")
    except urllib.error.HTTPError as e:
        if e.code != 421:
            fail(f"rebinding guard: expected 421, got {e.code}")
    ok("non-loopback Host refused")

    # --- session ids are validated before they reach the filesystem ---
    for probe in ("..", "....//", "%2e%2e", "not-a-sid"):
        try:
            req(f"/api/session/{probe}")
            fail(f"malformed session id accepted: {probe!r}")
        except urllib.error.HTTPError as e:
            if e.code != 400:
                fail(f"session id {probe!r}: expected 400, got {e.code}")
    ok("malformed session ids rejected")

    # --- the same-origin path still works, and the page carries a CSP ---
    with urllib.request.urlopen(urllib.request.Request(
            BASE + "/", headers={"Origin": BASE}), timeout=10) as resp:
        csp = resp.headers.get("Content-Security-Policy") or ""
        if "script-src 'nonce-" not in csp or "default-src 'none'" not in csp:
            fail(f"page missing a nonce-based CSP: {csp!r}")
        if resp.headers.get("X-Content-Type-Options") != "nosniff":
            fail("page missing nosniff")
    res = json.loads(raw(f"/api/session/{sid2}/rollback", data="{}", method="POST",
                         headers={"Origin": BASE}))
    if not res.get("target"):
        fail(f"same-origin rollback broke: {res}")
    ok("same-origin requests still work; CSP + nosniff present")

    # --- savepoints: the dossier shows the chain; rewind and drop act on it ---
    sys.path.insert(0, HERE)
    import overlord as core
    live = core.open_session(target, None, {"net": "host", "jail": False,
                                            "timeout": None, "merge_base": False})
    live.exec(["bash", "-c", "echo one > s1.txt"])
    live.exec(["bash", "-c", "echo two > s2.txt"])
    live.exec(["bash", "-c", "echo three > s3.txt"])
    sid3, _ = live.close()
    page = json.loads(req(f"/api/view/session/{sid3}"))["dossier"]
    if "03 &mdash; Savepoints" not in page or "3 savepoints" not in page:
        fail("savepoints section missing from the dossier")
    if page.count('data-keep="') != 3 or page.count('data-rewind="') != 2 or "s3.txt" not in page:
        fail(f"savepoint controls: keep={page.count('data-keep=')} rewind={page.count('data-rewind=')}")
    detail = json.loads(req(f"/api/session/{sid3}"))
    if [len(sp["paths"]) for sp in detail["savepoints"]] != [1, 1, 1]:
        fail(f"savepoints payload: {detail['savepoints']}")
    for bad in ('{"to": "1"}', '{"to": true}', '{"to": 9}'):
        try:
            req(f"/api/session/{sid3}/rewind", data=bad, method="POST")
            fail(f"bad rewind accepted: {bad}")
        except urllib.error.HTTPError as e:
            if e.code != 400:
                fail(f"bad rewind {bad}: expected 400, got {e.code}")
    res = json.loads(req(f"/api/session/{sid3}/rewind", data='{"to": 1}', method="POST"))
    if sorted(p for _k, p in res["changes"]) != ["s1.txt", "s2.txt"]:
        fail(f"ui rewind: {res}")
    page = json.loads(req(f"/api/view/session/{sid3}"))["dossier"]
    if "2 savepoints" not in page or "Rewound to @1" not in page or "s3.txt" in page:
        fail("dossier not re-rendered after rewind")
    res = json.loads(req(f"/api/session/{sid3}/commit", data='{"drop": "0"}', method="POST"))
    if not res.get("committed") or res.get("dropped") != [0]:
        fail(f"ui commit with drop: {res}")
    if os.path.exists(os.path.join(target, "s1.txt")) or not os.path.exists(
            os.path.join(target, "s2.txt")):
        fail("dropped savepoint reached the tree, or kept one did not")
    page = json.loads(req(f"/api/view/session/{sid3}"))["dossier"]
    if 'class="n dropped">@0' not in page or "savepoints @0" not in page:
        fail("committed dossier does not show the dropped savepoint")
    ok("savepoints rendered; rewind and drop-on-commit act through the UI")

    print("PASS: mission control")
finally:
    server.terminate()
    server.wait()
    subprocess.run(["rm", "-rf", OVERLORD_HOME, target])
