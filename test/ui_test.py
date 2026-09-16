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
import urllib.parse

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OVERLORD_HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = OVERLORD_HOME
sys.path.insert(0, HERE)
import ui  # noqa: E402  (the launch token: open mode's credential)
import overlord as _core  # noqa: E402
if _core.detect_backend() is None:
    print("SKIP: ui (no sandbox backend here — see `overlord doctor`)")
    sys.exit(0)
PORT = 7791
BASE = f"http://127.0.0.1:{PORT}"


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


def req(path, data=None, method=None):
    r = urllib.request.Request(
        BASE + path, data=data.encode() if data else None, method=method,
        headers={"Cookie": ui.local_cookie()}
    )
    with urllib.request.urlopen(r, timeout=10) as resp:
        return resp.read().decode()


target = tempfile.mkdtemp()
with open(os.path.join(target, "f.txt"), "w") as f:
    f.write("v1\n")

# a scripted reviewer for the countersignature endpoint
REVIEW_SCRIPT = os.path.join(OVERLORD_HOME, "approve.json")
with open(REVIEW_SCRIPT, "w") as f:
    json.dump([{"tool_calls": [{"name": "approve", "input": {"reason": "looks right"}}]}], f)
os.environ["OVERLORD_REVIEW_SCRIPT"] = REVIEW_SCRIPT
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

    if "OVERLORD" not in req("/") or "workspace" not in req("/"):
        fail("workspace page render")
    if "mission control" not in req("/console"):
        fail("console page render")
    ok("workspace and console pages render")

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
        hdrs = {"Cookie": ui.local_cookie(), **(headers or {})}
        r = urllib.request.Request(BASE + path, data=data.encode() if data else None,
                                   method=method, headers=hdrs)
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
            BASE + "/", headers={"Origin": BASE, "Cookie": ui.local_cookie()}), timeout=10) as resp:
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

    # --- blame view: a committed path resolves to its sheet; unknown paths do not ---
    page = json.loads(req(f"/api/view/session/{sid}"))["dossier"]
    if f'data-blame="{os.path.join(target, "f.txt")}"' not in page:
        fail("committed manifest paths are not blame links")
    sheet = json.loads(req("/api/view/blame?path=" + urllib.parse.quote(
        os.path.join(target, "f.txt"))))["dossier"]
    if "06 &mdash; Blame" not in sheet or "[0]" not in sheet or ">v2<" not in sheet or \
            f'data-select="{sid}"' not in sheet or "own-0" not in sheet:
        fail(f"blame sheet: {sheet[:600]}")
    if "No committed session" not in json.loads(req("/api/view/blame?path=/nope"))["dossier"]:
        fail("blame of an unrecorded path")
    if json.loads(req("/api/blame?path=" + urllib.parse.quote(
            os.path.join(target, "f.txt"))))["state"] != "current":
        fail("blame JSON endpoint")
    ok("blame view: per-line sheet from a committed path, links back to the session")

    # --- countersignature and fork through the UI ---
    live = core.open_session(target, None, {"net": "host", "jail": False,
                                            "timeout": None, "merge_base": False})
    live.exec(["bash", "-c", "echo one > r1.txt"])
    live.exec(["bash", "-c", "echo two > r2.txt"])
    sid4, _ = live.close()
    page = json.loads(req(f"/api/view/session/{sid4}"))["dossier"]
    if 'class="stamp">unsigned' not in page or 'data-review="' not in page or \
            page.count('data-fork="') != 2 or 'id="countersigned"' not in page:
        fail("pending dossier lacks countersignature / fork controls")
    try:
        req(f"/api/session/{sid4}/commit", data='{"countersigned": true}', method="POST")
        fail("countersigned commit accepted without a review")
    except urllib.error.HTTPError as e:
        if e.code != 400:
            fail(f"unsigned countersigned commit: expected 400, got {e.code}")
    res = json.loads(req(f"/api/session/{sid4}/review",
                         data='{"provider": "scripted", "model": "rev-ui"}', method="POST"))
    if res["review"]["verdict"] != "approve":
        fail(f"ui review: {res}")
    page = json.loads(req(f"/api/view/session/{sid4}"))["dossier"]
    if 'class="stamp approve">approved' not in page or "looks right" not in page:
        fail("approval not rendered")
    forked = json.loads(req(f"/api/session/{sid4}/fork", data='{"at": 0}', method="POST"))["sid"]
    fpage = json.loads(req(f"/api/view/session/{forked}"))["dossier"]
    if "Forked from" not in fpage or f'data-select="{sid4}"' not in fpage or "r2.txt" in fpage:
        fail("fork dossier")
    page = json.loads(req(f"/api/view/session/{sid4}"))["dossier"]
    if "Forks" not in page or f'data-select="{forked}"' not in page:
        fail("origin dossier does not list its fork")
    res = json.loads(req(f"/api/session/{sid4}/rewind", data='{"to": 0}', method="POST"))
    page = json.loads(req(f"/api/view/session/{sid4}"))["dossier"]
    if "stale" not in page:
        fail("approval not shown stale after rewind")
    try:
        req(f"/api/session/{sid4}/commit", data='{"countersigned": true}', method="POST")
        fail("stale approval satisfied countersigned commit")
    except urllib.error.HTTPError as e:
        if e.code != 400:
            fail(f"stale countersigned commit: expected 400, got {e.code}")
    json.loads(req(f"/api/session/{sid4}/review",
                   data='{"provider": "scripted", "model": "rev-ui"}', method="POST"))
    res = json.loads(req(f"/api/session/{sid4}/commit", data='{"countersigned": true}', method="POST"))
    if not res.get("committed") or not os.path.exists(os.path.join(target, "r1.txt")):
        fail(f"countersigned commit via UI: {res}")
    page = json.loads(req(f"/api/view/session/{sid4}"))["dossier"]
    if "Countersigned" not in page or "scripted:rev-ui" not in page:
        fail("committed dossier does not show the countersignature")
    json.loads(req(f"/api/session/{forked}/rollback", data="{}", method="POST"))
    ok("countersignature: request, stale-after-rewind, re-sign, commit; fork lineage rendered")

    print("PASS: mission control")
finally:
    server.terminate()
    server.wait()
    subprocess.run(["rm", "-rf", OVERLORD_HOME, target])
