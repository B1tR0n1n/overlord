#!/usr/bin/env python3
"""Bundles e2e: a committed session exports as a signed tar.gz with its
record and retained objects; a second machine imports the record (blame
works there), refuses an altered member, refuses an unsigned bundle when
told to; a pending session exports its changes and replays onto a folder
as a new pending session with `import` causes that commits normally; the
workspace serves the export; crafted tars are refused. No network."""

import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
HOME = tempfile.mkdtemp()
HOME2 = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = HOME

import overlord as ov      # noqa: E402
import bundle              # noqa: E402
import audit               # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


def cli(*args, home=HOME):
    env = dict(os.environ, OVERLORD_HOME=home)
    return subprocess.run([sys.executable, os.path.join(HERE, "overlord.py"), *args],
                          capture_output=True, text=True, env=env)


BACKEND = ov.detect_backend()
if BACKEND is None:
    print("SKIP: bundle (no sandbox backend here — see `overlord doctor`)")
    sys.exit(0)
KERNEL = BACKEND == "kernel"
grants = {"net": "none" if KERNEL else "host", "jail": KERNEL, "timeout": None, "merge_base": False}
target = tempfile.mkdtemp()
with open(os.path.join(target, "f.txt"), "w") as f:
    f.write("v1\n")
with open(os.path.join(target, "gone.txt"), "w") as f:
    f.write("bye\n")
os.makedirs(os.path.join(target, "sub"))


def session(cmd, agent="scripted:x"):
    live = ov.open_session(target, BACKEND, grants, capture=True, agent=agent)
    live.exec(["bash", "-c", cmd])
    live.meta["task"] = "a task"
    ov.save_meta(live.sid, live.meta)
    sid, changes = live.close()
    return sid, changes


try:
    # 1. export a committed session: manifest, hashes, objects, signature
    sid, _ = session("echo v2 > f.txt")
    ov.commit_session(sid)
    out = os.path.join(HOME, "one.ovl")
    r = cli("export", sid, "-o", out)
    if r.returncode != 0 or not os.path.isfile(out) or "bundle key" not in r.stdout:
        fail(f"export: {r.stdout} {r.stderr}")
    with tarfile.open(out) as tar:
        names = tar.getnames()
        manifest = json.load(tar.extractfile("bundle.json"))
    if "record/meta.json" not in names or "record/provenance.jsonl" not in names or "bundle.sig" not in names:
        fail(f"members: {names}")
    objs = [n for n in names if n.startswith("objects/")]
    if len(objs) != 2 or manifest["sid"] != sid or manifest["status"] != "committed" \
            or set(manifest["files"]) != set(n for n in names if n not in ("bundle.json", "bundle.sig")):
        fail(f"manifest: {len(objs)} objects, {manifest.get('sid')} {manifest.get('status')}")
    if not any(e["action"] == "session.export" and e["sid"] == sid for e in audit.entries(n=0)):
        fail("export not audited")
    if os.stat(bundle.KEY_FILE).st_mode & 0o077:
        fail("bundle key not private")
    ok("export: record + both retained versions + hashed manifest + signature; audited")

    # 2. a second machine imports the record; blame works there; tamper and signature checks
    r = cli("import", out, "--require-signature", home=HOME2)
    if r.returncode == 0:
        fail("verified import without the key")
    r = cli("import", out, home=HOME2)
    if r.returncode != 0 or "NOT verified" not in r.stdout:
        fail(f"unsigned import should succeed but say so: {r.stdout} {r.stderr}")
    shutil.rmtree(os.path.join(HOME2, "sessions", sid))
    key2 = os.path.join(HOME2, "their.key")
    shutil.copy(bundle.KEY_FILE, key2)
    r = cli("import", out, "--require-signature", "--key", key2, home=HOME2)
    if r.returncode != 0 or "signature verified" not in r.stdout:
        fail(f"verified import: {r.stdout} {r.stderr}")
    r = cli("import", out, "--key", key2, home=HOME2)
    if r.returncode == 0:
        fail("a second import of the same id should be refused")
    m2 = json.load(open(os.path.join(HOME2, "sessions", sid, "meta.json")))
    if m2["status"] != "committed" or not m2["imported"]["verified"] or m2["imported"]["objects"] != 2:
        fail(f"imported meta: {m2.get('imported')} {m2['status']}")
    r = cli("blame", os.path.join(target, "f.txt"), home=HOME2)
    if r.returncode != 0 or sid[-6:] not in r.stdout and sid not in r.stdout:
        fail(f"blame on the second machine: {r.stdout} {r.stderr}")
    if "session.import" not in [e["action"] for e in json.loads("[" + ",".join(
            open(os.path.join(HOME2, "audit.jsonl")).read().split("\n")[:-1]) + "]")]:
        fail("import not audited on the second machine")
    # tamper: rewrite the transcript inside the tar
    bad = os.path.join(HOME, "bad.ovl")
    with tarfile.open(out) as src, tarfile.open(bad, "w:gz") as dst:
        for ti in src:
            data = src.extractfile(ti).read()
            if ti.name == "record/provenance.jsonl":
                data = data.replace(b'"modified"', b'"added"')
                ti.size = len(data)
            dst.addfile(ti, io.BytesIO(data))
    r = cli("import", bad, home=HOME2)
    if r.returncode == 0 or "altered" not in r.stderr:
        fail(f"altered member accepted: {r.stdout} {r.stderr}")
    # forged manifest: consistent hashes but no valid signature
    forged = os.path.join(HOME, "forged.ovl")
    with tarfile.open(out) as src, tarfile.open(forged, "w:gz") as dst:
        for ti in src:
            data = src.extractfile(ti).read()
            if ti.name == "bundle.json":
                mf = json.loads(data)
                mf["sid"] = "20200101-000000-abcdef"
                data = json.dumps(mf).encode()
                ti.size = len(data)
            dst.addfile(ti, io.BytesIO(data))
    r = cli("import", forged, "--require-signature", "--key", key2, home=HOME2)
    if r.returncode == 0:
        fail("forged manifest passed signature check")
    ok("second machine: record + objects imported, blame works; altered members and forged manifests refused")

    # 3. a pending session's changes replay onto a folder as a new pending session
    psid, changes = session("echo v3 > f.txt; echo new > sub/n.txt; rm gone.txt")
    if sorted(changes) != [("added", "sub/n.txt"), ("deleted", "gone.txt"), ("modified", "f.txt")]:
        fail(f"pending changes: {changes}")
    pout = os.path.join(HOME, "pending.ovl")
    res = bundle.export_session(psid, pout)
    if res["diff"]["added"] != ["sub/n.txt"] or res["diff"]["modified"] != ["f.txt"] \
            or res["diff"]["deleted"] != ["gone.txt"]:
        fail(f"pending diff: {res['diff']}")
    ov.rollback_session(psid)
    target2 = tempfile.mkdtemp()
    for n in ("f.txt", "gone.txt"):
        shutil.copy(os.path.join(target, n), os.path.join(target2, n))
    os.makedirs(os.path.join(target2, "sub"))
    before = open(os.path.join(target2, "f.txt")).read()
    r = cli("import", pout, "-t", target2, "--require-signature")
    if r.returncode != 0 or "replayed as new pending session" not in r.stdout:
        fail(f"replay import: {r.stdout} {r.stderr}")
    new = r.stdout.split("session ")[1].split(":")[0]
    m = ov.load_meta(new)
    if m["status"] != "pending" or m["imported_from"]["sid"] != psid or not m["imported_from"]["verified"] \
            or m["task"] != "a task":
        fail(f"replayed meta: {m.get('status')} {m.get('imported_from')} {m.get('task')}")
    ch = ov.session_stack(new, m)[0]
    if sorted(ch) != [("added", "sub/n.txt"), ("deleted", "gone.txt"), ("modified", "f.txt")]:
        fail(f"replayed changes: {ch}")
    prov = [json.loads(l) for l in open(ov.session_file(new, ov.PROVENANCE_FILE))]
    if not prov or any((p.get("caused_by") or {}).get("tool") != "import" for p in prov):
        fail(f"import cause missing: {[p.get('caused_by') for p in prov]}")
    tr = [json.loads(l) for l in open(ov.session_file(new, "transcript.jsonl"))]
    if tr[-1]["type"] != "note" or "imported from" not in tr[-1]["text"]:
        fail("replay transcript note")
    if open(os.path.join(target2, "f.txt")).read() != before or not os.path.exists(os.path.join(target2, "gone.txt")):
        fail("the folder changed before commit")
    res = ov.commit_session(new)
    if not res["committed"] or open(os.path.join(target2, "f.txt")).read() != "v3\n" \
            or os.path.exists(os.path.join(target2, "gone.txt")) \
            or open(os.path.join(target2, "sub", "n.txt")).read() != "new\n":
        fail("replayed session did not commit cleanly")
    r = cli("import", out, "-t", target2)
    if r.returncode == 0 or "no pending changes" not in r.stderr:
        fail("a committed bundle should not replay")
    ok("a pending session's changes replay onto another folder with import causes; commit applies them")

    # 4. the workspace serves the export; the inspector offers it
    import ui
    import chatui
    from http.server import ThreadingHTTPServer
    PORT = 7785
    server = ThreadingHTTPServer(("127.0.0.1", PORT), ui.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{PORT}/api/session/{sid}/export",
                                     headers={"Host": f"127.0.0.1:{PORT}", "Cookie": ui.local_cookie()})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data, hdrs = resp.read(), resp.headers
        if hdrs.get("Content-Type") != "application/gzip" or f'{sid}.ovl' not in hdrs.get("Content-Disposition", ""):
            fail(f"export headers: {dict(hdrs)}")
        got = os.path.join(HOME, "ui.ovl")
        with open(got, "wb") as f:
            f.write(data)
        mf, members, sig = bundle.read_bundle(got)
        if mf["sid"] != sid or not bundle.verify_signature(mf, sig, bundle.signing_key()):
            fail("the served bundle does not verify")
        html = chatui.render_inspector(sid)
        if f"/api/session/{sid}/export" not in html:
            fail("inspector lacks the Export link")
        ok("the workspace serves a verifiable bundle; the inspector links it")
    finally:
        server.shutdown()

    # 5. crafted tars are refused: escaping names, symlinks, unexpected members
    for name, kind in (("../../etc/cron.d/x", "file"), ("/etc/passwd", "file"),
                       ("record/link", "symlink"), ("elsewhere/x", "file")):
        p = os.path.join(HOME, "crafted.ovl")
        with tarfile.open(p, "w:gz") as tar:
            mf = json.dumps({"format": 1, "sid": sid, "files": {}, "exported": "x"}).encode()
            ti = tarfile.TarInfo("bundle.json")
            ti.size = len(mf)
            tar.addfile(ti, io.BytesIO(mf))
            ti = tarfile.TarInfo(name)
            if kind == "symlink":
                ti.type, ti.linkname = tarfile.SYMTYPE, "/etc/passwd"
                tar.addfile(ti)
            else:
                ti.size = 1
                tar.addfile(ti, io.BytesIO(b"x"))
        try:
            bundle.read_bundle(p)
            fail(f"crafted member accepted: {name}")
        except bundle.BundleError as e:
            if "refusing" not in str(e) and "unexpected" not in str(e):
                fail(f"wrong refusal for {name}: {e}")
    ok("crafted bundles refused: escaping names, absolute paths, symlinks, unexpected members")

    print("PASS: bundles")
finally:
    subprocess.run(["rm", "-rf", HOME, HOME2, target])
