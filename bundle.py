#!/usr/bin/env python3
"""OVERLORD bundles — hand a session to someone else as one file.

    overlord export <sid> [-o session.ovl]      # a signed tar.gz
    overlord import session.ovl                 # the record, on this machine
    overlord import session.ovl -t /srv/app     # a pending session's changes,
                                                # replayed as a new pending
                                                # session on that folder
    overlord bundle key                         # the signing key to share

What goes in: the session's record (meta, transcript, provenance, output),
the retained file versions its provenance names (so blame keeps working
where it lands), and — for a pending session — every changed file's
content and the list of deletions. A manifest hashes every member; the
manifest is HMAC-signed with ~/.overlord/bundle.key (made on first use,
mode 600). Import verifies each hash and, when it has the key, the
signature; an altered member or a forged manifest is refused. Without the
key the import is marked unverified and --require-signature refuses it.
Extraction is strict: relative names under known prefixes, regular files
only, sizes as declared.

A replayed import opens a new session on the folder, writes the files and
deletions inside the transaction with an `import` cause on every layer,
and closes it pending: the usual review, diff, savepoints and commit apply.
Nothing reaches the folder until a person commits. Both export and import
are audited.
"""

import base64
import hashlib
import hmac
import io
import json
import os
import secrets
import shutil
import socket
import tarfile
import time

import overlord as core

FORMAT = 1
KEY_FILE = os.path.join(core.OVERLORD_HOME, "bundle.key")
PREFIXES = ("record/", "objects/", "diff/")
RECORD_FILES = ("meta.json", "transcript.jsonl", "provenance.jsonl", "output.log", "review.log")
CHUNK = 512 * 1024


class BundleError(core.OverlordError):
    pass


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def signing_key(create=True):
    try:
        with open(KEY_FILE) as f:
            return f.read().strip()
    except OSError:
        if not create:
            return None
    os.makedirs(core.OVERLORD_HOME, exist_ok=True)
    key = secrets.token_hex(32)
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key + "\n")
    return key


def _sign(key, manifest):
    canon = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key.encode(), canon, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- export


def export_session(sid, out=None):
    m = core.load_meta(sid)
    if m.get("status") == "open":
        raise BundleError("error: the session is open (a holder runs it); close it first")
    sdir = core.session_path(sid)
    members = {}                                  # name -> bytes
    for name in RECORD_FILES:
        p = os.path.join(sdir, name)
        if os.path.isfile(p):
            with open(p, "rb") as f:
                members[f"record/{name}"] = f.read()
    for name in sorted(os.listdir(sdir)):
        p = os.path.join(sdir, name)
        if name.startswith("transcript.rewound") and os.path.isfile(p):
            with open(p, "rb") as f:
                members[f"record/{name}"] = f.read()
    # retained versions the provenance names, so blame survives the move
    digests = set()
    prov = members.get("record/provenance.jsonl", b"")
    for line in prov.decode(errors="replace").splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        for k in ("before_sha256", "after_sha256"):
            if r.get(k):
                digests.add(r[k])
    for d in sorted(digests):
        p = os.path.join(core.OBJECTS_DIR, d)
        if os.path.isfile(p):
            with open(p, "rb") as f:
                members[f"objects/{d}"] = f.read()
    # a pending session's changes, as files, so they can be replayed elsewhere
    diff = {"added": [], "modified": [], "deleted": [], "skipped": []}
    if m.get("status") == "pending":
        changes, origin, _t, uppers = core.session_stack(sid, m)
        for kind, rel in changes:
            if kind in ("deleted", "replaced-dir") or rel.endswith("/"):
                if kind in ("deleted", "replaced-dir"):
                    diff["deleted"].append(rel.rstrip("/"))
                continue
            src = core._safe_join(uppers[origin[rel]], rel) if rel in origin else None
            if not src or not os.path.isfile(src) or os.path.islink(src):
                diff["skipped"].append(rel)
                continue
            if os.path.getsize(src) > 64 << 20:
                diff["skipped"].append(rel)
                continue
            with open(src, "rb") as f:
                members[f"diff/{rel}"] = f.read()
            diff[kind if kind in ("added", "modified") else "modified"].append(rel)
    manifest = {"format": FORMAT, "sid": sid, "status": m.get("status"), "target": m.get("target"),
                "owner": m.get("owner"), "agent": m.get("agent"), "task": (m.get("task") or "")[:300],
                "exported": time.strftime(core.TS_FORMAT), "host": socket.gethostname(),
                "overlord": core.VERSION, "diff": diff,
                "files": {name: _sha(data) for name, data in members.items()}}
    import audit
    manifest["by"] = audit.actor_name(m.get("owner"))
    manifest["audit"] = [e for e in audit.entries(n=0) if e.get("sid") == sid][-50:]
    key = signing_key()
    bundle_json = json.dumps(manifest, indent=1).encode()
    sig = _sign(key, {"files": manifest["files"], "sid": sid, "exported": manifest["exported"]})
    out = out or f"{sid}.ovl"
    with tarfile.open(out, "w:gz") as tar:
        def add(name, data):
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(data), int(time.time()), 0o600
            tar.addfile(ti, io.BytesIO(data))
        add("bundle.json", bundle_json)
        add("bundle.sig", (sig + "\n").encode())
        for name, data in members.items():
            add(name, data)
    audit.record("session.export", sid=sid, owner=m.get("owner"), out=os.path.basename(out),
                 members=len(members), status=m.get("status"))
    return {"path": out, "members": len(members), "diff": diff, "bytes": os.path.getsize(out)}


# ---------------------------------------------------------------- import


def read_bundle(path):
    """Strictly read a bundle: known names only, regular files only, every
    hash as the manifest says. Returns (manifest, members, signature)."""
    try:
        tar = tarfile.open(path, "r:gz")
    except (tarfile.TarError, OSError) as e:
        raise BundleError(f"error: not a bundle: {e}")
    members, manifest, sig = {}, None, None
    with tar:
        for ti in tar:
            name = ti.name
            if name.startswith("/") or ".." in name.split("/") or "\\" in name:
                raise BundleError(f"error: refusing bundle member {name!r}")
            if not ti.isreg():
                raise BundleError(f"error: refusing non-file bundle member {name!r}")
            if name not in ("bundle.json", "bundle.sig") and not name.startswith(PREFIXES):
                raise BundleError(f"error: unexpected bundle member {name!r}")
            data = tar.extractfile(ti).read()
            if len(data) != ti.size:
                raise BundleError(f"error: short read on {name}")
            if name == "bundle.json":
                try:
                    manifest = json.loads(data.decode())
                except ValueError:
                    raise BundleError("error: bundle.json is not JSON")
            elif name == "bundle.sig":
                sig = data.decode().strip()
            else:
                members[name] = data
    if not manifest or manifest.get("format") != FORMAT:
        raise BundleError("error: missing or unsupported bundle.json")
    declared = manifest.get("files") or {}
    if set(declared) != set(members):
        raise BundleError("error: bundle members do not match the manifest")
    for name, data in members.items():
        if _sha(data) != declared[name]:
            raise BundleError(f"error: {name} does not match its hash — the bundle was altered")
    core.validate_session_id(str(manifest.get("sid") or ""))
    return manifest, members, sig


def verify_signature(manifest, sig, key):
    if not sig or not key:
        return False
    want = _sign(key, {"files": manifest["files"], "sid": manifest["sid"], "exported": manifest["exported"]})
    return hmac.compare_digest(want, sig)


def import_bundle(path, target=None, key_file=None, require_signature=False):
    manifest, members, sig = read_bundle(path)
    key = None
    if key_file:
        with open(key_file) as f:
            key = f.read().strip()
    else:
        key = signing_key(create=False)
    verified = verify_signature(manifest, sig, key)
    if require_signature and not verified:
        raise BundleError("error: signature missing, wrong, or no key to check it with (--key)")
    sid = manifest["sid"]
    import audit
    # retained objects land in the content-addressed store, checked by name
    kept_objects = 0
    for name, data in members.items():
        if name.startswith("objects/"):
            d = name[len("objects/"):]
            if _sha(data) != d:
                raise BundleError(f"error: object {d} is not what it claims")
            os.makedirs(core.OBJECTS_DIR, exist_ok=True)
            p = os.path.join(core.OBJECTS_DIR, d)
            if not os.path.exists(p):
                with open(p + ".tmp", "wb") as f:
                    f.write(data)
                os.replace(p + ".tmp", p)
            kept_objects += 1
    if target is None:
        # the record, as it was, under its own id
        sdir = core.session_path(sid)
        if os.path.exists(sdir):
            raise BundleError(f"error: session {sid} already exists here")
        os.makedirs(sdir)
        try:
            for name, data in members.items():
                if name.startswith("record/"):
                    fn = name[len("record/"):]
                    if "/" in fn:
                        raise BundleError(f"error: refusing record member {fn!r}")
                    with open(os.path.join(sdir, fn), "wb") as f:
                        f.write(data)
            meta = json.loads(members["record/meta.json"].decode())
            meta["id"] = sid
            if meta.get("status") == "pending":
                meta["status"] = "imported"            # no layers travelled: reviewable, not committable
            meta.pop("holder_pid", None)
            meta["imported"] = {"from": manifest.get("host"), "exported": manifest.get("exported"),
                                "by": manifest.get("by"), "ts": time.strftime(core.TS_FORMAT),
                                "verified": verified, "objects": kept_objects}
            core.save_meta(sid, meta)
        except Exception:
            shutil.rmtree(sdir, ignore_errors=True)
            raise
        audit.record("session.import", sid=sid, owner=meta.get("owner"), mode="record",
                     verified=verified, source=manifest.get("host"))
        return {"sid": sid, "mode": "record", "verified": verified, "objects": kept_objects,
                "status": meta["status"]}
    # replay: a new pending session on the folder carrying the bundle's changes
    diff = manifest.get("diff") or {}
    if manifest.get("status") != "pending" or not (diff.get("added") or diff.get("modified")
                                                     or diff.get("deleted")):
        raise BundleError("error: this bundle carries no pending changes to replay (import it "
                          "without -t to keep the record)")
    target = os.path.realpath(target)
    backend = core.detect_backend()
    if backend is None:
        raise BundleError("error: no sandbox backend available")
    grants = {"net": "none", "jail": backend == "kernel", "timeout": None, "merge_base": False}
    live = core.open_session(target, backend, grants, capture=True,
                             agent=manifest.get("agent") or "import", owner=core_owner())
    new = live.sid
    try:
        cause = {"tool": "import", "summary": f"bundle {os.path.basename(path)} from {manifest.get('host')}",
                 "turn": 0}
        for rel in list(diff.get("added", [])) + list(diff.get("modified", [])):
            data = members.get(f"diff/{rel}")
            if data is None:
                continue
            _write_inside(live, rel, data, cause)
        for rel in diff.get("deleted", []):
            rc, out = live.exec(["rm", "-rf", "--", rel], timeout=60, cause=cause)
        live.meta["task"] = manifest.get("task") or f"imported from {manifest.get('host')}"
        live.meta["imported_from"] = {"sid": sid, "from": manifest.get("host"),
                                      "exported": manifest.get("exported"), "by": manifest.get("by"),
                                      "verified": verified}
        tr = members.get("record/transcript.jsonl") or b""
        if True:                      # the record always says where it came from
            with open(os.path.join(live.sdir, "transcript.jsonl"), "wb") as f:
                f.write(tr)
                f.write((json.dumps({"ts": time.strftime(core.TS_FORMAT), "type": "note",
                                     "text": f"imported from {manifest.get('host')} as {new}; "
                                             f"the changes above were replayed here"
                                             + ("" if verified else " (signature not verified)")})
                         + "\n").encode())
        core.save_meta(new, live.meta)
    finally:
        _sid, changes = live.close()
    audit.record("session.import", sid=new, owner=live.meta.get("owner"), mode="replay",
                 source_sid=sid, verified=verified, source=manifest.get("host"), files=len(changes))
    return {"sid": new, "mode": "replay", "verified": verified, "changes": changes,
            "objects": kept_objects}


def core_owner():
    try:
        import auth
        return auth.current_user()
    except ImportError:
        return None


def _write_inside(live, rel, data, cause):
    """Write a file inside the transaction in base64 chunks (argv-sized)."""
    code = ("import base64,os,sys\n"
            "p=sys.argv[1]; d=os.path.dirname(p); d and os.makedirs(d, exist_ok=True)\n"
            "mode='ab' if sys.argv[3]=='append' else 'wb'\n"
            "open(p, mode).write(base64.b64decode(sys.argv[2]))\n")
    first = True
    for i in range(0, max(len(data), 1), CHUNK):
        chunk = base64.b64encode(data[i:i + CHUNK]).decode()
        rc, out = live.exec(["python3", "-c", code, rel, chunk, "write" if first else "append"],
                            timeout=120, cause=cause)
        if rc != 0:
            raise BundleError(f"error: could not write {rel} inside the session: {out.decode(errors='replace')[-200:]}")
        first = False


# ---------------------------------------------------------------- cli


def cmd_export(args):
    r = export_session(args.session, args.out)
    d = r["diff"]
    extra = (f"; changes: {len(d['added'])} added, {len(d['modified'])} modified, "
             f"{len(d['deleted'])} deleted" if any(d.values()) else "")
    print(f"exported {args.session} to {r['path']} ({r['bytes']} bytes, {r['members']} member(s){extra})")
    print(f"the importing machine verifies it with the key in {KEY_FILE} (overlord bundle key)")
    return 0


def cmd_import(args):
    r = import_bundle(args.bundle, target=args.target, key_file=args.key,
                      require_signature=args.require_signature)
    v = "signature verified" if r["verified"] else "signature NOT verified"
    if r["mode"] == "record":
        print(f"imported record {r['sid']} (status {r['status']}, {r['objects']} retained object(s); {v})")
    else:
        print(f"replayed as new pending session {r['sid']}: {len(r['changes'])} change(s); {v}")
        print(f"review with: overlord diff {r['sid']}   then overlord commit {r['sid']}")
    return 0


def cmd_bundle(args):
    if args.bundle_cmd == "key":
        print(f"{KEY_FILE}\n{signing_key()}")
        return 0
    raise BundleError("error: unknown bundle subcommand")


def add_bundle_parsers(sub):
    pe = sub.add_parser("export", help="a session as one signed file")
    pe.add_argument("session")
    pe.add_argument("-o", "--out")
    pe.set_defaults(fn=cmd_export)
    pi = sub.add_parser("import", help="a bundle: its record, or its changes replayed onto a folder")
    pi.add_argument("bundle")
    pi.add_argument("-t", "--target", help="replay a pending bundle's changes onto this folder")
    pi.add_argument("--key", help="the exporting machine's bundle.key")
    pi.add_argument("--require-signature", action="store_true")
    pi.set_defaults(fn=cmd_import)
    pb = sub.add_parser("bundle", help="bundle signing")
    bs = pb.add_subparsers(dest="bundle_cmd", required=True)
    bs.add_parser("key", help="print (creating if needed) this machine's signing key")
    pb.set_defaults(fn=cmd_bundle)
