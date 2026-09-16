#!/usr/bin/env python3
"""OVERLORD retention — what the machine keeps, and for how long.

Records accumulate: a committed session keeps its meta, transcript and
provenance forever by default (they are what `blame` and the journal are
made of), the object store keeps every committed file version, and locks
are left behind by crashed processes. `overlord gc` prunes with rules
that never touch live work:

  - a pending session is never removed;
  - a committed or rolled-back record older than --keep-days is removed,
    but the newest --keep-last committed records are kept regardless;
  - an object no remaining record refers to is removed;
  - a lock file nobody holds is removed.

The audit log and the cost ledger are never pruned here — they are the
account of what happened. Defaults live in ~/.overlord/retention.json
({"keep_days": 30, "keep_last": 50}); a systemd timer in packaging/ runs
this nightly.

    overlord gc [--keep-days N] [--keep-last N] [--dry-run]
"""

import fcntl
import json
import os
import shutil
import time

import overlord as core

CONFIG_FILE = os.path.join(core.OVERLORD_HOME, "retention.json")
DEFAULTS = {"keep_days": 30, "keep_last": 50}


def load_config():
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_FILE) as f:
            saved = json.load(f)
        for k in DEFAULTS:
            if isinstance(saved.get(k), int) and saved[k] >= 0:
                cfg[k] = saved[k]
    except (OSError, ValueError):
        pass
    return cfg


def save_config(cfg):
    os.makedirs(core.OVERLORD_HOME, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump({k: int(cfg.get(k, DEFAULTS[k])) for k in DEFAULTS}, f, indent=2)


def _finished_ts(m):
    return m.get("committed") or m.get("finished") or m.get("started") or ""


def plan(keep_days=None, keep_last=None):
    """What gc would do. Nothing is touched here."""
    cfg = load_config()
    keep_days = cfg["keep_days"] if keep_days is None else keep_days
    keep_last = cfg["keep_last"] if keep_last is None else keep_last
    cutoff = time.strftime(core.TS_FORMAT, time.localtime(time.time() - keep_days * 86400))
    metas = []
    for sid in core.list_sessions():
        try:
            metas.append(core.load_meta(sid))
        except core.OverlordError:
            continue
    done = sorted((m for m in metas if m.get("status") in ("committed", "rolled-back")),
                  key=lambda m: (m.get("committed_ns") or 0, _finished_ts(m)), reverse=True)
    protected = {m["id"] for m in done[:keep_last] if m.get("status") == "committed"}
    remove = [m for m in done if m["id"] not in protected and _finished_ts(m) < cutoff]
    keep_ids = {m["id"] for m in metas} - {m["id"] for m in remove}

    referenced = set()
    for sid in keep_ids:
        prov = core.session_file(sid, core.PROVENANCE_FILE)
        if not os.path.isfile(prov):
            continue
        with open(prov) as f:
            for line in f:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                for k in ("before_sha256", "after_sha256"):
                    if r.get(k):
                        referenced.add(r[k])
    orphans = []
    if os.path.isdir(core.OBJECTS_DIR):
        for name in os.listdir(core.OBJECTS_DIR):
            if name.endswith(".tmp") or name in referenced:
                continue
            orphans.append(name)

    stale_locks = []
    if os.path.isdir(core.LOCKS_DIR):
        for name in os.listdir(core.LOCKS_DIR):
            path = os.path.join(core.LOCKS_DIR, name)
            try:
                fd = open(path, "a")
            except OSError:
                continue
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                stale_locks.append(name)          # nobody holds it
            except BlockingIOError:
                pass
            finally:
                fd.close()
    return {"keep_days": keep_days, "keep_last": keep_last, "cutoff": cutoff,
            "sessions": [{"id": m["id"], "status": m.get("status"), "finished": _finished_ts(m),
                          "target": m.get("target")} for m in remove],
            "objects": orphans, "locks": stale_locks, "records_kept": len(keep_ids)}


def run(keep_days=None, keep_last=None, dry_run=False):
    p = plan(keep_days, keep_last)
    if dry_run:
        return {**p, "dry_run": True}
    for s in p["sessions"]:
        shutil.rmtree(core.session_path(s["id"]), ignore_errors=True)
    freed = 0
    for name in p["objects"]:
        path = os.path.join(core.OBJECTS_DIR, name)
        try:
            freed += os.path.getsize(path)
            os.unlink(path)
        except OSError:
            pass
    for name in p["locks"]:
        try:
            os.unlink(os.path.join(core.LOCKS_DIR, name))
        except OSError:
            pass
    import audit
    audit.record("gc", sessions=len(p["sessions"]), objects=len(p["objects"]),
                 locks=len(p["locks"]), keep_days=p["keep_days"], keep_last=p["keep_last"])
    return {**p, "dry_run": False, "freed_bytes": freed}


def usage():
    """Disk taken by records and objects, for doctor and healthz."""
    def size(path):
        total = 0
        for root, _d, files in os.walk(path):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
        return total
    return {"sessions": len(core.list_sessions()),
            "sessions_bytes": size(core.SESSIONS_DIR) if os.path.isdir(core.SESSIONS_DIR) else 0,
            "objects": len(os.listdir(core.OBJECTS_DIR)) if os.path.isdir(core.OBJECTS_DIR) else 0,
            "objects_bytes": size(core.OBJECTS_DIR) if os.path.isdir(core.OBJECTS_DIR) else 0}


def cmd_gc(args):
    if args.set_keep_days is not None or args.set_keep_last is not None:
        cfg = load_config()
        if args.set_keep_days is not None:
            cfg["keep_days"] = max(0, args.set_keep_days)
        if args.set_keep_last is not None:
            cfg["keep_last"] = max(0, args.set_keep_last)
        save_config(cfg)
        print(f"retention: keep_days={cfg['keep_days']} keep_last={cfg['keep_last']}")
        return 0
    r = run(args.keep_days, args.keep_last, dry_run=args.dry_run)
    verb = "would remove" if r["dry_run"] else "removed"
    print(f"{verb}: {len(r['sessions'])} record(s) finished before {r['cutoff'][:10]} "
          f"(keeping the newest {r['keep_last']} committed), {len(r['objects'])} orphan object(s), "
          f"{len(r['locks'])} stale lock(s); {r['records_kept']} record(s) kept")
    for s in r["sessions"][:20]:
        print(f"  {s['id']}  {s['status']:12} {s['finished'][:10]}  {s['target']}")
    if len(r["sessions"]) > 20:
        print(f"  … {len(r['sessions']) - 20} more")
    return 0


def add_gc_parser(sub):
    pg = sub.add_parser("gc", help="prune old records, orphan objects and stale locks")
    pg.add_argument("--keep-days", type=int, help="remove finished records older than this")
    pg.add_argument("--keep-last", type=int, help="always keep this many newest committed records")
    pg.add_argument("--dry-run", action="store_true")
    pg.add_argument("--set-keep-days", type=int, help="save a default")
    pg.add_argument("--set-keep-last", type=int, help="save a default")
    pg.set_defaults(fn=cmd_gc)
