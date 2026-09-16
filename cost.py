#!/usr/bin/env python3
"""OVERLORD cost — what the model spends, and the lines it may not cross.

Every model call already returns its token usage; the session keeps the
running total (meta["usage"]). This module prices it, writes one ledger
line per call, and enforces budgets before the next call is made:

  prices   ~/.overlord/cost.json {"prices": {"<model substring>": {"in": $/M, "out": $/M}}}
           A few known list prices ship as defaults; set your own contract's.
           An unknown model is still counted in tokens; its dollars are null.
  ledger   ~/.overlord/ledger.jsonl — one line per call: ts, session, owner,
           model, in, out, usd. `overlord cost` sums it by model, account, day.
  budgets  most restrictive of: the global config ("budget" in cost.json),
           the policy rule for the target ("budget": {...}), the account
           (users.json "budget"). Keys: session_tokens, session_usd, day_usd,
           month_usd (set it to your provider's monthly cap: the API does not
           report the cap, so the meter measures against the number you give).
  ~/.overlord/ratelimit.json  the provider's own rate-limit headers from its
           last reply — the only live statement of headroom a key can get.
           A session that crosses a line stops with reason "budget" before
           the next call; the stop is in the transcript and the audit log.

    overlord cost [--days N] [--user U]      # spend by model / account / day
    overlord cost prices                     # the table in effect
    overlord cost set-price <model> <in> <out>
    overlord cost budget [--session-tokens N] [--session-usd X] [--day-usd X]
"""

import json
import os
import threading
import time

import overlord as core

CONFIG_FILE = os.path.join(core.OVERLORD_HOME, "cost.json")
LEDGER_FILE = os.path.join(core.OVERLORD_HOME, "ledger.jsonl")
BUDGET_KEYS = ("session_tokens", "session_usd", "day_usd", "month_usd")
RATE_FILE = os.path.join(core.OVERLORD_HOME, "ratelimit.json")

# USD per million tokens, list prices; substring match, longest key wins.
# Override in cost.json — a contract price, a gateway, a model not listed.
DEFAULT_PRICES = {
    "claude-fable-5": {"in": 10.0, "out": 50.0},
    "claude-mythos-5": {"in": 10.0, "out": 50.0},
    "claude-opus-5": {"in": 5.0, "out": 25.0},
    "claude-opus-4": {"in": 15.0, "out": 75.0},      # 4 and 4.1
    "claude-opus-4-5": {"in": 5.0, "out": 25.0},
    "claude-opus-4-6": {"in": 5.0, "out": 25.0},
    "claude-opus-4-7": {"in": 5.0, "out": 25.0},
    "claude-opus-4-8": {"in": 5.0, "out": 25.0},
    "claude-sonnet-5": {"in": 2.0, "out": 10.0},
    "claude-sonnet-4": {"in": 3.0, "out": 15.0},
    "claude-haiku-4": {"in": 1.0, "out": 5.0},
    "gpt-5": {"in": 1.25, "out": 10.0},
    "gpt-5-mini": {"in": 0.25, "out": 2.0},
    "gemini-2.5-pro": {"in": 1.25, "out": 10.0},
    "gemini-2.5-flash": {"in": 0.30, "out": 2.50},
}
_LOCK = threading.Lock()


class BudgetExceeded(core.OverlordError):
    """A budget line was crossed; the session stops before the next call."""


# ---------------------------------------------------------------- config


def load_config():
    cfg = {"prices": dict(DEFAULT_PRICES), "budget": {}}
    try:
        with open(CONFIG_FILE) as f:
            saved = json.load(f)
    except (OSError, ValueError):
        return cfg
    for k, v in (saved.get("prices") or {}).items():
        if isinstance(v, dict) and "in" in v and "out" in v:
            cfg["prices"][str(k)] = {"in": float(v["in"]), "out": float(v["out"])}
    cfg["budget"] = _clean_budget(saved.get("budget") or {})
    return cfg


def save_config(cfg):
    os.makedirs(core.OVERLORD_HOME, exist_ok=True)
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"prices": cfg.get("prices", {}), "budget": cfg.get("budget", {})}, f, indent=2)
    os.replace(tmp, CONFIG_FILE)


def _clean_budget(b):
    out = {}
    for k in BUDGET_KEYS:
        v = b.get(k) if isinstance(b, dict) else None
        if v in (None, "", 0, "0"):
            continue
        try:
            v = float(v)
        except (TypeError, ValueError):
            raise core.OverlordError(f"error: budget {k} must be a number")
        if v <= 0:
            raise core.OverlordError(f"error: budget {k} must be positive")
        out[k] = int(v) if k == "session_tokens" else v
    return out


def price_for(model, prices=None):
    """(usd per M in, usd per M out) for a model name, or None if unpriced."""
    prices = prices if prices is not None else load_config()["prices"]
    model = (model or "").lower()
    best = None
    for key, p in prices.items():
        if key.lower() in model and (best is None or len(key) > len(best[0])):
            best = (key, p)
    return (best[1]["in"], best[1]["out"]) if best else None


def cost_of(model, usage, prices=None):
    """Dollars for a usage dict {in, out}, or None when the model is unpriced."""
    p = price_for(model, prices)
    if not p:
        return None
    return (usage.get("in", 0) * p[0] + usage.get("out", 0) * p[1]) / 1_000_000


# ---------------------------------------------------------------- ledger


def ledger_append(sid, owner, model, usage, usd, kind="agent"):
    row = {"ts": time.strftime(core.TS_FORMAT), "session": sid, "owner": owner, "model": model,
           "kind": kind, "in": int(usage.get("in", 0)), "out": int(usage.get("out", 0)),
           "usd": None if usd is None else round(usd, 6)}
    os.makedirs(core.OVERLORD_HOME, exist_ok=True)
    with _LOCK:
        with open(LEDGER_FILE, "a") as f:
            f.write(json.dumps(row) + "\n")
    return row


def ledger_rows(days=None, owner=None):
    if not os.path.isfile(LEDGER_FILE):
        return []
    cutoff = None
    if days is not None:
        cutoff = time.strftime(core.TS_FORMAT, time.localtime(time.time() - days * 86400))
    out = []
    with open(LEDGER_FILE) as f:
        for line in f:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if cutoff and (r.get("ts") or "") < cutoff:
                continue
            if owner is not None and r.get("owner") != owner:
                continue
            out.append(r)
    return out


def spent(days=None, owner=None):
    """Totals over the ledger: tokens, dollars (priced calls only), calls."""
    t = {"in": 0, "out": 0, "usd": 0.0, "calls": 0, "unpriced": 0}
    for r in ledger_rows(days, owner):
        t["in"] += r.get("in", 0)
        t["out"] += r.get("out", 0)
        t["calls"] += 1
        if r.get("usd") is None:
            t["unpriced"] += 1
        else:
            t["usd"] += r["usd"]
    return t


def spent_today(owner=None):
    day = time.strftime("%Y-%m-%d")
    t = {"in": 0, "out": 0, "usd": 0.0, "calls": 0}
    for r in ledger_rows(days=2, owner=owner):
        if (r.get("ts") or "")[:10] != day:
            continue
        t["in"] += r.get("in", 0)
        t["out"] += r.get("out", 0)
        t["calls"] += 1
        t["usd"] += r.get("usd") or 0.0
    return t


def spent_month(owner=None):
    """This calendar month, which is what a provider's spend cap counts."""
    month = time.strftime("%Y-%m")
    t = {"in": 0, "out": 0, "usd": 0.0, "calls": 0}
    for r in ledger_rows(days=32, owner=owner):
        if (r.get("ts") or "")[:7] != month:
            continue
        t["in"] += r.get("in", 0)
        t["out"] += r.get("out", 0)
        t["calls"] += 1
        t["usd"] += r.get("usd") or 0.0
    return t


# ---------------------------------------------------------------- rate limits
# Every provider reply carries its rate-limit state: what the limit is, what
# is left, when it refills. Recorded per provider from the last reply seen.
# It is a lower bound between calls (the bucket refills), which the meter says.

_RATE_KEYS = ("requests", "tokens", "input-tokens", "output-tokens")


def _provider_of(url):
    host = (url.split("//", 1)[-1].split("/", 1)[0] or "").lower()
    if "anthropic.com" in host:
        return "anthropic"
    if "openai.com" in host:
        return "azure" if "azure" in host else "openai"
    if "googleapis.com" in host:
        return "gemini"
    return "openai-compatible"


def note_ratelimit(url, headers):
    """providers.RESPONSE_HOOK: fold one reply's headers into the store."""
    get = headers.get if hasattr(headers, "get") else (lambda k, d=None: d)
    found = {}
    for key in _RATE_KEYS:
        for prefix in (f"anthropic-ratelimit-{key}-", f"x-ratelimit-{{}}-{key}"):
            if "{}" in prefix:
                limit, rem, reset = (get(prefix.format(w)) for w in ("limit", "remaining", "reset"))
            else:
                limit, rem, reset = (get(prefix + w) for w in ("limit", "remaining", "reset"))
            if limit is not None or rem is not None:
                found[key.replace("-", "_")] = {"limit": _num(limit), "remaining": _num(rem), "reset": reset}
                break
    retry = get("retry-after")
    if not found and retry is None:
        return None
    entry = {"seen": time.time(), "at": time.strftime(core.TS_FORMAT), "url": url.split("?", 1)[0],
             **found}
    if retry is not None:
        entry["retry_after"] = _num(retry)
    with _LOCK:
        store = ratelimits()
        prov = _provider_of(url)
        # a 429 carries only retry-after; keep the last reply's limit numbers
        # rather than erase them, and clear a stale retry-after once a normal
        # reply reports headroom again
        merged = {**store.get(prov, {}), **entry}
        if found and "retry_after" not in entry:
            merged.pop("retry_after", None)
        store[prov] = merged
        try:
            os.makedirs(core.OVERLORD_HOME, exist_ok=True)
            tmp = RATE_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(store, f)
            os.replace(tmp, RATE_FILE)
        except OSError:
            pass
    return entry


def _num(v):
    try:
        return float(v) if v is not None and "." in str(v) else (int(v) if v is not None else None)
    except (TypeError, ValueError):
        return None


def ratelimits():
    try:
        with open(RATE_FILE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


# ---------------------------------------------------------------- budgets


def budget_for(target=None, owner=None):
    """The limits in effect: global config, the policy rule for the target,
    the account — the smallest of each key wins. Also says where each came from."""
    limits, source = {}, {}

    def take(b, name):
        for k, v in (b or {}).items():
            if k in BUDGET_KEYS and (k not in limits or v < limits[k]):
                limits[k], source[k] = v, name

    take(load_config()["budget"], "global")
    if target:
        pol = core.load_policy()
        if pol:
            rule = core._policy_rule(pol, os.path.realpath(target))
            if rule:
                take(_clean_budget(rule.get("budget") or {}), "policy")
    if owner:
        import auth
        take(_clean_budget(auth.user_budget(owner)), f"account:{owner}")
    return limits, source


def check(meta):
    """Raise BudgetExceeded if the session's next call would run past a
    limit. Called before every model call."""
    usage = meta.get("usage") or {}
    owner = meta.get("owner")
    limits, source = budget_for(meta.get("target"), owner)
    if not limits:
        return limits
    tokens = usage.get("in", 0) + usage.get("out", 0)
    if "session_tokens" in limits and tokens >= limits["session_tokens"]:
        raise BudgetExceeded(f"budget: this session has used {tokens} tokens, the limit is "
                             f"{limits['session_tokens']} ({source['session_tokens']})")
    usd = usage.get("usd")
    if "session_usd" in limits and usd is not None and usd >= limits["session_usd"]:
        raise BudgetExceeded(f"budget: this session has spent ${usd:.4f}, the limit is "
                             f"${limits['session_usd']:.2f} ({source['session_usd']})")
    if "day_usd" in limits:
        today = spent_today(owner)["usd"]
        if today >= limits["day_usd"]:
            who = owner or "this machine"
            raise BudgetExceeded(f"budget: {who} has spent ${today:.4f} today, the daily limit is "
                                 f"${limits['day_usd']:.2f} ({source['day_usd']})")
    if "month_usd" in limits:
        month = spent_month(owner)["usd"]
        if month >= limits["month_usd"]:
            who = owner or "this machine"
            raise BudgetExceeded(f"budget: {who} has spent ${month:.4f} this month, the monthly limit is "
                                 f"${limits['month_usd']:.2f} ({source['month_usd']})")
    return limits


def summary(meta):
    """For the UI: tokens, dollars and the limits in effect for a session."""
    usage = meta.get("usage") or {}
    limits, source = budget_for(meta.get("target"), meta.get("owner"))
    return {"in": usage.get("in", 0), "out": usage.get("out", 0), "usd": usage.get("usd"),
            "priced": price_for(meta.get("agent", "").split(":", 1)[-1]) is not None,
            "limits": limits, "sources": source}


# ---------------------------------------------------------------- cli


def _fmt_usd(v):
    return "—" if v is None else f"${v:.4f}"


def cmd_cost(args):
    c = args.cost_cmd or "show"
    if c == "show":
        rows = ledger_rows(args.days, args.user)
        if not rows:
            print("no model calls recorded" + (f" in the last {args.days} day(s)" if args.days else ""))
            return 0
        by_model, by_owner, by_day = {}, {}, {}
        for r in rows:
            for key, bucket in ((r.get("model") or "?", by_model), (r.get("owner") or "(local)", by_owner),
                                ((r.get("ts") or "")[:10], by_day)):
                t = bucket.setdefault(key, {"in": 0, "out": 0, "usd": 0.0, "calls": 0, "unpriced": 0})
                t["in"] += r.get("in", 0)
                t["out"] += r.get("out", 0)
                t["calls"] += 1
                if r.get("usd") is None:
                    t["unpriced"] += 1
                else:
                    t["usd"] += r["usd"]
        for title, bucket in (("by model", by_model), ("by account", by_owner), ("by day", by_day)):
            print(f"{title}:")
            for k, t in sorted(bucket.items()):
                extra = f"  ({t['unpriced']} unpriced call(s))" if t["unpriced"] else ""
                print(f"  {k:32} {t['calls']:5} call(s)  in {t['in']:>9}  out {t['out']:>8}  "
                      f"{_fmt_usd(t['usd'])}{extra}")
        tot = spent(args.days, args.user)
        print(f"total: {tot['calls']} call(s), {tot['in']} in / {tot['out']} out, {_fmt_usd(tot['usd'])}"
              + (f" — {tot['unpriced']} call(s) on unpriced models; `overlord cost set-price`"
                 if tot["unpriced"] else ""))
        limits, source = budget_for(None, args.user)
        if limits:
            print("budget: " + ", ".join(f"{k}={v} ({source[k]})" for k, v in limits.items()))
        return 0
    if c == "prices":
        cfg = load_config()
        for k, p in sorted(cfg["prices"].items()):
            print(f"  {k:28} in ${p['in']:.2f}/M   out ${p['out']:.2f}/M"
                  + ("" if k in DEFAULT_PRICES and DEFAULT_PRICES[k] == p else "   (yours)"))
        print(f"\nunlisted models are counted in tokens only; edit {CONFIG_FILE} or `overlord cost set-price`")
        return 0
    if c == "set-price":
        cfg = load_config()
        cfg["prices"][args.model] = {"in": float(args.usd_in), "out": float(args.usd_out)}
        save_config(cfg)
        print(f"priced {args.model}: in ${float(args.usd_in):.2f}/M, out ${float(args.usd_out):.2f}/M")
        return 0
    if c == "budget":
        cfg = load_config()
        b = dict(cfg["budget"])
        for k in BUDGET_KEYS:
            v = getattr(args, k)
            if v is not None:
                if v == 0:
                    b.pop(k, None)
                else:
                    b[k] = v
        cfg["budget"] = _clean_budget(b)
        save_config(cfg)
        print("global budget: " + (", ".join(f"{k}={v}" for k, v in cfg["budget"].items()) or "none"))
        return 0
    raise core.OverlordError("error: unknown cost subcommand")


def add_cost_parser(sub):
    pc = sub.add_parser("cost", help="what the models spent; prices and budgets")
    cs = pc.add_subparsers(dest="cost_cmd")
    ps = cs.add_parser("show", help="spend by model, account and day (default)")
    for p in (pc, ps):
        p.add_argument("--days", type=int, help="only the last N days")
        p.add_argument("--user", help="only this account")
    cs.add_parser("prices", help="the price table in effect")
    pp = cs.add_parser("set-price", help="price a model (USD per million tokens)")
    pp.add_argument("model")
    pp.add_argument("usd_in", type=float)
    pp.add_argument("usd_out", type=float)
    pb = cs.add_parser("budget", help="global limits (0 clears one)")
    pb.add_argument("--session-tokens", dest="session_tokens", type=int)
    pb.add_argument("--session-usd", dest="session_usd", type=float)
    pb.add_argument("--day-usd", dest="day_usd", type=float)
    pb.add_argument("--month-usd", dest="month_usd", type=float,
                    help="this calendar month; match it to your provider's spend cap")
    pc.set_defaults(fn=cmd_cost)
