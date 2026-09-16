#!/usr/bin/env python3
"""Cost e2e: prices match by longest model substring and yours override the
defaults; every model call writes a ledger line (agent and review) and the
session carries its running dollars; a budget from policy, the global
config or the account stops a conversation BEFORE the call that would
cross it, with the stop in the transcript and the audit log; `overlord
cost` sums the ledger; the workspace shows spend and lets an admin set
limits. Scripted provider, no network."""

import json
import os
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = HOME

import overlord as ov      # noqa: E402
import agent               # noqa: E402
import cost                # noqa: E402
import audit               # noqa: E402
import auth                # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


def cli(*args, stdin=None):
    return subprocess.run([sys.executable, os.path.join(HERE, "overlord.py"), *args],
                          capture_output=True, text=True, env=os.environ, input=stdin)


BACKEND = ov.detect_backend()
if BACKEND is None:
    print("SKIP: cost (no sandbox backend here — see `overlord doctor`)")
    sys.exit(0)
KERNEL = BACKEND == "kernel"
grants = {"net": "none" if KERNEL else "host", "jail": KERNEL, "timeout": None, "merge_base": False}
target = tempfile.mkdtemp()
with open(os.path.join(target, "lib.py"), "w") as f:
    f.write("def a():\n    return 1\n")

# three calls of 1000 in / 500 out each, writing a file on the first two
SCRIPT = [{"text": "one", "usage": {"in": 1000, "out": 500},
           "tool_calls": [{"name": "shell", "input": {"command": "echo a > a.txt"}}]},
          {"text": "two", "usage": {"in": 1000, "out": 500},
           "tool_calls": [{"name": "shell", "input": {"command": "echo b > b.txt"}}]},
          {"text": "done", "usage": {"in": 1000, "out": 500}}]


def run(model="scripted", owner=None, script=SCRIPT):
    p = agent.ScriptedProvider(script)
    p.model = model
    live = ov.open_session(target, BACKEND, grants, capture=True, agent=f"scripted:{model}", owner=owner)
    ev = []
    agent.run_agent(live, p, "do it", max_turns=6, emit=ev.append)
    sid, changes = live.close()
    return sid, changes, ev


try:
    # 1. prices: longest substring wins, yours override, unknown is unpriced
    if cost.price_for("claude-opus-4-1-20250805") != (15.0, 75.0):
        fail("default price lookup")
    if cost.price_for("gpt-5-mini-2025") != (0.25, 2.0):
        fail("longest match should win (gpt-5-mini over gpt-5)")
    if cost.price_for("mystery-model") is not None or cost.cost_of("mystery-model", {"in": 5, "out": 5}) is not None:
        fail("unknown model priced")
    r = cli("cost", "set-price", "scripted", "2", "10")
    if r.returncode != 0 or cost.price_for("scripted") != (2.0, 10.0):
        fail(f"set-price: {r.stdout} {r.stderr}")
    usd = cost.cost_of("scripted", {"in": 1000, "out": 500})
    if abs(usd - (1000 * 2 + 500 * 10) / 1e6) > 1e-9:
        fail(f"cost_of: {usd}")
    if "(yours)" not in cli("cost", "prices").stdout:
        fail("cost prices does not mark an override")
    ok("prices: longest model match, overrides, unpriced models stay counted in tokens")

    # 2. every call writes a ledger line; the session carries running dollars
    sid, changes, ev = run()
    m = ov.load_meta(sid)
    if m["usage"]["in"] != 3000 or m["usage"]["out"] != 1500 or abs(m["usage"]["usd"] - 0.021) > 1e-9:
        fail(f"session usage: {m['usage']}")
    rows = cost.ledger_rows()
    if len(rows) != 3 or any(r["session"] != sid or r["kind"] != "agent" or r["in"] != 1000 for r in rows):
        fail(f"ledger: {rows}")
    done = [e for e in ev if e["type"] == "done"][-1]
    if done["reason"] != "end_turn" or done["usage"]["usd"] != m["usage"]["usd"]:
        fail(f"done event usage: {done}")
    ov.rollback_session(sid)
    ok("a ledger line per call; the session and its done event carry the dollars")

    # 3. a policy budget stops the session before the crossing call
    with open(ov.POLICY_FILE, "w") as f:
        json.dump({"default": {"budget": {"session_tokens": 2000}}}, f)
    sid, changes, ev = run()
    kinds = [e["type"] for e in ev]
    done = [e for e in ev if e["type"] == "done"][-1]
    errs = [e for e in ev if e["type"] == "error"]
    if done["reason"] != "budget" or kinds.count("tool_call") != 2 or not errs or "policy" not in errs[-1]["text"]:
        fail(f"policy budget: reason={done['reason']} tool_calls={kinds.count('tool_call')} errs={errs}")
    m = ov.load_meta(sid)
    if m["usage"]["in"] != 2000:
        fail(f"the third call should not have happened: {m['usage']}")
    if sorted(changes) != [("added", "a.txt"), ("added", "b.txt")]:
        fail(f"work before the stop is kept for review: {changes}")
    stops = [e for e in audit.entries(action="budget.stop") if e.get("sid") == sid]
    if len(stops) != 1 or "2000" not in stops[0]["reason"]:
        fail(f"budget stop not audited: {stops}")
    ov.rollback_session(sid)
    os.unlink(ov.POLICY_FILE)
    ok("policy budget: stopped before the crossing call; work kept; stop in transcript and audit")

    # 4. the global daily dollar limit, and an account's own limit
    r = cli("cost", "budget", "--day-usd", "0.03")
    if r.returncode != 0 or cost.load_config()["budget"] != {"day_usd": 0.03}:
        fail(f"cost budget: {r.stdout} {r.stderr} {cost.load_config()}")
    sid, changes, ev = run()                           # 0.021 today so far → passes fully
    ov.rollback_session(sid)
    sid, changes, ev = run()                           # 0.042 ≥ 0.03 → stops before the first call
    done = [e for e in ev if e["type"] == "done"][-1]
    if done["reason"] != "budget" or "today" not in [e for e in ev if e["type"] == "error"][-1]["text"] \
            or ov.load_meta(sid)["usage"]["in"] != 0:
        fail(f"daily limit: {done} {ov.load_meta(sid)['usage']}")
    ov.rollback_session(sid)
    cli("cost", "budget", "--day-usd", "0")
    if cost.load_config()["budget"]:
        fail("budget not cleared")
    cli("users", "add", "bob", "--password-stdin", stdin="bob-password\n")
    r = cli("users", "budget", "bob", "--session-usd", "0.01")
    if r.returncode != 0 or auth.user_budget("bob") != {"session_usd": 0.01}:
        fail(f"users budget: {r.stdout} {r.stderr}")
    limits, source = cost.budget_for(target, "bob")
    if limits != {"session_usd": 0.01} or source["session_usd"] != "account:bob":
        fail(f"budget_for bob: {limits} {source}")
    # $0.007 a call: the second call ends at $0.014, past the line, so the
    # third is never made — a limit stops the next call, it does not predict it
    sid, changes, ev = run(owner="bob")
    done = [e for e in ev if e["type"] == "done"][-1]
    if done["reason"] != "budget" or ov.load_meta(sid)["usage"]["in"] != 2000:
        fail(f"account limit: {done} {ov.load_meta(sid)['usage']}")
    ov.rollback_session(sid)
    sid, changes, ev = run(owner="alice")               # no account limit → runs to the end
    if [e for e in ev if e["type"] == "done"][-1]["reason"] != "end_turn":
        fail("another account was limited by bob's budget")
    ov.rollback_session(sid)
    if "budget session_usd=0.01" not in cli("users", "list").stdout:
        fail("users list does not show the budget")
    ok("global daily limit and an account's own limit; the most restrictive line wins")

    # 4b. the provider's rate-limit headers are the live statement of headroom
    e = cost.note_ratelimit("https://api.anthropic.com/v1/messages", {
        "anthropic-ratelimit-tokens-limit": "500000", "anthropic-ratelimit-tokens-remaining": "412000",
        "anthropic-ratelimit-tokens-reset": "2026-09-16T21:00:42Z",
        "anthropic-ratelimit-requests-limit": "1000", "anthropic-ratelimit-requests-remaining": "997",
        "anthropic-ratelimit-requests-reset": "2026-09-16T21:00:01Z",
        "anthropic-ratelimit-input-tokens-limit": "500000", "anthropic-ratelimit-input-tokens-remaining": "410000",
        "anthropic-ratelimit-input-tokens-reset": "2026-09-16T21:00:42Z"})
    if e["tokens"] != {"limit": 500000, "remaining": 412000, "reset": "2026-09-16T21:00:42Z"} \
            or e["requests"]["remaining"] != 997 or e["input_tokens"]["remaining"] != 410000:
        fail(f"anthropic rate headers: {e}")
    cost.note_ratelimit("https://api.openai.com/v1/responses", {
        "x-ratelimit-limit-tokens": "30000", "x-ratelimit-remaining-tokens": "29500", "x-ratelimit-reset-tokens": "1s",
        "x-ratelimit-limit-requests": "500", "x-ratelimit-remaining-requests": "499", "x-ratelimit-reset-requests": "120ms"})
    cost.note_ratelimit("https://api.openai.com/v1/responses", {"retry-after": "12"})
    cost.note_ratelimit("http://127.0.0.1:11434/v1/chat/completions", {"content-type": "application/json"})
    rl = cost.ratelimits()
    if rl["anthropic"]["tokens"]["remaining"] != 412000 or rl["openai"]["tokens"]["remaining"] != 29500 \
            or rl["openai"]["retry_after"] != 12 or "openai-compatible" in rl or not rl["anthropic"].get("seen"):
        fail(f"rate store: {rl}")
    # a later normal reply clears the stale retry-after
    cost.note_ratelimit("https://api.openai.com/v1/responses", {
        "x-ratelimit-limit-tokens": "30000", "x-ratelimit-remaining-tokens": "30000", "x-ratelimit-reset-tokens": "0s"})
    if "retry_after" in cost.ratelimits()["openai"] or cost.ratelimits()["openai"]["tokens"]["remaining"] != 30000:
        fail(f"retry-after not cleared by a normal reply: {cost.ratelimits()['openai']}")
    ok("rate-limit headers from Anthropic and OpenAI replies are kept per provider; a 429's retry-after too, then cleared")

    # 4c. a monthly line, measured on the calendar month like a provider's cap
    r = cli("cost", "budget", "--month-usd", "0.05")
    if r.returncode != 0 or cost.load_config()["budget"] != {"month_usd": 0.05}:
        fail(f"month budget: {r.stdout} {r.stderr} {cost.load_config()}")
    if cost.spent_month()["usd"] < 0.05:
        fail(f"expected the month's ledger to be past $0.05 by now: {cost.spent_month()}")
    sid, changes, ev = run()
    done = [e for e in ev if e["type"] == "done"][-1]
    if done["reason"] != "budget" or "this month" not in [e for e in ev if e["type"] == "error"][-1]["text"]:
        fail(f"monthly limit: {done}")
    ov.rollback_session(sid)
    cli("cost", "budget", "--month-usd", "0")
    ok("a monthly limit stops the next call; `overlord cost budget --month-usd` sets it")

    # 5. the review's tokens are on the ledger too; `overlord cost` sums it
    import review
    live = ov.open_session(target, BACKEND, grants, capture=True, agent="scripted:scripted")
    live.exec(["bash", "-c", "echo r > r.txt"])
    sid, _ = live.close()
    rp = agent.ScriptedProvider([{"usage": {"in": 700, "out": 30},
                                  "tool_calls": [{"name": "approve", "input": {"reason": "fine"}}]}])
    rp.model = "reviewer-x"
    review.run_review(sid, rp)
    rev = [r for r in cost.ledger_rows() if r["kind"] == "review"]
    if len(rev) != 1 or rev[0]["in"] != 700 or rev[0]["model"] != "reviewer-x" or rev[0]["usd"] is not None:
        fail(f"review ledger: {rev}")
    ov.rollback_session(sid)
    out = cli("cost").stdout
    if "by model" not in out or "reviewer-x" not in out or "unpriced" not in out or "by account" not in out:
        fail(f"cost show:\n{out}")
    out = cli("cost", "--user", "bob").stdout
    if "reviewer-x" in out or "bob" not in out:
        fail(f"cost --user:\n{out}")
    ok("review calls are on the ledger; `overlord cost` sums by model, account and day")

    # 6. workspace: spend and limits visible, an admin sets budgets, the inspector shows tokens
    os.unlink(auth.USERS_FILE)            # back to open mode; signed-in access is auth_test's
    import ui
    import chatui
    from http.server import ThreadingHTTPServer
    PORT = 7796
    server = ThreadingHTTPServer(("127.0.0.1", PORT), ui.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    BASE = f"http://127.0.0.1:{PORT}"

    def req(path, data=None, method=None):
        body = json.dumps(data).encode() if data is not None else None
        r = urllib.request.Request(BASE + path, data=body, method=method,
                                   headers={"Host": f"127.0.0.1:{PORT}", "Cookie": ui.local_cookie()})
        try:
            with urllib.request.urlopen(r, timeout=20) as resp:
                return resp.status, json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or "{}")

    try:
        code, d = req("/api/cost")
        if code != 200 or d["month"]["calls"] < 10 or d["scope"] != "everyone" or "scripted" not in d["prices"]:
            fail(f"cost GET: {code} {d}")
        if d["rate"]["anthropic"]["tokens"]["remaining"] != 412000 or d["mtd"]["calls"] < 10 or not d.get("now"):
            fail(f"cost GET lacks the meter's sources: rate={d.get('rate')} mtd={d.get('mtd')}")
        code, d = req("/api/cost", {"budget": {"month_usd": "40"}}, "PUT")
        if code != 200 or d["budget"].get("month_usd") != 40.0:
            fail(f"month budget via API: {code} {d}")
        code, d = req("/api/cost", {"budget": {"session_tokens": 4000, "day_usd": "", "month_usd": ""}}, "PUT")
        if code != 200 or d["budget"] != {"session_tokens": 4000}:
            fail(f"cost PUT: {code} {d}")
        code, d = req("/api/cost", {"budget": {"session_usd": -1}}, "PUT")
        if code != 400:
            fail("negative budget accepted")
        chatui.save_settings({"provider": "scripted", "workdir": target, "jail": KERNEL,
                              "net": "none" if KERNEL else "host"})
        spath = os.path.join(HOME, "script.json")
        with open(spath, "w") as f:
            json.dump(SCRIPT, f)
        os.environ["OVERLORD_AGENT_SCRIPT"] = spath
        code, d = req("/api/chats", {"message": "spend", "target": target}, "POST")
        sid = d["sid"]
        import time
        frm = 0
        for _ in range(200):
            code, e = req(f"/api/chats/{sid}/events?from={frm}")
            frm = e["next"]
            if not e["running"]:
                break
            time.sleep(0.05)
        code, conv = req(f"/api/chats/{sid}")
        c = conv["meta"]["cost"]
        if c["in"] != 3000 or c["limits"] != {"session_tokens": 4000} or not c["priced"]:
            fail(f"conversation cost: {c}")
        if "3.0k in" not in conv["inspector"] or "$" not in conv["inspector"]:
            fail("inspector lacks the cost line")
        req(f"/api/session/{sid}/rollback", {}, "POST")
        ok("workspace: spend and limits shown, budgets set by an admin, tokens in the inspector")
    finally:
        server.shutdown()

    print("PASS: cost")
finally:
    subprocess.run(["rm", "-rf", HOME, target])
