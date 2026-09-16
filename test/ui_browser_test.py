#!/usr/bin/env python3
"""Mission control in a real browser.

test/ui_test.py drives the HTTP API and never executes the page's JavaScript.
That hole let a ReferenceError in the detail renderer ship: the server-rendered
first paint was correct, so the page looked fine until you clicked a session,
at which point the commit/rollback controls silently failed to render.

This suite loads the page in Chromium and asserts on the rendered DOM: no
console errors, the controls survive a register click, provenance attribution
reaches the manifest, the grant envelope shows capability (not status), the
drift refusal renders, and the layout does not overflow on a phone.

Skips cleanly (exit 0) when Playwright or Chromium is absent, so a bare
checkout and packaging/install.sh are unaffected.
"""

import glob
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = int(os.environ.get("OVERLORD_UI_TEST_PORT", "7797"))
BASE = f"http://127.0.0.1:{PORT}"


def skip(why):
    print(f"SKIP: browser suite — {why}")
    sys.exit(0)


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


try:
    from playwright.sync_api import sync_playwright
except ImportError:
    skip("playwright not installed (pip install playwright)")


def _chromium_path():
    """Prefer a preinstalled Chromium; let Playwright resolve its own otherwise."""
    for pat in ("/opt/pw-browsers/chromium*/chrome-linux/chrome",
                os.path.expanduser("~/.cache/ms-playwright/chromium*/chrome-linux/chrome")):
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[-1]
    return None


OVERLORD_HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = OVERLORD_HOME
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import ui  # noqa: E402  (the launch token: open mode's credential)
import overlord as _core  # noqa: E402
if _core.detect_backend() is None:
    print("SKIP: ui_browser (no sandbox backend here — see `overlord doctor`)")
    sys.exit(0)
target = tempfile.mkdtemp()
with open(os.path.join(target, "calc.py"), "w") as f:
    f.write("def add(a, b):\n    return a + b\n")

# An agent session: the only kind that carries grants AND caused_by attribution.
script = [
    {"text": "Inspecting.", "tool_calls": [{"name": "list_dir", "input": {"path": "."}}]},
    {"text": "Writing.", "tool_calls": [
        {"name": "write_file", "input": {"path": "test_calc.py",
                                         "content": "from calc import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n\n\nif __name__ == '__main__':\n    test_add(); print('ok')\n"}},
        {"name": "write_file", "input": {"path": "Makefile",
                                         "content": ".PHONY: test\n\ntest:\n\tpython3 test_calc.py\n"}}]},
    {"text": "Verifying.", "tool_calls": [{"name": "shell", "input": {"command": "make test"}}]},
    {"text": "Added a Makefile."},
]
spath = os.path.join(OVERLORD_HOME, "script.json")
with open(spath, "w") as f:
    json.dump(script, f)

env = os.environ.copy()
env["OVERLORD_AGENT_SCRIPT"] = spath
agent = subprocess.run(
    [sys.executable, os.path.join(HERE, "overlord.py"), "agent", "--jail", "--net", "none",
     "--provider", "scripted", "-t", target, "add a Makefile"],
    env=env, capture_output=True, text=True)
if agent.returncode != 0:
    fail(f"agent session did not run: {agent.stderr[-400:]}")

# A second, plain session we can drift out from under, to exercise the refusal.
subprocess.run(
    [sys.executable, os.path.join(HERE, "overlord.py"), "run", "-t", target, "--stack",
     "--", "bash", "-c", "echo agent > calc.py"],
    env=os.environ.copy(), capture_output=True, text=True)
with open(os.path.join(target, "calc.py"), "w") as f:
    f.write("drifted externally\n")          # the real tree moves under the session

server = subprocess.Popen(
    [sys.executable, os.path.join(HERE, "overlord.py"), "ui", "--port", str(PORT)],
    env=os.environ.copy(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

errors, chrome = [], _chromium_path()
try:
    for _ in range(60):
        try:
            urllib.request.urlopen(BASE + "/healthz", timeout=2)
            break
        except OSError:
            time.sleep(0.1)
    else:
        fail("ui server never came up")

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(**({"executable_path": chrome} if chrome else {}))
        except Exception as e:
            skip(f"chromium unavailable ({type(e).__name__})")
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        page.on("console",
                lambda m: errors.append(f"console.{m.type}: {m.text}") if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
        def clean(step):
            """A JS error must fail the step that caused it, not the run's end."""
            if errors:
                fail(f"{step}: " + "; ".join(errors))

        page.goto(BASE + "/console?token=" + ui.local_token(), wait_until="networkidle")
        clean("page load")

        if page.locator(".reg-item").count() != 2:
            fail(f"register shows {page.locator('.reg-item').count()} entries, expected 2")
        if page.locator(".btn-commit").count() != 1:
            fail("no commit control on the server-rendered first paint")
        ok("first paint: register + disposition controls")

        # The regression: clicking a register entry must re-render the dossier
        # for THAT session. A stale pane left by a thrown handler still holds
        # the first paint's controls, so identity is what has to be asserted.
        wanted = page.locator(".reg-item").nth(1).locator(".reg-sid").inner_text().strip()
        page.locator(".reg-item").nth(1).click()
        page.wait_for_timeout(600)
        clean("register click")
        shown = page.locator(".sec-title .sid").inner_text().strip()
        if shown != wanted:
            fail(f"clicked {wanted} but dossier still shows {shown}")
        if page.locator(".btn-commit").count() != 1:
            fail("commit control vanished after clicking a register entry")
        ok("register click re-renders the dossier for that session")

        # Provenance attribution has to reach the page, not just the record.
        page.locator(".reg-item").filter(has_text="JAIL").first.click()
        page.wait_for_timeout(600)
        clean("agent session click")
        causes = page.locator(".cause").count()
        rows = page.locator(".manifest tbody tr").count()
        if not rows:
            fail("agent session rendered no manifest rows")
        if causes != rows:
            fail(f"caused_by rendered on {causes}/{rows} manifest rows")
        ok(f"caused_by rendered on all {rows} manifest rows")

        grants = page.locator(".grants").inner_text().upper()
        if "JAIL" not in grants or "NET:NONE" not in grants:
            fail(f"grant envelope missing capability stamps: {grants!r}")
        if "PENDING" in grants:
            fail(f"session status leaked into the grant envelope: {grants!r}")
        ok("grant envelope shows capability, not status")

        # Savepoints: the chain renders, and "Rewind here" acts through the
        # same delegated click path as everything else.
        before = page.locator(".sp tbody tr").count()
        if before < 2 or page.locator("[data-rewind]").count() != before - 1:
            fail(f"savepoints: {before} rows, {page.locator('[data-rewind]').count()} rewind controls")
        page.locator("[data-rewind]").first.click()
        page.wait_for_timeout(800)
        clean("rewind click")
        after = page.locator(".sp tbody tr").count()
        if after != 1 or "rewound to @0" not in page.locator(".sp-note").first.inner_text().lower():
            fail(f"rewind via the page: {before} -> {after} rows")
        if page.locator(".manifest tbody tr").count() >= rows:
            fail("manifest did not shrink after rewind")
        ok(f"savepoints rendered; rewind here cut {before} rows to {after}")

        # Fork here: a new session appears and the page lands on its dossier,
        # which names its origin; the countersignature block is on the page.
        origin = page.locator(".sec-title .sid").inner_text().strip()
        if page.locator("[data-review]").count() != 1 or "UNSIGNED" not in page.locator(".sig").inner_text().upper():
            fail("countersignature block missing from a pending dossier")
        page.locator("[data-fork]").first.click()
        page.wait_for_timeout(900)
        clean("fork click")
        shown = page.locator(".sec-title .sid").inner_text().strip()
        lineage = page.locator(".facts").inner_text()
        if shown == origin or "forked from" not in lineage.lower() or origin not in lineage:
            fail(f"fork via the page: showing {shown}, lineage {lineage!r}")
        if page.locator(".reg-item").count() != 3:
            fail("fork did not appear in the register")
        ok("fork here creates a session and the page lands on its dossier")

        # Drift refusal: server-rendered, must reach the page intact.
        page.locator(".reg-item").filter(has_not_text="JAIL").first.click()
        page.wait_for_timeout(600)
        page.locator(".btn-commit").click()
        page.wait_for_selector(".refusal", timeout=5000)
        clean("commit")
        refusal = page.locator(".refusal").inner_text().lower()
        if "drift" not in refusal or "calc.py" not in refusal:
            fail(f"refusal panel missing drift detail: {refusal!r}")
        if os.path.isfile(os.path.join(target, "calc.py")) and \
                open(os.path.join(target, "calc.py")).read() != "drifted externally\n":
            fail("refused commit still wrote to the target")
        ok("drift refusal renders and the target is untouched")

        page.keyboard.press("j")
        page.wait_for_timeout(400)
        if page.locator(".reg-item.sel").count() != 1:
            fail("keyboard navigation lost the selection")
        ok("keyboard navigation over the register")

        page.set_viewport_size({"width": 400, "height": 900})
        page.wait_for_timeout(400)
        if page.evaluate("document.documentElement.scrollWidth > "
                         "document.documentElement.clientWidth + 1"):
            fail("horizontal overflow at 400px")
        ok("no horizontal overflow at 400px")

        browser.close()

    if errors:
        fail("console errors during the run:\n    " + "\n    ".join(errors))
    ok("zero console errors across the whole run")
    print("PASS: mission control (browser)")
finally:
    server.terminate()
    server.wait()
    subprocess.run(["rm", "-rf", OVERLORD_HOME, target])
