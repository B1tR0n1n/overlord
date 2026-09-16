#!/usr/bin/env python3
"""The workspace (chat front door) in a real browser.

Loads / in Chromium and drives it the way a person would: type a message,
watch the agent's turn stream in, read the change in the inspector, press
Commit, then reopen the conversation from the rail. Also opens Settings.
Uses the scripted provider so no network and no key are needed. Asserts zero
console errors across the run. Skips cleanly when Playwright/Chromium absent.
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
PORT = int(os.environ.get("OVERLORD_CHAT_TEST_PORT", "7798"))
BASE = f"http://127.0.0.1:{PORT}"


def skip(why):
    print(f"SKIP: chat browser suite — {why}")
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


def _chromium():
    for pat in ("/opt/pw-browsers/chromium*/chrome-linux/chrome",
                os.path.expanduser("~/.cache/ms-playwright/chromium*/chrome-linux/chrome")):
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[-1]
    return None


OVERLORD_HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = OVERLORD_HOME
target = tempfile.mkdtemp()
with open(os.path.join(target, "lib.py"), "w") as f:
    f.write("def a():\n    return 1\n")

# a scripted provider: one read, one write, then a summary
script = os.path.join(OVERLORD_HOME, "script.json")
with open(script, "w") as f:
    json.dump([
        {"text": "Let me look, then add a greeting.",
         "tool_calls": [{"name": "read_file", "input": {"path": "lib.py"}}]},
        {"tool_calls": [{"name": "write_file", "input": {
            "path": "lib.py",
            "content": "def a():\n    return 1\n\n\ndef greet():\n    return 'hi'\n"}}]},
        {"text": "Added a greet() function that returns 'hi'."}], f)
os.environ["OVERLORD_AGENT_SCRIPT"] = script

sys.path.insert(0, HERE)
import chatui  # noqa: E402
import overlord as core  # noqa: E402
chatui.save_settings({"provider": "scripted", "workdir": target,
                      "jail": core.detect_backend() == "kernel",
                      "net": "none" if core.detect_backend() == "kernel" else "host"})

server = subprocess.Popen(
    [sys.executable, os.path.join(HERE, "overlord.py"), "ui", "--port", str(PORT)],
    env=os.environ.copy(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

errors, chrome = [], _chromium()
try:
    for _ in range(60):
        try:
            urllib.request.urlopen(BASE + "/api/settings", timeout=2)
            break
        except OSError:
            time.sleep(0.1)
    else:
        fail("workspace server never came up")

    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(**({"executable_path": chrome} if chrome else {}))
        except Exception as e:
            skip(f"chromium unavailable ({type(e).__name__})")
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        page.on("console", lambda m: errors.append(f"console.{m.type}: {m.text}")
                if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))

        page.goto(BASE + "/", wait_until="networkidle")
        page.wait_for_timeout(400)
        if errors:
            fail("load: " + "; ".join(errors))
        if not page.locator(".welcome").count():
            fail("no welcome / empty state on first load")
        ok("workspace loads with a welcome and composer")

        # type a task and send
        page.locator("#input").fill("add a greet function to lib.py")
        page.locator("#send").click()
        # the agent's turn should stream in and then the composer re-enables
        page.wait_for_selector(".msg.assistant .bub", timeout=20000)
        page.wait_for_selector("[data-commit]", timeout=20000)   # rendered only when the run stops
        if errors:
            fail("during run: " + "; ".join(errors))
        if not page.locator(".msg.user").count():
            fail("the user's message was not shown")
        if not page.locator(".tool").count():
            fail("the tool call was not shown")
        if page.locator(".bub.live").count():
            fail("a bubble is still marked live after the run stopped")
        if page.locator(".msg.assistant").count() < 2:
            fail("streamed assistant turns did not each render as a bubble")
        ok("a message runs the agent and its turns stream into the chat")

        # the inspector shows the change and a commit control (auto-retrying
        # locators tolerate the panel re-rendering on the next poll)
        page.locator("#inspector").get_by_text("lib.py").first.wait_for(timeout=8000)
        if page.locator("[data-commit]").count() != 1:
            fail("no commit control in the inspector")
        ok("the inspector shows the pending change and Commit")

        # a new conversation appears in the rail and is selectable
        if page.locator(".conv").count() < 1:
            fail("conversation not listed in the rail")
        title = page.locator(".conv .t").first.inner_text()
        if "greet" not in title:
            fail(f"conversation title: {title!r}")
        ok("the conversation is listed and titled from the first message")

        # commit through the inspector
        page.locator("[data-commit]").click()
        page.wait_for_selector(".ins-state.ok", timeout=10000)
        if "greet" not in open(os.path.join(target, "lib.py")).read():
            fail("commit from the UI did not reach the folder")
        if errors:
            fail("after commit: " + "; ".join(errors))
        ok("Commit from the inspector applies the change to the folder")

        # settings modal opens and reports the working folder; the model
        # configuration surface is present and the live model list loads
        page.locator("#opensettings").click()
        page.wait_for_selector(".modal.open", timeout=5000)
        if page.locator("#s-workdir").input_value() != os.path.realpath(target):
            fail("settings modal did not show the working folder")
        for sel in ("#s-provider", "#s-model", "#s-baseurl", "#s-headers", "#g-maxtokens",
                    "#g-effort", "#g-thinking", "#g-temperature", "#g-system", "#g-stream"):
            if not page.locator(sel).count():
                fail(f"settings missing control {sel}")
        opts = page.locator("#s-provider option").count()
        if opts != 5:
            fail(f"provider choices: {opts}")
        page.locator("#s-models-note").get_by_text("models available").wait_for(timeout=8000)
        if not page.locator("#conn-section").count() or not page.locator("#c-add").count():
            fail("settings lacks the connectors section")
        if not page.locator("#mem-section").count() or not page.locator("#m-user").count():
            fail("settings lacks the memory section")
        if page.locator("#s-models option").count() != 1:
            fail("model datalist not populated from /api/models")
        page.locator("#closesettings").click()
        ok("Settings shows provider, endpoint, generation knobs, and a live model list")

        # a phone width must not overflow horizontally
        page.set_viewport_size({"width": 390, "height": 850})
        page.wait_for_timeout(300)
        if page.evaluate("document.documentElement.scrollWidth > "
                         "document.documentElement.clientWidth + 1"):
            fail("horizontal overflow at 390px")
        ok("no horizontal overflow at phone width")

        browser.close()
    if errors:
        fail("console errors during the run:\n    " + "\n    ".join(errors))
    ok("zero console errors across the whole run")
    print("PASS: workspace (browser)")
finally:
    server.terminate()
    server.wait()
    subprocess.run(["rm", "-rf", OVERLORD_HOME, target])
