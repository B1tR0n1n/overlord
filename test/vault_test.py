#!/usr/bin/env python3
"""Vault bridge e2e with a fake vault command: secret://NAME references
resolve at the point of use for provider keys (stored or by the
providers/<name> convention), connector env and headers, the SSO client
secret and webhook signatures; the resolver runs without a shell, caches
for a while, fails loudly and never prints a value; config audited."""

import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
HOME = tempfile.mkdtemp()
os.environ["OVERLORD_HOME"] = HOME
STORE = os.path.join(HOME, "store.json")
os.environ["FAKE_VAULT"] = STORE

import overlord as ov      # noqa: E402
import vault               # noqa: E402
import agent               # noqa: E402
import mcp as mcp_mod      # noqa: E402
import notify              # noqa: E402
import oidc                # noqa: E402
import audit               # noqa: E402


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print(f"  ok: {msg}")


def cli(*args):
    return subprocess.run([sys.executable, os.path.join(HERE, "overlord.py"), *args],
                          capture_output=True, text=True, env=os.environ)


def put(**kv):
    cur = json.load(open(STORE)) if os.path.isfile(STORE) else {}
    cur.update(kv)
    json.dump(cur, open(STORE, "w"))


put(**{"anthropic-key": "sk-ant-from-vault", "providers/openai": "sk-oa-convention",
       "gh-token": "ghp_secret", "sso-secret": "oidc-s3cret", "hook-secret": "hush"})
CMD = f"{sys.executable} {os.path.join(HERE, 'test', 'fake_vault.py')} {{name}}"

try:
    # 1. references before a resolver exists fail with a pointer; the CLI sets one
    try:
        vault.resolve("secret://anthropic-key")
        fail("resolved without a resolver")
    except vault.VaultError as e:
        if "set-command" not in str(e):
            fail(f"wrong error: {e}")
    if vault.resolve("plain-value") != "plain-value":
        fail("plain values must pass through")
    r = cli("secrets", "set-command", "echo nope")
    if r.returncode == 0:
        fail("a command without {name} was accepted")
    r = cli("secrets", "set-command", CMD, "--cache", "60")
    if r.returncode != 0 or os.stat(vault.CONFIG_FILE).st_mode & 0o077:
        fail(f"set-command: {r.stdout} {r.stderr}")
    r = cli("secrets", "test", "gh-token")
    if r.returncode != 0 or "ghp_secret" in r.stdout or "10 characters" not in r.stdout:
        fail(f"secrets test must report a length, never the value: {r.stdout}")
    r = cli("secrets", "test", "missing-one")
    if r.returncode == 0 or "exit 3" not in r.stderr:
        fail(f"unknown secret: {r.stdout} {r.stderr}")
    try:
        vault.fetch("../etc/passwd")
        fail("bad name accepted")
    except vault.VaultError:
        pass
    ok("resolver set by the CLI (needs {name}); test reports a length; unknown and bad names refused")

    # 2. provider keys: a stored secret:// value, the providers/<name> convention, env passthrough
    agent.save_key("anthropic", "secret://anthropic-key")
    if "sk-ant" in open(os.path.join(HOME, "keys.json")).read():
        fail("the key file holds a value, not the reference")
    if agent.load_key("anthropic") != "sk-ant-from-vault":
        fail("stored reference not resolved")
    if agent.load_key("openai") != "sk-oa-convention":
        fail("providers/<name> convention not used")
    try:
        agent.load_key("gemini")
        fail("no key anywhere should fail")
    except ov.OverlordError as e:
        if "providers/gemini" not in str(e):
            fail(f"error should name the convention: {e}")
    os.environ["GEMINI_API_KEY"] = "secret://gh-token"
    if agent.load_key("gemini") != "ghp_secret":
        fail("an env reference should resolve too")
    del os.environ["GEMINI_API_KEY"]
    ok("provider keys: stored references, the providers/<name> convention, env references")

    # 3. the cache: a changed vault value shows after the cache expires (or with cache 0)
    put(**{"gh-token": "ghp_rotated"})
    if vault.resolve("secret://gh-token") != "ghp_secret":
        fail("cache should still serve the old value within 60s")
    if vault.fetch("gh-token", fresh=True) != "ghp_rotated":
        fail("fresh fetch should see the rotation")
    cli("secrets", "set-command", CMD, "--cache", "0")
    put(**{"gh-token": "ghp_rotated2"})
    if vault.resolve("secret://gh-token") != "ghp_rotated2":
        fail("cache 0 should always ask")
    ok("cached for the configured seconds; a rotation shows after it, at once with cache 0")

    # 4. connectors, SSO and webhooks resolve at the point of use
    # the stdio transport builds its env through resolve_map before starting
    env = vault.resolve_map({"GITHUB_TOKEN": "secret://gh-token"})
    if env != {"GITHUB_TOKEN": "ghp_rotated2"}:
        fail(f"connector env: {env}")
    # whole values only: a reference embedded in a longer string is left alone
    h = mcp_mod._Http("x", {"url": "http://127.0.0.1:1/mcp", "headers": {"Authorization": "Bearer secret://gh-token"}})
    if h.headers["Authorization"] != "Bearer secret://gh-token":
        fail("an embedded reference must not be rewritten")
    h = mcp_mod._Http("x", {"url": "http://127.0.0.1:1/mcp", "headers": {"X-Token": "secret://gh-token"}})
    if h.headers["X-Token"] != "ghp_rotated2":
        fail(f"http connector headers: {h.headers}")
    hook = {"name": "t", "url": "http://127.0.0.1:1/x", "format": "json", "secret": "secret://hook-secret"}
    body = b'{"a":1}'
    if notify.signature(hook, body) != "sha256=" + hmac.new(b"hush", body, hashlib.sha256).hexdigest():
        fail("webhook signature should use the resolved secret")
    oidc.save_config({"issuer": "https://idp.example", "client_id": "c", "client_secret": "secret://sso-secret"})
    if "oidc-s3cret" in open(oidc.CONFIG_FILE).read():
        fail("oidc config holds a value")
    if vault.resolve(oidc.load_config()["client_secret"]) != "oidc-s3cret":
        fail("sso secret reference")
    os.unlink(oidc.CONFIG_FILE)
    ok("connector env and headers, webhook signatures and the SSO secret resolve references")

    # 5. audited; off
    ops = [e.get("op") for e in audit.entries(action="secrets.config")]
    if "set-command" not in ops:
        fail(f"config not audited: {ops}")
    if any("ghp_" in json.dumps(e) or "sk-ant" in json.dumps(e) for e in audit.entries(n=0)):
        fail("a secret value reached the audit log")
    if cli("secrets", "off").returncode != 0 or vault.configured():
        fail("secrets off")
    try:
        agent.load_key("openai")
        fail("convention still resolving after off")
    except ov.OverlordError:
        pass
    ok("configuration audited without values; off restores file-only keys")

    print("PASS: vault")
finally:
    subprocess.run(["rm", "-rf", HOME])
