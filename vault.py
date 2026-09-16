#!/usr/bin/env python3
"""OVERLORD vault bridge — bring your own secrets store.

Anywhere OVERLORD stores a secret — a provider API key, a connector's env
or headers, the SSO client secret, a webhook's signing secret — the value
may be a reference, `secret://NAME`, resolved at the moment of use by a
command you configure:

    overlord secrets set-command 'vault kv get -field=value secret/overlord/{name}'
    overlord secrets set-command 'pass show overlord/{name}'
    overlord secrets set-command 'aws secretsmanager get-secret-value --query SecretString --output text --secret-id {name}'
    overlord secrets test my-key | show | off

The command runs without a shell ({name} is substituted per argument); its
stdout, stripped, is the secret. Nothing sensitive is written by OVERLORD
when references are used, and `overlord secrets test` reports a length,
never a value. Provider keys have a convention as well: with a command
configured and no key in any file, `providers/<provider>` is asked for.

  ~/.overlord/vault.json   {"command": "...", "timeout": 15, "cache": 60}
"""

import json
import os
import re
import shlex
import subprocess
import threading
import time

import overlord as core

CONFIG_FILE = os.path.join(core.OVERLORD_HOME, "vault.json")
PREFIX = "secret://"
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/_.:@-]{0,127}$")
_LOCK = threading.Lock()
_CACHE = {}          # name -> (fetched_at, value)


class VaultError(core.OverlordError):
    pass


def load_config():
    try:
        with open(CONFIG_FILE) as f:
            c = json.load(f)
    except (OSError, ValueError):
        return None
    if not c.get("command"):
        return None
    return {"command": str(c["command"]), "timeout": float(c.get("timeout") or 15),
            "cache": float(c.get("cache") if c.get("cache") is not None else 60)}


def save_config(c):
    os.makedirs(core.OVERLORD_HOME, exist_ok=True)
    tmp = CONFIG_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(c, f, indent=2)
    os.replace(tmp, CONFIG_FILE)


def configured():
    return load_config() is not None


def is_ref(value):
    return isinstance(value, str) and value.startswith(PREFIX)


def fetch(name, fresh=False):
    """Run the command for NAME. Cached for the configured seconds."""
    if not _NAME_RE.match(name or ""):
        raise VaultError("error: a secret name is letters, digits and / _ . : @ -")
    c = load_config()
    if not c:
        raise VaultError(f"error: {PREFIX}{name} needs a resolver: overlord secrets set-command '...'")
    now = time.time()
    if not fresh and c["cache"] > 0:
        with _LOCK:
            hit = _CACHE.get(name)
            if hit and now - hit[0] < c["cache"]:
                return hit[1]
    argv = [a.replace("{name}", name) for a in shlex.split(c["command"])]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=c["timeout"],
                           stdin=subprocess.DEVNULL)
    except OSError as e:
        raise VaultError(f"error: secret resolver could not run ({argv[0]}): {e}")
    except subprocess.TimeoutExpired:
        raise VaultError(f"error: secret resolver timed out after {c['timeout']:.0f}s for {name}")
    if r.returncode != 0:
        tail = " ".join((r.stderr or "").split())[-200:]
        raise VaultError(f"error: secret resolver failed for {name} (exit {r.returncode}): {tail}")
    value = r.stdout.strip()
    if not value:
        raise VaultError(f"error: secret resolver returned nothing for {name}")
    with _LOCK:
        _CACHE[name] = (now, value)
    return value


def resolve(value):
    """A secret:// reference becomes its value; anything else passes through."""
    if is_ref(value):
        return fetch(value[len(PREFIX):])
    return value


def resolve_map(d):
    return {str(k): resolve(str(v)) for k, v in (d or {}).items()}


def provider_key(provider):
    """The conventional vault entry for a provider, when a resolver is
    configured and no file has a key. None when not configured."""
    if not configured():
        return None
    return fetch(f"providers/{provider}")


# ---------------------------------------------------------------- cli


def cmd_vault(args):
    c = args.secrets_cmd
    if c == "set-command":
        if "{name}" not in args.command:
            raise VaultError("error: the command must contain {name}")
        shlex.split(args.command)
        save_config({"command": args.command, "timeout": args.timeout, "cache": args.cache})
        import audit
        audit.record("secrets.config", op="set-command", command=args.command)
        _CACHE.clear()
        print("secret resolver set; use secret://NAME wherever a key, token or header goes")
        return 0
    if c == "show":
        cfg = load_config()
        if not cfg:
            print("no secret resolver: secrets live in mode-600 files under ~/.overlord")
            return 0
        print(f"command: {cfg['command']}\ntimeout: {cfg['timeout']:.0f}s\ncache:   {cfg['cache']:.0f}s")
        return 0
    if c == "test":
        v = fetch(args.name, fresh=True)
        print(f"resolved {args.name}: {len(v)} characters")
        return 0
    if c == "off":
        if os.path.isfile(CONFIG_FILE):
            os.unlink(CONFIG_FILE)
        _CACHE.clear()
        import audit
        audit.record("secrets.config", op="off")
        print("secret resolver off")
        return 0
    raise VaultError("error: unknown secrets subcommand")


def add_vault_parser(sub):
    ps = sub.add_parser("secrets", help="resolve secret://NAME through your own vault command")
    ss = ps.add_subparsers(dest="secrets_cmd", required=True)
    p = ss.add_parser("set-command")
    p.add_argument("command", help="a command line with {name}; runs without a shell")
    p.add_argument("--timeout", type=float, default=15)
    p.add_argument("--cache", type=float, default=60, help="seconds a resolved value is reused (0 = never)")
    ss.add_parser("show")
    ss.add_parser("test").add_argument("name")
    ss.add_parser("off")
    ps.set_defaults(fn=cmd_vault)
