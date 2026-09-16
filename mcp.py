#!/usr/bin/env python3
"""OVERLORD connectors — an MCP client, stdlib only.

    overlord mcp add <name> --command npx --arg -y --arg @scope/server [--env K=V]
    overlord mcp add <name> --url https://host/mcp [--header 'Authorization: Bearer …']
    overlord mcp list | test <name> | rm <name>
    overlord agent --connector <name> [--connector-approval ask|auto|readonly] …

A connector is a Model Context Protocol server: a process spoken to over
stdio, or a URL spoken to over streamable HTTP. Its tools are offered to the
model next to the built-in ones, namespaced `mcp__<server>__<tool>`, and a
call is routed back to the server that owns it.

Two things about connectors are different from everything else in OVERLORD,
and the design says so out loud:

  1. They run on the host, outside the jail and outside the transaction. A
     connector that sends an email has sent it; Discard cannot unsend it.
     So a session must be *granted* each connector by name (a grant, like
     jail or net), policy can cap the set, and every call is written to the
     transcript with the server that served it and shown to the reviewer as
     an external action.
  2. Non-read-only tools go through an approval gate by default: the run
     pauses, a person allows or denies, and the decision is recorded. A tool
     declares itself read-only through MCP's readOnlyHint annotation; anything
     else is treated as an action. Modes: ask (default), auto, readonly.

Servers are configured in ~/.overlord/mcp.json. A stdio server gets only the
environment you configure for it (plus PATH, HOME, LANG), never the whole
process environment, so one connector's token is not another's.
"""

import hashlib
import json
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request

import overlord as core

CONFIG_FILE = os.path.join(core.OVERLORD_HOME, "mcp.json")
PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "overlord", "version": "0.10"}
CALL_TIMEOUT = 120
PREFIX = "mcp__"
APPROVAL_MODES = ("ask", "auto", "readonly")
_SAFE_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "USER", "SHELL")


class MCPError(core.OverlordError):
    pass


# ---------------------------------------------------------------- config


def load_config():
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        cfg = {}
    servers = cfg.get("servers") if isinstance(cfg.get("servers"), dict) else {}
    return {"servers": {n: s for n, s in servers.items() if isinstance(s, dict)},
            "approval": cfg.get("approval") if cfg.get("approval") in APPROVAL_MODES else "ask"}


def save_config(cfg):
    os.makedirs(core.OVERLORD_HOME, exist_ok=True)
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG_FILE)


def _valid_name(name):
    if not name or not all(c.isalnum() or c in "-_" for c in name) or len(name) > 40:
        raise MCPError("error: connector names are letters, digits, - and _ (max 40)")
    return name


def _add_server_impl(name, command=None, args=None, env=None, cwd=None, url=None, headers=None):
    """Register a connector. Exactly one of command (stdio) or url (http)."""
    _valid_name(name)
    if bool(command) == bool(url):
        raise MCPError("error: a connector is either a command (stdio) or a url (http)")
    if url and not url.startswith(("http://", "https://")):
        raise MCPError("error: url must start with http:// or https://")
    entry = {"transport": "stdio" if command else "http", "enabled": True}
    if command:
        entry.update(command=command, args=list(args or []), env=dict(env or {}), cwd=cwd or "")
    else:
        entry.update(url=url, headers=dict(headers or {}))
    cfg = load_config()
    cfg["servers"][name] = entry
    save_config(cfg)
    return entry


def _remove_server_impl(name):
    cfg = load_config()
    if name not in cfg["servers"]:
        raise MCPError(f"error: no connector named {name}")
    del cfg["servers"][name]
    save_config(cfg)


def _set_approval_impl(mode):
    if mode not in APPROVAL_MODES:
        raise MCPError(f"error: approval must be one of {', '.join(APPROVAL_MODES)}")
    cfg = load_config()
    cfg["approval"] = mode
    save_config(cfg)


def public_config():
    """The configuration as the UI may see it: header and env values masked."""
    cfg = load_config()
    out = {"approval": cfg["approval"], "servers": {}}
    for n, s in cfg["servers"].items():
        e = {k: v for k, v in s.items() if k not in ("headers", "env")}
        e["headers"] = sorted((s.get("headers") or {}).keys())
        e["env"] = sorted((s.get("env") or {}).keys())
        out["servers"][n] = e
    return out


# ---------------------------------------------------------------- transports


class _Stdio:
    def __init__(self, name, spec):
        self.name = name
        import vault as vault_mod
        env = {k: os.environ[k] for k in _SAFE_ENV if k in os.environ}
        env.update(vault_mod.resolve_map(spec.get("env") or {}))     # secret:// resolved here
        try:
            self.proc = subprocess.Popen(
                [spec["command"], *spec.get("args", [])], cwd=spec.get("cwd") or None, env=env,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1)
        except OSError as e:
            raise MCPError(f"error: connector {name}: cannot start {spec['command']}: {e}")
        self._pending, self._lock, self._next = {}, threading.Lock(), 0
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self):
        for line in self.proc.stdout:
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if "id" in msg and ("result" in msg or "error" in msg):
                with self._lock:
                    ev = self._pending.get(msg["id"])
                if ev:
                    ev["msg"] = msg
                    ev["done"].set()
            elif msg.get("method") == "ping" and "id" in msg:
                self._write({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
        with self._lock:
            for ev in self._pending.values():
                ev["msg"] = {"error": {"message": "connector exited"}}
                ev["done"].set()

    def _write(self, obj):
        try:
            self.proc.stdin.write(json.dumps(obj) + "\n")
            self.proc.stdin.flush()
        except (OSError, ValueError):
            raise MCPError(f"error: connector {self.name} is gone")

    def request(self, method, params=None, timeout=CALL_TIMEOUT):
        with self._lock:
            self._next += 1
            rid = self._next
            ev = self._pending[rid] = {"done": threading.Event(), "msg": None}
        self._write({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        if not ev["done"].wait(timeout):
            with self._lock:
                self._pending.pop(rid, None)
            raise MCPError(f"error: connector {self.name}: {method} timed out after {timeout}s")
        with self._lock:
            self._pending.pop(rid, None)
        msg = ev["msg"]
        if "error" in msg:
            raise MCPError(f"error: connector {self.name}: {msg['error'].get('message') or msg['error']}")
        return msg.get("result") or {}

    def notify(self, method, params=None):
        self._write({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def close(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()


class _Http:
    """Streamable HTTP: one POST per message; the answer is JSON or an SSE
    stream carrying the response; Mcp-Session-Id is kept once issued."""

    def __init__(self, name, spec):
        import vault as vault_mod
        self.name, self.url = name, spec["url"]
        self.headers = vault_mod.resolve_map(spec.get("headers") or {})   # secret:// resolved here
        self.session, self._next, self._lock = None, 0, threading.Lock()

    def _post(self, obj, timeout):
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
             **self.headers}
        if self.session:
            h["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(self.url, data=json.dumps(obj).encode(), headers=h, method="POST")
        try:
            resp = urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            raise MCPError(f"error: connector {self.name}: HTTP {e.code}: "
                           f"{e.read().decode(errors='replace')[:300]}")
        except urllib.error.URLError as e:
            raise MCPError(f"error: connector {self.name}: unreachable: {e.reason}")
        sid = resp.headers.get("Mcp-Session-Id")
        if sid:
            self.session = sid
        return resp

    def request(self, method, params=None, timeout=CALL_TIMEOUT):
        with self._lock:
            self._next += 1
            rid = self._next
        with self._post({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}},
                        timeout) as resp:
            ctype = resp.headers.get("Content-Type", "")
            if "text/event-stream" in ctype:
                msg = None
                data = []
                for raw in resp:
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    if line.startswith("data:"):
                        data.append(line[5:].lstrip())
                    elif not line and data:
                        try:
                            cand = json.loads("\n".join(data))
                        except ValueError:
                            cand = None
                        data = []
                        if isinstance(cand, dict) and cand.get("id") == rid:
                            msg = cand
                            break
                if msg is None:
                    raise MCPError(f"error: connector {self.name}: no response to {method}")
            else:
                msg = json.load(resp)
        if "error" in msg:
            raise MCPError(f"error: connector {self.name}: {msg['error'].get('message') or msg['error']}")
        return msg.get("result") or {}

    def notify(self, method, params=None):
        try:
            with self._post({"jsonrpc": "2.0", "method": method, "params": params or {}}, 30):
                pass
        except MCPError:
            pass

    def close(self):
        pass


# ---------------------------------------------------------------- client


class Connector:
    """One connected server: handshake done, tools listed."""

    def __init__(self, name, spec):
        self.name = name
        self.transport = _Http(name, spec) if spec.get("transport") == "http" else _Stdio(name, spec)
        try:
            init = self.transport.request("initialize", {
                "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                "clientInfo": CLIENT_INFO}, timeout=30)
            self.transport.notify("notifications/initialized")
        except MCPError:
            self.transport.close()
            raise
        self.server_info = init.get("serverInfo") or {}
        self.tools = self._list_tools()

    def _list_tools(self):
        tools, cursor = [], None
        for _ in range(20):
            params = {"cursor": cursor} if cursor else {}
            res = self.transport.request("tools/list", params, timeout=30)
            tools.extend(res.get("tools") or [])
            cursor = res.get("nextCursor")
            if not cursor:
                break
        return tools

    def call(self, tool, arguments, timeout=CALL_TIMEOUT):
        res = self.transport.request("tools/call", {"name": tool, "arguments": arguments or {}},
                                     timeout=timeout)
        return _content_text(res), bool(res.get("isError"))

    def close(self):
        self.transport.close()


def _content_text(res):
    parts = []
    for c in res.get("content") or []:
        t = c.get("type")
        if t == "text":
            parts.append(c.get("text", ""))
        elif t == "image":
            parts.append(f"[image {c.get('mimeType', '')}, {len(c.get('data', ''))} base64 chars]")
        elif t == "resource":
            r = c.get("resource") or {}
            parts.append(r.get("text") or f"[resource {r.get('uri', '')}]")
        else:
            parts.append(json.dumps(c)[:2000])
    if not parts and res.get("structuredContent") is not None:
        parts.append(json.dumps(res["structuredContent"]))
    return "\n".join(parts)


def call_fingerprint(server, tool, arguments):
    """sha256 over exactly what a connector call is: the server, the tool and
    its arguments. An approval names this fingerprint, so it authorizes that
    call and no other; the call and its result are recorded against it."""
    body = json.dumps([server, tool, arguments], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


def tool_name(server, tool):
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in tool)[:40]
    return f"{PREFIX}{server}__{safe}"


def is_read_only(tool):
    ann = tool.get("annotations") or {}
    return bool(ann.get("readOnlyHint"))


SHELL_RE = re.compile(r"(^|[_\-. ])(shell|bash|zsh|sh|exec|execute|run_command|run_cmd|"
                      r"terminal|cmd|command|eval|spawn|subprocess|system|powershell)([_\-. ]|$)", re.I)


def looks_like_shell(tool):
    """A connector tool that would hand the model a shell on the host — the
    one capability the transaction exists to contain. Withheld unless the
    session was granted connector_shell."""
    return bool(SHELL_RE.search(tool.get("name") or ""))


class Registry:
    """The connectors a session was granted, connected on first use, with
    their tools in the agent's tool form."""

    def __init__(self, names, config=None, allow_shell=False):
        cfg = config or load_config()
        self.allow_shell = bool(allow_shell)
        self.withheld = []
        self.specs = {}
        for n in names or []:
            spec = cfg["servers"].get(n)
            if spec is None:
                raise MCPError(f"error: no connector named {n} (overlord mcp list)")
            if not spec.get("enabled", True):
                raise MCPError(f"error: connector {n} is disabled")
            self.specs[n] = spec
        self.approval = cfg["approval"]
        self._conns, self._map, self._lock = {}, {}, threading.Lock()

    def connect(self):
        with self._lock:
            for n, spec in self.specs.items():
                if n not in self._conns:
                    self._conns[n] = Connector(n, spec)
                    for t in self._conns[n].tools:
                        if not self.allow_shell and looks_like_shell(t):
                            self.withheld.append(tool_name(n, t["name"]))
                            continue
                        self._map[tool_name(n, t["name"])] = (n, t)
        return self

    def tools(self):
        """Agent-form tool definitions for every granted connector."""
        self.connect()
        out = []
        for name, (server, t) in self._map.items():
            desc = t.get("description") or t["name"]
            out.append({"name": name,
                        "description": f"[{server}] {desc}"[:1024],
                        "input_schema": t.get("inputSchema") or {"type": "object", "properties": {}},
                        "_server": server, "_tool": t["name"], "_read_only": is_read_only(t)})
        return out

    def owns(self, name):
        return name in self._map

    def describe(self, name):
        server, t = self._map[name]
        return {"server": server, "tool": t["name"], "read_only": is_read_only(t)}

    def call(self, name, arguments):
        server, t = self._map[name]
        return self._conns[server].call(t["name"], arguments)

    def close(self):
        with self._lock:
            for c in self._conns.values():
                try:
                    c.close()
                except Exception:
                    pass
            self._conns.clear()


def test_server(name):
    """Connect once and report: server info and its tools."""
    cfg = load_config()
    if name not in cfg["servers"]:
        raise MCPError(f"error: no connector named {name}")
    t0 = time.time()
    c = Connector(name, cfg["servers"][name])
    try:
        return {"name": name, "server": c.server_info, "seconds": round(time.time() - t0, 2),
                "tools": [{"name": t["name"], "description": (t.get("description") or "")[:200],
                           "read_only": is_read_only(t)} for t in c.tools]}
    finally:
        c.close()


# ---------------------------------------------------------------- CLI


def cmd_mcp(args):
    if args.mcp_cmd == "list":
        cfg = load_config()
        if not cfg["servers"]:
            print("no connectors configured (overlord mcp add …)")
            return 0
        print(f"approval mode: {cfg['approval']}")
        for n, s in cfg["servers"].items():
            where = s.get("url") if s.get("transport") == "http" else " ".join([s.get("command", "")] + s.get("args", []))
            print(f"  {n:20s} {s.get('transport'):6s} {where}{'' if s.get('enabled', True) else '  (disabled)'}")
        return 0
    if args.mcp_cmd == "add":
        env = {}
        for kv in args.env or []:
            if "=" not in kv:
                raise MCPError(f"error: --env wants K=V, got {kv!r}")
            k, v = kv.split("=", 1)
            env[k] = v
        headers = {}
        for h in args.header or []:
            if ":" not in h:
                raise MCPError(f"error: --header wants 'Name: value', got {h!r}")
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
        add_server(args.name, command=args.command, args=args.arg, env=env, cwd=args.cwd,
                   url=args.url, headers=headers)
        print(f"added connector {args.name}")
        return 0
    if args.mcp_cmd == "rm":
        remove_server(args.name)
        print(f"removed connector {args.name}")
        return 0
    if args.mcp_cmd == "test":
        r = test_server(args.name)
        si = r["server"]
        print(f"{args.name}: {si.get('name', '?')} {si.get('version', '')}  ({r['seconds']}s)")
        for t in r["tools"]:
            print(f"  {t['name']:30s} {'read-only ' if t['read_only'] else 'ACTION    '} {t['description']}")
        return 0
    if args.mcp_cmd == "approval":
        set_approval(args.mode)
        print(f"connector approval mode: {args.mode}")
        return 0
    raise MCPError("error: unknown mcp subcommand")


def add_mcp_parser(sub):
    pm = sub.add_parser("mcp", help="connectors: MCP servers whose tools the agent may use")
    ms = pm.add_subparsers(dest="mcp_cmd", required=True)
    ms.add_parser("list", help="configured connectors")
    pa = ms.add_parser("add", help="register a connector (stdio command or http url)")
    pa.add_argument("name")
    pa.add_argument("--command", help="stdio: the program to run")
    pa.add_argument("--arg", action="append", help="stdio: an argument (repeatable)")
    pa.add_argument("--env", action="append", metavar="K=V", help="stdio: environment (repeatable)")
    pa.add_argument("--cwd", help="stdio: working directory")
    pa.add_argument("--url", help="http: the server's MCP endpoint")
    pa.add_argument("--header", action="append", metavar="'Name: value'", help="http: request header")
    pr = ms.add_parser("rm", help="remove a connector")
    pr.add_argument("name")
    pt = ms.add_parser("test", help="connect and list a connector's tools")
    pt.add_argument("name")
    pv = ms.add_parser("approval", help="what happens before a non-read-only connector tool runs")
    pv.add_argument("mode", choices=APPROVAL_MODES)
    pm.set_defaults(fn=cmd_mcp)


# ---------------------------------------------------------------- audit


def add_server(name, command=None, args=None, env=None, cwd=None, url=None, headers=None):
    entry = _add_server_impl(name, command=command, args=args, env=env, cwd=cwd, url=url,
                             headers=headers)
    import audit
    audit.record("connector.config", op="add", server=name, transport=entry.get("transport"))
    return entry


def remove_server(name):
    r = _remove_server_impl(name)
    import audit
    audit.record("connector.config", op="remove", server=name)
    return r


def set_approval(mode):
    r = _set_approval_impl(mode)
    import audit
    audit.record("connector.config", op="approval", mode=mode)
    return r
