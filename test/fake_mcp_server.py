#!/usr/bin/env python3
"""A minimal MCP server over stdio for tests: two tools, one read-only.

    echo   (readOnlyHint)  -> returns its text argument
    send   (an action)     -> "sent: <to>" and records the call in a file
                              named by MCP_FAKE_LOG so tests can prove it ran
Also answers ping and paginates tools/list across two pages to exercise the
cursor path. Speaks newline-delimited JSON-RPC 2.0."""

import json
import os
import sys

TOOLS = [
    {"name": "echo", "description": "Echo text back",
     "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}},
                     "required": ["text"]},
     "annotations": {"readOnlyHint": True}},
    {"name": "run_shell", "description": "Run a shell command on the host (a general shell)",
     "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]},
     "annotations": {"readOnlyHint": False}},
    {"name": "send", "description": "Send a message somewhere (irreversible)",
     "inputSchema": {"type": "object", "properties": {"to": {"type": "string"},
                                                      "body": {"type": "string"}},
                     "required": ["to"]},
     "annotations": {"readOnlyHint": False, "destructiveHint": True}},
]


def reply(rid, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": rid}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    try:
        req = json.loads(line)
    except ValueError:
        continue
    method, rid, params = req.get("method"), req.get("id"), req.get("params") or {}
    if method == "initialize":
        reply(rid, {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake-mcp", "version": "1.0"}})
    elif method == "notifications/initialized":
        continue
    elif method == "ping":
        reply(rid, {})
    elif method == "tools/list":
        if params.get("cursor") == "page2":
            reply(rid, {"tools": TOOLS[1:]})
        else:
            reply(rid, {"tools": TOOLS[:1], "nextCursor": "page2"})
    elif method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        if name == "echo":
            reply(rid, {"content": [{"type": "text", "text": args.get("text", "")}]})
        elif name == "run_shell":
            reply(rid, {"content": [{"type": "text", "text": "would have run: " + str(args.get("cmd"))}]})
        elif name == "send":
            log = os.environ.get("MCP_FAKE_LOG")
            if log:
                with open(log, "a") as f:
                    f.write(json.dumps(args) + "\n")
            reply(rid, {"content": [{"type": "text", "text": f"sent: {args.get('to')}"}]})
        elif name == "boom":
            reply(rid, {"content": [{"type": "text", "text": "it broke"}], "isError": True})
        else:
            reply(rid, error={"code": -32602, "message": f"unknown tool {name}"})
    elif rid is not None:
        reply(rid, error={"code": -32601, "message": f"method not found: {method}"})
