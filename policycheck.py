#!/usr/bin/env python3
"""OVERLORD pre-commit policy gate — content checks on a pending diff.

`protected_hits` already gates commit on *which paths* a session touches. This
module gates on *what the diff contains*: secrets, compiled binaries, changes
to dependency manifests, and diffs larger than a threshold. It runs in
`commit_session`, against the exact content that would be replayed, and turns
each finding into one of three actions the policy rule chooses:

  block        refuse the commit (like a conflict); --force overrides, audited.
  countersign  demand a fresh second-model approval before commit.
  warn         record the finding on the audit trail and allow the commit.

The checks are pure functions over (rel, bytes): no I/O of their own beyond a
`locate` callback the caller supplies to read a changed file's new content, so
the whole gate is testable offline without a session. Nothing here mutates a
session or the tree — a blocked commit leaves the session pending for the
operator to inspect and roll back deliberately.

Config lives under a target's rule in policy.json, e.g.

    "checks": {
        "secrets":   "block",
        "binaries":  "warn",
        "deps":      "countersign",
        "max_files": 200,
        "max_bytes": 5242880,
        "size":      "block"
    }

A named check absent from the block, or set to a falsey value, is off. Legacy
value `true` means "block".
"""

import os
import re

ACTIONS = ("block", "countersign", "warn")
_DEFAULT_ACTION = "block"

# a rule value may be an action string, or True (== block) / False (off)
def _action_of(value):
    if value is True:
        return "block"
    if isinstance(value, str) and value.lower() in ACTIONS:
        return value.lower()
    return None


# ---------------------------------------------------------------- secrets

# Deny-list of shapes that are secrets almost regardless of context. Kept tight
# to hold false positives down: a hit should be worth a human's second look.
_SECRET_PATTERNS = [
    ("private-key",  re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token",  re.compile(rb"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("google-api-key", re.compile(rb"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe-key",   re.compile(rb"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("jwt",          re.compile(rb"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}\b")),
    # assignment of a long opaque value to a secret-named field
    ("secret-assignment", re.compile(
        rb"(?i)(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret|access[_-]?key)"
        rb"\s*[:=]\s*['\"][A-Za-z0-9/+_\-\.]{16,}['\"]")),
]


def scan_secrets(rel, data):
    """Findings for one file's bytes. One finding per pattern that hits, with
    the 1-based line of the first match — never the secret itself."""
    out = []
    for name, pat in _SECRET_PATTERNS:
        m = pat.search(data)
        if m:
            line = data.count(b"\n", 0, m.start()) + 1
            out.append({"check": "secrets", "path": rel,
                        "detail": f"{name} at line {line}"})
    return out


# ---------------------------------------------------------------- binaries


def is_binary(data):
    """A NUL byte in the first 8 KiB — the same heuristic git uses. Catches
    compiled artifacts, archives and images regardless of extension."""
    return b"\x00" in data[:8192]


def scan_binary(rel, data):
    if data and is_binary(data):
        return [{"check": "binaries", "path": rel,
                 "detail": f"binary content ({len(data)} bytes)"}]
    return []


# ---------------------------------------------------------------- dependencies

# Basenames whose change means the dependency set moved. Lockfiles included:
# a lockfile edit is a supply-chain event even when the manifest is untouched.
_DEP_FILES = frozenset((
    "requirements.txt", "requirements.in", "pipfile", "pipfile.lock",
    "poetry.lock", "pyproject.toml", "setup.py", "setup.cfg",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "npm-shrinkwrap.json", "go.mod", "go.sum", "cargo.toml", "cargo.lock",
    "gemfile", "gemfile.lock", "composer.json", "composer.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
))


def is_dep_file(rel):
    return os.path.basename(rel.rstrip("/")).lower() in _DEP_FILES


def scan_dep(rel):
    if is_dep_file(rel):
        return [{"check": "deps", "path": rel, "detail": "dependency manifest changed"}]
    return []


# ---------------------------------------------------------------- the gate


def evaluate(changes, locate, checks):
    """Run the configured checks over a session's changes.

    changes  list of (kind, rel) — the net diff (from session_stack).
    locate   rel -> absolute path of that file's NEW content in the upper
             layers, or None if it cannot be read. Called only for added and
             modified files.
    checks   the rule's "checks" dict (see module docstring).

    Returns a list of findings; each is {check, path, detail, action}. Findings
    whose action could not be resolved (check off) are omitted. Deterministic
    order: by path, then check.
    """
    if not isinstance(checks, dict) or not checks:
        return []
    a_secrets = _action_of(checks.get("secrets"))
    a_binary = _action_of(checks.get("binaries"))
    a_deps = _action_of(checks.get("deps"))
    a_size = _action_of(checks.get("size"))
    max_files = _int(checks.get("max_files"))
    max_bytes = _int(checks.get("max_bytes"))

    findings = []
    total_bytes = 0
    content_files = 0
    for kind, rel in changes:
        if rel.endswith("/") or kind == "deleted":
            if a_deps and kind == "deleted":
                findings += [dict(f, action=a_deps) for f in scan_dep(rel)]
            continue
        if kind not in ("added", "modified"):
            continue
        content_files += 1
        if a_deps:
            findings += [dict(f, action=a_deps) for f in scan_dep(rel)]
        data = _read(locate, rel) if (a_secrets or a_binary or max_bytes) else b""
        total_bytes += len(data)
        if a_secrets:
            findings += [dict(f, action=a_secrets) for f in scan_secrets(rel, data)]
        if a_binary:
            findings += [dict(f, action=a_binary) for f in scan_binary(rel, data)]

    if a_size and max_files and content_files > max_files:
        findings.append({"check": "size", "path": "",
                         "detail": f"{content_files} files changed (limit {max_files})",
                         "action": a_size})
    if a_size and max_bytes and total_bytes > max_bytes:
        findings.append({"check": "size", "path": "",
                         "detail": f"{total_bytes} bytes changed (limit {max_bytes})",
                         "action": a_size})

    findings.sort(key=lambda f: (f["path"], f["check"], f["detail"]))
    return findings


def worst(findings):
    """The strongest action present: block > countersign > warn > None."""
    order = {"block": 3, "countersign": 2, "warn": 1}
    top = None
    for f in findings:
        if order.get(f.get("action"), 0) > order.get(top, 0):
            top = f["action"]
    return top


def summarize(findings):
    """A short one-line-per-finding description for the operator or the audit
    record. Never includes secret material — scan_secrets already elides it."""
    return [f"[{f['action']}] {f['check']}: {f['path'] or '(diff)'} — {f['detail']}"
            for f in findings]


def _read(locate, rel):
    try:
        path = locate(rel)
        if not path or not os.path.isfile(path) or os.path.islink(path):
            return b""
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return b""


def _int(v):
    try:
        return int(v) if v else 0
    except (TypeError, ValueError):
        return 0
