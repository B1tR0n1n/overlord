# OVERLORD

An agent hypervisor — the trust kernel for delegated computing.

![OVERLORD demo: rm -rf inside a transactional shell, then rollback — everything comes back](assets/demo.gif)

Hand a program — or an AI agent — a fully writable copy of a directory. Let it
run. Then review every change it made as a hashed, attributed manifest and
**commit or roll back**, all or nothing. Transactional isolation, provenance,
and arbitration for untrusted execution — in dependency-free Python, on the
kernel's own primitives. It ships with a built-in agent (`overlord agent`) that
runs a model with its hands jailed, so you can watch the whole loop happen
inside the transaction and sign off on the diff.

## Thesis

Computing is transitioning to a new operator: machine agents. The OS has no native
concept of a machine actor. Every agent today runs with its principal's full authority
on infrastructure that cannot distinguish the principal's intent from the agent's
behavior. Every harness vendor duct-tapes around this independently and badly.

OVERLORD is the missing layer between the agent harness and the operating system.
Not an AI. Model-agnostic. A boring, load-bearing primitive — the SQLite pattern,
not the Windows pattern.

## The Four Primitives

1. **Capability, not identity** — an agent receives a scoped grant (paths, budget,
   network egress, time window), not a user account. Commander's intent expressed
   as kernel-enforced constraints.
2. **Provenance** — every mutation traceable to actor, instruction, and the reasoning
   artifact that caused it. A flight recorder for machine action.
3. **Reversibility** — agent action is transactional: snapshot, execute, inspect,
   commit or roll back. The keystone. Delegation is blocked on "what if it breaks
   something"; this removes the question.
4. **Arbitration** — when N agents contend for a resource, authority is scheduled
   the way CPU is scheduled.

## Install

```bash
sudo bash packaging/install.sh
overlord doctor
```

Installs the engine to `/usr/local/lib/overlord/`, a compiled ELF launcher to
`/usr/local/bin/overlord` (the AppArmor attachment point), the AppArmor profile
that enables the kernel backend on Ubuntu 24.04+, and the runtime deps
(`fuse-overlayfs`, `strace`).

## Use

```bash
overlord run -t /srv/app -- some-agent --do-things   # transactional execution
overlord run --jail --net none --timeout 300 -t /srv/app -- <cmd>   # scoped grants
overlord run --manifest cap.json -t /srv/app -- <cmd>               # grants from file
overlord run --trace -t /srv/app -- <cmd>            # + syscall flight recorder (strace)
overlord run --trace ebpf -t /srv/app -- <cmd>       # kernel-side recorder (root-only)
overlord run --merge-base -t /srv/app -- <cmd>       # keep base copy for commit --merge
overlord shell -t /srv/app                           # interactive transactional shell

overlord agent -t /srv/app "add a Makefile with a test target"   # jailed by default
overlord agent --net none -t /srv/app "<task>"       # ...and offline too
overlord agent --no-jail -t /srv/app "<task>"        # opt out: tools reach the real fs

overlord sessions                # pending/committed history with command provenance
overlord diff <session>          # added / modified / deleted / replaced-dir
overlord log <session>           # per-change sha256 before -> after, syscall count
overlord savepoints <session>    # the layer stack: one savepoint per command that wrote
overlord rewind <session> --to 3 # discard everything above savepoint @3
overlord resume <session> --note "..."   # agent carries on from there, reading the note
overlord commit <session>        # verify no external drift, replay onto real tree
overlord commit --drop tool:shell <sess>     # replay all but the shell tool's layers
overlord commit --only turn:2-4 <sess>       # replay only what turns 2–4 did
overlord commit --merge <sess>   # three-way merge non-overlapping drift (needs --merge-base)
overlord commit --force <sess>   # commit despite drift (explicit override)
overlord rollback <session>      # discard — target byte-identical
overlord blame <path>            # which session, turn, tool call, instruction put each line here
overlord doctor                  # backend / dependency diagnostics
```

The wrapped command sees a fully writable tree and exits believing everything
happened. Nothing touches the real tree until `commit`. Commit re-verifies the
snapshot fingerprints (size + mtime_ns of every file) and **refuses to clobber
external changes** made while the session was pending. If the session was run
with `--merge-base`, `commit --merge` three-way merges non-overlapping drift
(git merge-file against the kept base) and still refuses overlapping edits.

## Grants (the capability manifest)

Grants scope what a session may do — commander's intent as enforced constraints.
Set via flags or a JSON manifest (`--manifest cap.json`, flags override):

```json
{ "jail": true, "net": "none", "timeout": 300, "merge_base": false }
```

- **jail** — pivot_root jail: the process sees system dirs (ro by real perms),
  a private /tmp and /proc, and the target. `$HOME`, `/mnt`, and the rest of
  the filesystem *do not exist*. Kernel backend only.
- **net: none** — private empty network namespace. No egress, no loopback to
  host services. Kernel backend only.
- **timeout** — hard wall-clock limit; the process group is killed (exit 124).
- **merge_base** — keep a base copy (`cp --reflink=auto`) enabling `commit --merge`.

Arbitration: one executing session per target (flock; `--wait` queues), and a
new session is refused while another is pending on the same target (`--stack`
overrides).

## Savepoints: the tool call is the transaction

A session's upper layer is a *stack*. Every command that writes seals its
layer; the next command starts a new one. Each command runs in its own mount
namespace over the current stack (`lowerdir=layer_k:…:layer_0:target`), so a
savepoint costs one mount and copies nothing — it is SQL's `SAVEPOINT` on the
kernel's own overlay primitive. For the agent that means one savepoint per
tool call, stamped with the call that caused it. Three things fall out:

```bash
overlord savepoints <session>          # @0  1 path  turn 2 write_file(src/hello.py)
                                       # @1  2 paths turn 3 shell(rm scratch.txt; rm old.txt)
                                       # @2  1 path  turn 5 write_file(lib.py)
overlord rewind <session> --to 1       # world as it was after turn 3; transcript cut to match
overlord resume <session> --note "keep scratch.txt; make a() return 3"
overlord commit <session> --drop turn:3          # undo a decision, keep what came after
overlord blame src/lib.py              # per line: session · turn · tool call · the prompt
```

- **Rewind the agent to a thought.** `rewind` drops the layers above a
  savepoint and cuts the agent's transcript at the same point (the dropped
  tail is archived, because a rewind is itself an act with provenance).
  `resume` reopens the session on the surviving stack, rebuilds the model's
  message history exactly as it saw it, delivers your note as the next user
  turn, and lets it continue — from a world that matches what it remembers.
- **Commit by cause, not by path.** `commit --only` / `--drop` take selectors
  (`layer:N`, `layer:A-B`, `turn:N`, `tool:NAME`, `call:ID`) and replay just
  those layers in order. Overlayfs copies a whole file up on first write, so
  every layer's entries are complete and any ascending subset replays to a
  well-defined tree. Conflict detection covers every path the selected layers
  would touch on replay — not only the net diff — so a file one layer created
  and a later one deleted still cannot clobber a same-named file that
  appeared outside.
- **Blame to the prompt.** Commit retains the content it replaced and the
  content it wrote (content-addressed under `~/.overlord/objects`, capped per
  file by `OVERLORD_OBJECT_MAX`). `blame` walks the committed versions of a
  file and attributes each line to the session, turn, tool call and task that
  first produced it — `origin` for lines older than the record, `drift` for
  lines changed outside OVERLORD since the last commit.

Layers are addressed relative to the session dir (the mount data page is
4 KiB) and capped at 200 per session; past the cap the top layer keeps
absorbing writes. On the fuse backend the merged view is remounted between
commands; a lingering process that pins it makes the next savepoint coarser
rather than failing. Rewind is refused while a command is running.

## Mission control (web UI)

```bash
overlord ui          # http://127.0.0.1:7777 — localhost only
```

![OVERLORD mission control — a pending agent session's savepoint chain: one row per tool call that wrote, each with its paths, a keep checkbox that drops it from the commit when unticked, and a rewind-here control; the disposition below commits or voids](assets/ui.png)

The review moment for human eyes, rendered as a document of record rather than
a dashboard. The register indexes sessions; the dossier is the instrument a
human signs: the grant envelope the session ran under, a manifest of every
changed path with its before → after hashes and the tool call that caused it,
the savepoint chain (rewind to any row; untick a row and the commit drops it),
and the disposition — commit or void. Zero dependencies (stdlib http server),
server-rendered first paint, binds 127.0.0.1 only.

## Resident mode: daemon, policy, SDK

`overlord daemon` (or the systemd unit in packaging/) makes OVERLORD a
resident broker on a 0600 unix socket. Sessions requested through it are
bound by `~/.overlord/policy.json` — deny-by-default targets, forced jail/net,
timeout caps, force-commit gating — and callers can never obtain a looser
scope than policy grants. The Python SDK (`overlord_client.py`, installed to
/usr/local/lib/overlord/) embeds this in any harness: `run() -> Session`,
`session.diff/log/commit/rollback`. See docs/INTEGRATION.md.

## Red team

`test/redteam.sh` attacks the jail: symlink escape, dotdot traversal,
session-record tampering, host sysctl writes, device forgery, host pid
visibility, real-fs reads, overlay-internals reach, fd leaks, mount games.
Finding A3 (session records reachable via the strace bind) was found by this
suite and fixed — records are never exposed; strace gets an isolated trace/
bind only when in use. Every future breach becomes a fix + regression test.

## Backends

Two overlay backends, auto-detected, kernel preferred. `overlord doctor` names
the active one — read it before you trust a session.

| | containment | privileges |
|---|---|---|
| **kernel** | full — the overlay is mounted over the target's own path in a private mount namespace, so even absolute-path writes into the target are captured; `--jail` makes the rest of the filesystem cease to exist for the process | unprivileged user namespaces; on Ubuntu 24.04+ the shipped AppArmor profile grants exactly that to the `overlord` binary alone, nothing else weakened |
| **fuse** | cooperative — the overlay is the working directory, but absolute-path writes elsewhere are not intercepted | none |

The design choice that matters: **the fuse backend refuses `--jail` and
`--net` rather than pretending to honor them.** A degraded backend that
silently ignored a containment grant would be worse than no grant at all — so
it errors, and `doctor` tells you which backend is live before you rely on one.
The strong guarantee is the kernel backend; the cooperative one is a clearly
labelled fallback, never a disguise.

**Threat model, one line.** OVERLORD makes a program's writes to a target tree
transactional and reviewable, and — with `--jail --net none` on the kernel
backend — confines the process to that tree with no network. It is *not* a
defense against kernel exploits or a determined userns escape; it is the
missing transaction, provenance, and scope layer between an agent harness and
the OS, built on the kernel's own isolation rather than a new one.

## Provenance

Every session records `provenance.jsonl` — one record per change with sha256
before (lower) and after (upper), the savepoint layer that holds the final
content and the cause stamped on it (`caused_by`: turn, tool, call id,
summary), which survives commit and is what `blame` reads. With `--trace`, a
syscall-level record (`syscalls.jsonl`: exec, file mutation, connect, per pid,
timestamped) is captured via strace. `--trace ebpf` uses the bpftrace recorder
instead (installed to /usr/local/lib/overlord/provenance.bt) — lower overhead
and unfakeable by the traced process, but root-only and with a known
attach-race at process start.

## Test

```bash
bash test/smoke.sh                # 26 core transactional + replay-safety assertions
bash test/redteam.sh              # 10 jail escape attempts (kernel backend)
python3 test/daemon_sdk_test.py   # 17 daemon + SDK + policy + live-session assertions
python3 test/agent_test.py        # 10 agent loop, tool, provenance, and jail-default assertions
python3 test/savepoint_test.py    # 10 savepoint / rewind / resume / commit-by-cause / blame assertions
python3 test/ui_test.py           # 10 mission-control API + origin-guard + savepoint assertions
python3 test/ui_browser_test.py   # 9 mission-control DOM assertions (needs playwright)
```

`savepoint_test.py` runs on whichever backend is live; `OVERLORD_TEST_BACKEND=fuse`
forces the cooperative one, so both stacking implementations are exercised.

`ui_test.py` drives the HTTP API; `ui_browser_test.py` loads the page in
Chromium and asserts on the rendered DOM — console errors, the dossier
swapping on a register click, attribution reaching the manifest, the drift
refusal, keyboard navigation, and phone-width layout. The browser suite skips
cleanly when Playwright or Chromium is absent, so it never blocks a bare
checkout; it exists because an API-only UI test let a click-breaking
ReferenceError ship undetected.

Core suite (`smoke.sh`): isolation, diff completeness, provenance hashes,
byte-identical rollback, exact-replay commit, commit finality, conflict refusal
+ `--force`, create-collision refusal, shell, syscall trace, absolute-path
containment, mode-000 cleanup, timeout, manifest, arbitration, three-way merge,
jail sealing, net:none isolation. Kernel-only tests self-skip where userns
grants are absent.

## Roadmap

- fine-grained path grants (extra read-only / writable mounts in the jail)
- token/cost budget grants for LLM-backed agents
- eBPF recorder hardening (attach-race close, structured output)
- multi-target sessions; cross-target atomic commit
- forks: resume a rewound session as a new session so branches from one
  savepoint can be compared before either is committed
- blame across renames; a `blame` view in mission control

## Status

- 2026-09-01 — repo created; thesis.
- 2026-09-01 — v0: transactional run/diff/commit/rollback, dual backend, e2e suite.
- 2026-09-01 — v0.1: conflict detection, provenance flight recorder (hashes +
  strace), interactive shell, kernel-backend overmount containment, AppArmor
  packaging, installer.
- 2026-09-01 — v0.2: capability manifests (jail / net / timeout), pivot_root
  jail, network scoping, arbitration (locks + pending guard), three-way merge
  on commit, eBPF recorder wired (`--trace ebpf`, root-only).
- 2026-09-01 — v0.3: red team suite (10 attacks; found + fixed A3 session-record
  exposure), resident daemon with policy brokering (deny-by-default, grant caps,
  force gating), Python SDK, systemd unit, integration docs.
- 2026-09-01 — v0.4: mission control web UI (`overlord ui`) — session review,
  per-file diff with hashes, one-click commit/rollback, policy editor;
  zero-dependency, server-rendered, localhost-only.

  *(v0 → v0.4 landed in one build sprint on 2026-09-01.)*
- 2026-09-10 → 09-11 — v0.5, two parts. **The agent** — `overlord agent` runs a
  model (Anthropic / OpenAI, stdlib-only adapters) whose read/write/shell tools
  execute *inside* the transaction, jailed and offline by default, with every
  changed path linked back to the tool call that caused it; plus live sessions
  (open/exec/close, streaming daemon ops, SDK `LiveSession`) and mission control
  rebuilt as a document of record. **The hardening** — agent jailed by default
  (an unjailed one had been writing outside the transaction); UI cross-origin /
  CSRF refusal, CSP, and session-id path-injection guards; four replay-safety
  fixes (root-naming and kernel `.wh.` whiteouts, drifted-symlink escape,
  added-dir-over-file, post-snapshot descendants); clean teardown on a failed
  launch; a Chromium DOM test suite.
- 2026-09-15 — merged to `master`. SonarCloud quality gate green; 80 assertions
  across six suites.
- 2026-09-16 — v0.6: savepoints. The session holder now stays outside the
  jail and every command enters its own mount namespace over the current
  layer stack, so each writing command (each agent tool call) seals its own
  overlay layer with its cause stamped on it. On that: `rewind` (layers and
  transcript cut together, tail archived), `resume` (message history rebuilt
  as the model saw it, operator note injected), `commit --only/--drop`
  (replay a selection of layers; conflicts checked on everything replay would
  touch), and `blame` (committed content retained content-addressed; per-line
  attribution to session, turn, tool call and task, with drift detection).
  Mission control renders the chain with rewind-here and keep/drop controls;
  daemon ops and SDK methods for all of it. Also fixed: `log` printed its
  records twice; on the fuse backend a brand-new directory read as
  `replaced-dir` and its marker files could reach the tree on commit. 92
  assertions across seven suites, both backends.
