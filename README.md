# OVERLORD

An agent hypervisor — the trust kernel for delegated computing.

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
overlord run --trace -t /srv/app -- <cmd>            # + syscall flight recorder
overlord shell -t /srv/app                           # interactive transactional shell

overlord sessions                # pending/committed history with command provenance
overlord diff <session>          # added / modified / deleted / replaced-dir
overlord log <session>           # per-change sha256 before -> after, syscall count
overlord commit <session>        # verify no external drift, replay onto real tree
overlord commit --force <sess>   # commit despite drift (explicit override)
overlord rollback <session>      # discard — target byte-identical
overlord doctor                  # backend / dependency diagnostics
```

The wrapped command sees a fully writable tree and exits believing everything
happened. Nothing touches the real tree until `commit`. Commit re-verifies the
snapshot fingerprints (size + mtime_ns of every file) and **refuses to clobber
external changes** made while the session was pending.

## Backends

| | containment | privileges |
|---|---|---|
| **kernel** | full — overlay is mounted over the target's own path inside a private mount namespace, so absolute-path writes into the target are contained | needs userns capability grants; on Ubuntu 24.04+ the shipped AppArmor profile provides exactly this, scoped to the overlord binary only |
| **fuse** | cooperative — command runs with cwd inside the overlay; absolute-path writes to the real target are **not** intercepted | none |

Auto-detected, kernel preferred. `overlord doctor` shows what's active.

**Containment scope (both backends):** the transactional guarantee covers the
target tree. OVERLORD v0 is not a jail — the command can still write elsewhere
on the filesystem. Full isolation (pivot_root, network scoping) is the
capability-manifest milestone.

## Provenance

Every session records `provenance.jsonl` — one record per change with sha256
before (lower) and after (upper), which survives commit. With `--trace`, a
syscall-level record (`syscalls.jsonl`: exec, file mutation, connect, per pid,
timestamped) is captured via strace. `packaging/ebpf/provenance.bt` is the
experimental bpftrace equivalent — lower overhead, unfakeable by the traced
process, root-only, not yet wired into the CLI.

## Test

```bash
bash test/smoke.sh
```

E2E assertions: isolation, diff completeness, provenance hashes, byte-identical
rollback, exact-replay commit, commit finality, conflict refusal + `--force`,
create-collision refusal, shell, syscall trace, absolute-path containment.
Trace and containment tests self-skip on hosts without strace / userns grants.

## Roadmap

- capability manifests: scoped grants (paths, egress, budget) enforced at run
- pivot_root jail + network namespace scoping for the kernel backend
- eBPF provenance wired into `--trace` (bpftrace script exists, unwired)
- arbitration: session locks per target, queueing for contending agents
- merge-on-commit (three-way) instead of refuse-on-drift

## Status

- 2026-09-01 — repo created; thesis.
- 2026-09-01 — v0: transactional run/diff/commit/rollback, dual backend, e2e suite.
- 2026-09-01 — v0.1: conflict detection, provenance flight recorder (hashes +
  strace), interactive shell, kernel-backend overmount containment, AppArmor
  packaging, installer.
