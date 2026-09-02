# WARDEN

**Working name.** An agent hypervisor — the trust kernel for delegated computing.

## Thesis

Computing is transitioning to a new operator: machine agents. The OS has no native
concept of a machine actor. Every agent today runs with its principal's full authority
on infrastructure that cannot distinguish the principal's intent from the agent's
behavior. Every harness vendor duct-tapes around this independently and badly.

WARDEN is the missing layer between the agent harness and the operating system.
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

## Shape

A Linux-level daemon + library that wraps any agent process, from any vendor:

- OverlayFS / CoW snapshots → reversibility
- eBPF syscall capture → provenance
- Capability manifest format → grants
- Wrap-and-run CLI → adoption path (`warden run -- <any agent command>`)

## Status

2026-09-01 — repo created. Nothing exists yet but the thesis.
