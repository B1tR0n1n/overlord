# OVERLORD

An agent hypervisor — the trust kernel for delegated computing.

![OVERLORD demo: rm -rf inside a transactional shell, then rollback — everything comes back](assets/demo.gif)

Hand a program — or an AI agent — a fully writable copy of a directory. Let it
run. Then review every change it made as a hashed, attributed manifest and
**commit or roll back**, all or nothing. Transactional isolation, provenance,
and arbitration for untrusted execution — in dependency-free Python, on the
kernel's own primitives. It ships with a built-in agent (`overlord agent`) that
runs a model with its hands jailed, so you can watch the whole loop happen
inside the transaction and sign off on the diff. For people who just want to
use it, `overlord ui` opens a chat workspace where you talk to that agent and
press Commit when you like what it did — nothing on disk changes until you do.

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
overlord agent --provider openai-compatible --base-url http://127.0.0.1:11434/v1 \
               --model llama3 -t /srv/app "<task>"   # a local model, same jail
overlord agent --effort xhigh --max-tokens 64000 -t /srv/app "<task>"   # generation knobs
overlord models --provider anthropic                 # what the endpoint serves right now
overlord mcp add github --command npx --arg -y --arg @modelcontextprotocol/server-github \
                 --env GITHUB_TOKEN=…                # register an MCP connector (stdio)
overlord mcp add docs --url https://host/mcp --header 'Authorization: Bearer …'   # (http)
overlord agent --connector github -t /srv/app "<task>"   # grant it; actions ask you first
overlord memory show -t /srv/app                     # what the agent is told before message one
overlord memory user --add "Prefers pytest."         # a note about you, across every folder
overlord memory accept <session> --all               # keep the notes an agent proposed
overlord users add alice --role admin                # accounts: the UI now asks who you are
overlord tls selfsign --host overlord.lan            # a certificate for --bind
overlord sso set --issuer https://login.example.com --client-id … --client-secret-stdin \
    --domain example.com --admin alice@example.com   # OpenID Connect; accounts provisioned on sign-in
overlord ui --bind 0.0.0.0 --tls-cert ~/.overlord/tls/cert.pem --tls-key ~/.overlord/tls/key.pem
overlord skills add skills/python-testing            # packaged know-how, loaded when it fits
overlord skills new release -t /srv/app              # a project skill: part of the tree, reviewed like code
overlord webhooks add team https://hooks.slack.com/… # tell the channel when work waits for a person
overlord cost                                        # what the models spent, by model / account / day
overlord cost budget --day-usd 20                    # a line no conversation crosses
overlord audit verify                                # the hash chain of every consequential act
overlord gc --dry-run                                # what retention would prune

overlord sessions                # pending/committed history with command provenance
overlord diff <session>          # added / modified / deleted / replaced-dir
overlord log <session>           # per-change sha256 before -> after, syscall count
overlord savepoints <session>    # the layer stack: one savepoint per command that wrote
overlord rewind <session> --to 3 # discard everything above savepoint @3
overlord resume <session> --note "..."   # agent carries on from there, reading the note
overlord fork <session> --at 3   # a second continuation of the same moment, as a new session
overlord compare <sess-a> <sess-b>   # where two continuations diverge, per path
overlord review <session> --provider openai   # a second model countersigns the diff
overlord commit <session>        # verify no external drift, replay onto real tree
overlord commit --countersigned <sess>       # ...only with a fresh approval on record
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

## Models

The model thinks on your machine; only its hands are jailed. Every way to
reach one is in `providers.py`, stdlib only, behind one contract, and the
workspace, the CLI, the daemon and the SDK all share it:

| provider | reaches | auth |
|---|---|---|
| `anthropic` | Claude, native Messages API: streaming, adaptive thinking, `effort`, refusal handling, opt-in server-side refusal fallbacks | `ANTHROPIC_API_KEY` or the key store |
| `openai` | OpenAI Chat Completions: streaming, `reasoning_effort` | `OPENAI_API_KEY` |
| `azure` | Azure OpenAI deployments (`--base-url https://<resource>.openai.azure.com`, deployment as the model, `--azure-api-version`) | `AZURE_OPENAI_API_KEY` |
| `openai-compatible` | anything speaking the Chat Completions shape behind a base URL: Ollama, vLLM, LiteLLM, Groq, Together, your gateway | optional |
| `gemini` | Google Gemini REST: streaming, function calling | `GEMINI_API_KEY` |

Every provider takes a **base URL** and **extra headers**, which is how a
proxy or an enterprise gateway sits in front of it. `overlord models` lists
what an endpoint serves right now, and the workspace's Settings shows the same
list. Keys live in `~/.overlord/keys.json` (mode 600); environment variables
win over the store.

**Generation knobs** — `--max-tokens`, `--temperature`, `--top-p`, `--stop`,
`--effort low|medium|high|xhigh|max`, `--thinking summarized|off`,
`--system` (appended instructions), `--no-stream`, `--no-fallbacks` — are
model-aware: nothing is sent unless you set it. That matters because the
current Claude family rejects `temperature` and `top_p` outright and takes
its depth from `effort`; blank means the model's own default. Replies stream
as they are generated (the CLI prints them live; the workspace renders them
into the bubble), tool inputs that stream in are parsed strictly and handed
back as an error rather than run when malformed, and a reply cut off at
`max_tokens` or declined by a safety classifier never executes its tool
calls. The knobs and the endpoint a conversation ran with are recorded on
the session, so `resume` uses the same model the same way.

## Connectors (MCP)

`mcp.py` is a Model Context Protocol client, stdlib only: stdio servers
(a command) and streamable-HTTP servers (a URL), configured in
`~/.overlord/mcp.json`. Their tools are offered to the model next to the
built-ins, namespaced `mcp__<server>__<tool>`, and a call is routed back to
the server that owns it.

Connectors are different from everything else here, and the design says so:

- **They run on the host, outside the jail and outside the transaction.** A
  connector that sends an email has sent it; Discard cannot unsend it. So a
  session must be *granted* each connector by name (`--connector`, or the
  checkboxes on a new conversation), policy can list the connectors a
  brokered session may have (`"connectors": ["github"]` or `"*"`), and every
  call is written to the transcript with the server that served it and shown
  to the countersigning reviewer as an **external action**.
- **Actions ask first.** A tool declares itself read-only through MCP's
  `readOnlyHint`; anything else goes through the approval gate. In `ask` mode
  (the default) the run pauses: the CLI prompts on the terminal, the
  workspace shows an approval card with the exact input, a brokered run with
  no one to ask is denied. `auto` allows, `readonly` refuses every action.
  Each decision is recorded in the transcript.
- A stdio server gets only the environment you configure for it plus PATH,
  HOME and LANG, never the whole process environment, so one connector's
  token is not another's. `overlord mcp test <name>` connects and lists its
  tools with their read-only status.

## Memory

What the agent knows before your first message, and how that is allowed to
change (`memory.py`). Three sources, all injected into the system prompt,
all capped, and the session records what the model was told:

- **Project notes** — `OVERLORD.md` at the root of the working folder:
  conventions, commands, things learned about this codebase. The agent may
  extend it with the `remember` tool, **inside the transaction**: the note is
  a file change in the diff with a savepoint and a cause, committed or
  discarded with everything else. Memory is a file the person reviews.
- **Your notes** — `~/.overlord/memory.md`, about you and your preferences,
  across every folder. The agent cannot write it. `remember` with scope
  `user` only *proposes* a note; you accept it (a Save button in the
  workspace, `overlord memory accept` on the CLI) and the acceptance is
  recorded in that session's transcript.
- **The journal** — one line per committed agent session in a folder: the
  task, what the model said it did, which files changed. Derived from the
  engine's own records at commit time, never written by the model, so
  "recent work in this folder" is always true. Rolled-back sessions and
  plain command sessions leave no entry.

Nothing outside a transaction changes without a human hand, which is the
same rule as everywhere else in OVERLORD.

## Accounts, TLS, a team on one machine

`overlord ui` binds loopback with no accounts: the person at the keyboard
is the operator, as it always was. The first `overlord users add` turns
sign-in on (`auth.py`), and from then on every request names a principal —
a login cookie (HttpOnly, SameSite=Strict, Secure under TLS) or a bearer
token for scripts (`Authorization: Bearer ovl_…`, hashed at rest,
revocable one by one, `overlord users token`). Five wrong passwords in five
minutes lock that address+name for a minute; passwords are scrypt hashes in
a mode-600 file.

Three roles, checked on every route:

| role | may |
|---|---|
| **admin** | everything: accounts, policy, connector config, every record on the machine |
| **operator** | their own conversations — start, commit, discard, rewind, fork, review — and their own settings, API keys and notes; connectors may be used, not configured |
| **viewer** | read every record, change nothing (an auditor) |

Each account has its own `~/.overlord/users/<name>/` with its `ui.json`,
`keys.json` (a key you set is yours; the machine's shared key is the
fallback an admin can provision) and `memory.md`. A session records its
`owner`; sessions opened from the CLI have none and are the admin's to see.

**Single sign-on** (`oidc.py`): OpenID Connect, authorization code with
PKCE, state and nonce. `overlord sso set` names the issuer and client;
accounts are provisioned on first sign-in when the e-mail domain is
allowed, with the role from a listed e-mail (`--admin`, `--viewer`), a
groups claim (`--role-claim groups --role-map auditors=viewer`) or the
default. SSO accounts have no password and the password form refuses
them; local accounts coexist. What the trust rests on, stated plainly:
the TLS channel to the provider's token and userinfo endpoints plus the
state / nonce / PKCE round-trip — the ID token's claims are checked, its
signature is not (no RSA in the standard library), and the same identity
is confirmed by `userinfo` directly from the provider.

Logins outlive a restart of `overlord ui` (a mode-600 file keyed by the
cookie's hash, never the cookie), and a per-address rate limit
(`--rate-limit`, 3000 requests a minute by default) answers 429 to a
runaway script.

Beyond loopback the server refuses to start without both accounts and TLS
(`--bind 0.0.0.0 --tls-cert … --tls-key …`; `overlord tls selfsign` makes a
certificate with openssl for a private deployment). A `--host name`
allowlist backs the Host check, HSTS is sent, and a plain-HTTP probe at the
TLS port is shrugged off. A workspace that can commit an agent's changes to
a real tree is not something to leave on a LAN behind a Host header.

## Skills

Packaged know-how the agent pulls in when it fits (`skills.py`). A skill is
a folder with a `SKILL.md` — front matter `name`, `description`, an optional
`when` — and any supporting files. Two homes, one rule:

- **Project skills** live in `.overlord/skills/<name>/` inside the working
  folder. They are part of the tree, so part of the transaction: an agent
  may write or improve one, and that change is a diff a person reviews,
  committed or discarded with everything else. The next conversation in
  that folder is offered it.
- **Machine skills** live in `~/.overlord/skills/<name>/`, installed by a
  person (`overlord skills add <path>`, or Settings → Skills), offered to
  every conversation, capped per folder by the policy rule
  `"skills": [...] | "*" | []`.

The model is told the catalogue — names and descriptions only — and loads a
skill with the `skill` tool when its description fits the task, so the text
is not in the prompt until it is needed. A project skill shadows a machine
skill of the same name entirely. Every load is a transcript event; the
session records what it was offered. Two examples ship in `skills/`.

## Long conversations

A conversation's message list grows with every turn; without a rule it
grows until the model refuses it. The rule: when a call has used three
quarters of the context window (a generation setting, default 128k
tokens), the agent writes a **handover note** — the task, decisions, every
file touched, what remains, what bit it — the older turns are dropped, and
the note plus the last few messages become the conversation. The cut is
itself a transcript event (`compaction`: the note, what was kept, the
tokens that triggered it), the note's call is on the ledger, and a resume
rebuilds exactly the view the model had — nothing the model was told is
lost from the record, only from its context.

## Notifications

A gate nobody is told about is a gate that stalls. Webhooks (`notify.py`)
subscribe to **audit actions** — the log is already the machine's index of
consequential acts — and two acts exist for this: `session.needs_review`,
when an agent finishes with changes waiting for a person, and
`connector.approval_requested`, when an external action waits at the
approval gate. `budget.stop`, `session.commit`, `review.verdict` and the
rest are there to subscribe to. Format `slack` posts `{"text": …}` that
Slack-compatible incoming webhooks render, with a link to the conversation
when a base URL is set; format `json` posts the audit entry with a text
line and an HMAC signature (`X-Overlord-Signature`) when a secret is set.
Delivery is off the caller's path — a background queue, three attempts
with backoff, a 4xx tried once — and a failing endpoint never fails the
work. `overlord webhooks add|list|test|rm|base-url`, or Settings →
Notifications.

## Cost

Every model call returns its token usage; OVERLORD prices it (`cost.py`),
writes one ledger line per call (`~/.overlord/ledger.jsonl`: session,
account, model, tokens, dollars) and keeps the running total on the
session, in its `done` event and in the inspector. Prices are a table in
`~/.overlord/cost.json` — a few list prices ship as defaults, yours
override them (`overlord cost set-price <model> <in> <out>`); an unpriced
model is still counted in tokens.

Budgets are lines, not estimates: `session_tokens`, `session_usd`,
`day_usd`, from the global config (`overlord cost budget`), the policy rule
for a folder (`"budget": {...}`) or the account (`overlord users budget`),
the most restrictive of each winning. A conversation is checked **before
every call** and stops with reason `budget` at the first line it has
reached — the work done so far stays in the transaction for review, the
stop is in the transcript and on the audit log. Second-model reviews are
on the ledger too.

## Audit

Sessions keep their own records; `audit.py` keeps the machine's:
`~/.overlord/audit.jsonl`, one line per consequential act — open, reopen,
commit, refused commit, rollback, rewind, fork, review verdict, connector
decision, memory acceptance, connector or policy or budget change, sign-in
and failed sign-in, account change, budget stop, gc — from the CLI, the
daemon and the web UI alike, since they share the engine. Each line carries
the hash of the line before it; `overlord audit verify` walks the chain
and names the first altered or missing line, `doctor` checks it, the
workspace shows it to admins and viewers. The actor is the signed-in
account, else the session's owner, else the OS user.

## Retention and deployment

`overlord gc` prunes finished records older than `keep_days` (default 30,
the newest `keep_last` committed kept regardless), objects no remaining
record refers to, and locks nobody holds — never a pending session, never
the audit log or the ledger. `packaging/overlord-gc.timer` runs it nightly.

To run it for a team: `packaging/overlord-ui.service` (a system unit that
serves TLS on a bind address with `--log-json`, one JSON line per request
on stderr), `/healthz` for a load balancer or container runtime (no login,
nothing an outsider learns), and a `Dockerfile` for the fuse backend
(`--device /dev/fuse --cap-add SYS_ADMIN`). `overlord doctor` reports
accounts, TLS material, the audit chain and disk usage next to the
backends.

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

- **Fork a moment.** `fork <session> --at N` copies the stack up to a
  savepoint into a new pending session on the same snapshot, transcript cut
  to match, whiteouts and all. Resume both with different notes and
  `compare a b` shows, per path, where the two continuations diverge before
  either is committed. Committing one makes the other's snapshot stale, and
  conflict detection says so.

Layers are addressed relative to the session dir (the mount data page is
4 KiB) and capped at 200 per session; past the cap the top layer keeps
absorbing writes. On the fuse backend the merged view is remounted between
commands; a lingering process that pins it makes the next savepoint coarser
rather than failing. Rewind is refused while a command is running.

## Countersignature: a two-person rule for machines

```bash
overlord review <session> --provider openai      # the agent ran on anthropic
overlord commit --countersigned <session>
```

A pending diff is put in front of a second model that had no part in making
it. The reviewer never touches the tree: it gets the task, the grant
envelope, the agent's tool-call transcript and the full diff, plus one
read-only tool (`read_file`, served from the session's own flattened view),
and its only way to act is `approve` or `reject` with a reason. The verdict
is bound to a fingerprint of exactly what was reviewed — every path's kind
and before/after hash — so a rewind, a resume or a `--drop` makes it stale.
A fresh rejection blocks `commit` unless `--force`; `--countersigned` refuses
without a fresh approval; a policy rule `"require_review": true` makes the
daemon demand it for a target. The reviewer must be a different model from
the agent (`--same-model` overrides, and the record says so). The review has
provenance of its own: `review.jsonl` is the reviewer's transcript, and every
verdict ever given stays in the session record.

## Workspace (the chat, for everyone)

```bash
overlord ui          # http://127.0.0.1:7777 — localhost only
                     #   /          the workspace (chat)
                     #   /console   the document of record
```

![OVERLORD workspace — a chat with the agent on the left and centre: the person's message, the agent's reply, and each tool call it made (read_file, write_file, shell) with its output; on the right the Transaction panel shows the working folder, the sandbox grants (sandboxed, offline), the five changed files, the three steps, and Commit / Discard / second-model-check controls](assets/workspace.png)

The friendly face: a chat window, like the assistants people already know.
**One conversation is one transaction.** The first message opens a sandboxed,
offline copy of a folder and sets the agent to work; each later message
resumes it on the same copy; the panel on the right shows the running diff.
**Nothing on disk changes until you press Commit** — so you let it run, read
what it did, and decide. Discard throws the copy away and the folder is
byte-identical.

- **Conversations** are listed on the left and selectable; each is a
  transaction you can come back to, commit, or discard.
- **Settings** holds the model provider (Anthropic, OpenAI, Azure OpenAI,
  OpenAI-compatible, Gemini), the model picked from the endpoint's live list,
  the endpoint and extra headers for a gateway, the API key (stored in
  `~/.overlord/keys.json`, mode 600, never shown again), the generation knobs,
  the working folder, and the sandbox grants. Each provider keeps its own
  profile when you switch. On the kernel backend the agent's hands are jailed
  and offline by default; the model still thinks on your machine with network,
  only its tools are confined.
- **Accounts** (when on) appear under Settings: an admin adds people and
  sets roles; everyone can change their own password and mint a script
  token. A conversation you may only read shows a read-only composer.
- **Memory** lives under Settings: your notes (editable), the folder's
  project notes, and its journal of committed work; a note the agent proposes
  about you shows in the chat with a Save button.
- **Connectors** are granted per conversation from the welcome screen and
  configured under Settings; when the agent wants to run one that acts on the
  world, the chat pauses with an Allow / Deny card showing the exact input.
- **The inspector** is the review moment made friendly: the changed files, the
  steps that made them, Commit, Discard, and a one-click second-model check
  (the countersignature). Committed sessions link back into the console.

The model runs in-process, so `overlord ui` is the whole product — no daemon,
no build step, one file of stdlib Python, loopback only, with the same origin
guard and nonce CSP as the console.

## Mission control (the console)

```bash
overlord ui          # then open /console
```

![OVERLORD mission control — a pending agent session's savepoint chain: one row per tool call that wrote, each with its paths, a keep checkbox that drops it from the commit when unticked, rewind-here and fork-here controls; below it the countersignature block (unsigned, with a request control) and the disposition; the sidebar carries the blame lookup](assets/ui.png)

The review moment for human eyes, rendered as a document of record rather than
a dashboard. The register indexes sessions; the dossier is the instrument a
human signs: the grant envelope the session ran under, a manifest of every
changed path with its before → after hashes and the tool call that caused it,
the savepoint chain (rewind or fork at any row; untick a row and the commit
drops it), the countersignature (request one, see whether it still binds),
and the disposition — commit or void. Any committed path opens its blame
sheet: every line, and the session, turn, tool call and task that put it there. Zero dependencies (stdlib http server),
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
python3 test/review_fork_test.py  # 6 countersignature / fork / compare / policy assertions
python3 test/providers_test.py    # 10 provider adapter assertions: wire shapes, streaming, knobs, listing (offline)
python3 test/mcp_test.py          # 6 connector assertions: stdio + http transports, grants, approval gate, policy, workspace
python3 test/memory_test.py       # 7 memory assertions: injection, caps, transactional remember, proposals, journal, CLI, workspace
python3 test/auth_test.py         # 7 auth assertions: open mode, sign-in + lockout, roles, ownership, tokens, TLS + Host allowlist, CLI sessions
python3 test/cost_test.py         # 6 cost assertions: prices, ledger, policy / global / account budgets, review ledger, CLI, workspace
python3 test/audit_test.py        # 5 audit assertions: chained acts, tamper detection, actors + healthz, gc, --log-json + doctor
python3 test/skills_test.py       # 6 skills assertions: catalogue + shadowing, jailed / host loads, authored in-transaction, policy, CLI, workspace
python3 test/sso_test.py          # 5 SSO assertions against a fake provider: config, PKCE round-trip, role mapping + domains, password refusal, audit
python3 test/session_test.py      # 5 long-conversation assertions: compaction + record, exact resume replay, the window setting, durable logins, rate limit
python3 test/webhook_test.py      # 5 webhook assertions against a local receiver: config, needs-review + link + signature, approval gate + budget, retries, API
python3 test/chat_test.py         # 12 workspace assertions: settings, model config, streaming, resume, commit
python3 test/ui_test.py           # 12 mission-control API + origin-guard + savepoint + blame + review assertions
python3 test/ui_browser_test.py   # 10 mission-control DOM assertions (needs playwright)
python3 test/chat_browser_test.py # 8 workspace DOM assertions (needs playwright)
```

`savepoint_test.py` and `review_fork_test.py` run on whichever backend is
live; `OVERLORD_TEST_BACKEND=fuse` forces the cooperative one, so both
stacking implementations are exercised. `chat_test.py` drives the workspace
HTTP API with the scripted provider (no network); `chat_browser_test.py`
loads the chat in Chromium and drives it as a person would.

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
- blame across renames
- countersignature by a human-in-the-loop channel (a signed approval from
  outside the machine, same fingerprint binding)

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
  `replaced-dir` and its marker files could reach the tree on commit.
- 2026-09-16 — v0.7: the two-person rule, forks, blame in the UI. `review`
  puts a pending diff before a second model (read-only `read_file`, verdict
  bound to a fingerprint of the diff; a fresh rejection blocks commit,
  `commit --countersigned` and policy `require_review` demand a fresh
  approval; reviewer must differ from the agent). `fork --at N` copies a
  stack to a savepoint as a new pending session and `compare` shows where
  two continuations diverge. Mission control gets the countersignature
  block, fork-here, and a per-line blame sheet reachable from any committed
  path. 101 assertions across eight suites, both backends.
- 2026-09-16 — v0.8: the workspace. `overlord ui` now opens a chat front door
  at `/` (the console moves to `/console`): a conversation is a transaction, the
  first message opens a sandboxed offline session and runs the built-in agent
  in-process, follow-ups resume it, and the inspector shows the live diff with
  Commit / Discard and a one-click second-model check. Conversations are listed
  and selectable; a Settings panel holds the provider, model, API key (stored
  600, never echoed), working folder and sandbox grants. Shares the console's
  loopback bind, origin guard and nonce CSP; no daemon required. Also hardened
  `save_meta` to write atomically, so a reader never sees a half-written record.
  119 assertions across ten suites, both backends.
- 2026-09-16 — v0.9: model-configuration depth. `providers.py` — Anthropic
  (streaming, adaptive thinking, effort, refusal handling, opt-in server-side
  fallbacks), OpenAI, Azure OpenAI, OpenAI-compatible (Ollama, vLLM, LiteLLM,
  gateways) and Gemini, stdlib only, every one behind a base URL with extra
  headers; live model listing (`overlord models`, `/api/models`, SDK
  `models()`); model-aware generation knobs that are never sent unless set;
  streamed replies in the CLI and the workspace; strict parsing of streamed
  tool inputs; cut-off and refusal never run tool calls; per-conversation
  provider/model with the config recorded on the session. 131 assertions
  across eleven suites.
- 2026-09-16 — v0.10: connectors. `mcp.py`, a Model Context Protocol client
  over stdio and streamable HTTP; tools namespaced into the agent's set;
  connectors are grants (per session, per conversation, capped by policy);
  non-read-only tools pass an approval gate (ask / auto / readonly) — the CLI
  prompts, the workspace shows an Allow / Deny card, a brokered run without an
  approver is denied; every call and decision in the transcript and in the
  reviewer's dossier as an external action; `overlord mcp add|list|test|rm|
  approval`. 137 assertions across twelve suites.
- 2026-09-16 — v0.11: memory. `memory.py`: project notes (OVERLORD.md in
  the folder), the person's notes (~/.overlord/memory.md) and a per-folder
  journal of committed agent sessions, injected into the system prompt with
  caps and recorded on the session; a `remember` tool whose project scope is
  a transactional, attributed file change and whose user scope only proposes
  a note a person accepts; `overlord memory show|user|journal|accept`; a
  Memory section in the workspace with proposal cards. 144 assertions across
  thirteen suites.
- 2026-09-16 — v0.12: accounts, TLS, a team on one machine. `auth.py`:
  scrypt-hashed accounts in a mode-600 file, login cookies and hashed
  bearer tokens, lockout after repeated failures, roles admin / operator /
  viewer checked on every route, per-account settings, keys and notes,
  `owner` recorded on sessions and honoured in both pages; `overlord users`
  and `overlord tls selfsign`; `overlord ui --bind/--tls-cert/--tls-key/
  --host`, refused beyond loopback without accounts and TLS; a sign-in page,
  an Accounts panel and read-only conversations in the workspace. 152
  assertions across fourteen suites.
- 2026-09-16 — v0.13: cost, audit, retention, deployment. `cost.py`: a
  price table, a per-call ledger, dollars on the session, budgets from
  policy / config / account checked before every call with a `budget`
  stop. `audit.py`: a hash-chained machine-wide log of every consequential
  act with `overlord audit verify`. `retention.py`: `overlord gc`.
  `/healthz`, `overlord ui --log-json`, systemd units for the UI and
  nightly gc, a Dockerfile, doctor rows for accounts / TLS / audit / disk.
  163 assertions across sixteen suites.
- 2026-09-16 — v0.14: skills. `skills.py`: a SKILL.md catalogue from the
  folder (`.overlord/skills/`, part of the transaction — an agent may author
  one and it is a reviewed diff) and the machine (`~/.overlord/skills/`,
  policy-capped per folder), told to the model up front and loaded on demand
  with a `skill` tool, every load on the transcript; `overlord skills
  list|show|add|new|rm`; a Skills panel; two example skills. 169 assertions
  across seventeen suites.
- 2026-09-16 — v0.15: single sign-on. `oidc.py`: OpenID Connect
  authorization code with PKCE / state / nonce, identity from userinfo,
  accounts provisioned on first sign-in with roles from an e-mail list, a
  groups claim or a default, allowed domains, SSO accounts without
  passwords; `overlord sso set|show|test|off`; a sign-in button; every
  sign-in, refusal and change audited. 174 assertions across eighteen suites.
- 2026-09-16 — v0.16: long conversations. Context compaction: at three
  quarters of a configurable window the agent writes a handover note,
  older turns are dropped, the cut is a transcript event and a resume
  replays it exactly; the note's call is on the ledger. Logins persist
  across restarts (hashed at rest); a per-address rate limit. 179
  assertions across nineteen suites.
- 2026-09-16 — v0.17: notifications. `notify.py`: webhooks subscribed to
  audit actions, slack text or signed json, links to the conversation,
  background delivery with retries; `session.needs_review` and
  `connector.approval_requested` become audited acts; `overlord webhooks`;
  a Notifications panel; `?sid=` deep links. 184 assertions across twenty
  suites.
