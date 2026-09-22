# Integrating OVERLORD

Three ways in, from zero-effort to embedded.

## 0. The workspace (no integration, for people)

For someone who just wants to use it, not wire it in:

```bash
overlord ui        # open http://127.0.0.1:7777
```

A chat window. Set the model provider, API key and working folder in
Settings, then talk to the agent. Every conversation is a transaction on a
sandboxed copy of the folder; the panel on the right shows what changed;
nothing touches the real folder until Commit. The console (the document of
record, with savepoints, forks, blame and the countersignature) is one click
away at `/console`. The model runs in-process, so this is the whole product —
no daemon, no build.

## 1. Wrap any agent CLI (zero integration)

Any agent binary, any vendor, unmodified:

```bash
overlord run --jail --net none --timeout 600 -t ~/projects/app -- \
    claude -p "refactor the auth module"

overlord diff <session>      # what it did
overlord log  <session>      # hashes before -> after
overlord savepoints <session>  # one per command that wrote; rewind --to N
overlord commit <session>    # or rollback; --drop / --only select savepoints
```

The agent believes it edited the project. Nothing is real until you commit.

## 1b. Watch it happen (web UI)

```bash
overlord ui    # http://127.0.0.1:7777
```

Mission control: every pending session, its diff, and commit/rollback buttons.
Point it at a fleet of agents and it becomes the review console.

## 2. Python SDK (embed in a harness)

Run the broker once (`overlord daemon`, or the systemd unit in packaging/),
then from any Python harness:

```python
import sys; sys.path.insert(0, "/usr/local/lib/overlord")
from overlord_client import OverlordClient

ov = OverlordClient()
session = ov.run(
    "/srv/app",
    ["some-agent", "--task", "upgrade deps"],
    jail=True, net="none", timeout=600,
)
print(session.output_tail)
for kind, path in session.changes:
    print(f"{kind:10s} {path}")

if session.exit_code == 0:
    session.commit()          # raises OverlordError if the tree drifted
else:
    session.rollback()
```

### Choosing and configuring the model

```python
s = ov.agent("/srv/app", "add a Makefile", jail=True, net="none",
             provider="openai-compatible", model="llama3",
             base_url="http://127.0.0.1:11434/v1",            # a local server or a gateway
             headers={"X-Org": "team-a"},
             config={"max_tokens": 8000, "effort": "high", "stop": ["END"]})
for m in ov.models("anthropic"):                              # what the endpoint serves
    print(m["id"], m["context"])
```

Providers: `anthropic`, `openai`, `azure` (deployment as `model`, plus
`azure_api_version`), `openai-compatible`, `gemini`. Config keys: `max_tokens`,
`temperature`, `top_p`, `stop`, `effort`, `thinking`, `system_extra`, `stream`,
`fallbacks`; a blank knob is not sent, so a model that rejects it never sees it.
`on_event` receives `assistant_delta` events while text streams.

### Connectors from the SDK

```python
s = ov.agent("/srv/app", "open a PR for this change", jail=True, net="none",
             connectors=["github"],            # must be allowed by policy "connectors"
             connector_approval="ask",         # a brokered run has no terminal…
             approve_all=True)                 # …so say yes for this run explicitly
```

Policy: `"connectors": ["github", "docs"]` (or `"*"`) on a target rule lists
what a brokered session may be granted; without a rule the daemon grants
none. Every connector call is an event on the stream and a line in the
transcript; the reviewer sees them under EXTERNAL ACTIONS.

### Memory

Put an `OVERLORD.md` at the root of a folder and every agent session there is
told what it says (capped). Sessions that commit are journaled per folder and
the next session is told about them. A note the agent proposes about the
person arrives as a `memory_suggestion` event and is kept only when someone
accepts it (`overlord memory accept <sid> --id <id>`).

### Single sign-on

Register `https://<host>/auth/callback` as the redirect URI at your
provider, then `overlord sso set --issuer <issuer> --client-id <id>
--client-secret-stdin --domain <your domain> --admin <you>`. Roles can
follow a groups claim (`--role-claim groups --role-map ops=admin`). The
provider must be https; `overlord sso test` fetches its discovery document.

### Moving work between machines

`overlord export <sid>` on one machine, `overlord import file.ovl -t
<folder> --require-signature --key their.key` on another: the changes
arrive as a new pending session to review and commit there. Share
`overlord bundle key` out of band.

### Scripts against the web API

With accounts on, a script authenticates to `overlord ui` with a bearer
token: `overlord users token <name> --name ci` prints it once; send
`Authorization: Bearer ovl_…`. The token carries that account's role, so a
CI job that should only read gets a viewer's token. `GET /api/me` says who
the server thinks you are.

### Skills

Ship know-how with the code: a `.overlord/skills/<name>/SKILL.md` in the
repository is offered to every conversation in that folder and versioned
with it. Machine-wide skills come from `overlord skills add`; a policy rule
`"skills": ["python-testing"]` limits what a folder's sessions may load.

### Budgets, the ledger and the audit log

A policy rule may carry `"budget": {"session_tokens": N, "session_usd": X}`;
the daemon's agent sessions stop with reason `budget` before the call that
would run past it. `overlord cost --user <name>` reads the ledger;
`overlord audit --json` streams the machine-wide log for a SIEM, and
`overlord audit verify` (exit 1 on a break) belongs in a nightly check.

### Savepoints from the SDK

Every `exec` that writes seals a layer; `savepoints()` lists them, `rewind(n)`
drops everything above one (on a live session between commands, or on a
pending one), `commit(only=..., drop=...)` replays a selection, and
`blame(path)` answers who put each line there:

```python
live = ov.open("/srv/app", jail=True, net="none")
live.exec(["bash", "-c", "echo a > a.txt"])            # savepoint @0
live.exec(["bash", "-c", "rm a.txt; echo b > b.txt"])  # savepoint @1
live.rewind(0)                                          # a.txt is back
session = live.close()
session.commit(drop="layer:0")                          # or only="turn:2-4", "tool:write_file"

for line in ov.blame("/srv/app/b.txt")["lines"]:
    print(line["n"], line["owner"], line["text"])   # owner: version index, "origin" or "drift"

# an agent session: rewind to a thought, tell it what you want, let it go on
s = ov.agent("/srv/app", "add a Makefile with a test target", jail=True, net="none")
ov.rewind(s.sid, 1)
s = ov.resume(s.sid, note="use pytest, not unittest", on_event=print)
```

`resume` streams the same transcript events as `agent`; the session keeps its
id, and its `transcript.jsonl` carries a `rewind` and a `resume` event where the
history was cut and picked up.

### Countersignature and forks from the SDK

```python
s = ov.agent("/srv/app", "add a Makefile with a test target", jail=True, net="none")
rec = s.review(provider="openai")            # a model that had no part in the work
if rec["verdict"] == "approve":
    s.commit(countersigned=True)             # refuses if the diff changed since signing
else:
    print(rec["reason"], rec["paths"])

b = s.fork(at=1)                             # second continuation of savepoint @1
b = ov.resume(b.sid, note="do it with pytest instead")
for row in ov.compare(s.sid, b.sid):         # path, state (same/differ/only-a/only-b)
    print(row)
```

### Driving OVERLORD as an executor (a remediation loop, a console)

An external orchestrator that plans elsewhere and only *executes* through
OVERLORD gets four things: a step that names itself on provenance, a real
undo for a committed change, a place to put its own receipts on the
tamper-evident chain, and a model call that can only propose.

```python
ls = ov.open("/srv/app", jail=True, net="proxy",
             net_allow=["registry.example.com"], limits={"pids": 64})
rc, out, _ = ls.exec(["systemctl", "restart", "app"], timeout=30,
                     cause={"plan_id": "plan-7", "step_id": "s1", "action_id": "restart_service"})
s = ls.close()
s.commit()                                   # every path's provenance is caused_by that step

ov.audit("receipt.step", plan_id="plan-7", step_id="s1", status="ok", sid=s.sid)
head = ov.audit_head()                       # {seq, hash, keyed}: cite hash as the receipt's chain ref

r = ov.revert(s.sid)                         # verification failed: stage the inverse
ov.commit(r["sid"])                         # ...review it like any change, then commit
#   ov.revert(s.sid, commit=True)            # or land it at once; force=True skips unretained paths

plan = ov.complete("Propose steps for finding F-12 from the catalog: ...",
                   system="You only propose; output JSON.", purpose="planner")
# plan["text"], plan["prompt_sha256"], plan["output_sha256"] — audited as model.complete
```

`revert` undoes a **committed** session (added files removed, modified and
deleted files restored from retained before-content) as a **new pending
session**, so it is reviewed and committed like anything else; `rollback`
remains the pre-commit half. It restores content, not file modes, and refuses
a path whose before-content was not retained unless `force=True`. `audit`
accepts only namespaced actions (`ext.` `receipt.` `plan.` `finding.`
`approval.`) and marks them `via: daemon`; the engine's own names are
refused. `complete` runs one tool-less call through the engine's providers
and key store — a planner that cannot touch the tree by construction.

## 3. Policy-brokered fleets (the operator holds the keys)

`~/.overlord/policy.json` binds every session brokered by the daemon.
Callers can request grants; they can never obtain a looser scope than policy:

```json
{
  "default": null,
  "targets": {
    "/srv/staging":  { "jail": true, "net": "none", "timeout": 900, "allow_force": false,
                       "require_review": true },
    "/srv/scratch":  { "timeout": 3600, "allow_force": true }
  }
}
```

- `"default": null` = deny-by-default: targets not listed are refused.
- policy `jail`/`net` force containment on; `timeout` caps whatever is asked.
- `allow_force` gates `commit --force` through the daemon.
- `require_review` refuses every commit on the target without a fresh
  countersignature (`review`) bound to exactly the diff being committed.
- `connectors` lists the MCP connectors a brokered session may be granted
  (`"*"` for any); none without it.
- Edits apply immediately — policy is re-read per request.

The direct CLI is the operator's own authority and does not consult policy;
the daemon socket (0600) is what you hand to things you supervise.
