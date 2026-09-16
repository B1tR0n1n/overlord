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
- Edits apply immediately — policy is re-read per request.

The direct CLI is the operator's own authority and does not consult policy;
the daemon socket (0600) is what you hand to things you supervise.
