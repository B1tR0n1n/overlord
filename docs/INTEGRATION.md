# Integrating OVERLORD

Three ways in, from zero-effort to embedded.

## 1. Wrap any agent CLI (zero integration)

Any agent binary, any vendor, unmodified:

```bash
overlord run --jail --net none --timeout 600 -t ~/projects/app -- \
    claude -p "refactor the auth module"

overlord diff <session>      # what it did
overlord log  <session>      # hashes before -> after
overlord commit <session>    # or rollback
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

## 3. Policy-brokered fleets (the operator holds the keys)

`~/.overlord/policy.json` binds every session brokered by the daemon.
Callers can request grants; they can never obtain a looser scope than policy:

```json
{
  "default": null,
  "targets": {
    "/srv/staging":  { "jail": true, "net": "none", "timeout": 900, "allow_force": false },
    "/srv/scratch":  { "timeout": 3600, "allow_force": true }
  }
}
```

- `"default": null` = deny-by-default: targets not listed are refused.
- policy `jail`/`net` force containment on; `timeout` caps whatever is asked.
- `allow_force` gates `commit --force` through the daemon.
- Edits apply immediately — policy is re-read per request.

The direct CLI is the operator's own authority and does not consult policy;
the daemon socket (0600) is what you hand to things you supervise.
