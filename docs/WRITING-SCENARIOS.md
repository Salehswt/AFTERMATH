# Writing a scenario

A scenario is one intrusion, described in a single YAML file. Both the **attack**
and the **answer key** are generated from that one file, so they can never drift.

**The one rule:** every detection you write must return hits against the
telemetry the scenario actually produces. `attacks/validate_detections.py`
enforces this — it runs each `expected_detections` query against Elasticsearch
and **fails if any returns zero**. It runs as the last step of every install and
on demand via `./lab.sh validate-detections`. Don't write a query you haven't
seen return results.

---

## How a scenario reaches the user

Nothing special is needed to "install" a scenario — dropping the file in
`scenarios/` is enough:

- On `./install.sh` / `install.ps1`, **step 5** runs `seed.sh --all`, which seeds
  every scenario whose `requires:` matches the build (`linux` for the default
  Docker build, `windows` when `-WithWindowsVictim` is used), then backdates each
  by its `seed_time_offset`.
- **Step 6** runs `validate_detections.py`, so a broken answer key is caught at
  install time, not by a confused analyst.
- `SOLUTIONS.md` is regenerated from the YAML with `render_solutions.py`.

Linux/web scenarios seed from the **attacker container**; Windows scenarios seed
**on the VM** via Atomic Red Team (`seed-windows.ps1`).

---

## Anatomy of the YAML

Copy `scenarios/scenario_template.yml` and fill it in:

```yaml
id: scenario_NN_short          # must be unique; match the filename
name: "Human-readable title"
difficulty: easy               # easy | medium | hard
requires: linux                # linux (default build) | windows (needs the VM)
backstory: >                   # the ticket the analyst reads — NO spoilers
  What the analyst is told happened.
seed_time_offset: "-3d"        # shift events back so the timeline matches the ticket

chain:                         # ordered ATT&CK steps the seeder runs
  - technique: T1190           # a real ATT&CK ID (validated to be well-formed)
    action: web_sqli           # OPTIONAL: a named runner action; overrides
                               #   `technique` for lookup, so several scenarios
                               #   can reuse one ATT&CK ID with different behaviour
    test: 1                    # atomic test number (Windows) / ignored (Linux emulation)
    note: "what this step does"

expected_detections:           # the 'how to catch it' half of SOLUTIONS.md
  - source: modsecurity
    event_id: alert
    index: "lab-edge-modsecurity-*"   # which ES index/data view to search
    description: "what this detection means"
    query: 'event.module:"modsecurity" AND source.ip:"172.30.0.100"'  # Lucene

iocs:
  - { type: ip, value: "172.30.0.100" }

answer_summary: >
  One-paragraph IR-report writeup of the whole chain.
```

---

## The workflow

### 1. Implement the attack (if it's new)

The seeder runs real actions, not synthetic logs. If your chain uses a technique
the runner doesn't implement yet, add a function to `attacks/runner.py` and
register it in `ACTIONS{}`:

```python
def t1234_mything(victim):
    """One line on what it does and what telemetry it produces."""
    return sh(["curl", "-s", "-o", "/dev/null", "http://proxy:81/some/attack"])

ACTIONS = {
    ...
    "T1234.001": t1234_mything,     # keyed by ATT&CK ID, or
    "my_action":  t1234_mything,    # a named action (selected via `action:`)
}
```

Rules of the road for actions:
- Reuse the helpers: `sh([...])` runs a command (non-zero exit is fine — what
  matters is the traffic was sent), `_web([paths])` fires web requests at the
  DVWA edge, `SSH_OPTS`, `C2`, `time.sleep`.
- **An unimplemented technique exits 2** — a seeder that reports success while
  generating nothing is worse than one that fails.

### 2. Fire it and look at what actually lands

This is the step people skip, and it's why answer keys drift. Fire the action,
then look at the real telemetry before writing a single query:

```powershell
$CF = @('-f','docker-compose.yml','-f','docker-compose.linux-victim.yml')
# fire one technique live
docker compose @CF exec -T attacker python3 /attacks/runner.py T1234.001 1 172.30.0.50
# then inspect Elasticsearch — what fields/values did it produce?
```

Query ES (or use Kibana Discover) and find the fields that uniquely identify
*your* activity: a process name, a URL substring, a registry path, an auth
message. Write your `query` to match **those observed values**, not what you
assume they'll be.

### 3. Write the detections

Each `expected_detections` entry needs an `index` and a Lucene `query`. Keep them
specific enough to be about *this* scenario, general enough to survive re-seeds.

### 4. Validate the YAML, then the detections

```bash
./lab.sh validate scenarios/scenario_NN.yml   # required keys, well-formed ATT&CK ids
./lab.sh attack scenario_NN                    # seed it live
./lab.sh validate-detections                   # THE gate: every query must return > 0
python3 scripts/render_solutions.py            # regenerate SOLUTIONS.md
```

If `validate-detections` reports `[FAIL] 0`, your query doesn't match the
telemetry. Go back to step 2 — look at what actually landed and fix the query
(or the action).

---

## Query cookbook — the gotchas that bit us

Queries are **Lucene / `query_string`** (they read fine as KQL too; in Discover,
switch the search bar to Lucene).

- **No `/` in a wildcard.** `message:*bin/su*` throws a lexical error. The message
  field is analyzed into tokens, so match the token instead: `message:"su root"`
  or `message:bash_history`.
- **`host.name` is lowercase.** The agents report `wkstn-lnx` and `wkstn-01`, not
  `WKSTN-LNX`. This was a real bug in an early answer key.
- **WAF `source.ip` is the proxy, not the attacker.** The real client is pulled
  from `X-Forwarded-For` into `source.ip` by Logstash — so
  `source.ip:"172.30.0.100"` works on `lab-edge-modsecurity-*`.
- **The WAF only logs blocked/relevant requests** (`SecAuditEngine RelevantOnly`),
  so plain probes that return 200/404 won't appear in `lab-edge-modsecurity-*` —
  use the edge Suricata (`lab-edge-suricata-*`) for those.
- **Ground, don't guess.** Scenario 01 originally shipped
  `process.parent.name:"WINWORD.EXE"` — which the atomics never produce, so it
  returned zero. Always confirm against real data.

### Where telemetry lands

| Source | Index / data view | Useful fields |
|---|---|---|
| Elastic Agent (auth.log, sudo) | `logs-system.auth-*` | `system.auth.ssh.event`, `process.name:"sudo"`, `message` |
| Elastic Agent (Windows) | `logs-windows.sysmon_operational-*`, `logs-windows.powershell_operational-*` | `winlog.event_id`, `process.name`, `registry.path`, `file.name` |
| Suricata (2 sensors) | `lab-edge-suricata-*` | `event.kind:"alert"`, `source.ip`, `destination.ip` |
| ModSecurity (both WAFs) | `lab-edge-modsecurity-*` | `event.module:"modsecurity"`, `source.ip` (from XFF), `url.original` |

---

## Linux vs Windows scenarios

- **Linux / web (`requires: linux`)** — seeded from the attacker container by
  `runner.py`. You can build and validate them on the default Docker build with
  no VM. This is where most scenarios should live.
- **Windows (`requires: windows`)** — the chain's `technique`/`test` pairs are run
  **on the VM by Atomic Red Team** (`seed-windows.ps1` → `Invoke-AtomicTest`).
  You need `-WithWindowsVictim` up to seed and validate them. Ground the
  detections in the *stable* artifacts a given atomic produces (a fixed tool name,
  dump file or registry path), not in run-specific values, or they won't
  reproduce.

---

## Checklist before you commit

- [ ] `id` matches the filename and is unique
- [ ] `requires:` is correct for where the attack runs
- [ ] every chain technique is implemented in `ACTIONS{}` (or seeding exits 2)
- [ ] you **fired it and looked at the real telemetry** before writing queries
- [ ] every `expected_detections` entry has an `index` and a `query`
- [ ] `./lab.sh validate-detections` is green (0 failed)
- [ ] `SOLUTIONS.md` regenerated
- [ ] added the ticket to `SCENARIOS.md` (and, optionally, a saved search /
      detection rule + re-export the `dashboards/*.ndjson`)
