# guardian — Umanitek Agent Guardian (plugin dev doc)

Graph-driven agent security for Hermes. Guardian syncs a threat ruleset from the
local OriginTrail **DKG** node and matches every tool call and model request
against it. This is the plugin-level architecture/dev doc; the product README is
at the repo root.

## Design principles

- **The graph is the only source of truth.** There are no hardcoded threat
  rules that act as truth. The client syncs curated threats from the public
  context graph (verifiable-memory) merged with the node's local graph
  (shared-working-memory). On an empty graph, Guardian detects nothing until
  synced — by design. New candidate threats enter via `guardian report` and the
  curator's `guardian curate import`, never via client heuristics.
- **Deterministic HTTP pushes.** Every write to the DKG is a plain HTTP call
  from plugin code — never LLM/MCP-driven.
- **Fail-open everywhere.** A Guardian error must never break the agent loop.
  Every hook, every network call, every file op is wrapped and degrades to a
  no-op.
- **Audit by default.** Blocking is opt-in (`mode: block`).

## Module map

| module | responsibility |
|--------|----------------|
| `constants.py` | ontology IRIs, defaults, `$GUARDIAN_HOME` resolution, severity ladder |
| `config.py` | `GuardianConfig` from `plugins.entries.guardian.*` + env overrides |
| `quads.py` | **DRY core** — identifier builders, arg-shape normalization, install parsing, N-Triples escaping, threat/report quad builders |
| `detection.py` | pure matcher over a `Ruleset` — injection / escalation (tool **and** shape) / dependency; `Finding` |
| `ruleset.py` | graph-synced rule cache (`ruleset.json` + file lock + TTL, lazy background refresh) |
| `dkg_client.py` | stdlib `urllib` client for the DKG v10 HTTP API |
| `audit.py` | redaction, bounded JSONL logs, private WM audit KA, daily report rate limiter |
| `hooks.py` | the five hook handlers (all fail-open) + `guardian_block_message` |
| `cli.py` | `hermes guardian {status,sync,report,setup-graph,curate,dashboard}` |
| `dashboard/` | tiny loopback FastAPI app + single-page UI |

`$GUARDIAN_HOME` defaults to `$HERMES_HOME/guardian` and holds `ruleset.json`,
`ruleset.lock`, `audit.jsonl`, `findings.jsonl`, and rate/reject state files.

## Threat model & identifiers

Three categories, deterministic string identifiers (so independent nodes
converge on the same Threat KA):

- Dependency — `dep:{ecosystem}:{name}@{version}`
- Injection — `injection:{sha256(pattern)[:24]}`
- Escalation — `escalation:{tool}:{argShape}`

Curated threat subject URI: `urn:guardian:threat:{slug(identifier)}`.
Report/sighting subject URI (per-submitter, first-writer-wins safe):
`urn:guardian:report:{agentAddressLower}:{sha256(identifier)[:16]}`.

Reports **never** carry observed prompt/command text — that privacy-sensitive
evidence stays in the node's private WM audit KA.

## Configuration

`config.yaml` → `plugins.entries.guardian.*`; every key has an env override
(env wins).

| key | default | env |
|-----|---------|-----|
| `mode` | `audit` | `GUARDIAN_MODE` |
| `context_graph_id` | `umanitek/guardian-threats` | `GUARDIAN_CONTEXT_GRAPH_ID` |
| `dkg_url` | `http://127.0.0.1:9200` | `DKG_DAEMON_URL` |
| `sync_interval` | `300` | `GUARDIAN_SYNC_INTERVAL` |
| `report` | `true` | `GUARDIAN_REPORT` |
| `daily_report_limit` | `500` | `GUARDIAN_DAILY_REPORT_LIMIT` |
| `block_severity` | `critical` | `GUARDIAN_BLOCK_SEVERITY` |
| `dashboard_port` | `9700` | `GUARDIAN_DASHBOARD_PORT` |

Enable with `hermes plugins enable guardian`.

## CLI

```
hermes guardian status                 # config, node reachability, ruleset + findings counts
hermes guardian sync                   # force a ruleset refresh
hermes guardian report --type ...      # submit a NEW candidate threat to SWM
hermes guardian setup-graph            # curator: create + register the public CG (accessPolicy 0, publishPolicy 0)
hermes guardian curate list --pending  # candidate threats grouped by distinct reporters
hermes guardian curate show <id>       # one threat + its reporters
hermes guardian curate approve <id>    # promote to curated threat (share + vm/publish)
hermes guardian curate reject <id>     # reject locally (+ optional SWM false-positive)
hermes guardian curate import --file … # bulk import a catalog (OSV enrichment for deps)
hermes guardian dashboard [--port]     # start the loopback dashboard
```

## Dependencies

Standard library only, plus **fastapi/uvicorn** (already provided by the hermes
`[web]` extra) for the optional dashboard. No new PyPI dependencies.
