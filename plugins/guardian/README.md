# guardian — Umanitek Agent Guardian (plugin dev doc)

Graph-driven agent security for Hermes. Guardian syncs a threat ruleset from the
local OriginTrail **DKG** node and matches every tool call and model request
against it. This is the plugin-level architecture/dev doc; the product README is
at the repo root.

## Design principles

- **Three-tier trust model.** The **public** context graph (verifiable-memory),
  curated by Umanitek, is the source of truth: a public match is
  `confirmed=true`, `source="public"`, and blockable in block mode. When the
  public graph doesn't cover an identifier, the **community** pool
  (shared-working-memory) is checked: a community match flags
  (`confirmed=false`, `source="community"`) and is re-reported to strengthen
  consensus, but **never** blocks. Built-in **heuristics** only nominate NEW
  candidates (`source="heuristic"`), flagged/reported only when severity ≥
  `report_min_severity`. Public wins any identifier collision. On an empty
  graph nothing can block — high-severity heuristic candidates are still
  flagged and reported for curators to promote.
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
| `config.py` | `GuardianConfig` from `plugins.entries.guardian.*` + env overrides; per-category detection policy + `protected_paths` |
| `settings.py` | read/write the user-tunable detection policy (dashboard gear page); validated persistence back to `plugins.entries.guardian.*` |
| `quads.py` | **DRY core** — identifier builders, arg-shape normalization, install parsing, N-Triples escaping, threat/report quad builders |
| `detection.py` | pure matcher over a `Ruleset` — injection / escalation (tool **and** shape) / dependency / fileaccess / skill; `Finding`; `detect_custom_fileaccess` (user `protected_paths`, `source="custom"`) |
| `ruleset.py` | graph-synced rule cache (`ruleset.json` + file lock + TTL, lazy background refresh) |
| `dkg_client.py` | stdlib `urllib` client for the DKG v10 HTTP API |
| `audit.py` | redaction, bounded JSONL logs, private WM audit KA, daily report rate limiter + 6h per-identifier report cooldown (`REPORT_COOLDOWN_SECS`) |
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
| `daily_report_limit` | `9999` | `GUARDIAN_DAILY_REPORT_LIMIT` |
| `report_min_severity` | `high` | `GUARDIAN_REPORT_MIN_SEVERITY` |
| `block_severity` | `critical` | `GUARDIAN_BLOCK_SEVERITY` |
| `dashboard_port` | `9700` | `GUARDIAN_DASHBOARD_PORT` |
| `discover` | `true` | `GUARDIAN_DISCOVER` |
| `osv_lookup` | `true` | `GUARDIAN_OSV_LOOKUP` |
| `auto_attach` | `true` | `GUARDIAN_AUTO_ATTACH` |

`auto_attach` re-runs the `guardian attach` sweep in the background on session
start (at most once per 24h), so Hermes homes and OpenClaw workspaces installed
*after* Guardian get protected without any manual step.

Enable with `hermes plugins enable guardian`.

### Detection policy (user-tunable)

Two more subtrees under `plugins.entries.guardian.*` let a user tune *what*
gets flagged. No env override — these are edited via the dashboard gear page
(`settings.py` / `/api/settings`) or by hand:

| key | type | default | meaning |
|-----|------|---------|---------|
| `detection.<category>.enabled` | bool | `true` | turn a whole category on/off |
| `detection.<category>.min_severity` | severity | `info` | drop findings in that category below this level |
| `protected_paths` | `[glob, …]` | `[]` | user file/folder patterns; a match is a `source="custom"` critical finding |

`<category>` is one of the five in `DETECTION_CATEGORIES`
(`injection`, `escalation`, `dependency`, `fileaccess`, `skill`); severities are
the ladder `info < low < medium < high < critical`. Any category absent from
`detection` defaults to enabled at `info` (flag everything the graph knows).
Example — only critical dependency vulns, skills off, `~/.ssh` protected:

```yaml
plugins:
  entries:
    guardian:
      detection:
        dependency: { enabled: true, min_severity: critical }
        skill:      { enabled: false }
      protected_paths:
        - "~/.ssh/*"
        - "**/.env"
```

`config.py` exposes this policy via `GuardianConfig.category_setting(cat)` →
`{enabled, min_severity}` and `GuardianConfig.category_allows(cat, severity)`.
`hooks._flag_worthy` applies the per-category policy first (disabled category or
below-`min_severity` findings are dropped) before the heuristic gate.

**The `custom` finding source.** `detect_custom_fileaccess(tool_name, args,
protected_paths)` matches a file-tool path against the user's `protected_paths`
— glob on the full path, glob on the basename, or a directory-prefix for
glob-free patterns (`~` expanded) — and returns a `source="custom"`,
`severity="critical"` fileaccess `Finding`. Custom findings are the user's own
rule, so they behave differently from graph/heuristic findings:

- they **bypass** the per-category policy (`_flag_worthy` never drops a
  `source=="custom"` finding),
- they **always flag** and **block in block mode** for confirmed *or* custom
  findings ≥ `block_severity`, and
- they are **never** shared to the community pool — `_report_and_audit` skips
  SWM/private-KA for `source=="custom"` and audits locally only.

### Settings API

The loopback dashboard exposes the policy over HTTP (same `127.0.0.1` bind as
the rest of the dashboard):

- `GET /api/settings` → `read_settings()`: the full, defaulted view — `mode`,
  `block_severity`, `report`, `report_min_severity`, `discover`, `osv_lookup`,
  `categories` (`{cat: {enabled, min_severity}}`), `protected_paths`,
  `severity_order`, and `category_labels`.
- `POST /api/settings` (JSON body) → `write_settings(payload)` →
  `{ok, errors, settings}`; HTTP `400` when `ok` is false. Only known keys with
  valid values are written; `detection` is deep-merged per category and all
  unrelated config is preserved.

## CLI

```
hermes guardian status                 # config, node reachability, ruleset + findings counts
hermes guardian sync                   # force a ruleset refresh
hermes guardian report --type ...      # submit a NEW candidate threat to SWM
                                       #   (injection|escalation|dependency|fileaccess|skill)
hermes guardian setup-graph            # curator: create + register the public CG (accessPolicy 0, publishPolicy 0)
hermes guardian curate list --pending  # candidate threats grouped by distinct reporters
hermes guardian curate show <id>       # one threat + its reporters
hermes guardian curate approve <id>    # promote to curated threat, any of the five
                                       #   categories (share + vm/publish)
hermes guardian curate reject <id>     # reject locally (+ optional SWM false-positive)
hermes guardian curate import --file … # bulk import a catalog (OSV enrichment for deps)
hermes guardian dashboard [--port]     # start the loopback dashboard
```

## Dependencies

Standard library only, plus **fastapi/uvicorn** (already provided by the hermes
`[web]` extra) for the optional dashboard. No new PyPI dependencies.
