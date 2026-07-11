# blackbox — Agent Blackbox (plugin dev doc)

Graph-driven agent security for Hermes. Blackbox syncs a threat ruleset from the
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
  `report_min_severity`. Public wins any identifier collision. Raw curated data lives in SWM; the VM carries compact curation proofs (`curate anchor`), and a community row whose batch root matches an on-chain proof is promoted to the public tier at sync time - so one paid publish proves a whole batch instead of one KA per threat. On an empty
  graph nothing can block — high-severity heuristic candidates are still
  flagged and reported for curators to promote.
- **Deterministic HTTP pushes.** Every write to the DKG is a plain HTTP call
  from plugin code — never LLM/MCP-driven.
- **Fail-open everywhere.** A Blackbox error must never break the agent loop.
  Every hook, every network call, every file op is wrapped and degrades to a
  no-op.
- **Audit by default.** Blocking is opt-in (`mode: block`).

## Module map

| module | responsibility |
|--------|----------------|
| `constants.py` | ontology IRIs, defaults, `$BLACKBOX_HOME` resolution, severity ladder |
| `config.py` | `BlackboxConfig` from `plugins.entries.blackbox.*` + env overrides; per-category detection policy + `protected_paths` |
| `settings.py` | read/write the user-tunable detection policy (dashboard gear page); validated persistence back to `plugins.entries.blackbox.*` |
| `quads.py` | **DRY core** — identifier builders, arg-shape normalization, install parsing, N-Triples escaping, threat/report quad builders |
| `detection.py` | pure matcher over a `Ruleset` — injection / escalation (tool **and** shape) / dependency / fileaccess / skill; `Finding`; `detect_custom_fileaccess` (user `protected_paths`, `source="custom"`) |
| `ruleset.py` | graph-synced rule cache (`ruleset.json` + file lock + TTL, lazy background refresh) |
| `dkg_client.py` | stdlib `urllib` client for the DKG v10 HTTP API |
| `audit.py` | redaction, bounded JSONL logs, private WM audit KA, daily report rate limiter + 6h per-identifier report cooldown (`REPORT_COOLDOWN_SECS`) |
| `hooks.py` | the five hook handlers (all fail-open) + `blackbox_block_message` |
| `cli.py` | `hermes blackbox {status,sync,report,setup-graph,curate,dashboard}` |
| `dashboard/` | tiny loopback FastAPI app + single-page UI |

`$BLACKBOX_HOME` defaults to `$HERMES_HOME/blackbox` and holds `ruleset.json`,
`ruleset.lock`, `audit.jsonl`, `findings.jsonl`, and rate/reject state files.
The installer also creates a Blackbox-owned DKG home at
`$HERMES_HOME/blackbox/dkg`, installs a Blackbox-owned DKG CLI package under
`$HERMES_HOME/blackbox/dkg-cli`, and serves it on `http://127.0.0.1:9320`,
separate from the DKG CLI's default `~/.dkg` / `9200` node.

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

`config.yaml` → `plugins.entries.blackbox.*`; every key has an env override
(env wins).

| key | default | env |
|-----|---------|-----|
| `mode` | `audit` | `BLACKBOX_MODE` |
| `context_graph_id` | `umanitek/blackbox-threats-staging` | `BLACKBOX_CONTEXT_GRAPH_ID` |
| `dkg_url` | `http://127.0.0.1:9320` | `BLACKBOX_DKG_DAEMON_URL` / `BLACKBOX_DKG_URL` |
| `dkg_home` | `$HERMES_HOME/blackbox/dkg` | `BLACKBOX_DKG_HOME` |
| `dkg_bin` | `$HERMES_HOME/blackbox/dkg-cli/node_modules/.bin/dkg` | `BLACKBOX_DKG_BIN` |
| `sync_interval` | `60` | `BLACKBOX_SYNC_INTERVAL` |
| `report` | `true` | `BLACKBOX_REPORT` |
| `daily_report_limit` | `9999` | `BLACKBOX_DAILY_REPORT_LIMIT` |
| `report_min_severity` | `high` | `BLACKBOX_REPORT_MIN_SEVERITY` |
| `block_severity` | `critical` | `BLACKBOX_BLOCK_SEVERITY` |
| `dashboard_port` | `9700` | `BLACKBOX_DASHBOARD_PORT` |
| `discover` | `true` | `BLACKBOX_DISCOVER` |
| `osv_lookup` | `true` | `BLACKBOX_OSV_LOOKUP` |
| `auto_attach` | `true` | `BLACKBOX_AUTO_ATTACH` |

`auto_attach` re-runs the `blackbox attach` sweep in the background on session
start (at most once per 24h), so Hermes homes and OpenClaw workspaces installed
*after* Blackbox get protected without any manual step.

Enable with `hermes plugins enable blackbox`.

### Detection policy (user-tunable)

Two more subtrees under `plugins.entries.blackbox.*` let a user tune *what*
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
    blackbox:
      detection:
        dependency: { enabled: true, min_severity: critical }
        skill:      { enabled: false }
      protected_paths:
        - "~/.ssh/*"
        - "**/.env"
```

`config.py` exposes this policy via `BlackboxConfig.category_setting(cat)` →
`{enabled, min_severity}` and `BlackboxConfig.category_allows(cat, severity)`.
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

### The audit trail (visibility, separate from flagging)

Blackbox keeps a **complete local audit trail** independent of whether anything
flags — the "what did the agent do" record an operator wants, separate from the
threat feed. Every tool call is recorded to `audit.jsonl`; on top of that, the
`on_pre_tool_call` hook logs structured visibility for **both** the dedicated
file tools **and** the shell channel (`hooks._record_activity` →
`quads.parse_shell_reads` / `parse_downloads` / `parse_dependency_installs`):

- `file_access.jsonl` — every file read/written (incl. `cat`/`head`/… via a
  shell tool) and every download URL (`mode="download"`).
- `dependencies.jsonl` — a structured record of **every** package install
  (`ecosystem`, `name`, `version`) regardless of threat status — the enterprise
  lib inventory.

These are local-only and never shared to SWM. Threat *findings* are the tighter
overlay: built-in heuristics are deliberately narrow (a routine `rm -rf
node_modules`, `.env` template, `curl -k localhost`, or a skill that shells out
does not raise a threat), so the shared community graph stays high-signal while
the audit trail stays complete.

### Optional LLM reviewer

An opt-in `llm` subtree adds an LLM second opinion on prompt injection over the
observer path (`on_pre_api_request`). Off by default; every key has an env
override.

| key | default | env |
|-----|---------|-----|
| `llm.enabled` | `false` | `BLACKBOX_LLM_ENABLED` |
| `llm.provider` | `""` (`openai` \| `anthropic`) | `BLACKBOX_LLM_PROVIDER` |
| `llm.model` | `""` | `BLACKBOX_LLM_MODEL` |
| `llm.api_key` | `""` | `BLACKBOX_LLM_API_KEY` |

`BlackboxConfig.llm_ready` is true only when enabled with a known provider,
model, and key all set. When ready, `on_pre_api_request` spawns a daemon thread
(`_spawn_llm_review`) that calls `llm.review_injection(text, cfg)`; a positive
verdict becomes a `source="llm"` injection `Finding`. Like `custom`, an `llm`
finding **never blocks** and is **never** shared to the graph - it is audited
locally only (`_report_and_audit` skips SWM/private-KA for `source=="llm"`).

The reviewer is a tiny stdlib `urllib` client (`llm.py`) for OpenAI
(`/v1/chat/completions`) and Anthropic (`/v1/messages`); every path fails open
to `None`, and reviewed text is capped and secret-redacted before it leaves the
machine. Configure it with `hermes blackbox setup-llm`; it reuses Blackbox,
Hermes, or OpenClaw model credentials by default. Use
`hermes blackbox setup-llm --configure` to choose provider/key/model again, or
`BLACKBOX_LLM_PROVIDER`, `BLACKBOX_LLM_MODEL`, and `BLACKBOX_LLM_API_KEY` for
non-interactive installs. Disable with `hermes blackbox setup-llm --disable`.

> Enabling this sends the reviewed message text to the chosen provider, and the
> key is stored in plaintext under `plugins.entries.blackbox.llm.api_key`. Both
> are inherent to the feature - hence opt-in.

### Settings API

The loopback dashboard exposes the policy over HTTP (same `127.0.0.1` bind as
the rest of the dashboard):

- `GET /api/settings` → `read_settings()`: the full, defaulted view — `mode`,
  `block_severity`, `report`, `report_min_severity`, `discover`, `osv_lookup`,
  `categories` (`{cat: {enabled, min_severity}}`), `protected_paths`,
  `severity_order`, and `category_labels`.
- `POST /api/settings` (JSON body) → `write_settings(payload)` →
  `{ok, errors, settings}`; HTTP `400` when `ok` is false. Only known keys with
  valid values are written; `detection` and `llm` are deep-merged and all
  unrelated config is preserved. The `llm` view reports `has_key` (a bool),
  never the raw key.

## CLI

```
hermes blackbox status                 # config, node reachability, ruleset + findings counts
hermes blackbox sync --wait            # force a ruleset refresh after DKG catch-up
hermes blackbox chat                   # dedicated Blackbox operator chat
hermes blackbox report --type ...      # submit a NEW candidate threat to SWM
                                       #   (injection|escalation|dependency|fileaccess|skill)
hermes blackbox setup-graph            # curator: create + register the public/community CG
hermes blackbox curate list --pending  # candidate threats grouped by distinct reporters
hermes blackbox curate show <id>       # one threat + its reporters
hermes blackbox curate approve <id>    # promote to curated threat in SWM, any of
                                       #   the five categories (anchor covers VM)
hermes blackbox curate anchor          # curator: publish compact VM proofs (batch
                                       #   root + members) for curated SWM threats
hermes blackbox curate reject <id>     # reject locally (+ optional SWM false-positive)
hermes blackbox curate auto-accept --once
                                       # legacy private graph: approve pending DKG graph join requests
hermes blackbox curate redeliver-approval --agent 0x...
                                       # curator: re-send approval when a member is stuck at 0 rows
hermes blackbox curate import --file … # bulk import a catalog (OSV enrichment for deps)
hermes blackbox dashboard [--port]     # start the loopback dashboard
hermes blackbox setup-llm              # configure the optional LLM injection reviewer
hermes blackbox setup-llm --configure  # choose provider/key/model again
hermes blackbox setup-llm --disable    # turn the LLM reviewer off
```

### Legacy Private-Graph Join Repair

Public Guardian threat graphs do not need join approval. If a legacy/private
consumer node reports `Join request: this node is already a member` but
`hermes blackbox sync --wait` still ends with `data 0, shared memory 0`, the DKG
node may have missed the curator approval notification before syncing the graph
`_meta` rows. Do not edit DKG SQLite state by hand. On the curator node, run:

```bash
hermes blackbox curate auto-accept --once
hermes blackbox curate redeliver-approval --agent <consumer-agent-address>
```

Then rerun `hermes blackbox sync --wait --timeout 180` on the consumer.

### Private community access and relay reachability

The default community graph is private and agent-gated. A fresh member sends a
join request to the configured curator; after admission, SWM recovery is
authorized from the request's signed agent identity and the graph allowlist.
Do not force `SWM_SYNC_OPEN`: bypassing that check exposes private snapshots and
also skips the member-recovery authorization path that serves the snapshot.
Normal unsigned requests denied by the curator are expected; an admitted
member's signed recovery request is the path that matters.

Members do not need to share a LAN with the curator. The installers seed the
four mainnet-base circuit relays, request four relay reservations, and retain
DKG's normal direct-connection upgrade when one is possible. A recovery can
therefore continue through relay/reconnect churn without turning the VM or a
custom relay into the data plane.

### DKG 10.0.5 large-SWM recovery bridge

In stock DKG 10.0.5, the responder constructs the first metadata page with an
unbounded variable-graph self-join. On a large fragmented SWM graph, Oxigraph
can spend minutes on that query while the requester times out; repeated
subscriptions then supersede the unfinished session. Increasing timeouts alone
does not fix the query.

After `npm install`, both installers run
`scripts/patch-dkg-10.0.5-sync.py` against the Blackbox-owned CLI. The patch is
strictly version-gated and:

- reads fresh metadata with fast explicit-graph `FILTER EXISTS` queries before
  stable in-memory ordering and wire paging;
- replaces large array spreads that can overflow the JavaScript stack;
- serializes catch-up peers and uses 180-second page / 20-minute total recovery
  windows, a 120-second minimum graph budget, and a 60-minute responder session;
- restores strict private recovery authorization if an older forced-open
  experiment is present.

The config writer also removes an unselected retired Guardian graph, disables
unneeded `agents` metadata catch-up, and caps all background sync work at one
in-flight operation. On a migrated isolated Blackbox node, the installer
non-destructively unsubscribes any persisted graph absent from `contextGraphs`;
its stored triples remain intact. This leaves the selected community graph with
the recovery budget. Every modified DKG file receives a one-time backup. Later
agent versions are detected and left untouched so the upstream implementation
wins; rerun the installer after replacing a 10.0.5 npm install.

`hermes blackbox chat` bootstraps a managed `blackbox` profile, writes a
Blackbox-specific `SOUL.md`, pins `context_file_max_chars` high enough for this
repo's `AGENTS.md`, and launches from the source checkout recorded when the
plugin was copied into `~/.hermes/plugins/blackbox`. The managed profile is a
control surface, not a protected workload, so attach/dashboard discovery filters
it out via the managed SOUL marker.

## Dependencies

Standard library only, plus **fastapi/uvicorn** (already provided by the hermes
`[web]` extra) for the optional dashboard. No new PyPI dependencies.
