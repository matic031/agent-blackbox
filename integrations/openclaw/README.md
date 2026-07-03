# Umanitek Agent Guardian — OpenClaw plugin

Mirrors the hermes Guardian plugin's detection inside an OpenClaw agent and
reports sightings to the **same** local DKG node / threat graph. Same threat
identifiers, same arg shapes, same severities — a hermes node and an OpenClaw
node computing the same threat converge on the same subject URI.

- **Detection rules come only from the threat graph.** The plugin syncs a
  ruleset from your local DKG node (curated threats from the public graph + your
  node's local graph). On an empty graph it detects nothing until synced — by
  design.
- **Audit-only by default.** Blocking is opt-in (`mode: block`).
- **Fail-open.** Any error in a hook is swallowed; the agent loop is never
  broken. Threat pushes are deterministic HTTP calls, never LLM/MCP-driven.
- **Reports never carry observed content.** Sightings reference a threat
  identifier + severity only; the observed prompt/command stays in the private
  audit split.

## What it detects

| Category | Where | Identifier |
|----------|-------|------------|
| Prompt injection | tool params, the incoming run prompt, inbound messages | `injection:{sha256(pattern)[:24]}` |
| Privilege escalation | tool call shape (compares **both** tool name and arg shape) | `escalation:{tool}::{sha256(argShape)[:24]}` |
| Vulnerable dependency | install commands (`pip`/`uv`/`npm`/`pnpm`/`yarn`/`bun`/`cargo`/`gem`/`brew`) | `dep:{ecosystem}:{name}@{version}` |

## Hooks

| Hook | Behavior |
|------|----------|
| `before_tool_call` | detect escalation + dependency + injection over params; **block** (block mode, ≥ `blockSeverity`) or observe + report |
| `after_tool_call` | observe result (redacted); never blocks |
| `before_agent_run` | prompt-injection scan of the incoming prompt + history — **requires `allowConversationAccess`** |
| `message_received` | observe inbound content for injection sightings |
| `session_start` / `session_end` | lifecycle; `session_start` warms the ruleset |

## Install

### Option A — `openclaw plugins install`

```bash
openclaw plugins install ./integrations/openclaw
openclaw plugins enable guardian
```

### Option B — config merge (dkg-adapter pattern)

Point OpenClaw at the plugin directory and set its config in
`~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "load": { "paths": ["/absolute/path/to/agent-guardian/integrations/openclaw"] },
    "enabled": ["guardian"],
    "entries": {
      "guardian": {
        "hooks": { "allowConversationAccess": true },
        "config": {
          "mode": "audit",
          "contextGraphId": "umanitek/guardian-threats",
          "dkgUrl": "http://127.0.0.1:9200",
          "syncInterval": 300,
          "report": true,
          "dailyReportLimit": 500,
          "blockSeverity": "critical"
        }
      }
    }
  }
}
```

> **`allowConversationAccess` is required for `before_agent_run`.** It is a
> conversation hook; without
> `plugins.entries.guardian.hooks.allowConversationAccess=true` OpenClaw will
> not deliver the prompt/history to the plugin and the incoming-run
> prompt-injection scan is silently skipped. Tool-call, message, and session
> detection still work without it.

## Configuration

Set under `plugins.entries.guardian.config`; every key has an environment
override (env wins).

| Key | Default | Env | Meaning |
|-----|---------|-----|---------|
| `mode` | `audit` | `GUARDIAN_MODE` | `audit` \| `block` |
| `contextGraphId` | `umanitek/guardian-threats` | `GUARDIAN_CONTEXT_GRAPH_ID` | public curated CG id |
| `dkgUrl` | `http://127.0.0.1:9200` | `DKG_DAEMON_URL` | local node |
| `syncInterval` | `300` | `GUARDIAN_SYNC_INTERVAL` | seconds between ruleset refresh |
| `report` | `true` | `GUARDIAN_REPORT` | share sightings to SWM |
| `dailyReportLimit` | `500` | `GUARDIAN_DAILY_REPORT_LIMIT` | anti-bot cap on reports/day |
| `blockSeverity` | `critical` | `GUARDIAN_BLOCK_SEVERITY` | min severity blocked in block mode |

The DKG bearer token is resolved from `$DKG_API_TOKEN` / `$DKG_AUTH_TOKEN`, then
`$DKG_HOME/auth.token` (default `~/.dkg/auth.token`).

Ruleset cache is stored under the OpenClaw state dir
(`$OPENCLAW_STATE_DIR/guardian/ruleset.json`, default `~/.openclaw/guardian/`).

## Requirements

- Node ≥ 22.19 (OpenClaw runtime). Zero runtime dependencies — uses global
  `fetch`, `node:crypto`, and `node:fs`.
- A running local DKG v10 node. Without one, the plugin loads and fails open
  (detects nothing, reports nothing).

## Development

```bash
npm install
npm run typecheck   # tsc --noEmit
```

Detection semantics and threat identifiers are kept byte-identical to the Python
`plugins/guardian/` side and the reference `dkg/packages/node-ui/src/guardian.ts`.
Do not change identifier construction (`quads.ts`) or arg-shape normalization
(`detection.ts`) on one side without mirroring the other.
