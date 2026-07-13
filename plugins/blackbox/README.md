# Agent Blackbox

Real-time threat protection for AI agents.

Agent Blackbox checks prompts, tool calls, shell commands, file access, package
installs, and skills against a shared threat graph on the OriginTrail DKG. It
works with Hermes and OpenClaw, runs in audit mode by default, and can block
confirmed threats before they execute.

## Install

Run the installer:

```bash
curl -fsSL https://raw.githubusercontent.com/matic031/agent-guardian/feat/blackbox/scripts/blackbox-install.sh | bash
```

The installer sets up an isolated node from the official
`@origintrail-official/dkg` npm package and protects detected Hermes and
OpenClaw agents. Docker must be installed and running for its Blazegraph store.
The installer does not replace or modify an existing DKG node.

## Compatibility

- Hermes builds dated 2026-04-13 or later are supported. The installer uses a
  compatible Hermes build.
- OpenClaw 2026.6.11 or later is supported. Older releases do not provide the
  stable plugin hooks Blackbox requires.

Standard Hermes profiles and OpenClaw profiles are attached automatically. A
running OpenClaw Gateway must be restarted once after its plugin config changes.
For a remote or containerized agent, install Blackbox on the Gateway host.

## Use

```bash
hermes blackbox status       # check Blackbox and DKG health
hermes blackbox sync --wait  # pull the latest threat data now
hermes blackbox dashboard    # open http://127.0.0.1:9700
hermes blackbox attach       # protect all detected local agents
hermes blackbox detach       # remove protection
hermes blackbox chat         # open the Blackbox operator chat
```

Blackbox detects:

- prompt injection
- dangerous commands
- vulnerable or malicious dependencies
- sensitive file and secret access
- suspicious skills

Findings are logged locally and shown in the dashboard. In the default `audit`
mode, Blackbox warns without stopping the action. To block confirmed threats,
set the mode to `block` in the dashboard or in `config.yaml`:

```yaml
plugins:
  entries:
    blackbox:
      mode: block
```

## How threat data works

Blackbox uses two shared graphs:

- The **public graph** contains curator-approved threats. These can be blocked
  in block mode. Each public entry is a complete, self-contained threat
  knowledge asset, including its descriptive, provenance, and matching fields.
- The **community graph** contains reports awaiting review. These warn but
  never block.

Raw prompts, commands, file contents, secrets, and your local audit trail are
not published to either graph. Reports use deterministic identifiers instead
of the observed private content.

## Configuration

Settings are under `plugins.entries.blackbox` in `config.yaml`. The easiest way
to change them is through the dashboard settings page.

| Setting | Default | Purpose |
|---|---:|---|
| `mode` | `audit` | Warn only (`audit`) or stop confirmed threats (`block`) |
| `block_severity` | `critical` | Minimum severity blocked in block mode |
| `report` | `true` | Share eligible threat reports with the community graph |
| `report_min_severity` | `high` | Minimum severity shared as a report |
| `detection.<category>.enabled` | `true` | Enable or disable a detection category |
| `detection.<category>.min_severity` | `info` | Minimum visible severity for a category |
| `protected_paths` | `[]` | Local file globs that always block and are never shared |

Categories are `injection`, `escalation`, `dependency`, `fileaccess`, and
`skill`.

Example:

```yaml
plugins:
  entries:
    blackbox:
      detection:
        dependency:
          enabled: true
          min_severity: critical
        skill:
          enabled: false
      protected_paths:
        - "~/.ssh/*"
        - "**/.env"
```

### Optional AI reviewer

Blackbox can use your configured model for a second opinion on prompt
injection:

```bash
hermes blackbox setup-llm
```

This feature is off by default. It sends reviewed text to the selected model
provider, only warns, and never shares its verdict with the threat graphs.
Disable it with `hermes blackbox setup-llm --disable`.

## Troubleshooting sync

First check the node and retry the sync:

```bash
hermes blackbox status
hermes blackbox sync --wait
```

A first sync can continue in the background for several minutes. DKG requests
membership, the curator auto-approves it, and the node keeps syncing in the
background. To wait longer:

```bash
hermes blackbox sync --wait --timeout 180
```

## Curators

Curating reports and publishing approved threats are operator tasks. See the
[curator guide](../../CURATOR_README.md).
