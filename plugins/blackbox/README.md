# Agent Blackbox

Real-time threat protection for AI agents.

Agent Blackbox checks prompts, tool calls, shell commands, file access, package
installs, and skills against a shared threat graph on the OriginTrail DKG. It
works with Hermes and OpenClaw, runs in audit mode by default, and can block
confirmed threats before they execute.

## Install

Run the installer:

```bash
curl -fsSL https://raw.githubusercontent.com/umanitek/agent-blackbox/main/scripts/blackbox-install.sh | bash
```

The installer sets up an isolated node from the latest official
`@origintrail-official/dkg` npm package and protects detected Hermes and OpenClaw
agents. Docker must be installed and running for its Blazegraph store. The
installer does not replace or modify an existing DKG node.

The default context graph is private. The installer sends the local node's
signed join request to the default curator, which auto-approves valid requests.
Blackbox retries approval delivery and waits for local membership confirmation
before starting DKG catch-up. Local WM and the dashboard remain available while
the private graph is joining.

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
blackbox status       # check Blackbox and DKG health
blackbox sync --wait  # pull the latest threat data now
blackbox dashboard    # open http://127.0.0.1:9700
blackbox attach       # protect all detected local agents
blackbox detach       # remove protection
blackbox chat         # open the Blackbox assistant
```

The installer adds the `blackbox` command to your per-user PATH. It forwards
to `hermes blackbox`, so the longer form remains fully supported.

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

- The **public graph** contains Umanitek-verified threats. These can be blocked
  in block mode. “Public” is the VM trust tier; the default context graph still
  restricts its underlying data to approved nodes. The UI expands collection
  contents and lists each threat entity, not one row per collection.
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
| `context_graph_id` | `0x37b1Fdfd…/agent-blackbox` | Private Blackbox context graph |
| `graph_peer_id` | bundled curator peer | Receives the signed join request |

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
blackbox setup-llm
```

This feature is off by default. It sends reviewed text to the selected model
provider, only warns, and never shares its verdict with the threat graphs.
Disable it with `blackbox setup-llm --disable`.

## Troubleshooting sync

First check the node and retry the sync:

```bash
blackbox status
blackbox sync --wait
```

A first sync can continue in the background for several minutes. The default
curator auto-approves the signed request, and Blackbox keeps retrying until the
local DKG confirms membership. If `joining private graph` remains for more than
three minutes, rerun the command below and include the displayed agent address,
peer ID, and DKG log when reporting the problem:

```bash
blackbox sync --wait --timeout 180
```
