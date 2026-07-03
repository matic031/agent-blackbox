<div align="center">

<img src="./docs/agent-guardian-logo.jpeg" alt="Umanitek Agent Guardian" width="150">

# Umanitek Agent Guardian

**Real-time threat protection for your AI agents.**

[![License: MIT](https://img.shields.io/badge/License-MIT-80CA9C?style=flat-square)](LICENSE)
[![by Umanitek](https://img.shields.io/badge/by-Umanitek-5C7F87?style=flat-square)](#about-umanitek)

</div>

---

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/matic031/agent-guardian/feat/guardian/scripts/guardian-install.sh | bash
```

<details>
<summary><b>Manual install</b> - prefer not to pipe a script into bash?</summary>
<br>

The installer only automates the steps below (idempotent, no sudo). Run them yourself:

```bash
# 1. Get the code
git clone -b feat/guardian https://github.com/matic031/agent-guardian.git
cd agent-guardian

# 2. Python env (3.11-3.13) with the dashboard extras
python3 -m venv venv
venv/bin/pip install -e ".[web]"

# 3. Put `hermes` on your PATH
mkdir -p ~/.local/bin
ln -sf "$PWD/venv/bin/hermes" ~/.local/bin/hermes

# 4. Local DKG node (optional - without it Umanitek Agent Guardian still runs, with an empty ruleset)
npm i -g @origintrail-official/dkg
dkg hermes setup --network testnet   # testnet only for the beta

# 5. Enable Umanitek Agent Guardian and protect every local agent
hermes plugins enable guardian
hermes guardian attach
hermes guardian sync
```

Or download the script, read it, then run it:

```bash
curl -fsSLO https://raw.githubusercontent.com/matic031/agent-guardian/feat/guardian/scripts/guardian-install.sh
less guardian-install.sh
bash guardian-install.sh
```

</details>

## First run

```bash
hermes                     # start your agent - Umanitek Agent Guardian is already watching
hermes guardian dashboard  # open the live threat dashboard
hermes guardian attach     # protect every local agent
```

Works with **Hermes** and **OpenClaw**.

## What it catches

- **Vulnerable dependencies** - packages with known CVEs or malicious versions, caught at install time.
- **Prompt injection** - hidden instructions in web pages, files, or tool output that try to hijack your agent.
- **Dangerous commands** - shell commands that pipe remote scripts, exfiltrate data, or damage your system.
- **Sensitive file access** - reads of SSH keys, credentials, and other secrets.
- **Suspicious skills** - newly installed skills with malicious behavior.

## The public threat graph

<div align="center">
<img src="./docs/graph.png" alt="The Umanitek Agent Guardian threat graph" width="880">
</div>

This is the heart of Umanitek Agent Guardian: one shared, **curator-approved** threat graph on the OriginTrail DKG that every agent reads from. A threat added once protects every agent everywhere - and it's tamper-proof, so no single party can quietly rewrite it.

## How it works

Umanitek Agent Guardian runs inside your agent and checks every action against two shared threat graphs:

- **The public threat graph** - curated by Umanitek - is the source of truth. If a threat is there, Umanitek Agent Guardian flags it as confirmed and, in block mode, blocks it.
- **The community graph** covers what the public graph doesn't yet. Threats reported by agents across the network are flagged as unconfirmed so you see them - but they never block.

Built-in heuristics only nominate **new** high-severity candidates; agents report those to the community graph, where curators review them and promote the real ones to the public graph. When one agent learns a threat, every agent learns it.

Both graphs live on the **OriginTrail Decentralized Knowledge Graph (DKG)** - a tamper-proof, community threat database no single party can quietly rewrite.

> Approving what becomes public is a curator's job - see the [curator guide](CURATOR_README.md).

The dashboard (`hermes guardian dashboard`) shows all three graphs side by side: **Public** (curated), **Community** (reported by agents), and **Local** (your node).

## Auto-attach

```bash
hermes guardian attach   # protect every local agent at once
hermes guardian detach   # turn it back off
```

`attach` finds every Hermes home and OpenClaw workspace on your machine and enables Umanitek Agent Guardian in each one - no per-agent setup.

## Configuration

Set under `plugins.entries.guardian.*` in `config.yaml`.

| Key | Default | Meaning |
|-----|---------|---------|
| `mode` | `audit` | `audit` or `block` |
| `dkg_url` | `http://127.0.0.1:9200` | local DKG node |
| `context_graph_id` | `umanitek/guardian-threats` | the public curated threat graph |
| `daily_report_limit` | `9999` | max threat reports sent to the community graph per day |
| `report_min_severity` | `high` | minimum severity for heuristic candidates to be flagged and reported |
| `detection.<category>.enabled` | `true` | turn a whole category on/off (`injection`, `escalation`, `dependency`, `fileaccess`, `skill`) |
| `detection.<category>.min_severity` | `info` | quiet a category below this level, e.g. `detection.dependency.min_severity: critical` |
| `protected_paths` | `[]` | your own files/folders that always block and never leave your machine |

Full options in the [plugin README](plugins/guardian/README.md).

### Customize to your needs

Open the dashboard and click the gear icon - no config file needed. Switch threat categories on/off and set their minimum severity, list protected files and folders (globs welcome, e.g. `~/.ssh/*`, `**/.env`) that always block and never leave your machine, and flip between *audit* and *block* mode. Changes are saved to `config.yaml` and apply to every agent.

## About Umanitek

[Umanitek](https://umanitek.ai) is fighting for a safe internet in the age of AI. Umanitek Agent Guardian is built on the OriginTrail Decentralized Knowledge Graph, turning collective threat intelligence into real-time protection for every agent.

## License

MIT - see [LICENSE](LICENSE). A fork of [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent) (MIT).
