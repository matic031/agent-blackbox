# ============================================================================
# Agent Blackbox - one-command installer (Windows / PowerShell)
# ============================================================================
# Mirror of blackbox-install.sh. Wires up the Blackbox threat-graph plugin,
# installs the OriginTrail DKG node CLI (Windows-native), bootstraps a mainnet
# node (read-only for users), enables the plugin, and seeds config defaults.
#
# NOTE: The Hermes agent itself is best run under WSL2 on Windows. The DKG CLI
# (dkg) is Windows-native. This installer sets up the Python environment and
# DKG node; if you hit issues running `hermes`, use WSL2 (guidance printed at
# the end).
#
# Usage:
#   iwr -useb https://raw.githubusercontent.com/matic031/agent-guardian/feat/guardian/scripts/blackbox-install.ps1 | iex
#   # or, from a clone:
#   .\scripts\blackbox-install.ps1 [-SkipDkg]
#
# Idempotent: safe to re-run. If the DKG node or initial threat-graph sync
# cannot complete, the installer exits non-zero and prints clear next steps
# instead of claiming Blackbox is fully ready with an empty ruleset.
# ============================================================================

param(
    [switch]$SkipDkg,
    [switch]$Help
)

# Mainnet only - the real public threat graph (reading is free; only curators
# pay TRAC to publish). A valid dkg mainnet: mainnet-base (ETH gas) | mainnet-gnosis. No testnet.
$Network = if ($env:BLACKBOX_DKG_NETWORK) { $env:BLACKBOX_DKG_NETWORK } else { "mainnet-base" }

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ── Configuration (override via env) ────────────────────────────────────────
$RepoUrl     = if ($env:BLACKBOX_REPO_URL)    { $env:BLACKBOX_REPO_URL }    else { "https://github.com/matic031/agent-guardian.git" }
$RepoBranch  = if ($env:BLACKBOX_REPO_BRANCH) { $env:BLACKBOX_REPO_BRANCH } else { "feat/guardian" }
$HermesHome  = if ($env:HERMES_HOME)          { $env:HERMES_HOME }          else { "$env:USERPROFILE\.hermes" }
$BlackboxHome = if ($env:BLACKBOX_HOME)       { $env:BLACKBOX_HOME }        else { Join-Path $HermesHome "blackbox" }
$DkgPortExplicit = [bool]$env:BLACKBOX_DKG_PORT
$DkgStorePortExplicit = [bool]$env:BLACKBOX_DKG_STORE_PORT
$DkgUrlExplicit = [bool]($env:BLACKBOX_DKG_DAEMON_URL -or $env:BLACKBOX_DKG_URL)
$DkgPort     = if ($env:BLACKBOX_DKG_PORT)    { [int]$env:BLACKBOX_DKG_PORT } else { 9320 }
$DkgStorePort = if ($env:BLACKBOX_DKG_STORE_PORT) { [int]$env:BLACKBOX_DKG_STORE_PORT } else { 7879 }
$DkgHome     = if ($env:BLACKBOX_DKG_HOME)    { $env:BLACKBOX_DKG_HOME }    else { Join-Path $BlackboxHome "dkg" }
$DkgCliDir   = if ($env:BLACKBOX_DKG_CLI_DIR) { $env:BLACKBOX_DKG_CLI_DIR } else { Join-Path $BlackboxHome "dkg-cli" }
$DkgBin      = if ($env:BLACKBOX_DKG_BIN)     { $env:BLACKBOX_DKG_BIN }     else { Join-Path $DkgCliDir "node_modules\.bin\dkg.cmd" }
$DkgPackage  = if ($env:BLACKBOX_DKG_PACKAGE) { $env:BLACKBOX_DKG_PACKAGE } else { "@origintrail-official/dkg@latest" }
$DkgDaemonUrl = if ($env:BLACKBOX_DKG_DAEMON_URL) { $env:BLACKBOX_DKG_DAEMON_URL } elseif ($env:BLACKBOX_DKG_URL) { $env:BLACKBOX_DKG_URL } else { "http://127.0.0.1:$DkgPort" }
$NodeMajor   = if ($env:BLACKBOX_NODE_MAJOR)  { [int]$env:BLACKBOX_NODE_MAJOR } else { 22 }
# Old default, parked for now: umanitek/guardian-threats-staging
$ContextGraphId = if ($env:BLACKBOX_CONTEXT_GRAPH_ID) { $env:BLACKBOX_CONTEXT_GRAPH_ID } else { "umanitek/blackbox-threats-staging" }
$CatchupTimeout = if ($env:BLACKBOX_DKG_CATCHUP_TIMEOUT) { [int]$env:BLACKBOX_DKG_CATCHUP_TIMEOUT } else { 180 }
$script:InstallIncomplete = $false
$script:DkgAlreadyRunning = $false

# ── Echo helpers (DRY) ──────────────────────────────────────────────────────
function Write-Step    { param($m) Write-Host "-> $m" -ForegroundColor Cyan }
function Write-Ok      { param($m) Write-Host "[OK] $m" -ForegroundColor Green }
function Write-Warn2   { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Err2    { param($m) Write-Host "[X] $m" -ForegroundColor Red }
function Write-Heading { param($m) Write-Host ""; Write-Host $m -ForegroundColor Green }

function Write-Banner {
    Write-Host ""
    Write-Host "  +-----------------------------------------------------------+" -ForegroundColor Green
    Write-Host "  |        [S] Agent Blackbox - installer            |" -ForegroundColor Green
    Write-Host "  +-----------------------------------------------------------+" -ForegroundColor Green
    Write-Host "  |  A threat-graph immune system for your AI agent.          |" -ForegroundColor Green
    Write-Host "  |  Detect prompt injection, tool escalation & bad deps -    |" -ForegroundColor Green
    Write-Host "  |  shared across agents via the OriginTrail DKG.            |" -ForegroundColor Green
    Write-Host "  +-----------------------------------------------------------+" -ForegroundColor Green
    Write-Host ""
}

function Show-Usage {
    @"
Agent Blackbox installer (Windows)

Usage: blackbox-install.ps1 [-SkipDkg] [-Help]

Options:
  -SkipDkg          Skip DKG setup; plugin installs but first-run protection is incomplete
  -Help             Show this help and exit

The DKG node always bootstraps on mainnet - the real public threat graph.
Reading it is free; publishing costs TRAC. Blackbox does not support testnet.

Environment overrides:
	  BLACKBOX_REPO_URL, BLACKBOX_REPO_BRANCH, HERMES_HOME, BLACKBOX_NODE_MAJOR,
	  BLACKBOX_CONTEXT_GRAPH_ID, BLACKBOX_DKG_PORT, BLACKBOX_DKG_STORE_PORT, BLACKBOX_DKG_HOME,
	  BLACKBOX_DKG_CLI_DIR, BLACKBOX_DKG_BIN, BLACKBOX_DKG_DAEMON_URL,
	  BLACKBOX_DKG_CATCHUP_TIMEOUT

Blackbox uses its own DKG home and port by default:
  DKG home: $DkgHome
  DKG CLI:  $DkgBin
  DKG URL:  $DkgDaemonUrl
  Store:    http://127.0.0.1:$DkgStorePort/query

Note: Run the Hermes agent under WSL2 on Windows for best results.
This installer is idempotent. If DKG setup or the first ruleset sync cannot
complete, it exits non-zero and prints the command to retry.
"@ | Write-Host
}

if ($Help) { Show-Usage; exit 0 }

# ── Prerequisite checks ─────────────────────────────────────────────────────
function Test-Git {
    if (Get-Command git -ErrorAction SilentlyContinue) {
        Write-Ok "git $((git --version) -replace 'git version ','')"
    } else {
        Write-Err2 "git not found."
        Write-Step "Install: winget install Git.Git   (or https://git-scm.com/download/win)"
        exit 1
    }
}

function Resolve-Python {
    # Accept 3.11-3.13. Try py launcher pins, then python.
    $candidates = @("py -3.13", "py -3.12", "py -3.11", "python")
    foreach ($c in $candidates) {
        $parts = $c.Split(" ")
        $exe = $parts[0]
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        try {
            $args = @()
            if ($parts.Count -gt 1) { $args += $parts[1] }
            $args += @("-c", "import sys; raise SystemExit(0 if (3,11)<=sys.version_info[:2]<=(3,13) else 1)")
            & $exe @args 2>$null
            if ($LASTEXITCODE -eq 0) {
                $script:PyExe = $exe
                $script:PyArgs = if ($parts.Count -gt 1) { @($parts[1]) } else { @() }
                $ver = (& $exe @($script:PyArgs + @("-V")) 2>&1)
                Write-Ok "Python $ver ($c)"
                return
            }
        } catch { }
    }
    Write-Err2 "Python 3.11-3.13 not found."
    Write-Step "Install: winget install Python.Python.3.11   (or https://python.org/downloads)"
    exit 1
}

function Test-NodeOk {
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) { return $false }
    $maj = [int]((node -v) -replace '^v','' -replace '\..*$','')
    return ($maj -ge $NodeMajor)
}

function Test-NodeJs {
    if (Test-NodeOk) {
        Write-Ok "Node.js $(node -v) + npm $(npm -v 2>$null)"
        $script:HasNode = $true
        return
    }
    if ($SkipDkg) { $script:HasNode = $false; return }
    Write-Warn2 "Node.js $NodeMajor+ not found - installing it automatically (winget) ..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        try {
            winget install --id OpenJS.NodeJS.LTS --silent --accept-source-agreements --accept-package-agreements | Out-Null
            # Refresh PATH so node/npm resolve in this session.
            $env:Path = [System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
                        [System.Environment]::GetEnvironmentVariable('Path','User')
        } catch { Write-Warn2 "winget Node install did not complete." }
    } else {
        Write-Warn2 "winget not available for automatic Node install."
    }
    if (Test-NodeOk) {
        Write-Ok "Node.js $(node -v) installed"
        $script:HasNode = $true
    } else {
        $script:HasNode = $false
        Write-Step "Install Node ${NodeMajor} manually: winget install OpenJS.NodeJS.LTS (then re-run this installer)."
        Write-Step "The Blackbox plugin still works; the DKG node is added once Node is present."
    }
}

function Invoke-BlackboxDkg {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $prev = $env:DKG_HOME
    try {
        $env:DKG_HOME = $DkgHome
        & $DkgBin @Args
    } finally {
        if ($null -eq $prev) {
            Remove-Item Env:DKG_HOME -ErrorAction SilentlyContinue
        } else {
            $env:DKG_HOME = $prev
        }
    }
}

function Test-BlackboxDkgState {
    return ((Test-Path (Join-Path $DkgHome "auth.token")) -or (Test-Path (Join-Path $DkgHome "config.json")))
}

function Set-BlackboxDkgPort {
    param([int]$Port)
    $script:DkgPort = $Port
    if (-not $DkgUrlExplicit) {
        $script:DkgDaemonUrl = "http://127.0.0.1:$Port"
    }
}

function Test-PortInUse {
    param([int]$Port)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne(500)) {
            $client.EndConnect($async)
            return $true
        }
        return $false
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Select-BlackboxDkgPort {
    for ($candidate = $DkgPort; $candidate -le 9399; $candidate++) {
        if (-not (Test-PortInUse $candidate)) {
            Set-BlackboxDkgPort $candidate
            Write-Ok "Using Blackbox DKG port $DkgPort"
            return $true
        }
    }
    return $false
}

function Select-BlackboxDkgStorePort {
    for ($candidate = $DkgStorePort; $candidate -le 7899; $candidate++) {
        if (-not (Test-PortInUse $candidate)) {
            $script:DkgStorePort = $candidate
            Write-Ok "Using Blackbox Oxigraph port $DkgStorePort"
            return $true
        }
    }
    return $false
}

function Test-BlackboxDkgPort {
    try {
        Invoke-WebRequest -Uri "$DkgDaemonUrl/api/status" -UseBasicParsing -TimeoutSec 3 | Out-Null
        if (Test-BlackboxDkgState) {
            Write-Ok "Blackbox DKG endpoint already responds at $DkgDaemonUrl"
            $script:DkgAlreadyRunning = $true
            return $true
        }
        Write-Warn2 "Port $DkgPort already has a DKG endpoint, but $DkgHome has no Blackbox node state."
        if ($DkgPortExplicit -or $DkgUrlExplicit) {
            $script:InstallIncomplete = $true
            Write-Step "Set BLACKBOX_DKG_PORT to a free port or stop the process on $DkgDaemonUrl."
            return $false
        }
        Write-Step "Choosing a different Blackbox-owned port so the existing DKG node is untouched."
        if (Select-BlackboxDkgPort) { return $true }
        $script:InstallIncomplete = $true
        Write-Warn2 "Could not find a free Blackbox DKG port in 9320-9399."
        return $false
    } catch { }

    if (Test-PortInUse $DkgPort) {
        Write-Warn2 "Port $DkgPort is already in use, but it did not answer as a DKG node at $DkgDaemonUrl."
        if ($DkgPortExplicit -or $DkgUrlExplicit) {
            $script:InstallIncomplete = $true
            Write-Step "Set BLACKBOX_DKG_PORT to a free port and re-run the installer."
            return $false
        }
        Write-Step "Choosing a different Blackbox-owned port."
        if (Select-BlackboxDkgPort) { return $true }
        $script:InstallIncomplete = $true
        Write-Warn2 "Could not find a free Blackbox DKG port in 9320-9399."
        return $false
    }
    return $true
}

function Test-BlackboxStorePort {
    if (Test-PortInUse $DkgStorePort) {
        Write-Warn2 "Oxigraph port $DkgStorePort is already in use."
        if ($DkgStorePortExplicit) {
            $script:InstallIncomplete = $true
            Write-Step "Set BLACKBOX_DKG_STORE_PORT to a free port and re-run the installer."
            return $false
        }
        Write-Step "Choosing a different Blackbox-owned Oxigraph port."
        if (Select-BlackboxDkgStorePort) { return $true }
        $script:InstallIncomplete = $true
        Write-Warn2 "Could not find a free Blackbox Oxigraph port in 7879-7899."
        return $false
    }
    return $true
}

function Ensure-BlackboxDkgConfig {
    $writer = @'
import json
import os
import secrets
import sys
from pathlib import Path

home = Path(sys.argv[1]).expanduser()
api_port = int(sys.argv[2])
store_port = int(sys.argv[3])
context_graph = sys.argv[4]
home.mkdir(parents=True, exist_ok=True)
cfg_path = home / "config.json"
if cfg_path.exists():
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception:
        data = {}
else:
    data = {}
data.setdefault("name", "agent-blackbox")
data["apiPort"] = api_port
data.setdefault("listenPort", 0)
data["nodeRole"] = "edge"
data["networkConfig"] = "mainnet-base"
# Relay reachability (see the .sh installer for the full rationale): DKG builds
# its relay set from `relayPeers`; empty -> network-isolation denies every
# relayed connection and the node holds 0 reservations, so no one can reach it.
MAINNET_BASE_RELAYS = [
    "/ip4/178.104.98.10/tcp/9090/p2p/12D3KooWFWm8sg6dkitmdBd5Uxaqp3CDRL27mFcM7vEHK92Xapyy",
    "/ip4/168.119.127.54/tcp/9090/p2p/12D3KooWMasqzRrim48ZJM64UyTfHufDTmSG3n3jqwsS5phz8m91",
    "/ip4/178.156.237.133/tcp/9090/p2p/12D3KooWDgTunUpkGaE7dYCaDP1CCBT6Dm2HPMXSZhJn2KXYLH15",
    "/ip4/178.105.211.42/tcp/9090/p2p/12D3KooWCodgXHMwybaEe93rbKgWMfGXQvUb6cpT3VCrjCbbnyEu",
]
existing_relays = data.get("relayPeers") if isinstance(data.get("relayPeers"), list) else []
merged_relays = list(dict.fromkeys([*existing_relays, *MAINNET_BASE_RELAYS]))
data["relayPeers"] = merged_relays
data["relayReservationCount"] = int(data.get("relayReservationCount") or 4)
graphs = data.get("contextGraphs")
if not isinstance(graphs, list):
    graphs = []
if context_graph not in graphs:
    graphs.append(context_graph)
data["contextGraphs"] = graphs
data.setdefault("autoUpdate", {"enabled": False})
data["chain"] = {
    "type": "evm",
    "rpcUrl": "https://mainnet.base.org",
    "rpcUrls": ["https://base-rpc.publicnode.com", "https://base.drpc.org"],
    "hubAddress": "0x99Aa571fD5e681c2D27ee08A7b7989DB02541d13",
    "chainId": "base:8453",
}
auth = data.get("auth") if isinstance(data.get("auth"), dict) else {}
data["auth"] = {**auth, "enabled": True}
store = data.get("store") if isinstance(data.get("store"), dict) else {}
options = store.get("options") if isinstance(store.get("options"), dict) else {}
options["port"] = store_port
data["store"] = {"backend": "oxigraph-server", "options": options}
cfg_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
token_path = home / "auth.token"
if not token_path.exists():
    token_path.write_text(
        "# DKG node API token - treat this like a password\n"
        + secrets.token_urlsafe(32)
        + "\n",
        encoding="utf-8",
    )
    os.chmod(token_path, 0o600)
'@
    $writerFile = Join-Path $env:TEMP "blackbox_dkg_config.py"
    Set-Content -Path $writerFile -Value $writer -Encoding UTF8
    try {
        & $VenvPython $writerFile $DkgHome $DkgPort $DkgStorePort $ContextGraphId
        if ($LASTEXITCODE -ne 0) { throw "dkg config exit $LASTEXITCODE" }
    } finally {
        Remove-Item $writerFile -Force -ErrorAction SilentlyContinue
    }
}

# ── Locate (or fetch) the repo ──────────────────────────────────────────────
function Resolve-Repo {
    $scriptDir = Split-Path -Parent $PSCommandPath
    if ($scriptDir) {
        $d = Split-Path -Parent $scriptDir
        if ((Test-Path "$d\pyproject.toml") -and (Test-Path "$d\plugins\blackbox")) {
            $script:RepoDir = $d
            Write-Step "Using existing checkout at $RepoDir"
            return
        }
    }
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Err2 "git is required to download Blackbox. Install git and re-run."
        exit 1
    }
    $script:RepoDir = if ($env:BLACKBOX_INSTALL_DIR) { $env:BLACKBOX_INSTALL_DIR } else { "$env:USERPROFILE\agent-guardian" }
    if (Test-Path "$RepoDir\.git") {
        Write-Step "Updating existing clone at $RepoDir"
        git -C $RepoDir fetch --depth 1 origin $RepoBranch 2>$null
        git -C $RepoDir checkout $RepoBranch 2>$null
        git -C $RepoDir pull --ff-only 2>$null
    } else {
        Write-Step "Cloning $RepoUrl -> $RepoDir"
        git clone --depth 1 --branch $RepoBranch $RepoUrl $RepoDir
    }
    Write-Ok "Repo ready at $RepoDir"
}

# ── Python venv + editable install ──────────────────────────────────────────
function Install-PythonEnv {
    Write-Heading "Installing Hermes + Blackbox (Python)"
    $script:VenvDir = "$RepoDir\venv"
    $script:VenvPython = "$VenvDir\Scripts\python.exe"
    if (-not (Test-Path $VenvDir)) {
        Write-Step "Creating virtual environment ..."
        & $script:PyExe @($script:PyArgs + @("-m", "venv", $VenvDir))
    } else {
        Write-Step "Reusing existing venv at $VenvDir"
    }
    Write-Step "Upgrading pip and installing agent-guardian[web] (editable) ..."
    & $VenvPython -m pip install --upgrade pip | Out-Null
    Push-Location $RepoDir
    try {
        & $VenvPython -m pip install -e ".[web]"
    } finally {
        Pop-Location
    }
    Write-Ok "Blackbox installed (editable, with dashboard extras)"
    $script:HermesBin = "$VenvDir\Scripts\hermes.exe"
}

# ── DKG node CLI + bootstrap ────────────────────────────────────────────────
function Install-Dkg {
    Write-Heading "Setting up the OriginTrail DKG node"
    if ($SkipDkg) {
        $script:InstallIncomplete = $true
        Write-Warn2 "Skipping DKG node setup (-SkipDkg)."
        Show-DkgManualHint
        return
    }
    if (-not $script:HasNode) {
        $script:InstallIncomplete = $true
        Write-Warn2 "Node.js $NodeMajor+ not available - cannot set up the DKG node or sync the threat graph."
        Show-DkgManualHint
        return
    }

    New-Item -ItemType Directory -Force -Path $DkgCliDir | Out-Null
    if (Test-Path $DkgBin) {
        Write-Ok "Blackbox DKG CLI already installed"
    } else {
        Write-Step "Installing the Blackbox-owned DKG CLI ($DkgPackage) ..."
        Write-Step "  CLI dir: $DkgCliDir"
        try {
            npm install --prefix $DkgCliDir $DkgPackage 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "npm exit $LASTEXITCODE" }
            Write-Ok "Blackbox DKG CLI installed at $DkgBin"
        } catch {
            $script:InstallIncomplete = $true
            Write-Warn2 "Local npm install failed. The plugin is installed, but threat-graph sync is not active."
            Show-DkgManualHint
            return
        }
    }
    Patch-DkgSyncBudgets

    New-Item -ItemType Directory -Force -Path $DkgHome | Out-Null
    if (-not (Test-BlackboxDkgPort)) {
        Show-DkgManualHint
        return
    }
    if ($script:DkgAlreadyRunning) {
        $script:DkgReady = $true
        return
    }
    if (-not (Test-BlackboxStorePort)) {
        Show-DkgManualHint
        return
    }
    Ensure-BlackboxDkgConfig

    Write-Step "Bootstrapping a Blackbox-owned $Network node at $DkgDaemonUrl ..."
    Write-Step "  DKG home: $DkgHome"
    Write-Step "  DKG CLI:  $DkgBin"
    Write-Step "  Store:    http://127.0.0.1:$DkgStorePort/query"
    Write-Step "  (non-interactive; reading the public threat graph is free - no funds needed)"
    try {
        Invoke-BlackboxDkg start
        if ($LASTEXITCODE -ne 0) { throw "dkg exit $LASTEXITCODE" }
        Write-Ok "DKG node bootstrapped on $Network"
        $script:DkgReady = $true
    } catch {
        $script:InstallIncomplete = $true
        Write-Warn2 "DKG node bootstrap did not complete. Threat-graph sync is not active yet."
        Show-DkgManualHint
    }
}

# Pull the curated ruleset now so detection is live immediately after install.
function Sync-Ruleset {
    if (-not $script:DkgReady) { return }
    Write-Heading "Syncing the threat ruleset"
    Write-Step "Pulling curated threats from the graph (hermes blackbox sync --wait) ..."
    $out = & $script:HermesBin blackbox sync --wait --timeout $CatchupTimeout --require-rules 2>&1
    $code = $LASTEXITCODE
    if ($out) { $out | ForEach-Object { Write-Host $_ } }
    if ($code -eq 0) {
        Write-Ok "Ruleset synced - Blackbox is watching with the latest threats"
    } else {
        $script:InstallIncomplete = $true
        Write-Err2 "Initial threat-graph sync did not load any rules."
        Write-Step "Blackbox is installed, but setup is incomplete until DKG returns a non-empty ruleset."
        Write-Step "Retry after fixing DKG/catch-up with: hermes blackbox sync --wait --require-rules"
    }
}

# Stock DKG v10.0.5 gives the whole catch-up a 120s budget shared by every
# graph and all three SWM phases, so a large public community graph can never
# finish one meta pass and a fresh node stays at 0 community rows. Patch the
# requester budgets in the Blackbox-owned DKG CLI (env-overridable, larger
# defaults). Idempotent; warns and continues if upstream moved the constants.
function Patch-DkgSyncBudgets {
    $py = @'
import pathlib, sys

cli_dir = pathlib.Path(sys.argv[1])
marker = "Ops patch (umanitek)"
budgets = (
    "const _envMs = (name, fallback) => {\n"
    "    const v = Number(process.env[name] ?? '');\n"
    "    return Number.isFinite(v) && v > 0 ? v : fallback;\n"
    "};\n"
)
edits = [
    ("dkg-agent-constants.js",
     "export const SYNC_TOTAL_TIMEOUT_MS = 120_000;",
     budgets + "export const SYNC_TOTAL_TIMEOUT_MS = _envMs('DKG_SYNC_TOTAL_TIMEOUT_MS', 600_000);"),
    ("dkg-agent-constants.js",
     "export const SYNC_PAGE_TIMEOUT_MS = 45_000;",
     "export const SYNC_PAGE_TIMEOUT_MS = _envMs('DKG_SYNC_PAGE_TIMEOUT_MS', 90_000);"),
    ("dkg-agent-constants.js",
     "export const SYNC_MIN_GRAPH_BUDGET_MS = 10_000;",
     "export const SYNC_MIN_GRAPH_BUDGET_MS = _envMs('DKG_SYNC_MIN_GRAPH_BUDGET_MS', 120_000);"),
    ("sync/durable-session.js",
     "export const DURABLE_DATA_SYNC_SESSION_TTL_MS = 10 * 60_000;",
     "const _ttlEnv = Number(process.env.DKG_SYNC_SESSION_TTL_MS ?? '');\n"
     "export const DURABLE_DATA_SYNC_SESSION_TTL_MS = "
     "Number.isFinite(_ttlEnv) && _ttlEnv > 0 ? _ttlEnv : 60 * 60_000;"),
    # Effectively-empty agent gate -> PUBLIC (see the .sh installer for why).
    ("dkg-agent-crypto.js",
     "return sawAgentGate ? agents : null;",
     "return (sawAgentGate && agents.length > 0) ? agents : null;"),
]
roots = sorted(cli_dir.glob("node_modules/**/dkg-agent/dist"))
if not roots:
    print("dkg-agent dist not found under " + str(cli_dir), file=sys.stderr)
    sys.exit(1)
failed = False
for root in roots:
    for rel, stock, replacement in edits:
        path = root / rel
        if not path.is_file():
            failed = True
            print(f"missing {path}", file=sys.stderr)
            continue
        text = path.read_text()
        if replacement.splitlines()[-1] in text:
            continue
        if stock not in text:
            failed = True
            print(f"stock line not found in {path}: {stock}", file=sys.stderr)
            continue
        path.write_text(text.replace(stock, f"// {marker}: sync budget, env-overridable\n" + replacement, 1))
sys.exit(1 if failed else 0)
'@
    $tmp = Join-Path $env:TEMP "blackbox-patch-dkg-sync.py"
    Set-Content -Path $tmp -Value $py -Encoding UTF8
    & $script:VenvPython $tmp $DkgCliDir
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "DKG sync budgets patched for large community-graph catch-up"
    } else {
        Write-Warn2 "Could not patch DKG sync budgets; large community graphs may not fully catch up."
    }
    Remove-Item -Path $tmp -ErrorAction SilentlyContinue
}

function Show-DkgManualHint {
    Write-Step "To set up the DKG node later:"
    Write-Host "      New-Item -ItemType Directory -Force -Path `"$DkgCliDir`""
    Write-Host "      npm install --prefix `"$DkgCliDir`" `"$DkgPackage`""
    Write-Host "      `$env:BLACKBOX_DKG_HOME = `"$DkgHome`""
    Write-Host "      `$env:BLACKBOX_DKG_BIN = `"$DkgBin`""
    Write-Host "      `$env:BLACKBOX_DKG_PORT = `"$DkgPort`""
    Write-Host "      `$env:BLACKBOX_DKG_STORE_PORT = `"$DkgStorePort`""
    Write-Host "      `$env:BLACKBOX_DKG_DAEMON_URL = `"$DkgDaemonUrl`""
    Write-Host "      # create config.json/auth.token as in scripts/blackbox-install.ps1, then:"
    Write-Host "      `$env:DKG_HOME = `$env:BLACKBOX_DKG_HOME; & `$env:BLACKBOX_DKG_BIN start"
    Write-Host "      # then re-run:  hermes blackbox sync --wait --require-rules"
}

# ── Enable plugin + seed config defaults (idempotent) ───────────────────────
function Enable-AndSeed {
    Write-Heading "Enabling Blackbox and seeding config defaults"

    Write-Step "Enabling the blackbox plugin (hermes plugins enable blackbox) ..."
    try {
        & $HermesBin plugins enable blackbox 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "hermes exit $LASTEXITCODE" }
        Write-Ok "Plugin enabled"
    } catch {
        Write-Warn2 "Could not run 'hermes plugins enable blackbox' automatically."
        Write-Step "Run it yourself after the install: hermes plugins enable blackbox"
    }

    Write-Step "Seeding plugins.entries.blackbox defaults into $HermesHome\config.yaml ..."
    $seeder = @'
import sys, os
cfg_path, dkg_url, dkg_home, dkg_bin = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
try:
    import yaml
except Exception:
    print("  (PyYAML unavailable - skipping seed; run 'hermes blackbox status' to configure)")
    sys.exit(0)
os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
data = {}
if os.path.exists(cfg_path):
    with open(cfg_path) as f:
        data = yaml.safe_load(f) or {}
plugins = data.setdefault("plugins", {})
entries = plugins.setdefault("entries", {})
blackbox = entries.setdefault("blackbox", {})
legacy_dkg_urls = {"http://127.0.0.1:9200", "http://localhost:9200"}
legacy_graphs = {"umanitek/guardian-threats-staging", "umanitek/guardian-threats"}
default_dkg_home = os.path.abspath(os.path.expanduser("~/.dkg"))
added = []
current_dkg_url = str(blackbox.get("dkg_url") or blackbox.get("dkgUrl") or "").rstrip("/")
current_dkg_home = str(blackbox.get("dkg_home") or blackbox.get("dkgHome") or "").strip()
current_dkg_home_abs = os.path.abspath(os.path.expanduser(current_dkg_home)) if current_dkg_home else ""
uses_shared_dkg_home = current_dkg_home_abs == default_dkg_home
uses_unpaired_shared_dkg_home = uses_shared_dkg_home and (not current_dkg_url or current_dkg_url in legacy_dkg_urls)
current_graph = str(blackbox.get("context_graph_id") or "")
if "dkg_url" not in blackbox or current_dkg_url in legacy_dkg_urls or uses_unpaired_shared_dkg_home:
    blackbox["dkg_url"] = dkg_url.rstrip("/")
    added.append("dkg_url")
if "dkg_home" not in blackbox or not blackbox.get("dkg_home") or uses_unpaired_shared_dkg_home:
    blackbox["dkg_home"] = dkg_home
    added.append("dkg_home")
current_dkg_bin = str(blackbox.get("dkg_bin") or blackbox.get("dkgBin") or "").strip()
if not current_dkg_bin or current_dkg_bin == "dkg":
    blackbox["dkg_bin"] = dkg_bin
    added.append("dkg_bin")
if current_graph in legacy_graphs:
    blackbox["context_graph_id"] = os.environ.get("BLACKBOX_CONTEXT_GRAPH_ID", "umanitek/blackbox-threats-staging")
    added.append("context_graph_id")
defaults = {
    "mode": "audit",
    # PUBLIC staging graph: open reads/SWM for every node, publish authority
    # stays with the curator wallet, and Verifiable Memory publishing works
    # (impossible on the retired private CG). TODO(launch): production graph.
    "context_graph_id": os.environ.get("BLACKBOX_CONTEXT_GRAPH_ID", "umanitek/blackbox-threats-staging"),
    "sync_interval": 60,
    "report": True,
    "daily_report_limit": 9999,
    "report_min_severity": "high",
    "block_severity": "critical",
    "dashboard_port": 9700,
    # Optional LLM reviewer — off until `hermes blackbox setup-llm` fills it in.
    "llm": {"enabled": False, "provider": "", "model": "", "api_key": ""},
}
for k, v in defaults.items():
    if k not in blackbox:
        blackbox[k] = v
        added.append(k)
with open(cfg_path, "w") as f:
    yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
print("  seeded: " + ", ".join(added) if added else "  already configured - no changes")
'@
    $seedFile = Join-Path $env:TEMP "blackbox_seed.py"
    Set-Content -Path $seedFile -Value $seeder -Encoding UTF8
    try {
        & $VenvPython $seedFile "$HermesHome\config.yaml" $DkgDaemonUrl $DkgHome $DkgBin
        if ($LASTEXITCODE -ne 0) { throw "seed exit $LASTEXITCODE" }
        Write-Ok "Config defaults seeded (audit mode - blocking is opt-in)"
    } catch {
        Write-Warn2 "Could not seed config automatically. Run 'hermes blackbox status' to verify configuration."
    } finally {
        Remove-Item $seedFile -Force -ErrorAction SilentlyContinue
    }
}

function Get-BlackboxMode {
    $reader = @'
import sys, os
cfg_path = sys.argv[1]
try:
    import yaml
except Exception:
    print("audit")
    sys.exit(0)
data = {}
if os.path.exists(cfg_path):
    with open(cfg_path) as f:
        data = yaml.safe_load(f) or {}
mode = data.get("plugins", {}).get("entries", {}).get("blackbox", {}).get("mode", "audit")
mode = str(mode).lower()
print(mode if mode in ("audit", "block") else "audit")
'@
    $readerFile = Join-Path $env:TEMP "blackbox_mode_read.py"
    Set-Content -Path $readerFile -Value $reader -Encoding UTF8
    try {
        $out = (& $VenvPython $readerFile "$HermesHome\config.yaml" 2>$null | Select-Object -Last 1)
        if ($out -eq "block") { return "block" }
        return "audit"
    } finally {
        Remove-Item $readerFile -Force -ErrorAction SilentlyContinue
    }
}

function Set-BlackboxMode {
    param([string]$Mode)
    $writer = @'
import sys, os
cfg_path, mode = sys.argv[1], sys.argv[2]
try:
    import yaml
except Exception:
    print("  (PyYAML unavailable - could not save protection mode)")
    sys.exit(1)
if mode not in ("audit", "block"):
    sys.exit(1)
os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
data = {}
if os.path.exists(cfg_path):
    with open(cfg_path) as f:
        data = yaml.safe_load(f) or {}
blackbox = data.setdefault("plugins", {}).setdefault("entries", {}).setdefault("blackbox", {})
blackbox["mode"] = mode
blackbox.setdefault("block_severity", "critical")
with open(cfg_path, "w") as f:
    yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
'@
    $writerFile = Join-Path $env:TEMP "blackbox_mode_write.py"
    Set-Content -Path $writerFile -Value $writer -Encoding UTF8
    try {
        & $VenvPython $writerFile "$HermesHome\config.yaml" $Mode
        return ($LASTEXITCODE -eq 0)
    } finally {
        Remove-Item $writerFile -Force -ErrorAction SilentlyContinue
    }
}

function Configure-BlackboxMode {
    Write-Heading "Choosing Blackbox enforcement mode"
    $current = if ($env:BLACKBOX_MODE) { $env:BLACKBOX_MODE.ToLowerInvariant() } else { "" }
    if (($current -ne "audit") -and ($current -ne "block")) {
        $current = Get-BlackboxMode
    }
    if ($current -ne "block") { $current = "audit" }

    if ([Console]::IsInputRedirected) {
        $script:BlackboxSelectedMode = $current
        Write-Step "Non-interactive install - keeping Blackbox in $current mode."
        return
    }

    Write-Host "  Choose how Blackbox should react when it finds threats."
    Write-Host "    1) Audit - log and report findings, but do not stop actions. [recommended]"
    Write-Host "    2) Block - stop confirmed threats at/above the configured severity."
    $ans = Read-Host "  Protection mode [1/2, Enter keeps $current]"
    switch -Regex ($ans) {
        '^(2|b|block)$' { $script:BlackboxSelectedMode = "block"; break }
        '^(1|a|audit)?$' { $script:BlackboxSelectedMode = $current; break }
        default {
            Write-Warn2 "Unknown protection mode '$ans' - keeping $current."
            $script:BlackboxSelectedMode = $current
        }
    }

    if (Set-BlackboxMode $script:BlackboxSelectedMode) {
        Write-Ok "Blackbox protection mode set to: $script:BlackboxSelectedMode"
    } else {
        Write-Warn2 "Could not save Blackbox protection mode. Set it later in the dashboard or config.yaml."
    }
}

# ── Auto-protect every local agent (best-effort, non-fatal) ─────────────────
# Discovers every local Hermes home + OpenClaw workspace and enables Blackbox
# in each, so protection is on everywhere without per-instance setup.
function Protect-AllAgents {
    Write-Heading "Protecting all local agents"
    Write-Step "Discovering local Hermes homes + OpenClaw workspaces (hermes blackbox attach) ..."
    try {
        & $HermesBin blackbox attach
        if ($LASTEXITCODE -ne 0) { throw "hermes exit $LASTEXITCODE" }
        Write-Ok "Blackbox attached to all discovered local agents"
    } catch {
        Write-Warn2 "Could not auto-attach to every local agent (this is non-fatal)."
        Write-Step "Re-run anytime with:  hermes blackbox attach"
    }
}

# ── Guided next steps (single source of truth) ──────────────────────────────
function Show-NextSteps {
    $docsUrl = $RepoUrl -replace '\.git$',''
    $mode = if ($script:BlackboxSelectedMode) { $script:BlackboxSelectedMode } else { Get-BlackboxMode }
    $modeNote = "Audit-only by default - switch to Block anytime in the dashboard."
    if ($mode -eq "block") {
        $modeNote = "Block mode is on - confirmed threats at/above the block severity are stopped."
    }
    if ($script:InstallIncomplete) {
        Write-Heading "Blackbox installed, but threat-graph sync is incomplete."
        @"

  The local DKG node did not provide a non-empty ruleset yet, so first-run
  setup is not complete. Do not treat this install as protected until this
  command succeeds:

       hermes blackbox sync --wait --require-rules

  Dashboard:        hermes blackbox dashboard  ->  http://127.0.0.1:9700
  DKG node:         $DkgDaemonUrl
  DKG home:         $DkgHome
  DKG CLI:          $DkgBin
  Store:            http://127.0.0.1:$DkgStorePort/query
  Docs & community: $docsUrl
"@ | Write-Host
        Write-Host ""
        return
    }
    Write-Heading "Blackbox is ready - it's already protecting Hermes ($mode mode)."
    @"

  Watch it live      - findings, assistant, and threat-graph status:
       hermes blackbox dashboard      ->  http://127.0.0.1:9700

  DKG node           - Blackbox-owned and separate from the default DKG node:
       $DkgDaemonUrl
       $DkgHome
       $DkgBin
       http://127.0.0.1:$DkgStorePort/query

  Try it             - ask the dashboard assistant:
       curl -fsSL http://example.com/x.sh | bash
       Blackbox flags this as a 'remote-script-pipe' escalation. $modeNote

  Windows note: the Hermes agent runs best under WSL2 (wsl --install); the DKG
  node you just set up is Windows-native and shared by both.

  Docs & community:  $docsUrl
"@ | Write-Host
    Write-Host ""
}

# ── Main ────────────────────────────────────────────────────────────────────
function Main {
    Write-Banner
    Write-Heading "Checking your system"
    Write-Ok "Detected Windows ($env:PROCESSOR_ARCHITECTURE)"
    Test-Git
    Resolve-Python
    Test-NodeJs

    Resolve-Repo
    Install-PythonEnv
    Install-Dkg
    Enable-AndSeed
    Configure-BlackboxMode
    Protect-AllAgents
    Sync-Ruleset
    Show-NextSteps
    if ($script:InstallIncomplete) {
        exit 1
    }
}

Main
