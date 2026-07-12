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
# Keep the managed DKG checkout and state in the Agent Guardian checkout. When
# invoked from a clone, use that clone; when piped through iex, use the checkout
# Resolve-Repo creates at BLACKBOX_INSTALL_DIR.
$DefaultRepoDir = if ($env:BLACKBOX_INSTALL_DIR) { $env:BLACKBOX_INSTALL_DIR } else { "$env:USERPROFILE\agent-guardian" }
if ($PSCommandPath) {
    $candidateRepoDir = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    if ((Test-Path "$candidateRepoDir\pyproject.toml") -and (Test-Path "$candidateRepoDir\plugins\blackbox")) {
        $DefaultRepoDir = $candidateRepoDir
    }
}
$BlackboxHome = if ($env:BLACKBOX_HOME)       { $env:BLACKBOX_HOME }        else { Join-Path $HermesHome "blackbox" }
$DkgPortExplicit = [bool]$env:BLACKBOX_DKG_PORT
$DkgStorePortExplicit = [bool]$env:BLACKBOX_DKG_STORE_PORT
$DkgUrlExplicit = [bool]($env:BLACKBOX_DKG_DAEMON_URL -or $env:BLACKBOX_DKG_URL)
$DkgPort     = if ($env:BLACKBOX_DKG_PORT)    { [int]$env:BLACKBOX_DKG_PORT } else { 9320 }
$DkgStorePort = if ($env:BLACKBOX_DKG_STORE_PORT) { [int]$env:BLACKBOX_DKG_STORE_PORT } else { 7879 }
$DkgHome     = if ($env:BLACKBOX_DKG_HOME)    { $env:BLACKBOX_DKG_HOME }    else { Join-Path $DefaultRepoDir ".dkg" }
$DkgCliDir   = if ($env:BLACKBOX_DKG_CLI_DIR) { $env:BLACKBOX_DKG_CLI_DIR } else { Join-Path $DefaultRepoDir "dkg" }
$DkgBin      = if ($env:BLACKBOX_DKG_BIN)     { $env:BLACKBOX_DKG_BIN }     else { Join-Path $DkgCliDir "node_modules\.bin\dkg.cmd" }
$DkgRepoUrl  = if ($env:BLACKBOX_DKG_REPO_URL) { $env:BLACKBOX_DKG_REPO_URL } else { "https://github.com/matic031/dkg.git" }
$DkgRepoBranch = if ($env:BLACKBOX_DKG_REPO_BRANCH) { $env:BLACKBOX_DKG_REPO_BRANCH } else { "feat/blackbox" }
$DkgDaemonUrl = if ($env:BLACKBOX_DKG_DAEMON_URL) { $env:BLACKBOX_DKG_DAEMON_URL } elseif ($env:BLACKBOX_DKG_URL) { $env:BLACKBOX_DKG_URL } else { "http://127.0.0.1:$DkgPort" }
$NodeMajor   = if ($env:BLACKBOX_NODE_MAJOR)  { [int]$env:BLACKBOX_NODE_MAJOR } else { 22 }
# Old default, parked for now: umanitek/guardian-threats-staging
$ContextGraphId = if ($env:BLACKBOX_CONTEXT_GRAPH_ID) { $env:BLACKBOX_CONTEXT_GRAPH_ID } else { "umanitek/blackbox-threats-staging" }
$CatchupTimeout = if ($env:BLACKBOX_DKG_CATCHUP_TIMEOUT) { [int]$env:BLACKBOX_DKG_CATCHUP_TIMEOUT } else { 180 }
$script:InstallIncomplete = $false
$script:DkgAlreadyRunning = $false
$script:DkgRestartRequired = $false
$script:DkgRuntimeMarker = Join-Path $DkgHome ".blackbox-runtime.sha256"
$script:DkgRuntimeFingerprint = ""

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
	  BLACKBOX_DKG_CLI_DIR, BLACKBOX_DKG_BIN, BLACKBOX_DKG_REPO_URL,
	  BLACKBOX_DKG_REPO_BRANCH, BLACKBOX_DKG_DAEMON_URL,
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
    $names = @(
        "DKG_HOME",
        "DKG_CATCHUP_MAX_CONCURRENT_PEERS",
        "DKG_SYNC_PAGE_TIMEOUT_MS",
        "DKG_SYNC_TOTAL_TIMEOUT_MS",
        "DKG_SYNC_MIN_GRAPH_BUDGET_MS",
        "DKG_SYNC_RESPONDER_PER_SNAPSHOT_ROW_LIMIT",
        "DKG_SYNC_RESPONDER_GLOBAL_SNAPSHOT_ROW_LIMIT",
        "Path"
    )
    $previous = @{}
    foreach ($name in $names) {
        $previous[$name] = [System.Environment]::GetEnvironmentVariable($name, "Process")
    }
    try {
        $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
        if ($nodeCommand -and $nodeCommand.Source) {
            $env:Path = "$(Split-Path -Parent $nodeCommand.Source);$env:Path"
        }
        $env:DKG_HOME = $DkgHome
        if (-not $env:DKG_CATCHUP_MAX_CONCURRENT_PEERS) { $env:DKG_CATCHUP_MAX_CONCURRENT_PEERS = "1" }
        if (-not $env:DKG_SYNC_PAGE_TIMEOUT_MS) { $env:DKG_SYNC_PAGE_TIMEOUT_MS = "180000" }
        if (-not $env:DKG_SYNC_TOTAL_TIMEOUT_MS) { $env:DKG_SYNC_TOTAL_TIMEOUT_MS = "1200000" }
        if (-not $env:DKG_SYNC_MIN_GRAPH_BUDGET_MS) { $env:DKG_SYNC_MIN_GRAPH_BUDGET_MS = "120000" }
        if (-not $env:DKG_SYNC_RESPONDER_PER_SNAPSHOT_ROW_LIMIT) { $env:DKG_SYNC_RESPONDER_PER_SNAPSHOT_ROW_LIMIT = "500000" }
        if (-not $env:DKG_SYNC_RESPONDER_GLOBAL_SNAPSHOT_ROW_LIMIT) { $env:DKG_SYNC_RESPONDER_GLOBAL_SNAPSHOT_ROW_LIMIT = "1500000" }
        & $DkgBin @Args
    } finally {
        foreach ($name in $names) {
            if ($null -eq $previous[$name]) {
                Remove-Item "Env:$name" -ErrorAction SilentlyContinue
            } else {
                Set-Item "Env:$name" $previous[$name]
            }
        }
    }
}

function Test-BlackboxDkgState {
    return ((Test-Path (Join-Path $DkgHome "auth.token")) -or (Test-Path (Join-Path $DkgHome "config.json")))
}

function Remove-StaleDkgSubscriptions {
    $cleaner = Join-Path $RepoDir "scripts\blackbox-clean-dkg-subscriptions.py"
    if (-not (Test-Path $cleaner)) {
        $script:InstallIncomplete = $true
        Write-Warn2 "DKG subscription cleaner is missing; stale graphs cannot be verified safely."
        return $false
    }
    & $script:VenvPython $cleaner $DkgHome $DkgDaemonUrl $ContextGraphId
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Stale DKG graph subscriptions checked"
        return $true
    } else {
        $script:InstallIncomplete = $true
        Write-Warn2 "Could not clean stale DKG graph subscriptions; setup is incomplete."
        return $false
    }
}

function Prepare-BlackboxDkgRuntimeFingerprint {
    $fingerprinter = Join-Path $RepoDir "scripts\blackbox-dkg-runtime-fingerprint.py"
    if (-not (Test-Path $fingerprinter)) {
        $script:InstallIncomplete = $true
        Write-Warn2 "DKG runtime fingerprint helper is missing; loaded checkout state cannot be verified."
        return $false
    }
    $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
    if (-not $nodeCommand -or -not $nodeCommand.Source) {
        $script:InstallIncomplete = $true
        Write-Warn2 "Could not resolve the Node.js runtime for DKG fingerprinting."
        return $false
    }
    $fingerprintOutput = @(& $script:VenvPython $fingerprinter compute $DkgCliDir $DkgHome $nodeCommand.Source $DkgBin 2>&1)
    if ($LASTEXITCODE -ne 0) {
        $script:InstallIncomplete = $true
        if ($fingerprintOutput) {
            $fingerprintOutput | ForEach-Object { Write-Warn2 "$_" }
        }
        Write-Warn2 "Could not fingerprint the configured DKG runtime; setup is incomplete."
        return $false
    }
    $script:DkgRuntimeFingerprint = "$($fingerprintOutput | Select-Object -Last 1)".Trim()
    $applied = if (Test-Path $script:DkgRuntimeMarker) {
        (Get-Content -Raw $script:DkgRuntimeMarker).Trim()
    } else {
        ""
    }
    if ($applied -ne $script:DkgRuntimeFingerprint) {
        $script:DkgRestartRequired = $true
    }
    return $true
}

function Save-BlackboxDkgRuntimeFingerprint {
    $fingerprinter = Join-Path $RepoDir "scripts\blackbox-dkg-runtime-fingerprint.py"
    if (-not $script:DkgRuntimeFingerprint) {
        $script:InstallIncomplete = $true
        Write-Warn2 "DKG runtime fingerprint is empty after restart."
        return $false
    }
    & $script:VenvPython $fingerprinter record $script:DkgRuntimeMarker $script:DkgRuntimeFingerprint
    if ($LASTEXITCODE -ne 0) {
        $script:InstallIncomplete = $true
        Write-Warn2 "DKG restarted, but its applied runtime fingerprint could not be recorded."
        return $false
    }
    return $true
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
original = None
if cfg_path.exists():
    try:
        original = cfg_path.read_text(encoding="utf-8")
        data = json.loads(original)
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
# Keep catch-up focused on the selected Blackbox graph after migrating from
# the retired Guardian default. Preserve it when explicitly selected.
legacy_graphs = {"umanitek/guardian-threats-staging", "umanitek/guardian-threats"}
graphs = [g for g in graphs if g not in legacy_graphs or g == context_graph]
if context_graph not in graphs:
    graphs.append(context_graph)
data["contextGraphs"] = graphs
data["syncAgentsMeta"] = False
# Blackbox explicitly subscribes and targets its curator. Generic per-peer
# startup fanout only delays that catch-up behind unrelated network graphs.
data["syncOnConnectEnabled"] = False
# Large first-run base-network syncs can occupy the single worker for minutes.
# Keep enough FIFO capacity for post-approval metadata/SWM catch-up from the curator
# instead of dropping it behind the default two-entry queue and leaving a newly
# admitted private-graph member permanently at 0 rows.
data["syncGlobalMaxInflight"] = 1
data["syncGlobalQueueLimit"] = 32
# Retired pre-fork workaround; current DKG handles configured subscriptions.
data.pop("restrictAutoSubscribeContextGraphs", None)
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
# A populated curator store can need longer than the 30-second DKG default to
# reopen its RocksDB state. Killing it at that boundary creates a restart loop.
options["readyTimeoutMs"] = 120000
data["store"] = {"backend": "oxigraph-server", "options": options}
rendered = json.dumps(data, indent=2) + "\n"
changed = rendered != original
if changed:
    cfg_path.write_text(rendered, encoding="utf-8")
token_path = home / "auth.token"
if not token_path.exists():
    token_path.write_text(
        "# DKG node API token - treat this like a password\n"
        + secrets.token_urlsafe(32)
        + "\n",
        encoding="utf-8",
    )
    os.chmod(token_path, 0o600)
    changed = True
print("changed" if changed else "unchanged")
'@
    $writerFile = Join-Path $env:TEMP "blackbox_dkg_config.py"
    Set-Content -Path $writerFile -Value $writer -Encoding UTF8
    try {
        $configState = & $VenvPython $writerFile $DkgHome $DkgPort $DkgStorePort $ContextGraphId
        if ($LASTEXITCODE -ne 0) { throw "dkg config exit $LASTEXITCODE" }
        if (($configState | Select-Object -Last 1) -eq "changed") {
            $script:DkgRestartRequired = $true
        }
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
    $script:RepoDir = $DefaultRepoDir
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
function Install-BlackboxDkgCheckout {
    $entrypoint = Join-Path $DkgCliDir "packages\cli\dist\cli.js"
    $buildMarker = Join-Path $DkgCliDir ".git\blackbox-build-commit"
    $previousCommit = ""
    $backupDir = ""
    $needsBuild = $false
    $gitCommand = Get-Command git -ErrorAction SilentlyContinue
    $corepackCommand = Get-Command corepack -ErrorAction SilentlyContinue
    $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
    if (-not $gitCommand -or -not $corepackCommand -or -not $nodeCommand) {
        Write-Warn2 "git, Node.js, and Corepack are required to build the Blackbox DKG checkout."
        return $false
    }

    if (Test-Path (Join-Path $DkgCliDir ".git")) {
        & git -C $DkgCliDir diff --quiet
        $worktreeClean = $LASTEXITCODE -eq 0
        & git -C $DkgCliDir diff --cached --quiet
        $indexClean = $LASTEXITCODE -eq 0
        if (-not $worktreeClean -or -not $indexClean) {
            Write-Warn2 "Managed DKG checkout has local changes; refusing to overwrite $DkgCliDir."
            return $false
        }
        $previousCommit = (& git -C $DkgCliDir rev-parse HEAD).Trim()
        & git -C $DkgCliDir remote set-url origin $DkgRepoUrl
        if ($LASTEXITCODE -ne 0) { return $false }
        & git -C $DkgCliDir fetch --depth 1 origin $DkgRepoBranch
        if ($LASTEXITCODE -ne 0) { return $false }
        & git -C $DkgCliDir checkout --detach FETCH_HEAD
        if ($LASTEXITCODE -ne 0) { return $false }
    } else {
        if ((Test-Path $DkgCliDir) -and @(Get-ChildItem -Force $DkgCliDir).Count -gt 0) {
            $backupDir = "$DkgCliDir.npm-backup-$(Get-Date -Format yyyyMMddHHmmss)"
            Write-Step "Moving the legacy npm DKG install to $backupDir"
            Move-Item $DkgCliDir $backupDir
        }
        & git clone --depth 1 --branch $DkgRepoBranch $DkgRepoUrl $DkgCliDir
        if ($LASTEXITCODE -ne 0) {
            if ($backupDir -and -not (Test-Path $DkgCliDir)) {
                Move-Item $backupDir $DkgCliDir
            }
            Write-Warn2 "Could not clone DKG from $DkgRepoUrl#$DkgRepoBranch."
            return $false
        }
        $needsBuild = $true
    }

    $currentCommit = (& git -C $DkgCliDir rev-parse HEAD).Trim()
    $builtCommit = if (Test-Path $buildMarker) { (Get-Content -Raw $buildMarker).Trim() } else { "" }
    if ($previousCommit -ne $currentCommit -or $builtCommit -ne $currentCommit -or -not (Test-Path $entrypoint)) {
        $needsBuild = $true
    }
    if ($needsBuild) {
        Write-Step "Building DKG feat/blackbox at $($currentCommit.Substring(0, 12)) ..."
        Push-Location $DkgCliDir
        try {
            & corepack pnpm install --frozen-lockfile
            if ($LASTEXITCODE -ne 0) { throw "pnpm install exit $LASTEXITCODE" }
            & corepack pnpm run build:runtime:packages
            if ($LASTEXITCODE -ne 0) { throw "pnpm build exit $LASTEXITCODE" }
        } catch {
            Write-Warn2 "Could not install or build the Blackbox DKG checkout: $_"
            return $false
        } finally {
            Pop-Location
        }
        Set-Content -Path $buildMarker -Value "$currentCommit`n" -Encoding Ascii -NoNewline
        $script:DkgRestartRequired = $true
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $DkgBin) | Out-Null
    $launcher = "@echo off`r`n`"$($nodeCommand.Source)`" `"$entrypoint`" %*`r`n"
    Set-Content -Path $DkgBin -Value $launcher -Encoding Ascii -NoNewline
    Write-Ok "Blackbox DKG checkout ready ($($currentCommit.Substring(0, 12)), $DkgRepoBranch)"
    return $true
}

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

    Write-Step "Installing the Blackbox DKG checkout ($DkgRepoUrl#$DkgRepoBranch) ..."
    Write-Step "  Checkout: $DkgCliDir"
    if (-not (Install-BlackboxDkgCheckout)) {
        $script:InstallIncomplete = $true
        Show-DkgManualHint
        return
    }

    New-Item -ItemType Directory -Force -Path $DkgHome | Out-Null
    if (-not (Test-BlackboxDkgPort)) {
        Show-DkgManualHint
        return
    }
    if ($script:DkgAlreadyRunning) {
        Ensure-BlackboxDkgConfig
        if (-not (Prepare-BlackboxDkgRuntimeFingerprint)) {
            Show-DkgManualHint
            return
        }
        if (-not (Remove-StaleDkgSubscriptions)) {
            Show-DkgManualHint
            return
        }
        if (-not $script:DkgRestartRequired) {
            $script:DkgReady = $true
            return
        }
        Write-Step "Restarting the Blackbox-owned DKG node to activate sync and relay updates ..."
        try {
            Invoke-BlackboxDkg stop
            if ($LASTEXITCODE -ne 0) { throw "dkg stop exit $LASTEXITCODE" }
            Invoke-BlackboxDkg start
            if ($LASTEXITCODE -ne 0) { throw "dkg start exit $LASTEXITCODE" }
            Write-Ok "Blackbox DKG node restarted with the current sync settings"
            if (-not (Save-BlackboxDkgRuntimeFingerprint) -or -not (Remove-StaleDkgSubscriptions)) {
                Show-DkgManualHint
                return
            }
            $script:DkgReady = $true
        } catch {
            $script:InstallIncomplete = $true
            Write-Warn2 "Could not restart the Blackbox DKG node; the updated sync settings are not active."
            Show-DkgManualHint
        }
        return
    }
    if (-not (Test-BlackboxStorePort)) {
        Show-DkgManualHint
        return
    }
    Ensure-BlackboxDkgConfig
    if (-not (Prepare-BlackboxDkgRuntimeFingerprint)) {
        Show-DkgManualHint
        return
    }

    Write-Step "Bootstrapping a Blackbox-owned $Network node at $DkgDaemonUrl ..."
    Write-Step "  DKG home: $DkgHome"
    Write-Step "  DKG CLI:  $DkgBin"
    Write-Step "  Store:    http://127.0.0.1:$DkgStorePort/query"
    Write-Step "  (non-interactive; reading the public threat graph is free - no funds needed)"
    try {
        Invoke-BlackboxDkg start
        if ($LASTEXITCODE -ne 0) { throw "dkg exit $LASTEXITCODE" }
        Write-Ok "DKG node bootstrapped on $Network"
        if (-not (Save-BlackboxDkgRuntimeFingerprint) -or -not (Remove-StaleDkgSubscriptions)) {
            Show-DkgManualHint
            return
        }
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

function Show-DkgManualHint {
    Write-Step "To set up the DKG node later:"
    Write-Host "      git clone --depth 1 --branch `"$DkgRepoBranch`" `"$DkgRepoUrl`" `"$DkgCliDir`""
    Write-Host "      Set-Location `"$DkgCliDir`"; corepack pnpm install --frozen-lockfile; corepack pnpm run build:runtime:packages"
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
