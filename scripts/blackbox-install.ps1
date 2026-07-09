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
$DkgPort     = if ($env:BLACKBOX_DKG_PORT)    { [int]$env:BLACKBOX_DKG_PORT } else { 9320 }
$DkgHome     = if ($env:BLACKBOX_DKG_HOME)    { $env:BLACKBOX_DKG_HOME }    else { Join-Path $BlackboxHome "dkg" }
$DkgDaemonUrl = if ($env:BLACKBOX_DKG_DAEMON_URL) { $env:BLACKBOX_DKG_DAEMON_URL } elseif ($env:BLACKBOX_DKG_URL) { $env:BLACKBOX_DKG_URL } else { "http://127.0.0.1:$DkgPort" }
$NodeMajor   = if ($env:BLACKBOX_NODE_MAJOR)  { [int]$env:BLACKBOX_NODE_MAJOR } else { 22 }
$ContextGraphId = if ($env:BLACKBOX_CONTEXT_GRAPH_ID) { $env:BLACKBOX_CONTEXT_GRAPH_ID } else { "umanitek/blackbox-threats-staging" }
$CatchupTimeout = if ($env:BLACKBOX_DKG_CATCHUP_TIMEOUT) { [int]$env:BLACKBOX_DKG_CATCHUP_TIMEOUT } else { 180 }
$script:InstallIncomplete = $false

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
  BLACKBOX_CONTEXT_GRAPH_ID, BLACKBOX_DKG_PORT, BLACKBOX_DKG_HOME,
  BLACKBOX_DKG_DAEMON_URL, BLACKBOX_DKG_CATCHUP_TIMEOUT

Blackbox uses its own DKG home and port by default:
  DKG home: $DkgHome
  DKG URL:  $DkgDaemonUrl

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
        & dkg @Args
    } finally {
        if ($null -eq $prev) {
            Remove-Item Env:DKG_HOME -ErrorAction SilentlyContinue
        } else {
            $env:DKG_HOME = $prev
        }
    }
}

function Test-BlackboxDkgPort {
    try {
        Invoke-WebRequest -Uri "$DkgDaemonUrl/api/status" -UseBasicParsing -TimeoutSec 3 | Out-Null
        Write-Ok "Blackbox DKG endpoint already responds at $DkgDaemonUrl"
        return $true
    } catch { }

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect("127.0.0.1", $DkgPort, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne(500)) {
            $client.EndConnect($async)
            $script:InstallIncomplete = $true
            Write-Warn2 "Port $DkgPort is already in use, but it did not answer as a DKG node at $DkgDaemonUrl."
            Write-Step "Set BLACKBOX_DKG_PORT to a free port and re-run the installer."
            return $false
        }
    } catch {
        return $true
    } finally {
        $client.Close()
    }
    return $true
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

    if (Get-Command dkg -ErrorAction SilentlyContinue) {
        Write-Ok "dkg CLI already installed"
    } else {
        Write-Step "Installing the DKG CLI (npm i -g @origintrail-official/dkg) ..."
        try {
            npm i -g '@origintrail-official/dkg' 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "npm exit $LASTEXITCODE" }
            Write-Ok "dkg CLI installed"
        } catch {
            $script:InstallIncomplete = $true
            Write-Warn2 "Global npm install failed. The plugin is installed, but threat-graph sync is not active."
            Show-DkgManualHint
            return
        }
    }

    New-Item -ItemType Directory -Force -Path $DkgHome | Out-Null
    if (-not (Test-BlackboxDkgPort)) {
        Show-DkgManualHint
        return
    }

    Write-Step "Bootstrapping a Blackbox-owned $Network node at $DkgDaemonUrl ..."
    Write-Step "  DKG home: $DkgHome"
    Write-Step "  (non-interactive; reading the public threat graph is free - no funds needed)"
    try {
        Invoke-BlackboxDkg hermes setup --network $Network --port $DkgPort --daemon-url $DkgDaemonUrl --no-fund
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

function Show-DkgManualHint {
    Write-Step "To set up the DKG node later:"
    Write-Host "      npm i -g '@origintrail-official/dkg'"
    Write-Host "      `$env:BLACKBOX_DKG_HOME = `"$DkgHome`""
    Write-Host "      `$env:BLACKBOX_DKG_PORT = `"$DkgPort`""
    Write-Host "      `$env:BLACKBOX_DKG_DAEMON_URL = `"$DkgDaemonUrl`""
    Write-Host "      `$env:DKG_HOME = `$env:BLACKBOX_DKG_HOME; dkg hermes setup --network $Network --port `$env:BLACKBOX_DKG_PORT --daemon-url `$env:BLACKBOX_DKG_DAEMON_URL --no-fund"
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
cfg_path, dkg_url, dkg_home = sys.argv[1], sys.argv[2], sys.argv[3]
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
added = []
current_dkg_url = str(blackbox.get("dkg_url") or blackbox.get("dkgUrl") or "").rstrip("/")
has_dkg_home = bool(blackbox.get("dkg_home") or blackbox.get("dkgHome"))
if "dkg_url" not in blackbox or (current_dkg_url in legacy_dkg_urls and not has_dkg_home):
    blackbox["dkg_url"] = dkg_url.rstrip("/")
    added.append("dkg_url")
if "dkg_home" not in blackbox or not blackbox.get("dkg_home"):
    blackbox["dkg_home"] = dkg_home
    added.append("dkg_home")
defaults = {
    "mode": "audit",
    # TEMPORARY: default to the private STAGING graph while production is still
    # being seeded. TODO(launch): switch to "umanitek/blackbox-threats" (production).
    "context_graph_id": os.environ.get("BLACKBOX_CONTEXT_GRAPH_ID", "umanitek/blackbox-threats-staging"),
    "sync_interval": 300,
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
        & $VenvPython $seedFile "$HermesHome\config.yaml" $DkgDaemonUrl $DkgHome
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
