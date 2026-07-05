#!/bin/bash
# ============================================================================
# Umanitek Agent Guardian — one-command installer (macOS / Linux)
# ============================================================================
# A thin, guided wrapper around the Hermes Agent dev setup that adds the
# Guardian threat-graph layer: it wires up the plugin, installs the OriginTrail
# DKG node CLI, bootstraps a mainnet node (read-only for users), enables the plugin, and seeds
# sensible config defaults — so onboarding is one command and dead simple.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/matic031/agent-guardian/feat/guardian/scripts/guardian-install.sh | bash
#   # or, from a clone:
#   ./scripts/guardian-install.sh [--help]
#
# Idempotent: safe to re-run. Optional steps (DKG node) never hard-fail the
# install — if they can't complete, you get clear manual next-steps and the
# rest of the install proceeds.
# ============================================================================

set -euo pipefail

# ── Configuration (override via env) ────────────────────────────────────────
REPO_URL="${GUARDIAN_REPO_URL:-https://github.com/matic031/agent-guardian.git}"
REPO_BRANCH="${GUARDIAN_REPO_BRANCH:-feat/guardian}"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
DKG_NETWORK="${GUARDIAN_DKG_NETWORK:-mainnet-base}"   # a valid dkg mainnet (mainnet-base | mainnet-gnosis). Base uses ETH for gas. No testnet.
NODE_MAJOR="${GUARDIAN_NODE_MAJOR:-22}"

# ── Colors / echo helpers (DRY) ─────────────────────────────────────────────
# ANSI-C ($'...') quoting stores REAL escape bytes, so the codes render both
# via `echo` and inside `cat <<EOF` heredocs (a plain '\033' string does not).
if [ -t 1 ]; then
    GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; CYAN=$'\033[0;36m'
    RED=$'\033[0;31m'; MINT=$'\033[38;5;115m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
    GREEN=''; YELLOW=''; CYAN=''; RED=''; MINT=''; BOLD=''; NC=''
fi

step()    { echo "${CYAN}→${NC} $1"; }
ok()      { echo "${GREEN}✓${NC} $1"; }
warn()    { echo "${YELLOW}⚠${NC} $1"; }
err()     { echo "${RED}✗${NC} $1"; }
heading() { echo ""; echo "${MINT}${BOLD}$1${NC}"; }

banner() {
    echo ""
    echo -e "${MINT}${BOLD}"
    echo "  ┌───────────────────────────────────────────────────────────┐"
    echo "  │        🛡  Umanitek Agent Guardian — installer            │"
    echo "  ├───────────────────────────────────────────────────────────┤"
    echo "  │  A threat-graph immune system for your AI agent.          │"
    echo "  │  Detect prompt injection, tool escalation & bad deps —    │"
    echo "  │  shared across agents via the OriginTrail DKG.            │"
    echo "  └───────────────────────────────────────────────────────────┘"
    echo -e "${NC}"
}

usage() {
    cat <<EOF
Umanitek Agent Guardian installer

Usage: guardian-install.sh [OPTIONS]

Options:
  --skip-dkg     Skip the DKG node install/bootstrap (plugin still installs;
                 you can bootstrap the node later — see next-steps output)
  -h, --help     Show this help and exit

The DKG node always bootstraps on mainnet — the real public threat graph.
Reading it is free; publishing costs TRAC. Guardian does not support testnet.

Environment overrides:
  GUARDIAN_REPO_URL, GUARDIAN_REPO_BRANCH, HERMES_HOME,
  GUARDIAN_NODE_MAJOR, GUARDIAN_INSTALL_DIR

This installer is idempotent — re-running it repairs a partial install.
Optional steps (the DKG node) never hard-fail; you always get guidance.
EOF
}

# ── Arg parsing ─────────────────────────────────────────────────────────────
SKIP_DKG=false
while [ $# -gt 0 ]; do
    case "$1" in
        --skip-dkg) SKIP_DKG=true; shift ;;
        -h|--help)  usage; exit 0 ;;
        *) err "Unknown option: $1"; echo; usage; exit 1 ;;
    esac
done

# ── Locate (or fetch) the repo ──────────────────────────────────────────────
# When run from a clone, use it in-place. When piped from curl, clone REPO_URL.
resolve_repo() {
    local script_src="${BASH_SOURCE[0]:-}"
    if [ -n "$script_src" ] && [ -f "$script_src" ]; then
        local d
        d="$(cd "$(dirname "$script_src")/.." && pwd)"
        if [ -f "$d/pyproject.toml" ] && [ -d "$d/plugins/guardian" ]; then
            REPO_DIR="$d"
            step "Using existing checkout at $REPO_DIR"
            return 0
        fi
    fi
    # curl | bash path — clone fresh
    if ! command -v git >/dev/null 2>&1; then
        err "git is required to download Guardian. Install git and re-run."
        exit 1
    fi
    REPO_DIR="${GUARDIAN_INSTALL_DIR:-$HOME/agent-guardian}"
    if [ -d "$REPO_DIR/.git" ]; then
        step "Updating existing clone at $REPO_DIR"
        git -C "$REPO_DIR" fetch --depth 1 origin "$REPO_BRANCH" >/dev/null 2>&1 || true
        git -C "$REPO_DIR" checkout "$REPO_BRANCH" >/dev/null 2>&1 || true
        git -C "$REPO_DIR" pull --ff-only >/dev/null 2>&1 || true
    else
        step "Cloning $REPO_URL → $REPO_DIR"
        git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$REPO_DIR"
    fi
    ok "Repo ready at $REPO_DIR"
}

# ── Prerequisite checks (guidance, not silent failure) ──────────────────────
check_git() {
    if command -v git >/dev/null 2>&1 && git --version >/dev/null 2>&1; then
        ok "git $(git --version | awk '{print $3}')"
    else
        err "git not found."
        case "$OS" in
            macos) step "Install: xcode-select --install   (or: brew install git)" ;;
            linux) step "Install: sudo apt install git   (or your distro's package manager)" ;;
        esac
        exit 1
    fi
}

check_python() {
    # Accept 3.11–3.13. Prefer python3.11/3.12/3.13, then python3.
    PY=""
    for c in python3.13 python3.12 python3.11 python3; do
        command -v "$c" >/dev/null 2>&1 || continue
        if "$c" -c 'import sys; raise SystemExit(0 if (3,11)<=sys.version_info[:2]<=(3,13) else 1)' 2>/dev/null; then
            PY="$c"; break
        fi
    done
    if [ -n "$PY" ]; then
        ok "Python $($PY -V 2>&1 | awk '{print $2}') ($PY)"
    elif command -v uv >/dev/null 2>&1; then
        # No system 3.11–3.13 (e.g. the machine only has 3.14) — that's fine:
        # uv fetches a compatible interpreter when it builds the venv.
        warn "No system Python 3.11–3.13 found — uv will provide a compatible one."
        PY=""
    else
        err "Python 3.11–3.13 not found (and uv isn't installed)."
        case "$OS" in
            macos) step "Easiest fix: brew install uv   (or: brew install python@3.12)" ;;
            linux) step "Easiest fix: curl -LsSf https://astral.sh/uv/install.sh | sh   (or: apt install python3.12 python3.12-venv)" ;;
        esac
        exit 1
    fi
}

# Node ≥ NODE_MAJOR is needed for the DKG CLI. If it's missing we auto-install
# it (best-effort) so the DKG node bootstraps without a manual detour.
_node_ok() {
    command -v node >/dev/null 2>&1 || return 1
    local maj; maj="$(node -v 2>/dev/null | sed 's/^v//' | cut -d. -f1)"
    [ "${maj:-0}" -ge "$NODE_MAJOR" ] 2>/dev/null
}

ensure_node() {
    if _node_ok; then
        ok "Node.js $(node -v) + npm $(npm -v 2>/dev/null || echo '?')"
        HAS_NODE=true
        return 0
    fi
    if [ "$SKIP_DKG" = true ]; then
        HAS_NODE=false
        return 0
    fi
    warn "Node.js $NODE_MAJOR+ not found — installing it automatically (via nvm)…"
    # nvm is the portable path on both macOS and Linux and needs no sudo.
    export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
    if [ ! -s "$NVM_DIR/nvm.sh" ]; then
        step "Installing nvm into $NVM_DIR …"
        if ! curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash >/dev/null 2>&1; then
            warn "Could not install nvm automatically."
            _node_manual_hint
            HAS_NODE=false
            return 0
        fi
    fi
    # shellcheck disable=SC1091
    . "$NVM_DIR/nvm.sh"
    step "Installing Node $NODE_MAJOR (nvm install $NODE_MAJOR) …"
    if nvm install "$NODE_MAJOR" >/dev/null 2>&1 && nvm use "$NODE_MAJOR" >/dev/null 2>&1 && _node_ok; then
        ok "Node.js $(node -v) installed via nvm"
        HAS_NODE=true
    else
        warn "Automatic Node install did not complete."
        _node_manual_hint
        HAS_NODE=false
    fi
}

_node_manual_hint() {
    case "$OS" in
        macos) step "Install Node $NODE_MAJOR manually: brew install node@$NODE_MAJOR   (or: nvm install $NODE_MAJOR)" ;;
        linux) step "Install Node $NODE_MAJOR manually: nvm install $NODE_MAJOR   (https://github.com/nvm-sh/nvm)" ;;
    esac
    step "The Guardian plugin still works; re-run this installer once Node is present to add the DKG node."
}

# ── OS / arch detection ─────────────────────────────────────────────────────
detect_os() {
    ARCH="$(uname -m)"
    case "$(uname -s)" in
        Darwin*) OS="macos" ;;
        Linux*)  OS="linux" ;;
        *) err "Unsupported OS: $(uname -s). Guardian supports macOS and Linux (use guardian-install.ps1 on Windows)."; exit 1 ;;
    esac
    ok "Detected $OS ($ARCH)"
}

# ── Python venv + editable install (reuse setup-hermes.sh when present) ──────
install_python_env() {
    heading "Installing Hermes + Guardian (Python)"
    VENV_DIR="$REPO_DIR/venv"
    # Fast idempotent re-run: if a working hermes venv already exists, don't let
    # setup-hermes.sh (which `rm -rf venv`s on every run) rebuild it from scratch.
    if [ -x "$VENV_DIR/bin/hermes" ] && "$VENV_DIR/bin/python" -c "import hermes_cli" >/dev/null 2>&1; then
        ok "Existing Hermes environment detected — reusing it"
        ensure_web_extra
        HERMES_BIN="$VENV_DIR/bin/hermes"
        return 0
    fi
    if [ -x "$REPO_DIR/setup-hermes.sh" ] || [ -f "$REPO_DIR/setup-hermes.sh" ]; then
        step "Reusing $REPO_DIR/setup-hermes.sh for the base environment..."
        # setup-hermes.sh is interactive at the end; feed 'n' to skip the wizard
        # so the one-command path stays non-blocking. It creates ./venv.
        if printf 'n\nn\n' | bash "$REPO_DIR/setup-hermes.sh"; then
            ok "Base environment ready via setup-hermes.sh"
        else
            warn "setup-hermes.sh did not complete cleanly — falling back to a minimal venv install."
            minimal_python_env
        fi
    else
        minimal_python_env
    fi
    ensure_web_extra
    HERMES_BIN="$VENV_DIR/bin/hermes"
}

# The dashboard needs fastapi/uvicorn (the `[web]` extra, already part of
# `[all]`). Verify by IMPORTING them — not by shelling pip, which a uv-built
# venv doesn't ship. Only install if genuinely missing, preferring `uv pip`.
ensure_web_extra() {
    step "Checking dashboard extras (fastapi/uvicorn) …"
    if "$VENV_DIR/bin/python" -c "import fastapi, uvicorn" >/dev/null 2>&1; then
        ok "Dashboard extras present"
        return 0
    fi
    step "Installing dashboard extras (.[web]) …"
    local installed=false
    if command -v uv >/dev/null 2>&1; then
        ( cd "$REPO_DIR" && VIRTUAL_ENV="$VENV_DIR" uv pip install -e ".[web]" >/dev/null 2>&1 ) && installed=true
    fi
    if [ "$installed" != true ]; then
        ( cd "$REPO_DIR" && "$VENV_DIR/bin/python" -m pip install -e ".[web]" >/dev/null 2>&1 ) && installed=true
    fi
    if [ "$installed" = true ] && "$VENV_DIR/bin/python" -c "import fastapi, uvicorn" >/dev/null 2>&1; then
        ok "Dashboard extras installed"
    else
        warn "Dashboard extras unavailable — 'hermes guardian dashboard' may not start. Retry: (cd $REPO_DIR && uv pip install -e '.[web]')"
    fi
}

minimal_python_env() {
    VENV_DIR="$REPO_DIR/venv"
    if [ ! -d "$VENV_DIR" ]; then
        if [ -n "$PY" ]; then
            step "Creating virtual environment ($PY) ..."
            "$PY" -m venv "$VENV_DIR"
        elif command -v uv >/dev/null 2>&1; then
            step "Creating virtual environment (uv fetches Python 3.12) ..."
            ( cd "$REPO_DIR" && uv venv --python 3.12 "$VENV_DIR" )
        else
            err "Need Python 3.11–3.13 or uv to build the environment."; exit 1
        fi
    else
        step "Reusing existing venv at $VENV_DIR"
    fi
    step "Installing agent-guardian[web] (editable) ..."
    # A uv-built venv ships no pip, so install with uv when it's available.
    if command -v uv >/dev/null 2>&1; then
        ( cd "$REPO_DIR" && VIRTUAL_ENV="$VENV_DIR" uv pip install -e ".[web]" )
    else
        "$VENV_DIR/bin/python" -m pip install --upgrade pip >/dev/null
        ( cd "$REPO_DIR" && "$VENV_DIR/bin/python" -m pip install -e ".[web]" )
    fi
    ok "Guardian installed (editable, with dashboard extras)"
}

# ── hermes command on PATH (symlink into ~/.local/bin) ───────────────────────
link_hermes() {
    local link_dir="$HOME/.local/bin"
    mkdir -p "$link_dir"
    if [ -x "$HERMES_BIN" ]; then
        ln -sf "$HERMES_BIN" "$link_dir/hermes"
        ok "Linked hermes → $link_dir/hermes"
        case ":$PATH:" in
            *":$link_dir:"*) : ;;
            *) warn "Add $link_dir to your PATH:  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
        esac
    fi
    # Prefer the venv binary for the rest of this run.
    export PATH="$VENV_DIR/bin:$link_dir:$PATH"
}

# ── DKG node CLI + bootstrap (optional, non-fatal) ──────────────────────────
install_dkg() {
    heading "Setting up the OriginTrail DKG node"
    if [ "$SKIP_DKG" = true ]; then
        warn "Skipping DKG node setup (--skip-dkg)."
        dkg_manual_hint
        return 0
    fi
    if [ "${HAS_NODE:-false}" != true ]; then
        warn "Node.js $NODE_MAJOR+ not available — skipping DKG node setup."
        dkg_manual_hint
        return 0
    fi

    if command -v dkg >/dev/null 2>&1; then
        ok "dkg CLI already installed ($(dkg --version 2>/dev/null || echo present))"
    else
        step "Installing the DKG CLI (npm i -g @origintrail-official/dkg) ..."
        if npm i -g @origintrail-official/dkg >/dev/null 2>&1; then
            ok "dkg CLI installed"
        else
            warn "Global npm install failed (permissions?). The plugin is installed; you can add the node later."
            dkg_manual_hint
            return 0
        fi
    fi

    step "Bootstrapping a $DKG_NETWORK node (dkg hermes setup --network $DKG_NETWORK) ..."
    step "  (non-interactive; reading the public threat graph is free — no funds needed)"
    if dkg hermes setup --network "$DKG_NETWORK" --no-fund; then
        ok "DKG node bootstrapped on $DKG_NETWORK"
        DKG_READY=true
    else
        warn "DKG node bootstrap did not complete. Guardian works offline (empty ruleset) until the node is up."
        dkg_manual_hint
    fi
}

# Pull the curated ruleset from the graph now, so detection is live immediately
# after install rather than after the user runs a manual sync.
sync_ruleset() {
    [ "${DKG_READY:-false}" = true ] || return 0
    heading "Syncing the threat ruleset"
    step "Pulling curated threats from the graph (hermes guardian sync) ..."
    if "$HERMES_BIN" guardian sync >/dev/null 2>&1; then
        ok "Ruleset synced — Guardian is watching with the latest threats"
    else
        warn "Initial sync skipped (the graph may be empty or the node still warming up)."
        step "It syncs automatically every few minutes; force it anytime with: hermes guardian sync"
    fi
}

dkg_manual_hint() {
    step "To set up the DKG node later:"
    echo "      npm i -g @origintrail-official/dkg"
    echo "      dkg hermes setup --network $DKG_NETWORK   # mainnet — the real public threat graph"
    echo "      # then re-run:  hermes guardian sync"
}

# ── Enable plugin + seed config defaults (idempotent) ───────────────────────
enable_and_seed() {
    heading "Enabling Guardian and seeding config defaults"

    step "Enabling the guardian plugin (hermes plugins enable guardian) ..."
    if "$HERMES_BIN" plugins enable guardian >/dev/null 2>&1; then
        ok "Plugin enabled"
    else
        warn "Could not run 'hermes plugins enable guardian' automatically."
        step "Run it yourself after the install: hermes plugins enable guardian"
    fi

    step "Seeding plugins.entries.guardian defaults into $HERMES_HOME/config.yaml ..."
    if "$VENV_DIR/bin/python" - "$HERMES_HOME/config.yaml" "$DKG_NETWORK" <<'PYEOF'
import sys, os
cfg_path, network = sys.argv[1], sys.argv[2]
try:
    import yaml
except Exception:
    print("  (PyYAML unavailable — skipping seed; run 'hermes guardian status' to configure)")
    sys.exit(0)

os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
data = {}
if os.path.exists(cfg_path):
    with open(cfg_path) as f:
        data = yaml.safe_load(f) or {}

plugins = data.setdefault("plugins", {})
entries = plugins.setdefault("entries", {})
guardian = entries.setdefault("guardian", {})
# Idempotent: only fill keys that are missing — never clobber user edits.
defaults = {
    "mode": "audit",
    # TEMPORARY: default to the STAGING graph while production is still being
    # seeded. TODO(launch): switch back to "umanitek/guardian-threats" (production).
    "context_graph_id": "umanitek/guardian-threats-staging",
    "dkg_url": "http://127.0.0.1:9200",
    "sync_interval": 300,
    "report": True,
    "daily_report_limit": 9999,
    "report_min_severity": "high",
    "block_severity": "critical",
    "dashboard_port": 9700,
    # Optional LLM reviewer — off until `hermes guardian setup-llm` fills it in.
    "llm": {"enabled": False, "provider": "", "model": "", "api_key": ""},
}
added = [k for k, v in defaults.items() if k not in guardian and guardian.setdefault(k, v) is v]
with open(cfg_path, "w") as f:
    yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
if added:
    print("  seeded: " + ", ".join(added))
else:
    print("  already configured — no changes")
PYEOF
    then
        ok "Config defaults seeded (audit mode — blocking is opt-in)"
    else
        warn "Could not seed config automatically. Run 'hermes guardian status' to verify configuration."
    fi
}

read_guardian_mode() {
    "$VENV_DIR/bin/python" - "$HERMES_HOME/config.yaml" <<'PYEOF'
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
mode = (
    data.get("plugins", {})
    .get("entries", {})
    .get("guardian", {})
    .get("mode", "audit")
)
mode = str(mode).lower()
print(mode if mode in ("audit", "block") else "audit")
PYEOF
}

write_guardian_mode() {
    local mode="$1"
    "$VENV_DIR/bin/python" - "$HERMES_HOME/config.yaml" "$mode" <<'PYEOF'
import sys, os
cfg_path, mode = sys.argv[1], sys.argv[2]
try:
    import yaml
except Exception:
    print("  (PyYAML unavailable — could not save protection mode)")
    sys.exit(1)
if mode not in ("audit", "block"):
    sys.exit(1)
os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
data = {}
if os.path.exists(cfg_path):
    with open(cfg_path) as f:
        data = yaml.safe_load(f) or {}
guardian = data.setdefault("plugins", {}).setdefault("entries", {}).setdefault("guardian", {})
guardian["mode"] = mode
guardian.setdefault("block_severity", "critical")
with open(cfg_path, "w") as f:
    yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
PYEOF
}

configure_guardian_mode() {
    heading "Choosing Guardian enforcement mode"
    local current="${GUARDIAN_MODE:-}"
    current="$(printf '%s' "$current" | tr '[:upper:]' '[:lower:]')"
    if [ "$current" != "audit" ] && [ "$current" != "block" ]; then
        current="$(read_guardian_mode 2>/dev/null || echo audit)"
    fi
    [ "$current" = "block" ] || current="audit"

    if ! { [ -r /dev/tty ] && [ -w /dev/tty ]; }; then
        GUARDIAN_SELECTED_MODE="$current"
        step "Non-interactive install — keeping Guardian in $current mode."
        return 0
    fi

    printf '  Choose how Guardian should react when it finds threats.\n' > /dev/tty
    printf '    1) Audit — log and report findings, but do not stop actions. [recommended]\n' > /dev/tty
    printf '    2) Block — stop confirmed threats at/above the configured severity.\n' > /dev/tty
    printf '  Protection mode [1/2, Enter keeps %s]: ' "$current" > /dev/tty
    local ans=""
    read -r ans < /dev/tty || ans=""
    case "$ans" in
        2|b|B|block|BLOCK|Block) GUARDIAN_SELECTED_MODE="block" ;;
        1|a|A|audit|AUDIT|Audit|"") GUARDIAN_SELECTED_MODE="$current" ;;
        *)
            warn "Unknown protection mode '$ans' — keeping $current."
            GUARDIAN_SELECTED_MODE="$current"
            ;;
    esac

    if write_guardian_mode "$GUARDIAN_SELECTED_MODE"; then
        ok "Guardian protection mode set to: $GUARDIAN_SELECTED_MODE"
    else
        warn "Could not save Guardian protection mode. Set it later in the dashboard or config.yaml."
    fi
}

# ── Auto-protect every local agent (best-effort, non-fatal) ─────────────────
# Discovers every local Hermes home + OpenClaw workspace and enables Guardian
# in each, so protection is on everywhere without per-instance setup.
attach_all_agents() {
    heading "Protecting all local agents"
    step "Discovering local Hermes homes + OpenClaw workspaces (hermes guardian attach) ..."
    if "$HERMES_BIN" guardian attach; then
        ok "Guardian attached to all discovered local agents"
    else
        warn "Could not auto-attach to every local agent (this is non-fatal)."
        step "Re-run anytime with:  hermes guardian attach"
    fi
}

# ── Optional: configure the LLM prompt-injection reviewer ───────────────────
# Interactive-only. Under `curl | bash` the script's stdin is the pipe, so we
# talk to the user through /dev/tty directly and skip cleanly when there isn't
# one (CI, non-interactive installs). Never fatal.
setup_llm() {
    heading "Optional: AI prompt-injection reviewer"
    if ! { [ -r /dev/tty ] && [ -w /dev/tty ]; }; then
        step "Non-interactive install - skipping."
        step "Set it up later with:  hermes guardian setup-llm"
        return 0
    fi
    printf '  Guardian can use an LLM (OpenAI or Anthropic) for a second opinion on\n' > /dev/tty
    printf '  prompt injection. It only flags, never blocks. Off unless you enable it.\n' > /dev/tty
    printf '  Configure it now? [y/N]: ' > /dev/tty
    local ans=""
    read -r ans < /dev/tty || ans=""
    case "$ans" in
        y|Y|yes|YES|Yes)
            # The subcommand reads /dev/tty itself for its prompts.
            if "$HERMES_BIN" guardian setup-llm; then
                ok "LLM reviewer configured"
            else
                warn "LLM setup skipped or failed (non-fatal). Re-run: hermes guardian setup-llm"
            fi
            ;;
        *)
            step "Skipped. Enable anytime with:  hermes guardian setup-llm"
            ;;
    esac
}

# ── Guided next steps (short — everything above already ran) ─────────────────
next_steps() {
    local docs_url="${REPO_URL%.git}"
    local path_note=""
    local mode="${GUARDIAN_SELECTED_MODE:-$(read_guardian_mode 2>/dev/null || echo audit)}"
    local mode_note="Audit-only by default - switch to Block anytime in the dashboard."
    if [ "$mode" = "block" ]; then
        mode_note="Block mode is on - confirmed threats at/above the block severity are stopped."
    fi
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) : ;;
        *) path_note=$'\n  First reload your shell so `hermes` is on PATH:  exec $SHELL -l' ;;
    esac
    heading "🎉 Guardian is ready — it now protects all your local agents ($mode mode)."
    cat <<EOF
${path_note}
  ${BOLD}Start your agent${NC}   — Guardian watches every tool call automatically:
       hermes

  ${BOLD}Watch it live${NC}      — findings + threat-graph status in your browser:
       hermes guardian dashboard      →  http://127.0.0.1:${GUARDIAN_DASHBOARD_PORT:-9700}

  ${BOLD}Try it${NC}            - in a hermes chat, ask it to run:
       rm -rf ~/
       Guardian flags this as an 'rm-rf-system-paths' escalation. $mode_note

  Docs & community:  $docs_url
EOF
    echo ""
}

# ── Main ────────────────────────────────────────────────────────────────────
main() {
    banner
    heading "Checking your system"
    detect_os
    check_git
    check_python
    ensure_node

    resolve_repo
    install_python_env
    link_hermes
    install_dkg
    enable_and_seed
    configure_guardian_mode
    attach_all_agents
    sync_ruleset
    setup_llm
    next_steps
}

main "$@"
