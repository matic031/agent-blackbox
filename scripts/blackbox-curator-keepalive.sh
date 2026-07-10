#!/bin/bash
# ============================================================================
# Agent Blackbox — curator DKG node keepalive / auto-restart
# ============================================================================
# Keeps the Blackbox-managed DKG node up and self-healing. It fixes the
# crash-loop we hit where, after an UNCLEAN shutdown, Oxigraph's WAL recovery of
# a large store takes longer than the daemon's ~15s startup readiness timeout —
# so the daemon declares failure and restarts, killing Oxigraph mid-recovery,
# forever. This wrapper:
#
#   1. SAFE-RECOVERS Oxigraph before every daemon start: it launches Oxigraph
#      standalone, waits (uninterrupted) until it actually listens (recovery
#      complete), then stops it with SIGTERM so the store is CHECKPOINTED. The
#      daemon's own Oxigraph then opens the clean store in seconds — no timeout,
#      no crash-loop.
#   2. AUTO-RESTARTS: polls /api/status and, on death, re-runs the safe sequence.
#   3. Shuts down CLEANLY on SIGINT/SIGTERM (so the next start is fast).
#
# Usage (curator machine):
#   scripts/blackbox-curator-keepalive.sh            # run in foreground / screen
#   nohup scripts/blackbox-curator-keepalive.sh >> ~/.hermes/logs/curator-keepalive.log 2>&1 &
#
# All knobs are env-overridable; defaults target the Blackbox curator node.
# ============================================================================

set -uo pipefail

DKG_HOME="${BLACKBOX_DKG_HOME:-$HOME/.dkg}"
# Resolve the dkg binary robustly: a login screen may not have the nvm-global
# `dkg` on PATH, so fall back to nvm globals then the Blackbox-owned CLI. Using a
# bare "dkg" here is what caused `nohup: dkg: No such file or directory`.
resolve_dkg_bin() {
    if [ -n "${BLACKBOX_DKG_BIN:-}" ] && [ -x "$BLACKBOX_DKG_BIN" ]; then echo "$BLACKBOX_DKG_BIN"; return; fi
    local c; c="$(command -v dkg 2>/dev/null)"; if [ -n "$c" ]; then echo "$c"; return; fi
    for p in "$HOME"/.nvm/versions/node/*/bin/dkg "$HOME"/.hermes/blackbox/dkg-cli/node_modules/.bin/dkg /usr/local/bin/dkg /opt/homebrew/bin/dkg; do
        [ -x "$p" ] && { echo "$p"; return; }
    done
    echo dkg
}
DKG_BIN="$(resolve_dkg_bin)"

# Pin the Node runtime to the one the dkg CLI was installed under. The CLI's
# shebang is `#!/usr/bin/env node`, so `dkg start` runs under whatever `node` is
# first on PATH. If that differs from the install's Node (e.g. a login/screen
# shell finds Homebrew node v20 while the nvm-global dkg was built for v22), the
# node-ui DashboardDB's native better-sqlite3 fails to load with a
# NODE_MODULE_VERSION mismatch and the daemon crashes on EVERY start — a silent
# crash-loop. nvm keeps `node` beside `dkg` in the same bin dir, so prepend it.
pin_dkg_node_runtime() {
    local bindir node_bin
    bindir="$(dirname "$DKG_BIN")"
    node_bin="${BLACKBOX_DKG_NODE_BIN:-$bindir/node}"
    if [ -x "$node_bin" ]; then
        PATH="$(dirname "$node_bin"):$PATH"; export PATH
        log "pinned node runtime $("$node_bin" -v 2>/dev/null) from $(dirname "$node_bin")"
    else
        log "WARN: no node beside $DKG_BIN; daemon will use PATH node ($(command -v node 2>/dev/null || echo none)) — a NODE_MODULE_VERSION mismatch may crash it"
    fi
}

API_URL="${BLACKBOX_DKG_DAEMON_URL:-http://127.0.0.1:9320}"
OXI_STORE="${BLACKBOX_DKG_OXI_STORE:-$DKG_HOME/oxigraph-data}"
OXI_BIND="${BLACKBOX_DKG_OXI_BIND:-127.0.0.1:7878}"
# The open-community flags (curator serves SWM to any peer; admission open).
export DKG_NETWORK_ADMISSION_MODE="${DKG_NETWORK_ADMISSION_MODE:-open}"
export DKG_SWM_SYNC_OPEN="${DKG_SWM_SYNC_OPEN:-1}"
POLL_SECS="${BLACKBOX_KEEPALIVE_POLL_SECS:-20}"
RECOVER_MAX_SECS="${BLACKBOX_KEEPALIVE_RECOVER_MAX_SECS:-600}"

log() { echo "[keepalive $(date '+%H:%M:%S')] $*"; }

# Find the Oxigraph binary the node uses (cached under the DKG home).
oxi_binary() {
    local b
    b="$(ls -1 "$DKG_HOME"/oxigraph/oxigraph-* 2>/dev/null | head -1)"
    echo "${BLACKBOX_DKG_OXI_BIN:-$b}"
}

# Health = the API PORT is listening (process alive), NOT that /api/status is
# fast. Under the join-request flood the HTTP handler blocks for 10s+ while the
# node is perfectly alive and still serving p2p/approvals — probing /api/status
# (curl -fsS -m5) therefore false-positived "down" and restarted a healthy node
# every ~45s, which only added load and killed in-flight approvals. A closed
# port is the real crash signal (e.g. the better-sqlite3 ABI death), and that
# still triggers a restart. Keep a generous curl as a secondary "definitely
# alive" shortcut so a fast API answer also counts.
api_up() {
    local port="${API_URL##*:}"
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 && return 0
    curl -s -o /dev/null -m 15 "$API_URL/api/status" 2>/dev/null
}

# Stop ONLY this node, never another DKG node on the same machine. Order:
#   1. `dkg stop` (home-specific — signals via $DKG_HOME/daemon.pid; also stops
#      the supervisor so it can't respawn the worker mid-recovery).
#   2. Kill the worker recorded in $DKG_HOME/daemon.pid (curator-specific).
#   3. Kill any Oxigraph bound to THIS store path (uniquely identifiable, and the
#      lock holder that causes the crash-loop). The staging node's Oxigraph uses
#      a different --location, so it is never matched.
stop_node() {
    local hard="${1:-}"
    local sig="-TERM"; [ "$hard" = "hard" ] && sig="-9"
    DKG_HOME="$DKG_HOME" "$DKG_BIN" stop >/dev/null 2>&1
    sleep 2
    local dpid; dpid="$(cat "$DKG_HOME/daemon.pid" 2>/dev/null)"
    [ -n "$dpid" ] && kill $sig "$dpid" 2>/dev/null
    # Oxigraph is identified by its unique --location <OXI_STORE> in argv.
    for pid in $(pgrep -f -- "--location $OXI_STORE" 2>/dev/null); do kill $sig "$pid" 2>/dev/null; done
    sleep 1
}

# Launch Oxigraph standalone, wait until it LISTENS (recovery done), then SIGTERM
# it for a clean checkpoint. Returns 0 on success.
safe_recover_oxigraph() {
    local oxi; oxi="$(oxi_binary)"
    if [ -z "$oxi" ] || [ ! -x "$oxi" ]; then
        log "no Oxigraph binary found under $DKG_HOME/oxigraph — skipping pre-recovery"
        return 0
    fi
    log "pre-recovering store $OXI_STORE (uninterrupted)…"
    "$oxi" serve --location "$OXI_STORE" --bind "$OXI_BIND" >/tmp/blackbox-oxi-recover.log 2>&1 &
    local oxpid=$!
    local waited=0
    while ! (echo >"/dev/tcp/${OXI_BIND%%:*}/${OXI_BIND##*:}") 2>/dev/null; do
        sleep 3; waited=$((waited+3))
        if ! kill -0 "$oxpid" 2>/dev/null; then
            log "Oxigraph exited during recovery: $(tail -1 /tmp/blackbox-oxi-recover.log)"; return 1
        fi
        if [ "$waited" -ge "$RECOVER_MAX_SECS" ]; then
            log "recovery exceeded ${RECOVER_MAX_SECS}s — killing and continuing"; kill -9 "$oxpid" 2>/dev/null; return 1
        fi
    done
    log "store recovered in ${waited}s — clean checkpoint (SIGTERM)"
    kill -TERM "$oxpid" 2>/dev/null
    local i=0; while kill -0 "$oxpid" 2>/dev/null && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done
    kill -9 "$oxpid" 2>/dev/null
    sleep 2
    return 0
}

start_node() {
    log "clearing orphans + stale state, pre-recovering, starting daemon…"
    stop_node hard
    rm -f "$DKG_HOME/daemon.pid" "$DKG_HOME/api.port" 2>/dev/null
    safe_recover_oxigraph
    ( cd "$DKG_HOME" && DKG_HOME="$DKG_HOME" nohup "$DKG_BIN" start >>"$HOME/.hermes/logs/curator-daemon.log" 2>&1 & )
    # wait up to ~3 min for the (now-fast) store open + agent init
    local i=0
    until api_up; do sleep 5; i=$((i+1)); [ $i -gt 36 ] && { log "daemon did not answer $API_URL within 180s"; return 1; }; done
    log "daemon UP at $API_URL"
    return 0
}

cleanup() { log "shutting down cleanly (SIGTERM to node)…"; "$DKG_BIN" stop >/dev/null 2>&1 || stop_node; exit 0; }
trap cleanup INT TERM

mkdir -p "$HOME/.hermes/logs"
log "keepalive starting — home=$DKG_HOME url=$API_URL admission=$DKG_NETWORK_ADMISSION_MODE swm_open=$DKG_SWM_SYNC_OPEN"
pin_dkg_node_runtime
if ! api_up; then start_node || log "initial start failed; will retry in loop"; fi
# Require several CONSECUTIVE misses before restarting. A single transient
# /api/status failure (node busy under sync load, a brief GC pause, a slow
# store checkpoint) must never hard-restart a healthy node — that flap-kills
# the curator, which is worse than no keepalive.
FAILS=0
FAIL_THRESHOLD="${BLACKBOX_KEEPALIVE_FAIL_THRESHOLD:-3}"
while true; do
    sleep "$POLL_SECS"
    if api_up; then FAILS=0; continue; fi
    FAILS=$((FAILS+1))
    log "node not answering ($FAILS/$FAIL_THRESHOLD)"
    if [ "$FAILS" -ge "$FAIL_THRESHOLD" ]; then
        log "node DOWN for $FAILS consecutive checks — restarting"
        start_node && FAILS=0 || log "restart failed; retrying next cycle"
    fi
done
