#!/usr/bin/env python3
"""Open the DKG relay gates so a Blackbox node can reach peers via ANY relay.

DKG isolates relayed connections to a node's own small preferred-relay set
(relay-network-policy.js) and quarantines flapping relays (relay-flap-guard.js).
On the public mainnet-base relays that means a member and the curator, reached
through *different* relays, drop each other's relayed connection in ~300ms —
far too short to move the ~270k SWM rows, so members read 0. Neither gate has a
config/env off-switch (isolation is hard-tied to config.networkIdentity, which
mainnet requires), so the only fix is patching the two dkg-core functions.

Idempotent (detects the patched behaviour, not just its own marker), backs up
each file once, and self-locates the dkg-core the local `dkg` runs. Run it on
EVERY node (curator + members): the two relay patches are safe everywhere (they
only open relay reachability, no data is exposed). Pass --serve-open ONLY on the
curator to also force the umanitek open-SWM serve (request-authorize.js) — that
turns the private graph into an open-read pool, so never do it on a node holding
private graphs you don't want served.

Wiring: called from scripts/blackbox-install.sh and the curator keepalive, so a
`dkg` upgrade that wipes the dist patches gets them re-applied on next start.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path


def _resolve_dkg_core_dist(explicit: str | None) -> Path | None:
    """Find <dkg>/node_modules/@origintrail-official/dkg-core/dist."""
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    env = os.environ.get("BLACKBOX_DKG_CORE_DIST")
    if env:
        candidates.append(Path(env).expanduser())
    dkg_bin = shutil.which("dkg")
    bin_paths = [dkg_bin] if dkg_bin else []
    home = Path.home()
    bin_paths += [str(p) for p in home.glob(".nvm/versions/node/*/bin/dkg")]
    bin_paths += [str(p) for p in home.glob(".hermes/*/dkg-cli/node_modules/.bin/dkg")]
    for b in bin_paths:
        try:
            real = Path(b).resolve()
        except OSError:
            continue
        pkg = real.parent.parent  # .../dkg/dist/cli.js -> .../dkg
        candidates.append(pkg / "node_modules" / "@origintrail-official" / "dkg-core" / "dist")
    candidates += list(home.glob("**/node_modules/@origintrail-official/dkg-core/dist"))
    for c in candidates:
        if c and (c / "relay-network-policy.js").is_file():
            return c
    return None


# Each entry: (file, done-signature, exact original, replacement). done-signature
# is a string unique to the patched form (matches this script's output AND the
# earlier hand-applied patch), so re-runs are a no-op either way.
def _patches(dist: Path):
    net = dist / "relay-network-policy.js"
    flap = dist / "relay-flap-guard.js"
    # request-authorize lives in the sibling dkg-agent package.
    auth = dist.parent.parent / "dkg-agent" / "dist" / "sync" / "auth" / "request-authorize.js"

    relay = [
        (
            net,
            "void activeRelayPeerIds;",
            """export function buildActiveRelayPathGate(activeRelayPeerIds, log = () => { }) {
    const short = (id) => id.slice(-8);
    return ({ direction, relayPeerId, remotePeerId, addr }) => {
        if (activeRelayPeerIds.has(relayPeerId))
            return false;
        log(`Network isolation: denying ${direction} relayed connection ` +
            `relay=${short(relayPeerId)}${remotePeerId ? ` remote=${short(remotePeerId)}` : ''}` +
            `${addr ? ` addr=${addr}` : ''}`);
        return true;
    };
}""",
            """export function buildActiveRelayPathGate(activeRelayPeerIds, log = () => { }) {
    // BLACKBOX_RELAY_OPEN: network isolation disabled — allow relayed connections
    // through ANY relay so members/curator reach each other over public relays.
    void activeRelayPeerIds;
    void log;
    return () => false;
}""",
        ),
        (
            flap,
            "denyInboundRelayedConnection: () => false",
            """export function buildRelayFlapConnectionGater(guard, log = () => { }) {
    const short = (id) => id.slice(-8);
    const denyRelayedPath = (direction, relayPeerId, remotePeerId, addr) => {
        const result = guard.checkRelayedConnection({ relayPeerId, remotePeerId });
        if (!result.deny)
            return false;
        if (result.shouldLog) {
            const remainingSeconds = Math.ceil((result.quarantineMsRemaining ?? 0) / 1000);
            log(`Relay flap guard: denying ${direction} relayed connection ` +
                `remote=${short(remotePeerId)} relay=${short(relayPeerId)} ` +
                `quarantineRemaining=${remainingSeconds}s${addr ? ` addr=${addr}` : ''}`);
        }
        return true;
    };
    return {
        denyInboundRelayedConnection: (relay, remotePeer) => denyRelayedPath('inbound', relay.toString(), remotePeer.toString()),
        denyDialMultiaddr: (multiaddr) => {
            const addr = multiaddr.toString();
            const parsed = parseCircuitRelayPeerIds(addr);
            if (!parsed)
                return false;
            if (!parsed.remotePeerId)
                return false;
            return denyRelayedPath('outbound', parsed.relayPeerId, parsed.remotePeerId, addr);
        },
    };
}""",
            """export function buildRelayFlapConnectionGater(guard, log = () => { }) {
    // BLACKBOX_RELAY_OPEN: flap-guard denials disabled — flaky public relays get
    // quarantined (120s+, exponential) and block the bulk SWM transfer; never deny.
    void guard;
    void log;
    return {
        denyInboundRelayedConnection: () => false,
        denyDialMultiaddr: () => false,
    };
}""",
        ),
    ]
    serve = [
        (
            auth,
            "const SWM_SYNC_OPEN = true",
            "const SWM_SYNC_OPEN = /^(1|true|open|yes|on)$/i.test(process.env.DKG_SWM_SYNC_OPEN ?? '');",
            "// BLACKBOX_RELAY_OPEN: forced on — the daemon supervisor filters env, so an\n"
            "// exported DKG_SWM_SYNC_OPEN never reaches this worker; hard-enable so the\n"
            "// curator serves members whose node sends an unsigned/unbound sync envelope.\n"
            "const SWM_SYNC_OPEN = true || /^(1|true|open|yes|on)$/i.test(process.env.DKG_SWM_SYNC_OPEN ?? '');",
        ),
    ]
    return relay, serve


def _apply(entry) -> str:
    path, done_sig, original, replacement = entry
    if not path.is_file():
        return f"MISSING  {path}"
    text = path.read_text(encoding="utf-8")
    if done_sig in text:
        return f"already  {path.name}"
    if original not in text:
        return f"SKIP(no-match, version?)  {path.name}"
    backup = path.with_suffix(path.suffix + ".bak-blackbox-relay-open")
    if not backup.exists():
        backup.write_text(text, encoding="utf-8")
    path.write_text(text.replace(original, replacement, 1), encoding="utf-8")
    return f"patched  {path.name}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Open DKG relay gates for Blackbox.")
    ap.add_argument("--dist", help="dkg-core dist dir (else auto-detect)")
    ap.add_argument("--serve-open", action="store_true",
                    help="CURATOR ONLY: also force open-SWM serve (opens private graph reads)")
    args = ap.parse_args()

    dist = _resolve_dkg_core_dist(args.dist)
    if not dist:
        print("patch-dkg-relay-open: could not locate dkg-core dist; set BLACKBOX_DKG_CORE_DIST",
              file=sys.stderr)
        return 2
    print(f"patch-dkg-relay-open: {dist}")
    relay, serve = _patches(dist)
    results = [_apply(e) for e in relay]
    if args.serve_open:
        results += [_apply(e) for e in serve]
    for r in results:
        print(f"  {r}")
    if any(r.startswith("SKIP(no-match") for r in results):
        print("  note: a no-match usually means a different dkg version — patch that "
              "function by hand or update this script.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
