#!/usr/bin/env python3
"""Keep operator-owned Blackbox curator settings present across restarts."""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from pathlib import Path


NETWORK_AGENT_PROFILE_GRAPH = "did:dkg:context-graph:agents"


def _atomic_write_text(path: Path, text: str) -> None:
    """Replace ``path`` without changing its permissions."""
    original_mode = stat.S_IMODE(path.stat().st_mode)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, original_mode)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def ensure_graph_auto_approval(config_path: Path, graph_id: str) -> bool:
    """Ensure ``graph_id`` is configured and auto-approved; preserve all else."""
    with config_path.open(encoding="utf-8") as handle:
        config = json.load(handle)
    if not isinstance(config, dict):
        raise ValueError(f"DKG config must be a JSON object: {config_path}")

    changed = False
    for key in ("contextGraphs", "autoApproveJoinRequests"):
        current = config.get(key)
        if current is None:
            current = []
        if not isinstance(current, list) or not all(isinstance(item, str) for item in current):
            raise ValueError(f"DKG config field {key!r} must be a string array")
        if graph_id not in current:
            config[key] = [*current, graph_id]
            changed = True

    desired = {
        "syncOnConnectEnabled": False,
        "syncReconcilerEnabled": False,
    }
    for key, value in desired.items():
        if config.get(key) != value:
            config[key] = value
            changed = True

    promote_queue = config.get("promoteQueue")
    if promote_queue is None:
        promote_queue = {}
    if not isinstance(promote_queue, dict):
        raise ValueError("DKG config field 'promoteQueue' must be an object")
    updated_queue = {**promote_queue, "workerConcurrency": 1, "pollIntervalMs": 1000}
    if promote_queue != updated_queue:
        config["promoteQueue"] = updated_queue
        changed = True

    if not changed:
        return False

    _atomic_write_text(config_path, json.dumps(config, indent=2) + "\n")
    return True


def ensure_network_profiles_used_for_auto_approval(dkg_agent_dist: Path) -> bool:
    """Repair the DKG 10.0.6 auto-approval profile lookup.

    Network agent profiles are authenticated and stored in the public
    ``agents`` context graph.  The released auto-approval handler calls
    ``loadEncryptionKeyTriplesByAgent()``, but that loader only searches the
    curator's private local-agent graph.  A valid new user's key is therefore
    invisible at the exact point where admission needs it.

    Extend the loader's two proof-checked queries (active keys and
    revocations) to search both graphs.  Exact guards keep this fail-closed on
    DKG versions whose implementation no longer matches the affected release.
    """
    registry_path = dkg_agent_dist / "dkg-agent-registry.js"
    lifecycle_path = dkg_agent_dist / "dkg-agent-lifecycle.js"
    registry = registry_path.read_text(encoding="utf-8")
    lifecycle = lifecycle_path.read_text(encoding="utf-8")

    if (
        "autoApproveJoinRequests?.includes(contextGraphId)" not in lifecycle
        or "await this.loadEncryptionKeyTriplesByAgent()" not in lifecycle
    ):
        raise ValueError(
            "DKG join auto-approval implementation is not the supported 10.0.6 shape"
        )

    function_start = registry.find("    async loadEncryptionKeyTriplesByAgent() {")
    function_end = registry.find("    async persistAgentToStore(", function_start)
    if function_start < 0 or function_end < 0:
        raise ValueError("DKG encryption-key loader was not found")

    loader = registry[function_start:function_end]
    original = "          GRAPH <${graph}> {"
    repaired = (
        f"          VALUES ?sourceGraph {{ <${{graph}}> <{NETWORK_AGENT_PROFILE_GRAPH}> }}\n"
        "          GRAPH ?sourceGraph {"
    )
    repaired_count = loader.count(repaired)
    if repaired_count == 2:
        return False
    if repaired_count != 0 or loader.count(original) != 2:
        raise ValueError("DKG encryption-key loader does not match the supported query shape")

    loader = loader.replace(original, repaired)
    updated = registry[:function_start] + loader + registry[function_end:]
    _atomic_write_text(registry_path, updated)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ensure a curator keeps graph-scoped DKG join auto-approval enabled."
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--graph", required=True)
    parser.add_argument(
        "--dkg-agent-dist",
        type=Path,
        help="Optional @origintrail-official/dkg-agent/dist directory to repair",
    )
    args = parser.parse_args()
    if not args.graph.strip():
        parser.error("--graph must not be empty")
    changed = ensure_graph_auto_approval(args.config, args.graph)
    if args.dkg_agent_dist:
        changed = ensure_network_profiles_used_for_auto_approval(args.dkg_agent_dist) or changed
    print("updated" if changed else "already configured")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
