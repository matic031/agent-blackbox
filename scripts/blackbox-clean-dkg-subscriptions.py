#!/usr/bin/env python3
"""Remove stale Blackbox DKG subscriptions without deleting graph data."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path


class CleanupError(RuntimeError):
    """Raised when the local DKG daemon cannot retire a subscription."""


def _load_token(dkg_home: Path) -> str:
    path = dkg_home.expanduser() / "auth.token"
    try:
        token = next(
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    except (OSError, StopIteration) as exc:
        raise CleanupError(f"could not read DKG admin token from {path}") from exc
    return token


def clean_subscriptions(
    dkg_home: Path,
    daemon_url: str,
    selected_graph: str,
    *,
    opener: urllib.request.OpenerDirector | None = None,
) -> list[str]:
    """Unsubscribe active graphs absent from this isolated node's config."""
    token = _load_token(dkg_home)
    client = opener or urllib.request.build_opener()
    base_url = daemon_url.rstrip("/")
    try:
        config = json.loads(
            (dkg_home.expanduser() / "config.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError) as exc:
        raise CleanupError(f"could not read DKG config from {dkg_home}") from exc
    configured = config.get("contextGraphs")
    allowed = {
        str(graph)
        for graph in (configured if isinstance(configured, list) else [])
        if str(graph).strip()
    }
    allowed.add(selected_graph)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    list_request = urllib.request.Request(
        base_url + "/api/context-graph/subscriptions", headers=headers
    )
    try:
        with client.open(list_request, timeout=15) as response:
            listing = json.loads(response.read().decode("utf-8") or "{}")
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise CleanupError(f"could not list DKG subscriptions: {exc}") from exc

    active = listing.get("subscriptions")
    if not isinstance(active, list):
        raise CleanupError("DKG subscription response did not contain a list")
    stale = []
    for row in active:
        graph = row.get("contextGraphId") if isinstance(row, dict) else None
        if isinstance(graph, str) and graph not in allowed:
            stale.append(graph)

    endpoint = base_url + "/api/context-graph/unsubscribe"
    removed: list[str] = []
    for graph in stale:
        request = urllib.request.Request(
            endpoint,
            data=json.dumps({"contextGraphId": graph}).encode("utf-8"),
            method="POST",
            headers={
                **headers,
                "Content-Type": "application/json",
            },
        )
        try:
            with client.open(request, timeout=15) as response:
                payload = json.loads(response.read().decode("utf-8") or "{}")
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise CleanupError(f"could not unsubscribe {graph}: {exc}") from exc
        if payload.get("subscribed") is True:
            raise CleanupError(f"DKG kept stale graph subscribed: {graph}")
        if graph not in removed:
            removed.append(graph)
    return removed


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 3:
        print(
            f"usage: {Path(sys.argv[0]).name} <dkg-home> <daemon-url> <selected-graph>",
            file=sys.stderr,
        )
        return 2
    try:
        removed = clean_subscriptions(Path(args[0]), args[1], args[2])
    except CleanupError as exc:
        print(f"blackbox-clean-dkg-subscriptions: {exc}", file=sys.stderr)
        return 1
    if removed:
        print("blackbox-clean-dkg-subscriptions: removed " + ", ".join(removed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
