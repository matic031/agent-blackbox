#!/usr/bin/env python3
"""Remove stale Blackbox DKG subscriptions without deleting graph data."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class CleanupError(RuntimeError):
    """Raised when the local DKG daemon cannot retire a subscription."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never forward the node-admin bearer token through an HTTP redirect."""

    def redirect_request(self, *_args, **_kwargs):
        return None


def _build_local_opener() -> urllib.request.OpenerDirector:
    """Ignore ambient proxies and redirects for token-bearing loopback calls."""
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
    )


def _local_daemon_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise CleanupError(
            "subscription maintenance requires a direct loopback DKG URL"
        )
    return value.rstrip("/")


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
    client = opener or _build_local_opener()
    base_url = _local_daemon_url(daemon_url)
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

    if not stale:
        return []

    endpoint = base_url + "/api/context-graph/unsubscribe"
    removed: list[str] = []
    for graph in list(dict.fromkeys(stale)):
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
        if (
            payload.get("unsubscribed") != graph
            or payload.get("subscribed") is not False
        ):
            raise CleanupError(
                f"DKG did not confirm stale graph removal: {graph}"
            )
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
