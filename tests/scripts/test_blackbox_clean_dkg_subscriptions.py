"""Behavior coverage for removing persisted stale DKG subscriptions."""

from __future__ import annotations

import importlib.util
import json
import urllib.request
from pathlib import Path

import pytest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "blackbox-clean-dkg-subscriptions.py"
)
SPEC = importlib.util.spec_from_file_location(
    "blackbox_clean_dkg_subscriptions", SCRIPT_PATH
)
if SPEC is None or SPEC.loader is None:
    raise ImportError(f"Failed to load {SCRIPT_PATH}")
CLEANER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLEANER)


class _Response:
    def __init__(self, payload: dict[str, object]):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class _Opener:
    def __init__(self, subscriptions, dormant=(), unsubscribe_payload=None):
        self.subscriptions = list(subscriptions)
        self.dormant = list(dormant)
        self.unsubscribe_payload = unsubscribe_payload
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if request.get_method() == "GET":
            return _Response(
                {
                    "count": len(self.subscriptions),
                    "subscriptions": [
                        {"contextGraphId": graph, "subscribed": True}
                        for graph in self.subscriptions
                    ],
                    "rehydration": {"dormantIds": self.dormant},
                }
            )
        body = json.loads(request.data.decode("utf-8"))
        graph = body["contextGraphId"]
        if self.unsubscribe_payload is not None:
            return _Response(self.unsubscribe_payload)
        self.subscriptions = [item for item in self.subscriptions if item != graph]
        return _Response(
            {
                "unsubscribed": graph,
                "subscribed": False,
                "coreHosted": False,
            }
        )


def _home(
    tmp_path: Path,
    token: str = "secret-admin-token",
    configured: tuple[str, ...] = ("umanitek/blackbox-threats-staging",),
) -> Path:
    home = tmp_path / "dkg"
    home.mkdir()
    (home / "auth.token").write_text(
        f"# private\n{token}\n", encoding="utf-8"
    )
    (home / "config.json").write_text(
        json.dumps({"contextGraphs": list(configured)}), encoding="utf-8"
    )
    return home


def test_unsubscribes_active_stale_graphs_with_admin_auth(tmp_path):
    opener = _Opener(
        [
            "umanitek/blackbox-threats-staging",
            "umanitek/guardian-threats-staging",
            "new-test",
        ]
    )

    removed = CLEANER.clean_subscriptions(
        _home(tmp_path),
        "http://127.0.0.1:9320/",
        "umanitek/blackbox-threats-staging",
        opener=opener,
    )

    assert removed == ["umanitek/guardian-threats-staging", "new-test"]
    assert len(opener.requests) == 3
    list_request, list_timeout = opener.requests[0]
    assert list_request.get_method() == "GET"
    assert list_request.full_url.endswith("/api/context-graph/subscriptions")
    assert list_timeout == 15
    for request, timeout in opener.requests[1:]:
        assert request.full_url == "http://127.0.0.1:9320/api/context-graph/unsubscribe"
        assert request.get_method() == "POST"
        assert request.headers["Authorization"] == "Bearer secret-admin-token"
        assert timeout == 15
    assert opener.subscriptions == ["umanitek/blackbox-threats-staging"]


def test_preserves_explicitly_selected_legacy_graph(tmp_path):
    opener = _Opener(
        [
            "umanitek/guardian-threats-staging",
            "custom/private-graph",
            "umanitek/guardian-threats",
        ]
    )

    removed = CLEANER.clean_subscriptions(
        _home(
            tmp_path,
            configured=(
                "umanitek/guardian-threats-staging",
                "custom/private-graph",
            ),
        ),
        "http://127.0.0.1:9320",
        "umanitek/guardian-threats-staging",
        opener=opener,
    )

    assert removed == ["umanitek/guardian-threats"]
    bodies = [json.loads(request.data) for request, _ in opener.requests[1:]]
    assert bodies == [{"contextGraphId": "umanitek/guardian-threats"}]
    assert opener.subscriptions == [
        "umanitek/guardian-threats-staging",
        "custom/private-graph",
    ]


def test_no_stale_subscriptions_does_not_reset_persisted_state(tmp_path):
    opener = _Opener(["umanitek/blackbox-threats-staging"])

    removed = CLEANER.clean_subscriptions(
        _home(tmp_path),
        "http://127.0.0.1:9320",
        "umanitek/blackbox-threats-staging",
        opener=opener,
    )

    assert removed == []
    assert len(opener.requests) == 1
    assert opener.requests[0][0].get_method() == "GET"


def test_dormant_stale_rows_do_not_block_active_cleanup(tmp_path):
    opener = _Opener(
        [
            "umanitek/blackbox-threats-staging",
            "active/stale-graph",
        ],
        dormant=["old/private-graph"],
    )

    removed = CLEANER.clean_subscriptions(
        _home(tmp_path),
        "http://127.0.0.1:9320",
        "umanitek/blackbox-threats-staging",
        opener=opener,
    )

    assert removed == ["active/stale-graph"]
    assert len(opener.requests) == 2
    assert opener.dormant == ["old/private-graph"]


def test_rejects_non_loopback_daemon_before_network_call(tmp_path):
    opener = _Opener([])

    try:
        CLEANER.clean_subscriptions(
            _home(tmp_path),
            "https://example.com:9320",
            "umanitek/blackbox-threats-staging",
            opener=opener,
        )
    except CLEANER.CleanupError as exc:
        assert "direct loopback DKG URL" in str(exc)
    else:
        raise AssertionError("admin maintenance must reject a remote URL")
    assert opener.requests == []


def test_missing_admin_token_fails_without_network_call(tmp_path):
    opener = _Opener([])

    try:
        CLEANER.clean_subscriptions(
            tmp_path / "missing", "http://127.0.0.1:9320", "selected", opener=opener
        )
    except CLEANER.CleanupError as exc:
        assert "could not read DKG admin token" in str(exc)
    else:
        raise AssertionError("missing token should fail")
    assert opener.requests == []


def test_default_local_opener_disables_ambient_proxies(monkeypatch):
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)

    ambient_opener = urllib.request.build_opener()
    ambient_proxy_handlers = [
        handler
        for handler in ambient_opener.handlers
        if isinstance(handler, urllib.request.ProxyHandler)
    ]
    opener = CLEANER._build_local_opener()
    proxy_handlers = [
        handler
        for handler in opener.handlers
        if isinstance(handler, urllib.request.ProxyHandler)
    ]

    assert any(
        handler.proxies.get("http") == "http://127.0.0.1:9"
        for handler in ambient_proxy_handlers
    )
    assert proxy_handlers == []


@pytest.mark.parametrize(
    "payload",
    (
        {},
        {"error": "not removed"},
        {"unsubscribed": "another/graph", "subscribed": False},
        {"unsubscribed": "stale/graph"},
        {"unsubscribed": "stale/graph", "subscribed": True},
    ),
)
def test_unsubscribe_requires_exact_daemon_confirmation(tmp_path, payload):
    opener = _Opener(["stale/graph"], unsubscribe_payload=payload)

    with pytest.raises(CLEANER.CleanupError, match="did not confirm"):
        CLEANER.clean_subscriptions(
            _home(tmp_path),
            "http://127.0.0.1:9320",
            "umanitek/blackbox-threats-staging",
            opener=opener,
        )

    assert opener.subscriptions == ["stale/graph"]
