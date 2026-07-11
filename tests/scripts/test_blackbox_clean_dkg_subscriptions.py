"""Behavior coverage for removing persisted stale DKG subscriptions."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


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
    def __init__(self, subscriptions):
        self.subscriptions = subscriptions
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
                }
            )
        body = json.loads(request.data.decode("utf-8"))
        return _Response(
            {
                "unsubscribed": body["contextGraphId"],
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


def test_unsubscribes_retired_graphs_with_admin_auth(tmp_path):
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
        assert request.full_url == (
            "http://127.0.0.1:9320/api/context-graph/unsubscribe"
        )
        assert request.get_method() == "POST"
        assert request.headers["Authorization"] == "Bearer secret-admin-token"
        assert timeout == 15


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
