"""Release contract: curated public VM only; community SWM is coming soon."""

from argparse import Namespace
from pathlib import Path

from fastapi.testclient import TestClient

from plugins.blackbox import cli, config, constants, detection, hooks, ruleset
from plugins.blackbox.dashboard import server


DASHBOARD_HTML = (
    Path(__file__).resolve().parents[2]
    / "plugins"
    / "blackbox"
    / "dashboard"
    / "static"
    / "index.html"
)


def test_refresh_queries_only_verifiable_memory(monkeypatch, tmp_path):
    views = []

    class Client:
        def query(self, _query, _cg, **kwargs):
            views.append(kwargs["view"])
            return []

    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    monkeypatch.setattr(ruleset, "_memory_cache", None)
    ruleset.refresh(config.BlackboxConfig(), Client())

    assert views
    assert set(views) == {constants.VIEW_VERIFIABLE_MEMORY}


def test_cached_community_rules_are_discarded():
    cached = {
        "injection": [
            {"identifier": "public", "source": "public", "pattern_src": "safe"},
            {"identifier": "community", "source": "community", "pattern_src": "unsafe"},
        ],
        "graph_threats": [
            {"identifier": "public", "source": "public"},
            {"identifier": "community", "source": "community"},
        ],
    }

    restored = ruleset._deserialize(cached)

    assert [r["identifier"] for r in restored.injection] == ["public"]
    assert [r["identifier"] for r in restored.graph_threats] == ["public"]


def test_config_cannot_enable_threat_sharing(monkeypatch):
    monkeypatch.setenv("BLACKBOX_REPORT", "true")
    cfg = config.load_blackbox_config()
    assert cfg.report is False
    assert cfg.daily_report_limit == 0


def test_dashboard_settings_fallback_keeps_community_sharing_off():
    html = DASHBOARD_HTML.read_text(encoding="utf-8")

    assert 'report: false, report_min_severity: "high"' in html
    assert "out.report = false;" in html
    assert 'report: true, report_min_severity: "high"' not in html
    assert "out.report = data.report !== false;" not in html


def test_report_command_submits_nothing(monkeypatch, capsys):
    monkeypatch.setattr(cli, "DkgClient", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("report must not create a DKG client")
    ))

    assert cli._cmd_report(Namespace()) == 2
    assert "coming soon" in capsys.readouterr().out.lower()


def test_detection_audit_never_shares(monkeypatch):
    shared = []

    class Client:
        def share_knowledge_asset(self, *args):
            shared.append(args)

    monkeypatch.setattr(hooks.audit, "recently_reported", lambda _identifier: False)
    monkeypatch.setattr(hooks.audit, "mark_reported", lambda _identifier: None)
    monkeypatch.setattr(hooks.audit, "write_private_audit_ka", lambda *args: None)
    monkeypatch.setattr(hooks, "DkgClient", lambda *args, **kwargs: Client())
    hooks._report_and_audit(
        config.BlackboxConfig(report=True),
        "pre_tool_call",
        [detection.Finding(
            identifier="candidate", category="escalation", severity="critical",
            title="candidate", confirmed=False, source="community",
        )],
        {},
    )

    assert shared == []


def test_dashboard_sync_never_requests_private_join(monkeypatch):
    events = []

    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox"
        context_graph_id = "legacy/private"

    class Client:
        def __init__(self, **_kwargs):
            pass

        def subscribe_context_graph(self, cg_id):
            events.append(("subscribe", cg_id))

        def request_join(self, *_args):
            raise AssertionError("private join must never be requested")

    class Rules:
        @staticmethod
        def refresh(_cfg, _client):
            return ruleset.Ruleset()

    monkeypatch.setattr(server.sync_state, "read", lambda: {})
    result = server._sync_ruleset_once(lambda: Cfg(), Client, Rules)

    assert result == {"total": 0, "public": 0, "community": 0}
    assert events == [("subscribe", "legacy/private")]


def test_dashboard_community_surfaces_are_static_coming_soon(monkeypatch):
    app = server.create_app()
    with TestClient(app) as client:
        graph = client.get("/api/graph?tier=community").json()
        reports = client.get("/api/reports").json()
        threat = client.get("/api/threat?tier=community&identifier=x").json()

    assert graph == {
        "tier": "community", "threats": [], "total": 0, "offset": 0,
        "limit": 1000, "partial": False, "coming_soon": True,
    }
    assert reports == {"reports": [], "coming_soon": True, "sharing_enabled": False}
    assert threat["coming_soon"] is True
