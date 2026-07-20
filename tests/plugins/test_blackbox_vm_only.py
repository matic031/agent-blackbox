"""Release contract: curated public VM only; community SWM is coming soon."""

import time
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
OPENCLAW_DIR = Path(__file__).resolve().parents[2] / "integrations" / "openclaw"


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


def test_openclaw_runtime_is_vm_only_and_reporting_cannot_be_reenabled():
    ruleset_src = (OPENCLAW_DIR / "src" / "ruleset.ts").read_text(encoding="utf-8")
    config_src = (OPENCLAW_DIR / "src" / "config.ts").read_text(encoding="utf-8")
    client_src = (OPENCLAW_DIR / "src" / "dkgClient.ts").read_text(encoding="utf-8")

    tiers = ruleset_src.split("const TIERS", 1)[1].split("];", 1)[0]
    assert '["verifiable-memory", "public"]' in tiers
    assert "shared-working-memory" not in tiers
    assert 'view: DkgView = "verifiable-memory"' in client_src
    assert "report: false" in config_src
    assert "dailyReportLimit: 0" in config_src
    assert "report: bool(env.BLACKBOX_REPORT)" not in config_src
    assert 'row.source !== "community"' in ruleset_src


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


def test_dashboard_does_not_query_rules_while_durable_catchup_runs(monkeypatch):
    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox"
        context_graph_id = "public/graph"

    class Client:
        def __init__(self, **_kwargs):
            pass

        def subscribe_context_graph(self, _cg_id):
            raise AssertionError("active catch-up must not be resubscribed")

        def catchup_status(self, _cg_id):
            return {"status": "running", "includeSharedMemory": False}

    cached = ruleset.Ruleset()

    class Rules:
        @staticmethod
        def peek(_cfg):
            return cached

        @staticmethod
        def refresh(_cfg, _client):
            raise AssertionError("VM must not be queried during durable catch-up")

    monkeypatch.setattr(server.sync_state, "read", lambda: {})

    assert server._sync_ruleset_once(lambda: Cfg(), Client, Rules) == {
        "total": 0,
        "public": 0,
        "community": 0,
    }


def test_dashboard_keeps_old_rules_and_advances_verified_count_during_sync(monkeypatch):
    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox"
        context_graph_id = "public/replacement"

    class Client:
        def __init__(self, **_kwargs):
            raise AssertionError("active replacement must use the verified cache")

    cached = ruleset.Ruleset(
        dependency={
            "npm:last-good": {
                "identifier": "npm:last-good",
                "source": "public",
            }
        },
        graph_threats=[
            {
                "identifier": "npm:last-good",
                "source": "public",
            }
        ],
        synced_at=time.time() - 60,
    )

    class Rules:
        @staticmethod
        def peek(_cfg):
            return cached

    monkeypatch.setattr(
        server.sync_state,
        "read",
        lambda: {"status": "running", "public_entries": 10},
    )

    assert server._sync_ruleset_once(lambda: Cfg(), Client, Rules) == {
        "total": 10,
        "public": 10,
        "community": 0,
    }


def test_dashboard_subscribes_at_most_once_when_status_is_unavailable(monkeypatch):
    calls = []

    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox"
        context_graph_id = "public/one-shot-subscribe"

    class Client:
        def __init__(self, **_kwargs):
            pass

        def catchup_status(self, _cg_id):
            return {}

        def subscribe_context_graph(self, cg_id):
            calls.append(cg_id)
            return {}

    class Rules:
        @staticmethod
        def refresh(_cfg, _client):
            return ruleset.Ruleset()

    monkeypatch.setattr(server.sync_state, "read", lambda: {})
    server._subscription_attempts.discard(Cfg.context_graph_id)

    server._sync_ruleset_once(lambda: Cfg(), Client, Rules)
    server._sync_ruleset_once(lambda: Cfg(), Client, Rules)

    assert calls == [Cfg.context_graph_id]


def test_dashboard_does_not_resubscribe_terminal_catchup_without_job_id(monkeypatch):
    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox"
        context_graph_id = "public/terminal-no-job-id"
        sync_interval = 60

    class Client:
        def __init__(self, **_kwargs):
            pass

        def catchup_status(self, _cg_id):
            return {"status": "done"}

        def subscribe_context_graph(self, _cg_id):
            raise AssertionError("terminal catch-up must not be resubscribed")

    cached = ruleset.Ruleset(
        dependency={
            "npm:ready": {
                "identifier": "npm:ready",
                "source": "public",
            }
        },
        graph_threats=[
            {
                "identifier": "npm:ready",
                "source": "public",
            }
        ],
        synced_at=time.time(),
    )

    class Rules:
        @staticmethod
        def peek(_cfg):
            return cached

        @staticmethod
        def refresh(_cfg, _client):
            raise AssertionError("fresh terminal cache must not be refreshed")

    monkeypatch.setattr(server.sync_state, "read", lambda: {})
    server._subscription_attempts.discard(Cfg.context_graph_id)

    assert server._sync_ruleset_once(lambda: Cfg(), Client, Rules)["public"] == 1


def test_dashboard_reuses_fresh_large_ruleset_without_querying_blazegraph(monkeypatch):
    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox"
        context_graph_id = "public/fresh-cache"
        sync_interval = 60

    class Client:
        def __init__(self, **_kwargs):
            pass

        def catchup_status(self, _cg_id):
            return {"status": "done", "jobId": "settled-job"}

        def subscribe_context_graph(self, _cg_id):
            raise AssertionError("settled catch-up must not be resubscribed")

    cached = ruleset.Ruleset(
        dependency={
            "npm:demo": {
                "identifier": "npm:demo",
                "source": "public",
            }
        },
        graph_threats=[
            {
                "identifier": "npm:demo",
                "source": "public",
            }
        ],
        synced_at=time.time(),
    )

    class Rules:
        @staticmethod
        def peek(_cfg):
            return cached

        @staticmethod
        def refresh(_cfg, _client):
            raise AssertionError("fresh cache must not trigger a full VM scan")

    monkeypatch.setattr(server.sync_state, "read", lambda: {})
    server._subscription_attempts.discard(Cfg.context_graph_id)

    assert server._sync_ruleset_once(lambda: Cfg(), Client, Rules) == {
        "total": 1,
        "public": 1,
        "community": 0,
    }


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
