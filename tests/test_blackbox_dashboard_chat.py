import subprocess
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from plugins.blackbox import attach
from plugins.blackbox.dashboard import server


def test_dashboard_public_graph_uses_vm_verified_ruleset_rows(monkeypatch):
    from plugins.blackbox import audit, config, dkg_client, ruleset

    cfg = SimpleNamespace(
        mode="audit",
        context_graph_id="umanitek/blackbox-threats-staging",
        dkg_url="http://127.0.0.1:9320",
        dkg_home="/tmp/blackbox-dkg",
        dkg_bin="/tmp/dkg",
        sync_interval=60,
    )

    class FakeRuleset:
        synced_at = 123.0

        def counts(self):
            return {"injection": 1, "dependency": 2}

        def source_count(self, source):
            return {"public": 2, "community": 1}.get(source, 0)

        def iter_rules(self):
            yield "dependency", {
                "identifier": "dep:npm:verified-one@1.0.0",
                "severity": "critical",
                "name": "Verified one",
                "source": "public",
            }
            yield "dependency", {
                "identifier": "dep:npm:verified-two@2.0.0",
                "severity": "high",
                "name": "Verified two",
                "source": "public",
            }
            yield "injection", {
                "identifier": "injection:community-only",
                "severity": "medium",
                "name": "Community only",
                "source": "community",
            }

    fake_ruleset = FakeRuleset()
    monkeypatch.setattr(config, "load_blackbox_config", lambda: cfg)
    monkeypatch.setattr(ruleset, "get", lambda _cfg=None: fake_ruleset)
    monkeypatch.setattr(audit, "count_findings", lambda: 0)
    monkeypatch.setattr(dkg_client.DkgClient, "reachable", lambda self, timeout=None: False)
    monkeypatch.setattr(
        dkg_client.DkgClient,
        "query",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("public dashboard rows must not query full threats directly from VM")
        ),
    )

    client = TestClient(server.create_app())

    status = client.get("/api/graph-status").json()
    assert status["curated"] == 2
    assert status["sync_progress"]["public"] == {
        "count": 2,
        "state": "ready",
        "label": "VM synced",
    }

    public = client.get("/api/graph?tier=public&limit=1&offset=1").json()
    assert public == {
        "tier": "public",
        "threats": [{
            "identifier": "dep:npm:verified-two@2.0.0",
            "category": "dependency",
            "severity": "high",
            "name": "Verified two",
        }],
        "total": 2,
        "offset": 1,
        "limit": 1,
        "partial": False,
    }


def test_ruleset_sync_once_refreshes_without_directly_requeueing_catchup():
    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox-dkg"
        context_graph_id = "umanitek/guardian-threats-staging"
        curator_peer_id = "curator-peer"

    events = []

    class FakeClient:
        def __init__(self, *, url, dkg_home):
            self.url = url
            self.dkg_home = dkg_home
            events.append(("client", url, dkg_home))

        def subscribe_context_graph(self, cg_id):
            raise AssertionError("dashboard sync must leave catch-up throttling to ruleset.refresh")

        def request_join(self, cg_id, curator_peer_id):
            raise AssertionError("dashboard sync must leave join throttling to ruleset.refresh")

    class FakeRuleset:
        def counts(self):
            return {"injection": 1, "dependency": 4}

        def source_count(self, source):
            return 0

    class FakeRulesetModule:
        @staticmethod
        def refresh(cfg, client):
            events.append(("refresh", cfg.context_graph_id, client.url, client.dkg_home))
            return FakeRuleset()

    first = server._sync_ruleset_once(lambda: Cfg(), FakeClient, FakeRulesetModule)
    second = server._sync_ruleset_once(lambda: Cfg(), FakeClient, FakeRulesetModule)

    assert first == {"total": 5, "community": 0}
    assert second == first
    assert events == [
        ("client", "http://127.0.0.1:9320", "/tmp/blackbox-dkg"),
        ("refresh", "umanitek/guardian-threats-staging", "http://127.0.0.1:9320", "/tmp/blackbox-dkg"),
        ("client", "http://127.0.0.1:9320", "/tmp/blackbox-dkg"),
        ("refresh", "umanitek/guardian-threats-staging", "http://127.0.0.1:9320", "/tmp/blackbox-dkg"),
    ]


def test_dashboard_zero_graph_count_settles_after_first_payload():
    html = (Path(server.__file__).parent / "static" / "index.html").read_text(
        encoding="utf-8"
    )

    assert "if (value == null) return true;" in html
    assert "Treating every reachable zero" in html
    assert "return !(lastStatus && lastStatus.node_reachable === false);" not in html


def test_dashboard_retries_empty_ruleset_promptly():
    assert server._RULESET_EMPTY_RETRY_SEC <= 30


def test_blackbox_dashboard_chat_starts_session(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="hello\n", stderr="\nsession_id: sid-1\n")

    monkeypatch.setattr(server.shutil, "which", lambda name: "/bin/hermes")
    monkeypatch.setattr(server.subprocess, "run", fake_run)
    monkeypatch.setattr(attach, "_repo_root", lambda: Path("/tmp/repo"))

    client = TestClient(server.create_app())
    res = client.post("/api/blackbox-chat", json={"message": "hi"})

    assert res.status_code == 200
    assert res.json() == {"ok": True, "answer": "hello", "session_id": "sid-1"}
    assert calls == [["/bin/hermes", "blackbox", "chat", "--query", "hi", "--quiet", "--pass-session-id"]]


def test_blackbox_dashboard_chat_resumes_session(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="follow-up\n", stderr="\nsession_id: sid-1\n")

    monkeypatch.setattr(server.shutil, "which", lambda name: "/bin/hermes")
    monkeypatch.setattr(server.subprocess, "run", fake_run)
    monkeypatch.setattr(attach, "_repo_root", lambda: Path("/tmp/repo"))

    client = TestClient(server.create_app())
    res = client.post("/api/blackbox-chat", json={"message": "which of these?", "session_id": "sid-1"})

    assert res.status_code == 200
    assert res.json() == {"ok": True, "answer": "follow-up", "session_id": "sid-1"}
    assert calls == [
        [
            "/bin/hermes",
            "blackbox",
            "chat",
            "--query",
            "which of these?",
            "--quiet",
            "--pass-session-id",
            "--resume",
            "sid-1",
        ]
    ]


def test_attach_targets_include_unavailable_supported_agents(monkeypatch):
    def fake_attach_all(*, hermes=True, openclaw=True, dry_run=False):
        if hermes and not openclaw:
            return {
                "hermes": [
                    {
                        "kind": "hermes",
                        "target": "/tmp/home/.hermes",
                        "already": True,
                    }
                ]
            }
        if openclaw and not hermes:
            return {"openclaw": []}
        return {}

    monkeypatch.setattr(attach, "attach_all", fake_attach_all)

    client = TestClient(server.create_app())
    res = client.get("/api/attach-targets")

    assert res.status_code == 200
    targets = res.json()["targets"]
    hermes = next(t for t in targets if t["kind"] == "hermes")
    openclaw = next(t for t in targets if t["kind"] == "openclaw")
    assert hermes["available"] is True
    assert hermes["protected"] is True
    assert openclaw["available"] is False
    assert "OpenClaw was not detected" in openclaw["disabled_reason"]


def test_attach_targets_do_not_duplicate_errored_supported_agents(monkeypatch):
    def fake_attach_all(*, hermes=True, openclaw=True, dry_run=False):
        if hermes and not openclaw:
            return {"hermes": []}
        if openclaw and not hermes:
            return {
                "openclaw": [
                    {
                        "kind": "openclaw",
                        "target": "/tmp/.openclaw",
                        "error": "cannot read openclaw.json",
                    }
                ]
            }
        return {}

    monkeypatch.setattr(attach, "attach_all", fake_attach_all)

    client = TestClient(server.create_app())
    res = client.get("/api/attach-targets")

    assert res.status_code == 200
    openclaw_rows = [t for t in res.json()["targets"] if t["kind"] == "openclaw"]
    assert len(openclaw_rows) == 1
    assert openclaw_rows[0]["available"] is False
    assert openclaw_rows[0]["disabled_reason"] == "cannot read openclaw.json"
