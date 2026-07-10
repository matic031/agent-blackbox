import subprocess
from pathlib import Path

from fastapi.testclient import TestClient

from plugins.blackbox import attach
from plugins.blackbox.dashboard import server


def test_ruleset_sync_once_subscribes_and_refreshes():
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
            events.append(("subscribe", cg_id))

        def request_join(self, cg_id, curator_peer_id):
            events.append(("join", cg_id, curator_peer_id))

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

    total = server._sync_ruleset_once(lambda: Cfg(), FakeClient, FakeRulesetModule)

    assert total == {"total": 5, "community": 0}
    assert events == [
        ("client", "http://127.0.0.1:9320", "/tmp/blackbox-dkg"),
        ("subscribe", "umanitek/guardian-threats-staging"),
        ("refresh", "umanitek/guardian-threats-staging", "http://127.0.0.1:9320", "/tmp/blackbox-dkg"),
    ]


def test_ruleset_sync_once_requests_join_when_subscribe_fails():
    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox-dkg"
        context_graph_id = "umanitek/guardian-threats-staging"
        curator_peer_id = "curator-peer"

    events = []

    class FakeClient:
        def __init__(self, *, url, dkg_home):
            pass

        def subscribe_context_graph(self, cg_id):
            events.append(("subscribe", cg_id))
            raise RuntimeError("not on the allowlist")

        def request_join(self, cg_id, curator_peer_id):
            events.append(("join", cg_id, curator_peer_id))

    class FakeRuleset:
        def counts(self):
            return {"injection": 0}

        def source_count(self, source):
            return 0

    class FakeRulesetModule:
        @staticmethod
        def refresh(cfg, client):
            events.append(("refresh", cfg.context_graph_id))
            return FakeRuleset()

    assert server._sync_ruleset_once(lambda: Cfg(), FakeClient, FakeRulesetModule) == {"total": 0, "community": 0}
    assert events == [
        ("subscribe", "umanitek/guardian-threats-staging"),
        ("join", "umanitek/guardian-threats-staging", "curator-peer"),
        ("refresh", "umanitek/guardian-threats-staging"),
    ]


def test_dashboard_approver_skips_open_access_graph():
    approved = []

    class OpenClient:
        def list_context_graph_agents(self, cg_id):
            return []

        def list_join_requests(self, cg_id):
            return [{"agentAddress": "0x" + "1" * 40}]

        def approve_join(self, cg_id, addr):
            approved.append(addr)

    assert server._approve_joins_once(OpenClient(), "umanitek/guardian-threats-staging") == []
    assert approved == []


def test_dashboard_approver_still_admits_legacy_private_graph():
    approved = []

    class PrivateClient:
        def list_context_graph_agents(self, cg_id):
            return ["0x" + "c" * 40]

        def list_join_requests(self, cg_id):
            return [{"agentAddress": "0x" + "1" * 40, "name": "fresh-node"}]

        def approve_join(self, cg_id, addr):
            approved.append(addr)

    out = server._approve_joins_once(PrivateClient(), "some/private-cg")

    assert out == [{"agentAddress": "0x" + "1" * 40, "name": "fresh-node"}]
    assert approved == ["0x" + "1" * 40]


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
