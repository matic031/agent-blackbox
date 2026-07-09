import subprocess
from pathlib import Path

from fastapi.testclient import TestClient

from plugins.blackbox import attach
from plugins.blackbox.dashboard import server


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
