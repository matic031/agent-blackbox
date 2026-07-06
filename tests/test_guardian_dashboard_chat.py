import subprocess
from pathlib import Path

from fastapi.testclient import TestClient

from plugins.guardian import attach
from plugins.guardian.dashboard import server


def test_guardian_dashboard_chat_starts_session(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="hello\n", stderr="\nsession_id: sid-1\n")

    monkeypatch.setattr(server.shutil, "which", lambda name: "/bin/hermes")
    monkeypatch.setattr(server.subprocess, "run", fake_run)
    monkeypatch.setattr(attach, "_repo_root", lambda: Path("/tmp/repo"))

    client = TestClient(server.create_app())
    res = client.post("/api/guardian-chat", json={"message": "hi"})

    assert res.status_code == 200
    assert res.json() == {"ok": True, "answer": "hello", "session_id": "sid-1"}
    assert calls == [["/bin/hermes", "guardian", "chat", "--query", "hi", "--quiet", "--pass-session-id"]]


def test_guardian_dashboard_chat_resumes_session(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="follow-up\n", stderr="\nsession_id: sid-1\n")

    monkeypatch.setattr(server.shutil, "which", lambda name: "/bin/hermes")
    monkeypatch.setattr(server.subprocess, "run", fake_run)
    monkeypatch.setattr(attach, "_repo_root", lambda: Path("/tmp/repo"))

    client = TestClient(server.create_app())
    res = client.post("/api/guardian-chat", json={"message": "which of these?", "session_id": "sid-1"})

    assert res.status_code == 200
    assert res.json() == {"ok": True, "answer": "follow-up", "session_id": "sid-1"}
    assert calls == [
        [
            "/bin/hermes",
            "guardian",
            "chat",
            "--query",
            "which of these?",
            "--quiet",
            "--pass-session-id",
            "--resume",
            "sid-1",
        ]
    ]
