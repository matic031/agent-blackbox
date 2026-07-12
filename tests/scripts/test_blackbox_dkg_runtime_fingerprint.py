"""Tests for durable Blackbox DKG runtime activation fingerprints."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "blackbox-dkg-runtime-fingerprint.py"
)
SPEC = importlib.util.spec_from_file_location(
    "blackbox_dkg_runtime_fingerprint", SCRIPT_PATH
)
if SPEC is None or SPEC.loader is None:
    raise ImportError(f"Failed to load {SCRIPT_PATH}")
FINGERPRINTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FINGERPRINTER)


def _make_runtime(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    cli_dir = tmp_path / "dkg-cli"
    dkg_home = tmp_path / "dkg-home"
    cli_package = cli_dir / "packages" / "cli"
    agent_package = cli_dir / "packages" / "agent"
    (cli_package / "dist" / "daemon").mkdir(parents=True)
    (agent_package / "dist" / "sync").mkdir(parents=True)
    dkg_home.mkdir()
    (cli_package / "package.json").write_text(
        '{"name":"@origintrail-official/dkg","version":"10.0.6"}\n',
        encoding="utf-8",
    )
    (cli_package / "dist" / "daemon" / "lifecycle.js").write_text(
        "export const lifecycle = 1;\n",
        encoding="utf-8",
    )
    (agent_package / "package.json").write_text(
        '{"name":"@origintrail-official/dkg-agent","version":"10.0.6"}\n',
        encoding="utf-8",
    )
    (agent_package / "dist" / "sync" / "requester.js").write_text(
        "export const requester = 1;\n",
        encoding="utf-8",
    )
    (dkg_home / "config.json").write_text(
        '{"contextGraphs":["umanitek/blackbox-threats-staging"]}\n',
        encoding="utf-8",
    )
    dkg_bin = tmp_path / "dkg"
    dkg_bin.write_text("launcher-v1\n", encoding="utf-8")
    node_bin = Path(sys.executable)
    return cli_dir, dkg_home, node_bin, dkg_bin


def test_fingerprint_is_stable_and_tracks_runtime_inputs(tmp_path, monkeypatch):
    runtime = _make_runtime(tmp_path)
    first = FINGERPRINTER.compute_fingerprint(*runtime)
    second = FINGERPRINTER.compute_fingerprint(*runtime)

    assert len(first) == 64
    assert first == second

    config = runtime[1] / "config.json"
    config.write_text('{"contextGraphs":["changed"]}\n', encoding="utf-8")
    config_changed = FINGERPRINTER.compute_fingerprint(*runtime)
    assert config_changed != first

    monkeypatch.setenv("DKG_SYNC_TOTAL_TIMEOUT_MS", "2400000")
    environment_changed = FINGERPRINTER.compute_fingerprint(*runtime)
    assert environment_changed != config_changed


def test_interrupted_restart_stays_stale_across_next_invocation(tmp_path):
    runtime = _make_runtime(tmp_path)
    marker = runtime[1] / ".blackbox-runtime.sha256"
    loaded = FINGERPRINTER.compute_fingerprint(*runtime)
    FINGERPRINTER.record_fingerprint(marker, loaded)

    # Simulate a rebuilt checkout followed by a crash before daemon restart.
    requester = runtime[0] / "packages" / "agent" / "dist" / "sync" / "requester.js"
    requester.write_text("export const requester = 2;\n", encoding="utf-8")
    desired_first_retry = FINGERPRINTER.compute_fingerprint(*runtime)
    desired_second_retry = FINGERPRINTER.compute_fingerprint(*runtime)

    assert desired_first_retry == desired_second_retry
    assert marker.read_text(encoding="utf-8").strip() == loaded
    assert marker.read_text(encoding="utf-8").strip() != desired_second_retry

    # Only a successful daemon start records the newly loaded runtime.
    FINGERPRINTER.record_fingerprint(marker, desired_second_retry)
    assert marker.read_text(encoding="utf-8").strip() == desired_second_retry
    if os.name != "nt":
        assert os.stat(marker).st_mode & 0o777 == 0o600


def test_cli_compute_and_atomic_record(tmp_path, capsys):
    runtime = _make_runtime(tmp_path)
    assert FINGERPRINTER.main(["compute", *(str(path) for path in runtime)]) == 0
    fingerprint = capsys.readouterr().out.strip()
    marker = runtime[1] / ".blackbox-runtime.sha256"

    assert FINGERPRINTER.main(["record", str(marker), fingerprint]) == 0
    assert marker.read_text(encoding="utf-8") == fingerprint + "\n"


def test_invalid_record_value_fails_closed(tmp_path, capsys):
    marker = tmp_path / "marker"

    assert FINGERPRINTER.main(["record", str(marker), "not-a-sha"]) == 1
    output = capsys.readouterr()

    assert "64-character SHA-256" in output.err
    assert not marker.exists()


def test_record_works_when_fchmod_is_unavailable(tmp_path, monkeypatch):
    marker = tmp_path / "marker"
    monkeypatch.delattr(FINGERPRINTER.os, "fchmod", raising=False)

    FINGERPRINTER.record_fingerprint(marker, "a" * 64)

    assert marker.read_text(encoding="utf-8") == "a" * 64 + "\n"


def test_wait_for_runtime_rejects_old_commit_then_accepts_built_commit():
    expected = "4a59421180c509c0fc3d90a9e409191c554fea74"
    calls = 0

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal calls
            calls += 1
            commit = "6ffc0c9b" if calls == 1 else "4a594211"
            body = json.dumps({"commit": commit}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = FINGERPRINTER.wait_for_runtime(
            f"http://127.0.0.1:{server.server_port}", expected, 3
        )
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()

    assert payload["commit"] == "4a594211"
    assert calls >= 2


def test_snapshot_limits_are_part_of_runtime_fingerprint(tmp_path, monkeypatch):
    runtime = _make_runtime(tmp_path)
    first = FINGERPRINTER.compute_fingerprint(*runtime)
    monkeypatch.setenv("DKG_SYNC_RESPONDER_GLOBAL_SNAPSHOT_ROW_LIMIT", "1600000")
    assert FINGERPRINTER.compute_fingerprint(*runtime) != first
