#!/usr/bin/env python3
"""Compute and atomically record the DKG runtime loaded by Blackbox.

The installer uses this durable fingerprint to distinguish a daemon that has
actually been restarted onto the current checkout and config from files that
were updated on disk after an interrupted install.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


RUNTIME_ENV_DEFAULTS = {
    "DKG_CATCHUP_MAX_CONCURRENT_PEERS": "1",
    "DKG_SYNC_PAGE_TIMEOUT_MS": "180000",
    "DKG_SYNC_TOTAL_TIMEOUT_MS": "1200000",
    "DKG_SYNC_MIN_GRAPH_BUDGET_MS": "120000",
    "DKG_SYNC_RESPONDER_PER_SNAPSHOT_ROW_LIMIT": "500000",
    "DKG_SYNC_RESPONDER_GLOBAL_SNAPSHOT_ROW_LIMIT": "1500000",
}


class FingerprintError(RuntimeError):
    """Raised when the installed runtime cannot be fingerprinted safely."""


def _add_bytes(digest: "hashlib._Hash", label: str, data: bytes) -> None:
    label_bytes = label.encode("utf-8")
    digest.update(len(label_bytes).to_bytes(8, "big"))
    digest.update(label_bytes)
    digest.update(len(data).to_bytes(8, "big"))
    digest.update(data)


def _runtime_files(cli_dir: Path, dkg_home: Path, dkg_bin: Path) -> list[Path]:
    monorepo_cli = cli_dir / "packages" / "cli"
    cli_package = (
        monorepo_cli
        if (monorepo_cli / "package.json").is_file()
        else cli_dir / "node_modules" / "@origintrail-official" / "dkg"
    )
    config = dkg_home / "config.json"
    required = [config, cli_package / "package.json", dkg_bin]
    missing = [path for path in required if not path.is_file()]
    if missing:
        raise FingerprintError(f"required runtime file is missing: {missing[0]}")

    agent_dists = []
    monorepo_agent_dist = cli_dir / "packages" / "agent" / "dist"
    if monorepo_agent_dist.is_dir():
        agent_dists.append(monorepo_agent_dist)
    agent_dists.extend(sorted(cli_dir.glob("node_modules/**/dkg-agent/dist")))
    if not agent_dists:
        raise FingerprintError(f"dkg-agent dist not found under {cli_dir}")

    files = set(required)
    files.update((cli_package / "dist").rglob("*.js"))
    for dist in agent_dists:
        package_json = dist.parent / "package.json"
        if not package_json.is_file():
            raise FingerprintError(f"dkg-agent package metadata is missing: {package_json}")
        files.add(package_json)
        files.update(dist.rglob("*.js"))
    return sorted(files, key=lambda path: str(path.resolve()))


def compute_fingerprint(
    cli_dir: Path,
    dkg_home: Path,
    node_bin: Path,
    dkg_bin: Path,
) -> str:
    cli_dir = cli_dir.expanduser().resolve()
    dkg_home = dkg_home.expanduser().resolve()
    node_bin = node_bin.expanduser().resolve()
    dkg_bin = dkg_bin.expanduser().resolve()
    if not node_bin.is_file():
        raise FingerprintError(f"Node.js executable is missing: {node_bin}")
    try:
        node_version = subprocess.run(
            [str(node_bin), "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise FingerprintError(f"could not identify Node.js runtime: {exc}") from exc
    if not node_version:
        raise FingerprintError("Node.js returned an empty version")

    digest = hashlib.sha256()
    _add_bytes(digest, "format", b"blackbox-dkg-runtime-v1")
    _add_bytes(digest, "node-path", str(node_bin).encode("utf-8"))
    _add_bytes(digest, "node-version", node_version.encode("utf-8"))
    for name, default in sorted(RUNTIME_ENV_DEFAULTS.items()):
        value = os.environ.get(name) or default
        _add_bytes(digest, f"env:{name}", value.encode("utf-8"))
    for path in _runtime_files(cli_dir, dkg_home, dkg_bin):
        _add_bytes(digest, f"file:{path.resolve()}", path.read_bytes())
    return digest.hexdigest()


def record_fingerprint(marker: Path, fingerprint: str) -> None:
    normalized = fingerprint.strip().lower()
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise FingerprintError("runtime fingerprint must be a 64-character SHA-256 value")
    marker = marker.expanduser().resolve()
    marker.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{marker.name}.", dir=marker.parent)
    temporary_path = Path(temporary)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(normalized + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, marker)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary_path.unlink(missing_ok=True)
        raise


def wait_for_runtime(
    daemon_url: str,
    expected_commit: str,
    timeout_seconds: float,
) -> dict[str, object]:
    """Wait until the daemon API serves the checkout that was just built."""
    expected = expected_commit.strip().lower()
    if len(expected) < 7 or any(ch not in "0123456789abcdef" for ch in expected):
        raise FingerprintError("expected commit must be a Git hexadecimal revision")
    if timeout_seconds <= 0:
        raise FingerprintError("runtime wait timeout must be positive")

    status_url = daemon_url.rstrip("/") + "/api/status"
    deadline = time.monotonic() + timeout_seconds
    last_detail = "daemon API has not responded"
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request(
                status_url,
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=min(3.0, timeout_seconds)) as response:
                payload = json.loads(response.read().decode("utf-8"))
            actual = str(
                payload.get("commit") or payload.get("commitShort") or ""
            ).strip().lower()
            if actual and (expected.startswith(actual) or actual.startswith(expected)):
                return payload
            last_detail = f"daemon serves commit {actual or 'unknown'}, expected {expected[:12]}"
        except (OSError, UnicodeError, json.JSONDecodeError, urllib.error.URLError) as exc:
            last_detail = str(exc)
        time.sleep(0.5)
    raise FingerprintError(
        f"DKG runtime did not become ready at {status_url} within "
        f"{timeout_seconds:g}s ({last_detail})"
    )


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if len(args) == 5 and args[0] == "compute":
            print(compute_fingerprint(*(Path(value) for value in args[1:])))
            return 0
        if len(args) == 3 and args[0] == "record":
            record_fingerprint(Path(args[1]), args[2])
            return 0
        if len(args) == 4 and args[0] == "wait":
            payload = wait_for_runtime(args[1], args[2], float(args[3]))
            actual = str(payload.get("commit") or payload.get("commitShort") or "")
            print(actual)
            return 0
    except (OSError, ValueError, FingerprintError) as exc:
        print(f"blackbox-dkg-runtime-fingerprint: {exc}", file=sys.stderr)
        return 1
    print(
        f"usage: {Path(sys.argv[0]).name} compute <dkg-cli-dir> <dkg-home> "
        "<node-bin> <dkg-bin>\n"
        f"       {Path(sys.argv[0]).name} record <marker> <sha256>\n"
        f"       {Path(sys.argv[0]).name} wait <daemon-url> <expected-commit> <timeout-seconds>",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
