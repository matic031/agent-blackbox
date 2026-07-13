"""Regression coverage for the Blackbox installer's LLM reviewer setup."""

from __future__ import annotations

import json
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "scripts" / "blackbox-install.sh"
INSTALL_PS1 = REPO_ROOT / "scripts" / "blackbox-install.ps1"


def _extract_function_body(name: str) -> str:
    text = INSTALL_SH.read_text()
    match = re.search(
        rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"{name}() not found in scripts/blackbox-install.sh"
    return match["body"]


def _extract_unix_config_writer() -> str:
    text = INSTALL_SH.read_text(encoding="utf-8")
    match = re.search(
        r"^ensure_blackbox_dkg_config\(\)\s*\{.*?<<'PYEOF'\n"
        r"(?P<code>.*?)^PYEOF\n\s*\)\"",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert match is not None
    return match["code"]


def _extract_powershell_function_body(name: str) -> str:
    text = INSTALL_PS1.read_text(encoding="utf-8")
    match = re.search(
        rf"^function\s+{re.escape(name)}\s*\{{\s*\n(?P<body>.*?)^\}}",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"{name} not found in scripts/blackbox-install.ps1"
    return match["body"]


def test_llm_setup_reuses_existing_config_without_prompting() -> None:
    body = _extract_function_body("setup_llm")

    assert "blackbox setup-llm --configure" not in body
    assert "blackbox setup-llm --auto" in body
    assert "existing Blackbox, Hermes, or OpenClaw LLM config" in body
    assert "LLM reviewer not configured; this is optional" in body


def test_llm_setup_is_optional_not_install_blocking() -> None:
    body = _extract_function_body("setup_llm")

    assert "LLM setup skipped" not in body
    assert "blackbox setup-llm --auto" in body
    assert "BLACKBOX_LLM_INCOMPLETE=true" not in body
    assert "BLACKBOX_INSTALL_INCOMPLETE=true" not in body
    assert not re.search(r"<\s*/dev/tty", body), "installer must not prompt for optional LLM setup"


def test_next_steps_only_blocks_on_threat_graph_sync() -> None:
    body = _extract_function_body("next_steps")

    assert "BLACKBOX_THREAT_GRAPH_INCOMPLETE" in body
    assert "BLACKBOX_LLM_INCOMPLETE" not in body
    assert "The LLM reviewer is not configured yet." not in body


def test_hermes_setup_defaults_to_reuse_without_prompting() -> None:
    text = INSTALL_SH.read_text()
    body = _extract_function_body("run_hermes_setup")

    assert 'BLACKBOX_HERMES_SETUP="${BLACKBOX_HERMES_SETUP:-reuse}"' in text
    assert "reuse_existing_hermes_api_keys" in body
    assert "No existing Hermes API key found; skipping Hermes setup wizard." in body
    assert "Threat-graph sync does not require a Nous subscription or model key." in body


def test_hermes_key_reuse_finds_existing_env_files() -> None:
    body = _extract_function_body("reuse_existing_hermes_api_keys")

    assert '"$REPO_DIR/.env"' in body
    assert '"$HOME/.hermes/.env"' in body
    assert "Reused existing Hermes API key configuration" in body
    assert "grep -E \"$HERMES_API_KEY_RE\"" in body


def test_unix_installer_uses_isolated_blackbox_dkg_node() -> None:
    text = INSTALL_SH.read_text()

    assert 'BLACKBOX_DKG_PORT="${BLACKBOX_DKG_PORT:-9320}"' in text
    assert 'BLACKBOX_DKG_STORE_PORT="${BLACKBOX_DKG_STORE_PORT:-7879}"' in text
    assert 'BLACKBOX_INSTALL_ROOT="${BLACKBOX_INSTALL_DIR:-$HOME/agent-guardian}"' in text
    assert 'BLACKBOX_DKG_HOME="${BLACKBOX_DKG_HOME:-$BLACKBOX_INSTALL_ROOT/.dkg}"' in text
    assert 'BLACKBOX_DKG_CLI_DIR="${BLACKBOX_DKG_CLI_DIR:-$BLACKBOX_INSTALL_ROOT/dkg}"' in text
    assert 'BLACKBOX_DKG_BIN="${BLACKBOX_DKG_BIN:-$BLACKBOX_DKG_CLI_DIR/node_modules/.bin/dkg}"' in text
    assert 'BLACKBOX_DKG_REPO_URL="${BLACKBOX_DKG_REPO_URL:-https://github.com/matic031/dkg.git}"' in text
    assert 'BLACKBOX_DKG_REPO_BRANCH="${BLACKBOX_DKG_REPO_BRANCH:-feat/blackbox}"' in text
    assert 'BLACKBOX_DKG_DAEMON_URL="${BLACKBOX_DKG_DAEMON_URL:-${BLACKBOX_DKG_URL:-http://127.0.0.1:$BLACKBOX_DKG_PORT}}"' in text
    assert 'git clone --depth 1 --branch "$BLACKBOX_DKG_REPO_BRANCH"' in text
    assert "corepack pnpm run build:runtime:packages" in text
    assert "blackbox-build-commit" in text
    assert "ensure_blackbox_dkg_config" in text
    assert 'blackbox_dkg start' in text
    assert '"apiPort"] = api_port' in text
    assert 'options["port"] = store_port' in text
    assert 'blackbox_dkg subscribe "$blackbox_cg" --save' in text
    assert "uses_unpaired_shared_dkg_home" in text
    assert "uses_legacy_blackbox_dkg_home" in text
    assert "migrate_legacy_blackbox_dkg_home" in text
    assert 'blackbox["dkg_home"] = dkg_home' in text
    assert 'blackbox["dkg_bin"] = dkg_bin' in text
    assert "npm i -g" not in text
    assert "npm install -g" not in text
    assert '"dkg_url": "http://127.0.0.1:9200"' not in text


# The 4 mainnet-base core relays the installer seeds into config.relayPeers.
# On DKG <=10.0.4 an empty relayPeers left the node with 0 circuit reservations
# ("No reachable curator found"); 10.0.5+ also resolves relays from
# preferredRelays + the built-in mainnet-base network config, so this seeding is
# now defensive belt-and-suspenders rather than the sole reachability path. It
# stays because it is harmless (deduped) and protects pre-10.0.5 nodes; guard the
# exact multiaddrs and the merge logic against silent regression either way.
MAINNET_BASE_RELAYS = (
    "/ip4/178.104.98.10/tcp/9090/p2p/12D3KooWFWm8sg6dkitmdBd5Uxaqp3CDRL27mFcM7vEHK92Xapyy",
    "/ip4/168.119.127.54/tcp/9090/p2p/12D3KooWMasqzRrim48ZJM64UyTfHufDTmSG3n3jqwsS5phz8m91",
    "/ip4/178.156.237.133/tcp/9090/p2p/12D3KooWDgTunUpkGaE7dYCaDP1CCBT6Dm2HPMXSZhJn2KXYLH15",
    "/ip4/178.105.211.42/tcp/9090/p2p/12D3KooWCodgXHMwybaEe93rbKgWMfGXQvUb6cpT3VCrjCbbnyEu",
)

_RELAY_SEED_ASSERTS = (
    'existing_relays = data.get("relayPeers")',
    "merged_relays = list(dict.fromkeys([*existing_relays, *MAINNET_BASE_RELAYS]))",
    'data["relayPeers"] = merged_relays',
    'data["relayReservationCount"] = int(data.get("relayReservationCount") or 4)',
)


def test_unix_installer_seeds_relay_peers_for_reachability() -> None:
    text = INSTALL_SH.read_text()

    for relay in MAINNET_BASE_RELAYS:
        assert relay in text, f"missing mainnet-base relay {relay}"
    for line in _RELAY_SEED_ASSERTS:
        assert line in text, f"relayPeers seeding line missing: {line}"


def test_windows_installer_seeds_relay_peers_for_reachability() -> None:
    text = INSTALL_PS1.read_text()

    for relay in MAINNET_BASE_RELAYS:
        assert relay in text, f"missing mainnet-base relay {relay}"
    for line in _RELAY_SEED_ASSERTS:
        assert line in text, f"relayPeers seeding line missing: {line}"


def test_windows_installer_uses_isolated_blackbox_dkg_node() -> None:
    text = INSTALL_PS1.read_text()

    assert "$DkgPort" in text and "9320" in text
    assert "$DkgStorePort" in text and "7879" in text
    assert '$DkgHome     = if ($env:BLACKBOX_DKG_HOME)' in text
    assert '$DkgCliDir   = if ($env:BLACKBOX_DKG_CLI_DIR)' in text
    assert 'Join-Path $DefaultRepoDir ".dkg"' in text
    assert 'Join-Path $DefaultRepoDir "dkg"' in text
    assert '$DkgBin      = if ($env:BLACKBOX_DKG_BIN)' in text
    assert '$DkgRepoUrl  = if ($env:BLACKBOX_DKG_REPO_URL)' in text
    assert '$DkgRepoBranch = if ($env:BLACKBOX_DKG_REPO_BRANCH)' in text
    assert '$DkgDaemonUrl = if ($env:BLACKBOX_DKG_DAEMON_URL)' in text
    assert "git clone --depth 1 --branch $DkgRepoBranch" in text
    assert "corepack pnpm run build:runtime:packages" in text
    assert "blackbox-build-commit" in text
    assert "Ensure-BlackboxDkgConfig" in text
    assert "Invoke-BlackboxDkg start" in text
    assert 'data["apiPort"] = api_port' in text
    assert 'options["port"] = store_port' in text
    assert "uses_unpaired_shared_dkg_home" in text
    assert "uses_legacy_blackbox_dkg_home" in text
    assert "Move-LegacyBlackboxDkgHome" in text
    assert 'blackbox["dkg_home"] = dkg_home' in text
    assert 'blackbox["dkg_bin"] = dkg_bin' in text
    assert "npm i -g" not in text
    assert "npm install -g" not in text
    assert '"dkg_url": "http://127.0.0.1:9200"' not in text


def test_dkg_config_migration_removes_only_unselected_legacy_graphs(tmp_path: Path) -> None:
    home = tmp_path / "dkg"
    home.mkdir()
    config = home / "config.json"
    config.write_text(
        json.dumps(
            {
                "contextGraphs": [
                    "umanitek/guardian-threats-staging",
                    "custom/private-graph",
                ],
                "syncAgentsMeta": True,
                "restrictAutoSubscribeContextGraphs": True,
            }
        ),
        encoding="utf-8",
    )
    writer = _extract_unix_config_writer()

    subprocess.run(
        [
            sys.executable,
            "-c",
            writer,
            str(home),
            "9320",
            "7879",
            "umanitek/blackbox-threats-staging",
        ],
        check=True,
    )
    migrated = json.loads(config.read_text(encoding="utf-8"))

    assert migrated["contextGraphs"] == [
        "custom/private-graph",
        "umanitek/blackbox-threats-staging",
    ]
    assert migrated["autoApproveJoinRequests"] == ["umanitek/blackbox-threats-staging"]
    assert "syncAgentsMeta" not in migrated
    assert "syncOnConnectEnabled" not in migrated
    assert "syncGlobalMaxInflight" not in migrated
    assert "syncGlobalQueueLimit" not in migrated
    assert "restrictAutoSubscribeContextGraphs" not in migrated
    assert migrated["store"]["options"]["readyTimeoutMs"] == 120000

    subprocess.run(
        [
            sys.executable,
            "-c",
            writer,
            str(home),
            "9320",
            "7879",
            "umanitek/guardian-threats-staging",
        ],
        check=True,
    )
    explicitly_selected = json.loads(config.read_text(encoding="utf-8"))
    assert "umanitek/guardian-threats-staging" in explicitly_selected["contextGraphs"]


def test_dkg_config_writer_reports_only_real_runtime_changes(tmp_path: Path) -> None:
    home = tmp_path / "dkg"
    writer = _extract_unix_config_writer()
    command = [
        sys.executable,
        "-c",
        writer,
        str(home),
        "9320",
        "7879",
        "umanitek/blackbox-threats-staging",
    ]

    first = subprocess.run(command, check=True, capture_output=True, text=True)
    config = home / "config.json"
    first_mtime = config.stat().st_mtime_ns
    second = subprocess.run(command, check=True, capture_output=True, text=True)

    assert first.stdout.strip() == "changed"
    assert second.stdout.strip() == "unchanged"
    assert config.stat().st_mtime_ns == first_mtime


def test_dkg_config_writer_recovers_invalid_utf8(tmp_path: Path) -> None:
    home = tmp_path / "dkg"
    home.mkdir()
    config = home / "config.json"
    config.write_bytes(b"\xff\xfeinvalid")
    writer = _extract_unix_config_writer()

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            writer,
            str(home),
            "9320",
            "7879",
            "umanitek/blackbox-threats-staging",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert completed.stdout.strip() == "changed"
    recovered = json.loads(config.read_text(encoding="utf-8"))
    assert recovered["contextGraphs"] == ["umanitek/blackbox-threats-staging"]


def test_installers_apply_native_dkg_membership_and_relay_defaults() -> None:
    unix = INSTALL_SH.read_text(encoding="utf-8")
    windows = INSTALL_PS1.read_text(encoding="utf-8")

    for text in (unix, windows):
        assert "blackbox-clean-dkg-subscriptions.py" in text
        assert "DKG_CATCHUP_MAX_CONCURRENT_PEERS" in text
        assert "DKG_SYNC_PAGE_TIMEOUT_MS" in text and "180000" in text
        assert "DKG_SYNC_TOTAL_TIMEOUT_MS" in text and "1200000" in text
        assert "DKG_SYNC_MIN_GRAPH_BUDGET_MS" in text and "120000" in text
        assert "DKG_SYNC_RESPONDER_PER_SNAPSHOT_ROW_LIMIT" not in text
        assert "DKG_SYNC_RESPONDER_GLOBAL_SNAPSHOT_ROW_LIMIT" not in text
        assert "blackbox-dkg-runtime-fingerprint.py" in text
        assert "DKG daemon is ready on checkout" in text
        assert 'data["autoApproveJoinRequests"] = auto_approve' in text
        assert 'data.pop("syncOnConnectEnabled", None)' in text
        assert 'data.pop("syncGlobalMaxInflight", None)' in text
        assert 'data.pop("syncGlobalQueueLimit", None)' in text
        assert 'data.pop("restrictAutoSubscribeContextGraphs", None)' in text
        assert 'options["readyTimeoutMs"] = 120000' in text


def test_installers_restart_running_owned_dkg_only_for_runtime_changes() -> None:
    unix = _extract_function_body("install_dkg")
    windows = INSTALL_PS1.read_text(encoding="utf-8")

    assert "BLACKBOX_DKG_RESTART_REQUIRED" in INSTALL_SH.read_text(encoding="utf-8")
    assert 'if [ "$BLACKBOX_DKG_RESTART_REQUIRED" != true ]; then' in unix
    assert "blackbox_dkg stop && blackbox_dkg start && wait_for_blackbox_dkg_runtime" in unix
    assert "install_blackbox_dkg_checkout" in unix
    assert "prepare_blackbox_dkg_runtime_fingerprint" in unix
    assert "record_blackbox_dkg_runtime_fingerprint" in unix
    assert ".blackbox-runtime.sha256" in INSTALL_SH.read_text(encoding="utf-8")

    assert "if ($script:DkgAlreadyRunning)" in windows
    assert "if (-not $script:DkgRestartRequired)" in windows
    assert "Invoke-BlackboxDkg stop" in windows
    assert "Invoke-BlackboxDkg start" in windows
    assert "Wait-BlackboxDkgRuntime" in windows
    assert "updated sync settings are not active" in windows
    assert "Prepare-BlackboxDkgRuntimeFingerprint" in windows
    assert "Save-BlackboxDkgRuntimeFingerprint" in windows
    assert ".blackbox-runtime.sha256" in windows


def test_installers_migrate_only_the_known_legacy_blackbox_dkg_paths() -> None:
    unix = INSTALL_SH.read_text(encoding="utf-8")
    windows = INSTALL_PS1.read_text(encoding="utf-8")

    assert '$HOME/.hermes/blackbox/dkg' in unix
    assert '$HOME/.hermes/blackbox/dkg-cli/node_modules/.bin/dkg' in unix
    assert 'mv "$legacy_home" "$BLACKBOX_DKG_HOME"' in unix
    assert 'DKG_HOME="$legacy_home" "$legacy_bin" stop' in unix
    assert '.hermes\\blackbox\\dkg' in windows
    assert 'Move-Item $legacyHome $DkgHome' in windows
    assert '& $legacyBin stop' in windows


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is unavailable")
def test_unix_legacy_dkg_state_moves_into_project_without_losing_identity(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    legacy = home / ".hermes" / "blackbox" / "dkg"
    target = home / "agent-guardian" / ".dkg"
    legacy.mkdir(parents=True)
    target.parent.mkdir(parents=True)
    (legacy / "config.json").write_text('{"apiPort":9320}\n', encoding="utf-8")
    (legacy / "agent-key.bin").write_bytes(b"preserved-peer-identity")
    body = _extract_function_body("migrate_legacy_blackbox_dkg_home")
    command = f"""
migrate_legacy_blackbox_dkg_home() {{
{body}
}}
warn() {{ :; }}
step() {{ :; }}
ok() {{ :; }}
HOME={shlex.quote(str(home))}
BLACKBOX_DKG_HOME={shlex.quote(str(target))}
BLACKBOX_INSTALL_INCOMPLETE=false
BLACKBOX_THREAT_GRAPH_INCOMPLETE=false
migrate_legacy_blackbox_dkg_home
"""

    subprocess.run(["bash", "-c", command], check=True)

    assert not legacy.exists()
    assert (target / "config.json").is_file()
    assert (target / "agent-key.bin").read_bytes() == b"preserved-peer-identity"


def test_installers_do_not_report_ready_after_cleanup_failure() -> None:
    unix_cleanup = _extract_function_body("clean_stale_dkg_subscriptions")
    unix_install = _extract_function_body("install_dkg")
    windows_cleanup = _extract_powershell_function_body(
        "Remove-StaleDkgSubscriptions"
    )
    windows_install = _extract_powershell_function_body("Install-Dkg")

    assert "BLACKBOX_INSTALL_INCOMPLETE=true" in unix_cleanup
    assert "BLACKBOX_THREAT_GRAPH_INCOMPLETE=true" in unix_cleanup
    assert "return 1" in unix_cleanup
    assert "if ! clean_stale_dkg_subscriptions; then" in unix_install
    assert "! clean_stale_dkg_subscriptions; then" in unix_install

    assert "$script:InstallIncomplete = $true" in windows_cleanup
    assert "return $false" in windows_cleanup
    assert "if (-not (Remove-StaleDkgSubscriptions))" in windows_install


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is unavailable")
def test_unix_runtime_marker_survives_interrupted_restart_window(
    tmp_path: Path,
) -> None:
    cli_dir = tmp_path / "dkg-cli"
    home = tmp_path / "dkg-home"
    cli_package = cli_dir / "packages" / "cli"
    agent_package = cli_dir / "packages" / "agent"
    (cli_package / "dist").mkdir(parents=True)
    (agent_package / "dist").mkdir(parents=True)
    home.mkdir()
    (cli_package / "package.json").write_text(
        '{"name":"@origintrail-official/dkg","version":"10.0.6"}\n',
        encoding="utf-8",
    )
    (cli_package / "dist" / "cli.js").write_text(
        "export const cli = 1;\n", encoding="utf-8"
    )
    (agent_package / "package.json").write_text(
        '{"name":"@origintrail-official/dkg-agent","version":"10.0.6"}\n',
        encoding="utf-8",
    )
    agent_runtime = agent_package / "dist" / "agent.js"
    agent_runtime.write_text("export const agent = 1;\n", encoding="utf-8")
    (home / "config.json").write_text("{}\n", encoding="utf-8")
    dkg_bin = tmp_path / "dkg"
    dkg_bin.write_text("launcher\n", encoding="utf-8")
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").symlink_to(Path(sys.executable))
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "node").symlink_to(Path(sys.executable))
    marker = home / ".blackbox-runtime.sha256"
    prepare_body = _extract_function_body(
        "prepare_blackbox_dkg_runtime_fingerprint"
    )
    record_body = _extract_function_body(
        "record_blackbox_dkg_runtime_fingerprint"
    )

    def invoke(*, record: bool) -> tuple[str, ...]:
        command = f"""
warn() {{ :; }}
prepare_blackbox_dkg_runtime_fingerprint() {{
{prepare_body}
}}
record_blackbox_dkg_runtime_fingerprint() {{
{record_body}
}}
REPO_DIR={shlex.quote(str(REPO_ROOT))}
VENV_DIR={shlex.quote(str(venv))}
BLACKBOX_DKG_CLI_DIR={shlex.quote(str(cli_dir))}
BLACKBOX_DKG_HOME={shlex.quote(str(home))}
BLACKBOX_DKG_BIN={shlex.quote(str(dkg_bin))}
BLACKBOX_DKG_RUNTIME_MARKER={shlex.quote(str(marker))}
BLACKBOX_DKG_RUNTIME_FINGERPRINT=''
BLACKBOX_DKG_RESTART_REQUIRED=false
BLACKBOX_INSTALL_INCOMPLETE=false
BLACKBOX_THREAT_GRAPH_INCOMPLETE=false
PATH={shlex.quote(str(fake_bin))}:$PATH
prepare_blackbox_dkg_runtime_fingerprint
prepare_rc=$?
record_rc=skipped
if {str(record).lower()}; then
    record_blackbox_dkg_runtime_fingerprint
    record_rc=$?
fi
fingerprint_length=$(printf %s "$BLACKBOX_DKG_RUNTIME_FINGERPRINT" | wc -c | tr -d ' ')
printf '%s|%s|%s|%s\n' "$prepare_rc" "$BLACKBOX_DKG_RESTART_REQUIRED" "$fingerprint_length" "$record_rc"
"""
        completed = subprocess.run(
            ["bash", "-c", command],
            check=True,
            capture_output=True,
            text=True,
        )
        return tuple(completed.stdout.strip().split("|"))

    assert invoke(record=True) == ("0", "true", "64", "0")
    assert invoke(record=False) == ("0", "false", "64", "skipped")

    # Disk changes without a successful restart must remain stale on every retry.
    agent_runtime.write_text("export const agent = 2;\n", encoding="utf-8")
    assert invoke(record=False) == ("0", "true", "64", "skipped")
    assert invoke(record=False) == ("0", "true", "64", "skipped")


def test_unix_installer_stops_dkg_setup_when_checkout_fails(tmp_path: Path) -> None:
    install_body = _extract_function_body("install_dkg")
    continued = tmp_path / "continued"
    command = f"""
heading() {{ :; }}
ok() {{ :; }}
step() {{ :; }}
warn() {{ :; }}
dkg_manual_hint() {{ printf 'manual-hint\n'; }}
install_blackbox_dkg_checkout() {{ return 1; }}
check_blackbox_dkg_port() {{ : > {shlex.quote(str(continued))}; return 0; }}
install_dkg() {{
{install_body}
}}
SKIP_DKG=false
HAS_NODE=true
BLACKBOX_DKG_CLI_DIR={shlex.quote(str(tmp_path / 'dkg-cli'))}
BLACKBOX_DKG_BIN=/bin/true
BLACKBOX_DKG_REPO_URL=https://example.invalid/dkg.git
BLACKBOX_DKG_REPO_BRANCH=feat/blackbox
install_dkg
"""
    result = subprocess.run(
        ["bash", "-c", command],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "manual-hint" in result.stdout
    assert not continued.exists(), "installer continued into DKG port/config setup"


def test_windows_dkg_checkout_failure_is_fatal_to_dkg_setup() -> None:
    install_body = _extract_powershell_function_body("Install-Dkg")
    failure_guard = """if (-not (Install-BlackboxDkgCheckout)) {
        $script:InstallIncomplete = $true
        Show-DkgManualHint
        return
    }"""
    assert failure_guard in install_body
    assert install_body.index(failure_guard) < install_body.index(
        "New-Item -ItemType Directory -Force -Path $DkgHome"
    )
