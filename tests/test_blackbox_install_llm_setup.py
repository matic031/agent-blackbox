"""Regression coverage for the Blackbox installer's LLM reviewer setup."""

from __future__ import annotations

import re
from pathlib import Path


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
    assert 'BLACKBOX_DKG_HOME="${BLACKBOX_DKG_HOME:-$BLACKBOX_HOME/dkg}"' in text
    assert 'BLACKBOX_DKG_CLI_DIR="${BLACKBOX_DKG_CLI_DIR:-$BLACKBOX_HOME/dkg-cli}"' in text
    assert 'BLACKBOX_DKG_BIN="${BLACKBOX_DKG_BIN:-$BLACKBOX_DKG_CLI_DIR/node_modules/.bin/dkg}"' in text
    assert 'BLACKBOX_DKG_DAEMON_URL="${BLACKBOX_DKG_DAEMON_URL:-${BLACKBOX_DKG_URL:-http://127.0.0.1:$BLACKBOX_DKG_PORT}}"' in text
    assert 'npm install --prefix "$BLACKBOX_DKG_CLI_DIR" "$BLACKBOX_DKG_PACKAGE"' in text
    assert "ensure_blackbox_dkg_config" in text
    assert 'blackbox_dkg start' in text
    assert '"apiPort"] = api_port' in text
    assert 'options["port"] = store_port' in text
    assert 'blackbox_dkg subscribe "$blackbox_cg" --save' in text
    assert "uses_unpaired_shared_dkg_home" in text
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
    assert '$DkgBin      = if ($env:BLACKBOX_DKG_BIN)' in text
    assert '$DkgDaemonUrl = if ($env:BLACKBOX_DKG_DAEMON_URL)' in text
    assert "npm install --prefix $DkgCliDir $DkgPackage" in text
    assert "Ensure-BlackboxDkgConfig" in text
    assert "Invoke-BlackboxDkg start" in text
    assert 'data["apiPort"] = api_port' in text
    assert 'options["port"] = store_port' in text
    assert "uses_unpaired_shared_dkg_home" in text
    assert 'blackbox["dkg_home"] = dkg_home' in text
    assert 'blackbox["dkg_bin"] = dkg_bin' in text
    assert "npm i -g" not in text
    assert "npm install -g" not in text
    assert '"dkg_url": "http://127.0.0.1:9200"' not in text
