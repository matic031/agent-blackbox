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
    assert 'BLACKBOX_DKG_HOME="${BLACKBOX_DKG_HOME:-$BLACKBOX_HOME/dkg}"' in text
    assert 'BLACKBOX_DKG_DAEMON_URL="${BLACKBOX_DKG_DAEMON_URL:-${BLACKBOX_DKG_URL:-http://127.0.0.1:$BLACKBOX_DKG_PORT}}"' in text
    assert 'blackbox_dkg dkg hermes setup --network "$DKG_NETWORK"' in text
    assert '--port "$BLACKBOX_DKG_PORT"' in text
    assert '--daemon-url "$BLACKBOX_DKG_DAEMON_URL"' in text
    assert 'blackbox_dkg dkg subscribe "$blackbox_cg" --save' in text
    assert 'blackbox["dkg_home"] = dkg_home' in text
    assert '"dkg_url": "http://127.0.0.1:9200"' not in text


def test_windows_installer_uses_isolated_blackbox_dkg_node() -> None:
    text = INSTALL_PS1.read_text()

    assert "$DkgPort" in text and "9320" in text
    assert '$DkgHome     = if ($env:BLACKBOX_DKG_HOME)' in text
    assert '$DkgDaemonUrl = if ($env:BLACKBOX_DKG_DAEMON_URL)' in text
    assert "Invoke-BlackboxDkg hermes setup --network $Network" in text
    assert "--port $DkgPort" in text
    assert "--daemon-url $DkgDaemonUrl" in text
    assert 'blackbox["dkg_home"] = dkg_home' in text
    assert '"dkg_url": "http://127.0.0.1:9200"' not in text
