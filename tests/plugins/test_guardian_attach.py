"""Tests for ``guardian attach`` / ``guardian detach`` discovery + merge logic."""

import json

import pytest
import yaml

from _guardian_loader import load_guardian


attach = load_guardian("attach")
constants = load_guardian("constants")


# ---------------------------------------------------------------------------
# Fixtures — fake Hermes homes + OpenClaw workspace under tmp_path
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_env(tmp_path, monkeypatch):
    """A fake $HOME with two Hermes homes (default + a profile) and an OpenClaw ws.

    Returns a dict of the interesting paths. ``HERMES_HOME`` points at the
    default home so ``discover_hermes_homes`` resolves it.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: home)

    # Default hermes home with an existing config.yaml.
    hermes_default = home / ".hermes"
    hermes_default.mkdir()
    (hermes_default / "config.yaml").write_text(
        yaml.safe_dump({"providers": {"openai": {}}, "plugins": {"enabled": []}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(hermes_default))

    # A profile home (no config yet — attach must create it).
    profile = hermes_default / "profiles" / "work"
    profile.mkdir(parents=True)

    # A home with NO config file at all.
    bare_home = hermes_default  # default already has config; use profile as the bare one

    # An OpenClaw workspace (existing install → has openclaw.json).
    openclaw_ws = home / ".openclaw"
    openclaw_ws.mkdir()
    (openclaw_ws / "openclaw.json").write_text(
        json.dumps({"someKey": "keepme", "plugins": {"enabled": ["other"]}}, indent=2),
        encoding="utf-8",
    )

    # A non-openclaw dir that must NOT be discovered (no openclaw.json).
    (home / ".openclaw-dev").mkdir()

    return {
        "home": home,
        "hermes_default": hermes_default,
        "profile": profile,
        "bare_home": bare_home,
        "openclaw_ws": openclaw_ws,
    }


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_discover_hermes_homes_finds_default_and_profile(fake_env):
    homes = attach.discover_hermes_homes()
    assert fake_env["hermes_default"] in homes
    assert fake_env["profile"] in homes


def test_discover_hermes_homes_deduplicates(fake_env):
    homes = attach.discover_hermes_homes()
    assert len(homes) == len(set(homes))


def test_discover_openclaw_only_existing_installs(fake_env):
    workspaces = attach.discover_openclaw_workspaces()
    assert fake_env["openclaw_ws"] in workspaces
    # .openclaw-dev exists but has no openclaw.json → excluded.
    assert (fake_env["home"] / ".openclaw-dev") not in workspaces


# ---------------------------------------------------------------------------
# attach_hermes — copies plugin + enables idempotently
# ---------------------------------------------------------------------------


def test_attach_hermes_copies_plugin_and_enables(fake_env):
    home = fake_env["hermes_default"]
    report = attach.attach_hermes(home)
    assert report["ok"]
    # Plugin copied into the home.
    assert (home / "plugins" / "guardian" / "__init__.py").exists()
    # __pycache__/tests excluded.
    assert not (home / "plugins" / "guardian" / "__pycache__").exists()
    assert not (home / "plugins" / "guardian" / "tests").exists()
    # guardian added to plugins.enabled.
    data = yaml.safe_load((home / "config.yaml").read_text())
    assert "guardian" in data["plugins"]["enabled"]
    # Other keys preserved.
    assert "providers" in data


def test_attach_hermes_is_idempotent(fake_env):
    home = fake_env["hermes_default"]
    attach.attach_hermes(home)
    before = (home / "config.yaml").read_text()
    second = attach.attach_hermes(home)
    after = (home / "config.yaml").read_text()
    # Second run reports "already" and makes no config change.
    assert second["already"] is True
    assert second["enabled"] is False
    assert before == after
    # No duplicate list entry.
    data = yaml.safe_load(after)
    assert data["plugins"]["enabled"].count("guardian") == 1


def test_attach_hermes_creates_config_for_bare_home(fake_env):
    profile = fake_env["profile"]  # no config.yaml yet
    report = attach.attach_hermes(profile)
    assert report["ok"] and report["enabled"]
    cfg = profile / "config.yaml"
    assert cfg.exists()
    data = yaml.safe_load(cfg.read_text())
    assert data["plugins"]["enabled"] == ["guardian"]


def test_attach_hermes_dry_run_writes_nothing(fake_env):
    home = fake_env["hermes_default"]
    before = (home / "config.yaml").read_text()
    report = attach.attach_hermes(home, dry_run=True)
    assert report["ok"] and report["dry_run"]
    # No plugin dir, no config change.
    assert not (home / "plugins" / "guardian").exists()
    assert (home / "config.yaml").read_text() == before


# ---------------------------------------------------------------------------
# detach_hermes
# ---------------------------------------------------------------------------


def test_detach_hermes_disables_and_optionally_removes(fake_env):
    home = fake_env["hermes_default"]
    attach.attach_hermes(home)
    assert (home / "plugins" / "guardian").exists()

    report = attach.detach_hermes(home, remove_files=True)
    assert report["ok"] and report["disabled"] and report["removed"]
    data = yaml.safe_load((home / "config.yaml").read_text())
    assert "guardian" not in data["plugins"]["enabled"]
    assert not (home / "plugins" / "guardian").exists()


def test_detach_hermes_idempotent(fake_env):
    home = fake_env["hermes_default"]
    report = attach.detach_hermes(home)
    assert report["ok"] and report["already"]


def test_detach_hermes_dry_run_writes_nothing(fake_env):
    home = fake_env["hermes_default"]
    attach.attach_hermes(home)
    before = (home / "config.yaml").read_text()
    report = attach.detach_hermes(home, remove_files=True, dry_run=True)
    assert report["ok"]
    assert (home / "config.yaml").read_text() == before
    assert (home / "plugins" / "guardian").exists()  # not removed in dry-run


# ---------------------------------------------------------------------------
# attach_openclaw — writes the guardian entry block, idempotent
# ---------------------------------------------------------------------------


def test_attach_openclaw_writes_guardian_block(fake_env):
    ws = fake_env["openclaw_ws"]
    report = attach.attach_openclaw(ws)
    assert report["ok"] and report["changed"]

    data = json.loads((ws / "openclaw.json").read_text())
    plugins = data["plugins"]
    assert "guardian" in plugins["allow"]
    entry = plugins["entries"]["guardian"]
    assert entry["enabled"] is True
    assert entry["hooks"]["allowConversationAccess"] is True
    assert entry["config"]["mode"]
    assert entry["config"]["daemonUrl"]
    assert entry["config"]["contextGraphId"]
    # Unrelated keys preserved.
    assert data["someKey"] == "keepme"
    # A backup was made.
    assert (ws / "openclaw.json.guardian.bak").exists()


def test_attach_openclaw_is_idempotent(fake_env):
    ws = fake_env["openclaw_ws"]
    attach.attach_openclaw(ws)
    before = (ws / "openclaw.json").read_text()
    second = attach.attach_openclaw(ws)
    after = (ws / "openclaw.json").read_text()
    assert second["already"] is True
    assert second["changed"] is False
    assert before == after
    data = json.loads(after)
    assert data["plugins"]["allow"].count("guardian") == 1


def test_attach_openclaw_dry_run_writes_nothing(fake_env):
    ws = fake_env["openclaw_ws"]
    before = (ws / "openclaw.json").read_text()
    report = attach.attach_openclaw(ws, dry_run=True)
    assert report["ok"] and report["changed"] and report["dry_run"]
    assert (ws / "openclaw.json").read_text() == before


def test_detach_openclaw_removes_block(fake_env):
    ws = fake_env["openclaw_ws"]
    attach.attach_openclaw(ws)
    report = attach.detach_openclaw(ws)
    assert report["ok"] and report["changed"]
    data = json.loads((ws / "openclaw.json").read_text())
    assert "guardian" not in (data["plugins"].get("allow") or [])
    assert "guardian" not in (data["plugins"].get("entries") or {})


# ---------------------------------------------------------------------------
# attach_all / detach_all report
# ---------------------------------------------------------------------------


def test_attach_all_reports_targets(fake_env):
    report = attach.attach_all()
    assert report["count"] >= 2  # at least default home + openclaw ws
    assert all(row["ok"] for row in report["hermes"])
    assert all(row["ok"] for row in report["openclaw"])
