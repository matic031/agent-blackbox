"""Auto-protect every local agent — ``guardian attach`` / ``guardian detach``.

Discovers every local Hermes home and OpenClaw workspace and enables Guardian
in each, so the user never has to enable it per-instance.

The trick for Hermes is that *a user plugin with the same name as a bundled
plugin replaces it* (``hermes_cli/plugins.py``): copying this plugin into a
home's ``plugins/guardian/`` and adding ``guardian`` to ``plugins.enabled`` in
that home's ``config.yaml`` activates it with no bundled-vs-user conflict.

Everything here is pure and testable: each function takes explicit paths, honours
``dry_run`` (no writes), and fails open per target (one bad home never aborts the
rest — the caller collects a per-target report). Only stdlib + PyYAML are used.
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import constants

logger = logging.getLogger(__name__)

try:  # PyYAML ships with hermes; degrade gracefully if it is somehow absent.
    import yaml
except Exception:  # pragma: no cover - yaml is a hard dep in practice
    yaml = None  # type: ignore[assignment]


# Files/dirs never copied into a target home's plugins/guardian/ — build
# artifacts and the plugin's own tests have no business in a runtime home.
_COPY_EXCLUDE_DIRS = {"__pycache__", "tests", ".pytest_cache"}
_COPY_EXCLUDE_SUFFIXES = (".pyc", ".pyo")


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _plugin_source_dir() -> Path:
    """Absolute path to this plugin's own directory (the copy source)."""
    return Path(__file__).resolve().parent


def _repo_root() -> Path:
    """Best-effort repo root: ``<repo>/plugins/guardian`` → ``<repo>``."""
    return _plugin_source_dir().parents[1]


def discover_hermes_homes() -> List[Path]:
    """Return every local Hermes home directory to protect.

    Includes the resolved default home, ``~/.hermes``, every existing
    ``~/.hermes/profiles/*/`` directory, and (on Windows) ``%LOCALAPPDATA%/hermes``.
    The canonical default is always included even if not yet created; results are
    de-duplicated preserving order.
    """
    homes: List[Path] = []

    def _add(path: Optional[Path]) -> None:
        if path is None:
            return
        try:
            resolved = path.expanduser()
        except Exception:
            return
        if resolved not in homes:
            homes.append(resolved)

    # The canonical default (honours profile switching / $HERMES_HOME) — always
    # included even if the directory does not exist yet.
    try:
        _add(constants.hermes_home())
    except Exception:  # pragma: no cover - defensive
        pass

    default_dot = Path.home() / ".hermes"
    _add(default_dot)

    # Every existing profile directory under the default home.
    profiles_dir = default_dot / "profiles"
    try:
        if profiles_dir.is_dir():
            for child in sorted(profiles_dir.iterdir()):
                if child.is_dir():
                    _add(child)
    except Exception:
        pass

    # Windows: %LOCALAPPDATA%/hermes.
    if os.name == "nt":
        local_appdata = os.environ.get("LOCALAPPDATA")
        if local_appdata:
            _add(Path(local_appdata) / "hermes")

    return homes


def discover_openclaw_workspaces() -> List[Path]:
    """Return existing local OpenClaw workspaces (those with an ``openclaw.json``).

    Candidate roots come from ``$OPENCLAW_STATE_DIR``, ``$OPENCLAW_HOME/.openclaw``,
    ``~/.openclaw``, ``~/.openclaw-dev`` and the legacy ``~/.clawdbot``. Only
    directories that actually contain an ``openclaw.json`` are returned (an
    existing install), de-duplicated preserving order.
    """
    candidates: List[Path] = []

    def _add(path: Optional[Path]) -> None:
        if path is None:
            return
        try:
            resolved = path.expanduser()
        except Exception:
            return
        if resolved not in candidates:
            candidates.append(resolved)

    state_dir = os.environ.get("OPENCLAW_STATE_DIR")
    if state_dir and state_dir.strip():
        _add(Path(state_dir.strip()))
    openclaw_home = os.environ.get("OPENCLAW_HOME")
    if openclaw_home and openclaw_home.strip():
        _add(Path(openclaw_home.strip()) / ".openclaw")
    _add(Path.home() / ".openclaw")
    _add(Path.home() / ".openclaw-dev")
    _add(Path.home() / ".clawdbot")  # legacy name

    return [c for c in candidates if (c / "openclaw.json").is_file()]


# ---------------------------------------------------------------------------
# YAML helpers (idempotent, preserve unrelated keys)
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> Dict[str, Any]:
    if yaml is None or not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.debug("guardian.attach: could not parse %s (%s)", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def _dump_yaml(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(data, default_flow_style=False, sort_keys=False)
    path.write_text(text, encoding="utf-8")


def _enabled_list_has(data: Dict[str, Any], name: str) -> bool:
    plugins = data.get("plugins")
    if not isinstance(plugins, dict):
        return False
    enabled = plugins.get("enabled")
    return isinstance(enabled, list) and name in enabled


# ---------------------------------------------------------------------------
# Plugin file copy (dedup, version-aware)
# ---------------------------------------------------------------------------


def _installed_plugin_version(dest: Path) -> Optional[str]:
    """Read ``__version__`` from an installed copy's ``constants.py`` (cheap parse)."""
    const_path = dest / "constants.py"
    if not const_path.exists():
        return None
    try:
        for line in const_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("__version__"):
                _, _, rhs = stripped.partition("=")
                return rhs.strip().strip("'\"")
    except Exception:
        return None
    return None


def _needs_copy(dest: Path) -> bool:
    """True when the plugin should be (re)copied: missing or version mismatch."""
    if not (dest / "__init__.py").exists():
        return True
    return _installed_plugin_version(dest) != constants.__version__


def _copy_plugin_tree(src: Path, dest: Path) -> None:
    """Copy the plugin tree from *src* to *dest*, excluding pycache/tests.

    Replaces any existing copy so a version bump fully refreshes the files.
    """
    if dest.exists():
        shutil.rmtree(dest)

    def _ignore(_dir: str, names: List[str]) -> List[str]:
        ignored: List[str] = []
        for name in names:
            if name in _COPY_EXCLUDE_DIRS or name.endswith(_COPY_EXCLUDE_SUFFIXES):
                ignored.append(name)
        return ignored

    shutil.copytree(src, dest, ignore=_ignore)


# ---------------------------------------------------------------------------
# Hermes attach / detach
# ---------------------------------------------------------------------------


def attach_hermes(home: Path, *, dry_run: bool = False) -> Dict[str, Any]:
    """Enable Guardian in a single Hermes *home*.

    Copies the plugin into ``<home>/plugins/guardian/`` (only when missing or a
    version mismatch) and adds ``guardian`` to ``plugins.enabled`` in
    ``<home>/config.yaml`` idempotently, preserving every other key. Returns a
    per-target report dict; fails open (``ok=False`` + ``error`` on failure).
    """
    home = home.expanduser()
    report: Dict[str, Any] = {
        "target": str(home),
        "kind": "hermes",
        "ok": False,
        "copied": False,
        "enabled": False,
        "already": False,
        "dry_run": dry_run,
    }
    try:
        src = _plugin_source_dir()
        dest = home / "plugins" / "guardian"
        # Don't copy a home onto itself (e.g. running from inside a home).
        same_tree = src == dest or src == dest.resolve() if dest.exists() else False
        needs = (not same_tree) and _needs_copy(dest)
        if needs and not dry_run:
            _copy_plugin_tree(src, dest)
        report["copied"] = needs

        config_path = home / "config.yaml"
        data = _load_yaml(config_path)
        if _enabled_list_has(data, "guardian"):
            report["already"] = True
        else:
            if not dry_run:
                plugins = data.setdefault("plugins", {})
                if not isinstance(plugins, dict):
                    plugins = {}
                    data["plugins"] = plugins
                enabled = plugins.get("enabled")
                if not isinstance(enabled, list):
                    enabled = []
                    plugins["enabled"] = enabled
                if "guardian" not in enabled:
                    enabled.append("guardian")
                _dump_yaml(config_path, data)
            report["enabled"] = True
        report["ok"] = True
    except Exception as exc:  # fail open per target
        logger.debug("guardian.attach: attach_hermes(%s) failed: %s", home, exc)
        report["error"] = str(exc)
    return report


def detach_hermes(home: Path, *, remove_files: bool = False, dry_run: bool = False) -> Dict[str, Any]:
    """Disable Guardian in a single Hermes *home*.

    Removes ``guardian`` from ``plugins.enabled`` (idempotent) and, when
    *remove_files* is set, deletes ``<home>/plugins/guardian/``. Fails open.
    """
    home = home.expanduser()
    report: Dict[str, Any] = {
        "target": str(home),
        "kind": "hermes",
        "ok": False,
        "disabled": False,
        "removed": False,
        "already": False,
        "dry_run": dry_run,
    }
    try:
        config_path = home / "config.yaml"
        data = _load_yaml(config_path)
        if _enabled_list_has(data, "guardian"):
            if not dry_run:
                data["plugins"]["enabled"] = [p for p in data["plugins"]["enabled"] if p != "guardian"]
                _dump_yaml(config_path, data)
            report["disabled"] = True
        else:
            report["already"] = True

        dest = home / "plugins" / "guardian"
        if remove_files and dest.exists():
            if not dry_run:
                shutil.rmtree(dest)
            report["removed"] = True
        report["ok"] = True
    except Exception as exc:
        logger.debug("guardian.attach: detach_hermes(%s) failed: %s", home, exc)
        report["error"] = str(exc)
    return report


# ---------------------------------------------------------------------------
# OpenClaw attach / detach
# ---------------------------------------------------------------------------


def _openclaw_load_paths_entry() -> Optional[str]:
    """Absolute path to ``integrations/openclaw`` in this repo, or ``None``.

    Guardian may have been copied into a user home (no sibling ``integrations/``),
    in which case there is nothing to point OpenClaw at — the caller records the
    intent and logs a clear note.
    """
    candidate = _repo_root() / "integrations" / "openclaw"
    return str(candidate) if candidate.is_dir() else None


def attach_openclaw(workspace: Path, *, dry_run: bool = False) -> Dict[str, Any]:
    """Enable Guardian in a single OpenClaw *workspace*.

    Backs up ``openclaw.json``, then idempotently merges:

    * ``plugins.allow`` += ``"guardian"``
    * ``plugins.load.paths`` += the absolute path to ``integrations/openclaw``
    * ``plugins.entries.guardian`` = the Guardian config + hook grants

    Preserves every other key. Fails open per target.
    """
    import json  # local import: only this path needs JSON I/O

    workspace = workspace.expanduser()
    config_path = workspace / "openclaw.json"
    report: Dict[str, Any] = {
        "target": str(workspace),
        "kind": "openclaw",
        "ok": False,
        "changed": False,
        "already": False,
        "backed_up": False,
        "dry_run": dry_run,
    }
    try:
        try:
            data = json.loads(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}

        cfg = load_guardian_config_snapshot()
        load_path = _openclaw_load_paths_entry()
        if load_path is None:
            report["note"] = (
                "integrations/openclaw not found next to this Guardian copy "
                "(likely copied into a user home); recording intent without a load path."
            )
            logger.info("guardian.attach: %s", report["note"])

        changed = _merge_openclaw(data, cfg, load_path)
        report["changed"] = changed
        report["already"] = not changed

        if changed and not dry_run:
            # Back up before writing.
            if config_path.exists():
                backup = config_path.with_suffix(".json.guardian.bak")
                shutil.copy2(config_path, backup)
                report["backed_up"] = True
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        report["ok"] = True
    except Exception as exc:
        logger.debug("guardian.attach: attach_openclaw(%s) failed: %s", workspace, exc)
        report["error"] = str(exc)
    return report


def _merge_openclaw(data: Dict[str, Any], cfg: Dict[str, Any], load_path: Optional[str]) -> bool:
    """Idempotently merge the Guardian block into an ``openclaw.json`` dict.

    Returns ``True`` when anything changed. Pure (mutates *data* in place); the
    caller decides whether to persist.
    """
    changed = False
    plugins = data.setdefault("plugins", {})
    if not isinstance(plugins, dict):
        plugins = {}
        data["plugins"] = plugins

    allow = plugins.get("allow")
    if not isinstance(allow, list):
        allow = []
        plugins["allow"] = allow
    if "guardian" not in allow:
        allow.append("guardian")
        changed = True

    if load_path is not None:
        load = plugins.get("load")
        if not isinstance(load, dict):
            load = {}
            plugins["load"] = load
        paths = load.get("paths")
        if not isinstance(paths, list):
            paths = []
            load["paths"] = paths
        if load_path not in paths:
            paths.append(load_path)
            changed = True

    entries = plugins.get("entries")
    if not isinstance(entries, dict):
        entries = {}
        plugins["entries"] = entries
    desired_entry = {
        "enabled": True,
        "config": {
            "daemonUrl": cfg["dkg_url"],
            "contextGraphId": cfg["context_graph_id"],
            "mode": cfg["mode"],
        },
        "hooks": {"allowConversationAccess": True},
    }
    if entries.get("guardian") != desired_entry:
        entries["guardian"] = desired_entry
        changed = True
    return changed


def detach_openclaw(workspace: Path, *, dry_run: bool = False) -> Dict[str, Any]:
    """Disable Guardian in a single OpenClaw *workspace* (idempotent, fail-open)."""
    import json

    workspace = workspace.expanduser()
    config_path = workspace / "openclaw.json"
    report: Dict[str, Any] = {
        "target": str(workspace),
        "kind": "openclaw",
        "ok": False,
        "changed": False,
        "already": False,
        "dry_run": dry_run,
    }
    try:
        if not config_path.exists():
            report["already"] = True
            report["ok"] = True
            return report
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        plugins = data.get("plugins")
        changed = False
        if isinstance(plugins, dict):
            allow = plugins.get("allow")
            if isinstance(allow, list) and "guardian" in allow:
                plugins["allow"] = [p for p in allow if p != "guardian"]
                changed = True
            load = plugins.get("load")
            if isinstance(load, dict) and isinstance(load.get("paths"), list):
                target = _openclaw_load_paths_entry()
                if target and target in load["paths"]:
                    load["paths"] = [p for p in load["paths"] if p != target]
                    changed = True
            entries = plugins.get("entries")
            if isinstance(entries, dict) and "guardian" in entries:
                del entries["guardian"]
                changed = True
        report["changed"] = changed
        report["already"] = not changed
        if changed and not dry_run:
            config_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        report["ok"] = True
    except Exception as exc:
        logger.debug("guardian.attach: detach_openclaw(%s) failed: %s", workspace, exc)
        report["error"] = str(exc)
    return report


# ---------------------------------------------------------------------------
# Config snapshot (for the OpenClaw entry) — decoupled from the running config
# ---------------------------------------------------------------------------


def load_guardian_config_snapshot() -> Dict[str, Any]:
    """Resolve the Guardian config values to seed into an OpenClaw workspace.

    Uses :func:`config.load_guardian_config` when available (honours env +
    config.yaml), else falls back to constants. Kept tiny so ``attach`` stays
    testable without a full hermes config.
    """
    try:
        from .config import load_guardian_config

        cfg = load_guardian_config()
        return {
            "dkg_url": cfg.dkg_url,
            "context_graph_id": cfg.context_graph_id,
            "mode": cfg.mode,
        }
    except Exception:
        return {
            "dkg_url": constants.DEFAULT_DKG_URL,
            "context_graph_id": constants.DEFAULT_CONTEXT_GRAPH_ID,
            "mode": "audit",
        }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def attach_all(*, hermes: bool = True, openclaw: bool = True, dry_run: bool = False) -> Dict[str, Any]:
    """Attach Guardian to every discovered target. Returns a combined report."""
    report: Dict[str, Any] = {"hermes": [], "openclaw": [], "dry_run": dry_run}
    if hermes:
        for home in discover_hermes_homes():
            report["hermes"].append(attach_hermes(home, dry_run=dry_run))
    if openclaw:
        for ws in discover_openclaw_workspaces():
            report["openclaw"].append(attach_openclaw(ws, dry_run=dry_run))
    report["count"] = _protected_count(report)
    return report


def detach_all(
    *, hermes: bool = True, openclaw: bool = True, remove_files: bool = False, dry_run: bool = False
) -> Dict[str, Any]:
    """Detach Guardian from every discovered target. Returns a combined report."""
    report: Dict[str, Any] = {"hermes": [], "openclaw": [], "dry_run": dry_run}
    if hermes:
        for home in discover_hermes_homes():
            report["hermes"].append(detach_hermes(home, remove_files=remove_files, dry_run=dry_run))
    if openclaw:
        for ws in discover_openclaw_workspaces():
            report["openclaw"].append(detach_openclaw(ws, dry_run=dry_run))
    return report


def _protected_count(report: Dict[str, Any]) -> int:
    """Number of targets Guardian is (now) protecting in an attach report."""
    total = 0
    for row in report.get("hermes", []):
        if row.get("ok"):
            total += 1
    for row in report.get("openclaw", []):
        if row.get("ok"):
            total += 1
    return total
