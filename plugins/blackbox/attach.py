"""Auto-protect every local agent — ``blackbox attach`` / ``blackbox detach``.

Discovers every local Hermes home and OpenClaw workspace and enables Blackbox
in each, so the user never has to enable it per-instance.

The trick for Hermes is that *a user plugin with the same name as a bundled
plugin replaces it* (``hermes_cli/plugins.py``): copying this plugin into a
home's ``plugins/blackbox/`` and adding ``blackbox`` to ``plugins.enabled`` in
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
_BLACKBOX_CHAT_PROFILE = "blackbox"
_BLACKBOX_CHAT_SOUL_MARKER = "<!-- managed-by: hermes-blackbox-chat -->"
_SOURCE_ROOT_MARKER = ".blackbox-source-root"

try:  # PyYAML ships with hermes; degrade gracefully if it is somehow absent.
    import yaml
except Exception:  # pragma: no cover - yaml is a hard dep in practice
    yaml = None  # type: ignore[assignment]


# Files/dirs never copied into a target home's plugins/blackbox/ — build
# artifacts and the plugin's own tests have no business in a runtime home.
_COPY_EXCLUDE_DIRS = {"__pycache__", "tests", ".pytest_cache", "node_modules"}
_COPY_EXCLUDE_SUFFIXES = (".pyc", ".pyo")

# The OpenClaw JS plugin is bundled inside an installed copy under this name so
# OpenClaw always has something to load, even when Blackbox was copied into a
# user home with no sibling ``integrations/`` (see ``_openclaw_plugin_source``).
_BUNDLED_OPENCLAW_DIRNAME = "_openclaw"


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _plugin_source_dir() -> Path:
    """Absolute path to this plugin's copy source.

    Installed copies carry ``.blackbox-source-root`` pointing back to the
    checkout that produced them. Prefer that checkout when it still exists so a
    re-run of ``hermes blackbox attach`` refreshes stale user-plugin files from
    the repo instead of copying the installed copy onto itself.
    """
    own = Path(__file__).resolve().parent
    marker = own / _SOURCE_ROOT_MARKER
    try:
        if marker.exists():
            root = Path(marker.read_text(encoding="utf-8").strip()).expanduser()
            candidate = (root / "plugins" / "blackbox").resolve()
            if candidate.is_dir() and candidate != own:
                return candidate
    except Exception:
        pass
    return own


def _repo_root() -> Path:
    """Best-effort repo root: ``<repo>/plugins/blackbox`` → ``<repo>``."""
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
                if child.is_dir() and not is_managed_blackbox_chat_profile(child):
                    _add(child)
    except Exception:
        pass

    # Windows: %LOCALAPPDATA%/hermes.
    if os.name == "nt":
        local_appdata = os.environ.get("LOCALAPPDATA")
        if local_appdata:
            _add(Path(local_appdata) / "hermes")

    return homes


def is_managed_blackbox_chat_profile(path: Path) -> bool:
    """Return True for the internal Blackbox control chat profile.

    The dashboard's attach/connected-agent surfaces list protected workloads.
    The managed ``blackbox`` profile is the operator/control profile launched by
    ``hermes blackbox chat``; showing it as a defended agent is misleading.
    """
    try:
        resolved = path.expanduser()
        if resolved.name != _BLACKBOX_CHAT_PROFILE or resolved.parent.name != "profiles":
            return False
        soul = resolved / "SOUL.md"
        return soul.exists() and _BLACKBOX_CHAT_SOUL_MARKER in soul.read_text(encoding="utf-8")
    except Exception:
        return False


def discover_openclaw_workspaces() -> List[Path]:
    """Return existing local OpenClaw workspaces (those with an ``openclaw.json``).

    Candidate roots come from ``$OPENCLAW_STATE_DIR``, ``$OPENCLAW_HOME/.openclaw``,
    the legacy ``~/.clawdbot``, **and any ``~/.openclaw*`` profile directory**
    (so ``openclaw --profile prod`` writing to ``~/.openclaw-prod`` is picked up
    live without any config change on our side). Only directories that actually
    contain an ``openclaw.json`` are returned, de-duplicated preserving order.
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

    # Glob every ``~/.openclaw*`` profile so any --profile/--dev workspace
    # created after the dashboard started still gets auto-attached.
    try:
        home = Path.home()
        for candidate in sorted(home.glob(".openclaw*")):
            if candidate.is_dir():
                _add(candidate)
    except Exception:  # pragma: no cover - defensive
        pass

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
        logger.debug("blackbox.attach: could not parse %s (%s)", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def _atomic_write(path: Path, text: str) -> None:
    """Write *text* via a temp file + rename so a reader never sees a torn file.

    A concurrent auto-attach sweep (or the dashboard reading a config) can race a
    write; ``os.replace`` is atomic on the same filesystem, so readers always see
    either the old or the new complete file, never a half-written one.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _dump_yaml(path: Path, data: Dict[str, Any]) -> None:
    _atomic_write(path, yaml.safe_dump(data, default_flow_style=False, sort_keys=False))


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
    """True when the plugin should be (re)copied: missing, version bump, or a
    same-version in-place source edit (so dev iteration propagates without a
    manual version bump)."""
    init = dest / "__init__.py"
    if not init.exists():
        return True
    if _installed_plugin_version(dest) != constants.__version__:
        return True
    try:
        src_dir = _plugin_source_dir()
        installed_at = init.stat().st_mtime
        newest_src = max(
            p.stat().st_mtime for p in src_dir.rglob("*.py") if "__pycache__" not in p.parts
        )
        return newest_src > installed_at
    except Exception:  # pragma: no cover - best effort
        return False


def _copy_ignore(_dir: str, names: List[str]) -> List[str]:
    return [n for n in names if n in _COPY_EXCLUDE_DIRS or n.endswith(_COPY_EXCLUDE_SUFFIXES)]


def _copy_plugin_tree(src: Path, dest: Path) -> None:
    """Copy the plugin tree from *src* to *dest*, excluding pycache/tests.

    Replaces any existing copy so a version bump fully refreshes the files, and
    bundles the OpenClaw JS plugin so an installed copy can still point OpenClaw
    at it (an installed ``plugins/blackbox`` has no sibling ``integrations/``).
    """
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, ignore=_copy_ignore)
    _bundle_openclaw_plugin(src, dest)
    source_root = _source_checkout_root(src)
    if source_root is not None:
        try:
            (dest / _SOURCE_ROOT_MARKER).write_text(str(source_root), encoding="utf-8")
        except OSError:
            pass


def _source_checkout_root(src: Path) -> Optional[Path]:
    try:
        resolved = src.resolve()
        root = resolved.parents[1]
        if (root / ".git").exists() and (root / "plugins" / "blackbox").resolve() == resolved:
            return root
    except Exception:
        return None
    return None


def _bundle_openclaw_plugin(src: Path, dest: Path) -> None:
    """Ensure the OpenClaw JS plugin lives at ``dest/_openclaw``.

    Sourced from the source copy's own bundle (a re-copy from another installed
    copy) or the repo checkout (the first copy from ``integrations/openclaw``).
    Best-effort: bundling must never break the Hermes/Python attach, so any
    failure is logged and swallowed — OpenClaw attach then reports itself
    unprotected via ``_openclaw_load_paths_entry`` rather than crashing.
    """
    dest_bundle = dest / _BUNDLED_OPENCLAW_DIRNAME
    if _is_openclaw_plugin_dir(dest_bundle):
        return  # copytree already carried a valid bundle over from *src*
    for candidate in (src / _BUNDLED_OPENCLAW_DIRNAME, _repo_openclaw_dir()):
        if not _is_openclaw_plugin_dir(candidate):
            continue
        try:
            if dest_bundle.exists():
                shutil.rmtree(dest_bundle)
            shutil.copytree(candidate, dest_bundle, ignore=_openclaw_ignore)
        except Exception as exc:  # pragma: no cover - best effort
            logger.debug("blackbox.attach: bundling OpenClaw plugin failed: %s", exc)
        return


def _openclaw_ignore(_dir: str, names: List[str]) -> List[str]:
    """Exclude deps/build/test dirs from the bundled OpenClaw plugin."""
    skip = {"node_modules", "dist", ".turbo", "test", "tests", "__pycache__"}
    return [n for n in names if n in skip or n.endswith((".pyc", ".log", ".tsbuildinfo"))]


# ---------------------------------------------------------------------------
# Hermes attach / detach
# ---------------------------------------------------------------------------


def attach_hermes(home: Path, *, dry_run: bool = False) -> Dict[str, Any]:
    """Enable Blackbox in a single Hermes *home*.

    Copies the plugin into ``<home>/plugins/blackbox/`` (only when missing or a
    version mismatch) and adds ``blackbox`` to ``plugins.enabled`` in
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
        dest = home / "plugins" / "blackbox"
        # Don't copy a home onto itself (e.g. running from inside a home).
        same_tree = src == dest or src == dest.resolve() if dest.exists() else False
        needs = (not same_tree) and _needs_copy(dest)
        if needs and not dry_run:
            _copy_plugin_tree(src, dest)
        report["copied"] = needs

        config_path = home / "config.yaml"
        data = _load_yaml(config_path)
        if _enabled_list_has(data, "blackbox"):
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
                if "blackbox" not in enabled:
                    enabled.append("blackbox")
                _dump_yaml(config_path, data)
            report["enabled"] = True
        report["ok"] = True
    except Exception as exc:  # fail open per target
        logger.debug("blackbox.attach: attach_hermes(%s) failed: %s", home, exc)
        report["error"] = str(exc)
    return report


def detach_hermes(home: Path, *, remove_files: bool = False, dry_run: bool = False) -> Dict[str, Any]:
    """Disable Blackbox in a single Hermes *home*.

    Removes ``blackbox`` from ``plugins.enabled`` (idempotent) and, when
    *remove_files* is set, deletes ``<home>/plugins/blackbox/``. Fails open.
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
        if _enabled_list_has(data, "blackbox"):
            if not dry_run:
                data["plugins"]["enabled"] = [p for p in data["plugins"]["enabled"] if p != "blackbox"]
                _dump_yaml(config_path, data)
            report["disabled"] = True
        else:
            report["already"] = True

        dest = home / "plugins" / "blackbox"
        if remove_files and dest.exists():
            if not dry_run:
                shutil.rmtree(dest)
            report["removed"] = True
        report["ok"] = True
    except Exception as exc:
        logger.debug("blackbox.attach: detach_hermes(%s) failed: %s", home, exc)
        report["error"] = str(exc)
    return report


# ---------------------------------------------------------------------------
# OpenClaw attach / detach
# ---------------------------------------------------------------------------


def _repo_openclaw_dir() -> Path:
    """The OpenClaw JS plugin in a repo checkout (sibling ``integrations/``)."""
    return _repo_root() / "integrations" / "openclaw"


def _bundled_openclaw_dir() -> Path:
    """The OpenClaw JS plugin bundled inside this (possibly installed) copy."""
    return _plugin_source_dir() / _BUNDLED_OPENCLAW_DIRNAME


def _is_openclaw_plugin_dir(path: Path) -> bool:
    """True when *path* is the OpenClaw plugin (identified by its manifest)."""
    try:
        return (path / "openclaw.plugin.json").is_file()
    except Exception:
        return False


def _openclaw_plugin_source() -> Optional[Path]:
    """Locate the OpenClaw JS plugin wherever this Blackbox copy runs from.

    An installed copy (``~/.hermes/plugins/blackbox``) has no sibling
    ``integrations/``, so the plugin is bundled into ``_openclaw`` at copy time
    and checked first; a repo checkout finds it via ``integrations/openclaw``.
    Returns ``None`` only when neither exists (e.g. a bare package with no repo),
    which the caller reports as an unprotected OpenClaw rather than a crash.
    """
    for candidate in (_bundled_openclaw_dir(), _repo_openclaw_dir()):
        if _is_openclaw_plugin_dir(candidate):
            return candidate
    return None


def _openclaw_load_paths_entry() -> Optional[str]:
    """Absolute path OpenClaw should load the Blackbox plugin from, or ``None``."""
    src = _openclaw_plugin_source()
    return str(src) if src is not None else None


def attach_openclaw(workspace: Path, *, dry_run: bool = False) -> Dict[str, Any]:
    """Enable Blackbox in a single OpenClaw *workspace*.

    Backs up ``openclaw.json``, then idempotently merges:

    * ``plugins.allow`` += ``"blackbox"``
    * ``plugins.load.paths`` += the absolute path to ``integrations/openclaw``
    * ``plugins.entries.blackbox`` = the Blackbox config + hook grants

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

        cfg = load_blackbox_config_snapshot()
        load_path = _openclaw_load_paths_entry()
        if load_path is None:
            report["note"] = (
                "integrations/openclaw not found next to this Blackbox copy "
                "(likely copied into a user home); recording intent without a load path."
            )
            logger.info("blackbox.attach: %s", report["note"])

        changed = _merge_openclaw(data, cfg, load_path)
        report["changed"] = changed
        report["already"] = not changed

        if changed and not dry_run:
            # Back up before writing.
            if config_path.exists():
                backup = config_path.with_suffix(".json.blackbox.bak")
                shutil.copy2(config_path, backup)
                report["backed_up"] = True
            _atomic_write(config_path, json.dumps(data, indent=2) + "\n")
        # Honest status: without a load path the blackbox block is recorded but
        # OpenClaw won't actually load the hook, so this workspace isn't protected.
        report["protected"] = load_path is not None
        report["ok"] = load_path is not None
    except Exception as exc:
        logger.debug("blackbox.attach: attach_openclaw(%s) failed: %s", workspace, exc)
        report["error"] = str(exc)
    return report


def _merge_openclaw(data: Dict[str, Any], cfg: Dict[str, Any], load_path: Optional[str]) -> bool:
    """Idempotently merge the Blackbox block into an ``openclaw.json`` dict.

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
    if "blackbox" not in allow:
        allow.append("blackbox")
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
            "dkgUrl": cfg["dkg_url"],
            "dkgHome": cfg["dkg_home"],
            "contextGraphId": cfg["context_graph_id"],
            "mode": cfg["mode"],
            # Point OpenClaw's local findings log at THIS Hermes blackbox home so
            # the one dashboard surfaces OpenClaw detections too. OpenClaw writes
            # findings.openclaw.jsonl here; the dashboard merges all findings*.jsonl.
            "blackboxHome": cfg.get("blackbox_home") or str(constants.blackbox_home()),
        },
        "hooks": {"allowConversationAccess": True},
    }
    if entries.get("blackbox") != desired_entry:
        entries["blackbox"] = desired_entry
        changed = True
    return changed


def detach_openclaw(workspace: Path, *, dry_run: bool = False) -> Dict[str, Any]:
    """Disable Blackbox in a single OpenClaw *workspace* (idempotent, fail-open)."""
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
            if isinstance(allow, list) and "blackbox" in allow:
                plugins["allow"] = [p for p in allow if p != "blackbox"]
                changed = True
            load = plugins.get("load")
            if isinstance(load, dict) and isinstance(load.get("paths"), list):
                # Remove ANY blackbox openclaw load path, not just the one that
                # resolves from this location — detaching an installed home would
                # otherwise orphan an entry pointing at a now-removed plugin.
                marker = os.path.join("integrations", "openclaw")
                kept = [
                    p for p in load["paths"]
                    if not (isinstance(p, str) and p.rstrip("/").endswith(marker))
                ]
                if len(kept) != len(load["paths"]):
                    load["paths"] = kept
                    changed = True
            entries = plugins.get("entries")
            if isinstance(entries, dict) and "blackbox" in entries:
                del entries["blackbox"]
                changed = True
        report["changed"] = changed
        report["already"] = not changed
        if changed and not dry_run:
            _atomic_write(config_path, json.dumps(data, indent=2) + "\n")
        report["ok"] = True
    except Exception as exc:
        logger.debug("blackbox.attach: detach_openclaw(%s) failed: %s", workspace, exc)
        report["error"] = str(exc)
    return report


# ---------------------------------------------------------------------------
# Config snapshot (for the OpenClaw entry) — decoupled from the running config
# ---------------------------------------------------------------------------


def load_blackbox_config_snapshot() -> Dict[str, Any]:
    """Resolve the Blackbox config values to seed into an OpenClaw workspace.

    Uses :func:`config.load_blackbox_config` when available (honours env +
    config.yaml), else falls back to constants. Kept tiny so ``attach`` stays
    testable without a full hermes config.
    """
    try:
        from .config import load_blackbox_config

        cfg = load_blackbox_config()
        return {
            "dkg_url": cfg.dkg_url,
            "dkg_home": cfg.dkg_home,
            "context_graph_id": cfg.context_graph_id,
            "mode": cfg.mode,
            "blackbox_home": str(constants.blackbox_home()),
        }
    except Exception:
        return {
            "dkg_url": constants.DEFAULT_DKG_URL,
            "dkg_home": str(constants.blackbox_dkg_home()),
            "context_graph_id": constants.DEFAULT_CONTEXT_GRAPH_ID,
            "mode": "audit",
            "blackbox_home": str(constants.blackbox_home()),
        }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def attach_all(*, hermes: bool = True, openclaw: bool = True, dry_run: bool = False) -> Dict[str, Any]:
    """Attach Blackbox to every discovered target. Returns a combined report."""
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
    """Detach Blackbox from every discovered target. Returns a combined report."""
    report: Dict[str, Any] = {"hermes": [], "openclaw": [], "dry_run": dry_run}
    if hermes:
        for home in discover_hermes_homes():
            report["hermes"].append(detach_hermes(home, remove_files=remove_files, dry_run=dry_run))
    if openclaw:
        for ws in discover_openclaw_workspaces():
            report["openclaw"].append(detach_openclaw(ws, dry_run=dry_run))
    return report


def _protected_count(report: Dict[str, Any]) -> int:
    """Number of targets Blackbox is (now) protecting in an attach report."""
    total = 0
    for row in report.get("hermes", []):
        if row.get("ok"):
            total += 1
    for row in report.get("openclaw", []):
        if row.get("ok"):
            total += 1
    return total
