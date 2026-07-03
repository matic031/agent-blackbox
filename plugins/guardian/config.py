"""Guardian configuration loading.

Config lives under ``plugins.entries.guardian.*`` in the hermes ``config.yaml``
and is read via :func:`hermes_cli.config.load_config`. Every key has an
environment-variable override that wins over the file (see the table in the
plugin README). Loading always fails open — a missing/broken config file
yields :class:`GuardianConfig` defaults rather than raising.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Tuple

from . import constants

#: The five detection categories a user can tune individually.
DETECTION_CATEGORIES = ("injection", "escalation", "dependency", "fileaccess", "skill")

logger = logging.getLogger(__name__)

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}

#: Sensible out-of-the-box protected paths — high-signal credential stores an
#: agent rarely has a legitimate reason to read. Applied only when the config
#: key is absent; an explicit (even empty) ``protected_paths`` list wins.
DEFAULT_PROTECTED_PATHS: Tuple[str, ...] = (
    "~/.ssh/*",
    "~/.aws/credentials",
    "*.pem",
)


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    raw = str(value).strip().lower()
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    return default


def _as_int(value: Any, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _env_or(entry: Dict[str, Any], *, env: str, key: str, default: Any) -> Any:
    """Resolve a single config value: env var wins, then config entry, then default."""
    env_val = os.environ.get(env)
    if env_val is not None and env_val.strip() != "":
        return env_val.strip()
    if key in entry and entry[key] is not None:
        return entry[key]
    return default


@dataclass(frozen=True)
class GuardianConfig:
    """Resolved Guardian settings for the current process."""

    mode: str = "audit"
    context_graph_id: str = constants.DEFAULT_CONTEXT_GRAPH_ID
    dkg_url: str = constants.DEFAULT_DKG_URL
    sync_interval: int = 300
    report: bool = True
    daily_report_limit: int = 9999
    report_min_severity: str = "high"
    block_severity: str = "critical"
    dashboard_port: int = 9700
    discover: bool = True
    osv_lookup: bool = True
    auto_attach: bool = True
    #: Per-category user policy: ``{category: {"enabled": bool, "min_severity": str}}``.
    #: Missing categories default to enabled at ``info`` (flag everything the
    #: graph knows). Config key: ``plugins.entries.guardian.detection.*``.
    categories: Mapping[str, Any] = field(default_factory=dict)
    #: User-defined protected path patterns (globs / prefixes). Access to a
    #: matching path is flagged locally (source="custom", never shared to SWM)
    #: and blocks in block mode. Config key: ``protected_paths``. Defaults to
    #: :data:`DEFAULT_PROTECTED_PATHS` when the key is absent.
    protected_paths: Tuple[str, ...] = DEFAULT_PROTECTED_PATHS

    @property
    def block_enabled(self) -> bool:
        """True when the plugin is allowed to block tool calls."""
        return self.mode.lower() == "block"

    def meets_block_threshold(self, severity: str) -> bool:
        """True when *severity* is at or above the configured block threshold."""
        rank = constants.SEVERITY_RANK
        floor = rank.get(self.block_severity.lower(), rank["critical"])
        return rank.get((severity or "").lower(), -1) >= floor

    def meets_report_threshold(self, severity: str) -> bool:
        """True when a heuristic candidate at *severity* is worth flagging.

        Graph-backed findings (public or community) are always flagged; this
        threshold only gates the built-in discovery heuristics so low-signal
        candidates don't drown the findings feed and the community graph.
        """
        rank = constants.SEVERITY_RANK
        floor = rank.get(self.report_min_severity.lower(), rank["high"])
        return rank.get((severity or "").lower(), -1) >= floor

    def category_setting(self, category: str) -> Dict[str, Any]:
        """Resolved user policy for one category: ``{"enabled", "min_severity"}``.

        Defaults: enabled at ``info`` — flag everything Guardian can detect for
        that category. A user who only cares about e.g. critical dependency
        vulns sets ``detection.dependency.min_severity: critical``.
        """
        raw = self.categories.get(category) if isinstance(self.categories, Mapping) else None
        raw = raw if isinstance(raw, Mapping) else {}
        min_sev = str(raw.get("min_severity") or "info").lower()
        if min_sev not in constants.SEVERITY_RANK:
            min_sev = "info"
        enabled = raw.get("enabled")
        return {
            "enabled": bool(enabled) if isinstance(enabled, bool) else True,
            "min_severity": min_sev,
        }

    def category_allows(self, category: str, severity: str) -> bool:
        """True when the user's policy lets a *category* finding at *severity* flag."""
        setting = self.category_setting(category)
        if not setting["enabled"]:
            return False
        rank = constants.SEVERITY_RANK
        floor = rank[setting["min_severity"]]
        return rank.get((severity or "").lower(), -1) >= floor


def _guardian_entry() -> Dict[str, Any]:
    """Return the ``plugins.entries.guardian`` mapping, or ``{}`` on any error."""
    try:
        from hermes_cli.config import load_config

        cfg = load_config()
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("guardian: config load failed (%s); using defaults", exc)
        return {}
    entries = ((cfg.get("plugins") or {}).get("entries") or {})
    entry = entries.get("guardian") or {}
    return entry if isinstance(entry, dict) else {}


def load_guardian_config() -> GuardianConfig:
    """Build a :class:`GuardianConfig` from config file + environment overrides."""
    entry = _guardian_entry()
    mode = str(_env_or(entry, env="GUARDIAN_MODE", key="mode", default="audit")).lower()
    if mode not in {"audit", "block"}:
        mode = "audit"
    block_severity = str(
        _env_or(entry, env="GUARDIAN_BLOCK_SEVERITY", key="block_severity", default="critical")
    ).lower()
    if block_severity not in constants.SEVERITY_RANK:
        block_severity = "critical"
    report_min_severity = str(
        _env_or(
            entry,
            env="GUARDIAN_REPORT_MIN_SEVERITY",
            key="report_min_severity",
            default="high",
        )
    ).lower()
    if report_min_severity not in constants.SEVERITY_RANK:
        report_min_severity = "high"
    categories = _normalize_categories(entry.get("detection"))
    protected_paths = _normalize_protected_paths(entry.get("protected_paths"))
    return GuardianConfig(
        mode=mode,
        context_graph_id=str(
            _env_or(
                entry,
                env="GUARDIAN_CONTEXT_GRAPH_ID",
                key="context_graph_id",
                default=constants.DEFAULT_CONTEXT_GRAPH_ID,
            )
        ),
        dkg_url=str(
            _env_or(entry, env="DKG_DAEMON_URL", key="dkg_url", default=constants.DEFAULT_DKG_URL)
        ).rstrip("/"),
        sync_interval=_as_int(
            _env_or(entry, env="GUARDIAN_SYNC_INTERVAL", key="sync_interval", default=300), 300
        ),
        report=_as_bool(_env_or(entry, env="GUARDIAN_REPORT", key="report", default=True), True),
        daily_report_limit=_as_int(
            _env_or(
                entry,
                env="GUARDIAN_DAILY_REPORT_LIMIT",
                key="daily_report_limit",
                default=9999,
            ),
            9999,
        ),
        report_min_severity=report_min_severity,
        block_severity=block_severity,
        dashboard_port=_as_int(
            _env_or(entry, env="GUARDIAN_DASHBOARD_PORT", key="dashboard_port", default=9700), 9700
        ),
        discover=_as_bool(_env_or(entry, env="GUARDIAN_DISCOVER", key="discover", default=True), True),
        osv_lookup=_as_bool(
            _env_or(entry, env="GUARDIAN_OSV_LOOKUP", key="osv_lookup", default=True), True
        ),
        auto_attach=_as_bool(
            _env_or(entry, env="GUARDIAN_AUTO_ATTACH", key="auto_attach", default=True), True
        ),
        categories=categories,
        protected_paths=protected_paths,
    )


def _normalize_categories(raw: Any) -> Dict[str, Dict[str, Any]]:
    """Validate the ``detection`` config mapping into per-category policy dicts."""
    out: Dict[str, Dict[str, Any]] = {}
    if not isinstance(raw, dict):
        return out
    for category in DETECTION_CATEGORIES:
        item = raw.get(category)
        if not isinstance(item, dict):
            continue
        setting: Dict[str, Any] = {}
        if isinstance(item.get("enabled"), bool):
            setting["enabled"] = item["enabled"]
        min_sev = str(item.get("min_severity") or "").lower()
        if min_sev in constants.SEVERITY_RANK:
            setting["min_severity"] = min_sev
        if setting:
            out[category] = setting
    return out


def _normalize_protected_paths(raw: Any) -> Tuple[str, ...]:
    """Validate ``protected_paths`` into a tuple of non-empty pattern strings.

    A missing key (``None``) falls back to :data:`DEFAULT_PROTECTED_PATHS`; an
    explicit list — including an empty one — is honoured verbatim so a user who
    clears the list keeps it cleared.
    """
    if raw is None:
        return DEFAULT_PROTECTED_PATHS
    if not isinstance(raw, (list, tuple)):
        return ()
    out = []
    for item in raw:
        text = str(item or "").strip()
        if text and text not in out:
            out.append(text)
    return tuple(out[:100])
