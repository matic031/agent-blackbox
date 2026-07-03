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
from dataclasses import dataclass
from typing import Any, Dict

from . import constants

logger = logging.getLogger(__name__)

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


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
    daily_report_limit: int = 500
    block_severity: str = "critical"
    dashboard_port: int = 9700
    discover: bool = True
    osv_lookup: bool = True

    @property
    def block_enabled(self) -> bool:
        """True when the plugin is allowed to block tool calls."""
        return self.mode.lower() == "block"

    def meets_block_threshold(self, severity: str) -> bool:
        """True when *severity* is at or above the configured block threshold."""
        rank = constants.SEVERITY_RANK
        floor = rank.get(self.block_severity.lower(), rank["critical"])
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
                default=500,
            ),
            500,
        ),
        block_severity=block_severity,
        dashboard_port=_as_int(
            _env_or(entry, env="GUARDIAN_DASHBOARD_PORT", key="dashboard_port", default=9700), 9700
        ),
        discover=_as_bool(_env_or(entry, env="GUARDIAN_DISCOVER", key="discover", default=True), True),
        osv_lookup=_as_bool(
            _env_or(entry, env="GUARDIAN_OSV_LOOKUP", key="osv_lookup", default=True), True
        ),
    )
