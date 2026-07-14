"""Client-side OSV vulnerability lookup for dependency auto-discovery.

A tiny, dependency-free helper around ``https://api.osv.dev/v1/query``. It is
the DISCOVERY nomination layer for dependencies: when an install is detected
whose package is NOT already in the graph ruleset, :func:`lookup` asks OSV
whether that exact ``package@version`` is known-vulnerable. If so, the caller
auto-submits a *candidate* dependency threat.

Design constraints (all enforced here):

* **stdlib only** — ``urllib``; no new third-party dependency.
* **fail-open** — any transport/parse error returns ``None`` (no finding).
* **short timeout** — never delays the agent loop meaningfully.
* **privacy** — only OSV-*vulnerable* installs are ever surfaced; a clean
  package returns ``None`` and is never reported.
* **cached** — an in-memory dedupe cache keyed by ``eco:name@version`` so a
  repeated install in the same process makes at most one network call.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_OSV_URL = "https://api.osv.dev/v1/query"
_TIMEOUT = 3.0

#: Blackbox ecosystem slug → OSV ecosystem name. ``homebrew`` has no OSV
#: ecosystem, so it is intentionally absent (skipped, never looked up).
_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "cargo": "crates.io",
    "rubygems": "RubyGems",
}

# In-memory result cache. Value is the finding dict or None (clean/skip).
_cache: Dict[str, Optional[Dict[str, str]]] = {}
_cache_lock = threading.Lock()


def osv_ecosystem(ecosystem: str) -> Optional[str]:
    """Map a Blackbox ecosystem slug to its OSV name, or ``None`` to skip."""
    return _ECOSYSTEM_MAP.get((ecosystem or "").strip().lower())


def _severity_of(vuln: Dict[str, Any]) -> str:
    """Best-effort severity from an OSV vuln record (defaults to ``high``)."""
    # OSV database_specific.severity is the most common human label.
    dbs = vuln.get("database_specific")
    if isinstance(dbs, dict):
        raw = str(dbs.get("severity") or "").strip().lower()
        if raw:
            return raw
    # Fall back to ecosystem-specific severity blocks when present.
    for aff in vuln.get("affected") or []:
        if isinstance(aff, dict):
            aff_dbs = aff.get("database_specific")
            if isinstance(aff_dbs, dict):
                raw = str(aff_dbs.get("severity") or "").strip().lower()
                if raw:
                    return raw
    return "high"


def _query(osv_eco: str, name: str, version: str) -> Optional[Dict[str, Any]]:
    body = json.dumps({"package": {"ecosystem": osv_eco, "name": name}, "version": version}).encode("utf-8")
    req = urllib.request.Request(
        _OSV_URL, data=body, headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            raw = resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError) as exc:
        logger.debug("blackbox: OSV query failed for %s@%s: %s", name, version, exc)
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:  # pragma: no cover - defensive
        return None


def lookup(ecosystem: str, name: str, version: str) -> Optional[Dict[str, str]]:
    """Return ``{advisory_id, severity}`` if OSV knows *name@version* vulnerable.

    Returns ``None`` when the package is clean, the ecosystem is unsupported,
    the version is missing, or anything fails (fail-open). Cached per process.
    """
    eco = (ecosystem or "").strip().lower()
    name = (name or "").strip()
    version = (version or "").strip()
    if not name or not version:
        return None
    osv_eco = osv_ecosystem(eco)
    if not osv_eco:
        return None
    key = f"{eco}:{name.lower()}@{version}"
    with _cache_lock:
        if key in _cache:
            return _cache[key]
    result: Optional[Dict[str, str]] = None
    data = _query(osv_eco, name, version)
    if isinstance(data, dict):
        vulns = data.get("vulns")
        if isinstance(vulns, list) and vulns:
            first = vulns[0] if isinstance(vulns[0], dict) else {}
            advisory_id = str(first.get("id") or "OSV")
            result = {"advisory_id": advisory_id, "severity": _severity_of(first)}
    with _cache_lock:
        _cache[key] = result
    return result
