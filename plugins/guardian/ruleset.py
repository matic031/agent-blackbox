"""Graph-synced rule cache.

The :class:`Ruleset` is built entirely from DKG query results, merged from two
tiers with strict precedence:

* ``verifiable-memory`` (the curated public threat graph) → rules tagged
  ``source: "public"``. The source of truth: matches are CONFIRMED and, in
  block mode, blockable.
* ``shared-working-memory`` (the community pool) → rules tagged
  ``source: "community"``. Checked only when the public graph doesn't already
  cover the identifier: matches are flagged but NEVER block — anyone can write
  to the community pool, so it must not be able to stop tool calls.

It is cached to ``$GUARDIAN_HOME/ruleset.json`` and refreshed lazily:
:func:`get` returns the cached ruleset immediately and, if the cache is older
than ``sync_interval``, kicks off a single non-blocking background refresh
(guarded by a file lock so only one refresher runs across processes). Every
path fails open to the last-good (or empty) ruleset.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import constants
from .config import GuardianConfig, load_guardian_config
from .dkg_client import DkgClient, extract_binding

logger = logging.getLogger(__name__)

# SPARQL that pulls every threat's queryable fields in one shot.
_THREATS_SPARQL = """
PREFIX g: <http://umanitek.ai/ontology/guardian/>
PREFIX schema: <http://schema.org/>
SELECT ?identifier ?severity ?name ?pattern ?toolName ?argShape
       ?packageName ?packageVersion ?packageEcosystem ?advisoryId ?curated
       ?category ?skillName ?skillVersion ?dangerShape
WHERE {
  ?threat g:identifier ?identifier .
  OPTIONAL { ?threat g:severity ?severity . }
  OPTIONAL { ?threat schema:name ?name . }
  OPTIONAL { ?threat g:pattern ?pattern . }
  OPTIONAL { ?threat g:toolName ?toolName . }
  OPTIONAL { ?threat g:argShape ?argShape . }
  OPTIONAL { ?threat g:packageName ?packageName . }
  OPTIONAL { ?threat g:packageVersion ?packageVersion . }
  OPTIONAL { ?threat g:packageEcosystem ?packageEcosystem . }
  OPTIONAL { ?threat schema:identifier ?advisoryId . }
  OPTIONAL { ?threat g:curated ?curated . }
  OPTIONAL { ?threat g:category ?category . }
  OPTIONAL { ?threat g:skillName ?skillName . }
  OPTIONAL { ?threat g:skillVersion ?skillVersion . }
  OPTIONAL { ?threat g:dangerShape ?dangerShape . }
}
LIMIT 2000
"""


@dataclass
class Ruleset:
    """Compiled detection rules. See :mod:`detection` for how each is used."""

    injection: List[Dict[str, Any]] = field(default_factory=list)
    escalation: List[Dict[str, Any]] = field(default_factory=list)
    dependency: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    fileaccess: List[Dict[str, Any]] = field(default_factory=list)
    skill: List[Dict[str, Any]] = field(default_factory=list)
    synced_at: float = 0.0

    def counts(self) -> Dict[str, int]:
        return {
            "injection": len(self.injection),
            "escalation": len(self.escalation),
            "dependency": len(self.dependency),
            "fileaccess": len(self.fileaccess),
            "skill": len(self.skill),
        }


# ---------------------------------------------------------------------------
# Build from query bindings
# ---------------------------------------------------------------------------


def _row_to_rule(row: Dict[str, Any], source: str = "public") -> Optional[tuple]:
    """Map one SPARQL binding row to ``(category, key, rule)`` or ``None``.

    *source* tags the rule's trust tier: ``"public"`` (verifiable-memory, the
    curated source of truth) or ``"community"`` (shared-working-memory).
    """
    identifier = extract_binding(row.get("identifier"))
    if not identifier:
        return None
    severity = constants.normalize_severity(extract_binding(row.get("severity")), "high")
    name = extract_binding(row.get("name")) or identifier
    if identifier.startswith("injection:"):
        pattern_src = extract_binding(row.get("pattern"))
        if not pattern_src:
            return None
        try:
            compiled = re.compile(pattern_src, re.IGNORECASE)
        except re.error as exc:
            logger.debug("guardian: skipping bad injection pattern %s: %s", identifier, exc)
            return None
        return ("injection", identifier, {
            "identifier": identifier,
            "pattern": compiled,
            "pattern_src": pattern_src,
            "severity": severity,
            "name": name,
            "source": source,
        })
    if identifier.startswith("escalation:"):
        tool_name = extract_binding(row.get("toolName"))
        arg_shape = extract_binding(row.get("argShape"))
        if not tool_name or not arg_shape:
            return None
        return ("escalation", identifier, {
            "identifier": identifier,
            "toolName": tool_name,
            "argShape": arg_shape,
            "severity": severity,
            "name": name,
            "source": source,
        })
    if identifier.startswith("dep:"):
        eco = extract_binding(row.get("packageEcosystem")).lower()
        pkg = extract_binding(row.get("packageName")).lower()
        ver = extract_binding(row.get("packageVersion"))
        if not (eco and pkg and ver):
            # Fall back to parsing the identifier: dep:{eco}:{name}@{version}
            try:
                _, rest = identifier.split(":", 1)
                eco2, tail = rest.split(":", 1)
                pkg2, ver2 = tail.rsplit("@", 1)
                eco, pkg, ver = eco2.lower(), pkg2.lower(), ver2
            except ValueError:
                return None
        key = f"{eco}:{pkg}@{ver}"
        return ("dependency", key, {
            "identifier": identifier,
            "ecosystem": eco,
            "packageName": pkg,
            "packageVersion": ver,
            "advisoryId": extract_binding(row.get("advisoryId")),
            "severity": severity,
            "name": name,
            "source": source,
        })
    if identifier.startswith("fileaccess:"):
        tool_name = extract_binding(row.get("toolName"))
        category = extract_binding(row.get("category"))
        if not (tool_name and category):
            # Fall back to parsing: fileaccess:{tool}:{category}
            try:
                _, tool_name, category = identifier.split(":", 2)
            except ValueError:
                return None
        return ("fileaccess", identifier, {
            "identifier": identifier,
            "toolName": tool_name.strip().lower(),
            "category": category.strip().lower(),
            "severity": severity,
            "name": name,
            "source": source,
        })
    if identifier.startswith("skill:"):
        rule = {
            "identifier": identifier,
            "skillName": extract_binding(row.get("skillName")),
            "skillVersion": extract_binding(row.get("skillVersion")),
            "dangerShape": extract_binding(row.get("dangerShape")),
            "severity": severity,
            "name": name,
            "source": source,
        }
        return ("skill", identifier, rule)
    return None


def build_from_rows(rows: List[Dict[str, Any]], source: str = "public") -> Ruleset:
    """Build a :class:`Ruleset` from ``(rows, source)`` pairs or plain rows.

    *rows* may be a flat list of binding rows (all tagged *source*) or a list
    of ``(row, source)`` tuples as produced by :func:`refresh`. Precedence is
    identifier-first-wins with public beating community, so a community row can
    never shadow (or escalate/downgrade) a curated public rule.
    """
    rs = Ruleset(synced_at=time.time())
    inj_seen: set = set()
    esc_seen: set = set()
    fa_seen: set = set()
    skill_seen: set = set()
    for item in rows:
        if isinstance(item, tuple):
            row, row_source = item
        else:
            row, row_source = item, source
        mapped = _row_to_rule(row, row_source)
        if not mapped:
            continue
        category, key, rule = mapped
        if category == "injection":
            if key not in inj_seen:
                inj_seen.add(key)
                rs.injection.append(rule)
        elif category == "escalation":
            if key not in esc_seen:
                esc_seen.add(key)
                rs.escalation.append(rule)
        elif category == "fileaccess":
            if key not in fa_seen:
                fa_seen.add(key)
                rs.fileaccess.append(rule)
        elif category == "skill":
            if key not in skill_seen:
                skill_seen.add(key)
                rs.skill.append(rule)
        else:
            existing = rs.dependency.get(key)
            # Public (curated) rules always win over community rows.
            if existing is None or (
                existing.get("source") == "community" and rule.get("source") == "public"
            ):
                rs.dependency[key] = rule
    return rs


# ---------------------------------------------------------------------------
# Cache persistence
# ---------------------------------------------------------------------------


def _cache_path() -> Path:
    return constants.guardian_home() / "ruleset.json"


def _lock_path() -> Path:
    return constants.guardian_home() / "ruleset.lock"


def _serialize(rs: Ruleset) -> Dict[str, Any]:
    return {
        "synced_at": rs.synced_at,
        "injection": [
            {k: v for k, v in rule.items() if k != "pattern"} for rule in rs.injection
        ],
        "escalation": rs.escalation,
        "dependency": rs.dependency,
        "fileaccess": rs.fileaccess,
        "skill": rs.skill,
    }


def _deserialize(data: Dict[str, Any]) -> Ruleset:
    rs = Ruleset(synced_at=float(data.get("synced_at", 0.0)))
    for rule in data.get("injection", []):
        src = rule.get("pattern_src")
        if not src:
            continue
        try:
            compiled = re.compile(src, re.IGNORECASE)
        except re.error:
            continue
        rs.injection.append({**rule, "pattern": compiled})
    rs.escalation = list(data.get("escalation", []))
    rs.dependency = dict(data.get("dependency", {}))
    rs.fileaccess = list(data.get("fileaccess", []))
    rs.skill = list(data.get("skill", []))
    return rs


def _write_cache(rs: Ruleset) -> None:
    try:
        home = constants.guardian_home()
        home.mkdir(parents=True, exist_ok=True)
        tmp = _cache_path().with_suffix(".json.tmp")
        tmp.write_text(json.dumps(_serialize(rs)), encoding="utf-8")
        tmp.replace(_cache_path())
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("guardian: ruleset cache write failed: %s", exc)


def _read_cache() -> Optional[Ruleset]:
    path = _cache_path()
    if not path.exists():
        return None
    try:
        return _deserialize(json.loads(path.read_text(encoding="utf-8")))
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("guardian: ruleset cache read failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------

_memory_lock = threading.Lock()
_memory_cache: Optional[Ruleset] = None
_refreshing = False


def refresh(config: Optional[GuardianConfig] = None, client: Optional[DkgClient] = None) -> Ruleset:
    """Query the node, rebuild the ruleset, and persist it. Fail-open.

    Merges curated threats (VM view) with the node's local graph (SWM view).
    On total failure, returns the last-good cache or an empty ruleset — never
    raises.
    """
    global _memory_cache
    config = config or load_guardian_config()
    client = client or DkgClient(url=config.dkg_url)
    rows: List[Any] = []
    got_any = False
    # Public curated graph first (source of truth), then the community pool.
    tiers = (
        (constants.VIEW_VERIFIABLE_MEMORY, "public"),
        (constants.VIEW_SHARED_WORKING_MEMORY, "community"),
    )
    for view, tier in tiers:
        try:
            view_rows = client.query(_THREATS_SPARQL, config.context_graph_id, view=view)
            if view_rows:
                got_any = True
                rows.extend((row, tier) for row in view_rows)
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("guardian: ruleset query (%s) failed: %s", view, exc)
    if not got_any and not rows:
        # Nothing came back — keep the last-good ruleset instead of emptying.
        existing = _memory_cache or _read_cache()
        if existing is not None:
            existing.synced_at = time.time()
            _write_cache(existing)
            with _memory_lock:
                _memory_cache = existing
            return existing
    rs = build_from_rows(rows)
    _write_cache(rs)
    with _memory_lock:
        _memory_cache = rs
    return rs


def _background_refresh(config: GuardianConfig) -> None:
    global _refreshing
    # Cross-process single-refresher guard via an exclusive lock file.
    lock_fh = None
    try:
        import fcntl

        home = constants.guardian_home()
        home.mkdir(parents=True, exist_ok=True)
        lock_fh = open(_lock_path(), "w")
        try:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError):
            lock_fh.close()
            _refreshing = False  # release the in-process guard for the next attempt
            return  # another process is already refreshing
    except Exception:
        lock_fh = None  # platform without fcntl — fall back to in-process guard only
    try:
        refresh(config)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("guardian: background refresh failed: %s", exc)
    finally:
        _refreshing = False
        if lock_fh is not None:
            try:
                lock_fh.close()
            except Exception:
                pass


def get(config: Optional[GuardianConfig] = None) -> Ruleset:
    """Return the cached ruleset, lazily refreshing in the background if stale.

    Never blocks on the network: a stale cache is returned immediately while a
    single background thread refreshes it for the next call.
    """
    global _memory_cache, _refreshing
    config = config or load_guardian_config()
    with _memory_lock:
        cached = _memory_cache
    if cached is None:
        cached = _read_cache() or Ruleset()
        with _memory_lock:
            _memory_cache = cached
    age = time.time() - cached.synced_at
    if age > max(1, config.sync_interval) and not _refreshing:
        _refreshing = True
        try:
            threading.Thread(
                target=_background_refresh, args=(config,), name="guardian-ruleset", daemon=True
            ).start()
        except Exception:  # pragma: no cover
            _refreshing = False
    return cached
