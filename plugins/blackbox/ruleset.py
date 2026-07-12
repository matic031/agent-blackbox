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

It is cached to ``$BLACKBOX_HOME/ruleset.json`` and refreshed lazily:
:func:`get` returns the cached ruleset immediately and, if the cache is older
than ``sync_interval``, kicks off a single non-blocking background refresh
(guarded by a file lock so only one refresher runs across processes). Every
path fails open to the last-good (or empty) ruleset.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import constants, quads
from .config import BlackboxConfig, load_blackbox_config
from .dkg_client import DkgClient, extract_binding

logger = logging.getLogger(__name__)

# SPARQL that pulls every threat's queryable fields. Paginated (never a fixed
# cap) so the local detector loads the WHOLE curated graph — spam is controlled
# by curator approvals, not by truncating detection. ``ORDER BY`` gives a stable
# order so LIMIT/OFFSET pages don't overlap or skip rows.
_THREATS_HEAD = """PREFIX g: <http://umanitek.ai/ontology/guardian/>
PREFIX schema: <http://schema.org/>
SELECT ?identifier ?severity ?name ?pattern ?toolName ?argShape
       ?packageName ?packageVersion ?packageEcosystem ?advisoryId ?curated
       ?category ?skillName ?skillVersion ?dangerShape ?kind
"""

# Threat-matching graph patterns, shared by the plain query (VM view) and the
# shared-memory-scoped community query.
_THREATS_BODY = """  ?threat g:identifier ?identifier .
  OPTIONAL { ?threat g:kind ?kind . }
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
"""

_THREATS_SELECT = f"{_THREATS_HEAD}WHERE {{\n{_THREATS_BODY}}}\nORDER BY ?identifier\n"

# Rows fetched per page when syncing a tier. One SPARQL round-trip each.
_PAGE_SIZE = 5000
# Safety ceiling so a misbehaving node can never spin the pager forever.
_MAX_ROWS = 1_000_000


def _threats_sparql(limit: int, offset: int) -> str:
    return f"{_THREATS_SELECT}LIMIT {int(limit)} OFFSET {int(offset)}"


# Lean field set for the community tier: only the fields ``_row_to_rule`` can't
# derive from the identifier. dep/skill/fileaccess parse their details from the
# id; injection needs ``pattern`` and escalation ``toolName``/``argShape``.
# Fewer OPTIONAL joins keep the scoped read a few seconds vs the full query's ~11s.
_COMMUNITY_SELECT = """PREFIX g: <http://umanitek.ai/ontology/guardian/>
PREFIX schema: <http://schema.org/>
SELECT ?threat ?identifier ?severity ?kind ?name ?pattern ?toolName ?argShape ?curated
"""
_COMMUNITY_BODY = """  ?threat g:identifier ?identifier .
  OPTIONAL { ?threat g:severity ?severity . }
  OPTIONAL { ?threat g:kind ?kind . }
  OPTIONAL { ?threat schema:name ?name . }
  OPTIONAL { ?threat g:pattern ?pattern . }
  OPTIONAL { ?threat g:toolName ?toolName . }
  OPTIONAL { ?threat g:argShape ?argShape . }
  OPTIONAL { ?threat g:curated ?curated . }
"""
# Read in a single scoped query — no OFFSET paging, which would re-scan every
# slice per page. A cap hit is logged, never silently truncated; production
# scale needs the node's SWM view indexed (see the seed runbook).
_COMMUNITY_MAX_ROWS = 50_000


def _shared_memory_sparql(cg_id: str, limit: int) -> str:
    """The lean threats query scoped to a context graph's shared-memory slices.

    Run against the local store via :meth:`DkgClient.query_store` for the
    community tier (see there for why). No ORDER BY — a single read, no paging.
    """
    prefix = f"did:dkg:context-graph:{cg_id}/_shared_memory"
    return (
        f"{_COMMUNITY_SELECT}WHERE {{\n  GRAPH ?g {{\n{_COMMUNITY_BODY}  }}\n"
        f'  FILTER(STRSTARTS(STR(?g), "{prefix}"))\n}}\n'
        f"LIMIT {int(limit)}"
    )


def community_report_count(client: DkgClient, cfg: BlackboxConfig) -> int:
    """Fast count of outbound sightings (``ThreatReport``s) in the community
    pool, via a scoped store read (not the view). Fail-open to 0."""
    prefix = f"did:dkg:context-graph:{cfg.context_graph_id}/_shared_memory"
    sparql = (
        "SELECT (COUNT(DISTINCT ?r) AS ?n) WHERE { GRAPH ?g { "
        "?r a <http://umanitek.ai/ontology/guardian/ThreatReport> } "
        f'FILTER(STRSTARTS(STR(?g), "{prefix}")) }}'
    )
    rows = client.query_store(sparql, on_error=None)
    if not rows:
        return 0
    try:
        return int(extract_binding(rows[0].get("n")) or 0)
    except (ValueError, TypeError):
        return 0


# ---------------------------------------------------------------------------
# Curation-proof verification (raw data on SWM, proofs on VM)
# ---------------------------------------------------------------------------

# Mirrors `_PROOFS_SPARQL` in cli.py — the curator publishes these anchors via
# `curate anchor`; consumers verify their synced SWM rows against them.
_PROOFS_SPARQL = """PREFIX g: <http://umanitek.ai/ontology/guardian/>
SELECT ?proof ?root ?member WHERE {
  ?proof a g:CurationProof .
  ?proof g:anchorRoot ?root .
  ?proof g:anchorMember ?member .
}"""


def _fetch_proofs(client: DkgClient, cg_id: str) -> Dict[str, Dict[str, Any]]:
    """Curation proofs from the VM view: subject -> {root, members}. Fail-open
    to {} — no proofs simply means no community row can be promoted."""
    try:
        rows = client.query(_PROOFS_SPARQL, cg_id, view=constants.VIEW_VERIFIABLE_MEMORY, on_error=None)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: proof query failed: %s", exc)
        return {}
    proofs: Dict[str, Dict[str, Any]] = {}
    for row in rows or []:
        subj = extract_binding(row.get("proof"))
        root = extract_binding(row.get("root"))
        member = extract_binding(row.get("member"))
        if not (subj and root and member):
            continue
        entry = proofs.setdefault(subj, {"root": root, "members": set()})
        if entry["root"] == root:
            entry["members"].add(member)
    return proofs


def verified_identifiers(community_rows: List[Dict[str, Any]], proofs: Dict[str, Dict[str, Any]]) -> set:
    """Identifiers of SWM threat rows covered by a matching VM proof.

    A proof verifies only when EVERY member is present locally and the batch
    root recomputed over their anchor hashes equals the published root — a
    tampered or missing row invalidates its whole batch, never silently
    passes. Verified identifiers earn the blockable ``public`` tier.
    """
    candidates: List[Dict[str, str]] = []
    for row in community_rows:
        # Hash only threat-subject rows: reports (urn:guardian:report:*) share
        # the identifier and would shadow the threat row's hash.
        if not extract_binding(row.get("threat")).startswith("urn:guardian:threat:"):
            continue
        candidates.append({k: extract_binding(row.get(k)) for k in quads.ANCHOR_FIELDS})
    if not candidates or not proofs:
        return set()
    hashes = quads.anchor_hashes_from_rows(candidates)
    ok: set = set()
    for entry in proofs.values():
        members = entry["members"]
        if not members or not members.issubset(hashes.keys()):
            continue
        root = quads.anchor_root((ident, hashes[ident]) for ident in members)
        if root == entry["root"]:
            ok |= members
    return ok


@dataclass
class Ruleset:
    """Compiled detection rules. See :mod:`detection` for how each is used."""

    injection: List[Dict[str, Any]] = field(default_factory=list)
    escalation: List[Dict[str, Any]] = field(default_factory=list)
    dependency: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    fileaccess: List[Dict[str, Any]] = field(default_factory=list)
    skill: List[Dict[str, Any]] = field(default_factory=list)
    # IOC rules keyed by full identifier (``ioc:{type}:{value}``) for O(1) lookup.
    ioc: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    synced_at: float = 0.0

    def counts(self) -> Dict[str, int]:
        return {
            "injection": len(self.injection),
            "escalation": len(self.escalation),
            "dependency": len(self.dependency),
            "fileaccess": len(self.fileaccess),
            "skill": len(self.skill),
            "ioc": len(self.ioc),
        }

    def iter_rules(self):
        """Yield ``(category, rule)`` for every rule across all categories, so
        callers (e.g. the dashboard) can filter/count by ``rule["source"]``
        straight from the synced cache instead of re-querying the node."""
        for r in self.injection:
            yield "injection", r
        for r in self.escalation:
            yield "escalation", r
        for r in self.dependency.values():
            yield "dependency", r
        for r in self.fileaccess:
            yield "fileaccess", r
        for r in self.skill:
            yield "skill", r
        for r in self.ioc.values():
            yield "ioc", r

    def source_count(self, source: str) -> int:
        """How many rules are tagged with *source* (``public`` | ``community``)."""
        return sum(1 for _cat, r in self.iter_rules() if r.get("source") == source)


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
            logger.debug("blackbox: skipping bad injection pattern %s: %s", identifier, exc)
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
        key = quads.dependency_key(eco, pkg, ver)
        return ("dependency", key, {
            "identifier": identifier,
            "ecosystem": eco,
            "packageName": pkg,
            "packageVersion": ver,
            "advisoryId": extract_binding(row.get("advisoryId")),
            "kind": extract_binding(row.get("kind")) or None,
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
    if identifier.startswith("ioc:"):
        # ioc:{type}:{value} — type also carried in ?category; value is the rest.
        ioc_type = (extract_binding(row.get("category")) or "").strip().lower()
        parts = identifier.split(":", 2)
        if not ioc_type and len(parts) == 3:
            ioc_type = parts[1].strip().lower()
        return ("ioc", identifier, {
            "identifier": identifier,
            "iocType": ioc_type,
            "kind": extract_binding(row.get("kind")) or None,
            "severity": severity,
            "name": name,
            "source": source,
        })
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
        elif category == "ioc":
            existing = rs.ioc.get(key)
            # Public (curated) rules always win over community rows.
            if existing is None or (
                existing.get("source") == "community" and rule.get("source") == "public"
            ):
                rs.ioc[key] = rule
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
    return constants.blackbox_home() / "ruleset.json"


def _lock_path() -> Path:
    return constants.blackbox_home() / "ruleset.lock"


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
        "ioc": rs.ioc,
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
    rs.ioc = dict(data.get("ioc", {}))
    return rs


def _write_cache(rs: Ruleset) -> None:
    try:
        home = constants.blackbox_home()
        home.mkdir(parents=True, exist_ok=True)
        tmp = _cache_path().with_suffix(".json.tmp")
        tmp.write_text(json.dumps(_serialize(rs)), encoding="utf-8")
        tmp.replace(_cache_path())
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: ruleset cache write failed: %s", exc)


def _read_cache() -> Optional[Ruleset]:
    path = _cache_path()
    if not path.exists():
        return None
    try:
        return _deserialize(json.loads(path.read_text(encoding="utf-8")))
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: ruleset cache read failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Refresh
# ---------------------------------------------------------------------------

_memory_lock = threading.Lock()
_memory_cache: Optional[Ruleset] = None
_refreshing = False


_QUERY_ERROR = object()  # sentinel: distinguishes a tier failure from an empty tier


def _fetch_tier(client: DkgClient, cg_id: str, view: str) -> Optional[List[Dict[str, Any]]]:
    """Fully paginate one tier. Returns all rows, or ``None`` if the node errored.

    ``None`` (error) is distinct from ``[]`` (the tier is genuinely empty) so
    the caller can preserve a tier's last-good rules through a transient failure
    instead of wiping them.
    """
    # Community tier: one scoped store read (see ``query_store``). No OFFSET
    # paging, which would re-scan every slice; a cap hit is logged, not truncated.
    if view == constants.VIEW_SHARED_WORKING_MEMORY:
        rows = client.query_store(
            _shared_memory_sparql(cg_id, _COMMUNITY_MAX_ROWS), on_error=_QUERY_ERROR
        )
        if rows is _QUERY_ERROR:
            return None
        if len(rows) >= _COMMUNITY_MAX_ROWS:
            logger.warning(
                "blackbox: community read hit the %d-row cap; some shared-memory "
                "threats may be missing until the node's SWM view is indexed",
                _COMMUNITY_MAX_ROWS,
            )
        return rows

    rows: List[Dict[str, Any]] = []
    offset = 0
    while offset < _MAX_ROWS:
        page = client.query(
            _threats_sparql(_PAGE_SIZE, offset), cg_id, view=view, on_error=_QUERY_ERROR
        )
        if page is _QUERY_ERROR:
            return None
        rows.extend(page)
        if len(page) < _PAGE_SIZE:
            break
        offset += _PAGE_SIZE
    return rows


_EMPTY_RULESET_RETRY_S = 30.0


def refresh(config: Optional[BlackboxConfig] = None, client: Optional[DkgClient] = None) -> Ruleset:
    """Query the node, rebuild the ruleset, and persist it. Fail-open.

    Merges the curated public graph (VM) with the community pool (SWM), fully
    paginated (no cap). Fail-open is *per tier*: if one tier's query fails, that
    tier's last-good rules are preserved instead of being wiped, so a transient
    public-graph error can never silently drop every blockable rule. On total
    failure, returns the last-good cache or an empty ruleset — never raises.
    """
    global _memory_cache
    config = config or load_blackbox_config()
    client = client or DkgClient(url=config.dkg_url, dkg_home=config.dkg_home)
    # Public curated graph first (source of truth), then the community pool.
    tiers = (
        (constants.VIEW_VERIFIABLE_MEMORY, "public"),
        (constants.VIEW_SHARED_WORKING_MEMORY, "community"),
    )
    fetched = {tier: _fetch_tier(client, config.context_graph_id, view) for view, tier in tiers}

    # An entirely empty store gets an early cache-expiry below. Subscription,
    # admission, and catch-up are DKG daemon responsibilities; a cache read must
    # never restart network recovery.
    empty_success = all(rows == [] for rows in fetched.values())

    if all(rows is None for rows in fetched.values()):
        # Every tier failed — keep the last-good ruleset instead of emptying.
        existing = _memory_cache or _read_cache()
        if existing is not None:
            existing.synced_at = time.time()
            _write_cache(existing)
            with _memory_lock:
                _memory_cache = existing
            return existing

    # Curated SWM rows whose batch root matches an on-chain curation proof are
    # promoted to the blockable public tier: the raw data lives in SWM, the VM
    # carries only the anchor. Fail-open — verification errors leave every
    # community row at the flag-only tier.
    verified: set = set()
    community_rows = fetched.get("community")
    if community_rows:
        try:
            verified = verified_identifiers(community_rows, _fetch_proofs(client, config.context_graph_id))
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox: proof verification failed: %s", exc)
    rows: List[Any] = []
    for tier, view_rows in fetched.items():
        if view_rows is None:  # a failed tier (fail-open handled below)
            continue
        if tier == "community" and verified:
            rows.extend(
                (row, "public" if extract_binding(row.get("identifier")) in verified else "community")
                for row in view_rows
            )
        else:
            rows.extend((row, tier) for row in view_rows)
    rs = build_from_rows(rows)
    if empty_success:
        # A fresh node's subscribe/catch-up is async. Do not cache "0 rules" as
        # fresh for the full sync interval; retry soon so the dashboard updates
        # shortly after SWM lands locally.
        interval = max(1.0, float(config.sync_interval or 1))
        retry_after = min(_EMPTY_RULESET_RETRY_S, interval)
        rs.synced_at = time.time() - interval + retry_after

    errored = [tier for tier, view_rows in fetched.items() if view_rows is None]
    if errored:
        prior = _memory_cache or _read_cache()
        if prior is not None:
            _restore_tiers(rs, prior, errored)

    _write_cache(rs)
    with _memory_lock:
        _memory_cache = rs
    return rs


def _restore_tiers(rs: Ruleset, prior: Ruleset, tiers: List[str]) -> None:
    """Re-add *prior* rules from the given (errored) *tiers* into *rs*.

    Only fills gaps: a rule already present from a freshly-fetched tier wins,
    and public still beats community for a shared dependency key — mirroring
    :func:`build_from_rows` precedence.
    """
    keep = set(tiers)
    for attr in ("injection", "escalation", "fileaccess", "skill"):
        seen = {r.get("identifier") for r in getattr(rs, attr)}
        for rule in getattr(prior, attr):
            if rule.get("source") in keep and rule.get("identifier") not in seen:
                getattr(rs, attr).append(rule)
    for attr in ("dependency", "ioc"):
        target = getattr(rs, attr)
        for key, rule in getattr(prior, attr).items():
            if rule.get("source") not in keep:
                continue
            existing = target.get(key)
            if existing is None or (existing.get("source") == "community" and rule.get("source") == "public"):
                target[key] = rule


def _background_refresh(config: BlackboxConfig) -> None:
    global _refreshing
    # Cross-process single-refresher guard via an exclusive lock file.
    lock_fh = None
    try:
        import fcntl

        home = constants.blackbox_home()
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
        logger.debug("blackbox: background refresh failed: %s", exc)
    finally:
        _refreshing = False
        if lock_fh is not None:
            try:
                lock_fh.close()
            except Exception:
                pass


def get(config: Optional[BlackboxConfig] = None) -> Ruleset:
    """Return the cached ruleset, lazily refreshing in the background if stale.

    Never blocks on the network: a stale cache is returned immediately while a
    single background thread refreshes it for the next call.
    """
    global _memory_cache, _refreshing
    config = config or load_blackbox_config()
    with _memory_lock:
        cached = _memory_cache
    if cached is None:
        cached = _read_cache() or Ruleset()
        with _memory_lock:
            _memory_cache = cached
    age = time.time() - cached.synced_at
    # Atomic check-and-set under the lock so two callers can't both spawn.
    should_spawn = False
    with _memory_lock:
        if age > max(1, config.sync_interval) and not _refreshing:
            _refreshing = True
            should_spawn = True
    if should_spawn:
        try:
            threading.Thread(
                target=_background_refresh, args=(config,), name="blackbox-ruleset", daemon=True
            ).start()
        except Exception:  # pragma: no cover
            with _memory_lock:
                _refreshing = False
    return cached
