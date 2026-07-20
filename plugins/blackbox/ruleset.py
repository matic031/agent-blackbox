"""Graph-synced rule cache.

The :class:`Ruleset` is built only from the curated public
``verifiable-memory`` graph. Community Shared Working Memory is a future
feature and is neither queried nor matched by the current release.

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

_SELECT_COLUMNS = """?threat ?rdfType ?identifier ?severity ?name ?description
       ?pattern ?toolName ?argShape ?packageName ?packageVersion
       ?packageEcosystem ?advisoryId ?curated ?category ?skillName
       ?skillVersion ?dangerShape ?kind ?iocValue"""

_GUARDIAN_THREATS_SELECT = f"""PREFIX g: <http://umanitek.ai/ontology/guardian/>
PREFIX schema: <http://schema.org/>
SELECT DISTINCT {_SELECT_COLUMNS}
WHERE {{
  ?threat g:identifier ?identifier .
  OPTIONAL {{ ?threat a ?rdfType . }}
  OPTIONAL {{ ?threat g:kind ?kind . }}
  OPTIONAL {{ ?threat g:severity ?severity . }}
  OPTIONAL {{ ?threat schema:name ?name . }}
  OPTIONAL {{ ?threat schema:description ?description . }}
  OPTIONAL {{ ?threat g:pattern ?pattern . }}
  OPTIONAL {{ ?threat g:toolName ?toolName . }}
  OPTIONAL {{ ?threat g:argShape ?argShape . }}
  OPTIONAL {{ ?threat g:packageName ?packageName . }}
  OPTIONAL {{ ?threat g:packageVersion ?packageVersion . }}
  OPTIONAL {{ ?threat g:packageEcosystem ?packageEcosystem . }}
  OPTIONAL {{ ?threat schema:identifier ?advisoryId . }}
  OPTIONAL {{ ?threat g:curated ?curated . }}
  OPTIONAL {{ ?threat g:category ?category . }}
  OPTIONAL {{ ?threat g:skillName ?skillName . }}
  OPTIONAL {{ ?threat g:skillVersion ?skillVersion . }}
  OPTIONAL {{ ?threat g:dangerShape ?dangerShape . }}
}}
ORDER BY ?threat
"""

_DEFENDER_PREFIXES = """PREFIX defender: <urn:defender:>
PREFIX dp: <urn:defender:p:>
PREFIX schema: <http://schema.org/>
"""

_DEFENDER_DEPENDENCY_SELECT = f"""{_DEFENDER_PREFIXES}
SELECT DISTINCT ?threat ?rdfType ?identifier ?severity ?name ?description
       ?pattern ?toolName ?argShape ?packageName ?packageVersion
       ?packageEcosystem ?advisoryId ?curated ?category ?skillName
       ?skillVersion ?dangerShape ?kind ?iocValue
WHERE {{
    ?threat a defender:DependencySignal .
    BIND(defender:DependencySignal AS ?rdfType)
    OPTIONAL {{ ?threat dp:kind ?kind . }}
    OPTIONAL {{ ?threat dp:severity ?severity . }}
    OPTIONAL {{ ?threat schema:name ?name . }}
    OPTIONAL {{ ?threat schema:description ?description . }}
    OPTIONAL {{ ?threat dp:package ?packageName . }}
    OPTIONAL {{ ?threat dp:version ?packageVersion . }}
    OPTIONAL {{ ?threat dp:ecosystem ?packageEcosystem . }}
    OPTIONAL {{ ?threat dp:advisoryId ?advisoryId . }}
}}
ORDER BY ?threat
"""

_DEFENDER_INJECTION_SELECT = f"""{_DEFENDER_PREFIXES}
SELECT DISTINCT ?threat ?rdfType ?identifier ?severity ?name ?description
       ?pattern ?toolName ?argShape ?packageName ?packageVersion
       ?packageEcosystem ?advisoryId ?curated ?category ?skillName
       ?skillVersion ?dangerShape ?kind ?iocValue
WHERE {{
    ?threat a defender:InjectionSignal .
    BIND(defender:InjectionSignal AS ?rdfType)
    OPTIONAL {{ ?threat dp:kind ?kind . }}
    OPTIONAL {{ ?threat dp:severity ?severity . }}
    OPTIONAL {{ ?threat schema:name ?name . }}
    OPTIONAL {{ ?threat schema:description ?description . }}
    OPTIONAL {{ ?threat dp:pattern ?pattern . }}
}}
ORDER BY ?threat
"""

_DEFENDER_SKILL_SELECT = f"""{_DEFENDER_PREFIXES}
SELECT DISTINCT ?threat ?rdfType ?identifier ?severity ?name ?description
       ?pattern ?toolName ?argShape ?packageName ?packageVersion
       ?packageEcosystem ?advisoryId ?curated ?category ?skillName
       ?skillVersion ?dangerShape ?kind ?iocValue
WHERE {{
    ?threat a defender:SkillSignal .
    BIND(defender:SkillSignal AS ?rdfType)
    OPTIONAL {{ ?threat dp:kind ?kind . }}
    OPTIONAL {{ ?threat dp:severity ?severity . }}
    OPTIONAL {{ ?threat schema:name ?name . }}
    OPTIONAL {{ ?threat schema:description ?description . }}
}}
ORDER BY ?threat
"""

_DEFENDER_IOC_SELECT = f"""{_DEFENDER_PREFIXES}
SELECT DISTINCT ?threat ?rdfType ?identifier ?severity ?name ?description
       ?pattern ?toolName ?argShape ?packageName ?packageVersion
       ?packageEcosystem ?advisoryId ?curated ?category ?skillName
       ?skillVersion ?dangerShape ?kind ?iocValue
WHERE {{
    ?threat a defender:IocSignal .
    BIND(defender:IocSignal AS ?rdfType)
    OPTIONAL {{ ?threat dp:kind ?kind . }}
    OPTIONAL {{ ?threat dp:severity ?severity . }}
    OPTIONAL {{ ?threat schema:name ?name . }}
    OPTIONAL {{ ?threat schema:description ?description . }}
    OPTIONAL {{ ?threat dp:iocType ?category . }}
    OPTIONAL {{ ?threat dp:value ?iocValue . }}
}}
ORDER BY ?threat
"""

# Rows fetched per page when syncing a tier. One SPARQL round-trip each.
_PAGE_SIZE = 5000
# Safety ceiling so a misbehaving node can never spin the pager forever.
_MAX_ROWS = 1_000_000


def _threats_sparql(limit: int, offset: int) -> str:
    return f"{_DEFENDER_DEPENDENCY_SELECT}LIMIT {int(limit)} OFFSET {int(offset)}"


def _defender_threats_sparql(limit: int, offset: int) -> tuple:
    limit = int(limit)
    offset = int(offset)
    return (
        f"{_DEFENDER_DEPENDENCY_SELECT}LIMIT {limit} OFFSET {offset}",
        f"{_DEFENDER_INJECTION_SELECT}LIMIT {limit} OFFSET {offset}",
        f"{_DEFENDER_SKILL_SELECT}LIMIT {limit} OFFSET {offset}",
        f"{_DEFENDER_IOC_SELECT}LIMIT {limit} OFFSET {offset}",
    )


def _guardian_threats_sparql(limit: int, offset: int) -> str:
    return f"{_GUARDIAN_THREATS_SELECT}LIMIT {int(limit)} OFFSET {int(offset)}"


def community_report_count(client: DkgClient, cfg: BlackboxConfig) -> int:
    """Count outbound sightings in the official SWM view."""
    sparql = (
        "SELECT (COUNT(DISTINCT ?r) AS ?n) WHERE { "
        "?r a <http://umanitek.ai/ontology/guardian/ThreatReport> }"
    )
    rows = client.query(
        sparql,
        cfg.context_graph_id,
        view=constants.VIEW_SHARED_WORKING_MEMORY,
        on_error=None,
    )
    if not rows:
        return 0
    try:
        return int(extract_binding(rows[0].get("n")) or 0)
    except (ValueError, TypeError):
        return 0


# ---------------------------------------------------------------------------
# Legacy proof verification (backward compatibility)
# ---------------------------------------------------------------------------

# This fallback keeps already-published proof-era rows effective.
_PROOFS_SPARQL = """PREFIX g: <http://umanitek.ai/ontology/guardian/>
SELECT ?proof ?root ?member WHERE {
  ?proof a g:CurationProof .
  ?proof g:anchorRoot ?root .
  ?proof g:anchorMember ?member .
}"""


def _fetch_proofs(client: DkgClient, cg_id: str) -> Dict[str, Dict[str, Any]]:
    """Legacy proofs from the VM view: subject -> {root, members}. Fail-open
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
    graph_threats: List[Dict[str, Any]] = field(default_factory=list)
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

    def graph_entries(self, source: str) -> List[Dict[str, Any]]:
        entries = [item for item in self.graph_threats if item.get("source") == source]
        seen = {item.get("identifier") for item in entries}
        for category, rule in self.iter_rules():
            identifier = rule.get("identifier")
            if rule.get("source") != source or identifier in seen:
                continue
            seen.add(identifier)
            entries.append({
                "identifier": identifier,
                "category": category,
                "severity": str(rule.get("severity") or "info").lower(),
                "name": rule.get("name") or "",
                "subject": rule.get("subject") or "",
                "source": source,
            })
        return entries

    def graph_count(self, source: str) -> int:
        return len(self.graph_entries(source))


# ---------------------------------------------------------------------------
# Build from query bindings
# ---------------------------------------------------------------------------


def _row_identity(row: Dict[str, Any]) -> tuple:
    subject = extract_binding(row.get("threat"))
    rdf_type = extract_binding(row.get("rdfType"))
    identifier = extract_binding(row.get("identifier"))
    suffix = subject.rsplit(":", 1)[-1] if subject else ""
    if not identifier and rdf_type == "urn:defender:DependencySignal":
        eco = extract_binding(row.get("packageEcosystem")).lower()
        pkg = extract_binding(row.get("packageName")).lower()
        ver = extract_binding(row.get("packageVersion"))
        if eco and pkg and ver:
            identifier = f"dep:{eco}:{pkg}@{ver}"
    elif not identifier and rdf_type == "urn:defender:InjectionSignal" and suffix:
        identifier = f"injection:{suffix}"
    elif not identifier and rdf_type == "urn:defender:SkillSignal" and suffix:
        identifier = f"skill:{suffix}"
    elif not identifier and rdf_type == "urn:defender:IocSignal":
        ioc_type = extract_binding(row.get("category")).strip().lower()
        ioc_value = extract_binding(row.get("iocValue"))
        if ioc_type and ioc_value:
            identifier = f"ioc:{ioc_type}:{ioc_value}"
    return subject, rdf_type, identifier


def _row_to_graph_entry(row: Dict[str, Any], source: str) -> Optional[Dict[str, Any]]:
    subject, _rdf_type, identifier = _row_identity(row)
    if not identifier:
        return None
    prefix = identifier.split(":", 1)[0].lower()
    category = {
        "dep": "dependency",
        "injection": "injection",
        "escalation": "escalation",
        "fileaccess": "fileaccess",
        "skill": "skill",
        "ioc": "ioc",
    }.get(prefix, "other")
    return {
        "identifier": identifier,
        "category": category,
        "severity": constants.normalize_severity(extract_binding(row.get("severity")), "high"),
        "name": extract_binding(row.get("name")) or identifier,
        "subject": subject,
        "source": source,
    }


def _row_to_rule(row: Dict[str, Any], source: str = "public") -> Optional[tuple]:
    """Map one SPARQL binding row to ``(category, key, rule)`` or ``None``.

    *source* tags the rule's trust tier: ``"public"`` (verifiable-memory, the
    curated source of truth) or ``"community"`` (shared-working-memory).
    """
    subject, rdf_type, identifier = _row_identity(row)
    if not identifier:
        return None
    severity = constants.normalize_severity(extract_binding(row.get("severity")), "high")
    name = extract_binding(row.get("name")) or identifier
    common = {
        "identifier": identifier,
        "subject": subject,
        "description": extract_binding(row.get("description")),
        "severity": severity,
        "name": name,
        "source": source,
    }
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
            **common,
            "pattern": compiled,
            "pattern_src": pattern_src,
        })
    if identifier.startswith("escalation:"):
        tool_name = extract_binding(row.get("toolName"))
        arg_shape = extract_binding(row.get("argShape"))
        if not tool_name or not arg_shape:
            return None
        return ("escalation", identifier, {
            **common,
            "toolName": tool_name,
            "argShape": arg_shape,
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
            **common,
            "ecosystem": eco,
            "packageName": pkg,
            "packageVersion": ver,
            "advisoryId": extract_binding(row.get("advisoryId")),
            "kind": extract_binding(row.get("kind")) or None,
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
            **common,
            "toolName": tool_name.strip().lower(),
            "category": category.strip().lower(),
        })
    if identifier.startswith("skill:"):
        rule = {
            **common,
            "skillName": extract_binding(row.get("skillName")) or name,
            "skillVersion": extract_binding(row.get("skillVersion")),
            "dangerShape": extract_binding(row.get("dangerShape")),
        }
        return ("skill", identifier, rule)
    if identifier.startswith("ioc:"):
        # ioc:{type}:{value} — type also carried in ?category; value is the rest.
        ioc_type = (extract_binding(row.get("category")) or "").strip().lower()
        parts = identifier.split(":", 2)
        if not ioc_type and len(parts) == 3:
            ioc_type = parts[1].strip().lower()
        return ("ioc", identifier, {
            **common,
            "iocType": ioc_type,
            "value": extract_binding(row.get("iocValue")) or (parts[2] if len(parts) == 3 else ""),
            "kind": extract_binding(row.get("kind")) or None,
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
    graph_seen: set = set()
    for item in rows:
        if isinstance(item, tuple):
            row, row_source = item
        else:
            row, row_source = item, source
        graph_entry = _row_to_graph_entry(row, row_source)
        if graph_entry:
            graph_key = (row_source, graph_entry["identifier"])
            if graph_key not in graph_seen:
                graph_seen.add(graph_key)
                rs.graph_threats.append(graph_entry)
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
        "graph_threats": rs.graph_threats,
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
        if rule.get("source", "public") == "public":
            rs.injection.append({**rule, "pattern": compiled})
    rs.escalation = [r for r in data.get("escalation", []) if r.get("source", "public") == "public"]
    rs.dependency = {k: r for k, r in data.get("dependency", {}).items() if r.get("source", "public") == "public"}
    rs.fileaccess = [r for r in data.get("fileaccess", []) if r.get("source", "public") == "public"]
    rs.skill = [r for r in data.get("skill", []) if r.get("source", "public") == "public"]
    rs.ioc = {k: r for k, r in data.get("ioc", {}).items() if r.get("source", "public") == "public"}
    rs.graph_threats = [r for r in data.get("graph_threats", []) if r.get("source", "public") == "public"]
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


def _fetch_tier(
    client: DkgClient,
    cg_id: str,
    view: str,
    agent_address: Optional[str] = None,
) -> Optional[List[Dict[str, Any]]]:
    """Fully paginate one tier. Returns all rows, or ``None`` if the node errored.

    ``None`` (error) is distinct from ``[]`` (the tier is genuinely empty) so
    the caller can preserve a tier's last-good rules through a transient failure
    instead of wiping them.
    """
    rows: List[Dict[str, Any]] = []
    query_groups = (
        lambda limit, offset: (_guardian_threats_sparql(limit, offset),),
        _defender_threats_sparql,
    )
    for query_group in query_groups:
        offset = 0
        while offset < _MAX_ROWS:
            kwargs: Dict[str, Any] = {"view": view, "on_error": _QUERY_ERROR}
            if agent_address:
                kwargs["agent_address"] = agent_address
            pages = []
            for query in query_group(_PAGE_SIZE, offset):
                page = client.query(query, cg_id, **kwargs)
                if page is _QUERY_ERROR:
                    return None
                pages.append(page)
                rows.extend(page)
            if all(len(page) < _PAGE_SIZE for page in pages):
                break
            offset += _PAGE_SIZE
    return rows


_EMPTY_RULESET_RETRY_S = 30.0
_NONEMPTY_REFRESH_MIN_S = 15 * 60.0


def refresh(config: Optional[BlackboxConfig] = None, client: Optional[DkgClient] = None) -> Ruleset:
    """Query the node, rebuild the ruleset, and persist it. Fail-open.

    Reads only the verified public graph (VM), fully paginated (no cap). If its
    query fails, the last-good public rules are preserved. On total
    failure, returns the last-good cache or an empty ruleset — never raises.
    """
    global _memory_cache
    config = config or load_blackbox_config()
    client = client or DkgClient(url=config.dkg_url, dkg_home=config.dkg_home)
    tiers = ((constants.VIEW_VERIFIABLE_MEMORY, "public"),)
    fetched = {tier: _fetch_tier(client, config.context_graph_id, view) for view, tier in tiers}

    # An entirely empty store gets an early cache-expiry below. Subscription,
    # admission, and catch-up are DKG daemon responsibilities; a cache read must
    # never restart network recovery.
    empty_success = all(rows == [] for rows in fetched.values())

    if empty_success:
        # Snapshot replacement is atomic from the user's perspective. A
        # transient empty query (or a concurrent refresh racing catch-up)
        # must never erase an already verified, enforceable ruleset.
        prior = _memory_cache or _read_cache()
        if prior is not None and prior.source_count("public") > 0:
            prior.synced_at = time.time()
            _write_cache(prior)
            with _memory_lock:
                _memory_cache = prior
            return prior

    if all(rows is None for rows in fetched.values()):
        # Every tier failed — keep the last-good ruleset instead of emptying.
        existing = _memory_cache or _read_cache()
        if existing is not None:
            existing.synced_at = time.time()
            _write_cache(existing)
            with _memory_lock:
                _memory_cache = existing
            return existing

    rows: List[Any] = []
    for tier, view_rows in fetched.items():
        if view_rows is None:  # a failed tier (fail-open handled below)
            continue
        rows.extend((row, tier) for row in view_rows)
    rs = build_from_rows(rows)
    if empty_success:
        # A fresh node's subscribe/catch-up is async. Do not cache "0 rules" as
        # fresh for the full sync interval; retry soon so the dashboard updates
        # shortly after VM lands locally.
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
    graph_seen = {(item.get("source"), item.get("identifier")) for item in rs.graph_threats}
    for item in prior.graph_threats:
        key = (item.get("source"), item.get("identifier"))
        if item.get("source") in keep and key not in graph_seen:
            graph_seen.add(key)
            rs.graph_threats.append(item)
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
        lock_fh = open(_lock_path(), "w", encoding="utf-8")
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
    refresh_after = max(1.0, float(config.sync_interval or 1))
    if cached.source_count("public") > 0:
        refresh_after = max(refresh_after, _NONEMPTY_REFRESH_MIN_S)
    # Atomic check-and-set under the lock so two callers can't both spawn.
    should_spawn = False
    with _memory_lock:
        if age > refresh_after and not _refreshing:
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


def peek(config: Optional[BlackboxConfig] = None) -> Ruleset:
    """Return the last cached ruleset without starting a node refresh.

    The dashboard has one dedicated refresh worker. Request handlers and the
    dashboard's catch-up watcher use this read-only path so a large initial DKG
    transfer cannot accidentally fan out additional Blazegraph queries.
    """
    global _memory_cache
    config = config or load_blackbox_config()
    del config  # Kept for API symmetry and future profile-aware caches.
    with _memory_lock:
        cached = _memory_cache
    if cached is None:
        cached = _read_cache() or Ruleset()
        with _memory_lock:
            if _memory_cache is None:
                _memory_cache = cached
            else:
                cached = _memory_cache
    return cached
