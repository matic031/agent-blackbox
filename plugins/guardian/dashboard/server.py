"""Standalone Guardian dashboard — a tiny FastAPI app bound to loopback.

Routes:

* ``GET /``                 → the single-page ``static/index.html``.
* ``GET /api/findings``     → findings.jsonl, newest-first, paged.
* ``GET /api/graph-status`` → curated threat counts + last sync + ruleset counts.
* ``GET /api/reports``      → recent outbound sightings from the community graph.
* ``GET /api/agents``       → distinct threat reporters + this node's own agent.
* ``GET /api/graph``        → threats per tier: ``public`` (verifiable-memory,
  the curated Umanitek threat graph), ``community`` (shared-working-memory,
  the community pool), ``local`` (working-memory, this node's own graph).

FastAPI/uvicorn come from the hermes ``[web]`` extra — imported lazily so the
rest of the plugin has no web dependency. Served on ``127.0.0.1`` only.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).resolve().parent / "static"
_ASSETS_DIR = Path(__file__).resolve().parent / "assets"


def create_app():
    """Build and return the FastAPI application."""
    from fastapi import Body, FastAPI, Query
    from fastapi.responses import FileResponse, JSONResponse, HTMLResponse

    from .. import audit, constants, ruleset, settings
    from ..config import load_guardian_config
    from ..dkg_client import DkgClient, extract_binding

    app = FastAPI(title="Umanitek Agent Guardian", docs_url=None, redoc_url=None)

    _PREFIX = "PREFIX g: <http://umanitek.ai/ontology/guardian/> "

    def _count_query(client: "DkgClient", cfg: Any, where: str, view: str) -> int:
        """Run a single-``?n``-binding COUNT query; 0 on any failure (fail-open)."""
        try:
            rows = client.query(_PREFIX + where, cfg.context_graph_id, view=view)
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("guardian dashboard: count query failed: %s", exc)
            return 0
        if not rows:
            return 0
        try:
            return int(extract_binding(rows[0].get("n")) or "0")
        except (TypeError, ValueError):
            return 0

    @app.get("/", response_class=HTMLResponse)
    def index() -> Any:
        html = _STATIC_DIR / "index.html"
        if html.exists():
            # Never cache the SPA shell — it's a live tool that updates in place,
            # so a browser should always fetch the current dashboard, not a stale copy.
            return FileResponse(str(html), headers={"Cache-Control": "no-cache, no-store, must-revalidate"})
        return HTMLResponse("<h1>Guardian</h1><p>dashboard assets missing</p>", status_code=200)

    @app.get("/assets/{name}")
    def asset(name: str) -> Any:
        # Serve only the two known-safe brand SVGs (no path traversal).
        allowed = {"guardian-logo.svg", "umanitek-icon.svg"}
        if name not in allowed:
            return JSONResponse({"error": "not found"}, status_code=404)
        path = _ASSETS_DIR / name
        if not path.exists():
            return JSONResponse({"error": "not found"}, status_code=404)
        return FileResponse(str(path), media_type="image/svg+xml")

    @app.get("/vendor/{name}")
    def vendor(name: str) -> Any:
        # Serve only the vendored force-graph bundle (allowlist, no traversal).
        allowed = {"force-graph.min.js"}
        if name not in allowed:
            return JSONResponse({"error": "not found"}, status_code=404)
        path = _STATIC_DIR / "vendor" / name
        if not path.exists():
            return JSONResponse({"error": "not found"}, status_code=404)
        return FileResponse(str(path), media_type="application/javascript")

    @app.get("/api/settings")
    def get_settings() -> Any:
        """Current user-tunable detection policy (defaults included)."""
        try:
            return settings.read_settings()
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("guardian dashboard: read settings failed: %s", exc)
            return JSONResponse({"error": "could not read settings"}, status_code=500)

    @app.post("/api/settings")
    def post_settings(payload: Dict[str, Any] = Body(...)) -> Any:
        """Validate + persist detection policy under plugins.entries.guardian.*.

        Loopback-only (same bind as the whole dashboard); writes are validated
        server-side in :mod:`settings` so a malformed body can't corrupt config.
        """
        try:
            result = settings.write_settings(payload)
            return JSONResponse(result, status_code=200 if result.get("ok") else 400)
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("guardian dashboard: write settings failed: %s", exc)
            return JSONResponse({"ok": False, "errors": ["internal error"]}, status_code=500)

    @app.get("/api/findings")
    def findings(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)) -> Any:
        items = audit.read_findings(limit=limit, offset=offset)
        return {
            "mode": load_guardian_config().mode,
            "findings": items,
            "total": audit.count_findings(),
        }

    @app.get("/api/graph-status")
    def graph_status() -> Any:
        cfg = load_guardian_config()
        rs = ruleset.get(cfg)
        counts = rs.counts()
        curated = 0
        sightings = 0
        community = 0
        reachable = False
        try:
            client = DkgClient(url=cfg.dkg_url)
            reachable = client.reachable()
            curated = _count_query(
                client,
                cfg,
                "SELECT (COUNT(DISTINCT ?t) AS ?n) WHERE { ?t g:curated \"true\" . }",
                constants.VIEW_VERIFIABLE_MEMORY,
            )
            sightings = _count_query(
                client,
                cfg,
                "SELECT (COUNT(DISTINCT ?r) AS ?n) WHERE "
                "{ ?r a <http://umanitek.ai/ontology/guardian/ThreatReport> . }",
                constants.VIEW_SHARED_WORKING_MEMORY,
            )
            community = _count_query(
                client,
                cfg,
                "SELECT (COUNT(DISTINCT ?identifier) AS ?n) WHERE "
                "{ ?t g:identifier ?identifier . }",
                constants.VIEW_SHARED_WORKING_MEMORY,
            )
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("guardian dashboard: graph-status query failed: %s", exc)
        # Field names chosen to match what static/index.html reads.
        return {
            "mode": cfg.mode,
            "context_graph_id": cfg.context_graph_id,
            "dkg_url": cfg.dkg_url,
            "node_reachable": reachable,
            "sync_interval": cfg.sync_interval,
            "last_sync": rs.synced_at,
            "ruleset": counts,
            "curated": curated,
            "community": community,
            "sightings": sightings,
            "findings_logged": audit.count_findings(),
        }

    @app.get("/api/agents")
    def agents() -> Any:
        """Distinct threat reporters in SWM, plus this node's own agent.

        Fail-open: on any query failure we still return the local node agent
        (or, if even that fails, an empty list).
        """
        cfg = load_guardian_config()
        # Keyed by (framework, lowercased-address) so a wallet reported in a
        # different case doesn't show up as a second, duplicate agent.
        found: "Dict[tuple, Dict[str, Any]]" = {}
        local_key = None

        # Local node agent — always try to include it, labelled as this node.
        try:
            client = DkgClient(url=cfg.dkg_url)
            identity = client.agent_identity() or {}
            local_addr = identity.get("agentAddress") or identity.get("agentDid")
            if local_addr:
                local_key = ("hermes", str(local_addr).lower())
                found[local_key] = {
                    "framework": "hermes",
                    "address": str(local_addr),
                    "reports": 0,
                    "is_local": True,
                }
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("guardian dashboard: agent identity failed: %s", exc)

        # Distinct reporters of threats from the shared graph.
        try:
            client = DkgClient(url=cfg.dkg_url)
            sparql = (
                "PREFIX g: <http://umanitek.ai/ontology/guardian/> "
                "SELECT ?reporter ?framework (COUNT(?r) AS ?n) WHERE { "
                "?r a g:ThreatReport . "
                "OPTIONAL { ?r g:reporter ?reporter } "
                "OPTIONAL { ?r g:framework ?framework } "
                "} GROUP BY ?reporter ?framework"
            )
            rows = client.query(sparql, cfg.context_graph_id, view=constants.VIEW_SHARED_WORKING_MEMORY)
            for row in rows:
                addr = extract_binding(row.get("reporter"))
                if not addr:
                    continue
                fw = (extract_binding(row.get("framework")) or "").lower() or "unknown"
                try:
                    n = int(extract_binding(row.get("n")) or "0")
                except (TypeError, ValueError):
                    n = 0
                addr_lc = str(addr).lower()
                key = (fw, addr_lc)
                # Fold reporter rows for the local wallet into the local agent
                # entry regardless of the framework label reported alongside them.
                if local_key is not None and addr_lc == local_key[1]:
                    key = local_key
                if key in found:
                    found[key]["reports"] = max(found[key].get("reports", 0), n)
                else:
                    found[key] = {"framework": fw, "address": str(addr), "reports": n}
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("guardian dashboard: agents query failed: %s", exc)

        return {"agents": list(found.values())}

    def _tier_view(tier: str, default: str = "public") -> tuple:
        """Map a UI tier name to a DKG SPARQL view.

        ``public`` → verifiable-memory (the curated source of truth),
        ``community`` → shared-working-memory (the shared community pool),
        ``local`` → working-memory (this node's own private graph).
        """
        tier = (tier or default).lower()
        views = {
            "public": constants.VIEW_VERIFIABLE_MEMORY,
            "community": constants.VIEW_SHARED_WORKING_MEMORY,
            "local": constants.VIEW_WORKING_MEMORY,
        }
        if tier not in views:
            tier = default
        return tier, views[tier]

    @app.get("/api/graph")
    def graph(tier: str = Query("public")) -> Any:
        """Threats from one graph tier: ``public`` | ``community`` | ``local``."""
        cfg = load_guardian_config()
        tier, view = _tier_view(tier)

        def _category(identifier: str) -> str:
            ident = str(identifier or "")
            prefix = ident.split(":", 1)[0].lower() if ":" in ident else ""
            return {
                "dep": "dependency",
                "injection": "injection",
                "escalation": "escalation",
                "fileaccess": "fileaccess",
                "skill": "skill",
            }.get(prefix, "other")

        seen: "Dict[str, Dict[str, Any]]" = {}
        try:
            client = DkgClient(url=cfg.dkg_url)
            sparql = (
                "PREFIX g: <http://umanitek.ai/ontology/guardian/> "
                "PREFIX schema: <http://schema.org/> "
                "SELECT ?identifier ?severity ?name ?category WHERE { "
                "?t g:identifier ?identifier . "
                "OPTIONAL { ?t g:severity ?severity } "
                "OPTIONAL { ?t schema:name ?name } "
                "}"
            )
            rows = client.query(sparql, cfg.context_graph_id, view=view)
            for row in rows:
                identifier = extract_binding(row.get("identifier"))
                if not identifier or identifier in seen:
                    continue
                seen[identifier] = {
                    "identifier": identifier,
                    "category": _category(identifier),
                    "severity": (extract_binding(row.get("severity")) or "info").lower(),
                    "name": extract_binding(row.get("name")) or "",
                }
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("guardian dashboard: graph query failed: %s", exc)

        return {"tier": tier, "threats": list(seen.values())}

    @app.get("/api/reports")
    def reports(limit: int = Query(50, ge=1, le=200)) -> Any:
        cfg = load_guardian_config()
        out: List[Dict[str, Any]] = []
        try:
            client = DkgClient(url=cfg.dkg_url)
            sparql = (
                "PREFIX g: <http://umanitek.ai/ontology/guardian/> "
                "SELECT ?identifier (COUNT(DISTINCT ?reporter) AS ?reporters) "
                "(SAMPLE(?severity) AS ?sev) WHERE { "
                "?r a g:ThreatReport . ?r g:identifier ?identifier . ?r g:reporter ?reporter . "
                "OPTIONAL { ?r g:severity ?severity . } } "
                f"GROUP BY ?identifier ORDER BY DESC(?reporters) LIMIT {int(limit)}"
            )
            rows = client.query(sparql, cfg.context_graph_id, view=constants.VIEW_SHARED_WORKING_MEMORY)
            for row in rows:
                out.append({
                    "identifier": extract_binding(row.get("identifier")),
                    "reporters": int(extract_binding(row.get("reporters")) or "0"),
                    "severity": extract_binding(row.get("sev")) or "info",
                })
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("guardian dashboard: reports query failed: %s", exc)
        return {"reports": out}

    # Predicate IRI -> friendly detail key, for the single-threat lookup.
    _DETAIL_FIELDS = {
        constants.SEVERITY_PRED: "severity",
        constants.SCHEMA_NAME_PRED: "name",
        constants.SCHEMA_DESCRIPTION_PRED: "description",
        constants.OWASP_CATEGORY_PRED: "owasp",
        constants.PACKAGE_ECOSYSTEM_PRED: "ecosystem",
        constants.PACKAGE_NAME_PRED: "package",
        constants.PACKAGE_VERSION_PRED: "version",
        constants.FIXED_VERSION_PRED: "fixed_version",
        constants.TOOL_NAME_PRED: "tool",
        constants.ARG_SHAPE_PRED: "arg_shape",
        constants.CATEGORY_PRED: "file_category",
        constants.SKILL_NAME_PRED: "skill",
        constants.SKILL_VERSION_PRED: "skill_version",
        constants.DANGER_SHAPE_PRED: "danger_shape",
        constants.PATTERN_PRED: "pattern",
        constants.CURATED_PRED: "curated",
        constants.SCHEMA_DATE_MODIFIED_PRED: "modified",
    }

    @app.get("/api/threat")
    def threat(identifier: str = Query(..., min_length=1), tier: str = Query("community")) -> Any:
        """Full detail for ONE threat — a targeted point-lookup (scales to any
        graph size). ``tier`` ∈ public | community | local (legacy ``local``
        callers get this node's working memory). Fail-open."""
        cfg = load_guardian_config()
        tier, view = _tier_view(tier, default="community")
        prefix = identifier.split(":", 1)[0].lower() if ":" in identifier else ""
        category = prefix if prefix in ("dep", "injection", "escalation", "fileaccess", "skill") else "other"
        if category == "dep":
            category = "dependency"
        detail: Dict[str, Any] = {
            "identifier": identifier,
            "tier": tier,
            "category": category,
            "references": [],
            "found": False,
        }
        # A threat and its ThreatReports share g:identifier. A single bare
        # point-lookup returns both; we separate them in Python. This is far
        # cheaper than a SPARQL ``FILTER NOT EXISTS`` (which re-scans the whole
        # shared-memory view per candidate row — ~3x slower here) and folds the
        # reporter count into the same round-trip.
        lit = identifier.replace("\\", "\\\\").replace('"', '\\"')
        rdf_type = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        try:
            client = DkgClient(url=cfg.dkg_url)
            rows = client.query(
                _PREFIX + f'SELECT ?t ?p ?o WHERE {{ ?t g:identifier "{lit}" . ?t ?p ?o }}',
                cfg.context_graph_id,
                view=view,
            )
            subjects: Dict[str, List[Any]] = {}
            for row in rows:
                subjects.setdefault(extract_binding(row.get("t")), []).append(
                    (extract_binding(row.get("p")), extract_binding(row.get("o")))
                )
            reporters = set()
            for pairs in subjects.values():
                types = {obj for (pred, obj) in pairs if pred == rdf_type}
                if constants.REPORT_TYPE_IRI in types:  # a sighting, not the threat
                    for pred, obj in pairs:
                        if pred == constants.REPORTER_PRED and obj:
                            reporters.add(obj)
                        elif pred == constants.FRAMEWORK_PRED and obj:
                            detail.setdefault("framework", obj)
                    continue
                if constants.FALSE_POSITIVE_TYPE_IRI in types:
                    continue
                detail["found"] = True  # the threat asset itself
                for pred, obj in pairs:
                    if pred == constants.REFERENCE_PRED:
                        if obj and obj not in detail["references"]:
                            detail["references"].append(obj)
                    elif pred in _DETAIL_FIELDS:
                        detail[_DETAIL_FIELDS[pred]] = obj
            detail["reporters"] = len(reporters)
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("guardian dashboard: threat detail query failed: %s", exc)
        return detail

    return app


def start_dashboard(port: int = 9700) -> None:
    """Run the dashboard with uvicorn on ``127.0.0.1:{port}`` (blocking)."""
    import uvicorn

    uvicorn.run(create_app(), host="127.0.0.1", port=int(port), log_level="warning")
