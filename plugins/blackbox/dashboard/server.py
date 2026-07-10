"""Standalone Blackbox dashboard — a tiny FastAPI app bound to loopback.

Routes:

* ``GET /``                 → the single-page ``static/index.html``.
* ``GET /api/findings``     → findings.jsonl, newest-first, paged.
* ``GET /api/graph-status`` → curated threat counts + last sync + ruleset counts.
* ``GET /api/reports``      → recent outbound sightings from the community graph.
* ``GET /api/agents``       → distinct threat reporters + this node's own agent.
* ``GET /api/graph``        → threats per tier: ``public`` (verifiable-memory,
  the curated Umanitek threat graph), ``community`` (shared-working-memory,
  the community pool), ``local`` (working-memory, this node's own graph).

FastAPI/uvicorn come from the hermes ``[web]`` extra, imported lazily. Loopback only.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

logger = logging.getLogger(__name__)

_RESCAN_INTERVAL_SEC = 5.0
_RULESET_EMPTY_RETRY_SEC = 30.0
_RULESET_MIN_RETRY_SEC = 5.0

_STATIC_DIR = Path(__file__).resolve().parent / "static"
_ASSETS_DIR = Path(__file__).resolve().parent / "assets"


def _ruleset_total(rs: Any) -> int:
    try:
        return sum(int(v) for v in rs.counts().values())
    except Exception:
        return 0


def _ruleset_sync_counts(rs: Any) -> Dict[str, int]:
    return {
        "total": _ruleset_total(rs),
        "community": int(rs.source_count("community") or 0),
    }


def _sync_ruleset_once(load_config: Any, dkg_client_cls: Any, ruleset_mod: Any) -> Dict[str, int]:
    """Subscribe/catch up and refresh the VM/SWM ruleset once."""
    cfg = load_config()
    client = dkg_client_cls(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    subscribe_failed = False
    try:
        client.subscribe_context_graph(cfg.context_graph_id)
    except Exception as exc:  # pragma: no cover - best-effort self-heal
        subscribe_failed = True
        logger.debug("blackbox ruleset sync: subscribe %s failed: %s", cfg.context_graph_id, exc)
    if subscribe_failed and getattr(cfg, "curator_peer_id", ""):
        try:
            client.request_join(cfg.context_graph_id, cfg.curator_peer_id)
        except Exception as exc:  # pragma: no cover - best-effort self-heal
            logger.debug("blackbox ruleset sync: join request %s failed: %s", cfg.context_graph_id, exc)
    rs = ruleset_mod.refresh(cfg, client)
    return _ruleset_sync_counts(rs)


def _approve_joins_once(client: Any, cg_id: str) -> List[Dict[str, Any]]:
    """Approve pending joins only for legacy private graphs.

    Open Guardian graphs have an empty allowlist. Approving the first join would
    create an allowlist and make the graph invite-only, so this must no-op there.
    """
    try:
        if not client.list_context_graph_agents(cg_id):
            return []
    except Exception:
        return []
    pending = client.list_join_requests(cg_id)
    approved: List[Dict[str, Any]] = []
    for req in pending:
        addr = str(req.get("agentAddress") or "").strip()
        if not addr:
            continue
        client.approve_join(cg_id, addr)
        approved.append(req)
    return approved


def create_app():
    """Build and return the FastAPI application."""
    from fastapi import Body, FastAPI, Query
    from fastapi.responses import FileResponse, JSONResponse, HTMLResponse

    from .. import attach, audit, constants, ruleset, settings
    from ..config import load_blackbox_config
    from ..dkg_client import DkgClient, extract_binding

    app = FastAPI(title="Agent Blackbox", docs_url=None, redoc_url=None)

    _rescan_state: Dict[str, Any] = {"stop": False, "known": set(), "lock": threading.Lock()}

    def _rescan_once(*, force: bool = False) -> List[Dict[str, Any]]:
        """Discover local Hermes/OpenClaw workspaces and hook Blackbox into them.

        ``force`` re-attaches every discovered workspace — an idempotent
        self-heal used by the manual refresh, so a freshly installed or upgraded
        agent is (re-)protected at once. Otherwise only newly appeared
        workspaces are attached: the cheap diff the background loop runs every
        few seconds. Returns the attach-result row for each workspace it touched.
        Serialized so the loop and a manual refresh never write one config at the
        same time. Fail-open per target."""
        with _rescan_state["lock"]:
            current: Set[Tuple[str, str]] = set()
            for h in attach.discover_hermes_homes():
                current.add(("hermes", str(h)))
            for w in attach.discover_openclaw_workspaces():
                current.add(("openclaw", str(w)))
            known: Set[Tuple[str, str]] = _rescan_state["known"]
            removed = known - current
            touched: List[Dict[str, Any]] = []
            for kind, target in sorted(current if force else current - known):
                try:
                    if kind == "hermes":
                        row = attach.attach_hermes(Path(target))
                    else:
                        row = attach.attach_openclaw(Path(target))
                    touched.append(row)
                    if row.get("error"):
                        logger.warning("blackbox rescan: attach %s %s failed: %s", kind, target, row["error"])
                    elif not row.get("already"):
                        logger.info("blackbox rescan: auto-attached %s at %s", kind, target)
                except Exception as exc:  # pragma: no cover - fail open
                    logger.debug("blackbox rescan: attach %s %s raised: %s", kind, target, exc)
            for kind, target in removed:
                logger.info("blackbox rescan: %s workspace vanished at %s", kind, target)
            _rescan_state["known"] = current
            return touched

    def _rescan_loop() -> None:
        """Every ``_RESCAN_INTERVAL_SEC`` seconds, attach any newly appeared
        Hermes/OpenClaw workspace and log ones that vanished."""
        while not _rescan_state["stop"]:
            try:
                _rescan_once()
            except Exception as exc:  # pragma: no cover - fail open
                logger.debug("blackbox rescan: iteration failed: %s", exc)
            for _ in range(int(_RESCAN_INTERVAL_SEC * 10)):
                if _rescan_state["stop"]:
                    return
                time.sleep(0.1)

    def _approver_loop() -> None:
        """Curator-only legacy fallback for private graphs.

        Public Guardian graphs do not need join approval. ``list_join_requests``
        is server-side curator-gated, so on a non-curator node the call errors and
        this loop just idles — it self-selects to the curator's dashboard. On an
        open CG (empty allowlist) it never approves: the first approval would
        re-gate the graph for everyone (see ``_auto_approve_joins`` in cli.py)."""
        idle = 0
        while not _rescan_state["stop"]:
            try:
                cfg = load_blackbox_config()
                client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
                # ``_approve_joins_once`` no-ops on open CGs (empty allowlist):
                # approving the first join would write an ``allowedAgent`` entry
                # and flip the DKG gates from open to invite-only. Back off when
                # nothing was approved so open/idle graphs don't poll every 15s.
                approved = _approve_joins_once(client, cfg.context_graph_id)
                idle = 0 if approved else idle + 1
                for req in approved:
                    logger.info(
                        "blackbox approver: auto-admitted %s",
                        req.get("name") or req.get("agentAddress"),
                    )
            except Exception:  # not curator / node down — back off and keep idling
                idle += 1
            wait = 15 if idle < 3 else 120
            for _ in range(int(wait * 10)):
                if _rescan_state["stop"]:
                    return
                time.sleep(0.1)

    def _ruleset_sync_loop() -> None:
        """Keep VM/SWM threat rows syncing while the dashboard is running.

        ``sync_interval`` is a period, not a post-sync sleep: the sync's own
        duration is deducted from the wait so a refresh *starts* every
        ``sync_interval`` seconds even when the sync itself is slow."""
        last_total: Any = None
        while not _rescan_state["stop"]:
            wait = _RULESET_EMPTY_RETRY_SEC
            started = time.monotonic()
            try:
                cfg = load_blackbox_config()
                counts = _sync_ruleset_once(lambda: cfg, DkgClient, ruleset)
                total = int(counts.get("total") or 0)
                community = int(counts.get("community") or 0)
                elapsed = time.monotonic() - started
                wait = max(
                    _RULESET_MIN_RETRY_SEC,
                    float(cfg.sync_interval or _RULESET_EMPTY_RETRY_SEC) - elapsed,
                )
                if total == 0 or community == 0:
                    wait = min(_RULESET_EMPTY_RETRY_SEC, wait)
                if total != last_total:
                    logger.info(
                        "blackbox ruleset sync: %d rule(s), %d community; next refresh in %.0fs",
                        total,
                        community,
                        wait,
                    )
                    last_total = total
                else:
                    logger.debug(
                        "blackbox ruleset sync: %d rule(s), %d community; next refresh in %.0fs",
                        total,
                        community,
                        wait,
                    )
            except Exception as exc:  # pragma: no cover - fail open
                logger.debug("blackbox ruleset sync: iteration failed: %s", exc)
                wait = _RULESET_EMPTY_RETRY_SEC
            for _ in range(int(wait * 10)):
                if _rescan_state["stop"]:
                    return
                time.sleep(0.1)

    @app.on_event("startup")
    def _start_rescanner() -> None:
        # Do NOT pre-seed ``known``: attach is idempotent, so the first
        # iteration walks every workspace and self-heals anything the
        # CLI-level attach missed.
        t = threading.Thread(target=_rescan_loop, name="blackbox-rescan", daemon=True)
        t.start()
        logger.info("blackbox rescan: background thread started (interval %.1fs)", _RESCAN_INTERVAL_SEC)
        # Curator-only auto-accept: admits every community joiner with no operator
        # action. Self-gates via the curator-only join-requests endpoint.
        threading.Thread(target=_approver_loop, name="blackbox-approver", daemon=True).start()
        logger.info("blackbox approver: background auto-accept thread started")
        threading.Thread(target=_ruleset_sync_loop, name="blackbox-ruleset-sync", daemon=True).start()
        logger.info("blackbox ruleset sync: background thread started")

    @app.on_event("shutdown")
    def _stop_rescanner() -> None:
        _rescan_state["stop"] = True

    _PREFIX = "PREFIX g: <http://umanitek.ai/ontology/guardian/> "

    def _count_query(client: "DkgClient", cfg: Any, where: str, view: str) -> int:
        """Run a single-``?n``-binding COUNT query; 0 on any failure (fail-open)."""
        try:
            rows = client.query(_PREFIX + where, cfg.context_graph_id, view=view)
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox dashboard: count query failed: %s", exc)
            return 0
        if not rows:
            return 0
        try:
            return int(extract_binding(rows[0].get("n")) or "0")
        except (TypeError, ValueError):
            return 0

    # ---- non-blocking node reads -------------------------------------------
    # Node-backed reads are served stale-while-revalidate: the handler returns
    # the last good value instantly while a background thread recomputes it, and
    # every node call is gated on a cached liveness probe. A slow or dead node
    # never makes a poll wait. TTLs are generous: the poll serves from cache, so
    # the node is queried at most once per TTL per key, and graph data changes
    # slowly enough that ~20s of staleness is invisible.
    _SWR_TTL = 20.0         # refresh a cached node read at most this often
    _REACH_TTL = 15.0       # re-probe node liveness at most this often
    # Per-route liveness timeout; /api/status can take a couple seconds under
    # load, and a probe that's too tight would wrongly report a busy node as down.
    _REACH_TIMEOUT = 5.0
    _swr_lock = threading.Lock()
    _swr_state: Dict[str, Dict[str, Any]] = {}   # key -> {"val", "ts"}
    _swr_busy: Set[str] = set()
    _reach: Dict[str, Any] = {"ok": False, "ts": -1e9, "busy": False}

    def _node_reachable(cfg: Any) -> bool:
        """Cached DKG node liveness, refreshed off the request path.

        Returns the last probe result immediately (``False`` until the first
        lands) and spawns a background re-probe past ``_REACH_TTL``. Never
        blocks the caller, so gating a node query on this is free."""
        now = time.monotonic()
        with _swr_lock:
            stale = (now - _reach["ts"]) >= _REACH_TTL
            spawn = stale and not _reach["busy"]
            if spawn:
                _reach["busy"] = True
            cur = bool(_reach["ok"])
        if spawn:
            def _probe() -> None:
                ok = False
                try:
                    ok = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home).reachable(timeout=_REACH_TIMEOUT)
                except Exception:  # pragma: no cover - fail open
                    ok = False
                with _swr_lock:
                    _reach["ok"] = ok
                    _reach["ts"] = time.monotonic()
                    _reach["busy"] = False
            threading.Thread(target=_probe, name="blackbox-reach", daemon=True).start()
        return cur

    def _swr(key: str, producer: Any, default: Any, ttl: float = _SWR_TTL) -> Any:
        """Return the cached value for ``key`` instantly, refreshing in the
        background past ``ttl``; ``default`` until the first refresh lands.
        ``producer`` runs off the request path, so it may block on the node."""
        now = time.monotonic()
        with _swr_lock:
            entry = _swr_state.get(key)
            fresh = entry is not None and (now - entry["ts"]) < ttl
            cur = entry["val"] if entry is not None else default
            spawn = (not fresh) and (key not in _swr_busy)
            if spawn:
                _swr_busy.add(key)
        if spawn:
            def _run() -> None:
                try:
                    val = producer()
                except Exception as exc:  # pragma: no cover - fail open
                    logger.debug("blackbox dashboard: swr %s failed: %s", key, exc)
                    val = None
                with _swr_lock:
                    if val is not None:
                        _swr_state[key] = {"val": val, "ts": time.monotonic()}
                    _swr_busy.discard(key)
            threading.Thread(target=_run, name="blackbox-swr", daemon=True).start()
        return cur

    @app.get("/", response_class=HTMLResponse)
    def index() -> Any:
        html = _STATIC_DIR / "index.html"
        if html.exists():
            # Never cache the SPA shell; always fetch the current dashboard.
            return FileResponse(str(html), headers={"Cache-Control": "no-cache, no-store, must-revalidate"})
        return HTMLResponse("<h1>Blackbox</h1><p>dashboard assets missing</p>", status_code=200)

    @app.get("/assets/{name}")
    def asset(name: str) -> Any:
        # Serve only the two known-safe brand SVGs (no path traversal).
        allowed = {"blackbox-logo.svg", "umanitek-icon.svg"}
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
            logger.debug("blackbox dashboard: read settings failed: %s", exc)
            return JSONResponse({"error": "could not read settings"}, status_code=500)

    @app.post("/api/settings")
    def post_settings(payload: Dict[str, Any] = Body(...)) -> Any:
        """Validate + persist detection policy under plugins.entries.blackbox.*.

        Loopback-only; writes are validated server-side in :mod:`settings` so a
        malformed body can't corrupt config.
        """
        try:
            result = settings.write_settings(payload)
            return JSONResponse(result, status_code=200 if result.get("ok") else 400)
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox dashboard: write settings failed: %s", exc)
            return JSONResponse({"ok": False, "errors": ["internal error"]}, status_code=500)

    def _clean_chat_output(text: str) -> str:
        lines: List[str] = []
        for line in (text or "").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("session_id:"):
                continue
            if "Context file AGENTS.md TRUNCATED" in stripped:
                continue
            lines.append(line.rstrip())
        return "\n".join(lines).strip()

    def _parse_chat_session_id(text: str) -> Optional[str]:
        for line in (text or "").splitlines():
            stripped = line.strip()
            if stripped.startswith("session_id:"):
                return stripped.split(":", 1)[1].strip() or None
        return None

    @app.post("/api/blackbox-chat")
    def blackbox_chat(payload: Dict[str, Any] = Body(...)) -> Any:
        """Run one scoped Blackbox assistant turn through the managed profile."""
        message = str((payload or {}).get("message") or "").strip()
        if not message:
            return JSONResponse({"ok": False, "error": "Message is required."}, status_code=400)
        if len(message) > 4000:
            return JSONResponse({"ok": False, "error": "Message is too long."}, status_code=400)
        session_id = str((payload or {}).get("session_id") or "").strip()
        hermes = shutil.which("hermes") or os.environ.get("HERMES_BIN") or "hermes"
        argv = [hermes, "blackbox", "chat", "--query", message, "--quiet", "--pass-session-id"]
        if session_id:
            argv.extend(["--resume", session_id])
        try:
            proc = subprocess.run(
                argv,
                cwd=str(attach._repo_root()),
                text=True,
                capture_output=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            return JSONResponse({"ok": False, "error": "Blackbox took too long to answer."}, status_code=504)
        except Exception as exc:
            logger.debug("blackbox dashboard: chat failed: %s", exc)
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)
        next_session_id = _parse_chat_session_id(proc.stderr) or _parse_chat_session_id(proc.stdout) or session_id
        answer = _clean_chat_output(proc.stdout)
        err = _clean_chat_output(proc.stderr)
        if proc.returncode != 0:
            return JSONResponse(
                {"ok": False, "error": err or answer or "Blackbox chat failed.", "session_id": next_session_id},
                status_code=500,
            )
        return {"ok": True, "answer": answer or "(no response)", "session_id": next_session_id}

    @app.get("/api/findings")
    def findings(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)) -> Any:
        items = audit.read_findings(limit=limit, offset=offset)
        return {
            "mode": load_blackbox_config().mode,
            "findings": items,
            "total": audit.count_findings(),
        }

    @app.get("/api/audit")
    def audit_events(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)) -> Any:
        """Full agent-activity trail: session lifecycle + API + tool-call events."""
        items = audit.read_audit(limit=limit, offset=offset)
        return {
            "mode": load_blackbox_config().mode,
            "entries": items,
            "total": audit.count_audit(),
        }

    @app.get("/api/local-activity")
    def local_activity(sessions: int = Query(60, ge=1, le=200)) -> Any:
        """Local threat activity as sessions -> tool calls -> threats.

        Reconstructed from this machine's event logs, never the DKG node.
        """
        data = audit.read_local_activity(max_sessions=sessions)
        return {"mode": load_blackbox_config().mode, **data}

    @app.get("/api/graph-status")
    def graph_status() -> Any:
        cfg = load_blackbox_config()
        rs = ruleset.get(cfg)
        counts = rs.counts()
        # Community + sightings come from the synced ruleset cache, NOT the
        # shared-working-memory view, which does O(slice) trust work and times
        # out (HTTP 500) on a large pool.
        community = rs.source_count("community")

        # curated + sightings + liveness are the only node-dependent bits left.
        # Serve them stale-while-revalidate and skip them when the node is down.
        def _node_counts() -> Any:
            # None (not {}) when unreachable so _swr keeps the default and
            # retries next poll instead of caching "down" for the whole TTL.
            if not _node_reachable(cfg):
                return None
            client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
            return {
                "node_reachable": True,
                "curated": _count_query(
                    client,
                    cfg,
                    "SELECT (COUNT(DISTINCT ?t) AS ?n) WHERE { ?t g:curated \"true\" . }",
                    constants.VIEW_VERIFIABLE_MEMORY,
                ),
                "sightings": ruleset.community_report_count(client, cfg),
            }

        g = _swr("graph-status", _node_counts,
                 {"node_reachable": False, "curated": 0, "sightings": 0})
        return {
            "mode": cfg.mode,
            "context_graph_id": cfg.context_graph_id,
            "dkg_url": cfg.dkg_url,
            "dkg_home": cfg.dkg_home,
            "dkg_bin": cfg.dkg_bin,
            "node_reachable": g["node_reachable"],
            "sync_interval": cfg.sync_interval,
            "last_sync": rs.synced_at,
            "ruleset": counts,
            "curated": g["curated"],
            "community": community,
            "sightings": g["sightings"],
            "findings_logged": audit.count_findings(),
        }

    @app.get("/api/agents")
    def agents() -> Any:
        """Local protected agents + distinct threat reporters in SWM.

        A "protected agent" is any framework that has written findings into this
        shared blackbox home. Each is shown separately even when several share
        one node wallet, so a Hermes and an OpenClaw on one machine are two
        agents. Fail-open.
        """
        cfg = load_blackbox_config()
        # Keyed by (framework, lowercased-address) so the same wallet under two
        # frameworks shows as two agents, and the same wallet+framework folds.
        found: "Dict[tuple, Dict[str, Any]]" = {}

        # This node's wallet, shared by every local framework. Live node call,
        # so served through the SWR cache.
        def _load_identity() -> Any:
            if not _node_reachable(cfg):
                return None   # retry next poll; don't cache a "down" as empty
            try:
                ident = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home).agent_identity() or {}
                return str(ident.get("agentAddress") or ident.get("agentDid") or "")
            except Exception as exc:  # pragma: no cover - fail open
                logger.debug("blackbox dashboard: agent identity failed: %s", exc)
                return None
        local_addr = _swr("agent-identity", _load_identity, "") or ""

        attach_state: Dict[str, List[Dict[str, Any]]] = {"hermes": [], "openclaw": []}
        try:
            attach_state = attach.attach_all(dry_run=True)
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox dashboard: attach-state enumeration failed: %s", exc)
        attach_rows = attach_state.get("hermes", []) + attach_state.get("openclaw", [])
        known_local_fw = {
            str(row.get("kind") or "").lower()
            for row in attach_rows
            if row.get("target")
        }
        protected_local_fw = {
            str(row.get("kind") or "").lower()
            for row in attach_rows
            if row.get("target") and row.get("already")
        }

        # Local active agents: one per framework that has emitted a local
        # Blackbox audit/finding event. Attachment alone is not a live signal.
        try:
            local_fw = audit.local_active_frameworks()
        except Exception:  # pragma: no cover - fail open
            local_fw = []
        # Per-framework local finding counts.
        counts_by_fw: "Dict[str, int]" = {}
        try:
            for row in audit.read_findings(limit=100000):
                fw = (row.get("framework") or "hermes").lower()
                counts_by_fw[fw] = counts_by_fw.get(fw, 0) + 1
        except Exception:  # pragma: no cover - fail open
            pass
        for fw in local_fw:
            if fw in known_local_fw and fw not in protected_local_fw:
                continue
            key = (fw, local_addr.lower())
            found[key] = {
                "framework": fw,
                "address": local_addr or fw,
                "reports": 0,
                "findings": counts_by_fw.get(fw, 0),
                "is_local": True,
            }

        # Distinct threat reporters from the shared graph (may include remote
        # agents). Groups over the slow shared-working-memory view, so served
        # stale-while-revalidate; rows are cached raw and merged fresh below.
        def _load_reporters() -> Any:
            if not _node_reachable(cfg):
                return None   # keep default cached briefly; retry next poll
            try:
                client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
                # Read the RAW store (ms), scoped to the CG's shared-memory named
                # graphs, instead of the shared-working-memory view. The view's
                # per-slice trust work is O(slices) and times out (~160s) once the
                # pool holds thousands of reports, saturating oxigraph and starving
                # the node's P2P (peers drop to 0-alive → API offline). A flag-only
                # reporter count never needs the view. Mirrors
                # ruleset.community_report_count.
                prefix = f"did:dkg:context-graph:{cfg.context_graph_id}/_shared_memory"
                sparql = (
                    "PREFIX g: <http://umanitek.ai/ontology/guardian/> "
                    "SELECT ?reporter ?framework (COUNT(?r) AS ?n) WHERE { GRAPH ?g { "
                    "?r a g:ThreatReport . "
                    "OPTIONAL { ?r g:reporter ?reporter } "
                    "OPTIONAL { ?r g:framework ?framework } "
                    "} "
                    f'FILTER(STRSTARTS(STR(?g), "{prefix}")) '
                    "} GROUP BY ?reporter ?framework"
                )
                rows = client.query_store(sparql, on_error=None)
                if rows is None:
                    return None  # store error — keep the last cached reporters
            except Exception as exc:  # pragma: no cover - fail open
                logger.debug("blackbox dashboard: agents query failed: %s", exc)
                return None  # transient failure — keep the last cached reporters
            reporters: List[Dict[str, Any]] = []
            for row in rows:
                addr = extract_binding(row.get("reporter"))
                if not addr:
                    continue
                fw = (extract_binding(row.get("framework")) or "").lower() or "unknown"
                try:
                    n = int(extract_binding(row.get("n")) or "0")
                except (TypeError, ValueError):
                    n = 0
                reporters.append({"framework": fw, "address": str(addr), "count": n})
            return reporters

        for rep in (_swr("agents-reporters", _load_reporters, []) or []):
            fw, addr, n = rep["framework"], rep["address"], rep["count"]
            key = (fw, addr.lower())
            if key in found:
                found[key]["reports"] = max(found[key].get("reports", 0), n)
            else:
                found[key] = {"framework": fw, "address": addr, "reports": n}

        # Attached local workspaces — one card per protected workspace, so two
        # OpenClaw profiles on one node wallet render as two agents. Local-wallet
        # entries are absorbed here so the same framework doesn't render twice.
        try:
            attached = [
                (str(row.get("kind") or "").lower(), str(row.get("target") or ""))
                for row in attach_rows
                if row.get("already") and row.get("target")
            ]
            fw_with_ws = {fw for fw, _ in attached}
            local_addr_lc = local_addr.lower()
            for k in list(found.keys()):
                fw_k, addr_k = k
                if fw_k in fw_with_ws and addr_k == local_addr_lc:
                    found.pop(k, None)
            for fw, ws in attached:
                ws_name = Path(ws).name or ws
                key = (fw, ws.lower())
                if key in found:
                    found[key]["workspace"] = ws
                    found[key]["workspace_label"] = ws_name
                    continue
                found[key] = {
                    "framework": fw,
                    "address": local_addr or fw,
                    "reports": 0,
                    "findings": counts_by_fw.get(fw, 0),
                    "is_local": True,
                    "workspace": ws,
                    "workspace_label": ws_name,
                }
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox dashboard: attached-workspace enumeration failed: %s", exc)

        return {"agents": list(found.values())}

    @app.get("/api/attach-targets")
    def attach_targets() -> Any:
        """Discover local agent configs the dashboard can attach Blackbox to."""
        targets: List[Dict[str, Any]] = []
        returned: Set[str] = set()
        supported = {
            "hermes": "Hermes was not detected on this machine.",
            "openclaw": "OpenClaw was not detected on this machine. Start OpenClaw once so its openclaw.json workspace can be discovered.",
        }

        def _add_rows(kind: str, rows: Any) -> None:
            if not isinstance(rows, list):
                return
            saw_row = False
            for row in rows:
                if not isinstance(row, dict):
                    continue
                saw_row = True
                row["protected"] = bool(row.get("already"))
                row["available"] = bool(row.get("target")) and not row.get("error")
                if not row["available"]:
                    row["disabled_reason"] = str(row.get("error") or supported[kind])
                targets.append(row)
            if saw_row:
                returned.add(kind)

        try:
            _add_rows("hermes", attach.attach_all(openclaw=False, dry_run=True).get("hermes", []))
            _add_rows("openclaw", attach.attach_all(hermes=False, dry_run=True).get("openclaw", []))
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox dashboard: attach target discovery failed: %s", exc)
        for kind, reason in supported.items():
            if kind not in returned:
                targets.append({
                    "kind": kind,
                    "target": "",
                    "protected": False,
                    "available": False,
                    "disabled_reason": reason,
                })
        return {"targets": targets}

    @app.post("/api/attach")
    def attach_selected(payload: Dict[str, Any] = Body(...)) -> Any:
        """Attach Blackbox to selected local targets."""
        rows: List[Dict[str, Any]] = []
        for item in payload.get("targets") or []:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("kind") or "").lower()
            target = str(item.get("target") or "").strip()
            if not target:
                continue
            if kind == "hermes":
                rows.append(attach.attach_hermes(Path(target)))
            elif kind == "openclaw":
                rows.append(attach.attach_openclaw(Path(target)))
        ok = all(row.get("ok") for row in rows) if rows else False
        return JSONResponse({"ok": ok, "targets": rows}, status_code=200 if ok else 400)

    @app.post("/api/agents/protection")
    def save_agent_protection(payload: Dict[str, Any] = Body(...)) -> Any:
        """Apply desired Blackbox protection state for selected local targets."""
        rows: List[Dict[str, Any]] = []
        for item in payload.get("targets") or []:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("kind") or "").lower()
            target = str(item.get("target") or "").strip()
            enabled = bool(item.get("enabled"))
            if not target:
                continue
            if kind == "hermes":
                rows.append(attach.attach_hermes(Path(target)) if enabled else attach.detach_hermes(Path(target)))
            elif kind == "openclaw":
                rows.append(attach.attach_openclaw(Path(target)) if enabled else attach.detach_openclaw(Path(target)))
        ok = all(row.get("ok") for row in rows) if rows else False
        return JSONResponse({"ok": ok, "targets": rows}, status_code=200 if ok else 400)

    @app.post("/api/agents/rescan")
    def rescan_agents() -> Any:
        """Force an immediate re-hook + agent-detection sweep (the manual refresh).

        Re-attaches Blackbox to every local Hermes/OpenClaw workspace
        (idempotent), so a just-installed or upgraded agent is protected and
        shown without waiting for the background rescan loop. The frontend
        re-polls ``/api/agents`` afterwards to render any new cards. Fail-open:
        never 500s the dashboard."""
        try:
            touched = _rescan_once(force=True)
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox dashboard: manual rescan failed: %s", exc)
            return JSONResponse({"ok": False, "error": str(exc), "attached": 0, "newly_attached": 0})
        newly = sum(
            1 for row in touched
            if row.get("ok") and row.get("target") and not row.get("already") and not row.get("error")
        )
        return {"ok": True, "attached": len(touched), "newly_attached": newly}

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
        cfg = load_blackbox_config()
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
                "ioc": "ioc",
            }.get(prefix, "other")

        # Community tab: serve from the synced ruleset cache; the
        # shared-working-memory view times out on a large pool.
        if tier == "community":
            rs = ruleset.get(cfg)
            threats = [
                {
                    "identifier": r.get("identifier"),
                    "category": cat,
                    "severity": str(r.get("severity") or "info").lower(),
                    "name": r.get("name") or "",
                }
                for cat, r in rs.iter_rules()
                if r.get("source") == "community"
            ]
            return {"tier": tier, "threats": threats}

        # Public/local tiers read a live node view; served stale-while-revalidate.
        def _load() -> Any:
            if not _node_reachable(cfg):
                return None   # keep the default (empty) cached briefly; retry next poll
            seen: "Dict[str, Dict[str, Any]]" = {}
            try:
                client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
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
                logger.debug("blackbox dashboard: graph query failed: %s", exc)
            return {"tier": tier, "threats": list(seen.values())}

        return _swr("graph:" + tier, _load, {"tier": tier, "threats": []})

    @app.get("/api/reports")
    def reports(limit: int = Query(50, ge=1, le=200)) -> Any:
        cfg = load_blackbox_config()

        # Node-backed sightings list, served stale-while-revalidate.
        def _load() -> Any:
            if not _node_reachable(cfg):
                return None   # keep the default (empty) cached briefly; retry next poll
            out: List[Dict[str, Any]] = []
            try:
                client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
                # Raw store scoped to the CG's shared-memory graphs, not the
                # shared-working-memory view (O(slices), times out on the 15k pool
                # and saturates the node). Mirrors the community list/detail paths.
                prefix = f"did:dkg:context-graph:{cfg.context_graph_id}/_shared_memory"
                sparql = (
                    "PREFIX g: <http://umanitek.ai/ontology/guardian/> "
                    "SELECT ?identifier (COUNT(DISTINCT ?reporter) AS ?reporters) "
                    "(SAMPLE(?severity) AS ?sev) WHERE { GRAPH ?g { "
                    "?r a g:ThreatReport . ?r g:identifier ?identifier . ?r g:reporter ?reporter . "
                    "OPTIONAL { ?r g:severity ?severity . } } "
                    f'FILTER(STRSTARTS(STR(?g), "{prefix}")) }} '
                    f"GROUP BY ?identifier ORDER BY DESC(?reporters) LIMIT {int(limit)}"
                )
                rows = client.query_store(sparql, on_error=[]) or []
                for row in rows:
                    out.append({
                        "identifier": extract_binding(row.get("identifier")),
                        "reporters": int(extract_binding(row.get("reporters")) or "0"),
                        "severity": extract_binding(row.get("sev")) or "info",
                    })
            except Exception as exc:  # pragma: no cover - fail open
                logger.debug("blackbox dashboard: reports query failed: %s", exc)
            return {"reports": out}

        return _swr(f"reports:{limit}", _load, {"reports": []})

    # Predicate IRI -> friendly detail key, for the single-threat lookup.
    _DETAIL_FIELDS = {
        constants.SEVERITY_PRED: "severity",
        constants.KIND_PRED: "kind",
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
        constants.SCHEMA_CONTRIBUTOR_PRED: "contributor",
    }

    @app.get("/api/threat")
    def threat(identifier: str = Query(..., min_length=1), tier: str = Query("community")) -> Any:
        """Full detail for ONE threat via a targeted point-lookup.

        ``tier`` ∈ public | community | local. Fail-open."""
        cfg = load_blackbox_config()
        tier, view = _tier_view(tier, default="community")
        prefix = identifier.split(":", 1)[0].lower() if ":" in identifier else ""
        category = prefix if prefix in ("dep", "injection", "escalation", "fileaccess", "skill", "ioc") else "other"
        if category == "dep":
            category = "dependency"
        detail: Dict[str, Any] = {
            "identifier": identifier,
            "tier": tier,
            "category": category,
            "sources": [],
            "references": [],
            "found": False,
        }
        # A threat and its ThreatReports share g:identifier; one point-lookup
        # returns both and we separate them in Python. Far cheaper than a SPARQL
        # FILTER NOT EXISTS (~3x slower, re-scans the view per row) and folds the
        # reporter count into the same round-trip.
        lit = identifier.replace("\\", "\\\\").replace('"', '\\"')
        rdf_type = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
        try:
            # Skip the point-lookup on an unreachable node so opening a threat
            # can't hang on a dead node.
            client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home) if _node_reachable(cfg) else None
            if client is None:
                rows = []
            elif tier == "community":
                # Community detail from the store, not the shared-memory view —
                # the view does O(slice) trust work and times out on a large pool
                # (same reason the community list uses query_store), which would
                # otherwise hang the detail modal. Scope to this CG's SWM slices.
                sm = f"did:dkg:context-graph:{cfg.context_graph_id}/_shared_memory"
                rows = client.query_store(
                    _PREFIX + f'SELECT ?t ?p ?o WHERE {{ GRAPH ?gr {{ ?t g:identifier "{lit}" . ?t ?p ?o }} '
                    f'FILTER(STRSTARTS(STR(?gr), "{sm}")) }}',
                    on_error=[],
                )
            else:
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
                    elif pred == constants.SOURCE_PRED:
                        if obj and obj not in detail["sources"]:
                            detail["sources"].append(obj)
                    elif pred in _DETAIL_FIELDS:
                        detail[_DETAIL_FIELDS[pred]] = obj
            detail["reporters"] = len(reporters)
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox dashboard: threat detail query failed: %s", exc)
        return detail

    @app.on_event("startup")
    def _warm_node_caches() -> None:
        """Prime the SWR node caches at boot so the first load shows data
        instead of a "Loading…" window. Off-thread, fail-open."""
        def _warm() -> None:
            try:
                cfg = load_blackbox_config()
                # Probe liveness synchronously first and seed the cache, so the
                # reads below see the node's true state, not the cold default.
                try:
                    ok = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home).reachable(timeout=_REACH_TIMEOUT)
                except Exception:  # pragma: no cover - fail open
                    ok = False
                with _swr_lock:
                    _reach["ok"] = ok
                    _reach["ts"] = time.monotonic()
                    _reach["busy"] = False
                # Touch each cached endpoint to warm it. Two passes: the first
                # spawns the refresh, the second lands it.
                for _ in range(2):
                    graph_status()
                    graph("public")
                    reports(50)
                    agents()
                    time.sleep(2.5)
            except Exception as exc:  # pragma: no cover - best effort
                logger.debug("blackbox dashboard: cache warm failed: %s", exc)
        threading.Thread(target=_warm, name="blackbox-warm", daemon=True).start()

    return app


def start_dashboard(port: int = 9700) -> None:
    """Run the dashboard with uvicorn on ``127.0.0.1:{port}`` (blocking)."""
    import uvicorn

    uvicorn.run(create_app(), host="127.0.0.1", port=int(port), log_level="warning")
