"""Stdlib HTTP client for the local DKG v10 node.

Wraps the daemon's write/query API with a tiny, dependency-free ``urllib``
client. URL and token resolution mirror the original telemetry plugin
(``DKG_DAEMON_URL`` env → default; ``DKG_API_TOKEN``/``DKG_AUTH_TOKEN`` env →
``$DKG_HOME/auth.token``). Every request uses a short timeout and raises
:class:`DkgError` on a non-2xx response; all callers fail open.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import constants

logger = logging.getLogger(__name__)

_TIMEOUT = 3.0
#: SPARQL reads fan out across every shared-memory asset in the graph, so a
#: large curated graph can take a few seconds to evaluate. This is only ever
#: hit by the background ruleset refresh and the dashboard — never the hot hook
#: path, which serves a cached ruleset — so a generous ceiling is safe.
_QUERY_TIMEOUT = 30.0
#: On-chain ops (CG register, VM publish) need block confirmation — far longer
#: than the short read timeout. Used only by :meth:`register_context_graph` and
#: :meth:`publish`.
_ONCHAIN_TIMEOUT = 180.0
Quad = Dict[str, str]


class DkgError(RuntimeError):
    """Raised for any non-2xx daemon response or transport failure."""


def _is_already_finalized(exc: DkgError) -> bool:
    """True when a share failed only because the KA already exists sealed.

    The daemon rejects re-finalizing an assertion with a different (or same)
    merkle root; for our deterministic threat/report names that just means the
    content is already on the graph, so the caller can treat it as success.
    """
    msg = str(exc).lower()
    return "already finalized" in msg or "already exists" in msg


def _dkg_home() -> Path:
    env = os.environ.get("DKG_HOME")
    return Path(env).expanduser() if env else Path.home() / ".dkg"


def load_daemon_url() -> str:
    """Resolve the daemon URL: env override → hermes ``dkg.json`` → default."""
    env = os.environ.get("DKG_DAEMON_URL") or os.environ.get("GUARDIAN_DKG_DAEMON_URL")
    if env and env.strip():
        return env.strip().rstrip("/")
    cfg_path = constants.hermes_home() / "dkg.json"
    if cfg_path.exists():
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
            value = data.get("daemon_url") or data.get("daemonUrl")
            if isinstance(value, str) and value.strip():
                return value.strip().rstrip("/")
        except Exception:
            pass
    return constants.DEFAULT_DKG_URL


def load_token() -> Optional[str]:
    """Resolve the bearer token: env override → ``$DKG_HOME/auth.token``."""
    env = os.environ.get("DKG_API_TOKEN") or os.environ.get("DKG_AUTH_TOKEN")
    if env and env.strip():
        return env.strip()
    token_path = _dkg_home() / "auth.token"
    try:
        if token_path.exists():
            for line in token_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
    except Exception:
        return None
    return None


class DkgClient:
    """Minimal DKG v10 HTTP client. Construct with an explicit url/token or
    let :meth:`from_env` resolve them."""

    def __init__(self, url: Optional[str] = None, token: Optional[str] = None) -> None:
        self.url = (url or load_daemon_url()).rstrip("/")
        self.token = token if token is not None else load_token()

    @classmethod
    def from_env(cls) -> "DkgClient":
        return cls()

    # -- transport ---------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(f"{self.url}{path}", data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout or _TIMEOUT) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read(1024).decode("utf-8", errors="replace")
            raise DkgError(f"{method} {path} -> {exc.code}: {detail}") from exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise DkgError(f"{method} {path} transport error: {exc}") from exc
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    # -- status ------------------------------------------------------------

    def status(self) -> Dict[str, Any]:
        """Return node status; raises :class:`DkgError` if unreachable.

        ``GET /api/status`` is the public (no-auth) liveness endpoint; older
        daemons are probed via ``/api/info`` then ``/api/health``.
        """
        for route in ("/api/status", "/api/info", "/api/health"):
            try:
                return self._request("GET", route)
            except DkgError:
                continue
        raise DkgError("node unreachable on /api/status, /api/info, /api/health")

    def agent_identity(self) -> Dict[str, Any]:
        """Resolve the calling token to its agent identity.

        ``GET /api/agent/identity`` → ``{agentAddress, agentDid, name, ...}`` —
        the definitive way to learn which agent the node sees us as.
        """
        return self._request("GET", "/api/agent/identity")

    def reachable(self) -> bool:
        try:
            self.status()
            return True
        except DkgError:
            return False

    # -- context graph -----------------------------------------------------

    def create_context_graph(self, cg_id: str, name: str, description: str = "") -> Dict[str, Any]:
        """Create a local context graph (free, off-chain)."""
        body: Dict[str, Any] = {"id": cg_id, "name": name}
        if description:
            body["description"] = description
        return self._request("POST", "/api/context-graph/create", body)

    def register_context_graph(self, cg_id: str, access_policy: int, publish_policy: int) -> Dict[str, Any]:
        """Register a CG on-chain with explicit access/publish policies.

        For the public curated KB: ``access_policy=0`` (open discovery/share)
        and ``publish_policy=0`` (only curator wallets publish to VM). We pass
        ``publish_policy`` explicitly — an open CG otherwise defaults permissive.
        """
        return self._request(
            "POST",
            "/api/context-graph/register",
            {"id": cg_id, "accessPolicy": access_policy, "publishPolicy": publish_policy},
            timeout=_ONCHAIN_TIMEOUT,
        )

    # -- knowledge assets --------------------------------------------------

    def share_knowledge_asset(self, cg_id: str, name: str, quads: List[Quad]) -> Dict[str, Any]:
        """One-shot create+write+seal+share of a KA to SWM.

        ``POST /api/knowledge-assets {contextGraphId, name, quads, alsoShareSwm:true}``.
        Used for outbound sightings and curated-threat authoring.

        Idempotent: threat/report KA names are deterministic (``sha256`` of the
        threat identifier), so re-sharing the same threat is expected. The node
        rejects re-finalizing an existing sealed assertion; we treat that as
        success — the content is already on the graph.
        """
        try:
            return self._request(
                "POST",
                "/api/knowledge-assets",
                {"contextGraphId": cg_id, "name": name, "quads": quads, "alsoShareSwm": True},
            )
        except DkgError as exc:
            if _is_already_finalized(exc):
                return {"name": name, "idempotent": True}
            raise

    def write_private_knowledge_asset(self, cg_id: str, name: str, quads: List[Quad]) -> Dict[str, Any]:
        """Create+write+seal a KA in WM WITHOUT sharing to SWM (private audit)."""
        return self._request(
            "POST",
            "/api/knowledge-assets",
            {"contextGraphId": cg_id, "name": name, "quads": quads, "alsoShareSwm": False},
        )

    def publish(self, cg_id: str, name: str, epochs: int = 1) -> Dict[str, Any]:
        """Mint a sealed KA on-chain (VM). Returns ``{kaId, ual, txHash, ...}``."""
        return self._request(
            "POST",
            f"/api/knowledge-assets/{name}/vm/publish",
            {"contextGraphId": cg_id, "options": {"publishEpochs": max(1, int(epochs))}},
            timeout=_ONCHAIN_TIMEOUT,
        )

    # -- query -------------------------------------------------------------

    def query(
        self,
        sparql: str,
        cg_id: str,
        view: str = constants.VIEW_SHARED_WORKING_MEMORY,
        on_error: Any = None,
    ) -> List[Dict[str, Any]]:
        """Run a SPARQL SELECT and return normalized bindings.

        Each binding is a ``{var: value}`` dict of plain strings (literals and
        IRIs already unwrapped — see :func:`extract_binding`). On transport
        error it returns *on_error* (default ``[]``) rather than raising, since
        read paths fail open. A caller that must tell a genuine *empty* result
        (``[]``) apart from a *failure* passes a sentinel (e.g. ``on_error=None``
        won't collide with a successful empty ``[]``).
        """
        try:
            result = self._request(
                "POST",
                "/api/query",
                {"sparql": sparql, "contextGraphId": cg_id, "view": view},
                timeout=_QUERY_TIMEOUT,
            )
        except DkgError as exc:
            logger.debug("guardian: query failed: %s", exc)
            return [] if on_error is None else on_error
        return normalize_bindings(result)

    def register_agent(self, name: str, framework: str = "hermes") -> Dict[str, Any]:
        """Register a new agent on the node → ``{agentAddress, authToken, ...}``."""
        return self._request("POST", "/api/agent/register", {"name": name, "framework": framework})


# ---------------------------------------------------------------------------
# SPARQL binding normalization
# ---------------------------------------------------------------------------


def extract_binding(value: Any) -> str:
    """Unwrap a single SPARQL binding cell to a plain string.

    Handles the SPARQL-JSON ``{"value": "..."}`` object shape as well as the
    daemon's bare-string shape (IRIs bare, literals ``"..."``, typed literals
    ``"x"^^<...>``, lang literals ``"x"@en``).
    """
    if value is None:
        return ""
    if isinstance(value, dict):
        inner = value.get("value")
        return str(inner) if inner is not None else ""
    if isinstance(value, str):
        if value.startswith('"'):
            i = 1
            while i < len(value):
                if value[i] == '"' and value[i - 1] != "\\":
                    break
                i += 1
            return value[1:i] if i < len(value) else value
        return value
    return str(value)


def normalize_bindings(result: Any) -> List[Dict[str, Any]]:
    """Extract a list of binding rows from any of the daemon's response shapes."""
    if not isinstance(result, dict):
        return []
    rows = None
    if isinstance(result.get("bindings"), list):
        rows = result["bindings"]
    elif isinstance(result.get("results"), dict) and isinstance(result["results"].get("bindings"), list):
        rows = result["results"]["bindings"]
    elif isinstance(result.get("result"), dict) and isinstance(result["result"].get("bindings"), list):
        rows = result["result"]["bindings"]
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict)]
