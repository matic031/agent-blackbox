"""Stdlib HTTP client for the local DKG v10 node.

Wraps the daemon's write/query API with a tiny, dependency-free ``urllib``
client. Blackbox defaults to its own daemon URL and DKG home, not the DKG CLI's
``~/.dkg``/9200 defaults. URL/token resolution is
``BLACKBOX_DKG_*`` env → Blackbox config/home → ``$BLACKBOX_DKG_HOME/auth.token``.
Every request uses a short timeout and raises
:class:`DkgError` on a non-2xx response; all callers fail open.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import constants

logger = logging.getLogger(__name__)

_TIMEOUT = 3.0
# Read path: a large graph can take a few seconds to evaluate. Only the
# background refresh and the dashboard hit it, never the cached hot hook path.
_QUERY_TIMEOUT = 30.0
# Community tier reads scale with the pool, so a longer ceiling than the node API.
_STORE_TIMEOUT = 60.0
# On-chain ops (CG register, VM publish) wait for block confirmation.
_ONCHAIN_TIMEOUT = 180.0
Quad = Dict[str, str]


class DkgError(RuntimeError):
    """Raised for any non-2xx daemon response or transport failure."""


def _validate_quads_literal_sizes(quads: List[Quad]) -> None:
    """Mirror DKG's writable-literal preflight before sending seed/write payloads."""
    try:
        from . import quads as quad_terms

        quad_terms.assert_quads_literal_size(quads, label="quads")
    except ValueError as exc:
        raise DkgError(str(exc)) from exc


def _is_already_finalized(exc: DkgError) -> bool:
    """True when a share failed only because the KA already exists sealed.

    The daemon rejects re-finalizing an assertion with a different (or same)
    merkle root; for our deterministic threat/report names that just means the
    content is already on the graph, so the caller can treat it as success.
    """
    msg = str(exc).lower()
    return "already finalized" in msg or "already exists" in msg


def _is_wm_merkle_conflict(exc: DkgError) -> bool:
    """True when the local WM draft/finalized assertion is stale vs SWM."""
    msg = str(exc).lower()
    return (
        "wm_draft_conflict" in msg
        or "draft conflict" in msg
        or "different merkleroot" in msg
        or "different merkle root" in msg
    )


def _is_already_published(exc: DkgError) -> bool:
    """True when ``vm/publish`` failed only because the KA is already on-chain.

    Re-publishing a KA we already minted — e.g. the local seeded ledger was lost,
    or a prior publish confirmed on-chain *after* our client hit its timeout — is
    a no-op we can treat as success rather than a paid retry or a hard error.
    """
    msg = str(exc).lower()
    return (
        "already published" in msg
        or "already on chain" in msg
        or "already exists on chain" in msg
    )


def _job_id_from_error(exc: DkgError) -> Optional[str]:
    """Extract a daemon-returned job id from an HTTP error body if present."""
    msg = str(exc)
    for key in ("existingJobId", "jobId", "id"):
        m = re.search(rf'"{key}"\s*:\s*"([^"]+)"', msg)
        if m:
            return m.group(1)
    return None


def _coerce_chain_id(value: Any) -> Optional[int]:
    """Parse a chain id from an int or a ``"base:8453"``-style string."""
    if isinstance(value, bool):  # bool is an int subclass — reject it explicitly
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        m = re.search(r"(\d{2,7})", value)  # "base:8453" -> 8453
        if m:
            return int(m.group(1))
    return None


def _dkg_home(explicit: Optional[str] = None) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    env = os.environ.get("BLACKBOX_DKG_HOME")
    return Path(env).expanduser() if env else constants.blackbox_dkg_home()


def load_daemon_url() -> str:
    """Resolve the Blackbox daemon URL from Blackbox-specific settings."""
    env = os.environ.get("BLACKBOX_DKG_DAEMON_URL") or os.environ.get("BLACKBOX_DKG_URL")
    if env and env.strip():
        return env.strip().rstrip("/")
    port = os.environ.get("BLACKBOX_DKG_PORT")
    if port and port.strip():
        try:
            return f"http://127.0.0.1:{int(port.strip())}"
        except ValueError:
            pass
    return constants.DEFAULT_DKG_URL


def load_token(dkg_home: Optional[str] = None) -> Optional[str]:
    """Resolve the bearer token: Blackbox env override → Blackbox auth.token."""
    env = os.environ.get("BLACKBOX_DKG_API_TOKEN") or os.environ.get("BLACKBOX_DKG_AUTH_TOKEN")
    if env and env.strip():
        return env.strip()
    token_path = _dkg_home(dkg_home) / "auth.token"
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

    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        dkg_home: Optional[str] = None,
    ) -> None:
        self.url = (url or load_daemon_url()).rstrip("/")
        self.dkg_home = str(_dkg_home(dkg_home))
        self.token = token if token is not None else load_token(self.dkg_home)

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

    def status(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        """Return node status; raises :class:`DkgError` if unreachable.

        ``GET /api/status`` is the public (no-auth) liveness endpoint; older
        daemons are probed via ``/api/info`` as a fallback (``/api/health`` is
        not a DKG v10 route, so we don't probe it). Pass ``timeout`` for a fast
        liveness probe (e.g. the dashboard) so a dead node fails in a second or
        two rather than the default read timeout.
        """
        for route in ("/api/status", "/api/info"):
            try:
                return self._request("GET", route, timeout=timeout)
            except DkgError:
                continue
        raise DkgError("node unreachable on /api/status, /api/info")

    def agent_identity(self) -> Dict[str, Any]:
        """Resolve the calling token to its agent identity.

        ``GET /api/agent/identity`` → ``{agentAddress, agentDid, name, ...}`` —
        the definitive way to learn which agent the node sees us as.
        """
        return self._request("GET", "/api/agent/identity")

    def chain_info(self) -> Dict[str, Any]:
        """Best-effort network identity from ``/api/status``.

        DKG v10 reports its chain a few ways across builds — a bare ``chainId``
        (int, or a ``"base:8453"`` string), a nested ``chain`` object, and/or the
        human ``networkName``/``networkConfig`` strings. We parse whatever's
        present into ``{chain_id, network, is_mainnet, is_testnet}`` so callers
        can verify the node is on a supported MAINNET before spending TRAC.

        Never raises: unresolved fields come back ``None`` and callers decide
        policy (the seed preflight blocks a *positively-identified* testnet and
        only warns when the chain can't be determined).
        """
        try:
            st = self.status()
        except DkgError:
            return {"chain_id": None, "network": "", "is_mainnet": None, "is_testnet": None}
        chain = st.get("chain") if isinstance(st.get("chain"), dict) else {}
        chain_id = None
        for src in (st.get("chainId"), st.get("chain_id"), chain.get("chainId"), chain.get("chain_id"), chain.get("id")):
            chain_id = _coerce_chain_id(src)
            if chain_id is not None:
                break
        network = str(
            st.get("networkConfig") or st.get("networkName") or chain.get("name") or ""
        ).strip()
        is_mainnet: Optional[bool]
        is_testnet: Optional[bool]
        if chain_id is not None:
            is_mainnet = chain_id in constants.DKG_MAINNET_CHAINS
            is_testnet = chain_id in constants.DKG_TESTNET_CHAINS
        else:
            # No numeric id — fall back to keyword-matching the network string.
            low = network.lower()
            if any(t in low for t in ("testnet", "sepolia", "chiado", "lofar")):
                is_mainnet, is_testnet = False, True
            elif "mainnet" in low:
                is_mainnet, is_testnet = True, False
            else:
                is_mainnet = is_testnet = None
        return {"chain_id": chain_id, "network": network, "is_mainnet": is_mainnet, "is_testnet": is_testnet}

    def reachable(self, timeout: Optional[float] = None) -> bool:
        try:
            self.status(timeout=timeout)
            return True
        except DkgError:
            return False

    # -- context graph -----------------------------------------------------

    def create_context_graph(
        self,
        cg_id: str,
        name: str,
        description: str = "",
        access_policy: Optional[int] = None,
        allowed_agents: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create a local context graph (free, off-chain).

        Pass ``access_policy=0`` to create it PUBLIC. This is the *local*
        privacy classification the daemon writes into the CG's ``_meta`` graph
        and checks (``canReadContextGraph``) on every read. A new CG otherwise
        defaults to curated/private, and shared-working-memory reads fail closed
        on a private CG ("local node is not authorized") — so no other Blackbox
        user can ever see the community pool. ``0`` = public (anyone reads +
        subscribes to SWM), ``1`` = curated/private (allowlist-gated). Keep this
        in sync with ``register_context_graph(access_policy=0)`` so the on-chain
        and local classifications agree.
        """
        body: Dict[str, Any] = {"id": cg_id, "name": name}
        if description:
            body["description"] = description
        if access_policy is not None:
            body["accessPolicy"] = access_policy
        if allowed_agents:
            body["allowedAgents"] = allowed_agents
        return self._request("POST", "/api/context-graph/create", body)

    def add_context_graph_agent(self, cg_id: str, agent_address: str) -> Dict[str, Any]:
        """Add an agent address to the context graph's SWM allowlist."""
        enc = urllib.parse.quote(cg_id, safe="")
        return self._request(
            "POST",
            f"/api/context-graph/{enc}/add-participant",
            {"agentAddress": agent_address},
            timeout=_STORE_TIMEOUT,
        )

    def list_context_graph_agents(self, cg_id: str) -> List[str]:
        """Return agent addresses allowed in a context graph."""
        enc = urllib.parse.quote(cg_id, safe="")
        result = self._request("GET", f"/api/context-graph/{enc}/participants", timeout=_STORE_TIMEOUT)
        agents = result.get("allowedAgents") if isinstance(result, dict) else None
        return [str(agent) for agent in agents] if isinstance(agents, list) else []

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

    def subscribe_context_graph(self, cg_id: str, *, include_shared_memory: bool = True) -> Dict[str, Any]:
        """Subscribe the node to a context graph + catch up its data.

        What a *consumer* node needs: a fresh install that only set
        ``context_graph_id`` never subscribes the daemon, so its store stays empty.
        ``include_shared_memory`` (default True) pulls the SWM/community pool.
        Idempotent — the daemon no-ops when already subscribed.
        """
        return self._request(
            "POST",
            "/api/context-graph/subscribe",
            {"contextGraphId": cg_id, "includeSharedMemory": include_shared_memory},
            timeout=_STORE_TIMEOUT,
        )

    def list_join_requests(self, cg_id: str) -> List[Dict[str, Any]]:
        """Pending join requests for a private (allowlist) CG — curator-only.

        ``GET /api/context-graph/{id}/join-requests`` → ``{requests:[{agentAddress, name, ...}]}``.
        The id carries a ``/`` so it is path-encoded.
        """
        enc = urllib.parse.quote(cg_id, safe="")
        resp = self._request("GET", f"/api/context-graph/{enc}/join-requests", timeout=_STORE_TIMEOUT)
        return resp.get("requests", []) if isinstance(resp, dict) else []

    def approve_join(self, cg_id: str, agent_address: str) -> Dict[str, Any]:
        """Approve a pending join request → adds the agent to the CG allowlist.

        ``POST /api/context-graph/{id}/approve-join {agentAddress}``. This is how
        ``curate auto-accept`` admits every joiner into the community.
        """
        enc = urllib.parse.quote(cg_id, safe="")
        return self._request("POST", f"/api/context-graph/{enc}/approve-join",
                             {"agentAddress": agent_address}, timeout=_STORE_TIMEOUT)

    def redeliver_join_approval(self, cg_id: str, agent_address: str) -> Dict[str, Any]:
        """Curator-side: re-fire a join-approved notification to an approved agent.

        DKG can get into an otherwise-valid "already member, but no synced _meta"
        state after a missed approval notification or daemon restart. The v10
        daemon exposes this route so the curator can poke the approved member
        without touching DKG's internal SQLite state.
        """
        enc = urllib.parse.quote(cg_id, safe="")
        return self._request(
            "POST",
            f"/api/context-graph/{enc}/redeliver-approval",
            {"agentAddress": agent_address},
            timeout=_STORE_TIMEOUT,
        )

    def request_join(self, cg_id: str, curator_peer_id: str,
                     agent_name: str = "agent-blackbox") -> Dict[str, Any]:
        """Consumer-side: sign a join request and forward it to the curator.

        Two local HTTP calls (``sign-join`` → ``request-join``) — no ``dkg`` CLI
        dependency, so a fresh install auto-joins reliably. Idempotent: a repeat
        request or an already-member is a no-op. Returns the request-join result
        (``delivered`` count / ``alreadyMember``).
        """
        enc = urllib.parse.quote(cg_id, safe="")
        signed = self._request("POST", f"/api/context-graph/{enc}/sign-join", {}, timeout=_STORE_TIMEOUT)
        delegation = signed.get("delegation") if isinstance(signed, dict) else None
        if not delegation:
            raise DkgError("sign-join returned no delegation")
        return self._request("POST", f"/api/context-graph/{enc}/request-join",
                             {"delegation": delegation, "curatorPeerId": curator_peer_id,
                              "agentName": agent_name}, timeout=_STORE_TIMEOUT)

    # -- knowledge assets --------------------------------------------------

    def share_knowledge_asset(self, cg_id: str, name: str, quads: List[Quad],
                              create_timeout: Optional[float] = None) -> Dict[str, Any]:
        """Create/finalize a KA, then explicitly share its sealed assertion to SWM.

        Private/agent-gated context graphs require the node's sender-key SWM
        envelope. DKG's old one-shot ``alsoShareSwm:true`` path can leave assets
        without a publish-ready share intent, so Blackbox uses the explicit v10
        lifecycle: write/seal to WM, then enqueue ``/swm/share-async`` and poll
        the share job.

        Idempotent: threat/report KA names are deterministic (``sha256`` of the
        threat identifier), so re-sharing the same threat is expected. The node
        rejects re-finalizing an existing sealed assertion; we then share the
        already-sealed assertion instead of treating the whole operation as done.
        """
        _validate_quads_literal_sizes(quads)
        try:
            self._request(
                "POST",
                "/api/knowledge-assets",
                {"contextGraphId": cg_id, "name": name, "quads": quads, "alsoShareSwm": False},
                timeout=create_timeout or _STORE_TIMEOUT,
            )
        except DkgError as exc:
            if not (_is_already_finalized(exc) or _is_wm_merkle_conflict(exc)):
                raise
        return self.share_finalized_knowledge_asset(cg_id, name)

    def _ka_path(self, name: str, suffix: str = "") -> str:
        enc = urllib.parse.quote(name, safe="")
        return f"/api/knowledge-assets/{enc}{suffix}"

    def pull_knowledge_asset_from(
        self,
        cg_id: str,
        name: str,
        layer: str = "swm",
        *,
        on_conflict: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Pull the latest KA assertion from another layer into local WM.

        Used to repair stale local finalized state before re-sharing old assets.
        """
        body: Dict[str, Any] = {"contextGraphId": cg_id, "layer": layer}
        if on_conflict:
            body["onConflict"] = on_conflict
        return self._request(
            "POST",
            self._ka_path(name, "/wm/pull-from"),
            body,
            timeout=_STORE_TIMEOUT,
        )

    def share_async(self, cg_id: str, name: str) -> Dict[str, Any]:
        """Queue an async SWM share job for an already-finalized WM KA."""
        try:
            return self._request(
                "POST",
                self._ka_path(name, "/swm/share-async"),
                {"contextGraphId": cg_id, "entities": "all"},
                timeout=_STORE_TIMEOUT,
            )
        except DkgError as exc:
            job_id = _job_id_from_error(exc)
            if job_id:
                return {"jobId": job_id, "state": "existing"}
            raise

    def share_job(self, job_id: str) -> Dict[str, Any]:
        """Fetch one async SWM share job by id."""
        enc = urllib.parse.quote(job_id, safe="")
        return self._request("GET", f"/api/knowledge-assets/swm/share-jobs/{enc}", timeout=_STORE_TIMEOUT)

    @staticmethod
    def _share_job_id(result: Dict[str, Any]) -> Optional[str]:
        if not isinstance(result, dict):
            return None
        job = result.get("job") if isinstance(result.get("job"), dict) else result
        for key in ("jobId", "id", "job_id", "shareJobId", "existingJobId"):
            value = job.get(key)
            if value:
                return str(value)
        return None

    def wait_for_share_job(
        self,
        job_id: str,
        *,
        timeout_s: float = 600.0,
        poll_s: float = 5.0,
    ) -> Dict[str, Any]:
        """Poll an async SWM share job until it succeeds or fails."""
        deadline = time.monotonic() + max(1.0, float(timeout_s))
        last_state = "unknown"
        last_job: Dict[str, Any] = {}
        while True:
            job = self.share_job(job_id)
            last_job = job if isinstance(job, dict) else {}
            last_state = str(
                last_job.get("state") or last_job.get("status") or last_job.get("phase") or "unknown"
            ).lower()
            if last_state in {"succeeded", "success", "completed", "complete"}:
                return last_job
            if last_state in {"failed", "error", "cancelled", "canceled"}:
                detail = json.dumps(last_job, sort_keys=True)[:1000]
                raise DkgError(f"SWM share job {job_id} failed: {detail}")
            if time.monotonic() >= deadline:
                detail = json.dumps(last_job, sort_keys=True)[:1000]
                raise DkgError(
                    f"SWM share job {job_id} timed out after {int(timeout_s)}s "
                    f"(last state={last_state}, job={detail})"
                )
            time.sleep(max(1.0, float(poll_s)))

    def share_async_and_wait(
        self,
        cg_id: str,
        name: str,
        *,
        timeout_s: float = 600.0,
        poll_s: float = 5.0,
    ) -> Dict[str, Any]:
        """Queue async SWM share and poll the share job to completion."""
        result = self.share_async(cg_id, name)
        job_id = self._share_job_id(result)
        if not job_id:
            return result
        return self.wait_for_share_job(job_id, timeout_s=timeout_s, poll_s=poll_s)

    def share_finalized_knowledge_asset(self, cg_id: str, name: str) -> Dict[str, Any]:
        """Share an already-finalized WM KA to SWM via async job polling."""
        try:
            return self.share_async_and_wait(cg_id, name)
        except DkgError as exc:
            if _is_already_finalized(exc):
                return {"name": name, "idempotent": True}
            if _is_wm_merkle_conflict(exc):
                self.pull_knowledge_asset_from(cg_id, name, "swm", on_conflict="replace")
                return self.share_async_and_wait(cg_id, name)
            raise

    def write_private_knowledge_asset(self, cg_id: str, name: str, quads: List[Quad]) -> Dict[str, Any]:
        """Create+write+seal a KA in WM WITHOUT sharing to SWM (private audit)."""
        _validate_quads_literal_sizes(quads)
        return self._request(
            "POST",
            "/api/knowledge-assets",
            {"contextGraphId": cg_id, "name": name, "quads": quads, "alsoShareSwm": False},
            timeout=_STORE_TIMEOUT,
        )

    def publish_async(self, cg_id: str, name: str, epochs: int = 1) -> Dict[str, Any]:
        """Queue an async VM publish job for an already SWM-shared sealed KA."""
        try:
            result = self._request(
                "POST",
                self._ka_path(name, "/vm/publish-async"),
                {"contextGraphId": cg_id, "options": {"publishEpochs": max(1, int(epochs))}},
                timeout=_STORE_TIMEOUT,
            )
        except DkgError as exc:
            if _is_already_published(exc):
                return {"name": name, "idempotent": True}
            raise
        if isinstance(result, dict) and result.get("contextGraphError"):
            raise DkgError(
                f"vm/publish-async {name}: context-graph binding failed: "
                f"{result.get('contextGraphError')}"
            )
        return result

    def publisher_job(self, job_id: str) -> Dict[str, Any]:
        """Fetch one async publisher job by id."""
        query = urllib.parse.urlencode({"id": job_id})
        resp = self._request("GET", f"/api/publisher/job?{query}", timeout=_STORE_TIMEOUT)
        if isinstance(resp.get("job"), dict):
            return resp["job"]
        return resp

    @staticmethod
    def _publisher_job_id(result: Dict[str, Any]) -> Optional[str]:
        if not isinstance(result, dict):
            return None
        job = result.get("job") if isinstance(result.get("job"), dict) else result
        for key in ("id", "jobId", "job_id", "publisherJobId"):
            value = job.get(key)
            if value:
                return str(value)
        return None

    def wait_for_publish_job(
        self,
        job_id: str,
        *,
        timeout_s: float = 600.0,
        poll_s: float = 5.0,
    ) -> Dict[str, Any]:
        """Poll an async VM publisher job until it finalizes or fails."""
        deadline = time.monotonic() + max(1.0, float(timeout_s))
        last_status = "unknown"
        last_job: Dict[str, Any] = {}
        while True:
            job = self.publisher_job(job_id)
            last_job = job if isinstance(job, dict) else {}
            last_status = str(
                last_job.get("status") or last_job.get("state") or last_job.get("phase") or "unknown"
            ).lower()
            if last_job.get("contextGraphError"):
                raise DkgError(
                    f"publisher job {job_id}: context-graph binding failed: "
                    f"{last_job.get('contextGraphError')}"
                )
            if last_status in {"finalized", "succeeded", "success", "completed", "complete", "published"}:
                return last_job
            if last_status in {"failed", "error", "cancelled", "canceled"}:
                detail = json.dumps(last_job, sort_keys=True)[:1000]
                raise DkgError(f"publisher job {job_id} failed: {detail}")
            if time.monotonic() >= deadline:
                detail = json.dumps(last_job, sort_keys=True)[:1000]
                raise DkgError(
                    f"publisher job {job_id} timed out after {int(timeout_s)}s "
                    f"(last status={last_status}, job={detail})"
                )
            time.sleep(max(1.0, float(poll_s)))

    def publish_async_and_wait(
        self,
        cg_id: str,
        name: str,
        epochs: int = 1,
        *,
        timeout_s: float = 600.0,
        poll_s: float = 5.0,
    ) -> Dict[str, Any]:
        """Queue async VM publish and poll the publisher job to finality."""
        result = self.publish_async(cg_id, name, epochs=epochs)
        if result.get("idempotent"):
            return result
        job_id = self._publisher_job_id(result)
        if not job_id:
            return result
        return self.wait_for_publish_job(job_id, timeout_s=timeout_s, poll_s=poll_s)

    def publish(self, cg_id: str, name: str, epochs: int = 1) -> Dict[str, Any]:
        """Mint a sealed KA on-chain (VM) via async job polling.

        Idempotent on re-publish: if the KA is already on-chain (lost ledger, or
        a prior publish that confirmed after our client hit its timeout), we
        treat it as success instead of paying for a retry.
        """
        result = self.publish_async_and_wait(
            cg_id,
            name,
            epochs=epochs,
            timeout_s=_ONCHAIN_TIMEOUT,
            poll_s=5.0,
        )
        if isinstance(result, dict) and result.get("contextGraphError"):
            raise DkgError(
                f"vm/publish {name}: context-graph binding failed: "
                f"{result.get('contextGraphError')} — not recording as published"
            )
        return result

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
            logger.debug("blackbox: query failed: %s", exc)
            return [] if on_error is None else on_error
        return normalize_bindings(result)

    def query_store(self, sparql: str, on_error: Any = None) -> Any:
        """Run a SPARQL SELECT against the node's local triple store directly,
        bypassing the ``/api/query`` view layer. Fail-open like :meth:`query`.

        The ``shared-working-memory`` view does per-slice trust work that times
        out (HTTP 500) once the pool holds thousands of slices; the raw store
        answers the same scoped query in milliseconds. Used only for the
        community tier, which is flag-only and doesn't need the view's
        verification. Workaround for a node-side view-scaling limit — see the
        seed runbook.
        """
        store_url = self._store_url()
        if not store_url:
            return on_error
        data = urllib.parse.urlencode({"query": sparql}).encode("utf-8")
        last_exc: Optional[Exception] = None
        # Retry with backoff: a heavy scoped read can blip when many agents hit
        # the store at once, and a short pause lets it drain.
        for attempt in range(3):
            if attempt:
                time.sleep(attempt)
            try:
                req = urllib.request.Request(
                    store_url,
                    data=data,
                    headers={
                        "Accept": "application/sparql-results+json",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=_STORE_TIMEOUT) as resp:
                    return normalize_bindings(json.loads(resp.read().decode("utf-8")))
            except Exception as exc:  # noqa: BLE001 — reads fail open, same as query()
                last_exc = exc
        logger.debug("blackbox: store query failed after 3 attempts: %s", last_exc)
        return on_error

    def _store_url(self) -> Optional[str]:
        """The node's local SPARQL query endpoint (``storeUrl`` from status).

        Only a resolved URL is cached — never a transient status failure, which
        would otherwise poison the client for its lifetime and silently empty
        the community tier. Returns ``None`` (callers fail open) when unresolved.
        """
        url = getattr(self, "_store_url_cache", None)
        if url:
            return url
        try:
            resolved = self.status().get("storeUrl")
        except DkgError:
            resolved = None
        if isinstance(resolved, str) and resolved:
            self._store_url_cache = resolved
            return resolved
        return None

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
