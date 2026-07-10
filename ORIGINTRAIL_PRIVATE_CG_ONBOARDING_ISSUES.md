# DKG v10.0.5 — private/community context-graph onboarding & reachability issues

**Reporter:** Umanitek (Agent Blackbox)
**DKG version:** `@origintrail-official/dkg@10.0.5` (npm, mainnet-base), `nodeRole: edge`
**Context:** an intentionally-OPEN community graph implemented as a private
(`accessPolicy=1`) CG whose curator auto-approves every joiner, so all members
read + write the shared-working-memory (SWM) pool. Reads/writes work for the
curator; a freshly-joined remote member cannot catch up SWM. Below are the
node/protocol issues we hit that need an upstream fix, and the curator-side
workarounds we applied in the meantime (we can only patch the curator's node,
not the consumers' nodes).

---

## 1. A freshly-joined private-CG member's SWM sync request is unsigned → denied (BLOCKER)

**Symptom (curator/host log):**
```
Denied sync request for "umanitek/blackbox-threats-staging": malformed or mismatched
envelope (requesterPeer=n/a targetPeer=n/a remotePeer=<joiner> identityId=0 agentAddress=n/a) (phase=meta)
```
Every identity field is `n/a`. Reproduced on **three independent fresh members**
(different wallets/machines), so it is systemic, not per-node.

**What works:** the join handshake fully succeeds — the joiner is admitted
(`Invited agent 0x… with delegation`, added to the allowlist, receives
`Join request approved — auto-subscribing`) and connects to the curator peer
for SWM sync. Only the SWM **catch-up request envelope** is unsigned/unbound.

**Analysis:** `authorizePrivateSyncRequest`
(`dkg-agent/dist/sync/auth/request-authorize.js`) requires a bound, signed
envelope: `isSyncRequestEnvelopeBoundToPeer` (targetPeerId===localPeerId &&
requesterPeerId===remotePeerId) plus `requesterSignatureR/VS` and a recoverable
signer. A just-approved member's node sends the SWM **meta** sync request with
none of these set. It appears the node does not attach its agent identity /
sign the SWM catch-up request in the window after approval (durable-data sync
on the same node is unaffected — only `phase=meta` SWM is). Net effect: an
approved member can never bootstrap the historical SWM pool.

**Ask:** on a freshly-approved private-CG member, build the SWM sync request
with the same bound+signed envelope the durable-data path uses (attach
`requesterAgentAddress`, `targetPeerId`, `requesterPeerId`, and the signature).
Or expose a host-side option to authorize an SWM read by the authenticated
libp2p peer identity when the graph owner opts into open reads.

**Our curator-side workaround:** env flag `DKG_SWM_SYNC_OPEN=1` patched into
`authorizePrivateSyncRequest` to serve any peer (recovery serves plaintext, so
no key leaks) + into `dkg-publisher/dist/workspace-handler.js` to accept
plaintext SWM writes. This makes the private CG behave as an open community
pool. It only works because we can patch the curator; consumers are unpatched.

---

## 2. `relayPeers` is not populated from `preferredRelays` / the network relay set → node is unreachable

**Symptom (fresh consumer):**
```
request-join -> 502 No reachable curator found
  <curatorPeer>: Network identity probe failed / timeout
```
and the curator/host logs, on every relay:
```
Relay watchdog: no circuit reservation anywhere (0 /p2p-circuit self-addrs)
Network isolation: denying outbound relayed connection relay=… remote=…
```

**Analysis:** `dkg-core/dist/node.js` builds `activeNetworkRelayPeerIds` **only**
from `config.relayPeers`. With `relayPeers` empty (our managed config listed the
relays under `preferredRelays` / `bootstrapPeers` instead), and `networkIdentity`
set, `buildActiveRelayNetworkPolicy` receives an **empty** active-relay Set and
the isolation gate then **denies every relayed connection** → the node holds
**0 circuit reservations** → it is unreachable, so members cannot deliver a join
request or sync. The docs say `preferredRelays` are "prepended to the active
relayPeers list at daemon startup," but with `relayPeers` empty that merge does
not populate what `node.js` reads, and `relayReservationCount` is logged as
"ignored (no relayPeers configured)."

**Ask:** when `relayPeers` is empty, seed it from `preferredRelays` and/or the
`network/<env>.json` public relay set before building the isolation policy — or
treat an empty active-relay set as "allow the configured/known relays" rather
than "deny all relays." An edge node with no usable relays and a non-empty
`networkIdentity` currently self-isolates into unreachability with no error.

**Our workaround:** explicitly set `relayPeers` to the 4 mainnet-base core
relays in the node config (installer now seeds it). Reservations went 0 → 3/4.

---

## 3. Clearing an allowlist REVOKES rather than DELETES → an effectively-empty gate deadlocks a public-intended graph

**Symptom:** after clearing a CG's allowlist, plaintext SWM gossip is rejected
with `Cannot gossip SWM write for agent-gated context graph "…": no local
allowed signing agent key` — even for the curator, and even though the API
`list_context_graph_agents` returns `[]` and the on-chain `accessPolicy` is
public.

**Analysis:** `remove-participant` adds a `revokedAgent` `_meta` triple rather
than deleting the `allowedAgent` triple. `getContextGraphAgentGateAddresses`
(`dkg-agent/dist/dkg-agent-crypto.js`) sets `sawAgentGate=true` because
`meta.allowedAgents.length > 0`, then filters out all the (now-revoked) agents,
and returns `[]` — an **empty but non-null** gate. Downstream that reads as
"agent-gated with zero valid signers," so nothing can sign/read/publish. The
list API subtracts revoked and shows `[]`, hiding the deadlock.

**Ask:** treat an agent gate whose **effective** member set is empty as PUBLIC
(return `null`), not as a zero-member private gate — or actually delete the
allowedAgent entry on remove. Otherwise a graph can get wedged into an
unusable state that the management API reports as "open."

**Our workaround:** patched `getContextGraphAgentGateAddresses` to
`return (sawAgentGate && agents.length > 0) ? agents : null;`.

---

## 4. SWM catch-up budget/commit issues (see companion doc, still open on 10.0.5)

`ORIGINTRAIL_SWM_CATCHUP_ISSUE.md` (with the 2026-07-10 addendum) is unchanged
on 10.0.5: the whole catch-up shares a hardcoded 120s budget
(`SYNC_TOTAL_TIMEOUT_MS`), the SWM meta phase is all-or-nothing, and resume does
not persist across restarts (responder session is in-memory). A large SWM pool
therefore cannot be onboarded regardless of access model. We raised the budgets
via env-patched constants as a stopgap; the real fixes (incremental commit /
persisted resume / configurable budgets) remain upstream.

---

## 5. (Operational) daemon startup timeout vs large-store WAL recovery → crash-loop

Not a protocol bug, but painful: after an unclean shutdown, Oxigraph WAL replay
of a multi-GB store takes longer than the daemon's ~15s startup readiness
timeout, so the supervisor declares failure and restarts — killing Oxigraph
mid-recovery and looping forever. Recovery only completes if Oxigraph is left
running uninterrupted (we recovered it by launching Oxigraph standalone until it
listened, then SIGTERM for a clean checkpoint, then starting the daemon).

**Ask:** make the startup readiness timeout scale with / be configurable for
store size, and don't SIGKILL a store engine that is still making recovery
progress.

---

## Summary for the OT team

The blockers for an open community-pool use case are **#1** (fresh members can't
sign SWM catch-up requests) and **#2** (empty `relayPeers` → unreachable). **#3**
and **#5** are sharp edges that wedge a node. All are curator/host-side observable;
we have curator-side patches in place but cannot patch the many consumer nodes,
so #1 and #2 in particular need an upstream fix to work for unmodified clients.
