# DKG V10 — Public SWM catch-up cannot onboard a fresh node to a large shared-memory graph

**Reporter:** Umanitek (Agent Guardian)
**DKG version:** v10.0.2 (monorepo build), network `mainnet-base`, `nodeRole: edge`
**Severity:** blocks the core "subscribe to a public community graph and read it" flow once the SWM pool is large

## Summary

A fresh node that subscribes to a **public** Context Graph with a large **Shared Working Memory (SWM)** pool never receives the SWM data. The SWM catch-up phase is **all-or-nothing**: it only commits after the *entire* `_shared_memory_meta` graph downloads in one uninterrupted session, and it neither commits incrementally nor resumes across attempts. On a real mainnet link (relayed, flapping) the meta phase never completes a single pass, so `shared memory` inserted stays `0`.

The **durable-data** catch-up, on the *same node and link*, commits incrementally and succeeds. That isolates the problem: transport, data, access policy, and publisher are all fine — only the SWM path's commit/resume strategy fails.

## Environment / data shape

- Public Context Graph `umanitek/guardian-threats-staging`, `accessPolicy=public`, on-chain id 5.
- ~15,051 SWM entities · `_shared_memory` ≈ 231k triples · `_shared_memory_meta` ≈ **178,636 triples** · ~4,200 slices.
- Publisher (Node A) is healthy and serving; SWM fan-out delivers to peers with `rejected=0`.

## Reproduction

1. **Node A** (publisher): public CG with ~15k SWM entities shared.
2. **Node B** (fresh subscriber):
   ```
   dkg subscribe umanitek/guardian-threats-staging --save
   dkg sync catchup-status umanitek/guardian-threats-staging --watch
   ```
3. Catch-up reports `Status: done` with `shared memory 0` (or a handful). Re-triggering (node restart) always restarts from scratch.

## Observed — two independent fresh nodes

**Node B1 — remote, relayed connection:**
```
Result: peers 23/23, data 843, shared memory 0
swm     fetched meta/data 274000/9,  inserted 0/0,      resumed phases 0, transport failures 5, phase failures 3
durable fetched meta/data 102696/5025, inserted 78797/843     <-- durable commits incrementally
```
`swm fetched meta = 274000` is the 178k meta re-downloaded from offset 0 across retries — it never completes one pass, so **0 inserted**.

**Node B2 — fresh node on the same LAN, DIRECT connection to the publisher:**
```
Result: data 9271, shared memory 9
swm     fetched meta/data 15/9,       inserted 15/9
durable fetched meta/data 102619/9271, inserted 102619/9271   <-- durable fully synced
```
Even over a **direct LAN link**, SWM delivers ~9 while durable delivers everything it fetches. The difference is **commit strategy, not transport** — the direct link also flaps (connection closes ~every 13s), which the incremental durable path survives and the all-or-nothing SWM path does not.

## Root cause

1. **SWM commit is all-or-nothing.** The SWM meta phase must download the entire `_shared_memory_meta` before anything is inserted. The durable path commits per page as it arrives (`inserted` climbs with `fetched`); the SWM path shows `inserted 0` until the whole meta completes, which never happens on a real link.

2. **SWM resume does not work across re-triggers.** The checkpoint store is in-memory (`MemorySyncCheckpointStore`), and SWM resume *additionally* requires an in-memory "responder session":
   `packages/agent/src/sync/requester/page-fetch.ts` —
   ```
   if (usesPageSession && offset > 0 && !savedResponderSession) {
     checkpointStore.delete(checkpointKey);
     offset = 0;   // SWM restarts from scratch
   }
   ```
   A node restart is the only way to re-trigger a catch-up, and it wipes both the checkpoint and the session, so every attempt restarts from offset 0 (`resumedPhases: 0`). The code comment confirms it: *"Recovery never persists a responder session to resume."*

3. **Per-page timeout is a hardcoded 45s.** `SYNC_PAGE_TIMEOUT_MS = 45_000` (`packages/agent/src/dkg-agent-constants.ts`), not configurable. A single stalled or reset page over a relayed mainnet link aborts the whole meta phase.

## Impact

Any public Context Graph whose SWM grows beyond what one uninterrupted meta-download can carry over real mainnet transport becomes **un-onboardable**: new subscribers can never catch up the backlog, even though the durable tier syncs fine. This blocks the intended "subscribe to a public community graph and read it" flow at scale.

## Suggested fixes (any one unblocks it)

1. **Commit SWM catch-up incrementally per page**, as the durable path already does, so partial progress persists and a fresh node accumulates across attempts.
2. **Persist the SWM checkpoint + responder session** (or make SWM paging stateless/offset-based like the durable path) so catch-up resumes across restarts/reconnects instead of restarting from 0.
3. **Make `SYNC_PAGE_TIMEOUT_MS` configurable** and/or add adaptive backoff so a large meta phase can complete over a slow/flaky link.

Fix #1 or #2 is the real one; #3 alone only widens the window.

## What is NOT the problem (ruled out)

- Publisher data/config: CG is `accessPolicy=public`, SWM fan-out delivers with `rejected=0`, publisher serves pages.
- Transport: durable data fully syncs over the identical link; a direct LAN link fails the same way.
- Node health: reproduced against a healthy, freshly-restarted publisher (16 peers, fast store).

---

# Appendix — other DKG-side issues in the same `daemon.log`

Same node, same window. Listed for context; some share the P2P-substrate reliability theme with the SWM issue above. Counts are total occurrences in the log.

## A. VM publish cannot reach quorum — two distinct causes

Last successful on-chain publish: **2026-07-07 00:12:07** (nothing since). Two independent failure modes:

1. **Substrate transport resets during ACK collection.**
   `[ACKCollector] … substrate queued (transport): The stream has been reset` — **×6,520**; `V10 ACK collection failed (QuorumUnmetError): storage_ack_insufficient` — **×454**. The messenger-substrate connection to core storage peers resets mid-ACK, so the publisher cannot collect the required valid ACKs. (Same substrate-reliability theme as the SWM catch-up above.)

2. **Merkle-root / leaf-canonicalization mismatch.**
   `MERKLE_MISMATCH_IN_SWM` — **×161** (`publisher=0x… local=0x…`, same KA, different roots); `INVALID_SIGNATURE` — **×52**, all with `dial=ok`. Core peers compute a *different* merkle root than this **v10.0.2** node for the same KA — consistent with the backend-independent leaf-canonicalization (#1386 / #1399, shipped in v10.0.2) **not yet deployed to the core fleet** hosting the graph. A v10.0.2 publisher therefore cannot reach quorum against pre-v10.0.2 core nodes. The `packages/core/src/crypto/term-canon.ts` comment notes *"a coordinated release suffices; no migration."*
   **Fix:** roll the leaf-canon to the core fleet (coordinated release).

## B. Global `agents` registry graph is un-syncable — one oversized literal aborts the whole graph

`Sync … "agents" … failed: RDF literal … predicate=https://dkg.origintrail.io/skill#contextGraphsServed … is 118,689 Java MUTF-8 bytes, which exceeds the … 65,535 … limit` — **×449**; durable sync of `agents` times out — **×2,280**. One agent (`did:dkg:agent:0x146e2b5f…`) published a 118 KB `contextGraphsServed` value; because a store insert **aborts the whole batch** on a single over-limit literal, the global `agents` registry can no longer sync — degrading peer/agent discovery network-wide.
**Fix:** enforce the per-literal byte limit at **publish** time, and/or **skip the single over-limit triple** on sync instead of aborting the entire graph. (This is the same abort-instead-of-skip pattern that also affected a publisher-side KA.)

## C. `[promote-worker] claimNext error: fetch failed` — ×5,672

Very high-frequency background error from the promote worker (tight retry loop). Flagging for investigation — likely a fetch against an unavailable endpoint/peer that never backs off.

## D. Chain RPC heavily degraded

`429 Too Many Requests` — **×4,683**; `request timeout (code=TIMEOUT)` — **×2,985**; `[chain] provider error … rpc=base-mainnet.core.chainstack.com: failed to bootstrap network detection` — **×433**; `RPC endpoints exhausted` — **×27**. Partly provider-dependent (rate limits), but the **volume** suggests the node issues a very high number of chain calls under load. Worth checking `eth_call` / `eth_getLogs` batching and poll cadence to reduce RPC pressure (this compounds the publish failures in A, since publish needs chain reads).

## Addendum 2026-07-10 — reproduced unchanged on v10.0.5, root cause narrowed to hardcoded budgets

Re-tested with the published `@origintrail-official/dkg@10.0.5` (npm, mainnet-base) on a fresh consumer: `shared memory: 0 data + 127500 meta triples fetched`, then `Sync timeout for shared-memory meta phase … data phase (0 triples) … snapshot phase (0 triples)` — all three phases die on the same shared deadline.

The v10.0.5 numbers make the failure arithmetic, not environmental:

- `dkg-agent/dist/dkg-agent-constants.js`: `SYNC_TOTAL_TIMEOUT_MS = 120_000` — the **entire catch-up run** (every subscribed graph, and all three SWM phases of each) shares a 120s budget (`createContextGraphSyncDeadline` divides it by remaining graphs, floor `SYNC_MIN_GRAPH_BUDGET_MS = 10_000`).
- Our public graph's `_shared_memory_meta` is ~178k triples; observed transfer is ~1k triples/s over relayed mainnet links. One meta pass needs ~3 min > the whole budget, **so a fresh node can never complete it regardless of link quality**. We measured 127.5k/178k (71%) fetched at deadline, every attempt, forever.
- The new public-snapshot phase (`syncPublicSnapshotsForMeta`) only runs **after** the meta phase inside the **same** deadline, so the bulk-distribution lane added in 10.0.5 is starved by the exact defect it presumably exists to mitigate.
- Cross-restart resume is still broken as originally reported: checkpoints are now SQLite-persisted, but SWM resume additionally requires the requester-side responder-session entry, which is still an in-memory `Map` (`sync/requester/page-fetch.js`), so `offset` resets to 0 on restart.
- The responder paging session TTL (`DURABLE_DATA_SYNC_SESSION_TTL_MS = 10 min`) bounds any single-session pull; combined with the 120s requester budget the effective ceiling per pass is the 120s.

Workaround we now deploy (requester-side, no protocol change): raise `SYNC_TOTAL_TIMEOUT_MS` to 600s, `SYNC_PAGE_TIMEOUT_MS` to 90s, `SYNC_MIN_GRAPH_BUDGET_MS` to 120s (env-overridable) in the installed `dkg-agent` dist. With a 600s budget one meta pass fits inside the stock 10-min responder TTL and a fresh consumer completes SWM catch-up. This confirms suggested fix #3 (configurable budgets) unblocks real deployments even before #1/#2 (incremental commit / persisted resume) land — but #1/#2 remain the correct fixes, since any graph whose meta outgrows one responder-TTL window will hit the wall again.
