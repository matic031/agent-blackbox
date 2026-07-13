# DKG Knowledge-Collection Publisher

Publish large datasets to the OriginTrail DKG (V10, Base mainnet) as **batched
knowledge collections** — one on-chain transaction per ~1,000 records instead
of one per record. Every record still becomes an individually-addressable,
SPARQL-queryable knowledge asset inside its collection.

**Why batch:** on-chain gas is per *transaction*; TRAC is per *byte × epoch*.
Batching collapses the gas side ~1,000× while leaving the TRAC side unchanged.
Measured on Base mainnet (July 2026), per 1,000-record collection (~2 MB
payload, ~12k triples):

| Cost | Amount |
|---|---|
| Gas (mint tx) | ~0.25–1M gas ≈ **$0.00001–0.0001** |
| TRAC (1 epoch = 30 days) | **~1.1 TRAC** (0.0008 TRAC/KB/epoch network price) |
| One-time CG registration | **~100 TRAC** deposit (RFC-53), charged at first mint |

A 460k-record dataset ≈ 460 transactions ≈ **<$1 of ETH + ~510 TRAC per epoch**.
Per-record minting of the same dataset would be ~$5,000–14,000 of gas.

## Prerequisites

- A **DKG V10 edge node** on Base mainnet (`dkg start`, API on :9200), with
  its auth token readable (default `~/.dkg-mainnet/auth.token`).
- Node ≥ 20 (scripts use built-in `fetch`; no npm dependencies).
- **Funding — two wallets, and this will bite you if you skip it:**
  - The node's *operational wallet 0* pays the one-time ~100 TRAC CG
    registration deposit.
  - The mint itself is signed by the CG's **on-chain authorized publisher
    wallet** — often a *different* operational wallet of the node (check
    `wallets.json`, and the daemon log line `Signing on-chain publish
    (… signer=0x…)`). That wallet needs a small ETH float (~0.001) and enough
    TRAC for the publish costs. "insufficient funds … have 0" on mint = this.

## Quick start

```bash
# 1. Adapt mapping.mjs to your data (recordKey / recordQuads / extractRecords).

# 2. Slice the source into deduplicated batches (default 1000 records each):
node chunk.mjs path/to/your-data.json --size 1000

# 3. Validate everything without spending:
KC_CG_ID=my-dataset node publish.mjs --dry-run

# 4. Publish (creates the CG if needed, then one PAID tx per batch):
KC_CG_ID=my-dataset KC_CG_NAME="My Dataset" KC_EPOCHS=12 node publish.mjs

# Or one batch at a time:
KC_CG_ID=my-dataset node publish.mjs --batch batch-001
```

`registry.json` is the resumable ledger — a batch with a `txHash` is never
re-paid; kill/re-run is always safe. Verify content afterwards:

```bash
curl -s -X POST http://127.0.0.1:9200/api/query \
  -H "authorization: Bearer $(head -1 ~/.dkg-mainnet/auth.token)" \
  -H 'content-type: application/json' \
  -d '{"contextGraphId":"my-dataset","sparql":"SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s ?p ?o }"}'
```

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `DKG_ENDPOINT` / `DKG_PORT` | `http://127.0.0.1` / `9200` | node API |
| `DKG_AUTH_TOKEN_PATH` | `~/.dkg-mainnet/auth.token` | Bearer token file |
| `KC_NETWORK` | `mainnet-base` | expected `networkConfig`; publisher refuses any other node |
| `KC_CG_ID` / `KC_CG_NAME` | `my-collection` | context graph id / display name |
| `KC_EPOCHS` | `1` | storage epochs (30 days each) — TRAC scales linearly; extend later via `extendKnowledgeAssetLifetime` |
| `KC_ATTEMPTS` | `3` | max mint attempts per batch (see "store overload" below) |

## Sizing

~1,000 records ≈ 12k triples ≈ 2 MB request payload. The node caps request
bodies around 10 MB, and the publisher refuses payloads >9 MB — if your
records are fat, lower `--size`. TRAC cost = `0.0008 × payloadKB × epochs`
(read the live price from AskStorage via the Hub if you want it exact).

## Operational gotchas (each of these cost us real debugging time)

1. **Public Base RPCs throttle the node.** The node's chain reads race a
   hard-coded 2.5 s timeout; `mainnet.base.org` can take 60 s under burst,
   drpc 429s. Symptom: mint refused with `LU-5/LU-11: publish access-policy
   is unknown`. Fix: run the bundled caching proxy and point the node at it —
   ```bash
   node rpc-proxy.mjs &          # listens on 127.0.0.1:8547
   # ~/.dkg-mainnet/config.json → "chain": {"rpcUrl": "http://127.0.0.1:8547", "rpcUrls": ["http://127.0.0.1:8547"]}
   dkg stop && dkg start
   ```
   The proxy caches read-only calls (15 s TTL), dedupes concurrent identical
   reads, rotates upstreams on 429, and never caches nonces/tx submission.

2. **Do not hammer mint retries when the node's store is busy.** The mint
   internally runs a large CONSTRUCT ("lift") against the node's Oxigraph
   store with a 30 s client timeout — but an aborted query keeps running
   server-side. Rapid retries stack queries until Oxigraph pegs every core
   for half an hour. If mints keep timing out: **restart the daemon (fresh
   store queue) and mint immediately**, one attempt at a time
   (`KC_ATTEMPTS=1`). On a node without other heavy content this rarely
   triggers at all.

3. **Duplicate records.** A rootEntity URI can exist only once per context
   graph ("Rule 4" validation error). `chunk.mjs` dedupes globally by
   `recordKey()` before batching — make sure your key really is stable and
   unique per logical entity.

4. **No typed dateTimes.** `^^xsd:dateTime` literals hit a canonicalization
   skew between publisher and peers on mainnet and the mint fails. Publish
   timestamps as plain string literals (the example mapping does).

5. **No blank nodes; literals < ~100 KB.** The node rejects blank-node
   objects and tombstones oversized literals. The publisher pre-validates
   both before spending anything.

6. **Stale share after a daemon restart.** If a mint 409s with *"not a
   complete full share resident in Shared Memory"*, the publisher
   automatically discards the draft, reseals, and retries — no action needed,
   just noted so the log line doesn't surprise you.

7. **CG registration is automatic but not free.** The first mint on a new CG
   registers it on-chain and charges the ~100 TRAC RFC-53 deposit from the
   node's operational wallet. Budget for it; it happens once per CG.

## Files

| File | Purpose |
|---|---|
| `mapping.mjs` | **your adaptation point** — record → key + quads |
| `chunk.mjs` | source file → deduplicated `batches/batch-NNN.json` |
| `publish.mjs` | CG ensure → seal/share → one paid mint per batch, resumable ledger |
| `rpc-proxy.mjs` | local caching Base-RPC proxy (gotcha #1) |
