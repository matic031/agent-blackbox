# Blackbox DKG publishing runbook

This directory prepares and publishes the Blackbox threat corpus as batched
DKG V10 knowledge collections. It is designed for a long, restartable Base
mainnet run on the curator node: one paid VM transaction per approximately
1,000 signals, always for **12 epochs**.

The production corpus currently expected by the scripts is:

| Item | Contract |
|---|---:|
| Source file | `prod-threats-400k.json` |
| Source SHA-256 | `8d46bd868166de5f09d5952e71c350217326750ff1bce4f93d97c90862e07a8c` |
| Signals | **460,000** |
| Batch size | **1,000** |
| Collections / paid transactions | **460** |
| Lifetime | **12 epochs** |

The local source file and generated `batches/` are intentionally ignored by
Git. They contain the corpus and must be copied to the node separately from
the branch.

## Safety model

`run.mjs` is the only entrypoint needed for the production workflow. It:

- builds batches in a staging directory and replaces the old set only after a
  complete build succeeds;
- deduplicates every record globally and writes a SHA-256 manifest for the
  source, mapping, and every collection;
- validates all 460 files and all mapped RDF before any node write;
- requires the node to report `@origintrail-official/dkg` **10.0.6** on
  `mainnet-base`;
- requires the target context graph to already exist and be verifiably
  curated/private;
- snapshots the private graph allowlist during preflight and refuses to share
  or publish if membership changes during the run;
- enforces exactly 12 epochs and requires a manifest-bound confirmation token
  before any paid work;
- uses the DKG's persistent async SWM-share queue and synchronous VM endpoint,
  then pulls the finalized VM assertion back and re-shares it to encrypted SWM;
- verifies the restored SWM subjects and quads through the official DKG query
  API and records every DKG job ID and transaction in `registry.json`;
- publishes one collection at a time, polls it to a terminal state, and stops
  on the first error instead of stacking retries against Blazegraph;
- writes live state to `progress.json` and a timestamped durable log.

The script never creates or registers a context graph. That is intentional: CG
creation sets access, publishing and PCA policy and can charge the one-time
registration deposit. We will make that CG together after curator access is
available.

Run the self-contained integration smoke test after transferring/updating the
scripts. It uses a temporary corpus and local mock node; it performs no network
or paid operation:

```bash
node test.mjs
```

## Privacy and encryption

Official DKG npm 10.0.6 supports curated/private context graphs with X25519
workspace keys, HKDF-SHA256 key derivation and AES-256-GCM-encrypted SWM
distribution to allowed agents. The production preflight therefore refuses a
graph unless its `accessPolicy` is private/curated (`1`, `ownerOnly`, or
`allowList`). See the official package's
[`dkg-node` guide](https://www.npmjs.com/package/@origintrail-official/dkg?activeTab=readme)
for private context graphs, encryption-key rotation, and async publishing.

Important distinctions:

- use `accessPolicy: 1` for an on-chain curated/private graph;
- do **not** use CLI `--private` for this job: that creates a local-only graph
  which cannot be published to VM;
- all allowed agents must have valid workspace encryption keys;
- freeze membership while a production publisher is active: disable automatic
  join approval before starting, then review and add new members between runs;
- private access is not a substitute for reviewing the source. Never publish
  secrets, credentials, personal data, or other sensitive plaintext merely
  because the graph is private;
- the script sends normal `quads` through the named-KA lifecycle. The DKG node,
  not this script, performs the private-CG encryption and member fan-out. Do not
  add ad-hoc client-side encryption to RDF literals.

## Prerequisites on the curator node

- Linux/macOS shell, Node.js 22 or newer, and npm 10 or newer.
- Official DKG installed as `@origintrail-official/dkg@10.0.6`, running on
  port 9200 with Blazegraph configured.
- Blazegraph operation timeout set to at least 10 minutes for the large VM
  pull and SWM restore (`store.options.timeout: 600000`, or the equivalent
  official `DKG_BLAZEGRAPH_OPERATION_TIMEOUT_MS=600000` setting).
- Node admin token readable at `~/.dkg/auth.token`, or set
  `DKG_AUTH_TOKEN_PATH`.
- The final curated/private CG already created and visible to this token.
- Wallet funding:
  - the registration wallet needs the one-time approximately 100 TRAC deposit;
  - the publisher wallet needs native ETH gas and either direct-spend
    TRAC or valid PCA agent registration/funding;
  - the earlier public-style estimate was approximately **6,100 TRAC** for
    460,000 signals at 12 epochs. The first curated/private batch instead
    quoted 0.007096875 TRAC because the on-chain storage payload was the small
    encrypted-catalog commitment. Do not extrapolate either figure blindly;
    record the live quote and balance delta for several batches before funding
    the full run.
- At least 2 GB free disk for source, batches, Blazegraph growth, logs and
  temporary preparation files. More headroom is strongly recommended.

Check the node itself before starting:

```bash
dkg --version
dkg doctor
dkg publisher wallet list
dkg publisher stats
```

## 1. Transfer the corpus

Either copy `catalogs/prod-threats-400k.json` to the curator node and prepare
there, or prepare locally and copy the generated `batches/` directory. The
first approach is easiest to audit:

```bash
rsync -avP catalogs/prod-threats-400k.json \
  curator:/absolute/private/path/prod-threats-400k.json
```

The already-prepared local collection set is about 169 MB and can instead be
copied directly into the same checkout on the curator node:

```bash
rsync -avP scripts/dkg-kc-publisher/batches/ \
  curator:/absolute/path/agent-guardian/scripts/dkg-kc-publisher/batches/
```

Do not place the auth token, wallet files, or corpus in Git.

## 2. Prepare all 460 collections (no node calls, no cost)

From this directory on the curator node:

```bash
node run.mjs prepare --source /absolute/private/path/prod-threats-400k.json
```

This rebuilds `batches/`, writes `batches/manifest.json`, then maps and
validates the complete corpus. It uses a 4 GB Node heap by default. Expected
result:

```text
done: 460 batches, 460,000 records, 0 duplicates
local validation OK: 460,000 records, 460 batches, ... quads
dry-run complete: no node calls and no writes
```

Verify the source fingerprint:

```bash
sha256sum /absolute/private/path/prod-threats-400k.json
# macOS: shasum -a 256 /absolute/private/path/prod-threats-400k.json
```

It must equal the SHA-256 at the top of this runbook.

## 3. Create the private CG together

Do not guess these values. Once curator access is available, decide and record:

1. immutable CG slug/ID;
2. human-readable name;
3. description;
4. creator and every allowed agent address;
5. `accessPolicy: 1` (curated/private);
6. publish policy (normally curated);
7. PCA account ID, if PCA will fund the 12-epoch publishes;
8. publisher node identity attribution (`0` means no attribution);
9. which operational publisher wallet will be funded.

The basic two-phase CLI shape is:

```bash
dkg context-graph create <slug> \
  --name "<name>" \
  --description "<description>" \
  --access-policy 1 \
  --allowed-agent <0x-agent-address>

dkg context-graph register <full-context-graph-id> \
  --access-policy 1 \
  --publish-policy 0 \
  --pca-account-id <pca-id>
```

The bare slug may be expanded to `<creator-agent-address>/<slug>`; copy the
exact full ID printed by the create command. Registration is paid. Review the
command and wallet balances before running it.

## 4. Read-only production preflight

The production graph is registered on Base mainnet as on-chain CG **13**:

```text
0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox
```

On `blackbox-publisher-node`, use the node's internal API on port 8900. The
public nginx endpoint on port 9200 has a 1 MB body limit and rejects these
approximately 2.2 MB batch requests.

Set the exact full CG ID and run:

```bash
export KC_CG_ID='<full-context-graph-id>'
export KC_CG_ONCHAIN_ID=13
export KC_EPOCHS=12
export DKG_PORT=8900
export DKG_AUTH_TOKEN_PATH="$HOME/.dkg/auth.token"

node run.mjs preflight
```

Preflight repeats the complete local validation, checks node version/network,
verifies that this token can see a private CG, pins the sorted allowed-agent
membership fingerprint, prints wallet balances, and prints a paid confirmation
token like:

```text
<full-context-graph-id>:12:<manifest-hash-prefix>
```

Do not proceed if the wallet output is unclear, the graph policy is not
private, the allowlist is still changing, or the node is not official npm
10.0.6. Automatic join approval must remain disabled for the complete paid
run. The publisher checks the fingerprint again immediately before SWM sharing
and immediately before each paid publish.

## 5. Smoke-test one paid collection

First publish only the first collection:

```bash
node run.mjs publish \
  --batch batch-001 \
  --confirm '<exact-token-from-preflight>'
```

The first production smoke batch was confirmed on 2026-07-13:

```text
batch:       batch-001
members:     1,000
VM triples:  13,194
epochs:      12
transaction: 0x922fd626fedd9dec2a016200132e5211e3a851d529d99a452062036d3f0eefe6
block:       48589150
UAL:         did:dkg:base:8453/0x80738050893c3e769560331c8fd63a421b340d46/25191691567270760314062235701068010715288728691171855589300500455534398275743
```

The verified VM breakdown is 865 dependency signals, 103 injection signals,
and 32 skill signals. DKG logged the curated-CG encrypted inline path and only
the catalog commitment was priced for on-chain storage.

Then verify it before continuing:

```bash
node run.mjs status
dkg publisher jobs

curl -s -X POST http://127.0.0.1:8900/api/query \
  -H "authorization: Bearer $(grep -v '^#' ~/.dkg/auth.token | head -1)" \
  -H 'content-type: application/json' \
  -d '{"contextGraphId":"<full-context-graph-id>","sparql":"SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s ?p ?o }"}'
```

VM publication drains the KA's active SWM data as part of the canonical
`WM -> SWM -> VM` lifecycle. The publisher therefore performs a second,
non-paid operation after VM confirmation: it pulls the finalized assertion
from VM into WM and re-shares it to encrypted SWM. A batch is complete only
after the official `shared-working-memory` query view returns all 1,000
subjects and the restored quads match the prepared batch. DKG 10.0.6 does not
expose a named-KA `/swm/quads` endpoint; do not use that nonexistent endpoint
as a completion check.

Assets first written by DKG 10.0.5 may contain Blazegraph's legacy replacement
characters for non-ASCII RDF text. The publisher recognizes and records this
specific historical normalization as `legacy-blazegraph-unicode`; newly
created 10.0.6 assets must verify in `exact` mode.

Confirm all three views before continuing:

1. the publisher reports 1,000 promoted SWM root entities;
2. a separate allowed client syncs and queries the same 1,000 SWM threats;
3. the same client queries the 1,000 public VM threats.

Also confirm that a non-member cannot read the SWM data. Run Agent Guardian
sync and verify Source, Contributor and references in the product UI. Only
continue after this smoke test passes.

The official DKG default SWM TTL is 30 days. This corpus is intended to remain
available to the community for the full 12-epoch VM lifetime, so configure
`sharedMemoryTtlMs` to at least `31104000000` (360 days) on the curator and on
clients that must retain the full SWM corpus. Restart DKG after changing the
configuration and verify the effective value before the production run.

## 6. Run all remaining collections unattended

Use `nohup` or a terminal multiplexer. The script automatically skips the
finalized first batch and continues from `registry.json`:

```bash
nohup node run.mjs publish \
  --from-batch batch-002 \
  --confirm '<exact-token-from-preflight>' \
  > blackbox-publish-console.log 2>&1 &

echo $! > blackbox-publish.pid
tail -f blackbox-publish-console.log
```

In another shell:

```bash
node run.mjs status
dkg publisher stats
```

`progress.json` includes the current batch, DKG job ID/state, completed count,
percentage, last transaction, heartbeat, and ETA. Every invocation also writes
`publish-<timestamp>.log` in this directory.

Use one inclusive range invocation for a long continuation. This validates the
full corpus once, holds the single-publisher lock for the run, processes every
selected batch sequentially, and stops on the first error or insufficient-funds
response. Do not run a shell loop of one process per batch when a contiguous
range is intended.

`KC_PIPELINE_WIDTH=2` overlaps the free WM creation and encrypted SWM share for
the next batch with the current batch's paid VM wait. Paid VM publishing remains
strictly serialized at one transaction request at a time. The next batch keeps
its persistent `shareJobId` in `registry.json`, so a stop or rollback resumes it
without creating another share job. Set `KC_PIPELINE_WIDTH=1` to return to the
fully sequential path without changing or deleting the registry.

After VM finalization, the publisher queries and verifies the existing encrypted
SWM copy by exact subject count and quad-set hash. It skips the VM-to-WM pull and
second SWM share only when that verification succeeds; otherwise the full restore
and post-restore verification still run.

At the observed rate of about 30 minutes for two collections, a strictly
sequential 460-collection run is approximately **115 hours (4.8 days)**, not a
few hours. The bounded width-two pipeline can reduce idle time when SWM sharing
and paid VM confirmation have similar durations, but actual throughput remains
dependent on encrypted gossip, Blazegraph, peers, and chain confirmation. Do
not run concurrent paid publishers or increase the pipeline beyond two.

## Resume and error handling

Re-run the exact same publish command after a clean stop or machine restart.
The script reconciles persistent share job IDs before starting new work.
Finalized VM batches are never paid again. A finalized VM batch without a
verified `swmReplicatedAt` entry is resumed only through the free VM-to-SWM
restore path; it is not sent to the paid endpoint again.

DKG 10.0.5's async VM queue lost the large first-batch job while rewriting its
claimed state. The default is therefore `KC_VM_PUBLISH_MODE=sync`. A synchronous
request writes `publishStartedAt` before entering the paid endpoint. If the
request times out, disconnects, or the local lifecycle view remains stale, the
script derives the full KA ID from the reserved UAL and checks the official
`/api/kc/:kaId` chain metadata. It adopts an existing publish only when the
on-chain Merkle root and author match the prepared assertion and every expected
threat is queryable through the official VM view. The endpoint's all-zero root
with a null author is the official unminted placeholder and is not treated as a
collision. Any nonzero different root is a hard collision and stops before
another paid call. Do not remove
`publishStartedAt` merely to make a retry proceed.

- `registry.json` is the authoritative local ledger. Every update preserves the
  preceding version as `registry.json.bak`; back both up during the run.
- `progress.json` is a human/machine-readable live status snapshot.
- `registry.json.lock` prevents two paid publisher processes using the same
  ledger. If the process was killed uncleanly, verify no publisher is running
  before removing a stale lock.
- A failed async DKG job stops the script and records the phase/error. Inspect it with
  `dkg publisher job <job-id>` and node logs. Do not blindly delete job IDs or
  registry entries.
- A client timeout during KA creation is reconciled against the node's sealed
  WM quads and adopted only when the entire quad set matches.
- A chain-confirmed publish is reconciled only from matching author, Merkle
  root, and complete expected VM content. Extra DKG metadata quads are allowed;
  missing prepared quads are not.
- If the private allowlist fingerprint changes after preflight, the publisher
  stops before SWM sharing or payment. Review membership and encryption-key
  rotation, then start a new preflight rather than bypassing the guard.
- There are no automatic paid retries. Ambiguous or failed publishes must be
  inspected against chain state before retrying.

Useful diagnostics:

```bash
dkg logs --follow
dkg publisher stats
dkg publisher jobs
node run.mjs status
```

If Blazegraph is overloaded, stop this client cleanly, let the active DKG job
settle, inspect the queue and node logs, and only then resume. Rapid retries can
stack expensive graph work and make recovery take much longer.

Before starting, also verify that only one DKG service owns the configured
port. A second system or user service can continuously restart against the same
port and destabilize otherwise healthy jobs:

```bash
systemctl status dkg-node.service
systemctl --user status blackbox-dkg.service
ss -ltnp | grep ':8900'
```

## Files

| File | Purpose |
|---|---|
| `run.mjs` | production entrypoint and durable log tee |
| `chunk.mjs` | atomic deduplicated batching + checksummed manifest |
| `mapping.mjs` | Blackbox record-to-RDF mapping |
| `publish.mjs` | validation, private-CG preflight, async share, synchronous publish, resume |
| `rpc-proxy.mjs` | optional Base RPC caching/failover helper |
| `batches/manifest.json` | corpus and per-collection integrity contract |
| `registry.json` | paid-run ledger; never delete during a run |
| `progress.json` | current live status and error information |

## Supported overrides

| Variable | Default | Meaning |
|---|---|---|
| `DKG_ENDPOINT` / `DKG_PORT` | `http://127.0.0.1` / `8900` | curator node internal API |
| `DKG_AUTH_TOKEN_PATH` | `~/.dkg/auth.token` | node admin token file |
| `KC_NETWORK` | `mainnet-base` | required DKG network |
| `KC_DKG_VERSION` | `10.0.6` | exact official npm node version |
| `KC_CG_ID` | none | required full context graph ID |
| `KC_CG_ONCHAIN_ID` | none | pinned registered CG ID fallback when DKG omits `accessPolicy` from list output |
| `KC_EPOCHS` | `12` | enforced production lifetime |
| `KC_EXPECT_RECORDS` | `460000` | enforced corpus size |
| `KC_POLL_MS` | `30000` | async job polling interval |
| `KC_REQUEST_TIMEOUT_MS` | `2700000` | 45-minute mutation timeout with heartbeats |
| `KC_VM_PUBLISH_MODE` | `sync` | VM endpoint; use `async` only after the historical 10.0.5 queue issue is resolved and tested |
| `KC_PIPELINE_WIDTH` | `1` | `2` overlaps the next free SWM stage while keeping paid VM publishing serialized; `1` is the rollback path |
| `KC_PUBLISHER_NODE_IDENTITY_ID` | `0` | no-attribution publisher identity override |

Do not change the version, record count, epochs, mapping or batches during a
run. The manifest/registry checks intentionally refuse such drift.
