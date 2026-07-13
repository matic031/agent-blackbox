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
- requires the node to report `@origintrail-official/dkg` **10.0.5** on
  `mainnet-base`;
- requires the target context graph to already exist and be verifiably
  curated/private;
- enforces exactly 12 epochs and requires a manifest-bound confirmation token
  before any paid work;
- uses the DKG's persistent async SWM-share and VM-publish queues, recording
  every DKG job ID and transaction in `registry.json`;
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

Official DKG npm 10.0.5 supports curated/private context graphs with X25519
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
- private access is not a substitute for reviewing the source. Never publish
  secrets, credentials, personal data, or other sensitive plaintext merely
  because the graph is private;
- the script sends normal `quads` through the named-KA lifecycle. The DKG node,
  not this script, performs the private-CG encryption and member fan-out. Do not
  add ad-hoc client-side encryption to RDF literals.

## Prerequisites on the curator node

- Linux/macOS shell, Node.js 22 or newer, and npm 10 or newer.
- Official DKG installed as `@origintrail-official/dkg@10.0.5`, running on
  port 9200 with Blazegraph configured.
- Node admin token readable at `~/.dkg-mainnet/auth.token`, or set
  `DKG_AUTH_TOKEN_PATH`.
- The final curated/private CG already created and visible to this token.
- Wallet funding:
  - the registration wallet needs the one-time approximately 100 TRAC deposit;
  - the async publisher wallet needs native ETH gas and either direct-spend
    TRAC or valid PCA agent registration/funding;
  - budget approximately **6,100 TRAC** for 460,000 signals at 12 epochs, plus
    margin. The observed estimate is 1.1 TRAC per 1,000-signal collection per
    epoch. Confirm live pricing and balances before the paid run.
- At least 2 GB free disk for source, batches, Blazegraph growth, logs and
  temporary preparation files. More headroom is strongly recommended.

Check the node itself before starting:

```bash
dkg --version
dkg doctor
dkg publisher wallets
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
9. which operational/async publisher wallets will be funded.

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

Set the exact full CG ID and run:

```bash
export KC_CG_ID='<full-context-graph-id>'
export KC_EPOCHS=12

node run.mjs preflight
```

Preflight repeats the complete local validation, checks node version/network,
verifies that this token can see a private CG, prints wallet balances, and
prints a paid confirmation token like:

```text
<full-context-graph-id>:12:<manifest-hash-prefix>
```

Do not proceed if the wallet output is unclear, the graph policy is not
private, or the node is not official npm 10.0.5.

## 5. Smoke-test one paid collection

First publish only the first collection:

```bash
node run.mjs publish \
  --batch batch-001 \
  --confirm '<exact-token-from-preflight>'
```

Then verify it before continuing:

```bash
node run.mjs status
dkg publisher jobs

curl -s -X POST http://127.0.0.1:9200/api/query \
  -H "authorization: Bearer $(grep -v '^#' ~/.dkg-mainnet/auth.token | head -1)" \
  -H 'content-type: application/json' \
  -d '{"contextGraphId":"<full-context-graph-id>","sparql":"SELECT (COUNT(DISTINCT ?s) AS ?n) WHERE { ?s ?p ?o }"}'
```

Confirm encryption/private access from a non-member as well as an allowed
member, then run Agent Guardian sync and verify Source, Contributor and
references in the product UI. Only continue after this smoke test passes.

## 6. Run all remaining collections unattended

Use `nohup` or a terminal multiplexer. The script automatically skips the
finalized first batch and continues from `registry.json`:

```bash
nohup node run.mjs publish \
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

At the observed rate of about 30 minutes for two collections, a strictly
sequential 460-collection run is approximately **115 hours (4.8 days)**, not a
few hours. The preparation and smoke test can be completed in hours; the full
paid seed cannot at that measured rate. Do not increase concurrency merely to
meet a clock: parallel Blazegraph work can make the run slower and less safe.

## Resume and error handling

Re-run the exact same publish command after a clean stop or machine restart.
The script reconciles persistent share/publish job IDs before enqueueing new
work. Finalized batches are never paid again.

- `registry.json` is the authoritative local ledger. Every update preserves the
  preceding version as `registry.json.bak`; back both up during the run.
- `progress.json` is a human/machine-readable live status snapshot.
- `registry.json.lock` prevents two paid publisher processes using the same
  ledger. If the process was killed uncleanly, verify no publisher is running
  before removing a stale lock.
- A failed DKG job stops the script and records the phase/error. Inspect it with
  `dkg publisher job <job-id>` and node logs. Do not blindly delete job IDs or
  registry entries.
- A client timeout during KA creation is reconciled against the node's sealed
  WM quads and adopted only when the entire quad set matches.
- There are no automatic paid retries. The persistent DKG queue owns chain
  recovery; ambiguous or failed jobs must be inspected before retrying.

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

## Files

| File | Purpose |
|---|---|
| `run.mjs` | production entrypoint and durable log tee |
| `chunk.mjs` | atomic deduplicated batching + checksummed manifest |
| `mapping.mjs` | Blackbox record-to-RDF mapping |
| `publish.mjs` | validation, private-CG preflight, async share/publish, resume |
| `rpc-proxy.mjs` | optional Base RPC caching/failover helper |
| `batches/manifest.json` | corpus and per-collection integrity contract |
| `registry.json` | paid-run ledger; never delete during a run |
| `progress.json` | current live status and error information |

## Supported overrides

| Variable | Default | Meaning |
|---|---|---|
| `DKG_ENDPOINT` / `DKG_PORT` | `http://127.0.0.1` / `9200` | curator node API |
| `DKG_AUTH_TOKEN_PATH` | `~/.dkg-mainnet/auth.token` | token file |
| `KC_NETWORK` | `mainnet-base` | required DKG network |
| `KC_DKG_VERSION` | `10.0.5` | exact official npm node version |
| `KC_CG_ID` | none | required full context graph ID |
| `KC_EPOCHS` | `12` | enforced production lifetime |
| `KC_EXPECT_RECORDS` | `460000` | enforced corpus size |
| `KC_POLL_MS` | `30000` | async job polling interval |
| `KC_REQUEST_TIMEOUT_MS` | `2700000` | 45-minute mutation timeout with heartbeats |

Do not change the version, record count, epochs, mapping or batches during a
run. The manifest/registry checks intentionally refuse such drift.
