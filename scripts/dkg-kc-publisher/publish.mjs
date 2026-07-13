#!/usr/bin/env node
/**
 * Batched Knowledge-Collection publisher for a DKG V10 edge node (Base
 * mainnet). One PAID on-chain mint per batch anchors ALL records in that
 * batch as individually-addressable knowledge assets — this is the cost
 * lever: gas is per-transaction, TRAC is per-byte×epoch.
 *
 * Flow per batch:  create+seal+share KA (free, off-chain)  →  vm/publish (PAID).
 *
 * Safety rails:
 *  - refuses to run unless the node reports the expected network
 *  - resumable ledger (registry.json): a batch with a txHash is never re-paid;
 *    a sealed-but-unminted batch resumes at the mint step
 *  - transient pre-flight failures (chain policy-read timeouts) retry
 *    bounded; the tx is only signed after pre-flight passes, so those retries
 *    are free — but see README about NOT hammering retries when the store is
 *    the bottleneck
 *
 * Config via env:
 *   DKG_ENDPOINT   default http://127.0.0.1
 *   DKG_PORT       default 9200
 *   DKG_AUTH_TOKEN_PATH  default ~/.dkg-mainnet/auth.token
 *   KC_NETWORK     expected node networkConfig, default mainnet-base
 *   KC_CG_ID       context graph id, default my-collection
 *   KC_CG_NAME     display name, default = KC_CG_ID
 *   KC_EPOCHS      storage epochs (30 days each), default 1
 *   KC_ATTEMPTS    max vm/publish attempts per batch, default 3
 *   KC_KA_PREFIX   KA name prefix, default = KC_CG_ID
 *
 * Usage:
 *   node publish.mjs --dry-run           # build + validate quads, no writes
 *   node publish.mjs                     # all unpublished batches, in order
 *   node publish.mjs --batch batch-001   # one batch
 */
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { recordQuads } from './mapping.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const BASE = `${process.env.DKG_ENDPOINT ?? 'http://127.0.0.1'}:${process.env.DKG_PORT ?? '9200'}`;
const NETWORK = process.env.KC_NETWORK ?? 'mainnet-base';
const CG_ID = process.env.KC_CG_ID ?? 'my-collection';
const CG_NAME = process.env.KC_CG_NAME ?? CG_ID;
const EPOCHS = Number(process.env.KC_EPOCHS ?? '1');
const ATTEMPTS = Number(process.env.KC_ATTEMPTS ?? '3');
const KA_PREFIX = process.env.KC_KA_PREFIX ?? CG_ID;
const TOKEN_PATH = process.env.DKG_AUTH_TOKEN_PATH ?? join(homedir(), '.dkg-mainnet', 'auth.token');
const LEDGER = join(here, 'registry.json');

const argv = process.argv.slice(2);
const DRY = argv.includes('--dry-run');
const only = argv.includes('--batch') ? argv[argv.indexOf('--batch') + 1] : null;

const authToken = readFileSync(TOKEN_PATH, 'utf8').split('\n').map((l) => l.trim()).find((l) => l && !l.startsWith('#'));

async function api(method, path, body, timeoutMs = 60_000) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${authToken}` },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = { raw: text }; }
  if (!res.ok) { const e = new Error(`${res.status} ${path}: ${json.error ?? text.slice(0, 400)}`); e.body = json; throw e; }
  return json;
}

const ledger = existsSync(LEDGER) ? JSON.parse(readFileSync(LEDGER, 'utf8')) : { cg: null, batches: {} };
const saveLedger = () => writeFileSync(LEDGER, JSON.stringify(ledger, null, 2));

async function main() {
  const status = await api('GET', '/api/status');
  if (status.networkConfig !== NETWORK) {
    throw new Error(`refusing: node at ${BASE} is "${status.name}" (${status.networkConfig}), expected ${NETWORK}`);
  }
  console.log(`node OK: ${status.name} ${status.networkName} peers=${status.connectedPeers}`);

  const batchFiles = readdirSync(join(here, 'batches')).filter((f) => f.endsWith('.json')).sort()
    .filter((f) => !only || f === `${only}.json`);
  if (!batchFiles.length) throw new Error('no batch files — run chunk.mjs first');

  // Build + validate quads up front (cheap, catches mapping bugs before spending).
  const prepared = [];
  for (const f of batchFiles) {
    const { name, records } = JSON.parse(readFileSync(join(here, 'batches', f), 'utf8'));
    const quads = records.flatMap(recordQuads);
    for (const q of quads) {
      if (q.object.length > 60_000) throw new Error(`${name}: oversize literal on ${q.subject} ${q.predicate} (${q.object.length}B)`);
      if (!q.object.startsWith('"') && !/^[a-z][a-z0-9+.-]*:/i.test(q.object)) throw new Error(`${name}: object not IRI/literal: ${q.object.slice(0, 80)}`);
    }
    const bytes = JSON.stringify(quads).length;
    console.log(`${name}: ${records.length} records -> ${quads.length} quads, ~${(bytes / 1e6).toFixed(2)} MB payload`);
    if (bytes > 9_000_000) throw new Error(`${name}: payload exceeds the node's ~10MB request cap — use a smaller --size`);
    prepared.push({ name, quads });
  }
  if (DRY) { console.log('dry-run: no writes performed'); return; }

  // Ensure the context graph exists (free, local; on-chain registration —
  // and its ~100 TRAC deposit — happens automatically on the first mint).
  const exists = await api('GET', `/api/context-graph/exists?id=${encodeURIComponent(CG_ID)}`).catch(() => null);
  if (exists?.exists) {
    ledger.cg = CG_ID;
  } else if (!ledger.cg) {
    const created = await api('POST', '/api/context-graph/create', { id: CG_ID, name: CG_NAME, description: `${CG_NAME} — batched knowledge-collection publishing.` });
    ledger.cg = created.id ?? CG_ID;
    console.log('created CG:', JSON.stringify(created).slice(0, 200));
  }
  saveLedger();
  console.log('context graph:', ledger.cg);

  for (const { name, quads } of prepared) {
    const rec = (ledger.batches[name] ??= {});
    const kaName = `${KA_PREFIX}-${name}`;

    if (rec.txHash) { console.log(`[${name}] already published: ${rec.ual}`); continue; }

    if (!rec.sealed) {
      console.log(`[${name}] create+seal+share KA "${kaName}" (${quads.length} quads)...`);
      const r = await api('POST', '/api/knowledge-assets', {
        contextGraphId: ledger.cg, name: kaName, quads, finalize: true, alsoShareSwm: true,
      }, 600_000);
      if (Array.isArray(r.errors) && r.errors.length) throw new Error(`[${name}] phase errors: ${JSON.stringify(r.errors).slice(0, 500)}`);
      rec.sealed = true;
      saveLedger();
      console.log(`[${name}] sealed + shared`);
    }

    console.log(`[${name}] PAID vm/publish (epochs=${EPOCHS}) — one on-chain tx...`);
    let r;
    for (let attempt = 1; ; attempt++) {
      try {
        r = await api('POST', `/api/knowledge-assets/${encodeURIComponent(kaName)}/vm/publish`, {
          contextGraphId: ledger.cg, options: { publishEpochs: EPOCHS },
        }, 600_000);
        break;
      } catch (e) {
        // "not a complete full share" after a node restart → discard + reseal.
        if (/not a complete full share/i.test(e.message)) {
          console.log(`[${name}] stale SWM share — discarding + resealing...`);
          await api('POST', `/api/knowledge-assets/${encodeURIComponent(kaName)}/wm/discard`, { contextGraphId: ledger.cg }, 120_000).catch(() => {});
          rec.sealed = false; saveLedger();
          const rr = await api('POST', '/api/knowledge-assets', {
            contextGraphId: ledger.cg, name: kaName, quads, finalize: true, alsoShareSwm: true,
          }, 600_000);
          if (Array.isArray(rr.errors) && rr.errors.length) throw new Error(`[${name}] reseal phase errors: ${JSON.stringify(rr.errors).slice(0, 500)}`);
          rec.sealed = true; saveLedger();
          continue;
        }
        const transient = /access-policy is unknown|timed out|timeout|fetch failed/i.test(e.message);
        if (!transient || attempt >= ATTEMPTS) throw e;
        console.log(`[${name}] transient pre-flight failure (attempt ${attempt}/${ATTEMPTS}), retrying in 15s: ${e.message.slice(0, 120)}`);
        await new Promise((res) => setTimeout(res, 15_000));
      }
    }
    Object.assign(rec, { kaId: r.kaId, ual: r.ual, txHash: r.txHash, blockNumber: r.blockNumber, status: r.status, epochs: EPOCHS });
    saveLedger();
    console.log(`[${name}] MINTED ual=${r.ual} tx=${r.txHash} block=${r.blockNumber} status=${r.status}`);
  }

  console.log('\nDone. Ledger:', LEDGER);
}

main().catch((e) => { console.error('FATAL:', e.message); process.exit(1); });
