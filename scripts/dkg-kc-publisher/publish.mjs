#!/usr/bin/env node
/**
 * Safe, resumable DKG V10 knowledge-collection publisher.
 *
 * Paid publishing is deliberately explicit. The script validates the complete
 * manifest before writes, verifies the exact npm node version and a curated /
 * private context graph, then shares and publishes one collection at a time.
 */
import { createHash } from 'node:crypto';
import {
  closeSync, copyFileSync, existsSync, openSync, readFileSync, readdirSync,
  renameSync, statSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { recordKey, recordQuads } from './mapping.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const has = (flag) => argv.includes(flag);
const option = (name, fallback) => {
  const index = argv.indexOf(`--${name}`);
  return index === -1 ? fallback : argv[index + 1];
};

const selectedModes = [
  ['--publish', 'publish'], ['--preflight', 'preflight'], ['--dry-run', 'dry-run'],
].filter(([flag]) => has(flag));
const mode = selectedModes.length === 1 ? selectedModes[0][1] : null;
const onlyBatch = option('batch', null);
const batchDir = resolve(process.env.KC_BATCH_DIR ?? join(here, 'batches'));
const registryPath = resolve(process.env.KC_REGISTRY_PATH ?? join(here, 'registry.json'));
const progressPath = resolve(process.env.KC_PROGRESS_PATH ?? join(here, 'progress.json'));
const lockPath = `${registryPath}.lock`;
const endpoint = process.env.DKG_ENDPOINT ?? 'http://127.0.0.1';
const port = process.env.DKG_PORT ?? '9200';
const endpointUrl = new URL(endpoint);
if (!endpointUrl.port) endpointUrl.port = port;
endpointUrl.pathname = '/';
endpointUrl.search = '';
endpointUrl.hash = '';
const base = endpointUrl.toString().replace(/\/$/, '');
const network = process.env.KC_NETWORK ?? 'mainnet-base';
const expectedVersion = process.env.KC_DKG_VERSION ?? '10.0.5';
const contextGraphId = process.env.KC_CG_ID;
const epochs = Number(process.env.KC_EPOCHS ?? '12');
const kaPrefix = process.env.KC_KA_PREFIX ?? contextGraphId?.split('/').filter(Boolean).at(-1);
const tokenPath = resolve((process.env.DKG_AUTH_TOKEN_PATH ?? join(homedir(), '.dkg-mainnet', 'auth.token')).replace(/^~(?=\/)/, homedir()));
const pollMs = Number(process.env.KC_POLL_MS ?? '30000');
const requestTimeoutMs = Number(process.env.KC_REQUEST_TIMEOUT_MS ?? '2700000');
const expectedRecords = Number(process.env.KC_EXPECT_RECORDS ?? '460000');
const allowPartialManifest = process.env.KC_ALLOW_PARTIAL_MANIFEST === '1';
const swmOnlyBatches = Number(process.env.KC_SWM_ONLY_BATCHES ?? '0');
const pauseAfterBatch = Number(process.env.KC_PAUSE_AFTER_BATCH ?? '0');
const pauseControlPath = process.env.KC_PAUSE_CONTROL_PATH
  ? resolve(process.env.KC_PAUSE_CONTROL_PATH)
  : null;
const expectedManifestPath = process.env.KC_EXPECTED_MANIFEST_PATH
  ? resolve(process.env.KC_EXPECTED_MANIFEST_PATH)
  : null;
const vmPublishMode = process.env.KC_VM_PUBLISH_MODE ?? 'sync';
const vmMaxInflight = Number(process.env.KC_VM_MAX_INFLIGHT ?? '12');
const publisherNodeIdentityId = Number(process.env.KC_PUBLISHER_NODE_IDENTITY_ID ?? '0');
const expectedOnChainCgId = process.env.KC_CG_ONCHAIN_ID ?? '';
const startedAt = Date.now();
let lockFd;
let authToken;
let authTokens = [];
let progress = {};

function usage() {
  console.error(`usage:
  node publish.mjs --dry-run [--batch batch-001]
  KC_CG_ID=<id> node publish.mjs --preflight
  KC_CG_ID=<id> node publish.mjs --publish --confirm <token>

The exact paid confirmation token is printed by --preflight.`);
}

function assertConfig() {
  if (!mode) throw new Error('choose exactly one of --dry-run, --preflight, or --publish');
  if (!Number.isSafeInteger(epochs) || epochs !== 12) throw new Error(`KC_EPOCHS must be exactly 12 for this production corpus; got ${epochs}`);
  if (!Number.isSafeInteger(pollMs) || pollMs < 1_000) throw new Error(`KC_POLL_MS must be an integer >= 1000; got ${pollMs}`);
  if (!Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs < 60_000) throw new Error(`KC_REQUEST_TIMEOUT_MS must be >= 60000; got ${requestTimeoutMs}`);
  if (!Number.isSafeInteger(expectedRecords) || expectedRecords < 1) throw new Error(`KC_EXPECT_RECORDS must be a positive integer; got ${expectedRecords}`);
  if (!Number.isSafeInteger(swmOnlyBatches) || swmOnlyBatches < 0) throw new Error(`KC_SWM_ONLY_BATCHES must be a non-negative integer; got ${swmOnlyBatches}`);
  if (!Number.isSafeInteger(pauseAfterBatch) || pauseAfterBatch < 0) throw new Error(`KC_PAUSE_AFTER_BATCH must be a non-negative integer; got ${pauseAfterBatch}`);
  if (pauseAfterBatch > 0 && !pauseControlPath) throw new Error('KC_PAUSE_CONTROL_PATH is required when KC_PAUSE_AFTER_BATCH is non-zero');
  if (!['sync', 'async', 'async-all'].includes(vmPublishMode)) throw new Error(`KC_VM_PUBLISH_MODE must be sync, async, or async-all; got ${vmPublishMode}`);
  if (!Number.isSafeInteger(vmMaxInflight) || vmMaxInflight < 1) throw new Error(`KC_VM_MAX_INFLIGHT must be a positive integer; got ${vmMaxInflight}`);
  if (!Number.isSafeInteger(publisherNodeIdentityId) || publisherNodeIdentityId < 0) throw new Error(`KC_PUBLISHER_NODE_IDENTITY_ID must be a non-negative integer; got ${publisherNodeIdentityId}`);
  if ((mode === 'preflight' || mode === 'publish') && !contextGraphId) throw new Error('KC_CG_ID is required for node preflight/publish');
  if (mode === 'publish' && !kaPrefix) throw new Error('KC_KA_PREFIX or KC_CG_ID is required');
}

function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

function atomicJson(path, value) {
  const temp = `${path}.tmp-${process.pid}`;
  writeFileSync(temp, `${JSON.stringify(value, null, 2)}\n`);
  renameSync(temp, path);
}

function updateProgress(fields) {
  progress = { ...progress, ...fields, pid: process.pid, updatedAt: new Date().toISOString() };
  atomicJson(progressPath, progress);
}

function log(message) {
  console.log(`[${new Date().toISOString()}] ${message}`);
}

function duration(ms) {
  const seconds = Math.max(0, Math.round(ms / 1000));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  return `${hours ? `${hours}h ` : ''}${minutes ? `${minutes}m ` : ''}${rest}s`;
}

function readTokens() {
  if (!existsSync(tokenPath)) throw new Error(`auth token not found: ${tokenPath}`);
  const tokens = readFileSync(tokenPath, 'utf8').split('\n').map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
  if (tokens.length === 0) throw new Error(`auth token file is empty: ${tokenPath}`);
  return tokens;
}

async function api(method, path, body, timeoutMs = 60_000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error(`request exceeded ${timeoutMs}ms`)), timeoutMs);
  const heartbeat = setInterval(() => {
    log(`waiting for ${method} ${path} (${duration(Date.now() - requestStarted)})`);
    updateProgress({ heartbeat: `${method} ${path}`, heartbeatSeconds: Math.round((Date.now() - requestStarted) / 1000) });
  }, 60_000);
  const requestStarted = Date.now();
  try {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const candidates = [authToken, ...authTokens.filter((token) => token !== authToken)];
    let response;
    let text = '';
    for (const candidate of candidates) {
      response = await fetch(`${base}${path}`, {
        method,
        headers: { 'content-type': 'application/json', authorization: `Bearer ${candidate}` },
        body: payload,
        signal: controller.signal,
      });
      text = await response.text();
      if (response.status !== 401) {
        authToken = candidate;
        break;
      }
    }
    if (!response) throw new Error(`no API authentication candidates available for ${path}`);
    let json;
    try { json = JSON.parse(text); } catch { json = { raw: text }; }
    if (!response.ok) {
      const error = new Error(`${response.status} ${path}: ${json.error ?? text.slice(0, 500)}`);
      error.status = response.status;
      error.body = json;
      throw error;
    }
    return json;
  } catch (error) {
    if (controller.signal.aborted) {
      const timeoutError = new Error(`timeout waiting for ${method} ${path} after ${duration(timeoutMs)}; remote state may have changed`);
      timeoutError.code = 'CLIENT_TIMEOUT';
      throw timeoutError;
    }
    throw error;
  } finally {
    clearTimeout(timeout);
    clearInterval(heartbeat);
  }
}

function validateQuad(batchName, quad) {
  if (!quad || typeof quad !== 'object') throw new Error(`${batchName}: mapping returned a non-object quad`);
  if (!/^[a-z][a-z0-9+.-]*:/i.test(quad.subject) || quad.subject.startsWith('_:')) throw new Error(`${batchName}: invalid subject ${String(quad.subject).slice(0, 100)}`);
  if (!/^[a-z][a-z0-9+.-]*:/i.test(quad.predicate) || quad.predicate.startsWith('_:')) throw new Error(`${batchName}: invalid predicate ${String(quad.predicate).slice(0, 100)}`);
  if (typeof quad.object !== 'string') throw new Error(`${batchName}: quad object must be a string`);
  if (Buffer.byteLength(quad.object) > 60_000) throw new Error(`${batchName}: literal/object exceeds 60KB at ${quad.subject} ${quad.predicate}`);
  if (quad.object.startsWith('_:')) throw new Error(`${batchName}: blank-node objects are not supported`);
  if (!quad.object.startsWith('"') && !/^[a-z][a-z0-9+.-]*:/i.test(quad.object)) throw new Error(`${batchName}: object is not an IRI or quoted literal: ${quad.object.slice(0, 100)}`);
}

function loadAndValidateBatches() {
  const manifestPath = join(batchDir, 'manifest.json');
  if (!existsSync(manifestPath)) throw new Error(`batch manifest not found: ${manifestPath}; run chunk.mjs first`);
  const manifestBytes = readFileSync(manifestPath);
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  if (manifest.version !== 1) throw new Error(`unsupported manifest version: ${manifest.version}`);
  if (!manifest.complete && !allowPartialManifest) throw new Error('manifest is a partial/max-batches build; production publish requires the complete corpus');
  if (manifest.includedRecords !== expectedRecords) throw new Error(`expected ${expectedRecords.toLocaleString()} records, manifest has ${Number(manifest.includedRecords).toLocaleString()}`);
  if (manifest.batchCount !== manifest.batches?.length) throw new Error('manifest batchCount does not match batches list');
  if (manifest.batchCount !== Math.ceil(expectedRecords / manifest.batchSize)) throw new Error('manifest batch count/size does not cover the expected corpus exactly');
  if (swmOnlyBatches > manifest.batchCount) throw new Error(`KC_SWM_ONLY_BATCHES=${swmOnlyBatches} exceeds manifest batch count ${manifest.batchCount}`);
  if (pauseAfterBatch > manifest.batchCount) throw new Error(`KC_PAUSE_AFTER_BATCH=${pauseAfterBatch} exceeds manifest batch count ${manifest.batchCount}`);
  const mappingHash = sha256(readFileSync(join(here, 'mapping.mjs')));
  if (mappingHash !== manifest.mapping?.sha256) throw new Error('mapping.mjs changed since the batches were prepared; rebuild them before publishing');

  const namesOnDisk = readdirSync(batchDir).filter((name) => name.endsWith('.json') && name !== 'manifest.json').sort();
  const expectedFiles = manifest.batches.map((batch) => batch.file).sort();
  if (JSON.stringify(namesOnDisk) !== JSON.stringify(expectedFiles)) throw new Error('batch directory contents do not exactly match manifest (stale/missing JSON files)');

  const seenKeys = new Set();
  const stats = [];
  const selected = onlyBatch ? manifest.batches.filter((batch) => batch.name === onlyBatch) : manifest.batches;
  if (onlyBatch && selected.length !== 1) throw new Error(`batch not found in manifest: ${onlyBatch}`);

  for (let index = 0; index < manifest.batches.length; index += 1) {
    const entry = manifest.batches[index];
    const path = join(batchDir, entry.file);
    const bytes = readFileSync(path);
    if (statSync(path).size !== entry.bytes || sha256(bytes) !== entry.sha256) throw new Error(`${entry.name}: checksum/size differs from manifest`);
    const parsed = JSON.parse(bytes.toString('utf8'));
    if (parsed.name !== entry.name || !Array.isArray(parsed.records) || parsed.records.length !== entry.records) throw new Error(`${entry.name}: content does not match manifest metadata`);
    for (const record of parsed.records) {
      const key = recordKey(record);
      if (seenKeys.has(key)) throw new Error(`${entry.name}: duplicate record key across batches: ${key}`);
      seenKeys.add(key);
    }
    const mappedQuads = parsed.records.flatMap(recordQuads);
    for (const quad of mappedQuads) validateQuad(entry.name, quad);
    // An RDF graph is a set, not a bag. Triple stores collapse exact duplicate
    // triples, so commitments and receiver expectations must be calculated
    // from the same canonical set that the node will persist. This also keeps
    // repeated source tags/references from creating false integrity failures.
    const quads = canonicalRdfSetQuads(mappedQuads);
    const payloadBytes = Buffer.byteLength(JSON.stringify(quads));
    if (payloadBytes > 9_000_000) throw new Error(`${entry.name}: ${payloadBytes} byte payload exceeds the 9MB safety cap`);
    stats.push({
      name: entry.name,
      records: parsed.records.length,
      quads: quads.length,
      sourceQuads: mappedQuads.length,
      duplicateQuadsRemoved: mappedQuads.length - quads.length,
      payloadBytes,
      quadSetSha256: quadSetHash(quads),
      publicQuadsDigest: workspacePublicQuadsDigest(quads),
    });
    if ((index + 1) % 25 === 0 || index + 1 === manifest.batches.length) {
      log(`validated ${index + 1}/${manifest.batches.length} batch files`);
    }
  }
  if (!onlyBatch && seenKeys.size !== manifest.includedRecords) throw new Error('validated record-key count differs from manifest');
  return { manifest, manifestSha256: sha256(manifestBytes), selected, stats };
}

function privatePolicy(policy) {
  if (policy === 1) return true;
  const normalized = String(policy ?? '').toLowerCase().replace(/[^a-z]/g, '');
  return ['1', 'private', 'curated', 'owneronly', 'allowlist'].includes(normalized);
}

function walletBalanceSummary(wallets) {
  return {
    chainId: wallets.chainId,
    symbol: wallets.symbol,
    balances: wallets.balances.map(({ address, eth, trac, symbol }) => ({
      address, eth, trac, ...(symbol ? { symbol } : {}),
    })),
  };
}

function definitiveCreateRejection(error) {
  return error?.status === 413
    || (error?.status === 400 && /Assertion name cannot contain "\/"/.test(error.message ?? ''));
}

async function nodePreflight(manifestSha256) {
  authTokens = readTokens();
  authToken = authTokens[0];
  const status = await api('GET', '/api/status');
  if (status.networkConfig !== network) throw new Error(`node network is ${status.networkConfig}, expected ${network}`);
  if (status.version !== expectedVersion) throw new Error(`node DKG version is ${status.version ?? 'unknown'}, expected official npm ${expectedVersion}`);
  if (vmPublishMode !== 'sync' && status.asyncPublisher?.available !== true) {
    const reason = status.asyncPublisher?.reason ?? 'availability_not_reported';
    const operatorAction = reason === 'publisher_disabled'
      ? 'enable it with `dkg publisher enable`, configure at least one publisher wallet, then restart the daemon'
      : reason === 'no_publisher_wallets'
        ? 'configure at least one publisher wallet, then restart the daemon'
        : reason === 'publisher_starting'
          ? 'wait for the async publisher to become ready, then rerun preflight'
          : 'inspect the daemon publisher startup error, correct it, restart the daemon, and rerun preflight';
    throw new Error(`async VM mode ${vmPublishMode} requires an available async publisher; node reports ${reason}: ${operatorAction}`);
  }
  const exists = await api('GET', `/api/context-graph/exists?id=${encodeURIComponent(contextGraphId)}`);
  if (!exists.exists) throw new Error(`context graph does not exist: ${contextGraphId}; create and review it before publishing`);
  let graph;
  for (let attempt = 1; attempt <= 3 && !graph; attempt += 1) {
    const list = await api('GET', '/api/context-graph/list', undefined, requestTimeoutMs);
    graph = (list.contextGraphs ?? []).find((candidate) => [candidate.id, candidate.contextGraphId, candidate.uri, candidate.did].includes(contextGraphId));
    if (!graph && attempt < 3) await new Promise((resolvePromise) => setTimeout(resolvePromise, 2_000));
  }
  if (!graph) throw new Error(`context graph ${contextGraphId} exists but is not visible to this token in /api/context-graph/list`);
  let privacyEvidence = `accessPolicy=${String(graph.accessPolicy ?? 'private flag')}`;
  if (!privatePolicy(graph.accessPolicy) && !graph.private && !graph.isPrivate) {
    const onChainId = String(graph.onChainId ?? '');
    if (!expectedOnChainCgId || onChainId !== expectedOnChainCgId) {
      throw new Error(`context graph ${contextGraphId} is not verifiably private/curated (accessPolicy=${String(graph.accessPolicy)}, onChainId=${onChainId || 'missing'}); refusing to write corpus data`);
    }
    const participants = await api('GET', `/api/context-graph/${encodeURIComponent(contextGraphId)}/participants`);
    const ownerAddress = contextGraphId.split('/')[0]?.toLowerCase();
    const allowedAgents = (participants.allowedAgents ?? []).map((address) => String(address).toLowerCase());
    if (!ownerAddress || !allowedAgents.includes(ownerAddress)) {
      throw new Error(`context graph ${contextGraphId} has pinned on-chain id ${onChainId}, but its owner is not in the curated allowlist`);
    }
    privacyEvidence = `pinned onChainId=${onChainId}, curated owner allowlist`;
  }
  const wallets = await api('GET', '/api/wallets/balances');
  if (wallets.error || !Array.isArray(wallets.balances) || wallets.balances.length === 0) {
    throw new Error(`wallet balance preflight failed: ${wallets.error ?? 'no operational wallet balances returned'}`);
  }
  const publisherStats = await api('GET', '/api/publisher/stats');
  log(`node OK: ${status.name} v${status.version} ${status.networkConfig}, peers=${status.connectedPeers ?? 'unknown'}`);
  log(`private context graph OK: ${contextGraphId} (${privacyEvidence})`);
  log(`wallet preflight: ${JSON.stringify(walletBalanceSummary(wallets))}`);
  log(`async publisher queue: ${JSON.stringify(publisherStats).slice(0, 1000)}`);
  log(`VM publish mode: ${vmPublishMode}; publisher node identity id: ${publisherNodeIdentityId}`);
  const confirmation = `${contextGraphId}:12:${manifestSha256.slice(0, 12)}`
    + (swmOnlyBatches > 0 ? `:swm${swmOnlyBatches}` : '');
  log(`paid confirmation token: ${confirmation}`);
  return { status, graph, wallets, publisherStats, confirmation };
}

function loadRegistry(manifest, manifestSha256) {
  const expectedMeta = {
    version: 2,
    contextGraphId,
    network,
    dkgVersion: expectedVersion,
    epochs,
    sourceSha256: manifest.source.sha256,
    mappingSha256: manifest.mapping.sha256,
    manifestSha256,
    batchCount: manifest.batchCount,
    recordCount: manifest.includedRecords,
    allowPartialManifest,
    swmOnlyBatches,
  };
  if (!existsSync(registryPath)) return { meta: expectedMeta, createdAt: new Date().toISOString(), batches: {} };
  const registry = JSON.parse(readFileSync(registryPath, 'utf8'));
  for (const [key, value] of Object.entries(expectedMeta)) {
    if (registry.meta?.[key] !== value) throw new Error(`registry belongs to a different run: meta.${key}=${JSON.stringify(registry.meta?.[key])}, expected ${JSON.stringify(value)}`);
  }
  registry.batches ??= {};
  return registry;
}

function saveRegistry(registry) {
  registry.updatedAt = new Date().toISOString();
  if (existsSync(registryPath)) copyFileSync(registryPath, `${registryPath}.bak`);
  atomicJson(registryPath, registry);
}

function readBatch(entry) {
  const parsed = JSON.parse(readFileSync(join(batchDir, entry.file), 'utf8'));
  return { records: parsed.records, quads: canonicalRdfSetQuads(parsed.records.flatMap(recordQuads)) };
}

function canonicalRdfSetQuads(quads) {
  const unique = new Map();
  for (const quad of quads) {
    // Graph-scoped KAs are relocated into their UAL-derived assertion graph by
    // the node, so the submitted graph term is placement metadata and the
    // canonical public commitment deliberately binds only (s,p,o).
    const normalized = {
      subject: String(quad.subject),
      predicate: String(quad.predicate),
      object: String(quad.object),
      graph: '',
    };
    const key = JSON.stringify([
      normalized.subject,
      normalized.predicate,
      normalized.object,
      normalized.graph,
    ]);
    if (!unique.has(key)) unique.set(key, normalized);
  }
  return [...unique.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([, quad]) => quad);
}

function quadSetHash(quads) {
  return sha256([...quads].map((quad) => JSON.stringify(quad)).sort().join('\n'));
}

// Keep this byte-for-byte aligned with
// packages/publisher/src/workspace-snapshot-store.ts:workspacePublicQuadsDigest.
// Graph-scoped sharing normalizes every submitted quad into the UAL-derived
// assertion graph, so the durable commitment intentionally hashes graph="".
function workspacePublicQuadsDigest(quads) {
  const canonical = canonicalRdfSetQuads(quads)
    .map((quad) => [String(quad.subject), String(quad.predicate), String(quad.object), ''])
    .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
  return `sha256:${sha256(JSON.stringify(canonical))}`;
}

async function reconcileCreate(kaName, expectedQuads) {
  const encoded = encodeURIComponent(kaName);
  const query = `contextGraphId=${encodeURIComponent(contextGraphId)}`;
  const [state, stored] = await Promise.all([
    api('GET', `/api/knowledge-assets/${encoded}/wm?${query}`),
    api('GET', `/api/knowledge-assets/${encoded}/wm/quads?${query}`, undefined, requestTimeoutMs),
  ]);
  if (!state.currentAssertion || !Array.isArray(stored.quads)) return false;
  if (stored.quads.length !== expectedQuads.length || quadSetHash(stored.quads) !== quadSetHash(expectedQuads)) {
    throw new Error(`${kaName}: existing WM assertion differs from the prepared batch; refusing to adopt it`);
  }
  log(`${kaName}: reconciled an earlier create request from node state (${stored.quads.length.toLocaleString()} matching quads)`);
  return true;
}

async function pollShareJob(batchName, jobId) {
  let readFailures = 0;
  for (;;) {
    let job;
    try {
      job = await api('GET', `/api/knowledge-assets/swm/share-jobs/${encodeURIComponent(jobId)}`);
      readFailures = 0;
    } catch (error) {
      readFailures += 1;
      if (readFailures > 20 || (error.status && error.status < 500)) throw error;
      log(`[${batchName}] share-status read failed ${readFailures}/20; retrying without mutating: ${error.message}`);
      await new Promise((resolvePromise) => setTimeout(resolvePromise, pollMs));
      continue;
    }
    const state = job.state ?? job.status;
    updateProgress({ phase: 'sharing', currentBatch: batchName, dkgJobId: jobId, dkgJobState: state });
    log(`[${batchName}] share job ${jobId}: ${state}`);
    if (['succeeded', 'success', 'completed', 'finalized'].includes(state)) return job;
    if (['failed', 'cancelled'].includes(state)) throw new Error(`[${batchName}] share job ${jobId} ${state}: ${job.error ?? job.failure?.message ?? JSON.stringify(job).slice(0, 1000)}`);
    await new Promise((resolvePromise) => setTimeout(resolvePromise, pollMs));
  }
}

async function pollPublishJob(batchName, jobId) {
  let readFailures = 0;
  for (;;) {
    let response;
    try {
      response = await api('GET', `/api/publisher/job?id=${encodeURIComponent(jobId)}`);
      readFailures = 0;
    } catch (error) {
      readFailures += 1;
      // A freshly accepted async publisher job can briefly be absent from
      // the single-job read path while the durable job index catches up.
      // The list endpoint and worker may already contain/finalize it, so a
      // transient 404 is a status-read race, not proof that publishing
      // failed. Keep the retry bounded and never enqueue a replacement job.
      const transientNotFound = error.status === 404;
      if (readFailures > 20 || (error.status && error.status < 500 && !transientNotFound)) throw error;
      log(`[${batchName}] publish-status read failed ${readFailures}/20; retrying without mutating: ${error.message}`);
      await new Promise((resolvePromise) => setTimeout(resolvePromise, pollMs));
      continue;
    }
    const job = response.job ?? response;
    const state = job.status ?? job.state;
    updateProgress({ phase: 'publishing', currentBatch: batchName, dkgJobId: jobId, dkgJobState: state });
    log(`[${batchName}] publish job ${jobId}: ${state}`);
    if (state === 'finalized') return job;
    if (state === 'failed') throw new Error(`[${batchName}] publish job ${jobId} failed: ${job.failure?.message ?? job.error ?? JSON.stringify(job.failure ?? job).slice(0, 1500)}`);
    await new Promise((resolvePromise) => setTimeout(resolvePromise, pollMs));
  }
}

function publisherInflight(stats) {
  return ['accepted', 'claimed', 'validated', 'broadcast', 'included']
    .reduce((sum, state) => sum + Number(stats?.[state] ?? 0), 0);
}

async function waitForAsyncPublisherCapacity(batchName) {
  let lastReportedAt = 0;
  while (true) {
    const stats = await api('GET', '/api/publisher/stats');
    const inflight = publisherInflight(stats);
    if (inflight < vmMaxInflight) return;
    if (Date.now() - lastReportedAt >= 10_000 || lastReportedAt === 0) {
      log(`[${batchName}] publisher backpressure: ${inflight}/${vmMaxInflight} jobs in flight; waiting before enqueue`);
      updateProgress({
        phase: 'publisher-backpressure',
        currentBatch: batchName,
        publisherInflight: inflight,
        publisherMaxInflight: vmMaxInflight,
      });
      lastReportedAt = Date.now();
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, pollMs));
  }
}

function recordFinalized(rec, job) {
  const finalization = job.finalization ?? {};
  const inclusion = job.inclusion ?? {};
  const broadcast = job.broadcast ?? {};
  const txHash = finalization.txHash ?? inclusion.txHash ?? broadcast.txHash;
  if (!txHash && finalization.mode !== 'local' && finalization.mode !== 'noop') throw new Error('finalized DKG job has no transaction hash');
  Object.assign(rec, {
    status: 'finalized',
    publishJobState: 'finalized',
    txHash: txHash ?? null,
    ual: finalization.ual ?? null,
    blockNumber: inclusion.blockNumber ?? null,
    finalizedAt: new Date().toISOString(),
    dkgFinalizationMode: finalization.mode ?? null,
  });
}

function recordSynchronousFinalized(rec, result) {
  if (!result?.txHash || !result?.ual) throw new Error(`synchronous DKG publish response is missing txHash or ual: ${JSON.stringify(result).slice(0, 1500)}`);
  Object.assign(rec, {
    status: 'finalized',
    publishMode: 'sync',
    publishJobState: result.status ?? 'confirmed',
    txHash: result.txHash,
    ual: result.ual,
    blockNumber: result.blockNumber ?? null,
    finalizedAt: new Date().toISOString(),
    dkgFinalizationMode: 'published',
  });
}

async function publishSynchronous(entry, rec, kaName, registry) {
  if (rec.publishStartedAt) {
    throw new Error(`[${entry.name}] an earlier synchronous paid publish started at ${rec.publishStartedAt} without a recorded terminal result; verify chain and node state, then reconcile registry.json before retrying`);
  }
  rec.publishMode = 'sync';
  rec.publishStartedAt = new Date().toISOString();
  rec.status = 'publishing';
  saveRegistry(registry);
  log(`[${entry.name}] starting PAID synchronous VM publish for ${epochs} epochs`);
  const result = await api('POST', `/api/knowledge-assets/${encodeURIComponent(kaName)}/vm/publish`, {
    contextGraphId,
    options: { publishEpochs: epochs, publisherNodeIdentityId },
  }, requestTimeoutMs);
  recordSynchronousFinalized(rec, result);
}

async function waitForMidRunResume(completed, currentBatch) {
  if (!pauseControlPath || pauseAfterBatch === 0 || completed !== pauseAfterBatch) return;
  const readyPath = `${pauseControlPath}.ready.json`;
  const resumePath = `${pauseControlPath}.resume`;
  atomicJson(readyPath, {
    runPid: process.pid,
    contextGraphId,
    completedBatches: completed,
    currentBatch,
    readyAt: new Date().toISOString(),
  });
  if (existsSync(resumePath)) {
    log(`mid-run pause ${completed}/${pauseAfterBatch}: resume marker already present`);
    return;
  }
  log(`PAUSED after ${completed} batches; waiting for mid-run join validation before ${resumePath} is created`);
  let lastHeartbeat = 0;
  while (!existsSync(resumePath)) {
    if (Date.now() - lastHeartbeat >= 30_000) {
      updateProgress({
        status: 'paused',
        phase: 'awaiting-mid-join',
        completedBatches: completed,
        pauseReadyPath: readyPath,
        resumePath,
      });
      lastHeartbeat = Date.now();
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 2_000));
  }
  updateProgress({ status: 'running', phase: 'mid-join-complete', completedBatches: completed });
  log(`mid-run join validation complete; resuming after ${completed} batches`);
}

async function publishAll(validated, preflight) {
  const suppliedConfirmation = option('confirm', '');
  if (suppliedConfirmation !== preflight.confirmation) throw new Error(`paid confirmation mismatch; rerun --preflight and pass --confirm ${preflight.confirmation}`);
  lockFd = openSync(lockPath, 'wx');
  writeFileSync(lockFd, `${JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString(), contextGraphId })}\n`);

  const registry = loadRegistry(validated.manifest, validated.manifestSha256);
  saveRegistry(registry);
  const entries = onlyBatch ? validated.selected : validated.manifest.batches;
  let completed = Object.values(registry.batches).filter((record) => ['swm', 'finalized'].includes(record.status)).length;
  let processedThisRun = 0;
  updateProgress({
    status: 'running', phase: 'starting', startedAt: new Date(startedAt).toISOString(),
    contextGraphId, epochs, totalBatches: validated.manifest.batchCount,
    completedBatches: completed, totalRecords: validated.manifest.includedRecords,
  });

  await waitForMidRunResume(completed, null);

  for (const entry of entries) {
    const manifestIndex = validated.manifest.batches.findIndex((candidate) => candidate.name === entry.name);
    const targetMemory = manifestIndex < swmOnlyBatches ? 'SWM' : 'VM';
    const batchStartedAt = Date.now();
    const rec = (registry.batches[entry.name] ??= {
      checksum: entry.sha256,
      records: entry.records,
      epochs,
      targetMemory,
      status: 'pending',
    });
    if (rec.checksum !== entry.sha256) throw new Error(`${entry.name}: registry checksum differs from manifest`);
    if (rec.targetMemory && rec.targetMemory !== targetMemory) throw new Error(`${entry.name}: registry target memory ${rec.targetMemory} differs from ${targetMemory}`);
    rec.targetMemory = targetMemory;
    const priorCreateRejected = rec.createStartedAt
      && rec.lastError?.phase === 'create'
      && definitiveCreateRejection(rec.lastError);
    if (priorCreateRejected) {
      delete rec.createStartedAt;
      rec.status = 'pending';
      saveRegistry(registry);
      log(`[${entry.name}] retrying after definitive HTTP 413 gateway rejection`);
    }
    if (rec.status === 'swm' && targetMemory === 'SWM') {
      log(`[${entry.name}] already retained in SWM`);
      continue;
    }
    if (rec.status === 'finalized' && (rec.txHash || rec.dkgFinalizationMode === 'noop')) {
      log(`[${entry.name}] already finalized in VM: ${rec.txHash ?? rec.dkgFinalizationMode}`);
      continue;
    }
    const kaName = `${kaPrefix}-${entry.name}`;
    updateProgress({ phase: 'loading', currentBatch: entry.name, currentKa: kaName, completedBatches: completed });
    const { quads } = readBatch(entry);

    if (!rec.sealedAt) {
      let reconciled = false;
      if (rec.createStartedAt) {
        reconciled = await reconcileCreate(kaName, quads).catch((error) => {
          if (error.status === 404) return false;
          throw error;
        });
        if (!reconciled) throw new Error(`[${entry.name}] prior create request is not present as a complete sealed WM assertion; inspect ${kaName} before retrying`);
      }
      if (!reconciled) {
        rec.createStartedAt = new Date().toISOString();
        rec.status = 'creating';
        saveRegistry(registry);
        log(`[${entry.name}] creating and sealing ${kaName} (${quads.length.toLocaleString()} quads)`);
        try {
          const created = await api('POST', '/api/knowledge-assets', {
            contextGraphId, name: kaName, quads, finalize: true, alsoShareSwm: false,
          }, requestTimeoutMs);
          if (Array.isArray(created.errors) && created.errors.length > 0) throw new Error(`create phase errors: ${JSON.stringify(created.errors).slice(0, 1500)}`);
          rec.assertionUri = created.assertionUri ?? null;
        } catch (error) {
          const adopt = (error.code === 'CLIENT_TIMEOUT' || error.status === 409)
            ? await reconcileCreate(kaName, quads).catch(() => false)
            : false;
          if (!adopt) {
            if (definitiveCreateRejection(error)) {
              delete rec.createStartedAt;
              rec.status = 'pending';
            }
            rec.lastError = { at: new Date().toISOString(), phase: 'create', message: error.message, code: error.code ?? null, status: error.status ?? null };
            saveRegistry(registry);
            throw error;
          }
        }
      }
      try {
        rec.sealedAt = new Date().toISOString();
        rec.status = 'sealed';
        saveRegistry(registry);
      } catch (error) {
        rec.lastError = { at: new Date().toISOString(), phase: 'create', message: error.message, code: error.code ?? null };
        saveRegistry(registry);
        throw error;
      }
    }

    if (!rec.sharedAt) {
      if (!rec.shareJobId) {
        log(`[${entry.name}] enqueueing persistent SWM share job`);
        try {
          const queued = await api('POST', `/api/knowledge-assets/${encodeURIComponent(kaName)}/swm/share-async`, { contextGraphId });
          rec.shareJobId = queued.jobId;
          rec.status = 'sharing';
          saveRegistry(registry);
        } catch (error) {
          if (error.status === 409 && error.body?.existingJobId) {
            rec.shareJobId = error.body.existingJobId;
            saveRegistry(registry);
          } else throw error;
        }
      }
      try {
        await pollShareJob(entry.name, rec.shareJobId);
        rec.sharedAt = new Date().toISOString();
        rec.status = 'shared';
        saveRegistry(registry);
      } catch (error) {
        rec.lastError = { at: new Date().toISOString(), phase: 'share', message: error.message, code: error.code ?? null };
        rec.status = 'error';
        saveRegistry(registry);
        throw error;
      }
    }

    if (targetMemory === 'SWM') {
      rec.status = 'swm';
      rec.swmRetainedAt = new Date().toISOString();
      rec.durationSeconds = Math.round((Date.now() - batchStartedAt) / 1000);
      saveRegistry(registry);
      completed += 1;
      processedThisRun += 1;
      const elapsed = Date.now() - startedAt;
      const averageMs = elapsed / processedThisRun;
      const remaining = Math.max(0, validated.manifest.batchCount - completed);
      updateProgress({
        phase: 'batch-complete', currentBatch: entry.name, completedBatches: completed,
        percent: Number(((completed / validated.manifest.batchCount) * 100).toFixed(2)),
        estimatedRemainingSeconds: Math.round((averageMs * remaining) / 1000),
        lastMemoryLayer: 'SWM',
      });
      log(`[${entry.name}] retained in SWM; ${completed}/${validated.manifest.batchCount} complete`);
      await waitForMidRunResume(completed, entry.name);
      continue;
    }

    try {
      if (vmPublishMode === 'sync') {
        await publishSynchronous(entry, rec, kaName, registry);
        saveRegistry(registry);
      } else {
        if (!rec.publishJobId) {
          if (vmPublishMode === 'async-all') await waitForAsyncPublisherCapacity(entry.name);
          log(`[${entry.name}] enqueueing PAID async VM publish for ${epochs} epochs`);
          try {
            const queued = await api('POST', `/api/knowledge-assets/${encodeURIComponent(kaName)}/vm/publish-async`, {
              contextGraphId, options: { publishEpochs: epochs, publisherNodeIdentityId },
            });
            rec.publishMode = 'async';
            rec.publishJobId = queued.jobId;
            rec.status = 'publishing';
            rec.publishEnqueuedAt = new Date().toISOString();
            saveRegistry(registry);
          } catch (error) {
            if (error.status === 409 && error.body?.existingJobId) {
              rec.publishJobId = error.body.existingJobId;
              saveRegistry(registry);
            } else throw error;
          }
        }
        if (vmPublishMode === 'async-all') {
          rec.durationSeconds = Math.round((Date.now() - batchStartedAt) / 1000);
          saveRegistry(registry);
          const enqueued = Object.values(registry.batches)
            .filter((record) => record.targetMemory === 'VM' && record.publishJobId).length;
          updateProgress({
            phase: 'vm-enqueued', currentBatch: entry.name, completedBatches: completed,
            enqueuedVmBatches: enqueued,
          });
          log(`[${entry.name}] VM publish enqueued (${enqueued}/${validated.manifest.batchCount - swmOnlyBatches}); continuing without serial confirmation wait`);
          continue;
        }
        const job = await pollPublishJob(entry.name, rec.publishJobId);
        recordFinalized(rec, job);
      }
      rec.durationSeconds = Math.round((Date.now() - batchStartedAt) / 1000);
      saveRegistry(registry);
      completed += 1;
      processedThisRun += 1;
      const elapsed = Date.now() - startedAt;
      const averageMs = elapsed / processedThisRun;
      const remaining = Math.max(0, validated.manifest.batchCount - completed);
      updateProgress({
        phase: 'batch-complete', currentBatch: entry.name, completedBatches: completed,
        percent: Number(((completed / validated.manifest.batchCount) * 100).toFixed(2)),
        estimatedRemainingSeconds: Math.round((averageMs * remaining) / 1000),
        lastTxHash: rec.txHash, lastUal: rec.ual,
      });
      log(`[${entry.name}] finalized in VM tx=${rec.txHash ?? rec.dkgFinalizationMode} block=${rec.blockNumber ?? 'n/a'}; ${completed}/${validated.manifest.batchCount} complete`);
      await waitForMidRunResume(completed, entry.name);
    } catch (error) {
      rec.lastError = { at: new Date().toISOString(), phase: 'publish', message: error.message, code: error.code ?? null };
      rec.status = 'error';
      saveRegistry(registry);
      throw error;
    }
  }

  if (vmPublishMode === 'async-all') {
    const vmEntries = entries.filter((entry) => (
      validated.manifest.batches.findIndex((candidate) => candidate.name === entry.name) >= swmOnlyBatches
    ));
    updateProgress({
      phase: 'awaiting-vm-batch', completedBatches: completed,
      enqueuedVmBatches: vmEntries.length,
    });
    log(`all ${vmEntries.length} VM publications are enqueued; waiting for terminal results in parallel`);
    const outcomes = new Array(vmEntries.length);
    let nextVmEntry = 0;
    const finalizeEntry = async (entry) => {
      const rec = registry.batches[entry.name];
      if (rec?.status === 'finalized' && (rec.txHash || rec.dkgFinalizationMode === 'noop')) return;
      if (!rec?.publishJobId) throw new Error(`[${entry.name}] has no async VM publish job id`);
      try {
        const job = await pollPublishJob(entry.name, rec.publishJobId);
        recordFinalized(rec, job);
        const enqueuedAt = Date.parse(rec.publishEnqueuedAt ?? rec.publishStartedAt ?? '');
        rec.durationSeconds = Number.isFinite(enqueuedAt)
          ? Math.round((Date.now() - enqueuedAt) / 1000)
          : rec.durationSeconds;
        saveRegistry(registry);
        completed += 1;
        updateProgress({
          phase: 'vm-finalized', currentBatch: entry.name, completedBatches: completed,
          percent: Number(((completed / validated.manifest.batchCount) * 100).toFixed(2)),
          lastTxHash: rec.txHash, lastUal: rec.ual,
        });
        log(`[${entry.name}] async VM finalized tx=${rec.txHash ?? rec.dkgFinalizationMode} block=${rec.blockNumber ?? 'n/a'}; ${completed}/${validated.manifest.batchCount} complete`);
      } catch (error) {
        rec.lastError = { at: new Date().toISOString(), phase: 'publish', message: error.message, code: error.code ?? null };
        rec.status = 'error';
        saveRegistry(registry);
        throw error;
      }
    };
    const workers = Array.from(
      { length: Math.min(vmMaxInflight, vmEntries.length) },
      async () => {
        while (true) {
          const index = nextVmEntry;
          nextVmEntry += 1;
          if (index >= vmEntries.length) return;
          try {
            await finalizeEntry(vmEntries[index]);
            outcomes[index] = { status: 'fulfilled' };
          } catch (reason) {
            outcomes[index] = { status: 'rejected', reason };
          }
        }
      },
    );
    await Promise.all(workers);
    const failures = outcomes.filter((outcome) => outcome.status === 'rejected');
    if (failures.length > 0) {
      const messages = failures.map((outcome) => outcome.reason?.message ?? String(outcome.reason));
      throw new Error(`${failures.length}/${vmEntries.length} async VM publications failed: ${messages.join(' | ')}`);
    }
  }

  updateProgress({ status: 'complete', phase: 'complete', completedAt: new Date().toISOString(), completedBatches: completed });
  log(`complete: registry=${registryPath}`);
}

function releaseLock() {
  if (lockFd !== undefined) {
    try { closeSync(lockFd); } catch {}
    lockFd = undefined;
    try { unlinkSync(lockPath); } catch {}
  }
}

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    try { updateProgress({ status: 'stopped', phase: 'signal', signal }); } catch {}
    releaseLock();
    process.exit(128 + (signal === 'SIGINT' ? 2 : 15));
  });
}

async function main() {
  assertConfig();
  updateProgress({ status: 'validating', phase: 'local-validation', mode });
  const validated = loadAndValidateBatches();
  const totalQuads = validated.stats.reduce((sum, batch) => sum + batch.quads, 0);
  const totalPayloadBytes = validated.stats.reduce((sum, batch) => sum + batch.payloadBytes, 0);
  if (!validated.manifest.complete) log(`HARNESS MODE: accepting an explicit ${validated.manifest.batchCount}-batch prefix of the checksummed production corpus`);
  log(`local validation OK: ${validated.manifest.includedRecords.toLocaleString()} records, ${validated.manifest.batchCount} batches, ${totalQuads.toLocaleString()} quads, ${(totalPayloadBytes / 1e9).toFixed(2)} GB JSON payload`);
  if (expectedManifestPath) {
    atomicJson(expectedManifestPath, {
      version: 1,
      // Bind the canonical verification manifest to the immutable batch build
      // instead of changing its checksum on every dry-run/preflight.
      generatedAt: validated.manifest.createdAt,
      source: validated.manifest.source,
      mapping: validated.manifest.mapping,
      batchManifestSha256: validated.manifestSha256,
      contextGraphId: contextGraphId ?? null,
      kaPrefix: kaPrefix ?? null,
      swmOnlyBatches,
      vmBatches: validated.manifest.batchCount - swmOnlyBatches,
      totalRecords: validated.manifest.includedRecords,
      totalQuads,
      totalPayloadBytes,
      batches: validated.stats.map((batch, index) => ({
        ordinal: index + 1,
        batch: batch.name,
        kaName: kaPrefix ? `${kaPrefix}-${batch.name}` : null,
        targetMemory: index < swmOnlyBatches ? 'SWM' : 'VM',
        records: batch.records,
        quads: batch.quads,
        sourceQuads: batch.sourceQuads,
        duplicateQuadsRemoved: batch.duplicateQuadsRemoved,
        payloadBytes: batch.payloadBytes,
        quadSetSha256: batch.quadSetSha256,
        publicQuadsDigest: batch.publicQuadsDigest,
      })),
    });
    log(`expected per-KA manifest: ${expectedManifestPath}`);
  }
  if (mode === 'dry-run') {
    updateProgress({ status: 'validated', phase: 'dry-run-complete', validatedBatches: validated.stats.length });
    log('dry-run complete: no node calls and no writes');
    return;
  }
  updateProgress({ status: 'preflighting', phase: 'node-preflight' });
  const preflight = await nodePreflight(validated.manifestSha256);
  if (mode === 'preflight') {
    updateProgress({ status: 'ready', phase: 'preflight-complete', confirmationToken: preflight.confirmation });
    log('preflight complete: no node writes and no paid transactions');
    return;
  }
  await publishAll(validated, preflight);
}

main().catch((error) => {
  try { updateProgress({ status: 'error', phase: progress.phase ?? 'unknown', error: error?.message ?? String(error), failedAt: new Date().toISOString() }); } catch {}
  releaseLock();
  console.error(`[${new Date().toISOString()}] FATAL: ${error?.stack ?? error}`);
  usage();
  process.exit(1);
}).finally(releaseLock);
