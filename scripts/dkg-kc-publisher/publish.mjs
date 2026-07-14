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
const fromBatch = option('from-batch', null);
const toBatch = option('to-batch', null);
const batchDir = resolve(process.env.KC_BATCH_DIR ?? join(here, 'batches'));
const registryPath = resolve(process.env.KC_REGISTRY_PATH ?? join(here, 'registry.json'));
const progressPath = resolve(process.env.KC_PROGRESS_PATH ?? join(here, 'progress.json'));
const lockPath = `${registryPath}.lock`;
const endpoint = process.env.DKG_ENDPOINT ?? 'http://127.0.0.1';
const port = process.env.DKG_PORT ?? '8900';
const endpointUrl = new URL(endpoint);
if (!endpointUrl.port) endpointUrl.port = port;
endpointUrl.pathname = '/';
endpointUrl.search = '';
endpointUrl.hash = '';
const base = endpointUrl.toString().replace(/\/$/, '');
const network = process.env.KC_NETWORK ?? 'mainnet-base';
const expectedVersion = process.env.KC_DKG_VERSION ?? '10.0.6';
const contextGraphId = process.env.KC_CG_ID;
const epochs = Number(process.env.KC_EPOCHS ?? '12');
const kaPrefix = process.env.KC_KA_PREFIX ?? contextGraphId?.split('/').filter(Boolean).at(-1);
const tokenPath = resolve((process.env.DKG_AUTH_TOKEN_PATH ?? join(homedir(), '.dkg', 'auth.token')).replace(/^~(?=\/)/, homedir()));
const pollMs = Number(process.env.KC_POLL_MS ?? '30000');
const requestTimeoutMs = Number(process.env.KC_REQUEST_TIMEOUT_MS ?? '2700000');
const expectedRecords = Number(process.env.KC_EXPECT_RECORDS ?? '460000');
const vmPublishMode = process.env.KC_VM_PUBLISH_MODE ?? 'sync';
const swmRestoreMode = process.env.KC_SWM_RESTORE_MODE ?? 'restore';
const pipelineWidth = Number(process.env.KC_PIPELINE_WIDTH ?? '1');
const publisherNodeIdentityId = Number(process.env.KC_PUBLISHER_NODE_IDENTITY_ID ?? '0');
const expectedOnChainCgId = process.env.KC_CG_ONCHAIN_ID ?? '';
const confirmedVmRecoveries = new Map(Object.entries(JSON.parse(process.env.KC_CONFIRMED_VM_RECOVERIES ?? '{}')));
const startedAt = Date.now();
let lockFd;
let authToken;
let progress = {};

function usage() {
  console.error(`usage:
  node publish.mjs --dry-run [--batch batch-001 | --from-batch batch-001 --to-batch batch-460]
  KC_CG_ID=<id> node publish.mjs --preflight
  KC_CG_ID=<id> node publish.mjs --publish --confirm <token> [--batch batch-001 | --from-batch batch-001 --to-batch batch-460]

The exact paid confirmation token is printed by --preflight.`);
}

function assertConfig() {
  if (!mode) throw new Error('choose exactly one of --dry-run, --preflight, or --publish');
  if (!Number.isSafeInteger(epochs) || epochs !== 12) throw new Error(`KC_EPOCHS must be exactly 12 for this production corpus; got ${epochs}`);
  if (!Number.isSafeInteger(pollMs) || pollMs < 1_000) throw new Error(`KC_POLL_MS must be an integer >= 1000; got ${pollMs}`);
  if (!Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs < 60_000) throw new Error(`KC_REQUEST_TIMEOUT_MS must be >= 60000; got ${requestTimeoutMs}`);
  if (!['sync', 'async'].includes(vmPublishMode)) throw new Error(`KC_VM_PUBLISH_MODE must be sync or async; got ${vmPublishMode}`);
  if (!['restore', 'skip'].includes(swmRestoreMode)) throw new Error(`KC_SWM_RESTORE_MODE must be restore or skip; got ${swmRestoreMode}`);
  if (!Number.isSafeInteger(pipelineWidth) || ![1, 2].includes(pipelineWidth)) throw new Error(`KC_PIPELINE_WIDTH must be 1 or 2; got ${pipelineWidth}`);
  if (!Number.isSafeInteger(publisherNodeIdentityId) || publisherNodeIdentityId < 0) throw new Error(`KC_PUBLISHER_NODE_IDENTITY_ID must be a non-negative integer; got ${publisherNodeIdentityId}`);
  for (const [batchName, recovery] of confirmedVmRecoveries) {
    if (!/^batch-\d{3}$/.test(batchName) || !recovery || typeof recovery !== 'object') throw new Error(`invalid KC_CONFIRMED_VM_RECOVERIES entry: ${batchName}`);
    if (!/^did:dkg:[^/]+\/0x[0-9a-fA-F]{40}\/\d+$/.test(String(recovery.ual ?? ''))) throw new Error(`invalid confirmed VM UAL for ${batchName}`);
    if (!/^0x[0-9a-fA-F]{64}$/.test(String(recovery.txHash ?? ''))) throw new Error(`invalid confirmed VM transaction hash for ${batchName}`);
  }
  if ((mode === 'preflight' || mode === 'publish') && !contextGraphId) throw new Error('KC_CG_ID is required for node preflight/publish');
  if (mode === 'publish' && !kaPrefix) throw new Error('KC_KA_PREFIX or KC_CG_ID is required');
  if (onlyBatch && (fromBatch || toBatch)) throw new Error('--batch cannot be combined with --from-batch or --to-batch');
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

function readToken() {
  if (!existsSync(tokenPath)) throw new Error(`auth token not found: ${tokenPath}`);
  const token = readFileSync(tokenPath, 'utf8').split('\n').map((line) => line.trim()).find((line) => line && !line.startsWith('#'));
  if (!token) throw new Error(`auth token file is empty: ${tokenPath}`);
  return token;
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
    const response = await fetch(`${base}${path}`, {
      method,
      headers: { 'content-type': 'application/json', authorization: `Bearer ${authToken}` },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    const text = await response.text();
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
  if (!manifest.complete) throw new Error('manifest is a partial/max-batches build; production publish requires the complete corpus');
  if (manifest.includedRecords !== expectedRecords) throw new Error(`expected ${expectedRecords.toLocaleString()} records, manifest has ${Number(manifest.includedRecords).toLocaleString()}`);
  if (manifest.batchCount !== manifest.batches?.length) throw new Error('manifest batchCount does not match batches list');
  if (manifest.batchCount !== Math.ceil(expectedRecords / manifest.batchSize)) throw new Error('manifest batch count/size does not cover the expected corpus exactly');
  const mappingHash = sha256(readFileSync(join(here, 'mapping.mjs')));
  if (mappingHash !== manifest.mapping?.sha256) throw new Error('mapping.mjs changed since the batches were prepared; rebuild them before publishing');

  const namesOnDisk = readdirSync(batchDir).filter((name) => name.endsWith('.json') && name !== 'manifest.json').sort();
  const expectedFiles = manifest.batches.map((batch) => batch.file).sort();
  if (JSON.stringify(namesOnDisk) !== JSON.stringify(expectedFiles)) throw new Error('batch directory contents do not exactly match manifest (stale/missing JSON files)');

  const seenKeys = new Set();
  const stats = [];
  let selected = manifest.batches;
  if (onlyBatch) {
    selected = manifest.batches.filter((batch) => batch.name === onlyBatch);
    if (selected.length !== 1) throw new Error(`batch not found in manifest: ${onlyBatch}`);
  } else if (fromBatch || toBatch) {
    const startName = fromBatch ?? manifest.batches[0]?.name;
    const endName = toBatch ?? manifest.batches.at(-1)?.name;
    const startIndex = manifest.batches.findIndex((batch) => batch.name === startName);
    const endIndex = manifest.batches.findIndex((batch) => batch.name === endName);
    if (startIndex === -1) throw new Error(`batch not found in manifest: ${startName}`);
    if (endIndex === -1) throw new Error(`batch not found in manifest: ${endName}`);
    if (startIndex > endIndex) throw new Error(`invalid batch range: ${startName} is after ${endName}`);
    selected = manifest.batches.slice(startIndex, endIndex + 1);
  }

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
    const quads = parsed.records.flatMap(recordQuads);
    for (const quad of quads) validateQuad(entry.name, quad);
    const payloadBytes = Buffer.byteLength(JSON.stringify(quads));
    if (payloadBytes > 9_000_000) throw new Error(`${entry.name}: ${payloadBytes} byte payload exceeds the 9MB safety cap`);
    stats.push({ name: entry.name, records: parsed.records.length, quads: quads.length, payloadBytes });
    if ((index + 1) % 25 === 0 || index + 1 === manifest.batches.length) {
      log(`validated ${index + 1}/${manifest.batches.length} batch files`);
    }
  }
  if (seenKeys.size !== manifest.includedRecords) throw new Error('validated record-key count differs from manifest');
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
    || (error?.status === 400 && /Assertion name cannot contain "\/"/.test(error.message ?? ''))
    || definitiveContextGraphValidationRejection(error);
}

function definitiveContextGraphValidationRejection(error) {
  const status = error?.status ?? (/^503\s/.test(error?.message ?? '') ? 503 : null);
  return status === 503
    && /Failed to validate contextGraphId against known context graphs:/.test(error.message ?? '');
}

async function readGraphMembership() {
  const participants = await api('GET', `/api/context-graph/${encodeURIComponent(contextGraphId)}/participants`);
  const allowedAgents = [...new Set((participants.allowedAgents ?? []).map((address) => String(address).toLowerCase()))].sort();
  if (allowedAgents.length === 0) throw new Error(`context graph ${contextGraphId} has no readable allowed-agent membership`);
  return { allowedAgents, fingerprint: sha256(JSON.stringify(allowedAgents)) };
}

async function assertGraphMembershipUnchanged(expected) {
  const current = await readGraphMembership();
  if (current.fingerprint !== expected.fingerprint) {
    throw new Error(`private context graph membership changed during the publishing run (expected ${expected.allowedAgents.length} agents, found ${current.allowedAgents.length}); refusing to share or publish until membership and encryption keys are reviewed`);
  }
}

async function nodePreflight(manifestSha256) {
  authToken = readToken();
  const status = await api('GET', '/api/status');
  if (status.networkConfig !== network) throw new Error(`node network is ${status.networkConfig}, expected ${network}`);
  if (status.version !== expectedVersion) throw new Error(`node DKG version is ${status.version ?? 'unknown'}, expected official npm ${expectedVersion}`);
  const exists = await api('GET', `/api/context-graph/exists?id=${encodeURIComponent(contextGraphId)}`);
  if (!exists.exists) throw new Error(`context graph does not exist: ${contextGraphId}; create and review it before publishing`);
  let graph;
  for (let attempt = 1; attempt <= 3 && !graph; attempt += 1) {
    const list = await api('GET', '/api/context-graph/list', undefined, requestTimeoutMs);
    graph = (list.contextGraphs ?? []).find((candidate) => [candidate.id, candidate.contextGraphId, candidate.uri, candidate.did].includes(contextGraphId));
    if (!graph && attempt < 3) await new Promise((resolvePromise) => setTimeout(resolvePromise, 2_000));
  }
  if (!graph) throw new Error(`context graph ${contextGraphId} exists but is not visible to this token in /api/context-graph/list`);
  const membership = await readGraphMembership();
  let privacyEvidence = `accessPolicy=${String(graph.accessPolicy ?? 'private flag')}`;
  if (!privatePolicy(graph.accessPolicy) && !graph.private && !graph.isPrivate) {
    const onChainId = String(graph.onChainId ?? '');
    if (!expectedOnChainCgId || onChainId !== expectedOnChainCgId) {
      throw new Error(`context graph ${contextGraphId} is not verifiably private/curated (accessPolicy=${String(graph.accessPolicy)}, onChainId=${onChainId || 'missing'}); refusing to write corpus data`);
    }
    const ownerAddress = contextGraphId.split('/')[0]?.toLowerCase();
    if (!ownerAddress || !membership.allowedAgents.includes(ownerAddress)) {
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
  log(`private context graph membership pinned: ${membership.allowedAgents.length} agents, sha256:${membership.fingerprint}`);
  log(`wallet preflight: ${JSON.stringify(walletBalanceSummary(wallets))}`);
  log(`async publisher queue: ${JSON.stringify(publisherStats).slice(0, 1000)}`);
  log(`VM publish mode: ${vmPublishMode}; publisher node identity id: ${publisherNodeIdentityId}`);
  log(`SWM pipeline width: ${pipelineWidth}; post-publish SWM restore: ${swmRestoreMode}; paid VM concurrency: 1`);
  const confirmation = `${contextGraphId}:12:${manifestSha256.slice(0, 12)}`;
  log(`paid confirmation token: ${confirmation}`);
  return { status, graph, membership, wallets, publisherStats, confirmation };
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
  return { records: parsed.records, quads: parsed.records.flatMap(recordQuads) };
}

function quadSetHash(quads) {
  return sha256([...quads].map((quad) => JSON.stringify(quad)).sort().join('\n'));
}

function legacyBlazegraphText(value) {
  return [...value].map((character) => (
    character.codePointAt(0) > 127 ? '\ufffd'.repeat(Buffer.byteLength(character)) : character
  )).join('');
}

function legacyBlazegraphQuads(quads) {
  return quads.map((quad) => ({
    ...quad,
    subject: legacyBlazegraphText(quad.subject),
    predicate: legacyBlazegraphText(quad.predicate),
    object: legacyBlazegraphText(quad.object),
  }));
}

function sparqlIri(value) {
  if (!/^[^<>"{}|^`\\\u0000-\u0020]+$/.test(value)) throw new Error(`unsafe RDF subject IRI: ${value}`);
  return `<${value}>`;
}

async function queryMemoryQuads(view, expectedQuads) {
  const subjects = [...new Set(expectedQuads.map((quad) => quad.subject))];
  const quads = [];
  for (let offset = 0; offset < subjects.length; offset += 100) {
    const values = subjects.slice(offset, offset + 100).map(sparqlIri).join(' ');
    const response = await api('POST', '/api/query', {
      contextGraphId,
      view,
      sparql: `SELECT DISTINCT ?s ?p ?o WHERE { VALUES ?s { ${values} } ?s ?p ?o }`,
    }, requestTimeoutMs);
    const bindings = response?.result?.bindings ?? response?.bindings;
    if (!Array.isArray(bindings)) throw new Error(`unexpected ${view} query response at subject offset ${offset}`);
    for (const binding of bindings) {
      const subject = typeof binding.s === 'string' ? binding.s : binding.s?.value;
      const predicate = typeof binding.p === 'string' ? binding.p : binding.p?.value;
      const object = typeof binding.o === 'string' ? binding.o : binding.o?.value;
      if (![subject, predicate, object].every((value) => typeof value === 'string')) {
        throw new Error(`malformed ${view} binding at subject offset ${offset}`);
      }
      quads.push({ subject, predicate, object, graph: '' });
    }
  }
  return { quads, subjectCount: new Set(quads.map((quad) => quad.subject)).size };
}

const querySwmQuads = (expectedQuads) => queryMemoryQuads('shared-working-memory', expectedQuads);

function memoryVerificationMode(stored, expectedQuads) {
  const expectedSubjectCount = new Set(expectedQuads.map((quad) => quad.subject)).size;
  if (stored.subjectCount !== expectedSubjectCount) return null;
  const storedSet = new Set(stored.quads.map((quad) => JSON.stringify(quad)));
  if (expectedQuads.every((quad) => storedSet.has(JSON.stringify(quad)))) return 'exact';
  if (legacyBlazegraphQuads(expectedQuads).every((quad) => storedSet.has(JSON.stringify(quad)))) {
    return 'legacy-blazegraph-unicode';
  }
  return null;
}

function exactMemoryVerificationMode(stored, expectedQuads) {
  const baseMode = memoryVerificationMode(stored, expectedQuads);
  if (!baseMode) return null;
  if (stored.quads.length === expectedQuads.length) return baseMode;

  const expectedSet = new Set(expectedQuads.map((quad) => JSON.stringify(quad)));
  const expectedSubjects = new Set(expectedQuads.map((quad) => quad.subject));
  const extras = stored.quads.filter((quad) => !expectedSet.has(JSON.stringify(quad)));
  const trustLevelPredicate = 'http://dkg.io/ontology/trustLevel';
  const trustLevelZero = '"0"^^<http://www.w3.org/2001/XMLSchema#integer>';
  if (extras.length !== expectedSubjects.size) return null;
  if (new Set(extras.map((quad) => quad.subject)).size !== expectedSubjects.size) return null;
  if (!extras.every((quad) => (
    expectedSubjects.has(quad.subject)
    && quad.predicate === trustLevelPredicate
    && quad.object === trustLevelZero
    && quad.graph === ''
  ))) return null;
  return `${baseMode}-with-dkg-trust-level`;
}

function reservedKaIdentity(reservedUal) {
  const match = String(reservedUal ?? '').match(/^did:dkg:[^/]+\/(0x[0-9a-fA-F]{40})\/(\d+)$/);
  if (!match) return null;
  const ordinal = BigInt(match[2]);
  if (ordinal >= (1n << 96n)) throw new Error(`reserved KA ordinal exceeds 96 bits: ${match[2]}`);
  return {
    agentAddress: match[1],
    ordinal: match[2],
    kaId: ((BigInt(match[1]) << 96n) | ordinal).toString(),
  };
}

function publishedKaIdentity(ual) {
  const match = String(ual ?? '').match(/^did:dkg:[^/]+\/(0x[0-9a-fA-F]{40})\/(\d+)$/);
  return match ? { contract: match[1], kaId: match[2] } : null;
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

async function pollShareJob(batchName, jobId, pipelined = false) {
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
    if (pipelined) {
      updateProgress({ pipelinePhase: 'sharing', pipelineBatch: batchName, pipelineJobId: jobId, pipelineJobState: state });
    } else {
      updateProgress({ phase: 'sharing', currentBatch: batchName, dkgJobId: jobId, dkgJobState: state });
    }
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
      if (readFailures > 20 || (error.status && error.status < 500)) throw error;
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

function recordFinalized(rec, job) {
  const finalization = job.finalization ?? {};
  const inclusion = job.inclusion ?? {};
  const broadcast = job.broadcast ?? {};
  const txHash = finalization.txHash ?? inclusion.txHash ?? broadcast.txHash;
  if (!txHash && finalization.mode !== 'local' && finalization.mode !== 'noop') throw new Error('finalized DKG job has no transaction hash');
  Object.assign(rec, {
    status: 'vm-finalized',
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
    status: 'vm-finalized',
    publishMode: 'sync',
    publishJobState: result.status ?? 'confirmed',
    txHash: result.txHash,
    ual: result.ual,
    blockNumber: result.blockNumber ?? null,
    finalizedAt: new Date().toISOString(),
    dkgFinalizationMode: 'published',
  });
}

function vmStatusIsFinalized(status) {
  const assertion = status?.currentAssertion;
  return status?.state === 'published'
    && status?.status === 'vm-confirmed'
    && typeof status?.publishedUal === 'string'
    && status.publishedUal.startsWith('did:dkg:')
    && typeof assertion === 'string'
    && assertion.length > 0
    && status.wmCurrentAssertion === assertion
    && status.swmCurrentAssertion === assertion
    && status.vmCurrentAssertion === assertion;
}

async function reconcileChainConfirmedVm(entry, rec, status, expectedQuads, registry) {
  const reserved = reservedKaIdentity(status?.reservedUal);
  const assertion = status?.swmCurrentAssertion;
  if (!reserved || typeof assertion !== 'string' || !assertion) return false;
  if (status.wmCurrentAssertion !== assertion) return false;

  let chain;
  try {
    chain = await api('GET', `/api/kc/${reserved.kaId}`);
  } catch (error) {
    if (error.status === 404) return false;
    throw error;
  }

  const chainRoot = String(chain.merkleRoot ?? '').toLowerCase();
  const emptyRoot = `0x${'0'.repeat(64)}`;
  if (chainRoot === emptyRoot && (chain.author === null || chain.author === undefined)) return false;
  const expectedRoot = `0x${assertion.replace(/^0x/, '')}`.toLowerCase();
  if (chainRoot !== expectedRoot) {
    throw new Error(`[${entry.name}] reserved KA ${reserved.kaId} is already published with a different assertion (chain=${chainRoot || 'missing'}, prepared=${expectedRoot}); refusing to publish or reconcile`);
  }
  if (String(chain.author ?? '').toLowerCase() !== reserved.agentAddress.toLowerCase()) {
    throw new Error(`[${entry.name}] reserved KA ${reserved.kaId} has unexpected chain author ${String(chain.author ?? 'missing')}; refusing to reconcile`);
  }

  const vm = await queryMemoryQuads('verifiable-memory', expectedQuads);
  const vmVerificationMode = memoryVerificationMode(vm, expectedQuads);
  if (!vmVerificationMode) {
    log(`[${entry.name}] chain assertion is confirmed but expected VM quads are not fully queryable yet`);
    return false;
  }

  const finalizedAt = new Date().toISOString();
  Object.assign(rec, {
    status: 'vm-finalized',
    publishMode: 'sync-chain-reconciled',
    publishJobState: 'chain-confirmed',
    finalizedAt,
    dkgFinalizationMode: 'published-chain-reconciled',
    chainKaId: reserved.kaId,
    chainKaOrdinal: reserved.ordinal,
    chainMerkleRoot: chainRoot,
    chainAuthor: chain.author,
    vmAssertion: assertion,
    vmVerifiedAt: finalizedAt,
    vmVerificationMode,
    vmVerifiedQuadCount: vm.quads.length,
    vmVerifiedSubjectCount: vm.subjectCount,
  });

  const swm = await querySwmQuads(expectedQuads);
  const swmVerificationMode = memoryVerificationMode(swm, expectedQuads);
  if (swmVerificationMode) {
    rec.swmRestoreQuadCount = swm.quads.length;
    rec.swmRestoreSubjectCount = swm.subjectCount;
    rec.swmVerificationMode = swmVerificationMode;
    rec.swmReplicatedAt = finalizedAt;
    rec.status = 'finalized';
  }
  delete rec.lastError;
  saveRegistry(registry);
  log(`[${entry.name}] reconciled chain-confirmed KA ${reserved.kaId} from matching Merkle root and ${vm.subjectCount.toLocaleString()} VM subjects`);
  return true;
}

async function reconcileExplicitConfirmedVm(entry, rec, status, expectedQuads, registry) {
  const recovery = confirmedVmRecoveries.get(entry.name);
  if (!recovery || !rec.publishStartedAt) return false;
  const published = publishedKaIdentity(recovery.ual);
  const reserved = reservedKaIdentity(status?.reservedUal);
  const assertion = status?.wmCurrentAssertion;
  if (!published || !reserved || typeof assertion !== 'string' || !assertion) return false;

  const chain = await api('GET', `/api/kc/${published.kaId}`);
  const chainRoot = String(chain.merkleRoot ?? '').toLowerCase();
  const expectedRoot = `0x${assertion.replace(/^0x/, '')}`.toLowerCase();
  if (chainRoot !== expectedRoot) throw new Error(`[${entry.name}] confirmed recovery UAL has Merkle root ${chainRoot || 'missing'}, expected ${expectedRoot}`);
  if (String(chain.author ?? '').toLowerCase() !== reserved.agentAddress.toLowerCase()) {
    throw new Error(`[${entry.name}] confirmed recovery UAL has author ${String(chain.author ?? 'missing')}, expected ${reserved.agentAddress}`);
  }

  const vm = await queryMemoryQuads('verifiable-memory', expectedQuads);
  const vmVerificationMode = exactMemoryVerificationMode(vm, expectedQuads);
  if (!vmVerificationMode) throw new Error(`[${entry.name}] confirmed recovery UAL does not contain the exact expected VM quad set`);

  const finalizedAt = new Date().toISOString();
  Object.assign(rec, {
    status: 'vm-finalized',
    publishMode: 'sync-explicit-chain-reconciled',
    publishJobState: 'chain-confirmed',
    txHash: recovery.txHash,
    ual: recovery.ual,
    blockNumber: recovery.blockNumber ?? null,
    finalizedAt,
    dkgFinalizationMode: 'published-chain-reconciled',
    chainKaId: published.kaId,
    chainKaOrdinal: reserved.ordinal,
    chainMerkleRoot: chainRoot,
    chainAuthor: chain.author,
    vmAssertion: assertion,
    vmVerifiedAt: finalizedAt,
    vmVerificationMode,
    vmVerifiedQuadCount: vm.quads.length,
    vmVerifiedSubjectCount: vm.subjectCount,
  });
  delete rec.lastError;
  saveRegistry(registry);
  log(`[${entry.name}] reconciled explicitly confirmed UAL from matching chain state and exact VM data (${vm.subjectCount.toLocaleString()} subjects, ${vm.quads.length.toLocaleString()} quads)`);
  return true;
}

async function reconcileSynchronousPublish(entry, rec, kaName, expectedQuads, registry, waitForCompletion) {
  const deadline = Date.now() + requestTimeoutMs;
  const query = `contextGraphId=${encodeURIComponent(contextGraphId)}`;
  for (;;) {
    let status;
    try {
      status = await api('GET', `/api/knowledge-assets/${encodeURIComponent(kaName)}/vm?${query}`);
    } catch (error) {
      if (!waitForCompletion || (error.status && error.status < 500)) throw error;
      log(`[${entry.name}] VM reconciliation read failed; retrying without republishing: ${error.message}`);
    }
    if (vmStatusIsFinalized(status)) {
      Object.assign(rec, {
        status: 'vm-finalized',
        publishMode: 'sync-reconciled',
        publishJobState: 'vm-confirmed',
        txHash: rec.txHash ?? null,
        ual: status.publishedUal,
        blockNumber: rec.blockNumber ?? null,
        finalizedAt: new Date().toISOString(),
        dkgFinalizationMode: 'published-vm-reconciled',
        vmAssertion: status.currentAssertion,
      });
      delete rec.lastError;
      saveRegistry(registry);
      log(`[${entry.name}] reconciled paid publish from matching WM/SWM/VM state: ${status.publishedUal}`);
      return true;
    }
    if (status && await reconcileExplicitConfirmedVm(entry, rec, status, expectedQuads, registry)) return true;
    if (status && await reconcileChainConfirmedVm(entry, rec, status, expectedQuads, registry)) return true;
    if (!waitForCompletion) return false;
    if (Date.now() >= deadline) {
      throw new Error(`[${entry.name}] paid publish response was lost and VM did not become confirmed within ${duration(requestTimeoutMs)}; inspect chain and node state before retrying`);
    }
    updateProgress({ phase: 'publish-reconcile', currentBatch: entry.name, heartbeat: `GET ${kaName}/vm` });
    log(`[${entry.name}] paid response unavailable; waiting for VM confirmation without republishing`);
    await new Promise((resolvePromise) => setTimeout(resolvePromise, Math.min(pollMs, 30_000)));
  }
}

async function publishSynchronous(entry, rec, kaName, expectedQuads, registry, membership) {
  if (await reconcileSynchronousPublish(entry, rec, kaName, expectedQuads, registry, false)) return;
  if (rec.publishStartedAt
      && rec.lastError?.phase === 'publish'
      && definitiveContextGraphValidationRejection(rec.lastError)) {
    delete rec.publishStartedAt;
    rec.status = 'shared';
    saveRegistry(registry);
    log(`[${entry.name}] retrying after definitive pre-publish context graph validation rejection`);
  }
  if (rec.publishStartedAt) {
    throw new Error(`[${entry.name}] an earlier synchronous paid publish started at ${rec.publishStartedAt} without a recorded terminal result; verify chain and node state, then reconcile registry.json before retrying`);
  }
  await assertGraphMembershipUnchanged(membership);
  rec.publishMode = 'sync';
  rec.publishStartedAt = new Date().toISOString();
  rec.status = 'publishing';
  saveRegistry(registry);
  updateProgress({ phase: 'publishing', currentBatch: entry.name, currentKa: kaName });
  log(`[${entry.name}] starting PAID synchronous VM publish for ${epochs} epochs`);
  let result;
  try {
    result = await api('POST', `/api/knowledge-assets/${encodeURIComponent(kaName)}/vm/publish`, {
      contextGraphId,
      options: { publishEpochs: epochs, publisherNodeIdentityId },
    }, requestTimeoutMs);
  } catch (error) {
    if (definitiveContextGraphValidationRejection(error)) {
      delete rec.publishStartedAt;
      rec.status = 'shared';
      rec.lastError = { at: new Date().toISOString(), phase: 'publish', message: error.message, code: error.code ?? null, status: error.status };
      saveRegistry(registry);
      throw error;
    }
    if (error.code !== 'CLIENT_TIMEOUT' && !/fetch failed/i.test(error.message ?? '')) throw error;
    log(`[${entry.name}] paid publish response was lost; reconciling VM state without retrying the paid request`);
    await reconcileSynchronousPublish(entry, rec, kaName, expectedQuads, registry, true);
    return;
  }
  recordSynchronousFinalized(rec, result);
}

function hasFinalizedVm(rec) {
  return Boolean(rec.txHash || rec.ual || ['noop', 'published-chain-reconciled'].includes(rec.dkgFinalizationMode));
}

function batchComplete(rec) {
  return hasFinalizedVm(rec) && Boolean(rec.swmReplicatedAt || (swmRestoreMode === 'skip' && rec.swmRestoreSkippedAt));
}

function skipPublishedAssetSwmRestore(entry, rec, registry) {
  rec.swmRestoreMode = 'skipped-vm-only';
  rec.swmRestoreSkippedAt = new Date().toISOString();
  rec.status = 'finalized';
  delete rec.lastError;
  saveRegistry(registry);
  log(`[${entry.name}] VM finalized; skipped post-publish SWM restoration by explicit configuration`);
}

async function restorePublishedAssetToSwm(entry, rec, kaName, expectedQuads, registry) {
  if (rec.swmReplicatedAt) return;

  updateProgress({ phase: 'swm-restore', currentBatch: entry.name, currentKa: kaName });
  const existing = await querySwmQuads(expectedQuads);
  const existingVerificationMode = memoryVerificationMode(existing, expectedQuads);
  if (existingVerificationMode) {
    rec.swmRestoreQuadCount = existing.quads.length;
    rec.swmRestoreSubjectCount = existing.subjectCount;
    rec.swmVerificationMode = existingVerificationMode;
    rec.swmReplicatedAt = new Date().toISOString();
    rec.status = 'finalized';
    delete rec.lastError;
    saveRegistry(registry);
    log(`[${entry.name}] existing encrypted SWM copy verified; restore not required`);
    return;
  }

  log(`[${entry.name}] restoring the finalized VM assertion to encrypted SWM`);
  try {
    if (!rec.swmRestoreJobId) {
      const pulled = await api('POST', `/api/knowledge-assets/${encodeURIComponent(kaName)}/wm/pull-from`, {
        contextGraphId,
        layer: 'vm',
        onConflict: 'replace',
      }, requestTimeoutMs);
      if (pulled?.wmDraft !== 'open' || pulled?.seededFrom?.layer !== 'vm') {
        throw new Error(`unexpected VM pull response: ${JSON.stringify(pulled).slice(0, 1500)}`);
      }
      rec.swmRestorePulledAt = new Date().toISOString();
      rec.status = 'swm-restoring';
      saveRegistry(registry);

      try {
        const queued = await api('POST', `/api/knowledge-assets/${encodeURIComponent(kaName)}/swm/share-async`, { contextGraphId });
        rec.swmRestoreJobId = queued.jobId;
      } catch (error) {
        if (error.status === 409 && error.body?.existingJobId) rec.swmRestoreJobId = error.body.existingJobId;
        else throw error;
      }
      saveRegistry(registry);
    }
    const job = await pollShareJob(entry.name, rec.swmRestoreJobId);
    const stored = await querySwmQuads(expectedQuads);
    const expectedSubjectCount = new Set(expectedQuads.map((quad) => quad.subject)).size;
    const exactMatch = stored.quads.length === expectedQuads.length
      && stored.subjectCount === expectedSubjectCount
      && quadSetHash(stored.quads) === quadSetHash(expectedQuads);
    const legacyMatch = stored.quads.length === expectedQuads.length
      && stored.subjectCount === expectedSubjectCount
      && quadSetHash(stored.quads) === quadSetHash(legacyBlazegraphQuads(expectedQuads));
    if (!exactMatch && !legacyMatch) {
      throw new Error(`restored SWM content differs from ${entry.name}; refusing to mark the batch complete`);
    }
    if (legacyMatch && !exactMatch) log(`[${entry.name}] SWM verification matched legacy Blazegraph Unicode normalization`);
    rec.swmRestorePromotedCount = job?.result?.promotedCount ?? job?.promotedCount ?? null;
    rec.swmRestoreQuadCount = stored.quads.length;
    rec.swmRestoreSubjectCount = stored.subjectCount;
    rec.swmVerificationMode = exactMatch ? 'exact' : 'legacy-blazegraph-unicode';
    rec.swmReplicatedAt = new Date().toISOString();
    rec.status = 'finalized';
    delete rec.lastError;
    saveRegistry(registry);
    log(`[${entry.name}] encrypted SWM copy restored after VM finalization`);
  } catch (error) {
    rec.lastError = { at: new Date().toISOString(), phase: 'swm-restore', message: error.message, code: error.code ?? null };
    rec.status = 'error';
    saveRegistry(registry);
    throw error;
  }
}

async function stageSharedEntry(entry, registry, membership, completed, pipelined = false) {
  const batchStartedAt = Date.now();
  const rec = (registry.batches[entry.name] ??= { checksum: entry.sha256, records: entry.records, epochs, status: 'pending' });
  if (rec.checksum !== entry.sha256) throw new Error(`${entry.name}: registry checksum differs from manifest`);
  const priorCreateRejected = rec.createStartedAt
    && rec.lastError?.phase === 'create'
    && definitiveCreateRejection(rec.lastError);
  if (priorCreateRejected) {
    delete rec.createStartedAt;
    rec.status = 'pending';
    saveRegistry(registry);
    log(`[${entry.name}] retrying after definitive HTTP 413 gateway rejection`);
  }
  if (rec.status === 'finalized' && batchComplete(rec)) {
    log(`[${entry.name}] already finalized: ${rec.txHash ?? rec.dkgFinalizationMode}`);
    return { skip: true, entry, rec, batchStartedAt };
  }

  const kaName = `${kaPrefix}-${entry.name}`;
  if (pipelined) {
    updateProgress({ pipelinePhase: 'loading', pipelineBatch: entry.name, pipelineKa: kaName });
  } else {
    updateProgress({ phase: 'loading', currentBatch: entry.name, currentKa: kaName, completedBatches: completed });
  }
  const { quads } = readBatch(entry);

  if (!hasFinalizedVm(rec) && !rec.sealedAt) {
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
      log(`[${entry.name}] creating and sealing ${kaName} (${quads.length.toLocaleString()} quads)${pipelined ? ' in pipeline' : ''}`);
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
    rec.sealedAt = new Date().toISOString();
    rec.status = 'sealed';
    saveRegistry(registry);
  }

  if (!hasFinalizedVm(rec) && !rec.sharedAt) {
    if (rec.shareJobId) {
      const stored = await querySwmQuads(quads);
      const verificationMode = exactMemoryVerificationMode(stored, quads);
      if (verificationMode) {
        rec.sharedAt = new Date().toISOString();
        rec.shareVerificationMode = verificationMode;
        rec.shareReconciledAt = rec.sharedAt;
        rec.status = 'shared';
        delete rec.lastError;
        saveRegistry(registry);
        log(`[${entry.name}] reconciled prior share job from exact SWM state (${stored.subjectCount.toLocaleString()} subjects, ${stored.quads.length.toLocaleString()} quads)`);
      }
    }
    if (!rec.shareJobId) {
      await assertGraphMembershipUnchanged(membership);
      log(`[${entry.name}] enqueueing persistent SWM share job${pipelined ? ' in pipeline' : ''}`);
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
    if (!rec.sharedAt) {
      try {
        await pollShareJob(entry.name, rec.shareJobId, pipelined);
        rec.sharedAt = new Date().toISOString();
        rec.status = 'shared';
        saveRegistry(registry);
        if (pipelined) updateProgress({ pipelinePhase: 'shared', pipelineBatch: entry.name });
      } catch (error) {
        const stored = await querySwmQuads(quads).catch(() => null);
        const verificationMode = stored ? exactMemoryVerificationMode(stored, quads) : null;
        if (verificationMode) {
          rec.sharedAt = new Date().toISOString();
          rec.shareVerificationMode = verificationMode;
          rec.shareReconciledAt = rec.sharedAt;
          rec.status = 'shared';
          delete rec.lastError;
          saveRegistry(registry);
          log(`[${entry.name}] reconciled failed share job from exact SWM state (${stored.subjectCount.toLocaleString()} subjects, ${stored.quads.length.toLocaleString()} quads)`);
          if (pipelined) updateProgress({ pipelinePhase: 'shared', pipelineBatch: entry.name });
        } else {
          rec.lastError = { at: new Date().toISOString(), phase: 'share', message: error.message, code: error.code ?? null };
          rec.status = 'error';
          saveRegistry(registry);
          throw error;
        }
      }
    }
  }

  return { skip: false, entry, rec, kaName, quads, batchStartedAt };
}

async function publishAll(validated, preflight) {
  const suppliedConfirmation = option('confirm', '');
  if (suppliedConfirmation !== preflight.confirmation) throw new Error(`paid confirmation mismatch; rerun --preflight and pass --confirm ${preflight.confirmation}`);
  lockFd = openSync(lockPath, 'wx');
  writeFileSync(lockFd, `${JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString(), contextGraphId })}\n`);

  const registry = loadRegistry(validated.manifest, validated.manifestSha256);
  saveRegistry(registry);
  const entries = validated.selected;
  let completed = Object.values(registry.batches).filter((record) => record.status === 'finalized' && batchComplete(record)).length;
  let processedThisRun = 0;
  updateProgress({
    status: 'running', phase: 'starting', startedAt: new Date(startedAt).toISOString(),
    contextGraphId, epochs, totalBatches: validated.manifest.batchCount,
    completedBatches: completed, totalRecords: validated.manifest.includedRecords,
  });

  const staged = new Map();
  const ensureStaged = (entry, pipelined = false) => {
    if (!staged.has(entry.name)) {
      const promise = stageSharedEntry(entry, registry, preflight.membership, completed, pipelined);
      promise.catch(() => {});
      staged.set(entry.name, promise);
    }
    return staged.get(entry.name);
  };

  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    if (staged.has(entry.name)) updateProgress({ phase: 'awaiting-shared', currentBatch: entry.name });
    const stage = await ensureStaged(entry);
    staged.delete(entry.name);
    if (stage.skip) continue;
    const { rec, kaName, quads, batchStartedAt } = stage;
    const nextEntry = entries[index + 1];
    if (pipelineWidth === 2 && nextEntry) {
      log(`[${entry.name}] starting bounded SWM pipeline for ${nextEntry.name}`);
      ensureStaged(nextEntry, true);
    }

    try {
      if (!hasFinalizedVm(rec) && vmPublishMode === 'sync') {
        await publishSynchronous(entry, rec, kaName, quads, registry, preflight.membership);
        saveRegistry(registry);
      } else if (!hasFinalizedVm(rec)) {
        if (!rec.publishJobId) {
          await assertGraphMembershipUnchanged(preflight.membership);
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
        const job = await pollPublishJob(entry.name, rec.publishJobId);
        recordFinalized(rec, job);
      }
      if (swmRestoreMode === 'restore') await restorePublishedAssetToSwm(entry, rec, kaName, quads, registry);
      else skipPublishedAssetSwmRestore(entry, rec, registry);
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
      log(`[${entry.name}] finalized tx=${rec.txHash ?? rec.dkgFinalizationMode} block=${rec.blockNumber ?? 'n/a'}; ${completed}/${validated.manifest.batchCount} complete`);
    } catch (error) {
      if (definitiveContextGraphValidationRejection(error) || definitiveContextGraphValidationRejection(rec.lastError)) {
        delete rec.publishStartedAt;
        rec.status = 'shared';
        rec.lastError = { at: new Date().toISOString(), phase: 'publish', message: error.message, code: error.code ?? null, status: error.status ?? 503 };
        saveRegistry(registry);
      } else if (rec.lastError?.phase !== 'swm-restore') {
        rec.lastError = { at: new Date().toISOString(), phase: 'publish', message: error.message, code: error.code ?? null };
        rec.status = 'error';
        saveRegistry(registry);
      }
      throw error;
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
  log(`local validation OK: ${validated.manifest.includedRecords.toLocaleString()} records, ${validated.manifest.batchCount} batches, ${totalQuads.toLocaleString()} quads, ${(totalPayloadBytes / 1e9).toFixed(2)} GB JSON payload`);
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
