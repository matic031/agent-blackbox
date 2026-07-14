#!/usr/bin/env node
/** Integration smoke test for validation, private-CG guard, async jobs and resume. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { recordQuads } from './mapping.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const temp = mkdtempSync(join(tmpdir(), 'blackbox-publisher-test-'));
const batches = join(temp, 'batches');
const tokenPath = join(temp, 'auth.token');
const registryPath = join(temp, 'registry.json');
const progressPath = join(temp, 'progress.json');
const sourcePath = join(temp, 'source.json');
const owner = '0x1111111111111111111111111111111111111111';
const cg = `${owner}/private-blackbox`;
const staleAssertion = 'ab'.repeat(32);
const staleOrdinal = 7n;
const staleKaId = ((BigInt(owner) << 96n) | staleOrdinal).toString();
const freshOrdinal = 8n;
const freshKaId = ((BigInt(owner) << 96n) | freshOrdinal).toString();
let accessPolicy = 1;
let publishState = 'finalized';
let rejectCreateStatus;
let rejectPublishStatus;
let rejectPublishError;
let synchronousPublish = false;
let staleVmStatus = false;
let missingLifecycleStamp = false;
let includeTrustLevel = false;
let chainMerkleRoot = `0x${staleAssertion}`;
let membershipChanges = false;
let participantReads = 0;
let queryBatchDir = batches;
let queryBatchName = 'batch-001';
let publishDelayMs = 0;
let pipelineFixture = false;
let shareState = 'succeeded';
let activePaidPublishes = 0;
let maxActivePaidPublishes = 0;
let swmOverlappedPaidPublish = false;
let swmMismatchReads = 0;
const pipelineEvents = [];
const calls = { create: 0, share: 0, publish: 0, pull: 0 };

function run(script, args, env = {}) {
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, [join(here, script), ...args], {
      cwd: here,
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('exit', (code) => resolvePromise({ code, stdout, stderr }));
  });
}

function json(response, status, body) {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(body));
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1');
  if (request.method === 'GET' && url.pathname === '/api/status') return json(response, 200, { name: 'fixture', version: '10.0.6', networkConfig: 'mainnet-base', connectedPeers: 3 });
  if (request.method === 'GET' && url.pathname === '/api/context-graph/exists') return json(response, 200, { id: cg, exists: true });
  if (request.method === 'GET' && url.pathname === '/api/context-graph/list') return json(response, 200, { contextGraphs: [{ id: cg, accessPolicy, onChainId: '13' }] });
  if (request.method === 'GET' && url.pathname.endsWith('/participants')) {
    participantReads += 1;
    const allowedAgents = membershipChanges && participantReads > 1
      ? [owner, '0x2222222222222222222222222222222222222222']
      : [owner];
    return json(response, 200, { contextGraphId: cg, allowedAgents });
  }
  if (request.method === 'GET' && url.pathname === '/api/wallets/balances') return json(response, 200, {
    chainId: 'base:8453',
    rpcUrl: 'https://rpc.example/private-provider-secret',
    wallets: [owner],
    balances: [{ address: owner, eth: '1', trac: '10000' }],
  });
  if (request.method === 'GET' && url.pathname === '/api/publisher/stats') return json(response, 200, { accepted: 0, finalized: 0, failed: 0 });
  if (request.method === 'GET' && url.pathname === `/api/kc/${staleKaId}`) {
    return json(response, 200, { kaId: staleKaId, merkleRoot: chainMerkleRoot, author: owner });
  }
  if (request.method === 'GET' && url.pathname === `/api/kc/${freshKaId}`) {
    return json(response, 200, { kaId: freshKaId, merkleRoot: `0x${'0'.repeat(64)}`, author: null });
  }
  if (request.method === 'POST' && url.pathname === '/api/query') {
    if (swmMismatchReads > 0) {
      swmMismatchReads -= 1;
      return json(response, 200, { result: { bindings: [] } });
    }
    const batch = JSON.parse(readFileSync(join(queryBatchDir, `${queryBatchName}.json`)));
    const quads = batch.records.flatMap(recordQuads);
    if (includeTrustLevel) {
      for (const subject of new Set(quads.map((quad) => quad.subject))) {
        quads.push({
          subject,
          predicate: 'http://dkg.io/ontology/trustLevel',
          object: '"0"^^<http://www.w3.org/2001/XMLSchema#integer>',
          graph: '',
        });
      }
    }
    const bindings = quads.map((quad) => ({
      s: quad.subject,
      p: quad.predicate,
      o: quad.object,
    }));
    return json(response, 200, { result: { bindings } });
  }
  if (request.method === 'POST' && url.pathname === '/api/knowledge-assets') {
    calls.create += 1;
    if (rejectCreateStatus) {
      const status = rejectCreateStatus;
      rejectCreateStatus = undefined;
      const error = status === 400
        ? 'Invalid "name": Assertion name cannot contain "/"'
        : status === 503
          ? 'Failed to validate contextGraphId against known context graphs: Store scheduler queue wait timeout (normal: blazegraph.query)'
          : 'fixture gateway limit';
      return json(response, status, { error });
    }
    return json(response, 201, { status: 'wm-sealed', assertionUri: 'urn:test:assertion' });
  }
  if (request.method === 'POST' && url.pathname.endsWith('/swm/share-async')) {
    calls.share += 1;
    const kaName = decodeURIComponent(url.pathname.split('/').at(-3));
    pipelineEvents.push({ type: 'share', kaName, at: Date.now() });
    if (pipelineFixture && kaName.endsWith('batch-002')) {
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 100));
      if (activePaidPublishes > 0) swmOverlappedPaidPublish = true;
    }
    return json(response, 200, { jobId: `share-${calls.share}`, state: 'queued' });
  }
  if (request.method === 'GET' && url.pathname.startsWith('/api/knowledge-assets/swm/share-jobs/share-')) {
    if (shareState === 'failed') return json(response, 200, { jobId: url.pathname.split('/').at(-1), state: 'failed', error: 'fixture lease expired' });
    return json(response, 200, { jobId: url.pathname.split('/').at(-1), state: 'succeeded', result: { promotedCount: 2 } });
  }
  if (request.method === 'POST' && url.pathname.endsWith('/wm/pull-from')) {
    calls.pull += 1;
    const kaName = decodeURIComponent(url.pathname.split('/').at(-3));
    queryBatchName = kaName.endsWith('batch-002') ? 'batch-002' : 'batch-001';
    return json(response, 200, { wmDraft: 'open', seededFrom: { layer: 'vm' } });
  }
  if (request.method === 'POST' && url.pathname.endsWith('/vm/publish-async')) {
    calls.publish += 1;
    return json(response, 202, { jobId: 'publish-1', status: 'accepted' });
  }
  if (request.method === 'POST' && url.pathname.endsWith('/vm/publish')) {
    calls.publish += 1;
    if (rejectPublishStatus) {
      const status = rejectPublishStatus;
      rejectPublishStatus = undefined;
      const error = rejectPublishError
        ?? 'Failed to validate contextGraphId against known context graphs: Store scheduler queue wait timeout (normal: blazegraph.query)';
      rejectPublishError = undefined;
      return json(response, status, { error });
    }
    synchronousPublish = true;
    const kaName = decodeURIComponent(url.pathname.split('/').at(-3));
    queryBatchName = kaName.endsWith('batch-002') ? 'batch-002' : 'batch-001';
    activePaidPublishes += 1;
    maxActivePaidPublishes = Math.max(maxActivePaidPublishes, activePaidPublishes);
    pipelineEvents.push({ type: 'publish-start', kaName, at: Date.now() });
    if (publishDelayMs) await new Promise((resolvePromise) => setTimeout(resolvePromise, publishDelayMs));
    pipelineEvents.push({ type: 'publish-end', kaName, at: Date.now() });
    activePaidPublishes -= 1;
    return json(response, 200, { status: 'confirmed', txHash: '0xsync', ual: 'did:dkg:sync', blockNumber: 456 });
  }
  if (request.method === 'GET' && url.pathname.endsWith('/vm')) {
    const assertion = staleVmStatus ? staleAssertion : 'ef'.repeat(32);
    const ordinal = staleVmStatus ? staleOrdinal : freshOrdinal;
    return json(response, 200, {
      state: 'promoted',
      status: staleVmStatus ? 'draft-open' : 'swm-shared',
      memoryLayer: 'SWM',
      wmCurrentAssertion: assertion,
      swmCurrentAssertion: missingLifecycleStamp ? null : assertion,
      vmCurrentAssertion: null,
      publishedUal: null,
      reservedUal: `did:dkg:base:8453/${owner}/${ordinal}`,
    });
  }
  if (request.method === 'GET' && url.pathname === '/api/publisher/job') {
    if (publishState === 'failed') return json(response, 200, { job: { jobId: 'publish-1', status: 'failed', failure: { message: 'fixture chain failure' } } });
    return json(response, 200, { job: { jobId: 'publish-1', status: 'finalized', broadcast: { txHash: '0xabc' }, inclusion: { txHash: '0xabc', blockNumber: 123 }, finalization: { mode: 'published', txHash: '0xabc', ual: 'did:dkg:test' } } });
  }
  return json(response, 404, { error: `${request.method} ${url.pathname} not mocked` });
});

try {
  mkdirSync(batches, { recursive: true });
  writeFileSync(tokenPath, 'test-token\n');
  writeFileSync(sourcePath, JSON.stringify({
    dependencies: [{ type: 'dependency', ecosystem: 'npm', name: 'Example-Package', version: '1.0.0', title: 'fixture dependency' }],
    iocs: [{ type: 'ioc', ioc_type: 'domain', value: 'EVIL.EXAMPLE.', threat: 'fixture IOC' }],
  }));

  const chunk = await run('chunk.mjs', [sourcePath, '--size', '2', '--expect-records', '2', '--out-dir', batches]);
  assert.equal(chunk.code, 0, chunk.stderr);
  const dry = await run('publish.mjs', ['--dry-run'], { KC_BATCH_DIR: batches, KC_EXPECT_RECORDS: '2', KC_PROGRESS_PATH: progressPath });
  assert.equal(dry.code, 0, dry.stderr);
  const rangedDry = await run('publish.mjs', ['--dry-run', '--from-batch', 'batch-001', '--to-batch', 'batch-001'], { KC_BATCH_DIR: batches, KC_EXPECT_RECORDS: '2', KC_PROGRESS_PATH: progressPath });
  assert.equal(rangedDry.code, 0, rangedDry.stderr);
  const conflictingSelection = await run('publish.mjs', ['--dry-run', '--batch', 'batch-001', '--from-batch', 'batch-001'], { KC_BATCH_DIR: batches, KC_EXPECT_RECORDS: '2', KC_PROGRESS_PATH: progressPath });
  assert.notEqual(conflictingSelection.code, 0, 'conflicting batch selectors unexpectedly succeeded');
  assert.match(conflictingSelection.stderr, /--batch cannot be combined/);
  const invalidPipeline = await run('publish.mjs', ['--dry-run'], { KC_BATCH_DIR: batches, KC_EXPECT_RECORDS: '2', KC_PROGRESS_PATH: progressPath, KC_PIPELINE_WIDTH: '3' });
  assert.notEqual(invalidPipeline.code, 0, 'unsafe pipeline width unexpectedly succeeded');
  assert.match(invalidPipeline.stderr, /KC_PIPELINE_WIDTH must be 1 or 2/);
  const invalidRestoreMode = await run('publish.mjs', ['--dry-run'], { KC_BATCH_DIR: batches, KC_EXPECT_RECORDS: '2', KC_PROGRESS_PATH: progressPath, KC_SWM_RESTORE_MODE: 'invalid' });
  assert.notEqual(invalidRestoreMode.code, 0, 'invalid SWM restore mode unexpectedly succeeded');
  assert.match(invalidRestoreMode.stderr, /KC_SWM_RESTORE_MODE must be restore or skip/);

  await new Promise((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise));
  const port = server.address().port;
  const env = {
    KC_BATCH_DIR: batches,
    KC_EXPECT_RECORDS: '2',
    KC_CG_ID: cg,
    DKG_ENDPOINT: 'http://127.0.0.1',
    DKG_PORT: String(port),
    DKG_AUTH_TOKEN_PATH: tokenPath,
    KC_REGISTRY_PATH: registryPath,
    KC_PROGRESS_PATH: progressPath,
    KC_POLL_MS: '1000',
    KC_VM_PUBLISH_MODE: 'async',
  };

  accessPolicy = 0;
  const publicGraph = await run('publish.mjs', ['--preflight'], env);
  assert.notEqual(publicGraph.code, 0, 'public CG preflight unexpectedly succeeded');
  assert.match(publicGraph.stderr, /not verifiably private\/curated/);

  accessPolicy = undefined;
  const pinnedPrivateGraph = await run('publish.mjs', ['--preflight'], { ...env, KC_CG_ONCHAIN_ID: '13' });
  assert.equal(pinnedPrivateGraph.code, 0, pinnedPrivateGraph.stderr);
  assert.match(pinnedPrivateGraph.stdout, /pinned onChainId=13, curated owner allowlist/);

  accessPolicy = 1;
  const preflight = await run('publish.mjs', ['--preflight'], env);
  assert.equal(preflight.code, 0, preflight.stderr);
  assert.doesNotMatch(preflight.stdout, /private-provider-secret/);
  const manifestHash = createHash('sha256').update(readFileSync(join(batches, 'manifest.json'))).digest('hex');
  const confirmation = `${cg}:12:${manifestHash.slice(0, 12)}`;
  assert.match(preflight.stdout, new RegExp(confirmation.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  const rangeBatches = join(temp, 'range-batches');
  const rangeRegistryPath = join(temp, 'range-registry.json');
  const rangeProgressPath = join(temp, 'range-progress.json');
  const rangeChunk = await run('chunk.mjs', [sourcePath, '--size', '1', '--expect-records', '2', '--out-dir', rangeBatches]);
  assert.equal(rangeChunk.code, 0, rangeChunk.stderr);
  const rangeManifestHash = createHash('sha256').update(readFileSync(join(rangeBatches, 'manifest.json'))).digest('hex');
  const rangeConfirmation = `${cg}:12:${rangeManifestHash.slice(0, 12)}`;
  queryBatchDir = rangeBatches;
  queryBatchName = 'batch-002';
  synchronousPublish = false;
  const rangedPublish = await run('publish.mjs', [
    '--publish', '--from-batch', 'batch-002', '--to-batch', 'batch-002', '--confirm', rangeConfirmation,
  ], {
    ...env,
    KC_BATCH_DIR: rangeBatches,
    KC_VM_PUBLISH_MODE: 'sync',
    KC_REGISTRY_PATH: rangeRegistryPath,
    KC_PROGRESS_PATH: rangeProgressPath,
  });
  assert.equal(rangedPublish.code, 0, rangedPublish.stderr);
  assert.equal(synchronousPublish, true);
  assert.deepEqual(calls, { create: 1, share: 1, publish: 1, pull: 0 });
  const rangeRegistry = JSON.parse(readFileSync(rangeRegistryPath, 'utf8'));
  assert.equal(rangeRegistry.batches['batch-001'], undefined, 'range publish processed a batch before --from-batch');
  assert.equal(rangeRegistry.batches['batch-002'].status, 'finalized');
  queryBatchDir = batches;
  queryBatchName = 'batch-001';
  synchronousPublish = false;
  Object.assign(calls, { create: 0, share: 0, publish: 0, pull: 0 });

  const pipelineRegistryPath = join(temp, 'pipeline-registry.json');
  const pipelineProgressPath = join(temp, 'pipeline-progress.json');
  queryBatchDir = rangeBatches;
  queryBatchName = 'batch-001';
  publishDelayMs = 500;
  pipelineFixture = true;
  maxActivePaidPublishes = 0;
  swmOverlappedPaidPublish = false;
  pipelineEvents.length = 0;
  const pipelinePublish = await run('publish.mjs', [
    '--publish', '--from-batch', 'batch-001', '--to-batch', 'batch-002', '--confirm', rangeConfirmation,
  ], {
    ...env,
    KC_BATCH_DIR: rangeBatches,
    KC_VM_PUBLISH_MODE: 'sync',
    KC_PIPELINE_WIDTH: '2',
    KC_REGISTRY_PATH: pipelineRegistryPath,
    KC_PROGRESS_PATH: pipelineProgressPath,
  });
  assert.equal(pipelinePublish.code, 0, pipelinePublish.stderr);
  assert.equal(maxActivePaidPublishes, 1, 'pipeline ran concurrent paid publishes');
  assert.equal(swmOverlappedPaidPublish, true, 'next SWM stage did not overlap the current paid publish');
  assert.deepEqual(calls, { create: 2, share: 2, publish: 2, pull: 0 });
  const firstPublishEnd = pipelineEvents.find((event) => event.type === 'publish-end' && event.kaName.endsWith('batch-001'));
  const nextShare = pipelineEvents.find((event) => event.type === 'share' && event.kaName.endsWith('batch-002'));
  assert.equal(Boolean(firstPublishEnd && nextShare && nextShare.at < firstPublishEnd.at), true, 'next batch was not staged before the current paid publish completed');
  const pipelineRegistry = JSON.parse(readFileSync(pipelineRegistryPath, 'utf8'));
  assert.equal(pipelineRegistry.batches['batch-001'].status, 'finalized');
  assert.equal(pipelineRegistry.batches['batch-002'].status, 'finalized');
  const callsAfterPipeline = { ...calls };
  const pipelineResume = await run('publish.mjs', [
    '--publish', '--from-batch', 'batch-001', '--to-batch', 'batch-002', '--confirm', rangeConfirmation,
  ], {
    ...env,
    KC_BATCH_DIR: rangeBatches,
    KC_VM_PUBLISH_MODE: 'sync',
    KC_PIPELINE_WIDTH: '2',
    KC_REGISTRY_PATH: pipelineRegistryPath,
    KC_PROGRESS_PATH: pipelineProgressPath,
  });
  assert.equal(pipelineResume.code, 0, pipelineResume.stderr);
  assert.deepEqual(calls, callsAfterPipeline, 'pipeline resume replayed a paid or mutating operation');
  queryBatchDir = batches;
  queryBatchName = 'batch-001';
  publishDelayMs = 0;
  pipelineFixture = false;
  synchronousPublish = false;
  Object.assign(calls, { create: 0, share: 0, publish: 0, pull: 0 });

  const vmOnlyRegistryPath = join(temp, 'vm-only-registry.json');
  const vmOnlyProgressPath = join(temp, 'vm-only-progress.json');
  const vmOnlyEnv = {
    ...env,
    KC_VM_PUBLISH_MODE: 'sync',
    KC_SWM_RESTORE_MODE: 'skip',
    KC_REGISTRY_PATH: vmOnlyRegistryPath,
    KC_PROGRESS_PATH: vmOnlyProgressPath,
  };
  const vmOnlyPublish = await run('publish.mjs', ['--publish', '--confirm', confirmation], vmOnlyEnv);
  assert.equal(vmOnlyPublish.code, 0, vmOnlyPublish.stderr);
  assert.deepEqual(calls, { create: 1, share: 1, publish: 1, pull: 0 });
  const vmOnlyRegistry = JSON.parse(readFileSync(vmOnlyRegistryPath, 'utf8'));
  assert.equal(vmOnlyRegistry.batches['batch-001'].status, 'finalized');
  assert.equal(vmOnlyRegistry.batches['batch-001'].swmRestoreMode, 'skipped-vm-only');
  assert.equal(typeof vmOnlyRegistry.batches['batch-001'].swmRestoreSkippedAt, 'string');
  assert.equal(vmOnlyRegistry.batches['batch-001'].swmReplicatedAt, undefined);
  const callsAfterVmOnly = { ...calls };
  const vmOnlyResume = await run('publish.mjs', ['--publish', '--confirm', confirmation], vmOnlyEnv);
  assert.equal(vmOnlyResume.code, 0, vmOnlyResume.stderr);
  assert.deepEqual(calls, callsAfterVmOnly, 'VM-only resume replayed a paid or mutating operation');

  Object.assign(calls, { create: 0, share: 0, publish: 0, pull: 0 });
  const shareRecoveryRegistryPath = join(temp, 'share-recovery-registry.json');
  const shareRecoveryProgressPath = join(temp, 'share-recovery-progress.json');
  const shareRecoveryEnv = {
    ...vmOnlyEnv,
    KC_REGISTRY_PATH: shareRecoveryRegistryPath,
    KC_PROGRESS_PATH: shareRecoveryProgressPath,
  };
  shareState = 'failed';
  swmMismatchReads = 1;
  const failedShare = await run('publish.mjs', ['--publish', '--confirm', confirmation], shareRecoveryEnv);
  assert.notEqual(failedShare.code, 0, 'failed share job unexpectedly produced success');
  assert.deepEqual(calls, { create: 1, share: 1, publish: 0, pull: 0 });
  const recoveredShare = await run('publish.mjs', ['--publish', '--confirm', confirmation], shareRecoveryEnv);
  assert.equal(recoveredShare.code, 0, recoveredShare.stderr);
  assert.deepEqual(calls, { create: 1, share: 1, publish: 1, pull: 0 });
  const recoveredRegistry = JSON.parse(readFileSync(shareRecoveryRegistryPath, 'utf8'));
  assert.equal(recoveredRegistry.batches['batch-001'].shareVerificationMode, 'exact');
  assert.equal(typeof recoveredRegistry.batches['batch-001'].shareReconciledAt, 'string');
  assert.equal(recoveredRegistry.batches['batch-001'].status, 'finalized');

  Object.assign(calls, { create: 0, share: 0, publish: 0, pull: 0 });
  const inlineShareRegistryPath = join(temp, 'inline-share-registry.json');
  const inlineShareProgressPath = join(temp, 'inline-share-progress.json');
  const inlineShare = await run('publish.mjs', ['--publish', '--confirm', confirmation], {
    ...vmOnlyEnv,
    KC_REGISTRY_PATH: inlineShareRegistryPath,
    KC_PROGRESS_PATH: inlineShareProgressPath,
  });
  assert.equal(inlineShare.code, 0, inlineShare.stderr);
  assert.deepEqual(calls, { create: 1, share: 1, publish: 1, pull: 0 });
  const inlineShareRegistry = JSON.parse(readFileSync(inlineShareRegistryPath, 'utf8'));
  assert.equal(inlineShareRegistry.batches['batch-001'].shareVerificationMode, 'exact');
  assert.equal(typeof inlineShareRegistry.batches['batch-001'].shareReconciledAt, 'string');
  assert.equal(inlineShareRegistry.batches['batch-001'].status, 'finalized');
  shareState = 'succeeded';

  Object.assign(calls, { create: 0, share: 0, publish: 0, pull: 0 });
  const publishRejectionRegistryPath = join(temp, 'publish-rejection-registry.json');
  const publishRejectionProgressPath = join(temp, 'publish-rejection-progress.json');
  const publishRejectionEnv = {
    ...vmOnlyEnv,
    KC_REGISTRY_PATH: publishRejectionRegistryPath,
    KC_PROGRESS_PATH: publishRejectionProgressPath,
  };
  rejectPublishStatus = 503;
  const publishRejected = await run('publish.mjs', ['--publish', '--confirm', confirmation], publishRejectionEnv);
  assert.notEqual(publishRejected.code, 0, 'pre-publish context graph rejection unexpectedly succeeded');
  assert.deepEqual(calls, { create: 1, share: 1, publish: 1, pull: 0 });
  const rejectedPublishRegistry = JSON.parse(readFileSync(publishRejectionRegistryPath, 'utf8'));
  assert.equal(rejectedPublishRegistry.batches['batch-001'].status, 'shared');
  assert.equal(rejectedPublishRegistry.batches['batch-001'].publishStartedAt, undefined);
  rejectedPublishRegistry.batches['batch-001'].publishStartedAt = '2026-01-01T00:00:00.000Z';
  rejectedPublishRegistry.batches['batch-001'].status = 'error';
  writeFileSync(publishRejectionRegistryPath, `${JSON.stringify(rejectedPublishRegistry, null, 2)}\n`);
  const publishRejectionRetry = await run('publish.mjs', ['--publish', '--confirm', confirmation], publishRejectionEnv);
  assert.equal(publishRejectionRetry.code, 0, publishRejectionRetry.stderr);
  assert.deepEqual(calls, { create: 1, share: 1, publish: 2, pull: 0 });

  Object.assign(calls, { create: 0, share: 0, publish: 0, pull: 0 });
  const senderKeyRegistryPath = join(temp, 'sender-key-rejection-registry.json');
  const senderKeyProgressPath = join(temp, 'sender-key-rejection-progress.json');
  const senderKeyEnv = {
    ...vmOnlyEnv,
    KC_REGISTRY_PATH: senderKeyRegistryPath,
    KC_PROGRESS_PATH: senderKeyProgressPath,
  };
  rejectPublishStatus = 500;
  rejectPublishError = 'SWM Sender Key setup rejected by 1 agent(s): 0x2222222222222222222222222222222222222222: did:dkg:agent:test#x25519: not-agent-gated: Context graph is not DKG-agent gated';
  const senderKeyRejected = await run('publish.mjs', ['--publish', '--confirm', confirmation], senderKeyEnv);
  assert.notEqual(senderKeyRejected.code, 0, 'sender-key pre-publish rejection unexpectedly succeeded');
  assert.deepEqual(calls, { create: 1, share: 1, publish: 1, pull: 0 });
  const senderKeyRegistry = JSON.parse(readFileSync(senderKeyRegistryPath, 'utf8'));
  assert.equal(senderKeyRegistry.batches['batch-001'].status, 'shared');
  assert.equal(senderKeyRegistry.batches['batch-001'].publishStartedAt, undefined);
  senderKeyRegistry.batches['batch-001'].publishStartedAt = '2026-01-01T00:00:00.000Z';
  senderKeyRegistry.batches['batch-001'].status = 'error';
  writeFileSync(senderKeyRegistryPath, `${JSON.stringify(senderKeyRegistry, null, 2)}\n`);
  const senderKeyRetry = await run('publish.mjs', ['--publish', '--confirm', confirmation], senderKeyEnv);
  assert.equal(senderKeyRetry.code, 0, senderKeyRetry.stderr);
  assert.deepEqual(calls, { create: 1, share: 1, publish: 2, pull: 0 });

  Object.assign(calls, { create: 0, share: 0, publish: 0, pull: 0 });
  const transportRegistryPath = join(temp, 'sender-key-transport-registry.json');
  const transportProgressPath = join(temp, 'sender-key-transport-progress.json');
  const transportEnv = {
    ...vmOnlyEnv,
    KC_REGISTRY_PATH: transportRegistryPath,
    KC_PROGRESS_PATH: transportProgressPath,
  };
  rejectPublishStatus = 500;
  rejectPublishError = 'Network identity probe failed for 12D3KooWFixture: retryable probe backed off for 29632ms after send timeout elapsed';
  const transportRejected = await run('publish.mjs', ['--publish', '--confirm', confirmation], transportEnv);
  assert.notEqual(transportRejected.code, 0, 'sender-key transport rejection unexpectedly succeeded');
  assert.deepEqual(calls, { create: 1, share: 1, publish: 1, pull: 0 });
  const transportRegistry = JSON.parse(readFileSync(transportRegistryPath, 'utf8'));
  assert.equal(transportRegistry.batches['batch-001'].status, 'shared');
  assert.equal(transportRegistry.batches['batch-001'].publishStartedAt, undefined);
  const transportRetry = await run('publish.mjs', ['--publish', '--confirm', confirmation], transportEnv);
  assert.equal(transportRetry.code, 0, transportRetry.stderr);
  assert.deepEqual(calls, { create: 1, share: 1, publish: 2, pull: 0 });

  Object.assign(calls, { create: 0, share: 0, publish: 0, pull: 0 });

  rejectCreateStatus = 413;
  const rejected = await run('publish.mjs', ['--publish', '--confirm', confirmation], env);
  assert.notEqual(rejected.code, 0, 'HTTP 413 unexpectedly produced success');
  assert.deepEqual(calls, { create: 1, share: 0, publish: 0, pull: 0 });
  const rejectedRegistry = JSON.parse(readFileSync(registryPath, 'utf8'));
  assert.equal(rejectedRegistry.batches['batch-001'].createStartedAt, undefined);
  assert.equal(rejectedRegistry.batches['batch-001'].lastError.status, 413);
  rejectedRegistry.batches['batch-001'].createStartedAt = '2026-01-01T00:00:00.000Z';
  writeFileSync(registryPath, `${JSON.stringify(rejectedRegistry, null, 2)}\n`);

  rejectCreateStatus = 400;
  const invalidName = await run('publish.mjs', ['--publish', '--confirm', confirmation], env);
  assert.notEqual(invalidName.code, 0, 'invalid assertion name unexpectedly produced success');
  assert.deepEqual(calls, { create: 2, share: 0, publish: 0, pull: 0 });
  const invalidNameRegistry = JSON.parse(readFileSync(registryPath, 'utf8'));
  assert.equal(invalidNameRegistry.batches['batch-001'].createStartedAt, undefined);
  assert.equal(invalidNameRegistry.batches['batch-001'].lastError.status, 400);

  swmMismatchReads = 1;
  const publish = await run('publish.mjs', ['--publish', '--confirm', confirmation], env);
  assert.equal(publish.code, 0, publish.stderr);
  assert.deepEqual(calls, { create: 3, share: 2, publish: 1, pull: 1 });
  const registry = JSON.parse(readFileSync(registryPath, 'utf8'));
  assert.equal(registry.batches['batch-001'].txHash, '0xabc');
  assert.equal(registry.batches['batch-001'].epochs, 12);
  assert.equal(registry.batches['batch-001'].status, 'finalized');
  assert.equal(registry.batches['batch-001'].swmRestoreQuadCount > 0, true);
  assert.equal(typeof registry.batches['batch-001'].swmReplicatedAt, 'string');

  const resume = await run('publish.mjs', ['--publish', '--confirm', confirmation], env);
  assert.equal(resume.code, 0, resume.stderr);
  assert.deepEqual(calls, { create: 3, share: 2, publish: 1, pull: 1 }, 'resume replayed a paid/mutating operation');

  const wrongConfirmation = await run('publish.mjs', ['--publish', '--confirm', 'wrong-token'], env);
  assert.notEqual(wrongConfirmation.code, 0, 'wrong paid confirmation unexpectedly succeeded');
  assert.deepEqual(calls, { create: 3, share: 2, publish: 1, pull: 1 }, 'wrong confirmation reached a mutation');

  publishState = 'failed';
  const failureRegistryPath = join(temp, 'failure-registry.json');
  const failureProgressPath = join(temp, 'failure-progress.json');
  const failure = await run('publish.mjs', ['--publish', '--confirm', confirmation], {
    ...env,
    KC_REGISTRY_PATH: failureRegistryPath,
    KC_PROGRESS_PATH: failureProgressPath,
  });
  assert.notEqual(failure.code, 0, 'failed DKG job unexpectedly produced success');
  assert.match(failure.stderr, /fixture chain failure/);
  const failureRegistry = JSON.parse(readFileSync(failureRegistryPath, 'utf8'));
  assert.equal(failureRegistry.batches['batch-001'].status, 'error');
  assert.equal(failureRegistry.batches['batch-001'].lastError.phase, 'publish');
  const failureProgress = JSON.parse(readFileSync(failureProgressPath, 'utf8'));
  assert.equal(failureProgress.status, 'error');

  const syncRegistryPath = join(temp, 'sync-registry.json');
  const syncProgressPath = join(temp, 'sync-progress.json');
  publishState = 'finalized';
  synchronousPublish = false;
  const syncPublish = await run('publish.mjs', ['--publish', '--confirm', confirmation], {
    ...env,
    KC_VM_PUBLISH_MODE: 'sync',
    KC_REGISTRY_PATH: syncRegistryPath,
    KC_PROGRESS_PATH: syncProgressPath,
  });
  assert.equal(syncPublish.code, 0, syncPublish.stderr);
  assert.equal(synchronousPublish, true);
  const syncRegistry = JSON.parse(readFileSync(syncRegistryPath, 'utf8'));
  assert.equal(syncRegistry.batches['batch-001'].txHash, '0xsync');
  assert.equal(syncRegistry.batches['batch-001'].ual, 'did:dkg:sync');
  assert.equal(syncRegistry.batches['batch-001'].publishMode, 'sync');
  assert.equal(syncRegistry.batches['batch-001'].status, 'finalized');
  assert.equal(typeof syncRegistry.batches['batch-001'].swmReplicatedAt, 'string');

  const staleRegistry = structuredClone(syncRegistry);
  const staleRecord = staleRegistry.batches['batch-001'];
  for (const field of [
    'txHash', 'ual', 'blockNumber', 'finalizedAt', 'dkgFinalizationMode',
    'swmReplicatedAt', 'swmRestoreJobId', 'swmRestorePulledAt',
  ]) delete staleRecord[field];
  staleRecord.status = 'publishing';
  staleRecord.publishMode = 'sync';
  staleRecord.publishStartedAt = '2026-01-01T00:00:00.000Z';

  const chainRegistryPath = join(temp, 'chain-registry.json');
  const chainProgressPath = join(temp, 'chain-progress.json');
  writeFileSync(chainRegistryPath, `${JSON.stringify(staleRegistry, null, 2)}\n`);
  staleVmStatus = true;
  synchronousPublish = false;
  const callsBeforeChainReconcile = { ...calls };
  const chainReconcile = await run('publish.mjs', ['--publish', '--confirm', confirmation], {
    ...env,
    KC_VM_PUBLISH_MODE: 'sync',
    KC_REGISTRY_PATH: chainRegistryPath,
    KC_PROGRESS_PATH: chainProgressPath,
  });
  assert.equal(chainReconcile.code, 0, chainReconcile.stderr);
  assert.equal(synchronousPublish, false, 'chain reconciliation replayed the paid endpoint');
  assert.deepEqual(calls, callsBeforeChainReconcile, 'chain reconciliation replayed a mutating operation');
  const chainRegistry = JSON.parse(readFileSync(chainRegistryPath, 'utf8'));
  assert.equal(chainRegistry.batches['batch-001'].status, 'finalized');
  assert.equal(chainRegistry.batches['batch-001'].chainKaId, staleKaId);
  assert.equal(chainRegistry.batches['batch-001'].chainMerkleRoot, `0x${staleAssertion}`);
  assert.equal(chainRegistry.batches['batch-001'].vmVerifiedSubjectCount, 2);
  assert.equal(chainRegistry.batches['batch-001'].dkgFinalizationMode, 'published-chain-reconciled');

  const collisionRegistryPath = join(temp, 'collision-registry.json');
  const collisionProgressPath = join(temp, 'collision-progress.json');
  writeFileSync(collisionRegistryPath, `${JSON.stringify(staleRegistry, null, 2)}\n`);
  chainMerkleRoot = `0x${'cd'.repeat(32)}`;
  const collision = await run('publish.mjs', ['--publish', '--confirm', confirmation], {
    ...env,
    KC_VM_PUBLISH_MODE: 'sync',
    KC_REGISTRY_PATH: collisionRegistryPath,
    KC_PROGRESS_PATH: collisionProgressPath,
  });
  assert.notEqual(collision.code, 0, 'different on-chain assertion unexpectedly reconciled');
  assert.match(collision.stderr, /already published with a different assertion/);
  assert.deepEqual(calls, callsBeforeChainReconcile, 'collision check reached a mutating operation');

  const explicitRegistryPath = join(temp, 'explicit-registry.json');
  const explicitProgressPath = join(temp, 'explicit-progress.json');
  writeFileSync(explicitRegistryPath, `${JSON.stringify(staleRegistry, null, 2)}\n`);
  chainMerkleRoot = `0x${staleAssertion}`;
  missingLifecycleStamp = true;
  includeTrustLevel = true;
  const callsBeforeExplicitReconcile = { ...calls };
  const explicitReconcile = await run('publish.mjs', ['--publish', '--confirm', confirmation], {
    ...env,
    KC_VM_PUBLISH_MODE: 'sync',
    KC_SWM_RESTORE_MODE: 'skip',
    KC_CONFIRMED_VM_RECOVERIES: JSON.stringify({
      'batch-001': {
        ual: `did:dkg:base:8453/0x2222222222222222222222222222222222222222/${staleKaId}`,
        txHash: `0x${'12'.repeat(32)}`,
        blockNumber: 456,
      },
    }),
    KC_REGISTRY_PATH: explicitRegistryPath,
    KC_PROGRESS_PATH: explicitProgressPath,
  });
  assert.equal(explicitReconcile.code, 0, explicitReconcile.stderr);
  assert.equal(synchronousPublish, false, 'explicit reconciliation replayed the paid endpoint');
  assert.deepEqual(calls, callsBeforeExplicitReconcile, 'explicit reconciliation replayed a mutating operation');
  const explicitRegistry = JSON.parse(readFileSync(explicitRegistryPath, 'utf8'));
  assert.equal(explicitRegistry.batches['batch-001'].status, 'finalized');
  assert.equal(explicitRegistry.batches['batch-001'].chainKaId, staleKaId);
  assert.equal(explicitRegistry.batches['batch-001'].vmVerificationMode, 'exact-with-dkg-trust-level');
  assert.equal(explicitRegistry.batches['batch-001'].vmVerifiedSubjectCount, 2);
  assert.equal(explicitRegistry.batches['batch-001'].swmRestoreMode, 'skipped-vm-only');
  missingLifecycleStamp = false;
  includeTrustLevel = false;

  const membershipRegistryPath = join(temp, 'membership-registry.json');
  const membershipProgressPath = join(temp, 'membership-progress.json');
  staleVmStatus = false;
  membershipChanges = true;
  participantReads = 0;
  const callsBeforeMembershipChange = { ...calls };
  const membershipChange = await run('publish.mjs', ['--publish', '--confirm', confirmation], {
    ...env,
    KC_REGISTRY_PATH: membershipRegistryPath,
    KC_PROGRESS_PATH: membershipProgressPath,
  });
  assert.notEqual(membershipChange.code, 0, 'changed private-CG membership unexpectedly published');
  assert.match(membershipChange.stderr, /membership changed during the publishing run/);
  assert.equal(calls.publish, callsBeforeMembershipChange.publish, 'membership change reached the paid endpoint');
  assert.equal(calls.share, callsBeforeMembershipChange.share, 'membership change reached SWM sharing');
  assert.equal(calls.create, callsBeforeMembershipChange.create + 1, 'membership guard did not stop at the expected boundary');
  console.log('publisher integration smoke test: PASS');
} finally {
  await new Promise((resolvePromise) => server.close(resolvePromise));
  rmSync(temp, { recursive: true, force: true });
}
