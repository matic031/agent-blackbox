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
const expectedPath = join(temp, 'expected-manifest.json');
const cg = '0xtest/private-blackbox';
let accessPolicy = 1;
let publishState = 'finalized';
let rejectCreateStatus;
let synchronousPublish = false;
let asyncPublisher = { available: true };
let publisherStats = { accepted: 0, finalized: 0, failed: 0 };
let lastCreateBody;
const calls = { create: 0, share: 0, publish: 0 };

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
  if (request.method === 'GET' && url.pathname === '/api/status') return json(response, 200, {
    name: 'fixture', version: '10.0.5', networkConfig: 'mainnet-base', connectedPeers: 3, asyncPublisher,
  });
  if (request.method === 'GET' && url.pathname === '/api/context-graph/exists') return json(response, 200, { id: cg, exists: true });
  if (request.method === 'GET' && url.pathname === '/api/context-graph/list') return json(response, 200, { contextGraphs: [{ id: cg, accessPolicy, onChainId: '13' }] });
  if (request.method === 'GET' && url.pathname.endsWith('/participants')) return json(response, 200, { contextGraphId: cg, allowedAgents: ['0xtest'] });
  if (request.method === 'GET' && url.pathname === '/api/wallets/balances') return json(response, 200, {
    chainId: 'base:8453',
    rpcUrl: 'https://rpc.example/private-provider-secret',
    wallets: ['0xtest'],
    balances: [{ address: '0xtest', eth: '1', trac: '10000' }],
  });
  if (request.method === 'GET' && url.pathname === '/api/publisher/stats') return json(response, 200, publisherStats);
  if (request.method === 'POST' && url.pathname === '/api/knowledge-assets') {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    lastCreateBody = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    calls.create += 1;
    if (rejectCreateStatus) {
      const status = rejectCreateStatus;
      rejectCreateStatus = undefined;
      const error = status === 400 ? 'Invalid "name": Assertion name cannot contain "/"' : 'fixture gateway limit';
      return json(response, status, { error });
    }
    return json(response, 201, { status: 'wm-sealed', assertionUri: 'urn:test:assertion' });
  }
  if (request.method === 'POST' && url.pathname.endsWith('/swm/share-async')) {
    calls.share += 1;
    return json(response, 200, { jobId: 'share-1', state: 'queued' });
  }
  if (request.method === 'GET' && url.pathname === '/api/knowledge-assets/swm/share-jobs/share-1') return json(response, 200, { jobId: 'share-1', state: 'succeeded' });
  if (request.method === 'POST' && url.pathname.endsWith('/vm/publish-async')) {
    calls.publish += 1;
    return json(response, 202, { jobId: 'publish-1', status: 'accepted' });
  }
  if (request.method === 'POST' && url.pathname.endsWith('/vm/publish')) {
    calls.publish += 1;
    synchronousPublish = true;
    return json(response, 200, { status: 'confirmed', txHash: '0xsync', ual: 'did:dkg:sync', blockNumber: 456 });
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
    dependencies: [{
      type: 'dependency', ecosystem: 'npm', name: 'Example-Package', version: '1.0.0',
      title: 'fixture dependency', references: ['https://duplicate.example', 'https://duplicate.example'],
    }],
    iocs: [{ type: 'ioc', ioc_type: 'domain', value: 'EVIL.EXAMPLE.', threat: 'fixture IOC' }],
  }));

  const chunk = await run('chunk.mjs', [sourcePath, '--size', '2', '--expect-records', '2', '--out-dir', batches]);
  assert.equal(chunk.code, 0, chunk.stderr);
  const dry = await run('publish.mjs', ['--dry-run'], {
    KC_BATCH_DIR: batches,
    KC_EXPECT_RECORDS: '2',
    KC_PROGRESS_PATH: progressPath,
    KC_EXPECTED_MANIFEST_PATH: expectedPath,
  });
  assert.equal(dry.code, 0, dry.stderr);
  const fixtureRecords = JSON.parse(readFileSync(join(batches, 'batch-001.json'), 'utf8')).records;
  const rawQuads = fixtureRecords.flatMap(recordQuads);
  const uniqueQuadKeys = new Set(rawQuads.map((quad) => JSON.stringify([
    quad.subject, quad.predicate, quad.object, '',
  ])));
  const expected = JSON.parse(readFileSync(expectedPath, 'utf8'));
  assert.equal(expected.batches[0].sourceQuads, rawQuads.length);
  assert.equal(expected.batches[0].quads, uniqueQuadKeys.size);
  assert.equal(expected.batches[0].duplicateQuadsRemoved, rawQuads.length - uniqueQuadKeys.size);
  assert.equal(expected.batches[0].duplicateQuadsRemoved, 1);

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

  asyncPublisher = {
    available: false,
    reason: 'publisher_disabled',
    retryable: false,
    operatorActionRequired: true,
  };
  const disabledPublisher = await run('publish.mjs', ['--preflight'], env);
  assert.notEqual(disabledPublisher.code, 0, 'async preflight unexpectedly accepted a disabled publisher');
  assert.match(disabledPublisher.stderr, /requires an available async publisher; node reports publisher_disabled/);
  assert.match(disabledPublisher.stderr, /dkg publisher enable/);
  asyncPublisher = { available: true };

  rejectCreateStatus = 413;
  const rejected = await run('publish.mjs', ['--publish', '--confirm', confirmation], env);
  assert.notEqual(rejected.code, 0, 'HTTP 413 unexpectedly produced success');
  assert.deepEqual(calls, { create: 1, share: 0, publish: 0 });
  const rejectedRegistry = JSON.parse(readFileSync(registryPath, 'utf8'));
  assert.equal(rejectedRegistry.batches['batch-001'].createStartedAt, undefined);
  assert.equal(rejectedRegistry.batches['batch-001'].lastError.status, 413);
  rejectedRegistry.batches['batch-001'].createStartedAt = '2026-01-01T00:00:00.000Z';
  writeFileSync(registryPath, `${JSON.stringify(rejectedRegistry, null, 2)}\n`);

  rejectCreateStatus = 400;
  const invalidName = await run('publish.mjs', ['--publish', '--confirm', confirmation], env);
  assert.notEqual(invalidName.code, 0, 'invalid assertion name unexpectedly produced success');
  assert.deepEqual(calls, { create: 2, share: 0, publish: 0 });
  const invalidNameRegistry = JSON.parse(readFileSync(registryPath, 'utf8'));
  assert.equal(invalidNameRegistry.batches['batch-001'].createStartedAt, undefined);
  assert.equal(invalidNameRegistry.batches['batch-001'].lastError.status, 400);

  const publish = await run('publish.mjs', ['--publish', '--confirm', confirmation], env);
  assert.equal(publish.code, 0, publish.stderr);
  assert.deepEqual(calls, { create: 3, share: 1, publish: 1 });
  assert.equal(lastCreateBody.quads.length, uniqueQuadKeys.size, 'create payload retained duplicate RDF triples');
  assert.equal(
    new Set(lastCreateBody.quads.map((quad) => JSON.stringify([
      quad.subject, quad.predicate, quad.object, quad.graph ?? '',
    ]))).size,
    lastCreateBody.quads.length,
    'create payload is not an RDF set',
  );
  const registry = JSON.parse(readFileSync(registryPath, 'utf8'));
  assert.equal(registry.batches['batch-001'].txHash, '0xabc');
  assert.equal(registry.batches['batch-001'].epochs, 12);

  const resume = await run('publish.mjs', ['--publish', '--confirm', confirmation], env);
  assert.equal(resume.code, 0, resume.stderr);
  assert.deepEqual(calls, { create: 3, share: 1, publish: 1 }, 'resume replayed a paid/mutating operation');

  const wrongConfirmation = await run('publish.mjs', ['--publish', '--confirm', 'wrong-token'], env);
  assert.notEqual(wrongConfirmation.code, 0, 'wrong paid confirmation unexpectedly succeeded');
  assert.deepEqual(calls, { create: 3, share: 1, publish: 1 }, 'wrong confirmation reached a mutation');

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

  const asyncAllRegistryPath = join(temp, 'async-all-registry.json');
  const asyncAllProgressPath = join(temp, 'async-all-progress.json');
  const publishesBeforeAsyncAll = calls.publish;
  publisherStats = { accepted: 1, finalized: 0, failed: 0 };
  setTimeout(() => { publisherStats = { accepted: 0, finalized: 1, failed: 0 }; }, 1_100);
  const asyncAllPublish = await run('publish.mjs', ['--publish', '--confirm', confirmation], {
    ...env,
    KC_VM_PUBLISH_MODE: 'async-all',
    KC_VM_MAX_INFLIGHT: '1',
    KC_REGISTRY_PATH: asyncAllRegistryPath,
    KC_PROGRESS_PATH: asyncAllProgressPath,
  });
  assert.equal(asyncAllPublish.code, 0, asyncAllPublish.stderr);
  assert.match(asyncAllPublish.stdout, /publisher backpressure: 1\/1 jobs in flight/);
  assert.equal(calls.publish, publishesBeforeAsyncAll + 1);
  const asyncAllRegistry = JSON.parse(readFileSync(asyncAllRegistryPath, 'utf8'));
  assert.equal(asyncAllRegistry.batches['batch-001'].txHash, '0xabc');
  assert.equal(asyncAllRegistry.batches['batch-001'].status, 'finalized');
  const asyncAllProgress = JSON.parse(readFileSync(asyncAllProgressPath, 'utf8'));
  assert.equal(asyncAllProgress.status, 'complete');
  assert.equal(asyncAllProgress.completedBatches, 1);
  console.log('publisher integration smoke test: PASS');
} finally {
  await new Promise((resolvePromise) => server.close(resolvePromise));
  rmSync(temp, { recursive: true, force: true });
}
