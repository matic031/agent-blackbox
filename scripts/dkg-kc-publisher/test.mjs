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
const cg = '0xtest/private-blackbox';
let accessPolicy = 1;
let publishState = 'finalized';
let rejectCreateStatus;
let synchronousPublish = false;
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

const server = createServer((request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1');
  if (request.method === 'GET' && url.pathname === '/api/status') return json(response, 200, { name: 'fixture', version: '10.0.6', networkConfig: 'mainnet-base', connectedPeers: 3 });
  if (request.method === 'GET' && url.pathname === '/api/context-graph/exists') return json(response, 200, { id: cg, exists: true });
  if (request.method === 'GET' && url.pathname === '/api/context-graph/list') return json(response, 200, { contextGraphs: [{ id: cg, accessPolicy, onChainId: '13' }] });
  if (request.method === 'GET' && url.pathname.endsWith('/participants')) return json(response, 200, { contextGraphId: cg, allowedAgents: ['0xtest'] });
  if (request.method === 'GET' && url.pathname === '/api/wallets/balances') return json(response, 200, {
    chainId: 'base:8453',
    rpcUrl: 'https://rpc.example/private-provider-secret',
    wallets: ['0xtest'],
    balances: [{ address: '0xtest', eth: '1', trac: '10000' }],
  });
  if (request.method === 'GET' && url.pathname === '/api/publisher/stats') return json(response, 200, { accepted: 0, finalized: 0, failed: 0 });
  if (request.method === 'POST' && url.pathname === '/api/knowledge-assets') {
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
    return json(response, 200, { jobId: `share-${calls.share}`, state: 'queued' });
  }
  if (request.method === 'GET' && url.pathname.startsWith('/api/knowledge-assets/swm/share-jobs/share-')) {
    return json(response, 200, { jobId: url.pathname.split('/').at(-1), state: 'succeeded', result: { promotedCount: 2 } });
  }
  if (request.method === 'POST' && url.pathname.endsWith('/wm/pull-from')) {
    calls.pull += 1;
    return json(response, 200, { wmDraft: 'open', seededFrom: { layer: 'vm' } });
  }
  if (request.method === 'GET' && url.pathname.endsWith('/swm/quads')) {
    const batch = JSON.parse(readFileSync(join(batches, 'batch-001.json')));
    return json(response, 200, { quads: batch.records.flatMap(recordQuads) });
  }
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
    dependencies: [{ type: 'dependency', ecosystem: 'npm', name: 'Example-Package', version: '1.0.0', title: 'fixture dependency' }],
    iocs: [{ type: 'ioc', ioc_type: 'domain', value: 'EVIL.EXAMPLE.', threat: 'fixture IOC' }],
  }));

  const chunk = await run('chunk.mjs', [sourcePath, '--size', '2', '--expect-records', '2', '--out-dir', batches]);
  assert.equal(chunk.code, 0, chunk.stderr);
  const dry = await run('publish.mjs', ['--dry-run'], { KC_BATCH_DIR: batches, KC_EXPECT_RECORDS: '2', KC_PROGRESS_PATH: progressPath });
  assert.equal(dry.code, 0, dry.stderr);

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
  console.log('publisher integration smoke test: PASS');
} finally {
  await new Promise((resolvePromise) => server.close(resolvePromise));
  rmSync(temp, { recursive: true, force: true });
}
