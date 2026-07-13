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

const server = createServer((request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1');
  if (request.method === 'GET' && url.pathname === '/api/status') return json(response, 200, { name: 'fixture', version: '10.0.5', networkConfig: 'mainnet-base', connectedPeers: 3 });
  if (request.method === 'GET' && url.pathname === '/api/context-graph/exists') return json(response, 200, { id: cg, exists: true });
  if (request.method === 'GET' && url.pathname === '/api/context-graph/list') return json(response, 200, { contextGraphs: [{ id: cg, accessPolicy }] });
  if (request.method === 'GET' && url.pathname === '/api/wallets/balances') return json(response, 200, { wallets: ['0xtest'], balances: [{ address: '0xtest', eth: '1', trac: '10000' }] });
  if (request.method === 'GET' && url.pathname === '/api/publisher/stats') return json(response, 200, { accepted: 0, finalized: 0, failed: 0 });
  if (request.method === 'POST' && url.pathname === '/api/knowledge-assets') {
    calls.create += 1;
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
  };

  accessPolicy = 0;
  const publicGraph = await run('publish.mjs', ['--preflight'], env);
  assert.notEqual(publicGraph.code, 0, 'public CG preflight unexpectedly succeeded');
  assert.match(publicGraph.stderr, /not verifiably private\/curated/);

  accessPolicy = 1;
  const preflight = await run('publish.mjs', ['--preflight'], env);
  assert.equal(preflight.code, 0, preflight.stderr);
  const manifestHash = createHash('sha256').update(readFileSync(join(batches, 'manifest.json'))).digest('hex');
  const confirmation = `${cg}:12:${manifestHash.slice(0, 12)}`;
  assert.match(preflight.stdout, new RegExp(confirmation.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  const publish = await run('publish.mjs', ['--publish', '--confirm', confirmation], env);
  assert.equal(publish.code, 0, publish.stderr);
  assert.deepEqual(calls, { create: 1, share: 1, publish: 1 });
  const registry = JSON.parse(readFileSync(registryPath, 'utf8'));
  assert.equal(registry.batches['batch-001'].txHash, '0xabc');
  assert.equal(registry.batches['batch-001'].epochs, 12);

  const resume = await run('publish.mjs', ['--publish', '--confirm', confirmation], env);
  assert.equal(resume.code, 0, resume.stderr);
  assert.deepEqual(calls, { create: 1, share: 1, publish: 1 }, 'resume replayed a paid/mutating operation');

  const wrongConfirmation = await run('publish.mjs', ['--publish', '--confirm', 'wrong-token'], env);
  assert.notEqual(wrongConfirmation.code, 0, 'wrong paid confirmation unexpectedly succeeded');
  assert.deepEqual(calls, { create: 1, share: 1, publish: 1 }, 'wrong confirmation reached a mutation');

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
  console.log('publisher integration smoke test: PASS');
} finally {
  await new Promise((resolvePromise) => server.close(resolvePromise));
  rmSync(temp, { recursive: true, force: true });
}
