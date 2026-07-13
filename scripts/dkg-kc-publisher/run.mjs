#!/usr/bin/env node
/** Single entrypoint for preparing, preflighting, publishing, and monitoring. */
import { createWriteStream, existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const here = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const command = argv[0];
const rest = argv.slice(1);
const option = (name, fallback) => {
  const index = rest.indexOf(`--${name}`);
  return index === -1 ? fallback : rest[index + 1];
};

function help() {
  console.error(`usage:
  node run.mjs prepare --source /path/prod-threats-400k.json
  KC_CG_ID=<id> node run.mjs preflight
  KC_CG_ID=<id> node run.mjs publish --confirm <token> [--batch batch-001 | --from-batch batch-001 --to-batch batch-460]
  node run.mjs status

prepare rebuilds all 460 checksummed collections and runs the complete dry-run.
preflight verifies the official npm node, private CG, network, wallets and prints
the paid confirmation token. publish resumes registry.json automatically.`);
}

function run(script, args, logStream) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, [join(here, script), ...args], {
      cwd: here,
      env: { ...process.env, NODE_OPTIONS: process.env.NODE_OPTIONS ?? '--max-old-space-size=4096' },
      stdio: ['inherit', 'pipe', 'pipe'],
    });
    for (const [stream, target] of [[child.stdout, process.stdout], [child.stderr, process.stderr]]) {
      stream.on('data', (chunk) => {
        target.write(chunk);
        logStream?.write(chunk);
      });
    }
    child.on('error', rejectPromise);
    child.on('exit', (code, signal) => {
      if (code === 0) resolvePromise();
      else rejectPromise(new Error(`${script} exited ${signal ? `on ${signal}` : `with code ${code}`}`));
    });
  });
}

function showStatus() {
  const progressPath = resolve(process.env.KC_PROGRESS_PATH ?? join(here, 'progress.json'));
  const registryPath = resolve(process.env.KC_REGISTRY_PATH ?? join(here, 'registry.json'));
  if (!existsSync(progressPath) && !existsSync(registryPath)) throw new Error('no progress.json or registry.json exists yet');
  if (existsSync(progressPath)) {
    const progress = JSON.parse(readFileSync(progressPath, 'utf8'));
    console.log(JSON.stringify(progress, null, 2));
  }
  if (existsSync(registryPath)) {
    const registry = JSON.parse(readFileSync(registryPath, 'utf8'));
    const records = Object.values(registry.batches ?? {});
    const counts = records.reduce((result, record) => {
      const status = record.status ?? 'unknown';
      result[status] = (result[status] ?? 0) + 1;
      return result;
    }, {});
    console.log(JSON.stringify({ registry: registryPath, meta: registry.meta, batchStatuses: counts, updatedAt: registry.updatedAt }, null, 2));
  }
}

async function main() {
  if (command === 'status') {
    showStatus();
    return;
  }
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const logPath = join(here, `${command ?? 'run'}-${stamp}.log`);
  const log = createWriteStream(logPath, { flags: 'a' });
  console.log(`durable log: ${logPath}`);
  try {
    if (command === 'prepare') {
      const source = option('source', null);
      if (!source) throw new Error('prepare requires --source <json>');
      const maxBatches = option('max-batches', '0');
      const expectRecords = maxBatches === '0' ? (process.env.KC_EXPECT_RECORDS ?? '460000') : option('expect-records', process.env.KC_EXPECT_RECORDS ?? '460000');
      await run('chunk.mjs', [resolve(source), '--size', option('size', '1000'), '--max-batches', maxBatches, '--expect-records', expectRecords], log);
      await run('publish.mjs', ['--dry-run'], log);
    } else if (command === 'preflight') {
      await run('publish.mjs', ['--preflight'], log);
    } else if (command === 'publish') {
      const confirmation = option('confirm', null);
      if (!confirmation) throw new Error('publish requires --confirm <token> from preflight');
      const args = ['--publish', '--confirm', confirmation];
      const batch = option('batch', null);
      if (batch) args.push('--batch', batch);
      const fromBatch = option('from-batch', null);
      if (fromBatch) args.push('--from-batch', fromBatch);
      const toBatch = option('to-batch', null);
      if (toBatch) args.push('--to-batch', toBatch);
      await run('publish.mjs', args, log);
    } else {
      help();
      process.exitCode = 1;
    }
  } finally {
    await new Promise((resolvePromise) => log.end(resolvePromise));
  }
}

main().catch((error) => {
  console.error(`FATAL: ${error?.stack ?? error}`);
  help();
  process.exit(1);
});
