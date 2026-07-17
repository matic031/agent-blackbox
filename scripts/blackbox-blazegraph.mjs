#!/usr/bin/env node

import { access } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

function fail(message) {
  process.stderr.write(`Blazegraph setup failed: ${message}\n`);
  process.exit(1);
}

const args = process.argv.slice(2);
const healthCheck = args[0] === 'check';
const [dkgCheckout, namespace, portText] = healthCheck ? args.slice(1) : args;
if (!dkgCheckout || !namespace) {
  fail('usage: blackbox-blazegraph.mjs <dkg-checkout> <namespace> [preferred-port]');
}

if (healthCheck) {
  const dkgRoot = path.resolve(dkgCheckout);
  const modulePaths = [
    path.join(
      dkgRoot,
      'node_modules',
      '@origintrail-official',
      'dkg',
      'dist',
      'daemon',
      'store-health-check.js',
    ),
    path.join(dkgRoot, 'packages', 'cli', 'dist', 'daemon', 'store-health-check.js'),
  ];
  try {
    let modulePath;
    for (const candidate of modulePaths) {
      try {
        await access(candidate);
        modulePath = candidate;
        break;
      } catch {}
    }
    if (!modulePath) {
      throw new Error(`published DKG store health check not found under ${dkgRoot}`);
    }
    const { checkExternalStoreReachable, formatHealthCheckFailure } = await import(
      pathToFileURL(modulePath).href
    );
    const result = await checkExternalStoreReachable({
      storeConfig: { backend: 'blazegraph', options: { url: namespace } },
      timeoutMs: 10_000,
    });
    if (!result.ok) {
      throw new Error(formatHealthCheckFailure(result));
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
    process.exit(0);
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
}

const port = Number(portText || '9999');
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  fail(`invalid preferred port: ${portText}`);
}

const dkgRoot = path.resolve(dkgCheckout);
const modulePaths = [
  path.join(
    dkgRoot,
    'node_modules',
    '@origintrail-official',
    'dkg',
    'dist',
    'daemon',
    'blazegraph-docker.js',
  ),
  // Kept as a migration fallback so an interrupted custom-checkout install can
  // still explain itself cleanly before the npm package replaces it.
  path.join(dkgRoot, 'packages', 'cli', 'dist', 'daemon', 'blazegraph-docker.js'),
];

try {
  let modulePath;
  for (const candidate of modulePaths) {
    try {
      await access(candidate);
      modulePath = candidate;
      break;
    } catch {
      // Try the next supported install layout.
    }
  }
  if (!modulePath) {
    throw new Error(`published DKG Blazegraph provisioner not found under ${dkgRoot}`);
  }
  const { provisionBlazegraphDocker } = await import(pathToFileURL(modulePath).href);
  const result = await provisionBlazegraphDocker({
    namespace,
    port,
    pollTimeoutMs: 120_000,
    log: (message) => process.stderr.write(`${message}\n`),
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
