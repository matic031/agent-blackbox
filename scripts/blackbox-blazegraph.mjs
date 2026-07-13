#!/usr/bin/env node

import { access } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

function fail(message) {
  process.stderr.write(`Blazegraph setup failed: ${message}\n`);
  process.exit(1);
}

const [dkgCheckout, namespace, portText] = process.argv.slice(2);
if (!dkgCheckout || !namespace) {
  fail('usage: blackbox-blazegraph.mjs <dkg-checkout> <namespace> [preferred-port]');
}

const port = Number(portText || '9999');
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  fail(`invalid preferred port: ${portText}`);
}

const modulePath = path.join(
  path.resolve(dkgCheckout),
  'packages',
  'cli',
  'dist',
  'daemon',
  'blazegraph-docker.js',
);

try {
  await access(modulePath);
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
