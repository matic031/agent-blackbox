#!/usr/bin/env node
import { chmodSync, readFileSync, renameSync, writeFileSync } from 'node:fs';

const file = process.argv[2];
if (!file) throw new Error('usage: node configure-dkg-throughput.mjs /path/to/config.json');

const config = JSON.parse(readFileSync(file, 'utf8'));
config.promoteQueue = {
  ...(config.promoteQueue ?? {}),
  workerConcurrency: 1,
  pollIntervalMs: 1000,
};

const temporary = `${file}.throughput.tmp`;
writeFileSync(temporary, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
chmodSync(temporary, 0o600);
renameSync(temporary, file);
process.stdout.write(`configured DKG promote worker throughput: ${file}\n`);
