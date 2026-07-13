#!/usr/bin/env node
/**
 * Deterministically split a source bundle into globally-deduplicated batches.
 * Output is built in a staging directory and swapped into place only after the
 * complete manifest has been written, so a failed rebuild cannot leave a mix
 * of old and new collections.
 */
import { createHash } from 'node:crypto';
import {
  mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractRecords, recordKey } from './mapping.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const positional = argv.filter((value, index) => !value.startsWith('--') && (index === 0 || !argv[index - 1].startsWith('--')));
const sourceArg = positional[0];

function option(name, fallback) {
  const index = argv.indexOf(`--${name}`);
  return index === -1 ? fallback : argv[index + 1];
}

function positiveInteger(name, value, { allowZero = false } = {}) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < (allowZero ? 0 : 1)) {
    throw new Error(`--${name} must be ${allowZero ? 'a non-negative' : 'a positive'} integer; got ${value}`);
  }
  return parsed;
}

function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

if (!sourceArg) {
  console.error('usage: node chunk.mjs <source.json> [--size 1000] [--max-batches 0] [--expect-records 460000] [--out-dir batches]');
  process.exit(1);
}

const source = resolve(sourceArg);
const size = positiveInteger('size', option('size', '1000'));
const maxBatches = positiveInteger('max-batches', option('max-batches', '0'), { allowZero: true });
const expectedRecordsRaw = option('expect-records', undefined);
const expectedRecords = expectedRecordsRaw === undefined ? undefined : positiveInteger('expect-records', expectedRecordsRaw);
const outDir = resolve(option('out-dir', join(here, 'batches')));
const stagingDir = `${outDir}.staging-${process.pid}`;
const backupDir = `${outDir}.backup-${process.pid}`;

rmSync(stagingDir, { recursive: true, force: true });
rmSync(backupDir, { recursive: true, force: true });
mkdirSync(stagingDir, { recursive: true });

try {
  console.log(`[prepare] reading ${source}`);
  const sourceBytes = readFileSync(source);
  const records = extractRecords(JSON.parse(sourceBytes.toString('utf8')));
  if (!Array.isArray(records)) throw new Error('mapping.extractRecords() must return an array');
  console.log(`[prepare] source records: ${records.length.toLocaleString()}`);

  const seen = new Set();
  const batches = [];
  let batchRecords = [];
  let duplicateRecords = 0;

  const flush = () => {
    if (batchRecords.length === 0) return false;
    const number = batches.length + 1;
    const name = `batch-${String(number).padStart(3, '0')}`;
    const file = `${name}.json`;
    const body = JSON.stringify({ name, records: batchRecords });
    writeFileSync(join(stagingDir, file), body);
    batches.push({ name, file, records: batchRecords.length, bytes: Buffer.byteLength(body), sha256: sha256(body) });
    console.log(`[prepare] ${name}: ${batchRecords.length.toLocaleString()} records`);
    batchRecords = [];
    return maxBatches > 0 && batches.length >= maxBatches;
  };

  for (const record of records) {
    const key = recordKey(record);
    if (typeof key !== 'string' || key.length === 0) throw new Error('mapping.recordKey() returned an empty/non-string key');
    if (seen.has(key)) {
      duplicateRecords += 1;
      continue;
    }
    seen.add(key);
    batchRecords.push(record);
    if (batchRecords.length === size && flush()) break;
  }
  if (!(maxBatches > 0 && batches.length >= maxBatches)) flush();

  const includedRecords = batches.reduce((sum, batch) => sum + batch.records, 0);
  const complete = maxBatches === 0 || includedRecords === seen.size;
  if (expectedRecords !== undefined && includedRecords !== expectedRecords) {
    throw new Error(`record-count contract failed: expected ${expectedRecords.toLocaleString()}, prepared ${includedRecords.toLocaleString()}`);
  }

  const mappingPath = join(here, 'mapping.mjs');
  const manifest = {
    version: 1,
    createdAt: new Date().toISOString(),
    source: {
      file: basename(source),
      bytes: statSync(source).size,
      sha256: sha256(sourceBytes),
      records: records.length,
    },
    mapping: { file: 'mapping.mjs', sha256: sha256(readFileSync(mappingPath)) },
    batchSize: size,
    maxBatches,
    complete,
    uniqueRecords: seen.size,
    includedRecords,
    duplicateRecords,
    batchCount: batches.length,
    batches,
  };
  writeFileSync(join(stagingDir, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);

  let movedOld = false;
  try {
    try {
      renameSync(outDir, backupDir);
      movedOld = true;
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    renameSync(stagingDir, outDir);
    if (movedOld) rmSync(backupDir, { recursive: true, force: true });
  } catch (error) {
    if (movedOld) {
      rmSync(outDir, { recursive: true, force: true });
      renameSync(backupDir, outDir);
    }
    throw error;
  }

  console.log(`[prepare] done: ${batches.length} batches, ${includedRecords.toLocaleString()} records, ${duplicateRecords.toLocaleString()} duplicates`);
  console.log(`[prepare] manifest: ${join(outDir, 'manifest.json')}`);
} catch (error) {
  rmSync(stagingDir, { recursive: true, force: true });
  rmSync(backupDir, { recursive: true, force: true });
  console.error(`[prepare] FATAL: ${error?.stack ?? error}`);
  process.exit(1);
}
