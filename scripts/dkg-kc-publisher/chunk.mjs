#!/usr/bin/env node
/**
 * Chunker — slice a source file into deterministic N-record batch files under
 * batches/, deduplicated globally by recordKey() so no rootEntity ever repeats
 * across collections (the publish validator rejects that).
 *
 * Usage:
 *   node chunk.mjs <source.json> [--size 1000] [--max-batches 0]
 *
 * Re-running with the same source produces identical batches, so it composes
 * with the publisher's resumable ledger.
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { recordKey, extractRecords } from './mapping.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const src = argv.find((a) => !a.startsWith('--'));
const flag = (name, dflt) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? Number(argv[i + 1]) : dflt;
};
const SIZE = flag('size', 1000);
const MAX = flag('max-batches', 0); // 0 = all

if (!src) { console.error('usage: node chunk.mjs <source.json> [--size 1000] [--max-batches 0]'); process.exit(1); }

console.log('reading', src, '...');
const records = extractRecords(JSON.parse(readFileSync(src, 'utf8')));
console.log(`source: ${records.length} records`);

const outDir = join(here, 'batches');
mkdirSync(outDir, { recursive: true });

const seen = new Set();
let batch = [], n = 0, dupes = 0;
const flush = () => {
  if (!batch.length) return false;
  n += 1;
  const name = `batch-${String(n).padStart(3, '0')}`;
  writeFileSync(join(outDir, `${name}.json`), JSON.stringify({ name, records: batch }));
  console.log(`${name}: ${batch.length} records`);
  batch = [];
  return MAX > 0 && n >= MAX;
};

for (const r of records) {
  const k = recordKey(r);
  if (seen.has(k)) { dupes += 1; continue; }
  seen.add(k);
  batch.push(r);
  if (batch.length === SIZE && flush()) break;
}
if (!(MAX > 0 && n >= MAX)) flush(); // trailing partial batch

console.log(`done: ${n} batches, ${seen.size} unique records, ${dupes} duplicates skipped`);
