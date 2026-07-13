#!/usr/bin/env node
/**
 * Local caching JSON-RPC proxy for Base mainnet — shields the DKG node from
 * public-RPC rate limits (429s) that blow its hard-coded 2.5s chain-read
 * budget.
 *
 *  - short-TTL cache for READ-ONLY methods only (eth_call, blockNumber, ...);
 *    tx submission, nonces, gas estimates are ALWAYS forwarded fresh
 *  - in-flight dedup: identical concurrent reads share one upstream request
 *  - upstream rotation with per-endpoint cooldown on 429/5xx/timeouts
 *
 * Listens on 127.0.0.1:8547. Point the node's chain.rpcUrl here.
 */
import { createServer } from 'node:http';

const PORT = 8547;
const UPSTREAMS = [
  'https://base.drpc.org',
  'https://base-rpc.publicnode.com',
  'https://mainnet.base.org',
  'https://base.meowrpc.com',
];

// method -> cache TTL ms. Anything not listed is never cached.
const CACHE_TTL = {
  eth_chainId: 3_600_000,
  net_version: 3_600_000,
  eth_blockNumber: 2_000,
  eth_call: 15_000,
  eth_getCode: 300_000,
  eth_getLogs: 5_000,
  eth_getBlockByNumber: 5_000,
  eth_feeHistory: 5_000,
  eth_gasPrice: 5_000,
  eth_maxPriorityFeePerGas: 5_000,
};

const cache = new Map();      // key -> { expires, value }
const inflight = new Map();   // key -> Promise
const cooldown = new Map();   // upstream -> notBeforeTs

async function callUpstream(payload) {
  const body = JSON.stringify(payload);
  let lastErr;
  for (let round = 0; round < 2; round++) {
    for (const u of UPSTREAMS) {
      if ((cooldown.get(u) ?? 0) > Date.now()) continue;
      try {
        const res = await fetch(u, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body,
          signal: AbortSignal.timeout(8_000),
        });
        if (res.status === 429 || res.status >= 500) {
          cooldown.set(u, Date.now() + 20_000);
          lastErr = new Error(`${u}: HTTP ${res.status}`);
          continue;
        }
        const json = await res.json();
        // JSON-RPC-level throttle answers also mean "rotate"
        if (json?.error && /too many|rate|limit/i.test(String(json.error.message ?? ''))) {
          cooldown.set(u, Date.now() + 20_000);
          lastErr = new Error(`${u}: rpc throttle: ${json.error.message}`);
          continue;
        }
        return json;
      } catch (e) {
        cooldown.set(u, Date.now() + 10_000);
        lastErr = e;
      }
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw lastErr ?? new Error('all upstreams failed');
}

async function handleOne(req) {
  const ttl = CACHE_TTL[req.method];
  if (!ttl) {
    const r = await callUpstream(req);
    return { ...r, id: req.id };
  }
  const key = `${req.method}:${JSON.stringify(req.params ?? [])}`;
  const hit = cache.get(key);
  if (hit && hit.expires > Date.now()) return { ...hit.value, id: req.id };
  if (inflight.has(key)) {
    const value = await inflight.get(key);
    return { ...value, id: req.id };
  }
  const p = (async () => {
    const value = await callUpstream(req);
    if (!value.error) cache.set(key, { expires: Date.now() + ttl, value });
    return value;
  })();
  inflight.set(key, p);
  try {
    const value = await p;
    return { ...value, id: req.id };
  } finally {
    inflight.delete(key);
  }
}

const server = createServer((req, res) => {
  if (req.method !== 'POST') { res.writeHead(405).end(); return; }
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', async () => {
    try {
      const parsed = JSON.parse(body);
      const out = Array.isArray(parsed)
        ? await Promise.all(parsed.map(handleOne))
        : await handleOne(parsed);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(out));
    } catch (e) {
      res.writeHead(200, { 'content-type': 'application/json' });
      const id = (() => { try { return JSON.parse(body)?.id ?? null; } catch { return null; } })();
      res.end(JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32603, message: `proxy: ${e.message}` } }));
    }
  });
});

server.listen(PORT, '127.0.0.1', () => console.log(`base rpc proxy on http://127.0.0.1:${PORT} -> ${UPSTREAMS.length} upstreams`));
