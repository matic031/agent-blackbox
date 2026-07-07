/**
 * Client-side OSV vulnerability lookup for dependency auto-discovery.
 *
 * A tiny, dependency-free helper around `https://api.osv.dev/v1/query` using the
 * global `fetch` (Node >=18). It is the DISCOVERY nomination layer for
 * dependencies: when an install is detected whose package is NOT already in the
 * graph ruleset, `lookup` asks OSV whether that exact `package@version` is
 * known-vulnerable. If so, the caller auto-submits a candidate dependency threat.
 *
 * Faithful port of `plugins/blackbox/osv.py`. Design constraints:
 *   - global `fetch` only — no new runtime dependency.
 *   - fail-open — any transport/parse error resolves to null (no finding).
 *   - short timeout — never delays the agent loop meaningfully.
 *   - privacy — only OSV-*vulnerable* installs are ever surfaced; a clean
 *     package resolves to null and is never reported.
 *   - cached — an in-memory dedupe cache keyed by `eco:name@version` so a
 *     repeated install in the same process makes at most one network call.
 */
import type { OsvHit } from "./detection.js";
import type { BlackboxSeverity } from "./quads.js";

const OSV_URL = "https://api.osv.dev/v1/query";
const TIMEOUT_MS = 3000;

/**
 * Blackbox ecosystem slug → OSV ecosystem name. `homebrew` has no OSV
 * ecosystem, so it is intentionally absent (skipped, never looked up).
 */
const ECOSYSTEM_MAP: Record<string, string> = {
  npm: "npm",
  pypi: "PyPI",
  cargo: "crates.io",
  rubygems: "RubyGems",
};

// In-memory result cache. Value is the OsvHit or null (clean/skip).
const cache = new Map<string, OsvHit | null>();

/** Map a Blackbox ecosystem slug to its OSV name, or null to skip. */
export function osvEcosystem(ecosystem: string): string | null {
  return ECOSYSTEM_MAP[(ecosystem || "").trim().toLowerCase()] ?? null;
}

/** Best-effort severity from an OSV vuln record (defaults to `high`). */
function severityOf(vuln: Record<string, unknown>): BlackboxSeverity {
  const dbs = vuln.database_specific;
  if (dbs && typeof dbs === "object") {
    const raw = String((dbs as Record<string, unknown>).severity ?? "").trim().toLowerCase();
    if (raw) return raw as BlackboxSeverity;
  }
  const affected = Array.isArray(vuln.affected) ? vuln.affected : [];
  for (const aff of affected) {
    if (aff && typeof aff === "object") {
      const affDbs = (aff as Record<string, unknown>).database_specific;
      if (affDbs && typeof affDbs === "object") {
        const raw = String((affDbs as Record<string, unknown>).severity ?? "").trim().toLowerCase();
        if (raw) return raw as BlackboxSeverity;
      }
    }
  }
  return "high";
}

async function query(
  osvEco: string,
  name: string,
  version: string,
): Promise<Record<string, unknown> | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(OSV_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ package: { ecosystem: osvEco, name }, version }),
      signal: controller.signal,
    });
    if (!res.ok) return null;
    return (await res.json()) as Record<string, unknown>;
  } catch {
    return null; // fail open
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Return `{advisoryId, severity}` if OSV knows `name@version` vulnerable.
 * Resolves to null when the package is clean, the ecosystem is unsupported, the
 * version is missing, or anything fails (fail-open). Cached per process.
 * Port of Python `osv.lookup`.
 */
export async function lookup(
  ecosystem: string,
  name: string,
  version: string,
): Promise<OsvHit | null> {
  const eco = (ecosystem || "").trim().toLowerCase();
  const pkg = (name || "").trim();
  const ver = (version || "").trim();
  if (!pkg || !ver) return null;
  const osvEco = osvEcosystem(eco);
  if (!osvEco) return null;
  const key = `${eco}:${pkg.toLowerCase()}@${ver}`;
  if (cache.has(key)) return cache.get(key) ?? null;
  let result: OsvHit | null = null;
  const data = await query(osvEco, pkg, ver);
  if (data && typeof data === "object") {
    const vulns = (data as Record<string, unknown>).vulns;
    if (Array.isArray(vulns) && vulns.length > 0) {
      const first = (vulns[0] && typeof vulns[0] === "object" ? vulns[0] : {}) as Record<
        string,
        unknown
      >;
      const advisoryId = String(first.id ?? "OSV");
      result = { advisoryId, severity: severityOf(first) };
    }
  }
  cache.set(key, result);
  return result;
}
