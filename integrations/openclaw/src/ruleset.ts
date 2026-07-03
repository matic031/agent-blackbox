/**
 * Graph-synced rule cache.
 *
 * The ruleset is the ONLY source of detection truth. We SPARQL the local DKG
 * node for curated `g:Threat` nodes, normalize them into a `Ruleset`, and cache
 * to a JSON file under the OpenClaw state dir with a TTL. On an empty graph the
 * ruleset is empty and the matcher detects nothing — by design.
 *
 * Fail-open: if the node is unreachable we keep serving the last cached (or
 * empty) ruleset and try again after the TTL.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { DkgClient, DkgError } from "./dkgClient.js";
import {
  DependencyRule,
  EscalationRule,
  FileAccessRule,
  InjectionRule,
  Ruleset,
  SkillRule,
  emptyRuleset,
} from "./detection.js";
import {
  GUARDIAN_ARG_SHAPE_PRED,
  GUARDIAN_CATEGORY_PRED,
  GUARDIAN_CURATED_PRED,
  GUARDIAN_DANGER_SHAPE_PRED,
  GUARDIAN_IDENTIFIER_PRED,
  GUARDIAN_OWASP_CATEGORY_PRED,
  GUARDIAN_PACKAGE_ECOSYSTEM_PRED,
  GUARDIAN_PACKAGE_NAME_PRED,
  GUARDIAN_PACKAGE_VERSION_PRED,
  GUARDIAN_PATTERN_PRED,
  GUARDIAN_SEVERITY_PRED,
  GUARDIAN_SKILL_NAME_PRED,
  GUARDIAN_SKILL_VERSION_PRED,
  GUARDIAN_THREAT_TYPE_IRI,
  GUARDIAN_TOOL_NAME_PRED,
  SCHEMA_DESCRIPTION,
  SCHEMA_NAME,
  normalizeSeverity,
} from "./quads.js";

const SCHEMA_ADVISORY = "http://schema.org/identifier";

/** SPARQL that pulls every curated threat's fields as subject/predicate/object rows. */
function rulesetQuery(): string {
  return `
SELECT ?s ?p ?o WHERE {
  ?s <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <${GUARDIAN_THREAT_TYPE_IRI}> .
  ?s <${GUARDIAN_CURATED_PRED}> "true" .
  ?s ?p ?o .
}`.trim();
}

export function resolveStateDir(explicit?: string): string {
  if (explicit) return explicit;
  const base =
    process.env.OPENCLAW_STATE_DIR ||
    process.env.OPENCLAW_HOME ||
    join(homedir(), ".openclaw");
  return join(base, "guardian");
}

/** Extract SPARQL SELECT bindings from the node's response envelope, tolerantly.
 * The v10 node nests them under ``result.bindings`` (singular); older/other
 * shapes use ``results.bindings`` or a top-level ``bindings``. */
function extractBindings(resp: unknown): Array<Record<string, unknown>> {
  const r = resp as Record<string, unknown> | null;
  const container = (r?.result ?? r?.results ?? r) as Record<string, unknown> | undefined;
  const bindings =
    (container as { bindings?: unknown })?.bindings ?? (r as { bindings?: unknown })?.bindings;
  return Array.isArray(bindings) ? (bindings as Array<Record<string, unknown>>) : [];
}

/** Unwrap a binding value: ``{value}`` object, a quoted N-Triples literal
 * (``"x"``, ``"x"^^<type>``, ``"x"@lang``), or a bare IRI/string. */
function bindingValue(v: unknown): string | undefined {
  if (v == null) return undefined;
  if (typeof v === "object" && "value" in (v as Record<string, unknown>)) {
    return String((v as { value: unknown }).value);
  }
  const s = String(v);
  const m = s.match(/^"([\s\S]*)"(?:\^\^.*|@.*)?$/);
  return m ? m[1] : s;
}

interface ThreatAccum {
  identifier?: string;
  severity?: string;
  name?: string;
  pattern?: string;
  owaspCategory?: string;
  toolName?: string;
  argShape?: string;
  packageName?: string;
  packageVersion?: string;
  packageEcosystem?: string;
  advisoryId?: string;
  // fileaccess
  category?: string;
  // skill
  skillName?: string;
  skillVersion?: string;
  dangerShape?: string;
}

function normalizeThreats(resp: unknown): Ruleset {
  const bySubject = new Map<string, ThreatAccum>();
  for (const b of extractBindings(resp)) {
    const s = bindingValue(b.s);
    const p = bindingValue(b.p);
    const o = bindingValue(b.o);
    if (!s || !p || o === undefined) continue;
    const acc = bySubject.get(s) ?? {};
    switch (p) {
      case GUARDIAN_IDENTIFIER_PRED: acc.identifier = o; break;
      case GUARDIAN_SEVERITY_PRED: acc.severity = o; break;
      case SCHEMA_NAME: acc.name ??= o; break;
      case SCHEMA_DESCRIPTION: acc.name ??= o; break;
      case GUARDIAN_PATTERN_PRED: acc.pattern = o; break;
      case GUARDIAN_OWASP_CATEGORY_PRED: acc.owaspCategory = o; break;
      case GUARDIAN_TOOL_NAME_PRED: acc.toolName = o; break;
      case GUARDIAN_ARG_SHAPE_PRED: acc.argShape = o; break;
      case GUARDIAN_PACKAGE_NAME_PRED: acc.packageName = o; break;
      case GUARDIAN_PACKAGE_VERSION_PRED: acc.packageVersion = o; break;
      case GUARDIAN_PACKAGE_ECOSYSTEM_PRED: acc.packageEcosystem = o; break;
      case SCHEMA_ADVISORY: acc.advisoryId = o; break;
      case GUARDIAN_CATEGORY_PRED: acc.category = o; break;
      case GUARDIAN_SKILL_NAME_PRED: acc.skillName = o; break;
      case GUARDIAN_SKILL_VERSION_PRED: acc.skillVersion = o; break;
      case GUARDIAN_DANGER_SHAPE_PRED: acc.dangerShape = o; break;
      default: break;
    }
    bySubject.set(s, acc);
  }

  const ruleset = emptyRuleset();
  ruleset.fetchedAt = Date.now();
  for (const acc of bySubject.values()) {
    if (!acc.identifier) continue;
    const severity = normalizeSeverity(acc.severity, "medium");
    const name = acc.name || acc.identifier;
    if (acc.identifier.startsWith("injection:") && acc.pattern) {
      const rule: InjectionRule = {
        identifier: acc.identifier,
        pattern: acc.pattern,
        severity,
        name,
        owaspCategory: acc.owaspCategory,
      };
      ruleset.injection.push(rule);
    } else if (acc.identifier.startsWith("escalation:") && acc.toolName && acc.argShape) {
      const rule: EscalationRule = {
        identifier: acc.identifier,
        toolName: acc.toolName,
        argShape: acc.argShape,
        severity,
        name,
      };
      ruleset.escalation.push(rule);
    } else if (acc.identifier.startsWith("dep:") && acc.packageName && acc.packageVersion) {
      const eco = (acc.packageEcosystem || "").toLowerCase();
      const key = `${eco}:${acc.packageName.toLowerCase()}@${acc.packageVersion}`;
      const rule: DependencyRule = {
        identifier: acc.identifier,
        severity,
        advisoryId: acc.advisoryId,
        name,
      };
      ruleset.dependency[key] = rule;
    } else if (acc.identifier.startsWith("fileaccess:")) {
      // Prefer explicit predicates; fall back to parsing fileaccess:{tool}:{category}.
      let toolName = acc.toolName;
      let category = acc.category;
      if (!toolName || !category) {
        const parts = acc.identifier.split(":");
        // ["fileaccess", tool, category] — mirror Python identifier.split(":", 2).
        if (parts.length >= 3) {
          toolName = parts[1];
          category = parts.slice(2).join(":");
        }
      }
      if (toolName && category) {
        const rule: FileAccessRule = {
          identifier: acc.identifier,
          toolName: toolName.trim().toLowerCase(),
          category: category.trim().toLowerCase(),
          severity,
          name,
        };
        ruleset.fileaccess.push(rule);
      }
    } else if (acc.identifier.startsWith("skill:")) {
      // Skill rules are built unconditionally (fields optional), like Python.
      const rule: SkillRule = {
        identifier: acc.identifier,
        skillName: acc.skillName ?? "",
        skillVersion: acc.skillVersion ?? "",
        dangerShape: acc.dangerShape ?? "",
        severity,
        name,
      };
      ruleset.skill.push(rule);
    }
  }
  return ruleset;
}

export interface RulesetCacheOptions {
  client: DkgClient;
  contextGraphId: string;
  stateDir?: string;
  /** TTL seconds; below this a get() serves the cache without a refresh. */
  ttlSeconds?: number;
}

/**
 * Lazy, TTL'd ruleset cache. `get()` returns the in-memory ruleset immediately
 * and triggers a background refresh when stale; the refresh is fail-open.
 */
export class RulesetCache {
  private readonly client: DkgClient;
  private readonly contextGraphId: string;
  private readonly cachePath: string;
  private readonly ttlMs: number;
  private ruleset: Ruleset;
  private refreshing = false;

  constructor(opts: RulesetCacheOptions) {
    this.client = opts.client;
    this.contextGraphId = opts.contextGraphId;
    this.ttlMs = (opts.ttlSeconds ?? 300) * 1000;
    this.cachePath = join(resolveStateDir(opts.stateDir), "ruleset.json");
    this.ruleset = this.loadFromDisk() ?? emptyRuleset();
  }

  private loadFromDisk(): Ruleset | null {
    try {
      const parsed = JSON.parse(readFileSync(this.cachePath, "utf8")) as Partial<Ruleset>;
      if (parsed && Array.isArray(parsed.injection)) {
        // Backfill arrays absent from caches written before fileaccess/skill
        // support so the detectors never see `undefined`.
        return {
          ...emptyRuleset(),
          ...parsed,
          injection: parsed.injection ?? [],
          escalation: parsed.escalation ?? [],
          dependency: parsed.dependency ?? {},
          fileaccess: parsed.fileaccess ?? [],
          skill: parsed.skill ?? [],
        } as Ruleset;
      }
    } catch {
      /* no cache yet */
    }
    return null;
  }

  private saveToDisk(rs: Ruleset): void {
    try {
      mkdirSync(dirname(this.cachePath), { recursive: true });
      writeFileSync(this.cachePath, JSON.stringify(rs), "utf8");
    } catch {
      /* best effort */
    }
  }

  private isStale(): boolean {
    return Date.now() - this.ruleset.fetchedAt > this.ttlMs;
  }

  /** Force a synchronous sync from the node. Fail-open (returns current on error). */
  async sync(): Promise<Ruleset> {
    if (this.refreshing) return this.ruleset;
    this.refreshing = true;
    try {
      const resp = await this.client.query(rulesetQuery(), this.contextGraphId, "shared-working-memory");
      const next = normalizeThreats(resp);
      this.ruleset = next;
      this.saveToDisk(next);
    } catch (err) {
      if (!(err instanceof DkgError)) throw err;
      // node unreachable — keep serving the last ruleset, bump fetchedAt so we
      // don't hammer a down node every tool call.
      this.ruleset = { ...this.ruleset, fetchedAt: Date.now() };
    } finally {
      this.refreshing = false;
    }
    return this.ruleset;
  }

  /** Cached ruleset; kicks off a fire-and-forget refresh when stale. */
  get(): Ruleset {
    if (this.isStale() && !this.refreshing) {
      void this.sync();
    }
    return this.ruleset;
  }

  counts(): {
    injection: number;
    escalation: number;
    dependency: number;
    fileaccess: number;
    skill: number;
  } {
    return {
      injection: this.ruleset.injection.length,
      escalation: this.ruleset.escalation.length,
      dependency: Object.keys(this.ruleset.dependency).length,
      fileaccess: this.ruleset.fileaccess.length,
      skill: this.ruleset.skill.length,
    };
  }
}
