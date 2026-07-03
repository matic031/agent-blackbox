/**
 * Identifier + quad builders for the Umanitek Guardian threat graph.
 *
 * This file is a FAITHFUL port of the canonical Python `plugins/guardian/quads.py`
 * (the tested, shipped ground truth). A hermes node and an OpenClaw node that see
 * the same threat MUST compute the same subject URI, otherwise the cross-framework
 * threat-graph flywheel breaks (first-writer-wins on SWM root entities depends on
 * byte-identical identifiers). The contract is pinned by
 * `tests/parity/identifier_fixtures.json` and asserted by `test/parity.mjs`.
 *
 * Zero runtime deps: `node:crypto` for sha256, everything else pure.
 */
import { createHash } from "node:crypto";

export type GuardianSeverity = "info" | "low" | "medium" | "high" | "critical";

/** Severity ladder, lowest → highest. Mirrors constants.SEVERITY_ORDER. */
export const SEVERITY_ORDER: readonly GuardianSeverity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
];

export const SEVERITY_RANK: Record<GuardianSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

// --- Ontology IRIs (shared vocabulary; identical to constants.py) ----------
export const GUARDIAN_ONTOLOGY = "http://umanitek.ai/ontology/guardian/";
export const GUARDIAN_THREAT_TYPE_IRI = `${GUARDIAN_ONTOLOGY}Threat`;
export const GUARDIAN_DEP_THREAT_TYPE_IRI = `${GUARDIAN_ONTOLOGY}VulnerabilityAdvisory`;
export const GUARDIAN_INJECTION_THREAT_TYPE_IRI = `${GUARDIAN_ONTOLOGY}PromptInjectionThreat`;
export const GUARDIAN_ESCALATION_THREAT_TYPE_IRI = `${GUARDIAN_ONTOLOGY}EscalationThreat`;
export const GUARDIAN_FILE_ACCESS_THREAT_TYPE_IRI = `${GUARDIAN_ONTOLOGY}FileAccessThreat`;
export const GUARDIAN_SUSPICIOUS_SKILL_THREAT_TYPE_IRI = `${GUARDIAN_ONTOLOGY}SuspiciousSkillThreat`;
export const GUARDIAN_REPORT_TYPE_IRI = `${GUARDIAN_ONTOLOGY}ThreatReport`;
export const GUARDIAN_IDENTIFIER_PRED = `${GUARDIAN_ONTOLOGY}identifier`;
export const GUARDIAN_CURATED_PRED = `${GUARDIAN_ONTOLOGY}curated`;
export const GUARDIAN_SEVERITY_PRED = `${GUARDIAN_ONTOLOGY}severity`;
export const GUARDIAN_PATTERN_PRED = `${GUARDIAN_ONTOLOGY}pattern`;
export const GUARDIAN_TOOL_NAME_PRED = `${GUARDIAN_ONTOLOGY}toolName`;
export const GUARDIAN_ARG_SHAPE_PRED = `${GUARDIAN_ONTOLOGY}argShape`;
export const GUARDIAN_OWASP_CATEGORY_PRED = `${GUARDIAN_ONTOLOGY}owaspCategory`;
export const GUARDIAN_REPORTS_THREAT_PRED = `${GUARDIAN_ONTOLOGY}reportsThreat`;
export const GUARDIAN_REPORTER_PRED = `${GUARDIAN_ONTOLOGY}reporter`;
export const GUARDIAN_FRAMEWORK_PRED = `${GUARDIAN_ONTOLOGY}framework`;
export const GUARDIAN_PACKAGE_NAME_PRED = `${GUARDIAN_ONTOLOGY}packageName`;
export const GUARDIAN_PACKAGE_VERSION_PRED = `${GUARDIAN_ONTOLOGY}packageVersion`;
export const GUARDIAN_PACKAGE_ECOSYSTEM_PRED = `${GUARDIAN_ONTOLOGY}packageEcosystem`;
// threat kind: distinguishes active malware from a mere vulnerability. Only
// `malware` blocks (at/above block_severity); `vulnerability` always flags but
// never auto-blocks, so a legit-but-vulnerable package isn't stopped.
export const GUARDIAN_KIND_PRED = `${GUARDIAN_ONTOLOGY}kind`;
export const KIND_MALWARE = "malware";
export const KIND_VULNERABILITY = "vulnerability";
// file-access predicates (g:toolName reused; category is new) ---------------
export const GUARDIAN_CATEGORY_PRED = `${GUARDIAN_ONTOLOGY}category`;
// suspicious-skill predicates -----------------------------------------------
export const GUARDIAN_SKILL_NAME_PRED = `${GUARDIAN_ONTOLOGY}skillName`;
export const GUARDIAN_SKILL_VERSION_PRED = `${GUARDIAN_ONTOLOGY}skillVersion`;
export const GUARDIAN_DANGER_SHAPE_PRED = `${GUARDIAN_ONTOLOGY}dangerShape`;

const RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const SCHEMA_NAME = "http://schema.org/name";
const SCHEMA_DESCRIPTION = "http://schema.org/description";
const SCHEMA_DATE_MODIFIED = "http://schema.org/dateModified";
const SCHEMA_IDENTIFIER = "http://schema.org/identifier";
const XSD_DATETIME = "http://www.w3.org/2001/XMLSchema#dateTime";

export interface Quad {
  subject: string;
  predicate: string;
  object: string;
}

// ---------------------------------------------------------------------------
// Hashing / slugs / URIs
// ---------------------------------------------------------------------------

/**
 * SHA-256 hex digest of the RAW UTF-8 bytes of `value`, truncated to `length`.
 *
 * Port of Python `stable_hash`: it hashes the string's raw bytes, NOT a JSON
 * stringification. Do not add quotes / JSON.stringify here — that would diverge
 * from the Python identifiers.
 */
export function stableHash(value: string, length = 24): string {
  return createHash("sha256").update(value, "utf8").digest("hex").slice(0, length);
}

/** lowercase, non `[a-z0-9._-]` → `-`, trim leading/trailing dashes, ≤96 chars. */
export function slug(value: string): string {
  const lowered = String(value).toLowerCase().replace(/[^a-z0-9._-]+/g, "-");
  const trimmed = lowered.replace(/^-+|-+$/g, "").slice(0, 96);
  return trimmed || "unknown";
}

export function normalizeSeverity(value: unknown, fallback: GuardianSeverity = "info"): GuardianSeverity {
  const raw = String(value ?? "").trim().toLowerCase();
  if (raw === "moderate") return "medium";
  return raw in SEVERITY_RANK ? (raw as GuardianSeverity) : fallback;
}

/** Stable curated-threat subject URI for a threat `identifier`. */
export function threatUri(identifier: string): string {
  return `urn:guardian:threat:${slug(identifier)}`;
}

/** Back-compat alias. */
export const threatUriFor = threatUri;

/**
 * Per-submitter namespaced report subject URI:
 *   `urn:guardian:report:{addrLower}:{sha256(identifier)[:16]}`
 * where the hash is over the RAW identifier bytes (Python parity).
 */
export function reportUri(identifier: string, agentAddress: string): string {
  const addr = (agentAddress || "anonymous").toLowerCase();
  return `urn:guardian:report:${addr}:${stableHash(identifier, 16)}`;
}

/** Back-compat alias with the older (agentAddress, identifier) arg order. */
export function reportUriFor(agentAddress: string, identifier: string): string {
  return reportUri(identifier, agentAddress);
}

// ---------------------------------------------------------------------------
// Identifier builders
// ---------------------------------------------------------------------------

/** `dep:{ecosystem}:{name}@{version}` — ecosystem + name lowercased/trimmed. */
export function dependencyIdentifier(ecosystem: string, name: string, version: string): string {
  return `dep:${ecosystem.trim().toLowerCase()}:${name.trim().toLowerCase()}@${version.trim()}`;
}

/** `injection:{sha256(pattern)[:24]}` — hashes the RAW pattern bytes. */
export function injectionIdentifier(pattern: string): string {
  return `injection:${stableHash(pattern, 24)}`;
}

/**
 * `escalation:{tool}:{argShape}` — human-readable, single colon, shape NOT hashed.
 * The shape is kept literal so the id is legible, e.g.
 * `escalation:shell:remote-script-pipe`.
 */
export function escalationIdentifier(toolName: string, argShape: string): string {
  return `escalation:${toolName.trim().toLowerCase()}:${argShape.trim()}`;
}

/**
 * `fileaccess:{tool}:{category}` — e.g. `fileaccess:read_file:ssh-private-key`.
 * Both parts kept literal (lowercased+trimmed) so the id is legible and two
 * nodes touching the same sensitive-path category converge on one threat KA.
 */
export function fileaccessIdentifierFor(toolName: string, category: string): string {
  return `fileaccess:${toolName.trim().toLowerCase()}:${category.trim().toLowerCase()}`;
}

/** `skill:{name}@{version}` — the known-bad (graph-matched) skill id. */
export function skillVersionIdentifierFor(name: string, version: string): string {
  return `skill:${name.trim().toLowerCase()}@${version.trim()}`;
}

/** `skill:{name}:{dangerShape}` — a heuristic dangerous-code/permission id. */
export function skillShapeIdentifierFor(name: string, dangerShape: string): string {
  return `skill:${name.trim().toLowerCase()}:${dangerShape.trim()}`;
}

/**
 * The threat identifier string. Faithful to Python's identifier builders.
 *   dependency    -> `dep:{ecosystem}:{name}@{version}`   (eco+name lowercased+trimmed)
 *   injection     -> `injection:{sha256(pattern_raw)[:24]}`
 *   escalation    -> `escalation:{toolName}:{argShape}`    (tool lowercased, shape literal)
 *   fileaccess    -> `fileaccess:{toolName}:{category}`    (both lowercased+trimmed)
 *   skill_version -> `skill:{name}@{version}`              (name lowercased, version literal)
 *   skill_shape   -> `skill:{name}:{dangerShape}`          (name lowercased, shape literal)
 */
export function threatIdentifierFor(
  args:
    | { type: "dependency"; ecosystem: string; name: string; version: string }
    | { type: "injection"; pattern: string }
    | { type: "escalation"; toolName: string; argShape: string }
    | { type: "fileaccess"; toolName: string; category: string }
    | { type: "skill_version"; name: string; version: string }
    | { type: "skill_shape"; name: string; dangerShape: string },
): string {
  if (args.type === "dependency") {
    return dependencyIdentifier(args.ecosystem, args.name, args.version);
  }
  if (args.type === "injection") {
    return injectionIdentifier(args.pattern);
  }
  if (args.type === "fileaccess") {
    return fileaccessIdentifierFor(args.toolName, args.category);
  }
  if (args.type === "skill_version") {
    return skillVersionIdentifierFor(args.name, args.version);
  }
  if (args.type === "skill_shape") {
    return skillShapeIdentifierFor(args.name, args.dangerShape);
  }
  return escalationIdentifier(args.toolName, args.argShape);
}

// ---------------------------------------------------------------------------
// N-Triples term escaping
// ---------------------------------------------------------------------------

function q(subject: string, predicate: string, object: string): Quad {
  return { subject, predicate, object };
}

/** Render an IRI term (bare, per the daemon's quad object convention). */
export function iri(value: string): string {
  return value;
}

/**
 * Render a plain-string literal term with N-Triples escaping.
 * Matches Python `literal`: escapes backslash, doublequote, \n, \r, \t (all five).
 */
export function literal(value: string): string {
  const escaped = String(value)
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t");
  return `"${escaped}"`;
}

/** Render an `xsd:dateTime` typed literal (UTC ISO-8601 with `Z`). */
export function datetimeLiteral(ts?: number): string {
  const iso = new Date(ts ?? Date.now()).toISOString(); // always UTC, ends in Z
  return `${literal(iso)}^^${XSD_DATETIME}`;
}

/** N-Triples xsd:dateTime typed literal from an epoch-ms timestamp. */
export function literalIso(ts: number): string {
  return datetimeLiteral(ts);
}

export interface ReportInput {
  identifier: string;
  category: "injection" | "escalation" | "dependency" | "fileaccess" | "skill";
  severity: GuardianSeverity;
  /** Reporter agent address (node default agent). Lowercased for the URI. */
  reporter: string;
  framework: "hermes" | "openclaw";
  ts?: number;
  /** Present only for NEW candidate threats so a curator can promote directly. */
  candidate?: {
    pattern?: string;
    toolName?: string;
    argShape?: string;
    packageName?: string;
    packageVersion?: string;
    packageEcosystem?: string;
    advisoryId?: string;
    owaspCategory?: string;
    // fileaccess
    fileCategory?: string;
    // skill
    skillName?: string;
    skillVersion?: string;
    dangerShape?: string;
  };
}

/**
 * Build the SWM sighting/report quads for one finding. Faithful port of Python
 * `build_report_quads`. Reports NEVER carry observed prompt/command text (privacy
 * split — that stays in the private WM audit). `g:reportsThreat` links to the
 * curated threat URI; for a NEW candidate the category-conditional threat fields
 * are carried inline so the curator can promote it directly.
 *
 * IRIs (the rdf:type object and reportsThreat object) are emitted BARE — Python
 * `iri()` returns the value with no angle brackets.
 */
export function buildReportQuads(input: ReportInput): Quad[] {
  const ts = input.ts;
  const reporter = (input.reporter || "anonymous").toLowerCase();
  const subj = reportUri(input.identifier, input.reporter);
  const threat = threatUri(input.identifier);
  const out: Quad[] = [
    q(subj, RDF_TYPE, iri(GUARDIAN_REPORT_TYPE_IRI)),
    q(subj, GUARDIAN_REPORTS_THREAT_PRED, iri(threat)),
    q(subj, GUARDIAN_IDENTIFIER_PRED, literal(input.identifier)),
    q(subj, GUARDIAN_REPORTER_PRED, literal(reporter)),
    q(subj, GUARDIAN_FRAMEWORK_PRED, literal(input.framework)),
    q(subj, GUARDIAN_SEVERITY_PRED, literal(normalizeSeverity(input.severity))),
    q(subj, SCHEMA_DATE_MODIFIED, datetimeLiteral(ts)),
  ];
  const c = input.candidate ?? {};
  if (input.category === "injection" && c.pattern) {
    out.push(q(subj, GUARDIAN_PATTERN_PRED, literal(c.pattern)));
    if (c.owaspCategory) out.push(q(subj, GUARDIAN_OWASP_CATEGORY_PRED, literal(c.owaspCategory)));
  } else if (input.category === "escalation") {
    if (c.toolName) out.push(q(subj, GUARDIAN_TOOL_NAME_PRED, literal(c.toolName)));
    if (c.argShape) out.push(q(subj, GUARDIAN_ARG_SHAPE_PRED, literal(c.argShape)));
  } else if (input.category === "dependency") {
    if (c.packageName) out.push(q(subj, GUARDIAN_PACKAGE_NAME_PRED, literal(c.packageName)));
    if (c.packageVersion) out.push(q(subj, GUARDIAN_PACKAGE_VERSION_PRED, literal(c.packageVersion)));
    if (c.packageEcosystem) out.push(q(subj, GUARDIAN_PACKAGE_ECOSYSTEM_PRED, literal(c.packageEcosystem)));
    if (c.advisoryId) out.push(q(subj, SCHEMA_IDENTIFIER, literal(c.advisoryId)));
  } else if (input.category === "fileaccess") {
    if (c.toolName) out.push(q(subj, GUARDIAN_TOOL_NAME_PRED, literal(c.toolName)));
    if (c.fileCategory) out.push(q(subj, GUARDIAN_CATEGORY_PRED, literal(c.fileCategory)));
  } else if (input.category === "skill") {
    if (c.skillName) out.push(q(subj, GUARDIAN_SKILL_NAME_PRED, literal(c.skillName)));
    if (c.skillVersion) out.push(q(subj, GUARDIAN_SKILL_VERSION_PRED, literal(c.skillVersion)));
    if (c.dangerShape) out.push(q(subj, GUARDIAN_DANGER_SHAPE_PRED, literal(c.dangerShape)));
  }
  return out;
}

export { RDF_TYPE, SCHEMA_NAME, SCHEMA_DESCRIPTION, SCHEMA_DATE_MODIFIED, SCHEMA_IDENTIFIER, XSD_DATETIME };
