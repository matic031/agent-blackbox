/**
 * Ruleset-driven matcher — a faithful port of the canonical Python
 * `plugins/guardian/quads.py` (arg-shape + dependency parsing) and
 * `plugins/guardian/detection.py` (the matchers).
 *
 * Detection rules come ONLY from the synced threat graph (see ruleset.ts).
 * On an empty graph the matcher detects nothing until synced — by design.
 *
 * Three pure detectors:
 *   - detectInjection(text, ruleset)         — cached regex over text
 *   - detectEscalation(toolName, args, rs)   — compares BOTH toolName AND argShape
 *   - detectDependency(toolName, args, rs)   — parses install cmds → dep lookup
 *
 * `normalizeArgShape` lives here (single source) and is reused by the reporter
 * for identifier building, so client detection and curator-authored escalation
 * shapes stay consistent. It returns the SINGLE top-priority shape (or null),
 * exactly like Python's `normalize_arg_shape`.
 */
import {
  GuardianSeverity,
  escalationIdentifier,
  fileaccessIdentifierFor,
  injectionIdentifier,
  dependencyIdentifier,
  skillVersionIdentifierFor,
  skillShapeIdentifierFor,
} from "./quads.js";

export type ThreatCategory =
  | "injection"
  | "escalation"
  | "dependency"
  | "fileaccess"
  | "skill";

// --- Ruleset shape ---------------------------------------------------------
export interface InjectionRule {
  identifier: string;
  pattern: string; // regex source
  severity: GuardianSeverity;
  name: string;
  owaspCategory?: string;
}
export interface EscalationRule {
  identifier: string;
  toolName: string; // lowercased for comparison
  argShape: string;
  severity: GuardianSeverity;
  name: string;
}
export interface DependencyRule {
  identifier: string;
  severity: GuardianSeverity;
  advisoryId?: string;
  name: string;
}
export interface FileAccessRule {
  identifier: string;
  toolName: string; // lowercased for comparison
  category: string; // lowercased for comparison
  severity: GuardianSeverity;
  name: string;
}
export interface SkillRule {
  identifier: string;
  skillName: string;
  skillVersion: string;
  dangerShape: string;
  severity: GuardianSeverity;
  name: string;
}
export interface Ruleset {
  injection: InjectionRule[];
  escalation: EscalationRule[];
  /** Keyed by `{ecosystem}:{name}@{version}` (ecosystem+name lowercased). */
  dependency: Record<string, DependencyRule>;
  fileaccess: FileAccessRule[];
  skill: SkillRule[];
  fetchedAt: number;
}

export function emptyRuleset(): Ruleset {
  return {
    injection: [],
    escalation: [],
    dependency: {},
    fileaccess: [],
    skill: [],
    fetchedAt: 0,
  };
}

/**
 * Privacy-safe candidate threat attributes forwarded to `buildReportQuads` so a
 * curator can promote a candidate directly. NEVER carries raw prompts, paths, or
 * file/skill source — only signatures (pattern / category / danger shape / ...).
 * Mirrors Python `Finding.fields`.
 */
export interface FindingFields {
  pattern?: string;
  owaspCategory?: string;
  toolName?: string;
  argShape?: string;
  ecosystem?: string;
  packageName?: string;
  packageVersion?: string;
  advisoryId?: string;
  fileCategory?: string;
  skillName?: string;
  skillVersion?: string;
  dangerShape?: string;
}

export interface Finding {
  identifier: string;
  category: ThreatCategory;
  severity: GuardianSeverity;
  title: string;
  toolName: string | null;
  matched: string; // rule name / matched pattern source (not observed content)
  evidence: string; // redacted snippet
  /**
   * True when the finding matched a curated GRAPH rule (blockable). False when
   * raised only by a built-in discovery heuristic (a candidate nominated to the
   * community graph). Mirrors Python `Finding.confirmed`.
   */
  confirmed: boolean;
  /** Privacy-safe candidate threat fields (see `FindingFields`). */
  fields: FindingFields;
}

const MAX_TEXT = 50_000;

/**
 * Compiled-regex cache keyed by pattern source. Peer-supplied patterns are
 * untrusted: compilation and execution are guarded per-regex.
 */
const regexCache = new Map<string, RegExp | null>();

function compile(source: string): RegExp | null {
  if (regexCache.has(source)) return regexCache.get(source) ?? null;
  let re: RegExp | null = null;
  try {
    re = new RegExp(source, "i");
  } catch {
    re = null;
  }
  regexCache.set(source, re);
  return re;
}

/** Run each cached injection regex over `text`. Fail-open per regex. */
export function detectInjection(text: string, ruleset: Ruleset): Finding[] {
  if (!text) return [];
  const capped = text.length > MAX_TEXT ? text.slice(0, MAX_TEXT) : text;
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const rule of ruleset.injection) {
    if (seen.has(rule.identifier)) continue;
    const re = compile(rule.pattern);
    if (!re) continue;
    try {
      if (re.test(capped)) {
        seen.add(rule.identifier);
        out.push({
          identifier: rule.identifier,
          category: "injection",
          severity: rule.severity,
          title: rule.name || "Prompt injection pattern matched",
          toolName: null,
          matched: rule.pattern,
          evidence: sampleAround(capped, re),
          confirmed: true,
          fields: {},
        });
      }
    } catch {
      // untrusted regex blew up at match time — skip it, keep going.
    }
  }
  return out;
}

/**
 * Escalation: derive the arg shape deterministically, then match a rule ONLY
 * when BOTH toolName AND argShape agree.
 */
export function detectEscalation(
  toolName: string,
  args: unknown,
  ruleset: Ruleset,
): Finding[] {
  const shape = normalizeArgShape(toolName, args);
  if (!shape) return [];
  const tool = (toolName || "").trim().toLowerCase();
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const rule of ruleset.escalation) {
    if (seen.has(rule.identifier)) continue;
    if (rule.toolName.trim().toLowerCase() !== tool) continue;
    if (rule.argShape.trim() !== shape) continue;
    seen.add(rule.identifier);
    out.push({
      identifier: rule.identifier,
      category: "escalation",
      severity: rule.severity,
      title: rule.name || `Dangerous ${tool} call (${shape})`,
      toolName: toolName || "",
      matched: shape,
      evidence: shape,
      confirmed: true,
      fields: {},
    });
  }
  // Discovery layer: a dangerous shape that no graph rule covers is still a
  // candidate escalation nominated to the community graph.
  if (out.length === 0) {
    out.push({
      identifier: escalationIdentifier(tool, shape),
      category: "escalation",
      severity: "high",
      title: `Suspicious ${tool} call (${shape})`,
      toolName: toolName || "",
      matched: shape,
      evidence: shape,
      confirmed: false,
      fields: { toolName: tool, argShape: shape },
    });
  }
  return out;
}

/**
 * Best-effort extraction of a command string for dependency parsing.
 * Port of Python `_command_text`: string args → raw; dict args → first present
 * COMMAND_KEYS value, else ALL string values joined (unconditionally — this
 * differs from `commandFromArgs`, which only joins for shell-like tools).
 */
export function commandText(args: unknown): string {
  if (typeof args === "string") return args;
  if (args == null || typeof args !== "object" || Array.isArray(args)) return "";
  const obj = args as Record<string, unknown>;
  for (const key of COMMAND_KEYS) {
    const val = obj[key];
    if (typeof val === "string" && val) return val;
  }
  return Object.values(obj)
    .filter((v): v is string => typeof v === "string")
    .join(" ");
}

/** Dependency: parse install commands → look up in ruleset.dependency. */
export function detectDependency(
  toolName: string,
  args: unknown,
  ruleset: Ruleset,
): Finding[] {
  const command = commandText(args);
  if (!command) return [];
  const dependencyRules = ruleset.dependency ?? {};
  if (Object.keys(dependencyRules).length === 0) return [];
  const installs = parseDependencyInstalls(command);
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const dep of installs) {
    if (!dep.version) continue; // ruleset keys are pinned versions
    const eco = dep.ecosystem.toLowerCase();
    const name = dep.name.toLowerCase();
    const key = `${eco}:${name}@${dep.version}`;
    const rule = dependencyRules[key];
    if (!rule || seen.has(key)) continue;
    seen.add(key);
    out.push({
      identifier: rule.identifier || dependencyIdentifier(eco, name, dep.version),
      category: "dependency",
      severity: rule.severity,
      title: rule.name || `Vulnerable dependency ${name}@${dep.version}`,
      toolName: toolName || "",
      matched: key,
      evidence: rule.advisoryId
        ? `${dep.ecosystem}:${dep.name}@${dep.version} (${rule.advisoryId})`
        : `${dep.ecosystem}:${dep.name}@${dep.version}`,
      confirmed: true,
      fields: {},
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Arg-shape normalization (shared by detection + curator) — port of quads.py
// ---------------------------------------------------------------------------

// A remote-download-piped-to-interpreter shape: `curl ... | sh`, `wget ... | bash`.
const REMOTE_SCRIPT_RE = /\b(?:curl|wget)\b[\s\S]{0,500}\|\s*(?:sh|bash|zsh|python|python3|node)\b/i;
// `rm -rf` against system / home roots.
const RM_RF_SYSTEM_RE =
  /\brm\s+(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-r\s+-f|-f\s+-r)\b[\s\S]{0,200}(?:\s\/(?:etc|var|usr|bin|sbin|opt|private|System|Library)\b|\s~\/?|\s\/\s*$|\s\$HOME\b)/i;
// `chmod 777` / world-writable perms.
const CHMOD_WORLD_RE = /\bchmod\s+(?:-R\s+)?0?777\b/i;
// Piping a fetched payload straight into eval.
const CURL_EVAL_RE = /\b(?:curl|wget)\b[\s\S]{0,300}\|\s*eval\b/i;
// Disabling TLS verification on a network fetch.
const INSECURE_FETCH_RE = /\b(?:curl|wget)\b[\s\S]{0,200}(?:--insecure|-k\b|--no-check-certificate)/i;

/**
 * Ordered so the most specific / most dangerous shape wins for a given command.
 * Mirrors Python `_SHELL_SHAPE_RULES` exactly (priority order matters).
 */
const SHELL_SHAPE_RULES: ReadonlyArray<readonly [string, RegExp]> = [
  ["remote-script-pipe", REMOTE_SCRIPT_RE],
  ["remote-eval-pipe", CURL_EVAL_RE],
  ["rm-rf-system-paths", RM_RF_SYSTEM_RE],
  ["chmod-world-writable", CHMOD_WORLD_RE],
  ["insecure-tls-fetch", INSECURE_FETCH_RE],
];

// Tool names whose payload is treated as a shell command string.
const SHELL_TOOLS = new Set(["terminal", "shell", "bash", "run_command", "exec", "command"]);
const COMMAND_KEYS = ["command", "cmd", "shell", "script", "input"] as const;

const MAX_SHAPE_SCAN = 8000;

/**
 * Best-effort extraction of a shell command string from tool args.
 * Port of Python `_command_from_args`:
 *   - string args             → the raw string (capped)
 *   - dict args               → first present COMMAND_KEYS value
 *   - shell-like tools only    → concat of string values as fallback
 *   - anything else            → ""
 */
export function commandFromArgs(toolName: string, args: unknown): string {
  if (typeof args === "string") return args.slice(0, MAX_SHAPE_SCAN);
  if (args == null || typeof args !== "object" || Array.isArray(args)) return "";
  const obj = args as Record<string, unknown>;
  for (const key of COMMAND_KEYS) {
    const val = obj[key];
    if (typeof val === "string" && val) return val.slice(0, MAX_SHAPE_SCAN);
  }
  // Fall back to concatenating string values for shell-like tools only.
  if (SHELL_TOOLS.has((toolName || "").toLowerCase())) {
    const parts = Object.values(obj).filter((v): v is string => typeof v === "string");
    return parts.join(" ").slice(0, MAX_SHAPE_SCAN);
  }
  return "";
}

/**
 * Derive a deterministic escalation `argShape` for a tool call.
 *
 * Returns the SINGLE top-priority stable slug (e.g. `remote-script-pipe`) or
 * `null` when the call matches no known dangerous shape. Deterministic and pure
 * so the client detector and the curator authoring flow agree on identifiers.
 * Port of Python `normalize_arg_shape` (returns ONE shape or None).
 */
export function normalizeArgShape(toolName: string, args: unknown): string | null {
  const command = commandFromArgs(toolName, args);
  if (!command) return null;
  for (const [shape, pattern] of SHELL_SHAPE_RULES) {
    try {
      if (pattern.test(command)) return shape;
    } catch {
      // static patterns; ignore any engine hiccup and keep scanning.
    }
  }
  return null;
}

/** Convenience: the escalation identifier an invocation would produce (or null). */
export function escalationIdentifierFor(toolName: string, args: unknown): string | null {
  const shape = normalizeArgShape(toolName, args);
  return shape ? escalationIdentifier(toolName, shape) : null;
}

// ---------------------------------------------------------------------------
// Built-in injection heuristics (discovery layer — OWASP LLM01/LLM06)
// Port of quads.py `_INJECTION_HEURISTICS` / `scan_injection_heuristics`.
// ---------------------------------------------------------------------------

// Each entry is [severity, owasp, regex]. The DISCOVERY nomination layer: a
// prompt matching one NOT already in the graph is auto-submitted as a candidate.
// Privacy: only the matched substring (truncated) is ever carried off-box.
const INJECTION_HEURISTICS: ReadonlyArray<readonly [GuardianSeverity, string, RegExp]> = [
  ["high", "LLM01", /ignore\s+(?:all\s+)?previous\s+instructions/i],
  ["high", "LLM01", /disregard\s+(?:all\s+)?(?:prior|previous|above)\s+(?:instructions|rules|prompts)/i],
  ["high", "LLM06", /(?:reveal|show|print|repeat|disclose)\b[\s\S]{0,40}\bsystem\s+prompt/i],
  ["high", "LLM01", /you\s+are\s+now\b[\s\S]{0,40}\b(?:DAN|developer\s+mode|jailbroken|unrestricted)/i],
  ["medium", "LLM01", /pretend\s+(?:to\s+be|you\s+are)\b[\s\S]{0,40}\b(?:no\s+restrictions|unrestricted|without\s+rules)/i],
  ["high", "LLM06", /(?:exfiltrate|leak|send|upload|post)\b[\s\S]{0,40}\b(?:api\s*key|secret|token|credentials|password|env(?:ironment)?\s+variables)/i],
];

/** Truncation cap for the matched dangerous phrase carried on a candidate. */
const INJECTION_PHRASE_CAP = 120;
const MAX_INJECTION_SCAN = 50_000;

export interface InjectionHeuristicHit {
  pattern: string;
  severity: GuardianSeverity;
  owasp: string;
}

/**
 * Return built-in injection matches as `[{pattern, severity, owasp}]`.
 * `pattern` is the matched dangerous substring (truncated ~120 chars) — NEVER
 * the surrounding prompt. Port of Python `scan_injection_heuristics`.
 */
export function scanInjectionHeuristics(text: string): InjectionHeuristicHit[] {
  if (!text) return [];
  const scan = text.length > MAX_INJECTION_SCAN ? text.slice(0, MAX_INJECTION_SCAN) : text;
  const out: InjectionHeuristicHit[] = [];
  const seen = new Set<string>();
  for (const [severity, owasp, pattern] of INJECTION_HEURISTICS) {
    let m: RegExpMatchArray | null = null;
    try {
      m = scan.match(pattern);
    } catch {
      continue;
    }
    if (!m) continue;
    const phrase = m[0].slice(0, INJECTION_PHRASE_CAP);
    if (seen.has(phrase)) continue;
    seen.add(phrase);
    out.push({ pattern: phrase, severity, owasp });
  }
  return out;
}

/**
 * Built-in injection discovery: heuristic matches not already in the graph.
 * PRIVACY: the candidate carries ONLY the matched dangerous phrase (truncated
 * ~120 chars) — never the surrounding text. Port of Python `discover_injection`.
 */
export function discoverInjection(text: string, ruleset: Ruleset): Finding[] {
  const known = new Set<string>();
  for (const rule of ruleset.injection ?? []) {
    if (rule.identifier) known.add(rule.identifier);
  }
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const hit of scanInjectionHeuristics(text || "")) {
    const identifier = injectionIdentifier(hit.pattern);
    if (known.has(identifier) || seen.has(identifier)) continue;
    seen.add(identifier);
    out.push({
      identifier,
      category: "injection",
      severity: hit.severity,
      title: "Suspicious prompt-injection phrase",
      toolName: null,
      matched: hit.pattern,
      evidence: hit.pattern,
      confirmed: false,
      fields: { pattern: hit.pattern, owaspCategory: hit.owasp },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Sensitive file-access categories (discovery layer)
// Port of quads.py `_SENSITIVE_PATH_RULES` / `file_access_arg` /
// `sensitive_path_category` + detection.py `detect_fileaccess`.
// ---------------------------------------------------------------------------

// [category, severity, path-regex]. Matched against the accessed path only; the
// candidate carries ONLY the category + tool — never the exact path.
const SENSITIVE_PATH_RULES: ReadonlyArray<readonly [string, GuardianSeverity, RegExp]> = [
  ["ssh-private-key", "critical", /(?:^|\/)\.ssh(?:\/|$)|(?:^|\/)id_(?:rsa|ed25519|ecdsa|dsa)\b/i],
  ["env-file", "high", /(?:^|\/)\.env(?:\.[\w.-]+)?$/i],
  [
    "credentials",
    "critical",
    /(?:^|\/)\.aws\/credentials$|(?:^|\/)\.netrc$|(?:^|\/)\.npmrc$|(?:^|\/)\.docker\/config\.json$|(?:^|\/)\.kube\/config$|(?:^|\/)\.config\/gcloud(?:\/|$)/i,
  ],
  ["password-store", "critical", /(?:^|\/)\.password-store(?:\/|$)|(?:^|\/)\.pgpass$/i],
  [
    "browser-cookies",
    "high",
    /(?:Cookies|Login Data)$|(?:^|\/)Library\/Keychains(?:\/|$)|(?:^|\/)login\.keychain/i,
  ],
  ["system-shadow", "critical", /^\/etc\/(?:shadow|passwd|sudoers)$/i],
];

// Tools whose args reference a file/path. Value = mode (read | write).
const FILE_ACCESS_TOOLS: Record<string, "read" | "write"> = {
  read_file: "read",
  write_file: "write",
  edit_file: "write",
  edit: "write",
  patch: "write",
  apply_patch: "write",
  create_file: "write",
  delete_file: "write",
  open_file: "read",
  cat: "read",
  skill_manage: "write",
};
const PATH_KEYS = ["path", "file", "file_path", "filepath", "filename", "target", "target_file"] as const;

function npmrcHasToken(args: unknown): boolean {
  let text = typeof args === "string" ? args : "";
  if (args != null && typeof args === "object" && !Array.isArray(args)) {
    for (const v of Object.values(args as Record<string, unknown>)) {
      if (typeof v === "string") text += "\n" + v;
    }
  }
  return text.toLowerCase().includes("_authtoken");
}

export interface FileAccess {
  tool: string;
  path: string;
  mode: "read" | "write";
}

/**
 * Extract `{tool, path, mode}` for a file-access tool call, or `null`.
 * Port of Python `file_access_arg`.
 */
export function fileAccessArg(toolName: string, args: unknown): FileAccess | null {
  const tool = (toolName || "").trim().toLowerCase();
  const mode = FILE_ACCESS_TOOLS[tool];
  if (!mode || args == null || typeof args !== "object" || Array.isArray(args)) return null;
  const obj = args as Record<string, unknown>;
  let path = "";
  for (const key of PATH_KEYS) {
    const val = obj[key];
    if (typeof val === "string" && val.trim()) {
      path = val.trim();
      break;
    }
  }
  if (!path) return null;
  return { tool, path, mode };
}

export interface SensitiveCategory {
  category: string;
  severity: GuardianSeverity;
}

/**
 * Classify `path` into a sensitive category, or `null`. The `.npmrc` file is
 * only sensitive when it carries an `_authToken` (checked via `args`).
 * Port of Python `sensitive_path_category`.
 */
export function sensitivePathCategory(path: string, args?: unknown): SensitiveCategory | null {
  if (!path) return null;
  const p = path.trim();
  if (p.endsWith(".npmrc")) {
    return npmrcHasToken(args) ? { category: "credentials", severity: "high" } : null;
  }
  for (const [category, severity, pattern] of SENSITIVE_PATH_RULES) {
    try {
      if (pattern.test(p)) return { category, severity };
    } catch {
      continue;
    }
  }
  return null;
}

/**
 * Detect access to a sensitive-path category (graph rule or built-in).
 * PRIVACY: the finding carries ONLY the category + tool — never the exact path
 * or file contents. Port of Python `detect_fileaccess`.
 */
export function detectFileaccess(toolName: string, args: unknown, ruleset: Ruleset): Finding[] {
  const access = fileAccessArg(toolName, args);
  if (!access) return [];
  const hit = sensitivePathCategory(access.path, args);
  if (!hit) return [];
  const tool = access.tool;
  const category = hit.category;
  let identifier = fileaccessIdentifierFor(tool, category);
  let severity: GuardianSeverity = hit.severity;
  let confirmed = false;
  let name: string | undefined;
  for (const rule of ruleset.fileaccess ?? []) {
    if (
      String(rule.toolName || "").toLowerCase() === tool &&
      String(rule.category || "").toLowerCase() === category
    ) {
      confirmed = true;
      severity = rule.severity ?? severity;
      name = rule.name;
      identifier = rule.identifier || identifier;
      break;
    }
  }
  return [
    {
      identifier,
      category: "fileaccess",
      severity,
      title: name || `Sensitive file access (${category})`,
      toolName: tool,
      matched: category,
      evidence: `${access.mode} ${category}`,
      confirmed,
      fields: { toolName: tool, fileCategory: category },
    },
  ];
}

// ---------------------------------------------------------------------------
// Suspicious-skill danger-shape scanning (discovery layer)
// Port of quads.py `_SKILL_CODE_RULES` / `_SKILL_PERMISSION_RULES` /
// `skill_install_arg` / `scan_skill_dangers` + detection.py `detect_skill`.
// ---------------------------------------------------------------------------

// [dangerShape, severity, regex] over the skill's declared code/content.
const SKILL_CODE_RULES: ReadonlyArray<readonly [string, GuardianSeverity, RegExp]> = [
  [
    "shell-exec",
    "high",
    /\b(?:os\.system|subprocess\.(?:run|call|Popen|check_output)|child_process|exec(?:Sync)?\s*\(|spawn(?:Sync)?\s*\()/i,
  ],
  ["remote-script-pipe", "critical", REMOTE_SCRIPT_RE],
  [
    "credential-exfil",
    "critical",
    /(?:os\.environ|process\.env|getenv)\b[\s\S]{0,120}\b(?:requests\.(?:post|get)|fetch\s*\(|urlopen|http[s]?:\/\/)/i,
  ],
  [
    "obfuscation",
    "high",
    /\b(?:eval|exec)\s*\(\s*(?:base64|atob|Buffer\.from|codecs\.decode)|\bbase64\.b64decode\b[\s\S]{0,40}\b(?:eval|exec)/i,
  ],
];

// [dangerShape, severity, regex] over declared permissions/capabilities.
// No trailing \b — several of these end in `*` (a non-word char).
const SKILL_PERMISSION_RULES: ReadonlyArray<readonly [string, GuardianSeverity, RegExp]> = [
  ["over-broad-filesystem", "high", /\b(?:filesystem[:_-]?\*|fs[:_-]?full|read[_-]?write[_-]?all|allowallpaths)/i],
  ["over-broad-shell", "high", /\b(?:arbitrary[_-]?shell|shell[:_-]?\*|exec[:_-]?any|allowshell)/i],
  ["over-broad-network", "medium", /\b(?:network[:_-]?\*|raw[_-]?socket|allowallhosts|net[:_-]?any)/i],
];

// Tools that install/modify a skill.
const SKILL_TOOLS = new Set([
  "skill_manage",
  "skill_install",
  "install_skill",
  "plugin_install",
  "install_plugin",
]);
const SKILL_NAME_KEYS = ["name", "skill", "skill_name", "id", "plugin"] as const;
const SKILL_VERSION_KEYS = ["version", "skill_version", "ver"] as const;
const SKILL_CODE_KEYS = ["code", "content", "source", "body", "script"] as const;
const SKILL_PERM_KEYS = ["permissions", "capabilities", "scopes", "allow", "grants"] as const;

const MAX_SKILL_SCAN = 20_000;

/** Deep-stringify a value the way Python `_stringify` does. */
function stringify(value: unknown): string {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map((v) => stringify(v)).join(" ");
  if (value != null && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .map(([k, v]) => `${k} ${stringify(v)}`)
      .join(" ");
  }
  return value != null ? String(value) : "";
}

export interface SkillInstall {
  name: string;
  version: string;
  code: string;
  permissions: string;
}

/**
 * Extract a skill install/modify descriptor, or `null`. `code`/`permissions`
 * are the concatenated content to scan; they are NEVER carried off-box — only
 * matched danger-shape names are submitted. Port of Python `skill_install_arg`.
 */
export function skillInstallArg(toolName: string, args: unknown): SkillInstall | null {
  const tool = (toolName || "").trim().toLowerCase();
  if (!SKILL_TOOLS.has(tool) || args == null || typeof args !== "object" || Array.isArray(args)) {
    return null;
  }
  const obj = args as Record<string, unknown>;
  let name = "";
  for (const key of SKILL_NAME_KEYS) {
    const val = obj[key];
    if (typeof val === "string" && val.trim()) {
      name = val.trim();
      break;
    }
  }
  if (!name) return null;
  let version = "";
  for (const key of SKILL_VERSION_KEYS) {
    const val = obj[key];
    if (typeof val === "string" && val.trim()) {
      version = val.trim();
      break;
    }
  }
  const code = SKILL_CODE_KEYS.filter((k) => obj[k])
    .map((k) => stringify(obj[k]))
    .join(" ");
  const perms = SKILL_PERM_KEYS.filter((k) => obj[k])
    .map((k) => stringify(obj[k]))
    .join(" ");
  return {
    name,
    version,
    code: code.slice(0, MAX_SKILL_SCAN),
    permissions: perms.slice(0, MAX_SKILL_SCAN),
  };
}

export interface SkillDanger {
  dangerShape: string;
  severity: GuardianSeverity;
}

/**
 * Return built-in skill danger matches as `[{dangerShape, severity}]`. Scans
 * `code` for dangerous-code shapes and `permissions` for over-broad capability
 * grants. Port of Python `scan_skill_dangers`.
 */
export function scanSkillDangers(code: string, permissions: string): SkillDanger[] {
  const out: SkillDanger[] = [];
  const seen = new Set<string>();
  const passes: ReadonlyArray<readonly [string, ReadonlyArray<readonly [string, GuardianSeverity, RegExp]>]> = [
    [code || "", SKILL_CODE_RULES],
    [permissions || "", SKILL_PERMISSION_RULES],
  ];
  for (const [text, rules] of passes) {
    if (!text) continue;
    for (const [shape, severity, pattern] of rules) {
      if (seen.has(shape)) continue;
      try {
        if (pattern.test(text)) {
          seen.add(shape);
          out.push({ dangerShape: shape, severity });
        }
      } catch {
        continue;
      }
    }
  }
  return out;
}

/**
 * Detect a suspicious skill install/modify (graph known-bad or built-in).
 * Three signals: known-bad `skill:{name}@{version}` from the graph; dangerous-
 * code shapes; over-broad permission grants. PRIVACY: a finding carries the
 * skill name + matched danger shape — never the full skill source.
 * Port of Python `detect_skill`.
 */
export function detectSkill(toolName: string, args: unknown, ruleset: Ruleset): Finding[] {
  const skill = skillInstallArg(toolName, args);
  if (!skill) return [];
  const out: Finding[] = [];
  const seen = new Set<string>();
  const name = skill.name;
  const version = skill.version;
  // (a) known-bad from graph: match name@version or name against skill: rules.
  for (const rule of ruleset.skill ?? []) {
    const ruleName = String(rule.skillName || "").trim().toLowerCase();
    const ruleVer = String(rule.skillVersion || "").trim();
    if (ruleName && ruleName === name.toLowerCase() && (!ruleVer || ruleVer === version)) {
      const ident = rule.identifier || skillVersionIdentifierFor(name, version);
      if (seen.has(ident)) continue;
      seen.add(ident);
      out.push({
        identifier: ident,
        category: "skill",
        severity: rule.severity ?? "high",
        title: rule.name || `Known-bad skill ${name}`,
        // Python: skill.get("tool", "") or (tool_name or "").lower(); the
        // install descriptor has no `tool` key so this is always the tool name.
        toolName: (toolName || "").toLowerCase(),
        matched: name,
        evidence: `known-bad skill ${name}`,
        confirmed: true,
        fields: { skillName: name, skillVersion: version },
      });
    }
  }
  // (b)+(c) built-in dangerous-code / over-broad-permission discovery.
  for (const danger of scanSkillDangers(skill.code, skill.permissions)) {
    const shape = danger.dangerShape;
    const ident = skillShapeIdentifierFor(name, shape);
    if (seen.has(ident)) continue;
    seen.add(ident);
    out.push({
      identifier: ident,
      category: "skill",
      severity: danger.severity ?? "high",
      title: `Suspicious skill ${name} (${shape})`,
      toolName: (toolName || "").toLowerCase(),
      matched: shape,
      evidence: `skill ${name}: ${shape}`,
      confirmed: false,
      fields: { skillName: name, skillVersion: version, dangerShape: shape },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Dependency install parsing (shared by detection + curator import) — port
// ---------------------------------------------------------------------------

const SHELL_INSTALL_PATTERNS = [
  /\b(?:python(?:3)?\s+-m\s+)?pip3?\s+install\b/i,
  /\buv\s+pip\s+install\b/i,
  /\buv\s+add\b/i,
  /\buvx\b/i,
  /\bnpm\s+(?:install|i|add)\b/i,
  /\bpnpm\s+add\b/i,
  /\byarn\s+add\b/i,
  /\bbun\s+add\b/i,
  /\bcargo\s+add\b/i,
  /\bgem\s+install\b/i,
  /\bbrew\s+install\b/i,
];

const TOKEN_RE = /"([^"]*)"|'([^']*)'|(\S+)/g;

function tokenizeShell(command: string): string[] {
  const out: string[] = [];
  for (const m of command.matchAll(TOKEN_RE)) {
    out.push(m[1] ?? m[2] ?? m[3] ?? "");
  }
  return out;
}

export interface ParsedPackage {
  ecosystem: string;
  name: string;
  version: string;
}

/**
 * Parse a single install token into `{name, version}` for `ecosystem`.
 * Port of Python `_parse_package_token`.
 */
function parsePackageToken(raw: string, ecosystem: string): { name: string; version: string } | null {
  const token = raw.replace(/,/g, "").replace(/;/g, "").trim();
  if (
    !token ||
    token.startsWith("http://") ||
    token.startsWith("https://") ||
    token.startsWith("/") ||
    token.startsWith(".") ||
    token.startsWith("@git")
  ) {
    return null;
  }
  if (ecosystem === "pypi" || ecosystem === "rubygems") {
    const exact = /^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9._+!-]+)$/.exec(token);
    if (exact) return { name: exact[1], version: exact[2] };
    const loose = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?$/.exec(token);
    if (loose) return { name: loose[1], version: "" };
    return null;
  }
  if (ecosystem === "npm") {
    const idx = token.lastIndexOf("@");
    if (idx > 0) return { name: token.slice(0, idx), version: token.slice(idx + 1) }; // scoped names start with @, require idx > 0
    if (/^(?:@[A-Za-z0-9._-]+\/)?[A-Za-z0-9._-]+$/.test(token)) return { name: token, version: "" };
    return null;
  }
  // cargo / homebrew / other: name[@version]
  const idx = token.lastIndexOf("@");
  if (idx > 0) return { name: token.slice(0, idx), version: token.slice(idx + 1) };
  if (/^[A-Za-z0-9._+/-]+$/.test(token)) return { name: token, version: "" };
  return null;
}

// manager token spec key -> [ecosystem, number of leading subcommand tokens to skip].
// The lookup order in the loop mirrors Python's `_MANAGER_SPECS` dict lookups.
type ManagerSpec = { eco: string; skip: number };

const MANAGER_SPECS_PAIR: Record<string, ManagerSpec> = {
  "pip|install": { eco: "pypi", skip: 2 },
  "pip3|install": { eco: "pypi", skip: 2 },
  "uv|pip": { eco: "pypi", skip: 3 }, // `uv pip install <pkg>`
  "uv|add": { eco: "pypi", skip: 2 },
  "pnpm|add": { eco: "npm", skip: 2 },
  "yarn|add": { eco: "npm", skip: 2 },
  "bun|add": { eco: "npm", skip: 2 },
  "cargo|add": { eco: "cargo", skip: 2 },
  "gem|install": { eco: "rubygems", skip: 2 },
  "brew|install": { eco: "homebrew", skip: 2 },
};

const MANAGER_SPECS_SINGLE: Record<string, ManagerSpec> = {
  uvx: { eco: "pypi", skip: 1 },
  // `npm install|i|add` is handled explicitly below (the Python `("npm", None)` entry).
};

/**
 * Parse install commands into `[{ecosystem, name, version}, ...]`.
 * Faithful port of Python `parse_dependency_installs`, including the `i = j`
 * advance (the outer index jumps past the packages consumed for this manager)
 * and dedup by `{ecosystem}:{name.lower()}:{version}`.
 */
export function parseDependencyInstalls(command: string): ParsedPackage[] {
  if (!command || !SHELL_INSTALL_PATTERNS.some((re) => re.test(command))) return [];
  const tokens = tokenizeShell(command);
  const out: ParsedPackage[] = [];
  const seen = new Set<string>();
  let i = 0;
  while (i < tokens.length) {
    const tok = (tokens[i] ?? "").toLowerCase();
    const nxt = i + 1 < tokens.length ? (tokens[i + 1] ?? "").toLowerCase() : null;
    let ecosystem = "";
    let start = -1;

    // Python special-cases `(tok, "pip") in _MANAGER_SPECS and nxt == "pip"`
    // ahead of the generic pair lookup so `uv pip install` resolves to skip=3.
    if (MANAGER_SPECS_PAIR[`${tok}|pip`] && nxt === "pip") {
      const spec = MANAGER_SPECS_PAIR[`${tok}|pip`];
      ecosystem = spec.eco;
      start = i + spec.skip;
    } else if (nxt !== null && MANAGER_SPECS_PAIR[`${tok}|${nxt}`]) {
      const spec = MANAGER_SPECS_PAIR[`${tok}|${nxt}`];
      ecosystem = spec.eco;
      start = i + spec.skip;
    } else if (MANAGER_SPECS_SINGLE[tok]) {
      const spec = MANAGER_SPECS_SINGLE[tok];
      ecosystem = spec.eco;
      start = i + spec.skip;
    } else if (tok === "npm" && (nxt === "install" || nxt === "i" || nxt === "add")) {
      ecosystem = "npm";
      start = i + 2;
    }

    if (start < 0 || !ecosystem) {
      i += 1;
      continue;
    }

    let j = start;
    while (j < tokens.length) {
      const raw = tokens[j] ?? "";
      if (raw === ";" || raw === "&&" || raw === "||" || raw === "|") break;
      if (raw.startsWith("-") || raw === "install" || raw === "add" || raw === "i") {
        j += 1;
        continue;
      }
      const parsed = parsePackageToken(raw, ecosystem);
      if (parsed && parsed.name) {
        const key = `${ecosystem}:${parsed.name.toLowerCase()}:${parsed.version}`;
        if (!seen.has(key)) {
          seen.add(key);
          out.push({ ecosystem, name: parsed.name, version: parsed.version });
        }
      }
      j += 1;
    }
    i = j;
  }
  return out;
}

/** Back-compat alias for callers expecting the old name. */
export const detectDependencyInstalls = parseDependencyInstalls;

// ---------------------------------------------------------------------------
// Text flattening (injection scan helper) + evidence sampling
// ---------------------------------------------------------------------------

/** Flatten string-ish leaves from tool params into text (for injection scan). */
export function collectText(value: unknown, out: string[] = [], depth = 0): string[] {
  if (value == null || depth > 6) return out;
  if (typeof value === "string") {
    if (value.trim()) out.push(value);
    return out;
  }
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 100)) collectText(item, out, depth + 1);
    return out;
  }
  if (typeof value === "object") {
    for (const child of Object.values(value as Record<string, unknown>)) {
      collectText(child, out, depth + 1);
    }
  }
  return out;
}

function sampleAround(text: string, re: RegExp): string {
  try {
    const m = text.match(new RegExp(re.source, "i"));
    if (m && typeof m.index === "number") {
      const start = Math.max(0, m.index - 40);
      return text.slice(start, m.index + m[0].length + 40);
    }
  } catch {
    /* ignore */
  }
  return text.slice(0, 120);
}

// ---------------------------------------------------------------------------
// OSV dependency auto-discovery (discovery layer) — port of detection.py
// `discover_dependency_candidates` + osv.py `lookup`.
// ---------------------------------------------------------------------------

/** `{advisoryId, severity}` when OSV knows a package@version vulnerable. */
export interface OsvHit {
  advisoryId: string;
  severity: GuardianSeverity;
}

/** Async OSV lookup: (ecosystem, name, version) → OsvHit | null. */
export type OsvLookup = (
  ecosystem: string,
  name: string,
  version: string,
) => Promise<OsvHit | null> | OsvHit | null;

/**
 * Best-effort OSV auto-discovery of vulnerable installs not in the graph.
 *
 * Parses install commands, skips any pinned dep already covered by a graph
 * rule, and calls `osvLookup(ecosystem, name, version)` — which returns an
 * `OsvHit` when OSV knows it vulnerable, else null. Only OSV-VULNERABLE installs
 * become candidates; clean deps are never surfaced (privacy). Runs OFF the
 * blocking path (callers invoke this best-effort). Port of Python
 * `discover_dependency_candidates`.
 */
export async function discoverDependencyCandidates(
  toolName: string,
  args: unknown,
  ruleset: Ruleset,
  osvLookup: OsvLookup,
): Promise<Finding[]> {
  const command = commandText(args);
  if (!command) return [];
  const dependencyRules = ruleset.dependency ?? {};
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const dep of parseDependencyInstalls(command)) {
    const version = dep.version || "";
    if (!version) continue;
    const eco = dep.ecosystem.toLowerCase();
    const name = dep.name;
    const key = `${eco}:${name.toLowerCase()}@${version}`;
    if (key in dependencyRules || seen.has(key)) continue; // graph rule or dup
    seen.add(key);
    let hit: OsvHit | null = null;
    try {
      hit = await osvLookup(eco, name, version);
    } catch {
      hit = null; // fail open
    }
    if (!hit) continue;
    out.push({
      identifier: dependencyIdentifier(eco, name, version),
      category: "dependency",
      severity: hit.severity ?? "high",
      title: `OSV-vulnerable dependency ${name}@${version}`,
      toolName: toolName || "",
      matched: key,
      evidence: `${eco}:${name}@${version} (${hit.advisoryId})`,
      confirmed: false,
      fields: {
        ecosystem: eco,
        packageName: name,
        packageVersion: version,
        advisoryId: hit.advisoryId,
      },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Orchestrator — port of detection.py `detect_all` / `_graph_escalation`.
// ---------------------------------------------------------------------------

/**
 * Run every detector (graph rules + built-in discovery) across categories.
 * Graph-only detectors (dependency lookup, curated injection regexes) always
 * run. When `discover` is true the built-in escalation/injection/file-access/
 * skill nomination layer also runs. Dependency OSV auto-discovery is NOT run
 * here — it is best-effort and runs off the blocking path (see index.ts).
 * Port of Python `detect_all`.
 */
export function detectAll(
  toolName: string,
  args: unknown,
  ruleset: Ruleset,
  discover = true,
): Finding[] {
  const findings: Finding[] = [];
  findings.push(
    ...(discover
      ? detectEscalation(toolName, args, ruleset)
      : detectEscalation(toolName, args, ruleset).filter((f) => f.confirmed)),
  );
  findings.push(...detectDependency(toolName, args, ruleset));
  let argsText: string;
  try {
    argsText = typeof args === "string" ? args : JSON.stringify(args);
  } catch {
    argsText = String(args);
  }
  argsText = argsText ?? "";
  findings.push(...detectInjection(argsText, ruleset));
  if (discover) {
    findings.push(...discoverInjection(argsText, ruleset));
    findings.push(...detectFileaccess(toolName, args, ruleset));
    findings.push(...detectSkill(toolName, args, ruleset));
  }
  return findings;
}
