/**
 * Umanitek Agent Guardian — OpenClaw plugin.
 *
 * Mirrors the hermes guardian plugin's detection and reports sightings to the
 * SAME local DKG node / threat graph. Detection rules come ONLY from the synced
 * threat graph (ruleset.ts); on an empty graph nothing is detected — by design.
 *
 * Hooks:
 *   before_tool_call   — detect escalation/dependency/injection over params;
 *                        block (block mode, >= block_severity) or observe+report
 *   after_tool_call    — observe result (redacted); never blocks
 *   before_agent_run   — prompt-injection scan (needs allowConversationAccess)
 *   message_received   — observe inbound content for injection sightings
 *   session_start/end  — lifecycle observation
 *
 * Everything is fail-open: any error in a handler is swallowed and the agent
 * loop proceeds. Threat pushes to the DKG are deterministic HTTP calls only.
 */
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import type {
  PluginHookAfterToolCallEvent,
  PluginHookBeforeAgentRunEvent,
  PluginHookBeforeAgentRunResult,
  PluginHookBeforeToolCallEvent,
  PluginHookBeforeToolCallResult,
  PluginHookMessageReceivedEvent,
  PluginHookSessionEndEvent,
  PluginHookSessionStartEvent,
} from "openclaw/plugin-sdk/plugin-entry";
import {
  Finding,
  Ruleset,
  collectText,
  detectAll,
  detectCustomFileAccess,
  detectInjection,
  discoverInjection,
  discoverDependencyCandidates,
} from "./detection.js";
import { DkgClient, DkgError } from "./dkgClient.js";
import { GuardianConfig, categoryAllows, resolveConfig } from "./config.js";
import { RulesetCache } from "./ruleset.js";
import { GuardianSeverity, SEVERITY_RANK, buildReportQuads, stableHash } from "./quads.js";
import { lookup as osvLookup } from "./osv.js";
import { redact, sanitizeText } from "./redact.js";

const PLUGIN_ID = "guardian";
const FRAMEWORK = "openclaw" as const;

/**
 * Idempotent-registration guard. OpenClaw has NO unsubscribe primitive, so a
 * second `register(api)` for the same plugin id must not double-wire hooks.
 * Keyed by a stable per-process token so reloads with a fresh api still wire
 * once. We track the api object identity in a WeakSet plus a module flag.
 */
const registeredApis = new WeakSet<object>();
let registeredOnce = false;

interface GuardianRuntime {
  cfg: GuardianConfig;
  client: DkgClient;
  ruleset: RulesetCache;
  /** Cached reporter agent address, resolved lazily from the node (never the token). */
  reporterAddress?: string;
  log: (level: "debug" | "warn", msg: string, meta?: unknown) => void;
  dailyReports: { date: string; count: number };
  /**
   * Per-identifier report cooldown stamps (identifier → epoch ms of the last
   * outbound sighting). A re-fire of the same identifier within
   * `REPORT_COOLDOWN_MS` adds no signal and is not re-reported. Mirrors
   * Python `audit.REPORT_COOLDOWN_SECS` / `allow_report`.
   */
  recentReports: Map<string, number>;
}

/** Re-reporting the same identifier within this window adds no signal (the
 * sighting KA name is stable per identifier+reporter, so a re-share only
 * refreshes dateModified) — skip it. Mirrors Python audit.REPORT_COOLDOWN_SECS. */
const REPORT_COOLDOWN_MS = 6 * 3600 * 1000;

/** Drop expired cooldown stamps so the map stays small. */
function pruneRecentReports(rt: GuardianRuntime, now: number): void {
  if (rt.recentReports.size <= 2048) return;
  for (const [identifier, ts] of rt.recentReports) {
    if (now - ts >= REPORT_COOLDOWN_MS) rt.recentReports.delete(identifier);
  }
}

/**
 * Apply the user's detection policy to raw findings. Two layers:
 *
 *   1. Per-category policy (`detection.<category>.{enabled,minSeverity}`) — a
 *      disabled category never flags; a category floor drops anything below it
 *      (e.g. "only critical dependency vulns").
 *   2. Heuristic gate — built-in discovery candidates additionally need
 *      `reportMinSeverity`; they are nominations, not confirmed threats.
 *
 * Graph-backed findings (public / community) skip the heuristic gate. User
 * custom rules (`source === "custom"`) bypass the category policy entirely —
 * the user explicitly asked for them. Mirrors Python `hooks._flag_worthy`.
 */
function flagWorthy(cfg: GuardianConfig, findings: Finding[]): Finding[] {
  const out: Finding[] = [];
  for (const f of findings) {
    if (f.source === "custom") {
      out.push(f);
      continue;
    }
    if (!categoryAllows(cfg, f.category, f.severity)) continue;
    if (f.source === "heuristic" && SEVERITY_RANK[f.severity] < SEVERITY_RANK[cfg.reportMinSeverity]) {
      continue;
    }
    out.push(f);
  }
  return out;
}

/**
 * Resolve (and cache on the runtime) the reporter agent address from the node.
 * Definitive source is `GET /api/agent/identity`; fails open to "node". We do
 * NOT derive the reporter from the auth token — the node's true agent address is
 * what namespaces the per-submitter report URI.
 */
async function resolveReporter(rt: GuardianRuntime): Promise<string> {
  if (rt.reporterAddress !== undefined) return rt.reporterAddress;
  try {
    rt.reporterAddress = await rt.client.reporterAddress();
  } catch {
    rt.reporterAddress = "node";
  }
  return rt.reporterAddress;
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

function underDailyCap(rt: GuardianRuntime): boolean {
  const d = today();
  if (rt.dailyReports.date !== d) {
    rt.dailyReports = { date: d, count: 0 };
  }
  return rt.dailyReports.count < rt.cfg.dailyReportLimit;
}

/**
 * Report a sighting to the SWM (one-shot KA share). Deterministic HTTP, fully
 * fail-open, rate-limited by daily cap + per-identifier cooldown. Reports
 * carry NO observed content.
 */
async function reportSighting(rt: GuardianRuntime, finding: Finding): Promise<void> {
  // Custom (user-configured) rules are personal: they are surfaced/blocked
  // locally but NEVER leave this machine — no community sighting. Mirrors
  // Python `_report_and_audit` skipping `source == "custom"`.
  if (finding.source === "custom") return;
  if (!rt.cfg.report) return;
  // Per-threat cooldown: a re-fire of the same identifier within the window
  // adds no signal — skip the sighting. Mirrors Python `audit.allow_report`.
  const now = Date.now();
  const last = rt.recentReports.get(finding.identifier);
  if (last !== undefined && now - last < REPORT_COOLDOWN_MS) {
    rt.log("debug", `guardian: report cooldown active for ${finding.identifier}`);
    return;
  }
  if (!underDailyCap(rt)) {
    rt.log("debug", "guardian: daily report cap reached, dropping sighting");
    return;
  }
  // Stamp before the share (like Python's allow_report) so a burst of re-fires
  // can't queue N identical shares while the first is in flight.
  rt.recentReports.set(finding.identifier, now);
  pruneRecentReports(rt, now);
  try {
    const reporter = await resolveReporter(rt);
    // For candidate (heuristic-only) findings, forward the privacy-safe threat
    // fields so a curator can promote the candidate directly. `fields` only ever
    // holds signatures (pattern/category/shape/...), never raw prompts, paths,
    // or file/skill source. Mirrors Python `_share_sighting`.
    const quads = buildReportQuads({
      identifier: finding.identifier,
      category: finding.category,
      severity: finding.severity,
      reporter,
      framework: FRAMEWORK,
      candidate: finding.fields,
    });
    // KA name matches Python hooks._share_sighting exactly:
    // "report-" + stableHash(identifier + reporter, 16). Hashing in the
    // reporter keeps two reporters of the same threat from colliding on one
    // KA name while staying stable per (identifier, reporter).
    const name = `report-${stableHash(finding.identifier + reporter, 16)}`;
    await rt.client.shareKnowledgeAsset(rt.cfg.contextGraphId, name, quads);
    rt.dailyReports.count += 1;
  } catch (err) {
    if (err instanceof DkgError) {
      rt.log("debug", `guardian: sighting report failed (node unreachable): ${err.message}`);
      return;
    }
    rt.log("debug", `guardian: sighting report error: ${(err as Error).message}`);
  }
}

/**
 * Findings that can block at or above the block threshold: CONFIRMED public-graph
 * matches (`source === "public"`) and the user's own custom rules
 * (`source === "custom"`). Community-pool matches and discovery candidates never
 * block — they only alert/report. Mirrors Python's `pre_tool_call` blocking
 * filter (`f.confirmed or f.source == "custom"`).
 */
function meetsBlock(finding: Finding, cfg: GuardianConfig): boolean {
  return (
    (finding.confirmed || finding.source === "custom") &&
    SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[cfg.blockSeverity]
  );
}

function maxSeverity(findings: Finding[]): GuardianSeverity {
  return findings.reduce<GuardianSeverity>(
    (best, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[best] ? f.severity : best),
    "info",
  );
}

function blockMessage(findings: Finding[]): string {
  const worst = maxSeverity(findings);
  const titles = [...new Set(findings.map((f) => f.title))].slice(0, 3).join("; ");
  return `Umanitek Guardian blocked this action (${worst}): ${titles}`;
}

// --- Hook handlers ---------------------------------------------------------

function makeBeforeToolCall(rt: GuardianRuntime) {
  return async (
    event: PluginHookBeforeToolCallEvent,
  ): Promise<PluginHookBeforeToolCallResult | void> => {
    try {
      const ruleset: Ruleset = rt.ruleset.get();
      const params = (event.params ?? {}) as Record<string, unknown>;
      // detectAll covers escalation + dependency + injection, plus the built-in
      // discovery layer (candidate injection / file-access / skill) when
      // `discover` is enabled. detectCustomFileAccess adds the user's own
      // protected-path rules (source="custom"). flagWorthy then applies the
      // per-category policy + heuristic gate (custom rules bypass both).
      // Mirrors Python `detect_all` + `detect_custom_fileaccess` + `_flag_worthy`.
      const raw = detectAll(event.toolName, params, ruleset, rt.cfg.discover);
      raw.push(...detectCustomFileAccess(event.toolName, params, rt.cfg.protectedPaths));
      const findings: Finding[] = flagWorthy(rt.cfg, raw);

      // Dependency OSV auto-discovery runs OFF the blocking path (best-effort,
      // fail-open) so a network lookup never delays or breaks the tool call.
      if (rt.cfg.discover && rt.cfg.osvLookup) {
        void discoverDependencyCandidates(event.toolName, params, ruleset, osvLookup)
          .then((candidates) => {
            for (const f of flagWorthy(rt.cfg, candidates)) void reportSighting(rt, f);
          })
          .catch(() => {
            /* fail-open — OSV discovery must never break the loop */
          });
      }

      if (findings.length === 0) return;

      // Observe + report every finding (fire-and-forget; never blocks the loop).
      for (const f of findings) void reportSighting(rt, f);

      if (rt.cfg.mode === "block") {
        // Confirmed graph findings and the user's own custom rules can block
        // (see meetsBlock).
        const blocking = findings.filter((f) => meetsBlock(f, rt.cfg));
        if (blocking.length > 0) {
          return { block: true, blockReason: blockMessage(blocking) };
        }
      }
      return;
    } catch (err) {
      rt.log("debug", `guardian: before_tool_call error: ${(err as Error).message}`);
      return; // fail-open
    }
  };
}

function makeAfterToolCall(rt: GuardianRuntime) {
  return async (event: PluginHookAfterToolCallEvent): Promise<void> => {
    try {
      // Observation only — record a redacted result summary for local audit.
      if (event.error) {
        rt.log("debug", `guardian: tool ${event.toolName} errored`, { error: sanitizeText(event.error, 300) });
      }
    } catch {
      /* fail-open */
    }
  };
}

function makeBeforeAgentRun(rt: GuardianRuntime) {
  return async (
    event: PluginHookBeforeAgentRunEvent,
  ): Promise<PluginHookBeforeAgentRunResult> => {
    try {
      const ruleset = rt.ruleset.get();
      const text = [event.prompt ?? "", ...collectText(event.messages)].join("\n");
      let findings = detectInjection(text, ruleset);
      if (rt.cfg.discover) findings.push(...discoverInjection(text, ruleset));
      findings = flagWorthy(rt.cfg, findings);
      if (findings.length === 0) return { outcome: "pass" };

      for (const f of findings) void reportSighting(rt, f);

      if (rt.cfg.mode === "block") {
        const blocking = findings.filter((f) => meetsBlock(f, rt.cfg));
        if (blocking.length > 0) {
          return {
            outcome: "block",
            reason: `guardian:prompt-injection:${blocking.map((f) => f.identifier).join(",")}`,
            message: "This request was blocked because it contained prompt-injection content.",
          };
        }
      }
      return { outcome: "pass" };
    } catch (err) {
      rt.log("debug", `guardian: before_agent_run error: ${(err as Error).message}`);
      return { outcome: "pass" }; // fail-open
    }
  };
}

function makeMessageReceived(rt: GuardianRuntime) {
  return async (event: PluginHookMessageReceivedEvent): Promise<void> => {
    try {
      const ruleset = rt.ruleset.get();
      const text = event.content ?? "";
      const findings = detectInjection(text, ruleset);
      if (rt.cfg.discover) findings.push(...discoverInjection(text, ruleset));
      for (const f of flagWorthy(rt.cfg, findings)) void reportSighting(rt, f);
    } catch {
      /* fail-open — message_received is observation-only */
    }
  };
}

function makeSessionStart(rt: GuardianRuntime) {
  return async (event: PluginHookSessionStartEvent): Promise<void> => {
    rt.log("debug", `guardian: session_start ${event.sessionId}`);
    // Warm the ruleset so the first tool call has fresh rules.
    try {
      await rt.ruleset.sync();
    } catch {
      /* fail-open */
    }
  };
}

function makeSessionEnd(rt: GuardianRuntime) {
  return async (event: PluginHookSessionEndEvent): Promise<void> => {
    rt.log("debug", `guardian: session_end ${event.sessionId} (${event.reason ?? "unknown"})`);
  };
}

// --- Registration ----------------------------------------------------------

function buildRuntime(api: OpenClawPluginApi): GuardianRuntime {
  const cfg = resolveConfig((api.pluginConfig ?? {}) as Record<string, unknown>);
  const client = new DkgClient({ url: cfg.dkgUrl });
  const ruleset = new RulesetCache({
    client,
    contextGraphId: cfg.contextGraphId,
    ttlSeconds: cfg.syncInterval,
  });
  // Reporter address is resolved lazily from the node (GET /api/agent/identity),
  // cached on the runtime, and fails open to "node". It is NOT derived from the
  // auth token — the node's true agent address namespaces the per-submitter URI.
  const log = (level: "debug" | "warn", msg: string, meta?: unknown) => {
    try {
      const logger = api.logger as unknown as Record<string, ((m: string, x?: unknown) => void) | undefined>;
      const fn = logger?.[level] ?? logger?.info;
      if (typeof fn === "function") fn(msg, meta);
    } catch {
      /* logging must never throw */
    }
  };
  return {
    cfg,
    client,
    ruleset,
    log,
    dailyReports: { date: today(), count: 0 },
    recentReports: new Map<string, number>(),
  };
}

export function register(api: OpenClawPluginApi): void {
  // Idempotent guard: no unsubscribe primitive exists, so never double-wire.
  if (registeredApis.has(api) || registeredOnce) {
    try {
      (api.logger as unknown as { debug?: (m: string) => void })?.debug?.(
        "guardian: register() called again; skipping duplicate hook wiring",
      );
    } catch {
      /* ignore */
    }
    return;
  }
  registeredApis.add(api);
  registeredOnce = true;

  const rt = buildRuntime(api);

  api.on("before_tool_call", makeBeforeToolCall(rt), { priority: 100 });
  api.on("after_tool_call", makeAfterToolCall(rt));
  api.on("before_agent_run", makeBeforeAgentRun(rt), { priority: 100 });
  api.on("message_received", makeMessageReceived(rt));
  api.on("session_start", makeSessionStart(rt));
  api.on("session_end", makeSessionEnd(rt));

  rt.log(
    "debug",
    `guardian: registered (mode=${rt.cfg.mode}, cg=${rt.cfg.contextGraphId}, dkg=${rt.client.url})`,
  );
}

/** For tests: reset the process-level idempotency latch. */
export function __resetRegistrationGuardForTests(): void {
  registeredOnce = false;
}

export default definePluginEntry({
  id: PLUGIN_ID,
  name: "Umanitek Agent Guardian",
  description:
    "Mirrors hermes guardian detection in OpenClaw and reports sightings to the local DKG threat graph.",
  // No exclusive `kind` — Guardian is a hook-only policy/observability plugin
  // and must not claim a singleton slot (memory | context-engine).
  register,
});

export { resolveConfig } from "./config.js";
export type { GuardianConfig } from "./config.js";
