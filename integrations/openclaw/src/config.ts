/**
 * Guardian config resolution.
 *
 * Source order (later wins): built-in defaults → `plugins.entries.guardian.config`
 * (passed by OpenClaw as `api.pluginConfig`) → environment overrides.
 *
 * Keys mirror the hermes plugin's config table so the two frameworks stay in
 * lockstep.
 */
import { GuardianSeverity, SEVERITY_RANK, normalizeSeverity } from "./quads.js";

export interface GuardianConfig {
  mode: "audit" | "block";
  contextGraphId: string;
  dkgUrl: string;
  syncInterval: number; // seconds
  report: boolean;
  dailyReportLimit: number;
  blockSeverity: GuardianSeverity;
  /** Run the built-in discovery nomination layer (candidate threats). */
  discover: boolean;
  /** Run OSV dependency auto-discovery off the blocking path. */
  osvLookup: boolean;
}

const DEFAULTS: GuardianConfig = {
  mode: "audit",
  contextGraphId: "umanitek/guardian-threats",
  dkgUrl: "http://127.0.0.1:9200",
  syncInterval: 300,
  report: true,
  dailyReportLimit: 500,
  blockSeverity: "critical",
  discover: true,
  osvLookup: true,
};

function str(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function num(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const n = Number(value);
    if (Number.isFinite(n)) return n;
  }
  return undefined;
}

function bool(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    const v = value.trim().toLowerCase();
    if (["true", "1", "yes", "on"].includes(v)) return true;
    if (["false", "0", "no", "off"].includes(v)) return false;
  }
  return undefined;
}

function mode(value: unknown): "audit" | "block" | undefined {
  const v = str(value)?.toLowerCase();
  return v === "audit" || v === "block" ? v : undefined;
}

function severity(value: unknown): GuardianSeverity | undefined {
  const v = str(value);
  if (!v) return undefined;
  const norm = normalizeSeverity(v, "critical");
  return norm in SEVERITY_RANK ? norm : undefined;
}

/**
 * Merge plugin config + env into a resolved GuardianConfig. `pluginConfig` is
 * the `plugins.entries.guardian.config` object OpenClaw injects per handler.
 */
export function resolveConfig(pluginConfig: Record<string, unknown> = {}): GuardianConfig {
  const env = process.env;
  return {
    mode: mode(env.GUARDIAN_MODE) ?? mode(pluginConfig.mode) ?? DEFAULTS.mode,
    contextGraphId:
      str(env.GUARDIAN_CONTEXT_GRAPH_ID) ??
      str(pluginConfig.contextGraphId) ??
      str(pluginConfig.context_graph_id) ??
      DEFAULTS.contextGraphId,
    dkgUrl: str(env.DKG_DAEMON_URL) ?? str(pluginConfig.dkgUrl) ?? str(pluginConfig.dkg_url) ?? DEFAULTS.dkgUrl,
    syncInterval:
      num(env.GUARDIAN_SYNC_INTERVAL) ??
      num(pluginConfig.syncInterval) ??
      num(pluginConfig.sync_interval) ??
      DEFAULTS.syncInterval,
    report: bool(env.GUARDIAN_REPORT) ?? bool(pluginConfig.report) ?? DEFAULTS.report,
    dailyReportLimit:
      num(env.GUARDIAN_DAILY_REPORT_LIMIT) ??
      num(pluginConfig.dailyReportLimit) ??
      num(pluginConfig.daily_report_limit) ??
      DEFAULTS.dailyReportLimit,
    blockSeverity:
      severity(env.GUARDIAN_BLOCK_SEVERITY) ??
      severity(pluginConfig.blockSeverity) ??
      severity(pluginConfig.block_severity) ??
      DEFAULTS.blockSeverity,
    discover:
      bool(env.GUARDIAN_DISCOVER) ??
      bool(pluginConfig.discover) ??
      DEFAULTS.discover,
    osvLookup:
      bool(env.GUARDIAN_OSV_LOOKUP) ??
      bool(pluginConfig.osvLookup) ??
      bool(pluginConfig.osv_lookup) ??
      DEFAULTS.osvLookup,
  };
}

export { DEFAULTS as GUARDIAN_CONFIG_DEFAULTS };
