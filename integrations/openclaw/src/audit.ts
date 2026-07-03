/**
 * Local findings log for the OpenClaw plugin.
 *
 * The Guardian dashboard's "Live findings" table reads JSONL logs from the
 * shared guardian home. The Python (Hermes) plugin writes `findings.jsonl`;
 * this module writes `findings.openclaw.jsonl` into the SAME home (see
 * `config.guardianHome`, set by `hermes guardian attach`) so the one dashboard
 * surfaces OpenClaw detections alongside Hermes'. Line shape matches the Python
 * `audit.record` finding line so `audit.read_findings` flattens it unchanged.
 *
 * Best-effort and fail-open — a logging error must never break the agent loop.
 */
import { appendFileSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "./detection.js";
import { sanitizeText } from "./redact.js";

const FRAMEWORK = "openclaw" as const;
const LOG_FILE = "findings.openclaw.jsonl";
const LOG_MAX_BYTES = 8 * 1024 * 1024; // trim at 8 MB (matches Python)
const LOG_KEEP_BYTES = 4 * 1024 * 1024; // keep most-recent ~4 MB after trimming

/** UTC `YYYY-MM-DDTHH:MM:SSZ` — matches Python `time.strftime(...gmtime())`. */
function isoNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** Append one finding to `<home>/findings.openclaw.jsonl`. Fail-open. */
export function recordFinding(
  home: string,
  event: string,
  finding: Finding,
  toolName?: string,
): void {
  try {
    if (!home) return;
    mkdirSync(home, { recursive: true });
    const now = Date.now() / 1000;
    const tool = toolName ?? finding.toolName ?? "";
    const line = {
      ts: now,
      iso: isoNow(),
      event,
      framework: FRAMEWORK,
      detail: { tool_name: tool },
      // Same nested shape Python writes so read_findings lifts these fields.
      finding: {
        identifier: finding.identifier,
        category: finding.category,
        severity: finding.severity,
        title: finding.title,
        tool_name: tool,
        evidence: sanitizeText(String(finding.evidence ?? ""), 700),
        confirmed: finding.confirmed,
        candidate: !finding.confirmed,
        source: finding.source,
        framework: FRAMEWORK,
        ts: now,
      },
    };
    const path = join(home, LOG_FILE);
    appendFileSync(path, JSON.stringify(line) + "\n", "utf8");
    trimIfNeeded(path);
  } catch {
    /* fail-open — never break the agent loop over a log write */
  }
}

/** Keep the tail of the log when it grows past the cap (whole lines only). */
function trimIfNeeded(path: string): void {
  try {
    if (statSync(path).size <= LOG_MAX_BYTES) return;
    const buf = readFileSync(path);
    let tail = buf.subarray(buf.length - LOG_KEEP_BYTES);
    const nl = tail.indexOf(0x0a); // drop a possibly-partial first line
    if (nl !== -1) tail = tail.subarray(nl + 1);
    writeFileSync(path, tail);
  } catch {
    /* defensive */
  }
}
