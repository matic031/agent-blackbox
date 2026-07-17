import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { currentWorkspace, recordEvent } from "../src/audit.ts";

const root = mkdtempSync(join(tmpdir(), "blackbox-openclaw-audit-"));
const previous = {
  config: process.env.OPENCLAW_CONFIG_PATH,
  state: process.env.OPENCLAW_STATE_DIR,
  home: process.env.OPENCLAW_HOME,
};

try {
  delete process.env.OPENCLAW_CONFIG_PATH;
  delete process.env.OPENCLAW_HOME;
  process.env.OPENCLAW_STATE_DIR = join(root, ".openclaw-dev");
  const logHome = join(root, "shared-blackbox");

  recordEvent(logHome, "session_start", { session_id: "test" });

  const row = JSON.parse(readFileSync(join(logHome, "audit.openclaw.jsonl"), "utf8"));
  if (row.workspace !== currentWorkspace() || row.workspace !== process.env.OPENCLAW_STATE_DIR) {
    throw new Error(`workspace mismatch: ${JSON.stringify(row)}`);
  }
  console.log("PASS  OpenClaw audit workspace attribution");
} finally {
  if (previous.config === undefined) delete process.env.OPENCLAW_CONFIG_PATH;
  else process.env.OPENCLAW_CONFIG_PATH = previous.config;
  if (previous.state === undefined) delete process.env.OPENCLAW_STATE_DIR;
  else process.env.OPENCLAW_STATE_DIR = previous.state;
  if (previous.home === undefined) delete process.env.OPENCLAW_HOME;
  else process.env.OPENCLAW_HOME = previous.home;
  rmSync(root, { recursive: true, force: true });
}
