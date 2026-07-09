/**
 * Cross-language identifier PARITY test.
 *
 * Asserts the TypeScript integration reproduces the canonical Python
 * `plugins/blackbox/quads.py` byte-for-byte, using the shared ground-truth
 * fixture `tests/parity/identifier_fixtures.json`. If any group fails the
 * cross-framework threat-graph flywheel would silently break (the same threat
 * seen by Hermes and OpenClaw would get different IDs → no correlation).
 *
 * Run with (tsx transpiles the imported .ts modules on the fly):
 *   npx -y tsx integrations/openclaw/test/parity.mjs
 *
 * Exits non-zero on any mismatch.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  threatIdentifierFor,
  threatUri,
  reportUri,
  buildReportQuads,
  literal,
  javaModifiedUtf8ByteLength,
  MAX_LITERAL_BYTES,
} from "../src/quads.ts";
import { normalizeArgShape, parseDependencyInstalls } from "../src/detection.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(here, "../../../tests/parity/identifier_fixtures.json");
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));

let failures = 0;

function report(group, ok, detail) {
  if (ok) {
    console.log(`PASS  ${group}`);
  } else {
    failures += 1;
    console.log(`FAIL  ${group}`);
    if (detail) console.log(detail);
  }
}

function eq(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

// --- identifiers + threatUri ------------------------------------------------
{
  let ok = true;
  const mismatches = [];
  for (const c of fixture.identifiers) {
    let id;
    if (c.kind === "dependency") {
      id = threatIdentifierFor({
        type: "dependency",
        ecosystem: c.in.ecosystem,
        name: c.in.name,
        version: c.in.version,
      });
    } else if (c.kind === "injection") {
      id = threatIdentifierFor({ type: "injection", pattern: c.in.pattern });
    } else if (c.kind === "fileaccess") {
      id = threatIdentifierFor({
        type: "fileaccess",
        toolName: c.in.tool_name,
        category: c.in.category,
      });
    } else if (c.kind === "skill_version") {
      id = threatIdentifierFor({
        type: "skill_version",
        name: c.in.name,
        version: c.in.version,
      });
    } else if (c.kind === "skill_shape") {
      id = threatIdentifierFor({
        type: "skill_shape",
        name: c.in.name,
        dangerShape: c.in.danger_shape,
      });
    } else {
      id = threatIdentifierFor({
        type: "escalation",
        toolName: c.in.tool_name,
        argShape: c.in.arg_shape,
      });
    }
    const uri = threatUri(id);
    if (id !== c.identifier || uri !== c.threatUri) {
      ok = false;
      mismatches.push(
        `  ${c.kind} ${JSON.stringify(c.in)}\n    id  got=${id} want=${c.identifier}\n    uri got=${uri} want=${c.threatUri}`,
      );
    }
  }
  report("identifiers", ok, mismatches.join("\n"));
}

// --- reportUris -------------------------------------------------------------
{
  let ok = true;
  const mismatches = [];
  for (const c of fixture.reportUris) {
    const got = reportUri(c.identifier, c.reporter);
    if (got !== c.reportUri) {
      ok = false;
      mismatches.push(`  ${c.identifier} / "${c.reporter}"\n    got=${got}\n    want=${c.reportUri}`);
    }
  }
  report("reportUris", ok, mismatches.join("\n"));
}

// --- argShapes (single top-priority shape or null) --------------------------
{
  let ok = true;
  const mismatches = [];
  for (const c of fixture.argShapes) {
    const got = normalizeArgShape(c.tool, c.args);
    const want = c.shape ?? null;
    if (got !== want) {
      ok = false;
      mismatches.push(`  ${c.tool} ${JSON.stringify(c.args)}\n    got=${got} want=${want}`);
    }
  }
  report("argShapes", ok, mismatches.join("\n"));
}

// --- dependencyParses -------------------------------------------------------
{
  let ok = true;
  const mismatches = [];
  for (const c of fixture.dependencyParses) {
    const got = parseDependencyInstalls(c.command);
    const want = c.packages;
    if (!eq(got, want)) {
      ok = false;
      mismatches.push(
        `  ${JSON.stringify(c.command)}\n    got =${JSON.stringify(got)}\n    want=${JSON.stringify(want)}`,
      );
    }
  }
  report("dependencyParses", ok, mismatches.join("\n"));
}

// --- reportQuads (drop dateModified, sort by (predicate,object)) ------------
{
  const DATE_MODIFIED = "http://schema.org/dateModified";
  const sortQuads = (quads) =>
    [...quads]
      .filter((q) => q.predicate !== DATE_MODIFIED)
      .sort((a, b) =>
        a.predicate < b.predicate
          ? -1
          : a.predicate > b.predicate
            ? 1
            : a.object < b.object
              ? -1
              : a.object > b.object
                ? 1
                : 0,
      );

  let ok = true;
  const mismatches = [];
  for (const c of fixture.reportQuads) {
    const i = c.in;
    const quads = buildReportQuads({
      identifier: i.identifier,
      category: i.category,
      severity: i.severity,
      reporter: i.reporter_address,
      framework: i.framework,
      candidate: {
        pattern: i.pattern,
        owaspCategory: i.owasp_category,
        toolName: i.tool_name,
        argShape: i.arg_shape,
        packageName: i.package_name,
        packageVersion: i.package_version,
        packageEcosystem: i.ecosystem,
        advisoryId: i.advisory_id,
        fileCategory: i.file_category,
        skillName: i.skill_name,
        skillVersion: i.skill_version,
        dangerShape: i.danger_shape,
      },
    });
    const got = sortQuads(quads);
    const want = sortQuads(c.quadsNoDate);
    if (!eq(got, want)) {
      ok = false;
      mismatches.push(`  ${i.identifier}\n    got =${JSON.stringify(got)}\n    want=${JSON.stringify(want)}`);
    }
  }
  report("reportQuads", ok, mismatches.join("\n"));
}

// --- literal caps -----------------------------------------------------------
{
  const value = literal("x".repeat(MAX_LITERAL_BYTES + 1000)).slice(1, -1);
  const escaped = literal("\n".repeat(MAX_LITERAL_BYTES));
  const emoji = literal("😀".repeat(MAX_LITERAL_BYTES));
  report(
    "literal cap",
    javaModifiedUtf8ByteLength(`"${value}"`) <= MAX_LITERAL_BYTES &&
      javaModifiedUtf8ByteLength(escaped) <= MAX_LITERAL_BYTES &&
      javaModifiedUtf8ByteLength(emoji) <= MAX_LITERAL_BYTES &&
      value.endsWith("...[truncated]"),
    `literal MUTF-8 byteLength=${javaModifiedUtf8ByteLength(`"${value}"`)}`,
  );
}

console.log("");
if (failures > 0) {
  console.log(`RESULT: ${failures} group(s) FAILED`);
  process.exit(1);
}
console.log("RESULT: all groups PASS");
