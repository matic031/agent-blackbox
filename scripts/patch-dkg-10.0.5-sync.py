#!/usr/bin/env python3
"""Patch the DKG 10.0.5 sync hot spots that block large Blackbox SWM recovery.

This is a narrowly version-gated operational bridge for
``@origintrail-official/dkg-agent@10.0.5``.  It does not change the wire
protocol.  The important fix makes the responder build its stable SWM metadata
snapshot with explicit-graph ``FILTER EXISTS`` queries.  Oxigraph answers that
shape quickly; the stock ``VALUES ?g`` self-join can run for minutes before it
serves page one.

The remaining edits are the corresponding large-array fixes that OriginTrail
landed on ``main`` after the 10.0.5 tag (PR #1595), plus the existing Blackbox
timeout/session defaults.  The patcher also removes a retired local experiment
that treated an explicitly empty agent gate as public; an empty gate must stay
fail-closed.  Re-running the script is a no-op.  Every changed file gets a
one-time ``.bak-blackbox-sync-10.0.5`` backup.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path


SUPPORTED_VERSION = "10.0.5"
BACKUP_SUFFIX = ".bak-blackbox-sync-10.0.5"
QUERY_MARKER = "BLACKBOX_SYNC_10_0_5: explicit-graph SWM metadata snapshot"


class PatchError(RuntimeError):
    """Raised when a supported DKG build no longer matches the known source."""


def _backup(path: Path) -> None:
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    if not backup.exists():
        shutil.copy2(path, backup)


def _write(path: Path, text: str) -> None:
    _backup(path)
    path.write_text(text, encoding="utf-8")


def _replace_once(
    path: Path,
    original: str,
    replacement: str,
    *,
    already: str | None = None,
) -> bool:
    text = path.read_text(encoding="utf-8")
    if (already or replacement) in text:
        return False
    if original not in text:
        raise PatchError(f"expected DKG 10.0.5 source not found in {path}: {original!r}")
    _write(path, text.replace(original, replacement, 1))
    return True


def _patch_sync_constants(root: Path) -> int:
    path = root / "dkg-agent-constants.js"
    budgets = (
        "const _envMs = (name, fallback) => {\n"
        "    const v = Number(process.env[name] ?? '');\n"
        "    return Number.isFinite(v) && v > 0 ? v : fallback;\n"
        "};\n"
    )
    changed = 0
    text = path.read_text(encoding="utf-8")
    total = "export const SYNC_TOTAL_TIMEOUT_MS = _envMs('DKG_SYNC_TOTAL_TIMEOUT_MS', 1_200_000);"
    if total not in text:
        stock = "export const SYNC_TOTAL_TIMEOUT_MS = 120_000;"
        previous = "export const SYNC_TOTAL_TIMEOUT_MS = _envMs('DKG_SYNC_TOTAL_TIMEOUT_MS', 600_000);"
        if stock in text:
            text = text.replace(stock, budgets + total, 1)
        elif previous in text:
            text = text.replace(previous, total, 1)
        else:
            raise PatchError(f"expected DKG 10.0.5 source not found in {path}: {stock!r}")
        _write(path, text)
        changed += 1

    text = path.read_text(encoding="utf-8")
    page = "export const SYNC_PAGE_TIMEOUT_MS = _envMs('DKG_SYNC_PAGE_TIMEOUT_MS', 180_000);"
    if page not in text:
        stock = "export const SYNC_PAGE_TIMEOUT_MS = 45_000;"
        previous = "export const SYNC_PAGE_TIMEOUT_MS = _envMs('DKG_SYNC_PAGE_TIMEOUT_MS', 90_000);"
        if stock in text:
            text = text.replace(stock, page, 1)
        elif previous in text:
            text = text.replace(previous, page, 1)
        else:
            raise PatchError(f"expected DKG 10.0.5 source not found in {path}: {stock!r}")
        _write(path, text)
        changed += 1

    changed += _replace_once(
        path,
        "export const SYNC_MIN_GRAPH_BUDGET_MS = 10_000;",
        "export const SYNC_MIN_GRAPH_BUDGET_MS = _envMs('DKG_SYNC_MIN_GRAPH_BUDGET_MS', 120_000);",
    )

    session = root / "sync" / "durable-session.js"
    changed += _replace_once(
        session,
        "export const DURABLE_DATA_SYNC_SESSION_TTL_MS = 10 * 60_000;",
        "const _ttlEnv = Number(process.env.DKG_SYNC_SESSION_TTL_MS ?? '');\n"
        "export const DURABLE_DATA_SYNC_SESSION_TTL_MS = "
        "Number.isFinite(_ttlEnv) && _ttlEnv > 0 ? _ttlEnv : 60 * 60_000;",
    )

    return changed


def _patch_catchup_concurrency(root: Path) -> int:
    """Serialize catch-up peers so they cannot supersede one another."""
    path = root / "sync" / "map-with-concurrency.js"
    return _replace_once(
        path,
        "return Number.isInteger(raw) && raw > 0 ? raw : 4;",
        "return Number.isInteger(raw) && raw > 0 ? raw : 1;",
    )


def _restore_fail_closed_agent_gate(root: Path) -> int:
    """Undo the retired empty-gate-to-public experiment, if present."""
    path = root / "dkg-agent-crypto.js"
    text = path.read_text(encoding="utf-8")
    stock = "return sawAgentGate ? agents : null;"
    unsafe = "return (sawAgentGate && agents.length > 0) ? agents : null;"
    if stock in text:
        return 0
    if unsafe not in text:
        raise PatchError(
            f"expected DKG 10.0.5 agent-gate source not found in {path}"
        )
    text = text.replace(unsafe, stock, 1)
    text = re.sub(
        r"\n        // Ops patch \(umanitek\): an agent gate whose effective member set is\n"
        r"(?:        //.*\n)+?(?=        return sawAgentGate \? agents : null;)",
        "\n",
        text,
        count=1,
    )
    _write(path, text)
    return 1


def _restore_strict_private_sync(root: Path) -> int:
    """Undo the retired forced-open experiment if an older install has it."""
    path = root / "sync" / "auth" / "request-authorize.js"
    text = path.read_text(encoding="utf-8")
    changed = False
    forced = "const SWM_SYNC_OPEN = true || /^(1|true|open|yes|on)$/i.test("
    strict = "const SWM_SYNC_OPEN = /^(1|true|open|yes|on)$/i.test("
    if forced in text:
        text = text.replace(forced, strict, 1)
        changed = True
    if "if (SWM_SYNC_OPEN) {" in text:
        text = text.replace(
            "if (SWM_SYNC_OPEN) {",
            "if (SWM_SYNC_OPEN && !request.recovery) {",
            1,
        )
        changed = True
    if changed:
        _write(path, text)
    return int(changed)


def _patch_swm_meta_snapshot(root: Path) -> int:
    path = root / "sync" / "responder" / "graph-plan.js"
    text = path.read_text(encoding="utf-8")
    if QUERY_MARKER in text:
        return 0
    pattern = re.compile(
        r"async function readSwmMetaRows\(store, swmMetaGraphs, cutoffIso, signal\) \{.*?\n\}"
        r"(?=\nasync function readSwmMetaRowsPage\()",
        re.DOTALL,
    )
    replacement = f'''async function readSwmMetaRows(store, swmMetaGraphs, cutoffIso, signal) {{
    const rows = [];
    // {QUERY_MARKER}
    // Oxigraph is fast for an explicit GRAPH plus FILTER EXISTS. The stock
    // VALUES ?g / GRAPH ?g self-join can take minutes on a large SWM graph,
    // keeping aborted queries alive and preventing the first 500-row page.
    for (const graph of swmMetaGraphs) {{
        const res = await store.query(`
      SELECT ?s ?p ?o WHERE {{
        GRAPH <${{assertSafeIri(graph)}}> {{
          ?s ?p ?o .
          ${{cutoffIso
            ? `FILTER EXISTS {{
            ?s <${{DKG_PUBLISHED_AT}}> ?ts .
            FILTER(?ts >= ${{sparqlString(cutoffIso)}}^^<http://www.w3.org/2001/XMLSchema#dateTime>)
          }}`
            : ''}}
        }}
      }}
    `, syncResponderStoreOptions(signal, 'sync.responder.readSwmMetaRows'));
        if (res.type !== 'bindings')
            continue;
        for (const row of res.bindings) {{
            const s = row['s'];
            const p = row['p'];
            const o = row['o'];
            if (s && p && o)
                rows.push({{ s, p, o, g: graph }});
        }}
    }}
    return rows.sort(compareRows);
}}'''
    patched, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise PatchError(f"readSwmMetaRows() did not match DKG 10.0.5 in {path}")
    _write(path, patched)
    return 1


def _patch_large_array_appends(root: Path) -> int:
    edits = (
        (
            root / "sync" / "responder" / "graph-plan.js",
            "        rows.push(...graphRows.filter((row) => roots.has(row.s) || rootPrefixes.some((prefix) => row.s.startsWith(prefix))));",
            "        for (const row of graphRows) {\n"
            "            if (roots.has(row.s) || rootPrefixes.some((prefix) => row.s.startsWith(prefix)))\n"
            "                rows.push(row);\n"
            "        }",
        ),
        (
            root / "sync" / "requester" / "swm-recovery.js",
            "        all.push(...page.quads);",
            "        for (const quad of page.quads)\n            all.push(quad);",
        ),
        (
            root / "sync-verify-worker-impl.js",
            "                allQuadsForKC.push(...quads);",
            "                for (const quad of quads)\n                    allQuadsForKC.push(quad);",
        ),
        (
            root / "dkg-agent-utils.js",
            "                allQuadsForKC.push(...quads);",
            "                for (const quad of quads)\n                    allQuadsForKC.push(quad);",
        ),
    )
    changed = 0
    for path, original, replacement in edits:
        changed += _replace_once(path, original, replacement)
    return changed


def patch_root(root: Path) -> int:
    package_json = root.parent / "package.json"
    if not package_json.is_file():
        raise PatchError(f"missing {package_json}")
    version = str(json.loads(package_json.read_text(encoding="utf-8")).get("version", ""))
    if version != SUPPORTED_VERSION:
        print(f"skip {root}: dkg-agent {version or 'unknown'} (patch is only for {SUPPORTED_VERSION})")
        return 0

    # A source-drift failure late in the patch must not strand a half-patched
    # npm install.  Keep an in-memory transaction snapshot; one-time backups
    # are still retained for operator rollback after a successful run.
    candidates = (
        root / "dkg-agent-constants.js",
        root / "sync" / "durable-session.js",
        root / "dkg-agent-crypto.js",
        root / "sync" / "map-with-concurrency.js",
        root / "sync" / "auth" / "request-authorize.js",
        root / "sync" / "responder" / "graph-plan.js",
        root / "sync" / "requester" / "swm-recovery.js",
        root / "sync-verify-worker-impl.js",
        root / "dkg-agent-utils.js",
    )
    before = {path: path.read_text(encoding="utf-8") for path in candidates}
    try:
        changed = 0
        changed += _patch_sync_constants(root)
        changed += _patch_catchup_concurrency(root)
        changed += _restore_fail_closed_agent_gate(root)
        changed += _restore_strict_private_sync(root)
        changed += _patch_swm_meta_snapshot(root)
        changed += _patch_large_array_appends(root)
        return changed
    except Exception:
        for path, original in before.items():
            if path.read_text(encoding="utf-8") != original:
                path.write_text(original, encoding="utf-8")
        raise


def find_dist_roots(cli_dir: Path) -> list[Path]:
    return sorted(cli_dir.expanduser().glob("node_modules/**/dkg-agent/dist"))


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print(f"usage: {Path(sys.argv[0]).name} <dkg-cli-directory>", file=sys.stderr)
        return 2
    cli_dir = Path(args[0]).expanduser()
    roots = find_dist_roots(cli_dir)
    if not roots:
        print(f"dkg-agent dist not found under {cli_dir}", file=sys.stderr)
        return 1
    try:
        changed = sum(patch_root(root) for root in roots)
    except (OSError, ValueError, PatchError) as exc:
        print(f"patch-dkg-10.0.5-sync: {exc}", file=sys.stderr)
        return 1
    print(f"patch-dkg-10.0.5-sync: {len(roots)} install(s), {changed} change(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
