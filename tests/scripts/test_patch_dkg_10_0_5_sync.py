"""Behavior tests for the version-gated DKG 10.0.5 sync hotfix."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "patch-dkg-10.0.5-sync.py"
)
SPEC = importlib.util.spec_from_file_location("patch_dkg_10_0_5_sync", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise ImportError(f"Failed to load {SCRIPT_PATH}")
PATCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PATCHER)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _make_dkg_agent_fixture(
    tmp_path: Path,
    *,
    version: str = "10.0.5",
    drifted_constant: bool = False,
) -> tuple[Path, Path]:
    """Create the relevant portion of a compiled dkg-agent npm install."""
    cli_dir = tmp_path / "dkg-cli"
    package_dir = (
        cli_dir / "node_modules" / "@origintrail-official" / "dkg-agent"
    )
    dist = package_dir / "dist"
    _write(package_dir / "package.json", f'{{"version": "{version}"}}\n')

    total_timeout = "121_000" if drifted_constant else "120_000"
    _write(
        dist / "dkg-agent-constants.js",
        "export const OTHER_CONSTANT = 1;\n"
        f"export const SYNC_TOTAL_TIMEOUT_MS = {total_timeout};\n"
        "export const SYNC_PAGE_TIMEOUT_MS = 45_000;\n"
        "export const SYNC_MIN_GRAPH_BUDGET_MS = 10_000;\n",
    )
    _write(
        dist / "sync" / "durable-session.js",
        "export const DURABLE_DATA_SYNC_SESSION_TTL_MS = 10 * 60_000;\n",
    )
    _write(
        dist / "sync" / "map-with-concurrency.js",
        "export const CATCHUP_MAX_CONCURRENT_PEER_SYNCS = (() => {\n"
        "    const raw = Number(process.env.DKG_CATCHUP_MAX_CONCURRENT_PEERS);\n"
        "    return Number.isInteger(raw) && raw > 0 ? raw : 4;\n"
        "})();\n",
    )
    _write(
        dist / "dkg-agent-crypto.js",
        "function agentsForGate(sawAgentGate, agents) {\n"
        "    return sawAgentGate ? agents : null;\n"
        "}\n",
    )
    _write(
        dist / "sync" / "auth" / "request-authorize.js",
        "const SWM_SYNC_OPEN = true || /^(1|true|open|yes|on)$/i.test(\n"
        "    process.env.DKG_SWM_SYNC_OPEN ?? '',\n"
        ");\n"
        "export async function authorizePrivateSyncRequest(request) {\n"
        "    if (SWM_SYNC_OPEN) {\n"
        "        return true;\n"
        "    }\n"
        "    return authorizeStrictly(request);\n"
        "}\n",
    )
    _write(
        dist / "sync" / "responder" / "graph-plan.js",
        "async function readSwmMetaRows(store, swmMetaGraphs, cutoffIso, signal) {\n"
        "    const values = graphValues(swmMetaGraphs);\n"
        "    const res = await store.query(`\n"
        "      SELECT DISTINCT ?g ?s ?p ?o WHERE {\n"
        "        VALUES ?g { ${values} }\n"
        "        GRAPH ?g { ?s ?p ?o }\n"
        "      }\n"
        "    `, syncResponderStoreOptions(signal, "
        "'sync.responder.readSwmMetaRows'));\n"
        "    return res.bindings;\n"
        "}\n"
        "async function readSwmMetaRowsPage() {\n"
        "    return [];\n"
        "}\n"
        "async function readFreshSwmDataRows() {\n"
        "    const rows = [];\n"
        "    const graphRows = [];\n"
        "    const roots = new Set();\n"
        "    const rootPrefixes = [];\n"
        "        rows.push(...graphRows.filter((row) => roots.has(row.s) || "
        "rootPrefixes.some((prefix) => row.s.startsWith(prefix))));\n"
        "    return rows;\n"
        "}\n",
    )
    _write(
        dist / "sync" / "requester" / "swm-recovery.js",
        "async function recover(page) {\n"
        "    const all = [];\n"
        "        all.push(...page.quads);\n"
        "    return all;\n"
        "}\n",
    )
    for relative_path in ("sync-verify-worker-impl.js", "dkg-agent-utils.js"):
        _write(
            dist / relative_path,
            "function collect(quads) {\n"
            "    const allQuadsForKC = [];\n"
            "                allQuadsForKC.push(...quads);\n"
            "    return allQuadsForKC;\n"
            "}\n",
        )

    return cli_dir, dist


def _source_files(dist: Path) -> list[Path]:
    return [
        dist / "dkg-agent-constants.js",
        dist / "sync" / "durable-session.js",
        dist / "sync" / "map-with-concurrency.js",
        dist / "dkg-agent-crypto.js",
        dist / "sync" / "auth" / "request-authorize.js",
        dist / "sync" / "responder" / "graph-plan.js",
        dist / "sync" / "requester" / "swm-recovery.js",
        dist / "sync-verify-worker-impl.js",
        dist / "dkg-agent-utils.js",
    ]


def test_patches_supported_install_and_second_run_is_noop(tmp_path, capsys):
    cli_dir, dist = _make_dkg_agent_fixture(tmp_path)
    source_files = _source_files(dist)
    original = {path: path.read_text(encoding="utf-8") for path in source_files}

    assert PATCHER.main([str(cli_dir)]) == 0
    first_output = capsys.readouterr()
    assert "1 install(s)" in first_output.out
    assert "patch-dkg-10.0.5-sync:" in first_output.out
    assert first_output.err == ""

    constants = (dist / "dkg-agent-constants.js").read_text(encoding="utf-8")
    assert "DKG_SYNC_TOTAL_TIMEOUT_MS', 1_200_000" in constants
    assert "DKG_SYNC_PAGE_TIMEOUT_MS', 180_000" in constants
    assert "DKG_SYNC_MIN_GRAPH_BUDGET_MS', 120_000" in constants
    assert constants.count("const _envMs =") == 1

    durable = (dist / "sync" / "durable-session.js").read_text(encoding="utf-8")
    assert "process.env.DKG_SYNC_SESSION_TTL_MS" in durable
    assert "60 * 60_000" in durable

    concurrency = (dist / "sync" / "map-with-concurrency.js").read_text(
        encoding="utf-8"
    )
    assert "raw : 1" in concurrency
    assert "raw : 4" not in concurrency

    crypto = (dist / "dkg-agent-crypto.js").read_text(encoding="utf-8")
    assert "return sawAgentGate ? agents : null;" in crypto
    assert "sawAgentGate && agents.length > 0" not in crypto

    auth = (
        dist / "sync" / "auth" / "request-authorize.js"
    ).read_text(encoding="utf-8")
    assert "const SWM_SYNC_OPEN = true ||" not in auth
    assert "if (SWM_SYNC_OPEN && !request.recovery)" in auth

    graph_plan = (
        dist / "sync" / "responder" / "graph-plan.js"
    ).read_text(encoding="utf-8")
    snapshot = graph_plan.split(
        "async function readSwmMetaRowsPage", maxsplit=1
    )[0]
    assert PATCHER.QUERY_MARKER in snapshot
    assert "for (const graph of swmMetaGraphs)" in snapshot
    assert "GRAPH <${assertSafeIri(graph)}>" in snapshot
    assert "FILTER EXISTS" in snapshot
    assert "VALUES ?g { ${values}" not in snapshot
    assert "GRAPH ?g { ?s ?p ?o }" not in snapshot
    assert "rows.push(...graphRows.filter" not in graph_plan
    assert "rows.push(row);" in graph_plan

    recovery = (
        dist / "sync" / "requester" / "swm-recovery.js"
    ).read_text(encoding="utf-8")
    assert "all.push(...page.quads)" not in recovery
    assert "for (const quad of page.quads)" in recovery
    for relative_path in ("sync-verify-worker-impl.js", "dkg-agent-utils.js"):
        source = (dist / relative_path).read_text(encoding="utf-8")
        assert "allQuadsForKC.push(...quads)" not in source
        assert "for (const quad of quads)" in source

    first_patched = {
        path: path.read_text(encoding="utf-8") for path in source_files
    }
    for path in source_files:
        backup = path.with_name(path.name + PATCHER.BACKUP_SUFFIX)
        if first_patched[path] != original[path]:
            assert backup.read_text(encoding="utf-8") == original[path]
        else:
            assert not backup.exists()

    assert PATCHER.main([str(cli_dir)]) == 0
    second_output = capsys.readouterr()
    assert "0 change(s)" in second_output.out
    assert second_output.err == ""
    assert {
        path: path.read_text(encoding="utf-8") for path in source_files
    } == first_patched
    for path in source_files:
        backup = path.with_name(path.name + PATCHER.BACKUP_SUFFIX)
        if first_patched[path] != original[path]:
            assert backup.read_text(encoding="utf-8") == original[path]
        else:
            assert not backup.exists()


def test_unsupported_agent_version_is_left_untouched(tmp_path, capsys):
    cli_dir, dist = _make_dkg_agent_fixture(tmp_path, version="10.0.6")
    source_files = _source_files(dist)
    original = {path: path.read_bytes() for path in source_files}

    assert PATCHER.main([str(cli_dir)]) == 0
    output = capsys.readouterr()

    assert "dkg-agent 10.0.6" in output.out
    assert "patch is only for 10.0.5" in output.out
    assert output.err == ""
    assert {path: path.read_bytes() for path in source_files} == original
    assert not list(dist.rglob(f"*{PATCHER.BACKUP_SUFFIX}"))


def test_migrates_previous_budget_only_ops_patch(tmp_path):
    cli_dir, dist = _make_dkg_agent_fixture(tmp_path)
    constants = dist / "dkg-agent-constants.js"
    source = constants.read_text(encoding="utf-8")
    source = source.replace(
        "export const SYNC_TOTAL_TIMEOUT_MS = 120_000;",
        "const _envMs = (name, fallback) => {\n"
        "    const v = Number(process.env[name] ?? '');\n"
        "    return Number.isFinite(v) && v > 0 ? v : fallback;\n"
        "};\n"
        "export const SYNC_TOTAL_TIMEOUT_MS = _envMs('DKG_SYNC_TOTAL_TIMEOUT_MS', 600_000);",
    ).replace(
        "export const SYNC_PAGE_TIMEOUT_MS = 45_000;",
        "export const SYNC_PAGE_TIMEOUT_MS = _envMs('DKG_SYNC_PAGE_TIMEOUT_MS', 90_000);",
    )
    constants.write_text(source, encoding="utf-8")

    assert PATCHER.main([str(cli_dir)]) == 0

    patched = constants.read_text(encoding="utf-8")
    assert "DKG_SYNC_TOTAL_TIMEOUT_MS', 1_200_000" in patched
    assert "DKG_SYNC_PAGE_TIMEOUT_MS', 180_000" in patched
    assert patched.count("const _envMs =") == 1


def test_restores_retired_empty_agent_gate_experiment(tmp_path):
    cli_dir, dist = _make_dkg_agent_fixture(tmp_path)
    crypto = dist / "dkg-agent-crypto.js"
    crypto.write_text(
        "function agentsForGate(sawAgentGate, agents) {\n"
        "        // Ops patch (umanitek): an agent gate whose effective member set is\n"
        "        // empty must collapse to public.\n"
        "        return (sawAgentGate && agents.length > 0) ? agents : null;\n"
        "}\n",
        encoding="utf-8",
    )

    assert PATCHER.main([str(cli_dir)]) == 0

    restored = crypto.read_text(encoding="utf-8")
    assert "return sawAgentGate ? agents : null;" in restored
    assert "agents.length > 0" not in restored
    assert "empty must collapse to public" not in restored


def test_supported_source_drift_fails_closed(tmp_path, capsys):
    cli_dir, dist = _make_dkg_agent_fixture(tmp_path, drifted_constant=True)
    constants = dist / "dkg-agent-constants.js"
    original = constants.read_bytes()

    assert PATCHER.main([str(cli_dir)]) == 1
    output = capsys.readouterr()

    assert output.out == ""
    assert "expected DKG 10.0.5 source not found" in output.err
    assert "SYNC_TOTAL_TIMEOUT_MS = 120_000" in output.err
    assert constants.read_bytes() == original
    assert not constants.with_name(constants.name + PATCHER.BACKUP_SUFFIX).exists()


def test_swm_snapshot_function_drift_is_not_rewritten(tmp_path):
    _, dist = _make_dkg_agent_fixture(tmp_path)
    graph_plan = dist / "sync" / "responder" / "graph-plan.js"
    drifted = graph_plan.read_text(encoding="utf-8").replace(
        "async function readSwmMetaRows(",
        "async function readSwmMetaRowsV2(",
        1,
    )
    graph_plan.write_text(drifted, encoding="utf-8")

    with pytest.raises(PATCHER.PatchError, match=r"readSwmMetaRows\(\) did not match"):
        PATCHER._patch_swm_meta_snapshot(dist)

    assert graph_plan.read_text(encoding="utf-8") == drifted
    assert not graph_plan.with_name(
        graph_plan.name + PATCHER.BACKUP_SUFFIX
    ).exists()


def test_late_source_drift_rolls_back_earlier_edits(tmp_path, capsys):
    cli_dir, dist = _make_dkg_agent_fixture(tmp_path)
    graph_plan = dist / "sync" / "responder" / "graph-plan.js"
    graph_plan.write_text(
        graph_plan.read_text(encoding="utf-8").replace(
            "async function readSwmMetaRows(",
            "async function readSwmMetaRowsV2(",
            1,
        ),
        encoding="utf-8",
    )
    source_files = _source_files(dist)
    original = {path: path.read_text(encoding="utf-8") for path in source_files}

    assert PATCHER.main([str(cli_dir)]) == 1
    output = capsys.readouterr()

    assert "readSwmMetaRows() did not match" in output.err
    assert {
        path: path.read_text(encoding="utf-8") for path in source_files
    } == original


def test_missing_dist_is_reported_without_traceback(tmp_path, capsys):
    assert PATCHER.main([str(tmp_path / "empty-cli")]) == 1
    output = capsys.readouterr()

    assert output.out == ""
    assert "dkg-agent dist not found" in output.err
    assert "Traceback" not in output.err


def test_patch_root_rejects_missing_package_metadata(tmp_path):
    dist = tmp_path / "dkg-agent" / "dist"
    dist.mkdir(parents=True)

    with pytest.raises(PATCHER.PatchError, match="missing .*package.json"):
        PATCHER.patch_root(dist)
