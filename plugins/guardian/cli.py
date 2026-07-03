"""``hermes guardian <sub>`` CLI.

Subcommands: ``status``, ``sync``, ``report``, ``setup-graph``,
``curate {list|show|approve|reject|import}``, and ``dashboard``. Curator flows
build quads via :mod:`quads` and talk to the node via :class:`DkgClient`;
read flows fail open with a friendly message.
"""

from __future__ import annotations

import argparse
import json
import logging
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import attach, audit, constants, quads, ruleset
from .config import GuardianConfig, load_guardian_config
from .dkg_client import DkgClient, DkgError, extract_binding

logger = logging.getLogger(__name__)

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


# ---------------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------------


def setup_cli(parser: argparse.ArgumentParser) -> None:
    """Build the ``hermes guardian`` subparser tree."""
    sub = parser.add_subparsers(dest="guardian_command")

    sub.add_parser("status", help="Show config, node reachability, ruleset + findings counts").set_defaults(
        func=_cmd_status
    )
    sub.add_parser("sync", help="Force a ruleset refresh from the DKG node").set_defaults(func=_cmd_sync)

    attach_p = sub.add_parser(
        "attach", help="Auto-protect every local Hermes home + OpenClaw workspace"
    )
    attach_p.add_argument("--dry-run", action="store_true", help="Show what would change; write nothing")
    attach_p.add_argument("--hermes-only", action="store_true", help="Only attach to Hermes homes")
    attach_p.add_argument("--openclaw-only", action="store_true", help="Only attach to OpenClaw workspaces")
    attach_p.set_defaults(func=_cmd_attach)

    detach_p = sub.add_parser("detach", help="Disable Guardian in every local agent")
    detach_p.add_argument("--dry-run", action="store_true", help="Show what would change; write nothing")
    detach_p.add_argument("--remove-files", action="store_true", help="Also delete copied plugin files")
    detach_p.add_argument("--hermes-only", action="store_true", help="Only detach from Hermes homes")
    detach_p.add_argument("--openclaw-only", action="store_true", help="Only detach from OpenClaw workspaces")
    detach_p.set_defaults(func=_cmd_detach)

    report = sub.add_parser("report", help="Submit a NEW candidate threat to the community graph (SWM)")
    report.add_argument(
        "--type", required=True,
        choices=["injection", "escalation", "dependency", "fileaccess", "skill"],
    )
    report.add_argument("--pattern", help="injection: regex source")
    report.add_argument("--owasp", help="injection: OWASP category (e.g. LLM01)")
    report.add_argument("--tool", help="escalation/fileaccess: tool name")
    report.add_argument("--arg-shape", dest="arg_shape", help="escalation: arg shape slug")
    report.add_argument("--ecosystem", help="dependency: ecosystem (npm/pypi/...)")
    report.add_argument("--name", help="dependency: package name (or threat display name)")
    report.add_argument("--version", help="dependency: package version")
    report.add_argument("--advisory-id", dest="advisory_id", help="dependency: advisory id")
    report.add_argument("--category", help="fileaccess: sensitive-path category (e.g. ssh-private-key)")
    report.add_argument("--skill-name", dest="skill_name", help="skill: skill name")
    report.add_argument("--skill-version", dest="skill_version", help="skill: known-bad version")
    report.add_argument("--danger-shape", dest="danger_shape", help="skill: danger shape slug (e.g. shell-exec)")
    report.add_argument("--severity", default="high", choices=list(constants.SEVERITY_ORDER))
    report.add_argument("--description", default="", help="Human-readable description")
    report.set_defaults(func=_cmd_report)

    setup_graph = sub.add_parser("setup-graph", help="Curator: create + register the public threat CG")
    setup_graph.add_argument("--network", default="testnet", help="Target network (informational)")
    setup_graph.set_defaults(func=_cmd_setup_graph)

    curate = sub.add_parser("curate", help="Curator: review + promote community threats")
    csub = curate.add_subparsers(dest="curate_command")

    clist = csub.add_parser("list", help="List candidate threats grouped by distinct reporters")
    clist.add_argument("--pending", action="store_true", help="Only show non-curated candidates")
    clist.set_defaults(func=_cmd_curate_list)

    cshow = csub.add_parser("show", help="Show one threat/candidate and its reporters")
    cshow.add_argument("identifier")
    cshow.set_defaults(func=_cmd_curate_show)

    capprove = csub.add_parser("approve", help="Promote a candidate to a curated threat (share + publish)")
    capprove.add_argument("identifier")
    capprove.add_argument("--severity", choices=list(constants.SEVERITY_ORDER))
    capprove.add_argument("--name", help="Override display name")
    capprove.add_argument("--description", default="", help="Override description")
    capprove.add_argument("--epochs", type=int, default=1, help="VM publish epochs")
    capprove.add_argument("--no-publish", action="store_true", help="Share to SWM only, skip vm/publish")
    capprove.set_defaults(func=_cmd_curate_approve)

    creject = csub.add_parser("reject", help="Mark a candidate rejected (locally; optional SWM false-positive)")
    creject.add_argument("identifier")
    creject.add_argument("--dispute", action="store_true", help="Also publish a g:FalsePositive to SWM")
    creject.set_defaults(func=_cmd_curate_reject)

    cimport = csub.add_parser("import", help="Bulk import candidate threats from a catalog file or directory")
    csrc = cimport.add_mutually_exclusive_group(required=True)
    csrc.add_argument("--file", help="Path to a JSON catalog file")
    csrc.add_argument("--dir", dest="dir", help="Import every *.json catalog in a directory")
    cimport.add_argument(
        "--type",
        choices=["injection", "escalation", "dependency", "fileaccess", "skill"],
        help="Force a type",
    )
    cimport.add_argument("--osv-enrich", action="store_true", help="OSV-enrich dependency entries before publish")
    cimport.add_argument("--no-publish", action="store_true", help="Share to SWM (the free local tier) only; skip vm/publish")
    cimport.set_defaults(func=_cmd_curate_import)

    dash = sub.add_parser("dashboard", help="Start the local Guardian dashboard")
    dash.add_argument("--port", type=int, help="Override dashboard port")
    dash.set_defaults(func=_cmd_dashboard)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _cmd_status(args: argparse.Namespace) -> int:
    cfg = load_guardian_config()
    client = DkgClient(url=cfg.dkg_url)
    reachable = client.reachable()
    rs = ruleset.get(cfg)
    counts = rs.counts()
    print("Umanitek Agent Guardian")
    print(f"  mode:              {cfg.mode}")
    print(f"  block severity:    {cfg.block_severity}")
    print(f"  context graph:     {cfg.context_graph_id}")
    print(f"  DKG node:          {cfg.dkg_url}  [{'reachable' if reachable else 'unreachable'}]")
    print(f"  reports:           {'on' if cfg.report else 'off'} (limit {cfg.daily_report_limit}/day)")
    print(f"  sync interval:     {cfg.sync_interval}s")
    print(f"  ruleset:           {counts['injection']} injection, "
          f"{counts['escalation']} escalation, {counts['dependency']} dependency, "
          f"{counts['fileaccess']} fileaccess, {counts['skill']} skill")
    print(f"  findings logged:   {audit.count_findings()}")
    print(f"  dashboard:         http://127.0.0.1:{cfg.dashboard_port}")
    _print_attached_targets()
    return 0


def _print_attached_targets() -> None:
    """List which local Hermes homes / OpenClaw workspaces have Guardian attached."""
    attached_hermes = []
    for home in attach.discover_hermes_homes():
        try:
            data = attach._load_yaml(home / "config.yaml")
            if attach._enabled_list_has(data, "guardian"):
                attached_hermes.append(str(home))
        except Exception:
            continue
    attached_openclaw = []
    for ws in attach.discover_openclaw_workspaces():
        try:
            import json as _json

            cfg_path = ws / "openclaw.json"
            data = _json.loads(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else {}
            allow = ((data.get("plugins") or {}).get("allow")) if isinstance(data, dict) else None
            if isinstance(allow, list) and "guardian" in allow:
                attached_openclaw.append(str(ws))
        except Exception:
            continue
    print(f"  attached (hermes): {len(attached_hermes)}")
    for path in attached_hermes:
        print(f"      - {path}")
    print(f"  attached (openclaw): {len(attached_openclaw)}")
    for path in attached_openclaw:
        print(f"      - {path}")


def _cmd_sync(args: argparse.Namespace) -> int:
    cfg = load_guardian_config()
    rs = ruleset.refresh(cfg)
    counts = rs.counts()
    print(f"Ruleset synced from {cfg.context_graph_id}:")
    print(f"  {counts['injection']} injection, {counts['escalation']} escalation, "
          f"{counts['dependency']} dependency")
    return 0


def _cmd_attach(args: argparse.Namespace) -> int:
    do_hermes = not args.openclaw_only
    do_openclaw = not args.hermes_only
    report = attach.attach_all(hermes=do_hermes, openclaw=do_openclaw, dry_run=args.dry_run)
    prefix = "Would protect" if args.dry_run else "Protected"
    for row in report.get("hermes", []):
        _print_hermes_attach_row(row, prefix)
    for row in report.get("openclaw", []):
        _print_openclaw_attach_row(row, prefix)
    count = report.get("count", 0)
    if args.dry_run:
        print(f"\nDry run: Guardian would watch {count} agent(s). Nothing was written.")
    else:
        print(f"\nGuardian is watching {count} agent(s). Restart any running agent to activate.")
    return 0


def _cmd_detach(args: argparse.Namespace) -> int:
    do_hermes = not args.openclaw_only
    do_openclaw = not args.hermes_only
    report = attach.detach_all(
        hermes=do_hermes, openclaw=do_openclaw, remove_files=args.remove_files, dry_run=args.dry_run
    )
    prefix = "Would detach" if args.dry_run else "Detached"
    for row in report.get("hermes", []):
        if row.get("error"):
            print(f"  ! {row['target']} (hermes): {row['error']}")
        elif row.get("already") and not row.get("removed"):
            print(f"  - {row['target']} (hermes): already detached")
        else:
            extra = ", files removed" if row.get("removed") else ""
            print(f"  {prefix} {row['target']} (hermes){extra}")
    for row in report.get("openclaw", []):
        if row.get("error"):
            print(f"  ! {row['target']} (openclaw): {row['error']}")
        elif row.get("already"):
            print(f"  - {row['target']} (openclaw): already detached")
        else:
            print(f"  {prefix} {row['target']} (openclaw)")
    print("\nGuardian detached. Restart any running agent to apply.")
    return 0


def _print_hermes_attach_row(row: Dict[str, Any], prefix: str) -> None:
    if row.get("error"):
        print(f"  ! {row['target']} (hermes): {row['error']}")
        return
    if row.get("already") and not row.get("copied"):
        print(f"  - {row['target']} (hermes): already protected")
        return
    bits = []
    if row.get("copied"):
        bits.append("plugin copied")
    if row.get("enabled"):
        bits.append("enabled")
    elif row.get("already"):
        bits.append("already enabled")
    detail = f" ({', '.join(bits)})" if bits else ""
    print(f"  {prefix} {row['target']} (hermes){detail}")


def _print_openclaw_attach_row(row: Dict[str, Any], prefix: str) -> None:
    if row.get("error"):
        print(f"  ! {row['target']} (openclaw): {row['error']}")
        return
    if row.get("already"):
        print(f"  - {row['target']} (openclaw): already protected")
        return
    note = f"  note: {row['note']}" if row.get("note") else ""
    print(f"  {prefix} {row['target']} (openclaw){note}")


def _cmd_report(args: argparse.Namespace) -> int:
    cfg = load_guardian_config()
    client = DkgClient(url=cfg.dkg_url)
    try:
        identifier, quad_kwargs = _build_candidate(args)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    reporter = _resolve_reporter(client)
    q = quads.build_report_quads(
        identifier=identifier,
        category=args.type,
        severity=args.severity,
        reporter_address=reporter,
        framework="hermes",
        **quad_kwargs,
    )
    name = f"report-{quads.stable_hash(identifier + reporter, 16)}"
    try:
        client.share_knowledge_asset(cfg.context_graph_id, name, q)
    except DkgError as exc:
        print(f"error: failed to share report: {exc}")
        return 1
    print(f"Reported candidate threat: {identifier}")
    print(f"  shared to {cfg.context_graph_id} (SWM) as reporter {reporter}")
    return 0


def _cmd_setup_graph(args: argparse.Namespace) -> int:
    cfg = load_guardian_config()
    client = DkgClient(url=cfg.dkg_url)
    cg = cfg.context_graph_id
    try:
        client.create_context_graph(cg, name="Umanitek Guardian Threats",
                                    description="Curated agent-security threat intelligence.")
        print(f"Created context graph {cg} (or already existed).")
    except DkgError as exc:
        print(f"note: create returned: {exc}")
    try:
        client.register_context_graph(cg, access_policy=0, publish_policy=0)
        print(f"Registered {cg} on-chain (accessPolicy=0, publishPolicy=0) on {args.network}.")
    except DkgError as exc:
        print(f"error: register failed: {exc}")
        return 1
    return 0


def _cmd_curate_list(args: argparse.Namespace) -> int:
    cfg = load_guardian_config()
    client = DkgClient(url=cfg.dkg_url)
    sparql = """
PREFIX g: <http://umanitek.ai/ontology/guardian/>
SELECT ?identifier (COUNT(DISTINCT ?reporter) AS ?reporters)
       (SAMPLE(?severity) AS ?sev) (SAMPLE(?curated) AS ?cur)
WHERE {
  ?report a g:ThreatReport .
  ?report g:identifier ?identifier .
  ?report g:reporter ?reporter .
  OPTIONAL { ?report g:severity ?severity . }
  OPTIONAL { ?threat g:identifier ?identifier . ?threat g:curated ?curated . }
}
GROUP BY ?identifier
ORDER BY DESC(?reporters)
LIMIT 200
"""
    rows = client.query(sparql, cfg.context_graph_id, view=constants.VIEW_SHARED_WORKING_MEMORY)
    if not rows:
        print("No community reports found (empty graph or node unreachable).")
        return 0
    print(f"{'reporters':>9}  {'sev':<8}  {'curated':<7}  identifier")
    for row in rows:
        ident = extract_binding(row.get("identifier"))
        reporters = extract_binding(row.get("reporters")) or "0"
        sev = extract_binding(row.get("sev")) or "-"
        curated = extract_binding(row.get("cur")).lower() == "true"
        if args.pending and curated:
            continue
        print(f"{reporters:>9}  {sev:<8}  {'yes' if curated else 'no':<7}  {ident}")
    return 0


def _cmd_curate_show(args: argparse.Namespace) -> int:
    cfg = load_guardian_config()
    client = DkgClient(url=cfg.dkg_url)
    ident = args.identifier
    esc = ident.replace('"', '\\"')
    sparql = f"""
PREFIX g: <http://umanitek.ai/ontology/guardian/>
SELECT ?reporter ?severity ?framework WHERE {{
  ?report a g:ThreatReport .
  ?report g:identifier "{esc}" .
  ?report g:reporter ?reporter .
  OPTIONAL {{ ?report g:severity ?severity . }}
  OPTIONAL {{ ?report g:framework ?framework . }}
}}
LIMIT 200
"""
    rows = client.query(sparql, cfg.context_graph_id, view=constants.VIEW_SHARED_WORKING_MEMORY)
    print(f"Threat: {ident}")
    print(f"  reporters: {len(rows)}")
    for row in rows:
        print(f"    - {extract_binding(row.get('reporter'))} "
              f"[{extract_binding(row.get('severity')) or '-'}] "
              f"via {extract_binding(row.get('framework')) or '-'}")
    return 0


def _cmd_curate_approve(args: argparse.Namespace) -> int:
    cfg = load_guardian_config()
    client = DkgClient(url=cfg.dkg_url)
    ident = args.identifier
    category, fields = _threat_fields_from_reports(client, cfg, ident)
    if category is None:
        print(f"error: could not resolve threat fields for {ident} from reports.")
        return 2
    severity = args.severity or fields.get("severity") or "high"
    name = args.name or fields.get("name") or ident
    description = args.description or fields.get("description") or f"Curated threat {ident}"
    q = quads.build_threat_quads(
        category=category,
        identifier=ident,
        severity=severity,
        name=name,
        description=description,
        curated=True,
        pattern=fields.get("pattern"),
        owasp_category=fields.get("owasp_category"),
        tool_name=fields.get("tool_name"),
        arg_shape=fields.get("arg_shape"),
        ecosystem=fields.get("ecosystem"),
        package_name=fields.get("package_name"),
        package_version=fields.get("package_version"),
        advisory_id=fields.get("advisory_id"),
        file_category=fields.get("file_category"),
        skill_name=fields.get("skill_name"),
        skill_version=fields.get("skill_version"),
        danger_shape=fields.get("danger_shape"),
    )
    ka_name = f"threat-{quads.slug(ident)}"
    try:
        client.share_knowledge_asset(cfg.context_graph_id, ka_name, q)
        print(f"Shared curated threat {ident} to {cfg.context_graph_id} (SWM).")
        if not args.no_publish:
            result = client.publish(cfg.context_graph_id, ka_name, epochs=args.epochs)
            ual = result.get("ual") if isinstance(result, dict) else None
            tx = result.get("txHash") if isinstance(result, dict) else None
            print(f"Published to VM. UAL={ual} txHash={tx}")
    except DkgError as exc:
        print(f"error: {exc}")
        return 1
    return 0


def _cmd_curate_reject(args: argparse.Namespace) -> int:
    cfg = load_guardian_config()
    ident = args.identifier
    # Local rejection: append to a rejects file so `list` can hide it if desired.
    try:
        home = constants.guardian_home()
        home.mkdir(parents=True, exist_ok=True)
        rejects = home / "rejected.json"
        data = []
        if rejects.exists():
            data = json.loads(rejects.read_text(encoding="utf-8"))
        if ident not in data:
            data.append(ident)
        rejects.write_text(json.dumps(data), encoding="utf-8")
    except Exception as exc:
        print(f"warning: could not persist local rejection: {exc}")
    print(f"Marked {ident} rejected locally (its reports will TTL-expire from SWM).")
    if args.dispute:
        client = DkgClient(url=cfg.dkg_url)
        reporter = _resolve_reporter(client)
        threat = quads.threat_uri(ident)
        fp_subj = f"urn:guardian:fp:{quads.stable_hash(ident + reporter, 24)}"
        q = [
            {"subject": fp_subj, "predicate": constants.RDF_TYPE, "object": constants.FALSE_POSITIVE_TYPE_IRI},
            {"subject": fp_subj, "predicate": constants.DISPUTES_PRED, "object": threat},
            {"subject": fp_subj, "predicate": constants.DISPUTE_REPORTER_PRED, "object": quads.literal(reporter.lower())},
            {"subject": fp_subj, "predicate": constants.SCHEMA_DATE_MODIFIED_PRED, "object": quads.datetime_literal()},
        ]
        try:
            client.share_knowledge_asset(cfg.context_graph_id, f"fp-{quads.stable_hash(ident + reporter, 16)}", q)
            print(f"Published false-positive dispute for {ident} to SWM.")
        except DkgError as exc:
            print(f"warning: dispute share failed: {exc}")
    return 0


def _cmd_curate_import(args: argparse.Namespace) -> int:
    cfg = load_guardian_config()
    client = DkgClient(url=cfg.dkg_url)

    catalog_paths = _resolve_import_paths(args)
    if catalog_paths is None:
        return 2  # error already printed
    if not catalog_paths:
        print("No catalog JSON files found to import.")
        return 0

    # While VM publish is blocked, --no-publish is the practical path: it shares
    # to SWM only (the free local/community tier).
    publish = not args.no_publish
    seeded, skipped, errors = 0, 0, 0
    for path in catalog_paths:
        try:
            catalog = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            if args.file:  # explicit single file: a bad file is a hard error
                print(f"error: invalid JSON: {exc}")
                return 2
            skipped += 1  # in --dir mode, silently skip non-JSON/bad files
            continue
        entries = _flatten_catalog(catalog, forced_type=args.type)
        if not entries:
            skipped += 1  # not a recognizable catalog
            continue
        if args.osv_enrich:
            entries = _osv_enrich(entries)
        s, e = _seed_entries(client, cfg, entries, publish=publish)
        seeded += s
        errors += e
        if args.dir:
            print(f"  {path.name}: {s} seeded, {e} errors")

    tier = "VM (published)" if publish else "the local graph (SWM)"
    print(f"Import complete: {seeded} threats seeded to {tier}, {skipped} skipped, {errors} errors.")
    return 0 if errors == 0 else 1


def _resolve_import_paths(args: argparse.Namespace) -> Optional[List[Path]]:
    """Resolve ``--file``/``--dir`` to a list of catalog paths, or ``None`` on error."""
    if args.file:
        path = Path(args.file).expanduser()
        if not path.exists():
            print(f"error: file not found: {path}")
            return None
        return [path]
    directory = Path(args.dir).expanduser()
    if not directory.is_dir():
        print(f"error: not a directory: {directory}")
        return None
    return sorted(p for p in directory.glob("*.json") if p.is_file())


def _seed_entries(
    client: DkgClient, cfg: GuardianConfig, entries: List[Dict[str, Any]], *, publish: bool
) -> tuple:
    """Seed flattened *entries* as curated threats. Returns ``(seeded, errors)``."""
    seeded, errors = 0, 0
    for entry in entries:
        try:
            category, ident, fields = _entry_to_threat(entry)
        except ValueError:
            errors += 1
            continue
        q = quads.build_threat_quads(
            category=category,
            identifier=ident,
            severity=fields.get("severity", "high"),
            name=fields.get("name", ident),
            description=fields.get("description", ""),
            curated=True,
            pattern=fields.get("pattern"),
            owasp_category=fields.get("owasp_category"),
            tool_name=fields.get("tool_name"),
            arg_shape=fields.get("arg_shape"),
            ecosystem=fields.get("ecosystem"),
            package_name=fields.get("package_name"),
            package_version=fields.get("package_version"),
            advisory_id=fields.get("advisory_id"),
            references=fields.get("references"),
            file_category=fields.get("file_category"),
            skill_name=fields.get("skill_name"),
            skill_version=fields.get("skill_version"),
            danger_shape=fields.get("danger_shape"),
        )
        ka_name = f"threat-{quads.slug(ident)}"
        try:
            client.share_knowledge_asset(cfg.context_graph_id, ka_name, q)
            if publish:
                client.publish(cfg.context_graph_id, ka_name, epochs=1)
            seeded += 1
        except DkgError:
            errors += 1
    return seeded, errors


def _cmd_dashboard(args: argparse.Namespace) -> int:
    cfg = load_guardian_config()
    port = args.port or cfg.dashboard_port
    try:
        from .dashboard.server import start_dashboard
    except Exception as exc:
        print(f"error: dashboard requires the [web] extra (fastapi/uvicorn): {exc}")
        return 1
    print(f"Starting Guardian dashboard on http://127.0.0.1:{port} (Ctrl-C to stop)")
    start_dashboard(port)
    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_reporter(client: DkgClient) -> str:
    # agent_identity is the definitive token→address resolution; status() is a
    # best-effort fallback for older daemons (same order as hooks._reporter_address).
    for resolver in (client.agent_identity, client.status):
        try:
            info = resolver()
        except Exception:
            continue
        if not isinstance(info, dict):
            continue
        for key in ("agentAddress", "defaultAgentAddress", "address"):
            val = info.get(key)
            if isinstance(val, str) and val:
                return val
    return "node"


def _build_candidate(args: argparse.Namespace) -> tuple:
    """Return ``(identifier, quad_kwargs)`` for ``report``; raise ValueError on bad input."""
    if args.type == "injection":
        if not args.pattern:
            raise ValueError("injection report requires --pattern")
        ident = quads.injection_identifier(args.pattern)
        return ident, {"pattern": args.pattern, "owasp_category": args.owasp}
    if args.type == "escalation":
        if not args.tool or not args.arg_shape:
            raise ValueError("escalation report requires --tool and --arg-shape")
        ident = quads.escalation_identifier(args.tool, args.arg_shape)
        return ident, {"tool_name": args.tool, "arg_shape": args.arg_shape}
    if args.type == "dependency":
        if not (args.ecosystem and args.name and args.version):
            raise ValueError("dependency report requires --ecosystem, --name, --version")
        ident = quads.dependency_identifier(args.ecosystem, args.name, args.version)
        return ident, {
            "ecosystem": args.ecosystem.lower(),
            "package_name": args.name,
            "package_version": args.version,
            "advisory_id": args.advisory_id,
        }
    if args.type == "fileaccess":
        if not (args.tool and args.category):
            raise ValueError("fileaccess report requires --tool and --category")
        ident = quads.fileaccess_identifier(args.tool, args.category)
        return ident, {
            "tool_name": args.tool.strip().lower(),
            "file_category": args.category.strip().lower(),
        }
    if args.type == "skill":
        if not args.skill_name or not (args.skill_version or args.danger_shape):
            raise ValueError(
                "skill report requires --skill-name and one of --skill-version / --danger-shape"
            )
        if args.skill_version:
            ident = quads.skill_version_identifier(args.skill_name, args.skill_version)
        else:
            ident = quads.skill_shape_identifier(args.skill_name, args.danger_shape)
        return ident, {
            "skill_name": args.skill_name.strip().lower(),
            "skill_version": (args.skill_version or "").strip() or None,
            "danger_shape": (args.danger_shape or "").strip() or None,
        }
    raise ValueError(f"unknown type: {args.type}")


def _threat_fields_from_reports(client: DkgClient, cfg: GuardianConfig, identifier: str):
    """Reconstruct threat fields from community reports for approval.

    Returns ``(category, fields)``. Category is derived from the identifier
    prefix; fields are gathered from any report carrying them.
    """
    prefix = identifier.split(":", 1)[0]
    category = {
        "injection": "injection",
        "escalation": "escalation",
        "dep": "dependency",
        "fileaccess": "fileaccess",
        "skill": "skill",
    }.get(prefix)
    if category is None:
        return None, {}
    esc = identifier.replace("\\", "\\\\").replace('"', '\\"')
    sparql = f"""
PREFIX g: <http://umanitek.ai/ontology/guardian/>
PREFIX schema: <http://schema.org/>
SELECT ?severity ?pattern ?owasp ?toolName ?argShape
       ?packageName ?packageVersion ?packageEcosystem ?advisoryId
       ?category ?skillName ?skillVersion ?dangerShape WHERE {{
  ?report a g:ThreatReport .
  ?report g:identifier "{esc}" .
  OPTIONAL {{ ?report g:severity ?severity . }}
  OPTIONAL {{ ?report g:pattern ?pattern . }}
  OPTIONAL {{ ?report g:owaspCategory ?owasp . }}
  OPTIONAL {{ ?report g:toolName ?toolName . }}
  OPTIONAL {{ ?report g:argShape ?argShape . }}
  OPTIONAL {{ ?report g:packageName ?packageName . }}
  OPTIONAL {{ ?report g:packageVersion ?packageVersion . }}
  OPTIONAL {{ ?report g:packageEcosystem ?packageEcosystem . }}
  OPTIONAL {{ ?report schema:identifier ?advisoryId . }}
  OPTIONAL {{ ?report g:category ?category . }}
  OPTIONAL {{ ?report g:skillName ?skillName . }}
  OPTIONAL {{ ?report g:skillVersion ?skillVersion . }}
  OPTIONAL {{ ?report g:dangerShape ?dangerShape . }}
}}
LIMIT 50
"""
    rows = client.query(sparql, cfg.context_graph_id, view=constants.VIEW_SHARED_WORKING_MEMORY)
    fields: Dict[str, Any] = {}
    for row in rows:
        for src, dst in (
            ("severity", "severity"), ("pattern", "pattern"), ("owasp", "owasp_category"),
            ("toolName", "tool_name"), ("argShape", "arg_shape"),
            ("packageName", "package_name"), ("packageVersion", "package_version"),
            ("packageEcosystem", "ecosystem"), ("advisoryId", "advisory_id"),
            ("category", "file_category"), ("skillName", "skill_name"),
            ("skillVersion", "skill_version"), ("dangerShape", "danger_shape"),
        ):
            val = extract_binding(row.get(src))
            if val and dst not in fields:
                fields[dst] = val
    # Fall back to parsing fields out of the deterministic identifier itself.
    if category == "dependency" and "package_name" not in fields:
        try:
            _, rest = identifier.split(":", 1)
            eco, tail = rest.split(":", 1)
            pkg, ver = tail.rsplit("@", 1)
            fields.setdefault("ecosystem", eco)
            fields.setdefault("package_name", pkg)
            fields.setdefault("package_version", ver)
        except ValueError:
            pass
    elif category == "fileaccess" and ("tool_name" not in fields or "file_category" not in fields):
        try:
            _, tool, file_category = identifier.split(":", 2)
            fields.setdefault("tool_name", tool)
            fields.setdefault("file_category", file_category)
        except ValueError:
            pass
    elif category == "skill" and "skill_name" not in fields:
        rest = identifier.split(":", 1)[1] if ":" in identifier else ""
        if "@" in rest:  # skill:{name}@{version}
            skill_name, _, skill_version = rest.rpartition("@")
            fields.setdefault("skill_name", skill_name)
            fields.setdefault("skill_version", skill_version)
        elif ":" in rest:  # skill:{name}:{dangerShape}
            skill_name, _, danger_shape = rest.partition(":")
            fields.setdefault("skill_name", skill_name)
            fields.setdefault("danger_shape", danger_shape)
        elif rest:
            fields.setdefault("skill_name", rest)
    return category, fields


def _is_bumblebee_catalog(catalog: Any) -> bool:
    """True for a bumblebee threat_intel catalog.

    Shape: a top-level ``entries`` list whose items are packages carrying both a
    ``package`` name and a ``versions`` list (one entry = one package, many
    versions). Distinct from the generic ``{threats:[...]}`` catalog.
    """
    if not isinstance(catalog, dict):
        return False
    entries = catalog.get("entries")
    if not isinstance(entries, list) or not entries:
        return False
    return any(
        isinstance(e, dict) and e.get("package") and isinstance(e.get("versions"), list)
        for e in entries
    )


def _flatten_bumblebee(catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Fan out a bumblebee catalog into one dependency entry per (package, version).

    Each entry maps to a ``dep:{ecosystem}:{package}@{version}`` threat. Name and
    description come from the entry name + ``_comment`` (trimmed short); severity,
    advisory id, and source url come from the entry.
    """
    out: List[Dict[str, Any]] = []
    comment = str(catalog.get("_comment") or "").strip()
    for entry in catalog.get("entries", []) or []:
        if not isinstance(entry, dict):
            continue
        ecosystem = str(entry.get("ecosystem") or "").strip()
        package = str(entry.get("package") or "").strip()
        versions = entry.get("versions")
        if not (ecosystem and package and isinstance(versions, list)):
            continue
        entry_name = str(entry.get("name") or package).strip()
        severity = entry.get("severity")
        advisory_id = entry.get("id")
        source = str(entry.get("source") or "").strip()
        # Short human description: prefer the per-entry name, append a trimmed
        # catalog comment so a curator sees the gist without the full essay.
        description = entry_name
        if comment:
            snippet = comment if len(comment) <= 240 else comment[:237].rstrip() + "..."
            description = f"{entry_name} — {snippet}" if entry_name else snippet
        references = [source] if source else []
        for version in versions:
            version = str(version).strip()
            if not version:
                continue
            out.append(
                {
                    "type": "dependency",
                    "ecosystem": ecosystem,
                    "package": package,
                    "version": version,
                    # `title` is the display name; `package` stays the package id
                    # (_entry_to_threat reads title first, package for the name).
                    "title": f"{package}@{version}",
                    "description": description,
                    "severity": severity,
                    "advisoryId": advisory_id,
                    "references": references,
                }
            )
    return out


def _flatten_catalog(catalog: Any, forced_type: Optional[str]) -> List[Dict[str, Any]]:
    """Flatten a threat catalog into per-threat entries.

    Accepts the bumblebee ``{entries:[{package, versions:[...]}]}`` format (fanned
    out one dependency threat per package+version), the generic ``{threats:[...]}``
    format, and the ``{dependencies/injection/escalation:[...]}`` split format.
    """
    if _is_bumblebee_catalog(catalog):
        return _flatten_bumblebee(catalog)
    out: List[Dict[str, Any]] = []
    if isinstance(catalog, list):
        for item in catalog:
            if isinstance(item, dict):
                out.append({**item, **({"type": forced_type} if forced_type else {})})
        return out
    if not isinstance(catalog, dict):
        return out
    for item in catalog.get("threats", []) or []:
        if isinstance(item, dict):
            out.append({**item, **({"type": forced_type} if forced_type else {})})
    for key, ctype in (
        ("dependencies", "dependency"),
        ("injection", "injection"),
        ("escalation", "escalation"),
        ("fileaccess", "fileaccess"),
        ("skills", "skill"),
    ):
        for item in catalog.get(key, []) or []:
            if isinstance(item, dict):
                out.append({"type": ctype, **item})
    return out


def _entry_to_threat(entry: Dict[str, Any]) -> tuple:
    """Return ``(category, identifier, fields)`` for a catalog entry."""
    ctype = str(entry.get("type") or "").lower()
    if ctype == "injection":
        pattern = str(entry.get("pattern") or "").strip()
        if not pattern:
            raise ValueError("injection needs pattern")
        ident = quads.injection_identifier(pattern)
        return "injection", ident, {
            "severity": constants.normalize_severity(entry.get("severity"), "high"),
            "name": entry.get("title") or entry.get("name") or f"Injection {pattern[:40]}",
            "description": entry.get("summary") or entry.get("description") or "",
            "pattern": pattern,
            "owasp_category": entry.get("owaspCategory") or entry.get("owasp") or "LLM01",
        }
    if ctype == "escalation":
        tool = str(entry.get("toolName") or entry.get("tool") or "").strip()
        shape = str(entry.get("argShape") or entry.get("arg_shape") or "").strip()
        if not tool or not shape:
            raise ValueError("escalation needs toolName + argShape")
        ident = quads.escalation_identifier(tool, shape)
        return "escalation", ident, {
            "severity": constants.normalize_severity(entry.get("severity"), "high"),
            "name": entry.get("title") or entry.get("name") or f"{tool} :: {shape}",
            "description": entry.get("summary") or entry.get("description") or "",
            "tool_name": tool,
            "arg_shape": shape,
        }
    if ctype == "dependency":
        eco = str(entry.get("ecosystem") or "").strip()
        name = str(entry.get("name") or entry.get("package") or entry.get("package_name") or "").strip()
        ver = str(entry.get("version") or entry.get("package_version") or "").strip()
        if not (eco and name and ver):
            raise ValueError("dependency needs ecosystem, name, version")
        ident = quads.dependency_identifier(eco, name, ver)
        return "dependency", ident, {
            "severity": constants.normalize_severity(entry.get("severity"), "high"),
            "name": entry.get("title") or entry.get("name") or f"{name}@{ver}",
            "description": entry.get("summary") or entry.get("description") or "",
            "ecosystem": eco.lower(),
            "package_name": name,
            "package_version": ver,
            "advisory_id": entry.get("advisoryId") or entry.get("advisory_id"),
            "references": entry.get("references") or [],
        }
    if ctype == "fileaccess":
        tool = str(entry.get("toolName") or entry.get("tool") or entry.get("tool_name") or "").strip()
        file_category = str(entry.get("category") or entry.get("file_category") or "").strip()
        if not tool or not file_category:
            raise ValueError("fileaccess needs tool + category")
        ident = quads.fileaccess_identifier(tool, file_category)
        return "fileaccess", ident, {
            "severity": constants.normalize_severity(entry.get("severity"), "high"),
            "name": entry.get("title") or entry.get("name") or f"{tool} :: {file_category}",
            "description": entry.get("summary") or entry.get("description") or "",
            "tool_name": tool.lower(),
            "file_category": file_category.lower(),
        }
    if ctype == "skill":
        skill_name = str(entry.get("skillName") or entry.get("skill_name") or entry.get("name") or "").strip()
        skill_version = str(entry.get("skillVersion") or entry.get("skill_version") or entry.get("version") or "").strip()
        danger_shape = str(entry.get("dangerShape") or entry.get("danger_shape") or "").strip()
        if not skill_name or not (skill_version or danger_shape):
            raise ValueError("skill needs name + (version or dangerShape)")
        if skill_version:
            ident = quads.skill_version_identifier(skill_name, skill_version)
        else:
            ident = quads.skill_shape_identifier(skill_name, danger_shape)
        return "skill", ident, {
            "severity": constants.normalize_severity(entry.get("severity"), "high"),
            "name": entry.get("title") or f"Skill {skill_name}",
            "description": entry.get("summary") or entry.get("description") or "",
            "skill_name": skill_name.lower(),
            "skill_version": skill_version or None,
            "danger_shape": danger_shape or None,
        }
    raise ValueError(f"unknown entry type: {ctype!r}")


def _osv_enrich(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """OSV-only enrichment for dependency entries (best-effort).

    Queries the OSV batch API for each dependency's ``(ecosystem, name,
    version)`` and stamps an advisory id + summary when found. Non-dependency
    entries pass through untouched.
    """
    deps = [e for e in entries if str(e.get("type", "")).lower() == "dependency"]
    if not deps:
        return entries
    osv_ecosystem = {"pypi": "PyPI", "python": "PyPI", "npm": "npm", "node": "npm"}
    queries = []
    for dep in deps:
        eco = osv_ecosystem.get(str(dep.get("ecosystem", "")).lower())
        name = dep.get("name") or dep.get("package") or dep.get("package_name")
        version = dep.get("version") or dep.get("package_version")
        queries.append({"package": {"ecosystem": eco, "name": name}, "version": version} if eco else {})
    try:
        body = json.dumps({"queries": queries}).encode("utf-8")
        req = urllib.request.Request(
            _OSV_BATCH_URL, data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=8.0) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        results = result.get("results", []) if isinstance(result, dict) else []
    except Exception as exc:
        logger.debug("guardian: OSV enrichment failed: %s", exc)
        return entries
    for dep, res in zip(deps, results):
        vulns = res.get("vulns", []) if isinstance(res, dict) else []
        if vulns and isinstance(vulns[0], dict):
            dep.setdefault("advisoryId", vulns[0].get("id"))
            dep.setdefault("summary", vulns[0].get("summary") or vulns[0].get("id"))
    return entries
