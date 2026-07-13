"""``hermes blackbox <sub>`` CLI.

Subcommands: ``status``, ``sync``, ``report``, ``setup-graph``,
``curate {list|show|approve|reject|import}``, and ``dashboard``. Curator flows
build quads via :mod:`quads` and talk to the node via :class:`DkgClient`;
read flows fail open with a friendly message.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from . import attach, audit, constants, llm, quads, ruleset, settings
from .config import BlackboxConfig, load_blackbox_config
from .dkg_client import DkgClient, DkgError, extract_binding

logger = logging.getLogger(__name__)

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_BLACKBOX_CHAT_PROFILE = "blackbox"
_BLACKBOX_SOUL_MARKER = "<!-- managed-by: hermes-blackbox-chat -->"
_BLACKBOX_SOURCE_ROOT_MARKER = ".blackbox-source-root"
_BLACKBOX_CONTEXT_FILE_MAX_CHARS = 100_000
_PRIVATE_AUTO_JOIN_GRAPH_IDS = {constants.DEFAULT_CONTEXT_GRAPH_ID}
_BLACKBOX_SOUL = f"""{_BLACKBOX_SOUL_MARKER}
# Agent Blackbox

You are Blackbox, the Agent Blackbox assistant. When asked who you are,
answer as Blackbox rather than Hermes.

Your job is to help operators work on Agent Blackbox: setup, local agent
attachment, audit/block mode, threat detection, dashboard behavior, and DKG
threat-graph workflows. Be direct, technical, and verify claims against real
Blackbox state before answering — NEVER answer threat-graph or detection
questions from general knowledge. If asked "what's in the public/community/local
graph", "what threats do we know", "recent activity", "connected agents", etc.,
you MUST fetch the real data from the sources below and answer from that.

## The three tiers (know the difference)
- **Public** (on-chain, verifiable memory): the curated Umanitek threat graph.
  Confirmed threats that BLOCK in block mode. Field name in APIs: `curated`.
- **Community** (shared working memory / SWM): an open pool any agent reports
  into. Flags only, never blocks. Field name: `community`.
- **Local** (this node's working memory + synced ruleset): what THIS node has
  pulled down and what it detects with offline. Field name: `ruleset`.

## Where to get each kind of data
Prefer the running dashboard API on http://127.0.0.1:9700 (all read-only, JSON):

- `GET /api/graph-status` — counts + config. Returns `mode`, `context_graph_id`,
  `dkg_url`, `node_reachable`, `last_sync`, `ruleset` (per-category local counts),
  `curated` (Public tier count), `community` (Community/SWM count),
  `sightings`, `findings_logged`.
- `GET /api/graph?tier=public|community|local` — the actual threat ENTRIES for a
  tier. Returns `{{tier, threats:[{{identifier, category, severity, name}}]}}`.
  Use this to list what's in the public/community/local graph.
- `GET /api/threat?tier=public|community&identifier=<id>` — full detail for one
  threat (description, references/advisories, reporters).
- `GET /api/findings?limit=&offset=` — threats Blackbox has flagged on this
  machine (newest first) with total.
- `GET /api/audit?limit=&offset=` — the full agent-activity feed (session
  lifecycle, API requests, tool calls with the real command, installs, flags).
- `GET /api/agents` — connected/protected local agents. Count the `agents` array
  EXACTLY; never estimate from generic Hermes status or sessions.
- `GET /api/reports` — recent outbound sightings shared to the community graph.

If the dashboard is NOT running (curl to :9700 fails), fall back to:
- `hermes blackbox status` — mode, node reachability, ruleset + findings counts.
- `hermes blackbox sync` — force a ruleset refresh from the DKG node first.
- Read the local state files directly under `$BLACKBOX_HOME` (usually
  `~/.hermes/blackbox/`): `ruleset.json` (synced threats by category, the local
  graph), `findings.jsonl` (every flag), `audit.jsonl` (activity),
  `dependencies.jsonl`, `file_access.jsonl`.

## Rules
- The endpoint is `/api/graph` (NOT `/api/threat-graph` — that does not exist).
- When the graph tiers read 0 but `ruleset` is non-zero, the DKG node/graph is
  unreachable for live queries while the local synced ruleset still works — say
  that explicitly rather than claiming the graph is empty.
- Quote real numbers and identifiers from the fetched JSON; don't paraphrase or
  invent entries.
"""


# ---------------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------------


def setup_cli(parser: argparse.ArgumentParser) -> None:
    """Build the ``hermes blackbox`` subparser tree."""
    parser.set_defaults(func=_cmd_chat)
    sub = parser.add_subparsers(dest="blackbox_command")

    chat = sub.add_parser(
        "chat",
        help="Start a Blackbox-named Hermes chat in the dedicated blackbox profile",
        description=(
            "Create/update the dedicated Blackbox profile, then launch normal "
            "Hermes chat through that profile. Extra args are passed to "
            "`hermes --profile blackbox chat`; bare text becomes `--query`."
        ),
    )
    _add_blackbox_chat_args(chat)
    chat.set_defaults(func=_cmd_chat)

    sub.add_parser("status", help="Show config, node reachability, ruleset + findings counts").set_defaults(
        func=_cmd_status
    )
    sync = sub.add_parser("sync", help="Force a ruleset refresh from the DKG node")
    sync.add_argument(
        "--wait",
        action="store_true",
        help="Wait for DKG catch-up before refreshing the Blackbox cache",
    )
    sync.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Seconds to wait for catch-up with --wait (default: 180)",
    )
    sync.add_argument(
        "--require-rules",
        action="store_true",
        help="Return non-zero if the refreshed ruleset is empty (used by installers)",
    )
    sync.set_defaults(func=_cmd_sync)

    attach_p = sub.add_parser(
        "attach", help="Auto-protect every local Hermes home + OpenClaw workspace"
    )
    attach_p.add_argument("--dry-run", action="store_true", help="Show what would change; write nothing")
    attach_p.add_argument("--hermes-only", action="store_true", help="Only attach to Hermes homes")
    attach_p.add_argument("--openclaw-only", action="store_true", help="Only attach to OpenClaw workspaces")
    attach_p.set_defaults(func=_cmd_attach)

    detach_p = sub.add_parser("detach", help="Disable Blackbox in every local agent")
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
    report.add_argument(
        "--kind", choices=[constants.KIND_MALWARE, constants.KIND_VULNERABILITY],
        help="dependency: malware (blocks) or vulnerability (flags only)",
    )
    report.add_argument("--category", help="fileaccess: sensitive-path category (e.g. ssh-private-key)")
    report.add_argument("--skill-name", dest="skill_name", help="skill: skill name")
    report.add_argument("--skill-version", dest="skill_version", help="skill: known-bad version")
    report.add_argument("--danger-shape", dest="danger_shape", help="skill: danger shape slug (e.g. shell-exec)")
    report.add_argument("--severity", default="high", choices=list(constants.SEVERITY_ORDER))
    report.add_argument("--description", default="", help="Human-readable description")
    report.set_defaults(func=_cmd_report)

    setup_graph = sub.add_parser("setup-graph", help="Curator: create + register the Blackbox threat graph")
    setup_graph.add_argument(
        "--network", default="mainnet-base", choices=("mainnet-base", "mainnet-gnosis"),
        help="Mainnet to register on (informational; the node's own network is what counts). No testnet.",
    )
    setup_graph.set_defaults(func=_cmd_setup_graph)

    curate = sub.add_parser("curate", help="Curator: review + promote community threats")
    csub = curate.add_subparsers(dest="curate_command")

    clist = csub.add_parser("list", help="List candidate threats grouped by distinct reporters")
    clist.add_argument("--pending", action="store_true", help="Only show non-curated candidates")
    clist.add_argument("--json", action="store_true", help="Emit machine-readable JSON (for an agent curator to parse)")
    clist.set_defaults(func=_cmd_curate_list)

    cshow = csub.add_parser("show", help="Show one threat/candidate and its reporters")
    cshow.add_argument("identifier")
    cshow.add_argument("--json", action="store_true", help="Emit machine-readable JSON (for an agent curator to parse)")
    cshow.set_defaults(func=_cmd_curate_show)

    capprove = csub.add_parser("approve", help="Promote a candidate and publish its full threat asset to VM")
    capprove.add_argument("identifier")
    capprove.add_argument("--severity", choices=list(constants.SEVERITY_ORDER))
    capprove.add_argument("--name", help="Override display name")
    capprove.add_argument("--description", default="", help="Override description")
    capprove.add_argument("--epochs", type=int, default=1, help="VM publish epochs")
    capprove.add_argument("--publish-timeout", type=int, default=600, help="Seconds to wait for async VM finality (default: 600)")
    capprove.add_argument("--publish-poll-interval", type=int, default=5, help="Seconds between async VM job polls (default: 5)")
    capprove.add_argument("--no-publish", action="store_true", help="Share the full threat to SWM only; skip VM publishing")
    capprove.add_argument("--publish-threat-ka", action="store_true",
                          help=argparse.SUPPRESS)  # compatibility: full VM publishing is the default
    capprove.add_argument("--source", help="Named source/feed for this threat (shown in the dashboard modal).")
    capprove.add_argument("--contributor", help="Attribution — who contributed this asset.")
    capprove.set_defaults(func=_cmd_curate_approve)

    canchor = csub.add_parser(
        "anchor",
        help="Compatibility migration: publish full VM assets for SWM-only curated threats",
    )
    canchor.add_argument("--batch-size", type=int, default=constants.DEFAULT_ANCHOR_BATCH_SIZE,
                         help=f"Full threat assets per migration batch (default {constants.DEFAULT_ANCHOR_BATCH_SIZE})")
    canchor.add_argument("--epochs", type=int, default=1, help="VM publish epochs")
    canchor.add_argument("--publish-timeout", type=int, default=600, help="Seconds to wait for async VM finality per threat asset (default: 600)")
    canchor.add_argument("--publish-poll-interval", type=int, default=5, help="Seconds between async VM job polls (default: 5)")
    canchor.add_argument("--dry-run", action="store_true", help="Report pending full threat assets without publishing")
    canchor.add_argument("--max-batches", type=int, default=0, help="Publish at most this many migration batches this run (0 = all pending)")
    canchor.add_argument("--adopt-existing", action="store_true",
                         help="One-time migration: adopt every complete urn:guardian:threat asset in local SWM into the curated ledger")
    canchor.set_defaults(func=_cmd_curate_anchor)

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
    cimport.add_argument("--no-publish", action="store_true", help="Share full threats to SWM only; skip VM publishing")
    cimport.add_argument("--publish-threat-kas", action="store_true",
                         help=argparse.SUPPRESS)  # compatibility: full VM publishing is the default
    cimport.add_argument("--dry-run", action="store_true", help="Preview what WOULD publish after dedup; spend no TRAC")
    cimport.add_argument("--check-graph", action="store_true", help="Also skip complete threat assets already on-chain (queries VM once)")
    cimport.add_argument("--epochs", type=int, default=1, help="Storage epochs per asset — higher = longer on-chain life, more TRAC (default 1)")
    cimport.add_argument("--publish-timeout", type=int, default=600, help="Seconds to wait for each async VM publish job (default: 600)")
    cimport.add_argument("--publish-poll-interval", type=int, default=5, help="Seconds between async VM job polls (default: 5)")
    cimport.add_argument("--limit", type=int, help="Publish at most N NEW threats this run (batch seeding). Re-run to continue — the seeded ledger resumes where you left off, so it never double-pays.")
    cimport.add_argument("--source", help="Named source/feed for entries that don't set their own (e.g. 'OSV.dev', 'Socket'). Shown in the dashboard modal.")
    cimport.add_argument("--contributor", help="Attribution stamped on entries that don't set their own — who contributed this batch (e.g. 'Umanitek').")
    cimport.set_defaults(func=_cmd_curate_import)

    dash = sub.add_parser("dashboard", help="Start the local Blackbox dashboard")
    dash.add_argument("--port", type=int, help="Override dashboard port")
    dash.set_defaults(func=_cmd_dashboard)

    setup_llm = sub.add_parser(
        "setup-llm", help="Configure the optional LLM prompt-injection reviewer (provider/model/key)"
    )
    setup_llm.add_argument("--provider", choices=["openai", "anthropic"], help="Skip the prompt: set provider")
    setup_llm.add_argument("--model", help="Skip the prompt: set model id (default: provider's recommended)")
    setup_llm.add_argument(
        "--key-source", choices=["hermes", "openclaw", "new"], help="Where to copy the API key from"
    )
    setup_llm.add_argument("--api-key", help="Skip the prompt: use this API key (with --key-source new)")
    setup_llm.add_argument(
        "--auto",
        action="store_true",
        help="Reuse existing Blackbox, Hermes, or OpenClaw model credentials without prompting",
    )
    setup_llm.add_argument(
        "--configure",
        action="store_true",
        help="Prompt for provider, API key, and model even when reusable config exists",
    )
    setup_llm.add_argument("--disable", action="store_true", help="Turn the LLM reviewer off and exit")
    setup_llm.set_defaults(func=_cmd_setup_llm)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _add_blackbox_chat_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("prompt", nargs="*", help='Bare prompt text, e.g. "who are you?"')
    parser.add_argument("-q", "--query", help="Single query (non-interactive mode)")
    parser.add_argument("--image", help="Optional local image path to attach to a single query")
    parser.add_argument("-m", "--model", help="Model to use")
    parser.add_argument("--provider", help="Inference provider")
    parser.add_argument("-t", "--toolsets", help="Comma-separated toolsets to enable")
    parser.add_argument("-s", "--skills", action="append", help="Preload one or more skills")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-Q", "--quiet", action="store_true", help="Suppress banner/spinner/tool previews")
    parser.add_argument("--resume", "-r", metavar="SESSION_ID", help="Resume a previous session by ID")
    parser.add_argument(
        "--continue",
        "-c",
        dest="continue_last",
        nargs="?",
        const=True,
        metavar="SESSION_NAME",
        help="Resume a session by name, or the most recent if no name given",
    )
    parser.add_argument("--worktree", "-w", action="store_true", help="Run in an isolated git worktree")
    parser.add_argument("--accept-hooks", action="store_true", help="Auto-approve unseen shell hooks")
    parser.add_argument("--checkpoints", action="store_true", help="Enable filesystem checkpoints")
    parser.add_argument("--max-turns", type=int, metavar="N", help="Maximum tool-calling iterations")
    parser.add_argument("--yolo", action="store_true", help="Bypass dangerous command approval prompts")
    parser.add_argument("--pass-session-id", action="store_true", help="Include session ID in the system prompt")
    parser.add_argument("--ignore-user-config", action="store_true", help="Ignore config.yaml")
    parser.add_argument("--ignore-rules", action="store_true", help="Skip AGENTS.md/SOUL.md/rules injection")
    parser.add_argument("--safe-mode", action="store_true", help="Disable all customizations")
    parser.add_argument("--tui", action="store_true", help="Launch the modern TUI")
    parser.add_argument("--cli", action="store_true", help="Force the classic prompt_toolkit REPL")
    parser.add_argument("--dev", dest="tui_dev", action="store_true", help="With --tui: run TypeScript sources")


def _cmd_chat(args: argparse.Namespace) -> int:
    profile = _ensure_blackbox_chat_profile()
    argv = _blackbox_chat_argv(_blackbox_chat_args(args), profile=profile)
    cwd = _blackbox_chat_cwd()
    if cwd is not None:
        os.chdir(cwd)
    env = dict(os.environ)
    env.pop("HERMES_HOME", None)
    env["HERMES_BLACKBOX_CHAT"] = "1"
    os.execvpe(argv[0], argv, env)
    return 1


def _ensure_blackbox_chat_profile(profile: str = _BLACKBOX_CHAT_PROFILE) -> str:
    from hermes_cli.profiles import create_profile, get_profile_dir, profile_exists

    if not profile_exists(profile):
        create_profile(
            profile,
            clone_config=True,
            no_alias=True,
            description="Agent Blackbox chat profile",
        )
    profile_dir = get_profile_dir(profile)
    _write_blackbox_soul(profile_dir)
    _ensure_blackbox_context_cap(profile_dir)
    attach.attach_hermes(profile_dir)
    return profile


def _blackbox_chat_args(args: argparse.Namespace) -> List[str]:
    out: List[str] = []
    for attr, flag in [
        ("query", "--query"),
        ("image", "--image"),
        ("model", "--model"),
        ("provider", "--provider"),
        ("toolsets", "--toolsets"),
        ("resume", "--resume"),
        ("max_turns", "--max-turns"),
    ]:
        value = getattr(args, attr, None)
        if value is not None:
            out.extend([flag, str(value)])
    for skill in getattr(args, "skills", None) or []:
        out.extend(["--skills", skill])
    continue_last = getattr(args, "continue_last", None)
    if continue_last is True:
        out.append("--continue")
    elif continue_last:
        out.extend(["--continue", str(continue_last)])
    for attr, flag in [
        ("verbose", "--verbose"),
        ("quiet", "--quiet"),
        ("worktree", "--worktree"),
        ("accept_hooks", "--accept-hooks"),
        ("checkpoints", "--checkpoints"),
        ("yolo", "--yolo"),
        ("pass_session_id", "--pass-session-id"),
        ("ignore_user_config", "--ignore-user-config"),
        ("ignore_rules", "--ignore-rules"),
        ("safe_mode", "--safe-mode"),
        ("tui", "--tui"),
        ("cli", "--cli"),
        ("tui_dev", "--dev"),
    ]:
        if getattr(args, attr, False):
            out.append(flag)
    prompt = getattr(args, "prompt", None) or []
    if prompt and not getattr(args, "query", None):
        out.extend(["--query", " ".join(prompt)])
    return out


def _blackbox_chat_cwd() -> Optional[Path]:
    candidates: List[Path] = []
    marker = Path(__file__).resolve().parent / _BLACKBOX_SOURCE_ROOT_MARKER
    try:
        if marker.exists():
            marked = Path(marker.read_text(encoding="utf-8").strip()).expanduser()
            candidates.append(marked)
    except Exception:
        pass
    try:
        candidates.append(attach._repo_root())
    except Exception:
        pass
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except Exception:
            continue
        if (resolved / "plugins" / "blackbox" / "cli.py").exists():
            return resolved
    return None


def _write_blackbox_soul(profile_dir: Path) -> None:
    soul_path = profile_dir / "SOUL.md"
    existing = ""
    if soul_path.exists():
        try:
            existing = soul_path.read_text(encoding="utf-8")
        except OSError:
            existing = ""
    if existing == _BLACKBOX_SOUL:
        return
    if existing and _BLACKBOX_SOUL_MARKER not in existing:
        backup = profile_dir / "SOUL.md.before-blackbox-chat"
        if not backup.exists():
            try:
                backup.write_text(existing, encoding="utf-8")
            except OSError:
                pass
    soul_path.write_text(_BLACKBOX_SOUL, encoding="utf-8")


def _ensure_blackbox_context_cap(profile_dir: Path) -> None:
    config_path = profile_dir / "config.yaml"
    if attach.yaml is None:
        if not config_path.exists():
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(
                f"context_file_max_chars: {_BLACKBOX_CONTEXT_FILE_MAX_CHARS}\n",
                encoding="utf-8",
            )
        return
    data = attach._load_yaml(config_path)
    current = data.get("context_file_max_chars")
    if isinstance(current, int) and current >= _BLACKBOX_CONTEXT_FILE_MAX_CHARS:
        return
    data["context_file_max_chars"] = _BLACKBOX_CONTEXT_FILE_MAX_CHARS
    attach._dump_yaml(config_path, data)


def _blackbox_chat_argv(chat_args: Optional[List[str]], profile: str = _BLACKBOX_CHAT_PROFILE) -> List[str]:
    args = [a for a in (chat_args or []) if a != "--"]
    argv = [sys.argv[0] or "hermes", "--profile", profile, "chat"]
    if args and not args[0].startswith("-"):
        argv.extend(["--query", " ".join(args)])
    else:
        argv.extend(args)
    return argv


def _cmd_status(args: argparse.Namespace) -> int:
    cfg = load_blackbox_config()
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    reachable = client.reachable()
    rs = ruleset.get(cfg)
    counts = rs.counts()
    print("Agent Blackbox")
    print(f"  mode:              {cfg.mode}")
    print(f"  block severity:    {cfg.block_severity}")
    print(f"  context graph:     {cfg.context_graph_id}")
    print(f"  DKG node:          {cfg.dkg_url}  [{'reachable' if reachable else 'unreachable'}]")
    print(f"  DKG home:          {cfg.dkg_home}")
    print(f"  DKG CLI:           {cfg.dkg_bin}")
    if Path(cfg.dkg_home).expanduser() == Path.home() / ".dkg":
        print("  note:              using shared ~/.dkg; OK for an intentional funded publisher node")
    if reachable:
        info = client.chain_info()
        cid = info.get("chain_id")
        net = info.get("network") or "unknown"
        if info.get("is_testnet"):
            suffix = " — TESTNET (publishing disabled)"
        elif info.get("is_mainnet") and cid == constants.DEFAULT_DKG_CHAIN_ID:
            suffix = " (Base mainnet)"
        elif info.get("is_mainnet"):
            suffix = " (mainnet, not Base — wallet is funded on Base)"
        elif cid is not None:
            suffix = " — unrecognized chain"
        else:
            suffix = ""
        idpart = f"chainId {cid}" if cid is not None else "chain unknown"
        print(f"  DKG network:       {net} ({idpart}){suffix}")
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
    """List which local Hermes homes / OpenClaw workspaces have Blackbox attached."""
    attached_hermes = []
    for home in attach.discover_hermes_homes():
        try:
            data = attach._load_yaml(home / "config.yaml")
            if attach._enabled_list_has(data, "blackbox"):
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
            if isinstance(allow, list) and "blackbox" in allow:
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
    cfg = load_blackbox_config()
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    private_graph = _should_request_private_join(cfg)
    admitted = not private_graph
    next_join_attempt = 0.0
    deadline = time.monotonic() + max(1, int(getattr(args, "timeout", 180) or 180))

    # The daemon owns subscriptions, approval delivery, catch-up, and ongoing
    # reconciliation. Blackbox only starts the native lifecycle once. A private
    # join is retried only until the curator accepts delivery; after that the
    # DKG's reliable join-approved outbox and auto-subscribe path take over.
    if not private_graph:
        try:
            client.subscribe_context_graph(cfg.context_graph_id)
        except DkgError as exc:
            print(f"warning: could not subscribe to {cfg.context_graph_id}: {exc}")

    rs = None
    attempt = 0
    while True:
        now = time.monotonic()
        rs = ruleset.refresh(cfg, client)
        counts = rs.counts()
        if sum(counts.values()) > 0:
            break

        if private_graph and not admitted and now >= next_join_attempt:
            status, admitted = _request_join(client, cfg.context_graph_id, cfg.curator_peer_id)
            if status:
                print(status)
            next_join_attempt = now + 5.0
        if not getattr(args, "wait", False) or now >= deadline:
            break
        attempt += 1
        if attempt == 1 or attempt % 10 == 0:
            print("Waiting for DKG admission and graph sync...")
        time.sleep(min(3.0, max(0.2, deadline - now)))

    assert rs is not None
    print(f"Ruleset synced from {cfg.context_graph_id}:")
    print(f"  {counts['injection']} injection, {counts['escalation']} escalation, "
          f"{counts['dependency']} dependency")
    if sum(counts.values()) == 0:
        print("  0 rules — no local public/SWM threat rows are available yet.")
        print("  The DKG daemon will keep syncing; retry with `hermes blackbox sync --wait`.")
        if getattr(args, "require_rules", False):
            print("  Required ruleset sync failed; install is incomplete until threat rows load from DKG.")
            return 2
    return 0


def _should_request_private_join(cfg: BlackboxConfig) -> bool:
    return bool(
        getattr(cfg, "curator_peer_id", "")
        and getattr(cfg, "context_graph_id", "") in _PRIVATE_AUTO_JOIN_GRAPH_IDS
    )


def _request_join(client: DkgClient, cg_id: str, curator_peer_id: str) -> tuple[Optional[str], bool]:
    """Submit one native private-graph join request.

    The boolean becomes true only once a curator received the request (or the
    node was already a member). Callers may safely retry delivery failures;
    after acceptance DKG owns every later retry and sync transition.
    """
    if not curator_peer_id:
        return None, False
    try:
        result = client.request_join(cg_id, curator_peer_id)
    except DkgError as exc:
        return f"warning: could not request join for {cg_id}: {exc}", False
    if not isinstance(result, dict):
        return f"Join request submitted for {cg_id}.", True
    if result.get("alreadyMember") or result.get("already_member"):
        return f"Join request: this node is already a member of {cg_id}.", True
    delivered = result.get("delivered")
    if isinstance(delivered, list):
        delivered_count = len(delivered)
    elif isinstance(delivered, bool):
        delivered_count = 1 if delivered else 0
    else:
        try:
            delivered_count = int(delivered or result.get("deliveredCount") or 0)
        except (TypeError, ValueError):
            delivered_count = 0
    if delivered_count:
        return f"Join request sent for {cg_id}: delivered to {delivered_count} curator(s).", True
    return f"Join request could not reach a curator for {cg_id}; retrying.", False


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
        print(f"\nDry run: Blackbox would watch {count} agent(s). Nothing was written.")
    else:
        print(f"\nBlackbox is watching {count} agent(s). Restart any running agent to activate.")
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
    print("\nBlackbox detached. Restart any running agent to apply.")
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
    cfg = load_blackbox_config()
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
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


def _require_mainnet_for_publish(client: DkgClient) -> bool:
    """Preflight before spending TRAC: is the node on a supported mainnet?

    Fresh DKG v10 nodes can come up on a testnet, or on a different mainnet than
    the curator wallet is funded on (the node's own default is Gnosis, not Base)
    — and publishing then silently goes to the wrong chain, or to a testnet, with
    no signal. So before any paid publish we check the node's real chain:

    * positively-identified **testnet** or an **unrecognized** chain → BLOCK.
    * a **mainnet that isn't Base** (Gnosis/NeuroWeb) → WARN, allow (valid override).
    * chain **can't be read** from ``/api/status`` → WARN, allow (fail-open so a
      healthy node whose status shape we don't recognize is never falsely blocked).
    """
    info = client.chain_info()
    cid = info.get("chain_id")
    net = info.get("network") or "unknown"
    if info.get("is_testnet"):
        print(f"error: DKG node is on a TESTNET ({net}, chainId={cid}). Blackbox is mainnet-only — refusing to publish.")
        dkg_home = getattr(client, "dkg_home", str(constants.blackbox_dkg_home()))
        dkg_url = getattr(client, "url", constants.DEFAULT_DKG_URL)
        dkg_bin = str(constants.blackbox_dkg_bin())
        print(
            "       Re-bootstrap the Blackbox node on mainnet:  "
            f'DKG_HOME="{dkg_home}" "{dkg_bin}" start  # configured for {dkg_url}'
        )
        return False
    if cid is not None and not info.get("is_mainnet"):
        print(f"error: DKG node is on an unrecognized chain (chainId={cid}, {net}); refusing to publish.")
        print("       Blackbox publishes only to a DKG mainnet (mainnet-base). Check your node config.")
        return False
    if cid is not None and cid != constants.DEFAULT_DKG_CHAIN_ID:
        print(f"warning: DKG node is on {net} (chainId={cid}), not Base (8453) — the curator wallet is funded")
        print("         with ETH on Base, so publishes go to this chain instead. Continue only if intentional.")
    elif cid is None:
        print(f"warning: could not read the DKG node's chain from /api/status (network={net!r}); proceeding without a mainnet check.")
    return True


def _cmd_setup_graph(args: argparse.Namespace) -> int:
    cfg = load_blackbox_config()
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    if not _require_mainnet_for_publish(client):
        return 1
    cg = cfg.context_graph_id
    curator_agent = ""
    try:
        curator_agent = str(client.agent_identity().get("agentAddress") or "")
    except DkgError as exc:
        print(f"warning: could not read local DKG agent identity before create: {exc}")
    try:
        # Private transport/read path with open membership. The DKG daemon is
        # configured to auto-approve valid join requests for this graph, while
        # publishPolicy=0 independently keeps VM promotion curator-only.
        client.create_context_graph(cg, name="Blackbox Threats",
                                    description="Curated agent-security threat intelligence.",
                                    access_policy=1,
                                    allowed_agents=[curator_agent] if curator_agent else None)
        print(f"Created context graph {cg} as private/open-membership (or already existed).")
    except DkgError as exc:
        print(f"note: create returned: {exc}")
    try:
        client.register_context_graph(cg, access_policy=1, publish_policy=0)
        print(f"Registered {cg} on-chain (accessPolicy=1 private, publishPolicy=0 curated) on {args.network}.")
    except DkgError as exc:
        print(f"error: register failed: {exc}")
        return 1
    print("DKG auto-approves valid joins for this graph; no Blackbox approver process is required.")
    return 0


def _cmd_curate_list(args: argparse.Namespace) -> int:
    cfg = load_blackbox_config()
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
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
    rejected = _load_rejected()  # locally-rejected candidates stay hidden
    items: List[Dict[str, Any]] = []
    for row in rows:
        ident = extract_binding(row.get("identifier"))
        if ident in rejected:
            continue
        curated = extract_binding(row.get("cur")).lower() == "true"
        if args.pending and curated:
            continue
        items.append({
            "identifier": ident,
            "reporters": int(extract_binding(row.get("reporters")) or "0"),
            "severity": extract_binding(row.get("sev")) or "info",
            "curated": curated,
        })
    if getattr(args, "json", False):
        print(json.dumps(items, indent=2))
        return 0
    if not rows:
        print("No community reports found (empty graph or node unreachable).")
        return 0
    print(f"{'reporters':>9}  {'sev':<8}  {'curated':<7}  identifier")
    for it in items:
        print(f"{it['reporters']:>9}  {it['severity']:<8}  {'yes' if it['curated'] else 'no':<7}  {it['identifier']}")
    return 0


# Report predicate IRI -> friendly field name. Reports carry these privacy-safe
# threat fields for candidates (see quads.build_report_quads), so a curator (or
# an agent curator) can judge WHAT the threat is, not just who reported it.
_REPORT_FIELD_NAMES = {
    constants.PATTERN_PRED: "pattern",
    constants.OWASP_CATEGORY_PRED: "owasp",
    constants.TOOL_NAME_PRED: "tool",
    constants.ARG_SHAPE_PRED: "arg_shape",
    constants.PACKAGE_ECOSYSTEM_PRED: "ecosystem",
    constants.PACKAGE_NAME_PRED: "package",
    constants.PACKAGE_VERSION_PRED: "version",
    constants.SCHEMA_IDENTIFIER_PRED: "advisory",
    constants.KIND_PRED: "kind",
    constants.CATEGORY_PRED: "file_category",
    constants.SKILL_NAME_PRED: "skill",
    constants.SKILL_VERSION_PRED: "skill_version",
    constants.DANGER_SHAPE_PRED: "danger_shape",
}


def _cmd_curate_show(args: argparse.Namespace) -> int:
    cfg = load_blackbox_config()
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    ident = args.identifier
    esc = ident.replace("\\", "\\\\").replace('"', '\\"')
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
    reports = [{
        "reporter": extract_binding(r.get("reporter")),
        "severity": extract_binding(r.get("severity")) or None,
        "framework": extract_binding(r.get("framework")) or None,
    } for r in rows]

    # The privacy-safe threat fields forwarded on the reports (what the threat IS).
    fields: Dict[str, str] = {}
    try:
        frows = client.query(
            'PREFIX g: <http://umanitek.ai/ontology/guardian/> '
            f'SELECT ?p ?o WHERE {{ ?report a g:ThreatReport . ?report g:identifier "{esc}" . ?report ?p ?o . }}',
            cfg.context_graph_id, view=constants.VIEW_SHARED_WORKING_MEMORY,
        )
        for fr in frows:
            name = _REPORT_FIELD_NAMES.get(extract_binding(fr.get("p")))
            val = extract_binding(fr.get("o"))
            if name and val and name not in fields:
                fields[name] = val
    except DkgError:
        pass

    if getattr(args, "json", False):
        print(json.dumps({
            "identifier": ident, "reporters": len(reports), "reports": reports, "fields": fields,
        }, indent=2))
        return 0
    print(f"Threat: {ident}")
    print(f"  reporters: {len(reports)}")
    if fields:
        print("  fields: " + ", ".join(f"{k}={v}" for k, v in fields.items()))
    for r in reports:
        print(f"    - {r['reporter']} [{r['severity'] or '-'}] via {r['framework'] or '-'}")
    return 0


def _cmd_curate_approve(args: argparse.Namespace) -> int:
    cfg = load_blackbox_config()
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    ident = args.identifier
    category, fields = _threat_fields_from_reports(client, cfg, ident)
    if category is None:
        print(f"error: could not resolve threat fields for {ident} from reports.")
        return 2
    # An injection id is a hash of its regex, so the pattern can't be recovered
    # from the identifier — without it in a report, approval would mint a rule
    # that can never match. Refuse rather than publish a dead (paid) rule.
    if category == "injection" and not fields.get("pattern"):
        print(f"error: no injection regex recoverable for {ident}; a report must carry --pattern first.")
        return 2
    kind = fields.get("kind")
    # Malware must block; force critical if a report under-stated it (see
    # constants.severity_for_kind). Curator --severity still wins when given.
    severity = args.severity or constants.severity_for_kind(kind, fields.get("severity"))
    name = args.name or fields.get("name") or ident
    description = args.description or fields.get("description") or f"Curated threat {ident}"
    quad_kwargs = dict(
        category=category,
        identifier=ident,
        severity=severity,
        name=name,
        description=description,
        curated=True,
        kind=kind,
        sources=[args.source] if args.source else (fields.get("sources") or None),
        references=fields.get("references"),
        contributor=args.contributor or fields.get("contributor"),
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
        ioc_type=fields.get("ioc_type"),
        minimal=False,
    )
    q = quads.build_threat_quads(**quad_kwargs)
    publish = not bool(getattr(args, "no_publish", False))
    if publish and not _require_mainnet_for_publish(client):
        return 1
    # One sealed KA moves through both tiers. Publishing this exact full asset
    # guarantees VM contains the name, description, provenance, references,
    # and category-specific match fields — never only a proof or reduced copy.
    ka_name = f"candidate-{quads.slug(ident)}"
    try:
        client.share_knowledge_asset(cfg.context_graph_id, ka_name, q)
        print(f"Shared full curated threat {ident} to {cfg.context_graph_id} (SWM).")
        _append_curated_ledger([ident])
        if publish:
            result = client.publish_async_and_wait(
                cfg.context_graph_id,
                ka_name,
                epochs=args.epochs,
                timeout_s=max(1, int(getattr(args, "publish_timeout", 600) or 600)),
                poll_s=max(1, int(getattr(args, "publish_poll_interval", 5) or 5)),
            )
            ual = result.get("ual") if isinstance(result, dict) else None
            tx = result.get("txHash") if isinstance(result, dict) else None
            print(f"Published full threat asset to VM. UAL={ual} txHash={tx}")
            # Record the on-chain publish so a later `import` never re-pays for it.
            _append_seeded_ledger([ident])
        else:
            print("VM publish skipped; re-run without --no-publish to publish the full threat asset.")
    except DkgError as exc:
        print(f"error: {exc}")
        return 1
    return 0


def _community_full_threat_identifiers(client: DkgClient, cfg) -> Optional[set]:
    """Complete threat assets currently available in this graph's SWM.

    Requiring both descriptive predicates rejects report rows and legacy lean
    copies. The curator ledger is intersected with this set before migration,
    so an arbitrary community writer cannot promote itself merely by setting
    ``g:curated``.
    """
    prefix = f"did:dkg:context-graph:{cfg.context_graph_id}/_shared_memory"
    sparql = f"""PREFIX g: <http://umanitek.ai/ontology/guardian/>
PREFIX schema: <http://schema.org/>
SELECT DISTINCT ?identifier WHERE {{
  GRAPH ?g {{
    ?threat g:identifier ?identifier ;
            schema:name ?name ;
            schema:description ?description .
  }}
  FILTER(STRSTARTS(STR(?g), "{prefix}"))
  FILTER(STRSTARTS(STR(?threat), "urn:guardian:threat:"))
}}"""
    _FAILED = object()
    rows = _FAILED
    for _ in range(3):  # a scoped store read can blip under concurrent load
        rows = client.query_store(sparql, on_error=_FAILED)
        if rows is not _FAILED:
            break
        time.sleep(1)
    if rows is _FAILED:
        return None  # signal a read failure — NOT an empty curated set
    return {
        extract_binding(row.get("identifier"))
        for row in rows or []
        if extract_binding(row.get("identifier"))
    }


def _pull_full_threat_asset(client: DkgClient, cfg: BlackboxConfig, identifier: str) -> str:
    """Pull a known complete SWM asset into WM and return its KA name.

    Proof-era curation used ``candidate-*``; the original full-asset writer used
    ``threat-*``. Trying both lets ``curate anchor`` act as an in-place migration
    without ever manufacturing another proof or reduced assertion.
    """
    errors: List[str] = []
    for name in (f"candidate-{quads.slug(identifier)}", f"threat-{quads.slug(identifier)}"):
        try:
            client.pull_knowledge_asset_from(
                cfg.context_graph_id,
                name,
                "swm",
                on_conflict="replace",
            )
            return name
        except DkgError as exc:
            errors.append(f"{name}: {exc}")
    raise DkgError(
        f"could not load the full SWM knowledge asset for {identifier}: " + "; ".join(errors)
    )


def _cmd_curate_anchor(args: argparse.Namespace) -> int:
    """Compatibility migration from proof/SWM-only rows to full VM assets.

    The command name remains for existing runbooks, but it never writes a
    ``CurationProof``. Each pending curated identifier is published as its own
    complete, already-sealed threat KA.
    """
    cfg = load_blackbox_config()
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    dry_run = bool(getattr(args, "dry_run", False))
    if not dry_run and not _require_mainnet_for_publish(client):
        return 1
    available = _community_full_threat_identifiers(client, cfg)
    if available is None:
        print("error: could not read full curated threats from the local store (node busy?). Try again.")
        return 1
    if getattr(args, "adopt_existing", False):
        adopt = sorted(available - _load_curated_ledger())
        if adopt:
            _append_curated_ledger(adopt)
            print(f"Adopted {len(adopt)} existing full SWM threat asset(s) into the curated ledger.")
        else:
            print("Adopt: every full SWM threat asset is already in the curated ledger.")
    curated = _load_curated_ledger()
    eligible = curated & available
    published_full = _existing_graph_identifiers(client, cfg)
    missing = len(curated - available)
    pending = sorted(eligible - published_full)
    print(f"Curated ledger: {len(curated)}  with full SWM assets: {len(eligible)}  "
          f"full assets on VM: {len(eligible & published_full)}  pending: {len(pending)}")
    if missing:
        print(f"note: {missing} ledger identifier(s) have no complete local SWM asset yet — share/sync first, then re-run.")
    if not pending:
        return 0
    batch_size = max(1, int(getattr(args, "batch_size", constants.DEFAULT_ANCHOR_BATCH_SIZE)
                            or constants.DEFAULT_ANCHOR_BATCH_SIZE))
    batches = [pending[i:i + batch_size] for i in range(0, len(pending), batch_size)]
    if dry_run:
        for n, batch in enumerate(batches, 1):
            print(f"  batch {n}/{len(batches)}: {len(batch)} full threat asset(s) (dry-run)")
        return 0
    max_batches = int(getattr(args, "max_batches", 0) or 0)
    if max_batches > 0 and len(batches) > max_batches:
        print(f"Publishing the first {max_batches} of {len(batches)} pending batch(es) this run "
              f"(re-run `curate anchor` to continue).")
        batches = batches[:max_batches]
    published = 0
    for n, batch in enumerate(batches, 1):
        for identifier in batch:
            try:
                name = _pull_full_threat_asset(client, cfg, identifier)
                result = client.publish_async_and_wait(
                    cfg.context_graph_id,
                    name,
                    epochs=args.epochs,
                    timeout_s=max(1, int(getattr(args, "publish_timeout", 600) or 600)),
                    poll_s=max(1, int(getattr(args, "publish_poll_interval", 5) or 5)),
                )
                ual = result.get("ual") if isinstance(result, dict) else None
                print(f"  batch {n}/{len(batches)}: {identifier} -> full VM asset published (UAL={ual})")
                _append_seeded_ledger([identifier])
                published += 1
            except DkgError as exc:
                print(f"error: full threat publish failed for {identifier}: {exc}")
                print("       completed assets stay valid; re-run `curate anchor` to retry the rest.")
                return 1
    print(f"Done: {published} full threat KA(s) published to VM.")
    return 0


def _cmd_curate_reject(args: argparse.Namespace) -> int:
    cfg = load_blackbox_config()
    ident = args.identifier
    # Local rejection: append to the rejects file so `curate list` hides it.
    try:
        rejects = _rejected_path()
        rejects.parent.mkdir(parents=True, exist_ok=True)
        data = sorted(_load_rejected() | {ident})
        rejects.write_text(json.dumps(data), encoding="utf-8")
    except Exception as exc:
        print(f"warning: could not persist local rejection: {exc}")
    print(f"Marked {ident} rejected locally (hidden from `curate list`; its reports TTL-expire from SWM).")
    if args.dispute:
        client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
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
    cfg = load_blackbox_config()
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)

    catalog_paths = _resolve_import_paths(args)
    if catalog_paths is None:
        return 2  # error already printed
    if not catalog_paths:
        print("No catalog JSON files found to import.")
        return 0

    # Full per-threat knowledge assets are the public graph contract. Operators
    # can opt out explicitly for a review-only SWM import with --no-publish.
    publish = not bool(getattr(args, "no_publish", False))
    dry_run = getattr(args, "dry_run", False)

    # Before spending any TRAC, verify the node is actually on a supported
    # mainnet (a dry-run or --no-publish/SWM-only run needs no chain check).
    if publish and not dry_run and not _require_mainnet_for_publish(client):
        return 1

    # Dedup — each mainnet VM publish costs TRAC, so never publish an identifier
    # twice. Skip anything in the curator's full-asset ledger, plus — with
    # --check-graph — anything already on-chain with the complete shape. The
    # set also grows in-run, so a repeat within a batch publishes at most once.
    already = _load_seeded_ledger()
    if getattr(args, "check_graph", False):
        already |= _existing_graph_identifiers(client, cfg)

    # --limit caps NEW publishes across the whole run (batch seeding). Thread the
    # remaining budget through each file so a --dir run stops at the batch size.
    limit = getattr(args, "limit", None)
    remaining = limit
    seeded = dup_skipped = errors = bad_files = 0
    published_ids: List[str] = []
    for path in catalog_paths:
        if remaining is not None and remaining <= 0:
            break
        try:
            catalog = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            if args.file:  # explicit single file: a bad file is a hard error
                print(f"error: invalid JSON: {exc}")
                return 2
            bad_files += 1  # in --dir mode, silently skip non-JSON/bad files
            continue
        entries = _flatten_catalog(catalog, forced_type=args.type)
        if not entries:
            bad_files += 1  # not a recognizable catalog
            continue
        if args.osv_enrich:
            entries = _osv_enrich(entries)
        s, sk, e, ids, attempted = _seed_entries(
            client, cfg, entries, publish=publish, already=already,
            dry_run=dry_run, epochs=max(1, int(getattr(args, "epochs", 1) or 1)),
            publish_timeout=max(1, int(getattr(args, "publish_timeout", 600) or 600)),
            publish_poll_interval=max(1, int(getattr(args, "publish_poll_interval", 5) or 5)),
            limit=remaining,
            contributor=getattr(args, "contributor", None),
            source=getattr(args, "source", None),
        )
        seeded += s
        dup_skipped += sk
        errors += e
        published_ids += ids
        if remaining is not None:
            remaining -= attempted
        if args.dir:
            print(f"  {path.name}: {s} new, {sk} dup, {e} err")

    # The ledger is appended per-publish inside _seed_entries (interrupt-safe),
    # so no end-of-run write is needed. published_ids is kept for the summary.

    capped = limit is not None and seeded >= limit
    if dry_run:
        action = "publish as full VM assets" if publish else "share to SWM only"
        print(f"Dry run: {seeded} NEW threats would {action}, {dup_skipped} skipped as duplicates, {errors} errors.")
        if publish:
            print("  Nothing published — no TRAC spent. Dedup keeps the bill to genuinely-new threats only.")
        else:
            print("  Nothing shared; --no-publish keeps this workflow off-chain.")
        if capped:
            print(f"  (Showing the next {limit} — the batch --limit. Drop --dry-run to publish exactly these.)")
    else:
        tier = "SWM + the public graph as full per-threat assets" if publish else "the local graph (SWM)"
        tail = f", {bad_files} unreadable files" if bad_files else ""
        print(f"Import complete: {seeded} new threats → {tier}, {dup_skipped} skipped as duplicates, {errors} errors{tail}.")
        if capped:
            print(f"  Batch --limit ({limit}) reached. Verify this batch, then re-run the SAME command to publish the next {limit} — the ledger resumes automatically.")
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


def _rejected_path() -> Path:
    """Curator-local record of identifiers rejected via ``curate reject``."""
    return constants.blackbox_home() / "rejected.json"


def _load_rejected() -> set:
    """Identifiers a curator has locally rejected (hidden from ``curate list``)."""
    try:
        data = json.loads(_rejected_path().read_text(encoding="utf-8"))
        return {str(x) for x in data} if isinstance(data, list) else set()
    except Exception:
        return set()


def _seeded_ledger_path() -> Path:
    """Curator-local record of identifiers published as complete VM assets.

    This deliberately uses a new ledger name. The legacy ``seeded_identifiers``
    file may describe reduced ``threat-vm-*`` assets, so trusting it would skip
    the full-asset migration the public graph now requires.
    """
    return constants.blackbox_home() / "published_full_threat_identifiers.txt"


def _curated_ledger_path() -> Path:
    """Curator-local record of every identifier this curator approved or seeded.

    The compatibility migration publishes EXACTLY this set as full VM assets.
    It never trusts a normal store scan by default: SWM is open-write, so store
    rows (including any ``curated`` flag) are attacker-writable; this ledger is
    curator-local.
    """
    return constants.blackbox_home() / "curated_identifiers.txt"


def _load_curated_ledger() -> set:
    try:
        return {
            ln.strip()
            for ln in _curated_ledger_path().read_text(encoding="utf-8").splitlines()
            if ln.strip()
        }
    except Exception:
        return set()


def _append_curated_ledger(identifiers: List[str]) -> None:
    if not identifiers:
        return
    path = _curated_ledger_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(identifiers) + "\n")
    except Exception:  # pragma: no cover - defensive
        pass


def _load_seeded_ledger() -> set:
    try:
        return {
            ln.strip()
            for ln in _seeded_ledger_path().read_text(encoding="utf-8").splitlines()
            if ln.strip()
        }
    except Exception:
        return set()


def _append_seeded_ledger(identifiers: List[str]) -> None:
    if not identifiers:
        return
    path = _seeded_ledger_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(identifiers) + "\n")
    except Exception:  # pragma: no cover - defensive
        pass


def _existing_graph_identifiers(client: DkgClient, cfg: BlackboxConfig) -> set:
    """Identifiers already on-chain as *complete* threat knowledge assets.

    Legacy proof KAs carry no ``g:identifier`` and legacy reduced KAs omit
    ``schema:name``/``schema:description``. Requiring both descriptive fields
    prevents either format from suppressing the required full-asset publish.
    """
    try:
        rows = client.query(
            "PREFIX g: <http://umanitek.ai/ontology/guardian/> "
            "PREFIX schema: <http://schema.org/> "
            "SELECT DISTINCT ?identifier WHERE { "
            "?t g:identifier ?identifier ; schema:name ?name ; schema:description ?description . }",
            cfg.context_graph_id,
            view=constants.VIEW_VERIFIABLE_MEMORY,
        )
        return {extract_binding(r.get("identifier")) for r in rows if extract_binding(r.get("identifier"))}
    except Exception:
        return set()


def _seed_entries(
    client: DkgClient,
    cfg: BlackboxConfig,
    entries: List[Dict[str, Any]],
    *,
    publish: bool,
    already: set,
    dry_run: bool = False,
    epochs: int = 1,
    publish_timeout: int = 600,
    publish_poll_interval: int = 5,
    limit: Optional[int] = None,
    contributor: Optional[str] = None,
    source: Optional[str] = None,
) -> tuple:
    """Seed flattened *entries* as curated threats, skipping duplicates.

    *already* is the running set of identifiers NOT to publish (the seeded
    ledger + optionally the on-chain set + anything seen earlier this run). It's
    mutated in place so a repeated identifier within the same run is published at
    most once — every skip saves a TRAC publish. *limit*, when set, stops after
    that many NEW threats so a catalog can be seeded in verifiable batches;
    untouched entries are left for a later run (the ledger resumes them). Returns
    ``(seeded, skipped, errors, new_ids, attempted)`` where ``attempted`` counts
    validated new identifiers that reached the dry-run/publish boundary.
    """
    seeded, skipped, errors, attempted = 0, 0, 0, 0
    new_ids: List[str] = []
    for entry in entries:
        if limit is not None and attempted >= limit:
            break
        try:
            category, ident, fields = _entry_to_threat(entry)
        except ValueError:
            errors += 1
            continue
        # Provenance is part of the public trust contract. A bulk seed without a
        # named source would create a DKG asset the dashboard cannot explain, so
        # fail it during dry-run before any TRAC can be spent.
        prov = _entry_provenance(entry)
        sources = prov["sources"] or ([source] if source else None)
        contributor_value = prov["contributor"] or contributor
        references = prov["references"]
        if not sources:
            errors += 1
            continue
        if ident in already:
            skipped += 1
            continue
        already.add(ident)  # never publish the same identifier twice in one run
        try:
            quad_kwargs = dict(
                category=category,
                identifier=ident,
                severity=fields.get("severity", "high"),
                name=fields.get("name", ident),
                description=fields.get("description", ""),
                curated=True,
                kind=fields.get("kind"),
                sources=sources,
                references=references,
                contributor=contributor_value,
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
                ioc_type=fields.get("ioc_type"),
                minimal=False,
            )
            q = quads.build_threat_quads(**quad_kwargs)
            quads.assert_quads_literal_size(q, label=f"threat:{ident}")
        except ValueError:
            errors += 1
            continue
        attempted += 1
        if dry_run:
            seeded += 1
            if publish:  # the ledger tracks on-chain publishes only
                new_ids.append(ident)
            continue
        ka_name = f"candidate-{quads.slug(ident)}"
        try:
            client.share_knowledge_asset(cfg.context_graph_id, ka_name, q)
            if publish:
                # Publish the exact same sealed, full threat KA that was shared
                # to SWM. A second reduced/proof-only asset can drift or omit
                # context and is not a valid public threat record.
                client.publish_async_and_wait(
                    cfg.context_graph_id,
                    ka_name,
                    epochs=epochs,
                    timeout_s=publish_timeout,
                    poll_s=publish_poll_interval,
                )
            seeded += 1
            # Every seeded threat is curator-blessed. The migration command uses
            # this ledger to find old SWM-only assets without trusting arbitrary
            # community rows.
            _append_curated_ledger([ident])
            if publish:  # only on-chain publishes belong in the seeded ledger;
                new_ids.append(ident)  # a --no-publish (SWM-only) run must not poison it
                # Persist per-publish, not just at run end: a long VM grind that's
                # interrupted (Ctrl-C, wallet drained, killed) must still resume
                # without re-paying for what already published on-chain.
                _append_seeded_ledger([ident])
        except DkgError as exc:
            print(f"warning: failed to seed {ident}: {exc}")
            errors += 1
    return seeded, skipped, errors, new_ids, attempted


def _cmd_dashboard(args: argparse.Namespace) -> int:
    cfg = load_blackbox_config()
    port = args.port or cfg.dashboard_port
    try:
        from .dashboard.server import start_dashboard
    except Exception as exc:
        print(f"error: dashboard requires the [web] extra (fastapi/uvicorn): {exc}")
        return 1
    _replace_existing_dashboard(port)
    try:
        report = attach.attach_all(hermes=True, openclaw=True, dry_run=False)
        newly = [r for r in report.get("hermes", []) + report.get("openclaw", []) if not r.get("already") and not r.get("error")]
        if newly:
            for row in report.get("hermes", []):
                if not row.get("already") and not row.get("error"):
                    _print_hermes_attach_row(row, "Auto-attached")
            for row in report.get("openclaw", []):
                if not row.get("already") and not row.get("error"):
                    _print_openclaw_attach_row(row, "Auto-attached")
            print("  Restart any running agent to activate.")
    except Exception as exc:
        logger.debug("dashboard auto-attach skipped: %s", exc)
    print(f"Starting Blackbox dashboard on http://127.0.0.1:{port} (Ctrl-C to stop)")
    start_dashboard(port)
    return 0


def _replace_existing_dashboard(port: int) -> None:
    """Kill any dashboard already bound to ``port`` so re-running ``hermes
    blackbox dashboard`` seamlessly restarts it instead of colliding.

    Loopback-only, best-effort: probe the port, resolve owning PIDs via
    ``lsof``, and send SIGTERM (then SIGKILL after a short wait). Skips the
    current process — we never signal ourselves. Fail-open: any error just
    proceeds to the bind, which will surface the normal port-in-use error.
    """
    import shutil
    import signal
    import socket

    # Quick reachability probe — if nothing's listening, skip everything.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    try:
        if sock.connect_ex(("127.0.0.1", int(port))) != 0:
            return
    finally:
        sock.close()

    lsof = shutil.which("lsof")
    if not lsof:
        print(f"warning: port {port} in use but 'lsof' unavailable — cannot auto-restart.")
        return

    try:
        import subprocess
        out = subprocess.run(
            [lsof, "-tiTCP:" + str(int(port)), "-sTCP:LISTEN"],
            capture_output=True, text=True, timeout=3,
        ).stdout
    except Exception as exc:
        logger.debug("dashboard auto-restart: lsof failed: %s", exc)
        return

    my_pid = os.getpid()
    pids = {int(p) for p in out.split() if p.isdigit() and int(p) != my_pid}
    if not pids:
        return

    print(f"restarting: found existing dashboard on port {port} (pid {', '.join(str(p) for p in sorted(pids))}) — stopping it...")
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except Exception as exc:
            logger.debug("dashboard auto-restart: SIGTERM %s failed: %s", pid, exc)

    # Wait up to 3s for graceful exit, then SIGKILL stragglers.
    import time as _time
    for _ in range(30):
        alive = []
        for pid in pids:
            try:
                os.kill(pid, 0)
                alive.append(pid)
            except (ProcessLookupError, PermissionError):
                pass
        if not alive:
            return
        _time.sleep(0.1)
    for pid in alive:
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception as exc:
            logger.debug("dashboard auto-restart: SIGKILL %s failed: %s", pid, exc)


# ---------------------------------------------------------------------------
# setup-llm: interactive picker for the optional LLM reviewer
# ---------------------------------------------------------------------------

#: Standard env var names each provider's key lives in (mirrors hermes auth).
_LLM_KEY_ENV_VARS = {
    "openai": ("OPENAI_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY", "ANTHROPIC_TOKEN"),
}

_PROVIDER_ALIASES = {
    "openai": "openai",
    "openai-api": "openai",
    "openai-responses": "openai",
    "openai-chat": "openai",
    "anthropic": "anthropic",
    "claude": "anthropic",
    "anthropic-api": "anthropic",
}

_PROVIDER_KEYS = ("provider", "model_provider", "modelProvider", "llm_provider", "llmProvider")
_MODEL_KEYS = ("model", "default", "default_model", "defaultModel", "llm_model", "llmModel")
_API_KEY_KEYS = ("api_key", "apiKey", "key", "token")
_API_KEY_ENV_KEYS = ("key_env", "keyEnv", "api_key_env", "apiKeyEnv", "env", "env_var", "envVar")


def _tty():
    """Return an interactive /dev/tty handle, or None (piped / no terminal)."""
    try:
        return open("/dev/tty", "r+")
    except Exception:
        return None


def _ask(prompt: str, tty) -> str:
    """Print *prompt* and read one trimmed line from the tty (or stdin)."""
    if tty is not None:
        tty.write(prompt)
        tty.flush()
        line = tty.readline()
        return line.strip() if line else ""
    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def _mask_key(key: str) -> str:
    """Show a key as ``sk-a…wxyz`` — enough to recognize, not enough to leak."""
    key = key or ""
    if len(key) <= 8:
        return "****"
    return f"{key[:4]}…{key[-4:]}"


def _env_key(provider: str) -> str:
    """First non-empty value among *provider*'s standard key env vars."""
    for name in _LLM_KEY_ENV_VARS.get(provider, ()):  # ordered, first wins
        val = os.environ.get(name)
        if val and val.strip():
            return val.strip()
    return ""


def _provider_alias(value: object) -> str:
    raw = str(value or "").strip().lower().replace("_", "-")
    return _PROVIDER_ALIASES.get(raw, "")


def _env_lookup(name: str, env: Optional[Dict[str, str]] = None) -> str:
    if not name:
        return ""
    if env and env.get(name):
        return str(env[name]).strip()
    return str(os.environ.get(name, "") or "").strip()


def _env_key_from(provider: str, env: Optional[Dict[str, str]] = None) -> str:
    for name in _LLM_KEY_ENV_VARS.get(provider, ()):
        val = _env_lookup(name, env)
        if val:
            return val
    return ""


def _value_from(mapping: Dict[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        val = mapping.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return ""


def _key_from_mapping(mapping: Dict[str, Any], provider: str, env: Optional[Dict[str, str]] = None) -> str:
    direct = _value_from(mapping, _API_KEY_KEYS)
    if direct:
        return direct
    for key in _API_KEY_ENV_KEYS:
        env_name = mapping.get(key)
        if env_name is not None:
            found = _env_lookup(str(env_name).strip(), env)
            if found:
                return found
    return _env_key_from(provider, env)


def _iter_dicts(value: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _iter_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_dicts(child)


def _candidate_from_mapping(
    mapping: Dict[str, Any],
    source: str,
    env: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, str]]:
    provider = _provider_alias(_value_from(mapping, _PROVIDER_KEYS))
    if not provider:
        return None
    api_key = _key_from_mapping(mapping, provider, env)
    if not api_key:
        return None
    model = _value_from(mapping, _MODEL_KEYS) or llm.default_model(provider)
    return {"source": source, "provider": provider, "model": model, "api_key": api_key}


def _parse_env_value(value: str) -> str:
    value = (value or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _load_env_file(path: Path) -> Dict[str, str]:
    env: Dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except Exception:
        return env
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:]
        key, _, value = line.partition("=")
        key = key.strip()
        if key:
            env[key] = _parse_env_value(value)
    return env


def _candidate_from_hermes_config(
    cfg: Dict[str, Any],
    env: Optional[Dict[str, str]],
    source: str,
) -> Optional[Dict[str, str]]:
    if not isinstance(cfg, dict):
        return None
    model_cfg = cfg.get("model") if isinstance(cfg.get("model"), dict) else {}
    candidates = [model_cfg, cfg]
    custom = cfg.get("custom_providers") or cfg.get("providers")
    if isinstance(custom, dict):
        candidates.extend(v for v in custom.values() if isinstance(v, dict))
    for candidate in candidates:
        resolved = _candidate_from_mapping(candidate, source, env)
        if resolved:
            return resolved
    return None


def _hermes_llm_candidate() -> Optional[Dict[str, str]]:
    try:
        from hermes_cli import config as hconfig

        cfg = hconfig.load_config()
        env = {**os.environ, **hconfig.load_env()}
    except Exception:
        cfg, env = {}, {}

    current = _candidate_from_hermes_config(cfg, env, "Hermes")
    if current:
        return current

    seen: set[Path] = set()
    for home in attach.discover_hermes_homes():
        try:
            resolved_home = home.expanduser().resolve()
        except Exception:
            continue
        if resolved_home in seen:
            continue
        seen.add(resolved_home)
        home_cfg = attach._load_yaml(resolved_home / "config.yaml")
        home_env = {**os.environ, **_load_env_file(resolved_home / ".env")}
        source = f"Hermes ({resolved_home})"
        candidate = _candidate_from_hermes_config(home_cfg, home_env, source)
        if candidate:
            return candidate
    return None


def _openclaw_llm_candidate() -> Optional[Dict[str, str]]:
    for workspace in attach.discover_openclaw_workspaces():
        path = workspace / "openclaw.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for mapping in _iter_dicts(data):
            resolved = _candidate_from_mapping(mapping, f"OpenClaw ({workspace})")
            if resolved:
                return resolved
    return None


def _auto_llm_candidate() -> tuple[str, Optional[Dict[str, str]]]:
    cfg = load_blackbox_config()
    if cfg.llm_ready:
        return "Blackbox", {
            "source": "Blackbox",
            "provider": cfg.llm_provider,
            "model": cfg.llm_model,
            "api_key": cfg.llm_api_key,
        }
    for resolver in (_hermes_llm_candidate, _openclaw_llm_candidate):
        candidate = resolver()
        if candidate:
            return candidate["source"], candidate
    return "", None


def _resolve_key(source: str, provider: str) -> str:
    """Resolve an API key for *provider* from the chosen *source*."""
    if source == "new":
        return ""
    if source == "openclaw":
        candidate = _openclaw_llm_candidate()
        if candidate and candidate["provider"] == provider:
            return candidate["api_key"]
    if source == "hermes":
        candidate = _hermes_llm_candidate()
        if candidate and candidate["provider"] == provider:
            return candidate["api_key"]
    return _env_key(provider)


def _cmd_setup_llm(args: argparse.Namespace) -> int:
    """Configure the opt-in LLM prompt-injection reviewer.

    Interactive by default (reads /dev/tty); fully scriptable via flags. Writes
    ``plugins.entries.blackbox.llm.*`` through the shared settings writer.
    """
    if args.disable:
        result = settings.write_settings({"llm": {"enabled": False}})
        print("LLM reviewer disabled." if result.get("ok") else f"error: {result.get('errors')}")
        return 0 if result.get("ok") else 1

    explicit = any(
        getattr(args, name, None)
        for name in ("provider", "model", "key_source", "api_key")
    )
    if not explicit and not getattr(args, "configure", False):
        source, candidate = _auto_llm_candidate()
        if candidate:
            if source == "Blackbox":
                print(
                    f"LLM reviewer already configured: "
                    f"provider={candidate['provider']}  model={candidate['model']}"
                )
                return 0
            result = settings.write_settings({
                "llm": {
                    "enabled": True,
                    "provider": candidate["provider"],
                    "model": candidate["model"],
                    "api_key": candidate["api_key"],
                }
            })
            if not result.get("ok"):
                print(f"error: could not save settings: {result.get('errors')}")
                return 1
            print(
                f"LLM reviewer enabled from {source}: "
                f"provider={candidate['provider']}  model={candidate['model']}"
            )
            return 0
        if args.auto:
            print("No reusable Hermes/OpenClaw LLM config found.")
            return 2

    tty = _tty()
    try:
        # --- provider -------------------------------------------------------
        provider = args.provider
        if not provider:
            if tty is None and not args.api_key:
                print("error: setup-llm needs a terminal, or pass --provider/--model/--api-key.")
                return 2
            ans = _ask("AI provider for the reviewer — [1] OpenAI (default)  [2] Anthropic: ", tty)
            provider = "anthropic" if ans in ("2", "anthropic") else "openai"

        # --- key source + resolution ---------------------------------------
        source = args.key_source
        api_key = args.api_key or ""
        if not api_key:
            if not source:
                ans = _ask(
                    "API key — [1] from Hermes env (default)  [2] from OpenClaw  [3] paste a new key: ",
                    tty,
                )
                source = {"2": "openclaw", "3": "new"}.get(ans, "hermes")
            api_key = _resolve_key(source, provider)
            if not api_key:
                env_hint = " / ".join(_LLM_KEY_ENV_VARS.get(provider, ()))
                if source != "new":
                    print(f"  No {provider} key found in the environment ({env_hint}).")
                api_key = _ask_secret("  Paste the API key: ", tty)

        if not api_key:
            print("error: no API key provided — nothing saved.")
            return 2

        # --- model ----------------------------------------------------------
        model = (args.model or "").strip()
        if not model:
            default_model = llm.default_model(provider)
            ans = _ask(f"Model id [{default_model}]: ", tty) if tty is not None else ""
            model = ans or default_model

        # --- persist --------------------------------------------------------
        result = settings.write_settings({
            "llm": {"enabled": True, "provider": provider, "model": model, "api_key": api_key},
        })
        if not result.get("ok"):
            print(f"error: could not save settings: {result.get('errors')}")
            return 1
        print(
            f"\nLLM reviewer enabled: provider={provider}  model={model}  key={_mask_key(api_key)}\n"
            "It gives a second opinion on prompt injection over the observer path (never blocks).\n"
            "Disable anytime with:  hermes blackbox setup-llm --disable"
        )
        return 0
    finally:
        if tty is not None:
            try:
                tty.close()
            except Exception:
                pass


def _ask_secret(prompt: str, tty) -> str:
    """Read a secret without echoing when possible; fall back to a plain read."""
    try:
        import getpass

        return getpass.getpass(prompt).strip()
    except Exception:
        return _ask(prompt, tty)


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
            "package_name": quads.canonical_package_name(args.ecosystem, args.name),
            "package_version": args.version,
            "advisory_id": args.advisory_id,
            "kind": getattr(args, "kind", None),
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


def _threat_fields_from_reports(client: DkgClient, cfg: BlackboxConfig, identifier: str):
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
       ?packageName ?packageVersion ?packageEcosystem ?advisoryId ?kind
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
  OPTIONAL {{ ?report g:kind ?kind . }}
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
            ("packageEcosystem", "ecosystem"), ("advisoryId", "advisory_id"), ("kind", "kind"),
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
    # Bumblebee data is Socket-derived (Shai-Hulud, GlassWorm, credential
    # stealers, …), so stamp "Socket" as the named source unless the file says
    # otherwise. A catalog-level contributor, if present, attributes every entry.
    default_source = str(catalog.get("source") or "Socket").strip()
    contributor = str(catalog.get("contributor") or "").strip()
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
                    # Bumblebee catalogs are Socket-confirmed *compromised*
                    # packages (Shai-Hulud, GlassWorm, credential stealers,
                    # typosquats) — malware, not mere vulnerabilities, so they
                    # block in block mode.
                    "kind": "malware",
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
                    "source": default_source,
                    "contributor": contributor,
                }
            )
    return out


def _catalog_provenance_defaults(catalog: Any) -> Dict[str, Any]:
    """Top-level ``source``/``contributor`` defaults, applied to entries that
    don't set their own (e.g. one root ``source`` for a whole OSV dump)."""
    if not isinstance(catalog, dict):
        return {}
    defaults: Dict[str, Any] = {}
    src = catalog.get("sources") or catalog.get("source")
    if src:
        defaults["source"] = src
    if catalog.get("contributor"):
        defaults["contributor"] = catalog.get("contributor")
    return defaults


def _apply_provenance_defaults(entry: Dict[str, Any], defaults: Dict[str, Any]) -> None:
    """Fill an entry's missing source/contributor from catalog-level *defaults*."""
    if defaults.get("source") and not (entry.get("source") or entry.get("sources")):
        entry["source"] = defaults["source"]
    if defaults.get("contributor") and not entry.get("contributor"):
        entry["contributor"] = defaults["contributor"]


def _entry_provenance(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Extract ``{sources, references, contributor}`` from a catalog entry.

    ``source``/``sources`` are named feeds; ``references`` are URLs; a source
    given as a URL is also surfaced as a reference.
    """
    raw_sources = entry.get("sources")
    if raw_sources is None:
        raw_sources = entry.get("source")
    if isinstance(raw_sources, str):
        raw_sources = [raw_sources]
    sources = [str(s).strip() for s in (raw_sources or []) if str(s).strip()]

    raw_refs = entry.get("references")
    if isinstance(raw_refs, str):
        raw_refs = [raw_refs]
    references = [str(r).strip() for r in (raw_refs or []) if str(r).strip()]
    for s in sources:
        if s.startswith(("http://", "https://")) and s not in references:
            references.append(s)

    contributor = str(entry.get("contributor") or "").strip() or None
    return {"sources": sources, "references": references, "contributor": contributor}


def _flatten_catalog(catalog: Any, forced_type: Optional[str]) -> List[Dict[str, Any]]:
    """Flatten a threat catalog into per-threat entries.

    Accepts the bumblebee ``{entries:[{package, versions:[...]}]}`` format (fanned
    out one dependency threat per package+version), the generic ``{threats:[...]}``
    format, and the ``{dependencies/injection/escalation:[...]}`` split format.
    A catalog-level ``source``/``contributor`` is stamped onto every entry that
    doesn't set its own.
    """
    if _is_bumblebee_catalog(catalog):
        return _flatten_bumblebee(catalog)
    out: List[Dict[str, Any]] = []
    if isinstance(catalog, list):
        for item in catalog:
            if isinstance(item, dict):
                out.append({**item, **({"type": forced_type} if forced_type else {})})
    elif isinstance(catalog, dict):
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
        # Split-format IOC entries already carry ``ioc_type``/``value``.
        for item in catalog.get("iocs", []) or []:
            if isinstance(item, dict):
                out.append({"type": "ioc", **item})
        # Backlog catalogs group indicators under ``backlog.{iocs,crypto,...}``;
        # each entry's own ``type`` (domain/url/wallet/...) is the IOC type.
        out.extend(_flatten_backlog(catalog.get("backlog")))
    defaults = _catalog_provenance_defaults(catalog)
    if defaults:
        for entry in out:
            _apply_provenance_defaults(entry, defaults)
    return out


def _flatten_backlog(backlog: Any) -> List[Dict[str, Any]]:
    """Flatten a catalog ``backlog`` object into importable ``ioc`` entries.

    ``backlog`` maps group names (``iocs``, ``crypto``, ``socket``, …) to lists
    of indicator dicts whose own ``type`` (``domain``/``url``/``ip``/``hash``/
    ``wallet``/``contract``) is the IOC type. Unknown indicator types are left
    for ``_entry_to_threat`` to reject during dry-run.
    """
    if not isinstance(backlog, dict):
        return []
    out: List[Dict[str, Any]] = []
    for group in backlog.values():
        if not isinstance(group, list):
            continue
        for item in group:
            if not isinstance(item, dict):
                continue
            rest = {k: v for k, v in item.items() if k != "type"}
            out.append({"type": "ioc", "ioc_type": str(item.get("type") or "").lower(), **rest})
    return out


def _entry_to_threat(entry: Dict[str, Any]) -> tuple:
    """Return ``(category, identifier, fields)`` for a catalog entry."""
    ctype = str(entry.get("type") or "").lower()
    if ctype == "ioc":
        ioc_type = str(entry.get("ioc_type") or entry.get("iocType") or "").strip().lower()
        value = str(entry.get("value") or entry.get("indicator") or "").strip()
        # Map feed-native indicator spellings onto the supported IOC types: an
        # ``ipv4``/``ipv6`` is an ``ip``; a hash algo (``sha256``/``sha1``/``md5``)
        # is a ``hash`` whose value carries the ``algo:`` prefix the detector emits.
        if ioc_type in ("ipv4", "ipv6"):
            ioc_type = "ip"
        elif ioc_type in ("sha256", "sha1", "sha512", "md5"):
            if not value.lower().startswith(("sha256:", "sha1:", "sha512:", "md5:")):
                value = f"{ioc_type}:{value}"
            ioc_type = "hash"
        if ioc_type not in quads.IOC_TYPES or not value:
            raise ValueError("ioc needs a supported ioc_type + value")
        ident = quads.ioc_identifier(ioc_type, value)
        threat = entry.get("threat") or entry.get("title") or entry.get("name")
        return "ioc", ident, {
            "severity": constants.normalize_severity(entry.get("severity"), "high"),
            "name": threat or f"{ioc_type}: {value[:80]}",
            "description": entry.get("summary") or entry.get("description") or "",
            "ioc_type": ioc_type,
            "references": entry.get("references") or [],
        }
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
        # Normalize a malformed leading ``@@`` scope (seen in bumblebee data:
        # ``@@antv/a8``) down to a single ``@`` so the seeded identifier matches
        # what an agent actually installs (``@antv/a8``) — otherwise the threat
        # can never fire and the TRAC publish is wasted.
        if name.startswith("@"):
            name = "@" + name.lstrip("@")
        ident = quads.dependency_identifier(eco, name, ver)
        raw_kind = str(entry.get("kind") or "").strip().lower()
        kind = raw_kind if raw_kind in (constants.KIND_MALWARE, constants.KIND_VULNERABILITY) else None
        return "dependency", ident, {
            # Malware floors to critical so it blocks under the default policy,
            # even when the source catalog omits an explicit severity.
            "severity": constants.severity_for_kind(kind, entry.get("severity")),
            "name": entry.get("title") or entry.get("name") or f"{name}@{ver}",
            "description": entry.get("summary") or entry.get("description") or "",
            "ecosystem": eco.lower(),
            "package_name": name,
            "package_version": ver,
            "advisory_id": entry.get("advisoryId") or entry.get("advisory_id"),
            "references": entry.get("references") or [],
            "kind": kind,
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
        logger.debug("blackbox: OSV enrichment failed: %s", exc)
        return entries
    for dep, res in zip(deps, results):
        vulns = res.get("vulns", []) if isinstance(res, dict) else []
        if vulns and isinstance(vulns[0], dict):
            dep.setdefault("advisoryId", vulns[0].get("id"))
            dep.setdefault("summary", vulns[0].get("summary") or vulns[0].get("id"))
    return entries
