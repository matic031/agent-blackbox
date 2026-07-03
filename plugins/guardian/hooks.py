"""Guardian hook handlers.

Five hooks, all fail-open (a broad ``try/except`` around every handler — a
Guardian bug must never break the agent loop):

* ``pre_tool_call`` — detect, audit, report, and (block mode only) block.
* ``post_tool_call`` — audit the redacted result.
* ``pre_api_request`` — scan the prompt/messages for injection (observer only).
* ``on_session_start`` / ``on_session_end`` — lifecycle audit; session start also
  re-runs the attach sweep in the background (throttled) so agents installed
  after Guardian get protected without a manual ``hermes guardian attach``.

Blocking uses the same contract as ``security-guidance``:
``return {"action": "block", "message": ...}`` in block mode, ``None`` otherwise.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from . import audit, config as config_mod, constants, detection, quads, ruleset
from .config import GuardianConfig
from .dkg_client import DkgClient, DkgError

logger = logging.getLogger(__name__)


def _config() -> GuardianConfig:
    return config_mod.load_guardian_config()


def guardian_block_message(findings: List[detection.Finding]) -> str:
    """Human-readable block message summarizing the blocking findings."""
    lines = [
        "Umanitek Guardian blocked this tool call — it matched "
        f"{len(findings)} known threat{'s' if len(findings) != 1 else ''} in the threat graph:",
        "",
    ]
    for f in findings:
        lines.append(f"- [{f.severity.upper()}] {f.category}: {f.title} ({f.identifier})")
    lines.append("")
    lines.append(
        "Treat the source content as untrusted. If this is a false positive, "
        "flag it with `hermes guardian curate reject <identifier>` or switch "
        "Guardian to audit mode (GUARDIAN_MODE=audit)."
    )
    return "\n".join(lines)


def _flag_worthy(cfg: GuardianConfig, findings: List[detection.Finding]) -> List[detection.Finding]:
    """Apply the user's detection policy to raw findings.

    Two layers:
    * Per-category policy (``detection.<category>.{enabled,min_severity}``) —
      a disabled category never flags; a category floor drops anything below
      it (e.g. "only critical dependency vulns").
    * Heuristic gate — built-in discovery candidates additionally need
      ``report_min_severity``; they are nominations, not confirmed threats.

    User-configured custom rules (``source == "custom"``) bypass the category
    policy: the user explicitly asked for them.
    """
    out: List[detection.Finding] = []
    for f in findings:
        if f.source == "custom":
            out.append(f)
            continue
        if not cfg.category_allows(f.category, f.severity):
            continue
        if f.source == "heuristic" and not cfg.meets_report_threshold(f.severity):
            continue
        out.append(f)
    return out


def _report_and_audit(cfg: GuardianConfig, event: str, findings: List[detection.Finding], detail: Dict[str, Any]) -> None:
    """Audit always; on findings write private audit KA + outbound SWM sighting."""
    finding_dicts = [f.to_dict() for f in findings]
    audit.record(event=event, findings=finding_dicts or None, detail=detail)
    if not findings:
        return
    client: Optional[DkgClient] = None
    try:
        client = DkgClient(url=cfg.dkg_url)
    except Exception:
        client = None
    for finding in finding_dicts:
        # Custom rules, LLM opinions, and secret-value findings are personal:
        # audited in the local JSONL logs above but never leaving this machine —
        # no private WM KA, no community sighting. Secret findings especially
        # must stay local (the value must never risk reaching the shared graph).
        if finding.get("source") in ("custom", "llm", "secret"):
            continue
        identifier = str(finding.get("identifier") or "")
        # Per-threat cooldown: a re-fire of the same identifier within the
        # window adds no signal — skip both the private KA and the sighting.
        if audit.recently_reported(identifier):
            continue
        # Private WM audit KA (observed evidence stays local). Stamp the cooldown
        # here so it bounds the KA independently of whether a sighting is sent.
        if client is not None:
            audit.mark_reported(identifier)
            audit.write_private_audit_ka(client, cfg.context_graph_id, event, finding)
        # Outbound SWM sighting (never carries observed prompt/command text).
        if cfg.report and client is not None and audit.allow_report(cfg.daily_report_limit):
            _share_sighting(client, cfg, finding)


def _share_sighting(client: DkgClient, cfg: GuardianConfig, finding: Dict[str, Any]) -> None:
    try:
        reporter = _reporter_address(client)
        # For candidate (heuristic-only) findings, forward the privacy-safe
        # threat fields so the curator can promote the candidate directly.
        # ``fields`` only ever holds signatures (pattern/category/shape/...),
        # never raw prompts, paths, or file/skill source.
        fields = finding.get("fields") if isinstance(finding.get("fields"), dict) else {}
        q = quads.build_report_quads(
            identifier=str(finding.get("identifier") or ""),
            category=str(finding.get("category") or ""),
            severity=str(finding.get("severity") or "info"),
            reporter_address=reporter,
            framework="hermes",
            **{k: v for k, v in fields.items() if v is not None},
        )
        name = f"report-{quads.stable_hash(str(finding.get('identifier')) + reporter, 16)}"
        client.share_knowledge_asset(cfg.context_graph_id, name, q)
    except DkgError as exc:
        logger.debug("guardian: sighting share failed: %s", exc)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("guardian: sighting share error: %s", exc)


_reporter_cache: Dict[str, str] = {}


def _reporter_address(client: DkgClient) -> str:
    """Resolve this node's agent address (cached). Falls back to ``node``.

    ``GET /api/agent/identity`` is the definitive resolution of our token to an
    agent address; ``/api/status`` is a best-effort fallback for older daemons.
    """
    if "addr" in _reporter_cache:
        return _reporter_cache["addr"]
    addr = "node"
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
                addr = val
                break
        if addr != "node":
            break
    _reporter_cache["addr"] = addr
    return addr


# ---------------------------------------------------------------------------
# Hook handlers
# ---------------------------------------------------------------------------


def on_pre_tool_call(
    tool_name: str = "",
    args: Any = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **_: Any,
) -> Optional[Dict[str, str]]:
    """Detect threats; audit + report; block in block mode for ≥ block_severity.

    Only CONFIRMED graph findings can block; discovery candidates only alert.
    """
    try:
        cfg = _config()
        rs = ruleset.get(cfg)
        # Visibility: log every file-access tool call (best-effort).
        _record_activity(tool_name, args)
        raw = detection.detect_all(tool_name, args, rs, discover=cfg.discover)
        raw += detection.detect_custom_fileaccess(tool_name, args, cfg.protected_paths)
        findings = _flag_worthy(cfg, raw)
        detail = {
            "tool_name": tool_name,
            "session_id": session_id,
            "task_id": task_id,
            "tool_call_id": tool_call_id,
            "args": audit.redact(args),
        }
        _report_and_audit(cfg, "pre_tool_call", findings, detail)
        # Dependency OSV auto-discovery runs OFF the blocking path (best-effort,
        # fail-open) so a network lookup never delays or breaks the tool call.
        if cfg.discover and cfg.osv_lookup:
            _spawn_osv_discovery(cfg, rs, tool_name, args)
        if cfg.block_enabled:
            # Public-graph findings and the user's own custom rules block;
            # community/heuristic findings only alert. A ``vulnerability``-kind
            # threat NEVER blocks (a legit-but-vulnerable package must keep
            # working) — only active ``malware`` is stopped.
            blocking = [
                f for f in findings
                if (f.confirmed or f.source in ("custom", "secret"))
                and getattr(f, "kind", None) != constants.KIND_VULNERABILITY
                and cfg.meets_block_threshold(f.severity)
            ]
            if blocking:
                return {"action": "block", "message": guardian_block_message(blocking)}
        return None
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("guardian: pre_tool_call failed: %s", exc)
        return None


def _record_activity(tool_name: str, args: Any) -> None:
    """Log what the agent touched to the visibility trail (fail-open).

    Covers BOTH the dedicated file tools AND the shell channel, so the audit
    trail is complete: a `cat ~/.ssh/id_rsa`, a `curl` download, and every
    `npm/pip install` run through a shell tool are all recorded (as file reads,
    downloads, and structured dependency-install records) — not just left as an
    opaque command string. This is visibility, not detection: everything is
    logged regardless of whether it flags.
    """
    try:
        access = quads.file_access_arg(tool_name, args)
        if access:
            audit.record_file_access(access["tool"], access["path"], access["mode"])
            return
        if (tool_name or "").strip().lower() not in quads._SHELL_TOOLS:
            return
        command = quads._command_from_args(tool_name, args)
        if not command:
            return
        for path in quads.parse_shell_reads(command):
            audit.record_file_access("shell", path, "read")
        for url in quads.parse_downloads(command):
            audit.record_file_access("shell", url, "download")
        for dep in quads.parse_dependency_installs(command):
            audit.record_dependency(dep["ecosystem"], dep["name"], dep.get("version", ""), "shell")
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("guardian: activity visibility log failed: %s", exc)


def _spawn_osv_discovery(cfg: GuardianConfig, rs: Any, tool_name: str, args: Any) -> None:
    """Run OSV dependency auto-discovery on a daemon thread (never blocks)."""
    import threading

    from . import osv

    def _run() -> None:
        try:
            findings = _flag_worthy(
                cfg, detection.discover_dependency_candidates(tool_name, args, rs, osv.lookup)
            )
            if findings:
                _report_and_audit(cfg, "osv_discovery", findings, {"tool_name": tool_name})
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("guardian: OSV discovery failed: %s", exc)

    try:
        threading.Thread(target=_run, name="guardian-osv", daemon=True).start()
    except Exception:  # pragma: no cover - fail open
        pass


def on_post_tool_call(
    tool_name: str = "",
    args: Any = None,
    result: Any = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    duration_ms: int = 0,
    **_: Any,
) -> None:
    """Audit the redacted tool result. Never blocks."""
    try:
        audit.record(
            event="post_tool_call",
            detail={
                "tool_name": tool_name,
                "session_id": session_id,
                "task_id": task_id,
                "tool_call_id": tool_call_id,
                "duration_ms": duration_ms,
                "result": audit.redact(result),
            },
        )
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("guardian: post_tool_call failed: %s", exc)


def _collect_message_text(messages: Any) -> str:
    parts: List[str] = []
    if isinstance(messages, list):
        for msg in messages[-20:]:
            if isinstance(msg, dict):
                content = msg.get("content")
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict) and isinstance(item.get("text"), str):
                            parts.append(item["text"])
                        elif isinstance(item, str):
                            parts.append(item)
    return "\n".join(parts)


def on_pre_api_request(**kwargs: Any) -> None:
    """Scan the user message + request messages for prompt-injection patterns.

    Observer-only: blocking happens at the tool call, not here.
    """
    try:
        cfg = _config()
        rs = ruleset.get(cfg)
        text = str(kwargs.get("user_message") or "")
        text += "\n" + _collect_message_text(kwargs.get("request_messages"))
        findings = detection.detect_injection(text, rs)
        if cfg.discover:
            findings = findings + detection.discover_injection(text, rs)
        findings = _flag_worthy(cfg, findings)
        detail = {
            "session_id": kwargs.get("session_id"),
            "task_id": kwargs.get("task_id"),
            "model": kwargs.get("model"),
            "provider": kwargs.get("provider"),
        }
        _report_and_audit(cfg, "pre_api_request", findings, detail)
        # Optional LLM second opinion — runs off-thread so it never delays the
        # request, and only when the user has configured it.
        if cfg.llm_ready:
            _spawn_llm_review(cfg, text, detail)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("guardian: pre_api_request failed: %s", exc)


def _spawn_llm_review(cfg: GuardianConfig, text: str, detail: Dict[str, Any]) -> None:
    """Ask the configured LLM for an injection second opinion on a daemon thread.

    Fail-open and fully off the request path: a positive verdict becomes a local
    ``source="llm"`` injection finding (audited + shown, never blocks, never
    shared to the graph). Any error is swallowed.
    """
    import threading

    from . import llm

    def _run() -> None:
        try:
            verdict = llm.review_injection(text, cfg)
            if not verdict:
                return
            reason = verdict.get("reason") or "LLM flagged prompt injection"
            finding = detection.Finding(
                identifier=f"injection:llm:{quads.stable_hash(reason, 12)}",
                category="injection",
                severity=verdict.get("severity", "high"),
                title="Prompt injection (LLM review)",
                evidence=reason,
                matched=reason,
                confirmed=False,
                source="llm",
            )
            worthy = _flag_worthy(cfg, [finding])
            if worthy:
                _report_and_audit(cfg, "pre_api_request", worthy, {**detail, "llm": True})
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("guardian: LLM review failed: %s", exc)

    try:
        threading.Thread(target=_run, name="guardian-llm", daemon=True).start()
    except Exception:  # pragma: no cover - fail open
        pass


_AUTO_ATTACH_INTERVAL_SECS = 24 * 60 * 60


def _auto_attach_due() -> bool:
    """True at most once per interval, tracked in a state file.

    The timestamp is stamped *before* the sweep runs so concurrent session
    starts don't each fan out their own attach thread. Any error skips the
    sweep rather than risking the session.
    """
    import json
    import time

    try:
        path = constants.guardian_home() / "auto_attach.json"
        now = time.time()
        try:
            last = float(json.loads(path.read_text(encoding="utf-8")).get("last_run", 0.0))
        except Exception:
            last = 0.0
        if now - last < _AUTO_ATTACH_INTERVAL_SECS:
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"last_run": now}), encoding="utf-8")
        return True
    except Exception as exc:
        logger.debug("guardian: auto-attach throttle failed: %s", exc)
        return False


def _spawn_auto_attach(cfg: GuardianConfig) -> None:
    """Re-run the attach sweep on a daemon thread (throttled, fail-open).

    Keeps protection current after install: a Hermes home or OpenClaw
    workspace created *after* Guardian was installed gets attached the next
    time any protected agent starts a session.
    """
    import threading

    if not cfg.auto_attach or not _auto_attach_due():
        return

    def _run() -> None:
        try:
            from . import attach

            report = attach.attach_all()
            changed = [
                row.get("target")
                for group in ("hermes", "openclaw")
                for row in report.get(group, [])
                if row.get("changed")
            ]
            if changed:
                audit.record(event="auto_attach", detail={"targets": changed})
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("guardian: auto-attach failed: %s", exc)

    try:
        threading.Thread(target=_run, name="guardian-auto-attach", daemon=True).start()
    except Exception:  # pragma: no cover - fail open
        pass


def on_session_start(session_id: str = "", **kwargs: Any) -> None:
    try:
        audit.record(event="session_start", detail={"session_id": session_id})
        _spawn_auto_attach(_config())
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("guardian: on_session_start failed: %s", exc)


def on_session_end(session_id: str = "", completed: bool = True, interrupted: bool = False, **kwargs: Any) -> None:
    try:
        audit.record(
            event="session_end",
            detail={"session_id": session_id, "completed": completed, "interrupted": interrupted},
        )
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("guardian: on_session_end failed: %s", exc)
