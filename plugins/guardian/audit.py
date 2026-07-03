"""Local audit trail, secret redaction, and outbound-report rate limiting.

Everything here is best-effort and fails open — audit logging must never break
the agent loop. Two JSONL logs live under ``$GUARDIAN_HOME``:

* ``audit.jsonl`` — every observed lifecycle/tool/api event (routine).
* ``findings.jsonl`` — only events that produced a Finding (threats).

Both are size-bounded (trimmed when they exceed a cap). On a finding we also
write a **private** WM audit knowledge asset (observed command/prompt kept
here, never shared to SWM) and count the sighting against a daily limit.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import constants, quads

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Redaction (ported verbatim from the original plugin/node-ui regexes)
# ---------------------------------------------------------------------------

_MAX_TEXT = 2000

_SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|token|secret|password|passwd|credential|authorization|private[_-]?key"
    r"|client[_-]?secret|access[_-]?token|refresh[_-]?token)",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)


def sanitize_text(value: str, max_len: int = _MAX_TEXT) -> str:
    """Redact common secret shapes from *value* and truncate to *max_len*.

    Uses the single canonical secret-value patterns from :mod:`quads`
    (openai/anthropic/aws/github/slack/gcp/stripe/private-key/jwt) plus opaque
    ``Bearer`` tokens, so a secret never lands raw in the audit log.
    """
    text = _BEARER_RE.sub("Bearer [REDACTED]", str(value))
    text = quads.redact_secret_values(text)
    if len(text) > max_len:
        return text[:max_len] + "...[truncated]"
    return text


def redact(value: Any, depth: int = 0) -> Any:
    """Recursively redact secrets from an arbitrary JSON-ish structure."""
    if depth > 5:
        return "[truncated-depth]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, (list, tuple)):
        return [redact(item, depth + 1) for item in list(value)[:50]]
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for key, child in value.items():
            key_str = str(key)
            if _SECRET_KEY_RE.search(key_str):
                out[key_str] = "[REDACTED]"
            elif key_str.lower() in {"content", "body", "input", "prompt"} and isinstance(child, str):
                out[key_str] = sanitize_text(child, 1200)
            else:
                out[key_str] = redact(child, depth + 1)
        return out
    return sanitize_text(str(value))


# ---------------------------------------------------------------------------
# Bounded JSONL logs
# ---------------------------------------------------------------------------

_LOG_MAX_BYTES = 8 * 1024 * 1024  # trim each log at 8 MB
_LOG_KEEP_BYTES = 4 * 1024 * 1024  # keep the most recent ~4 MB after trimming
_lock = threading.Lock()


def _home() -> Path:
    home = constants.guardian_home()
    try:
        home.mkdir(parents=True, exist_ok=True)
    except Exception:  # pragma: no cover - defensive
        pass
    return home


def _append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    line = json.dumps(record, ensure_ascii=False)
    with _lock:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        _trim_if_needed(path)


def _trim_if_needed(path: Path) -> None:
    """Keep the tail of *path* when it grows past the cap (whole lines only)."""
    try:
        if path.stat().st_size <= _LOG_MAX_BYTES:
            return
        with path.open("rb") as fh:
            fh.seek(-_LOG_KEEP_BYTES, os.SEEK_END)
            tail = fh.read()
        # Drop a possibly-partial first line.
        nl = tail.find(b"\n")
        if nl != -1:
            tail = tail[nl + 1 :]
        path.write_bytes(tail)
    except Exception:  # pragma: no cover - defensive
        pass


def _findings_files() -> List["tuple[Path, str]"]:
    """Return ``(path, default_framework)`` for every findings log in the home.

    ``findings.jsonl`` is the Hermes (Python) plugin's own log; sibling
    ``findings.<framework>.jsonl`` files are written by other local agents
    (e.g. OpenClaw writes ``findings.openclaw.jsonl``) into the SAME shared
    guardian home so the one dashboard surfaces every agent's detections. The
    framework is taken from each finding line when present, else the filename.
    """
    home = _home()
    out: List["tuple[Path, str]"] = [(home / "findings.jsonl", "hermes")]
    try:
        for extra in sorted(home.glob("findings.*.jsonl")):
            # findings.<framework>.jsonl → framework from the middle segment.
            parts = extra.name.split(".")
            fw = parts[1] if len(parts) == 3 else "unknown"
            out.append((extra, fw))
    except Exception:  # pragma: no cover - defensive
        pass
    return out


def _flatten_finding_row(rec: Dict[str, Any], default_fw: str) -> Dict[str, Any]:
    # Flatten to a dashboard-friendly row: the finding fields live under
    # ``finding`` (singular) per stored line; lift them up and stamp the event
    # time/tool so the UI can render each row directly.
    finding = rec.get("finding") or (rec.get("findings") or [{}])[0] or {}
    return {
        "time": rec.get("iso") or rec.get("ts"),
        "ts": rec.get("ts") or 0,
        "event": rec.get("event"),
        "identifier": finding.get("identifier"),
        "category": finding.get("category"),
        "severity": finding.get("severity"),
        "title": finding.get("title"),
        "framework": finding.get("framework") or rec.get("framework") or default_fw,
        "tool_name": finding.get("tool_name") or (rec.get("detail") or {}).get("tool_name"),
        "evidence": finding.get("evidence") or finding.get("title"),
        "confirmed": bool(finding.get("confirmed", True)),
        "source": finding.get("source") or ("public" if finding.get("confirmed", True) else "heuristic"),
    }


def read_findings(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """Return findings newest-first, paged, merged across every agent's log.

    Reads ``findings.jsonl`` plus any ``findings.<framework>.jsonl`` siblings in
    the shared guardian home and merges them newest-first by timestamp. Empty on
    any error.
    """
    rows: List[Dict[str, Any]] = []
    for path, default_fw in _findings_files():
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            rows.append(_flatten_finding_row(rec, default_fw))
    # Newest-first across all logs. Fall back to insertion order when a row has
    # no numeric ts (kept stable by enumerate tiebreak).
    rows.sort(key=lambda r: r.get("ts") or 0, reverse=True)
    return rows[offset : offset + limit]


def count_findings() -> int:
    total = 0
    for path, _ in _findings_files():
        if not path.exists():
            continue
        try:
            total += sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
        except Exception:
            continue
    return total


def local_frameworks() -> List[str]:
    """Frameworks that have written findings into this shared home (for the
    dashboard's agent list). Always includes ``hermes`` when its log exists."""
    out: List[str] = []
    for path, default_fw in _findings_files():
        if path.exists() and default_fw not in out:
            out.append(default_fw)
    return out


def local_active_frameworks() -> List[str]:
    """Frameworks with observed local Guardian activity.

    Findings identify their framework explicitly through ``findings*.jsonl``.
    Routine Hermes hooks write only ``audit.jsonl``; when that exists, Hermes is
    active even if no threat has been found yet.
    """
    out = local_frameworks()
    audit_path = _home() / "audit.jsonl"
    if "hermes" not in out and audit_path.exists():
        try:
            if any(line.strip() for line in audit_path.read_text(encoding="utf-8").splitlines()):
                out.insert(0, "hermes")
        except Exception:
            pass
    return out


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------


def record(
    *,
    event: str,
    findings: Optional[List[Dict[str, Any]]] = None,
    detail: Optional[Dict[str, Any]] = None,
) -> None:
    """Append an audit record; on findings also append to findings.jsonl.

    *findings* are Finding dicts (already redacted evidence). *detail* is any
    extra context (tool name, ids, redacted args) — it is redacted again here
    defensively before being written.
    """
    try:
        now = time.time()
        base = {
            "ts": now,
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "event": event,
        }
        if detail:
            base["detail"] = redact(detail)
        if findings:
            base["findingCount"] = len(findings)
            base["findings"] = [_finding_summary(f) for f in findings]
        _append_jsonl(_home() / "audit.jsonl", base)
        for finding in findings or []:
            _append_jsonl(_home() / "findings.jsonl", {**base, "finding": _finding_summary(finding)})
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("guardian: audit record failed: %s", exc)


def _finding_summary(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "identifier": finding.get("identifier"),
        "category": finding.get("category"),
        "severity": finding.get("severity"),
        "title": finding.get("title"),
        "framework": finding.get("framework") or "hermes",
        "tool_name": finding.get("tool_name"),
        "evidence": sanitize_text(str(finding.get("evidence") or ""), 700),
        "confirmed": bool(finding.get("confirmed", True)),
        "candidate": bool(finding.get("candidate", not finding.get("confirmed", True))),
        "source": str(finding.get("source") or ("public" if finding.get("confirmed", True) else "heuristic")),
        "ts": time.time(),
    }


# ---------------------------------------------------------------------------
# File-access visibility log ($GUARDIAN_HOME/file_access.jsonl)
# ---------------------------------------------------------------------------


def record_file_access(tool: str, path: str, mode: str) -> None:
    """Append a file-access visibility record so a user can see what files
    their agent touched. Records the tool, path, mode (read/write) and time.

    This is the VISIBILITY log — distinct from findings. It is local-only and
    NEVER shared to SWM. The path is truncated but not redacted (it is the
    whole point of the log); best-effort and fail-open.
    """
    try:
        now = time.time()
        _append_jsonl(_home() / "file_access.jsonl", {
            "ts": now,
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "tool": str(tool or "")[:120],
            "path": str(path or "")[:1000],
            "mode": str(mode or "")[:16],
        })
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("guardian: file access record failed: %s", exc)


def record_dependency(ecosystem: str, name: str, version: str, tool: str = "") -> None:
    """Append a structured 'a dependency was installed' record.

    This is the enterprise lib-inventory trail: EVERY install is recorded here
    (not only threats), so an operator can see every package an agent pulled in.
    Local-only visibility log, never shared to SWM; best-effort and fail-open.
    """
    try:
        now = time.time()
        _append_jsonl(_home() / "dependencies.jsonl", {
            "ts": now,
            "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "ecosystem": str(ecosystem or "")[:40],
            "name": str(name or "")[:200],
            "version": str(version or "")[:80],
            "tool": str(tool or "")[:120],
        })
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("guardian: dependency record failed: %s", exc)


def read_file_access(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """Return file-access visibility records newest-first, paged."""
    path = _home() / "file_access.jsonl"
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    out: List[Dict[str, Any]] = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out[offset : offset + limit]


def write_private_audit_ka(client: Any, cg_id: str, event: str, finding: Dict[str, Any]) -> None:
    """Write a private WM audit KA carrying the observed command/prompt.

    This is the privacy split: the redacted-but-still-local evidence lives in
    the node's private working memory (NOT shared to SWM). Best-effort — any
    failure is swallowed.
    """
    from . import quads

    try:
        ident = str(finding.get("identifier") or "unknown")
        ts = quads.datetime_literal()
        subj = f"urn:guardian:audit:{quads.stable_hash(ident + str(time.time()), 24)}"
        q = [
            {"subject": subj, "predicate": constants.RDF_TYPE, "object": f"{constants.GUARDIAN_ONTOLOGY}AuditRecord"},
            {"subject": subj, "predicate": constants.IDENTIFIER_PRED, "object": quads.literal(ident)},
            {"subject": subj, "predicate": constants.SEVERITY_PRED, "object": quads.literal(str(finding.get("severity") or "info"))},
            {"subject": subj, "predicate": constants.SCHEMA_DESCRIPTION_PRED, "object": quads.literal(sanitize_text(str(finding.get("evidence") or ""), 1200))},
            {"subject": subj, "predicate": constants.SCHEMA_DATE_MODIFIED_PRED, "object": ts},
        ]
        # Private: create+write+seal in WM, do NOT share to SWM.
        client.write_private_knowledge_asset(cg_id, subj.rsplit(":", 1)[-1], q)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("guardian: private audit KA write failed: %s", exc)


# ---------------------------------------------------------------------------
# Outbound-report daily rate limiter
# ---------------------------------------------------------------------------


def _rate_state_path() -> Path:
    return _home() / "report_rate.json"


#: Re-reporting the same identifier within this window adds no signal (the
#: sighting KA name is stable per identifier+reporter, so a re-share only
#: refreshes dateModified) — skip it to keep findings/reports low-noise.
REPORT_COOLDOWN_SECS = 6 * 3600


def _read_rate_state() -> Dict[str, Any]:
    path = _rate_state_path()
    if not path.exists():
        return {}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        return state if isinstance(state, dict) else {}
    except Exception:
        return {}


def recently_reported(identifier: str, cooldown: int = REPORT_COOLDOWN_SECS) -> bool:
    """True when *identifier* was reported within the last *cooldown* seconds.

    Fail-open: any state error reads as "not recently reported".
    """
    if not identifier:
        return False
    try:
        stamps = _read_rate_state().get("reported") or {}
        ts = float(stamps.get(identifier, 0))
        return (time.time() - ts) < max(1, cooldown)
    except Exception:  # pragma: no cover - fail open
        return False


def mark_reported(identifier: str) -> None:
    """Stamp *identifier* as handled now (per-threat cooldown), pruning expired.

    Decoupled from :func:`allow_report` so the cooldown also covers the private
    WM audit KA — otherwise, with reporting off or the daily cap hit, the stamp
    would never be set and the private KA would rewrite on every event.
    """
    if not identifier:
        return
    try:
        with _lock:
            state = _read_rate_state()
            stamps = state.get("reported")
            stamps = dict(stamps) if isinstance(stamps, dict) else {}
            now = time.time()
            stamps[identifier] = now
            state["reported"] = {
                k: v for k, v in stamps.items()
                if isinstance(v, (int, float)) and (now - v) < REPORT_COOLDOWN_SECS
            }
            _rate_state_path().write_text(json.dumps(state), encoding="utf-8")
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("guardian: mark_reported failed (%s)", exc)


def allow_report(daily_limit: int) -> bool:
    """Return True if another outbound SWM report is within today's cap.

    Only the date-keyed daily counter — the per-threat cooldown is enforced by
    :func:`recently_reported` / :func:`mark_reported` at the call site. Fail-open:
    if the state file cannot be read/written, allow the report.
    """
    today = time.strftime("%Y-%m-%d", time.gmtime())
    path = _rate_state_path()
    try:
        with _lock:
            state = _read_rate_state()
            if state.get("date") != today:
                # New day: reset the counter but preserve the cooldown stamps.
                state = {"date": today, "count": 0, "reported": state.get("reported", {})}
            if daily_limit > 0 and int(state.get("count", 0)) >= daily_limit:
                logger.debug("guardian: daily report limit %s reached", daily_limit)
                return False
            state["count"] = int(state.get("count", 0)) + 1
            path.write_text(json.dumps(state), encoding="utf-8")
            return True
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("guardian: rate-limit state failed (%s); allowing", exc)
        return True
