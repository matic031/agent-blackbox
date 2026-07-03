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

from . import constants

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
_OPENAI_RE = re.compile(r"sk-[A-Za-z0-9]{16,}")
_GITHUB_RE = re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}")
_AWS_RE = re.compile(r"AKIA[0-9A-Z]{16}")


def sanitize_text(value: str, max_len: int = _MAX_TEXT) -> str:
    """Redact common secret shapes from *value* and truncate to *max_len*."""
    text = _BEARER_RE.sub("Bearer [REDACTED]", str(value))
    text = _OPENAI_RE.sub("[REDACTED_API_KEY]", text)
    text = _GITHUB_RE.sub("[REDACTED_GITHUB_TOKEN]", text)
    text = _AWS_RE.sub("[REDACTED_AWS_KEY]", text)
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


def read_findings(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """Return findings newest-first, paged. Empty on any error."""
    path = _home() / "findings.jsonl"
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
            rec = json.loads(line)
        except Exception:
            continue
        # Flatten to a dashboard-friendly row: the finding fields live under
        # ``finding`` (singular) per stored line; lift them up and stamp the
        # event time/tool so the UI can render each row directly.
        finding = rec.get("finding") or (rec.get("findings") or [{}])[0] or {}
        out.append({
            "time": rec.get("iso") or rec.get("ts"),
            "event": rec.get("event"),
            "identifier": finding.get("identifier"),
            "category": finding.get("category"),
            "severity": finding.get("severity"),
            "title": finding.get("title"),
            "tool_name": finding.get("tool_name") or (rec.get("detail") or {}).get("tool_name"),
            "evidence": finding.get("evidence") or finding.get("title"),
        })
    return out[offset : offset + limit]


def count_findings() -> int:
    path = _home() / "findings.jsonl"
    if not path.exists():
        return 0
    try:
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    except Exception:
        return 0


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
        "tool_name": finding.get("tool_name"),
        "evidence": sanitize_text(str(finding.get("evidence") or ""), 700),
        "confirmed": bool(finding.get("confirmed", True)),
        "candidate": bool(finding.get("candidate", not finding.get("confirmed", True))),
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


def allow_report(daily_limit: int) -> bool:
    """Return True if another outbound SWM report is within today's cap.

    Increments a small date-keyed counter in ``report_rate.json``. Fail-open:
    if the state file cannot be read/written, allow the report.
    """
    if daily_limit <= 0:
        return True
    today = time.strftime("%Y-%m-%d", time.gmtime())
    path = _rate_state_path()
    try:
        with _lock:
            state = {}
            if path.exists():
                try:
                    state = json.loads(path.read_text(encoding="utf-8"))
                except Exception:
                    state = {}
            if state.get("date") != today:
                state = {"date": today, "count": 0}
            if int(state.get("count", 0)) >= daily_limit:
                logger.debug("guardian: daily report limit %s reached", daily_limit)
                return False
            state["count"] = int(state.get("count", 0)) + 1
            path.write_text(json.dumps(state), encoding="utf-8")
            return True
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("guardian: rate-limit state failed (%s); allowing", exc)
        return True
