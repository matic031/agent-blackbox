"""Multi-agent dashboard plumbing: the one blackbox home carries findings from
every local agent so the single dashboard surfaces them all.

The Python (Hermes) plugin writes ``findings.jsonl``; other local agents (e.g.
OpenClaw) write ``findings.<framework>.jsonl`` into the SAME shared home. The
dashboard readers merge them newest-first and tag each row's framework.
"""

import json
import time

from _blackbox_loader import load_blackbox

audit = load_blackbox("audit")
constants = load_blackbox("constants")


def _write_line(path, *, framework, identifier, severity, ts, category="injection"):
    finding = {
        "identifier": identifier,
        "category": category,
        "severity": severity,
        "title": "t",
        "tool_name": "",
        "evidence": "e",
        "confirmed": False,
        "source": "heuristic",
    }
    if framework:
        finding["framework"] = framework
    rec = {
        "ts": ts,
        "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
        "event": "pre_tool_call",
        "finding": finding,
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def test_read_findings_merges_hermes_and_openclaw_logs():
    home = constants.blackbox_home()
    home.mkdir(parents=True, exist_ok=True)
    # Hermes log: no framework field on the line → defaults to "hermes".
    _write_line(home / "findings.jsonl", framework=None, identifier="injection:h1", severity="high", ts=1000)
    _write_line(home / "findings.jsonl", framework=None, identifier="injection:h2", severity="critical", ts=1002)
    # OpenClaw log: framework-tagged sibling file.
    _write_line(home / "findings.openclaw.jsonl", framework="openclaw", identifier="escalation:o1",
                severity="critical", ts=1001, category="escalation")

    rows = audit.read_findings(limit=10)
    assert audit.count_findings() == 3
    # Newest-first across BOTH logs by ts.
    assert [r["ts"] for r in rows] == [1002, 1001, 1000]
    frameworks = [r["framework"] for r in rows]
    assert frameworks == ["hermes", "openclaw", "hermes"]
    # The OpenClaw row is tagged and carries its category/severity.
    oc = next(r for r in rows if r["framework"] == "openclaw")
    assert oc["category"] == "escalation" and oc["severity"] == "critical"


def test_local_frameworks_lists_every_agent_with_a_log():
    home = constants.blackbox_home()
    home.mkdir(parents=True, exist_ok=True)
    _write_line(home / "findings.jsonl", framework=None, identifier="injection:h", severity="high", ts=1)
    _write_line(home / "findings.openclaw.jsonl", framework="openclaw", identifier="injection:o", severity="high", ts=2)
    fws = audit.local_frameworks()
    assert "hermes" in fws and "openclaw" in fws


def test_read_findings_empty_home_is_empty():
    # A fresh home with no logs yields no findings (fail-open, no crash).
    assert audit.read_findings(limit=10) == []
    assert audit.count_findings() == 0
    assert audit.local_frameworks() == []


def test_openclaw_only_home_still_surfaces_findings():
    # Even with no Hermes log at all, an OpenClaw-only log is read + tagged.
    home = constants.blackbox_home()
    home.mkdir(parents=True, exist_ok=True)
    _write_line(home / "findings.openclaw.jsonl", framework="openclaw", identifier="skill:x", severity="critical",
                ts=5, category="skill")
    rows = audit.read_findings(limit=10)
    assert len(rows) == 1 and rows[0]["framework"] == "openclaw" and rows[0]["category"] == "skill"
    assert audit.local_frameworks() == ["openclaw"]
