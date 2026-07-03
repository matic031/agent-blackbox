"""Pure, testable matcher over a :class:`~plugins.guardian.ruleset.Ruleset`.

No hardcoded threat rules act as truth: every rule comes from the graph-synced
ruleset. Detection is three independent passes — injection (regex over text),
escalation (tool name AND arg shape), dependency (parse installs → lookup).
All matching is resilient to peer-supplied garbage: regex compile/exec errors
are caught per rule and oversized inputs are capped.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import quads

logger = logging.getLogger(__name__)

_MAX_INJECTION_TEXT = 50_000


@dataclass
class Finding:
    """One detected threat. ``evidence`` is expected to already be redacted.

    ``confirmed`` is True when the finding matched a curated GRAPH rule (a
    blockable, source-of-truth threat) and False when it was raised only by a
    built-in discovery heuristic (a *candidate* nominated to the community
    graph for a curator to promote). ``fields`` carries the privacy-safe
    candidate threat attributes (pattern/toolName/category/skillName/...) that
    the auto-submit path forwards to ``build_report_quads`` so a curator can
    promote a candidate directly — it NEVER contains raw prompts, paths, or
    file/skill source.
    """

    identifier: str
    category: str  # injection | escalation | dependency | fileaccess | skill
    severity: str
    title: str
    tool_name: str = ""
    matched: str = ""
    evidence: str = ""
    confirmed: bool = True
    fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identifier": self.identifier,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "tool_name": self.tool_name,
            "matched": self.matched,
            "evidence": self.evidence,
            "confirmed": self.confirmed,
            "candidate": not self.confirmed,
            "fields": dict(self.fields),
        }


@dataclass
class _RulesetProto:
    """Structural stand-in used only for type hints — the real Ruleset lives in
    ruleset.py but detection only reads these three attributes."""

    injection: List[Dict[str, Any]] = field(default_factory=list)
    escalation: List[Dict[str, Any]] = field(default_factory=list)
    dependency: Dict[str, Dict[str, Any]] = field(default_factory=dict)


def detect_injection(text: str, ruleset: Any) -> List[Finding]:
    """Match each cached injection regex against *text*.

    Patterns are peer-supplied and therefore untrusted: each is wrapped so a
    bad regex is skipped rather than raising. Text is capped for performance.
    """
    if not text:
        return []
    if len(text) > _MAX_INJECTION_TEXT:
        text = text[:_MAX_INJECTION_TEXT]
    out: List[Finding] = []
    seen: set = set()
    for rule in getattr(ruleset, "injection", []) or []:
        pattern = rule.get("pattern")
        identifier = rule.get("identifier", "")
        if pattern is None or identifier in seen:
            continue
        try:
            match = pattern.search(text)
        except Exception:  # pragma: no cover - untrusted regex
            continue
        if match:
            seen.add(identifier)
            out.append(
                Finding(
                    identifier=identifier,
                    category="injection",
                    severity=rule.get("severity", "high"),
                    title=rule.get("name") or "Prompt injection pattern matched",
                    matched=str(match.group(0))[:200],
                    evidence=str(match.group(0))[:200],
                    confirmed=True,
                )
            )
    return out


def detect_escalation(tool_name: str, args: Any, ruleset: Any) -> List[Finding]:
    """Match a tool call against escalation rules on BOTH toolName AND argShape.

    This is the fix for the original bug where only the tool name (or only the
    shape) was compared. We compute the observed shape once and require an
    exact (tool_name, arg_shape) match against a cached rule.
    """
    arg_shape = quads.normalize_arg_shape(tool_name or "", args)
    if not arg_shape:
        return []
    tool_lower = (tool_name or "").strip().lower()
    out: List[Finding] = []
    seen: set = set()
    for rule in getattr(ruleset, "escalation", []) or []:
        identifier = rule.get("identifier", "")
        rule_tool = str(rule.get("toolName", "")).strip().lower()
        rule_shape = str(rule.get("argShape", "")).strip()
        if identifier in seen:
            continue
        # Both must match. This is the corrected contract.
        if rule_tool == tool_lower and rule_shape == arg_shape:
            seen.add(identifier)
            out.append(
                Finding(
                    identifier=identifier,
                    category="escalation",
                    severity=rule.get("severity", "high"),
                    title=rule.get("name") or f"Dangerous {tool_lower} call ({arg_shape})",
                    tool_name=tool_name or "",
                    matched=arg_shape,
                    evidence=arg_shape,
                    confirmed=True,
                )
            )
    # Discovery layer: a dangerous shape that no graph rule covers is still a
    # candidate escalation nominated to the community graph.
    if not out:
        candidate_id = quads.escalation_identifier(tool_lower, arg_shape)
        out.append(
            Finding(
                identifier=candidate_id,
                category="escalation",
                severity="high",
                title=f"Suspicious {tool_lower} call ({arg_shape})",
                tool_name=tool_name or "",
                matched=arg_shape,
                evidence=arg_shape,
                confirmed=False,
                fields={"tool_name": tool_lower, "arg_shape": arg_shape},
            )
        )
    return out


def _command_text(args: Any) -> str:
    if isinstance(args, str):
        return args
    if isinstance(args, dict):
        for key in ("command", "cmd", "shell", "script", "input"):
            val = args.get(key)
            if isinstance(val, str) and val:
                return val
        # Fall back to any string values joined.
        return " ".join(v for v in args.values() if isinstance(v, str))
    return ""


def detect_dependency(tool_name: str, args: Any, ruleset: Any) -> List[Finding]:
    """Parse install commands, then look each package up in the ruleset.

    Only pinned installs (``name@version`` / ``name==version``) can match a
    ``dep:{eco}:{name}@{version}`` rule; unpinned installs have no version to
    key on and are skipped here (they surface as advisories elsewhere).
    """
    command = _command_text(args)
    if not command:
        return []
    dependency_rules = getattr(ruleset, "dependency", {}) or {}
    if not dependency_rules:
        return []
    out: List[Finding] = []
    seen: set = set()
    for dep in quads.parse_dependency_installs(command):
        version = dep.get("version") or ""
        if not version:
            continue
        eco = dep["ecosystem"].lower()
        name = dep["name"].lower()
        key = f"{eco}:{name}@{version}"
        rule = dependency_rules.get(key)
        if not rule or key in seen:
            continue
        seen.add(key)
        out.append(
            Finding(
                identifier=rule.get("identifier", quads.dependency_identifier(eco, name, version)),
                category="dependency",
                severity=rule.get("severity", "high"),
                title=rule.get("name") or f"Vulnerable dependency {name}@{version}",
                tool_name=tool_name or "",
                matched=key,
                evidence=f"{dep['ecosystem']}:{dep['name']}@{version}"
                + (f" ({rule.get('advisoryId')})" if rule.get("advisoryId") else ""),
                confirmed=True,
            )
        )
    return out


def discover_injection(text: str, ruleset: Any) -> List[Finding]:
    """Built-in injection discovery: heuristic matches not already in the graph.

    Runs the built-in OWASP LLM01/LLM06 heuristics over *text* and nominates a
    candidate for each match whose ``injection:{hash(phrase)}`` identifier is
    not already a graph rule. PRIVACY: the candidate carries ONLY the matched
    dangerous phrase (truncated ~120 chars) — never the surrounding text.
    """
    known: set = set()
    for rule in getattr(ruleset, "injection", []) or []:
        ident = rule.get("identifier")
        if ident:
            known.add(ident)
    out: List[Finding] = []
    seen: set = set()
    for hit in quads.scan_injection_heuristics(text or ""):
        phrase = hit["pattern"]
        identifier = quads.injection_identifier(phrase)
        if identifier in known or identifier in seen:
            continue
        seen.add(identifier)
        out.append(
            Finding(
                identifier=identifier,
                category="injection",
                severity=hit.get("severity", "high"),
                title="Suspicious prompt-injection phrase",
                matched=phrase,
                evidence=phrase,
                confirmed=False,
                fields={"pattern": phrase, "owasp_category": hit.get("owasp")},
            )
        )
    return out


def detect_fileaccess(tool_name: str, args: Any, ruleset: Any) -> List[Finding]:
    """Detect access to a sensitive-path category (graph rule or built-in).

    A file-access tool call whose path falls in a sensitive category is a
    finding. If a curated ``fileaccess:{tool}:{category}`` graph rule matches it
    is CONFIRMED; otherwise the built-in category detector nominates a
    candidate. PRIVACY: the finding carries ONLY the category + tool — never
    the exact path or file contents.
    """
    access = quads.file_access_arg(tool_name, args)
    if not access:
        return []
    hit = quads.sensitive_path_category(access["path"], args)
    if not hit:
        return []
    tool = access["tool"]
    category = hit["category"]
    identifier = quads.fileaccess_identifier(tool, category)
    severity = hit["severity"]
    confirmed = False
    name = None
    for rule in getattr(ruleset, "fileaccess", []) or []:
        if str(rule.get("toolName", "")).lower() == tool and str(rule.get("category", "")).lower() == category:
            confirmed = True
            severity = rule.get("severity", severity)
            name = rule.get("name")
            identifier = rule.get("identifier", identifier)
            break
    return [
        Finding(
            identifier=identifier,
            category="fileaccess",
            severity=severity,
            title=name or f"Sensitive file access ({category})",
            tool_name=tool,
            matched=category,
            evidence=f"{access['mode']} {category}",
            confirmed=confirmed,
            fields={"tool_name": tool, "file_category": category},
        )
    ]


def detect_skill(tool_name: str, args: Any, ruleset: Any) -> List[Finding]:
    """Detect a suspicious skill install/modify (graph known-bad or built-in).

    Three signals: known-bad ``skill:{name}@{version}`` from the graph;
    dangerous-code shapes; and over-broad permission grants. PRIVACY: a finding
    carries the skill name + matched danger shape — never the full skill source.
    """
    skill = quads.skill_install_arg(tool_name, args)
    if not skill:
        return []
    out: List[Finding] = []
    seen: set = set()
    name = skill["name"]
    version = skill["version"]
    # (a) known-bad from graph: match name@version or name against skill: rules.
    for rule in getattr(ruleset, "skill", []) or []:
        rule_name = str(rule.get("skillName", "")).strip().lower()
        rule_ver = str(rule.get("skillVersion", "")).strip()
        if rule_name and rule_name == name.lower() and (not rule_ver or rule_ver == version):
            ident = rule.get("identifier") or quads.skill_version_identifier(name, version)
            if ident in seen:
                continue
            seen.add(ident)
            out.append(
                Finding(
                    identifier=ident,
                    category="skill",
                    severity=rule.get("severity", "high"),
                    title=rule.get("name") or f"Known-bad skill {name}",
                    tool_name=skill.get("tool", "") or (tool_name or "").lower(),
                    matched=name,
                    evidence=f"known-bad skill {name}",
                    confirmed=True,
                    fields={"skill_name": name, "skill_version": version},
                )
            )
    # (b)+(c) built-in dangerous-code / over-broad-permission discovery.
    for danger in quads.scan_skill_dangers(skill["code"], skill["permissions"]):
        shape = danger["dangerShape"]
        ident = quads.skill_shape_identifier(name, shape)
        if ident in seen:
            continue
        seen.add(ident)
        out.append(
            Finding(
                identifier=ident,
                category="skill",
                severity=danger.get("severity", "high"),
                title=f"Suspicious skill {name} ({shape})",
                tool_name=(tool_name or "").lower(),
                matched=shape,
                evidence=f"skill {name}: {shape}",
                confirmed=False,
                fields={"skill_name": name, "skill_version": version, "danger_shape": shape},
            )
        )
    return out


def discover_dependency_candidates(tool_name: str, args: Any, ruleset: Any, osv_lookup: Any) -> List[Finding]:
    """Best-effort OSV auto-discovery of vulnerable installs not in the graph.

    Parses install commands, skips any pinned dep already covered by a graph
    rule, and calls *osv_lookup(ecosystem, name, version)* — which returns
    ``{advisory_id, severity}`` when OSV knows it vulnerable, else ``None``.
    Only OSV-VULNERABLE installs become candidates; clean deps are never
    surfaced (privacy). Runs OFF the blocking path — callers invoke this
    best-effort so it never delays or breaks the tool call.
    """
    command = _command_text(args)
    if not command:
        return []
    dependency_rules = getattr(ruleset, "dependency", {}) or {}
    out: List[Finding] = []
    seen: set = set()
    for dep in quads.parse_dependency_installs(command):
        version = dep.get("version") or ""
        if not version:
            continue
        eco = dep["ecosystem"].lower()
        name = dep["name"]
        key = f"{eco}:{name.lower()}@{version}"
        if key in dependency_rules or key in seen:
            continue  # already a graph rule (confirmed elsewhere) or duped
        seen.add(key)
        try:
            hit = osv_lookup(eco, name, version)
        except Exception:  # pragma: no cover - fail open
            hit = None
        if not hit:
            continue
        identifier = quads.dependency_identifier(eco, name, version)
        out.append(
            Finding(
                identifier=identifier,
                category="dependency",
                severity=hit.get("severity", "high"),
                title=f"OSV-vulnerable dependency {name}@{version}",
                tool_name=tool_name or "",
                matched=key,
                evidence=f"{eco}:{name}@{version} ({hit.get('advisory_id')})",
                confirmed=False,
                fields={
                    "ecosystem": eco,
                    "package_name": name,
                    "package_version": version,
                    "advisory_id": hit.get("advisory_id"),
                },
            )
        )
    return out


def detect_all(tool_name: str, args: Any, ruleset: Any, discover: bool = True) -> List[Finding]:
    """Run every detector (graph rules + built-in discovery) across categories.

    Graph-only detectors (dependency lookup, curated injection regexes) always
    run. When *discover* is True the built-in escalation/injection/file-access/
    skill nomination layer also runs. Dependency OSV auto-discovery is NOT run
    here — it is best-effort and runs off the blocking path (see :mod:`hooks`).
    """
    findings: List[Finding] = []
    findings.extend(detect_escalation(tool_name, args, ruleset) if discover else _graph_escalation(tool_name, args, ruleset))
    findings.extend(detect_dependency(tool_name, args, ruleset))
    try:
        args_text = args if isinstance(args, str) else json.dumps(args, ensure_ascii=False, default=str)
    except Exception:
        args_text = str(args)
    findings.extend(detect_injection(args_text, ruleset))
    if discover:
        findings.extend(discover_injection(args_text, ruleset))
        findings.extend(detect_fileaccess(tool_name, args, ruleset))
        findings.extend(detect_skill(tool_name, args, ruleset))
    return findings


def _graph_escalation(tool_name: str, args: Any, ruleset: Any) -> List[Finding]:
    """Graph-only escalation (drops the discovery candidate) — used when
    discovery is disabled so escalation still matches curated rules."""
    return [f for f in detect_escalation(tool_name, args, ruleset) if f.confirmed]
