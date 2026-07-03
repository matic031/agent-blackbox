"""Static constants for the Umanitek Agent Guardian plugin.

Everything here is a compile-time constant: the plugin version, the Guardian
ontology IRIs (shared by :mod:`quads`, :mod:`ruleset` and :mod:`cli` so the
whole plugin speaks one vocabulary), the default public context-graph id, and
the resolution of ``$GUARDIAN_HOME``.

The ontology IRIs are kept byte-for-byte identical to the original TypeScript
node-ui builders so independent Guardian nodes converge on the same threat
KAs and SPARQL filters keep matching across the Python and TS implementations.
"""

from __future__ import annotations

import os
from pathlib import Path

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Ontology
# ---------------------------------------------------------------------------

#: Base IRI for the Umanitek Guardian ontology (``g:`` prefix in SPARQL).
GUARDIAN_ONTOLOGY = "http://umanitek.ai/ontology/guardian/"

# rdf:type IRIs -------------------------------------------------------------
RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
XSD_DATETIME = "http://www.w3.org/2001/XMLSchema#dateTime"

THREAT_TYPE_IRI = f"{GUARDIAN_ONTOLOGY}Threat"
DEP_THREAT_TYPE_IRI = f"{GUARDIAN_ONTOLOGY}VulnerabilityAdvisory"
INJECTION_THREAT_TYPE_IRI = f"{GUARDIAN_ONTOLOGY}PromptInjectionThreat"
ESCALATION_THREAT_TYPE_IRI = f"{GUARDIAN_ONTOLOGY}EscalationThreat"
FILE_ACCESS_THREAT_TYPE_IRI = f"{GUARDIAN_ONTOLOGY}FileAccessThreat"
SUSPICIOUS_SKILL_THREAT_TYPE_IRI = f"{GUARDIAN_ONTOLOGY}SuspiciousSkillThreat"
REPORT_TYPE_IRI = f"{GUARDIAN_ONTOLOGY}ThreatReport"
FALSE_POSITIVE_TYPE_IRI = f"{GUARDIAN_ONTOLOGY}FalsePositive"

# Guardian predicates -------------------------------------------------------
IDENTIFIER_PRED = f"{GUARDIAN_ONTOLOGY}identifier"
CURATED_PRED = f"{GUARDIAN_ONTOLOGY}curated"
SEVERITY_PRED = f"{GUARDIAN_ONTOLOGY}severity"
PATTERN_PRED = f"{GUARDIAN_ONTOLOGY}pattern"
TOOL_NAME_PRED = f"{GUARDIAN_ONTOLOGY}toolName"
ARG_SHAPE_PRED = f"{GUARDIAN_ONTOLOGY}argShape"
OWASP_CATEGORY_PRED = f"{GUARDIAN_ONTOLOGY}owaspCategory"
PACKAGE_NAME_PRED = f"{GUARDIAN_ONTOLOGY}packageName"
PACKAGE_VERSION_PRED = f"{GUARDIAN_ONTOLOGY}packageVersion"
PACKAGE_ECOSYSTEM_PRED = f"{GUARDIAN_ONTOLOGY}packageEcosystem"
FIXED_VERSION_PRED = f"{GUARDIAN_ONTOLOGY}fixedVersion"
REFERENCE_PRED = f"{GUARDIAN_ONTOLOGY}reference"
REPORTS_THREAT_PRED = f"{GUARDIAN_ONTOLOGY}reportsThreat"
REPORTER_PRED = f"{GUARDIAN_ONTOLOGY}reporter"
FRAMEWORK_PRED = f"{GUARDIAN_ONTOLOGY}framework"
DISPUTES_PRED = f"{GUARDIAN_ONTOLOGY}disputes"
DISPUTE_REPORTER_PRED = f"{GUARDIAN_ONTOLOGY}disputeReporter"

# file-access predicates (g:toolName reused; category is new) ----------------
CATEGORY_PRED = f"{GUARDIAN_ONTOLOGY}category"
# suspicious-skill predicates -----------------------------------------------
SKILL_NAME_PRED = f"{GUARDIAN_ONTOLOGY}skillName"
SKILL_VERSION_PRED = f"{GUARDIAN_ONTOLOGY}skillVersion"
DANGER_SHAPE_PRED = f"{GUARDIAN_ONTOLOGY}dangerShape"

# schema.org predicates -----------------------------------------------------
SCHEMA_NAME_PRED = "http://schema.org/name"
SCHEMA_DESCRIPTION_PRED = "http://schema.org/description"
SCHEMA_IDENTIFIER_PRED = "http://schema.org/identifier"
SCHEMA_DATE_MODIFIED_PRED = "http://schema.org/dateModified"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

#: Default public curated context-graph id (config key ``context_graph_id``).
DEFAULT_CONTEXT_GRAPH_ID = "umanitek/guardian-threats"

#: Default local DKG node HTTP endpoint.
DEFAULT_DKG_URL = "http://127.0.0.1:9200"

#: Severity ladder, lowest → highest. ``info`` < ... < ``critical``.
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITY_ORDER)}

#: SPARQL views exposed by the DKG node ``/api/query`` route.
VIEW_WORKING_MEMORY = "working-memory"
VIEW_SHARED_WORKING_MEMORY = "shared-working-memory"
VIEW_VERIFIABLE_MEMORY = "verifiable-memory"


def normalize_severity(value: object, fallback: str = "info") -> str:
    """Coerce an arbitrary value to a known severity string.

    ``moderate`` (OSV/CVSS spelling) maps to ``medium``; anything unknown
    falls back to *fallback*.
    """
    raw = str(value or "").strip().lower()
    if raw == "moderate":
        return "medium"
    return raw if raw in SEVERITY_RANK else fallback


def hermes_home() -> Path:
    """Return the active ``HERMES_HOME`` directory.

    Prefers the hermes runtime helper (which honours profile switching); falls
    back to ``$HERMES_HOME`` and then ``~/.hermes`` so the plugin's CLI works
    even outside a running agent.
    """
    try:
        from hermes_constants import get_hermes_home

        return get_hermes_home()
    except Exception:
        env = os.environ.get("HERMES_HOME")
        return Path(env).expanduser() if env else Path.home() / ".hermes"


def guardian_home() -> Path:
    """Return ``$GUARDIAN_HOME`` — defaults to ``$HERMES_HOME/guardian``.

    Created on demand by the callers that write into it (ruleset cache, audit
    logs). An explicit ``GUARDIAN_HOME`` env var overrides the default.
    """
    env = os.environ.get("GUARDIAN_HOME")
    if env and env.strip():
        return Path(env).expanduser()
    return hermes_home() / "guardian"
