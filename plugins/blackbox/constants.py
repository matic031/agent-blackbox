"""Static constants for the Agent Blackbox plugin.

Everything here is a compile-time constant: the plugin version, the Blackbox
ontology IRIs (shared by :mod:`quads`, :mod:`ruleset` and :mod:`cli` so the
whole plugin speaks one vocabulary), the default public context-graph id, and
the resolution of ``$BLACKBOX_HOME``.

The ontology IRIs are kept byte-for-byte identical to the original TypeScript
node-ui builders so independent Blackbox nodes converge on the same threat
KAs and SPARQL filters keep matching across the Python and TS implementations.
"""

from __future__ import annotations

import os
from pathlib import Path

__version__ = "1.1.0"

# ---------------------------------------------------------------------------
# Ontology
# ---------------------------------------------------------------------------

#: Base IRI for the Blackbox ontology (``g:`` prefix in SPARQL). The path stays
#: ``/guardian/`` (not ``/blackbox/``) on purpose: the already-published threat
#: corpus uses these predicate/type IRIs, so keeping them leaves that data
#: queryable after the Guardian->Blackbox rename. The ``urn:guardian:`` subject
#: schemes in quads.py are kept for the same reason.
BLACKBOX_ONTOLOGY = "http://umanitek.ai/ontology/guardian/"

# rdf:type IRIs -------------------------------------------------------------
RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
XSD_DATETIME = "http://www.w3.org/2001/XMLSchema#dateTime"

THREAT_TYPE_IRI = f"{BLACKBOX_ONTOLOGY}Threat"
DEP_THREAT_TYPE_IRI = f"{BLACKBOX_ONTOLOGY}VulnerabilityAdvisory"
INJECTION_THREAT_TYPE_IRI = f"{BLACKBOX_ONTOLOGY}PromptInjectionThreat"
ESCALATION_THREAT_TYPE_IRI = f"{BLACKBOX_ONTOLOGY}EscalationThreat"
FILE_ACCESS_THREAT_TYPE_IRI = f"{BLACKBOX_ONTOLOGY}FileAccessThreat"
SUSPICIOUS_SKILL_THREAT_TYPE_IRI = f"{BLACKBOX_ONTOLOGY}SuspiciousSkillThreat"
REPORT_TYPE_IRI = f"{BLACKBOX_ONTOLOGY}ThreatReport"
FALSE_POSITIVE_TYPE_IRI = f"{BLACKBOX_ONTOLOGY}FalsePositive"

# Blackbox predicates -------------------------------------------------------
IDENTIFIER_PRED = f"{BLACKBOX_ONTOLOGY}identifier"
CURATED_PRED = f"{BLACKBOX_ONTOLOGY}curated"
SEVERITY_PRED = f"{BLACKBOX_ONTOLOGY}severity"
PATTERN_PRED = f"{BLACKBOX_ONTOLOGY}pattern"
TOOL_NAME_PRED = f"{BLACKBOX_ONTOLOGY}toolName"
ARG_SHAPE_PRED = f"{BLACKBOX_ONTOLOGY}argShape"
OWASP_CATEGORY_PRED = f"{BLACKBOX_ONTOLOGY}owaspCategory"
PACKAGE_NAME_PRED = f"{BLACKBOX_ONTOLOGY}packageName"
PACKAGE_VERSION_PRED = f"{BLACKBOX_ONTOLOGY}packageVersion"
PACKAGE_ECOSYSTEM_PRED = f"{BLACKBOX_ONTOLOGY}packageEcosystem"
FIXED_VERSION_PRED = f"{BLACKBOX_ONTOLOGY}fixedVersion"
REFERENCE_PRED = f"{BLACKBOX_ONTOLOGY}reference"
# Named provenance (feed/dataset), e.g. "OSV.dev" — distinct from g:reference
# (a URL). Multi-valued.
SOURCE_PRED = f"{BLACKBOX_ONTOLOGY}source"
REPORTS_THREAT_PRED = f"{BLACKBOX_ONTOLOGY}reportsThreat"
REPORTER_PRED = f"{BLACKBOX_ONTOLOGY}reporter"
FRAMEWORK_PRED = f"{BLACKBOX_ONTOLOGY}framework"
DISPUTES_PRED = f"{BLACKBOX_ONTOLOGY}disputes"
DISPUTE_REPORTER_PRED = f"{BLACKBOX_ONTOLOGY}disputeReporter"

# threat kind: distinguishes active malware from a mere vulnerability. Only
# ``malware`` blocks (at/above block_severity); ``vulnerability`` always flags
# but never auto-blocks, so a legit-but-vulnerable package isn't stopped.
KIND_PRED = f"{BLACKBOX_ONTOLOGY}kind"
KIND_MALWARE = "malware"
KIND_VULNERABILITY = "vulnerability"

# file-access predicates (g:toolName reused; category is new) ----------------
CATEGORY_PRED = f"{BLACKBOX_ONTOLOGY}category"
# suspicious-skill predicates -----------------------------------------------
SKILL_NAME_PRED = f"{BLACKBOX_ONTOLOGY}skillName"
SKILL_VERSION_PRED = f"{BLACKBOX_ONTOLOGY}skillVersion"
DANGER_SHAPE_PRED = f"{BLACKBOX_ONTOLOGY}dangerShape"

# schema.org predicates -----------------------------------------------------
SCHEMA_NAME_PRED = "http://schema.org/name"
SCHEMA_DESCRIPTION_PRED = "http://schema.org/description"
SCHEMA_IDENTIFIER_PRED = "http://schema.org/identifier"
SCHEMA_DATE_MODIFIED_PRED = "http://schema.org/dateModified"
# Optional attribution — who contributed the asset (org, handle, or wallet).
SCHEMA_CONTRIBUTOR_PRED = "http://schema.org/contributor"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

#: Default PRIVATE community context-graph id (config key ``context_graph_id``).
#: Private/allowlist so its SWM replicates over the working relay path; members
#: are auto-admitted by ``blackbox curate auto-accept``. Fresh graph because the
#: old public ``umanitek/guardian-threats-staging`` can't be flipped (on-chain
#: access policy is locked once registered).
DEFAULT_CONTEXT_GRAPH_ID = "umanitek/blackbox-threats-staging"

#: Legacy graph ids that predate the move to the private Blackbox CG. A node
#: still pointed at one of these old public defaults is transparently switched to
#: ``DEFAULT_CONTEXT_GRAPH_ID`` at config-load time, so an existing install syncs
#: the current graph with zero manual steps. A genuinely custom ``context_graph_id``
#: (anything not in this set) is always left untouched.
LEGACY_CONTEXT_GRAPH_IDS = frozenset({
    "umanitek/guardian-threats-staging",
    "umanitek/guardian-threats",
})

#: Default Blackbox-managed local DKG node HTTP endpoint. Deliberately not the
#: DKG CLI's default 9200, so Agent Blackbox never collides with a user's own
#: DKG node/cache.
DEFAULT_DKG_PORT = 9320
DEFAULT_DKG_URL = f"http://127.0.0.1:{DEFAULT_DKG_PORT}"

#: Community curator's node peer id. On a private community CG a fresh member
#: sends its join request here; the curator running ``blackbox curate
#: auto-accept`` admits it, after which subscribe + catch-up work. Makes
#: onboarding zero-touch. Override with ``BLACKBOX_CURATOR_PEER_ID``.
DEFAULT_CURATOR_PEER_ID = "12D3KooWBY9jmNATMPv1DZcKbFas5RtjpkhT69pPwvkUBY2MMnDX"

# ---------------------------------------------------------------------------
# DKG networks — Blackbox is MAINNET ONLY (never publishes to a testnet)
# ---------------------------------------------------------------------------
#: Supported DKG mainnets, by EVM chain id → dkg network slug. Base is the
#: default: the curator wallet is funded with ETH on Base. Gnosis/NeuroWeb are
#: allowed overrides (via ``BLACKBOX_DKG_NETWORK`` / ``setup-graph --network``).
DKG_MAINNET_CHAINS = {8453: "mainnet-base", 100: "mainnet-gnosis", 2043: "mainnet-neuroweb"}
#: Known DKG testnets. A node on any of these must NEVER be published to — the
#: real threat graph lives on mainnet. The preflight blocks these outright.
DKG_TESTNET_CHAINS = {84532: "testnet-base-sepolia", 10200: "testnet-gnosis-chiado", 20430: "testnet-neuroweb"}
#: The intended default chain. Fresh DKG v10 nodes can come up on a different
#: chain (the node default is Gnosis), so seeding verifies against this.
DEFAULT_DKG_CHAIN_ID = 8453  # Base mainnet

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


def severity_for_kind(kind: object, severity: object, fallback: str = "high") -> str:
    """Normalized severity, forcing ``malware`` to at least ``critical``.

    Malware must block under the default policy (``block_severity=critical``),
    so a malware entry that omits or under-states its severity is floored to
    ``critical``. A ``vulnerability`` (or unknown kind) keeps its normalized
    severity — a legit-but-vulnerable package should flag, not block.
    """
    sev = normalize_severity(severity, fallback)
    if str(kind or "").strip().lower() == KIND_MALWARE:
        return "critical"
    return sev


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


def blackbox_home() -> Path:
    """Return ``$BLACKBOX_HOME`` — defaults to ``$HERMES_HOME/blackbox``.

    Created on demand by the callers that write into it (ruleset cache, audit
    logs). An explicit ``BLACKBOX_HOME`` env var overrides the default.
    """
    env = os.environ.get("BLACKBOX_HOME")
    if env and env.strip():
        return Path(env).expanduser()
    return hermes_home() / "blackbox"


def blackbox_dkg_home() -> Path:
    """Return the Blackbox-managed DKG home.

    This is separate from the DKG CLI default ``~/.dkg`` so install/bootstrap,
    auth token reads, daemon pid/api-port files, and graph/cache storage do not
    touch a user's existing DKG node.
    """
    env = os.environ.get("BLACKBOX_DKG_HOME")
    if env and env.strip():
        return Path(env).expanduser()
    return blackbox_home() / "dkg"
