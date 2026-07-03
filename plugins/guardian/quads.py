"""Deterministic identifier, URI, and quad builders for the threat graph.

This is the single source of truth for:

* **threat identifiers** — ``dep:``/``injection:``/``escalation:`` strings that
  two independent nodes compute identically so they converge on the same
  Threat knowledge asset.
* **arg-shape normalization** — the deterministic ``normalize_arg_shape``
  heuristic that turns a tool call into an escalation signature. Detection
  (matching observed calls) and the CLI (authoring curated escalation threats)
  both import it from here, so client and curator shapes always agree.
* **N-Triples term escaping** and the quad builders
  (:func:`build_threat_quads`, :func:`build_report_quads`).

The identifier scheme and ontology are kept byte-for-byte compatible with the
original TypeScript ``node-ui`` builders.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from . import constants


# A quad is a ``{subject, predicate, object}`` dict. ``object`` is a ready N-Triples
# term (IRIs bare, literals quoted). No per-quad ``graph`` — the daemon pins it.
Quad = Dict[str, str]


# ---------------------------------------------------------------------------
# Hashing / slugs / URIs
# ---------------------------------------------------------------------------


def stable_hash(value: str, length: int = 24) -> str:
    """SHA-256 hex digest of *value*, truncated to *length* chars."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


_SLUG_RE = re.compile(r"[^a-z0-9._-]+")
_SLUG_TRIM_RE = re.compile(r"^-+|-+$")


def slug(value: str) -> str:
    """Lowercase, replace runs of non ``[a-z0-9._-]`` with ``-``, cap at 96 chars."""
    lowered = _SLUG_RE.sub("-", str(value).lower())
    trimmed = _SLUG_TRIM_RE.sub("", lowered)[:96]
    return trimmed or "unknown"


def threat_uri(identifier: str) -> str:
    """Stable curated-threat subject URI for a threat *identifier*."""
    return f"urn:guardian:threat:{slug(identifier)}"


def report_uri(identifier: str, agent_address: str) -> str:
    """Per-submitter namespaced report subject URI.

    SWM root entities are first-writer-wins, so each submitter's sighting of a
    threat gets its own subject: ``urn:guardian:report:{addrLower}:{h}`` where
    ``h`` is ``sha256(identifier)[:16]``. Counting distinct reporters of a
    threat therefore counts distinct namespaces.
    """
    addr = (agent_address or "anonymous").lower()
    return f"urn:guardian:report:{addr}:{stable_hash(identifier, 16)}"


# ---------------------------------------------------------------------------
# Identifier builders
# ---------------------------------------------------------------------------


def dependency_identifier(ecosystem: str, name: str, version: str) -> str:
    """``dep:{ecosystem}:{name}@{version}`` (ecosystem + name lowercased)."""
    return f"dep:{ecosystem.strip().lower()}:{name.strip().lower()}@{version.strip()}"


def injection_identifier(pattern: str) -> str:
    """``injection:{sha256(pattern)[:24]}``."""
    return f"injection:{stable_hash(pattern, 24)}"


def escalation_identifier(tool_name: str, arg_shape: str) -> str:
    """``escalation:{tool}:{argShape}`` — the human-readable escalation id.

    The shape is kept literal (not hashed) so the id is legible, e.g.
    ``escalation:shell:remote-script-pipe``. *arg_shape* is expected to already
    be a normalized slug from :func:`normalize_arg_shape`.
    """
    return f"escalation:{tool_name.strip().lower()}:{arg_shape.strip()}"


def fileaccess_identifier(tool_name: str, category: str) -> str:
    """``fileaccess:{tool}:{category}`` — e.g. ``fileaccess:read_file:ssh-private-key``.

    Both parts are kept literal (lowercased) so the id is legible and two nodes
    that touch the same sensitive-path category converge on one threat KA.
    """
    return f"fileaccess:{tool_name.strip().lower()}:{category.strip().lower()}"


def skill_version_identifier(name: str, version: str) -> str:
    """``skill:{name}@{version}`` — the known-bad (graph-matched) skill id."""
    return f"skill:{name.strip().lower()}@{version.strip()}"


def skill_shape_identifier(name: str, danger_shape: str) -> str:
    """``skill:{name}:{dangerShape}`` — a heuristic dangerous-code/permission id."""
    return f"skill:{name.strip().lower()}:{danger_shape.strip()}"


# ---------------------------------------------------------------------------
# Arg-shape normalization (shared by detection + curator)
# ---------------------------------------------------------------------------

# A remote-download-piped-to-interpreter shape: `curl ... | sh`, `wget ... | bash`.
REMOTE_SCRIPT_RE = re.compile(
    r"\b(?:curl|wget)\b[\s\S]{0,500}\|\s*(?:sh|bash|zsh|python|python3|node)\b",
    re.IGNORECASE,
)
# `rm -rf` against system / home roots.
RM_RF_SYSTEM_RE = re.compile(
    r"\brm\s+(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-r\s+-f|-f\s+-r)\b[\s\S]{0,200}"
    r"(?:\s/(?:etc|var|usr|bin|sbin|opt|private|System|Library)\b|\s~/?|\s/\s*$|\s\$HOME\b)",
    re.IGNORECASE,
)
# `chmod 777` / world-writable perms.
CHMOD_WORLD_RE = re.compile(r"\bchmod\s+(?:-R\s+)?0?777\b", re.IGNORECASE)
# Piping a fetched payload straight into eval.
CURL_EVAL_RE = re.compile(r"\b(?:curl|wget)\b[\s\S]{0,300}\|\s*eval\b", re.IGNORECASE)
# Disabling TLS verification on a network fetch.
INSECURE_FETCH_RE = re.compile(
    r"\b(?:curl|wget)\b[\s\S]{0,200}(?:--insecure|-k\b|--no-check-certificate)",
    re.IGNORECASE,
)

# Ordered so the most specific / most dangerous shape wins for a given command.
_SHELL_SHAPE_RULES = (
    ("remote-script-pipe", REMOTE_SCRIPT_RE),
    ("remote-eval-pipe", CURL_EVAL_RE),
    ("rm-rf-system-paths", RM_RF_SYSTEM_RE),
    ("chmod-world-writable", CHMOD_WORLD_RE),
    ("insecure-tls-fetch", INSECURE_FETCH_RE),
)

# Tool names whose payload is treated as a shell command string.
_SHELL_TOOLS = {"terminal", "shell", "bash", "run_command", "exec", "command"}
_COMMAND_KEYS = ("command", "cmd", "shell", "script", "input")

_MAX_SHAPE_SCAN = 8000


def _command_from_args(tool_name: str, args: Any) -> str:
    """Best-effort extraction of a shell command string from tool args."""
    if isinstance(args, str):
        return args[:_MAX_SHAPE_SCAN]
    if not isinstance(args, dict):
        return ""
    for key in _COMMAND_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val:
            return val[:_MAX_SHAPE_SCAN]
    # Fall back to concatenating string values for shell-like tools only.
    if (tool_name or "").lower() in _SHELL_TOOLS:
        parts = [v for v in args.values() if isinstance(v, str)]
        return " ".join(parts)[:_MAX_SHAPE_SCAN]
    return ""


def normalize_arg_shape(tool_name: str, args: Any) -> Optional[str]:
    """Derive a deterministic escalation ``argShape`` for a tool call.

    Returns a stable slug (e.g. ``remote-script-pipe``) or ``None`` when the
    call does not match any known dangerous shape. Deterministic and pure so
    the client detector and the curator authoring flow agree on identifiers.
    """
    command = _command_from_args(tool_name, args)
    if not command:
        return None
    for shape, pattern in _SHELL_SHAPE_RULES:
        try:
            if pattern.search(command):
                return shape
        except re.error:  # pragma: no cover - static patterns
            continue
    return None


# ---------------------------------------------------------------------------
# Built-in injection heuristics (discovery layer — OWASP LLM01/LLM06)
# ---------------------------------------------------------------------------

# Each entry is (severity, owasp, compiled-regex). These are the DISCOVERY
# nomination layer: a prompt matching one that is NOT already in the graph is
# auto-submitted as a *candidate* injection. Privacy: only the matched
# substring (truncated) is ever carried off-box — never the surrounding prompt.
_INJECTION_HEURISTICS = (
    ("high", "LLM01", re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE)),
    ("high", "LLM01", re.compile(r"disregard\s+(?:all\s+)?(?:prior|previous|above)\s+(?:instructions|rules|prompts)", re.IGNORECASE)),
    ("high", "LLM06", re.compile(r"(?:reveal|show|print|repeat|disclose)\b[\s\S]{0,40}\bsystem\s+prompt", re.IGNORECASE)),
    ("high", "LLM01", re.compile(r"you\s+are\s+now\b[\s\S]{0,40}\b(?:DAN|developer\s+mode|jailbroken|unrestricted)", re.IGNORECASE)),
    ("medium", "LLM01", re.compile(r"pretend\s+(?:to\s+be|you\s+are)\b[\s\S]{0,40}\b(?:no\s+restrictions|unrestricted|without\s+rules)", re.IGNORECASE)),
    ("high", "LLM06", re.compile(r"(?:exfiltrate|leak|send|upload|post)\b[\s\S]{0,40}\b(?:api\s*key|secret|token|credentials|password|env(?:ironment)?\s+variables)", re.IGNORECASE)),
)

#: Truncation cap for the matched dangerous phrase carried on a candidate.
_INJECTION_PHRASE_CAP = 120
_MAX_INJECTION_SCAN = 50_000


def scan_injection_heuristics(text: str) -> List[Dict[str, str]]:
    """Return built-in injection matches as ``[{pattern, severity, owasp}]``.

    ``pattern`` is the matched dangerous substring (truncated to ~120 chars) —
    NEVER the surrounding prompt. Deterministic and pure; used by detection to
    nominate candidate injection threats not yet in the graph.
    """
    if not text:
        return []
    scan = text[:_MAX_INJECTION_SCAN]
    out: List[Dict[str, str]] = []
    seen: set = set()
    for severity, owasp, pattern in _INJECTION_HEURISTICS:
        try:
            m = pattern.search(scan)
        except re.error:  # pragma: no cover - static patterns
            continue
        if not m:
            continue
        phrase = m.group(0)[:_INJECTION_PHRASE_CAP]
        if phrase in seen:
            continue
        seen.add(phrase)
        out.append({"pattern": phrase, "severity": severity, "owasp": owasp})
    return out


# ---------------------------------------------------------------------------
# Sensitive file-access categories (discovery layer)
# ---------------------------------------------------------------------------

# (category, severity, compiled-path-regex). Matched against the accessed path
# only; the candidate carries ONLY the category + tool — never the exact path.
_SENSITIVE_PATH_RULES = (
    ("ssh-private-key", "critical", re.compile(r"(?:^|/)\.ssh(?:/|$)|(?:^|/)id_(?:rsa|ed25519|ecdsa|dsa)\b", re.IGNORECASE)),
    ("env-file", "high", re.compile(r"(?:^|/)\.env(?:\.[\w.-]+)?$", re.IGNORECASE)),
    ("credentials", "critical", re.compile(
        r"(?:^|/)\.aws/credentials$|(?:^|/)\.netrc$|(?:^|/)\.npmrc$|(?:^|/)\.docker/config\.json$"
        r"|(?:^|/)\.kube/config$|(?:^|/)\.config/gcloud(?:/|$)", re.IGNORECASE)),
    ("password-store", "critical", re.compile(r"(?:^|/)\.password-store(?:/|$)|(?:^|/)\.pgpass$", re.IGNORECASE)),
    ("browser-cookies", "high", re.compile(
        r"(?:Cookies|Login Data)$|(?:^|/)Library/Keychains(?:/|$)|(?:^|/)login\.keychain", re.IGNORECASE)),
    ("system-shadow", "critical", re.compile(r"^/etc/(?:shadow|passwd|sudoers)$", re.IGNORECASE)),
)

# Tools whose args reference a file/path. Value = tuple of candidate arg keys.
_FILE_ACCESS_TOOLS = {
    "read_file": "read",
    "write_file": "write",
    "edit_file": "write",
    "edit": "write",
    "patch": "write",
    "apply_patch": "write",
    "create_file": "write",
    "delete_file": "write",
    "open_file": "read",
    "cat": "read",
    "skill_manage": "write",
}
_PATH_KEYS = ("path", "file", "file_path", "filepath", "filename", "target", "target_file")


def _npmrc_has_token(args: Any) -> bool:
    """True when a .npmrc write/content carries an ``_authToken`` (credential)."""
    text = _command_from_args("", args) if not isinstance(args, dict) else ""
    if isinstance(args, dict):
        for v in args.values():
            if isinstance(v, str):
                text += "\n" + v
    return "_authtoken" in text.lower()


def file_access_arg(tool_name: str, args: Any) -> Optional[Dict[str, str]]:
    """Extract ``{tool, path, mode}`` for a file-access tool call, or ``None``.

    Recognises the file-touching tools in :data:`_FILE_ACCESS_TOOLS`. ``mode``
    is ``read`` or ``write``. Returns ``None`` for non-file tools or missing
    path — pure/deterministic, used for both visibility logging and detection.
    """
    tool = (tool_name or "").strip().lower()
    if tool not in _FILE_ACCESS_TOOLS or not isinstance(args, dict):
        return None
    path = ""
    for key in _PATH_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            path = val.strip()
            break
    if not path:
        return None
    return {"tool": tool, "path": path, "mode": _FILE_ACCESS_TOOLS[tool]}


def sensitive_path_category(path: str, args: Any = None) -> Optional[Dict[str, str]]:
    """Classify *path* into a sensitive category, or ``None``.

    Returns ``{category, severity}``. The ``.npmrc`` file is only sensitive
    when it carries an ``_authToken`` (checked via *args*) — a bare .npmrc is
    ignored. Deterministic; the caller carries ONLY the category off-box.
    """
    if not path:
        return None
    p = path.strip()
    if p.endswith(".npmrc"):
        return {"category": "credentials", "severity": "high"} if _npmrc_has_token(args) else None
    for category, severity, pattern in _SENSITIVE_PATH_RULES:
        try:
            if pattern.search(p):
                return {"category": category, "severity": severity}
        except re.error:  # pragma: no cover - static patterns
            continue
    return None


# ---------------------------------------------------------------------------
# Suspicious-skill danger-shape scanning (discovery layer)
# ---------------------------------------------------------------------------

# (dangerShape, severity, compiled-regex) over the skill's declared code/content.
_SKILL_CODE_RULES = (
    ("shell-exec", "high", re.compile(
        r"\b(?:os\.system|subprocess\.(?:run|call|Popen|check_output)|child_process|exec(?:Sync)?\s*\(|spawn(?:Sync)?\s*\()", re.IGNORECASE)),
    ("remote-script-pipe", "critical", REMOTE_SCRIPT_RE),
    ("credential-exfil", "critical", re.compile(
        r"(?:os\.environ|process\.env|getenv)\b[\s\S]{0,120}\b(?:requests\.(?:post|get)|fetch\s*\(|urlopen|http[s]?://)", re.IGNORECASE)),
    ("obfuscation", "high", re.compile(
        r"\b(?:eval|exec)\s*\(\s*(?:base64|atob|Buffer\.from|codecs\.decode)|\bbase64\.b64decode\b[\s\S]{0,40}\b(?:eval|exec)", re.IGNORECASE)),
)

# (dangerShape, severity, compiled-regex) over declared permissions/capabilities.
# No trailing \b — several of these end in ``*`` (a non-word char).
_SKILL_PERMISSION_RULES = (
    ("over-broad-filesystem", "high", re.compile(r"\b(?:filesystem[:_-]?\*|fs[:_-]?full|read[_-]?write[_-]?all|allowallpaths)", re.IGNORECASE)),
    ("over-broad-shell", "high", re.compile(r"\b(?:arbitrary[_-]?shell|shell[:_-]?\*|exec[:_-]?any|allowshell)", re.IGNORECASE)),
    ("over-broad-network", "medium", re.compile(r"\b(?:network[:_-]?\*|raw[_-]?socket|allowallhosts|net[:_-]?any)", re.IGNORECASE)),
)

# Tools that install/modify a skill.
_SKILL_TOOLS = {"skill_manage", "skill_install", "install_skill", "plugin_install", "install_plugin"}
_SKILL_NAME_KEYS = ("name", "skill", "skill_name", "id", "plugin")
_SKILL_VERSION_KEYS = ("version", "skill_version", "ver")
_SKILL_CODE_KEYS = ("code", "content", "source", "body", "script")
_SKILL_PERM_KEYS = ("permissions", "capabilities", "scopes", "allow", "grants")

_MAX_SKILL_SCAN = 20_000


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return " ".join(_stringify(v) for v in value)
    if isinstance(value, dict):
        return " ".join(f"{k} {_stringify(v)}" for k, v in value.items())
    return str(value) if value is not None else ""


def skill_install_arg(tool_name: str, args: Any) -> Optional[Dict[str, str]]:
    """Extract a skill install/modify descriptor, or ``None``.

    Returns ``{name, version, code, permissions}`` (missing fields empty).
    ``code``/``permissions`` are the concatenated content to scan; they are
    NEVER carried off-box — only matched danger-shape names are submitted.
    """
    tool = (tool_name or "").strip().lower()
    if tool not in _SKILL_TOOLS or not isinstance(args, dict):
        return None
    name = ""
    for key in _SKILL_NAME_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            name = val.strip()
            break
    if not name:
        return None
    version = ""
    for key in _SKILL_VERSION_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            version = val.strip()
            break
    code = " ".join(_stringify(args.get(k)) for k in _SKILL_CODE_KEYS if args.get(k))
    perms = " ".join(_stringify(args.get(k)) for k in _SKILL_PERM_KEYS if args.get(k))
    return {"name": name, "version": version, "code": code[:_MAX_SKILL_SCAN], "permissions": perms[:_MAX_SKILL_SCAN]}


def scan_skill_dangers(code: str, permissions: str) -> List[Dict[str, str]]:
    """Return built-in skill danger matches as ``[{dangerShape, severity}]``.

    Scans *code* for dangerous-code shapes and *permissions* for over-broad
    capability grants. Deterministic; the caller carries only the shape name.
    """
    out: List[Dict[str, str]] = []
    seen: set = set()
    for text, rules in ((code or "", _SKILL_CODE_RULES), (permissions or "", _SKILL_PERMISSION_RULES)):
        if not text:
            continue
        for shape, severity, pattern in rules:
            if shape in seen:
                continue
            try:
                if pattern.search(text):
                    seen.add(shape)
                    out.append({"dangerShape": shape, "severity": severity})
            except re.error:  # pragma: no cover - static patterns
                continue
    return out


# ---------------------------------------------------------------------------
# Dependency install parsing (shared by detection + curator import)
# ---------------------------------------------------------------------------

_SHELL_INSTALL_PATTERNS = (
    re.compile(r"\b(?:python(?:3)?\s+-m\s+)?pip3?\s+install\b", re.IGNORECASE),
    re.compile(r"\buv\s+pip\s+install\b", re.IGNORECASE),
    re.compile(r"\buv\s+add\b", re.IGNORECASE),
    re.compile(r"\buvx\b", re.IGNORECASE),
    re.compile(r"\bnpm\s+(?:install|i|add)\b", re.IGNORECASE),
    re.compile(r"\bpnpm\s+add\b", re.IGNORECASE),
    re.compile(r"\byarn\s+add\b", re.IGNORECASE),
    re.compile(r"\bbun\s+add\b", re.IGNORECASE),
    re.compile(r"\bcargo\s+add\b", re.IGNORECASE),
    re.compile(r"\bgem\s+install\b", re.IGNORECASE),
    re.compile(r"\bbrew\s+install\b", re.IGNORECASE),
)

_TOKEN_RE = re.compile(r"""\"([^\"]*)\"|'([^']*)'|(\S+)""")


def _tokenize_shell(command: str) -> List[str]:
    out: List[str] = []
    for m in _TOKEN_RE.finditer(command):
        out.append(m.group(1) or m.group(2) or m.group(3) or "")
    return out


def _parse_package_token(raw: str, ecosystem: str) -> Optional[Dict[str, str]]:
    """Parse a single install token into ``{name, version}`` for *ecosystem*."""
    token = raw.replace(",", "").replace(";", "").strip()
    if not token or token.startswith(("http://", "https://", "/", ".", "@git")):
        return None
    if ecosystem in ("pypi", "rubygems"):
        exact = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9._+!-]+)", token)
        if exact:
            return {"name": exact.group(1), "version": exact.group(2)}
        loose = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?", token)
        if loose:
            return {"name": loose.group(1), "version": ""}
        return None
    if ecosystem == "npm":
        idx = token.rfind("@")
        if idx > 0:  # scoped names start with @, so require idx > 0
            return {"name": token[:idx], "version": token[idx + 1 :]}
        if re.fullmatch(r"(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+", token):
            return {"name": token, "version": ""}
        return None
    # cargo / homebrew / other: name[@version]
    idx = token.rfind("@")
    if idx > 0:
        return {"name": token[:idx], "version": token[idx + 1 :]}
    if re.fullmatch(r"[A-Za-z0-9._+/-]+", token):
        return {"name": token, "version": ""}
    return None


# manager token -> (ecosystem, number of leading subcommand tokens to skip)
_MANAGER_SPECS = {
    ("pip", "install"): ("pypi", 2),
    ("pip3", "install"): ("pypi", 2),
    ("uv", "pip"): ("pypi", 3),  # `uv pip install <pkg>`
    ("uv", "add"): ("pypi", 2),
    ("uvx",): ("pypi", 1),
    ("npm", None): ("npm", 2),  # npm install|i|add
    ("pnpm", "add"): ("npm", 2),
    ("yarn", "add"): ("npm", 2),
    ("bun", "add"): ("npm", 2),
    ("cargo", "add"): ("cargo", 2),
    ("gem", "install"): ("rubygems", 2),
    ("brew", "install"): ("homebrew", 2),
}


def parse_dependency_installs(command: str) -> List[Dict[str, str]]:
    """Parse install commands into ``[{ecosystem, name, version}, ...]``.

    Supports pip/uv/uvx/npm/pnpm/yarn/bun/cargo/gem/brew. Returns an empty list
    when the command is not an install (cheap gate first). Deduplicates.
    """
    if not command or not any(p.search(command) for p in _SHELL_INSTALL_PATTERNS):
        return []
    tokens = _tokenize_shell(command)
    out: List[Dict[str, str]] = []
    seen: set = set()
    i = 0
    while i < len(tokens):
        tok = tokens[i].lower()
        nxt = tokens[i + 1].lower() if i + 1 < len(tokens) else None
        ecosystem = ""
        start = -1
        if (tok, "pip") in _MANAGER_SPECS and nxt == "pip":
            ecosystem, skip = _MANAGER_SPECS[(tok, "pip")]
            start = i + skip
        elif (tok, nxt) in _MANAGER_SPECS:
            ecosystem, skip = _MANAGER_SPECS[(tok, nxt)]
            start = i + skip
        elif (tok,) in _MANAGER_SPECS:
            ecosystem, skip = _MANAGER_SPECS[(tok,)]
            start = i + skip
        elif tok == "npm" and nxt in ("install", "i", "add"):
            ecosystem, start = "npm", i + 2
        if start < 0 or not ecosystem:
            i += 1
            continue
        j = start
        while j < len(tokens):
            raw = tokens[j]
            if raw in (";", "&&", "||", "|"):
                break
            if raw.startswith("-") or raw in ("install", "add", "i"):
                j += 1
                continue
            parsed = _parse_package_token(raw, ecosystem)
            if parsed and parsed["name"]:
                key = f"{ecosystem}:{parsed['name'].lower()}:{parsed['version']}"
                if key not in seen:
                    seen.add(key)
                    out.append({"ecosystem": ecosystem, **parsed})
            j += 1
        i = j
    return out


# ---------------------------------------------------------------------------
# N-Triples term escaping
# ---------------------------------------------------------------------------


def iri(value: str) -> str:
    """Render an IRI term (bare, per the daemon's quad object convention)."""
    return value


def literal(value: str) -> str:
    """Render a plain-string literal term with N-Triples escaping."""
    escaped = (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def datetime_literal(ts: Optional[datetime] = None) -> str:
    """Render an ``xsd:dateTime`` typed literal (UTC ISO-8601)."""
    when = ts or datetime.now(timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    iso = when.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return f'{literal(iso)}^^{constants.XSD_DATETIME}'


def _q(subject: str, predicate: str, obj: str) -> Quad:
    return {"subject": subject, "predicate": predicate, "object": obj}


# ---------------------------------------------------------------------------
# Threat / report quad builders
# ---------------------------------------------------------------------------


def build_threat_quads(
    *,
    category: str,
    identifier: str,
    severity: str,
    name: str,
    description: str,
    curated: bool = True,
    ts: Optional[datetime] = None,
    # injection
    pattern: Optional[str] = None,
    owasp_category: Optional[str] = None,
    # escalation
    tool_name: Optional[str] = None,
    arg_shape: Optional[str] = None,
    # dependency
    ecosystem: Optional[str] = None,
    package_name: Optional[str] = None,
    package_version: Optional[str] = None,
    advisory_id: Optional[str] = None,
    fixed_version: Optional[str] = None,
    references: Optional[Iterable[str]] = None,
    # fileaccess
    file_category: Optional[str] = None,
    # skill
    skill_name: Optional[str] = None,
    skill_version: Optional[str] = None,
    danger_shape: Optional[str] = None,
) -> List[Quad]:
    """Build curated Threat quads for one of the threat categories.

    *category* ∈ ``{"injection", "escalation", "dependency", "fileaccess",
    "skill"}``. The subject URI is :func:`threat_uri` of *identifier*, so
    re-authoring the same threat targets the same KA.
    """
    subj = threat_uri(identifier)
    type_iri = {
        "injection": constants.INJECTION_THREAT_TYPE_IRI,
        "escalation": constants.ESCALATION_THREAT_TYPE_IRI,
        "dependency": constants.DEP_THREAT_TYPE_IRI,
        "fileaccess": constants.FILE_ACCESS_THREAT_TYPE_IRI,
        "skill": constants.SUSPICIOUS_SKILL_THREAT_TYPE_IRI,
    }.get(category)
    if type_iri is None:
        raise ValueError(f"unknown threat category: {category!r}")

    out: List[Quad] = [
        _q(subj, constants.RDF_TYPE, iri(type_iri)),
        _q(subj, constants.RDF_TYPE, iri(constants.THREAT_TYPE_IRI)),
        _q(subj, constants.IDENTIFIER_PRED, literal(identifier)),
        _q(subj, constants.CURATED_PRED, literal("true" if curated else "false")),
        _q(subj, constants.SEVERITY_PRED, literal(constants.normalize_severity(severity))),
        _q(subj, constants.SCHEMA_NAME_PRED, literal(name)),
        _q(subj, constants.SCHEMA_DESCRIPTION_PRED, literal(description)),
        _q(subj, constants.SCHEMA_DATE_MODIFIED_PRED, datetime_literal(ts)),
    ]

    if category == "injection":
        if pattern:
            out.append(_q(subj, constants.PATTERN_PRED, literal(pattern)))
        if owasp_category:
            out.append(_q(subj, constants.OWASP_CATEGORY_PRED, literal(owasp_category)))
    elif category == "escalation":
        if tool_name:
            out.append(_q(subj, constants.TOOL_NAME_PRED, literal(tool_name)))
        if arg_shape:
            out.append(_q(subj, constants.ARG_SHAPE_PRED, literal(arg_shape)))
    elif category == "dependency":
        if package_name:
            out.append(_q(subj, constants.PACKAGE_NAME_PRED, literal(package_name)))
        if package_version:
            out.append(_q(subj, constants.PACKAGE_VERSION_PRED, literal(package_version)))
        if ecosystem:
            out.append(_q(subj, constants.PACKAGE_ECOSYSTEM_PRED, literal(ecosystem)))
        if advisory_id:
            out.append(_q(subj, constants.SCHEMA_IDENTIFIER_PRED, literal(advisory_id)))
        if fixed_version:
            out.append(_q(subj, constants.FIXED_VERSION_PRED, literal(fixed_version)))
        for ref in list(references or [])[:20]:
            if ref:
                out.append(_q(subj, constants.REFERENCE_PRED, literal(str(ref))))
    elif category == "fileaccess":
        if tool_name:
            out.append(_q(subj, constants.TOOL_NAME_PRED, literal(tool_name)))
        if file_category:
            out.append(_q(subj, constants.CATEGORY_PRED, literal(file_category)))
    elif category == "skill":
        if skill_name:
            out.append(_q(subj, constants.SKILL_NAME_PRED, literal(skill_name)))
        if skill_version:
            out.append(_q(subj, constants.SKILL_VERSION_PRED, literal(skill_version)))
        if danger_shape:
            out.append(_q(subj, constants.DANGER_SHAPE_PRED, literal(danger_shape)))

    return out


def build_report_quads(
    *,
    identifier: str,
    category: str,
    severity: str,
    reporter_address: str,
    framework: str = "hermes",
    ts: Optional[datetime] = None,
    # optional full threat fields for NEW candidate threats
    pattern: Optional[str] = None,
    owasp_category: Optional[str] = None,
    tool_name: Optional[str] = None,
    arg_shape: Optional[str] = None,
    ecosystem: Optional[str] = None,
    package_name: Optional[str] = None,
    package_version: Optional[str] = None,
    advisory_id: Optional[str] = None,
    file_category: Optional[str] = None,
    skill_name: Optional[str] = None,
    skill_version: Optional[str] = None,
    danger_shape: Optional[str] = None,
) -> List[Quad]:
    """Build a sighting/report for SWM.

    The subject is per-submitter namespaced (:func:`report_uri`). A report
    NEVER carries observed prompt/command text (privacy split — that stays in
    the private WM audit). For a NEW candidate threat, the caller may pass the
    threat fields so the curator can promote it directly.
    """
    subj = report_uri(identifier, reporter_address)
    threat = threat_uri(identifier)
    out: List[Quad] = [
        _q(subj, constants.RDF_TYPE, iri(constants.REPORT_TYPE_IRI)),
        _q(subj, constants.REPORTS_THREAT_PRED, iri(threat)),
        _q(subj, constants.IDENTIFIER_PRED, literal(identifier)),
        _q(subj, constants.REPORTER_PRED, literal((reporter_address or "anonymous").lower())),
        _q(subj, constants.FRAMEWORK_PRED, literal(framework)),
        _q(subj, constants.SEVERITY_PRED, literal(constants.normalize_severity(severity))),
        _q(subj, constants.SCHEMA_DATE_MODIFIED_PRED, datetime_literal(ts)),
    ]
    if category == "injection" and pattern:
        out.append(_q(subj, constants.PATTERN_PRED, literal(pattern)))
        if owasp_category:
            out.append(_q(subj, constants.OWASP_CATEGORY_PRED, literal(owasp_category)))
    elif category == "escalation":
        if tool_name:
            out.append(_q(subj, constants.TOOL_NAME_PRED, literal(tool_name)))
        if arg_shape:
            out.append(_q(subj, constants.ARG_SHAPE_PRED, literal(arg_shape)))
    elif category == "dependency":
        if package_name:
            out.append(_q(subj, constants.PACKAGE_NAME_PRED, literal(package_name)))
        if package_version:
            out.append(_q(subj, constants.PACKAGE_VERSION_PRED, literal(package_version)))
        if ecosystem:
            out.append(_q(subj, constants.PACKAGE_ECOSYSTEM_PRED, literal(ecosystem)))
        if advisory_id:
            out.append(_q(subj, constants.SCHEMA_IDENTIFIER_PRED, literal(advisory_id)))
    elif category == "fileaccess":
        if tool_name:
            out.append(_q(subj, constants.TOOL_NAME_PRED, literal(tool_name)))
        if file_category:
            out.append(_q(subj, constants.CATEGORY_PRED, literal(file_category)))
    elif category == "skill":
        if skill_name:
            out.append(_q(subj, constants.SKILL_NAME_PRED, literal(skill_name)))
        if skill_version:
            out.append(_q(subj, constants.SKILL_VERSION_PRED, literal(skill_version)))
        if danger_shape:
            out.append(_q(subj, constants.DANGER_SHAPE_PRED, literal(danger_shape)))
    return out
