"""The conformance runner.

This is the part that does the work: it connects to a real MCP server as a
named identity, sends real calls, and compares what the server *did* against
what the policy says it should have done.

The comparison is the whole product. A scanner tells you what a tool
definition looks like; a fuzzer tells you whether the server survives bad
input; a red-team framework tells you what a model did with a poisoned tool.
None of them answers the question an auditor asks: *did this server refuse
what it had to refuse, for every identity, and can you show me the evidence?*
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

from .checks import Finding
from .client import CallOutcome, McpSession, ServerTool
from .evidence import Evidence, digest, now_iso, redact
from .oauth import (
    authorization_request,
    b64url,
    http_request,
    protected_resource_metadata,
    resource_metadata_url,
    resign,
    scope_set,
    tamper,
    token_probes,
)
from .policy import CRITICAL, HIGH, INFO, LOW, MEDIUM, Identity, Policy
from .rules import OAUTH_RULES, RULES
from .targets import Target, connect

# ---------------------------------------------------------------------------
# Pattern catalogues
# ---------------------------------------------------------------------------

# Instructions aimed at the model rather than at the user. The list follows
# the OWASP guide's own examples plus the phrasing that tool-poisoning
# reports keep using.
POISON_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ignores prior instructions", re.compile(r"(?i)\b(ignore|disregard|forget)\b[^\n]{0,40}\b(previous|prior|earlier|above)\b[^\n]{0,20}\b(instruction|prompt|rule|direction)")),
    ("hides the call", re.compile(r"(?i)\b(do\s*n[o']?t|don't|never)\b[^\n]{0,30}\b(tell|inform|mention|show|reveal|disclose)\b[^\n]{0,20}\b(the\s+)?user")),
    ("demands unconditional use", re.compile(r"(?i)\b(always|you\s+must)\b[^\n]{0,30}\b(use|call|invoke|run)\b[^\n]{0,20}\b(this\s+)?tool")),
    ("demands a side effect before use", re.compile(r"(?i)\bbefore\b[^\n]{0,30}\b(using|calling|invoking)\b[^\n]{0,40}\b(always|first|you\s+must)\b")),
    ("asks for secrets", re.compile(r"(?i)\b(api[_\s-]?key|secret|password|credential|access[_\s-]?token)\b[^\n]{0,40}\b(send|post|include|read|paste|reveal)")),
    ("exfiltration", re.compile(r"(?i)\b(send|post|upload|exfiltrate|forward)\b[^\n]{0,30}\b(to|at)\b[^\n]{0,30}\b(https?://|this\s+url|external|remote)")),
    ("system prompt exfiltration", re.compile(r"(?i)\b(reveal|print|show|repeat|output)\b[^\n]{0,30}\b(your\s+)?(system\s+prompt|initial\s+instructions|developer\s+message)")),
    ("hidden instruction marker", re.compile(r"(?i)<\s*(important|secret|system|hidden|instructions)\s*>")),
)

HIDDEN_CHARACTERS = {
    "\u200b": "zero-width space",
    "\u200c": "zero-width non-joiner",
    "\u200d": "zero-width joiner",
    "\u200e": "left-to-right mark",
    "\u200f": "right-to-left mark",
    "\u202a": "left-to-right embedding",
    "\u202b": "right-to-left embedding",
    "\u202c": "pop directional formatting",
    "\u2060": "word joiner",
    "\ufeff": "byte order mark",
    "\u202e": "right-to-left override",
}

# Parameter and tool names that hand model input to a shell, a file or a URL.
SINK_PARAMS = {
    "command": "executes a command",
    "cmd": "executes a command",
    "shell": "executes a command",
    "script": "executes a script",
    "eval": "evaluates code",
    "code": "evaluates code",
    "url": "fetches a URL",
    "uri": "fetches a URL",
    "webhook": "posts to an arbitrary endpoint",
    "endpoint": "posts to an arbitrary endpoint",
    "path": "reaches the filesystem",
    "file": "reaches the filesystem",
    "filename": "reaches the filesystem",
    "filepath": "reaches the filesystem",
    "sql": "reaches a database",
    "query": "reaches a database",
}

SINK_TOOL_NAMES = re.compile(
    r"(?i)(^|_)(exec|execute|shell|bash|sh|eval|run_?command|system|popen|spawn|curl|wget|http_?get|fetch|sql|query|db)(_|$)"
)

WRITE_TOOL_NAMES = re.compile(
    r"(?i)(^|_)(write|create|update|delete|remove|destroy|drop|insert|put|post|patch|send|publish|deploy|merge|grant|revoke|rotate|install|upload|refund|transfer|move|copy|rename|approve|reject|close|open|restart|run|exec)(_|$)"
)

# A tool whose name starts with one of these verbs only reads. Anything else is
# treated as state-changing and is not called without an explicit opt-in.
READ_ONLY_TOOL_NAMES = re.compile(
    r"(?i)^(get|list|read|search|find|describe|show|status|check|verify|count|whoami|cat|stat|info|query_?only|echo)(_|$)"
)

VAGUE_TOOL_NAMES = re.compile(r"(?i)(^|_)(do|run|handle|process|execute|any|anything|manage|admin)(_|$)")

FREE_FORM_PARAMS = {"task", "payload", "input", "command", "instructions", "data", "body", "content", "request"}

ERROR_LEAKS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("stack trace", re.compile(r"Traceback \(most recent call last\)")),
    ("source frame", re.compile(r'(?m)^\s*File ".*", line \d+')),
    ("absolute POSIX path", re.compile(r"(?<![\w.])/(?:home|Users|root|var|etc|opt|usr|tmp)/[^\s\"']+")),
    ("absolute Windows path", re.compile(r"[A-Za-z]:\\(?:Users|Windows|Program Files|Python)[^\s\"']*")),
    ("internal module path", re.compile(r"(?:node_modules|site-packages|\.venv)[\\/][^\s\"']+")),
)

TOKEN_PATTERNS = (
    ("a malformed token", "Bearer not-a-real-token"),
    ("a token with a tampered signature", "TAMPERED"),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def manifest_hash(tools: list[ServerTool]) -> str:
    """A stable fingerprint of the tool surface, for drift detection."""
    payload = [
        {
            "name": t.name,
            "description": t.description,
            "inputSchema": t.input_schema,
            "annotations": t.annotations,
        }
        for t in sorted(tools, key=lambda t: t.name)
    ]
    return digest(payload)


def _sample_value(name: str, spec: dict[str, Any]) -> Any:
    """Derive a minimal, harmless argument value from a JSON schema."""
    if not isinstance(spec, dict):
        return "attest-probe"
    if "default" in spec:
        return spec["default"]
    if isinstance(spec.get("enum"), list) and spec["enum"]:
        return spec["enum"][0]
    if isinstance(spec.get("const"), (str, int, float, bool)):
        return spec["const"]
    schema_type = spec.get("type")
    if isinstance(schema_type, list):
        schema_type = schema_type[0] if schema_type else None
    fmt = str(spec.get("format") or "").lower()
    if schema_type == "integer":
        return 1
    if schema_type == "number":
        return 1
    if schema_type == "boolean":
        return False
    if schema_type == "array":
        return []
    if schema_type == "object":
        return {}
    if schema_type == "null":
        return None
    if fmt == "email":
        return "probe@example.invalid"
    if fmt == "uri" or fmt == "url":
        return "https://example.invalid/probe"
    if fmt == "date-time":
        return "2026-01-01T00:00:00Z"
    if fmt == "date":
        return "2026-01-01"
    if fmt in ("uuid", "uuid4"):
        return "00000000-0000-4000-8000-000000000000"
    max_length = spec.get("maxLength")
    value = "attest-probe"
    if isinstance(max_length, int) and len(value) > max_length:
        value = value[: max(1, max_length)]
    return value


def probe_arguments(tool: ServerTool, override: dict[str, Any] | None = None) -> dict[str, Any]:
    """Minimal arguments that satisfy the schema: only required properties."""
    if override:
        return dict(override)
    schema = tool.input_schema or {}
    props = schema.get("properties") or {}
    required = schema.get("required") or []
    args: dict[str, Any] = {}
    for name in required:
        if name in props:
            args[name] = _sample_value(name, props[name])
        else:
            args[name] = "attest-probe"
    return args


def _is_safe_to_call(tool: ServerTool, allow_unsafe: bool, opted_in: bool) -> bool:
    """May the harness call this tool without being told to?

    The default is conservative on purpose. A conformance tool that changes
    state while it audits is worse than no tool at all, so a tool is only
    called when it declares itself read-only or when its name says it only
    reads. Everything else needs either an explicit argument pin in the policy
    (which is how the operator says "yes, call this one") or ``--allow-unsafe``
    for a sandboxed run.
    """
    if allow_unsafe or opted_in:
        return True
    if tool.read_only:
        return True
    if tool.destructive:
        return False
    if WRITE_TOOL_NAMES.search(tool.name):
        return False
    if READ_ONLY_TOOL_NAMES.search(tool.name):
        return True
    return False


def _hidden_characters(text: str) -> list[str]:
    return sorted({label for ch, label in HIDDEN_CHARACTERS.items() if ch in text})


def _looks_like_base64_blob(text: str) -> bool:
    return bool(re.search(r"[A-Za-z0-9+/]{48,}={0,2}", text))


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _expired_jwt() -> str:
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps({"sub": "probe", "exp": 1000000000}, separators=(",", ":")).encode())
    return f"{header}.{payload}."


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------


@dataclass
class ConformanceResult:
    findings: list[Finding] = field(default_factory=list)
    evidences: list[Evidence] = field(default_factory=list)
    tools: list[ServerTool] = field(default_factory=list)
    server_info: dict[str, Any] = field(default_factory=dict)
    manifest: str = ""
    calls_made: int = 0
    skipped: list[str] = field(default_factory=list)
    identities_tested: list[str] = field(default_factory=list)
    error: str = ""

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


# ---------------------------------------------------------------------------
# Static rules: everything that can be judged from tools/list alone
# ---------------------------------------------------------------------------


def check_schemas(tools: list[ServerTool]) -> list[Finding]:
    findings: list[Finding] = []
    for tool in tools:
        schema = tool.input_schema or {}
        props = schema.get("properties") or {}
        if schema.get("type") != "object":
            findings.append(
                Finding(
                    check="AT-SCHEMA-001",
                    severity=MEDIUM,
                    title=f"tool '{tool.name}' does not declare an object input schema",
                    detail="A schema without \"type\": \"object\" leaves the argument contract to the model's imagination.",
                    fix='Set "type": "object" on the tool input schema.',
                    evidence={"tool": tool.name},
                )
            )
        if schema.get("additionalProperties") is not False and props:
            findings.append(
                Finding(
                    check="AT-SCHEMA-001",
                    severity=MEDIUM,
                    title=f"tool '{tool.name}' accepts unknown arguments",
                    detail="additionalProperties is not false, so extra fields are silently accepted and can carry instructions.",
                    fix='Set "additionalProperties": false on the tool input schema.',
                    evidence={"tool": tool.name},
                )
            )
        for name, spec in props.items():
            if not isinstance(spec, dict):
                continue
            if "type" not in spec and "anyOf" not in spec and "oneOf" not in spec and "$ref" not in spec:
                findings.append(
                    Finding(
                        check="AT-SCHEMA-001",
                        severity=MEDIUM,
                        title=f"tool '{tool.name}' leaves argument '{name}' untyped",
                        detail="An untyped argument makes the value the model invents, which is how agents send the wrong type.",
                        fix=f'Type the argument "{name}" in the tool schema.',
                        evidence={"tool": tool.name, "argument": name},
                    )
                )
                continue
            if name in FREE_FORM_PARAMS and not spec.get("enum") and not spec.get("pattern"):
                findings.append(
                    Finding(
                        check="AT-SCHEMA-001",
                        severity=HIGH,
                        title=f"tool '{tool.name}' takes a free-form '{name}'",
                        detail="A single free-form string parameter is the shape the OWASP guide calls a god tool: it turns the tool into an arbitrary execution primitive.",
                        fix=f'Replace "{name}" with structured, typed parameters, or constrain it with an enum or a pattern.',
                        evidence={"tool": tool.name, "argument": name},
                    )
                )
            if spec.get("type") == "string" and not any(
                key in spec for key in ("enum", "pattern", "maxLength", "format")
            ):
                findings.append(
                    Finding(
                        check="AT-SCHEMA-001",
                        severity=LOW,
                        title=f"tool '{tool.name}' leaves argument '{name}' unbounded",
                        detail="An unbounded string argument accepts any size and any content.",
                        fix=f'Add "maxLength", "pattern" or an enum to "{name}".',
                        evidence={"tool": tool.name, "argument": name},
                    )
                )
    return findings


def check_poisoning(tools: list[ServerTool]) -> list[Finding]:
    findings: list[Finding] = []
    for tool in tools:
        surfaces: list[tuple[str, str]] = [("description", tool.description)]
        props = (tool.input_schema or {}).get("properties") or {}
        for name, spec in props.items():
            if isinstance(spec, dict):
                description = spec.get("description")
                if isinstance(description, str):
                    surfaces.append((f"parameter '{name}' description", description))
        for where, text in surfaces:
            if not text:
                continue
            for label, pattern in POISON_PATTERNS:
                match = pattern.search(text)
                if match:
                    findings.append(
                        Finding(
                            check="AT-POISON-001",
                            severity=CRITICAL,
                            title=f"tool '{tool.name}' hides an instruction in its {where}",
                            detail=f"The {where} contains text that matches '{label}': {match.group(0)[:120]!r}. A tool definition is read by the model, so this is an instruction channel that the user never sees.",
                            fix=f"Remove the instruction from the {where}. The tool's description should state what it does, not what the model must do.",
                            evidence={"tool": tool.name, "surface": where, "match": match.group(0)[:120]},
                        )
                    )
                    break
            hidden = _hidden_characters(text)
            if hidden:
                findings.append(
                    Finding(
                        check="AT-POISON-001",
                        severity=HIGH,
                        title=f"tool '{tool.name}' hides characters in its {where}",
                        detail=f"The {where} contains invisible characters ({', '.join(hidden)}), which is how instructions are smuggled past a human reviewer.",
                        fix=f"Strip invisible characters from the {where}.",
                        evidence={"tool": tool.name, "surface": where, "characters": hidden},
                    )
                )
            if "<!--" in text:
                findings.append(
                    Finding(
                        check="AT-POISON-001",
                        severity=HIGH,
                        title=f"tool '{tool.name}' hides an HTML comment in its {where}",
                        detail="HTML comments are invisible in rendered documentation and are read by the model.",
                        fix=f"Remove the HTML comment from the {where}.",
                        evidence={"tool": tool.name, "surface": where},
                    )
                )
            if _looks_like_base64_blob(text):
                findings.append(
                    Finding(
                        check="AT-POISON-001",
                        severity=MEDIUM,
                        title=f"tool '{tool.name}' carries an encoded blob in its {where}",
                        detail="A long base64-like string in a tool definition may be a payload that is decoded later.",
                        fix=f"Remove the encoded blob from the {where}.",
                        evidence={"tool": tool.name, "surface": where},
                    )
                )
    return findings


def check_sinks(tools: list[ServerTool]) -> list[Finding]:
    findings: list[Finding] = []
    for tool in tools:
        props = (tool.input_schema or {}).get("properties") or {}
        for name, spec in props.items():
            if name.lower() not in SINK_PARAMS:
                continue
            constrained = isinstance(spec, dict) and any(
                key in spec for key in ("enum", "pattern", "maxLength", "format")
            )
            if not constrained:
                findings.append(
                    Finding(
                        check="AT-SINK-001",
                        severity=HIGH,
                        title=f"tool '{tool.name}' takes an unconstrained '{name}'",
                        detail=f"'{name}' {SINK_PARAMS[name]}, and the schema does not constrain it. This is the shape the OWASP guide calls an injection sink.",
                        fix=f'Constrain "{name}" with an enum or pattern, or split the tool into narrow, single-purpose tools.',
                        evidence={"tool": tool.name, "argument": name},
                    )
                )
        if SINK_TOOL_NAMES.search(tool.name):
            findings.append(
                Finding(
                    check="AT-SINK-001",
                    severity=HIGH,
                    title=f"tool '{tool.name}' looks like an execution sink",
                    detail="The tool name matches a command, shell or query execution pattern, so model input can reach a shell or a database.",
                    fix="Run the tool in a sandbox with an allowlist, or rename and narrow it to a single safe operation.",
                    evidence={"tool": tool.name},
                )
            )
        if VAGUE_TOOL_NAMES.search(tool.name) and len(props) <= 1:
            findings.append(
                Finding(
                    check="AT-SINK-001",
                    severity=MEDIUM,
                    title=f"tool '{tool.name}' has a vague name and a broad contract",
                    detail="A vague tool name with a single parameter is the pattern the OWASP guide lists as a bad example.",
                    fix="Give the tool a specific, action-oriented name and one clearly typed job.",
                    evidence={"tool": tool.name},
                )
            )
    return findings


def check_approval(tools: list[ServerTool]) -> list[Finding]:
    findings: list[Finding] = []
    for tool in tools:
        if not WRITE_TOOL_NAMES.search(tool.name):
            continue
        if tool.read_only:
            continue
        if not tool.annotations:
            findings.append(
                Finding(
                    check="AT-APPROVAL-001",
                    severity=MEDIUM,
                    title=f"tool '{tool.name}' has side effects and declares no annotations",
                    detail="Without annotations the client cannot tell an agent that this tool changes state, and it cannot ask for approval.",
                    fix='Add annotations with readOnlyHint, destructiveHint and openWorldHint.',
                    evidence={"tool": tool.name},
                )
            )
            continue
        if not tool.destructive and "destructiveHint" not in tool.annotations:
            findings.append(
                Finding(
                    check="AT-APPROVAL-001",
                    severity=LOW,
                    title=f"tool '{tool.name}' does not say whether it is destructive",
                    detail="A tool that changes state should say whether the change can be undone.",
                    fix="Set destructiveHint explicitly.",
                    evidence={"tool": tool.name},
                )
            )
    return findings


def check_drift(tools: list[ServerTool], baseline: dict[str, Any] | None) -> list[Finding]:
    findings: list[Finding] = []
    if not baseline:
        return findings
    approved = baseline.get("tools") or {}
    current = {t.name: digest({"description": t.description, "inputSchema": t.input_schema, "annotations": t.annotations}) for t in tools}
    for name, approved_hash in approved.items():
        if name not in current:
            findings.append(
                Finding(
                    check="AT-DRIFT-001",
                    severity=MEDIUM,
                    title=f"tool '{name}' disappeared since the baseline",
                    detail="The approved baseline lists this tool and the server no longer offers it. The server was changed after approval.",
                    fix="Re-approve the new surface, or restore the tool.",
                    evidence={"tool": name},
                )
            )
            continue
        if current[name] != approved_hash:
            findings.append(
                Finding(
                    check="AT-DRIFT-001",
                    severity=CRITICAL,
                    title=f"tool '{name}' changed since the baseline",
                    detail="The definition differs from the approved one. An agent that was cleared for the old definition is now facing a new one.",
                    fix="Re-approve the change deliberately, then refresh the baseline.",
                    evidence={"tool": name, "approved": str(approved_hash)[:12], "current": current[name][:12]},
                )
            )
    for name in current:
        if name not in approved:
            findings.append(
                Finding(
                    check="AT-DRIFT-001",
                    severity=CRITICAL,
                    title=f"tool '{name}' appeared after the baseline",
                    detail="This tool was not in the approved surface. It may have been added without review, which is the rug pull the OWASP guide warns about.",
                    fix="Remove the tool, or approve it explicitly and refresh the baseline.",
                    evidence={"tool": name},
                )
            )
    return findings


def check_error_hygiene(text: str, tool: str) -> list[Finding]:
    findings: list[Finding] = []
    for label, pattern in ERROR_LEAKS:
        match = pattern.search(text)
        if match:
            findings.append(
                Finding(
                    check="AT-ERROR-001",
                    severity=MEDIUM,
                    title=f"tool '{tool}' leaks a {label} in its error",
                    detail=f"The error message contains a {label}: {match.group(0)[:120]!r}. Error text reaches the model and the logs.",
                    fix="Return a short error code, a safe explanation and a correlation id instead of the raw exception.",
                    evidence={"tool": tool, "match": match.group(0)[:120]},
                )
            )
            break
    return findings


def check_output(text: str, tool: str) -> list[Finding]:
    findings: list[Finding] = []
    for label, pattern in POISON_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append(
                Finding(
                    check="AT-INJECT-001",
                    severity=HIGH,
                    title=f"tool '{tool}' returned an instruction aimed at the model",
                    detail=f"The output matches '{label}': {match.group(0)[:120]!r}. Tool output is read by the model as content and can steer it.",
                    fix="Label the output as untrusted content and strip instruction-like text before returning it.",
                    evidence={"tool": tool, "match": match.group(0)[:120]},
                )
            )
            break
    from .evidence import SECRET_PATTERNS

    for label, pattern in SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            findings.append(
                Finding(
                    check="AT-SECRET-001",
                    severity=CRITICAL,
                    title=f"tool '{tool}' returned a {label}",
                    detail="The output carries what looks like a credential. Tool output goes into the model's context and often into the logs.",
                    fix="Redact the value at the source and return a masked form.",
                    evidence={"tool": tool, "pattern": label},
                )
            )
            break
    return findings


# ---------------------------------------------------------------------------
# The runner
# ---------------------------------------------------------------------------


@dataclass
class RunOptions:
    allow_unsafe: bool = False
    dry_run: bool = False
    baseline: dict[str, Any] | None = None
    only: list[str] = field(default_factory=list)
    timeout: float = 10.0


def _enabled(rule_id: str, options: RunOptions) -> bool:
    return not options.only or rule_id in options.only


def _open(target: Target, client: Any) -> McpSession:
    session = McpSession(connect(target, client.identity), client.name, timeout=target.timeout)
    return session.open()


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that are the same defect seen by several identities.

    The evidence records stay one per identity, so nothing is lost; the report
    just stops repeating itself.
    """
    order: list[tuple[str, str]] = []
    merged: dict[tuple[str, str], Finding] = {}
    identities: dict[tuple[str, str], list[str]] = {}
    for finding in findings:
        key = (finding.check, finding.title)
        if key not in merged:
            merged[key] = finding
            order.append(key)
            identities[key] = []
        name = str(finding.evidence.get("identity") or "")
        if name and name not in identities[key]:
            identities[key].append(name)
    for key, names in identities.items():
        if len(names) > 1:
            merged[key].evidence = {**merged[key].evidence, "identities": names}
    return [merged[key] for key in order]


def run_conformance(
    target: Target,
    policy: Policy,
    options: RunOptions | None = None,
) -> ConformanceResult:
    """Test a live MCP server against a policy, as every identity in it."""
    opts = options or RunOptions()
    result = ConformanceResult()

    identities = policy.identities()
    if not identities:
        result.error = (
            "the policy declares no identities: add an \"identity\" block with headers or env to at least one client"
        )
        return result

    sessions: dict[str, McpSession] = {}
    primary: McpSession | None = None
    try:
        for client in identities:
            if opts.dry_run:
                continue
            try:
                session = _open(target, client)
            except Exception as exc:  # noqa: BLE001 - a failed identity is a finding, not a crash
                result.findings.append(
                    Finding(
                        check="AT-AUTHZ-001",
                        severity=HIGH,
                        title=f"identity '{client.name}' could not connect",
                        detail=f"The handshake failed for this identity: {exc}",
                        fix="Check the credentials and the transport for this identity.",
                        evidence={"identity": client.name},
                    )
                )
                continue
            sessions[client.name] = session
            result.identities_tested.append(client.name)
            if primary is None:
                primary = session
                result.tools = session.tools
                result.server_info = session.client.server_info
                result.manifest = manifest_hash(session.tools)

        if primary is None:
            if not result.error:
                result.error = "no identity could open a session with the server"
            return result

        # -- static rules ---------------------------------------------------
        if _enabled("AT-SCHEMA-001", opts):
            result.findings.extend(check_schemas(result.tools))
        if _enabled("AT-POISON-001", opts):
            result.findings.extend(check_poisoning(result.tools))
        if _enabled("AT-SINK-001", opts):
            result.findings.extend(check_sinks(result.tools))
        if _enabled("AT-APPROVAL-001", opts):
            result.findings.extend(check_approval(result.tools))
        if _enabled("AT-DRIFT-001", opts):
            result.findings.extend(check_drift(result.tools, opts.baseline))

        if opts.dry_run:
            result.skipped.append("dry run: no calls were sent")
            return result

        # -- the authorization matrix --------------------------------------
        if _enabled("AT-AUTHZ-001", opts):
            _run_matrix(result, policy, sessions, opts)
        if _enabled("AT-AUTHZ-002", opts):
            _run_cases(result, policy, sessions, opts)
        if _enabled("AT-TOKEN-001", opts):
            _run_token_checks(result, policy, sessions, target, opts)
        if any(_enabled(rule, opts) for rule in OAUTH_RULES):
            _run_oauth_checks(result, policy, sessions, target, opts)
        if _enabled("AT-FAILCLOSED-001", opts):
            _run_fail_closed(result, sessions, opts)
        result.findings = _dedupe(result.findings)
        return result
    finally:
        for session in sessions.values():
            try:
                session.close()
            except Exception:
                pass


def _record(
    result: ConformanceResult,
    test_id: str,
    identity: str,
    method: str,
    request: dict[str, Any],
    outcome: CallOutcome,
    expected: str = "",
    observed: str = "",
) -> None:
    result.evidences.append(
        Evidence(
            test_id=test_id,
            identity=identity,
            method=method,
            request=request,
            response={
                "status": outcome.status,
                "detail": redact(outcome.detail),
                "error": outcome.error.to_dict() if outcome.error else None,
                "output": redact(outcome.text)[:4000],
            },
            expected=expected,
            observed=observed,
            detail=outcome.detail,
            duration_ms=outcome.elapsed_ms,
        )
    )


def _run_matrix(
    result: ConformanceResult,
    policy: Policy,
    sessions: dict[str, McpSession],
    opts: RunOptions,
) -> None:
    """Every identity against every tool: does the server do what the policy says?"""
    for name, session in sessions.items():
        client = policy.client(name)
        if client is None:
            continue
        for tool in session.tools:
            override = policy.probe_args(tool.name)
            opted_in = override is not None
            if not _is_safe_to_call(tool, opts.allow_unsafe, opted_in):
                result.skipped.append(
                    f"{name} → {tool.name}: not called, the tool changes state (use --allow-unsafe in a sandbox)"
                )
                continue
            args = probe_arguments(tool, override)
            expected, reason = policy.decision_for(name, tool.name, args)
            outcome = session.call_tool(tool.name, args)
            result.calls_made += 1
            _record(result, "AT-AUTHZ-001", name, "tools/call", outcome.request, outcome, expected, outcome.status)

            if outcome.status == "allow" and expected == "deny":
                result.findings.append(
                    Finding(
                        check="AT-AUTHZ-001",
                        severity=CRITICAL,
                        title=f"'{name}' was allowed to call '{tool.name}'",
                        detail=(
                            f"The policy denies '{tool.name}' for this identity ({reason}), but the server executed the call. "
                            "This is broken access control, not a policy tuning problem."
                        ),
                        fix=f"Enforce the decision inside the server's tool dispatcher, before the handler runs.",
                        evidence={
                            "identity": name,
                            "tool": tool.name,
                            "arguments": args,
                            "policy_reason": reason,
                            "elapsed_ms": outcome.elapsed_ms,
                        },
                    )
                )
            elif expected == "allow" and outcome.status == "deny":
                result.findings.append(
                    Finding(
                        check="AT-AUTHZ-001",
                        severity=MEDIUM,
                        title=f"'{name}' was refused '{tool.name}' although the policy allows it",
                        detail=(
                            f"The policy allows '{tool.name}' for this identity, but the server refused the call: {outcome.detail}. "
                            "The written policy and the deployed server disagree."
                        ),
                        fix="Align the server's authorization with the policy, then record which one is wrong.",
                        evidence={"identity": name, "tool": tool.name, "arguments": args, "policy_reason": reason},
                    )
                )
            elif outcome.status == "allow":
                text = outcome.text
                if text and (_enabled("AT-SECRET-001", opts) or _enabled("AT-INJECT-001", opts)):
                    for finding in check_output(text, tool.name):
                        if finding.check == "AT-SECRET-001" and not _enabled("AT-SECRET-001", opts):
                            continue
                        if finding.check == "AT-INJECT-001" and not _enabled("AT-INJECT-001", opts):
                            continue
                        result.findings.append(finding)
                if text and _enabled("AT-ERROR-001", opts):
                    result.findings.extend(check_error_hygiene(text, tool.name))
            elif outcome.status == "deny" and _enabled("AT-ERROR-001", opts):
                result.findings.extend(check_error_hygiene(outcome.detail, tool.name))


def _run_cases(
    result: ConformanceResult,
    policy: Policy,
    sessions: dict[str, McpSession],
    opts: RunOptions,
) -> None:
    """Explicit cases: the cross-user and cross-tenant checks a matrix cannot express."""
    for case in policy.cases:
        session = sessions.get(case.identity)
        if session is None:
            result.skipped.append(f"case {case.id}: identity '{case.identity}' has no session")
            continue
        tool = next((t for t in session.tools if t.name == case.tool), None)
        if tool is None:
            result.findings.append(
                Finding(
                    check="AT-AUTHZ-002",
                    severity=MEDIUM,
                    title=f"case {case.id} refers to a tool the server does not expose",
                    detail=f"Identity '{case.identity}' does not see a tool called '{case.tool}'. The case cannot be evaluated.",
                    fix="Fix the tool name in the case, or check whether the server hides tools from this identity.",
                    evidence={"case": case.id, "identity": case.identity, "tool": case.tool},
                )
            )
            continue
        if not _is_safe_to_call(tool, opts.allow_unsafe, True):
            result.skipped.append(f"case {case.id}: '{case.tool}' changes state, not called without --allow-unsafe")
            continue
        outcome = session.call_tool(case.tool, case.args)
        result.calls_made += 1
        _record(result, "AT-AUTHZ-002", case.identity, "tools/call", outcome.request, outcome, case.expect, outcome.status)
        if case.expect == "deny" and outcome.status == "allow":
            result.findings.append(
                Finding(
                    check="AT-AUTHZ-002",
                    severity=CRITICAL,
                    title=f"case {case.id}: '{case.identity}' reached an object it must not reach",
                    detail=(
                        f"The case expects '{case.tool}' to be refused for '{case.identity}'"
                        + (f" ({case.reason})" if case.reason else "")
                        + ", but the server executed the call."
                    ),
                    fix="Check ownership of the object at the point of use, not only the role of the caller.",
                    evidence={"case": case.id, "identity": case.identity, "tool": case.tool, "arguments": case.args},
                )
            )
        elif case.expect == "allow" and outcome.status == "deny":
            result.findings.append(
                Finding(
                    check="AT-AUTHZ-002",
                    severity=MEDIUM,
                    title=f"case {case.id}: '{case.identity}' was refused '{case.tool}'",
                    detail=f"The case expects the call to succeed, but the server refused it: {outcome.detail}",
                    fix="Align the server with the documented behaviour.",
                    evidence={"case": case.id, "identity": case.identity, "tool": case.tool},
                )
            )


def _run_token_checks(
    result: ConformanceResult,
    policy: Policy,
    sessions: dict[str, McpSession],
    target: Target,
    opts: RunOptions,
) -> None:
    """Tokens must be validated: a malformed or tampered token must not reach a tool."""
    if target.kind != "http":
        result.skipped.append("AT-TOKEN-001: token checks need an HTTP server, the identity rides on stdio environment variables")
        return
    bearer: str | None = None
    for client in policy.identities():
        for name, value in client.identity.resolved_headers().items():
            if name.lower() == "authorization" and value.lower().startswith("bearer "):
                bearer = value[len("bearer ") :]
                break
        if bearer:
            break
    if not bearer:
        result.skipped.append("AT-TOKEN-001: no identity carries an Authorization: Bearer header")
        return

    probes = [
        ("a malformed token", "Bearer not-a-real-token"),
        # ``tamper`` flips a bit of the signature bytes, so the server sees a
        # different token. A character flip left one token in sixty-four byte
        # for byte identical, and a server that verifies signatures then
        # accepted it: the harness reported a critical finding against a
        # server that was doing everything right.
        ("a token with a tampered signature", f"Bearer {tamper(bearer)}"),
        ("an expired token", f"Bearer {_expired_jwt()}"),
    ]
    for label, header in probes:
        client = connect(target, policy.identities()[0].identity)
        client.headers["Authorization"] = header
        try:
            session = McpSession(client, "tampered", timeout=target.timeout).open()
        except Exception as exc:  # noqa: BLE001 - refusing the handshake is the correct outcome
            result.evidences.append(
                Evidence(
                    test_id="AT-TOKEN-001",
                    identity="tampered",
                    method="initialize",
                    request={"headers": {"Authorization": header}},
                    response={"status": "deny", "detail": redact(str(exc))},
                    expected="deny",
                    observed="deny",
                    detail=str(exc),
                )
            )
            continue
        try:
            result.findings.append(
                Finding(
                    check="AT-TOKEN-001",
                    severity=CRITICAL,
                    title=f"the server accepted {label}",
                    detail=(
                        "A token that must never be valid completed the initialize handshake. "
                        "The server authenticates the shape of the token, not its validity."
                    ),
                    fix="Verify signature, issuer, audience and expiry on every request, and fail closed.",
                    evidence={"probe": label},
                )
            )
            tool = next((t for t in session.tools if _is_safe_to_call(t, opts.allow_unsafe, False)), None)
            if tool is not None:
                outcome = session.call_tool(tool.name, probe_arguments(tool))
                result.calls_made += 1
                _record(
                    result,
                    "AT-TOKEN-001",
                    "tampered",
                    "tools/call",
                    outcome.request,
                    outcome,
                    "deny",
                    outcome.status,
                )
        finally:
            session.close()


def _bearer_of(policy: Policy) -> str:
    """The first bearer token any identity carries."""
    for client in policy.identities():
        for name, value in client.identity.resolved_headers().items():
            if name.lower() == "authorization" and value.lower().startswith("bearer "):
                return value[7:].strip()
    return ""


def _oauth_session(target: Target, policy: Policy, header: str, name: str) -> McpSession:
    """Open a session with one specific Authorization header."""
    identity = Identity(headers={"Authorization": header})
    return McpSession(connect(target, identity), name, timeout=target.timeout).open()


def _run_oauth_checks(
    result: ConformanceResult,
    policy: Policy,
    sessions: dict[str, McpSession],
    target: Target,
    opts: RunOptions,
) -> None:
    """OAuth 2.1: the other half of the OWASP minimum test set.

    Every check here asks the server one question: *does it verify the token, or
    only look at it?* A refusal is the expected outcome and is recorded as
    evidence; a tool that runs anyway is a finding.
    """
    config = policy.oauth
    if target.kind != "http":
        result.skipped.append("AT-OAUTH-*: OAuth checks need an HTTP server, the identity rides on stdio environment variables")
        return
    if not config.declared:
        result.skipped.append(
            "AT-OAUTH-*: the policy declares no oauth block, so the OAuth checks do not apply to this target"
        )
        return

    bearer = _bearer_of(policy)
    if not bearer:
        result.skipped.append("AT-OAUTH-*: no identity carries an Authorization: Bearer header")
        return

    key = ""
    if config.has_key:
        try:
            key = config.key()
        except KeyError as exc:
            result.skipped.append("AT-OAUTH-*: %s" % exc)

    if _enabled("AT-OAUTH-001", opts):
        _probe_no_token(result, policy, target)
    if _enabled("AT-OAUTH-002", opts) or _enabled("AT-OAUTH-003", opts) or _enabled("AT-OAUTH-004", opts) \
            or _enabled("AT-OAUTH-005", opts) or _enabled("AT-OAUTH-006", opts):
        _probe_tokens(result, policy, target, bearer, key, opts)
    if _enabled("AT-OAUTH-007", opts):
        _probe_scope(result, policy, target, bearer, key, opts)
    if _enabled("AT-OAUTH-008", opts):
        _probe_resource_metadata(result, policy, target)
    if _enabled("AT-OAUTH-009", opts) or _enabled("AT-OAUTH-010", opts) or _enabled("AT-OAUTH-011", opts):
        _probe_authorization_endpoint(result, policy, target, opts)
    if _enabled("AT-OAUTH-012", opts):
        _probe_passthrough(result, policy, target, bearer)


def _oauth_finding(rule: str, title: str, detail: str, fix: str, evidence: dict[str, Any]) -> Finding:
    severity = RULES[rule].severity if rule in RULES else HIGH
    return Finding(check=rule, severity=severity, title=title, detail=detail, fix=fix, evidence=evidence)


def _probe_no_token(result: ConformanceResult, policy: Policy, target: Target) -> None:
    """A request without a token must be refused before any tool is reached."""
    try:
        session = _oauth_session(target, policy, "", "no-token")
    except Exception as exc:  # noqa: BLE001 - refusing the handshake is the correct outcome
        result.evidences.append(
            Evidence(
                test_id="AT-OAUTH-001",
                identity="no-token",
                method="initialize",
                request={"headers": {"Authorization": "<none>"}},
                response={"status": "deny", "detail": redact(str(exc))},
                expected="deny",
                observed="deny",
                detail=str(exc),
            )
        )
        return
    try:
        tools = [t.name for t in session.tools]
        result.findings.append(
            _oauth_finding(
                "AT-OAUTH-001",
                "the server accepted a request without a token",
                detail=(
                    "The initialize handshake completed with no Authorization header, and the server listed "
                    "%d tool(s). A server that needs no token needs no authorization either." % len(tools)
                ),
                fix="Require a bearer token on every request and refuse the handshake when it is missing.",
                evidence={"tools": tools},
            )
        )
        result.evidences.append(
            Evidence(
                test_id="AT-OAUTH-001",
                identity="no-token",
                method="initialize",
                request={"headers": {"Authorization": "<none>"}},
                response={"status": "allow", "detail": "handshake completed", "tools": tools},
                expected="deny",
                observed="allow",
            )
        )
    finally:
        session.close()


def _probe_tokens(
    result: ConformanceResult,
    policy: Policy,
    target: Target,
    bearer: str,
    key: str,
    opts: RunOptions,
) -> None:
    """Every token defect must be refused."""
    for probe in token_probes(bearer, key):
        if not _enabled(probe.rule, opts):
            continue
        if probe.needs_key and not key:
            result.skipped.append(
                "%s: needs the signing key in %r to mint a correctly signed %s"
                % (probe.rule, policy.oauth.signing_key_env, probe.label)
            )
            continue
        try:
            session = _oauth_session(target, policy, probe.header, "oauth-probe")
        except Exception as exc:  # noqa: BLE001 - refusing the handshake is the correct outcome
            result.evidences.append(
                Evidence(
                    test_id=probe.rule,
                    identity="oauth-probe",
                    method="initialize",
                    request={"headers": {"Authorization": probe.header}},
                    response={"status": "deny", "detail": redact(str(exc))},
                    expected="deny",
                    observed="deny",
                    detail=str(exc),
                )
            )
            continue
        try:
            result.findings.append(
                _oauth_finding(
                    probe.rule,
                    "the server accepted %s" % probe.label,
                    detail=(
                        "A token that must never be valid completed the initialize handshake: %s. "
                        "The server reads the token but does not verify it." % probe.detail
                    ),
                    fix="Verify the signature, the issuer, the audience, the expiry and the scope on every request.",
                    evidence={"probe": probe.label, "rule": probe.rule},
                )
            )
            tool = next((t for t in session.tools if _is_safe_to_call(t, opts.allow_unsafe, False)), None)
            if tool is not None:
                outcome = session.call_tool(tool.name, probe_arguments(tool))
                result.calls_made += 1
                _record(
                    result,
                    probe.rule,
                    "oauth-probe",
                    "tools/call",
                    outcome.request,
                    outcome,
                    "deny",
                    outcome.status,
                )
        finally:
            session.close()


def _probe_scope(
    result: ConformanceResult,
    policy: Policy,
    target: Target,
    bearer: str,
    key: str,
    opts: RunOptions,
) -> None:
    """A token without the scope a tool requires must not reach that tool."""
    required = policy.oauth.required_scopes
    if not required:
        result.skipped.append("AT-OAUTH-007: the policy declares no required_scopes for any tool")
        return
    if not key:
        result.skipped.append(
            "AT-OAUTH-007: needs the signing key in %r to mint a correctly signed token with a smaller scope"
            % policy.oauth.signing_key_env
        )
        return

    granted = scope_set(bearer)
    target_tool = next(
        (name for name, scope in required.items() if scope in granted),
        None,
    )
    if target_tool is None:
        result.skipped.append(
            "AT-OAUTH-007: the token carries %s, which does not cover any required scope"
            % (", ".join(sorted(granted)) or "no scope")
        )
        return

    scope = required[target_tool]
    reduced = sorted(granted - {scope})
    try:
        limited = resign(bearer, key, scope=" ".join(reduced))
    except (ValueError, json.JSONDecodeError) as exc:
        result.skipped.append("AT-OAUTH-007: the token is not a JWT, the scope cannot be reduced (%s)" % exc)
        return

    try:
        session = _oauth_session(target, policy, "Bearer " + limited, "scope-probe")
    except Exception as exc:  # noqa: BLE001 - refusing the handshake is a valid outcome
        result.evidences.append(
            Evidence(
                test_id="AT-OAUTH-007",
                identity="scope-probe",
                method="initialize",
                request={"scope": reduced},
                response={"status": "deny", "detail": redact(str(exc))},
                expected="deny",
                observed="deny",
                detail=str(exc),
            )
        )
        return
    try:
        tool = next((t for t in session.tools if t.name == target_tool), None)
        if tool is None:
            result.skipped.append("AT-OAUTH-007: the server does not expose the tool '%s'" % target_tool)
            return
        outcome = session.call_tool(tool.name, probe_arguments(tool))
        result.calls_made += 1
        _record(result, "AT-OAUTH-007", "scope-probe", "tools/call", outcome.request, outcome, "deny", outcome.status)
        if outcome.status == "allow":
            result.findings.append(
                _oauth_finding(
                    "AT-OAUTH-007",
                    "tool '%s' ran without the scope it requires" % target_tool,
                    detail=(
                        "The token was correctly signed and unexpired, but it carries only %s and not '%s'. "
                        "The server did not check the scope, so a token issued for a narrower job can do a wider one."
                        % (", ".join(reduced) or "no scope", scope)
                    ),
                    fix="Check the scope of the presented token against the scope each tool requires.",
                    evidence={"tool": target_tool, "missing_scope": scope, "granted": reduced},
                )
            )
    finally:
        session.close()


def _probe_resource_metadata(result: ConformanceResult, policy: Policy, target: Target) -> None:
    """The server must publish where a client can find its authorization server."""
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mcp-attest", "version": "1"},
            },
        }
    )
    response = http_request(
        target.url,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
        body=body,
        timeout=target.timeout,
    )
    if response.status not in (401, 403):
        result.skipped.append(
            "AT-OAUTH-008: the server answered HTTP %d to an unauthenticated request, so it has no refusal to point at"
            % response.status
        )
        return

    authenticate = response.headers.get("www-authenticate", "")
    pointed_at = resource_metadata_url(authenticate)
    if not pointed_at:
        result.findings.append(
            _oauth_finding(
                "AT-OAUTH-008",
                "the server refuses requests but does not say where its authorization server is",
                detail=(
                    "The answer to an unauthenticated request is HTTP %d with a WWW-Authenticate header that names no "
                    "resource_metadata. A client cannot discover the authorization server, so it has to guess or be "
                    "configured by hand." % response.status
                ),
                fix="Publish protected resource metadata (RFC 9728) and name it in the WWW-Authenticate header.",
                evidence={"www_authenticate": authenticate},
            )
        )
        return

    document, problem = protected_resource_metadata(pointed_at, timeout=target.timeout)
    if document is None:
        result.findings.append(
            _oauth_finding(
                "AT-OAUTH-008",
                "the protected resource metadata is not usable",
                detail="The server points at %s, but %s." % (pointed_at, problem),
                fix="Serve a JSON document with at least 'resource' and 'authorization_servers'.",
                evidence={"url": pointed_at, "problem": problem},
            )
        )
        return

    missing = [key for key in ("resource", "authorization_servers") if not document.get(key)]
    if missing:
        result.findings.append(
            _oauth_finding(
                "AT-OAUTH-008",
                "the protected resource metadata is missing %s" % ", ".join(missing),
                detail=(
                    "The document at %s does not carry %s, so a client cannot tell which server it is talking to "
                    "or where to authorize." % (pointed_at, ", ".join(missing))
                ),
                fix="Include 'resource' and 'authorization_servers' in the metadata document.",
                evidence={"url": pointed_at, "document": document},
            )
        )
        return

    expected = policy.oauth.resource
    declared = str(document.get("resource") or "")
    if expected and declared and declared.rstrip("/") != expected.rstrip("/"):
        result.findings.append(
            _oauth_finding(
                "AT-OAUTH-008",
                "the protected resource metadata names a different resource",
                detail="The metadata says the resource is %s, the policy expects %s." % (declared, expected),
                fix="Publish the canonical identifier of the resource the client asked for.",
                evidence={"declared": declared, "expected": expected},
            )
        )


def _probe_authorization_endpoint(
    result: ConformanceResult, policy: Policy, target: Target, opts: RunOptions
) -> None:
    """PKCE, redirect_uri and state, as the authorization endpoint handles them."""
    config = policy.oauth
    if not config.authorization_endpoint or not config.redirect_uri:
        result.skipped.append(
            "AT-OAUTH-009/010/011: the policy declares no authorization_endpoint or redirect_uri"
        )
        return

    challenge = b64url(hashlib.sha256(b"mcp-attest-verifier").digest())

    if _enabled("AT-OAUTH-009", opts):
        response = authorization_request(
            config.authorization_endpoint, config.redirect_uri, code_challenge=""
        )
        if _issued_code(response):
            result.findings.append(
                _oauth_finding(
                    "AT-OAUTH-009",
                    "the authorization endpoint issued a code without a PKCE challenge",
                    detail=(
                        "A request with no code_challenge was answered with an authorization code. "
                        "Without PKCE an intercepted code can be redeemed by whoever intercepted it."
                    ),
                    fix="Require code_challenge with code_challenge_method S256 on every authorization request.",
                    evidence={"location": response.location},
                )
            )

    if _enabled("AT-OAUTH-010", opts):
        rogue = config.redirect_uri + ".attest-rogue"
        response = authorization_request(config.authorization_endpoint, rogue, code_challenge=challenge)
        if _issued_code(response) and response.location.startswith(rogue):
            result.findings.append(
                _oauth_finding(
                    "AT-OAUTH-010",
                    "the authorization endpoint issued a code for an unregistered redirect_uri",
                    detail=(
                        "The request asked for %s, which is not the registered redirect URI, and the server answered "
                        "with an authorization code. The code can be sent to any address the attacker controls." % rogue
                    ),
                    fix="Compare redirect_uri against the registered value and refuse the request when they differ.",
                    evidence={"location": response.location},
                )
            )

    if _enabled("AT-OAUTH-011", opts):
        response = authorization_request(
            config.authorization_endpoint, config.redirect_uri, state="attest-state", code_challenge=challenge
        )
        if _issued_code(response) and "state=" not in response.location:
            result.findings.append(
                _oauth_finding(
                    "AT-OAUTH-011",
                    "the authorization response does not carry the state",
                    detail=(
                        "The client sent state=attest-state and the answer did not carry it back. "
                        "Without state binding a response can be injected into the client's session."
                    ),
                    fix="Echo the state parameter in the authorization response and bind it to the client session.",
                    evidence={"location": response.location},
                )
            )


def _issued_code(response: Any) -> bool:
    """Did the authorization endpoint hand out a code?"""
    if response.status not in (301, 302, 303, 307, 308):
        return False
    location = response.location or ""
    if "code=" not in location:
        return False
    query = location.split("?", 1)[1] if "?" in location else ""
    return "code=" in query


def _probe_passthrough(result: ConformanceResult, policy: Policy, target: Target, bearer: str) -> None:
    """A token issued for this server must not open a session with the upstream."""
    upstream = policy.oauth.upstream
    if not upstream:
        result.skipped.append("AT-OAUTH-012: the policy declares no upstream server to test against")
        return
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mcp-attest", "version": "1"},
            },
        }
    )
    response = http_request(
        upstream,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": "Bearer " + bearer,
        },
        body=body,
        timeout=target.timeout,
    )
    if response.status in (401, 403):
        result.evidences.append(
            Evidence(
                test_id="AT-OAUTH-012",
                identity="upstream",
                method="initialize",
                request={"url": upstream},
                response={"status": "deny", "detail": "the upstream answered HTTP %d" % response.status},
                expected="deny",
                observed="deny",
            )
        )
        return
    if response.status == 0:
        result.skipped.append("AT-OAUTH-012: the upstream %s is unreachable" % upstream)
        return
    result.findings.append(
        _oauth_finding(
            "AT-OAUTH-012",
            "the upstream server accepted a token issued for this server",
            detail=(
                "The token was minted for this resource, and the upstream answered HTTP %d to it. "
                "Either the client token is forwarded upstream, or the two servers share one trust domain. "
                "A token issued for one resource must not open another." % response.status
            ),
            fix="Exchange the client token for a token scoped to the upstream, or forward no credential at all.",
            evidence={"upstream": upstream, "status": response.status},
        )
    )


def _run_fail_closed(result: ConformanceResult, sessions: dict[str, McpSession], opts: RunOptions) -> None:
    """Invalid input must be refused, not executed."""
    for name, session in sessions.items():
        tool = next(
            (
                t
                for t in session.tools
                if _is_safe_to_call(t, opts.allow_unsafe, False) and (t.input_schema or {}).get("required")
            ),
            None,
        )
        if tool is None:
            continue
        schema = tool.input_schema or {}
        required = schema.get("required") or []
        if not required:
            continue
        broken = dict(schema.get("properties") or {})
        for field_name in required:
            broken.pop(field_name, None)
        broken["__attest_unknown__"] = "unexpected"
        outcome = session.call_tool(tool.name, broken)
        result.calls_made += 1
        _record(result, "AT-FAILCLOSED-001", name, "tools/call", outcome.request, outcome, "deny", outcome.status)
        if outcome.status == "allow":
            result.findings.append(
                Finding(
                    check="AT-FAILCLOSED-001",
                    severity=HIGH,
                    title=f"tool '{tool.name}' executed a call with missing required arguments",
                    detail=(
                        f"The schema requires {', '.join(required)}, but the server executed the call anyway and ignored an unknown field. "
                        "The server is not validating input, so a malformed call reaches the handler."
                    ),
                    fix="Validate the arguments against the schema in the dispatcher and reject the call when they do not match.",
                    evidence={"identity": name, "tool": tool.name, "missing": required},
                )
            )
        break
