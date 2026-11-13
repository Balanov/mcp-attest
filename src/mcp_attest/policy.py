"""Policy model.

The policy describes what an MCP gateway *should* do. The whole point of this
package is to compare that intent against what actually happened, so the
policy is kept deliberately small and explicit: no hidden defaults, because a
hidden default is exactly how "unset allowlist" turns into "allow everything".
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .oauth import OAuthConfig, oauth_config_from_dict

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}


class PolicyError(ValueError):
    """Raised when a policy file cannot be understood."""


@dataclass
class Conditional:
    """A rule that applies only to calls whose arguments match a condition.

    ``allow_when`` maps an argument name to an expected value. A plain value
    means equality; a string ending in "/" means prefix; a string containing
    "*" means shell-style glob. The explicit operator form is preferred in
    hand-written policies::

        {"allow_when": {"path": {"starts_with": "./out/"}}}
        {"allow_when": {"path": {"ends_with": ".md"}}}
        {"allow_when": {"count": {"gt": 100}}}
    """

    tool: str
    allow_when: dict[str, Any] = field(default_factory=dict)
    action: str = "deny"
    reason: str = "conditional rule"

    def matches(self, tool: str, args: dict[str, Any]) -> bool:
        if tool != self.tool:
            return False
        for key, expected in self.allow_when.items():
            actual = args.get(key)
            if not _value_matches(actual, expected):
                return False
        return True


def _value_matches(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        for op, operand in expected.items():
            if op == "eq" and actual != operand:
                return False
            if op == "not_eq" and actual == operand:
                return False
            if op == "starts_with" and not (isinstance(actual, str) and actual.startswith(str(operand))):
                return False
            if op == "ends_with" and not (isinstance(actual, str) and actual.endswith(str(operand))):
                return False
            if op == "contains" and not (isinstance(actual, str) and str(operand) in actual):
                return False
            if op == "in" and actual not in operand:
                return False
            if op == "not_in" and actual in operand:
                return False
            if op == "gt" and not (isinstance(actual, (int, float)) and actual > operand):
                return False
            if op == "gte" and not (isinstance(actual, (int, float)) and actual >= operand):
                return False
            if op == "lt" and not (isinstance(actual, (int, float)) and actual < operand):
                return False
            if op == "lte" and not (isinstance(actual, (int, float)) and actual <= operand):
                return False
            if op == "glob" and not (isinstance(actual, str) and fnmatch.fnmatch(actual, str(operand))):
                return False
            if op == "regex" and not (isinstance(actual, str) and re.search(str(operand), actual)):
                return False
        return True
    if isinstance(expected, str) and expected.endswith("/"):
        return isinstance(actual, str) and actual.startswith(expected)
    if isinstance(expected, str) and "*" in expected:
        return isinstance(actual, str) and fnmatch.fnmatch(actual, expected)
    return actual == expected


@dataclass
class Identity:
    """How a client presents itself to the server.

    ``headers`` are HTTP headers, ``env`` are environment variables for a stdio
    server. Values may reference the environment with ``${VAR}`` so that
    credentials never have to live in the policy file.
    """

    headers: dict[str, str] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)

    def resolved_headers(self, environ: dict[str, str] | None = None) -> dict[str, str]:
        return {k: _expand(v, environ) for k, v in self.headers.items()}

    def resolved_env(self, environ: dict[str, str] | None = None) -> dict[str, str]:
        return {k: _expand(v, environ) for k, v in self.env.items()}


def _expand(value: str, environ: dict[str, str] | None = None) -> str:
    """Expand ``${VAR}`` references against the environment."""
    import re

    env = environ if environ is not None else os.environ

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in env:
            raise PolicyError(f"environment variable {name!r} referenced by the policy is not set")
        return env[name]

    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", replace, value)


@dataclass
class Case:
    """One explicit expectation about one call.

    Cases express what a schema-derived probe cannot: a specific object owned
    by another principal, an amount above a threshold, a tool that must be
    refused for a specific identity.
    """

    id: str
    identity: str
    tool: str
    expect: str = "deny"  # "allow" | "deny"
    args: dict[str, Any] = field(default_factory=dict)
    reason: str = ""

    def matches_tool(self, tool: str) -> bool:
        return tool == self.tool


@dataclass
class ClientPolicy:
    name: str
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    conditional: list[Conditional] = field(default_factory=list)
    egress_hosts: list[str] = field(default_factory=list)
    has_allowlist: bool = False
    identity: Identity = field(default_factory=Identity)

    def decision(self, tool: str, args: dict[str, Any] | None = None) -> tuple[str, str]:
        """Return (decision, reason) for a call, evaluated locally.

        Conditional rules are evaluated first: they are the most specific
        statement in the policy and exist precisely to carve an exception out
        of a blanket allow or deny ("writes are denied, except inside ./out/").
        """
        args = args or {}
        for rule in self.conditional:
            if rule.matches(tool, args):
                return rule.action, rule.reason
        if "*" in self.deny or tool in self.deny:
            return "deny", "tool is on the deny list"
        if "*" in self.allow:
            return "allow", "wildcard allowlist"
        if tool in self.allow:
            return "allow", "tool is on the allow list"
        if not self.has_allowlist:
            return "allow", "no allowlist configured for this client"
        return "deny", "default deny: tool is not on the allow list"


@dataclass
class Policy:
    version: int = 1
    default_decision: str = "deny"
    clients: dict[str, ClientPolicy] = field(default_factory=dict)
    gateway_fail_closed: bool = True
    gateway_passthrough_credentials: bool = False
    gateway_mode: str = "routed"
    receipts_required: bool = True
    receipts_key_env: str = "MCP_ATTEST_KEY"
    cases: list[Case] = field(default_factory=list)
    probes: dict[str, dict[str, Any]] = field(default_factory=dict)
    oauth: OAuthConfig = field(default_factory=OAuthConfig)
    raw: dict[str, Any] = field(default_factory=dict)

    def client(self, name: str) -> ClientPolicy | None:
        return self.clients.get(name)

    def identities(self) -> list[ClientPolicy]:
        """Clients that carry an identity, i.e. that can be presented to a server."""
        return [c for c in self.clients.values() if c.identity.headers or c.identity.env]

    def probe_args(self, tool: str) -> dict[str, Any] | None:
        """Explicit arguments for a tool, if the policy pins them."""
        return self.probes.get(tool)

    def decision_for(self, actor: str, tool: str, args: dict[str, Any] | None = None) -> tuple[str, str]:
        """Decision for an actor, falling back to the policy default."""
        client = self.clients.get(actor)
        if client is None:
            return self.default_decision, f"unknown client '{actor}': policy default applies"
        decision, reason = client.decision(tool, args)
        if client.has_allowlist or client.allow or client.deny:
            return decision, reason
        return self.default_decision, reason


def load_policy(path: str | Path) -> Policy:
    raw_text = Path(path).read_text(encoding="utf-8")
    try:
        raw = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"policy is not valid JSON: {exc}") from exc
    return policy_from_dict(raw)


def policy_from_dict(raw: dict[str, Any]) -> Policy:
    clients: dict[str, ClientPolicy] = {}
    for name, spec in (raw.get("clients") or {}).items():
        tools = spec.get("tools") or {}
        allow = list(tools.get("allow") or [])
        deny = list(tools.get("deny") or [])
        conditional = []
        for rule in tools.get("conditional") or []:
            conditional.append(
                Conditional(
                    tool=rule.get("tool", ""),
                    allow_when=rule.get("allow_when") or {},
                    action=rule.get("action", "deny"),
                    reason=rule.get("reason", "conditional rule"),
                )
            )
        ident = spec.get("identity") or {}
        clients[name] = ClientPolicy(
            name=name,
            allow=allow,
            deny=deny,
            conditional=conditional,
            egress_hosts=list(spec.get("egress_hosts") or []),
            has_allowlist=bool(allow or deny or conditional),
            identity=Identity(
                headers=dict(ident.get("headers") or {}),
                env=dict(ident.get("env") or {}),
            ),
        )

    cases = []
    for case in raw.get("cases") or []:
        expect = str(case.get("expect", "deny")).lower()
        if expect not in ("allow", "deny"):
            raise PolicyError(f"case {case.get('id')!r}: expect must be 'allow' or 'deny', got {expect!r}")
        cases.append(
            Case(
                id=str(case.get("id") or f"case-{len(cases) + 1}"),
                identity=str(case.get("identity") or ""),
                tool=str(case.get("tool") or ""),
                expect=expect,
                args=dict(case.get("args") or {}),
                reason=str(case.get("reason") or ""),
            )
        )

    gateway = raw.get("gateway") or {}
    receipts = raw.get("receipts") or {}
    default_decision = raw.get("default_decision", "deny")
    if default_decision not in ("allow", "deny"):
        raise PolicyError(f"default_decision must be 'allow' or 'deny', got {default_decision!r}")

    return Policy(
        version=int(raw.get("version", 1)),
        default_decision=default_decision,
        clients=clients,
        gateway_fail_closed=bool(gateway.get("fail_closed", True)),
        gateway_passthrough_credentials=bool(gateway.get("passthrough_credentials", False)),
        gateway_mode=str(gateway.get("mode", "routed")),
        receipts_required=bool(receipts.get("required", True)),
        receipts_key_env=str(receipts.get("key_env", "MCP_ATTEST_KEY")),
        cases=cases,
        probes=dict(raw.get("probes") or {}),
        oauth=oauth_config_from_dict(raw.get("oauth")),
        raw=raw,
    )


STARTER_POLICY = {
    "version": 1,
    "default_decision": "deny",
    "clients": {
        "ci-bot": {
            "tools": {
                "allow": ["fs__read_file", "fs__list_directory"],
                "deny": ["fs__write_file", "fs__delete_everything"],
                "conditional": [
                    {
                        "tool": "fs__write_file",
                        "allow_when": {"path": "./out/"},
                        "action": "allow",
                        "reason": "writes are allowed only inside ./out/",
                    }
                ],
            },
            "egress_hosts": ["api.internal.example.com"],
        }
    },
    "gateway": {
        "mode": "routed",
        "fail_closed": True,
        "passthrough_credentials": False,
    },
    "receipts": {
        "required": True,
        "key_env": "MCP_ATTEST_KEY",
    },
}
