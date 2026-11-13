"""The rule catalogue.

Every rule has a stable identifier, a severity and a pointer to the test in
the OWASP MCP Security Testing Guide that it implements. The identifiers are
part of the product's contract: they are what CI gates on, what a procurement
questionnaire cites, and what a finding in an evidence bundle refers to.

The guide is the anchor, not decoration: the guide defines 79 tests across
hosts, clients, servers, tools, resources, transports, gateways and agentic
workflows, and its Appendix F names the tool categories a tester is expected to
have. ``AT-AUTHZ-*`` and ``AT-TOKEN-*`` cover the two categories that no tool
in the ecosystem ships today — the authorization matrix and token handling.
"""

from __future__ import annotations

from dataclasses import dataclass

from .policy import CRITICAL, HIGH, LOW, MEDIUM


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    owasp: str
    summary: str
    live: bool = False  # does the rule need to call the server?

    @property
    def needs_calls(self) -> bool:
        return self.live


RULES: dict[str, Rule] = {
    r.id: r
    for r in [
        Rule(
            id="AT-SCHEMA-001",
            name="strict tool schemas",
            severity=MEDIUM,
            owasp="MCPSTG-TOOL-04",
            summary="Tool input schemas must type their parameters, bound their length and reject unknown fields.",
        ),
        Rule(
            id="AT-POISON-001",
            name="no hidden instructions",
            severity=CRITICAL,
            owasp="MCPSTG-TOOL-01",
            summary="Tool names, descriptions and parameter descriptions must not instruct the model behind the user's back.",
        ),
        Rule(
            id="AT-SINK-001",
            name="guarded execution sinks",
            severity=HIGH,
            owasp="MCPSTG-TOOL-02",
            summary="Tools that execute commands or fetch URLs must be constrained by their schema.",
        ),
        Rule(
            id="AT-APPROVAL-001",
            name="declared risk and approval",
            severity=MEDIUM,
            owasp="MCPSTG-AUTHZ-02",
            summary="Tools with side effects must declare read-only, destructive and open-world hints.",
        ),
        Rule(
            id="AT-DRIFT-001",
            name="no manifest drift",
            severity=CRITICAL,
            owasp="MCPSTG-SUPP-01",
            summary="The tool manifest must match the approved baseline; a changed definition is a rug pull.",
        ),
        Rule(
            id="AT-AUTHZ-001",
            name="policy enforced per identity",
            severity=CRITICAL,
            owasp="MCPSTG-AUTHZ-01",
            summary="For every identity and every tool, the server's decision must equal the policy's decision.",
            live=True,
        ),
        Rule(
            id="AT-AUTHZ-002",
            name="cross-user objects refused",
            severity=CRITICAL,
            owasp="MCPSTG-AUTHZ-03",
            summary="A valid identifier that belongs to another principal must be refused.",
            live=True,
        ),
        Rule(
            id="AT-TOKEN-001",
            name="tokens validated",
            severity=CRITICAL,
            owasp="MCPSTG-AUTHN-04",
            summary="Malformed, expired and wrongly addressed tokens must be refused before any tool runs.",
            live=True,
        ),
        Rule(
            id="AT-FAILCLOSED-001",
            name="fail closed on invalid input",
            severity=HIGH,
            owasp="MCPSTG-CONF-01",
            summary="Invalid input must be refused, not executed and not answered with a crash.",
            live=True,
        ),
        Rule(
            id="AT-SECRET-001",
            name="no secrets in output",
            severity=CRITICAL,
            owasp="MCPSTG-SECR-01",
            summary="Tool output must not carry API keys, tokens, private keys or other credentials.",
            live=True,
        ),
        Rule(
            id="AT-INJECT-001",
            name="no injected instructions in output",
            severity=HIGH,
            owasp="MCPSTG-TOOL-01",
            summary="Tool output must not carry instructions aimed at the model.",
            live=True,
        ),
        Rule(
            id="AT-ERROR-001",
            name="clean error messages",
            severity=MEDIUM,
            owasp="MCPSTG-CONF-03",
            summary="Errors must not leak stack traces, internal hostnames or absolute paths.",
            live=True,
        ),
    ]
}

TRACE_RULES: dict[str, str] = {
    "C1": "default-deny",
    "C2": "list/call parity",
    "C3": "narrowing only",
    "C4": "credential separation",
    "C5": "fail closed",
    "C6": "enforcement parity",
    "C7": "shadow MCP",
    "C8": "receipt chain",
    "C9": "description integrity",
}

BLOCKING = {"critical", "high"}


def blocking_severities(strict: bool = False) -> set[str]:
    return {"critical", "high", "medium"} if strict else set(BLOCKING)


def rule_catalog() -> list[dict[str, object]]:
    return [
        {
            "id": r.id,
            "name": r.name,
            "severity": r.severity,
            "owasp": r.owasp,
            "summary": r.summary,
            "mode": "live" if r.live else "static",
        }
        for r in RULES.values()
    ]
