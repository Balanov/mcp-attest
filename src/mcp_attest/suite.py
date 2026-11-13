"""The suite format: one file that any harness can run.

A policy file answers "what must be true about this server". It is written for
one tool, in one tool's shape, with credentials that live in the environment.
That is the right shape for a single harness and the wrong shape for a shared
conformance suite: another vendor's harness cannot read it, and it carries
secrets it should not.

The suite format is the portable half. A suite is a JSON document that says
what to call, as whom, and what must come back — nothing about how to make the
call. Any harness that can open an MCP session and compare a decision with an
expectation can run it. The schema is published next to this module so that
"any harness" means something concrete.

The format is deliberately flat: identities, expectations, cases and probes.
No inheritance, no expressions, no plugin hooks.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .policy import Case, ClientPolicy, Conditional, Identity, Policy

FORMAT = "mcp-attest-suite"
VERSION = 1


class SuiteError(ValueError):
    """Raised when a suite document cannot be understood."""


@dataclass
class SuiteIdentity:
    name: str
    headers: dict[str, str] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    conditional: list[dict[str, Any]] = field(default_factory=list)
    cases: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Suite:
    name: str
    description: str = ""
    format: str = FORMAT
    version: int = VERSION
    target: dict[str, Any] = field(default_factory=dict)
    identities: list[SuiteIdentity] = field(default_factory=list)
    probes: dict[str, dict[str, Any]] = field(default_factory=dict)
    oauth: dict[str, Any] = field(default_factory=dict)
    rules: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "target": self.target,
            "identities": [
                {
                    "name": identity.name,
                    "headers": identity.headers,
                    "env": identity.env,
                    "expect": {
                        "allow": identity.allow,
                        "deny": identity.deny,
                        "conditional": identity.conditional,
                    },
                    "cases": identity.cases,
                }
                for identity in self.identities
            ],
            "probes": self.probes,
            "oauth": self.oauth,
            "rules": self.rules,
            "metadata": self.metadata,
        }


def export_suite(
    policy: Policy,
    name: str,
    description: str = "",
    target: dict[str, Any] | None = None,
    rules: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Turn a policy into a suite document.

    The policy is the source of truth; the suite is the portable projection of
    it. Credentials stay as ``${VAR}`` references, exactly as in the policy.
    """
    identities: list[SuiteIdentity] = []
    for client in policy.clients.values():
        identities.append(
            SuiteIdentity(
                name=client.name,
                headers=dict(client.identity.headers),
                env=dict(client.identity.env),
                allow=list(client.allow),
                deny=list(client.deny),
                conditional=[
                    {
                        "tool": rule.tool,
                        "allow_when": rule.allow_when,
                        "action": rule.action,
                        "reason": rule.reason,
                    }
                    for rule in client.conditional
                ],
                cases=[
                    {
                        "id": case.id,
                        "tool": case.tool,
                        "args": case.args,
                        "expect": case.expect,
                        "reason": case.reason,
                    }
                    for case in policy.cases
                    if case.identity == client.name
                ],
            )
        )

    suite = Suite(
        name=name,
        description=description,
        target=dict(target or {}),
        identities=identities,
        probes=dict(policy.probes),
        oauth=dict(policy.raw.get("oauth") or {}),
        rules=list(rules or []),
        metadata=dict(metadata or {}),
    )
    return suite.to_dict()


def load_suite(path: str | Path) -> Suite:
    """Read and validate a suite document."""
    raw = Path(path).read_text(encoding="utf-8")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SuiteError(f"the suite is not valid JSON: {exc}") from exc
    problems = validate_suite(document)
    if problems:
        raise SuiteError("; ".join(problems))
    return _from_dict(document)


def validate_suite(document: Any) -> list[str]:
    """Check a suite document against the published schema, in plain Python."""
    problems: list[str] = []
    if not isinstance(document, dict):
        return ["the suite must be a JSON object"]
    if document.get("format") != FORMAT:
        problems.append("format must be %r" % FORMAT)
    if document.get("version") != VERSION:
        problems.append("version must be %d" % VERSION)
    if not str(document.get("name") or "").strip():
        problems.append("the suite needs a name")
    identities = document.get("identities")
    if not isinstance(identities, list) or not identities:
        problems.append("the suite needs at least one identity")
        return problems
    seen: set[str] = set()
    for identity in identities:
        if not isinstance(identity, dict):
            problems.append("every identity must be an object")
            continue
        name = str(identity.get("name") or "")
        if not name:
            problems.append("every identity needs a name")
        elif name in seen:
            problems.append("identity %r appears twice" % name)
        seen.add(name)
        headers = identity.get("headers") or {}
        env = identity.get("env") or {}
        if not isinstance(headers, dict) or not isinstance(env, dict):
            problems.append("identity %r: headers and env must be objects" % name)
        if not headers and not env:
            problems.append("identity %r carries no headers and no env, so it cannot be presented" % name)
        expect = identity.get("expect") or {}
        if not isinstance(expect, dict):
            problems.append("identity %r: expect must be an object" % name)
            continue
        for key in ("allow", "deny"):
            if not isinstance(expect.get(key, []), list):
                problems.append("identity %r: expect.%s must be a list" % (name, key))
        for case in identity.get("cases") or []:
            if not isinstance(case, dict):
                problems.append("identity %r: every case must be an object" % name)
                continue
            if str(case.get("expect") or "deny") not in ("allow", "deny"):
                problems.append(
                    "identity %r: case %r must expect 'allow' or 'deny'"
                    % (name, case.get("id"))
                )
    target = document.get("target")
    if target is not None and not isinstance(target, dict):
        problems.append("target must be an object")
    return problems


def suite_to_policy(suite: Suite) -> Policy:
    """Turn a suite into a policy the runner already understands."""
    clients: dict[str, ClientPolicy] = {}
    cases: list[Case] = []
    for identity in suite.identities:
        conditional = [
            Conditional(
                tool=str(rule.get("tool") or ""),
                allow_when=dict(rule.get("allow_when") or {}),
                action=str(rule.get("action") or "deny"),
                reason=str(rule.get("reason") or "conditional rule"),
            )
            for rule in identity.conditional
        ]
        clients[identity.name] = ClientPolicy(
            name=identity.name,
            allow=list(identity.allow),
            deny=list(identity.deny),
            conditional=conditional,
            has_allowlist=bool(identity.allow or identity.deny or conditional),
            identity=Identity(headers=dict(identity.headers), env=dict(identity.env)),
        )
        for case in identity.cases:
            cases.append(
                Case(
                    id=str(case.get("id") or ""),
                    identity=identity.name,
                    tool=str(case.get("tool") or ""),
                    expect=str(case.get("expect") or "deny"),
                    args=dict(case.get("args") or {}),
                    reason=str(case.get("reason") or ""),
                )
            )

    raw: dict[str, Any] = {"version": 1, "default_decision": "deny"}
    if suite.oauth:
        raw["oauth"] = suite.oauth
    policy = Policy(
        version=1,
        default_decision="deny",
        clients=clients,
        cases=cases,
        probes=dict(suite.probes),
        raw=raw,
    )
    # The OAuth configuration lives in its own dataclass; rebuild it here so
    # that a suite carries exactly what a policy would have carried.
    from .oauth import oauth_config_from_dict

    policy.oauth = oauth_config_from_dict(suite.oauth)
    return policy


def _from_dict(document: dict[str, Any]) -> Suite:
    identities = []
    for identity in document.get("identities") or []:
        expect = identity.get("expect") or {}
        identities.append(
            SuiteIdentity(
                name=str(identity.get("name") or ""),
                headers=dict(identity.get("headers") or {}),
                env=dict(identity.get("env") or {}),
                allow=list(expect.get("allow") or []),
                deny=list(expect.get("deny") or []),
                conditional=list(expect.get("conditional") or []),
                cases=list(identity.get("cases") or []),
            )
        )
    return Suite(
        name=str(document.get("name") or ""),
        description=str(document.get("description") or ""),
        format=str(document.get("format") or FORMAT),
        version=int(document.get("version") or VERSION),
        target=dict(document.get("target") or {}),
        identities=identities,
        probes=dict(document.get("probes") or {}),
        oauth=dict(document.get("oauth") or {}),
        rules=list(document.get("rules") or []),
        metadata=dict(document.get("metadata") or {}),
    )
