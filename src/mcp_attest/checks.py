"""The conformance checks.

Each check encodes a failure mode that was observed in the wild or documented
by a vendor or a standards body. The check IDs are stable so they can be
referenced in CI, in policy review, and in procurement questionnaires.

  C1 default-deny            an unset allowlist must not mean "allow everything"
  C2 list/call parity        a tool hidden from tools/list must not be callable
  C3 narrowing only          a request may restrict a grant, never widen it
  C4 credential separation   the client's token must not be replayed upstream
  C5 fail closed             a policy that cannot be evaluated must not allow
  C6 enforcement parity      the policy decision and the observed decision must match
  C7 shadow MCP              every path an agent uses must be visible to the control point
  C8 receipt chain           every allowed call must leave a verifiable receipt
  C9 description integrity   a tool definition must not change after approval
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .policy import CRITICAL, HIGH, INFO, LOW, MEDIUM, Policy
from .receipts import verify_receipts
from .shadow import find_shadow_paths
from .trace import Trace

RULES = {
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

ERROR_REASON_PATTERNS = (
    "policy error",
    "scanner",
    "failed to evaluate",
    "internal error",
    "exception",
    "timeout while evaluating",
    "unavailable",
)


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    detail: str
    fix: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "rule": RULES.get(self.check, ""),
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "fix": self.fix,
            "evidence": self.evidence,
        }


def _c1_default_deny(policy: Policy, trace: Trace) -> list[Finding]:
    out: list[Finding] = []
    if policy.default_decision != "deny":
        out.append(
            Finding(
                "C1",
                CRITICAL,
                "Policy default is not deny",
                f"default_decision is '{policy.default_decision}'. Anything not explicitly listed is "
                "permitted, so a new tool appears with full access the moment a server ships it.",
                "Set \"default_decision\": \"deny\" and grant access per client.",
                {"default_decision": policy.default_decision},
            )
        )
    for name, client in policy.clients.items():
        if not client.has_allowlist:
            out.append(
                Finding(
                    "C1",
                    CRITICAL,
                    f"Client '{name}' has no allowlist",
                    "An unset allowlist is not an empty allowlist: this client can call every tool of every "
                    "server it can reach.",
                    "Give the client an explicit tools.allow list (and a tools.deny list for destructive tools).",
                    {"client": name},
                )
            )
    return out


def _c2_list_call_parity(policy: Policy, trace: Trace) -> list[Finding]:
    out: list[Finding] = []
    lists = trace.lists_by_actor()
    for actor, calls in trace.calls_by_actor().items():
        actor_lists = lists.get(actor)
        if not actor_lists:
            continue
        listed = set(actor_lists[0].names)
        for call in calls:
            if call.decision != "allow":
                continue
            if call.tool not in listed:
                out.append(
                    Finding(
                        "C2",
                        CRITICAL,
                        f"'{actor}' called a tool that was not in its tools/list",
                        f"Call to '{call.tool}' was allowed, but the tool never appeared in the listing for this "
                        "actor. A client that guesses a tool name gets through — the allowlist is applied to "
                        "listing but not to calling.",
                        "Apply one allowlist to both tools/list and tools/call, and deny by omission.",
                        {"actor": actor, "tool": call.tool, "line": call.line_no},
                    )
                )
    return out


def _c3_narrowing_only(policy: Policy, trace: Trace) -> list[Finding]:
    out: list[Finding] = []
    for actor, calls in trace.calls_by_actor().items():
        client = policy.client(actor)
        if client is None or not client.has_allowlist:
            continue
        if "*" in client.allow:
            continue
        for call in calls:
            if call.decision != "allow":
                continue
            if call.tool not in client.allow:
                out.append(
                    Finding(
                        "C3",
                        HIGH,
                        f"'{actor}' was allowed '{call.tool}' outside its grant",
                        "The observed call is outside the client's allowlist. A per-request control that widens a "
                        "grant is an escalation path, not a convenience.",
                        "Ensure request-level rules can only narrow the grant, never extend it.",
                        {"actor": actor, "tool": call.tool, "line": call.line_no},
                    )
                )
    return out


def _c4_credential_separation(policy: Policy, trace: Trace) -> list[Finding]:
    out: list[Finding] = []
    if policy.gateway_passthrough_credentials:
        out.append(
            Finding(
                "C4",
                HIGH,
                "Gateway replays client credentials upstream",
                "passthrough_credentials is enabled: the token the client presents to the gateway is also the "
                "token the gateway presents to the upstream server. A compromised gateway then holds the "
                "client's own credential, and the upstream cannot tell the two apart.",
                "Set \"passthrough_credentials\": false and issue a separate upstream credential per client.",
                {"gateway": policy.raw.get("gateway", {})},
            )
        )
    for event in trace.events:
        if event.type == "tool_call" and event.get("credential_passthrough"):
            out.append(
                Finding(
                    "C4",
                    CRITICAL,
                    "Observed credential pass-through",
                    "The trace records that the client credential was forwarded upstream verbatim.",
                    "Terminate the client credential at the gateway and mint a scoped upstream credential.",
                    {"line": event.line_no},
                )
            )
    return out


def _c5_fail_closed(policy: Policy, trace: Trace) -> list[Finding]:
    out: list[Finding] = []
    if not policy.gateway_fail_closed:
        out.append(
            Finding(
                "C5",
                HIGH,
                "Gateway is configured to fail open",
                "fail_closed is disabled: when a policy check cannot run, the call goes through. A scanner "
                "outage then becomes an authorization bypass.",
                "Set \"fail_closed\": true so an unavailable check blocks the call.",
                {"gateway": policy.raw.get("gateway", {})},
            )
        )
    for call in trace.tool_calls:
        reason = (call.reason or "").lower()
        if call.decision == "allow" and any(p in reason for p in ERROR_REASON_PATTERNS):
            out.append(
                Finding(
                    "C5",
                    CRITICAL,
                    "Call allowed after a failed policy evaluation",
                    f"The reason recorded for this call is '{call.reason}'. The control plane could not decide, "
                    "and the request was allowed anyway.",
                    "Fail closed: an undecidable call must be blocked, not passed.",
                    {"actor": call.actor, "tool": call.tool, "line": call.line_no, "reason": call.reason},
                )
            )
    return out


def _c6_enforcement_parity(policy: Policy, trace: Trace) -> list[Finding]:
    out: list[Finding] = []
    for call in trace.tool_calls:
        if not call.decision:
            continue
        expected, reason = policy.decision_for(call.actor, call.tool, call.args)
        if expected == call.decision:
            continue
        if expected == "deny" and call.decision == "allow":
            out.append(
                Finding(
                    "C6",
                    CRITICAL,
                    f"Policy denies '{call.tool}' but the gateway allowed it",
                    f"Local evaluation of the policy says deny ({reason}); the trace records allow "
                    f"('{call.reason}'). This is the 'policy accepted but not enforced' failure mode — a "
                    "conditional or argument-conditioned rule that is registered but never applied.",
                    "Replay the call against the gateway with the same arguments and fix the rule binding, then "
                    "add this call as a regression case in CI.",
                    {
                        "actor": call.actor,
                        "tool": call.tool,
                        "args": call.args,
                        "policy_reason": reason,
                        "observed": call.decision,
                        "line": call.line_no,
                    },
                )
            )
        else:
            out.append(
                Finding(
                    "C6",
                    LOW,
                    f"Gateway was stricter than the policy for '{call.tool}'",
                    f"The policy would allow this call ({reason}) but the gateway denied it. Not a security "
                    "issue, but it means the written policy is not the enforced policy.",
                    "Align the policy document with the gateway behaviour.",
                    {"actor": call.actor, "tool": call.tool, "line": call.line_no},
                )
            )
    return out


def _c7_shadow_mcp(policy: Policy, trace: Trace) -> list[Finding]:
    out: list[Finding] = []
    for path in find_shadow_paths(trace):
        out.append(
            Finding(
                "C7",
                HIGH,
                f"Client '{path.client}' reaches '{path.server}' outside the control point",
                "The gateway only protects the servers it routes. A tool call that goes straight to this "
                "server is invisible to every policy, log and audit trail you own.",
                "Route every server through the gateway, or add an explicit egress allowlist so the "
                "bypass is intentional and visible.",
                {"client": path.client, "server": path.server},
            )
        )
    return out


def _c8_receipt_chain(policy: Policy, trace: Trace) -> list[Finding]:
    out: list[Finding] = []
    allowed = [c for c in trace.tool_calls if c.decision == "allow"]
    if policy.receipts_required and allowed and not trace.receipts:
        out.append(
            Finding(
                "C8",
                HIGH,
                "Allowed calls left no receipts",
                f"{len(allowed)} call(s) were allowed and none of them produced a receipt. Without traceable "
                "logs, incident response and accountability degrade quickly — regulators ask for exactly this.",
                "Emit a signed receipt per allowed call (attest receipts --trace ...) and store them where the "
                "developer cannot edit them.",
                {"allowed_calls": len(allowed)},
            )
        )
    if trace.receipts:
        ok, problems = verify_receipts(trace.receipts)
        if not ok:
            out.append(
                Finding(
                    "C8",
                    CRITICAL,
                    "Receipt chain does not verify",
                    "; ".join(problems[:5]),
                    "Investigate the gap before the trail is relied upon in an incident.",
                    {"problems": problems[:10]},
                )
            )
        if len(trace.receipts) < len(allowed):
            out.append(
                Finding(
                    "C8",
                    MEDIUM,
                    "Receipt count is lower than the number of allowed calls",
                    f"{len(allowed)} allowed call(s), {len(trace.receipts)} receipt(s). Some allowed actions are "
                    "unaccounted for.",
                    "Emit a receipt for every allowed call.",
                    {"allowed_calls": len(allowed), "receipts": len(trace.receipts)},
                )
            )
    return out


def _c9_description_integrity(policy: Policy, trace: Trace) -> list[Finding]:
    out: list[Finding] = []
    seen: dict[tuple[str, str], tuple[str, int]] = {}
    for tl in trace.tools_lists:
        for tool in tl.tools:
            name = tool.get("name")
            digest = tool.get("description_sha256")
            if not name or not digest:
                continue
            key = (tl.actor, name)
            if key in seen and seen[key][0] != digest:
                prev_digest, prev_line = seen[key]
                out.append(
                    Finding(
                        "C9",
                        CRITICAL,
                        f"Tool '{name}' changed after it was listed",
                        "The description hash of an already-approved tool changed between two listings. This is the "
                        "shape of a rug pull: the tool was harmless at approval time.",
                        "Hash tool definitions at registration and hold any changed definition for review.",
                        {
                            "actor": tl.actor,
                            "tool": name,
                            "previous_hash": prev_digest[:12],
                            "new_hash": digest[:12],
                            "lines": [prev_line, tl.line_no],
                        },
                    )
                )
            else:
                seen[key] = (digest, tl.line_no)
    return out


CHECKS = (
    _c1_default_deny,
    _c2_list_call_parity,
    _c3_narrowing_only,
    _c4_credential_separation,
    _c5_fail_closed,
    _c6_enforcement_parity,
    _c7_shadow_mcp,
    _c8_receipt_chain,
    _c9_description_integrity,
)


def run_checks(policy: Policy, trace: Trace) -> list[Finding]:
    findings: list[Finding] = []
    for check in CHECKS:
        try:
            findings.extend(check(policy, trace))
        except Exception as exc:  # a broken check must not hide the others
            findings.append(
                Finding(
                    "C0",
                    INFO,
                    f"Check {getattr(check, '__name__', '?')} could not complete",
                    str(exc),
                    "Report this as a bug in mcp-attest.",
                )
            )
    return findings


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
