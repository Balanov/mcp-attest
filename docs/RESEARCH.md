# Why this exists — research notes

This is the evidence behind `mcp-attest`. It is kept out of the README on purpose:
the README explains the tool, this file explains the gap it closes.

## The gap

Gateways, policy engines and allowlists for Model Context Protocol are now
everywhere — Docker MCP Gateway, agentgateway, Bifrost, Runlayer, Lasso, Obot, and
GitHub's own `gh-aw-mcpg`. The policy language is not the problem.

The problem is that **nobody verifies the policy is enforced.**

## What the evaluations say

In a detailed evaluation of agentgateway published in October 2026, an
argument-conditioned policy was "reported as accepted and still did not enforce what
it said", and the conclusion was blunt: "turning a policy on is not the end of the
job — send real calls and check."

The same evaluation found policies that were accepted and had no effect at all.

The State of MCP Security 2026 survey describes the structural gap:

> "Gateways only protect the servers they route. An agent calling an MCP server
> outside the gateway is invisible."

> "Most gateways also do not do deep content inspection of responses. The gateway
> enforces who and where, not what."

## What the numbers say

- More than 40 CVEs against MCP implementations were disclosed in the first four
  months of 2026.
- An estimated 200,000 servers are exposed.
- 38% of scanned MCP servers had no authentication on critical endpoints.
- In April 2026 researchers hijacked Claude Code, Gemini CLI and GitHub Copilot
  through malicious pull-request titles, with bug bounties paid by the vendors.

## What buyers say

The buyers of this category are being told the same thing. The US DoD's Center for
Security and Information Technology wrote that "without these traceable audit logs,
incident response and accountability become significantly more difficult, especially
in multi-tenant environments."

## The missing primitive

The missing piece is small, sharp and useful: **a harness that takes a policy and a
trace and tells you, with evidence, whether your control plane does what you wrote
down.**

`mcp-attest` is that harness. It is not a gateway, it does not sit on the hot path,
and it does not need to be trusted with your traffic — it reads what already happened.

## Which failure is worth a product

Of the nine checks, C6 is the one that no existing tool does: it re-evaluates the
policy locally against every recorded call and flags any call whose observed
decision disagrees with the policy. That is the "accepted but not enforced" class
of failure, and it is the one that survives every dashboard review.

The rest of the checks exist because the same trace contains the evidence for them:
list/call parity (C2), shadow servers (C7), receipt chains (C8), and tool
definitions that changed after approval (C9).

## Sources

- Detailed evaluation of agentgateway, October 2026 — argument-conditioned policy
  accepted and not enforced; accepted policies with no effect.
- The State of MCP Security 2026 survey — gateway scope, response inspection.
- MCP implementation CVE disclosures, January–April 2026 — 40+ CVEs, ~200k exposed
  servers, 38% without authentication on critical endpoints.
- April 2026 pull-request-title hijacks of Claude Code, Gemini CLI and GitHub Copilot.
- US DoD Center for Security and Information Technology — traceability of audit logs
  in multi-tenant environments.
