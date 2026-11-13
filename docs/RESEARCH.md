# Why this exists — research notes

Evidence behind `mcp-attest`, with sources. The positioning and the honest
comparison with other tools live in [POSITIONING.md](POSITIONING.md).

Every quote was checked against its source on 2026-11-14. Every number carries
its denominator.

## The gap

Gateways, policy engines and allowlists for Model Context Protocol are now
everywhere — Docker MCP Gateway, agentgateway, Bifrost, Runlayer, Lasso, Obot,
and GitHub's own `gh-aw-mcpg`. The policy language is not the problem.

The problem is that **nobody verifies the policy is enforced**.

## The documented failure

In a detailed evaluation of agentgateway published in October 2026, an
argument-conditioned policy "was reported as accepted and still did not enforce
what it said, which is why I concluded that turning a policy on is not the end
of the job: send real calls and check"
([kuberneteslab.dev](https://kuberneteslab.dev/en/blog/agentgateway-mcp-enforcement/)).
The same evaluation found policies that were accepted and had no effect at all.

The State of MCP Security 2026 survey describes the structural gap
([pipelab.org](https://pipelab.org/blog/state-of-mcp-security-2026/)):

> "Gateways only protect the servers they route. An agent calling an MCP server
> outside the gateway is invisible."

> "Most gateways also do not do deep content inspection of responses. The
> gateway enforces who and where, not what."

The NSA/CISA design considerations put the same thing in buyer language
([nsa.gov](https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf)):
"Without these traceable audit logs, incident response and accountability become
significantly more difficult, especially in multi-tenant environments."

## The numbers, with denominators

- **38% of publicly reachable MCP servers expose tools with no
  authentication** — 195 of 514 servers in a continuous scan
  ([securityboulevard.com](https://securityboulevard.com/2026/11/why-mcp-security-disclosure-is-broken-and-what-the-industry-needs/),
  [aminrj.com](https://aminrj.com/posts/mcp-security-after-1year/)).
- **492 exposed servers in July 2025 → 1,467 in April 2026**, 74% on major
  cloud providers
  ([Trend Micro](https://www.trendaisecurity.com/en-us/resources-insights/deep-research/update-on-exposed-mcp-servers-the-threat-widens-to-the-cloud)).
- **21,000+ publicly accessible MCP endpoints** counted by Censys telemetry by
  May 2026; a dynamic study of 640 confirmed production servers found **91.8%**
  without OAuth and **687** tool instances exposing shell execution with no
  access control
  ([arXiv 2608.00150](https://arxiv.org/html/2608.00150)).
- **~200,000 vulnerable instances** inherited the April 2026 stdio design flaw
  in the official MCP SDKs, across 150M+ package downloads
  ([vicytech.com](https://www.vicytech.com/blog/mcp-hacking-attack-techniques-2026)).
- **30 CVEs** against MCP servers in the ecosystem's first year, tracked with
  severity and remediation status —
  [aminrj.com](https://aminrj.com/posts/mcp-security-after-1year/).
- **April 2026, "Comment and Control"** (Johns Hopkins, Aonan Guan and
  collaborators): a poisoned GitHub pull-request title hijacked Claude Code,
  Gemini CLI and GitHub Copilot and exfiltrated GitHub Actions secrets. The
  vendors paid bounties and issued no CVEs
  ([ai-hacking.cyberchaos.nl](https://ai-hacking.cyberchaos.nl/incidents),
  [futureagi.com](https://futureagi.com/blog/ai-agent-security-risks/)).

## Which failure is worth a product

Of the nine checks, C6 is the one that belongs to this tool: it re-evaluates
the policy locally against every recorded call and flags any call whose
observed decision disagrees with the policy. That is the "accepted but not
enforced" class of failure, and it is the one that survives every dashboard
review.

The rest of the checks exist because the same trace contains the evidence for
them: list/call parity (C2), shadow servers (C7), receipt chains (C8), and tool
definitions that changed after approval (C9).

Other tools do judge recorded MCP sessions — see the landscape table in
[POSITIONING.md](POSITIONING.md). This project is the narrow, dependency-free
answer to one question, not the only answer.

## Citation notes

- "State of MCP Security 2026" is a colliding title. The page above is
  Pipelock's vendor survey; an unrelated offline scan report of the same name
  is at
  [agent-audit-kit](https://github.com/sattyamjjain/agent-audit-kit/blob/main/research/state-of-mcp-2026/REPORT.md)
  (2,303 public server configs; 50.6% of remote servers without auth).
- `media.defense.gov` and `nsa.gov` return HTTP 403 to automated fetches (the
  NSA file serves fine in a browser); `securityboulevard.com` shows an
  interstitial to bots and opens normally in a browser.
