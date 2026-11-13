# Why this exists — research notes

Evidence behind `mcp-attest`, with sources. The positioning and the honest
comparison with other tools live in [POSITIONING.md](POSITIONING.md).

Every quote was checked against its source on 2026-11-14. Every number carries
its denominator.

## How the direction was chosen

The first version of this product was an offline auditor: it compared a
policy file against a recorded trace. That niche is occupied —
[agent-strace](https://pypi.org/project/agent-strace/),
[mcpsnoop](https://github.com/kerlenton/mcpsnoop),
[mcp-conformance](https://github.com/tomtom215/mcp-conformance),
[mcp-traceguard](https://github.com/tiempo0206/mcp-traceguard),
[assay](https://crates.io/crates/assay-policy) and
[snulbug](https://pypi.org/project/snulbug/) all judge recorded MCP sessions,
and several of them are older and better documented than that version was.

A wider sweep on 2026-11-14 found the live-testing niche is occupied too:
[mcp-assert](https://github.com/blackwell-systems/mcp-assert) (26★),
[mcp-fence](https://github.com/DaoyuanLi2816/mcp-fence) (37★),
[mcp-server-fuzzer](https://github.com/tavric-labs/mcp-server-fuzzer) (46★),
[mcp-fuzz](https://github.com/shriramkv/mcp-fuzz) (19★),
[mcpsec](https://github.com/manthanghasadiya/mcpsec) (26★),
[MCTS](https://github.com/MCP-Audit/MCTS) (31★) and
[OpenTrustBench](https://github.com/eulogik/OpenTrustBench) (14★) all point at
a live server, and
[promptfoo](https://www.promptfoo.dev/docs/red-team/mcp-security-testing/)
and [MCP-Scan](https://github.com/invariantlabs-ai/mcp-scan) cover red
teaming and poisoning.

So the direction was chosen by reading the standard rather than by taste. The
[OWASP MCP Security Testing Guide](https://github.com/OWASP/MCP-Security-Testing-Guide)
holds 79 tests and lists a minimum automated test set; two of its eight
categories have no tool:

> "**Authorization matrix:** every tool, role, scope, tenant, object, and
> read/write boundary, including valid IDs owned by another user."

> "**OAuth tests:** wrong audience, issuer, resource, scope, signature,
> expiry, redirect URI, `state`, and PKCE verifier; token passthrough must
> fail."

and Appendix F names the missing category:

> "**Policy-as-code test harness** | Asserts allow/deny decisions against the
> documented policy, with stable reason codes | `GOV`, `GW`, `AUTHZ`"

That is what this product is.

## The documented failure

In a detailed evaluation of agentgateway published in October 2026
([kuberneteslab.dev](https://kuberneteslab.dev/en/blog/agentgateway-mcp-enforcement/)),
an argument-conditioned policy "was reported as accepted and still did not
enforce what it said", and the conclusion was that "turning a policy on is
not the end of the job: send real calls and check".

The OWASP guide says the same about where the test has to happen:

> "Exercise the actual transport and JSON-RPC handler, not only the policy
> function. A secure policy that is bypassed by a second handler is not
> secure."

> "Security controls should be executable tests, not only checklist items."

[Pipelock's State of MCP Security 2026](https://pipelab.org/blog/state-of-mcp-security-2026/)
adds the half that gateways cannot see: "Gateways only protect the servers
they route. An agent calling an MCP server outside the gateway is
invisible." *(Vendor survey; the numbers below come from independent scans.)*

## The exposure

- **No authentication.** 195 of 514 publicly reachable MCP servers (38%)
  expose tools with no authentication —
  [securityboulevard.com](https://securityboulevard.com/2026/11/why-mcp-security-disclosure-is-broken-and-what-the-industry-needs/)
  · [aminrj.com](https://aminrj.com/posts/mcp-security-after-1year/).
- **Growth.** 492 exposed servers (July 2025) → 1,467 (April 2026), 74% on
  major cloud providers —
  [Trend Micro](https://www.trendaisecurity.com/en-us/resources-insights/deep-research/update-on-exposed-mcp-servers-the-threat-widens-to-the-cloud).
- **Production reality.** Censys counted 21,000+ publicly accessible MCP
  endpoints by May 2026; a study of 640 confirmed production servers found
  91.8% without OAuth and 687 tool instances exposing shell execution with
  no access control — [arXiv 2608.00150](https://arxiv.org/html/2608.00150).
- **Official SDKs.** A design flaw in the stdio transport of the official
  MCP SDKs was estimated to affect ~200,000 instances across 150M+ package
  downloads (April 2026, OX Security) —
  [vicytech.com](https://www.vicytech.com/blog/mcp-hacking-attack-techniques-2026).
- **CVE volume.** 30 CVEs against MCP servers in the ecosystem's first year
  — [aminrj.com](https://aminrj.com/posts/mcp-security-after-1year/).
- **Real-world compromise.** April 2026, "Comment and Control" (Johns
  Hopkins): a poisoned GitHub pull request title hijacked Claude Code,
  Gemini CLI and GitHub Copilot and exfiltrated GitHub Actions secrets. The
  vendors paid bounties and issued no CVEs —
  [ai-hacking.cyberchaos.nl](https://ai-hacking.cyberchaos.nl/incidents).
- **Regulatory guidance.** NSA/CISA, *MCP: Security Design Considerations*
  (June 2026) asks for logs that capture "a traceable sequence of actions
  across sessions" with "cryptographic hashes of results or output" —
  [nsa.gov](https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf).

## What the market actually pays for

PyPI monthly downloads, measured 2026-11-14:

| Package | Downloads / month |
|---|---|
| `agent-strace` | 3,170 |
| `mcp-scan` | 2,981 |
| `snulbug` | 761 |
| `mcp-fence` | 118 |

Two readings, both true: the category has real pull, and the pull sits with
the tools that live **in the traffic path** or **call a hosted model**. The
offline, deterministic half is thin — which is where this product stands.

## Why the evidence is signed

The OWASP guide is explicit about what a finding needs:

> "capture the request, the response, the identity, the timestamp, and the
> policy decision; redact secrets; record the configuration state at the time
> of the test. A finding without reproducible evidence is an opinion."

The NSA/CISA document asks for the same thing with hashes. Hence the
hash-chained, optionally HMAC-signed bundle, and `attest verify` to check it
offline.

## What this product does not claim

No claim in this repository is stronger than its source. In particular:

- there is no claim that this is the only tool that tests MCP servers;
- there is no claim of a score, a benchmark or an independent evaluation;
- every competitor listed in [POSITIONING.md](POSITIONING.md) is named with
  the thing it does better.
