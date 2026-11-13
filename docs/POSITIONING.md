# Positioning — what this solves, the evidence, and how this compares

This file exists because the honest version is more useful than the strong
version. Every quote below was checked against its source on 2026-11-14; every
number carries its denominator.

## 1. What it solves

One failure, precisely: **a rule that was accepted and never applied.**

You wrote a policy. The gateway accepted it. But for some calls the gateway
decided differently — an argument-conditioned rule that never matched, a
per-request control that widened a client's grant, a tool that stayed callable
after it was dropped from the listing. None of that shows up in a dashboard,
because a dashboard reports what the gateway believed, not what your policy
says.

`mcp-attest` takes the two files you already have — the policy and the trace —
re-evaluates every recorded call against the policy locally, and reports each
disagreement with the exact tool, arguments and decision.

Secondary classes it catches from the same two files: a tool hidden from
`tools/list` but callable by name (C2), a server the agent reaches outside the
gateway (C7), a call allowed because the policy check itself errored (C5), a
tool definition that changed after approval (C9), a client token replayed
upstream (C4), and a broken receipt chain (C8).

**What it deliberately does not do:** prevent anything, enforce at runtime,
scan an MCP server, or stand in the request path. It is evidence, not a
control. If the answer you need is "stop the call", use a gateway. If the
answer is "prove what actually happened", use this.

## 2. The evidence, with links

**The failure mode is documented, not invented.**

- *agentgateway, own evaluation, October 2026* —
  [kuberneteslab.dev](https://kuberneteslab.dev/en/blog/agentgateway-mcp-enforcement/):
  an argument-conditioned policy "was reported as accepted and still did not
  enforce what it said, which is why I concluded that turning a policy on is not
  the end of the job: send real calls and check." The same evaluation found
  policies that were accepted and had no effect at all.
- *Pipelock, State of MCP Security 2026* —
  [pipelab.org](https://pipelab.org/blog/state-of-mcp-security-2026/):
  "Gateways only protect the servers they route. An agent calling an MCP server
  outside the gateway is invisible." and "Most gateways also do not do deep
  content inspection of responses. The gateway enforces who and where, not
  what." *(Vendor survey; the numbers below come from independent scans.)*
- *NSA / CISA — MCP: Security Design Considerations* —
  [nsa.gov mirror](https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf)
  · [media.defense.gov original](https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF):
  "Without these traceable audit logs, incident response and accountability
  become significantly more difficult, especially in multi-tenant
  environments." The same document asks for logs that capture "a traceable
  sequence of actions across sessions" with "cryptographic hashes of results or
  output".

**The surface is exposed at scale.**

- 38% of publicly reachable MCP servers expose tools with **no
  authentication**: 195 of 514 servers in a continuous scan, with a forex
  platform (45 tools), a social-media automation service and a booking system
  among them — [securityboulevard.com](https://securityboulevard.com/2026/11/why-mcp-security-disclosure-is-broken-and-what-the-industry-needs/)
  · [aminrj.com](https://aminrj.com/posts/mcp-security-after-1year/).
- Exposed servers roughly tripled in nine months: 492 (July 2025) → **1,467**
  (April 2026), 74% of them on major cloud providers —
  [Trend Micro](https://www.trendaisecurity.com/en-us/resources-insights/deep-research/update-on-exposed-mcp-servers-the-threat-widens-to-the-cloud).
- Censys telemetry counted **21,000+** publicly accessible MCP endpoints by
  May 2026; a dynamic study of 640 confirmed production servers found **91.8%**
  without OAuth and 687 tool instances exposing shell execution with no access
  control — [arXiv 2608.00150](https://arxiv.org/html/2608.00150).
- April 2026, OX Security: a design flaw in the **official MCP SDKs' stdio
  transport** affected an estimated **200,000 instances** across 150M+ package
  downloads — [vicytech.com](https://www.vicytech.com/blog/mcp-hacking-attack-techniques-2026).
- CVE volume: **30 CVEs** against MCP servers in the ecosystem's first year,
  tracked with severity and remediation status —
  [aminrj.com](https://aminrj.com/posts/mcp-security-after-1year/).
- April 2026, "Comment and Control" (Johns Hopkins, Aonan Guan and
  collaborators): a poisoned GitHub pull-request title hijacked **Claude Code,
  Gemini CLI and GitHub Copilot** and exfiltrated GitHub Actions secrets. The
  vendors paid bounties and issued no CVEs —
  [ai-hacking.cyberchaos.nl](https://ai-hacking.cyberchaos.nl/incidents) ·
  [futureagi.com](https://futureagi.com/blog/ai-agent-security-risks/).

None of these are about *tools that prove policy enforcement* — they are about
the exposure the gap sits in. That is the argument for the gap, not for this
tool in particular.

## 3. What already exists — the honest landscape

The space is not empty. These tools all exist, all work on recorded MCP
sessions, and several are more mature than this one:

| Tool | What it does | What it is not |
|---|---|---|
| [agent-strace](https://pypi.org/project/agent-strace/) | Records and replays tool calls; `audit --policy` checks a session against a policy file and exits 1 for CI | Its policy is an agent **scope** (file globs, commands, network), not an MCP tool authorization policy with per-client grants and conditional rules |
| [mcpsnoop](https://github.com/kerlenton/mcpsnoop) | "Wireshark for MCP": proxy capture, `mcpsnoop check` gates CI on captured sessions (routing mismatch, tool drift, loosened annotations, schema problems), SARIF/JUnit, a GitHub Action | Judges **protocol and session health**, not "your policy said deny" |
| [mcp-conformance](https://github.com/tomtom215/mcp-conformance) | Clause-by-clause conformance against the MCP specification over recorded traces; every check falsified by a committed violation trace | Judges the **specification**, not your authorization policy |
| [mcp-traceguard](https://github.com/tiempo0206/mcp-traceguard) | Policy checks plus baseline/drift checks, SHA-256 chained traces, replayable scenario packs, SARIF | Compares against a **baseline of what was approved**, not against your policy's decision rules |
| [assay](https://crates.io/crates/assay-policy) | Runtime policy gate, tamper-evident evidence bundles, "declared-vs-observed" conformance, offline-verifiable archives | Enforces **at runtime**; a Rust tool with its own policy format |
| [snulbug](https://pypi.org/project/snulbug/) | Replay and audit logs, **learns** a policy from observed traffic, conformance packs, blast-radius analysis | Derives policy from traffic rather than checking yours |
| [Pipelock](https://pipelab.org/) | Commercial agent firewall with receipts and compliance proof | A vendor product, not an open tool |

## 4. The claim we can actually make

**We are not the best, and we should not say we are.** This project is at
v0.1.4, has five stars, no users, no independent evaluation and no benchmark.
Several of the tools above are older, more capable and better documented.

What is true, and narrow:

1. **One question, answered offline.** Given a policy file and a JSONL trace,
   `mcp-attest` re-evaluates the policy locally and reports every call where
   the recorded decision and the re-computed decision disagree. No proxy, no
   MCP SDK, no server, no model, no API key.
2. **Zero dependencies, one install.** Python 3.10+ and the standard library.
   It runs in CI in under a second on a committed trace. The alternatives that
   judge recorded sessions ship a recorder or a proxy (mcpsnoop,
   mcp-conformance), a runtime (agent-strace, assay) or a learned policy
   (snulbug).
3. **The policy language is the one you wrote.** Per-client allow and deny
   lists, conditions on arguments, a default decision — evaluated by your
   rules, not by a baseline, a scope file or a specification clause.
4. **Evidence out of the box.** Findings carry the exact tool, arguments and
   decision; receipts are hash-chained and optionally HMAC-signed.

What is **not** true, and should not be written anywhere:

- We are not the only tool that judges recorded MCP sessions.
- We are not more thorough: nine checks against dozens in the mature tools.
- We are not more expressive: our policy language is simpler than CEL.
- We have not been evaluated by anyone but us.

If a buyer asks "why you and not mcpsnoop?", the honest answer is: if you want
to watch the wire and gate on protocol drift, use mcpsnoop; if you want to
enforce at runtime, use a gateway. Use this if you want one offline question
answered about the policy you already wrote, with nothing installed in the
path.

## 5. Sources that need care

- "State of MCP Security 2026" is a **colliding title**: the page cited above
  is Pipelock's vendor survey; an unrelated offline scan report of the same
  name exists at
  [agent-audit-kit](https://github.com/sattyamjjain/agent-audit-kit/blob/main/research/state-of-mcp-2026/REPORT.md)
  (2,303 public server configs, 50.6% remote servers without auth). Cite the
  one you actually read.
- `media.defense.gov` and `nsa.gov` return HTTP 403 to automated fetches (the
  NSA file serves fine in a browser); the same NSA/CISA PDF is the document to
  cite by title, with `nsa.gov` as the link to prefer in public documents.
- `securityboulevard.com` shows an interstitial to automated fetches and the
  article opens normally in a browser.
