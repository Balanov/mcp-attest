# Positioning — what this solves, the evidence, and how this compares

This file exists because the honest version is more useful than the strong
version. Every quote below was checked against its source on 2026-11-14;
every number carries its denominator and a date.

## 1. What it solves

One failure, precisely: **the server allows what your access control says it
must not allow.**

You wrote a policy. An identity was granted a tool. But when the tool was
actually called, the server did not check the role, did not check the owner
of the object, did not check the token — and the call went through.

No dashboard shows that. A dashboard reports what the server believed.
`mcp-attest` sends the call, as that identity, and looks at what came back.

The second failure it covers is the token: a malformed, tampered or expired
bearer that still completes the handshake.

The third is OAuth: a token that is correctly signed but meant for another
audience, another issuer or a smaller scope; a redirect URI that is not
registered; an authorization code issued without a PKCE challenge; a token that
is accepted by an upstream server it was never minted for.

## 2. Why this gap, and why now

**The gap is named by the standard, not by us.**

The [OWASP MCP Security Testing Guide](https://github.com/OWASP/MCP-Security-Testing-Guide)
holds 79 security tests for hosts, clients, servers, tools, resources,
transports, gateways and agentic workflows. Its "Security Verification"
chapter says:

> "Security controls should be executable tests, not only checklist items."

and lists the minimum automated test set, beginning with:

> "**Authorization matrix:** every tool, role, scope, tenant, object, and
> read/write boundary, including valid IDs owned by another user."

and later:

> "**OAuth tests:** wrong audience, issuer, resource, scope, signature,
> expiry, redirect URI, `state`, and PKCE verifier; token passthrough must
> fail."

Its Appendix F names the tool category the tests expect and that the market
does not yet have:

> "**Policy-as-code test harness** | Asserts allow/deny decisions against the
> documented policy, with stable reason codes | `GOV`, `GW`, `AUTHZ`"

and, in the same table:

> "MCP client utility that can send raw JSON-RPC | Reproducible
> `tools/list`, `tools/call`, `resources/read`, `prompts/get` requests
> outside the model's control | All runtime tests"

Two of the eight minimum test categories — the authorization matrix and the
token tests — have no dedicated tool. Every tool below covers conformance,
robustness, poisoning or red-teaming. None of them answers "does this server
refuse what it must refuse, for every identity", and none of them performs the
OAuth tests the guide lists in the same section.

**The same gap was reached from the other side, independently.**

The agentgateway evaluation of October 2026
([kuberneteslab.dev](https://kuberneteslab.dev/en/blog/agentgateway-mcp-enforcement/))
concludes that "turning a policy on is not the end of the job: send real
calls and check", after finding a policy that "was reported as accepted and
still did not enforce what it said".

The OWASP guide says the same thing about where to test:
"Exercise the actual transport and JSON-RPC handler, not only the policy
function. A secure policy that is bypassed by a second handler is not
secure."

**The exposure is large and growing.**

- 38% of publicly reachable MCP servers expose tools with **no
  authentication**: 195 of 514 servers in a continuous scan —
  [securityboulevard.com](https://securityboulevard.com/2026/11/why-mcp-security-disclosure-is-broken-and-what-the-industry-needs/)
  · [aminrj.com](https://aminrj.com/posts/mcp-security-after-1year/).
- Exposed servers roughly tripled in nine months: 492 (July 2025) → **1,467**
  (April 2026), 74% of them on major cloud providers —
  [Trend Micro](https://www.trendaisecurity.com/en-us/resources-insights/deep-research/update-on-exposed-mcp-servers-the-threat-widens-to-the-cloud).
- Censys telemetry counted **21,000+** publicly accessible MCP endpoints by
  May 2026; a dynamic study of 640 confirmed production servers found
  **91.8%** without OAuth and 687 tool instances exposing shell execution
  with no access control — [arXiv 2608.00150](https://arxiv.org/html/2608.00150).
- CVE volume: **30 CVEs** against MCP servers in the ecosystem's first year —
  [aminrj.com](https://aminrj.com/posts/mcp-security-after-1year/).
- April 2026, "Comment and Control" (Johns Hopkins): a poisoned GitHub pull
  request title hijacked Claude Code, Gemini CLI and GitHub Copilot. The
  vendors paid bounties and issued no CVEs —
  [ai-hacking.cyberchaos.nl](https://ai-hacking.cyberchaos.nl/incidents).

None of those numbers is about tools that prove access control. They are the
size of the hole the product stands in.

## 3. What already exists — the honest landscape

The space is crowded, and a comparison that hides that would be worthless.
Everything below was checked on 2026-11-14; star counts and download counts
are from that day.

### Live testing and fuzzing

| Tool | What it does | What it is not |
|---|---|---|
| [mcp-assert](https://github.com/blackwell-systems/mcp-assert) (26★) | Lints, tests and fuzzes servers over real stdio/SSE/HTTP with YAML assertions and 24 error codes; a GitHub Action; scanned 102 servers and reported 4,794 schema issues across 55 of them | Asserts **behaviour against your expectations**. It has no identity dimension, no policy model and no signed evidence; nothing in it is about *who* called |
| [mcp-fence](https://github.com/DaoyuanLi2816/mcp-fence) (37★) | Config and source scanning, live inspection, schema-aware fuzzing, Docker sandboxing, SARIF and HTML reports; stdio only, HTTP is static-only | Finds weak metadata and crashes. It does not test an authorization decision |
| [mcp-fuzz](https://github.com/shriramkv/mcp-fuzz) (19★) | Stdlib-only robustness harness: 17 malformed and adversarial JSON-RPC cases, graded A–F on crash resistance, responsiveness, error correctness and envelope hygiene | Judges whether the server survives bad input, not whether it enforces a policy |
| [mcp-server-fuzzer](https://github.com/tavric-labs/mcp-server-fuzzer) (46★) | Black-box security assessment for live MCP servers | No identity model, no policy comparison |
| [mcpsec](https://github.com/manthanghasadiya/mcpsec) (26★) | AI-driven dynamic protocol fuzzer for MCP, aimed at state violations and application-layer flaws | Model-driven and non-deterministic |
| [MCTS](https://github.com/MCP-Audit/MCTS) (31★) | Local-first scanner: static and live tool discovery, risk scores, JSON/SARIF/HTML | A scanner with grades, not a conformance harness |
| [OpenTrustBench](https://github.com/eulogik/OpenTrustBench) (14★) | OWASP-mapped findings, trust cards graded A–F, SARIF, CI gate | Same shape as above |

### Scanning, metadata and model-driven red teaming

| Tool | What it does | What it is not |
|---|---|---|
| [MCP-Scan](https://github.com/invariantlabs-ai/mcp-scan) | Static scan of installed servers for tool poisoning and cross-origin escalation, plus a runtime proxy; the semantic pass calls a hosted guardrail | Its strong pass needs an API key and an LLM, so results are neither offline nor deterministic |
| [agent-audit-kit](https://github.com/sattyamjjain/agent-audit-kit) (12★) | Static scanner, 501 rules across 14 categories, OWASP mapping, GitHub Action, SARIF | Static only |
| [mcp-audit](https://github.com/apisec-inc/mcp-audit) (166★) | Scans MCP client configuration for exposed secrets and shadow APIs, generates AI-BOMs | Scans configuration, not the running server |
| [promptfoo](https://www.promptfoo.dev/docs/red-team/mcp-security-testing/) (now OpenAI) | Red-teaming agents and MCP servers with 100+ attack plugins, an MCP provider and an evil MCP server | Needs a model and an API key; the result is a judgement about a model's behaviour, not a deterministic gate on a server's decision |

### Recorded sessions and runtime enforcement

| Tool | What it does | What it is not |
|---|---|---|
| [agent-strace](https://pypi.org/project/agent-strace/) | Records and replays tool calls; `audit --policy` checks a session against a policy file and exits 1 for CI | Its policy is an agent **scope** (globs, commands, network), not a per-identity tool authorization matrix; it needs traffic first |
| [mcpsnoop](https://github.com/kerlenton/mcpsnoop) | "Wireshark for MCP": proxy capture, CI gating on captured sessions, SARIF and JUnit, an Action | Judges protocol and session health, not your policy's decision |
| [mcp-conformance](https://github.com/tomtom215/mcp-conformance) | Clause-by-clause conformance against the MCP specification over recorded traces | Judges the **specification** |
| [mcp-traceguard](https://github.com/tiempo0206/mcp-traceguard) | Policy checks, baseline and drift checks, SHA-256 chained traces, replayable scenario packs, SARIF | Compares against a **baseline of what was approved**, not against your policy's decision rules |
| [assay](https://crates.io/crates/assay-policy) | Runtime policy gate, tamper-evident evidence bundles, declared-vs-observed conformance | A Rust runtime with its own policy format; enforces rather than tests |
| [snulbug](https://pypi.org/project/snulbug/) | Replays and audits logs, **learns** a policy from observed traffic, conformance packs, blast-radius analysis | Derives the policy from traffic instead of checking yours |
| [Pipelock](https://pipelab.org/) | Commercial agent firewall with receipts and compliance proof | A vendor product |

### Demand, measured

PyPI monthly downloads on 2026-11-14: `agent-strace` 3,170 · `mcp-scan` 2,981
· `snulbug` 761 · `mcp-fence` 118. `mcp-fuzz` is not published on PyPI.

Read honestly, that says two things at once: the category has real pull, and
the pull is concentrated in the tools that sit **in the traffic path** or
**call a hosted model**. The offline, deterministic half of the market is
thin.

### Our own measurement

The numbers above are third-party. We measured the same thing ourselves with
`attest posture`, which is part of this product: every ninth server of the
1,698 the official MCP registry lists with an HTTP remote, measured with three
well-formed requests and no tool call at all.

Of 189 servers measured, 177 answered the handshake and **81 of them — 45.8% —
opened a session with no credentials at all**. 55 of the 78 that returned a
manifest expose a tool that reaches a shell, a file, a URL or a database. The
method and the numbers are in
[docs/posture/2026-11-14.md](posture/2026-11-14.md), and the scan is
reproducible with one command.

That is consistent with the third-party figures above, measured differently. It
is not a claim of superiority over anyone: it is the size of the hole the
product stands in, measured with the product itself.

## 4. The claim we can actually make

**We are not the best, and we should not say we are.** This project is at
v1.2.0, has a handful of stars, no users, no independent evaluation and no
benchmark. mcp-assert is older, better documented and has production
adoption we cannot match. promptfoo has a company's distribution behind it.

What is true, and narrow:

1. **The authorization matrix, against a live server.** Write who may call
   what; the harness derives every identity × tool pair, derives the
   arguments from the schema, sends the call as that identity and compares
   the server's decision with the policy's. Nothing else in the list does
   this.
2. **Cases for what a generated probe cannot say.** An identifier belonging to
   another principal, an amount above a threshold, a tool that must be
   refused — the cross-user test the OWASP guide puts first among the
   critical ones.
3. **Token validation.** A malformed token, a token with a tampered
   signature and an expired `alg: none` JWT are sent and must be refused.
4. **Deterministic and offline.** No model, no API key, no network beyond the
   server under test. The same policy and the same server give the same
   report every time, which is what makes it usable as a gate.
5. **Evidence a third party can check.** Every call is recorded with request,
   response, identity, timestamp, expected decision and observed decision;
   the records are hash-chained and optionally HMAC-signed, and `attest
   verify` checks them offline without trusting the machine that produced
   them.
6. **Nothing in the request path.** It cannot block a call. If the answer
   needed is "stop the call", use a gateway.
7. **The same policy, two inputs.** `attest test` sends the calls to a live
   server; `attest check --otlp` judges an OpenTelemetry export you already
   produce, against the same policy file. A team that already instruments its
   agent with OTel does not need a second instrumentation path to get an
   answer.
8. **The OAuth half of the standard.** Wrong audience, wrong issuer, wrong
   scope, tampered signature, expiry, `alg: none`, protected resource
   metadata, PKCE, redirect URI validation, state binding, token passthrough.
   Twelve checks the OWASP guide lists next to the authorization matrix, and
   no tool in the list above performs them.
9. **A suite other harnesses can run.** The `mcp-attest-suite` format and its
   schema are published, so the expectations are not locked inside this tool.
   A team that prefers another harness can still write the suite once.

What is **not** true, and should not be written anywhere:

- We are not more thorough than mcp-assert or mcp-fence; they cover
  conformance and robustness in more depth.
- We are not a scanner: we do not judge a schema or a description for its own
  sake.
- We are not a red team: there is no model in the loop, so there is no
  attempt to make an agent misbehave.
- We have not been evaluated by anyone but us.
- Our posture measurement is not a disclosure: it names no host, notifies
  nobody, and covers a systematic sample of the registry rather than the
  internet.

If a buyer asks "why you and not mcp-assert?", the honest answer is: if you
want to know whether your server returns the right answer, use mcp-assert. If
you want to know whether your **access control** holds for every identity, and
you want the evidence to be signed and reproducible, use this.

## 5. Sources that need care

- "State of MCP Security 2026" is a **colliding title**: the page cited above
  is Pipelock's vendor survey; an unrelated offline scan report of the same
  name exists at
  [agent-audit-kit](https://github.com/sattyamjjain/agent-audit-kit/blob/main/research/state-of-mcp-2026/REPORT.md)
  (2,303 public server configs, 50.6% of remote servers without auth). Cite
  the one you actually read.
- `media.defense.gov` and `nsa.gov` return HTTP 403 to automated fetches; the
  NSA file serves fine in a browser. Cite the document by title with
  `nsa.gov` as the link to prefer.
- `securityboulevard.com` shows an interstitial to automated fetches and the
  article opens normally in a browser.
- Star counts and download counts move. The ones quoted here are dated
  2026-11-14 and should be re-checked before they are used in a sales
  conversation.
