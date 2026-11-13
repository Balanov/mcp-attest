# Launch plan — mcp-attest v0.1.0

The goal of this launch is **market adoption, not a sale**. Nothing here asks
anyone to buy anything. The product is designed so that a buyer arrives on
their own once it is embedded in a pipeline someone depends on.

---

## 1. The positioning in one sentence

> Your MCP gateway can say a policy is enforced. `mcp-attest` shows you whether
> it is, from the trace you already have.

## 2. Why this gets picked up rather than admired

| Question a user asks | Answer in this product |
|---|---|
| Does it cost me anything to try? | `pipx install mcp-attest`, no account, no network, 30 seconds |
| Does it sit in my path? | No — it reads a trace. It cannot break production |
| Does it need my credentials? | No |
| Does it work with my gateway? | It reads JSONL — any proxy, harness or CI step can emit it |
| Where does it live afterwards? | A CI step that fails the build on a real finding |
| Who else uses it? | The GitHub Action runs in *your* repo; the badge is the distribution |

The adoption loop is the CI action: a user installs it, wires one step, gets a
green/red badge, and the pipeline then depends on it. That is a dependency, and
dependencies are what acquirers ask about.

## 3. Sequence

**Step 0 — before anything public (2 days)**

1. `pip install build && python -m build` → check the sdist and wheel.
2. Tag `v0.1.0`, push, let the release workflow publish to PyPI. Verify
   `pipx install mcp-attest` from a clean machine.
3. Commit `examples/policy.json` and `examples/session.jsonl` and make sure the
   README demo output is exactly what the tool prints.
4. Record a 40-second terminal recording of `attest check` on the example
   session — no voiceover, real output, real speed.

**Step 1 — the surfaces that make it installable (week 1)**

5. GitHub Action published and tagged `v0`.
6. A `POST` install snippet that also works with `uvx`.
7. A short GIF at the top of the README (terminal recording is fine).
8. MCP registry submission — publish the checker as an MCP server so agent
   clients can run it themselves. Check the current registry URL before
   submitting; this is the channel where the audience is already agent-shaped.

**Step 2 — the launch (week 2, one shot each)**

9. **Show HN** — post the product with the story of how the C6 failure mode
   was found. Rules: do not use LLM-written filler, do not ask for upvotes,
   post at a time when the author can answer comments for two hours, and do
   not repost more than once or twice a year. A technical audience rewards a
   specific failure, not a launch announcement.
10. **Dev.to / personal blog** — the long version: "we thought our MCP policy
    was enforced. Here is how we checked." This is the asset that search
    engines and agent crawlers pick up permanently.
11. **Reddit** — r/ClaudeAI, r/LocalLLaMA, r/MCP (check each subreddit's
    self-promotion rule before posting).
12. **MCP-focused newsletters and the MCP server registry** — these audiences
    are small and exactly on target.

**Step 3 — compounding (weeks 3–8)**

13. Every real finding becomes a public, anonymised test case in
    `tests/fixtures/`. This is the growth loop: each bug report becomes a
    regression case, and the regression suite is the marketing.
14. Integrations: OpenTelemetry GenAI spans, Claude Code session logs, Codex
    and Cursor transcripts. Each integration is a new reason to install.
15. A "policy conformance report" badge: a public endpoint that turns a
    repository's own `.attest/` directory into a shareable result.

## 4. The launch gate — do not contact buyers before this

The old portfolio failed because its numbers could not be verified. This
product must not repeat that. Before any outreach, the Signal Engine must
report for `Balanov/mcp-attest`:

| Signal | Threshold | Why |
|---|---|---|
| `audience.verdict` | `organic-like` or `mixed` | campaign-like stars are a liability, not an asset |
| `star_churn.removed_share` | < 0.2 | stars must survive a week without being reaped |
| `fan_concentration` | < 0.15 | the audience must not be the same people everywhere |
| PyPI monthly downloads | ≥ 300 | this is the metric buyers quote ("monthly downloads") |
| Watchers | ≥ 50 | the list a buyer scans before reaching out |
| Forks | ≥ 10 | third-party use, not bookmarks |
| CI installs (Action runs) | ≥ 20 in 30 days | the adoption that actually matters |
| Reproducible finding | ≥ 3 external reports of a real C6/C9 catch | proof the product finds real things |

`node cli.js --owner Balanov` with `mcp-attest` added to the tracked portfolio
produces the first six rows automatically.

## 5. Who buys this, and why

This is not a product sold by pitching. It is a product that lands in an
existing procurement conversation. The buyers already in market:

| Buyer type | Why they need it | Price shape |
|---|---|---|
| MCP gateway / policy vendors (agentgateway, Bifrost, Runlayer, Lasso, Obot, Docker MCP Gateway, gh-aw-mcpg) | They sell enforcement; they need proof it works, and a conformance suite is a product feature and a sales asset | This is the classic "picked up by a platform" asset |
| Agent platforms with an enterprise tier (Cloudflare, WorkOS, Atlassian, Salesforce Agentforce, ServiceNow) | Enterprise security reviews ask for evidence that agent access is controlled and logged | Licence + support |
| AI security vendors (Snyk, Datadog, Sentry, Invariant Labs) | Tool poisoning and shadow MCP are their category; a conformance harness is the missing QA layer | Acquisition candidate |
| Regulated industries' platform teams | CISA/DoD guidance and EU AI Act logging obligations are procurement requirements | Licence + support, annual |
| Standards bodies and certification regimes | A conformance suite is how a spec becomes enforceable | Consulting/licence |

Price shape for an OSS asset with no revenue but real adoption: the researched
range for a pre-revenue OSS asset is $5k–25k; a tool with CI installs inside
other companies' pipelines and a buyer-story ("your enforcement is unverified")
sits at the top of that range, $20–150k, with a support or earnout component.

## 6. What not to do

- **No bought stars, no star exchange, no coordinated clusters.** The engine
  measures this and the buyer measures it too; on the old portfolio it cost
  more than it bought. Organic adoption of a security tool comes from people
  who actually hit a C6 finding.
- **No "contact me to sell" framing on the landing page.** The product should
  look like a tool, and the sale should happen later, in a procurement
  conversation the buyer opens.
- **Do not market the MCP-security market size.** Market the specific failure:
  a rule that was accepted and never enforced.
- **Do not fork the existing portfolio into the launch.** `mcp-attest` is a new
  asset with its own audience. Mentioning the other projects is optional and
  comes after the product proves itself.

## 7. What "the market picked it up" looks like

By week 8, one of these is true:

- a third-party repository uses the GitHub Action in CI;
- an external issue reports a real finding the tool caught;
- PyPI downloads pass 1,000/month;
- a maintainer of an MCP gateway links to it as their conformance suite;
- someone asks for a policy format extension (a strong signal that it is in
  use).

Only after one of those does the acquisition conversation become credible —
and even then it starts with the buyer, not with us.
