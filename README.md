# mcp-attest

**Prove that your MCP policy actually enforces.**

`mcp-attest` is a conformance and attestation harness for agent access control.
It takes the policy you *wrote* and the trace of what *actually happened*, and
reports every point where they disagree — including the failure modes that
gateways accept silently: a rule that was registered but never enforced, a
tool that is hidden from `tools/list` but still callable, a client that reaches
a server outside the gateway, and a tool definition that changed after it was
approved.

```bash
pipx install mcp-attest
attest init
attest check --policy policy.json --trace trace.jsonl
```

```
!! [CRITICAL] C6 Policy denies 'shell__exec' but the gateway allowed it
          Local evaluation of the policy says deny (tool is on the deny list); the
          trace records allow ('argument-conditioned rule matched'). This is the
          'policy accepted but not enforced' failure mode — a rule that is
          registered but never applied.
          fix: Replay the call against the gateway with the same arguments and fix
               the rule binding, then add this call as a regression case in CI.

!! [CRITICAL] C9 Tool 'fs__read_file' changed after it was listed
          The description hash of an already-approved tool changed between two
          listings. This is the shape of a rug pull: the tool was harmless at
          approval time.

summary: critical=7, high=6
```

Exit code is `1` when a blocking finding exists, so it works as a CI gate
without a wrapper script. The session above is `examples/session.jsonl` — run
`attest check --policy examples/policy.json --trace examples/session.jsonl` to
reproduce it.

---

## Why this exists

Gateways, policy engines and allowlists for Model Context Protocol are now
everywhere — Docker MCP Gateway, agentgateway, Bifrost, Runlayer, Lasso, Obot,
and GitHub's own `gh-aw-mcpg`. The policy language is not the problem.

The problem is that **nobody verifies the policy is enforced.** In a detailed
evaluation of agentgateway published in October 2026, an argument-conditioned
policy was "reported as accepted and still did not enforce what it said", and
the conclusion was blunt: "turning a policy on is not the end of the job — send
real calls and check."

The same evaluation found policies that were accepted and had no effect at
all. The State of MCP Security 2026 survey describes the structural gap:
"Gateways only protect the servers they route. An agent calling an MCP server
outside the gateway is invisible," and "Most gateways also do not do deep
content inspection of responses. The gateway enforces who and where, not what."

Meanwhile the threat volume is not theoretical: more than 40 CVEs against MCP
implementations were disclosed in the first four months of 2026, an estimated
200,000 servers are exposed, 38% of scanned MCP servers had no authentication
on critical endpoints, and in April 2026 researchers hijacked Claude Code, Gemini
CLI and GitHub Copilot through malicious pull-request titles — with bug bounties
paid by the vendors.

And the buyers of this category are being told the same thing. The US DoD's
Center for Security and Information Technology wrote that "without these
traceable audit logs, incident response and accountability become significantly
more difficult, especially in multi-tenant environments."

So the missing primitive is small, sharp and useful: **a harness that takes a
policy and a trace and tells you, with evidence, whether your control plane
does what you wrote down.**

`mcp-attest` is that harness. It is not a gateway, it does not sit on the hot
path, and it does not need to be trusted with your traffic — it reads what
already happened.

## What it checks

| ID | Rule | The failure it catches |
|----|------|------------------------|
| C1 | default-deny | An unset allowlist silently meaning "allow everything" |
| C2 | list/call parity | A tool hidden from `tools/list` but callable by name |
| C3 | narrowing only | A per-request control widening a client's grant |
| C4 | credential separation | The client's token replayed upstream verbatim |
| C5 | fail closed | A call allowed because the policy check errored |
| C6 | enforcement parity | The policy says deny, the gateway allowed it |
| C7 | shadow MCP | A server the agent can reach outside the gateway |
| C8 | receipt chain | Allowed calls with no verifiable receipt, or a broken chain |
| C9 | description integrity | A tool definition changed after approval (rug pull) |

C6 is the one that matters most, and it is the one no existing tool does: it
re-evaluates your policy locally against every recorded call and flags any call
whose observed decision disagrees with the policy. That catches the
"accepted but not enforced" class directly.

## Install

```bash
pipx install mcp-attest          # isolated CLI
uvx mcp-attest check --help      # one-shot
pip install mcp-attest           # into a virtualenv
```

Python 3.10+, zero runtime dependencies.

## Use it in CI

```yaml
- uses: Balanov/mcp-attest@v0
  with:
    policy: .attest/policy.json
    trace: .attest/trace.jsonl
```

The action fails the job on any critical or high finding, so "our agent policy
is enforced" becomes something the pipeline proves instead of something the
security questionnaire asks about.

## Policy format

```json
{
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
            "allow_when": { "path": { "starts_with": "./out/" } },
            "action": "allow",
            "reason": "writes are allowed only inside ./out/"
          }
        ]
      },
      "egress_hosts": ["api.internal.example.com"]
    }
  },
  "gateway": { "mode": "routed", "fail_closed": true, "passthrough_credentials": false },
  "receipts": { "required": true, "key_env": "MCP_ATTEST_KEY" }
}
```

Condition operators: `eq`, `not_eq`, `starts_with`, `ends_with`, `contains`,
`in`, `not_in`, `gt`, `gte`, `lt`, `lte`, `glob`, `regex`. A bare string ending
in `/` is a prefix; a bare string containing `*` is a glob.

## Trace format

Newline-delimited JSON, one event per line. Any proxy, agent harness or CI
step can produce it.

```jsonl
{"type":"tools_list","actor":"ci-bot","tools":[{"name":"fs__read_file","description_sha256":"a1b2…"}]}
{"type":"tool_call","actor":"ci-bot","tool":"fs__read_file","args":{"path":"/srv/README.md"},"decision":"allow","upstream":true,"reason":"tool is on the allow list"}
{"type":"client_servers","client":"claude-code","servers":["fs","git"]}
{"type":"gateway_route","server":"fs","tools":["read_file","list_directory"]}
```

Full specification: [SPEC.md](SPEC.md).

## Receipts

`attest receipts --trace trace.jsonl --out receipts.jsonl` produces a
hash-chained receipt per allowed call. Each receipt commits to the previous
one, so removing or reordering a receipt breaks the chain. With
`MCP_ATTEST_KEY` set, every receipt is additionally signed with HMAC-SHA256,
so an auditor can detect edits without access to the gateway.

```bash
export MCP_ATTEST_KEY=…
attest receipts --trace trace.jsonl --out receipts.jsonl
# chain: ok (12 receipts, key=yes)
```

This is deliberately not a PKI. It answers the question an incident responder
actually asks: *did this session really contain these calls, in this order, and
has anything been altered since?*

## Commands

| Command | Purpose |
|---------|---------|
| `attest init` | Write a starter policy |
| `attest check` | Check a trace against a policy (`--json`, `--strict`) |
| `attest receipts` | Build and verify a hash-chained receipt trail |
| `attest shadow` | List paths that bypass the control point |
| `attest rules` | List the enforced rules |

## Design principles

- **Read-only.** It never sits in the request path and never holds a credential
  for the upstream. It reads evidence.
- **Evidence over opinion.** Every finding carries the exact line, tool,
  arguments and decision that produced it.
- **Offline.** No network calls, no telemetry, no account. Traces contain
  payloads and stay where they are.
- **Exit codes, not vibes.** `0` clean, `1` blocking finding, `2` bad input.

## Development

```bash
python -m venv .venv && . .venv/Scripts/activate
pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

## License

MIT. See [LICENSE](LICENSE).
