<div align="center">
  <img src="https://raw.githubusercontent.com/Balanov/mcp-attest/main/docs/readme/hero.png" alt="MCP-ATTEST — the authorization conformance harness for MCP servers. One command, every identity, real calls, evidence you can hand to an auditor." width="100%">
  <p><strong>Prove that your MCP server denies what it must deny.</strong></p>
  <p>One command · every identity · real calls · twelve rules · zero dependencies · MIT</p>
  <p>
    <a href="#install">Install</a> ·
    <a href="#run-it">Run it</a> ·
    <a href="#the-rules">The rules</a> ·
    <a href="#the-policy-file">Policy</a> ·
    <a href="#evidence">Evidence</a> ·
    <a href="#use-it-in-ci">CI</a> ·
    <a href="SPEC.md">Specification</a> ·
    <a href="https://balanov.pro/mcp-attest/">Website</a> ·
    <a href="README_RU.md">Русский</a>
  </p>
  <p>
    <a href="https://github.com/Balanov/mcp-attest/actions/workflows/ci.yml"><img src="https://github.com/Balanov/mcp-attest/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
    <a href="https://github.com/Balanov/mcp-attest/releases/latest"><img src="https://img.shields.io/github/v/release/Balanov/mcp-attest" alt="Latest release"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT license"></a>
    <a href="https://pypi.org/project/mcp-attest/"><img src="https://img.shields.io/pypi/v/mcp-attest.svg?color=2fd9a6" alt="PyPI version"></a>
    <a href="https://pypi.org/project/mcp-attest/"><img src="https://img.shields.io/pypi/pyversions/mcp-attest.svg" alt="Python 3.10+"></a>
  </p>
</div>

<div align="center">
  <img src="https://raw.githubusercontent.com/Balanov/mcp-attest/main/docs/readme/demo.gif" alt="mcp-attest test output against a vulnerable MCP server: alice was allowed to call refund_order although the policy denies it, the tool description hides an instruction from the user, the ledger export returns an AWS key" width="100%">
  <p><sub>Real output from the bundled vulnerable server. Exit code 1 means a blocking finding. <a href="examples/">Examples</a> · <a href="docs/POSITIONING.md">Why this exists</a>.</sub>
</div>

`mcp-attest` tests a live MCP server against the access control you wrote. It connects as each identity in your policy, sends real calls, and reports every place where the server's decision differs from the decision your policy requires.

It is not a gateway. It cannot block anything. It proves what your server does.

## Why mcp-attest?

- **It tests the decision, not the definition.** A scanner tells you what a tool description looks like. `mcp-attest` tells you whether `alice` may call `refund_order` — by calling it, as `alice`, and looking at what came back.
- **The matrix is generated, not typed.** Write who may call what. The harness derives every identity × tool pair, derives the arguments from the schema, and compares. Adding a tool to your server does not mean rewriting the test suite.
- **Deterministic.** No model, no API key, no network beyond the server under test. The same policy and the same server give the same report every time, which is what makes it usable as a gate.
- **Evidence, not opinion.** Every call is recorded with the request, the response, the identity, the timestamp and the policy decision. The records are hash-chained and optionally HMAC-signed, so an auditor can verify the bundle offline without trusting the machine that produced it.
- **Exit codes, not vibes.** `0` clean, `1` blocking finding, `2` bad input. It is a CI gate without a wrapper script.
- **Zero dependencies.** Python 3.10+ and the standard library. It speaks JSON-RPC itself instead of pulling an SDK into your pipeline.

## Where this sits

The MCP testing space is crowded, and pretending otherwise would be dishonest. [mcp-assert](https://github.com/blackwell-systems/mcp-assert) lints, tests and fuzzes servers over real transports with YAML assertions; [mcp-fence](https://github.com/DaoyuanLi2816/mcp-fence) scans configuration, inspects and fuzzes with a Docker sandbox; [mcp-fuzz](https://github.com/shriramkv/mcp-fuzz) grades protocol robustness; [MCP-Scan](https://github.com/invariantlabs-ai/mcp-scan) scans tool metadata for poisoning; [promptfoo](https://www.promptfoo.dev/docs/red-team/mcp-security-testing/) red-teams agents and MCP servers with a model in the loop; [mcpsnoop](https://github.com/kerlenton/mcpsnoop) and [mcp-conformance](https://github.com/tomtom215/mcp-conformance) judge recorded sessions.

What none of them does is the thing the [OWASP MCP Security Testing Guide](https://github.com/OWASP/MCP-Security-Testing-Guide) puts first in its minimum automated test set: **the authorization matrix** — every tool, role, scope, tenant and object, including identifiers that belong to someone else — and **token validation**. The guide names the tool it expects as a category: *"Policy-as-code test harness — asserts allow/deny decisions against the documented policy, with stable reason codes."*

That is this product. [Full comparison, sources and the claims we cannot make](docs/POSITIONING.md).

<div align="center">
  <img src="https://raw.githubusercontent.com/Balanov/mcp-attest/main/docs/readme/architecture.png" alt="mcp-attest flow: the policy is the expected side, the live server is the observed side, the comparison produces findings, an exit code and a signed evidence bundle" width="100%">
  <p><sub>The policy is the expected side. The server is the observed side. The gap between them is the finding. <a href="SPEC.md">Full specification</a>.</sub>
</div>

**[Website](https://balanov.pro/mcp-attest/) · [Specification](SPEC.md) · [Positioning](docs/POSITIONING.md) · [Research notes](docs/RESEARCH.md) · [MIT license](LICENSE)**

## Install

```sh
pipx install mcp-attest          # isolated CLI
uvx mcp-attest test --help       # one-shot
pip install mcp-attest           # into a virtualenv
```

From source:

```sh
git clone https://github.com/Balanov/mcp-attest.git
cd mcp-attest
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

## Run it

```sh
attest init --command "python my_server.py"        # scaffold a policy from the live tools
attest test --command "python my_server.py" --policy policy.json
```

Against the bundled vulnerable server:

```text
!! [CRITICAL] AT-POISON-001 tool 'refund_order' hides an instruction in its description
          The description contains text that matches 'hides the call': 'do not tell the user'.
          A tool definition is read by the model, so this is an instruction channel that the
          user never sees.
          fix: Remove the instruction from the description. The tool's description should state
               what it does, not what the model must do.

!! [CRITICAL] AT-AUTHZ-001 'alice' was allowed to call 'refund_order'
          The policy denies 'refund_order' for this identity (tool is on the deny list), but the
          server executed the call. This is broken access control, not a policy tuning problem.
          fix: Enforce the decision inside the server's tool dispatcher, before the handler runs.

!! [CRITICAL] AT-AUTHZ-002 case AUTHZ-CROSS-01: 'alice' reached an object it must not reach
          The case expects 'get_order' to be refused for 'alice' (order B-77 belongs to bob,
          not to alice), but the server executed the call.
          fix: Check ownership of the object at the point of use, not only the role of the caller.

summary: critical=4, high=2, medium=4, low=3
tested: 2 identities, 6 tools, 12 calls
```

Exit code `1` means a blocking finding exists. `--json` prints machine-readable findings, `--sarif` writes SARIF 2.1.0 for code scanning, `--strict` treats medium findings as blocking.

| Command | Purpose |
|---|---|
| `attest test` | Test a live server against a policy, as every identity in it |
| `attest init` | Write a starter policy, optionally from the live tool list |
| `attest verify` | Verify an evidence bundle offline |
| `attest check` | Audit a recorded trace against a policy |
| `attest receipts` | Build and verify a hash-chained receipt trail |
| `attest shadow` | List the servers an agent can reach outside the gateway |
| `attest rules` | List the enforced rules |

## The rules

Live rules run against a server you point it at. Each maps to a test in the OWASP MCP Security Testing Guide.

| ID | Rule | OWASP | The failure it catches |
|---|---|---|---|
| AT-AUTHZ-001 | policy enforced per identity | MCPSTG-AUTHZ-01 | The server allows what your policy denies |
| AT-AUTHZ-002 | cross-user objects refused | MCPSTG-AUTHZ-03 | A valid identifier belonging to another principal |
| AT-TOKEN-001 | tokens validated | MCPSTG-AUTHN-04 | A malformed, tampered or expired token gets through |
| AT-POISON-001 | no hidden instructions | MCPSTG-TOOL-01 | Instructions smuggled into tool metadata |
| AT-DRIFT-001 | no manifest drift | MCPSTG-SUPP-01 | A tool added or changed after approval (rug pull) |
| AT-SECRET-001 | no secrets in output | MCPSTG-SECR-01 | A credential in the tool output |
| AT-FAILCLOSED-001 | fail closed on invalid input | MCPSTG-CONF-01 | A call executed with missing required arguments |
| AT-INJECT-001 | no injected instructions in output | MCPSTG-TOOL-01 | Instructions aimed at the model inside a tool result |
| AT-SINK-001 | guarded execution sinks | MCPSTG-TOOL-02 | Model input reaching a shell, a file or a URL |
| AT-SCHEMA-001 | strict tool schemas | MCPSTG-TOOL-04 | Untyped, unbounded or free-form arguments |
| AT-APPROVAL-001 | declared risk and approval | MCPSTG-AUTHZ-02 | A state-changing tool that declares no risk |
| AT-ERROR-001 | clean error messages | MCPSTG-CONF-03 | Stack traces and internal paths in errors |

Trace rules run against a recorded session and are unchanged since 0.1: `C1` default-deny, `C2` list/call parity, `C3` narrowing only, `C4` credential separation, `C5` fail closed, `C6` enforcement parity, `C7` shadow MCP, `C8` receipt chain, `C9` description integrity.

## The policy file

One file holds both sides of the comparison: what each identity may call, and how that identity presents itself.

```json
{
  "version": 1,
  "default_decision": "deny",
  "clients": {
    "alice": {
      "tools": {
        "allow": ["list_orders", "get_order"],
        "deny": ["refund_order"]
      },
      "identity": {
        "headers": { "Authorization": "Bearer ${ALICE_TOKEN}" }
      }
    }
  },
  "cases": [
    {
      "id": "AUTHZ-CROSS-01",
      "identity": "alice",
      "tool": "get_order",
      "args": { "order_id": "B-77" },
      "expect": "deny",
      "reason": "order B-77 belongs to bob, not to alice"
    }
  ],
  "probes": {
    "get_order": { "order_id": "A-1" }
  }
}
```

- **identity** — how to present yourself. `headers` for HTTP servers, `env` for stdio servers. `${VAR}` is expanded from the environment, so credentials never live in the file.
- **cases** — explicit expectations that a generated probe cannot express: an identifier owned by someone else, an amount above a threshold, a tool that must be refused.
- **probes** — the arguments to send for a tool. Pinning arguments is also how you opt in to calling a tool that changes state.

## Evidence

```sh
attest test --url https://mcp.example.com/mcp --policy policy.json --evidence bundle.json
attest verify --bundle bundle.json
# bundle: ok (14 records, key=yes)
```

Each record carries the request, the response, the identity, the timestamp, the expected decision and the observed decision, with anything that looks like a credential redacted. The records are hash-chained and, with `MCP_ATTEST_KEY` set, signed with HMAC-SHA256.

That is what turns "our agent policy is enforced" from a sentence in a security questionnaire into an artifact a third party can check.

## Use it in CI

```yaml
- uses: Balanov/mcp-attest@v0
  with:
    policy: .attest/policy.json
    command: "python my_server.py"
    sarif: mcp-attest.sarif
```

The action fails the job on any critical or high finding, and the SARIF output lands in code scanning next to the rest of the repository's security results.

## What mcp-attest is not

- Not a gateway, proxy or enforcement point. It cannot block a call.
- Not a scanner. It does not judge a schema or a description; it exercises a server.
- Not a model-based red team. Nothing here calls an LLM, so nothing here is non-deterministic or billable.
- Not a PKI. A hash chain and an HMAC prove order and integrity, not identity.
- Not a hosted service. No account, no telemetry, no network calls beyond the server under test.

## Development

```sh
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

The suite starts real MCP servers — one over stdio, one over HTTP, one with broken token checks — and asserts on what the harness finds. CI runs it on Python 3.10–3.13 and publishes to PyPI from a tagged release through trusted publishing, with no API token in the repository.

## License

[MIT](LICENSE). Fork it, modify it, embed it, ship it.
