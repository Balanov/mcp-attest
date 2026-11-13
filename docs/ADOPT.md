# ADOPT — sixty seconds to a first run

This is the shortest path from "we have an MCP server" to "we know whether it
enforces our access control". It assumes nothing about your stack.

## 1. Install

```sh
pipx install mcp-attest
```

## 2. Describe who may do what

```sh
attest init --command "python my_server.py" --identity alice --identity lead
```

That writes `policy.json` from the live tool list: default deny, one entry per
identity. Read it and correct the allowlists — the scaffold knows what the
tools are called, not who may call them.

## 3. Run it

```sh
export ALICE_TOKEN=...        # credentials stay in the environment
export LEAD_TOKEN=...
attest test --command "python my_server.py" --policy policy.json
```

`0` means the server did what your policy says. `1` means there is a blocking
finding, and the output says which identity reached what it should not have.

## 4. Gate the build

```yaml
- uses: Balanov/mcp-attest@v0
  with:
    policy: .attest/policy.json
    command: "python my_server.py"
    sarif: mcp-attest.sarif
```

The action fails the job on a critical or high finding and uploads the SARIF
to code scanning.

## 5. Keep the evidence

```yaml
    evidence: mcp-attest-evidence.json
```

The bundle holds one record per call, hash-chained, and signed with
HMAC-SHA256 when `MCP_ATTEST_KEY` is set. Anyone can check it offline:

```sh
attest verify --bundle mcp-attest-evidence.json
```

## If your server uses OAuth

Add an `oauth` block to the policy: issuer, audience, the authorization
endpoint, the registered redirect URI, the resource, and the scope each tool
needs. Point `signing_key_env` at the HS256 signing key of your test
environment and the claim-level probes join the run.

```json
"oauth": {
  "issuer": "https://auth.example.com/",
  "audience": "mcp://orders",
  "signing_key_env": "MCP_ATTEST_OAUTH_KEY",
  "authorization_endpoint": "https://mcp.example.com/authorize",
  "redirect_uri": "https://client.example.com/callback",
  "resource": "https://mcp.example.com/mcp",
  "required_scopes": { "refund_order": "orders:write" }
}
```

## If you already export OpenTelemetry

```sh
attest check --policy policy.json --otlp otel-export.json
```

The same policy, applied to the spans you already produce.

## If another team runs the harness

```sh
attest suite export --policy policy.json --out suite.json --name orders-authorization
```

The suite is a portable document with a published schema: who may call what,
as whom, and what must come back. Hand it over instead of the policy.

## What it will not do

It will not call a tool that changes state unless you pin its arguments or
pass `--allow-unsafe`. It will not call a model. It will not send anything to
any third party. It will not block a call — it proves what your server does.
