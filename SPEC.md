# SPEC — mcp-attest

Version 1.0.0 · the specification of what the tool does on the wire, what it
records and what it decides. It is the contract; the implementation follows
it.

---

## 1. What it is

`mcp-attest` compares two things:

- **the expected side** — a policy file that says which identity may call
  which tool, with which arguments;
- **the observed side** — what a live MCP server actually did when the
  harness asked, as each identity.

Every disagreement is a finding. Every call is evidence.

The tool never enforces anything. It proves.

## 2. Transports

Both are spoken directly; no SDK is used.

### 2.1 stdio

The server is started as a child process. Messages are newline-delimited
JSON-RPC 2.0 on the child's stdin and stdout. Diagnostics are read from
stderr and discarded, so a chatty server cannot corrupt the stream.

The identity travels as environment variables, so each identity gets its own
process.

### 2.2 Streamable HTTP

`POST` to the endpoint with `Content-Type: application/json` and
`Accept: application/json, text/event-stream`. Both response shapes the
specification allows are handled: a single JSON body and an SSE stream.

`Mcp-Session-Id` is sent back when the server provides one and omitted when
it does not: the 2026-07-28 revision of the specification removed
transport-level sessions, and the harness works with both.

The identity travels as request headers.

### 2.3 Handshake

`initialize` is sent with the protocol version, empty client capabilities and
the client name and version. The server's `protocolVersion`, `capabilities`
and `serverInfo` are recorded. `notifications/initialized` follows. A failed
handshake ends the run for that identity; it is never retried silently.

`tools/list` is read to the end, following `nextCursor` up to twenty pages.
`resources/list` and `prompts/list` are attempted and are allowed to fail.

## 3. The policy file

```json
{
  "version": 1,
  "default_decision": "deny",
  "clients": {
    "alice": {
      "tools": {
        "allow": ["list_orders", "get_order"],
        "deny": ["refund_order"],
        "conditional": [
          { "tool": "refund_order", "allow_when": { "amount": { "lte": 100 } },
            "action": "allow", "reason": "small refunds are automatic" }
        ]
      },
      "identity": {
        "headers": { "Authorization": "Bearer ${ALICE_TOKEN}" },
        "env": { "MCP_ACTOR": "alice" }
      }
    }
  },
  "cases": [
    { "id": "AUTHZ-CROSS-01", "identity": "alice", "tool": "get_order",
      "args": { "order_id": "B-77" }, "expect": "deny", "reason": "belongs to bob" }
  ],
  "probes": { "get_order": { "order_id": "A-1" } },
  "gateway": { "mode": "routed", "fail_closed": true, "passthrough_credentials": false },
  "receipts": { "required": true, "key_env": "MCP_ATTEST_KEY" }
}
```

### 3.1 Decision order

For a call `(identity, tool, arguments)`:

1. a `conditional` rule whose `allow_when` matches the arguments decides, and
   its `action` and `reason` are used;
2. otherwise a `deny` entry decides deny;
3. otherwise a `*` in `allow` decides allow;
4. otherwise the tool name in `allow` decides allow;
5. otherwise the identity's `default_decision` decides.

An identity with no allowlist at all is governed by the policy's
`default_decision`, which is `deny`. An unset allowlist never means "allow
everything".

Condition operators: `eq`, `not_eq`, `starts_with`, `ends_with`, `contains`,
`in`, `not_in`, `gt`, `gte`, `lt`, `lte`, `glob`, `regex`. A bare string
ending in `/` is a prefix; a bare string containing `*` is a glob.

### 3.2 Identities

`identity.headers` and `identity.env` say how to present the identity. The
value `${VAR}` is expanded from the environment; an unset variable is an
error, never an empty header.

An identity with neither headers nor env is not presented to a server.

### 3.3 Cases and probes

`cases` are explicit expectations about one call. They exist for what a
generated probe cannot say: an identifier owned by another principal, an
amount above a threshold, a tool that must be refused for one identity.

`probes` pins the arguments for a tool. Pinning arguments is also the
operator's consent to call a tool that changes state.

## 4. Arguments

When no probe is pinned, the arguments are derived from the tool's input
schema: only the required properties, each with a value derived from its own
schema.

| Schema | Value |
|---|---|
| `default` | the default |
| `enum` | the first entry |
| `const` | the constant |
| `type: integer` / `number` | `1` |
| `type: boolean` | `false` |
| `type: array` | `[]` |
| `type: object` | `{}` |
| `format: email` | `probe@example.invalid` |
| `format: uri` / `url` | `https://example.invalid/probe` |
| `format: date-time` | `2026-01-01T00:00:00Z` |
| `format: date` | `2026-01-01` |
| `format: uuid` | `00000000-0000-4000-8000-000000000000` |
| anything else | `attest-probe`, truncated to `maxLength` |

## 5. What gets called

The default is conservative, because a conformance tool that changes state
while it audits is worse than no tool.

A tool is called when it declares `readOnlyHint: true`, or when its name
begins with a read-only verb (`get`, `list`, `read`, `search`, `find`,
`describe`, `show`, `status`, `check`, `verify`, `count`, `whoami`, `cat`,
`stat`, `info`), or when its arguments are pinned in `probes`, or when
`--allow-unsafe` is given.

Everything else is skipped, and the skip is reported. A skipped tool is never
a pass.

## 6. Observed decisions

| Observed | Meaning |
|---|---|
| `allow` | the tool ran and returned a result |
| `deny` | the call did not succeed: a JSON-RPC error, `isError: true`, or HTTP 401/403 |
| `error` | the server could not be reached, timed out, or broke the protocol |

A `deny` expectation is satisfied by `deny`. The tool did not run, which is
the property that matters. How politely the server said no is a separate
rule.

## 7. Rules

Twelve live rules, each mapped to a test in the OWASP MCP Security Testing
Guide. `attest rules` prints the catalogue.

| ID | Rule | OWASP | Severity |
|---|---|---|---|
| AT-AUTHZ-001 | policy enforced per identity | MCPSTG-AUTHZ-01 | critical |
| AT-AUTHZ-002 | cross-user objects refused | MCPSTG-AUTHZ-03 | critical |
| AT-TOKEN-001 | tokens validated | MCPSTG-AUTHN-04 | critical |
| AT-POISON-001 | no hidden instructions | MCPSTG-TOOL-01 | critical |
| AT-DRIFT-001 | no manifest drift | MCPSTG-SUPP-01 | critical |
| AT-SECRET-001 | no secrets in output | MCPSTG-SECR-01 | critical |
| AT-FAILCLOSED-001 | fail closed on invalid input | MCPSTG-CONF-01 | high |
| AT-INJECT-001 | no injected instructions in output | MCPSTG-TOOL-01 | high |
| AT-SINK-001 | guarded execution sinks | MCPSTG-TOOL-02 | high |
| AT-SCHEMA-001 | strict tool schemas | MCPSTG-TOOL-04 | medium |
| AT-APPROVAL-001 | declared risk and approval | MCPSTG-AUTHZ-02 | medium |
| AT-ERROR-001 | clean error messages | MCPSTG-CONF-03 | medium |

### 7.1 Token probes

Three probes are sent, each with an `Authorization: Bearer` header that must
be refused:

1. a malformed token;
2. the identity's real token with its last signature character changed;
3. an expired JWT with `alg: none`.

If the handshake completes with any of them, the token was accepted and the
finding is critical. The probes need an HTTP server, because on stdio the
identity travels in the environment.

### 7.2 Manifest drift

The manifest hash is a SHA-256 over the sorted list of tools with their
descriptions, input schemas and annotations. Compared against a baseline
file, a changed tool, a new tool and a removed tool are each reported.

### 7.3 Secrets

Output is scanned for AWS access keys, AWS secret keys, OpenAI and Anthropic
keys, GitHub and Slack tokens, Google API keys, JWTs, PEM private keys and
credentials embedded in URLs. The same patterns are used to redact the
evidence.

## 8. Evidence

One record per call:

```json
{
  "ts": "2026-11-14T12:00:00Z",
  "test_id": "AT-AUTHZ-001",
  "identity": "alice",
  "method": "tools/call",
  "request": { "method": "tools/call", "params": { "name": "refund_order", "arguments": {} } },
  "response": { "status": "allow", "detail": "", "error": null, "output": "" },
  "expected": "deny",
  "observed": "allow",
  "detail": "tool executed",
  "duration_ms": 3
}
```

The bundle holds the records, each committing to the previous one by hash,
and a seal over the whole set. With `MCP_ATTEST_KEY` set, every record is
also signed with HMAC-SHA256. `attest verify` recomputes the chain and the
signatures offline.

Secrets are redacted before a record is written. The bundle records the
server, the target, the manifest hash, the policy hash, the tool list and the
identities that took part.

## 9. Output and exit codes

| Code | Meaning |
|---|---|
| `0` | no finding at or above the blocking severity |
| `1` | a blocking finding exists (critical and high; medium too with `--strict`) |
| `2` | the run could not start: bad policy, bad target, unreachable server |

`--json` prints the findings and the run summary. `--sarif` writes SARIF
2.1.0 with one rule entry per rule that produced a finding.

## 10. Trace mode

`attest check --policy --trace` is unchanged since 0.1 and judges a recorded
session: `C1` default-deny, `C2` list/call parity, `C3` narrowing only,
`C4` credential separation, `C5` fail closed, `C6` enforcement parity,
`C7` shadow MCP, `C8` receipt chain, `C9` description integrity.

The trace format is newline-delimited JSON:

```jsonl
{"type":"tools_list","actor":"ci-bot","tools":[{"name":"fs__read_file","description_sha256":"a1b2"}]}
{"type":"tool_call","actor":"ci-bot","tool":"fs__read_file","args":{"path":"/srv/README.md"},"decision":"allow","upstream":true,"reason":"tool is on the allow list"}
{"type":"client_servers","client":"claude-code","servers":["fs","git"]}
{"type":"gateway_route","server":"fs","tools":["read_file","list_directory"]}
```

## 11. Safety

- The harness only calls a server the operator named.
- It writes nothing except the files it was asked to write.
- It sends nothing to any third party.
- Credentials live in the environment, not in the policy file, and are
  redacted from the evidence.
- Tools that change state are not called unless the operator asked for it.
