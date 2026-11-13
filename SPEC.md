# mcp-attest specification

Version 1. Two documents: a **policy** (intent) and a **trace** (observation).
`attest check` compares them.

## 1. Policy

A JSON object.

```jsonc
{
  "version": 1,                      // integer, currently 1
  "default_decision": "deny",        // "deny" | "allow" — applies to unknown clients and unlisted tools
  "clients": {
    "<client id>": {
      "tools": {
        "allow": ["tool__name"],     // exact names, or ["*"]
        "deny":  ["tool__name"],     // exact names, or ["*"]
        "conditional": [
          {
            "tool": "tool__name",
            "allow_when": { "<arg>": <condition> },
            "action": "allow" | "deny",
            "reason": "free text"
          }
        ]
      },
      "egress_hosts": ["host.example.com"]
    }
  },
  "gateway": {
    "mode": "routed",                // informational
    "fail_closed": true,            // false ⇒ finding C5
    "passthrough_credentials": false // true ⇒ finding C4
  },
  "receipts": {
    "required": true,
    "key_env": "MCP_ATTEST_KEY"
  }
}
```

### Decision order

For a call `(client, tool, args)`:

1. Any `conditional` rule whose `tool` matches and whose `allow_when` matches → its `action`.
2. `deny` list contains the tool (or `*`) → `deny`.
3. `allow` list contains the tool (or `*`) → `allow`.
4. The client has no allowlist at all → `allow` (this is finding C1).
5. Otherwise → `default_decision`.

Conditional rules are evaluated first because they are the most specific
statement in the policy: they exist to carve an exception out of a blanket
allow or deny.

### Conditions

`allow_when` maps an argument name to a condition.

| Form | Meaning |
|------|---------|
| `"value"` | equality |
| `"dir/"` (trailing slash) | prefix match |
| `"*.md"` (contains `*`) | shell-style glob |
| `{"eq": v}` | equality |
| `{"not_eq": v}` | inequality |
| `{"starts_with": s}` | string prefix |
| `{"ends_with": s}` | string suffix |
| `{"contains": s}` | substring |
| `{"in": [...]}` / `{"not_in": [...]}` | membership |
| `{"gt"/"gte"/"lt"/"lte": n}` | numeric comparison |
| `{"glob": s}` | shell-style glob |
| `{"regex": s}` | regular expression |

All conditions of a rule must match (logical AND).

## 2. Trace

Newline-delimited JSON. One event per line. Lines that are blank, comments
(`#`) or unparsable are skipped with a warning on stderr.

### `tools_list`

```jsonc
{"type":"tools_list","actor":"ci-bot","ts":"2026-11-13T10:00:00Z",
 "tools":[{"name":"fs__read_file","description_sha256":"a1b2…"}]}
```

`description_sha256` is optional. When present, two listings of the same
`(actor, tool)` with different hashes produce finding C9.

### `tool_call`

```jsonc
{"type":"tool_call","actor":"ci-bot","tool":"fs__read_file",
 "args":{"path":"/srv/README.md"},
 "decision":"allow" | "deny",
 "upstream": true | false,
 "reason":"free text",
 "ts":"2026-11-13T10:00:01Z"}
```

`upstream` records whether the call actually reached the server behind the
gateway. `reason` is used by C5 to detect a fail-open: a call allowed with a
reason mentioning a policy error, a scanner failure or a timeout.

### `client_servers`

```jsonc
{"type":"client_servers","client":"claude-code","servers":["fs","git"]}
```

Servers configured on a client. Compared against `gateway_route` to produce
finding C7.

### `gateway_route`

```jsonc
{"type":"gateway_route","server":"fs","tools":["read_file","list_directory"]}
```

### `receipt`

```jsonc
{"type":"receipt","id":"r000001","prev":"<hash of previous receipt, or 64 zeros>",
 "body":{"ts":"…","actor":"…","tool":"…","args_digest":"…","decision":"allow","upstream":true},
 "hash":"<sha256 of prev|canonical(body)>","sig":"<hmac-sha256 of hash>"}
```

`body.args_digest` is `sha256(canonical(args))` where canonical JSON is
`json.dumps(obj, sort_keys=True, separators=(",",":"))`.

## 3. Rules and severities

| ID | Severity when violated |
|----|------------------------|
| C1 | critical |
| C2 | critical |
| C3 | high |
| C4 | high (critical if observed in the trace) |
| C5 | high (critical if observed in the trace) |
| C6 | critical (policy denies, gateway allowed) / low (gateway stricter than policy) |
| C7 | high |
| C8 | critical (broken chain) / high (missing receipts) / medium (short chain) |
| C9 | critical |

`attest check` exits `1` when at least one critical or high finding exists
(`--strict` also counts medium), `2` on bad input, `0` otherwise.

## 4. Receipt chain

For each allowed call, in trace order:

```
body     = {ts, actor, tool, args_digest, decision, upstream}
hash     = sha256(prev + "|" + canonical(body))
prev_0   = "0" * 64
prev_i+1 = hash_i
sig      = HMAC-SHA256(key, hash)   # only when a key is configured
```

Verification recomputes each hash from the previous one and compares
signatures when a key is supplied.

## 5. Non-goals

`mcp-attest` deliberately does not:

- sit in the request path or proxy traffic;
- evaluate model prompts or classify content;
- maintain state between runs;
- send anything over the network.

It reads evidence that other tools produced.
