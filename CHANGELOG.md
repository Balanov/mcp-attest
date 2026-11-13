# Changelog

## Unreleased

### Added

- `attest check --otlp PATH` reads the trace from an OpenTelemetry export
  instead of a JSONL trace file, so a team that already emits OTel GenAI spans
  can check them against its policy without adding a second instrumentation
  path. The reader was contributed in #3; this wires it into the command line.

### Fixed

- The OTLP reader merged in #3 was only reachable as a library. `attest check`
  now accepts it, and the two sources are mutually exclusive.


All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-14

This release repoints the product. Version 0.1.x judged a recorded session
against a policy; 1.0.0 tests a live server against the policy, as every
identity in it, and produces evidence a third party can verify offline.

### Added

- `attest test` — the primary command. Connects to a live MCP server over
  stdio or Streamable HTTP, presents each identity from the policy, sends
  real calls and reports every point where the server's decision differs
  from the policy's decision.
- A JSON-RPC 2.0 client written for this tool: stdio and Streamable HTTP,
  the full `initialize` handshake, paginated `tools/list`, SSE responses and
  the `Mcp-Session-Id` header. No SDK, no dependencies.
- The authorization matrix: the policy is the expected side, the server is
  the observed side, and every identity × tool pair is compared. Arguments
  are derived from the tool's own schema.
- Policy `cases` — explicit expectations for what a generated probe cannot
  express, such as an identifier owned by another principal.
- Policy `probes` — pinned arguments per tool, which is also how an operator
  opts in to calling a tool that changes state.
- Policy `identity` — how each client presents itself, with `headers` for
  HTTP and `env` for stdio, and `${VAR}` expansion so credentials stay out
  of the file.
- Twelve live rules, each mapped to a test in the OWASP MCP Security
  Testing Guide: `AT-AUTHZ-001`, `AT-AUTHZ-002`, `AT-TOKEN-001`,
  `AT-POISON-001`, `AT-DRIFT-001`, `AT-SECRET-001`, `AT-FAILCLOSED-001`,
  `AT-INJECT-001`, `AT-SINK-001`, `AT-SCHEMA-001`, `AT-APPROVAL-001`,
  `AT-ERROR-001`.
- Token validation probes: a malformed token, a token with a tampered
  signature and an expired `alg: none` JWT.
- Tool-manifest snapshots and drift detection against an approved baseline
  (`--baseline`, `--update-baseline`).
- Evidence bundles: one record per call with request, response, identity,
  timestamp, expected decision and observed decision, secrets redacted,
  hash-chained, optionally HMAC-signed, with `attest verify` to check them
  offline.
- `--sarif` output in SARIF 2.1.0, so findings land in GitHub code
  scanning.
- `attest init --command/--url` — scaffold a policy from a live tool list.
- Example servers: `examples/servers/orders_server.py` (a vulnerable and a
  fixed variant over stdio) and `examples/servers/orders_http_server.py`
  (over Streamable HTTP, with switches for weak and missing token checks).
- The test suite now starts real MCP servers and asserts on what the
  harness finds.

### Changed

- The GitHub Action gained a `test` mode, an optional `baseline`, SARIF
  output and an evidence bundle.
- The README, the Russian README, `SPEC.md`, `docs/POSITIONING.md` and
  `docs/RESEARCH.md` were rebuilt around the new job.
- The positioning document now names the tools that appeared in this space
  since 0.1 — mcp-assert, mcp-fence, mcp-fuzz, mcp-server-fuzzer, mcpsec,
  MCTS, OpenTrustBench — and states what each does better.

### Unchanged

- `attest check`, `attest receipts`, `attest shadow` and the trace rules
  `C1`–`C9` keep their behaviour and their format.
- Zero runtime dependencies. Python 3.10+ and the standard library.

## [0.1.5] - 2026-11-14

### Added

- `docs/POSITIONING.md` — what the tool solves, the evidence with every source
  checked, the tools that already judge recorded MCP sessions, and the claims
  this project cannot make.

### Changed

- The README now states plainly that other tools already audit recorded MCP
  sessions, and says what actually makes this one different: one offline
  question, zero dependencies, no proxy, no SDK.
- Research notes: every number carries its denominator and a working link. Two
  figures were corrected — the ~200,000 instances are an SDK stdio design flaw,
  not exposed servers, and the CVE count is now cited to its source.
- The landing page attributes the survey to Pipelock and the design
  considerations to NSA/CISA, and links to the NSA mirror that does not block
  automated fetches.

## [0.1.4] - 2026-11-13

### Changed

- The readme visuals now use absolute URLs, so they render on the PyPI project
  page as well as on GitHub.

## [0.1.3] - 2026-11-13

### Changed

- The README was rebuilt around the product idea instead of the research: a hero
  diagram, a recorded demo, the nine checks in one table, and an explicit
  "what this is not" section.
- Added `docs/RESEARCH.md` — the market evidence that used to sit in the README
  now lives in one place, linked from the README.
- Added `README_RU.md` — Russian version of the README.
- Removed the stale `demo-policy.json`; `examples/policy.json` is the policy used
  by the examples and the demo.

### Added

- `docs/readme/hero.png`, `docs/readme/architecture.png` and `docs/readme/demo.gif`
  — the readme visuals, rendered from the real CLI output.

## [0.1.2] - 2026-11-13

### Changed

- The PyPI project page now points to the product page
  `https://balanov.pro/mcp-attest/` as `Homepage` and `Documentation`, so the
  package index leads to the landing page instead of the repository.
- The README links to the product page directly from the header.

## [0.1.1] - 2026-11-13

### Added

- CI and PyPI badges in the README.

### Fixed

- CLI output is forced to UTF-8, so findings containing em dashes no longer break
  on a Windows console with a legacy code page.

## [0.1.0] - 2026-11-13

### Added

- `attest init` — starter policy scaffold.
- `attest check` — conformance checks C1–C9 against a policy and a trace,
  with `--json` and `--strict` output modes and blocking exit codes.
- `attest receipts` — hash-chained, optionally HMAC-signed receipts for
  allowed calls, with chain verification.
- `attest shadow` — detection of MCP servers reachable outside the gateway.
- `attest rules` — machine-readable list of enforced rules.
- Policy condition operators: `eq`, `not_eq`, `starts_with`, `ends_with`,
  `contains`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`, `glob`, `regex`, plus
  prefix and glob shorthands.
- GitHub Action (`Balanov/mcp-attest@v0`) that fails a build on critical or
  high findings.
- Trace specification in `SPEC.md`.
