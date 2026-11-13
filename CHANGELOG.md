# Changelog

## Unreleased

### Added

- Initial public release: nine conformance checks, hash-chained receipts, shadow-path detection and the CI action.


All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
