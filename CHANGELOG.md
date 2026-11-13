# Changelog

## Unreleased

### Added

- Nothing yet: the next release starts from the 0.1.4 line.


All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
