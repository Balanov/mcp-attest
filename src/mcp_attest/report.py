"""How a run is reported: to a person, to a pipeline, or to a code scanner.

Three shapes, one source of truth: a human table, a JSON document that a
pipeline can diff, and SARIF 2.1.0 so the findings land in GitHub code
scanning next to the rest of the repository's security results.
"""

from __future__ import annotations

import json
from typing import Any

from .checks import Finding
from .conformance import ConformanceResult
from .policy import CRITICAL, HIGH, INFO, LOW, MEDIUM
from .rules import RULES

SEVERITY_BADGE = {
    "critical": "!!",
    "high": "! ",
    "medium": "~ ",
    "low": ". ",
    "info": "  ",
}

SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def print_findings(findings: list[Finding], as_json: bool) -> None:
    if as_json:
        print(json.dumps([f.to_dict() for f in findings], indent=2, ensure_ascii=False))
        return
    if not findings:
        print("no findings: the server did what the policy says")
        return
    for finding in findings:
        badge = SEVERITY_BADGE.get(finding.severity, "  ")
        print(f"{badge} [{finding.severity.upper():8}] {finding.check} {finding.title}")
        print(f"          {finding.detail}")
        print(f"          fix: {finding.fix}")
        print()


def print_result(result: ConformanceResult, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result_payload(result), indent=2, ensure_ascii=False))
        return
    print_findings(result.findings, False)
    counts = result.counts()
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "clean"
    print(f"summary: {summary}")
    print(
        f"tested: {len(result.identities_tested)} identities, {len(result.tools)} tools, "
        f"{result.calls_made} calls"
    )
    if result.skipped:
        print(f"skipped: {len(result.skipped)}")
        for note in result.skipped[:10]:
            print(f"  - {note}")
        if len(result.skipped) > 10:
            print(f"  … and {len(result.skipped) - 10} more")


def result_payload(result: ConformanceResult) -> dict[str, Any]:
    return {
        "server": result.server_info,
        "manifest_sha256": result.manifest,
        "identities": result.identities_tested,
        "tools": [t.name for t in result.tools],
        "calls": result.calls_made,
        "summary": result.counts(),
        "findings": [f.to_dict() for f in result.findings],
        "skipped": result.skipped,
        "error": result.error,
    }


def to_sarif(result: ConformanceResult, source: str = "mcp-server") -> dict[str, Any]:
    """SARIF 2.1.0, so findings show up in GitHub code scanning."""
    from . import __version__

    used = sorted({f.check for f in result.findings})
    rules = []
    for rule_id in used:
        rule = RULES.get(rule_id)
        rules.append(
            {
                "id": rule_id,
                "name": (rule.name if rule else rule_id).replace(" ", ""),
                "shortDescription": {"text": rule.name if rule else rule_id},
                "fullDescription": {"text": rule.summary if rule else rule_id},
                "helpUri": f"https://balanov.pro/mcp-attest/rules/#{rule_id.lower()}",
                "properties": {
                    "tags": ["security", "mcp", (rule.owasp if rule else "OWASP")],
                    "owasp": rule.owasp if rule else "",
                },
            }
        )
    sarif_results = []
    for finding in result.findings:
        sarif_results.append(
            {
                "ruleId": finding.check,
                "level": SARIF_LEVEL.get(finding.severity, "note"),
                "message": {"text": f"{finding.title}. {finding.detail}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": source},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {"severity": finding.severity, "fix": finding.fix, **finding.evidence},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-attest",
                        "version": __version__,
                        "informationUri": "https://balanov.pro/mcp-attest/",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def write_sarif(result: ConformanceResult, path: str, source: str = "mcp-server") -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(to_sarif(result, source), handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for finding in findings:
        out[finding.severity] = out.get(finding.severity, 0) + 1
    return out


__all__ = [
    "CRITICAL",
    "HIGH",
    "INFO",
    "LOW",
    "MEDIUM",
    "print_findings",
    "print_result",
    "result_payload",
    "to_sarif",
    "write_sarif",
]
