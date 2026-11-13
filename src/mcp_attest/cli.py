"""Command line interface for mcp-attest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .checks import RULES, Finding, run_checks, summarize
from .policy import STARTER_POLICY, PolicyError, load_policy
from .receipts import build_receipts, key_from_env, verify_receipts
from .shadow import find_shadow_paths
from .trace import load_trace, write_trace

SEVERITY_BADGE = {
    "critical": "!!",
    "high": "! ",
    "medium": "~ ",
    "low": ". ",
    "info": "  ",
}


def _print_findings(findings: list[Finding], as_json: bool) -> None:
    if as_json:
        print(json.dumps([f.to_dict() for f in findings], indent=2, ensure_ascii=False))
        return
    if not findings:
        print("no findings: the policy and the observed behaviour agree")
        return
    for f in findings:
        print(f"{SEVERITY_BADGE.get(f.severity, '  ')} [{f.severity.upper():8}] {f.check} {f.title}")
        print(f"          {f.detail}")
        print(f"          fix: {f.fix}")
        print()


def cmd_init(args: argparse.Namespace) -> int:
    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"refusing to overwrite {out} (use --force)", file=sys.stderr)
        return 2
    out.write_text(json.dumps(STARTER_POLICY, indent=2) + "\n", encoding="utf-8")
    print(f"wrote starter policy to {out}")
    print("next: attest check --policy %s --trace trace.jsonl" % out)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
    except (OSError, PolicyError) as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        return 2
    try:
        trace = load_trace(args.trace)
    except OSError as exc:
        print(f"trace error: {exc}", file=sys.stderr)
        return 2

    findings = run_checks(policy, trace)

    for warning in trace.warnings:
        print(f"trace warning: {warning}", file=sys.stderr)

    _print_findings(findings, args.json)

    counts = summarize(findings)
    if not args.json:
        summary_text = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "clean"
        print(f"summary: {summary_text}")

    blocking = {"critical", "high"}
    if args.strict:
        blocking = {"critical", "high", "medium"}
    hit = [f for f in findings if f.severity in blocking]
    return 1 if hit else 0


def cmd_receipts(args: argparse.Namespace) -> int:
    try:
        trace = load_trace(args.trace)
    except OSError as exc:
        print(f"trace error: {exc}", file=sys.stderr)
        return 2

    calls = [c for c in trace.tool_calls if c.decision == "allow"]
    key = key_from_env(args.key_env)
    receipts = build_receipts(calls, key)
    events = [r for r in receipts]

    if args.out:
        write_trace(args.out, events)
        print(f"wrote {len(events)} receipt(s) to {args.out}")
    else:
        for r in events:
            print(json.dumps(r, sort_keys=True, separators=(",", ":")))

    ok, problems = verify_receipts(receipts, key)
    print(f"chain: {'ok' if ok else 'broken'} ({len(receipts)} receipts, key={'yes' if key else 'no'})")
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    return 0 if ok else 1


def cmd_shadow(args: argparse.Namespace) -> int:
    try:
        trace = load_trace(args.trace)
    except OSError as exc:
        print(f"trace error: {exc}", file=sys.stderr)
        return 2
    paths = find_shadow_paths(trace)
    if args.json:
        print(json.dumps([p.to_dict() for p in paths], indent=2, ensure_ascii=False))
    else:
        if not paths:
            print("no shadow paths: every configured server is routed through the gateway")
        for p in paths:
            print(f"!  {p.client} -> {p.server}: {p.reason}")
    return 1 if paths else 0


def cmd_rules(args: argparse.Namespace) -> int:
    payload: list[dict[str, Any]] = [{"check": cid, "rule": name} for cid, name in sorted(RULES.items())]
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for item in payload:
            print(f"{item['check']}  {item['rule']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attest",
        description="Conformance and attestation harness for MCP agent access control.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="write a starter policy file")
    p_init.add_argument("--out", default="policy.json")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=cmd_init)

    p_check = sub.add_parser("check", help="check a trace against a policy")
    p_check.add_argument("--policy", required=True)
    p_check.add_argument("--trace", required=True)
    p_check.add_argument("--json", action="store_true")
    p_check.add_argument("--strict", action="store_true", help="treat medium findings as failures")
    p_check.set_defaults(func=cmd_check)

    p_receipts = sub.add_parser("receipts", help="build and verify a hash-chained receipt trail")
    p_receipts.add_argument("--trace", required=True)
    p_receipts.add_argument("--out")
    p_receipts.add_argument("--key-env", default="MCP_ATTEST_KEY")
    p_receipts.set_defaults(func=cmd_receipts)

    p_shadow = sub.add_parser("shadow", help="list paths that bypass the control point")
    p_shadow.add_argument("--trace", required=True)
    p_shadow.add_argument("--json", action="store_true")
    p_shadow.set_defaults(func=cmd_shadow)

    p_rules = sub.add_parser("rules", help="list the enforced rules")
    p_rules.add_argument("--json", action="store_true")
    p_rules.set_defaults(func=cmd_rules)

    return parser


def _configure_output() -> None:
    """Findings contain em dashes, so a legacy console code page must not crash the run."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


def main(argv: list[str] | None = None) -> int:
    _configure_output()
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
