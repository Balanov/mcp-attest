"""Command line interface for mcp-attest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .checks import RULES as TRACE_RULES
from .checks import Finding, run_checks, summarize
from .conformance import ConformanceResult, RunOptions, manifest_hash, run_conformance
from .evidence import bundle_to_dict, build_bundle, key_from_env, verify_bundle
from .otlp import load_otlp
from .policy import STARTER_POLICY, PolicyError, load_policy
from .receipts import build_receipts, verify_receipts
from .report import print_findings, print_result, result_payload, write_sarif
from .rules import RULES, blocking_severities, rule_catalog
from .shadow import find_shadow_paths
from .targets import parse_target
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


def _load_policy(path: str):
    try:
        return load_policy(path)
    except (OSError, PolicyError) as exc:
        raise SystemExit(f"policy error: {exc}")


def cmd_init(args: argparse.Namespace) -> int:
    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"refusing to overwrite {out} (use --force)", file=sys.stderr)
        return 2

    payload: dict[str, Any] = dict(STARTER_POLICY)
    if args.command or args.url:
        target = parse_target(args.command, args.url)
        from .client import McpSession
        from .targets import connect

        try:
            session = McpSession(connect(target), "bootstrap", timeout=target.timeout).open()
        except Exception as exc:  # noqa: BLE001
            print(f"cannot reach the server: {exc}", file=sys.stderr)
            return 2
        try:
            tools = {t.name: {"annotations": t.annotations} for t in session.tools}
            names = sorted(tools)
        finally:
            session.close()
        clients: dict[str, Any] = {}
        for name in args.identity or ["default"]:
            clients[name] = {
                "tools": {"allow": names, "deny": []},
                "identity": {"headers": {"Authorization": "Bearer ${MCP_ATTEST_TOKEN}"}},
            }
        payload = {
            "version": 1,
            "default_decision": "deny",
            "clients": clients,
            "gateway": {"mode": "routed", "fail_closed": True, "passthrough_credentials": False},
            "receipts": {"required": True, "key_env": "MCP_ATTEST_KEY"},
        }
        print(f"discovered {len(names)} tool(s): {', '.join(names)}")
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote starter policy to {out}")
    print("next: attest test --policy %s %s" % (out, _target_hint(args)))
    return 0


def _target_hint(args: argparse.Namespace) -> str:
    if getattr(args, "command", None):
        return '--command "%s"' % args.command
    if getattr(args, "url", None):
        return "--url %s" % args.url
    return "--command \"<your server>\""


def cmd_test(args: argparse.Namespace) -> int:
    policy = _load_policy(args.policy)

    try:
        target = parse_target(args.command, args.url, args.env, args.header, timeout=args.timeout)
    except ValueError as exc:
        print(f"target error: {exc}", file=sys.stderr)
        return 2

    baseline = None
    if args.baseline:
        try:
            baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"baseline error: {exc}", file=sys.stderr)
            return 2

    options = RunOptions(
        allow_unsafe=args.allow_unsafe,
        dry_run=args.dry_run,
        baseline=baseline,
        only=list(args.only or []),
        timeout=args.timeout,
    )

    try:
        result = run_conformance(target, policy, options)
    except PolicyError as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - a broken run is a usage error, not a crash
        print(f"run failed: {exc}", file=sys.stderr)
        return 2

    if result.error:
        print(f"run failed: {result.error}", file=sys.stderr)
        return 2

    if args.update_baseline:
        _write_baseline(args.update_baseline, result)
        print(f"wrote the tool baseline to {args.update_baseline}")

    if args.json:
        print(json.dumps(result_payload(result), indent=2, ensure_ascii=False))
    else:
        print_result(result, False)

    if args.sarif:
        write_sarif(result, args.sarif)
        print(f"wrote SARIF to {args.sarif}")

    if args.evidence:
        key = key_from_env(args.key_env)
        bundle = build_bundle(
            result.evidences,
            subject={
                "server": result.server_info,
                "target": target.describe(),
                "manifest_sha256": result.manifest,
                "policy_sha256": _file_digest(args.policy),
                "tools": [t.name for t in result.tools],
                "identities": result.identities_tested,
            },
            key=key,
        )
        with open(args.evidence, "w", encoding="utf-8") as handle:
            json.dump(bundle_to_dict(bundle), handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        print(f"wrote {len(result.evidences)} evidence record(s) to {args.evidence}")

    blocking = blocking_severities(args.strict)
    hit = [f for f in result.findings if f.severity in blocking]
    return 1 if hit else 0


def _file_digest(path: str) -> str:
    from .evidence import digest

    try:
        return digest(Path(path).read_text(encoding="utf-8"))
    except OSError:
        return ""


def _write_baseline(path: str, result: ConformanceResult) -> None:
    from .evidence import digest, now_iso

    tools = {
        t.name: digest(
            {"description": t.description, "inputSchema": t.input_schema, "annotations": t.annotations}
        )
        for t in sorted(result.tools, key=lambda t: t.name)
    }
    payload = {
        "version": 1,
        "created_at": now_iso(),
        "server": result.server_info,
        "manifest_sha256": manifest_hash(result.tools),
        "tools": tools,
    }
    Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"bundle error: {exc}", file=sys.stderr)
        return 2
    key = key_from_env(args.key_env)
    ok, problems = verify_bundle(bundle, key)
    records = len([r for r in bundle.get("records", []) if r.get("type") == "evidence"])
    print(f"bundle: {'ok' if ok else 'broken'} ({records} records, key={'yes' if key else 'no'})")
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    return 0 if ok else 1


def cmd_check(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
    except (OSError, PolicyError) as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        return 2
    try:
        if args.otlp:
            trace = load_otlp(args.otlp)
        else:
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

    blocking = blocking_severities(args.strict)
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
    if args.json:
        print(json.dumps({"live": rule_catalog(), "trace": [{"check": k, "rule": v} for k, v in sorted(TRACE_RULES.items())]}, indent=2))
        return 0
    print("live rules (attest test):")
    for rule in rule_catalog():
        print(f"  {rule['id']:<20} {rule['severity']:<8} {rule['owasp']:<18} {rule['name']}")
    print("")
    print("trace rules (attest check):")
    for cid, name in sorted(TRACE_RULES.items()):
        print(f"  {cid:<20} {'':<8} {'':<18} {name}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attest",
        description="Conformance and attestation harness for MCP agent access control.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_test = sub.add_parser("test", help="test a live MCP server against a policy, as every identity in it")
    p_test.add_argument("--policy", required=True, help="policy file with identities and allowlists")
    p_test.add_argument("--command", help="command that starts the server over stdio")
    p_test.add_argument("--url", help="URL of a server speaking Streamable HTTP")
    p_test.add_argument("--env", action="append", default=[], metavar="KEY=VALUE", help="extra environment for a stdio server")
    p_test.add_argument("--header", action="append", default=[], metavar="NAME: VALUE", help="extra HTTP header")
    p_test.add_argument("--baseline", help="approved tool manifest to compare against")
    p_test.add_argument("--update-baseline", metavar="PATH", help="write the current tool manifest as the baseline")
    p_test.add_argument("--allow-unsafe", action="store_true", help="also call tools that change state (use in a sandbox)")
    p_test.add_argument("--dry-run", action="store_true", help="show what would be called, send nothing")
    p_test.add_argument("--only", action="append", default=[], metavar="RULE", help="run only these rules")
    p_test.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds")
    p_test.add_argument("--json", action="store_true")
    p_test.add_argument("--sarif", metavar="PATH", help="write SARIF 2.1.0 for code scanning")
    p_test.add_argument("--evidence", metavar="PATH", help="write the signed evidence bundle")
    p_test.add_argument("--key-env", default="MCP_ATTEST_KEY", help="environment variable holding the HMAC key")
    p_test.add_argument("--strict", action="store_true", help="treat medium findings as failures")
    p_test.set_defaults(func=cmd_test)

    p_verify = sub.add_parser("verify", help="verify an evidence bundle offline")
    p_verify.add_argument("--bundle", required=True)
    p_verify.add_argument("--key-env", default="MCP_ATTEST_KEY")
    p_verify.set_defaults(func=cmd_verify)

    p_init = sub.add_parser("init", help="write a starter policy file")
    p_init.add_argument("--out", default="policy.json")
    p_init.add_argument("--force", action="store_true")
    p_init.add_argument("--command", help="discover the tools of a stdio server and scaffold a policy")
    p_init.add_argument("--url", help="discover the tools of an HTTP server and scaffold a policy")
    p_init.add_argument("--identity", action="append", default=[], help="name of an identity to scaffold (repeatable)")
    p_init.set_defaults(func=cmd_init)

    p_check = sub.add_parser("check", help="check a trace against a policy")
    p_check.add_argument("--policy", required=True)
    source = p_check.add_mutually_exclusive_group(required=True)
    source.add_argument("--trace", help="newline-delimited JSON trace")
    source.add_argument("--otlp", metavar="PATH", help="read the trace from an OpenTelemetry export")
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
