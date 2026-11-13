"""Conformance tests: the harness against real servers, over both transports."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_attest.conformance import RunOptions, manifest_hash, run_conformance  # noqa: E402
from mcp_attest.evidence import build_bundle, redact, verify_bundle  # noqa: E402
from mcp_attest.policy import load_policy  # noqa: E402
from mcp_attest.targets import parse_target  # noqa: E402

SERVER = ROOT / "examples" / "servers" / "orders_server.py"
HTTP_SERVER = ROOT / "examples" / "servers" / "orders_http_server.py"
STDIO_POLICY = ROOT / "examples" / "live-policy.json"
HTTP_POLICY = ROOT / "examples" / "live-policy-http.json"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def stdio_target(variant: str):
    return parse_target(f'"{sys.executable}" "{SERVER}" --variant {variant}', None, timeout=15.0)


class StdioConformanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_policy(STDIO_POLICY)

    def run_server(self, variant: str):
        return run_conformance(stdio_target(variant), self.policy, RunOptions(timeout=15.0))

    def test_vulnerable_server_is_reported(self) -> None:
        result = self.run_server("vulnerable")
        checks = {f.check for f in result.findings}
        self.assertIn("AT-AUTHZ-001", checks, "the denied refund was allowed")
        self.assertIn("AT-AUTHZ-002", checks, "the cross-user case was allowed")
        self.assertIn("AT-POISON-001", checks, "the hidden instruction was missed")
        self.assertIn("AT-SECRET-001", checks, "the leaked key was missed")
        critical = [f for f in result.findings if f.severity == "critical"]
        self.assertTrue(critical)

    def test_secure_server_is_clean(self) -> None:
        result = self.run_server("secure")
        blocking = [f for f in result.findings if f.severity in ("critical", "high")]
        self.assertEqual([], [(f.check, f.title) for f in blocking])
        self.assertTrue(result.calls_made > 0)

    def test_matrix_covers_every_identity(self) -> None:
        result = self.run_server("vulnerable")
        self.assertEqual(["alice", "lead"], result.identities_tested)

    def test_dangerous_tools_are_not_called_by_default(self) -> None:
        result = self.run_server("vulnerable")
        self.assertTrue(any("run_task" in note for note in result.skipped))

    def test_evidence_is_recorded_for_every_call(self) -> None:
        result = self.run_server("vulnerable")
        self.assertEqual(result.calls_made, len(result.evidences))
        for item in result.evidences:
            self.assertTrue(item.test_id)
            self.assertTrue(item.identity)
            self.assertIn("expected", item.to_dict())


class HttpConformanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.port = free_port()
        self.proc = subprocess.Popen(
            [sys.executable, str(HTTP_SERVER), "--port", str(self.port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.1)
        self.url = f"http://127.0.0.1:{self.port}/mcp"
        os.environ["ALICE_TOKEN"] = "alice-token"
        os.environ["LEAD_TOKEN"] = "lead-token"

    def tearDown(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        os.environ.pop("ALICE_TOKEN", None)
        os.environ.pop("LEAD_TOKEN", None)

    def test_http_transport_and_token_checks(self) -> None:
        policy = load_policy(HTTP_POLICY)
        target = parse_target(None, self.url, timeout=15.0)
        result = run_conformance(target, policy, RunOptions(timeout=15.0))
        blocking = [(f.check, f.title) for f in result.findings if f.severity in ("critical", "high")]
        self.assertEqual([], blocking)
        self.assertEqual([], [f for f in result.findings if f.check == "AT-TOKEN-001"])
        token_evidence = [e for e in result.evidences if e.test_id == "AT-TOKEN-001"]
        self.assertEqual(3, len(token_evidence), "the three bad tokens were not probed")
        self.assertTrue(all(e.observed == "deny" for e in token_evidence))


class WeakTokenServerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.port = free_port()
        self.proc = subprocess.Popen(
            [sys.executable, str(HTTP_SERVER), "--port", str(self.port), "--weak-tokens"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.1)
        self.url = f"http://127.0.0.1:{self.port}/mcp"
        os.environ["ALICE_TOKEN"] = "alice-token"
        os.environ["LEAD_TOKEN"] = "lead-token"

    def tearDown(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        os.environ.pop("ALICE_TOKEN", None)
        os.environ.pop("LEAD_TOKEN", None)

    def test_tampered_token_is_accepted_and_reported(self) -> None:
        policy = load_policy(HTTP_POLICY)
        target = parse_target(None, self.url, timeout=15.0)
        result = run_conformance(target, policy, RunOptions(timeout=15.0))
        token_findings = [f for f in result.findings if f.check == "AT-TOKEN-001"]
        self.assertTrue(token_findings, "a tampered token was accepted but not reported")


class EvidenceTest(unittest.TestCase):
    def test_bundle_verifies_and_detects_tampering(self) -> None:
        policy = load_policy(STDIO_POLICY)
        result = run_conformance(stdio_target("vulnerable"), policy, RunOptions(timeout=15.0))
        bundle = build_bundle(result.evidences, subject={"server": result.server_info}, key="s3cret")
        payload = bundle.to_dict()
        ok, problems = verify_bundle(payload, "s3cret")
        self.assertTrue(ok, problems)

        payload["records"][0]["body"]["identity"] = "mallory"
        ok, problems = verify_bundle(payload, "s3cret")
        self.assertFalse(ok)
        self.assertTrue(problems)

    def test_secrets_are_redacted(self) -> None:
        self.assertIn("[REDACTED]", redact("key AKIAIOSFODNN7EXAMPLE here"))
        self.assertNotIn("AKIA", redact("key AKIAIOSFODNN7EXAMPLE here"))

    def test_manifest_hash_is_stable(self) -> None:
        policy = load_policy(STDIO_POLICY)
        first = run_conformance(stdio_target("vulnerable"), policy, RunOptions(timeout=15.0))
        second = run_conformance(stdio_target("vulnerable"), policy, RunOptions(timeout=15.0))
        self.assertEqual(first.manifest, second.manifest)
        self.assertTrue(first.manifest)


class ProbeArgumentTest(unittest.TestCase):
    def test_arguments_come_from_the_schema(self) -> None:
        from mcp_attest.client import ServerTool
        from mcp_attest.conformance import probe_arguments

        tool = ServerTool.from_raw(
            {
                "name": "get_order",
                "inputSchema": {
                    "type": "object",
                    "required": ["order_id", "limit"],
                    "properties": {
                        "order_id": {"type": "string", "maxLength": 10},
                        "limit": {"type": "integer"},
                        "mode": {"type": "string", "enum": ["a", "b"]},
                    },
                },
            }
        )
        args = probe_arguments(tool)
        self.assertEqual({"order_id", "limit"}, set(args))
        self.assertEqual(1, args["limit"])


if __name__ == "__main__":
    unittest.main()
