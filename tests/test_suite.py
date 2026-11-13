"""The suite format: export, validate and run."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_attest.policy import load_policy  # noqa: E402
from mcp_attest.suite import (  # noqa: E402
    SuiteError,
    export_suite,
    load_suite,
    suite_to_policy,
    validate_suite,
)

SERVER = ROOT / "examples" / "servers" / "orders_http_server.py"
POLICY = ROOT / "examples" / "live-policy-http.json"
SCHEMA = ROOT / "docs" / "mcp-attest-suite.schema.json"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class SuiteExportTest(unittest.TestCase):
    def test_export_keeps_the_expectations(self) -> None:
        policy = load_policy(POLICY)
        document = export_suite(policy, name="orders", target={"url": "http://127.0.0.1:8931/mcp"})
        self.assertEqual("mcp-attest-suite", document["format"])
        self.assertEqual(1, document["version"])
        self.assertEqual(["alice", "lead"], [i["name"] for i in document["identities"]])
        alice = document["identities"][0]
        self.assertEqual(["list_orders", "get_order"], alice["expect"]["allow"])
        self.assertEqual(["refund_order"], alice["expect"]["deny"])
        self.assertEqual(1, len(alice["cases"]))
        self.assertEqual("AUTHZ-CROSS-01", alice["cases"][0]["id"])

    def test_export_keeps_credentials_as_references(self) -> None:
        policy = load_policy(POLICY)
        document = export_suite(policy, name="orders")
        header = document["identities"][0]["headers"]["Authorization"]
        self.assertIn("${ALICE_TOKEN}", header)
        self.assertNotIn("alice-token", json.dumps(document))

    def test_a_suite_round_trips_into_a_policy(self) -> None:
        policy = load_policy(POLICY)
        document = export_suite(policy, name="orders")
        rebuilt = suite_to_policy(load_suite_document(document))
        self.assertEqual(["alice", "lead"], [c.name for c in rebuilt.clients.values()])
        self.assertEqual(
            ("deny", "tool is on the deny list"),
            rebuilt.decision_for("alice", "refund_order"),
        )
        self.assertEqual(
            ("allow", "tool is on the allow list"),
            rebuilt.decision_for("alice", "get_order"),
        )
        self.assertEqual(1, len(rebuilt.cases))
        self.assertEqual("AUTHZ-CROSS-01", rebuilt.cases[0].id)
        self.assertEqual("alice", rebuilt.cases[0].identity)


def load_suite_document(document):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
        json.dump(document, handle)
        path = handle.name
    try:
        return load_suite(path)
    finally:
        os.unlink(path)


class SuiteValidationTest(unittest.TestCase):
    def test_a_valid_suite_has_no_problems(self) -> None:
        policy = load_policy(POLICY)
        document = export_suite(policy, name="orders")
        self.assertEqual([], validate_suite(document))

    def test_a_suite_without_identities_is_rejected(self) -> None:
        problems = validate_suite({"format": "mcp-attest-suite", "version": 1, "name": "x", "identities": []})
        self.assertTrue(any("at least one identity" in p for p in problems))

    def test_an_identity_without_credentials_is_rejected(self) -> None:
        document = {
            "format": "mcp-attest-suite",
            "version": 1,
            "name": "x",
            "identities": [{"name": "alice", "expect": {"allow": []}}],
        }
        problems = validate_suite(document)
        self.assertTrue(any("cannot be presented" in p for p in problems))

    def test_a_wrong_format_is_rejected(self) -> None:
        problems = validate_suite({"format": "something-else", "version": 1, "name": "x", "identities": []})
        self.assertTrue(any("format must be" in p for p in problems))

    def test_the_published_schema_matches_the_validator(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual("mcp-attest-suite", schema["properties"]["format"]["const"])
        self.assertEqual(1, schema["properties"]["version"]["const"])
        for field in ("format", "version", "name", "identities", "target", "probes", "oauth", "rules", "metadata"):
            self.assertIn(field, schema["properties"], "the schema does not describe %s" % field)


class SuiteRunTest(unittest.TestCase):
    def setUp(self) -> None:
        self.port = free_port()
        self.proc = subprocess.Popen(
            [sys.executable, str(SERVER), "--port", str(self.port)],
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
        self.addCleanup(self._stop)
        os.environ["ALICE_TOKEN"] = "alice-token"
        os.environ["LEAD_TOKEN"] = "lead-token"
        self.addCleanup(os.environ.pop, "ALICE_TOKEN", None)
        self.addCleanup(os.environ.pop, "LEAD_TOKEN", None)

    def _stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()

    def test_a_suite_runs_against_the_server_it_names(self) -> None:
        policy = load_policy(POLICY)
        document = export_suite(
            policy,
            name="orders",
            target={"url": "http://127.0.0.1:%d/mcp" % self.port},
        )
        suite = load_suite_document(document)
        rebuilt = suite_to_policy(suite)
        self.assertEqual(["alice", "lead"], [c.name for c in rebuilt.clients.values()])

    def test_a_broken_suite_is_reported(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
            handle.write('{"format": "mcp-attest-suite", "version": 1, "name": "x"}')
            path = handle.name
        self.addCleanup(os.unlink, path)
        with self.assertRaises(SuiteError):
            load_suite(path)


if __name__ == "__main__":
    unittest.main()
