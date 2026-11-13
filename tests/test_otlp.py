"""Tests for the OTLP input path."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from mcp_attest.otlp import load_otlp, otlp_to_trace, span_to_event

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ROOT = Path(__file__).resolve().parents[1]


class OtlpTest(unittest.TestCase):
    def setUp(self):
        self.trace = load_otlp(FIXTURES / "otlp.json")

    def test_tool_calls_are_mapped(self):
        self.assertEqual(len(self.trace.tool_calls), 2)
        first, second = self.trace.tool_calls
        self.assertEqual(first.actor, "ci-bot")
        self.assertEqual(first.tool, "read_file")
        self.assertEqual(first.decision, "allow")
        self.assertIs(first.upstream, True)
        self.assertEqual(first.args, {"path": "notes.txt"})
        self.assertEqual(second.tool, "write_file")
        self.assertEqual(second.decision, "deny")
        self.assertIs(second.upstream, False)

    def test_configuration_events_are_mapped(self):
        self.assertEqual(len(self.trace.tools_lists), 1)
        self.assertEqual(self.trace.tools_lists[0].names, ["read_file", "write_file"])
        self.assertEqual(self.trace.client_servers["claude-code"], ["fs", "git"])
        self.assertEqual(self.trace.gateway_routes["fs"], ["read_file"])

    def test_non_mcp_span_is_skipped_with_a_warning(self):
        self.assertEqual(len(self.trace.warnings), 1)
        self.assertIn("http.server.request", self.trace.warnings[0])

    def test_timestamps_are_iso(self):
        self.assertEqual([call.ts for call in self.trace.tool_calls],
                         ["2024-11-07T17:20:03.000000000Z", "2024-11-07T17:20:04.000000000Z"])
        for call in self.trace.tool_calls:
            self.assertTrue(call.ts.endswith("Z"))
            self.assertTrue(call.ts.endswith("Z"))

    def test_unknown_span_name_is_rejected(self):
        event, reason = span_to_event({"name": "some.other.span"})
        self.assertIsNone(event)
        self.assertIn("some.other.span", reason)

    def test_ndjson_export_is_accepted(self):
        payload = json.loads((FIXTURES / "otlp.json").read_text(encoding="utf-8"))
        lines = [json.dumps(payload), json.dumps(payload)]
        merged = otlp_to_trace({"resourceSpans": []})
        self.assertEqual(len(merged.tool_calls), 0)

    def test_empty_export_is_empty_trace(self):
        trace = otlp_to_trace({})
        self.assertEqual(trace.tool_calls, [])
        self.assertEqual(trace.warnings, [])


class OtlpCliTest(unittest.TestCase):
    """The export has to be reachable from the command line, not only as a library."""

    def _run(self, *args):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "mcp_attest", *args],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            env=env, cwd=str(ROOT),
        )

    def test_check_reads_an_otlp_export(self):
        proc = self._run("check", "--policy", "examples/policy.json",
                         "--otlp", str(FIXTURES / "otlp.json"))
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("C6", proc.stdout)
        self.assertIn("summary:", proc.stdout)
        self.assertIn("not an MCP span", proc.stderr)

    def test_check_needs_exactly_one_source(self):
        proc = self._run("check", "--policy", "examples/policy.json")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--trace", proc.stderr)


if __name__ == "__main__":
    unittest.main()
