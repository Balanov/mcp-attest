"""Tests for the OTLP input path."""

import json
import unittest
from pathlib import Path

from mcp_attest.otlp import load_otlp, otlp_to_trace, span_to_event

FIXTURES = Path(__file__).resolve().parent / "fixtures"


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


if __name__ == "__main__":
    unittest.main()
