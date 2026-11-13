"""The posture scanner: measured against a local server, never against anyone else's."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_attest.posture import (  # noqa: E402
    RegistryServer,
    _parse_mcp_body,
    _sensitivity,
    measure,
    render_report,
    sample_population,
    summarize,
)

SERVER = ROOT / "examples" / "servers" / "orders_http_server.py"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_server(port: int, *flags: str) -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, str(SERVER), "--port", str(port), *flags],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return proc
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("the example server did not start")


def stop_server(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


class PostureMeasureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.port = free_port()
        # --no-token-check is the switch that makes the server answer a
        # request that carries no credentials at all.
        self.proc = start_server(self.port, "--oauth", "--no-token-check")
        self.addCleanup(self._stop)
        self.url = "http://127.0.0.1:%d/mcp" % self.port

    def _stop(self) -> None:
        stop_server(self.proc)

    def test_an_open_server_is_reported_as_open(self) -> None:
        record = measure(self.url, "orders")
        self.assertTrue(record.reachable)
        self.assertFalse(record.requires_auth)
        self.assertIn("list_orders", record.tools)
        self.assertIn("get_order", record.tools)

    def test_a_server_that_refuses_is_reported_as_closed(self) -> None:
        other = free_port()
        proc = start_server(other, "--oauth")
        self.addCleanup(stop_server, proc)
        record = measure("http://127.0.0.1:%d/mcp" % other, "closed")
        self.assertTrue(record.requires_auth)
        self.assertEqual(401, record.status)

    def test_an_unreachable_server_is_not_an_error(self) -> None:
        record = measure("http://127.0.0.1:%d/mcp" % free_port(), "gone")
        self.assertFalse(record.reachable)
        self.assertEqual("unreachable", record.error)

    def test_no_tool_is_ever_called(self) -> None:
        """The scanner stops at the manifest, so a side effect cannot happen."""
        record = measure(self.url, "orders")
        self.assertNotIn("refund_order", record.sensitive)


class SensitivityTest(unittest.TestCase):
    def test_a_shell_tool_is_recognised(self) -> None:
        self.assertEqual("shell", _sensitivity({"name": "run_command"}))
        self.assertEqual("shell", _sensitivity({"name": "execute_bash"}))

    def test_a_file_tool_is_recognised(self) -> None:
        self.assertEqual("filesystem", _sensitivity({"name": "read_file"}))
        self.assertEqual("filesystem", _sensitivity({"name": "list_directory"}))

    def test_a_network_tool_is_recognised(self) -> None:
        self.assertEqual("network", _sensitivity({"name": "fetch_url"}))

    def test_a_parameter_reveals_the_sink(self) -> None:
        tool = {"name": "do_thing", "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}}}
        self.assertEqual("shell", _sensitivity(tool))

    def test_an_ordinary_tool_is_not_sensitive(self) -> None:
        self.assertEqual("", _sensitivity({"name": "list_orders"}))
        self.assertEqual("", _sensitivity({"name": "get_weather"}))


class ParseTest(unittest.TestCase):
    def test_an_sse_body_with_an_event_line_is_parsed(self) -> None:
        body = 'event: message\ndata: {"result":{"tools":[{"name":"a"}]}}'
        document = _parse_mcp_body(body)
        self.assertEqual("a", document["result"]["tools"][0]["name"])

    def test_a_json_body_is_parsed(self) -> None:
        document = _parse_mcp_body('{"result":{"tools":[]}}')
        self.assertEqual([], document["result"]["tools"])

    def test_a_body_that_is_neither_is_empty(self) -> None:
        self.assertEqual({}, _parse_mcp_body("not json at all"))
        self.assertEqual({}, _parse_mcp_body(""))


class SampleTest(unittest.TestCase):
    def test_a_stride_spreads_the_sample(self) -> None:
        population = [RegistryServer(name="s%02d" % i, url="http://x/%d" % i) for i in range(20)]
        chosen = sample_population(population, stride=5)
        self.assertEqual(["s00", "s05", "s10", "s15"], [s.name for s in chosen])

    def test_a_limit_caps_the_sample(self) -> None:
        population = [RegistryServer(name="s%02d" % i, url="http://x/%d" % i) for i in range(20)]
        self.assertEqual(3, len(sample_population(population, stride=1, limit=3)))


class SummaryTest(unittest.TestCase):
    def test_the_summary_counts_what_it_says(self) -> None:
        from mcp_attest.posture import PostureRecord

        records = [
            PostureRecord(name="a", url="http://a", reachable=True, requires_auth=False,
                          tools=["x", "run_shell"], sensitive=["shell:run_shell"]),
            PostureRecord(name="b", url="http://b", reachable=True, requires_auth=True),
            PostureRecord(name="c", url="http://c", reachable=False),
        ]
        summary = summarize(records)
        self.assertEqual(3, summary["measured"])
        self.assertEqual(2, summary["answered"])
        self.assertEqual(1, summary["unreachable"])
        self.assertEqual(1, summary["open_without_credentials"])
        self.assertEqual(1, summary["closed"])
        self.assertEqual(1, summary["open_exposing_sensitive_tools"])
        self.assertEqual(2, summary["tools_in_open_servers"])
        self.assertEqual(1, summary["sensitive_tools_in_open_servers"])

    def test_the_report_carries_the_method_and_no_names(self) -> None:
        from mcp_attest.posture import PostureRecord

        records = [PostureRecord(name="secret-host.example", url="http://secret-host.example", reachable=True,
                                 requires_auth=False, tools=["run_shell"])]
        summary = summarize(records)
        summary["registry_population"] = 100
        summary["stride"] = 9
        report = render_report(summary, source="the registry", when="2026-11-14", records=records)
        self.assertIn("No tool is ever", report)
        self.assertIn("every 9 of them", report)
        self.assertNotIn("secret-host.example", report)

    def test_the_report_can_include_the_names_when_asked(self) -> None:
        from mcp_attest.posture import PostureRecord

        records = [PostureRecord(name="secret-host.example", url="http://secret-host.example", reachable=True,
                                 requires_auth=False, tools=["run_shell"])]
        summary = summarize(records)
        report = render_report(summary, source="the registry", when="2026-11-14", include_hosts=True, records=records)
        self.assertIn("secret-host.example", report)


if __name__ == "__main__":
    unittest.main()
