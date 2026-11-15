"""Policy envelope errors must not become clean authorization verdicts."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from mcp_attest.policy import PolicyError, load_policy, policy_from_dict
from mcp_attest.cli import main


class PolicyEnvelopeTests(unittest.TestCase):
    def test_unknown_keys_are_named(self):
        for key in ("case", "probe", "unexpected"):
            with self.subTest(key=key):
                with self.assertRaisesRegex(PolicyError, key):
                    policy_from_dict({key: []})

    def test_only_integer_version_one_is_supported(self):
        for version in (0, 2, True, "1", 1.0, None):
            with self.subTest(version=repr(version)):
                with self.assertRaisesRegex(PolicyError, "supported version.*1"):
                    policy_from_dict({"version": version})

    def test_omitted_version_keeps_fail_closed_defaults(self):
        for raw in ({}, {"version": 1}):
            policy = policy_from_dict(raw)
            self.assertEqual(policy.version, 1)
            self.assertEqual(policy.default_decision, "deny")

    def test_cli_rejects_invalid_envelope_before_running(self):
        for raw, expected in (({"case": []}, "case"), ({"version": 2}, "supported version")):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "policy.json"
                path.write_text(json.dumps(raw), encoding="utf-8")
                errors = io.StringIO()
                with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as caught:
                    main(["test", "--policy", str(path)])
                self.assertEqual(caught.exception.code, 2)
                self.assertIn(expected, errors.getvalue())

    def test_shipped_policies_load(self):
        root = Path(__file__).resolve().parents[1]
        for name in ("policy.json", "live-policy.json", "live-policy-http.json", "live-policy-oauth.json"):
            with self.subTest(name=name):
                self.assertEqual(load_policy(root / "examples" / name).version, 1)
