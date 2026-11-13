import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mcp_attest.checks import run_checks  # noqa: E402
from mcp_attest.policy import STARTER_POLICY, policy_from_dict  # noqa: E402
from mcp_attest.receipts import build_receipts, verify_receipts  # noqa: E402
from mcp_attest.trace import load_trace  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def checks_of(findings):
    return sorted({f.check for f in findings})


class ChecksTest(unittest.TestCase):
    def setUp(self):
        self.policy = policy_from_dict(STARTER_POLICY)

    def test_broken_trace_triggers_the_expected_rules(self):
        trace = load_trace(FIXTURES / "broken.jsonl")
        findings = run_checks(self.policy, trace)
        found = checks_of(findings)
        for rule in ("C2", "C3", "C5", "C6", "C7", "C8", "C9"):
            self.assertIn(rule, found, f"expected {rule} to fire")

    def test_starter_policy_is_default_deny_clean(self):
        """The shipped starter policy must not trip the default-deny rule."""
        trace = load_trace(FIXTURES / "broken.jsonl")
        findings = run_checks(self.policy, trace)
        self.assertNotIn("C1", checks_of(findings))

    def test_enforcement_parity_is_critical(self):
        trace = load_trace(FIXTURES / "broken.jsonl")
        findings = run_checks(self.policy, trace)
        parity = [f for f in findings if f.check == "C6" and f.severity == "critical"]
        self.assertTrue(parity, "a policy denial that was allowed must be critical")
        self.assertIn("fs__write_file", parity[0].evidence.get("tool", ""))

    def test_description_change_is_flagged_as_rug_pull(self):
        trace = load_trace(FIXTURES / "broken.jsonl")
        findings = run_checks(self.policy, trace)
        rug = [f for f in findings if f.check == "C9"]
        self.assertEqual(len(rug), 1)
        self.assertEqual(rug[0].severity, "critical")

    def test_shadow_path_detected(self):
        trace = load_trace(FIXTURES / "broken.jsonl")
        findings = run_checks(self.policy, trace)
        shadow = [f for f in findings if f.check == "C7"]
        self.assertEqual(len(shadow), 1)
        self.assertEqual(shadow[0].evidence["server"], "git")

    def test_clean_trace_has_no_critical_findings(self):
        trace = load_trace(FIXTURES / "clean.jsonl")
        findings = run_checks(self.policy, trace)
        critical = [f for f in findings if f.severity == "critical"]
        self.assertEqual(critical, [], f"unexpected critical findings: {[f.title for f in critical]}")

    def test_policy_without_allowlist_fails_c1(self):
        policy = policy_from_dict(
            {"version": 1, "default_decision": "deny", "clients": {"ci-bot": {}}}
        )
        trace = load_trace(FIXTURES / "clean.jsonl")
        findings = run_checks(policy, trace)
        self.assertIn("C1", checks_of(findings))

    def test_default_allow_fails_c1(self):
        policy = policy_from_dict({"version": 1, "default_decision": "allow", "clients": {}})
        trace = load_trace(FIXTURES / "clean.jsonl")
        findings = run_checks(policy, trace)
        c1 = [f for f in findings if f.check == "C1"]
        self.assertTrue(any(f.title == "Policy default is not deny" for f in c1))


class ReceiptsTest(unittest.TestCase):
    def test_chain_verifies_and_detects_tampering(self):
        trace = load_trace(FIXTURES / "clean.jsonl")
        allowed = [c for c in trace.tool_calls if c.decision == "allow"]
        receipts = build_receipts(allowed)
        ok, problems = verify_receipts(receipts)
        self.assertTrue(ok, problems)

        receipts[1]["body"]["tool"] = "fs__delete_everything"
        ok, problems = verify_receipts(receipts)
        self.assertFalse(ok)
        self.assertTrue(any("hash mismatch" in p for p in problems))

    def test_signature_detects_wrong_key(self):
        trace = load_trace(FIXTURES / "clean.jsonl")
        allowed = [c for c in trace.tool_calls if c.decision == "allow"]
        receipts = build_receipts(allowed, key="right-key")
        ok, _ = verify_receipts(receipts, key="right-key")
        self.assertTrue(ok)
        ok, problems = verify_receipts(receipts, key="wrong-key")
        self.assertFalse(ok)
        self.assertTrue(any("signature" in p for p in problems))

    def test_removing_a_receipt_breaks_the_chain(self):
        trace = load_trace(FIXTURES / "clean.jsonl")
        allowed = [c for c in trace.tool_calls if c.decision == "allow"]
        receipts = build_receipts(allowed)
        del receipts[0]
        ok, problems = verify_receipts(receipts)
        self.assertFalse(ok)
        self.assertTrue(any("chain broken" in p for p in problems))


class PolicyTest(unittest.TestCase):
    def test_conditional_rule_allows_only_matching_path(self):
        policy = policy_from_dict(STARTER_POLICY)
        client = policy.client("ci-bot")
        decision, _ = client.decision("fs__write_file", {"path": "./out/report.txt"})
        self.assertEqual(decision, "allow")
        decision, _ = client.decision("fs__write_file", {"path": "/etc/hosts"})
        self.assertEqual(decision, "deny")

    def test_default_deny_for_unlisted_tool(self):
        policy = policy_from_dict(STARTER_POLICY)
        decision, reason = policy.decision_for("ci-bot", "fs__unknown")
        self.assertEqual(decision, "deny")
        self.assertIn("default deny", reason)


if __name__ == "__main__":
    unittest.main()
