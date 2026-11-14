"""OAuth conformance tests: the harness against a server with a real OAuth layer.

Every check in the OAuth set has a matching switch on the example server, so
each rule can be shown on its own: the secure server must be clean, and one
disabled check must produce exactly the rule that names it.
"""

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

from mcp_attest.conformance import RunOptions, run_conformance  # noqa: E402
from mcp_attest.oauth import b64url_decode, decode_jwt, mint_jwt, tamper  # noqa: E402
from mcp_attest.policy import policy_from_dict  # noqa: E402
from mcp_attest.targets import parse_target  # noqa: E402

SERVER = ROOT / "examples" / "servers" / "orders_http_server.py"
POLICY = ROOT / "examples" / "live-policy-oauth.json"

KEY = "test-signing-key"
ISSUER = "https://auth.example.com/"
AUDIENCE = "mcp://orders"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_server(port: int, *flags: str) -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, str(SERVER), "--port", str(port), "--oauth", *flags],
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


def make_token(subject: str, scope: str = "orders:read") -> str:
    now = int(time.time())
    return mint_jwt(
        {
            "sub": subject,
            "iss": ISSUER,
            "aud": AUDIENCE,
            "scope": scope,
            "iat": now,
            "exp": now + 3600,
        },
        KEY,
    )


def find_token_the_flip_missed() -> str:
    """A token whose signature the old character flip left unchanged.

    The AT-TOKEN-001 probe used to replace the first character of the
    signature with a letter picked from the last one. When the signature
    already began with that letter the token came back byte for byte
    identical, so a server that verifies signatures accepted it.
    """
    now = int(time.time())
    for index in range(4096):
        token = mint_jwt(
            {
                "sub": "alice",
                "iss": ISSUER,
                "aud": AUDIENCE,
                "scope": "orders:read",
                "iat": now,
                "exp": now + 3600,
                "n": index,
            },
            KEY,
        )
        signature = token.split(".")[2]
        if signature[0] == "A" and signature[-1] != "A":
            return token
    raise AssertionError("no signature with that shape was found")


def make_policy(port: int, upstream_port: int | None = None) -> object:
    raw = json.loads(POLICY.read_text(encoding="utf-8"))
    oauth = raw["oauth"]
    oauth["authorization_endpoint"] = "http://127.0.0.1:%d/authorize" % port
    oauth["redirect_uri"] = "http://127.0.0.1:%d/callback" % port
    oauth["resource"] = "http://127.0.0.1:%d/mcp" % port
    oauth["protected_resource_metadata"] = (
        "http://127.0.0.1:%d/.well-known/oauth-protected-resource" % port
    )
    if upstream_port is None:
        oauth.pop("upstream", None)
    else:
        oauth["upstream"] = "http://127.0.0.1:%d/mcp" % upstream_port
    return policy_from_dict(raw)


class TamperTest(unittest.TestCase):
    """A tampered token must differ in the bytes, not only in the spelling.

    The last character of a base64url signature carries four significant bits,
    so the signature can only end in sixteen characters. Flipping that
    character used to leave one token in sixteen byte for byte identical, and
    a server that verifies signatures accepted it — the harness then reported
    a vulnerability that was not there.
    """

    def token_for_each_possible_last_character(self) -> dict[str, str]:
        found: dict[str, str] = {}
        for index in range(4096):
            token = mint_jwt({"sub": "alice", "n": index}, KEY)
            found.setdefault(token.split(".")[2][-1], token)
            if len(found) == 16:
                break
        return found

    def test_a_tampered_signature_always_differs_from_the_original(self) -> None:
        found = self.token_for_each_possible_last_character()
        self.assertEqual(16, len(found), "a signature can end in sixteen characters")
        for last, token in sorted(found.items()):
            original = b64url_decode(token.split(".")[2])
            broken = b64url_decode(tamper(token).split(".")[2])
            self.assertNotEqual(original, broken, "the signature ending in %r did not change" % last)

    def test_a_tampered_token_keeps_its_header_and_payload(self) -> None:
        token = make_token("alice")
        broken = tamper(token)
        self.assertEqual(token.split(".")[:2], broken.split(".")[:2])
        header, payload = decode_jwt(broken)
        self.assertEqual("HS256", header["alg"])
        self.assertEqual("alice", payload["sub"])

    def test_a_tampered_token_stays_three_parts_of_base64url(self) -> None:
        broken = tamper(make_token("alice"))
        parts = broken.split(".")
        self.assertEqual(3, len(parts))
        self.assertEqual(43, len(parts[2]))
        self.assertEqual(32, len(b64url_decode(parts[2])))

    def test_a_signature_that_starts_with_a_is_tampered_too(self) -> None:
        token = ""
        for index in range(4096):
            candidate = mint_jwt({"sub": "alice", "n": index}, KEY)
            if candidate.split(".")[2][0] == "A":
                token = candidate
                break
        self.assertTrue(token, "no signature started with A")
        original = b64url_decode(token.split(".")[2])
        broken = b64url_decode(tamper(token).split(".")[2])
        self.assertNotEqual(original, broken, "a signature that started with A did not change")


class OAuthBase(unittest.TestCase):
    def setUp(self) -> None:
        self.port = free_port()
        self.proc = start_server(self.port)
        self.addCleanup(stop_server, self.proc)
        os.environ["ALICE_TOKEN"] = make_token("alice")
        os.environ["LEAD_TOKEN"] = make_token("lead", "orders:read orders:write")
        os.environ["MCP_ATTEST_OAUTH_KEY"] = KEY
        self.addCleanup(os.environ.pop, "ALICE_TOKEN", None)
        self.addCleanup(os.environ.pop, "LEAD_TOKEN", None)
        self.addCleanup(os.environ.pop, "MCP_ATTEST_OAUTH_KEY", None)

    def run_harness(self, port: int | None = None, upstream_port: int | None = None):
        port = port or self.port
        policy = make_policy(port, upstream_port)
        target = parse_target(None, "http://127.0.0.1:%d/mcp" % port, timeout=15.0)
        return run_conformance(target, policy, RunOptions(timeout=15.0))

    def checks(self, result) -> set[str]:
        return {f.check for f in result.findings}


class SecureOAuthServerTest(OAuthBase):
    def test_a_correct_server_has_no_oauth_findings(self) -> None:
        result = self.run_harness()
        oauth_findings = [f for f in result.findings if f.check.startswith("AT-OAUTH-")]
        self.assertEqual([], [(f.check, f.title) for f in oauth_findings])
        self.assertTrue(result.calls_made > 0, "the harness made no calls")

    def test_every_oauth_probe_ran(self) -> None:
        result = self.run_harness()
        seen = {e.test_id for e in result.evidences if e.test_id.startswith("AT-OAUTH-")}
        self.assertIn("AT-OAUTH-001", seen)
        self.assertIn("AT-OAUTH-002", seen)
        self.assertIn("AT-OAUTH-003", seen)
        self.assertIn("AT-OAUTH-004", seen)
        self.assertIn("AT-OAUTH-005", seen)
        self.assertIn("AT-OAUTH-006", seen)
        self.assertIn("AT-OAUTH-007", seen)


class TokenProbeTest(OAuthBase):
    """AT-TOKEN-001 must offer the server a token it cannot accept.

    The probe used to replace the first character of the signature instead of
    a bit of its bytes. One token in sixty-four came back byte for byte
    identical, the server accepted it as the valid token it was, and the
    harness reported a critical finding against a server that was doing
    everything right.
    """

    def probe_headers(self, result) -> list[str]:
        return [
            evidence.request.get("headers", {}).get("Authorization", "")
            for evidence in result.evidences
            if evidence.test_id == "AT-TOKEN-001"
        ]

    def test_a_correct_server_is_not_reported(self) -> None:
        os.environ["ALICE_TOKEN"] = find_token_the_flip_missed()
        result = self.run_harness()
        self.assertEqual(
            [],
            [(f.check, f.title) for f in result.findings if f.check == "AT-TOKEN-001"],
            "a server that verifies signatures was reported as accepting a tampered token",
        )

    def test_every_bad_token_is_refused(self) -> None:
        result = self.run_harness()
        token_evidence = [e for e in result.evidences if e.test_id == "AT-TOKEN-001"]
        self.assertEqual(3, len(token_evidence), "the three bad tokens were not probed")
        self.assertTrue(all(e.observed == "deny" for e in token_evidence))

    def test_the_probe_sends_a_tampered_token(self) -> None:
        valid = find_token_the_flip_missed()
        os.environ["ALICE_TOKEN"] = valid
        result = self.run_harness()
        headers = self.probe_headers(result)
        self.assertEqual(3, len(headers), "the three bad tokens were not probed")
        self.assertIn(
            "Bearer " + tamper(valid),
            headers,
            "the probe did not offer the server a tampered token",
        )
        self.assertNotIn("Bearer " + valid, headers, "the probe sent the valid token")

    def test_a_server_that_accepts_a_tampered_token_is_reported(self) -> None:
        port = free_port()
        proc = start_server(port, "--no-signature-check")
        self.addCleanup(stop_server, proc)
        result = self.run_harness(port=port)
        titles = [f.title for f in result.findings if f.check == "AT-TOKEN-001"]
        self.assertIn(
            "the server accepted a token with a tampered signature",
            titles,
            "the checker did not report the accepted token",
        )


class OAuthDefectTest(OAuthBase):
    """One disabled check, one rule."""

    def assert_rule(self, flag: str, rule: str) -> None:
        port = free_port()
        proc = start_server(port, flag)
        self.addCleanup(stop_server, proc)
        result = self.run_harness(port=port)
        self.assertIn(rule, self.checks(result), "%s was not reported" % rule)

    def test_missing_token_is_accepted(self) -> None:
        self.assert_rule("--no-token-check", "AT-OAUTH-001")

    def test_tampered_signature_is_accepted(self) -> None:
        self.assert_rule("--no-signature-check", "AT-OAUTH-002")

    def test_unsigned_token_is_accepted(self) -> None:
        self.assert_rule("--no-signature-check", "AT-OAUTH-003")

    def test_expired_token_is_accepted(self) -> None:
        self.assert_rule("--no-expiry-check", "AT-OAUTH-004")

    def test_wrong_audience_is_accepted(self) -> None:
        self.assert_rule("--no-audience-check", "AT-OAUTH-005")

    def test_wrong_issuer_is_accepted(self) -> None:
        self.assert_rule("--no-issuer-check", "AT-OAUTH-006")

    def test_scope_is_not_enforced(self) -> None:
        self.assert_rule("--no-scope-check", "AT-OAUTH-007")

    def test_resource_metadata_is_missing(self) -> None:
        self.assert_rule("--no-resource-metadata", "AT-OAUTH-008")

    def test_pkce_is_not_required(self) -> None:
        self.assert_rule("--no-pkce", "AT-OAUTH-009")

    def test_redirect_uri_is_not_checked(self) -> None:
        self.assert_rule("--no-redirect-check", "AT-OAUTH-010")

    def test_state_is_dropped(self) -> None:
        self.assert_rule("--no-state", "AT-OAUTH-011")


class TokenPassthroughTest(OAuthBase):
    def test_a_token_for_this_server_is_refused_upstream(self) -> None:
        upstream_port = free_port()
        proc = start_server(upstream_port, "--oauth-audience", "mcp://upstream")
        self.addCleanup(stop_server, proc)
        result = self.run_harness(upstream_port=upstream_port)
        self.assertNotIn("AT-OAUTH-012", self.checks(result))

    def test_an_upstream_that_accepts_the_token_is_reported(self) -> None:
        upstream_port = free_port()
        proc = start_server(upstream_port, "--oauth-audience", "mcp://upstream", "--no-audience-check")
        self.addCleanup(stop_server, proc)
        result = self.run_harness(upstream_port=upstream_port)
        self.assertIn("AT-OAUTH-012", self.checks(result))


class WithoutSigningKeyTest(OAuthBase):
    def test_claim_probes_are_skipped_not_passed(self) -> None:
        os.environ.pop("MCP_ATTEST_OAUTH_KEY", None)
        result = self.run_harness()
        checks = self.checks(result)
        self.assertNotIn("AT-OAUTH-004", checks, "an expired token was accepted")
        self.assertNotIn("AT-OAUTH-005", checks, "a wrong-audience token was accepted")
        skipped = " ".join(result.skipped)
        self.assertIn("AT-OAUTH-004", skipped)
        self.assertIn("signing key", skipped)


class OAuthWithoutPolicyTest(unittest.TestCase):
    """A policy with no oauth block must not produce OAuth findings."""

    def test_the_oauth_checks_do_not_run(self) -> None:
        port = free_port()
        proc = start_server(port)
        self.addCleanup(stop_server, proc)
        os.environ["ALICE_TOKEN"] = make_token("alice")
        os.environ["LEAD_TOKEN"] = make_token("lead", "orders:read orders:write")
        self.addCleanup(os.environ.pop, "ALICE_TOKEN", None)
        self.addCleanup(os.environ.pop, "LEAD_TOKEN", None)

        raw = json.loads(POLICY.read_text(encoding="utf-8"))
        raw.pop("oauth")
        policy = policy_from_dict(raw)
        target = parse_target(None, "http://127.0.0.1:%d/mcp" % port, timeout=15.0)
        result = run_conformance(target, policy, RunOptions(timeout=15.0))
        self.assertEqual([], [f for f in result.findings if f.check.startswith("AT-OAUTH-")])
        self.assertTrue(any("no oauth block" in note for note in result.skipped))


if __name__ == "__main__":
    unittest.main()
