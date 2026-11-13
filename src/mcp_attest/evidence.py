"""Evidence: what a third party needs to believe a test really happened.

The OWASP guide is explicit about what a finding needs: "capture the request,
the response, the identity, the timestamp, and the policy decision; redact
secrets; record the configuration state at the time of the test. A finding
without reproducible evidence is an opinion."

So every check the harness runs leaves a record with those fields, the records
are hash-chained into a bundle, and the bundle can be signed with HMAC-SHA256.
A recipient can then verify the bundle offline, without trusting the machine
that produced it and without trusting the server that was tested.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .receipts import GENESIS, canonical, chain_hash, sign

# Patterns whose match must never reach an evidence file. The harness records
# what it saw; it must not become the place where the secret leaks from.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws-secret-key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S{8,}")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("basic-auth-url", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s:@]+@")),
)

REDACTED = "[REDACTED]"


def redact(text: str) -> str:
    """Mask anything that looks like a credential."""
    out = text
    for _, pattern in SECRET_PATTERNS:
        out = pattern.sub(REDACTED, out)
    return out


def redact_structure(value: Any) -> Any:
    """Recursively redact strings inside a JSON-ish structure."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: redact_structure(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_structure(v) for v in value]
    return value


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Evidence:
    """One recorded exchange."""

    test_id: str
    identity: str
    method: str
    request: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)
    expected: str = ""
    observed: str = ""
    detail: str = ""
    duration_ms: int = 0
    ts: str = field(default_factory=now_iso)

    def body(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "test_id": self.test_id,
            "identity": self.identity,
            "method": self.method,
            "request": redact_structure(self.request),
            "response": redact_structure(self.response),
            "expected": self.expected,
            "observed": self.observed,
            "detail": redact(self.detail),
            "duration_ms": self.duration_ms,
        }

    def to_dict(self) -> dict[str, Any]:
        return self.body()


@dataclass
class Bundle:
    """A hash-chained, optionally signed set of evidence records."""

    version: int = 1
    created_at: str = field(default_factory=now_iso)
    subject: dict[str, Any] = field(default_factory=dict)
    records: list[dict[str, Any]] = field(default_factory=list)
    key_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "mcp-attest-bundle",
            "version": self.version,
            "created_at": self.created_at,
            "subject": self.subject,
            "key_id": self.key_id,
            "records": self.records,
        }


def build_bundle(
    evidences: list[Evidence],
    subject: dict[str, Any],
    key: str | None = None,
) -> Bundle:
    """Chain the evidence records into a tamper-evident bundle."""
    bundle = Bundle(subject=redact_structure(subject), key_id="hmac-sha256" if key else "")
    prev = GENESIS
    for index, item in enumerate(evidences):
        body = item.body()
        h = chain_hash(prev, body)
        record: dict[str, Any] = {
            "type": "evidence",
            "id": f"e{index + 1:06d}",
            "prev": prev,
            "body": body,
            "hash": h,
        }
        sig = sign(h, key)
        if sig:
            record["sig"] = sig
        bundle.records.append(record)
        prev = h
    bundle.records.append(
        {
            "type": "seal",
            "id": f"e{len(bundle.records) + 1:06d}",
            "prev": prev,
            "count": len(evidences),
            "hash": chain_hash(prev, {"count": len(evidences), "subject": bundle.subject}),
        }
    )
    return bundle


def verify_bundle(bundle: dict[str, Any], key: str | None = None) -> tuple[bool, list[str]]:
    """Verify the chain and, when a key is given, the signatures."""
    problems: list[str] = []
    records = bundle.get("records") or []
    evidence = [r for r in records if r.get("type") == "evidence"]
    seals = [r for r in records if r.get("type") == "seal"]
    if not evidence:
        return False, ["the bundle contains no evidence records"]

    prev = GENESIS
    for index, record in enumerate(evidence):
        rid = record.get("id", f"#{index + 1}")
        if record.get("prev") != prev:
            problems.append(f"{rid}: chain broken, expected prev={prev[:12]}… got {str(record.get('prev'))[:12]}…")
        body = record.get("body")
        if not isinstance(body, dict):
            problems.append(f"{rid}: missing body")
            prev = str(record.get("hash", prev))
            continue
        expected = chain_hash(prev, body)
        if record.get("hash") != expected:
            problems.append(f"{rid}: hash mismatch, this record was altered")
        if key:
            sig = record.get("sig")
            if not sig:
                problems.append(f"{rid}: unsigned record in a signed bundle")
            elif not hmac.compare_digest(sign(expected, key), str(sig)):
                problems.append(f"{rid}: signature does not verify")
        prev = str(record.get("hash", expected))

    if seals:
        seal = seals[-1]
        expected = chain_hash(prev, {"count": seal.get("count"), "subject": bundle.get("subject")})
        if seal.get("hash") != expected:
            problems.append("seal: the bundle was changed after it was sealed")
    return (not problems), problems


def digest(obj: Any) -> str:
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


def key_from_env(var: str = "MCP_ATTEST_KEY") -> str | None:
    return os.environ.get(var) or None


def bundle_to_dict(bundle: Bundle) -> dict[str, Any]:
    return bundle.to_dict()


def write_bundle(bundle: Bundle, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(bundle.to_dict(), handle, indent=2, ensure_ascii=False, sort_keys=False)
        handle.write("\n")
