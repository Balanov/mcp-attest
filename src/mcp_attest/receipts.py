"""Tamper-evident receipts.

Every tool call that a policy allows should leave behind a receipt that a third
party can verify without trusting the gateway. Receipts form a hash chain: each
one commits to the previous, so removing or reordering a receipt breaks the
chain. With a key present, each receipt is additionally signed with
HMAC-SHA256 so that an auditor can detect edits without access to the gateway.

This is deliberately not a PKI. It is a chain plus a MAC: enough to answer
"did this session really contain these calls, in this order, and has anything
been altered since" — which is the question an incident responder actually
asks.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

GENESIS = "0" * 64


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def args_digest(args: dict[str, Any]) -> str:
    return sha256_hex(canonical(args or {}))


def receipt_body(call: Any) -> dict[str, Any]:
    return {
        "ts": getattr(call, "ts", ""),
        "actor": getattr(call, "actor", ""),
        "tool": getattr(call, "tool", ""),
        "args_digest": args_digest(getattr(call, "args", {}) or {}),
        "decision": getattr(call, "decision", ""),
        "upstream": bool(getattr(call, "upstream", False)),
    }


def chain_hash(prev: str, body: dict[str, Any]) -> str:
    return sha256_hex(prev + "|" + canonical(body))


def sign(hash_hex: str, key: str | None) -> str:
    if not key:
        return ""
    return hmac.new(key.encode("utf-8"), hash_hex.encode("utf-8"), hashlib.sha256).hexdigest()


def build_receipts(calls: list[Any], key: str | None = None) -> list[dict[str, Any]]:
    """Build a hash-chained receipt for each call."""
    receipts: list[dict[str, Any]] = []
    prev = GENESIS
    for index, call in enumerate(calls):
        body = receipt_body(call)
        h = chain_hash(prev, body)
        receipt = {
            "type": "receipt",
            "id": f"r{index + 1:06d}",
            "prev": prev,
            "body": body,
            "hash": h,
        }
        sig = sign(h, key)
        if sig:
            receipt["sig"] = sig
        receipts.append(receipt)
        prev = h
    return receipts


def verify_receipts(receipts: list[dict[str, Any]], key: str | None = None) -> tuple[bool, list[str]]:
    """Verify the hash chain (and signatures when a key is supplied)."""
    problems: list[str] = []
    if not receipts:
        return False, ["no receipts found in the trace"]

    prev = GENESIS
    for index, receipt in enumerate(receipts):
        rid = receipt.get("id", f"#{index + 1}")
        if receipt.get("prev") != prev:
            problems.append(f"{rid}: chain broken, expected prev={prev[:12]}… got {str(receipt.get('prev'))[:12]}…")
        body = receipt.get("body")
        if not isinstance(body, dict):
            problems.append(f"{rid}: missing body")
            prev = str(receipt.get("hash", prev))
            continue
        expected = chain_hash(prev, body)
        if receipt.get("hash") != expected:
            problems.append(f"{rid}: hash mismatch, receipt content was altered")
        if key:
            sig = receipt.get("sig")
            if not sig:
                problems.append(f"{rid}: unsigned receipt in a signed chain")
            elif not hmac.compare_digest(sign(expected, key), str(sig)):
                problems.append(f"{rid}: signature does not verify")
        prev = str(receipt.get("hash", expected))

    return (not problems), problems


def key_from_env(var: str = "MCP_ATTEST_KEY") -> str | None:
    return os.environ.get(var) or None
