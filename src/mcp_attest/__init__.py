"""mcp-attest — conformance and attestation harness for MCP agent access control."""

__version__ = "0.1.0"

from .checks import RULES, Finding, run_checks, summarize
from .policy import Policy, load_policy, policy_from_dict
from .receipts import build_receipts, verify_receipts
from .shadow import find_shadow_paths
from .trace import Trace, load_trace

__all__ = [
    "RULES",
    "Finding",
    "Policy",
    "Trace",
    "build_receipts",
    "find_shadow_paths",
    "load_policy",
    "load_trace",
    "policy_from_dict",
    "run_checks",
    "summarize",
    "verify_receipts",
]
