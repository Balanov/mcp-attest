"""mcp-attest — conformance and attestation harness for MCP agent access control."""

__version__ = "1.2.1"

from .checks import RULES, Finding, run_checks, summarize
from .conformance import ConformanceResult, RunOptions, run_conformance
from .evidence import build_bundle, verify_bundle
from .policy import Policy, load_policy, policy_from_dict
from .receipts import build_receipts, verify_receipts
from .rules import RULES as LIVE_RULES
from .shadow import find_shadow_paths
from .trace import Trace, load_trace

__all__ = [
    "ConformanceResult",
    "Finding",
    "LIVE_RULES",
    "Policy",
    "RULES",
    "RunOptions",
    "Trace",
    "build_bundle",
    "build_receipts",
    "find_shadow_paths",
    "load_policy",
    "load_trace",
    "policy_from_dict",
    "run_checks",
    "run_conformance",
    "summarize",
    "verify_bundle",
    "verify_receipts",
]
