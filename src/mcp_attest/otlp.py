"""OTLP input.

Reads an OpenTelemetry export and turns the MCP spans in it into the trace
events the checks understand. The point is that a team already running OTel
does not have to add a second instrumentation path just to prove what their
agent was allowed to do.

Only spans that describe an MCP interaction are mapped. Everything else is
skipped and reported as a warning, so an export can be pointed at the tool
without pre-filtering it.

Expected span names
-------------------
mcp.tool.call        one tool invocation, with the policy decision
mcp.tools.list       the tool list an actor received
mcp.client.servers   the servers a client is configured with
mcp.gateway.route    the tools a gateway routes for a server

Attributes
----------
mcp.actor            who made the call
mcp.tool.name        the tool that was called
mcp.tool.arguments   JSON object with the arguments
mcp.policy.decision  allow | deny
mcp.policy.reason    why the policy decided that
mcp.upstream         whether the call went to the upstream server
mcp.servers          JSON array, for mcp.client.servers
mcp.tools            JSON array, for mcp.gateway.route
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .trace import Trace, parse_trace_lines

SPAN_TOOL_CALL = "mcp.tool.call"
SPAN_TOOLS_LIST = "mcp.tools.list"
SPAN_CLIENT_SERVERS = "mcp.client.servers"
SPAN_GATEWAY_ROUTE = "mcp.gateway.route"


def _attribute_value(raw: Any) -> Any:
    if not isinstance(raw, dict):
        return raw
    for key in ("stringValue", "intValue", "doubleValue", "boolValue", "bytesValue"):
        if key in raw:
            return raw[key]
    return raw


def _attributes(span: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in span.get("attributes") or []:
        if isinstance(item, dict) and "key" in item:
            out[str(item["key"])] = _attribute_value(item.get("value"))
    return out


def _timestamp(raw: Any) -> str:
    try:
        nanos = int(raw)
    except (TypeError, ValueError):
        return ""
    seconds, remainder = divmod(nanos, 1_000_000_000)
    moment = datetime.fromtimestamp(seconds, tz=timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S") + ".%09dZ" % remainder


def _as_json(value: Any, fallback: Any) -> Any:
    if value is None:
        return fallback
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value))
    except (TypeError, ValueError):
        return fallback


def _spans(payload: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for resource in payload.get("resourceSpans") or []:
        if not isinstance(resource, dict):
            continue
        for scope in resource.get("scopeSpans") or []:
            if not isinstance(scope, dict):
                continue
            for span in scope.get("spans") or []:
                if isinstance(span, dict):
                    out.append(span)
    return out


def span_to_event(span: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """Map one OTLP span to a trace event.

    Returns the event and an empty reason, or None and the reason the span was
    skipped.
    """
    name = str(span.get("name") or "")
    attrs = _attributes(span)
    ts = _timestamp(span.get("startTimeUnixNano"))

    if name == SPAN_TOOL_CALL:
        args = _as_json(attrs.get("mcp.tool.arguments"), {})
        if not isinstance(args, dict):
            args = {"value": args}
        decision = str(attrs.get("mcp.policy.decision") or "").lower()
        upstream = attrs.get("mcp.upstream")
        return {
            "type": "tool_call",
            "actor": str(attrs.get("mcp.actor") or "unknown"),
            "tool": str(attrs.get("mcp.tool.name") or ""),
            "args": args,
            "decision": decision,
            "upstream": bool(upstream) if upstream is not None else None,
            "reason": str(attrs.get("mcp.policy.reason") or ""),
            "ts": ts,
        }, ""

    if name == SPAN_TOOLS_LIST:
        tools = _as_json(attrs.get("mcp.tools"), [])
        if not isinstance(tools, list):
            tools = []
        return {
            "type": "tools_list",
            "actor": str(attrs.get("mcp.actor") or "unknown"),
            "tools": tools,
            "ts": ts,
        }, ""

    if name == SPAN_CLIENT_SERVERS:
        servers = _as_json(attrs.get("mcp.servers"), [])
        if not isinstance(servers, list):
            servers = []
        return {
            "type": "client_servers",
            "client": str(attrs.get("mcp.actor") or "unknown"),
            "servers": servers,
            "ts": ts,
        }, ""

    if name == SPAN_GATEWAY_ROUTE:
        tools = _as_json(attrs.get("mcp.tools"), [])
        if not isinstance(tools, list):
            tools = []
        return {
            "type": "gateway_route",
            "server": str(attrs.get("mcp.server") or attrs.get("mcp.actor") or "unknown"),
            "tools": tools,
            "ts": ts,
        }, ""

    return None, "span %r is not an MCP span, skipped" % name


def otlp_to_trace(payload: dict[str, Any]) -> Trace:
    events: list[dict[str, Any]] = []
    warnings: list[str] = []
    for span in _spans(payload):
        event, reason = span_to_event(span)
        if event is None:
            warnings.append(reason)
            continue
        events.append(event)
    lines = [json.dumps(event, sort_keys=True, separators=(",", ":")) for event in events]
    trace = parse_trace_lines(iter(lines))
    trace.warnings.extend(warnings)
    return trace


def load_otlp(path: str | Path) -> Trace:
    """Load an OTLP export.

    Accepts a single export payload, or newline-delimited export payloads, one
    per line.
    """
    text = Path(path).read_text(encoding="utf-8")
    payloads: list[dict[str, Any]] = []
    stripped = text.strip()
    if not stripped:
        return otlp_to_trace({})
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        payloads = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                payloads.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    else:
        if isinstance(parsed, list):
            payloads = [item for item in parsed if isinstance(item, dict)]
        elif isinstance(parsed, dict):
            payloads = [parsed]
    if not payloads:
        return otlp_to_trace({})

    merged: dict[str, Any] = {"resourceSpans": []}
    for payload in payloads:
        merged["resourceSpans"].extend(payload.get("resourceSpans") or [])
    return otlp_to_trace(merged)
