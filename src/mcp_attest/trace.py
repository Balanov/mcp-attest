"""Trace model.

A trace is newline-delimited JSON. Every line is one observed event from an
agent session, a gateway, or a client configuration. The format is intentionally
append-only and boring so that it can be produced by a proxy, a CI job, or a
hand-written fixture in a bug report.

Event types
-----------
tools_list    {"type":"tools_list","actor":"ci-bot","tools":[{"name":"...","description_sha256":"..."}]}
tool_call     {"type":"tool_call","actor":"ci-bot","tool":"...","args":{...},"decision":"allow|deny",
               "upstream":true|false,"reason":"...","ts":"..."}
client_servers {"type":"client_servers","client":"claude-code","servers":["fs","git"]}
gateway_route {"type":"gateway_route","server":"fs","tools":["read_file"]}
receipt       {"type":"receipt","id":"...","prev":"...","hash":"...","sig":"...","ts":"..."}
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

KNOWN_TYPES = {
    "tools_list",
    "tool_call",
    "client_servers",
    "gateway_route",
    "receipt",
    "note",
}


@dataclass
class Event:
    type: str
    raw: dict[str, Any] = field(default_factory=dict)
    line_no: int = 0

    def get(self, key: str, default: Any = None) -> Any:
        return self.raw.get(key, default)


@dataclass
class ToolCall:
    actor: str
    tool: str
    args: dict[str, Any]
    decision: str
    upstream: bool | None
    reason: str
    ts: str
    line_no: int


@dataclass
class ToolsList:
    actor: str
    tools: list[dict[str, Any]]
    ts: str
    line_no: int

    @property
    def names(self) -> list[str]:
        return [t.get("name", "") for t in self.tools if t.get("name")]


@dataclass
class Trace:
    events: list[Event] = field(default_factory=list)
    tool_calls: list[ToolCall] = field(default_factory=list)
    tools_lists: list[ToolsList] = field(default_factory=list)
    client_servers: dict[str, list[str]] = field(default_factory=dict)
    gateway_routes: dict[str, list[str]] = field(default_factory=dict)
    receipts: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def calls_by_actor(self) -> dict[str, list[ToolCall]]:
        out: dict[str, list[ToolCall]] = {}
        for call in self.tool_calls:
            out.setdefault(call.actor, []).append(call)
        return out

    def lists_by_actor(self) -> dict[str, list[ToolsList]]:
        out: dict[str, list[ToolsList]] = {}
        for tl in self.tools_lists:
            out.setdefault(tl.actor, []).append(tl)
        return out


def parse_trace_lines(lines: Iterator[str]) -> Trace:
    trace = Trace()
    for line_no, line in enumerate(lines, start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            trace.warnings.append(f"line {line_no}: not valid JSON, skipped")
            continue
        if not isinstance(data, dict):
            trace.warnings.append(f"line {line_no}: expected a JSON object")
            continue
        etype = data.get("type")
        if etype not in KNOWN_TYPES:
            trace.warnings.append(f"line {line_no}: unknown event type {etype!r}, skipped")
            continue

        event = Event(type=etype, raw=data, line_no=line_no)
        trace.events.append(event)

        if etype == "tools_list":
            trace.tools_lists.append(
                ToolsList(
                    actor=data.get("actor", "unknown"),
                    tools=data.get("tools") or [],
                    ts=data.get("ts", ""),
                    line_no=line_no,
                )
            )
        elif etype == "tool_call":
            trace.tool_calls.append(
                ToolCall(
                    actor=data.get("actor", "unknown"),
                    tool=data.get("tool", ""),
                    args=data.get("args") or {},
                    decision=str(data.get("decision", "")).lower(),
                    upstream=data.get("upstream"),
                    reason=data.get("reason", ""),
                    ts=data.get("ts", ""),
                    line_no=line_no,
                )
            )
        elif etype == "client_servers":
            trace.client_servers[data.get("client", "unknown")] = list(data.get("servers") or [])
        elif etype == "gateway_route":
            trace.gateway_routes[data.get("server", "unknown")] = list(data.get("tools") or [])
        elif etype == "receipt":
            trace.receipts.append(data)

    return trace


def load_trace(path: str | Path) -> Trace:
    with Path(path).open("r", encoding="utf-8") as fh:
        return parse_trace_lines(fh)


def write_trace(path: str | Path, events: list[dict[str, Any]]) -> None:
    lines = [json.dumps(e, sort_keys=True, separators=(",", ":")) for e in events]
    Path(path).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
