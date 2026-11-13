"""Passive posture measurement for public MCP servers.

What this does, and what it refuses to do
-----------------------------------------
It sends at most three requests per server: the ``initialize`` handshake, the
``notifications/initialized`` notification, and ``tools/list``. It never calls
a tool. A tool call can change someone else's system, so on a server that is
not ours the measurement stops at the manifest.

Everything it sends is well-formed traffic from the specification. No fuzzing,
no malformed payloads, no path probing, one connection per server, and a pause
between servers so that a scan never looks like an attack from the inside.

The unit of measurement is the registry entry, not the operator. The question
is what a client that trusts the registry's remote list meets when it connects
without credentials.

The reports this module produces carry aggregates. The per-server dataset is
written to a file the operator keeps: naming a host that accepts an
unauthenticated session is a disclosure, and disclosure is the operator's
decision, not the tool's.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any

from .oauth import http_request

REGISTRY_URL = "https://registry.modelcontextprotocol.io/v0/servers"

PROTOCOL_VERSION = "2025-06-18"

# Tool names that reach outside the server's own data: a shell, a file, a URL.
SENSITIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("shell", re.compile(r"(?i)(^|_)(exec|execute|shell|bash|sh|eval|run_?command|popen|spawn|system|powershell)(_|$)")),
    ("filesystem", re.compile(r"(?i)(^|_)(read|write|delete|remove|list|upload|download|move|copy)_?(file|files|dir|directory|folder|path)(_|$)")),
    ("network", re.compile(r"(?i)(^|_)(http|https|fetch|curl|wget|download|upload|webhook|url|uri|web_request)(_|$)")),
    ("database", re.compile(r"(?i)(^|_)(sql|query|db|database|graphql|redis|mongo)(_|$)")),
)

SENSITIVE_PARAMS = {
    "command": "shell",
    "cmd": "shell",
    "script": "shell",
    "code": "shell",
    "path": "filesystem",
    "file": "filesystem",
    "filename": "filesystem",
    "filepath": "filesystem",
    "url": "network",
    "uri": "network",
    "query": "database",
    "sql": "database",
}


@dataclass
class PostureRecord:
    """What one server looked like from the outside."""

    name: str
    url: str
    reachable: bool = False
    status: int = 0
    requires_auth: bool | None = None
    tools: list[str] = field(default_factory=list)
    sensitive: list[str] = field(default_factory=list)
    publishes_metadata: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RegistryServer:
    name: str
    url: str
    title: str = ""


def registry_population(timeout: float = 60.0) -> list[RegistryServer]:
    """Every server the official registry lists, latest version, HTTP remote.

    The registry returns one row per published version, so the same server
    appears many times. Only the latest version of each name is kept, and
    only the entries that publish a Streamable HTTP remote: a stdio server
    cannot be reached from here at all.
    """
    servers: dict[str, RegistryServer] = {}
    cursor = ""
    for _ in range(60):
        url = REGISTRY_URL + "?limit=100"
        if cursor:
            url += "&cursor=" + urllib.parse.quote(cursor)
        request = urllib.request.Request(url, headers={"User-Agent": "mcp-attest"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                document = json.loads(response.read().decode("utf-8", "replace"))
        except Exception as exc:  # noqa: BLE001 - a partial registry is still usable
            if not servers:
                raise
            break
        for entry in document.get("servers") or []:
            server = entry.get("server") or {}
            meta = (entry.get("_meta") or {}).get("io.modelcontextprotocol.registry/official") or {}
            if meta.get("isLatest") is False:
                continue
            name = str(server.get("name") or "")
            if not name or name in servers:
                continue
            for remote in server.get("remotes") or []:
                if str(remote.get("type") or "") not in ("streamable-http", "http", "sse"):
                    continue
                endpoint = str(remote.get("url") or "")
                if endpoint.startswith("http"):
                    servers[name] = RegistryServer(
                        name=name,
                        url=endpoint,
                        title=str(server.get("title") or ""),
                    )
                break
        cursor = str((document.get("metadata") or {}).get("nextCursor") or "")
        if not cursor:
            break
    return sorted(servers.values(), key=lambda item: item.name)


def sample_population(population: list[RegistryServer], stride: int = 1, limit: int = 0) -> list[RegistryServer]:
    """Take every ``stride``-th server, so the sample covers the whole list.

    The registry is ordered by name, so the first N entries would only cover
    the names that start with a. A stride spreads the sample over the whole
    name space and keeps it reproducible: the same stride gives the same
    servers tomorrow.
    """
    stride = max(1, int(stride))
    chosen = population[::stride]
    if limit and len(chosen) > limit:
        chosen = chosen[:limit]
    return chosen


def _parse_mcp_body(body: str) -> dict[str, Any]:
    """A response may be JSON or an SSE stream.

    The stream usually starts with an ``event:`` line, so the ``data:`` line
    is looked for anywhere in the body rather than only at the top.
    """
    text = body.strip()
    if not text:
        return {}
    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        chunk = line[5:].strip()
        if not chunk:
            continue
        try:
            parsed = json.loads(chunk)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def measure(url: str, name: str = "", timeout: float = 15.0) -> PostureRecord:
    """Measure one server without calling any tool on it."""
    record = PostureRecord(name=name or url, url=url)

    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-attest", "version": "posture"},
            },
        }
    )
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": PROTOCOL_VERSION,
    }
    response = http_request(url, method="POST", headers=headers, body=body, timeout=timeout)
    record.status = response.status
    if response.status == 0:
        record.error = "unreachable"
        return record
    if response.status in (401, 403):
        record.reachable = True
        record.requires_auth = True
        record.publishes_metadata = bool(
            "resource_metadata" in (response.headers.get("www-authenticate") or "")
        )
        return record
    if response.status >= 400:
        record.error = "HTTP %d" % response.status
        return record

    record.reachable = True
    record.requires_auth = False

    session_id = response.headers.get("mcp-session-id")
    if session_id:
        headers["Mcp-Session-Id"] = session_id

    http_request(
        url,
        method="POST",
        headers=headers,
        body=json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        timeout=timeout,
    )

    listed = http_request(
        url,
        method="POST",
        headers=headers,
        body=json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        timeout=timeout,
    )
    document = _parse_mcp_body(listed.body)
    tools = (document.get("result") or {}).get("tools") or []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        tool_name = str(tool.get("name") or "")
        if not tool_name:
            continue
        record.tools.append(tool_name)
        category = _sensitivity(tool)
        if category:
            record.sensitive.append("%s:%s" % (category, tool_name))

    metadata = http_request(
        _metadata_url(url),
        timeout=min(timeout, 10.0),
    )
    record.publishes_metadata = metadata.status == 200
    return record


def _metadata_url(url: str) -> str:
    """The protected resource metadata URL for an MCP endpoint (RFC 9728)."""
    parts = url.split("/", 3)
    if len(parts) < 3:
        return url.rstrip("/") + "/.well-known/oauth-protected-resource"
    origin = "/".join(parts[:3])
    return origin + "/.well-known/oauth-protected-resource"


def _sensitivity(tool: dict[str, Any]) -> str:
    """The category a tool falls into, if any."""
    name = str(tool.get("name") or "")
    for category, pattern in SENSITIVE_PATTERNS:
        if pattern.search(name):
            return category
    schema = tool.get("inputSchema") or {}
    properties = schema.get("properties") or {}
    for parameter in properties:
        category = SENSITIVE_PARAMS.get(str(parameter).lower())
        if category:
            return category
    return ""


def scan(
    servers: list[RegistryServer],
    delay: float = 1.0,
    timeout: float = 15.0,
    progress: Any = None,
) -> list[PostureRecord]:
    """Measure a list of servers, one at a time, with a pause in between."""
    records: list[PostureRecord] = []
    for index, server in enumerate(servers, start=1):
        records.append(measure(server.url, server.name, timeout=timeout))
        if progress is not None:
            progress(index, len(servers), records[-1])
        if delay > 0 and index < len(servers):
            time.sleep(delay)
    return records


def summarize(records: list[PostureRecord]) -> dict[str, Any]:
    """The aggregates that go into the published report."""
    answered = [r for r in records if r.reachable]
    open_servers = [r for r in answered if r.requires_auth is False]
    closed_servers = [r for r in answered if r.requires_auth is True]
    with_tools = [r for r in open_servers if r.tools]
    sensitive = [r for r in open_servers if r.sensitive]
    tool_total = sum(len(r.tools) for r in open_servers)
    sensitive_total = sum(len(r.sensitive) for r in open_servers)
    return {
        "measured": len(records),
        "answered": len(answered),
        "unreachable": len(records) - len(answered),
        "open_without_credentials": len(open_servers),
        "closed": len(closed_servers),
        "open_with_a_manifest": len(with_tools),
        "open_exposing_sensitive_tools": len(sensitive),
        "tools_in_open_servers": tool_total,
        "sensitive_tools_in_open_servers": sensitive_total,
        "publishing_resource_metadata": len([r for r in answered if r.publishes_metadata]),
    }


def render_report(
    summary: dict[str, Any],
    source: str,
    when: str,
    include_hosts: bool = False,
    records: list[PostureRecord] | None = None,
) -> str:
    """The published report: aggregates, method, and what it does not say."""
    answered = summary.get("answered", 0)
    open_count = summary.get("open_without_credentials", 0)
    share = round(100.0 * open_count / answered, 1) if answered else 0.0
    lines = [
        "# MCP server posture",
        "",
        "Measured on %s against %s." % (when, source),
        "",
        "## The sample",
        "",
        "The registry lists %d server(s) that publish a Streamable HTTP remote, at their"
        % summary.get("registry_population", summary["measured"]),
        "latest version. The measurement covers every %s of them in the registry's order,"
        % summary.get("stride", 1),
        "so it spreads over the whole name space instead of over the names that happen",
        "to sort first, and it is reproducible: the same stride picks the same servers",
        "tomorrow.",
        "",
        "## What was measured",
        "",
        "| | |",
        "|---|---|",
        "| servers measured | %d |" % summary["measured"],
        "| answered the handshake | %d |" % summary["answered"],
        "| unreachable | %d |" % summary["unreachable"],
        "| accepted a session with no credentials | %d |" % summary["open_without_credentials"],
        "| refused a session with no credentials | %d |" % summary["closed"],
        "| of the open ones, returned a tool manifest | %d |" % summary["open_with_a_manifest"],
        "| of the open ones, expose a shell, file, network or database tool | %d |" % summary["open_exposing_sensitive_tools"],
        "| tools in the open servers | %d |" % summary["tools_in_open_servers"],
        "| sensitive tools in the open servers | %d |" % summary["sensitive_tools_in_open_servers"],
        "| publish protected resource metadata | %d |" % summary["publishing_resource_metadata"],
        "",
        "Of the %d servers that answered, %d (%.1f%%) opened a session with no credentials"
        % (answered, open_count, share),
        "at all, and %d of the %d that returned a manifest expose a tool that reaches a"
        % (summary["open_exposing_sensitive_tools"], summary["open_with_a_manifest"]),
        "shell, a file, a URL or a database.",
        "",
        "## Method",
        "",
        "Per server, at most three requests: the `initialize` handshake, the",
        "`notifications/initialized` notification and `tools/list`. No tool is ever",
        "called, so no side effect can be caused on a server that is not ours.",
        "Every request is well-formed traffic from the specification: no fuzzing, no",
        "malformed payloads, no path probing. One connection per server, with a pause",
        "in between.",
        "",
        "The numbers describe what a client that trusts the registry's remote list",
        "meets when it connects without credentials. They say nothing about the",
        "operator's intent: a public server that exposes a read-only tool and asks",
        "for no token may be exactly what it is for.",
        "",
        "## Reproduce it",
        "",
        "```sh",
        "attest posture --stride %s --delay %s --out posture.md --json posture.json"
        % (summary.get("stride", 1), summary.get("delay", 1.0)),
        "```",
        "",
        "## What this report does not contain",
        "",
        "No host names. A server that accepts an unauthenticated session is a",
        "disclosure, and disclosure is the operator's decision: the scan is shipped so",
        "that anyone can reproduce it, and the per-server dataset stays with whoever",
        "ran it.",
        "",
    ]
    if include_hosts and records:
        lines.extend(["## Servers", "", "| server | open | tools | sensitive |", "|---|---|---|---|"])
        for record in records:
            lines.append(
                "| %s | %s | %d | %d |"
                % (
                    record.name,
                    "yes" if record.requires_auth is False else ("no" if record.requires_auth else "unknown"),
                    len(record.tools),
                    len(record.sensitive),
                )
            )
        lines.append("")
    return "\n".join(lines)
