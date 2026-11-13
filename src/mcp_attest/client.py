"""A minimal MCP client: stdio and Streamable HTTP, standard library only.

Why hand-rolled instead of using an SDK:

* The harness must send exactly the bytes it claims to send. A conformance
  tool that hides the protocol behind a library cannot show its own evidence.
* It has to run in CI containers and air-gapped runners where pulling an SDK
  and its dependency tree is a liability.
* It has to present a *different identity* per connection, which the SDKs
  abstract away.

The client is deliberately strict: it performs the full ``initialize``
handshake, refuses to continue if the handshake failed, and never silently
swallows a protocol error.
"""

from __future__ import annotations

import json
import os
import queue
import shlex
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from . import jsonrpc
from .jsonrpc import Error, ProtocolError, Response, TransportError

DEFAULT_PROTOCOL_VERSION = "2025-06-18"
DEFAULT_TIMEOUT = 10.0


def _client_info() -> dict[str, Any]:
    from . import __version__

    return {"name": "mcp-attest", "version": __version__}


@dataclass
class CallOutcome:
    """What a single ``tools/call`` actually did.

    ``status`` is deliberately coarse. From a security standpoint only two
    things matter: did the call *succeed* (the tool ran) or did it *not*
    succeed (the tool did not run). How politely the server said no is a
    different question, and one that the error-hygiene rule asks separately.
    """

    status: str  # "allow" | "deny" | "error"
    detail: str = ""
    error: Error | None = None
    result: Any = None
    elapsed_ms: int = 0
    request: dict[str, Any] = field(default_factory=dict)

    @property
    def text(self) -> str:
        """The tool output flattened to text, for scanning."""
        if not isinstance(self.result, dict):
            return ""
        parts: list[str] = []
        for item in self.result.get("content") or []:
            if isinstance(item, dict):
                if item.get("type") == "text" and isinstance(item.get("text"), str):
                    parts.append(item["text"])
        if not parts and isinstance(self.result.get("structuredContent"), dict):
            parts.append(json.dumps(self.result["structuredContent"], ensure_ascii=False))
        return "\n".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "detail": self.detail,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error.to_dict() if self.error else None,
        }


class McpClient:
    """Base class: one connection to one MCP server."""

    def __init__(self) -> None:
        self.server_info: dict[str, Any] = {}
        self.capabilities: dict[str, Any] = {}
        self.protocol_version: str = DEFAULT_PROTOCOL_VERSION
        self.session_id: str | None = None

    # -- transport primitives, implemented by subclasses -------------------

    def send(self, message: dict[str, Any]) -> None:
        raise NotImplementedError

    def receive(self, timeout: float) -> dict[str, Any]:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    # -- JSON-RPC plumbing ------------------------------------------------

    def call(self, method: str, params: dict[str, Any] | None = None, timeout: float = DEFAULT_TIMEOUT) -> Response:
        msg = jsonrpc.request(method, params)
        self.send(msg)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportError(f"no answer to {method!r} within {timeout:.0f}s")
            try:
                incoming = self.receive(remaining)
            except TransportError:
                raise
            if incoming.get("method") is not None:
                # A notification or a server-initiated request: not our answer.
                continue
            if incoming.get("id") != msg["id"]:
                continue
            return jsonrpc.as_response(incoming)

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self.send(jsonrpc.notification(method, params))


class StdioClient(McpClient):
    """MCP over stdio: newline-delimited JSON-RPC on the child's stdin/stdout."""

    def __init__(self, command: list[str], env: dict[str, str] | None = None, cwd: str | None = None) -> None:
        super().__init__()
        self.command = command
        child_env = dict(os.environ)
        if env:
            child_env.update(env)
        try:
            self._proc = subprocess.Popen(  # noqa: S603 - the command comes from the operator
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=child_env,
                cwd=cwd,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except OSError as exc:
            raise TransportError(f"cannot start {command[0]!r}: {exc}") from exc
        self._lines: queue.Queue[str | None] = queue.Queue()
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()

    def _pump(self) -> None:
        assert self._proc.stdout is not None
        try:
            for line in self._proc.stdout:
                self._lines.put(line)
        except Exception:
            pass
        self._lines.put(None)

    def send(self, message: dict[str, Any]) -> None:
        if self._proc.poll() is not None:
            raise TransportError(f"server process exited with code {self._proc.returncode}")
        assert self._proc.stdin is not None
        try:
            self._proc.stdin.write(jsonrpc.encode(message) + "\n")
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise TransportError(f"server stopped reading input: {exc}") from exc

    def receive(self, timeout: float) -> dict[str, Any]:
        try:
            line = self._lines.get(timeout=timeout)
        except queue.Empty:
            raise TransportError("timed out waiting for the server") from None
        if line is None:
            raise TransportError(f"server process exited with code {self._proc.poll()}")
        return jsonrpc.parse(line.strip())

    def close(self) -> None:
        try:
            if self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
        except Exception:
            pass
        for stream in (self._proc.stdin, self._proc.stdout):
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass


class HttpClient(McpClient):
    """MCP over Streamable HTTP.

    Handles both response shapes the specification allows: a single JSON body
    and an SSE stream. The ``Mcp-Session-Id`` header is used when the server
    provides one and ignored when it does not, because the 2026-07-28 revision
    of the specification removed transport-level sessions.
    """

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        super().__init__()
        self.url = url
        self.headers = dict(headers or {})
        self.timeout = timeout

    def _request_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "mcp-attest",
        }
        if self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        headers.update(self.headers)
        return headers

    def _post(self, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        data = jsonrpc.encode(payload).encode("utf-8")
        req = urllib.request.Request(self.url, data=data, headers=self._request_headers(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                self._remember_session(resp)
                body = resp.read().decode("utf-8", "replace")
                content_type = (resp.headers.get("Content-Type") or "").lower()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            content_type = (exc.headers.get("Content-Type") or "").lower() if exc.headers else ""
            status = exc.code
            exc.close()
            if status in (401, 403):
                raise _HttpDenied(status, body) from exc
            raise TransportError(f"HTTP {status} from {self.url}: {body[:200]}") from exc
        except urllib.error.URLError as exc:
            raise TransportError(f"cannot reach {self.url}: {exc.reason}") from exc
        except OSError as exc:
            raise TransportError(f"cannot reach {self.url}: {exc}") from exc

        if "text/event-stream" in content_type:
            return self._parse_sse(body)
        if not body.strip():
            raise TransportError("server returned an empty body")
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"server returned a body that is not JSON: {exc}") from exc

    @staticmethod
    def _parse_sse(body: str) -> dict[str, Any]:
        for line in body.splitlines():
            if line.startswith("data:"):
                chunk = line[5:].strip()
                if not chunk:
                    continue
                try:
                    parsed = json.loads(chunk)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, dict):
                    return parsed
        raise ProtocolError("SSE response carried no JSON-RPC message")

    def _remember_session(self, resp: Any) -> None:
        headers = getattr(resp, "headers", None)
        if headers is None:
            return
        session = headers.get("Mcp-Session-Id")
        if session:
            self.session_id = session

    def send(self, message: dict[str, Any]) -> None:
        # HTTP is request/response: nothing is queued here.
        return None

    def receive(self, timeout: float) -> dict[str, Any]:
        raise TransportError("HttpClient answers requests directly; use call()")

    def call(self, method: str, params: dict[str, Any] | None = None, timeout: float = DEFAULT_TIMEOUT) -> Response:
        msg = jsonrpc.request(method, params)
        payload = self._post(msg, timeout)
        if isinstance(payload, dict) and payload.get("id") is None and payload.get("method") is not None:
            raise ProtocolError("server replied with a request, not a response")
        return jsonrpc.as_response(payload if isinstance(payload, dict) else {})

    def close(self) -> None:
        return None


class _HttpDenied(Exception):
    """HTTP 401/403: the transport refused us before any tool ran."""

    def __init__(self, code: int, body: str) -> None:
        super().__init__(f"HTTP {code}")
        self.code = code
        self.body = body


@dataclass
class ServerTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    annotations: dict[str, Any]
    raw: dict[str, Any]

    @property
    def read_only(self) -> bool:
        return bool(self.annotations.get("readOnlyHint"))

    @property
    def destructive(self) -> bool:
        return bool(self.annotations.get("destructiveHint"))

    @property
    def open_world(self) -> bool:
        return bool(self.annotations.get("openWorldHint"))

    @property
    def idemponent_hint(self) -> bool:
        return bool(self.annotations.get("idempotentHint"))

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "ServerTool":
        return cls(
            name=str(raw.get("name") or ""),
            description=str(raw.get("description") or ""),
            input_schema=raw.get("inputSchema") or {},
            annotations=raw.get("annotations") or {},
            raw=raw,
        )


class McpSession:
    """One authenticated conversation with one server, as one identity."""

    def __init__(self, client: McpClient, identity: str, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.client = client
        self.identity = identity
        self.timeout = timeout
        self.tools: list[ServerTool] = []
        self.resources: list[dict[str, Any]] = []
        self.prompts: list[dict[str, Any]] = []

    def open(self) -> "McpSession":
        params = {
            "protocolVersion": self.client.protocol_version,
            "capabilities": {},
            "clientInfo": _client_info(),
        }
        try:
            resp = self.client.call("initialize", params, timeout=self.timeout)
        except _HttpDenied as exc:
            raise TransportError(f"server refused the handshake: HTTP {exc.code}") from exc
        if resp.is_error:
            raise ProtocolError(
                f"initialize failed: [{resp.error.code if resp.error else '?'}] {resp.error.message if resp.error else ''}"
            )
        result = resp.result or {}
        self.client.protocol_version = str(result.get("protocolVersion") or self.client.protocol_version)
        self.client.server_info = result.get("serverInfo") or {}
        self.client.capabilities = result.get("capabilities") or {}
        try:
            self.client.notify("notifications/initialized")
        except TransportError:
            pass
        self.tools = [ServerTool.from_raw(t) for t in self._list("tools/list", "tools")]
        self.resources = self._list("resources/list", "resources")
        self.prompts = self._list("prompts/list", "prompts")
        return self

    def _list(self, method: str, key: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(20):  # pagination guard
            params = {"cursor": cursor} if cursor else None
            try:
                resp = self.client.call(method, params, timeout=self.timeout)
            except (TransportError, ProtocolError):
                break
            if resp.is_error:
                break
            result = resp.result or {}
            chunk = result.get(key) or []
            if isinstance(chunk, list):
                items.extend([c for c in chunk if isinstance(c, dict)])
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return items

    def call_tool(self, name: str, args: dict[str, Any] | None = None) -> CallOutcome:
        payload = {"name": name, "arguments": args or {}}
        started = time.monotonic()
        try:
            resp = self.client.call("tools/call", payload, timeout=self.timeout)
        except _HttpDenied as exc:
            elapsed = int((time.monotonic() - started) * 1000)
            return CallOutcome(
                status="deny",
                detail=f"transport refused the call: HTTP {exc.code}",
                elapsed_ms=elapsed,
                request={"method": "tools/call", "params": payload},
            )
        except (TransportError, ProtocolError) as exc:
            elapsed = int((time.monotonic() - started) * 1000)
            return CallOutcome(
                status="error",
                detail=str(exc),
                elapsed_ms=elapsed,
                request={"method": "tools/call", "params": payload},
            )
        elapsed = int((time.monotonic() - started) * 1000)
        if resp.is_error:
            err = resp.error or Error(-32603, "unknown error")
            return CallOutcome(
                status="deny",
                detail=f"[{err.code}] {err.message}",
                error=err,
                elapsed_ms=elapsed,
                request={"method": "tools/call", "params": payload},
            )
        result = resp.result if isinstance(resp.result, dict) else {}
        if result.get("isError"):
            return CallOutcome(
                status="deny",
                detail="tool reported isError",
                result=result,
                elapsed_ms=elapsed,
                request={"method": "tools/call", "params": payload},
            )
        return CallOutcome(
            status="allow",
            detail="tool executed",
            result=result,
            elapsed_ms=elapsed,
            request={"method": "tools/call", "params": payload},
        )

    def close(self) -> None:
        self.client.close()


def split_command(command: str) -> list[str]:
    """Split a command line into argv, honouring quotes on every platform."""
    if isinstance(command, list):  # type: ignore[unreachable]
        return list(command)
    return shlex.split(command, posix=os.name != "nt")
