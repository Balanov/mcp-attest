"""JSON-RPC 2.0 messages: the wire format every MCP transport speaks.

Keeping our own tiny implementation means the harness sends exactly what it
documents, with no SDK in the path and no dependency drift between the version
we advertise and the version we call.
"""

from __future__ import annotations

import itertools
import json
from dataclasses import dataclass
from typing import Any

JSONRPC_VERSION = "2.0"

# The JSON-RPC error codes the harness reasons about.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


@dataclass(frozen=True)
class Error:
    code: int
    message: str
    data: Any = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            out["data"] = self.data
        return out

    @classmethod
    def from_dict(cls, raw: Any) -> "Error":
        if not isinstance(raw, dict):
            return cls(INTERNAL_ERROR, str(raw))
        try:
            code = int(raw.get("code", INTERNAL_ERROR))
        except (TypeError, ValueError):
            code = INTERNAL_ERROR
        return cls(code, str(raw.get("message", "")), raw.get("data"))


@dataclass
class Response:
    id: Any
    result: Any = None
    error: Error | None = None

    @property
    def is_error(self) -> bool:
        return self.error is not None


class ProtocolError(RuntimeError):
    """The server answered with something that is not a usable JSON-RPC message."""


class TransportError(RuntimeError):
    """The server could not be reached, or died mid-exchange."""


_ids = itertools.count(1)


def next_id() -> int:
    return next(_ids)


def request(method: str, params: dict[str, Any] | None = None, request_id: Any = None) -> dict[str, Any]:
    msg: dict[str, Any] = {
        "jsonrpc": JSONRPC_VERSION,
        "id": next_id() if request_id is None else request_id,
        "method": method,
    }
    if params is not None:
        msg["params"] = params
    return msg


def notification(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def encode(message: dict[str, Any]) -> str:
    """One JSON-RPC message as a single line.

    The stdio transport frames messages with newlines, so a message must never
    contain a raw newline: ``json.dumps`` escapes them for us.
    """
    return json.dumps(message, ensure_ascii=False, separators=(",", ":"))


def parse(text: str) -> dict[str, Any]:
    try:
        msg = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"server sent a line that is not JSON: {exc}") from exc
    if not isinstance(msg, dict):
        raise ProtocolError("server sent a JSON value that is not a JSON-RPC object")
    return msg


def as_response(message: dict[str, Any]) -> Response:
    if message.get("error") is not None:
        return Response(id=message.get("id"), error=Error.from_dict(message["error"]))
    return Response(id=message.get("id"), result=message.get("result"))
