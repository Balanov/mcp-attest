#!/usr/bin/env python3
"""A toy MCP server over Streamable HTTP, for exercising mcp-attest.

    python examples/servers/orders_http_server.py --port 8931

It speaks the same protocol as the stdio server, over HTTP, with bearer
tokens. Two flags change its behaviour so both outcomes can be seen:

``--weak-tokens``
    Accept any token that starts with a known prefix, the way a server that
    only looks at the first characters of a token does. ``mcp-attest`` then
    reports that a tampered token was accepted.

``--no-auth``
    Accept every request, the way a server that believes the network is
    friendly does. ``mcp-attest`` then reports that a token is not checked
    at all.

The data is synthetic and lives only in this file.
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTOCOL_VERSION = "2025-06-18"

TOKENS = {
    "alice-token": "alice",
    "lead-token": "lead",
}

ORDERS = {
    "A-1": {"owner": "alice", "total": 120, "status": "paid"},
    "B-77": {"owner": "bob", "total": 480, "status": "paid"},
}

TOOLS = [
    {
        "name": "list_orders",
        "description": "List the orders the caller may read.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "get_order",
        "description": "Read one order the caller owns.",
        "inputSchema": {
            "type": "object",
            "required": ["order_id"],
            "additionalProperties": False,
            "properties": {"order_id": {"type": "string", "maxLength": 32, "pattern": "^[A-Z]-[0-9]+$"}},
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
    },
    {
        "name": "refund_order",
        "description": "Refund an order. Only the lead role may call this.",
        "inputSchema": {
            "type": "object",
            "required": ["order_id", "amount"],
            "additionalProperties": False,
            "properties": {
                "order_id": {"type": "string", "pattern": "^[A-Z]-[0-9]+$"},
                "amount": {"type": "number", "minimum": 1, "maximum": 500},
            },
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
    },
]


class Handler(BaseHTTPRequestHandler):
    server_version = "orders-http/1.0"
    weak_tokens = False
    no_auth = False

    def log_message(self, fmt: str, *args) -> None:  # keep the console quiet
        pass

    # -- helpers ---------------------------------------------------------

    def actor(self) -> str | None:
        header = self.headers.get("Authorization") or ""
        if not header.lower().startswith("bearer "):
            return None
        token = header[7:].strip()
        if self.no_auth:
            return "alice"
        if self.weak_tokens:
            for known in TOKENS:
                if token.startswith(known[:8]):
                    return TOKENS[known]
            return None
        return TOKENS.get(token)

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -- HTTP ------------------------------------------------------------

    def do_GET(self) -> None:
        self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            message = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self.send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            return

        actor = self.actor()
        if actor is None:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer realm="orders"')
            body = json.dumps({"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32001, "message": "unauthorized"}}).encode()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        result = self.dispatch(message, actor)
        if result is None:
            return
        self.send_json(200, result)

    def dispatch(self, message: dict, actor: str) -> dict | None:
        method = message.get("method")
        message_id = message.get("id")
        params = message.get("params") or {}

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": message_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "orders-http", "version": "1.0.0"},
                },
            }
        if method in ("notifications/initialized", "initialized"):
            return None
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": message_id, "result": {"tools": TOOLS}}
        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": message_id, "result": {"resources": []}}
        if method == "prompts/list":
            return {"jsonrpc": "2.0", "id": message_id, "result": {"prompts": []}}
        if method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            try:
                text = self.call_tool(name, args, actor)
            except PermissionError as exc:
                return {"jsonrpc": "2.0", "id": message_id, "error": {"code": -32001, "message": str(exc)}}
            except Exception as exc:  # noqa: BLE001
                return {
                    "jsonrpc": "2.0",
                    "id": message_id,
                    "error": {"code": -32603, "message": f"{type(exc).__name__}: request could not be completed (ref-2)"},
                }
            return {
                "jsonrpc": "2.0",
                "id": message_id,
                "result": {"content": [{"type": "text", "text": text}], "isError": False},
            }
        return {"jsonrpc": "2.0", "id": message_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}

    def call_tool(self, name: str, args: dict, actor: str) -> str:
        if name == "list_orders":
            return json.dumps([o for o in ORDERS.values() if o["owner"] == actor])
        if name == "get_order":
            order_id = str(args.get("order_id", ""))
            order = ORDERS.get(order_id)
            if order is None:
                raise KeyError("no such order")
            if order["owner"] != actor and actor != "lead":
                raise PermissionError("order belongs to another principal")
            return json.dumps(order)
        if name == "refund_order":
            if actor != "lead":
                raise PermissionError("only the lead role may refund an order")
            order_id = str(args.get("order_id", ""))
            if order_id not in ORDERS:
                raise KeyError("no such order")
            return json.dumps({"order_id": order_id, "refunded": True})
        raise KeyError(f"unknown tool: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Toy MCP server over Streamable HTTP.")
    parser.add_argument("--port", type=int, default=8931)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--weak-tokens", action="store_true", help="accept any token with a known prefix")
    parser.add_argument("--no-auth", action="store_true", help="accept every request")
    args = parser.parse_args()

    Handler.weak_tokens = args.weak_tokens
    Handler.no_auth = args.no_auth
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"orders-http listening on http://{args.host}:{args.port}/mcp", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
