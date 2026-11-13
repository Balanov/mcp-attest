#!/usr/bin/env python3
"""A toy MCP server over Streamable HTTP, for exercising mcp-attest.

    python examples/servers/orders_http_server.py --port 8931

It speaks the same protocol as the stdio server, over HTTP, with bearer
tokens. Several flags change its behaviour so that both outcomes can be seen.

``--weak-tokens``
    Accept any token that starts with a known prefix, the way a server that
    only looks at the first characters of a token does. ``mcp-attest`` then
    reports that a tampered token was accepted.

``--no-auth``
    Accept every request, the way a server that believes the network is
    friendly does. ``mcp-attest`` then reports that a token is not checked
    at all.

``--oauth``
    Switch to a real OAuth 2.1 shape: tokens are HS256 JWTs, the server
    publishes protected resource metadata (RFC 9728) and authorization server
    metadata (RFC 8414), and it serves ``/authorize`` and ``/token``. Every
    individual check can then be switched off on its own, so a conformance
    harness can be shown one defect at a time:

    ``--no-token-check``         a request without a token is accepted
    ``--no-signature-check``     a tampered or unsigned token is accepted
    ``--no-expiry-check``        an expired token is accepted
    ``--no-audience-check``      a token for another audience is accepted
    ``--no-issuer-check``        a token from another issuer is accepted
    ``--no-scope-check``         a tool runs without the scope it requires
    ``--no-resource-metadata``   the refusal does not point at the metadata
    ``--no-pkce``                a code is issued without a PKCE challenge
    ``--no-redirect-check``      a code is issued for any redirect_uri
    ``--no-state``               the authorization response drops the state

The data is synthetic and lives only in this file.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.parse
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

# The scope every tool needs. A token that does not carry it must not run it.
TOOL_SCOPES = {
    "list_orders": "orders:read",
    "get_order": "orders:read",
    "refund_order": "orders:write",
}

ROLE_SCOPES = {
    "alice": ["orders:read"],
    "lead": ["orders:read", "orders:write"],
}


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def mint_jwt(payload: dict, key: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = "%s.%s" % (
        b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode()),
        b64url(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()),
    )
    signature = hmac.new(key.encode(), signing_input.encode("ascii"), hashlib.sha256).digest()
    return "%s.%s" % (signing_input, b64url(signature))


def decode_jwt(token: str) -> tuple[dict, dict]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload


class Handler(BaseHTTPRequestHandler):
    server_version = "orders-http/1.1"
    weak_tokens = False
    no_auth = False

    # OAuth switches
    oauth = False
    oauth_key = "test-signing-key"
    oauth_issuer = "https://auth.example.com/"
    oauth_audience = "mcp://orders"
    redirect_uri = "http://127.0.0.1:8931/callback"
    base_url = "http://127.0.0.1:8931"
    no_token_check = False
    no_signature_check = False
    no_expiry_check = False
    no_audience_check = False
    no_issuer_check = False
    no_scope_check = False
    no_resource_metadata = False
    no_pkce = False
    no_redirect_check = False
    no_state = False

    codes: dict[str, dict] = {}

    def log_message(self, fmt: str, *args) -> None:  # keep the console quiet
        pass

    # -- tokens ----------------------------------------------------------

    def bearer_token(self) -> str | None:
        header = self.headers.get("Authorization") or ""
        if not header.lower().startswith("bearer "):
            return None
        return header[7:].strip()

    def actor(self) -> str | None:
        """The principal behind this request, or None when it must be refused."""
        if self.oauth:
            return self.oauth_actor()
        token = self.bearer_token()
        if token is None:
            return None
        if self.no_auth:
            return "alice"
        if self.weak_tokens:
            for known in TOKENS:
                if token.startswith(known[:8]):
                    return TOKENS[known]
            return None
        return TOKENS.get(token)

    def oauth_actor(self) -> str | None:
        """Validate a JWT the way OAuth 2.1 asks, minus the checks that are off."""
        token = self.bearer_token()
        if token is None:
            if self.no_token_check:
                return "alice"
            return None
        try:
            header, payload = decode_jwt(token)
        except (ValueError, json.JSONDecodeError):
            if self.no_signature_check:
                return "alice"
            return None

        algorithm = str(header.get("alg") or "")
        if algorithm.lower() == "none":
            if self.no_signature_check:
                return str(payload.get("sub") or "alice")
            return None
        if not self.no_signature_check:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            signing_input = "%s.%s" % (parts[0], parts[1])
            expected = hmac.new(
                self.oauth_key.encode(), signing_input.encode("ascii"), hashlib.sha256
            ).digest()
            if not hmac.compare_digest(expected, b64url_decode(parts[2])):
                return None

        if not self.no_issuer_check:
            if str(payload.get("iss") or "") != self.oauth_issuer:
                return None
        if not self.no_audience_check:
            audience = payload.get("aud")
            audiences = audience if isinstance(audience, list) else [audience]
            if self.oauth_audience not in [str(a) for a in audiences]:
                return None
        if not self.no_expiry_check:
            expiry = payload.get("exp")
            if not isinstance(expiry, (int, float)) or expiry < time.time():
                return None
        subject = str(payload.get("sub") or "")
        return subject or None

    def scopes_of(self) -> set[str]:
        token = self.bearer_token()
        if not token:
            return set()
        try:
            _, payload = decode_jwt(token)
        except (ValueError, json.JSONDecodeError):
            return set()
        raw = payload.get("scope") or ""
        return {part for part in str(raw).split() if part}

    # -- helpers ---------------------------------------------------------

    def send_json(self, status: int, payload: dict, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def send_empty(self, status: int, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()

    def redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def authenticate_header(self) -> str:
        if self.no_resource_metadata:
            return 'Bearer realm="orders"'
        return 'Bearer realm="orders", resource_metadata="%s/.well-known/oauth-protected-resource"' % self.base_url

    def refuse(self, message_id, code: int = -32001) -> None:
        self.send_response(401)
        body = json.dumps(
            {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": "unauthorized"}}
        ).encode("utf-8")
        self.send_header("WWW-Authenticate", self.authenticate_header())
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -- HTTP ------------------------------------------------------------

    def do_GET(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path == "/.well-known/oauth-protected-resource":
            if self.no_resource_metadata:
                self.send_json(404, {"error": "not found"})
                return
            self.send_json(
                200,
                {
                    "resource": self.base_url + "/mcp",
                    "authorization_servers": [self.base_url],
                    "scopes_supported": ["orders:read", "orders:write"],
                    "bearer_methods_supported": ["header"],
                },
            )
            return
        if path == "/.well-known/oauth-authorization-server":
            self.send_json(
                200,
                {
                    "issuer": self.oauth_issuer,
                    "authorization_endpoint": self.base_url + "/authorize",
                    "token_endpoint": self.base_url + "/token",
                    "code_challenge_methods_supported": ["S256"],
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code"],
                },
            )
            return
        if path == "/authorize":
            self.handle_authorize()
            return
        self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path == "/token":
            self.handle_token()
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            message = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self.send_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            return

        actor = self.actor()
        if actor is None:
            self.refuse(message.get("id"))
            return

        result = self.dispatch(message, actor)
        if result is None:
            return
        self.send_json(200, result)

    # -- authorization ---------------------------------------------------

    def handle_authorize(self) -> None:
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        redirect_uri = (query.get("redirect_uri") or [""])[0]
        state = (query.get("state") or [""])[0]
        challenge = (query.get("code_challenge") or [""])[0]
        method = (query.get("code_challenge_method") or [""])[0]
        scope = (query.get("scope") or ["orders:read"])[0]

        if not self.no_redirect_check and redirect_uri != self.redirect_uri:
            self.send_json(400, {"error": "invalid_request", "error_description": "redirect_uri is not registered"})
            return
        if not self.no_pkce:
            if not challenge:
                self.send_json(400, {"error": "invalid_request", "error_description": "code_challenge is required"})
                return
            if method != "S256":
                self.send_json(400, {"error": "invalid_request", "error_description": "code_challenge_method must be S256"})
                return

        code = "code-%d" % (len(self.codes) + 1)
        self.codes[code] = {"challenge": challenge, "scope": scope, "redirect_uri": redirect_uri}
        params = {"code": code}
        if state and not self.no_state:
            params["state"] = state
        separator = "&" if "?" in redirect_uri else "?"
        self.redirect(redirect_uri + separator + urllib.parse.urlencode(params))

    def handle_token(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        form = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
        code = (form.get("code") or [""])[0]
        verifier = (form.get("code_verifier") or [""])[0]
        entry = self.codes.get(code)
        if entry is None:
            self.send_json(400, {"error": "invalid_grant"})
            return
        if entry["challenge"]:
            computed = b64url(hashlib.sha256(verifier.encode()).digest())
            if not hmac.compare_digest(computed, entry["challenge"]):
                self.send_json(400, {"error": "invalid_grant", "error_description": "PKCE verification failed"})
                return
        subject = "lead" if "orders:write" in entry["scope"] else "alice"
        now = int(time.time())
        token = mint_jwt(
            {
                "sub": subject,
                "iss": self.oauth_issuer,
                "aud": self.oauth_audience,
                "scope": entry["scope"],
                "iat": now,
                "exp": now + 3600,
            },
            self.oauth_key,
        )
        self.send_json(
            200,
            {
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": entry["scope"],
            },
        )

    # -- MCP -------------------------------------------------------------

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
        if self.oauth and not self.no_scope_check:
            needed = TOOL_SCOPES.get(str(name))
            if needed and needed not in self.scopes_of():
                raise PermissionError("the token does not carry the scope '%s' this tool needs" % needed)
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
    parser.add_argument("--oauth", action="store_true", help="speak OAuth 2.1: JWT tokens, metadata, /authorize and /token")
    parser.add_argument("--oauth-key", default="test-signing-key", help="HS256 signing key")
    parser.add_argument("--oauth-issuer", default="https://auth.example.com/")
    parser.add_argument("--oauth-audience", default="mcp://orders")
    parser.add_argument("--redirect-uri", default="", help="the registered redirect URI (default: <base>/callback)")
    parser.add_argument("--no-token-check", action="store_true")
    parser.add_argument("--no-signature-check", action="store_true")
    parser.add_argument("--no-expiry-check", action="store_true")
    parser.add_argument("--no-audience-check", action="store_true")
    parser.add_argument("--no-issuer-check", action="store_true")
    parser.add_argument("--no-scope-check", action="store_true")
    parser.add_argument("--no-resource-metadata", action="store_true")
    parser.add_argument("--no-pkce", action="store_true")
    parser.add_argument("--no-redirect-check", action="store_true")
    parser.add_argument("--no-state", action="store_true")
    args = parser.parse_args()

    base_url = "http://%s:%d" % (args.host, args.port)
    Handler.weak_tokens = args.weak_tokens
    Handler.no_auth = args.no_auth
    Handler.oauth = args.oauth
    Handler.oauth_key = args.oauth_key
    Handler.oauth_issuer = args.oauth_issuer
    Handler.oauth_audience = args.oauth_audience
    Handler.base_url = base_url
    Handler.redirect_uri = args.redirect_uri or (base_url + "/callback")
    Handler.no_token_check = args.no_token_check
    Handler.no_signature_check = args.no_signature_check
    Handler.no_expiry_check = args.no_expiry_check
    Handler.no_audience_check = args.no_audience_check
    Handler.no_issuer_check = args.no_issuer_check
    Handler.no_scope_check = args.no_scope_check
    Handler.no_resource_metadata = args.no_resource_metadata
    Handler.no_pkce = args.no_pkce
    Handler.no_redirect_check = args.no_redirect_check
    Handler.no_state = args.no_state

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"orders-http listening on {base_url}/mcp", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
