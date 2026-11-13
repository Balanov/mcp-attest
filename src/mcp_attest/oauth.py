"""OAuth 2.1 conformance probes for MCP servers.

The OWASP MCP Security Testing Guide puts OAuth tests in the same minimum set
as the authorization matrix: wrong audience, wrong issuer, wrong scope, wrong
signature, expiry, redirect URI, state, PKCE, and a token that must not be
passed through to an upstream server. None of the tools in the ecosystem check
them, so this module closes that half of the standard.

How a token defect is produced
------------------------------
There are two kinds of defect, and the difference matters for what a refusal
proves:

*Signature-level* defects — a malformed token, a tampered signature, an
``alg: none`` token — need no key. Any server that refuses them is doing the
right thing, whatever it does with claims.

*Claim-level* defects — an expired token, a token minted for another audience,
a token from another issuer, a token with too little scope — must be **properly
signed**, otherwise the server can refuse them for the wrong reason and the
test proves nothing. Minting such a token needs the signing key, so the
operator points the policy at one::

    "oauth": {"signing_key_env": "MCP_ATTEST_OAUTH_KEY"}

Without that key the claim-level probes are reported as *skipped*, never as
passed. A test that did not run is not a test that passed.

Only symmetric HS256 is supported, because it is the only signature scheme the
standard library can produce and verify without a dependency. For RS256 or
EdDSA, point the key at a file the operator controls and use a proxy that
mints the tokens; the claim-level checks in this module are about what the
server verifies, not about how the token was signed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from .jsonrpc import TransportError

# ---------------------------------------------------------------------------
# JWT primitives
# ---------------------------------------------------------------------------


def b64url(raw: bytes) -> str:
    """Base64url without padding, as JWT requires."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def mint_jwt(payload: dict[str, Any], key: str, alg: str = "HS256") -> str:
    """Sign a JWT with HS256."""
    header = {"alg": alg, "typ": "JWT"}
    signing_input = "%s.%s" % (b64url(_json_bytes(header)), b64url(_json_bytes(payload)))
    signature = hmac.new(key.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return "%s.%s" % (signing_input, b64url(signature))


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Split a JWT into its header and payload without verifying it."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT: expected three dot-separated parts")
    header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
    payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    return header, payload


def resign(token: str, key: str, **changes: Any) -> str:
    """Return a properly signed token with the given claims changed.

    This is the interesting mutation: the signature is valid, so a server that
    refuses the token refused it because of the claim, not because of the
    signature.
    """
    _, payload = decode_jwt(token)
    payload.update(changes)
    return mint_jwt(payload, key)


def tamper(token: str) -> str:
    """Flip the last character of the signature."""
    parts = token.split(".")
    if len(parts) != 3:
        return token + "x"
    signature = parts[2]
    if not signature:
        return token
    flipped = "A" if signature[-1] != "A" else "B"
    return "%s.%s.%s" % (parts[0], parts[1], signature[:-1] + flipped)


def unsigned(token: str) -> str:
    """Rebuild a token with ``alg: none`` and an empty signature."""
    try:
        _, payload = decode_jwt(token)
    except (ValueError, json.JSONDecodeError):
        return token
    header = {"alg": "none", "typ": "JWT"}
    return "%s.%s." % (b64url(_json_bytes(header)), b64url(_json_bytes(payload)))


def scope_set(token: str) -> set[str]:
    """The scopes a token carries, from either a string or a list claim."""
    try:
        _, payload = decode_jwt(token)
    except (ValueError, json.JSONDecodeError):
        return set()
    raw = payload.get("scope") or payload.get("scp") or ""
    if isinstance(raw, list):
        return {str(item) for item in raw}
    return {part for part in str(raw).replace(",", " ").split() if part}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class OAuthConfig:
    """What the policy expects the server's OAuth layer to look like."""

    issuer: str = ""
    audience: str = ""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    protected_resource_metadata: str = ""
    resource: str = ""
    redirect_uri: str = ""
    signing_key_env: str = ""
    upstream: str = ""
    required_scopes: dict[str, str] = field(default_factory=dict)
    declared: bool = False

    @property
    def has_key(self) -> bool:
        return bool(self.signing_key_env)

    def key(self, environ: dict[str, str] | None = None) -> str:
        import os

        env = environ if environ is not None else os.environ
        if not self.signing_key_env:
            return ""
        value = env.get(self.signing_key_env)
        if not value:
            raise KeyError(
                "the policy asks for the OAuth signing key in %r, but that variable is not set"
                % self.signing_key_env
            )
        return value


def oauth_config_from_dict(raw: dict[str, Any] | None) -> OAuthConfig:
    raw = raw or {}
    return OAuthConfig(
        issuer=str(raw.get("issuer") or ""),
        audience=str(raw.get("audience") or ""),
        authorization_endpoint=str(raw.get("authorization_endpoint") or ""),
        token_endpoint=str(raw.get("token_endpoint") or ""),
        protected_resource_metadata=str(raw.get("protected_resource_metadata") or ""),
        resource=str(raw.get("resource") or ""),
        redirect_uri=str(raw.get("redirect_uri") or ""),
        signing_key_env=str(raw.get("signing_key_env") or ""),
        upstream=str(raw.get("upstream") or ""),
        required_scopes=dict(raw.get("required_scopes") or {}),
        declared=bool(raw),
    )


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


@dataclass
class TokenProbe:
    """One token defect and the rule it tests."""

    rule: str
    label: str
    header: str
    needs_key: bool
    detail: str = ""


def token_probes(token: str, key: str) -> list[TokenProbe]:
    """Build the token defects to present to the server.

    ``key`` may be empty: the claim-level probes are then returned with
    ``needs_key`` set, and the caller reports them as skipped.
    """
    probes: list[TokenProbe] = [
        TokenProbe(
            rule="AT-OAUTH-002",
            label="a token with a tampered signature",
            header="Bearer " + tamper(token),
            needs_key=False,
            detail="the signature was altered after it was issued",
        ),
        TokenProbe(
            rule="AT-OAUTH-003",
            label="an unsigned token (alg: none)",
            header="Bearer " + unsigned(token),
            needs_key=False,
            detail="the token declares that it needs no signature",
        ),
    ]

    try:
        _, payload = decode_jwt(token)
    except (ValueError, json.JSONDecodeError):
        return probes

    expired = resign(token, key, exp=int(time.time()) - 3600, iat=int(time.time()) - 7200)
    probes.append(
        TokenProbe(
            rule="AT-OAUTH-004",
            label="an expired token",
            header="Bearer " + expired,
            needs_key=True,
            detail="signed correctly, but it expired an hour ago",
        )
    )

    audience = str(payload.get("aud") or "")
    if audience:
        probes.append(
            TokenProbe(
                rule="AT-OAUTH-005",
                label="a token minted for another audience",
                header="Bearer " + resign(token, key, aud="mcp://another-resource"),
                needs_key=True,
                detail="the token was issued for %s, not for this server" % audience,
            )
        )

    issuer = str(payload.get("iss") or "")
    if issuer:
        probes.append(
            TokenProbe(
                rule="AT-OAUTH-006",
                label="a token from another issuer",
                header="Bearer " + resign(token, key, iss="https://issuer.example.invalid/"),
                needs_key=True,
                detail="the token was issued by %s, not by the trusted issuer" % issuer,
            )
        )
    return probes


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


@dataclass
class HttpProbeResult:
    status: int
    headers: dict[str, str]
    body: str
    location: str = ""

    @property
    def refused(self) -> bool:
        return self.status in (400, 401, 403)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep a 3xx as a response instead of following it.

    The authorization endpoint answers with a redirect that carries the code,
    so the harness has to see that redirect rather than the page it points at.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
    body: str | None = None,
) -> HttpProbeResult:
    """A plain HTTP request that never raises on a status code."""
    data = body.encode("utf-8") if body is not None else None
    request_headers = {"User-Agent": "mcp-attest"}
    request_headers.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=request_headers)
    try:
        with _OPENER.open(req, timeout=timeout) as response:
            payload = response.read().decode("utf-8", "replace")
            return HttpProbeResult(
                status=response.status,
                headers={k.lower(): v for k, v in response.headers.items()},
                body=payload,
                location=response.headers.get("Location", "") or "",
            )
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", "replace")
        headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        exc.close()
        return HttpProbeResult(
            status=exc.code,
            headers=headers,
            body=payload,
            location=headers.get("location", ""),
        )
    except (urllib.error.URLError, OSError, TransportError) as exc:
        return HttpProbeResult(status=0, headers={}, body="unreachable: %s" % exc)


def resource_metadata_url(www_authenticate: str) -> str:
    """The URL a ``WWW-Authenticate`` header points at, if it names one."""
    for part in www_authenticate.split(","):
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == "resource_metadata":
            return value.strip().strip('"')
    return ""


def protected_resource_metadata(url: str, timeout: float = 10.0) -> tuple[dict[str, Any] | None, str]:
    """Fetch and parse the protected resource metadata document (RFC 9728)."""
    result = http_request(url, timeout=timeout)
    if result.status != 200:
        return None, "the endpoint answered HTTP %d" % result.status
    try:
        document = json.loads(result.body)
    except json.JSONDecodeError as exc:
        return None, "the document is not valid JSON: %s" % exc
    if not isinstance(document, dict):
        return None, "the document is not a JSON object"
    return document, ""


def authorization_request(
    endpoint: str,
    redirect_uri: str,
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
    client_id: str = "mcp-attest",
    scope: str = "",
) -> HttpProbeResult:
    """Ask the authorization endpoint for a code, with the given defects."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
    }
    if state:
        params["state"] = state
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = code_challenge_method
    if scope:
        params["scope"] = scope
    separator = "&" if "?" in endpoint else "?"
    return http_request(endpoint + separator + urllib.parse.urlencode(params), timeout=10.0)
