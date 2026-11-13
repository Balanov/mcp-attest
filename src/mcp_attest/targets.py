"""Where the server is and who we are when we talk to it.

A target is one server. An identity is one way of being that server's caller.
Both are explicit, because the whole point of the harness is that the
authorization decisions it observes belong to a named principal, recorded in
the evidence bundle.
"""

from __future__ import annotations

import shlex
import os
from dataclasses import dataclass, field
from typing import Any

from .client import HttpClient, McpClient, StdioClient
from .policy import Identity, PolicyError


@dataclass
class Target:
    """One MCP server the harness can talk to."""

    kind: str  # "stdio" | "http"
    command: list[str] = field(default_factory=list)
    url: str = ""
    env: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 10.0

    def describe(self) -> str:
        if self.kind == "stdio":
            return " ".join(self.command)
        return self.url


def parse_target(
    command: str | None,
    url: str | None,
    env: list[str] | None = None,
    headers: list[str] | None = None,
    timeout: float = 10.0,
) -> Target:
    """Build a target from the command line.

    ``--command`` starts a server over stdio, ``--url`` talks to one over
    Streamable HTTP. Exactly one of them is required.
    """
    if bool(command) == bool(url):
        raise ValueError("give either --command (stdio) or --url (streamable HTTP), not both")
    env_map: dict[str, str] = {}
    for item in env or []:
        if "=" not in item:
            raise ValueError(f"--env expects KEY=VALUE, got {item!r}")
        key, _, value = item.partition("=")
        env_map[key.strip()] = value
    header_map: dict[str, str] = {}
    for item in headers or []:
        if ":" not in item:
            raise ValueError(f"--header expects 'Name: value', got {item!r}")
        name, _, value = item.partition(":")
        header_map[name.strip()] = value.strip()
    if command:
        return Target(kind="stdio", command=split_command(command), env=env_map, timeout=timeout)
    return Target(kind="http", url=str(url), headers=header_map, timeout=timeout)


def split_command(command: str) -> list[str]:
    """Split a command line into argv, honouring quotes on every platform."""
    if os.name == "nt":
        # posix=False keeps Windows paths such as C:\\tools intact.
        parts = shlex.split(command, posix=False)
        return [p.strip('"') if p.startswith('"') and p.endswith('"') else p for p in parts]
    return shlex.split(command)


def connect(target: Target, identity: Identity | None = None, environ: dict[str, str] | None = None) -> McpClient:
    """Open a connection, presenting the given identity.

    A stdio server is a child process, so the identity travels as environment
    variables and the process is started per identity. An HTTP server is
    stateless from our side, so the identity travels as request headers.
    """
    ident = identity or Identity()
    if target.kind == "stdio":
        env = dict(target.env)
        env.update(ident.resolved_env(environ))
        return StdioClient(target.command, env=env)
    headers = dict(target.headers)
    headers.update(ident.resolved_headers(environ))
    return HttpClient(target.url, headers=headers, timeout=target.timeout)


def environment_or_raise(policy: Any) -> dict[str, str]:
    """Resolve every identity in the policy, failing loudly on a missing variable."""
    resolved: dict[str, str] = {}
    for client in policy.identities():
        for key, value in client.identity.env.items():
            resolved[f"{client.name}.{key}"] = value
        for key, value in client.identity.headers.items():
            resolved[f"{client.name}.{key}"] = value
    try:
        for client in policy.identities():
            client.identity.resolved_env()
            client.identity.resolved_headers()
    except PolicyError as exc:
        raise PolicyError(str(exc)) from exc
    return resolved
