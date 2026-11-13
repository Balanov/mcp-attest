"""Shadow path detection.

A gateway only sees what is routed through it. Anything an agent can reach
without passing the control point is a shadow path: it carries no policy, no
log and no receipt. These are the paths that make "we have a gateway" untrue.
"""

from __future__ import annotations

from dataclasses import dataclass

from .trace import Trace


@dataclass
class ShadowPath:
    client: str
    server: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"client": self.client, "server": self.server, "reason": self.reason}


def find_shadow_paths(trace: Trace) -> list[ShadowPath]:
    routed = set(trace.gateway_routes.keys())
    paths: list[ShadowPath] = []
    for client, servers in trace.client_servers.items():
        for server in servers:
            if server not in routed:
                paths.append(
                    ShadowPath(
                        client=client,
                        server=server,
                        reason="server is configured on the client but has no route in the gateway",
                    )
                )
    return paths
