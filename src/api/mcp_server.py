"""
mcp_server.py

MCP (Model Context Protocol) server exposing NetLanvas's read-only data
surface as MCP tools: topology, a single node's detail, inventory,
alerts, engine status, VLANs, subnets, and dashboard summary data.

Mounted into the same FastAPI app/process as the REST API (server.py)
at /mcp-root -- each tool below calls the existing route handler
coroutine directly (lazy-imported from api.server to avoid a circular
import, since server.py in turn imports mcp/mcp_asgi_app from here).
No extra HTTP hop, no duplicated query logic -- the handlers' own
error handling in server.py stays the single source of truth for what
each one returns.

Auth is deliberately NOT the MCP SDK's own built-in auth framework
(MCPServer's token_verifier requires an `auth=AuthSettings(issuer_url=
..., resource_server_url=...)`, i.e. a real OAuth authorization server
-- there isn't one here, and fabricating a fake issuer_url would be
misleading). Instead, server.py gates the /mcp-root mount itself with
the same security/api_tokens.py Bearer-token model /api/* already uses
(see security/middleware.py's authenticate_bearer_token, reused by
server.py's mcp_auth_gate middleware) -- but WITHOUT the GET-only-for-
read-only-tokens restriction /api/* applies: MCP's own transport is
POST-based JSON-RPC regardless of whether a given call reads or
writes, and every tool registered below is read-only by construction
(none of them call a mutating handler), so there is nothing to
restrict by method here. A session cookie is never accepted for this
mount -- MCP clients are non-browser callers by definition.
"""

import logging

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

logger = logging.getLogger("Netlanvas.MCP")

mcp = MCPServer(
    "NetLanvas",
    instructions=(
        "Read-only access to this NetLanvas appliance's live network "
        "inventory: discovered devices, topology, alerts, VLANs, "
        "subnets, and dashboard summary data. Nothing here can modify "
        "appliance state."
    ),
)


@mcp.tool()
async def get_topology(archive: str | None = None) -> dict:
    """Full network topology: nodes, links, and how they relate. Pass `archive` (a saved snapshot's date/id) to view a past state instead of live data."""
    from api.server import api_topology
    return await api_topology(archive=archive)


@mcp.tool()
async def get_node(node_id: int, archive: str | None = None) -> dict:
    """Full detail for a single discovered node/device by its id (see get_topology or list_inventory for ids)."""
    from api.server import get_node_details
    return await get_node_details(node_id=node_id, archive=archive)


@mcp.tool()
async def list_inventory() -> dict:
    """The full, flat inventory of discovered devices and their verification status."""
    from api.server import api_inventory_list
    return await api_inventory_list()


@mcp.tool()
async def get_alerts(limit: int = 50, status: str = "all", severity: str = "all", alert_type: str = "all") -> dict:
    """Active/historical alerts. status: all|open|acknowledged|resolved. severity: all|low|medium|high|critical. limit is capped at 200 server-side."""
    from api.server import list_alerts as _list_alerts
    return await _list_alerts(limit=limit, status=status, severity=severity, alert_type=alert_type)


@mcp.tool()
async def get_status(archive: str | None = None) -> dict:
    """Engine/poll-cycle status: tick progress, last run time, lock state."""
    from api.server import api_status
    return await api_status(archive=archive)


@mcp.tool()
async def get_vlans(archive: str | None = None) -> dict:
    """Discovered VLANs and their names/colors."""
    from api.server import list_vlans as _list_vlans
    return await _list_vlans(archive=archive)


@mcp.tool()
async def get_subnets(archive: str | None = None) -> dict:
    """Discovered IP subnets."""
    from api.server import list_subnets as _list_subnets
    return await _list_subnets(archive=archive)


@mcp.tool()
async def get_dashboard_data(archive: str | None = None) -> dict:
    """Summary counters/widgets as shown on the main dashboard."""
    from api.server import api_dashboard_data
    return await api_dashboard_data(archive=archive)


# A complete, self-contained Starlette app -- server.py mounts this
# directly at /mcp-root. Its own internal session manager still needs
# its lifespan entered/exited around the parent app's lifetime; see
# server.py's startup/shutdown handlers (mounting alone does not start
# it -- confirmed live, a mounted-but-unstarted session manager raises
# "Task group is not initialized" on first request).
#
# DNS-rebinding protection is OFF deliberately, not an oversight: this
# appliance has no fixed hostname (every install is reached at whatever
# LAN IP/hostname the user's network gives it -- there's no single
# allowed_hosts list that would work across installs), and the SDK's
# own protection targets a threat model that doesn't apply here anyway
# -- an unauthenticated local service being tricked into trusting a
# request relayed through a victim's browser from an attacker page.
# Every request to this mount still needs a valid Bearer token (see
# server.py's mcp_auth_gate), checked independently of Host/Origin, so
# a rebound request gains nothing without already having the secret.
# Confirmed live 2026-11-03: without this, every real request was
# silently rejected with "Invalid Host header" even from the
# appliance's own real LAN IP.
mcp_asgi_app = mcp.streamable_http_app(
    streamable_http_path="/mcp",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)
