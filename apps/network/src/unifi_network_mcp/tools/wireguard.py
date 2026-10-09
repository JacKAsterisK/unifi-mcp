"""Controlled IPv4 WireGuard provisioning through the shared VPN manager."""

import logging
from typing import Annotated, Any

from mcp.types import ToolAnnotations
from pydantic import Field, WithJsonSchema

from unifi_core.confirmation import create_preview, delete_preview, update_preview
from unifi_core.network.models.wireguard import (
    PeerCreateInput,
    ServerCreateInput,
    WireGuardError,
    WireGuardPeerCreate,
    WireGuardServerCreate,
    input_schema,
    server_view,
)
from unifi_core.write_verification import format_tool_payload
from unifi_network_mcp.runtime import server, vpn_manager

logger = logging.getLogger(__name__)


def failure(operation: str, exc: Exception) -> dict[str, Any]:
    logger.error("WireGuard %s failed: %s", operation, type(exc).__name__)
    guidance = str(exc) if isinstance(exc, WireGuardError) else "Check controller support, credentials and permissions"
    return {"success": False, "error": f"Failed to {operation}: {guidance}"}


def outcome(result) -> dict[str, Any]:
    return format_tool_payload(result, site=vpn_manager._connection.site, success_message="WireGuard change verified")


@server.tool(
    name="unifi_create_wireguard_server",
    description=(
        "Preview or create an IPv4 WireGuard server, initially disabled, on a verified WAN interface. "
        "Checks subnet/listen-port conflicts against configured networks and uses the built-in Vpn zone. "
        "The server private key is generated internally and never returned. Configure firewall rules before enabling. "
        "Requires local Network authentication and confirmation; readback verifies persistence. "
        "MCP previews read live state; API action previews show submitted arguments only."
    ),
    input_schema=input_schema(ServerCreateInput),
    permission_category="vpn_servers",
    permission_action="create",
    auth="local_only",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False),
)
async def create_wireguard_server(
    server_data: Annotated[dict[str, Any], WithJsonSchema(input_schema(WireGuardServerCreate))],
    confirm: bool = False,
) -> dict[str, Any]:
    try:
        if not confirm:
            payload = await vpn_manager.prepare_wireguard_server(server_data)
            return create_preview(
                "wireguard_server",
                payload,
                warnings=["Created disabled; review Vpn-zone firewall access before enabling"],
            )
        return outcome(await vpn_manager.create_wireguard_server(server_data))
    except Exception as exc:
        return failure("create WireGuard server", exc)


@server.tool(
    name="unifi_list_wireguard_peers",
    description=(
        "Read fresh WireGuard peers using a legacy server networkconf _id from unifi_list_vpn_servers. "
        "Returned peer _ids are scoped to these WireGuard peer tools; do not pass public API UUIDs. "
        "Private keys and other controller secrets are excluded. Requires local Network authentication."
    ),
    auth="local_only",
    annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
async def list_wireguard_peers(
    server_id: Annotated[str, Field(description="Legacy WireGuard server networkconf _id")],
) -> dict[str, Any]:
    try:
        return {"success": True, "data": await vpn_manager.list_wireguard_peers(server_id)}
    except Exception as exc:
        return failure("list WireGuard peers", exc)


@server.tool(
    name="unifi_create_wireguard_peer",
    description=(
        "Preview or create one IPv4 WireGuard peer using its client-generated public key and a free tunnel IP. "
        "Use the legacy server networkconf _id. This tool never accepts the client private key and "
        "advertises no networks behind the client. Gateway allowed_ips is empty; configure destination "
        "AllowedIPs separately in the client. Requires local Network authentication and confirmation. "
        "MCP previews read live state; API action previews show submitted arguments only."
    ),
    input_schema=input_schema(PeerCreateInput),
    permission_category="vpn_servers",
    permission_action="create",
    auth="local_only",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False),
)
async def create_wireguard_peer(
    server_id: str,
    peer_data: Annotated[dict[str, Any], WithJsonSchema(input_schema(WireGuardPeerCreate))],
    confirm: bool = False,
) -> dict[str, Any]:
    try:
        if not confirm:
            return create_preview("wireguard_peer", await vpn_manager.prepare_wireguard_peer(server_id, peer_data))
        return outcome(await vpn_manager.create_wireguard_peer(server_id, peer_data))
    except Exception as exc:
        return failure("create WireGuard peer", exc)


@server.tool(
    name="unifi_delete_wireguard_peer",
    description=(
        "Preview or revoke one WireGuard peer and verify it is absent. Requires local Network authentication "
        "and confirmation. Use server networkconf _id and peer _id from the WireGuard peer tool family. "
        "Revocation interrupts this peer's VPN access."
    ),
    permission_category="vpn_servers",
    permission_action="delete",
    auth="local_only",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False),
)
async def delete_wireguard_peer(server_id: str, peer_id: str, confirm: bool = False) -> dict[str, Any]:
    try:
        if not confirm:
            return delete_preview(
                "wireguard_peer",
                peer_id,
                resource_data=await vpn_manager.prepare_wireguard_peer_delete(server_id, peer_id),
            )
        return outcome(await vpn_manager.delete_wireguard_peer(server_id, peer_id))
    except Exception as exc:
        return failure("revoke WireGuard peer", exc)


@server.tool(
    name="unifi_delete_wireguard_server",
    description=(
        "Preview or delete a WireGuard server only after all its peers have been revoked. "
        "Use the legacy networkconf _id from unifi_list_vpn_servers, not an Integration API UUID. "
        "Requires local Network authentication and confirmation; verifies absence after deletion."
    ),
    permission_category="vpn_servers",
    permission_action="delete",
    auth="local_only",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False),
)
async def delete_wireguard_server(server_id: str, confirm: bool = False) -> dict[str, Any]:
    try:
        if not confirm:
            return delete_preview(
                "wireguard_server",
                server_id,
                resource_data=await vpn_manager.prepare_wireguard_server_delete(server_id),
            )
        return outcome(await vpn_manager.delete_wireguard_server(server_id))
    except Exception as exc:
        return failure("delete WireGuard server", exc)


@server.tool(
    name="unifi_update_wireguard_server_state",
    description=(
        "Preview or enable/disable a WireGuard server using its legacy networkconf _id. "
        "Current values are automatically preserved by a fresh fetch-merge-put; only enabled changes. "
        "Requires local Network authentication and confirmation. Review firewall access before enabling."
    ),
    permission_category="vpn_servers",
    permission_action="update",
    auth="local_only",
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False),
)
async def update_wireguard_server_state(server_id: str, enabled: bool, confirm: bool = False) -> dict[str, Any]:
    try:
        if not confirm:
            before, _ = await vpn_manager.prepare_wireguard_server_state(server_id, enabled)
            return update_preview(
                "wireguard_server",
                server_id,
                None,
                server_view(before),
                {"enabled": enabled},
                warnings=["Enabling activates VPN access under existing Vpn-zone firewall rules"],
            )
        return outcome(await vpn_manager.update_wireguard_server_state(server_id, enabled))
    except Exception as exc:
        return failure("update WireGuard server state", exc)
