"""Generic network mutations must not bypass narrower VPN policies."""

import json
import logging
from unittest.mock import AsyncMock, Mock, patch

import pytest

from unifi_network_mcp.resource_policy import vpn_network_denial


@pytest.mark.parametrize(
    "current,effective,category",
    [
        ({"purpose": "remote-user-vpn", "vpn_type": "wireguard-server"}, {}, "VPN_SERVERS"),
        ({"purpose": "vpn-client"}, {}, "VPN_CLIENTS"),
        ({"purpose": "site-vpn"}, {}, "VPN_CLIENTS"),
        ({"purpose": "corporate"}, {"purpose": "vpn-server"}, "VPN_SERVERS"),
        ({"purpose": "vpn-client"}, {"purpose": "vpn-server"}, "VPN_CLIENTS"),
        ({"purpose": "vpn-client"}, {"purpose": "vpn-server"}, "VPN_SERVERS"),
    ],
)
def test_old_and_new_vpn_roles_require_permissions(monkeypatch, current, effective, category):
    monkeypatch.setenv(f"UNIFI_POLICY_NETWORK_{category}_UPDATE", "false")
    assert vpn_network_denial(current, effective, "update") is not None


def test_lan_update_does_not_require_vpn_permissions(monkeypatch):
    monkeypatch.setenv("UNIFI_POLICY_NETWORK_VPN_CLIENTS_UPDATE", "false")
    monkeypatch.setenv("UNIFI_POLICY_NETWORK_VPN_SERVERS_UPDATE", "false")
    assert vpn_network_denial({"purpose": "corporate"}, {"purpose": "corporate"}, "update") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("confirm", [False, True])
async def test_generic_tool_rejects_vpn_even_when_network_update_allowed(monkeypatch, confirm):
    from unifi_network_mcp.tools.network import update_network

    monkeypatch.setenv("UNIFI_POLICY_NETWORK_NETWORKS_UPDATE", "true")
    monkeypatch.setenv("UNIFI_POLICY_NETWORK_VPN_SERVERS_UPDATE", "false")
    with patch("unifi_network_mcp.tools.network.network_manager") as manager:
        manager.get_network_details = AsyncMock(
            return_value={"purpose": "remote-user-vpn", "vpn_type": "wireguard-server"}
        )
        manager.update_network = AsyncMock()
        result = await update_network("synthetic-id", {"enabled": False}, confirm=confirm)
        assert result["success"] is False
        assert "disabled by policy for vpn_server" in result["error"]
        manager.update_network.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("network_allowed,vpn_allowed", [(True, False), (False, True)])
async def test_real_mcp_dispatch_requires_both_categories(monkeypatch, network_allowed, vpn_allowed):
    from mcp.types import ToolAnnotations

    from unifi_mcp_shared.permissioned_tool import setup_permissioned_tool
    from unifi_mcp_shared.server import UniFiMCPServer
    from unifi_network_mcp.categories import NETWORK_CATEGORY_MAP
    from unifi_network_mcp.tools.network import update_network

    server = UniFiMCPServer("vpn-policy-regression")
    setup_permissioned_tool(
        server=server,
        category_map=NETWORK_CATEGORY_MAP,
        server_prefix="network",
        register_tool_fn=Mock(),
        diagnostics_enabled_fn=lambda: False,
        wrap_tool_fn=Mock(),
        logger=logging.getLogger("test"),
    )
    server.tool(
        name="unifi_update_network",
        permission_category="network",
        permission_action="update",
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False
        ),
    )(update_network)

    monkeypatch.setenv("UNIFI_POLICY_NETWORK_NETWORKS_UPDATE", str(network_allowed).lower())
    monkeypatch.setenv("UNIFI_POLICY_NETWORK_VPN_SERVERS_UPDATE", str(vpn_allowed).lower())
    with patch("unifi_network_mcp.tools.network.network_manager") as manager:
        manager.get_network_details = AsyncMock(
            return_value={"purpose": "remote-user-vpn", "vpn_type": "wireguard-server"}
        )
        manager.update_network = AsyncMock()
        result = await server.call_tool(
            "unifi_update_network", {"network_id": "synthetic-id", "update_data": {"enabled": False}, "confirm": True}
        )
        content = result.content if hasattr(result, "content") else result
        if isinstance(content, tuple):
            content = content[0]
        payload = json.loads(next(block.text for block in content if hasattr(block, "text")))
        assert payload["success"] is False
        manager.update_network.assert_not_awaited()
        assert manager.get_network_details.await_count == int(network_allowed)
