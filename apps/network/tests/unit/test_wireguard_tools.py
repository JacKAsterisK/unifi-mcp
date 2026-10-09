"""Real schemas, permission gates, registry modes and safe MCP boundaries."""

import json
import os
import subprocess
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from jsonschema import Draft202012Validator
from mcp.server.mcpserver.exceptions import ToolError

from unifi_core.policy_gate import PolicyGateChecker
from unifi_core.write_verification import failed_write
from unifi_mcp_shared.permissioned_tool import create_permissioned_tool
from unifi_network_mcp.categories import NETWORK_CATEGORY_MAP, TOOL_MODULE_MAP
from unifi_network_mcp.tools import wireguard

MUTATIONS = {
    "create_wireguard_server": "create",
    "create_wireguard_peer": "create",
    "delete_wireguard_peer": "delete",
    "delete_wireguard_server": "delete",
    "update_wireguard_server_state": "update",
}
SECRET = "synthetic-opaque-controller-private-value"


def test_closed_real_create_schemas_and_module_mapping():
    for name, field in [("create_wireguard_server", "server_data"), ("create_wireguard_peer", "peer_data")]:
        tool = wireguard.server._tool_manager.get_tool("unifi_" + name)
        schema = tool.parameters
        Draft202012Validator.check_schema(schema)
        nested = schema["properties"][field]
        assert nested["additionalProperties"] is False
        assert "private_key" not in nested["properties"]
        validator = Draft202012Validator(schema)
        assert list(validator.iter_errors({field: {"private_key": SECRET}}))
        assert TOOL_MODULE_MAP["unifi_" + name] == "unifi_network_mcp.tools.wireguard"
        assert tool.annotations.read_only_hint is False


@pytest.mark.asyncio
async def test_production_dispatch_rejects_unknown_arguments_before_controller_access():
    with patch.object(wireguard, "vpn_manager") as manager:
        with pytest.raises(ToolError, match="unknown arguments"):
            await wireguard.server.call_tool(
                "unifi_create_wireguard_server", {"server_data": {}, "unexpected_private_key": SECRET}
            )
        assert not manager.mock_calls


@pytest.mark.parametrize("mode", ["lazy", "eager", "meta_only"])
def test_fresh_production_registry_registers_all_tools_and_local_auth(mode):
    program = (
        "import json; import unifi_network_mcp.main; import unifi_network_mcp.tools.wireguard; "
        "from unifi_network_mcp.runtime import get_tool_registry; "
        "print(json.dumps({k:{'auth':v.auth_method,'schema':v.input_schema} "
        "for k,v in get_tool_registry().items() if 'wireguard' in k}))"
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        check=True,
        timeout=45,
        env={**os.environ, "UNIFI_TOOL_REGISTRATION_MODE": mode},
    )
    entries = json.loads(result.stdout)
    assert set(entries) == {"unifi_" + name for name in MUTATIONS} | {"unifi_list_wireguard_peers"}
    assert all(entry["auth"] == "local_only" for entry in entries.values())
    assert entries["unifi_create_wireguard_peer"]["schema"]["properties"]["peer_data"]["additionalProperties"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("name", list(MUTATIONS))
@pytest.mark.parametrize("confirm", [False, True])
async def test_hard_policy_gate_denies_before_any_manager_interaction(monkeypatch, name, confirm):
    action = MUTATIONS[name]
    monkeypatch.setenv(f"UNIFI_POLICY_NETWORK_VPN_SERVERS_{action.upper()}", "false")
    decorator = create_permissioned_tool(
        original_tool_decorator=lambda **kwargs: lambda fn: fn,
        policy_gate_checker=PolicyGateChecker("network", NETWORK_CATEGORY_MAP),
        server_prefix="NETWORK",
        register_tool_fn=MagicMock(),
        diagnostics_enabled_fn=lambda: False,
        wrap_tool_fn=lambda fn, name: fn,
        logger=wireguard.logger,
    )
    gated = decorator(name="unifi_" + name, permission_category="vpn_servers", permission_action=action)(
        getattr(wireguard, name)
    )
    with patch.object(wireguard, "vpn_manager") as manager:
        result = await gated(confirm=confirm)
        assert result["success"] is False
        assert "disabled" in result["error"].lower()
        assert not manager.mock_calls


@pytest.mark.asyncio
async def test_default_preview_and_confirm_delegate_separately():
    with patch.object(wireguard, "vpn_manager") as manager:
        manager.prepare_wireguard_server = AsyncMock(return_value={"enabled": False})
        manager.create_wireguard_server = AsyncMock(
            return_value=failed_write("Readback failed", operation="create", mutation_applied=None)
        )
        manager._connection.site = "default"
        preview = await wireguard.create_wireguard_server({})
        assert preview["requires_confirmation"] is True
        manager.create_wireguard_server.assert_not_called()
        result = await wireguard.create_wireguard_server({}, confirm=True)
        assert result["success"] is False and result["mutation_applied"] is None
        manager.create_wireguard_server.assert_awaited_once_with({})


@pytest.mark.asyncio
@pytest.mark.parametrize("confirm", [False, True])
async def test_error_boundary_never_exposes_controller_exception_text(caplog, confirm):
    with patch.object(wireguard, "vpn_manager") as manager:
        manager.prepare_wireguard_peer = AsyncMock(side_effect=RuntimeError(SECRET))
        manager.create_wireguard_peer = AsyncMock(side_effect=RuntimeError(SECRET))
        result = await wireguard.create_wireguard_peer("server", {}, confirm)
    assert result["success"] is False
    assert SECRET not in repr(result) + caplog.text
