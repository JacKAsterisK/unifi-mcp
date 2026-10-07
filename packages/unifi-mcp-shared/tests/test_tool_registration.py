"""Tests for shared tool registration mode dispatch."""

import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from unifi_mcp_shared.tool_registration import register_tools_for_mode


def _config(**server_values):
    defaults = {"enabled_categories": None, "enabled_tools": None}
    defaults.update(server_values)
    return SimpleNamespace(server=defaults)


def _server():
    return SimpleNamespace(list_tools=AsyncMock(return_value=[]))


def _deps():
    return {
        "original_tool_decorator": Mock(),
        "tool_index_handler": Mock(),
        "start_async_tool": Mock(),
        "get_job_status": Mock(),
        "register_tool": Mock(),
        "support_bundle_handler": AsyncMock(return_value={"success": True, "data": {}}),
        "tool_module_map": {"unifi_list_clients": "unifi_network_mcp.tools.clients"},
        "setup_lazy_loading": Mock(return_value="lazy-loader"),
        "register_meta_tools": Mock(),
        "register_load_tools": Mock(),
        "auto_load_tools": Mock(),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,enabled", [("lazy", "unifi_list_clients"), ("eager", ""), ("eager", "unifi_execute")])
async def test_strict_profile_rejects_invalid_configuration_before_registration(mode, enabled):
    deps = _deps()
    with pytest.raises(ValueError):
        await register_tools_for_mode(
            mode=mode,
            server=_server(),
            base_package="test.tools",
            config=_config(strict_enabled_tools=True, enabled_tools=enabled),
            logger=logging.getLogger("test"),
            **deps,
        )
    deps["register_meta_tools"].assert_not_called()
    deps["auto_load_tools"].assert_not_called()


@pytest.mark.asyncio
async def test_strict_profile_finishes_filtering_and_removes_meta_tools():
    deps = _deps()
    tools = {
        name: SimpleNamespace(name=name) for name in ("unifi_list_clients", "unifi_execute", "unifi_delete_network")
    }
    server = SimpleNamespace(list_tools=AsyncMock(side_effect=lambda: list(tools.values())), remove_tool=tools.pop)
    await register_tools_for_mode(
        mode="eager",
        server=server,
        base_package="test.tools",
        config=_config(strict_enabled_tools=True, enabled_tools="unifi_list_clients"),
        logger=logging.getLogger("test"),
        **deps,
    )
    assert set(tools) == {"unifi_list_clients"}
    deps["register_meta_tools"].assert_not_called()
    deps["setup_lazy_loading"].assert_not_called()
    deps["auto_load_tools"].assert_called_once_with(base_package="test.tools", server=server, fail_on_error=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["list", "remove", "incomplete", "import"])
async def test_strict_profile_propagates_startup_failures(failure):
    deps = _deps()
    tool = SimpleNamespace(name="unifi_list_clients")
    server = SimpleNamespace(
        list_tools=AsyncMock(return_value=[tool, SimpleNamespace(name="unifi_execute")]),
        remove_tool=Mock(side_effect=RuntimeError("synthetic failure")),
    )
    if failure == "list":
        server.list_tools.side_effect = RuntimeError("synthetic failure")
    elif failure == "incomplete":
        server.list_tools.return_value = []
    elif failure == "import":
        deps["auto_load_tools"].side_effect = RuntimeError("synthetic failure")
    with pytest.raises(RuntimeError):
        await register_tools_for_mode(
            mode="eager",
            server=server,
            base_package="test.tools",
            config=_config(strict_enabled_tools=True, enabled_tools="unifi_list_clients"),
            logger=logging.getLogger("test"),
            **deps,
        )


class TestRegisterToolsForMode:
    """Tests for the tool visibility surfaces in each registration mode."""

    @pytest.mark.parametrize("mode", ["lazy", "meta_only", "eager"])
    async def test_legacy_apps_can_omit_support_handler(self, mode, caplog):
        deps = _deps()
        deps.pop("support_bundle_handler")
        with caplog.at_level("INFO"):
            await register_tools_for_mode(
                mode=mode,
                server=_server(),
                base_package="unifi_network_mcp.tools",
                config=_config(),
                logger=logging.getLogger("test"),
                **deps,
            )
        assert "support_bundle_handler" not in deps["register_meta_tools"].call_args.kwargs
        assert "get_support_bundle" not in caplog.text

    @pytest.mark.asyncio
    async def test_lazy_mode_registers_meta_tools_load_tools_and_lazy_loader(self):
        server = _server()
        deps = _deps()

        await register_tools_for_mode(
            mode="lazy",
            server=server,
            base_package="unifi_network_mcp.tools",
            config=_config(),
            logger=logging.getLogger("test"),
            **deps,
        )

        deps["register_meta_tools"].assert_called_once()
        assert deps["register_meta_tools"].call_args.kwargs["support_bundle_handler"] is deps["support_bundle_handler"]
        deps["setup_lazy_loading"].assert_called_once_with(server, deps["original_tool_decorator"])
        deps["register_load_tools"].assert_called_once()
        assert deps["register_load_tools"].call_args.kwargs["lazy_loader"] == "lazy-loader"
        deps["auto_load_tools"].assert_not_called()
        server.list_tools.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_meta_only_mode_registers_only_meta_tools_with_lazy_execute_support(self):
        server = _server()
        deps = _deps()

        await register_tools_for_mode(
            mode="meta_only",
            server=server,
            base_package="unifi_network_mcp.tools",
            config=_config(),
            logger=logging.getLogger("test"),
            **deps,
        )

        deps["register_meta_tools"].assert_called_once()
        assert deps["register_meta_tools"].call_args.kwargs["support_bundle_handler"] is deps["support_bundle_handler"]
        deps["setup_lazy_loading"].assert_called_once_with(server, deps["original_tool_decorator"])
        deps["register_load_tools"].assert_not_called()
        deps["auto_load_tools"].assert_not_called()
        server.list_tools.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_eager_mode_registers_direct_tools_through_auto_loader(self):
        server = _server()
        deps = _deps()

        await register_tools_for_mode(
            mode="eager",
            server=server,
            base_package="unifi_network_mcp.tools",
            config=_config(enabled_categories="clients,devices"),
            logger=logging.getLogger("test"),
            **deps,
        )

        deps["register_meta_tools"].assert_called_once()
        assert deps["register_meta_tools"].call_args.kwargs["support_bundle_handler"] is deps["support_bundle_handler"]
        deps["setup_lazy_loading"].assert_not_called()
        deps["register_load_tools"].assert_not_called()
        deps["auto_load_tools"].assert_called_once_with(
            base_package="unifi_network_mcp.tools",
            enabled_categories=["clients", "devices"],
            enabled_tools=None,
            server=server,
        )
        server.list_tools.assert_awaited_once()
