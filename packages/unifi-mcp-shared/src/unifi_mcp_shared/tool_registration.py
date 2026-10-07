"""Shared tool registration mode dispatch for MCP servers.

All three MCP servers (Network, Protect, Access) use the same three-mode
registration pattern: ``meta_only``, ``lazy``, and ``eager``.  This module
extracts that dispatch logic so each server's ``main.py`` only needs to
call :func:`register_tools_for_mode` with server-specific parameters.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any, Callable


def _parse_filter_list(value: Any) -> list[str] | None:
    """Parse a comma-separated string (or None/null) into a list or None."""
    if isinstance(value, str) and value not in ("null", ""):
        return [item.strip() for item in value.split(",")]
    if value in (None, "null", ""):
        return None
    # Already a list or other type — pass through
    return value


async def register_tools_for_mode(
    *,
    mode: str,
    server: Any,
    original_tool_decorator: Callable,
    tool_index_handler: Callable,
    start_async_tool: Callable,
    get_job_status: Callable,
    register_tool: Callable,
    tool_module_map: dict,
    setup_lazy_loading: Callable,
    base_package: str,
    config: Any,
    logger: logging.Logger,
    support_bundle_handler: Callable | None = None,
    prefix: str = "",
    server_label: str = "",
    register_meta_tools: Callable | None = None,
    register_load_tools: Callable | None = None,
    auto_load_tools: Callable | None = None,
) -> None:
    """Register meta-tools and domain tools based on *mode*.

    Args:
        mode: One of ``"meta_only"``, ``"lazy"``, or ``"eager"``.
        server: The FastMCP server instance.
        original_tool_decorator: The unwrapped ``server.tool`` decorator.
        tool_index_handler: Handler for the tool index meta-tool.
        start_async_tool: Handler for starting async tool execution.
        get_job_status: Handler for checking async job status.
        register_tool: Function to register tool metadata in the index.
        tool_module_map: Mapping of tool names to their module paths.
        setup_lazy_loading: Function to set up lazy loading for the server.
        base_package: Dotted package path for tool modules (e.g. ``"unifi_network_mcp.tools"``).
        config: Server config object (used for ``enabled_categories``/``enabled_tools``).
        logger: Logger instance.
        support_bundle_handler: Optional runtime callback; legacy callers can omit it.
        prefix: Tool name prefix (e.g. ``"protect"``). Empty string for Network (uses ``"unifi"``).
        server_label: Human-readable server name (e.g. ``"UniFi Protect"``).
        register_meta_tools: Shared meta-tools registration function.
        register_load_tools: Shared load_tools registration function.
        auto_load_tools: Shared eager tool auto-discovery function.
    """
    # Late-import defaults from shared package if not provided
    if register_meta_tools is None:
        from unifi_mcp_shared.meta_tools import register_meta_tools
    if register_load_tools is None:
        from unifi_mcp_shared.meta_tools import register_load_tools
    if auto_load_tools is None:
        from unifi_mcp_shared.tool_loader import auto_load_tools

    # Opt-in registration profile, separate from call-time permission gates.
    # Complete filtering before starting a transport; no background task or
    # indirect executor may expand this profile after startup.
    strict = str(config.server.get("strict_enabled_tools", False)).strip().lower()
    if strict not in {"true", "false", "1", "0", "yes", "no"}:
        raise ValueError("strict_enabled_tools must be a boolean.")
    if strict in {"true", "1", "yes"}:
        from unifi_mcp_shared.meta_tools import is_meta_tool

        enabled = _parse_filter_list(config.server.get("enabled_tools"))
        if mode != "eager" or not enabled or config.server.get("enabled_categories") not in (None, "", "null"):
            raise ValueError("Strict tool profiles require eager mode, explicit enabled_tools, and no category filter.")
        if not isinstance(enabled, Sequence) or any(not isinstance(name, str) or not name for name in enabled):
            raise ValueError("Strict enabled_tools must contain tool names.")
        if any(is_meta_tool(name) or name not in tool_module_map for name in enabled):
            raise ValueError("Strict enabled_tools must contain known direct domain tools only.")
        auto_load_tools(base_package=base_package, server=server, fail_on_error=True)
        allowed = set(enabled)
        tools = await server.list_tools()
        if not allowed.issubset({tool.name for tool in tools}):
            raise RuntimeError("Strict tool profile is missing a requested tool.")
        for tool in tools:
            if tool.name not in allowed:
                server.remove_tool(tool.name)
        if {tool.name for tool in await server.list_tools()} != allowed:
            raise RuntimeError("Strict tool profile could not be enforced.")
        logger.info("Strict profile registered %d direct tools", len(allowed))
        return

    # Build kwargs for meta-tools (prefix/server_label only if non-default)
    meta_kwargs: dict[str, Any] = dict(
        server=server,
        tool_decorator=original_tool_decorator,
        tool_index_handler=tool_index_handler,
        start_async_tool=start_async_tool,
        get_job_status=get_job_status,
        register_tool=register_tool,
    )
    if support_bundle_handler is not None:
        meta_kwargs["support_bundle_handler"] = support_bundle_handler
    if prefix:
        meta_kwargs["prefix"] = prefix
        meta_kwargs["server_label"] = server_label

    # Always register meta-tools first
    register_meta_tools(**meta_kwargs)

    tool_prefix = prefix or "unifi"
    support_hint = f", {tool_prefix}_get_support_bundle" if support_bundle_handler is not None else ""

    if mode == "meta_only":
        logger.info("Tool registration mode: meta_only")
        logger.info(
            "   Meta-tools: %s_tool_index, %s_execute, %s_batch, %s_batch_status%s",
            tool_prefix,
            tool_prefix,
            tool_prefix,
            tool_prefix,
            support_hint,
        )
        logger.info("   Use %s_execute to run domain tools by name", tool_prefix)
        logger.info("   To load all tools directly: set UNIFI_TOOL_REGISTRATION_MODE=eager")

        setup_lazy_loading(server, original_tool_decorator)
        logger.info("   On-demand loader ready - %d tools available via %s_execute", len(tool_module_map), tool_prefix)

    elif mode == "lazy":
        logger.info("Tool registration mode: lazy")
        logger.info(
            "   Meta-tools: %s_tool_index, %s_execute, %s_batch, %s_batch_status, %s_load_tools%s",
            tool_prefix,
            tool_prefix,
            tool_prefix,
            tool_prefix,
            tool_prefix,
            support_hint,
        )
        logger.info("   Use %s_execute to run any tool - works with all clients", tool_prefix)

        lazy_loader = setup_lazy_loading(server, original_tool_decorator)

        load_kwargs: dict[str, Any] = dict(
            server=server,
            tool_decorator=original_tool_decorator,
            lazy_loader=lazy_loader,
            register_tool=register_tool,
            tool_module_map=tool_module_map,
        )
        if prefix:
            load_kwargs["prefix"] = prefix
            load_kwargs["server_label"] = server_label
        register_load_tools(**load_kwargs)

        logger.info("   Lazy loader ready - %d tools available on-demand", len(tool_module_map))

    else:  # eager
        logger.info("Tool registration mode: eager")

        enabled_categories = _parse_filter_list(config.server.get("enabled_categories"))
        enabled_tools = _parse_filter_list(config.server.get("enabled_tools"))

        if enabled_categories:
            logger.info("   Filtering by categories: %s", enabled_categories)
        elif enabled_tools:
            logger.info("   Filtering to %d specific tools", len(enabled_tools))
        else:
            logger.info("   All tools registered (no filtering)")

        auto_load_tools(
            base_package=base_package,
            enabled_categories=enabled_categories,
            enabled_tools=enabled_tools,
            server=server,
        )

    # Log registered tools
    try:
        tools = await server.list_tools()
        logger.debug("Registered tools: %s", [tool.name for tool in tools])
    except Exception as e:
        logger.debug("Error listing tools: %s", e)
