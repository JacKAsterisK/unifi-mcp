"""Isolation-critical V2 ordering checks, with a synthetic controller only."""

import copy
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from unifi_core.exceptions import UniFiValidationError
from unifi_core.network.managers.firewall_manager import FirewallManager
from unifi_core.network.models.firewall import V2FirewallPolicyOrdering

SRC = "a" * 24
DST = "b" * 24
A = "1" * 24
B = "2" * 24
C = "3" * 24
FOREIGN = "4" * 24


def policy(identifier, index, predefined=False, destination=DST, enabled=True):
    return {
        "_id": identifier,
        "index": index,
        "predefined": predefined,
        "enabled": enabled,
        "source": {"zone_id": SRC},
        "destination": {"zone_id": destination},
    }


BASE = [
    policy(A, 10000),
    policy(B, 10001, enabled=False),
    policy("system-generated-id", 30000, predefined=True),
    policy(C, 40000),
    policy("terminal-generated-id", 2147483647, predefined=True),
    policy(FOREIGN, 10000, destination=SRC),
]


@pytest.fixture
def controller():
    connection = MagicMock()
    connection.site = "default"
    connection.ensure_connected = AsyncMock(return_value=True)
    connection.ensure_session_connected = AsyncMock(return_value=True)
    # Cache is deliberately stale: membership must come from live GETs.
    connection.get_cached.return_value = [{"_id": "stale-zone"}]
    state = {"rows": copy.deepcopy(BASE), "apply": True, "write_error": None, "read_error": None, "written": False}

    async def request(req):
        if req.method == "put":
            state["written"] = True
            if state["write_error"]:
                raise state["write_error"]
            if state["apply"]:
                ranks = {pid: 10000 + i for i, pid in enumerate(req.data["before_predefined_ids"])}
                ranks.update({pid: 40000 + i for i, pid in enumerate(req.data["after_predefined_ids"])})
                for row in state["rows"]:
                    if row["_id"] in ranks:
                        row["index"] = ranks[row["_id"]]
            return []  # Controller responses need not echo the ordering.
        if state["written"] and state["read_error"]:
            raise state["read_error"]
        if req.path == "/firewall/zone":
            return [{"_id": SRC}, {"_id": DST}]
        assert req.path == "/firewall-policies"
        return copy.deepcopy(state["rows"])

    connection.request = AsyncMock(side_effect=request)
    return FirewallManager(connection), connection, state


@pytest.mark.asyncio
async def test_fresh_pair_read_preserves_disabled_rules_and_excludes_other_pair(controller):
    manager, connection, _ = controller
    result = await manager.get_v2_firewall_policy_ordering(SRC, DST)
    assert result["before_predefined_ids"] == [A, B]
    assert result["after_predefined_ids"] == [C]
    assert result["predefined_ids"] == ["system-generated-id", "terminal-generated-id"]
    assert [call.args[0].path for call in connection.request.await_args_list] == [
        "/firewall/zone",
        "/firewall-policies",
    ]


@pytest.mark.asyncio
async def test_put_uses_exact_v2_payload_and_verifies_without_reordering_other_pair(controller):
    manager, connection, state = controller
    foreign_before = copy.deepcopy(state["rows"][-1])
    result = await manager.reorder_v2_firewall_policies(SRC, DST, [B, A], [C])
    assert result["success"] and result["mutation_applied"] and result["verified"]
    writes = [call.args[0] for call in connection.request.await_args_list if call.args[0].method == "put"]
    assert len(writes) == 1
    assert writes[0].path == "/firewall-policies/batch-reorder"
    assert writes[0].data == {
        "source_zone_id": SRC,
        "destination_zone_id": DST,
        "before_predefined_ids": [B, A],
        "after_predefined_ids": [C],
    }
    assert result["ordering"]["before_predefined_ids"] == [B, A]
    assert state["rows"][-1] == foreign_before
    connection._invalidate_cache.assert_any_call("firewall_policies")
    connection._invalidate_cache.assert_any_call("firewall_policy_ordering")


@pytest.mark.asyncio
async def test_verified_noop_avoids_put(controller):
    manager, connection, _ = controller
    result = await manager.reorder_v2_firewall_policies(SRC, DST, [A, B], [C])
    assert result["success"] and result["mutation_applied"] is False
    assert all(call.args[0].method == "get" for call in connection.request.await_args_list)


@pytest.mark.asyncio
@pytest.mark.parametrize("before,after", [([A], [C]), ([A, B, FOREIGN], [C]), ([A, B, "5" * 24], [C])])
async def test_missing_foreign_or_unknown_rule_aborts_before_write(controller, before, after):
    manager, connection, _ = controller
    with pytest.raises(ValueError, match="preserve every custom policy"):
        await manager.reorder_v2_firewall_policies(SRC, DST, before, after)
    assert all(call.args[0].method == "get" for call in connection.request.await_args_list)


@pytest.mark.asyncio
async def test_new_rule_since_preview_prevents_stale_membership_write(controller):
    manager, connection, state = controller
    await manager.preview_v2_firewall_policy_ordering(SRC, DST, [B, A], [C])
    state["rows"].append(policy("5" * 24, 10002))
    with pytest.raises(ValueError):
        await manager.reorder_v2_firewall_policies(SRC, DST, [B, A], [C])
    assert all(call.args[0].method == "get" for call in connection.request.await_args_list)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "before,after",
    [([A, A], [C]), ([A, B], [B]), ([123], []), (["wrong"], []), (["a9cb4ac7-5f53-4e11-8dfe-5b8fd12b9448"], [])],
)
async def test_invalid_ids_or_duplicates_are_rejected_before_io(controller, before, after):
    manager, connection, _ = controller
    with pytest.raises(ValidationError):
        await manager.reorder_v2_firewall_policies(SRC, DST, before, after)
    connection.request.assert_not_awaited()


def test_strict_model_rejects_unknown_fields_and_tuple_coercion():
    data = dict(source_zone_id=SRC, destination_zone_id=DST, before_predefined_ids=[A], after_predefined_ids=[])
    with pytest.raises(ValidationError):
        V2FirewallPolicyOrdering(**data, ignored=True)
    with pytest.raises(ValidationError):
        V2FirewallPolicyOrdering(**{**data, "before_predefined_ids": (A,)})


@pytest.mark.asyncio
async def test_missing_session_aborts_without_key_transport(controller):
    manager, connection, _ = controller
    connection.ensure_session_connected.return_value = False
    with pytest.raises(Exception, match="local session credentials"):
        await manager.get_v2_firewall_policy_ordering(SRC, DST)
    connection.request.assert_not_awaited()
    connection.request_integration_api.assert_not_called()


@pytest.mark.asyncio
async def test_nonexistent_zone_aborts_before_policy_read(controller):
    manager, connection, _ = controller
    with pytest.raises(UniFiValidationError, match="existing V2 firewall zones"):
        await manager.get_v2_firewall_policy_ordering(SRC, "6" * 24)
    assert connection.request.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [{"index": None}, {"index": True}, {"predefined": None}, {"index": 30000}])
async def test_unclassifiable_order_aborts(controller, change):
    manager, _, state = controller
    state["rows"][0].update(change)
    with pytest.raises(Exception, match="Failed to read V2 firewall policy ordering"):
        await manager.get_v2_firewall_policy_ordering(SRC, DST)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["write", "read", "ignored"])
async def test_unknown_or_unverified_outcome_never_replays_and_does_not_leak(controller, caplog, failure):
    manager, connection, state = controller
    secret = "controller-only-key-do-not-log"
    if failure == "write":
        state["write_error"] = TimeoutError(secret)
    elif failure == "read":
        state["read_error"] = RuntimeError(secret)
    else:
        state["apply"] = False
    with (
        patch("unifi_core.network.managers.firewall_manager.asyncio.sleep", new=AsyncMock()),
        caplog.at_level(logging.WARNING),
    ):
        result = await manager.reorder_v2_firewall_policies(SRC, DST, [B, A], [C])
    assert result["success"] is False and result["mutation_applied"] is None and result["verified"] is False
    assert sum(call.args[0].method == "put" for call in connection.request.await_args_list) == 1
    assert secret not in str(result) and secret not in caplog.text


@pytest.mark.asyncio
async def test_tool_preview_delegates_without_mutating(controller):
    manager, connection, _ = controller
    # Patch the runtime alias before first import, and the module alias if an
    # earlier test already loaded the tool module.
    with patch("unifi_network_mcp.runtime.firewall_manager", manager):
        from unifi_network_mcp.tools import firewall
    with patch.object(firewall, "firewall_manager", manager):
        result = await firewall.reorder_v2_firewall_policies(SRC, DST, [B, A], [C])
    assert result["success"] and result["requires_confirmation"]
    assert all(call.args[0].method == "get" for call in connection.request.await_args_list)


@pytest.mark.asyncio
async def test_tool_confirm_delegates_and_read_tool_returns_complete_order(controller):
    manager, _, _ = controller
    with patch("unifi_network_mcp.runtime.firewall_manager", manager):
        from unifi_network_mcp.tools import firewall
    with patch.object(firewall, "firewall_manager", manager):
        result = await firewall.reorder_v2_firewall_policies(SRC, DST, [B, A], [C], confirm=True)
        read = await firewall.get_v2_firewall_policy_ordering(SRC, DST)
    assert result["success"] and read["ordering"]["before_predefined_ids"] == [B, A]


@pytest.mark.asyncio
async def test_tool_invalid_input_and_opaque_error_do_not_leak(controller, caplog):
    manager, connection, _ = controller
    with patch("unifi_network_mcp.runtime.firewall_manager", manager):
        from unifi_network_mcp.tools import firewall
    secret = "opaque-secret-from-controller"
    with patch.object(firewall, "firewall_manager", manager), caplog.at_level(logging.ERROR):
        bad = await firewall.reorder_v2_firewall_policies(secret, DST, [A], [], confirm=True)
        connection.request.assert_not_awaited()
        manager.get_v2_firewall_policy_ordering = AsyncMock(side_effect=RuntimeError(secret))
        failed = await firewall.get_v2_firewall_policy_ordering(SRC, DST)
    assert not bad["success"] and not failed["success"]
    assert secret not in str(bad) + str(failed) + caplog.text
