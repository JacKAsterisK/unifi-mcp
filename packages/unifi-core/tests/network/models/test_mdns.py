"""mDNS field and write verification contracts."""

from copy import deepcopy
from unittest.mock import AsyncMock, MagicMock

import pytest
from unifi_core.network.managers.system_manager import SystemManager
from unifi_core.network.models.mdns import mdns_from_controller, mdns_to_controller_update

RECORD = {
    "_id": "mdns-id",
    "key": "mdns",
    "site_id": "default",
    "mode": "all",
    "predefined_services": [],
    "custom_services": [],
    "enabled_for": "some",
    "enabled_for_network_ids": ["n1", "n2"],
    "future_setting": {"nested": [1]},
}


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"mode": "off"},
        {"mode": None},
        {"enabled_for": "all"},
        {"enabled_for_network_ids": []},
        {"id": "other"},
        {"extra": 1},
        {"predefined_services": [{"code": ""}]},
        {"predefined_services": [{"code": "ok", "extra": 1}]},
        {"custom_services": [{"name": "a", "address": "bad"}]},
        {"custom_services": [{"name": "a", "address": "_http._tcp", "extra": 1}]},
        {"custom_services": "bad"},
    ],
)
def test_invalid_update_is_value_free(bad):
    with pytest.raises(ValueError) as exc:
        mdns_to_controller_update(bad)
    assert "bad" not in str(exc.value)
    assert "other" not in str(exc.value)


def test_read_and_list_replacement():
    record = mdns_from_controller(RECORD)
    assert record.id == "mdns-id"
    assert record.enabled_for_network_ids == ["n1", "n2"]
    assert mdns_to_controller_update({"predefined_services": [{"code": "shelly"}]}) == {
        "predefined_services": [{"code": "shelly"}]
    }
    assert mdns_to_controller_update({"custom_services": [{"name": "Web", "address": "_http._tcp.local"}]}) == {
        "custom_services": [{"name": "Web", "address": "_http._tcp.local"}]
    }


@pytest.mark.parametrize("ids", [[], ["not-an-object-id"], ["a" * 24, "a" * 24], [42], "a" * 24, None])
def test_selected_network_ids_are_strict_unique_object_ids(ids):
    with pytest.raises(ValueError):
        mdns_to_controller_update({"enabled_for_network_ids": ids})


@pytest.mark.asyncio
async def test_scope_update_preserves_services_unknown_fields_and_verifies_new_membership():
    before = {**deepcopy(RECORD), "enabled_for_network_ids": ["a" * 24]}
    wanted = ["a" * 24, "b" * 24]
    after = {**deepcopy(before), "enabled_for_network_ids": wanted}
    networks = [{"_id": item, "purpose": "corporate", "enabled": True, "ip_subnet": "10.0.1.1/24"} for item in wanted]
    manager, conn = manager_and_connection([[before], networks, [], [after]])
    result = await manager.update_mdns_settings({"enabled_for_network_ids": wanted})
    assert result.success and result.mutation_applied
    assert result.persisted_fields == ("enabled_for_network_ids",)
    assert conn.request.call_args_list[1].args[0].path == "/rest/networkconf"
    sent = conn.request.call_args_list[2].args[0].data
    assert sent == after
    assert before["enabled_for_network_ids"] == ["a" * 24]
    assert conn.request.await_count == 4


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["all", "none", None])
async def test_scope_list_cannot_change_scope_selector(scope):
    before = {**deepcopy(RECORD), "enabled_for": scope}
    manager, conn = manager_and_connection([[before]])
    result = await manager.update_mdns_settings({"enabled_for_network_ids": ["a" * 24]})
    assert not result.success and result.mutation_applied is False
    assert conn.request.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("record", [None, {"purpose": "wan"}, {"enabled": False}, {"gateway_type": "switch"}])
async def test_unknown_or_ineligible_network_rejected_before_write(record):
    networks = (
        []
        if record is None
        else [{"_id": "a" * 24, "purpose": "corporate", "enabled": True, "ip_subnet": "10.0.1.1/24", **record}]
    )
    manager, conn = manager_and_connection([[deepcopy(RECORD)], networks])
    result = await manager.update_mdns_settings({"enabled_for_network_ids": ["a" * 24]})
    assert not result.success and result.mutation_applied is False
    assert all(call.args[0].method == "get" for call in conn.request.call_args_list)


@pytest.mark.asyncio
async def test_scope_silent_drop_does_not_verify_against_old_preserved_membership():
    before = {**deepcopy(RECORD), "enabled_for_network_ids": ["a" * 24]}
    wanted = ["a" * 24, "b" * 24]
    networks = [{"_id": item, "purpose": "corporate", "ip_subnet": "10.0.1.1/24"} for item in wanted]
    manager, conn = manager_and_connection([[before], networks, [], [deepcopy(before)]])
    result = await manager.update_mdns_settings({"enabled_for_network_ids": wanted})
    assert not result.success and result.mutation_applied is True
    assert "enabled_for_network_ids" in result.dropped_fields
    assert sum(call.args[0].method == "put" for call in conn.request.call_args_list) == 1


@pytest.mark.asyncio
async def test_scope_preview_uses_fresh_inventory_and_never_writes():
    before = deepcopy(RECORD)
    networks = [{"_id": "a" * 24, "purpose": "corporate", "ip_subnet": "10.0.1.1/24"}]
    manager, conn = manager_and_connection([[before], networks])
    view, updates = await manager.preview_mdns_settings_update({"enabled_for_network_ids": ["a" * 24]})
    assert view.enabled_for_network_ids == ["n1", "n2"]
    assert updates["enabled_for_network_ids"] == ["a" * 24]
    assert conn.request.await_count == 2
    assert all(call.args[0].method == "get" for call in conn.request.call_args_list)


def test_read_tolerates_new_and_legacy_nested_shapes_but_write_stays_strict():
    raw = deepcopy(RECORD)
    raw["predefined_services"] = [{"code": "printers", "enabled": True}]
    raw["custom_services"] = [{"name": "_hap._tcp"}]
    settings = mdns_from_controller(raw).model_dump()
    assert settings["predefined_services"] == [{"code": "printers"}]
    assert settings["custom_services"] == [{"name": "_hap._tcp", "address": None}]
    with pytest.raises(ValueError, match="predefined_services"):
        mdns_to_controller_update({"predefined_services": raw["predefined_services"]})
    with pytest.raises(ValueError, match="custom_services"):
        mdns_to_controller_update({"custom_services": raw["custom_services"]})


def manager_and_connection(responses):
    conn = MagicMock()
    conn.site = "default"
    conn.request = AsyncMock(side_effect=responses)
    conn.ensure_session_connected = AsyncMock(return_value=True)
    conn._invalidate_cache = MagicMock()
    return SystemManager(conn), conn


@pytest.mark.parametrize(
    "fields",
    [
        {"mode": "all", "custom_services": [{"name": "Web", "address": "_http._tcp"}]},
        {"mode": "all", "predefined_services": [{"code": "printers"}]},
        {"mode": "custom", "custom_services": [], "predefined_services": []},
    ],
)
def test_impossible_explicit_service_selection_is_rejected(fields):
    with pytest.raises(ValueError, match="requires"):
        mdns_to_controller_update(fields)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "updates",
    [
        {"custom_services": [{"name": "Web", "address": "_http._tcp"}]},
        {"mode": "custom"},
    ],
)
async def test_partial_update_is_checked_against_fresh_mode_and_lists(updates):
    manager, conn = manager_and_connection([[deepcopy(RECORD)]])
    result = await manager.update_mdns_settings(updates)
    assert result.success is False
    assert result.mutation_applied is False
    assert "requires" in result.error
    assert conn.request.await_count == 1
    assert conn.request.call_args.args[0].method == "get"


@pytest.mark.asyncio
async def test_mode_and_service_list_can_transition_together():
    updates = {"mode": "custom", "custom_services": [{"name": "Web", "address": "_http._tcp"}]}
    after = {**deepcopy(RECORD), **updates}
    manager, conn = manager_and_connection([[deepcopy(RECORD)], [], [after]])
    result = await manager.update_mdns_settings(updates)
    assert result.success is True
    assert set(result.persisted_fields) == {"mode", "custom_services"}
    assert set(result.unchanged_fields) == {"enabled_for", "enabled_for_network_ids"}
    assert conn.request.call_args_list[1].args[0].data == after


@pytest.mark.asyncio
async def test_full_merge_and_verified_scope():
    before = deepcopy(RECORD)
    before["mode"] = "custom"
    before["predefined_services"] = [{"code": "printers"}]
    after = deepcopy(before)
    after["custom_services"] = [{"name": "Web", "address": "_http._tcp"}]
    manager, conn = manager_and_connection([[before], {"meta": {"rc": "ok"}}, [after]])
    result = await manager.update_mdns_settings({"custom_services": after["custom_services"]})
    assert result.success and result.mutation_applied
    payload = conn.request.call_args_list[1].args[0].data
    assert payload["future_setting"] == before["future_setting"]
    assert payload["enabled_for"] == "some"
    assert payload["enabled_for_network_ids"] == ["n1", "n2"]
    assert payload["custom_services"] == after["custom_services"]
    assert before["custom_services"] == []
    conn._invalidate_cache.assert_called_once()


@pytest.mark.asyncio
async def test_empty_write_response_still_verifies_persisted_update():
    after = deepcopy(RECORD)
    after["mode"] = "auto"
    manager, conn = manager_and_connection([[deepcopy(RECORD)], [], [after]])
    result = await manager.update_mdns_settings({"mode": "auto"})
    assert result.success and result.mutation_applied is True
    assert result.persisted_fields == ("mode",)
    assert conn.request.await_count == 3


@pytest.mark.asyncio
async def test_untouched_legacy_nested_values_survive_full_write():
    before = deepcopy(RECORD)
    before["predefined_services"] = [{"code": "printers", "enabled": True}]
    before["custom_services"] = [{"name": "_hap._tcp"}]
    after = deepcopy(before)
    after["mode"] = "auto"
    manager, conn = manager_and_connection([[before], [], [after]])
    result = await manager.update_mdns_settings({"mode": "auto"})
    assert result.success
    sent = conn.request.call_args_list[1].args[0].data
    assert sent["predefined_services"] == before["predefined_services"]
    assert sent["custom_services"] == before["custom_services"]


@pytest.mark.asyncio
async def test_noop_skips_write():
    manager, conn = manager_and_connection([[deepcopy(RECORD)]])
    result = await manager.update_mdns_settings({"mode": "all"})
    assert result.success and not result.mutation_applied
    assert conn.request.await_count == 1


@pytest.mark.asyncio
async def test_scope_change_is_failed_verification():
    after = deepcopy(RECORD)
    after["mode"] = "auto"
    after["enabled_for"] = "all"
    manager, _ = manager_and_connection([[deepcopy(RECORD)], {"meta": {"rc": "ok"}}, [after]])
    result = await manager.update_mdns_settings({"mode": "auto"})
    assert not result.success
    assert "enabled_for" in result.coerced_fields
    assert "future_setting" not in repr(result.to_dict())


@pytest.mark.asyncio
async def test_uncertain_write_invalidates_cache_without_secret_leak():
    manager, conn = manager_and_connection([[deepcopy(RECORD)], RuntimeError("secret-code")])
    result = await manager.update_mdns_settings({"mode": "auto"})
    assert not result.success and result.metadata["outcome_uncertain"]
    assert result.mutation_applied is None
    assert "secret-code" not in repr(result.to_dict())
    conn._invalidate_cache.assert_called_once()


@pytest.mark.asyncio
async def test_read_requires_exact_singleton():
    manager, _ = manager_and_connection([[]])
    with pytest.raises(RuntimeError, match="Failed to read mDNS settings"):
        await manager.get_mdns_settings()


@pytest.mark.asyncio
async def test_invalid_manager_input_is_rejected_before_connection():
    manager, conn = manager_and_connection([])
    with pytest.raises(ValueError, match="enabled_for"):
        await manager.update_mdns_settings({"enabled_for": "all"})
    conn.ensure_session_connected.assert_not_awaited()
    conn.request.assert_not_awaited()


@pytest.mark.asyncio
async def test_readback_error_is_uncertain_and_value_free():
    manager, conn = manager_and_connection(
        [[deepcopy(RECORD)], {"meta": {"rc": "ok"}}, RuntimeError("synthetic-secret")]
    )
    result = await manager.update_mdns_settings({"mode": "auto"})
    assert not result.success and result.metadata["outcome_uncertain"]
    assert result.mutation_applied is None
    assert "synthetic-secret" not in repr(result.to_dict())
    conn._invalidate_cache.assert_called_once()
