"""Synthetic controller contract, conflict checks and uncertain-write boundaries."""

import base64
from copy import deepcopy
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiounifi.errors import Forbidden
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from unifi_core.network.managers.vpn_manager import VpnManager
from unifi_core.network.models.wireguard import (
    WireGuardError,
    WireGuardPeerCreate,
    WireGuardServerCreate,
    server_public_key,
    server_view,
    validate_input,
)
from unifi_core.redaction import redact_sensitive_fields

SECRET = "controller-only-secret-that-must-never-escape"
KEY = base64.b64encode(bytes(range(32))).decode()
SERVER_INPUT = {"name": "Development", "ip_subnet": "10.77.31.1/24", "local_port": 51821}
PEER_INPUT = {"name": "Developer", "interface_ip": "10.77.31.2", "public_key": KEY}
SERVER = {
    "_id": "server",
    "vpn_type": "wireguard-server",
    "name": "Development",
    "ip_subnet": "10.77.31.1/24",
    "enabled": False,
    "opaque": SECRET,
}
PEER = {"_id": "peer", "network_id": "server", **PEER_INPUT, "allowed_ips": [], "private_key": SECRET}


@pytest.fixture
def controller():
    conn = MagicMock()
    conn.site = "default"
    conn.ensure_session_connected = AsyncMock(return_value=True)
    conn.networks = [{"_id": "wan", "purpose": "wan", "wan_networkgroup": "WAN"}]
    conn.zones = [{"_id": "vpn-zone", "name": "Vpn", "default_zone": True}]
    conn.peers = []
    conn.write_error = None
    conn.read_error_after_write = False
    conn.did_write = False
    conn.dropped = None
    conn.store_public_key = False
    conn.override_private_key = None

    async def request(req):
        if req.method == "get":
            if conn.did_write and conn.read_error_after_write:
                raise RuntimeError(SECRET)
            if req.path == "/rest/networkconf":
                return deepcopy(conn.networks)
            if req.path == "/firewall/zone":
                return deepcopy(conn.zones)
            if req.path.endswith("/users"):
                return deepcopy(conn.peers)
            raise AssertionError("Unexpected read path")
        conn.did_write = True
        if conn.write_error:
            raise conn.write_error
        if req.path == "/rest/networkconf":
            raw = {"_id": "server", **deepcopy(req.data), "opaque": SECRET}
            private = X25519PrivateKey.from_private_bytes(base64.b64decode(raw["x_wireguard_private_key"]))
            if conn.store_public_key:
                raw["wireguard_public_key"] = base64.b64encode(private.public_key().public_bytes_raw()).decode()
            if conn.override_private_key is not None:
                raw["x_wireguard_private_key"] = conn.override_private_key
            conn.networks.append(raw)
            if conn.dropped:
                raw.pop(conn.dropped, None)
        elif req.path.endswith("/users/batch"):
            assert isinstance(req.data, list) and len(req.data) == 1
            assert "network_id" not in req.data[0]
            # Network 10.6.106 validates present address fields even when empty.
            assert "interface_ipv6" not in req.data[0]
            assert req.data[0]["preshared_key"] == ""
            conn.peers.append({"_id": "peer", "network_id": "server", **deepcopy(req.data[0]), "private_key": SECRET})
            if conn.dropped:
                conn.peers[0].pop(conn.dropped, None)
        elif req.path.endswith("/users/batch_delete"):
            assert req.method == "post" and req.data == ["peer"]
            conn.peers = []
        elif req.method == "delete":
            conn.networks = [record for record in conn.networks if record["_id"] != "server"]
        elif req.method == "put":
            conn.networks[-1] = deepcopy(req.data)
        else:
            raise AssertionError("Unexpected mutation path")
        return [{"private_key": SECRET}]

    conn.request = AsyncMock(side_effect=request)
    return conn


@pytest.mark.asyncio
async def test_server_preview_is_read_only_then_create_is_disabled_verified_and_secret_free(controller, caplog):
    manager = VpnManager(controller)
    preview = await manager.prepare_wireguard_server(SERVER_INPUT)
    assert preview["enabled"] is False
    assert "x_wireguard_private_key" not in preview
    assert all(call.args[0].method == "get" for call in controller.request.call_args_list)
    result = await manager.create_wireguard_server(SERVER_INPUT)
    assert result.success is True
    assert result.resource["enabled"] is False
    assert result.resource["wireguard_public_key"]
    secret = controller.networks[-1]["x_wireguard_private_key"]
    assert secret not in repr(result) + repr(preview) + caplog.text
    assert SECRET not in repr(result) + caplog.text
    assert sum(call.args[0].method == "post" for call in controller.request.call_args_list) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("collision", ["name", "subnet", "port", "wan", "zone"])
async def test_server_preflight_rejects_collisions_without_writes(controller, collision):
    if collision == "name":
        controller.networks.append({"name": "Development"})
    elif collision == "subnet":
        controller.networks.append({"ip_subnet": "10.77.0.1/16"})
    elif collision == "port":
        controller.networks.append({"local_port": "51821"})
    elif collision == "wan":
        controller.networks = []
    else:
        controller.zones[0]["default_zone"] = False
    with pytest.raises(WireGuardError):
        await VpnManager(controller).create_wireguard_server(SERVER_INPUT)
    assert not controller.did_write


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["enabled", "local_port", "x_wireguard_private_key", "firewall_zone_id"])
async def test_server_silent_field_drop_cannot_report_success(controller, field):
    controller.dropped = field
    result = await VpnManager(controller).create_wireguard_server(SERVER_INPUT)
    assert result.success is False
    assert ("wireguard_public_key" if field == "x_wireguard_private_key" else field) in result.dropped_fields
    assert SECRET not in repr(result)


@pytest.mark.asyncio
async def test_create_also_accepts_controller_with_consistent_public_and_private_fields(controller):
    controller.store_public_key = True
    result = await VpnManager(controller).create_wireguard_server(SERVER_INPUT)
    assert result.success
    assert result.resource["wireguard_public_key"] == controller.networks[-1]["wireguard_public_key"]


@pytest.mark.asyncio
@pytest.mark.parametrize("stored", [KEY, SECRET, None])
async def test_missing_malformed_or_changed_stored_private_key_cannot_verify_expected_key(controller, stored, caplog):
    controller.override_private_key = stored
    if stored is None:
        controller.dropped = "x_wireguard_private_key"
    result = await VpnManager(controller).create_wireguard_server(SERVER_INPUT)
    assert not result.success
    assert "wireguard_public_key" in result.dropped_fields + result.coerced_fields
    assert SECRET not in repr(result) + caplog.text
    if stored is not None:
        assert stored not in repr(result) + caplog.text
    assert sum(call.args[0].method == "post" for call in controller.request.call_args_list) == 1


def test_private_only_public_projection_matches_rfc7748_vector_without_mutating_or_exposing_record():
    # RFC 7748 section 6.1: Alice's X25519 private/public pair.
    private = base64.b64encode(
        bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    ).decode()
    public = base64.b64encode(
        bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    ).decode()
    record = {**SERVER, "x_wireguard_private_key": private}
    original = deepcopy(record)
    assert server_public_key(record) == public
    view = server_view(record)
    assert view["wireguard_public_key"] == public
    assert private not in repr(view)
    assert SECRET not in repr(view)
    assert record == original
    assert server_public_key({"wireguard_public_key": public}) == public
    assert server_public_key({**record, "wireguard_public_key": KEY}) is None


@pytest.mark.parametrize("private", [SECRET, "***REDACTED***", KEY[:-1], base64.b64encode(b"short").decode(), 42, {}])
def test_malformed_private_projection_does_not_fall_back_to_an_unverified_public_value(private):
    view = server_view({**SERVER, "x_wireguard_private_key": private, "wireguard_public_key": KEY})
    assert "wireguard_public_key" not in view
    assert "x_wireguard_private_key" not in view
    assert SECRET not in repr(view)


@pytest.mark.asyncio
async def test_vpn_server_inventory_exposes_derived_public_before_existing_secret_redaction(controller, caplog):
    controller.get_cached.return_value = None
    controller.networks.append(
        {**{key: value for key, value in SERVER.items() if key != "opaque"}, "x_wireguard_private_key": KEY}
    )
    original = deepcopy(controller.networks)
    result = await VpnManager(controller).get_vpn_servers()
    assert result[0]["wireguard_public_key"] == server_public_key(controller.networks[-1])
    assert controller.networks == original
    public_result = redact_sensitive_fields(result)
    assert KEY not in repr(public_result) + caplog.text
    assert SECRET not in repr(public_result) + caplog.text
    assert public_result[0]["wireguard_public_key"] == result[0]["wireguard_public_key"]


@pytest.mark.asyncio
async def test_peer_create_uses_v2_array_and_never_transmits_client_private_key(controller):
    controller.networks.append(SERVER)
    result = await VpnManager(controller).create_wireguard_peer("server", PEER_INPUT)
    assert result.success
    req = next(call.args[0] for call in controller.request.call_args_list if call.args[0].method == "post")
    assert req.path == "/wireguard/server/users/batch"
    assert req.data[0]["allowed_ips"] == []
    assert "interface_ipv6" not in req.data[0]
    assert req.data[0]["preshared_key"] == ""
    assert "private_key" not in req.data[0]
    assert SECRET not in repr(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["name", "interface_ip", "public_key"])
async def test_peer_preflight_rejects_duplicate_identity(controller, field):
    controller.networks.append(SERVER)
    existing = {
        **PEER,
        "name": "Other",
        "interface_ip": "10.77.31.3",
        "public_key": base64.b64encode(b"a" * 32).decode(),
    }
    existing[field] = PEER_INPUT[field]
    controller.peers = [existing]
    with pytest.raises(WireGuardError, match="already exists"):
        await VpnManager(controller).create_wireguard_peer("server", PEER_INPUT)
    assert not controller.did_write


@pytest.mark.asyncio
@pytest.mark.parametrize("ip", ["10.77.31.1", "10.77.31.0", "10.77.31.255", "10.77.30.2"])
async def test_peer_address_must_be_usable_in_tunnel(controller, ip):
    controller.networks.append(SERVER)
    with pytest.raises(WireGuardError, match="Peer address"):
        await VpnManager(controller).create_wireguard_peer("server", {**PEER_INPUT, "interface_ip": ip})
    assert not controller.did_write


@pytest.mark.asyncio
async def test_peer_revoke_contract_and_server_deletion_requires_empty_peers(controller):
    controller.networks.append(SERVER)
    controller.peers = [PEER]
    manager = VpnManager(controller)
    with pytest.raises(WireGuardError, match="Revoke all peers"):
        await manager.delete_wireguard_server("server")
    result = await manager.delete_wireguard_peer("server", "peer")
    assert result.success and result.operation == "delete"
    assert SECRET not in repr(result)
    result = await manager.delete_wireguard_peer("server", "peer")
    assert result.success and result.mutation_applied is False
    result = await manager.delete_wireguard_server("server")
    assert result.success
    assert not any(record.get("_id") == "server" for record in controller.networks)


@pytest.mark.asyncio
async def test_state_update_fetch_merge_put_preserves_opaque_configuration(controller):
    controller.networks.append(SERVER)
    result = await VpnManager(controller).update_wireguard_server_state("server", True)
    assert result.success and result.resource["enabled"] is True
    request = next(call.args[0] for call in controller.request.call_args_list if call.args[0].method == "put")
    assert request.data["opaque"] == SECRET
    assert SECRET not in repr(result)


@pytest.mark.asyncio
async def test_ipv4_workflow_cannot_activate_an_ipv6_server(controller):
    controller.networks.append({**SERVER, "ipv6_subnet": "fd00::1/64"})
    manager = VpnManager(controller)
    with pytest.raises(WireGuardError, match="IPv6"):
        await manager.update_wireguard_server_state("server", True)
    assert not controller.did_write
    assert (await manager.update_wireguard_server_state("server", False)).success


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["rejected", "timeout", "readback"])
@pytest.mark.parametrize("operation", ["server", "peer", "revoke", "delete", "state"])
async def test_rejections_and_uncertain_outcomes_never_retry_or_leak(controller, failure, operation, caplog):
    if operation != "server":
        controller.networks.append(SERVER)
    if operation == "revoke":
        controller.peers = [PEER]
    if failure == "rejected":
        controller.write_error = Forbidden(SECRET)
    elif failure == "timeout":
        controller.write_error = TimeoutError(SECRET)
    else:
        controller.read_error_after_write = True
    manager = VpnManager(controller)
    action = {
        "server": lambda: manager.create_wireguard_server(SERVER_INPUT),
        "peer": lambda: manager.create_wireguard_peer("server", PEER_INPUT),
        "revoke": lambda: manager.delete_wireguard_peer("server", "peer"),
        "delete": lambda: manager.delete_wireguard_server("server"),
        "state": lambda: manager.update_wireguard_server_state("server", True),
    }[operation]
    result = await action()
    assert result.success is False
    assert result.mutation_applied is (False if failure == "rejected" else None)
    assert sum(call.args[0].method != "get" for call in controller.request.call_args_list) == 1
    assert SECRET not in repr(result) + caplog.text


@pytest.mark.asyncio
async def test_session_required_even_if_api_key_inventory_works(controller):
    controller.ensure_session_connected.return_value = False
    with pytest.raises(WireGuardError, match="local Network session"):
        await VpnManager(controller).create_wireguard_server(SERVER_INPUT)
    controller.request.assert_not_called()


@pytest.mark.asyncio
async def test_inconsistent_client_purpose_cannot_be_targeted_as_server(controller):
    controller.networks.append({**SERVER, "purpose": "vpn-client"})
    with pytest.raises(WireGuardError, match="server not found"):
        await VpnManager(controller).create_wireguard_peer("server", PEER_INPUT)
    assert not controller.did_write


@pytest.mark.parametrize(
    "data",
    [
        {"private_key": SECRET},
        {"allowed_ips": ["192.168.50.0/24"]},
        {"interface_ip": "10.77.31.2/32"},
        {"public_key": "not-a-key"},
    ],
)
def test_peer_inputs_cannot_silently_accept_private_keys_or_lan_routes(data):
    with pytest.raises(WireGuardError) as exc:
        validate_input(WireGuardPeerCreate, {**PEER_INPUT, **data})
    assert SECRET not in str(exc.value)


@pytest.mark.parametrize(
    "data",
    [
        {"enabled": True},
        {"ipv6_subnet": "fd00::/64"},
        {"local_port": True},
        {"ip_subnet": "10.77.31.0/24"},
        {"ip_subnet": "10.77.31.1/32"},
    ],
)
def test_server_inputs_are_strict_and_cannot_bypass_staging(data):
    with pytest.raises(WireGuardError):
        validate_input(WireGuardServerCreate, {**SERVER_INPUT, **data})
