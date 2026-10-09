"""REST inventory projection and real Core action privacy/readback integration."""

import base64
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient
from unifi_core.network.managers.vpn_manager import VpnManager

from tests.test_action_credential_audit import _audit_rows, _post
from tests.test_action_endpoint import _bootstrap

SECRET = "synthetic-controller-only-wireguard-secret"
PUBLIC_KEY = base64.b64encode(bytes(range(32))).decode()


@pytest.mark.asyncio
async def test_peer_resource_route_excludes_secrets_even_when_redaction_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("UNIFI_API_DB_KEY", "k")
    app, key, _ = await _bootstrap(tmp_path, scopes="read", redact_sensitive_fields=False)
    manager = MagicMock()
    manager.list_wireguard_peers = AsyncMock(
        return_value=[
            {
                "_id": "peer",
                "network_id": "server",
                "name": "Developer",
                "interface_ip": "10.77.31.2",
                "public_key": PUBLIC_KEY,
                "allowed_ips": [],
                "private_key": SECRET,
                "opaque": SECRET,
            }
        ]
    )
    app.state.manager_factory.get_domain_manager = AsyncMock(return_value=manager)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            response = await client.get(
                "/v1/sites/default/vpn-servers/server/wireguard-peers", headers={"Authorization": f"Bearer {key}"}
            )
        assert response.status_code == 200
        assert response.json()["items"][0]["id"] == "peer"
        assert SECRET not in response.text
        manager.list_wireguard_peers.assert_awaited_once_with("server")
    finally:
        await app.state.engine.dispose()


@pytest.mark.asyncio
async def test_peer_action_preserves_uncertain_write_and_audit_privacy(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("UNIFI_API_DB_KEY", "k")
    monkeypatch.setenv("UNIFI_POLICY_NETWORK_VPN_SERVERS_CREATE", "true")
    app, key, cid = await _bootstrap(tmp_path)
    connection = MagicMock()
    connection.site = "default"
    connection.ensure_session_connected = AsyncMock(return_value=True)
    connection.request = AsyncMock(
        side_effect=[
            [{"_id": "server", "vpn_type": "wireguard-server", "ip_subnet": "10.77.31.1/24", "opaque": SECRET}],
            [],
            TimeoutError(SECRET),
        ]
    )
    app.state.manager_factory.get_domain_manager = AsyncMock(return_value=VpnManager(connection))
    try:
        response = await _post(
            app,
            key,
            cid,
            "unifi_create_wireguard_peer",
            {
                "server_id": "server",
                "peer_data": {"name": "Developer", "interface_ip": "10.77.31.2", "public_key": PUBLIC_KEY},
            },
            True,
        )
        assert response.status_code == 200
        assert response.json()["success"] is False
        assert response.json()["mutation_applied"] is None
        assert sum(call.args[0].method != "get" for call in connection.request.call_args_list) == 1
        audit = await _audit_rows(app, "unifi_create_wireguard_peer")
        assert len(audit) == 1
        assert SECRET not in response.text + caplog.text + repr(audit[0].detail)
    finally:
        await app.state.engine.dispose()
