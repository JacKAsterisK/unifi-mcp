"""Real TLS/SDK regressions; all credentials and keys here are synthetic."""

import hashlib
import ssl
from pathlib import Path

import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web
from aiounifi.errors import WebsocketError
from unifi_core.auth import UniFiAuth
from unifi_core.network.managers.connection_manager import (
    ConnectionManager,
    _probe_endpoint,
    detect_unifi_os_pre_login,
)
from unifi_core.network.transport import controller_tls, sdk_tls

FIXTURES = Path(__file__).parents[1] / "fixtures" / "tls"
PIN = hashlib.sha256(ssl.PEM_cert_to_DER_cert((FIXTURES / "cert.pem").read_text())).hexdigest()
WRONG_PIN = "00" * 32


@pytest_asyncio.fixture
async def gateway(monkeypatch):
    monkeypatch.setenv("UNIFI_NETWORK_CONTROLLER_TYPE", "proxy")
    monkeypatch.setenv("UNIFI_CONTROLLER_TYPE", "proxy")
    received = []

    async def handler(request):
        received.append((request.method, request.path, dict(request.headers), await request.read()))
        if request.path.endswith("/events"):
            ws = web.WebSocketResponse()
            await ws.prepare(request)
            await ws.send_str("synthetic-event")
            await ws.close()
            return ws
        if request.path == "/redirect":
            raise web.HTTPTemporaryRedirect(location="https://localhost:1/leak")
        response = web.json_response({"meta": {"rc": "ok"}, "data": []})
        if request.path.endswith("/login"):
            response.set_cookie("TOKEN", "synthetic-cookie")
        return response

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(FIXTURES / "cert.pem", FIXTURES / "key.pem")
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=context)
    await site.start()
    port = runner.addresses[0][1]
    try:
        yield port, received
    finally:
        await runner.cleanup()


@pytest.mark.parametrize("pin", ["short", "g" * 64, " " * 64])
def test_bad_pin_rejected_at_construction(pin):
    with pytest.raises(ValueError, match="SHA-256"):
        ConnectionManager("127.0.0.1", "test", "test", verify_ssl=True, tls_sha256=pin)


def test_pin_cannot_be_combined_with_insecure_mode():
    with pytest.raises(ValueError, match="VERIFY_SSL=true"):
        controller_tls(False, PIN)


@pytest.mark.asyncio
@pytest.mark.parametrize("pin", [WRONG_PIN, ""])
async def test_wrong_pin_or_untrusted_ca_sends_no_login(gateway, pin):
    port, received = gateway
    manager = ConnectionManager(
        "127.0.0.1", "test", "synthetic-password", port=port, verify_ssl=True, tls_sha256=pin, max_retries=1
    )
    try:
        assert not await manager.initialize()
        assert received == []
    finally:
        await manager._discard_connection()


@pytest.mark.asyncio
async def test_valid_pin_covers_login_probes_sdk_websocket_and_reconnect(gateway):
    port, received = gateway
    manager = ConnectionManager(
        "127.0.0.1", "test", "synthetic-password", port=port, verify_ssl=True, tls_sha256=PIN, max_retries=1
    )
    try:
        assert await manager.initialize()
        session = manager._aiohttp_session
        assert await detect_unifi_os_pre_login(session, manager.url_base) is True
        assert await _probe_endpoint(
            session, manager.url_base + "/api/self/sites", aiohttp.ClientTimeout(total=2), "test"
        )
        messages = []
        await manager.controller.connectivity.websocket(messages.append)
        assert messages == ["synthetic-event"]
        previous_count = len(received)
        manager.controller.connectivity.config.ssl_context = sdk_tls(controller_tls(True, WRONG_PIN))
        with pytest.raises(WebsocketError) as mismatch:
            await manager.controller.connectivity.websocket(messages.append)
        assert isinstance(mismatch.value.__cause__, aiohttp.ServerFingerprintMismatch)
        assert len(received) == previous_count
        await manager._discard_connection()
        assert await manager.initialize()
        assert sum(path.endswith("/login") for _, path, _, _ in received) == 2
        assert any(
            "TOKEN=synthetic-cookie" in headers.get("Cookie", "")
            for _, path, headers, _ in received
            if path.endswith("/sites")
        )
    finally:
        await manager._discard_connection()


@pytest.mark.asyncio
async def test_authenticated_redirect_cannot_leave_controller(gateway):
    port, received = gateway
    manager = ConnectionManager(
        "127.0.0.1", "test", "synthetic-password", port=port, verify_ssl=True, tls_sha256=PIN, max_retries=1
    )
    try:
        assert await manager.initialize()
        with pytest.raises(aiohttp.ClientConnectionError, match="unexpected origin"):
            await manager._aiohttp_session.get(manager.url_base + "/redirect")
        assert received[-1][1] == "/redirect"
    finally:
        await manager._discard_connection()


@pytest.mark.asyncio
@pytest.mark.parametrize("pin,expected", [(PIN, True), (WRONG_PIN, False)])
async def test_api_key_negotiation_uses_same_tls_policy(gateway, pin, expected):
    port, received = gateway
    manager = ConnectionManager(
        "127.0.0.1", "", "", port=port, verify_ssl=True, tls_sha256=pin, auth=UniFiAuth(api_key="synthetic-key")
    )
    try:
        assert await manager.initialize() is expected
        if expected:
            assert received[0][2]["X-API-Key"] == "synthetic-key"
            await manager.request_integration("/v1/sites")
        else:
            assert received == []
    finally:
        await manager._discard_connection()


@pytest.mark.asyncio
async def test_probes_cannot_override_verified_connector(gateway):
    port, received = gateway
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=controller_tls(True))) as session:
        assert await detect_unifi_os_pre_login(session, f"https://127.0.0.1:{port}") is None
        assert not await _probe_endpoint(
            session, f"https://127.0.0.1:{port}/api/self/sites", aiohttp.ClientTimeout(total=2), "test"
        )
    assert received == []
