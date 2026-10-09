"""Fresh, verified WireGuard operations used by the existing VPN singleton.

Legacy server records and V2 peer batches share networkconf ObjectIDs. Writes
use the session route once; uncertain outcomes never trigger another write.
"""

import base64
import ipaddress
import logging
from copy import deepcopy
from dataclasses import replace
from typing import Awaitable, Callable

from aiounifi.errors import Forbidden, NoPermission, TwoFaTokenRequired, Unauthorized
from aiounifi.models.api import ApiRequest, ApiRequestV2
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from unifi_core.network.managers.connection_manager import controller_error_code, response_status
from unifi_core.network.models.wireguard import (
    WireGuardError,
    WireGuardPeerCreate,
    WireGuardServerCreate,
    peer_view,
    server_view,
    validate_id,
    validate_input,
)
from unifi_core.write_verification import WriteVerificationResult, failed_write, noop_write, verify_write

logger = logging.getLogger("unifi-network-mcp")


class WireGuardOperations:
    """Mixin using VpnManager's connection, mutation lock and cache invalidator."""

    async def _wg_session(self) -> None:
        try:
            ready = await self._connection.ensure_session_connected()
        except Exception as exc:
            logger.error("WireGuard session preparation failed: %s", type(exc).__name__)
            ready = False
        if not ready:
            raise WireGuardError("WireGuard provisioning requires local Network session authentication")

    async def _wg_records(self, request: ApiRequest) -> list[dict]:
        try:
            response = await self._connection.request(request)
            records = response.get("data") if isinstance(response, dict) else response
            if not isinstance(records, list) or not all(isinstance(record, dict) for record in records):
                raise ValueError("Malformed collection")
            return records
        except Exception as exc:
            logger.error("WireGuard inventory read failed: %s", type(exc).__name__)
            raise WireGuardError(
                "Failed to read fresh WireGuard inventory; check controller support and permissions"
            ) from None

    async def _wg_networks(self) -> list[dict]:
        return await self._wg_records(ApiRequest(method="get", path="/rest/networkconf"))

    async def _wg_server(self, server_id: str) -> dict:
        validate_id(server_id)
        matches = [record for record in await self._wg_networks() if record.get("_id") == server_id]
        if (
            len(matches) != 1
            or matches[0].get("vpn_type") != "wireguard-server"
            or matches[0].get("purpose") not in (None, "remote-user-vpn", "vpn-server")
        ):
            raise WireGuardError("WireGuard server not found; use its legacy networkconf _id, not a public API UUID")
        return matches[0]

    async def _wg_peers(self, server_id: str) -> list[dict]:
        validate_id(server_id)
        records = await self._wg_records(ApiRequestV2(method="get", path=f"/wireguard/{server_id}/users"))
        if any(record.get("network_id") != server_id or not record.get("_id") for record in records):
            raise WireGuardError("WireGuard peer collection has missing or mismatched identifiers")
        return records

    async def list_wireguard_peers(self, server_id: str) -> list[dict]:
        await self._wg_session()
        await self._wg_server(server_id)
        return [peer_view(record) for record in await self._wg_peers(server_id)]

    async def prepare_wireguard_server(self, server_data: dict) -> dict:
        model = validate_input(WireGuardServerCreate, server_data)
        await self._wg_session()
        networks = await self._wg_networks()
        subnet = ipaddress.IPv4Interface(model.ip_subnet).network
        if not any(
            record.get("purpose") == "wan" and record.get("wan_networkgroup", "").lower() == model.wireguard_interface
            for record in networks
        ):
            raise WireGuardError("Selected WAN interface was not found in the current site")
        for record in networks:
            if record.get("name") == model.name:
                raise WireGuardError("A network or VPN with this name already exists")
            if str(record.get("local_port", "")) == str(model.local_port):
                raise WireGuardError("The requested VPN listen port is already configured")
            if record.get("ip_subnet"):
                try:
                    existing = ipaddress.ip_network(record["ip_subnet"], strict=False)
                except ValueError:
                    raise WireGuardError(
                        "Cannot verify subnet conflicts because an existing subnet is malformed"
                    ) from None
                if existing.version == 4 and subnet.overlaps(existing):
                    raise WireGuardError("The requested tunnel subnet overlaps an existing network or VPN")
        zones = await self._wg_records(ApiRequestV2(method="get", path="/firewall/zone"))
        vpn_zones = [
            zone for zone in zones if zone.get("default_zone") is True and str(zone.get("name", "")).casefold() == "vpn"
        ]
        if len(vpn_zones) != 1 or not vpn_zones[0].get("_id"):
            raise WireGuardError("A unique built-in Vpn firewall zone is required; custom VPN zones are unsupported")
        return {**model.to_controller(), "firewall_zone_id": vpn_zones[0]["_id"]}

    async def _wg_write_once(
        self, request: ApiRequest, operation: str, readback: Callable[[], Awaitable[WriteVerificationResult]]
    ) -> WriteVerificationResult:
        try:
            await self._connection.request(request)
        except Exception as exc:
            logger.error("WireGuard mutation failed: %s", type(exc).__name__)
            if (
                isinstance(exc, (Forbidden, NoPermission, TwoFaTokenRequired, Unauthorized))
                or controller_error_code(exc) is not None
                or response_status(exc) in {400, 401, 403, 404, 405, 409, 422, 429}
            ):
                return failed_write(
                    "Controller rejected the WireGuard change; check permissions and inputs", operation=operation
                )
            return failed_write(
                "WireGuard write outcome uncertain; inspect fresh inventory before any further mutation",
                operation=operation,
                mutation_applied=None,
            )
        finally:
            self._invalidate_vpn_caches()
        try:
            return await readback()
        except Exception as exc:
            logger.error("WireGuard write readback failed: %s", type(exc).__name__)
            return failed_write(
                "WireGuard write outcome uncertain; readback failed. Inspect inventory before any further mutation",
                operation=operation,
                mutation_applied=None,
            )

    async def create_wireguard_server(self, server_data: dict) -> WriteVerificationResult:
        async with self._wireguard_lock:
            payload = await self.prepare_wireguard_server(server_data)
            # Never accept or return private keys. Only confirmed creation generates
            # a server secret; the developer generates their own key on the client.
            key = X25519PrivateKey.generate()
            public_key = base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii")
            request_data = {
                **payload,
                "x_wireguard_private_key": base64.b64encode(key.private_bytes_raw()).decode("ascii"),
            }

            async def readback() -> WriteVerificationResult:
                matches = [record for record in await self._wg_networks() if record.get("name") == payload["name"]]
                if len(matches) != 1 or not matches[0].get("_id"):
                    raise WireGuardError("Created server cannot be uniquely identified")
                after = matches[0]
                public_view = server_view(after)
                verification_state = {key: value for key, value in after.items() if key != "wireguard_public_key"}
                if "wireguard_public_key" in public_view:
                    verification_state["wireguard_public_key"] = public_view["wireguard_public_key"]
                requested = {**payload, "wireguard_public_key": public_key}
                if after.get("ipv6_subnet"):
                    return failed_write(
                        "Controller enabled an unexpected IPv6 subnet; inspect the staged server",
                        operation="create",
                        mutation_applied=True,
                        resource=server_view(after),
                    )
                return replace(
                    verify_write(
                        operation="create",
                        requested=requested,
                        after=verification_state,
                        absent_value_defaults={"ipv6_subnet": ""},
                    ),
                    resource=public_view,
                )

            return await self._wg_write_once(
                ApiRequest(method="post", path="/rest/networkconf", data=request_data), "create", readback
            )

    async def prepare_wireguard_peer(self, server_id: str, peer_data: dict) -> dict:
        model = validate_input(WireGuardPeerCreate, peer_data)
        await self._wg_session()
        server = await self._wg_server(server_id)
        try:
            interface = ipaddress.IPv4Interface(server["ip_subnet"])
        except (ValueError, KeyError, TypeError):
            raise WireGuardError("WireGuard server has no valid IPv4 subnet") from None
        address = ipaddress.IPv4Address(model.interface_ip)
        if address not in interface.network or address in (
            interface.ip,
            interface.network.network_address,
            interface.network.broadcast_address,
        ):
            raise WireGuardError("Peer address must be usable inside the server subnet and distinct from the gateway")
        for peer in await self._wg_peers(server_id):
            if any(peer.get(field) == getattr(model, field) for field in ("name", "interface_ip", "public_key")):
                raise WireGuardError("A peer with this name, address, or public key already exists on the server")
        return {**model.to_controller(), "network_id": server_id}

    async def create_wireguard_peer(self, server_id: str, peer_data: dict) -> WriteVerificationResult:
        async with self._wireguard_lock:
            payload = await self.prepare_wireguard_peer(server_id, peer_data)

            async def readback() -> WriteVerificationResult:
                matches = [
                    peer for peer in await self._wg_peers(server_id) if peer.get("public_key") == payload["public_key"]
                ]
                if len(matches) != 1:
                    raise WireGuardError("Created peer cannot be uniquely identified")
                after = matches[0]
                if after.get("interface_ipv6"):
                    return failed_write(
                        "Controller enabled an unexpected peer IPv6 address; inspect the peer",
                        operation="create",
                        mutation_applied=True,
                        resource=peer_view(after),
                    )
                return replace(
                    verify_write(
                        operation="create", requested=payload, after=after, absent_value_defaults={"interface_ipv6": ""}
                    ),
                    resource=peer_view(after),
                )

            # Network 10.6.106's UI posts a JSON array, even for one peer.
            return await self._wg_write_once(
                ApiRequestV2(
                    method="post",
                    path=f"/wireguard/{server_id}/users/batch",
                    data=[{key: value for key, value in payload.items() if key != "network_id"}],
                ),
                "create",
                readback,
            )

    async def prepare_wireguard_peer_delete(self, server_id: str, peer_id: str) -> dict | None:
        validate_id(peer_id)
        await self._wg_session()
        await self._wg_server(server_id)
        matches = [peer for peer in await self._wg_peers(server_id) if peer.get("_id") == peer_id]
        if len(matches) > 1:
            raise WireGuardError("Peer identifier is ambiguous")
        return peer_view(matches[0]) if matches else None

    async def delete_wireguard_peer(self, server_id: str, peer_id: str) -> WriteVerificationResult:
        async with self._wireguard_lock:
            before = await self.prepare_wireguard_peer_delete(server_id, peer_id)
            if before is None:
                return noop_write(operation="delete")

            async def readback() -> WriteVerificationResult:
                if any(peer.get("_id") == peer_id for peer in await self._wg_peers(server_id)):
                    return failed_write(
                        "Controller accepted revocation but the peer still exists",
                        operation="delete",
                        mutation_applied=None,
                    )
                return WriteVerificationResult(success=True, mutation_applied=True, operation="delete", resource=before)

            return await self._wg_write_once(
                ApiRequestV2(method="post", path=f"/wireguard/{server_id}/users/batch_delete", data=[peer_id]),
                "delete",
                readback,
            )

    async def prepare_wireguard_server_delete(self, server_id: str) -> dict:
        await self._wg_session()
        server = await self._wg_server(server_id)
        if await self._wg_peers(server_id):
            raise WireGuardError("Revoke all peers before deleting the WireGuard server")
        return server_view(server)

    async def delete_wireguard_server(self, server_id: str) -> WriteVerificationResult:
        async with self._wireguard_lock:
            before = await self.prepare_wireguard_server_delete(server_id)

            async def readback() -> WriteVerificationResult:
                if any(record.get("_id") == server_id for record in await self._wg_networks()):
                    return failed_write(
                        "Controller accepted deletion but the server still exists",
                        operation="delete",
                        mutation_applied=None,
                    )
                return WriteVerificationResult(success=True, mutation_applied=True, operation="delete", resource=before)

            return await self._wg_write_once(
                ApiRequest(method="delete", path=f"/rest/networkconf/{server_id}"), "delete", readback
            )

    async def prepare_wireguard_server_state(self, server_id: str, enabled: bool) -> tuple[dict, dict]:
        if type(enabled) is not bool:
            raise WireGuardError("WireGuard enabled must be a boolean")
        await self._wg_session()
        before = await self._wg_server(server_id)
        if enabled and before.get("ipv6_subnet"):
            raise WireGuardError("IPv4 provisioning cannot enable an IPv6-configured server; review IPv6 separately")
        return before, {**deepcopy(before), "enabled": enabled}

    async def update_wireguard_server_state(self, server_id: str, enabled: bool) -> WriteVerificationResult:
        async with self._wireguard_lock:
            before, merged = await self.prepare_wireguard_server_state(server_id, enabled)
            if before.get("enabled", True) is enabled:
                return noop_write(resource=server_view(before))

            async def readback() -> WriteVerificationResult:
                after = await self._wg_server(server_id)
                return replace(
                    verify_write(
                        operation="update",
                        requested={"enabled": enabled},
                        before=before,
                        after=after,
                        absent_value_defaults={"enabled": True},
                    ),
                    resource=server_view(after),
                )

            return await self._wg_write_once(
                ApiRequest(method="put", path=f"/rest/networkconf/{server_id}", data=merged), "update", readback
            )
