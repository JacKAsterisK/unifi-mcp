"""Closed inputs and public projections for IPv4 WireGuard provisioning."""

import base64
import ipaddress
import re
from copy import deepcopy
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


class WireGuardError(ValueError):
    """Fixed, safe guidance suitable for callers; never controller exception text."""


class ClosedInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)


class WireGuardServerCreate(ClosedInput):
    name: str = Field(min_length=1, max_length=32)
    ip_subnet: str = Field(description="First usable IPv4 gateway and prefix, for example 10.77.31.1/24")
    local_port: int = Field(ge=1024, le=65535)
    wireguard_interface: Literal["wan", "wan2"] = "wan"

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if value != value.strip() or any(ord(char) < 32 for char in value):
            raise ValueError("Use a nonblank name without surrounding whitespace or control characters")
        return value

    @field_validator("ip_subnet")
    @classmethod
    def validate_subnet(cls, value: str) -> str:
        interface = ipaddress.IPv4Interface(value)
        if "/" not in value or not 16 <= interface.network.prefixlen <= 30:
            raise ValueError("Use an IPv4 subnet with a prefix between /16 and /30")
        private_networks = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        if interface.ip != interface.network.network_address + 1 or not any(
            interface.network.subnet_of(ipaddress.IPv4Network(network)) for network in private_networks
        ):
            raise ValueError("Use the first usable address of a private IPv4 subnet")
        return str(interface)

    def to_controller(self) -> dict[str, Any]:
        network = ipaddress.IPv4Interface(self.ip_subnet).network
        return {
            **self.model_dump(),
            "purpose": "remote-user-vpn",
            "vpn_type": "wireguard-server",
            "enabled": False,
            "ipv6_subnet": "",
            "setting_preference": "manual",
            "dhcpd_start": str(network.network_address + 2),
            "dhcpd_stop": str(network.broadcast_address - 1),
            "dhcpd_dns_enabled": False,
            "dhcpd_wins_enabled": False,
            "wireguard_interface_binding_mode_ip_version": "v4",
            "wireguard_local_wan_ip": "any",
            "vpn_binding_mode": "interface",
            "vpn_client_configuration_remote_ip_override_enabled": False,
        }


class WireGuardPeerCreate(ClosedInput):
    name: str = Field(min_length=1, max_length=32)
    interface_ip: str = Field(description="Peer IPv4 address inside the server subnet; omit /32")
    public_key: str = Field(description="Base64 WireGuard public key generated on the developer's client")

    _name = field_validator("name")(WireGuardServerCreate.validate_name.__func__)

    @field_validator("interface_ip")
    @classmethod
    def validate_address(cls, value: str) -> str:
        return str(ipaddress.IPv4Address(value))

    @field_validator("public_key")
    @classmethod
    def validate_key(cls, value: str) -> str:
        decoded = base64.b64decode(value, validate=True)
        if len(decoded) != 32 or decoded == bytes(32) or base64.b64encode(decoded).decode("ascii") != value:
            raise ValueError("Use a canonical base64-encoded 32-byte public key")
        return value

    def to_controller(self) -> dict[str, Any]:
        # Gateway allowed_ips describes networks BEHIND a peer, not the client's
        # destination AllowedIPs. Remote developers advertise no LAN routes.
        return {**self.model_dump(), "allowed_ips": [], "interface_ipv6": ""}


class ServerCreateInput(ClosedInput):
    server_data: WireGuardServerCreate
    confirm: bool = False


class PeerCreateInput(ClosedInput):
    server_id: str
    peer_data: WireGuardPeerCreate
    confirm: bool = False


def validate_input(model: type[ClosedInput], data: dict) -> ClosedInput:
    try:
        return model.model_validate(data)
    except (ValidationError, ValueError, TypeError):
        raise WireGuardError(f"Invalid {model.__name__} input; check the closed tool schema") from None


def validate_id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise WireGuardError("Invalid WireGuard identifier; use the legacy networkconf/peer _id")
    return value


def input_schema(model: type[ClosedInput]) -> dict:
    schema = deepcopy(model.model_json_schema())
    definitions = schema.pop("$defs", {})

    def resolve(node: Any) -> Any:
        if isinstance(node, dict):
            if "$ref" in node:
                node = {**definitions[node["$ref"].split("/")[-1]], **{k: v for k, v in node.items() if k != "$ref"}}
            return {key: resolve(value) for key, value in node.items()}
        if isinstance(node, list):
            return [resolve(value) for value in node]
        return node

    return resolve(schema)


def server_public_key(record: dict) -> str | None:
    """Project a public key from persisted controller material, never a secret.

    Network 10.6.106 stores only x_wireguard_private_key. Derive its public
    counterpart before response redaction. A malformed or inconsistent record
    has no verifiable public key; never fall back to an expected create value.
    """
    stored_public = record.get("wireguard_public_key")
    private = record.get("x_wireguard_private_key")
    try:
        if private is not None:
            decoded = base64.b64decode(private, validate=True)
            if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != private:
                return None
            derived = base64.b64encode(
                X25519PrivateKey.from_private_bytes(decoded).public_key().public_bytes_raw()
            ).decode("ascii")
            return derived if stored_public is None or stored_public == derived else None
        decoded = base64.b64decode(stored_public, validate=True)
        if len(decoded) == 32 and decoded != bytes(32) and base64.b64encode(decoded).decode("ascii") == stored_public:
            return stored_public
    except (ValueError, TypeError):
        pass
    return None


def server_view(record: dict) -> dict:
    keys = ("_id", "name", "ip_subnet", "local_port", "wireguard_interface", "firewall_zone_id")
    view = {**{key: record[key] for key in keys if key in record}, "enabled": record.get("enabled", True)}
    public = server_public_key(record)
    if public is not None:
        view["wireguard_public_key"] = public
    return view


def peer_view(record: dict) -> dict:
    keys = ("_id", "network_id", "name", "interface_ip", "public_key", "allowed_ips")
    return {key: record[key] for key in keys if key in record}
