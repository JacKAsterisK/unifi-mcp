"""Additional policy checks for resources shared by multiple tool families."""

from unifi_core.network.managers.vpn_manager import classify_vpn_type
from unifi_core.network.models.vpn import is_vpn_network
from unifi_core.policy_gate import PolicyGateChecker
from unifi_network_mcp.categories import NETWORK_CATEGORY_MAP


def vpn_network_denial(current: dict, effective: dict, action: str) -> str | None:
    """Generic network writes must respect both old and new VPN categories.

    Unknown VPN records require both gates rather than guessing their role.
    The ordinary network gate is enforced by the tool's registration wrapper.
    """
    checker = PolicyGateChecker("NETWORK", NETWORK_CATEGORY_MAP)
    categories = set()
    for record in (current, effective):
        if not is_vpn_network(record):
            continue
        client, server = classify_vpn_type(record.get("purpose"), record.get("vpn_type"))
        if client or not server:
            categories.add("vpn_client")
        if server or not client:
            categories.add("vpn_server")
    for category in sorted(categories):
        if not checker.check(category, action):
            return checker.denial_message(category, action)
    return None
