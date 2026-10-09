"""Separate, expiring, direct-tool-only Network provisioning profile."""

import argparse
import base64
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from readonly_launcher import ROOT, unprotect, windows_environment
from readonly_launcher import TOOLS as READ_TOOLS
from readonly_launcher import child_environment as readonly_environment

TOOLS = READ_TOOLS + (
    "unifi_list_wireguard_peers",
    "unifi_create_wireguard_server",
    "unifi_create_wireguard_peer",
    "unifi_delete_wireguard_peer",
    "unifi_delete_wireguard_server",
    "unifi_update_wireguard_server_state",
    "unifi_update_vpn_server_alternate_address",
    "unifi_create_network",
    "unifi_update_network",
    "unifi_delete_network",
    "unifi_create_firewall_zone",
    "unifi_update_firewall_zone",
    "unifi_delete_firewall_zone",
    "unifi_create_firewall_policy",
    "unifi_update_firewall_policy",
    "unifi_delete_firewall_policy",
    "unifi_get_firewall_policy_details",
    "unifi_get_firewall_policy_ordering",
    "unifi_reorder_firewall_policies",
    "unifi_get_v2_firewall_policy_ordering",
    "unifi_reorder_v2_firewall_policies",
    "unifi_set_client_ip_settings",
    "unifi_list_port_profiles",
    "unifi_get_port_profile_details",
    "unifi_create_port_profile",
    "unifi_delete_port_profile",
    "unifi_get_switch_ports",
    "unifi_get_port_stats",
    "unifi_set_switch_port_profile",
)
ALLOWED_ACTIONS = {
    "VPN_SERVERS": ("CREATE", "UPDATE", "DELETE"),
    "NETWORKS": ("CREATE", "UPDATE", "DELETE"),
    "FIREWALL_POLICIES": ("CREATE", "UPDATE", "DELETE"),
    "CLIENTS": ("UPDATE",),
    "SWITCH": ("CREATE", "UPDATE", "DELETE"),
}


def remaining_seconds(settings: dict) -> float:
    if settings.get("profile_kind") != "provision":
        raise ValueError("Use the separate provisioning profile, never the read-only profile.")
    try:
        deadline = datetime.fromisoformat(settings["expires_at"])
        if deadline.tzinfo is None:
            raise ValueError("Missing timezone")
        remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
    except (KeyError, ValueError, TypeError):
        raise ValueError("Provisioning profile requires a valid expiry time.") from None
    if not 0 < remaining <= 8 * 3600:
        raise ValueError("Provisioning profile is expired or exceeds the eight-hour lifetime.")
    return remaining


def child_environment(settings: dict, credentials: dict, parent: dict) -> dict[str, str]:
    remaining_seconds(settings)
    env = readonly_environment(settings, credentials, parent)
    env["UNIFI_ENABLED_TOOLS"] = ",".join(TOOLS)
    for category, actions in ALLOWED_ACTIONS.items():
        for action in actions:
            env[f"UNIFI_POLICY_NETWORK_{category}_{action}"] = "true"
    key = credentials.get("api_key")
    if key is not None:
        if not isinstance(key, str) or not key or any(char.isspace() for char in key):
            raise ValueError("Invalid optional Network Integration API key.")
        env["UNIFI_NETWORK_API_KEY"] = key
    return env


def config_template(profile: Path) -> str:
    quote = json.dumps
    return (
        "[mcp_servers.unifi_local_provision]\n"
        f"command = {quote(str(ROOT / '.venv/Scripts/python.exe'))}\n"
        f'args = [{quote(str(Path(__file__).resolve()))}, "--profile", {quote(str(profile))}]\n'
        f"cwd = {quote(str(ROOT))}\n"
        "enabled = false\n"
        f"enabled_tools = {quote(list(TOOLS))}\n"
        'disabled_tools = ["unifi_execute", "unifi_batch", "unifi_load_tools"]\n'
        "startup_timeout_sec = 60\n"
        "tool_timeout_sec = 60\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--print-config", action="store_true")
    args = parser.parse_args()
    profile = args.profile.resolve()
    if args.print_config:
        print(config_template(profile))
        return 0
    try:
        windows = os.environ.get("SYSTEMROOT", r"C:\Windows")
        powershell = Path(windows) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        checked = subprocess.run(
            [
                str(powershell),
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(ROOT / "scripts/windows/verify_private_profile.ps1"),
                str(profile),
            ],
            capture_output=True,
            timeout=15,
            env=windows_environment(os.environ),
        )
        if checked.returncode:
            raise ValueError("Unsafe or missing profile")
        settings = json.loads((profile / "settings.json").read_text(encoding="utf-8-sig"))
        remaining_seconds(settings)
        encrypted = base64.b64decode((profile / "credential.dpapi").read_bytes(), validate=True)
        credentials = json.loads(unprotect(encrypted))
        env = child_environment(settings, credentials, os.environ)
        with subprocess.Popen(
            [str(ROOT / ".venv/Scripts/python.exe"), "-B", "-c", "from unifi_network_mcp.main import main; main()"],
            cwd=ROOT,
            env=env,
        ) as process:
            try:
                return process.wait(timeout=remaining_seconds(settings))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                print(
                    "Provisioning profile expired; MCP process stopped. Inspect inventory if a write was in progress.",
                    file=sys.stderr,
                )
                return 1
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print(
            "UniFi provisioning launcher failed. Check the private profile, expiry, Windows user and setup.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
