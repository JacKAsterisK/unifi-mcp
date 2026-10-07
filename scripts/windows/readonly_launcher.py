"""Launch the local read-only Network MCP with DPAPI credentials and a clean env."""

import argparse
import base64
import ctypes
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS = (
    "unifi_list_networks",
    "unifi_get_network_details",
    "unifi_list_devices",
    "unifi_get_device_details",
    "unifi_list_clients",
    "unifi_get_client_details",
    "unifi_get_system_info",
    "unifi_list_vpn_servers",
    "unifi_list_vpn_clients",
    "unifi_list_firewall_zones",
    "unifi_list_firewall_policies",
    "unifi_list_legacy_firewall_rules",
    "unifi_get_gateway_settings",
)
WINDOWS_ENV = (
    "SYSTEMROOT",
    "WINDIR",
    "SYSTEMDRIVE",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROCESSOR_ARCHITECTURE",
)


class Blob(ctypes.Structure):
    _fields_ = [("size", ctypes.c_ulong), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def unprotect(ciphertext: bytes) -> bytes:
    """Windows DPAPI CurrentUser; the original user and machine must decrypt."""
    if sys.platform != "win32":
        raise ValueError("This credential profile requires Windows.")
    buffer = ctypes.create_string_buffer(ciphertext)
    source = Blob(len(ciphertext), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    result = Blob()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt.CryptUnprotectData.argtypes = [
        ctypes.POINTER(Blob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(Blob),
    ]
    crypt.CryptUnprotectData.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    if not crypt.CryptUnprotectData(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(result)):
        raise ValueError("Could not decrypt the credential profile for this Windows user.")
    try:
        return ctypes.string_at(result.data, result.size)
    finally:
        ctypes.memset(result.data, 0, result.size)
        kernel.LocalFree(result.data)


def windows_environment(parent: dict) -> dict[str, str]:
    """Only inbox Windows runtime paths are inherited by child processes."""
    inherited = {key.upper(): value for key, value in parent.items()}
    env = {key: inherited[key] for key in WINDOWS_ENV if key in inherited}
    system_root = env.get("SYSTEMROOT", r"C:\Windows")
    env["PATH"] = str(Path(system_root) / "System32") + os.pathsep + system_root
    return env


def child_environment(settings: dict, credentials: dict, parent: dict) -> dict[str, str]:
    """Allowlist inherited runtime variables; never inherit configuration/policy."""
    host = settings.get("host", "")
    if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", host):
        raise ValueError("Invalid controller host.")
    port = settings.get("port", 443)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid controller port.")
    pin = settings.get("tls_sha256", "").replace(":", "")
    if not re.fullmatch(r"[A-Fa-f0-9]{64}", pin):
        raise ValueError("An independently verified SHA-256 certificate pin is required.")
    site = settings.get("site", "default")
    if not isinstance(site, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", site):
        raise ValueError("Invalid controller site.")
    if any(not isinstance(credentials.get(key), str) or not credentials[key] for key in ("username", "password")):
        raise ValueError("The credential profile is incomplete.")
    env = windows_environment(parent)
    env.update(
        {
            "UNIFI_NETWORK_HOST": host,
            "UNIFI_NETWORK_PORT": str(port),
            "UNIFI_NETWORK_SITE": site,
            "UNIFI_NETWORK_USERNAME": credentials["username"],
            "UNIFI_NETWORK_PASSWORD": credentials["password"],
            "UNIFI_NETWORK_VERIFY_SSL": "true",
            "UNIFI_NETWORK_TLS_SHA256": pin,
            "UNIFI_NETWORK_CONTROLLER_TYPE": "proxy",
            "UNIFI_NETWORK_TOOL_PERMISSION_MODE": "confirm",
            "UNIFI_POLICY_CREATE": "false",
            "UNIFI_POLICY_UPDATE": "false",
            "UNIFI_POLICY_DELETE": "false",
            "UNIFI_TOOL_REGISTRATION_MODE": "eager",
            "UNIFI_STRICT_ENABLED_TOOLS": "true",
            "UNIFI_ENABLED_TOOLS": ",".join(TOOLS),
            "UNIFI_MCP_HTTP_ENABLED": "false",
            "UNIFI_NETWORK_WEBSOCKET_ENABLED": "false",
            "UNIFI_MCP_DIAGNOSTICS": "false",
            "UNIFI_NETWORK_REDACT_SENSITIVE_FIELDS": "true",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    return env


def config_template(profile: Path) -> str:
    # JSON string escaping is also valid for these TOML basic strings.
    quote = json.dumps
    python = ROOT / ".venv" / "Scripts" / "python.exe"
    return (
        "[mcp_servers.unifi_local_readonly]\n"
        f"command = {quote(str(python))}\n"
        f'args = [{quote(str(Path(__file__).resolve()))}, "--profile", {quote(str(profile))}]\n'
        f"cwd = {quote(str(ROOT))}\n"
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
        # Validate permissions before reading settings or encrypted credentials.
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
            raise ValueError("Credential profile permissions are unsafe or the profile is missing.")
        settings = json.loads((profile / "settings.json").read_text(encoding="utf-8-sig"))
        encrypted = base64.b64decode((profile / "credential.dpapi").read_bytes(), validate=True)
        credentials = json.loads(unprotect(encrypted))
        env = child_environment(settings, credentials, os.environ)
        python = ROOT / ".venv/Scripts/python.exe"
        # Inherit binary stdio directly so stdout remains MCP JSON-RPC.
        return subprocess.call(
            [str(python), "-B", "-c", "from unifi_network_mcp.main import main; main()"], cwd=ROOT, env=env
        )
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print(
            "Read-only UniFi launcher failed. Check the private profile, Windows user, and local setup.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
