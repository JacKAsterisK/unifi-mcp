"""Windows launcher checks with disposable synthetic profiles only."""

import base64
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "readonly_launcher.py"
spec = importlib.util.spec_from_file_location("readonly_launcher", SCRIPT)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
SETTINGS = {"host": "127.0.0.1", "port": 443, "site": "default", "tls_sha256": "00" * 32}
CREDENTIALS = {"username": "synthetic-user", "password": "synthetic-password"}


def test_poisoned_parent_environment_cannot_change_controller_or_policy():
    parent = {
        "SystemRoot": r"C:\Windows",
        "UNIFI_NETWORK_HOST": "attacker.invalid",
        "UNIFI_POLICY_NETWORK_VPN_SERVERS_UPDATE": "true",
        "UNIFI_AUTO_CONFIRM": "true",
        "UNIFI_PERMISSIONS_NETWORKS_UPDATE": "true",
        "CONFIG_PATH": "attacker.yaml",
        "PYTHONPATH": "attacker",
        "HTTPS_PROXY": "attacker",
        "PATH": "attacker",
    }
    env = launcher.child_environment(SETTINGS, CREDENTIALS, parent)
    result = subprocess.run(
        [sys.executable, "-c", "import json,os;print(json.dumps(dict(os.environ)))"],
        env=env,
        capture_output=True,
        check=True,
        text=True,
    )
    child = json.loads(result.stdout)
    assert child["UNIFI_NETWORK_HOST"] == "127.0.0.1"
    for name in (
        "UNIFI_POLICY_NETWORK_VPN_SERVERS_UPDATE",
        "UNIFI_AUTO_CONFIRM",
        "UNIFI_PERMISSIONS_NETWORKS_UPDATE",
        "CONFIG_PATH",
        "PYTHONPATH",
        "HTTPS_PROXY",
    ):
        assert name not in child
    assert child["UNIFI_POLICY_UPDATE"] == "false"
    assert child["UNIFI_STRICT_ENABLED_TOOLS"] == "true"
    assert "attacker" not in child["PATH"]


def test_launcher_allowlist_contains_only_registered_read_tools():
    manifest = json.loads((launcher.ROOT / "apps/network/src/unifi_network_mcp/tools_manifest.json").read_text())
    entries = {tool["name"]: tool for tool in manifest["tools"]}
    assert set(launcher.TOOLS).issubset(entries)
    for name in launcher.TOOLS:
        assert entries[name]["annotations"]["readOnlyHint"] is True


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI/NTFS integration")
def test_powershell_setup_roundtrip_acl_and_corrupt_ciphertext(tmp_path):
    root = str(launcher.ROOT).replace("'", "''")
    profile = str(tmp_path / "profile").replace("'", "''")
    # Override interactive prompts only in this test process; never use a real account.
    script = rf"""
    function Read-Host {{ param($Prompt) if ($Prompt -like 'Confirm*') {{ 'VIEW ONLY' }} else {{ '{"00" * 32}' }} }}
    function Get-Credential {{
        param($Message)
        [PSCredential]::new('synthetic-user',(ConvertTo-SecureString 'synthetic-password' -AsPlainText -Force))
    }}
    & '{root}\scripts\windows\configure_readonly.ps1' -ControllerHost '127.0.0.1' -ProfileDirectory '{profile}'
    """
    powershell = Path(os.environ["SYSTEMROOT"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run([str(powershell), "-NoProfile", "-Command", script], capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert CREDENTIALS["password"].encode() not in result.stdout + result.stderr
    directory = tmp_path / "profile"
    encrypted = base64.b64decode((directory / "credential.dpapi").read_bytes(), validate=True)
    assert CREDENTIALS["password"].encode() not in encrypted
    assert json.loads(launcher.unprotect(encrypted)) == CREDENTIALS
    settings = json.loads((directory / "settings.json").read_text())
    assert launcher.child_environment(settings, CREDENTIALS, os.environ)["UNIFI_NETWORK_HOST"] == "127.0.0.1"
    check = [str(powershell), "-NoProfile", "-File", str(SCRIPT.parent / "verify_private_profile.ps1"), str(directory)]
    assert subprocess.run(check, capture_output=True, timeout=15).returncode == 0
    with pytest.raises(ValueError, match="decrypt"):
        launcher.unprotect(b"invalid-dpapi-ciphertext")
    # Grant Everyone access and prove the launcher refuses the altered profile.
    subprocess.run(
        ["icacls.exe", str(directory / "settings.json"), "/grant", "*S-1-1-0:R"], capture_output=True, check=True
    )
    assert subprocess.run(check, capture_output=True, timeout=15).returncode == 1


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI/NTFS integration")
def test_password_file_staging_completion_and_rotation(tmp_path):
    directory = tmp_path / "profile"
    source = tmp_path / "password.txt"
    password = " password with spaces "
    source.write_bytes((password + "\r\n").encode())
    powershell = Path(os.environ["SYSTEMROOT"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    command = [
        str(powershell),
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(SCRIPT.parent / "configure_readonly.ps1"),
        "-ProfileDirectory",
        str(directory),
        "-ViewOnlyConfirmed",
    ]

    def setup(*arguments):
        result = subprocess.run(command + list(arguments), capture_output=True, timeout=30)
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        assert password.encode() not in result.stdout + result.stderr

    def decrypted():
        return json.loads(launcher.unprotect(base64.b64decode((directory / "credential.dpapi").read_bytes())))

    setup("-Username", "synthetic-user", "-PasswordFile", str(source), "-CredentialOnly")
    assert decrypted() == {"username": "synthetic-user", "password": password}
    assert not (directory / "settings.json").exists()
    assert not (directory / "codex-config.toml").exists()
    assert source.read_text() == password + "\n"
    setup("-UseStoredCredential", "-TrustedTlsSha256", "00" * 32)
    assert decrypted()["password"] == password
    assert json.loads((directory / "settings.json").read_text())["tls_sha256"] == "00" * 32
    config = (directory / "codex-config.toml").read_text()
    assert password not in config
    assert "disabled_tools" in config
    # Rotate an existing profile, including repairing stale explicit file ACLs.
    for filename in ("credential.dpapi", "settings.json", "codex-config.toml"):
        subprocess.run(
            ["icacls.exe", str(directory / filename), "/grant", "*S-1-1-0:R"], capture_output=True, check=True
        )
    source.write_text("replacement-password\n", encoding="utf-8")
    setup("-Username", "synthetic-user", "-PasswordFile", str(source), "-TrustedTlsSha256", "11" * 32)
    assert decrypted()["password"] == "replacement-password"
    check = [str(powershell), "-NoProfile", "-File", str(SCRIPT.parent / "verify_private_profile.ps1"), str(directory)]
    assert subprocess.run(check, capture_output=True, timeout=15).returncode == 0
    assert json.loads((directory / "settings.json").read_text())["tls_sha256"] == "11" * 32
