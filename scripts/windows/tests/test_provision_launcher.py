"""Disposable writer profile checks; no gateway connections or real secrets."""

import base64
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

SCRIPTS = Path(__file__).parents[1]
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("provision_launcher", SCRIPTS / "provision_launcher.py")
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
sys.path.remove(str(SCRIPTS))

SETTINGS = {"profile_kind": "provision", "host": "127.0.0.1", "port": 443, "site": "default", "tls_sha256": "00" * 32}
CREDENTIALS = {"username": "synthetic-writer", "password": "synthetic-password", "api_key": "synthetic-api-key"}


def settings():
    return {**SETTINGS, "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()}


def test_writer_uses_pin_confirm_direct_allowlist_and_only_scoped_policy_exceptions():
    parent = {
        "SYSTEMROOT": r"C:\Windows",
        "UNIFI_NETWORK_TOOL_PERMISSION_MODE": "bypass",
        "UNIFI_POLICY_NETWORK_SYSTEM_UPDATE": "true",
        "HTTPS_PROXY": "attacker",
        "PYTHONPATH": "attacker",
    }
    env = launcher.child_environment(settings(), CREDENTIALS, parent)
    assert env["UNIFI_NETWORK_TOOL_PERMISSION_MODE"] == "confirm"
    assert env["UNIFI_NETWORK_VERIFY_SSL"] == "true"
    assert env["UNIFI_NETWORK_TLS_SHA256"] == "00" * 32
    assert env["UNIFI_POLICY_UPDATE"] == "false"
    assert env["UNIFI_POLICY_NETWORK_VPN_SERVERS_CREATE"] == "true"
    assert "UNIFI_POLICY_NETWORK_SYSTEM_UPDATE" not in env
    assert "HTTPS_PROXY" not in env and "PYTHONPATH" not in env
    assert env["UNIFI_NETWORK_API_KEY"] == CREDENTIALS["api_key"]
    assert env["UNIFI_STRICT_ENABLED_TOOLS"] == "true"
    assert "unifi_execute" not in env["UNIFI_ENABLED_TOOLS"]
    assert "enabled = false" in launcher.config_template(Path("private-profile"))
    assert CREDENTIALS["password"] not in launcher.config_template(Path("private-profile"))


def test_readonly_environment_remains_hard_denied_and_ignores_writer_api_key():
    env = launcher.readonly_environment(settings(), CREDENTIALS, os.environ)
    assert env["UNIFI_POLICY_CREATE"] == "false"
    assert not any(name.startswith("UNIFI_POLICY_NETWORK_") for name in env)
    assert "UNIFI_NETWORK_API_KEY" not in env
    assert "unifi_create_wireguard_server" not in env["UNIFI_ENABLED_TOOLS"]


def test_every_allowed_write_has_matching_scoped_policy_and_registered_schema():
    from unifi_core.policy_gate import PolicyGateChecker
    from unifi_network_mcp.categories import NETWORK_CATEGORY_MAP

    manifest = json.loads((launcher.ROOT / "apps/network/src/unifi_network_mcp/tools_manifest.json").read_text())
    entries = {tool["name"]: tool for tool in manifest["tools"]}
    assert len(launcher.TOOLS) == len(set(launcher.TOOLS))
    env = launcher.child_environment(settings(), CREDENTIALS, {})
    with patch.dict(os.environ, env, clear=True):
        checker = PolicyGateChecker("network", NETWORK_CATEGORY_MAP)
        for name in launcher.TOOLS:
            tool = entries[name]
            if not tool["annotations"]["readOnlyHint"]:
                assert checker.check(tool["permission_category"], tool["permission_action"])
        assert checker.check("system", "update") is False
        assert checker.check("switch", "delete") is False


@pytest.mark.parametrize(
    "update",
    [
        {"profile_kind": "readonly"},
        {"expires_at": "invalid"},
        {"expires_at": "2020-01-01T00:00:00+00:00"},
        {"expires_at": "2100-01-01T00:00:00+00:00"},
        {"expires_at": "2100-01-01T00:00:00"},
    ],
)
def test_expired_invalid_or_readonly_profiles_fail_closed(update):
    with pytest.raises(ValueError):
        launcher.child_environment({**settings(), **update}, CREDENTIALS, {})


def test_optional_api_key_does_not_inherit_from_parent():
    env = launcher.child_environment(
        settings(), {"username": "writer", "password": "pw"}, {"UNIFI_NETWORK_API_KEY": "attacker"}
    )
    assert "UNIFI_NETWORK_API_KEY" not in env


def test_expiry_stops_child_without_exposing_credentials(tmp_path, capsys):
    (tmp_path / "settings.json").write_text(json.dumps(settings()))
    (tmp_path / "credential.dpapi").write_bytes(base64.b64encode(b"synthetic-encrypted"))
    process = MagicMock()
    process.wait.side_effect = [subprocess.TimeoutExpired("mcp", 1), 0]
    context = MagicMock()
    context.__enter__.return_value = process
    with (
        patch.object(sys, "argv", ["launcher", "--profile", str(tmp_path)]),
        patch.object(launcher.subprocess, "run", return_value=MagicMock(returncode=0)),
        patch.object(launcher, "unprotect", return_value=json.dumps(CREDENTIALS).encode()),
        patch.object(launcher.subprocess, "Popen", return_value=context),
    ):
        assert launcher.main() == 1
    process.kill.assert_called_once()
    assert "expired" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI and NTFS")
def test_powershell_writer_setup_dpapi_acl_and_readonly_collision(tmp_path):
    profile = tmp_path / "profile"
    root = str(launcher.ROOT).replace("'", "''")
    quoted_profile = str(profile).replace("'", "''")
    command = rf"""
    function Get-Credential {{
        param($Message)
        [PSCredential]::new('synthetic-writer',(ConvertTo-SecureString 'synthetic-password' -AsPlainText -Force))
    }}
    function Read-Host {{
        param($Prompt,[switch]$AsSecureString)
        ConvertTo-SecureString 'synthetic-api-key' -AsPlainText -Force
    }}
    & '{root}\scripts\windows\configure_provision.ps1' -ControllerHost '127.0.0.1' `
        -TrustedTlsSha256 '{"00" * 32}' -ProfileDirectory '{quoted_profile}' -IncludeApiKey
    """
    powershell = Path(os.environ["SYSTEMROOT"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run([str(powershell), "-NoProfile", "-Command", command], capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert all(value.encode() not in result.stdout + result.stderr for value in CREDENTIALS.values())
    encrypted = base64.b64decode((profile / "credential.dpapi").read_bytes(), validate=True)
    assert json.loads(launcher.unprotect(encrypted)) == CREDENTIALS
    stored = json.loads((profile / "settings.json").read_text())
    assert stored["profile_kind"] == "provision"
    assert launcher.remaining_seconds(stored) > 0
    checked = subprocess.run(
        [str(powershell), "-NoProfile", "-File", str(SCRIPTS / "verify_private_profile.ps1"), str(profile)],
        capture_output=True,
        timeout=15,
    )
    assert checked.returncode == 0
    assert "enabled = false" in (profile / "codex-config.toml").read_text()
    (profile / "settings.json").write_text(json.dumps({"profile_kind": "readonly"}))
    rejected = subprocess.run([str(powershell), "-NoProfile", "-Command", command], capture_output=True, timeout=30)
    assert b"Refusing to overwrite" in rejected.stderr
    assert json.loads(launcher.unprotect(encrypted)) == CREDENTIALS
