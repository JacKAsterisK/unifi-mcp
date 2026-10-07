# Local read-only UniFi Network MCP on Windows

Use a dedicated local account with **Network → View Only** permissions and no
permissions for other applications. Do not use the owner's account. UniFi calls
accounts that access its management interface “Admins”; a Basic account is for
services such as WiFi or VPN. In the local console, open People/Admins, select
Admin, restrict it to local access where offered, and choose application permissions.
Verify its effective Network role before storing its credentials.

## Install and configure

From a trusted checkout, install the locked runtime:

```powershell
uv sync --locked --package unifi-network-mcp
.\setup-readonly.bat
```

Setup prompts for the dedicated account and the gateway certificate's SHA-256
fingerprint. Confirm that fingerprint using trusted owner access to the gateway
certificate details. A fingerprint observed over an unverified network connection
alone is not proof of identity. Do not paste passwords into chat or config.toml.

Setup stores a DPAPI CurrentUser encrypted credential and settings under
`%LOCALAPPDATA%\UniFiMCP\readonly`. NTFS permissions allow only the current user and
SYSTEM. This profile requires the same Windows user on the same machine; it is
not a portable credential backup. Setup can rotate an existing profile.

For a password already placed in a local file, setup also accepts `-Username`
and `-PasswordFile`; the password is read in-process rather than placed on the
command line. `-CredentialOnly` stages an encrypted credential without settings
or an authenticated connection. Finish that staged profile with
`-UseStoredCredential -TrustedTlsSha256 <confirmed fingerprint>`.
`-ViewOnlyConfirmed` records the operator's prior verification of the account
role; it does not inspect or change controller permissions. Setup preserves the
plaintext source file. Remove it after verifying the encrypted profile if it is
no longer needed.

Add the entry from that directory's `codex-config.toml` to your user Codex MCP
configuration, then reload/restart the MCP connection. Keep the checkout and
profile writable only by the owner account, away from the developer's file share.
The generated configuration contains executable paths and a tool allowlist, with
no password or API key. Do not run the launcher under the developer's account.

The launcher:

- inherits only selected Windows runtime variables;
- sets the local endpoint, verified certificate pin, eager strict registration,
  and an explicit direct read-tool list;
- denies create/update/delete globally, uses confirmation mode, and discards
  inherited per-category overrides, legacy auto-confirm settings, CONFIG_PATH,
  PYTHONPATH, proxy settings, and credential providers;
- uses stdio only, disables the event listener and diagnostics, and keeps
  response redaction enabled;
- validates profile ownership/permissions before decrypting and passes binary
  stdio directly to the installed Python server.

The controller's View Only role is the independent write boundary. Global policy
denials by themselves can be overridden by more specific environment variables;
the clean launcher prevents inheriting those overrides. An account with admin
rights remains an admin account even when this launcher is used.

## Certificate policy and rotation

Network accepts `UNIFI_NETWORK_TLS_SHA256` (or shared `UNIFI_TLS_SHA256`) with
`UNIFI_NETWORK_VERIFY_SSL=true`. A SHA-256 pin identifies the DER certificate and
replaces CA/hostname validation. Without a pin, verification uses normal CA and
hostname checks. Existing insecure mode remains available for compatibility, but
the read-only launcher never selects it. Invalid pins and a pin combined with
`VERIFY_SSL=false` are rejected when the connection manager is constructed.

Detection, login, HTTP reads, SDK requests, reconnects, and websocket TLS use the
same policy. Detection does not follow redirects, and authenticated HTTP redirect
hops cannot leave the configured HTTPS origin. The aiounifi annotation adapter
is a type-only cast: the installed SDK forwards aiohttp Fingerprint unchanged to
HTTP and websocket calls, covered by real local TLS regression tests.

If a firmware update, reset, or certificate replacement breaks the connection:

1. Keep the existing pin and investigate through trusted owner access.
2. Confirm the intended gateway and the new certificate details independently.
3. Run setup again with the confirmed new SHA-256 fingerprint.
4. Restart the connection and verify read-only inventory results.

Do not disable verification or automatically accept a new certificate to recover.

## Strict direct-tool registration

`UNIFI_STRICT_ENABLED_TOOLS=true` requires eager registration, a nonempty
`UNIFI_ENABLED_TOOLS` list of known direct domain tools, and no category filter.
It excludes meta-tools and on-demand loading, awaits removal before starting MCP
transports, verifies the final tool list, and fails startup on import/filter errors.
It is separate from permission gates: ordinary/default profiles still advertise
tools regardless of policy denials and retain their existing meta-tool behavior.

The additional Codex `enabled_tools` list mirrors the server profile. To extend
inventory, review each tool's read annotation and credential requirements, then
update both lists deliberately. Some gateway/firewall endpoints may reject View
Only accounts or require an API key on particular controller releases. A rejected
read is a capability limitation; do not substitute an admin credential silently.

## Verification and removal

Run `pytest scripts/windows/tests`, the core TLS suite, shared registration suite,
and Network tests. Windows tests use synthetic disposable profiles and verify
DPAPI roundtrip, corrupted ciphertext refusal, unsafe ACL refusal, and inherited
environment isolation. POSIX credential-provider process-group fixtures are
skipped on Windows; run them on Linux before release.

To remove access, disable/delete the dedicated gateway account, remove the Codex
MCP entry, stop its process, and delete its local credential profile. Network
provisioning and developer VPN/Windows accounts have separate revocation steps.

References: [Ubiquiti account management](https://help.ui.com/hc/en-us/articles/28692158912279-Adding-Admins-in-UniFi),
[aiohttp TLS policy](https://docs.aiohttp.org/en/stable/client_advanced.html),
[Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).
