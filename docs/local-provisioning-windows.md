# Local Windows provisioning

This optional profile lets the Network MCP provision a VLAN, firewall policies,
DHCP reservations, access-port profiles/assignment and an IPv4 WireGuard server without
browser automation. The existing read-only profile remains separate.

## Configure a temporary writer

1. Install the locked environment with `uv sync --locked --package unifi-network-mcp`.
2. Use a **local UniFi account with Network write permissions**. A separate
   temporary account preserves the inventory account's View Only boundary.
   Alternatively, temporarily grant the existing account Network write access
   and restore View Only after provisioning.
3. Independently compare the gateway's SHA-256 certificate fingerprint with its
   certificate viewer. This profile requires an exact certificate pin, including
   when the certificate is self-signed. It does not change Windows trust.
4. Run `setup-provision.bat -IncludeApiKey`. Enter the local controller address,
   certificate fingerprint, local login and optional Network Integration API key.
   Omit `-IncludeApiKey` when zone creation and policy ordering are not needed.
   These operations require the key in addition to the session account.
5. Review the generated MCP entry at
   `%LOCALAPPDATA%\UniFiMCP\provision\codex-config.toml`, add it to Codex's MCP
   configuration, and explicitly set its `enabled` value to `true` for the work.

To reuse a login already stored by `setup-readonly.bat`, pass
`-ReuseReadOnlyLogin` with the same controller address, port and certificate pin.
Setup checks the source profile's permissions and target before decrypting it,
then stores a separate writer profile. It does not modify the original profile
or the UniFi account's role. An Integration key is still prompted securely with
`-IncludeApiKey`; keys are never copied from the inventory profile. When sharing
one UniFi account between profiles, the inventory account loses its independent
controller-enforced View Only boundary until you restore that role.

To diagnose stored-login reuse, add `-ValidateStoredLogin` to the same command
with `-ReuseReadOnlyLogin`. This checks permissions, the controller target and
DPAPI decryption, then exits before the API-key prompt or any profile writes.
No gateway connection is made. Permission failures report the file category,
operation and exception class without printing credential contents. The batch
launcher uses the inbox Windows PowerShell executable regardless of `PATH`.
If the profile is stored elsewhere, supply `-ReadOnlyProfileDirectory` with its
private directory and `-ProfileDirectory` with the separate writer directory.
Both paths are explicit and do not depend on the process's AppData location.

Setup stores credentials using Windows CurrentUser DPAPI and restricts the
profile to the current Windows user and SYSTEM. It makes no gateway connection
and does not edit Codex configuration. The default lifetime is two hours;
`-LifetimeHours 1` through `8` changes it. The launcher refuses expired profiles
and stops its server process at expiry. Inspect live inventory if expiry interrupts
a mutation. Expiry stops this local MCP process; it does **not** revoke the UniFi
account, API key or resources already created. Disable the MCP entry and revoke
the temporary account/API key when finished. Rerun setup to renew the profile.

The launcher excludes inherited UniFi settings, proxies and Python import
overrides. It enables an explicit list of direct tools in eager mode, with
confirmation required and other mutation categories denied. Dynamic executors,
batches, HTTP serving and websockets are excluded. This is a scoped workflow,
not a resource-level ACL: the allowed tools can change existing resources within
their categories. Review target IDs and previews before applying changes.

## WireGuard tools

The contract targets UniFi Network **10.6.106**. Peer reads were checked against
that version, and mutation routes/payloads were checked against its installed
official UI. Server conflict preflight and peer inventory were also checked using
a View Only connection. Mutations are covered by synthetic controller tests; successful
provisioning on a real gateway remains an acceptance check.

| Tool | Behavior |
| --- | --- |
| `unifi_create_wireguard_server` | Validates subnet and configured VPN port conflicts; creates a disabled server on WAN/WAN2 in the built-in Vpn zone. |
| `unifi_update_wireguard_server_state` | Fresh fetch-merge-put of enabled state, with readback verification. |
| `unifi_list_wireguard_peers` | Reads current peers; excludes private keys and opaque controller fields. |
| `unifi_create_wireguard_peer` | Adds one client public key at an unused IPv4 tunnel address. |
| `unifi_delete_wireguard_peer` | Revokes one peer and verifies absence. |
| `unifi_delete_wireguard_server` | Deletes a server only after all peers have been revoked. |

All mutations preview by default (`confirm=false`) and apply with `confirm=true`.
MCP previews validate live inventory; generic API action previews only show
submitted arguments. Confirmed calls repeat preflight checks against fresh state.
Server creation generates its private key internally and returns its public key.
The developer generates their own private key on their client and supplies only
the public key. Use the server's legacy **networkconf `_id`** and peer `_id`,
not `wireguard_id` or Integration API UUIDs.

Example server input:

```json
{"server_data":{"name":"Dev-WG","ip_subnet":"10.77.31.1/24","local_port":51821,"wireguard_interface":"wan"}}
```

The subnet uses the first usable private IPv4 gateway address, with prefix
/16 through /30. IPv6, preshared keys, arbitrary gateway routes and client private
key export are outside this initial contract. Server creation checks other
configured network/VPN subnets and VPN listen ports; it does not prove the port
is free of every gateway service or port-forward rule. Check those before activation.
It cannot detect overlap with the remote developer's LAN unless you compare the
remote subnet separately. The local mutation lock prevents races within one MCP
process; other admins/processes can still change the controller concurrently.

On the gateway, a peer's `allowed_ips` describes **networks behind that peer**.
These tools keep it empty for a remote developer. Configure the client's
`AllowedIPs` separately with only the development host/subnets it should reach.
Client routes do not enforce isolation: deploy peer-specific firewall rules
before enabling the staged server, accounting for existing Vpn-zone allows.

Each mutation reads back state and checks requested fields or resource absence.
A timeout or failed readback returns `mutation_applied=null`: inspect fresh state
before any further mutation. No uncertain write is automatically replayed or
switched to another API/authentication route. Readback mismatches may leave a
partially applied resource; inspect the result and use the revoke/delete tools
for an explicitly reviewed rollback.

## V2 firewall policy ordering

Use `unifi_get_v2_firewall_policy_ordering` and
`unifi_reorder_v2_firewall_policies` for policies returned by
`unifi_list_firewall_policies`. These tools use the local-session V2 API with
controller ObjectIDs. The older Integration ordering tools use UUIDs and can
return different policy membership; never mix the two families or map policies
by name.

The V2 read returns complete `before_predefined_ids` and `after_predefined_ids`
for one zone pair. Preserve every custom policy exactly once, including disabled
policies. `predefined_ids` are context only and cannot be submitted. Reads and
mutation preflight bypass cached inventory. Confirmation sends one batch-reorder
request and verifies fresh ordering; a transport failure or unverified order
returns an unknown outcome that requires inspection before another write.
An unchanged order is a verified no-op. The contract was checked against the
installed Network 10.6.106 UI; live mutation acceptance remains outstanding.
