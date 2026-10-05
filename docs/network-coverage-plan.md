# Network Coverage and Browsing Privacy Plan

Date: October 4, 2026. Status: planned expansion; no sensor, gateway, or privacy
VPN deployment has been made for this plan.

## Where The Project Is

| Layer | Current state | Next evidence |
|---|---|---|
| Endpoint SOC | Windows/Sysmon to Wazuh, SQL and Power BI is built; the public console uses a sanitized historical snapshot | Recheck loader performance and reporting refresh before adding load |
| Private SOC administration | Stage 4c in progress: Windows/VM/phone enrolled, management-only Windows grant, local checks and a reported phone denial over cellular; firewall tables reviewed, backup helper repaired, new checkpoint creation and five active guest services afterward reported under pictured Production-Only settings | Checkpoint metadata, protected current private backups and separate restore validation; trusted authenticated access, approved off-LAN access, remaining denied paths and revocation |
| Network IDS | Stage 5 not started; no whole-home packet coverage verified | Verified capture point, Suricata pilot, benign event through Wazuh and reporting |
| Whole-network browsing privacy | Not implemented or validated by this project | Gateway/client coverage, egress/DNS/IPv6 tests, provider trust and failure behavior reviewed |

The current phone test checks unauthorized SOC access. It is not a browsing
privacy test, and permanent phone dashboard access is not a prerequisite.

## Execution Order

1. Finish the current access/recovery checks and investigate recorded host
   memory pressure. Confirm SQL response and Power BI refresh before expansion.
2. Inventory the router/gateway, switches, Wi-Fi segments, Hyper-V switches and
   approved endpoints privately. Identify where traffic can actually be
   observed and how much sensor capacity is available. Installing a sensor in
   the existing Hyper-V NAT VM is not evidence of whole-home coverage.
3. Establish one supported capture feed and build a Suricata pilot. Follow the
   [Wazuh Suricata integration](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html)
   for EVE log collection. Trace a benign event through the sensor and Wazuh;
   validate the SQL/reporting representation separately rather than assuming
   endpoint-oriented reports already cover network fields.
4. Verify each intended device/segment with controlled traffic. Record capture
   gaps, drops, encryption limits, log access and retention. Expand only to
   devices/networks the owner is authorized to monitor.
5. Design whole-network privacy routing separately, based on actual gateway
   capabilities. Review the provider/egress trust boundary, DNS handling,
   IPv4/IPv6 coverage, devices without a VPN client, local SOC access and what
   happens if the privacy tunnel fails. No provider or paid service is selected.

## Keep The Controls Separate

- Tailscale currently provides private device connectivity and SOC access
  permissions. It does not automatically route ordinary public browsing;
  [exit-node routing requires explicit configuration and authorization](https://tailscale.com/docs/features/exit-nodes).
- A home-based exit node still uses its own home internet connection for
  egress. It is not, by itself, a way to hide internet destinations from that
  home's ISP. An external privacy-egress design changes whom the user trusts;
  it does not remove all providers, website tracking, account identity or
  endpoint risk.
- Suricata is a network detection sensor, not a privacy VPN. Decide which
  traffic the capture feed sees before and after encryption; do not promise
  decrypted browsing content or claim complete visibility from one test.
- The SOC's logs are themselves sensitive. Keep personal destinations and
  device inventory private, minimize retained data, and publish only reviewed
  sanitized evidence. Do not add TLS interception as a default requirement.

## Completion Evidence

Maintain a coverage matrix for devices/segments and a separate privacy-routing
matrix for IPv4, IPv6, DNS, local access and tunnel-failure behavior. Trace
benign events end to end, verify logs remain access-restricted, and document
what is not covered. Neither a connected VPN icon nor a running sensor proves
complete security, complete privacy, or whole-network visibility.
