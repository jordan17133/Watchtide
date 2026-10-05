# Network Coverage and Browsing Privacy Plan

Updated: October 5, 2026. Status: privacy/security planning with a read-only
host baseline; no sensor, gateway or privacy-VPN deployment has been made.

The owner has prioritized home-network privacy and security and declined the
temporary phone dashboard test. Leave the phone denied. Off-LAN administration
is deferred and unverified, not complete; it is not a prerequisite for planning
privacy routing or network detection.

## Where The Project Is

| Layer | Current state | Next evidence |
|---|---|---|
| Endpoint SOC | Windows/Sysmon to Wazuh, SQL and Power BI is built; the public console uses a sanitized historical snapshot | Recheck loader performance and reporting refresh before adding load |
| Private SOC administration | Local trusted IPv4 HTTPS/login verified; renewal setup reported successful; management-only Windows grant unchanged; phone remains denied | Automatic renewal check/actual rotation, remaining denied/public-access and recovery checks; approved off-LAN administration deferred |
| Network IDS | Stage 5 not started; no whole-home packet coverage verified | Verified capture point, Suricata pilot, benign event through Wazuh and reporting |
| Whole-network browsing privacy | Not implemented or validated by this project | Gateway/client coverage, egress/DNS/IPv6 tests, provider trust and failure behavior reviewed |

## Read-Only Baseline: October 5

- The Windows SOC host's active physical connection is Wi-Fi; Ethernet adapters
  are disconnected. The owner identified an ISP-supplied gateway privately.
- Windows Firewall reports enabled on Domain, Private and Public profiles.
  This is not a review of every effective firewall rule or public exposure.
- Microsoft Defender reports antivirus, real-time, behavior and download
  scanning protection enabled, with tamper protection on. This is not a malware
  clearance or a complete endpoint-security audit.
- Tailscale reports Running with no exit node selected on Windows. This does
  not rule out every other VPN, proxy or routing path; it does confirm that
  this Tailscale client is not using exit-node browsing protection.
- Disk-encryption inspection failed with access denied. Encryption status is
  unknown, not proven disabled. No encryption setting or recovery key changed.

No router, firewall, DNS, VPN, account, Hyper-V or SOC runtime setting changed
during these checks. Exact hardware inventory, addresses and raw output remain
private. Account MFA, gateway configuration and other home devices were not
audited.

## Execution Order

1. Preserve the current private SOC access and keep the phone denied. Review
   gateway Wi-Fi/admin security, account MFA, updates and backup recovery before
   changing settings. Investigate recorded host memory pressure before adding
   sensor or gateway load to the SOC host; confirm SQL and Power BI health.
2. Privately inventory the gateway, existing routers/firewalls, Wi-Fi segments,
   intended devices and any existing VPN subscription. Check actual vendor
   support for an outbound VPN client, not just VPN pass-through or a VPN
   server. Do not buy equipment, choose a paid service or flash firmware yet.
3. Design whole-home privacy routing first. Compare a supported VPN-capable
   gateway with a device-client pilot if hardware is unavailable. A device
   pilot protects only tested devices, not the whole home. Review provider
   trust, DNS, IPv4/IPv6, tunnel-failure behavior, local SOC access and Wi-Fi
   migration. Keep a wired recovery route and validated backups before a
   gateway cutover; do not enable bridge mode while relying on its Wi-Fi.
4. Deploy only the reviewed, approved design, then test each intended device
   and segment. Verify external routing, DNS/IPv6 handling and no unintended
   direct fallback when the tunnel fails. Recheck private SOC/loader access and
   reporting. Record any bypasses and device exceptions explicitly.
5. Plan a supported traffic capture feed and build a separate Suricata pilot
   after resource and capture-point review. Follow the
   [Wazuh Suricata integration](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html)
   for EVE log collection. Trace a benign event through the sensor and Wazuh;
   validate the SQL/reporting representation separately rather than assuming
   endpoint-oriented reports already cover network fields. Installing a sensor
   in the Hyper-V NAT VM is not evidence of whole-home coverage. Test each
   intended segment, record capture gaps/drops and protect the private logs.

## ISP Gateway Constraints

[Xfinity documents VPN pass-through](https://www.xfinity.com/support/articles/using-a-vpn-connection),
which is different from running an outbound VPN for every home device. A
supported privacy gateway needs a VPN client; for example,
[Proton's router requirements](https://protonvpn.com/support/installing-protonvpn-on-a-router)
specify an OpenVPN or WireGuard client, and
[NordVPN's native-firmware compatibility list](https://support.nordvpn.com/hc/en-us/articles/20379585675793-Which-routers-don-t-support-NordVPN)
lists Xfinity gateways as unsupported for its service. These are capability
references, not a provider recommendation or a purchase decision. No built-in
whole-home privacy client has been verified on the owner's gateway.

[Xfinity bridge mode disables the private Wi-Fi network](https://www.xfinity.com/support/articles/wireless-gateway-enable-disable-bridge-mode).
Do not enable it during this Wi-Fi-based session or before a replacement
router/access point and wired recovery access are ready. A diagram or a
connected VPN app is not proof that every device follows the private route.

Gateway Wi-Fi/admin protection and service settings require a separate review;
the [FTC home-network guide](https://consumer.ftc.gov/articles/how-secure-your-home-wi-fi-network)
covers strong encryption/passwords, updates and unnecessary remote-access
features. Do not disable features blindly or publish their credentials.

## Keep The Controls Separate

- Tailscale currently provides private device connectivity and SOC access
  permissions. It does not automatically route ordinary public browsing;
  [exit-node routing requires explicit configuration and authorization](https://tailscale.com/docs/features/exit-nodes).
- A home-based exit node still uses its own home internet connection for
  egress. It is not, by itself, a way to hide internet destinations from that
  home's ISP. An external privacy-egress design changes whom the user trusts;
  it does not remove all providers, website tracking, account identity or
  endpoint risk.
- A properly configured external privacy VPN can reduce ISP visibility into
  destinations, but the ISP still sees a VPN connection and traffic timing/
  volume. It shifts network trust to another operator and does not erase
  browser history, signed-in account tracking or cookies. See
  [EFF's VPN privacy limits](https://ssd.eff.org/module/choosing-vpn-thats-right-you).
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
