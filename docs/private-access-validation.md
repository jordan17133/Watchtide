# Tailscale Enrollment, Policy and Access Validation

**Date:** October 3, 2026; rechecked October 4, 2026.

**Status:** partial validation; private-access milestone remains open.

## Initial scope and method

The Ubuntu client's status output listed both the Linux SOC VM and Windows admin host in the tailnet. A separate check with the Windows client's `status --json` confirmed the client is Running, the Windows device is online, and the SOC peer is online.

From the Windows admin host, TCP connection probes targeted the VM's Tailscale address using PowerShell `Test-NetConnection`. The detailed follow-up on TCP 55000 confirmed the connection used the Tailscale interface. Both machines were on the home network; this was not an off-LAN test. Actual addresses, account names and device inventory are omitted from this public report.

## Initial connectivity results

| Check | Expected for this milestone | Observed | Interpretation |
|---|---|---|---|
| Device enrollment | Admin host and SOC VM enrolled and online | Confirmed from both clients | Enrollment gate passed |
| SSH, TCP 22 | Admin host can connect | TCP connection succeeded | Port reachability confirmed; authenticated SSH login still pending |
| Dashboard, TCP 443 | Admin host can connect | TCP connection succeeded | Port reachability confirmed; HTTPS certificate and dashboard login still pending |
| Indexer, TCP 9200 | No direct tailnet connection | TCP connection failed | Consistent with the loopback-only design; remote and unprivileged tests still pending |
| Wazuh API, TCP 55000 | No direct tailnet connection needed by this admin path | TCP connection succeeded, repeated with interface details | Open restriction issue; narrow the policy and retest |
| Scheduled SQL loader | Scheduled task continues to run | Latest Task Scheduler result was 0 (success) | Useful continuity evidence; new-event flow and Power BI refresh still pending |

These probes do not establish authenticated application access or prove that all other sources are denied. The unsuccessful indexer probe establishes unreachability from this source at this time, not the exact listener or firewall configuration.

## Policy review and applied change

Adding the VPN created a path on which TCP 55000 is reachable from the Windows admin host. This is a private-network TCP observation, not evidence of public-internet exposure or unauthorized API use. API authentication was not tested.

The actual current policy was read from the authenticated admin console before editing. It had a default allow-all grant, a default self-device Tailscale SSH rule and no active legacy ACLs or tests. The device inventory contained only the Windows admin host and Ubuntu VM. The exact original and replacement policies are retained outside Git.

After explicit approval, the default grant was replaced with one device-scoped [grant](https://tailscale.com/docs/features/access-control/grants) for Windows-to-VM `tcp:22` and `tcp:443`, using explicit IPv4/IPv6 host aliases. No API, indexer, ingestion/enrollment, wildcard or user-wide grant remains. The `ssh` section is empty: ordinary OpenSSH remains the intended SSH service; Tailscale SSH was not enabled. The existing loader target resolves to the Hyper-V private network, so its restricted tunnel was not migrated or edited. Operating-system firewalls, service listeners and Wazuh configuration were unchanged.

The first save was rejected because its test cases mixed IPv4 sources with IPv6 destinations. The original policy remained active. Tests were corrected to stay within each address family, without changing the approved permissions. The corrected save was accepted, and the server's persisted Tests view confirmed all four cases: four allowed and sixteen denied TCP assertions. These assertions validate policy intent, not application authentication or physical off-LAN behavior. The user-scoped Preview Rules view did not display the device-address-based draft; it was not used as proof of access.

## Post-change results

Windows-to-VM socket connection probes used fresh connections and a four-second timeout. These are local tailnet checks, not off-LAN tests.

| Service | Tailnet IPv4 | Tailnet IPv6 | Interpretation |
|---|---|---|---|
| OpenSSH, TCP 22 | Reachable | Reachable | Network permission retained; authenticated login pending |
| Dashboard, TCP 443 | Reachable | Unreachable | IPv4 permission retained; IPv6 failed before and after the change despite policy allowance; listener/firewall diagnosis and HTTPS/login checks pending |
| Agent events, TCP 1514 | Unreachable | Unreachable | No remote-ingestion grant for this milestone; existing local agent path unchanged |
| Enrollment, TCP 1515 | Unreachable | Unreachable | No enrollment grant for this milestone |
| Indexer, TCP 9200 | Unreachable | Unreachable | No direct tailnet access from this admin device |
| Wazuh API, TCP 55000 | Unreachable | Unreachable | Initial local API reachability issue resolved for this source; other-source/off-LAN proof pending |

The next scheduled SQL load, run 323, started at 21:57 EDT on October 3 and finished successfully at 21:58. Read-only SQL checks confirmed 72 alerts fetched, 49 new alerts inserted, 42 of those from the Sysmon channel, and 10 vulnerability findings snapshotted. Sysmon, the Windows Wazuh service and Tailscale remained Running. This proves loader/collection continuity more directly than a task exit code alone; it is not a tagged controlled-event trace or a Power BI refresh test. The Wazuh manager's current agent Active status was not independently queried.

## October 4 Recheck

The authenticated admin console still contains exactly one device-scoped grant
for the Windows admin host to reach the SOC VM on TCP 22/443, an empty `ssh`
section, and the same four policy tests. No policy changes were made. Fresh
IPv4/IPv6 socket probes reproduced every result in the post-change table above.
The Windows Tailscale client and its Linux peer were online; Sysmon, WazuhSvc,
and Tailscale were Running. These remain local checks, not proof from another
network or an unprivileged device.

Certificate-verified TLS handshakes to dashboard TCP 443 found two outstanding
trust issues: system trust could not build the issuer chain, and the existing
Wazuh CA rejected the certificate's identity for both the tailnet IP and the
MagicDNS hostname. No certificate check was bypassed, no login credentials
were sent, and no certificates or trust stores were changed. Port reachability
is not trusted HTTPS or authenticated dashboard access.

Choose and validate the dashboard's private hostname/certificate and trust
distribution before remote login. A private CA avoids publishing certificate
names but requires securely distributing trust to approved clients. Tailscale
can provision publicly trusted HTTPS certificates; its [HTTPS documentation](https://tailscale.com/docs/how-to/set-up-https-certificates)
explains that those certificate hostnames enter public Certificate Transparency
logs. That tradeoff needs review before enabling it; neither route was applied.

A subsequent read-only SQL check initially timed out, then succeeded on retry.
Windows had less than 1 GB free memory, and SQL Server logged event 17890 about
its process memory being paged out. Scheduled run 392 eventually succeeded:
195 alerts fetched, 117 inserted, and over eight minutes elapsed. Memory
pressure is a plausible contributor, not a proven sole cause. Free host memory
and recheck later load durations before expanding the lab. See the [reliability
follow-up](reliability-validation.md#subsequent-runtime-follow-up).

Power BI Desktop is installed, but a refresh was not attempted while the host
was under memory pressure. Current VM-console recovery/checkpoint availability
could not be independently verified with this session's permissions. No
firewall, service, scheduled task, or Hyper-V settings were changed. The current
policy does not authorize a newly enrolled phone or laptop: enroll a test
client first, verify default denial, then separately review any minimal grant.

## Phone Enrollment and Off-LAN Denial

An iPhone was enrolled on October 4 and verified in the authenticated admin
console under the same tailnet account. The active policy was reread: it still
contains only the Windows-to-VM TCP 22/443 grant. No phone grant, firewall rule,
certificate, or service configuration was changed. A fresh Windows socket
probe confirmed the VM was online and dashboard TCP 443 remained reachable
from the permitted admin host; this is not an authenticated HTTPS check.

The user tested the VM's tailnet IPv4 HTTPS address in Safari on the phone.
After an initially inconclusive white screen, Safari reported a connection
timeout. The user explicitly confirmed Wi-Fi was off, Tailscale remained
Connected, and normal websites loaded over cellular. This is a user-performed
off-LAN denial observation for one phone and one IPv4 service, consistent with
the unchanged device-scoped policy. No certificate warning was bypassed and
no Wazuh credentials were submitted. It does not establish denial of every
port/address family, identify the packet-drop mechanism, or prove approved
off-LAN access, authenticated dashboard use, revocation, or public exposure.

Separately, the user's Ubuntu SSH session reported `active` for
`wazuh-manager`, `wazuh-indexer`, `wazuh-dashboard`, and `tailscaled`. The
session's connection route and SSH host-key trust were not independently
verified. Its read-only `ss` output showed:

| Service | Reported listener binding | Interpretation |
|---|---|---|
| OpenSSH, TCP 22 | All IPv4 and IPv6 interfaces | Listener available on both families; access controls still required |
| Dashboard, TCP 443 | All IPv4 interfaces; no IPv6 listener | Explains the observed IPv6 dashboard gap; IPv6 support was not enabled |
| Indexer, TCP 9200 | IPv4-mapped loopback | Network-interface listener remains restricted to the VM itself |
| Wazuh API, TCP 55000 | All IPv4 and IPv6 interfaces | Broad listener is not proof of public reachability; host firewall review remains necessary |

Next: review the current VM firewall and recovery baseline and resolve trusted
HTTPS identity. The phone remains a denied test client; permanent phone
dashboard access is not required for the whole-network SOC goal. Any temporary
permission for an approved off-LAN test needs separate review. Enrollment is
not authorization; the restricted loader path remains unchanged. Raw device
inventory and terminal output are not included in this public report. The
broader goal and execution order are in the [network coverage plan](network-coverage-plan.md).

## User-Reported Firewall Rule Review

On October 4, the user's Ubuntu session reported UFW active, low-level logging,
incoming deny and outgoing allow defaults. Its displayed service exceptions
allow SSH, dashboard and agent traffic from the three broad private IPv4
address ranges. These are network-range permissions, not individual-device
permissions. The build log records why they were added: Hyper-V's Default
Switch previously changed address ranges and interrupted access. No allowance
for API TCP 55000 or indexer TCP 9200 appeared in the UFW summary.

The supplied IPv4 and IPv6 `INPUT` chains both have a `DROP` policy, with
`ts-input` evaluated before the corresponding UFW chains. Both `ts-input`
chains accept traffic on `tailscale0`, the VM's own tailnet address on loopback,
and UDP 41641. The IPv4 chain also contains a non-Tailscale CGNAT-source drop
and a narrower return exception; the displayed UDP acceptance precedes them.
The `nft` table inventory listed filter, NAT and mangle tables for both families.
Table names alone do not establish every rule or the active firewall backend.

For traffic accepted in these `ts-input` chains, later UFW input rules are not
an additional service restriction. Tailscale's internal access-policy filtering
is a separate control, so the approved device-scoped TCP 22/443 grant remains
important. This is consistent with the documented [netfilter integration](https://tailscale.com/docs/reference/netfilter-modes)
and [internal packet filtering](https://tailscale.com/docs/features/firewall-mode).
The UDP allowance supports Tailscale transport; it does not itself grant access
to Wazuh services.

These initial snippets were user-supplied configuration observations, not an
independently collected full firewall audit, an exact backup or an all-source
reachability test. The following full filter-table review extends that evidence;
public reachability and recovery validation remain open. No rule, listener,
policy or routing configuration was changed. Private device addresses and raw
output are omitted from this report.

### Full Filter Table Follow-Up

The user subsequently supplied complete IPv4 and IPv6 filter-table exports
from `iptables-save -t filter` and `ip6tables-save -t filter`, collected on
October 4. Both export headers identify version 1.8.10 using the `nf_tables`
backend. The supplied filter-table configuration review is now complete;
this is not a complete live exposure or recovery audit.

| Area | Observation in the supplied exports | Interpretation |
|---|---|---|
| Base policies | INPUT and FORWARD default to DROP; OUTPUT defaults to ACCEPT, in both families | Explicit earlier accept rules still take precedence |
| Tailscale input | `ts-input` runs first and accepts `tailscale0` traffic in both families | Tailnet service restrictions depend on the separate Tailscale access policy, not subsequent UFW input rules |
| Non-Tailscale IPv4 TCP | User rules allow only 22/443/1514/1515 from the three broad private ranges | Preserves existing Hyper-V administration and collection paths; not device-level least privilege |
| Non-Tailscale IPv6 TCP | No user-defined TCP service allowance; loopback and established/related traffic accepted | No new management/data-port TCP permission found on other IPv6 interfaces |
| API and indexer | No reachable rule permitting new non-Tailscale TCP connections to 55000/9200 found; loopback and established/related exceptions remain | Consistent with restricted internal data-service access; not proof of all-source network denial |
| Control traffic | ICMP/ICMPv6, DHCP and selected multicast discovery rules are present | Incoming deny is not a claim that every non-Tailscale packet is dropped |
| Forwarding | Tailscale forwarding chains run before UFW and accept selected marked/Tailscale traffic | Default FORWARD DROP and the UFW routed summary do not alone prove forwarding disabled |

The forwarding chains do not establish that kernel IP forwarding, advertised
subnet routes or an exit node are enabled. None was enabled during this review;
their current runtime state was not independently queried on the VM. General
browsing privacy and whole-network sensor coverage are not established by
these rules.

The transcript also records a user-performed password-authenticated OpenSSH
session using the existing local hostname. It is evidence of local shell
access, not an authenticated off-LAN tailnet test or independent host-key
verification. Raw login links, usernames, device addresses and terminal output
were not copied into the public documentation.

Next: verify VM-console recovery and checkpoint availability, retain an exact
private configuration backup before any change, then resolve trusted dashboard
HTTPS identity. Router/publishing review and fresh live allowed/denied tests
remain required. The existing broad local allowances were preserved, as were
the restricted loader key and loopback indexer. No additional filter-chain dump
is required merely to repeat this configuration review.

### Fresh Local Probes and Console Evidence

Fresh Windows TCP socket probes on October 4 compared the VM's existing local
IPv4 hostname/address with its tailnet IPv4 and IPv6 addresses. DNS still
matched the local address supplied in the transcript. Windows route lookups
selected the Hyper-V Default Switch for the local address and Tailscale for
both tailnet addresses. Each socket attempt had a 2.5-second timeout and sent
no application login credentials. These are home-network probes, not approved
off-LAN or all-source tests.

| Service | Hyper-V local IPv4 | Tailnet IPv4 | Tailnet IPv6 |
|---|---|---|---|
| OpenSSH, TCP 22 | Reachable | Reachable | Reachable |
| Dashboard, TCP 443 | Reachable | Reachable | Not reachable |
| Agent events, TCP 1514 | Reachable | Not reachable | Not reachable |
| Enrollment, TCP 1515 | Not reachable | Not reachable | Not reachable |
| Indexer, TCP 9200 | Not reachable | Not reachable | Not reachable |
| Wazuh API, TCP 55000 | Not reachable | Not reachable | Not reachable |

The indexer/API results agree with restricted direct access on these tested
paths. Tailnet results reproduce the earlier management-only observations,
including the known IPv6 dashboard listener gap. Local TCP 1515 did not connect
despite a firewall allowance: its listener/service state has not been diagnosed,
and no enrollment permission or service was enabled. Existing agent-port
reachability is not a substitute for verifying agent Active status or event flow.

The user also supplied a screenshot of Hyper-V VMConnect showing the running
SOC VM and an authenticated Ubuntu console prompt. This is user-provided
evidence of console access independent of guest SSH/Tailscale, not a tested
restore or independent verification of checkpoint availability. The screenshot
does not show a checkpoint list; its login banner is not a fresh Windows-host
memory or SOC-service measurement. No screenshot or raw inventory was published.

Next: confirm the latest checkpoint and exact private configuration backup,
then choose the trusted dashboard certificate path. Public exposure, revocation,
approved off-LAN access and reporting health remain unverified. No runtime
settings were changed during these checks.

## Remaining checks

- [x] Enroll Windows admin host and Ubuntu SOC VM.
- [x] Record initial local TCP reachability and the open API restriction issue.
- [x] Review the actual tailnet policy and enrolled devices; save its exact original outside Git.
- [x] Apply the approved narrow policy with four accepted policy tests, preserve the restricted loader path, and retest local permitted and excluded ports.
- [x] Verify a post-change scheduled SQL load and newly imported Sysmon alerts.
- [x] Enroll an iPhone test client and record its user-performed IPv4 HTTPS denial over cellular with a working public-web control.
- [x] Identify the IPv6 dashboard listener gap from user-provided VM output; the dashboard currently listens only on IPv4.
- [x] Review user-provided UFW summary and IPv4/IPv6 INPUT and Tailscale chains; document Tailscale-before-UFW ordering without claiming a complete firewall audit.
- [x] Review complete user-supplied IPv4/IPv6 filter-table exports and identify the nf_tables backend; separate new TCP restrictions from control traffic, established connections and forwarding exceptions.
- [x] Recheck local Hyper-V and tailnet IPv4/IPv6 TCP paths without application authentication; record the local enrollment-port gap rather than enabling it.
- [x] Record user-provided screenshot evidence of an authenticated Hyper-V Ubuntu console session.
- [ ] Verify a current checkpoint and exact private configuration backups before VM/firewall changes; console evidence is not a restore test.
- [ ] Verify SSH login and dashboard login with a trusted HTTPS identity.
- [ ] Test approved admin access from another network and the remaining denied services/address families from an unprivileged device.
- [ ] Check direct public access, device revocation, new-event flow into SQL and Power BI refresh.

The remaining gates and recovery procedure are in [private-access-plan.md](private-access-plan.md). A tailnet policy change was applied and tested locally; no firewall or service configuration change was made. The overall private-access security milestone remains in progress. Private addresses, account/device inventory and unredacted screenshots are excluded from public publication.
