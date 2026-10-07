# Nmap: Understand The SOC Exposure Baseline

Updated October 7, 2026. **Saved scan rechecked; no new scan performed.** The
technical L2 baseline passes. The owner's explanation and a separate
Nmap-to-Suricata detection exercise remain open.

## The Question

From the approved Windows computer, which selected SOC VM services can be
reached over Tailscale? This is an access check, not a malware scan, exploit,
browsing monitor or proof of public Internet exposure.

## What The Saved Scan Shows

The October 6 evening exercise used Nmap 7.991 and one owned VM. Its structured
XML records a successful TCP-connect scan of exactly four ports in 4.08 seconds.
The scan started October 7 at 03:50:26 UTC, which was October 6 locally. A
read-only recheck matched the XML against the original private exercise record:
same target, ports, states and reasons. The original XML/hash stay private.

| TCP port | Our configured purpose | Observed | Plain-English interpretation |
|---|---|---|---|
| 22 | Ordinary SSH administration | Open; `syn-ack` | Windows could establish a TCP connection; successful account login is a separate test |
| 443 | Wazuh dashboard HTTPS | Open; `syn-ack` | Windows could reach this port; browser trust/login are separate checks |
| 9200 | Wazuh Indexer | Filtered; `no-response` | No direct connection result from this path; the exact filtering component is not established |
| 55000 | Wazuh management API | Filtered; `no-response` | Not directly reachable in this exercise; this is not an API authentication test |

The result matches the intended management-only path. The scheduled SQL loader
does not need direct Tailscale access to port 9200: its restricted SSH connection
forwards to the VM's loopback Indexer, with Indexer credentials and TLS checks.
That explains how SQL ingestion works while the direct 9200 probe is filtered.

Nmap actually labels 9200 `wap-wsp` in this XML, with `method="table"`. That
label is a conventional port lookup, not a detected application. Our deployed
configuration identifies the Indexer; this scan did not use version probes.
Do not infer an unexpected application from that label alone.

Nmap states describe a particular source/path/time. Open means a service
accepted the probe; closed means a reachable response indicated no accepting
listener; filtered means Nmap could not establish the port's open/closed state.
An open private port is not automatically a vulnerability, and this small scan
does not assess other ports or other devices.
[Nmap port states](https://nmap.org/book/man-port-scanning-basics.html)

The chosen `-sT` method asks Windows to make ordinary TCP connections. It does
not require raw-packet scanning or the Npcap driver. Connections can leave server
log entries; absence of a Suricata alert does not mean there was no traffic.
[Nmap TCP-connect scan](https://nmap.org/book/scan-methods-connect-scan.html)

## Connect Nmap To Suricata

This is a planned, separate bounded exercise, not a deployed change:

1. Select one owned source/target and verify a path/interface on which the sensor
   can observe the actual TCP probes. Do not assume the VPN and Hyper-V paths
   are interchangeable, or weaken access controls to make the test easier.
2. Prepare and offline-test a narrowly scoped TCP teaching rule and negative
   control. Explain its match conditions and false positives before live use.
   A packet-count threshold is not automatically a count of distinct ports;
   retries or normal connections can satisfy an overly broad rule.
3. Run a short, automatically stopped capture and the selected small TCP-connect
   scan. Keep actual packet evidence, drop/resource statistics and Nmap XML
   private. Leave persistent capture, packet blocking and broad scripts off.
4. Independently compare the scan's destination ports and times with the captured
   packets and detection. Classify it as authorized validation, not an incident.
5. Trace the exact new detection through Wazuh, Indexer, the normal loader and
   existing reporting. Nmap XML is analyst evidence, not input to the alert loader.

Our completed Suricata trial cannot be reused unchanged: its capture filter
admits only VM-to-host ICMP requests, its rule requires the special ping marker,
and its route guard excludes VPN interfaces. The earlier Nmap scan instead used
TCP over Tailscale. Neither exercise establishes detection of the other's traffic.
The permanent sensor remains masked; no new capture, rule or collection change
was made during this review.

## Finish Line

- [x] Install the reviewed Nmap tool and complete the four-port baseline.
- [x] Recheck saved XML scope, completion, states and original exercise agreement.
- [x] Explain why direct Indexer denial and restricted loader access can coexist.
- [x] Separate lookup labels, connection states and application authentication.
- [ ] Owner explains one open port, one filtered port and the loader path.
- [ ] Prove the selected TCP scan is visible to the intended sensor.
- [ ] Validate the TCP rule/control and trace the resulting labeled alert.

The checked explanation items mean the explanation is documented, not that the
owner has demonstrated understanding. See the [L2 commands and learning track](analyst-toolkit-runbook.md#l2-a-small-nmap-exposure-check)
and [network coverage checklist](soc-network-maturity-plan.md).
