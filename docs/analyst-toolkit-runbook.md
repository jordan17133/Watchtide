# Analyst Toolkit And Learning Runbook

Added October 6, 2026. This extends existing runbook Stage 5 and the detection
validation track. It does not replace the working SOC or renumber its stages.
The owner selected learning through practical investigation, with each new tool
introduced for a specific question. Exercises and installations have separate
completion records; planned exercises are not validated detections.

## Where Each Tool Fits

| Tool | Question it answers | Place in Watchtide | When to use it |
|---|---|---|---|
| Wazuh | What collected activity matched a rule? | Existing endpoint and alert pipeline | Daily health checks and investigations |
| Suricata | What visible network traffic matched a detection? | Offline reporting trace verified; live sensor pending | Network detection and rule validation |
| Wireshark / TShark | What did the individual packets actually say? | Analyst workbench for saved captures and later bounded live captures | Investigate a network question; TShark is Wireshark's command-line analyzer |
| Nmap | Which tested services are reachable from this device? | Active exposure checks and controlled scan exercises | Establish a baseline and recheck after access changes |
| Burp Suite Community | What request did a browser send, and how did a lab app respond? | Separate web-security practice lab | Learn HTTP, authentication, access control and manual testing |
| sqlmap | Does a selected lab web input allow SQL injection? | Later web-lab validation | Compare a known vulnerable input with a corrected control |
| Metasploit | Does a selected vulnerability/test produce the expected behavior and evidence? | Later separate test-VM validation | One documented module/test at a time, with cleanup |

Nmap actively contacts a target. Wireshark examines packets. Suricata applies
detection rules to packets it receives. Wazuh collects and analyzes configured
events. SQL and Power BI organize/report the resulting data. Installing an
analyst tool does not automatically connect its output to Wazuh or Power BI.

```text
Known lab activity -> supported capture point -> packets -> Suricata -> EVE
                                                  |                     |
                                                  v                     v
                                          Wireshark analysis          Wazuh
                                                                        |
                                                              Indexer -> SQL -> Power BI

Nmap / web-lab tools -> generate selected activity for an investigation
Analyst -> compare packets, application/endpoint logs and alerts -> case verdict
```

The current warehouse imports Wazuh alerts, not every packet, Nmap result or
ordinary flow. Scan XML and captures remain private case evidence. A new routine
network-telemetry feed needs its own collection, schema, retention and health
design; see the [network maturity plan](soc-network-maturity-plan.md).

## A Daily Routine You Can Explain

1. **Check health, about three minutes.** Open Pipeline Health and inspect the
   latest successful load, event freshness and failures. Check the expected
   agent is connected. Power BI is an imported snapshot: check its refresh time.
   A quiet dashboard with broken collection cannot establish that activity is safe.
2. **Choose one question, about five minutes.** Open Wazuh and examine one new
   alert or change. Record the event time, device, account/process where available,
   rule, and source evidence. Severity is a review priority, not an incident verdict.
3. **Choose evidence that fits, about five minutes.** For a process alert, inspect
   endpoint events. For a packet question with an available capture, use
   Wireshark. For an access question, compare firewall policy and a bounded Nmap
   check. Network tools need not run every morning.
4. **Record a conclusion, about two minutes.** Use expected activity, authorized
   test, suspicious, confirmed malicious or unresolved. State what supports the
   conclusion and what remains unknown. Preserve private evidence and follow-up.

Investigations can take longer. These times describe a starting routine, not a
requirement to close an unfamiliar alert in fifteen minutes. Review one completed
case each week and explain it without reading the commands.

## Learning And Execution Order

| Lesson | Work | Proof of completion | Initial status |
|---|---|---|---|
| L0: Understand the pipeline | Explain where source events, alerts and report rows come from | Owner can trace one existing alert and distinguish event time from ingest/refresh time | Existing trace available; understanding review open |
| L1: Read packets | Inspect the existing positive/negative synthetic fixtures in Wireshark/TShark | Explain addresses, ICMP types, payload and the rule's exact match conditions | TShark decode/control checks pass; owner explanation pending |
| L2: Check service exposure | Use Nmap on four selected TCP ports of one owned SOC VM, from one documented path | Expected/actual table; explain open, closed and filtered; save private XML | Four-port Tailscale baseline passes; owner explanation pending |
| L3: Prove a capture point | Bounded passive Suricata capture with harmless owned traffic | Packet counts, drops, resource use, positive/negative result and observed scope | [Bounded live trial and independent packet review passed](suricata-live-trial.md); owner explanation pending |
| L4: Follow a live detection | Inspect the capture and trace the exact live alert through existing reporting | Same event identity and fields agree; distinguish it from the offline fixture | [Saved-live handoff completed](suricata-live-reporting-handoff.md); authenticated Wazuh dashboard, Indexer and normal-loader SQL agree; fresh Power BI refresh/rendering deferred |
| L5: Learn web requests | Separate practice app/VM or vendor training lab; manual Burp Proxy/Repeater exercise | Explain one request/response, cookie/session behavior and server evidence | Planned; lab placement and resources first |
| L6: Test SQL injection | Use sqlmap on one selected input in the separate lab after manual inspection | Vulnerable/corrected comparison; explain the flaw and observed evidence | Planned; no database extraction objective |
| L7: Validate a controlled technique | One Metasploit test on the separate test VM | Prerequisites, expected/actual logs, detection/miss, cleanup and case | Planned; lab isolation and test selection first |

Existing hardening, backup/restore and access gates stay in the main plan.
Lessons L1/L2 can proceed without enabling sustained capture or making an
additional practice VM compete with the existing 8 GB SOC VM for memory.
Broader network coverage still requires a supported traffic feed. The existing
Wi-Fi/Hyper-V NAT layout is not verified to show every home device.

Before each operation, explain four things: **what it does, why we need it,
what result we expect, and how we will check it.** Afterward, compare the result
with the expectation and ask the owner to explain one observation in their own
words. AI-assisted execution and the owner's explanation are recorded separately.

## L1: Our First Packet Lesson

Use the same reviewed synthetic fixture generator as the completed offline
Suricata pilot. Preparing or reading these files sends no network packets.
All addresses below are documentation examples, not real home devices. Packet
times are fixed at January 1, 2026 UTC; they are not live observation times.

Open `positive.pcap` and `negative.pcap` in Wireshark. Its three main panes show
the packet list, decoded fields and underlying bytes. Enter `icmp` in the display
filter. A display filter hides unrelated rows from view; it does not change the
capture file or firewall.

| File / packet | Source -> destination | ICMP type | Payload | Expected marker-rule match |
|---|---|---|---|---|
| positive / 1 | 192.0.2.10 -> 192.0.2.20 | 8, echo request | WATCHTIDE-PILOT | Yes |
| negative / 1 | 192.0.2.10 -> 192.0.2.20 | 8, echo request | WATCHTIDE-CONTROL | No: required text absent |
| negative / 2 | 192.0.2.20 -> 192.0.2.10 | 0, echo reply | WATCHTIDE-PILOT | No: required request type absent |

Read [the actual rule](../suricata/rules/watchtide-pilot.rules): `itype:8` requires
an echo request and `content:"WATCHTIDE-PILOT"` requires those bytes. Both
conditions must match. The rule's `sid:9000001` identifies the signature;
Suricata priority and Wazuh alert level are different fields. This deliberately
benign marker verifies detection mechanics; a match is not proof of malware.

The command-line equivalent makes the same fields easy to compare:

```powershell
# Set this to the private lesson folder created during preparation.
$lesson = Read-Host 'Private lesson folder'
$tshark = 'C:\Program Files\Wireshark\tshark.exe'
& $tshark -n -r (Join-Path $lesson 'positive.pcap') -Y icmp -T fields `
    -e frame.number -e ip.src -e ip.dst -e icmp.type -e data.data
& $tshark -n -r (Join-Path $lesson 'negative.pcap') -Y icmp -T fields `
    -e frame.number -e ip.src -e ip.dst -e icmp.type -e data.data
```

`-r` reads a saved file, `-Y` selects displayed packets, `-T fields` selects a
table-like output, each `-e` names one field and `-n` disables name resolution.
Hexadecimal payload bytes are the same text shown decoded in Wireshark.
The owner should explain why only the first packet matches before we add a new
rule. Machine verification does not complete that learning step.

## L2: A Small Nmap Exposure Check

Write down the selected target, source device/interface, start time and expected
ports privately. Choose one owned VM address/hostname, not a range. The previously
excluded website remains outside every exercise. Begin with this reviewed scope:

```powershell
$nmap = 'C:\Program Files (x86)\Nmap\nmap.exe'
$socTarget = Read-Host 'Single owned SOC VM address or hostname'
# Set $lesson to your existing private lesson folder first.
& $nmap -sT -Pn -n -p 22,443,9200,55000 --scan-delay 250ms `
    --max-retries 1 --host-timeout 30s --reason `
    -oX (Join-Path $lesson 'soc-exposure.xml') $socTarget
```

The selected installation path may differ; check it before running. `-sT`
attempts normal TCP connections. `-Pn` skips the separate host-discovery test
(it does not guarantee a live host). `-p` limits ports; `-n` avoids reverse
lookups. The delay, retry and timeout settings bound the exercise. `--reason`
explains classification; `-oX` saves structured evidence. No version probes,
OS guesses, NSE scripts, credentials or exploitation are included.

For the existing approved Windows-to-VM Tailscale path, expect 22/443 reachable
and 9200/55000 unreachable. Recheck actual current policy and target path before
using that expectation; the Hyper-V LAN path is a separate test. Explain:

- **Open:** a connection succeeded from this source at this time.
- **Closed:** the target returned a response indicating no accepting listener.
- **Filtered:** the probes could not establish the port state, often because
  traffic is filtered; a timeout is not proof of the exact filter responsible.

The service name shown beside a port can be a conventional port-name lookup;
this exercise does not identify the actual application version. A private open
port is not proof of Internet exposure. Save discrepancies for investigation,
rather than changing access until every port is green. Do not expect the current
ICMP marker rule to detect a TCP scan. Detection testing needs a suitable rule
and a sensor that actually sees the packets.

## Installation And Evidence Discipline

Use official stable releases, match vendor SHA-256 records and inspect publisher
signatures before execution. Record tool/version/source, purpose, dependencies,
installation changes, test result and removal method. Start with Wireshark and
Nmap only. Burp, sqlmap and Metasploit are planned for their own lab lessons.

Wireshark's documented silent Windows installation does not install Npcap;
saved-file analysis works without that driver. Nmap's initial `-sT -Pn` exercise
uses Windows TCP sockets. Live capture/raw scans and Npcap are a separate setup
decision. Select only needed Nmap components and skip its performance registry
modifications. The standard free Nmap installer requires an interactive setup;
do not assume its OEM-only silent option applies.

Keep real packet captures, scan XML, HTTP sessions, credentials and screenshots
containing personal destinations in protected private storage outside Git.
Publish reviewed summaries, generic fields and explicitly labeled test results.
Use the existing case register for investigations; use a lesson note for learning.
Only update validation counts after the relevant evidence passes.

## Execution Record

October 6 preparation: official Wireshark 4.6.9 and Nmap 7.991 Windows packages
matched vendor SHA-256 records and had valid Wireshark Foundation / Nmap Software
LLC publisher signatures. Initial PATH/standard-folder checks found neither tool.
Wireshark's reviewed silent installer exited zero; installed TShark reports
4.6.9. The synthetic files match the earlier pilot's reviewed hashes. Actual
TShark decoding found one echo request with the marker, one request with a
different payload and one reply with the marker. An equivalent display filter
matched one positive and zero negative packets. This checks packet interpretation,
not a new Suricata engine run. No live capture or Npcap installation was enabled.

Nmap's interactive installation completed with the reviewed minimal component
selection; installed Nmap reports 7.991. No Npcap service is present. Its warning
about unavailable Npcap is expected for this setup; the selected TCP-connect
scan completed successfully using Windows sockets. Raw-scan/capture capability
is not claimed.

An initial preflight stopped before sending scans: private DNS did not resolve,
and the existing Windows Tailscale service was found stopped. Restoring that
automatically configured service left the backend waiting in NoState. Opening
the existing Tailscale desktop application resumed its saved session; no new
login, ACL or routing changes were required. The reason for the earlier service
stop is unestablished; do not attribute it to Nmap installation.

After verifying the expected enrolled SOC peer was online, the four-port Nmap
exercise completed in 4.08 seconds on the approved Windows-to-VM Tailscale path:

| TCP port | Expected | Observed | Nmap reason |
|---|---|---|---|
| 22 | Open | Open | syn-ack |
| 443 | Open | Open | syn-ack |
| 9200 | Unreachable | Filtered | no-response |
| 55000 | Unreachable | Filtered | no-response |

The result agrees with this path's baseline. It does not identify the exact
filter responsible, verify authenticated SSH/API access or establish public
Internet exposure. XML and exact source/target metadata remain private. No live
Suricata detection of the scan is claimed. Owner packet/port explanations are
still pending; see the dated build-log entry for this batch's final checks.

## References

- [Wireshark guide](https://www.wireshark.org/docs/wsug_html_chunked/) and
  [Windows installation options](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html).
- [Nmap TCP scan behavior](https://nmap.org/book/man-port-scanning-techniques.html),
  [port states](https://nmap.org/book/man-port-scanning-basics.html) and
  [Windows setup](https://nmap.org/book/inst-windows.html).
- [Burp getting started](https://portswigger.net/burp/documentation/desktop/getting-started)
  and [Web Security Academy](https://portswigger.net/web-security).
- [sqlmap project](https://sqlmap.org/) and
  [Metasploit module workflow](https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html).
