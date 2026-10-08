# TCP Rule And Control Lesson

Prepared October 7, 2026 Eastern. This is the independent offline portion of
the existing Stage 5 / TCP-Nmap learning track, not an enabled detection.

## What We Are Doing And Why

A TCP **SYN** is a request to start a connection. We are preparing small saved
examples of fast requests, slower requests and nonmatches, then comparing their
packet fields with a proposed rule. No packets are sent to a device.

The next engine check must answer: **does the installed Suricata actually
produce the expected alerts and nonalerts?** Packet decoding alone cannot
answer that. After that passes, a separate bounded owned-VM exercise can test
the real capture path and reporting pipeline. The existing Nmap four-port
exposure baseline is already complete; we are not repeating it.

## The Teaching Rule

The separate [candidate rule](../suricata/rules/watchtide-tcp-lesson.rules)
uses SID 9000002; the existing ICMP pilot SID 9000001 is unchanged.

```text
TCP, exactly SYN flags
    + stateless packet matching
    + four matching packets from the same source within ten seconds
    + at most one alert per threshold window
    = a controlled connection-burst observation, not an incident verdict
```

`tcp.flags:S` selects an exact SYN flag set; other combinations such as ECN
variants are outside this small lesson. `flow:stateless` avoids requiring an
established handshake. `threshold:type both, track by_src, count 4, seconds 10`
expresses the intended threshold and limit. The action is **alert**, not drop.
These meanings are documented in the version-matched
[TCP keywords](https://docs.suricata.io/en/suricata-8.0.7/rules/header-keywords.html#tcp-flags),
[flow keywords](https://docs.suricata.io/en/suricata-8.0.7/rules/flow-keywords.html)
and [threshold reference](https://docs.suricata.io/en/suricata-8.0.7/rules/thresholding.html).
Actual engine verification remains open.

The candidate counts matching **packets**, not unique destination ports, unique
connections, exploit attempts or malicious intent. Browser activity, retries or
legitimate diagnostics can resemble a burst. It is not a production tuning
decision, a comprehensive scan detector or a vendor detection from ET Open.
Maintained-feed selection keeps its own [rollout gates](detection-library-plan.md).

## Seven Controls

All files use documentation-only addresses, synthetic Ethernet/TCP headers,
no payload, and fixed January 1, 2026 timestamps. They are not recorded browsing.

| Saved example | Packets / timing | Expected SID 9000002 alerts, not engine results | What it checks |
|---|---|---:|---|
| Fast burst | 4 SYNs, 0-3 seconds | 1 | Threshold reached by one source |
| Repeated burst | 8 SYNs, 0-7 seconds | 1 | Alert-frequency limit |
| Below threshold | 3 SYNs, 0-2 seconds | 0 | Too few matches |
| Slow requests | 4 SYNs at 0, 4, 8, 12 seconds | 0 | Not all four inside ten seconds |
| Split sources | 4 SYNs, two from each of two sources | 0 | Per-source tracking |
| ACK control | 4 ACK packets | 0 | Required TCP flags |
| Same-port burst | 4 SYNs to one destination port | 1 | Exposes why a match is not proof of multi-port scanning |

Each file must run in a **fresh engine process** so threshold state cannot leak
between controls. Compare every result, not just the expected positive.

The generator uses the existing reviewed Scapy dependency; it does not implement
a pretend Suricata detection engine or a network sender. Its
[preparation helper](../suricata/prepare_tcp_lesson.py) writes fresh files only
under protected private storage and refuses to overwrite earlier evidence.
The pre-created parent needs an actual Windows reader-permission audit; the
Python path guard does not replace that audit. Partial jobs are preserved,
not blindly rerun.

## What Passed So Far

- Twelve focused tests pass: deterministic packet bytes/timestamps, exact flags,
  source/port/count controls, unchanged earlier evidence, candidate rule fields,
  hashes and truthful expected-versus-observed labels. No network operations.
- Seven actual PCAPs contain 31 packets. The existing TShark decoded all seven
  independently, including flags, source/destination ports, timing spans and
  zero payload. Eight input hashes match the private preparation manifest.
- All nine prepared-file and parent reader checks passed; the additional private
  TShark review is also restricted. No captures or raw output are committed.
- The first TShark review stopped before writing output because this installed
  version returns ISO timestamps in JSON's epoch field. A read-only reproduction
  and structured date parser corrected the review; no packets or fixtures changed.
- At 11:36 PM Eastern the running Windows agent owned one Established data-port
  connection. Its protected state file was unreadable here; this is not a fresh
  authenticated heartbeat check. At 11:40 PM, bounded SQL observations were
  recent (12.35-minute load age, 13.04-minute endpoint age), with five queue
  warnings and 40 Sysmon errors still requiring the documented loss review.

**Not run:** Suricata syntax/replay, Nmap, live capture, rule deployment, Wazuh
collection changes, manager restart, firewall/VPN changes or report refresh.
The permanent Suricata service is not enabled by these files.

Full regression: 371 Python tests passed, 13 opt-in SQL tests skipped. The
structural inventory checked 294 files and 439 local file links with no errors.
These checks do not substitute for an installed-engine run or live report rendering.

## How This Leads To Nmap

Nmap `-sT` asks the operating system to establish TCP connections. It can
generate SYN packets, but its timing, retries, flag combinations and visible
path matter. Four requested ports do not guarantee this rule will alert.
[Nmap's connect-scan explanation](https://nmap.org/book/scan-methods-connect-scan.html)
describes its connection/handshake behavior. A future test must compare the
actual saved packets with the exact rule, not declare a detection from an Nmap
output screen alone.

## Finish Lines

- [x] Prepare deterministic, harmless TCP examples and a separate candidate.
- [x] Decode every example with Scapy and actual TShark; preserve private hashes.
- [ ] Run isolated syntax/replay checks using installed Suricata 8.0.7 with
  service/config preflight, fresh processes, time/resource bounds and no reload.
  This needs the owner's authenticated Ubuntu sudo step, not the loader key.
- [ ] Explain one match, two nonmatches and the same-port limitation to the owner.
- [ ] After source/resource gates, separately scope one owned-device Nmap/capture
  exercise with automatic stop, packet/drop evidence and post-test health.
- [ ] Trace a labeled detection through Wazuh, Indexer, normal-loader SQL and
  actual fresh Power BI rendering. Synthetic files are not incidents or new coverage.

The [health work](collection-loss-and-notifications.md) continues in parallel;
these fixtures do not close loss-cause, heartbeat or automatic-notification gates.
