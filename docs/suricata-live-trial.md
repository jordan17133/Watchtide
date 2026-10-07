# First Live Suricata Trial

Updated: October 7, 2026. Status: bounded activation prepared and 12 local
regression tests pass. **The Ubuntu live trial has not run.** Existing proof
still consists of the offline marker test and its exact reporting trace.

## Plain-English Purpose

Suricata has already recognized a marked packet saved in a file. This trial
asks a different question: can it recognize that marker in an actual packet
moving across the virtual network between the SOC VM and its Windows host?

Send one harmless echo request without the marker, then one with it. Each
request gets a separate short capture window. The unmarked request should
produce no detection; the marked request should produce SID 9000001. Neither
packet is an attack. An alert here means the test condition matched.

```text
Ubuntu test ping -> Hyper-V virtual network -> Windows host
                         |
                   Ubuntu Suricata
                         |
                  private EVE + PCAP
```

This is a sensor-placement test, not a browsing-history collector. Traffic
between the VM and its host does not establish visibility of the host's
Internet connections or traffic from a separate Wi-Fi phone.

## Actual Device Scope

The current owner-selected scope is two physical devices: the Windows PC and
the iPhone. The Ubuntu VM is a component inside the PC, not a third physical
device. Broader guest/IoT expansion is a future option, not current coverage.

| Source | Evidence so far | Important gap |
|---|---|---|
| Windows endpoint | Sysmon/Wazuh alerts and existing SQL/Power BI reporting | Stored alerts are not a complete connection, DNS or browser-history archive |
| Ubuntu sensor | Offline marker detection and controlled reporting trace | Live interface/packet/drop evidence remains pending this trial |
| Windows Internet traffic | No live Suricata feed verified | The NAT VM does not automatically observe the host's browsing |
| iPhone | Tailscale enrollment reported; SOC access remains denied | No packet feed or endpoint telemetry into the SOC verified |

## Boundaries And Stop Path

- Keep the permanent Suricata service masked and inactive. Run only the
  reviewed foreground test process, using the previously validated rule.
- Use the Windows host's verified Hyper-V virtual-adapter address. The guest
  must find a directly connected Ethernet route on the same private subnet.
  A changed route, gateway, VPN route or unsupported address stops the job.
- Apply a capture filter for IPv4 echo requests from that guest to that host
  only. Replies, browsing, DNS, other devices and other protocols are excluded.
- Require at least 2 GiB available guest memory before starting. During the
  observation window, stop for sensor RSS over 512 MiB or guest available
  memory below 1 GiB. These are safety gates, not performance certification.
- Wrap each capture in a 35-second watchdog, with forced termination after
  another five seconds if needed. The normal job stops its own process group
  earlier. Forced shutdown is a failed trial, never a success.
- After startup, verify Suricata dropped its root identity to its service
  account. Keep one capture thread, no promiscuous mode, and no inline blocking.
- Save small PCAPs, EVE, route facts, engine/ping logs and resource measurements
  privately. Do not publish raw traffic, addresses or private staging paths.
- Leave installed configuration, Wazuh collection, the loader key, Tailscale
  access controls, firewall rules and router unchanged. No new driver, package,
  SSH key or always-on service is required for this trial.

The activation uses the owner's existing SSH/sudo authentication. Credentials
are entered only at those local prompts, never shared in chat or embedded in
the launcher. The preparation-only SSH key is not broadened into shell access.

## Acceptance Checklist

- [x] Prepare bounded activation without executing capture.
- [x] Pass 12 local checks covering route restrictions, capture configuration,
  fixed pings, watchdog cleanup, resource checks, result validation and launcher.
- [ ] Run guest preflight and validate the live configuration with Suricata.
- [ ] Observe exactly one request in each test window, with matching flow fields.
- [ ] Verify explicit zero kernel drops; absent counters must not count as zero.
- [ ] Verify one marker alert and zero control alerts, with current timestamps.
- [ ] Record private PCAP hashes, wall time, sampled peak RSS and child CPU time.
  Child CPU includes the ping/watchdog, not just the Suricata process. Sampled
  peak RSS is not a guarantee that no higher transient peak occurred.
- [ ] Confirm five SOC services remain active, installed configuration matches
  its preflight bytes, and no Suricata process survives the trial.
- [ ] Independently inspect the saved packets with Wireshark/TShark.
- [ ] Explain the result and the unobserved paths in the owner's own words.

A missing ping reply is not automatically a detection failure: the Windows
firewall may decline echo replies. The test instead requires evidence that
the request itself was captured and decoded. No firewall exception is added
just to make ping answer.

## Reporting Comes Separately

This trial saves private evidence; it does not append live EVE to Wazuh or
change the existing offline-only collection label. Do not relabel a live
event as the historical synthetic fixture just to reuse that source.

After capture and independent packet inspection pass, review a protected
live-event source and accurate validation label. Then trace the same live
event through Wazuh, the Indexer, the scheduled loader, SQL and the existing
Network Detection page. Routine DNS/flow coverage and the iPhone need their
own supported feeds, retention budgets and health checks.

See the [learning runbook](analyst-toolkit-runbook.md) and
[network maturity checklist](soc-network-maturity-plan.md).

## References

- [Suricata 8.0.7 command-line options](https://docs.suricata.io/en/suricata-8.0.7/command-line-options.html)
  describe exclusive rule loading, foreground capture and single runmode.
- [Suricata 8.0.7 configuration](https://docs.suricata.io/en/suricata-8.0.7/configuration/suricata-yaml.html)
  documents privilege dropping, statistics and bounded PCAP logging.
