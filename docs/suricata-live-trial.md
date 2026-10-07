# First Live Suricata Trial

Updated: October 7, 2026. Status: revised bounded activation prepared and 29 local
regression tests pass. **No successful live capture is verified.** The first
authenticated attempt stopped during parent-directory preflight. The second
passed that guard, created private staging evidence and stopped with a generic
failure. The third confirmed that earlier stop, built the configuration and
failed during the engine's identity transition in configuration-test mode.
No capture started. Existing detection proof still consists of the offline
marker test and its exact reporting trace.

The first guard incorrectly required root ownership of the configuration
directory. The hash-verified reviewed package's installation script intentionally
assigns that directory to the Suricata service account with mode `0750`.
The corrected guard checks root-owned ancestors, inspects the actual directory
metadata and accepts service ownership only when it matches the exact installed
package override, account, group and mode. The configuration file itself still
must be root-owned, single-linked, non-symlinked and not group/world writable.
No ownership or permissions are changed to make the guard pass. The owner's
second attempt confirmed the exact directory ownership, mode and package override.

The next failure was reproduced locally using the hash-verified package's actual
YAML: the optional `security.lua` section is empty, parsed as `None`, and the
old configuration builder tried to edit it as a mapping. The revised builder
handles empty sections, preserves other security settings and rejects malformed
non-mapping sections. The full packaged YAML now builds and round-trips locally;
the guest's Suricata syntax test and actual capture remain separate gates.

The owner read the third attempt's protected engine log: the main-thread
`capng_change_id` call failed. The test subprocess had already been started as
the service account, but the exact live configuration requested another
privilege transition. The revised `-T` check starts as root with no supplementary
groups and lets the engine perform its configured identity drop. It tests the
same file/rule used for capture, with fatal rule-initialization errors and a
30-second timeout. It does not select a capture interface or run packet capture.
The live sensor's service-account setting and observed non-root UID gate stay
unchanged. Guest verification of the corrected check is still pending.

Before another capture, the revised activation reviews the specified stopped
attempt's protected evidence directory. It accepts either the exact three
pre-configuration artifacts or the now-reviewed privilege-failed syntax stage.
For the latter, it requires the exact root-protected diagnostic/config files,
the specific two-line engine failure, matching phase/type, an empty service-owned
syntax directory and the unchanged trial configuration, route and rule. Capture
artifacts, other errors or changed settings stop the job.
Failures now report the phase and exception type without printing private
details; a root-protected diagnostic file retains the traceback for review.

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
- [x] Pass 29 local checks covering route restrictions, capture configuration,
  fixed pings, watchdog cleanup, resource checks, result validation and launcher.
  Checks include the exact package-managed directory exception, empty YAML
  sections, prior-attempt review and safe failure diagnostics. Capture failure
  still checks service health and unchanged installed configuration, without
  losing the failed phase.
- [x] Confirm the installed configuration-directory facts from guest preflight.
- [x] Confirm the specified second attempt stopped before configuration/capture
  using its protected artifacts, not only the generic console message.
- [x] Read the third attempt's engine error and identify the identity-transition
  failure in configuration-test mode, before capture.
- [ ] Review that exact protected syntax-failure stage during revised activation.
- [ ] Validate the live configuration with the corrected Suricata `-T` check.
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
- [Suricata 8.0.7 initialization](https://github.com/OISF/suricata/blob/suricata-8.0.7/src/suricata.c)
  performs the configured privilege transition in test mode, then exits before
  dispatching capture threads; [privilege implementation](https://github.com/OISF/suricata/blob/suricata-8.0.7/src/util-privs.c)
  identifies the failing main-thread capability/identity transition.
