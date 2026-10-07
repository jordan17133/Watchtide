# Watchtide Network SOC Maturity Plan

Updated October 6, 2026. This is the expanded target and acceptance checklist,
not a claim that the planned controls are deployed. The target is a dependable,
private home SOC that explains observed device activity, detects suspicious
behavior and supports evidence-based investigation and recovery.

## Current Position

The endpoint SOC and reporting pipeline are working. The controlled offline
network event is verified through Suricata, Wazuh, the Indexer, SQL and the existing
Power BI report. Live capture and whole-home coverage are not yet established.

| Existing runbook stage | Evidence-backed status | Remaining boundary |
|---|---|---|
| 0 Lab | Hyper-V/Ubuntu lab built; production-only checkpoint creation and five active services afterward reported | Separate restore and off-VM backup validation remain open |
| 1 Wazuh | Manager, Indexer and dashboard deployed; trusted local dashboard login verified | Availability, recovery and access reviews continue |
| 2 Sysmon | Windows endpoint telemetry established | Do not assume every desired event type is collected |
| 3 Agent | Existing Windows agent/log collection established | Every additional endpoint needs its own health and event-path proof |
| 4 Event path | Existing Windows event trace completed | New devices and new telemetry types require separate traces |
| 4b Posture | Historical CIS improvement from 27.1% to 37.0%; file/logging checks, SOC Python security patch and reviewed Steam access restrictions verified | Other Python workloads, dependency/CVE review, fresh posture inventory, disk/boot and account/exposure gates remain open |
| 4c Private access | Device-scoped Tailscale SSH/HTTPS grant and trusted local dashboard access verified | Off-network administration deferred; renewal replacement, revocation and other access/recovery gates remain open |
| 5 Network detection | Suricata 8.0.7 offline positive/negative controls and full reporting trace pass | Live capture, routine network telemetry and wider coverage remain open |
| 6 Console | Public sanitized snapshot deployed | Private live analyst API/console not deployed |
| 7 Warehouse | Scheduled ingestion and read-only report views work; guarded SQL snapshot-read fix enabled | Sustained performance, late-event proof, backup/restore and actual reporting-account review remain open |
| 8 Power BI | All six existing pages rendered after refresh; network fields/metrics/filter checked | Refresh-duration benchmark and one unpublished visual-schema check remain open |

The October 6 [host exposure audit](host-exposure-validation.md) verified strict,
loopback-bound loader SSH and subsequent automatic ingestion, interpreted a
bounded blocked-packet sample and confirmed a Windows blocked-traffic collection
gap. It also identified broad Hyper-V management exceptions for workflow review.
This is partial host-level coverage evidence, not an inventory or packet feed for
every device in the home. Firewall, audit and agent settings were unchanged.

A fresh read-only warehouse check found 27,994 accumulated alerts and exactly
one controlled-validation network record. Three recent automatic loads succeeded
in 3.891, 2.398 and 3.257 seconds. These are point-in-time observations, not a
sustained availability or performance benchmark. The separately inspected
Power BI import has its own October 5, 6:20 PM Eastern snapshot time.

The [report validation](network-reporting-validation.md),
[refresh diagnosis](report-refresh-reliability.md) and
[access results](private-access-validation.md) retain their detailed limits.
The [applied software batch](software-hardening-validation.md) records the
October 5-6 patch/access results and preserved workload boundaries; it does not
replace those earlier reporting snapshots with a new refresh or posture scan.

## Questions The Finished SOC Should Answer

- Which owned devices are present, who owns them, and which addresses belonged
  to them at the event time?
- Which device contacted which destination, using which protocol, with what
  timing, direction, duration and data volume?
- Where supported endpoint telemetry exists, which process and account initiated
  the connection, and what happened before and after it?
- Is the behavior expected for that device, an authorized test, suspicious,
  confirmed malicious, or unresolved?
- Which detection matched, what evidence supports the verdict, and what would
  this rule or sensor miss?
- Are the sensors, collectors, warehouse and reports healthy, or are packets,
  events or refreshes being lost or delayed?
- How can an affected device be contained, evidence preserved and service
  restored without destroying the information needed for investigation?

## Visibility And Privacy Boundaries

The current Wi-Fi host and Hyper-V NAT VM are not a verified whole-home packet
feed. Hyper-V mirroring copies traffic from selected source adapters to a
destination adapter on the same virtual switch; it is not proof that unrelated
home Wi-Fi traffic reaches the sensor.
[Microsoft's mirroring reference](https://learn.microsoft.com/en-us/powershell/module/hyper-v/set-vmnetworkadapter?view=windowsserver2025-ps)
defines that scope. Actual topology and visibility tests decide the design.

Whole-home coverage may need a supported gateway/switch mirror or another
capture architecture, potentially with additional hardware. No purchase,
bridge-mode change or routing change is approved by this plan. A gateway feed
may still miss same-segment device-to-device traffic; test both internet-bound
and local paths, IPv4 and IPv6, guests and IoT separately.

Encrypted traffic also limits content visibility. Metadata can be useful, but
do not promise full HTTPS URLs, page contents, credentials or decrypted VPN
traffic from a passive sensor. Zeek's
[TLS logging explanation](https://docs.zeek.org/en/current/reference/logs/ssl.html)
distinguishes encrypted HTTP from inspectable connection metadata. Encrypted
DNS, newer TLS privacy features and VPN placement need explicit coverage notes.
TLS interception is not a default requirement for this home SOC.

Tailscale currently provides restricted private SOC connectivity. Ordinary
browsing-privacy routing remains deferred, as recorded in the
[separate network/privacy plan](network-coverage-plan.md).

Only monitor owned devices or traffic with permission. Personal destinations,
packet payloads, accounts and raw logs stay private. Choose collection and
retention deliberately; do not enable credential/body logging just because a
logger supports it. Public portfolio evidence remains reviewed and sanitized.

## Execution Checklist

These phases extend the existing runbook; they do not renumber its stages.

### A Reliability And Recovery

- [x] Diagnose the actual SQL deadlock, test guarded snapshot reads and verify
  the subsequent six-page Desktop report.
- [ ] Measure normal and busy host/guest CPU, memory, paging, disk and loader
  behavior over a representative observation window.
- [ ] Establish log-growth budgets and failure alerts before sustained capture.
- [ ] Validate protected off-VM configuration and SQL backups with a separate
  restore test. Checkpoints are not independent backups.
- [ ] Recheck certificate renewal/replacement, least-privilege report identity,
  MFA/account posture, device revocation and approved recovery access.

Acceptance: published scope for the tests, measured freshness and resource
budgets, recoverable backups and a tested recovery procedure. Target at least
99% scheduled-loader success over seven days and report freshness within 30
minutes under the documented workload; these targets are not an availability SLA.

### B Device Inventory And Coverage Map

- [ ] Privately inventory computers, phones, IoT and guest devices with owner,
  OS, segment, logging capability and update responsibility.
- [ ] Record physical/virtual network paths, NAT boundaries, DNS resolvers,
  IPv4/IPv6 and VPN interfaces without changing them.
- [ ] Track address-assignment history rather than treating an IP or randomized
  MAC as a permanent identity.
- [ ] Build a coverage matrix for endpoint logs, packet visibility, routine
  connection records, detections, last-seen time and known gaps.

Acceptance: every in-scope device has an explicit observed, partial, unsupported
or untested status. Absence of records is never automatically marked safe.

### C Bounded Live Suricata Trial

- [x] Review current guest interfaces, permissions, service state and resources
  through the bounded activation's reported prerequisite checks.
- [x] Prepare a separately approved, time-limited passive trial for one candidate
  interface, requiring guest route verification before capture and preserving
  the masked always-on service with a clear stop path.
- [x] Use harmless owned traffic and the proven marker rule; record packet
  counts, capture drops, alerts, CPU/memory and SOC/loader health before/after.
- [x] Independently inspect the saved positive and negative packets, their
  marker/control payloads, exact path and actual timestamps.
- [ ] Explain the test labels and exact observed/unobserved scope in the owner's
  own words.

Acceptance: a real live packet is observed and the expected rule result is
explained, with capture/resource limits recorded. This is not yet whole-home
visibility, packet blocking or permission to leave capture running indefinitely.

October 7 preparation: the [bounded live trial](suricata-live-trial.md) has
29 local regression checks, a direct-route gate, narrow test-packet filter,
resource guards and per-capture watchdogs. The fourth activation subsequently
passed its guest route/prerequisite gates and actual capture. Current device
scope is the Windows PC and iPhone; the VM is inside the PC. No browsing or phone
packet coverage is claimed.
The first authenticated attempt stopped before capture at an over-strict
directory-owner guard. The second attempt confirmed the exact package-managed
directory facts without permission changes, then stopped after staging. An
empty optional YAML section reproduced from the reviewed package is now handled
correctly. Protected prior-attempt review must pass before another capture.
The third attempt passed that review but its configuration-test identity change
failed before capture. The corrected test lets Suricata drop privileges itself;
the live non-root UID check remains required. The owner supplied the fourth
activation's pass: one captured/decoded request in each control, explicit zero
drops, one marker alert and no control alert, resource measurements and five
active SOC services. No sensor process survived. The owner then completed the
read-only transfer: both actual captures pass independent TShark inspection,
including hashes, request fields, marker/control and the alert's packet time.
The owner's explanation remains open, so Phase C's learning gate is not closed.

### D Live Alert Reporting

- [ ] Choose protected live EVE paths, rotation, access permissions, labels and
  bounded retention before changing Wazuh collection.
- [ ] Trace the same harmless live alert through the manager, Indexer, scheduled
  loader, SQL and Power BI without confusing it with the historical fixture.
- [x] Verify the saved-live pilot through the authenticated Wazuh dashboard,
  TLS-verified Indexer and normal-loader SQL, preserving original packet time.
- [ ] Refresh the existing Power BI project with both controlled contexts;
  deferred while the owner uses the PC, not treated as a failed refresh.
- [ ] Test collector/file rotation and service restart recovery without duplicate
  ingestion or interruption to existing endpoint logs.

Acceptance: the exact live document and original fields agree across layers;
freshness, duplicates, rotation and rollback are checked.

October 7: the [one-time saved-live handoff](suricata-live-reporting-handoff.md)
completed with a separate protected source/label and manager-only restart. All
five guest services were active afterward. Independent Indexer and SQL checks
found the exact document once; its original fields and packet time agree with
the reviewed capture. The authenticated Wazuh dashboard shows the same document.
The normal scheduled loader succeeded and now stores one offline and one
saved-live validation record. Existing Power BI definitions are updated, but
fresh Desktop verification is deferred while the owner uses the PC.
This bounded pilot does not close routine collection/rotation or recovery gates.

### E Routine Network Activity

- [ ] Select useful DNS, connection/flow, available TLS/HTTP metadata and sensor
  statistics rather than enabling every protocol or payload logger.
- [ ] Design a bounded routine-telemetry path with its own schema, indexes,
  validation, retention and health checks. The current loader reads Wazuh alerts;
  it does not ingest every non-alert EVE transaction.
- [ ] Report source/destination, protocol, bytes, duration, DNS outcome where
  visible, sensor/segment and original observation time.
- [ ] Add baseline comparisons by device and test outliers against benign
  explanations before calling them incidents.

Acceptance: ordinary activity is searchable without manufacturing an alert for
every connection, and growth/collection loss are measured.
[Suricata EVE documentation](https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-output.html)
supports separate protocol, flow and statistics event types.

### F Broader Network Coverage

- [ ] Compare feasible traffic-feed designs against the actual Wi-Fi/NAT setup,
  permissions, budget, downtime tolerance and recovery access.
- [ ] Prove coverage per device/segment and per path, including local traffic,
  outbound traffic, IPv6 and encrypted/VPN paths.
- [ ] Decide whether a dedicated sensor or network hardware is warranted by
  measured coverage and resources; do not stack services onto the SOC VM blindly.

Acceptance: the coverage matrix names observed devices and blind spots. Wider
coverage is earned through tests, not inferred from an installed sensor.

### G Correlation And Detection Engineering

- [ ] Complete the [analyst-toolkit lessons](analyst-toolkit-runbook.md): explain
  packets with Wireshark, check selected owned services with Nmap and, after lab
  placement/isolation, compare Burp/sqlmap/Metasploit exercises with collected
  evidence. Record operator understanding separately from automated execution.
- [ ] Correlate supported endpoint process/account evidence with network events;
  verify required event sources before promising attribution.
- [ ] Validate rules for authorized scan patterns, authentication bursts, new
  destinations, suspicious DNS/connection behavior and unexpected local access
  using controlled tests and benign comparison traffic.
- [ ] Separate rule existence, observed technique, analyst triage and validated
  attack-test coverage. The latest report's 39 observations do not prove all
  have been triaged; the documented reviewed baseline contains 38.
- [ ] Version rules, capture their intended scope, test positives/negatives and
  preserve unsuppressed parent detections and rollback.
- [ ] Evaluate Zeek for additional behavioral evidence only after useful coverage
  and a resource budget exist. If adopted, test shared Community ID correlation
  and provenance rather than assuming two logs represent the same connection.

Acceptance: each promoted rule has known data prerequisites, test evidence,
false-positive limits and a documented analyst decision path.

### H Analyst Workflow And Reporting

- [ ] Add useful private views for inventory, network timelines, DNS/flows,
  detection evidence and coverage/health gaps to the existing reporting stack.
- [ ] Tie findings to cases with an owner, evidence, verdict, time window and
  repeatable triage procedure; ordinary traffic is not an incident count.
- [ ] Test actionable notifications with deduplication, cooldowns and delivery
  failures. Do not send raw private logs to external services by default.
- [ ] Review any threat-intelligence lookup's privacy implications before sending
  hashes, destinations or artifacts outside the lab.
- [ ] Implement the future private live analyst API only with authentication,
  role-scoped actions and an audit trail; public Pages stays snapshot-only.

Acceptance: a controlled detection can be understood, investigated, assigned and
closed without exposing private evidence or flooding notifications.

### I Monitor The Monitoring

- [ ] Detect missing agent/sensor heartbeats, capture drops, alert-queue loss,
  collector lag, loader failures, stale reports, disk pressure and certificate
  expiry. Distinguish a quiet network from a dead feed.
- [ ] Test clock synchronization, delayed/out-of-order events, deduplication,
  log rotation, expected restarts and bounded late-event reconciliation.
- [ ] Automate offline checks for rules, parsing, schemas and publication;
  schedule live canary tests only with explicit scope and authorization.
- [ ] Preserve the unpublished Microsoft visual-schema limitation until an
  official schema is available; do not force a green check by downgrading it.

Acceptance: intentional benign failure tests produce the expected health signal
and recover without silently losing evidence. Suricata exposes engine statistics
and discarded-alert counters in its
[configuration reference](https://docs.suricata.io/en/suricata-8.0.7/configuration/suricata-yaml.html).

### J Response And Advanced Portfolio Work

- [ ] Document manual containment, evidence preservation and separate restore
  exercises before considering automatic blocking or remote response.
- [ ] Evaluate segmentation and device isolation with verified allowed/denied
  traffic and a tested rollback; no gateway or firewall change is implicit here.
- [ ] Extend the separate attack-test lab, phishing cases and optional AD/EDR
  work without introducing attacks into daily-use devices.
- [ ] Build a sanitized architecture/coverage diagram and demonstration showing
  a benign event, detection, investigation, case and report.
- [ ] Treat optional AI assistance as an evidence-organizing aid: untrusted log
  text must not issue instructions, and a model verdict must not authorize access,
  suppression or blocking. No external AI telemetry upload is part of this plan.

Acceptance: response exercises are safe and repeatable, claims are tied to
evidence, and the public portfolio demonstrates actual scope and remaining gaps.

## Immediate Next Step

Start with a read-only capture-point and resource review for Phase C, alongside
the inventory in Phase B and reliability gates in Phase A. Then prepare the
bounded live trial for separate review. This plan does not activate a sensor,
change SSH/Tailscale/firewall policy, collect household browsing data or authorize
automatic blocking. Each command should be explained before execution: what it
checks or changes, why it is needed, and what result would stop the next step.
