# Saved Live Suricata Alert: Reporting Handoff

Updated October 7, 2026. **Handoff executed; Wazuh dashboard, Indexer and SQL
verified.** The bounded live capture and independent TShark inspection pass.
Exactly one saved-live document reached the TLS-verified Indexer and SQL through
the normal scheduled loader. The existing warehouse now contains one offline
and one controlled-live validation record. The existing Power BI definitions
are updated; its fresh Desktop refresh/rendering is deferred while the owner
uses the PC. No continuous capture or browsing/phone coverage is claimed.

## Plain-English Purpose

Suricata saw our harmless marked packet and saved a detection. Now we want
that same detection to travel through the SOC's normal reporting pipeline:

```text
Previously captured packet -> saved Suricata EVE alert
                                    |
                         separate labeled test log
                                    |
                  Wazuh -> Indexer -> scheduled loader
                                    |
                          SQL -> existing Power BI
```

This is a delayed handoff of a verified live-capture test, not a new capture,
real-time monitoring or an incident. Its original packet time must stay intact;
Wazuh's later processing time and SQL's load time are different facts.

## Executed Change

1. Require the reviewed Ubuntu manager, five healthy SOC services, active
   Filebeat and a masked/inactive Suricata with no sensor process.
2. Re-read the exact completed trial. Require both PCAP hashes, the original
   result/path hashes, canonical alert identity and independent packet-review
   facts. Preserve every original event field, including its packet timestamp.
3. Test that actual alert against Wazuh's installed JSON decoder and rule
   86601/level 3. Refuse an alert threshold or automatic response that could
   discard or act on the benign test.
4. Back up Wazuh's configuration and its metadata privately. Append only one
   separate JSON source; keep the offline collector and all existing bytes.
   Preserve ownership, permissions and extended attributes; validate before use.
5. Briefly restart only `wazuh-manager`. After it announces the initially empty
   source, append exactly one saved alert. Do not send another packet or start
   Suricata. The new log remains a bounded one-event test source, not a feed.
6. Require the matching local alert: source, controlled-live label, original
   timestamp/path/protocol, ICMP fields, signature/revision/priority/action and
   Wazuh rule/decoder. Recheck services, masked state and installed manager
   settings. Attempt guarded configuration restoration after a failed change;
   never overwrite a detected concurrent edit.

The source is `/var/lib/watchtide-suricata-live-pilot/eve.json`. Its directory is
root-owned and readable/traversable by the Wazuh group (`0750`); the log is
root-write/Wazuh-read (`0640`). It uses `only-future-events: yes` and
`@watchtide_validation: controlled-live-suricata-trial`. The earlier source's
`controlled-offline-suricata-pilot` label is unchanged. Preexisting source or
label state stops the job instead of generating duplicates.

The one-time launcher uses existing SSH/sudo prompts and verified host identity,
not another key or expanded maintenance permissions. No firewall, Tailscale,
router, loader, package or always-on capture change is included. The manager
restart briefly interrupts processing. Do not rerun a completed or stopped job;
retain its private evidence for review. Recovery from power loss or a forced
termination is not proven by these regression tests.

## Reporting Update

The [SQL view](../warehouse/sql/11_network_reporting.sql) now distinguishes
`Controlled live validation` from the original `Controlled validation` and
unrecognized `Labeled validation`. Packet source `wire/pcap` alone does not tell
us whether a record came from a live trial or offline replay. A label classifies
a record; it is not, by itself, independent evidence of sensor coverage.

The guarded SQL update compared the deployed baseline, saved its original
definition privately, used a three-second lock timeout and a transaction, and
preserved all 32 report columns and the original one-record classification.
No stored telemetry, grants or loader settings changed. The existing Power BI
controlled-test measure now includes both known contexts; its Network Detection
chart has a separate live-test color. The original five pages were not regenerated.
Definitions and SQL tests pass; Desktop refresh/rendering is still a separate gate.

## Observed Proof

The owner's one-time activation returned `SURICATA_LIVE_WAZUH_LOCAL_ALERT_VERIFIED`:
the installed rule test passed, only the manager restarted, and all five guest
SOC services were active afterward. Independent read-only checks then matched
the exact Indexer document, raw SQL event and all report identity/network fields.
The controlled-live label occurs exactly once in the Indexer and SQL. The same
document was opened in the existing authenticated in-app Wazuh dashboard.

| Time (UTC, October 7) | Meaning |
|---|---|
| 14:35:45.491168 | Suricata observed the marked packet during the earlier trial |
| 15:51:26.552 | Wazuh processed the saved alert after the manual handoff |
| 15:57:43.530 | The normal scheduled loader stored the document in SQL |

The interval before Wazuh processing includes a deliberate saved-event delay;
it is not a real-time ingestion performance measurement. Original packet
microseconds remain in the Indexer source and SQL; the dashboard's formatted
date field displays milliseconds. Wazuh renders the integer flow identifier
with six decimal places. Exact decimal comparison confirmed unchanged numeric
value; SQL retains that decoded string and the complete matching raw event.

Task Scheduler returned 0 for the 11:57:41 Eastern run; the corresponding
successful warehouse run covers the event's SQL load time. The four Windows
SOC services were running. Private evidence retains the actual document ID,
addresses, original event and comparisons outside the repository. The read-only
verifier has five focused tests for identity, uniqueness, timing, context and
exact flow-number formatting. It does not insert data or run the loader.

In simple terms: the detector noticed our special test ping, Wazuh understood
its alert, and the warehouse kept the same record. SID `9000001` recognizes an
ICMP echo request containing `WATCHTIDE-PILOT`; it does not recognize malware.
The unmarked request did not alert. Suricata priority 3 and Wazuh level 3 are
separate severity systems, even though this test uses the same number.

## Acceptance Checklist

- [x] Independently inspect both actual saved packets and positive alert time.
- [x] Prepare pinned one-time handoff with 12 new focused regression tests.
- [x] Pass 19 reporting checks, including 11 actual disposable-database tests;
  no synthetic test database remains.
- [x] Apply only the new reporting context branch, preserving schema and records.
- [x] Run authenticated guest preflight, configuration/rule validation and handoff.
- [x] Find exactly one matching live-test document in the TLS-verified Indexer.
- [x] Open the same labeled document in the existing authenticated dashboard.
- [x] Verify that the normal scheduled loader stores the same document and fields.
- [ ] Refresh the existing six-page Power BI project and verify the live context,
  both timestamps, both controlled records and resettable filter.
- [ ] Explain the marker rule, observed path and missing browsing/phone coverage.

No incident-case or ATT&CK coverage credit is added for this harmless validation.
Continuous EVE collection, rotation, sustained performance, routine DNS/flow
records and iPhone telemetry remain separate stages.

See [capture evidence](suricata-live-trial.md),
[offline reporting proof](network-reporting-validation.md) and
[network maturity checklist](soc-network-maturity-plan.md).

References: [Wazuh JSON sources, labels and future-event collection](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html),
[installed-rule testing](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html).
