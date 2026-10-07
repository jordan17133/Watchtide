# Suricata To Wazuh: Controlled Handoff

Updated October 5, 2026. Status: the corrected one-time handoff completed in the
owner's supplied guest result. An independent TLS-verified, read-only Indexer
query found exactly one matching labeled alert with the original network fields.
This proves controlled offline EVE-to-SIEM ingestion, not live network coverage.
The normal scheduled loader collected the same event, independently verified in
SQL. A subsequent [reporting check](network-reporting-validation.md) opened the
exact alert in the authenticated dashboard and deployed a verified network view.
The subsequent six-page Desktop retest rendered the matching event and all four
network metrics; the new context filter also resets to All. The controlled
offline reporting trace passes; live coverage remains a separate gate.

## Purpose

The [offline test](suricata-offline-validation.md) proved that Suricata's marker
rule matches the intended synthetic packet and not two negative controls.
This step checks the next connection: can the existing Wazuh manager read that
actual saved EVE event, decode its fields and produce an alert for the existing
dashboard? It does not install another dashboard or enable network capture.

## First Attempt And Correction

The owner supplied `EVE_AND_WAZUH_RULE_PREFLIGHT_PASSED`, followed by a parent
ownership/write-permission refusal. In the reviewed job, that refusal occurs
before the pilot directory is created, configuration is replaced or the manager
is restarted. Independent checks found five active SOC services and zero indexed
pilot alerts. The exact rejected parent's metadata was not separately retrieved.

The first job placed the input beneath a shared system-log parent and required
root-only write trust. The correction keeps that guard intact and instead puts
the single-event input at `/var/lib/watchtide-suricata-pilot/eve.json`, beneath
the private application-state parent that already passed the guest check. It
does not loosen shared folder permissions or add a logging-group exception.
Parent checks now run earlier and identify the rejected path on failure.

The corrected activation also pins the stopped attempt's private evidence and
requires its original configuration and EVE checksums to match current inputs.
It refuses completed/recovery evidence, old/new pilot directories or an existing
old/new collector. It is a separately reviewed continuation, not a blind rerun.
That continuation has now completed; do not run either activation again.

## Completed Handoff

The owner supplied `STOPPED_ATTEMPT_BACKUP_MATCHES_CURRENT_CONFIG`, successful
EVE/rule preflight, a manager-only restart and
`SURICATA_WAZUH_LOCAL_ALERT_VERIFIED`. The result reported all five SOC services
active and live capture still disabled. The configured source is the bounded
controlled-test log, not the continuously captured Suricata log.

An independent read-only search used the exact reported Wazuh alert ID and
signature through the existing restricted loader tunnel. It returned one
matching document from the October 5 alert index, with these verified fields:

| Field | Verified value |
|---|---|
| Suricata signature | SID 9000001, revision 1, benign ICMP pilot marker |
| Wazuh rule / decoder | Rule 86601, level 3 / `json`; groups `ids`, `suricata` |
| Test context | `controlled-offline-suricata-pilot`, packet source `wire/pcap` |
| Network | Synthetic `192.0.2.10` to `192.0.2.20`; ICMP echo request type 8, code 0 |
| Original packet time | January 1, 2026, 00:00:01 UTC; preserved fixture time |
| Wazuh processing time | October 5, 2026, 12:43:09.941 PM Eastern / 16:43:09.941 UTC |
| Verdict | Expected controlled offline validation; not an incident |

The two numeric severity fields have different meanings: Suricata priority 3
is not Wazuh level 3. The indexed result happens to contain both values. This
test earns no new incident-case or ATT&CK technique credit.

A subsequent independent maintenance status check confirmed the five services
active. The Indexer query is proof of searchable storage, not proof that the
alert has been opened in the authenticated dashboard. A later authenticated
Threat Hunting check did open the same alert-index document, with the same label,
fields and timestamps. The view had initially selected archives; it was switched
to alerts to match the exact Indexer document. Raw screenshots stay private.

The first bounded SQL lookup preceded the next scheduled load. A later read-only
query matched the exact Indexer document and Wazuh alert in `sg.alerts`, including
rule 86601/level 3, the controlled-test label, signature, reserved network
addresses, ICMP protocol and original packet time in `raw_json`. The existing
loader's scheduled run succeeded at 16:57 UTC, inserting 67 alerts in 2.576
seconds. No manual loader run or Power BI refresh was performed. This proves
warehouse ingestion of this record, not a network-specific reporting view,
completed Power BI refresh or sustained loader performance.

## Reviewed Job

1. Require the reviewed Ubuntu manager, healthy SOC services and Filebeat, and
   an inactive, masked Suricata with no running capture process.
2. Read the saved positive/negative EVE files, completed test result and pinned
   synthetic packet fixture privately. Require the known marker, signature,
   addresses, protocol, priority, revision and original fixture timestamp.
3. Test the actual EVE line against the installed Wazuh JSON decoder and built-in
   Suricata rule using `wazuh-logtest`. Stop if the expected rule does not match,
   the alert threshold would discard it, or an automatic response may act on it.
4. For this corrected continuation, first compare current inputs with the stopped
   attempt's protected backup. Back up the manager configuration privately and
   append only a JSON collector
   for a protected, initially empty, controlled-test log. Keep existing bytes,
   file ownership, permissions and extended attributes; validate before restart.
5. Briefly restart only `wazuh-manager`. Wait for its collector to announce the
   test source, then append the original EVE line once. Collection adds an
   explicit controlled-offline-test label without rewriting the packet time.
6. Require a matching local Wazuh alert with the exact location, label, signature,
   decoder, rule and original network fields. Recheck SOC health and Suricata's
   masked/inactive state. If this phase fails after the configuration change,
   attempt to restore and validate the previous settings and restart the manager.

The protected log is bounded to one synthetic event, not the live Suricata log.
Existing automatic responses are not disabled or edited. No new SSH permissions,
package installation, firewall/Tailscale change, capture or blocking is included.
The manager restart briefly interrupts processing; this is a real change, not a
dry run. The restricted maintenance key remains limited to its original actions.
The one-time job uses normal, privately entered SSH/sudo authentication instead.

Do not rerun the job after success or failure: existing pilot state deliberately
stops duplicate ingestion. Private backup/audit files support diagnosis. Recovery
refuses to overwrite detected concurrent configuration edits and may need local
review. A forced process termination, power loss or storage failure is not a
tested restore scenario. Any already emitted test alert is retained as evidence.

## Evidence And Remaining Gates

- All 140 project tests pass, including 33 focused handoff checks. The guest job
  parses with Python 3.12 syntax. These are offline checks, not deployment proof.
- Independent preflight confirmed all five existing SOC services active and a
  working TLS-verified, read-only Indexer search through the existing restricted
  loader tunnel. It found zero SID 9000001 alerts before the proposed handoff.
- Actual saved EVE/installed-rule preflight and local manager alert generation
  passed in the supplied guest result; the independent Indexer query confirmed
  the same alert and network fields. Subsequent dashboard visual confirmation passed.
  An alert in the local manager log alone is not dashboard proof. Dashboard
  filter: `rule.groups:suricata AND data.alert.signature_id:9000001`.
- Packet time is fixed January 1, 2026; the independently inspected Wazuh
  processing timestamp is October 5. Classify the result as controlled offline validation,
  not an incident, live traffic observation or new ATT&CK test coverage.
- SQL ingestion and preservation of the network fields passed independently
  after the normal scheduled load. A later read-only network view deployment and
  report-definition validation passed; a subsequent actual Desktop retest
  verified the matching event in the existing sixth page
  ([report and limits](network-reporting-validation.md)). The guest job neither
  writes SQL directly nor alters that loader.
- The later October 7 [bounded live capture](suricata-live-trial.md) passed its
  packet/drop/resource checks and independent inspection. Its
  [separate reporting handoff](suricata-live-reporting-handoff.md) is prepared,
  not executed. Wider home-network visibility remains open; neither test
  inspects personal browsing.

References: [Wazuh Suricata integration](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html),
[configuration checks](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/verifying-configuration.html),
[log-test tool](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html),
[JSON collection and future events](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html).
