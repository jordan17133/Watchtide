# Suricata To Wazuh: Controlled Handoff

Updated October 5, 2026. Status: the first Ubuntu attempt validated the saved
EVE event and installed Wazuh rule, then stopped at the protected-parent check
before changing collection or restarting the manager. A corrected one-time job
is prepared and tested locally; its execution and indexed/dashboard proof remain
pending. No completed Wazuh collection integration is claimed.

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
- Actual saved EVE and the installed built-in rule passed in the supplied guest
  preflight result: rule 86601, level 3, decoder `json`. Suricata SID 9000001 and
  priority 3 are separate fields. A generated local manager alert remains pending.
- Then verify the same labeled event in the Indexer and authenticated dashboard.
  An alert in the local manager log alone is not dashboard proof. Dashboard
  filter: `rule.groups:suricata AND data.alert.signature_id:9000001`.
- Packet time is fixed January 1, 2026; the Wazuh processing timestamp must be
  examined separately. Classify the result as controlled offline validation,
  not an incident, live traffic observation or new ATT&CK test coverage.
- SQL ingestion, correct network reporting fields and Power BI refresh remain
  separate checks. The normal scheduled loader may collect the indexed test;
  this job neither writes SQL directly nor alters that loader.
- Limited live capture, capture loss/resource measurement and wider home-network
  visibility remain future gates. This does not inspect personal browsing.

References: [Wazuh Suricata integration](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html),
[configuration checks](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/verifying-configuration.html),
[log-test tool](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html),
[JSON collection and future events](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html).
