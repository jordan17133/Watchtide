# Suricata Pilot: Traffic, Rules and Reporting

Updated: October 5, 2026. Status: Suricata 8.0.7 installed and isolated marker-rule
validation passed in the owner's supplied engine result. A subsequent maintenance
check confirmed the installed package and five healthy SOC services. The corrected
[controlled Wazuh handoff](suricata-wazuh-handoff.md) completed in supplied guest
output, and independent Indexer/SQL queries verified the same labeled alert.
Suricata remains masked; no live capture feed is enabled. The exact alert is now
verified in the existing dashboard and a deployed read-only network reporting
view. The existing six-page Power BI report refreshed and rendered, including
the matching event and network metrics; live capture remains separate
([reporting proof and limits](network-reporting-validation.md)). See
the [engine validation evidence](suricata-offline-validation.md).

## What We Are Adding

Sysmon tells the SOC what happened on the Windows computer. Suricata adds
observations about the network packets available to its sensor. The aim is to
learn how to read a network alert, prove a rule with a harmless test, and trace
that alert into the existing reports.

```text
Observed packets -> Suricata rule -> EVE JSON log
  -> Wazuh collection/decoder/rule -> indexed Wazuh alert
  -> existing SQL loader -> network reporting fields -> Power BI
```

These are two different rule layers: Suricata matches packet traffic; Wazuh
interprets the resulting log and assigns its own alert level. An alert means
something matched a rule, not that a compromise has been confirmed. Start in
passive IDS mode: observe and alert, without blocking packets.

## First Scope

The existing SOC uses a Hyper-V NAT VM. No whole-home mirrored traffic feed has
been verified. A sensor running there does not automatically see traffic from
every phone, browser or Wi-Fi device. Keep whole-home visibility as a later,
separately measured goal.

The Windows host has recorded memory pressure and slow SQL loads. Do not add a
second VM, a large ruleset or an always-on capture service before checking
resources and reporting health. Prefer a short offline replay of synthetic,
benign packets for the first rule test. Offline replay proves that the rule
works on those packets, not that live network capture works.

Existing Tailscale access stays unchanged. No phone dashboard grant, extra VPN,
router purchase, bridge-mode change or TLS interception is required for this
pilot. Ordinary encrypted application traffic is not automatically decrypted
for the sensor.

## Step 1: Read-Only Ubuntu Preflight

Run in the already authenticated Ubuntu SSH session, not a new Windows prompt:

```bash
free -h
df -h /
command -v suricata || printf 'SURICATA_NOT_INSTALLED\n'
apt-cache policy suricata
```

- `free -h`: checks available guest memory before adding a process beside Wazuh.
- `df -h /`: checks room for the package and private test logs.
- `command -v`: tells us whether Suricata is already installed.
- `apt-cache policy`: shows the installed/candidate package and repository.

These commands do not install, update or restart anything. Review the output
before providing an installation command. Repository metadata can be stale;
review the actual package version, dependencies and any service auto-start
behavior before installation. Use documentation matching that version.

**Initial October 5 preflight:** the owner supplied the read-only guest checks. Available
memory and disk support attempting a bounded pilot, not an always-on capture or
resolution of the Windows/SQL performance issue. At that point Suricata was not
installed and the cached Ubuntu candidate was 7.0.3. Upstream lists 7.x as end-of-life and
8.x as stable ([release page](https://suricata.io/download/)). Review the actual
candidate from the [developer-maintained Ubuntu source](https://docs.suricata.io/en/suricata-8.0.7/install/ubuntu.html)
and simulate installation before installing anything.

The owner activated the separate temporary maintenance connection. An actual
tailnet status request succeeded; shell commands, extra arguments, command
chaining, a no-command shell request and remote port forwarding were denied.
This proves the tested local access boundaries, not off-network access, future
expiry or every forwarding mode. The original loader and network policy remain
unchanged. Private keys, device selectors and activation payloads are not
portfolio assets.

The approved source-setup action backed up APT sources privately, added the
developer-maintained stable PPA, refreshed package metadata and simulated the
installation. The actual candidate is `1:8.0.7-0ubuntu0`: ten new packages,
zero upgrades and zero removals. All five existing services were active after
this action. This action did not install Suricata; the maintenance connection
still cannot install software.

The owner separately approved and ran a one-time offline installation
job. Its reviewed package tries to enable/start the service during installation,
so the job uses a service mask and temporary Suricata-only startup denial, then
verifies the service is inactive and still masked. It pins the reviewed package
and nine dependencies, checks trusted APT origin/package digest and refuses a
changed plan. Offline tests run as the non-root Suricata account with one rule
and synthetic PCAP files. No new SSH key, live capture, packet blocking, Wazuh
edit or firewall change is included. The supplied result passed: one positive
packet produced one SID 9000001 alert; two negative controls produced zero.
All ten pinned package versions passed the job's checks, Suricata remained
masked, and all five SOC services stayed active. A subsequent maintenance check
independently confirmed the installed package and service health. Raw engine
logs have not been independently retrieved; the [report](suricata-offline-validation.md)
separates those evidence sources and remaining limits.

## Step 2: Prove One Harmless Rule

The validated [starter rule](../suricata/rules/watchtide-pilot.rules) matches an
IPv4 ICMP echo request containing the exact ASCII marker `WATCHTIDE-PILOT`.
It is a validation signal, not an attack signature or a general ping detector.

| Rule part | Meaning |
|---|---|
| `alert` | Record a match, rather than request packet blocking |
| `icmp any any -> any any` | Inspect ICMP traffic in the selected test input; this grants no network access |
| `itype:8` | Match an IPv4 echo request, not an echo reply |
| `content:"WATCHTIDE-PILOT"` | Require our deliberate test label |
| `priority:3` | Low-priority validation signal in Suricata; not Wazuh level 3 |
| `sid:9000001; rev:1` | Identify this Suricata signature and its revision; not a Wazuh rule ID |

The completed offline job syntax-tested the rule and replayed one positive
marker packet and two negative controls: a request without the marker and an
echo reply with the marker. This tests both the content match and the
echo-request constraint; the supplied result matched the expected counts.
Use only this rule for the isolated replay; check for SID collisions before
merging it into any larger ruleset. Do not download malware or scan other
people's devices. A deliberately generated match should be classified as a
controlled test, not an incident or a false positive.

Suricata supports configuration testing (`-T`), isolated rule selection (`-S`)
and offline packet replay (`-r`); see its
[command-line reference](https://docs.suricata.io/en/suricata-8.0.7/command-line-options.html).
The package version is now verified separately; documentation alone is not
deployment evidence.

## Step 3: Read The Event Before Tuning

Read a real EVE alert and answer these questions before changing severity:

| Field/context | Analyst question |
|---|---|
| Timestamp | When did it happen, in which timezone, and was a test running? |
| Source and destination | Which device contacted which other device? Interpret direction relative to the capture point. |
| Protocol and ports, where present | What kind of conversation was observed? ICMP does not have TCP/UDP ports. |
| Signature ID, revision and message | Exactly which detection matched? |
| Suricata priority and Wazuh level | What did each engine assign, rather than assuming the scales are identical? |
| Repetition and nearby events | One expected test, a recurring legitimate task, or unexplained activity? |
| Capture scope and drops | What could this sensor miss? No alerts is not proof of safety. |

Inspect the actual JSON rather than assuming every event has the same fields.
EVE can contain alerts and other event types; see the
[EVE reference](https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-output.html).
DNS/HTTP/flow records are not automatically security alerts. Keep payloads,
destinations and private device identifiers out of public examples.

## Step 4: Connect Wazuh And Reporting

Review collection only after a genuine EVE test record exists. The official
[Wazuh integration](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html)
collects an EVE file as JSON and searches alerts with `rule.groups:suricata`.
Its example uses a separate sensor endpoint with a Wazuh agent.

Our existing Ubuntu VM instead runs the Wazuh manager. Do not install an agent
over the manager. Verify its local logcollector/configuration if choosing that
temporary collection path; a future separate sensor would use its own agent.
Back up and validate any configuration before a separately planned restart.

The bounded local handoff has now passed: the supplied job validated the genuine
saved EVE, backed up settings, added one controlled-test source and restarted only
the manager. The independent Indexer lookup verified the same alert with its
label, signature, original packet timestamp and network fields. The normal
scheduled loader collected that exact record, verified read-only in SQL. Do not
rerun the activation or treat this fixed test input as a live sensor feed. The
existing dashboard now visibly shows the exact alert-index record. The network
view is deployed and the existing Power BI page now displays the same event.
All six pages rendered, and the new context selector was tested back to All.

The current loader already retains each indexed alert's full JSON in
`sg.alerts.raw_json`, but its extracted process/channel fields and current
original reporting views are Windows-oriented. The focused `rpt.network_alerts`
view now exposes the verified network fields in the sixth page. Do not change the
loader's restricted tunnel or expose the indexer/API for this integration.

Wazuh alerts are the loader's input, not every EVE flow or every archive event.
Existing archive retention is not a license to ingest unlimited network logs.
Choose event types, file permissions, rotation and storage limits before live
capture. Recheck loader duration, SQL freshness and Power BI refresh after each
increase in collection.

## Completion Gates

| Gate | Current status | Required proof |
|---|---|---|
| Maintenance access | Tested local status allowed; forbidden commands and remote forwarding denied | Other-source, future expiry/revocation and off-LAN tests remain separate |
| Resource/package review | Installed 8.0.7 verified; ten pinned versions and startup prevention passed in the supplied result | Host/SQL performance follow-up remains open before sustained capture |
| Rule engine validation | Passed in supplied engine output: one positive alert, zero alerts on two controls | Raw evidence private; no live feed or Wazuh ingestion inferred |
| Wazuh alert | Same exact alert verified in the Indexer and existing authenticated dashboard | Verdict remains controlled offline validation, not an incident |
| SQL ingestion/reporting | Exact indexed event and network fields independently matched; read-only `rpt.network_alerts` deployed and verified | Sustained performance and actual reporting-account review remain separate |
| Power BI network reporting | Passed: all six pages rendered; same record, four metrics and context reset verified; saved model/available schemas checked | Sustained refresh performance and actual reporting-account review remain separate; one Desktop schema is unpublished |
| Limited live capture | Pending | Verified interface, harmless live test, recorded load/drops and capture gaps |
| Whole-home coverage | Not verified | Supported capture feed and per-device/segment tests |

Keep raw packet captures and EVE logs outside tracked source. The reserved
`suricata/data/` directory is ignored and excluded from the public-copy process;
these controls do not sanitize arbitrary files stored elsewhere. Publish only
reviewed, sanitized test evidence, never personal browsing logs.
