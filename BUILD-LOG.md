# Watchtide Build Log

A running record of how the Watchtide home SOC lab was built, what broke, and how it was fixed. The step-by-step plan lives in [SentinelGrid-Build-Runbook.md](SentinelGrid-Build-Runbook.md). Alert investigations live in [triage/](triage/).

## Status at a glance (2026-10-05)

| Runbook stage | Status |
|---|---|
| 0. Prepare the lab (Hyper-V, Ubuntu VM) | Done |
| 1. Wazuh all-in-one stack | Done and hardened |
| 2. Sysmon on Windows | Done |
| 3. Wazuh agent on Windows | Done, agent `jordan-pc` is Active |
| 4. Prove the event path end to end | Done, traced through every layer (docs/event-trace.md) |
| 5. Suricata network telemetry | Partial: controlled offline event verified through dashboard/Indexer/SQL/Power BI; live capture and whole-home coverage pending |
| 6. Watchtide API on live Wazuh data | Private live API not started; public console serves a sanitized snapshot of real lab data |
| 4b. Posture review | Done: 437 of 447 vulnerability findings resolved (10 open, zero Critical); CIS 27.1% to 37.0% |
| 7. SQL Server reporting storage | Done: loader every 15 minutes; case log with history (`warehouse/cases.py`) meets the incident gate |
| 8. Power BI report | All six pages rendered after refresh; network fields/metrics/filter verified; saved model parsed, available-schema checks passed with one unpublished schema; imported cache ignored |
| Detection validation | In progress: controlled SSH password-guessing test detected end to end; every Critical alert since tuning explained |
| 4c. Tailscale private remote access | Trusted local HTTPS/dashboard login verified; renewal setup reported successful; phone test declined and approved off-LAN access deferred; remaining exposure/recovery/reporting gates open |

## What is running

```text
Windows 11 host (jordan-pc)
  Sysmon64 (SwiftOnSecurity config) -> Windows Event Log
  Wazuh agent 4.14.8 ------------------------------+
                                                   | TCP 1514/1515
Hyper-V VM "SentinelGrid-Wazuh" (Default Switch)   v
  Ubuntu Server 24.04.5, 4 vCPU, 8 GB RAM, 150 GB disk
  Wazuh manager -> Filebeat -> Wazuh indexer -> Wazuh dashboard (https://soc-vm.mshome.net)
                                     ^ 127.0.0.1:9200 only
                                     | SSH tunnel (restricted key)
Windows host                         |
  Task Scheduler \SentinelGrid\SentinelGridLoader, every 15 min
    loader/wazuh_to_sql.py (Python 3.14 venv) -> SQL Server 2025 Developer
      SentinelGridWarehouse: sg.* tables, rpt.* views -> Power BI Desktop
```

- The loader reaches the Indexer through an SSH tunnel because the Indexer only listens on the VM's loopback address. Its SSH key is limited in `authorized_keys` to `permitopen="127.0.0.1:9200"` with `command="/bin/false"`, so it cannot open a shell (verified). Port 9200 stays closed in `ufw`.
- The loader signs in as `sentinelgrid_loader`, an Indexer user whose role can only read `wazuh-alerts-*` and `wazuh-states-vulnerabilities-*`. TLS is verified against the Wazuh root CA.
- SQL Server is capped at 4 GB of RAM because the Wazuh VM reserves 8 GB.

- The Sysmon event channel is collected through the `default` agent group's `agent.conf`, so every future agent in that group picks it up automatically.
- The VM is reached by hostname (`soc-vm.mshome.net`) instead of IP, because Hyper-V's Default Switch hands out a new IP on every VM reboot.

## Timeline

### 2026-10-05: Assess all ten remaining scanner findings without suppressing them
- Compared the October 5 warehouse snapshot with actual installed runtimes, package manifests, signed Steam components and primary CVE/vendor records. Counts remain ten: seven High, three Medium, zero Critical; no new resolved-finding credit.
- Verified Python 3.13.15 is outside CVE-2026-3087's affected range and contains the fixed extraction path. Separately identified September 30 security releases 3.13.16 and 3.14.8 as newer than the active workload/SOC runtimes; controlled patching and environment dependency review remain pending.
- Steam's signed components report 10.96.30.42 rather than the uninstall entry's 2.10.91.91. Selected installation and registry ACLs still grant ordinary Users FullControl, so the eight findings cannot all be dismissed as inventory limitations. Confirmed permissions do not prove exploitability; no exploit, reinstall or ACL change was performed.
- The installed OpenAI.Codex package still displays ChatGPT in its manifest at the detected version. The CVE describes browser rendering without a desktop affected-version range, so applicability remains unproven. Corrected older blanket reinstall/clearance advice below. Sysmon, Wazuh and Tailscale remain running; the latest three automatic loads succeeded. See [per-finding evidence, limits and patch checklist](docs/vulnerability-applicability-review.md).

### 2026-10-05: Confirm local firewall log output and basic TPM readiness
- Owner-performed read-only checks in administrator PowerShell reported a 16,412-byte firewall log, updated at 9:42:17 PM Eastern after the logging change, with 163 `DROP` records in the last 200 lines. This passes the basic local output check based on supplied results; raw records, exact packet timestamps and sources were not independently inspected. Packet counts are not confirmed attack or attacker counts. Interpretation and Wazuh collection remain separate gates.
- `Get-Tpm` reported present, ready, enabled and activated. Basic TPM readiness passed, not disk encryption or complete firmware compatibility. The Windows system drive remains unencrypted and host Secure Boot remains off. Recovery-key custody and remaining firmware checks precede any separately approved change; no boot setting, TPM state, encryption, log permissions or service was changed by these read-only checks. See [hardening validation](docs/hardening-validation.md).

### 2026-10-05: Verify effective firewall logging and identify disk/boot gaps
- The owner's administrator run returned `FIREWALL_BLOCKED_LOGGING_VERIFIED`. Independent readback confirmed blocked logging enabled with a 16 MB limit on all three enabled profiles; incoming/outgoing defaults and allowed-traffic logging remained unchanged. The saved metadata and protected evidence-directory permissions passed review. Sysmon, Wazuh and Tailscale remained running; no rule changes or service restarts were performed by the helper.
- The first real scheduled loader run afterward succeeded with 144 alerts inserted in 2.788 seconds. No manual ingestion was needed; this confirms immediate pipeline continuity, not sustained performance or a new Power BI refresh.
- Reading the actual firewall log was denied to the normal automation account. Its ACL was left intact, and actual new-drop output/collection remain unverified. This closes the configuration check, not the end-to-end firewall telemetry gate.
- Elevated owner output reported the system drive fully decrypted with BitLocker protection off and Secure Boot disabled. Independent Windows state confirmed Secure Boot off; firmware mode is UEFI. No encryption/firmware change, TPM clearing, recovery-key disclosure or reboot occurred. Readiness and recovery-key custody must be reviewed before any approved boot/encryption change. See [hardening results](docs/hardening-validation.md).

### 2026-10-05: Close the reviewed private-file hardening check
- The owner deferred recovery work and selected hardening. No SQL backup or restore drill ran; recovery remains open.
- Reviewed private evidence, installer backups, loader credentials and the loader SSH key without reading secret contents. Three targets had extra local allow entries; their ACLs were restricted to the owner, SYSTEM and Administrators. The already protected loader key was left unchanged. All four target audits passed, with prior permission metadata retained privately and a guarded rollback helper.
- Reviewed descendant permission metadata separately; nonsecret tool-library and public-key exceptions were retained. Thirteen real dummy-file assertions passed, including restoration after a forced post-write verification failure. The next real automatic load succeeded with 102 inserted alerts in 2.895 seconds, the existing restricted maintenance connection still worked, and five guest services remained active. No manual load, service restart or network change was needed.
- Effective Windows firewall policy showed blocked-traffic logging off with a 4 MB limit despite earlier registry settings. Prepared a helper that changes only logging and verifies effective policy, with eight mocked assertions. The first non-elevated attempt refused before changes; administrator apply and actual log output remain pending. No new CIS score is claimed.
- Added publication rejection for tracked backup/database/private-key-container/capture artifacts before public replacement, plus Git exclusions and regression coverage. See [hardening validation and remaining gates](docs/hardening-validation.md). Live capture remains disabled.

### 2026-10-05: Verify the six-page report and resettable network filter
- Inspected all six pages in the existing Desktop project after refresh. SOC Overview showed 27,327 alerts; Endpoint Posture, ATT&CK Coverage, Cases and Pipeline Health rendered populated charts/tables. Pipeline Health's imported data timestamp was 6:20 PM Eastern, not a live connection or a measured refresh duration.
- Network Detection displayed one record, one controlled validation, zero unclassified and one signature. Its register matched SID 9000001, reserved addresses, ICMP, both severity scales, the document reference and both processing/fixture timestamps. This is the same offline validation event, not an incident or new attack-test credit.
- Corrected only the new context selector so it can clear back to All, tested selection/reset and saved the existing PBIP at 8:17 PM Eastern. Updated the generator and added a regression test that leaves the Endpoint Posture selector unchanged. The saved model persists single-table refresh (`maxParallelismPerRefresh: 1`); no original page was regenerated.
- Rechecked the saved model with Microsoft's parser: 18 tables, 32 network columns and four measures. All 161 publication/setup tests passed, including 11 actual isolated SQL checks; another 15 reliability tests and three mocked recovery paths passed. Ten saved network definitions passed available Microsoft schemas; Desktop upgraded the edited slicer to 2.13.0, which returned 404 from both official schema sources. No complete current-page/full-report schema pass is claimed.
- A read-only check confirmed snapshot reads still enabled; three recent automatic loader runs succeeded in 2.398, 3.257 and 2.435 seconds. Sustained memory/performance remains open. No live capture, guest restart, network/SSH change, manual load or public snapshot refresh was performed. See [report proof](docs/network-reporting-validation.md) and [reliability limits](docs/report-refresh-reliability.md).

### 2026-10-05: Apply the guarded reporting concurrency fix
- After the owner closed the report, the warehouse preflight found no other connections or transactions. An empty Desktop window remained but held no warehouse connection. Enabled committed-snapshot reads through the tested helper and independently confirmed the live setting. No client kill, forced rollback, service restart or manual loader run was used.
- The next scheduled loader inserted 91 alerts in 2.537 seconds. A network aggregate initially timed out, then completed in 0.432 seconds; a sequential read of all 18 report sources completed in 1.872 seconds. These bounded results do not close intermittent memory/performance follow-up.
- Repeated checks passed: 160 publication/setup tests including 11 actual isolated SQL tests, 15 reliability tests, three mocked recovery paths and all 11 new-page Microsoft schema checks. The existing Desktop project was reopened with single-table loading selected; confirmation, successful actual refresh and all-six-page rendering remain open. Live capture and public snapshot remain unchanged. See [deployment evidence](docs/report-refresh-reliability.md).

### 2026-10-05: Diagnose the actual Power BI refresh failure
- The owner reported an unresponsive refresh, then supplied SQL deadlock error 1205 on `rpt alerts`, with the other tables cancelled. Read-only inspection of the existing SQL event file confirmed two Power BI reads and a Python writer in a page-lock cycle on `sg.alerts`; committed-snapshot reads were disabled. This is not a Suricata incident.
- Windows had less than 1 GB available memory, 88% committed memory and substantial paging at a sampled point. Two report reads exceeded seven minutes, while the latest scheduled loader succeeded in 113 seconds versus two seconds on each of the preceding two runs. Memory pressure may contribute; sustained performance is not resolved.
- The repeat test run timed out creating its isolated database (144 tests, one setup error). Strengthened partial-creation cleanup and added guarded opt-in snapshot maintenance plus five guard/two SQL concurrency tests. A subsequent quiet rerun passed 160 publication/setup tests, another 15 reliability tests and three mocked PowerShell recovery paths. No disposable test databases remained. The next scheduled loader succeeded in 1.764 seconds before any snapshot-option change. The owner approved a quiet-window change after Power BI closes; deployment and successful Desktop refresh remain pending. No other-client rollback, session kill, service restart or live capture is included. See [refresh reliability](docs/report-refresh-reliability.md).

### 2026-10-05: Verify the dashboard and add bounded network reporting
- Opened the existing authenticated Wazuh Threat Hunting view, filtered SID 9000001 and checked the exact alert-index document against the earlier Indexer/SQL result. The same rule, validation label, synthetic addresses and packet/processing timestamps are visible. Raw screenshot evidence remains private.
- Added only `rpt.network_alerts` to the live warehouse in a validated transaction; zero telemetry rows changed. The exact pilot fields matched. Existing reporting-user simulation can read the view but not the raw alert table; no account or grant changed. Bounded verification took 0.45 seconds, not a sustained benchmark.
- Added a Network Detection page to the existing Power BI project without regenerating the original five pages. The complete model parsed with Microsoft's Analysis Services library; the new page's 11 definitions passed published schemas and offline layout/query checks. Original visual schema 2.13.0 was not yet public; the new page uses published 2.12.0. Actual Desktop refresh, DAX evaluation and visual rendering remain open.
- All 153 tests passed, including nine disposable-database SQL tests. Fixed two test-harness issues and removed this run's leftover synthetic test database before the successful cleanup-verified rerun. No live capture, blocking, Wazuh restart, network/SSH permission change, loader change or public snapshot refresh was performed. See [reporting evidence and limits](docs/network-reporting-validation.md).

### 2026-10-05: Complete the controlled Wazuh handoff and verify the same alert in SQL
- The owner supplied the corrected job's success: stopped-backup match, genuine EVE/rule preflight, manager-only restart and `SURICATA_WAZUH_LOCAL_ALERT_VERIFIED`. The measured alert uses Suricata SID 9000001 and Wazuh rule 86601/level 3, with all five SOC services active and live capture disabled.
- Independently queried the exact reported alert/signature through the existing TLS-verified, read-only Indexer tunnel. Exactly one matching document preserves the controlled-test label, synthetic source/destination, ICMP type/code, JSON decoder and January fixture time. Wazuh processed it October 5 at 12:43:09.941 PM Eastern; it is controlled validation, not an incident or new ATT&CK coverage credit.
- A subsequent maintenance status confirmed five active SOC services. The browser tab currently needs login, so visual dashboard confirmation remains pending. The first bounded SQL lookup preceded the next scheduled load; a later read-only lookup matched the exact Indexer document, rule/level, test label, network fields and fixture timestamp in `sg.alerts.raw_json`. The successful scheduled run inserted 67 alerts in 2.576 seconds. No manual loader run, Power BI refresh, further guest settings, live capture, blocking or SSH/network permission change was made. One short successful run does not close the sustained-performance gate. All 140 offline regression tests passed; the initial sandbox run was blocked by temporary-folder permissions and passed on rerun with normal filesystem access. See [proof and remaining gates](docs/suricata-wazuh-handoff.md).

### 2026-10-05: Stop safely at the input-folder guard and prepare a correction
- The owner supplied actual saved-EVE/installed-rule preflight success, then a protected-parent refusal. In the reviewed job, that refusal occurs before pilot creation, configuration replacement or restart. Independent read-only checks found five active SOC services and zero indexed pilot alerts; the exact rejected parent metadata was not retrieved.
- Kept the strict permissions guard and moved the proposed one-event input beneath the already checked private application-state parent. Prepared a corrected one-time activation that compares the stopped attempt's protected original settings/EVE with current inputs and rejects completed/recovery evidence and both old/new collector locations or directories. No shared-folder permission changes, live capture or new SSH/network permissions are included.
- All 140 tests pass, including 33 focused handoff checks. Corrected payload/hash, Python 3.12 syntax and private Windows artifact permissions passed. Corrected guest execution, a generated manager alert and indexed/dashboard/reporting proof remain pending ([scope and results](docs/suricata-wazuh-handoff.md)).

### 2026-10-05: Prepare the selected Suricata-to-Wazuh handoff
- The owner selected getting the validated alert into the existing Wazuh dashboard. Prepared one password-authenticated job to inspect genuine saved EVE, test the installed decoder/rule, back up settings and add a protected controlled-test log source. A brief manager-only restart and one preserved historical EVE append are included; live capture, blocking and new SSH/network permissions are not.
- All 134 project tests pass, including 27 focused handoff checks for preservation, event matching, duplicate refusal, automatic-response safety, configuration replacement and recovery. Python 3.12 syntax and private artifact-directory permissions pass. These are preparation checks, not Ubuntu deployment proof.
- Independent maintenance status confirmed five active SOC services and installed Suricata 8.0.7. The existing TLS-verified, read-only Indexer connection worked and returned zero pilot alerts. The guest handoff, indexed record, dashboard and SQL/Power BI trace remain pending. See [handoff scope and gates](docs/suricata-wazuh-handoff.md).

### 2026-10-05: Complete the isolated Suricata rule test
- The owner supplied `OFFLINE_SURICATA_VALIDATION_PASSED`: one positive packet produced one SID 9000001 alert, and two negative controls produced zero alerts. The job's syntax and exact ten-package checks passed; the result reported a masked Suricata service and all five existing SOC services active. No live capture, Wazuh collection change or extra SSH key was included.
- A subsequent read-only maintenance check independently confirmed installed package `1:8.0.7-0ubuntu0`, all five services active, unused guest swap and available guest memory/disk. This does not independently retrieve the raw engine logs, close host/SQL performance follow-up, or prove recovery.
- Added a sanitized [validation report](docs/suricata-offline-validation.md) and updated current statuses. Synthetic test traffic is not a compromise, new incident case or new ATT&CK coverage credit. Wazuh ingestion, SQL/Power BI trace and live/whole-home traffic coverage remain separate open gates. No further collection/configuration change was made; the next scope awaits owner choice.

### 2026-10-05: Verify restricted maintenance and prepare the offline install/test job
- The owner reported successful activation. A subsequent actual tailnet status request passed with all five existing services active. Shell commands, extra arguments, command chaining, a no-command shell request and remote port forwarding were denied. These are tested local boundaries, not proof of off-LAN access, future expiry or revocation.
- Ran the approved package-source preparation: protected APT source backup, developer-maintained stable PPA, successful metadata refresh and version-pinned simulated installation. Actual candidate is `1:8.0.7-0ubuntu0`; the preview adds ten packages, upgrades/removes none, and all five services remained active. No software was installed by this action.
- The owner separately approved preparation of a pinned offline installation/test phase. Inspected the exact package archive and its startup script, with the archive matching publisher metadata. Prepared a one-time password-authenticated job that checks trusted APT origin/digest and exact dependencies, prevents automatic Suricata startup, keeps the service masked, and runs non-root offline syntax/positive/negative tests using Scapy-generated synthetic packets. No extra SSH key, Wazuh edit, live capture, packet blocking or firewall change is included.
- All 107 project tests passed, including 20 new offline-job regression checks; Python 3.12 syntax/digest and private artifact-access checks passed. Actual Ubuntu installation/engine output remain pending. Raw package/access evidence, activation payload and synthetic PCAP artifacts stay private; no Suricata deployment or whole-home coverage is claimed.

### 2026-10-05: Guest preflight and restricted automation preparation
- The user supplied read-only guest checks showing available memory/disk for a short Suricata pilot, no swap usage and no installed Suricata. The cached Ubuntu candidate is 7.0.3; reviewed upstream guidance now marks 7.x end-of-life and recommends its maintained stable Ubuntu source. This does not close Windows host-memory or SQL-loader performance follow-up.
- After an administration SSH check failed authentication, the owner explicitly approved preparing a separate restricted automation connection. Prepared a temporary, single-device-bound key and fixed-action maintenance helper for status, approved package-source setup, installation preview and revocation. Package installation, general shells and Wazuh edits are outside this initial scope. The loader key and tailnet policy remain unchanged.
- Twenty-five new offline access-boundary tests passed, with all 87 project tests passing; Python 3.12 syntax checks and Windows key ACL checks passed. A pre-activation tailnet SSH probe rejected the new key while verifying the existing VM host identity. Ubuntu activation, actual allowed/denied tests and repository setup remain pending; no guest configuration/package change is claimed. Key material, activation payload and raw output remain private.

### 2026-10-05: Prepare the Suricata traffic/rules/reporting pilot
- The owner deferred extra VPN/router work and moved on to traffic interpretation, events, rules and reporting. Existing Tailscale permissions remain unchanged and the phone stays denied; broader privacy routing and approved off-LAN administration remain deferred/unverified.
- Reviewed the loader and reporting views: full indexed-alert JSON is retained in SQL, but extracted process/channel fields are Windows-oriented. Network reporting needs real decoded field validation, not a new public connection to the SOC.
- Prepared an alert-only ICMP marker rule and a [plain-English pilot guide](docs/suricata-pilot.md), with positive/negative engine tests, Wazuh collection, reporting and live capture as separate pending gates. The rule has not been loaded by a Suricata engine. A NAT-VM sensor does not establish whole-home visibility.
- Read-only Windows checks again found limited free memory at that moment; Hyper-V switch inventory was denied by permissions, not evidence of a missing switch. Requested read-only Ubuntu resource/package output before installation. No packages, services, firewall, VPN, Hyper-V, loader, SQL, Power BI or console snapshot changed.
- Reserved private sensor-data storage outside publication and added text scanning for rule files. All 62 publication/recovery regression tests passed, including two new rule-file/data-exclusion checks; these tests do not validate packet detection or live collection.

### 2026-10-05: Prioritize home-network privacy and security
- The owner declined temporary phone dashboard access and prioritized privacy/security. No phone grant was added. Approved off-LAN administration is deferred/unverified rather than marked complete; the working local Tailscale/HTTPS setup remains in place.
- Read-only host checks found an active Wi-Fi connection, Windows Firewall enabled on all three profiles, and Defender antivirus/real-time/behavior/download protection and tamper protection enabled. Tailscale reports Running with no exit node selected. These are bounded observations, not a full security audit or proof that no other privacy tool exists.
- Disk-encryption inspection returned access denied, leaving status unknown. No encryption setting or recovery key changed. The owner supplied the ISP-gateway model privately; its admin settings were not inspected.
- Reviewed primary vendor guidance distinguishing VPN pass-through from a gateway VPN client and warning that bridge mode turns off private Wi-Fi. Updated the [network/privacy plan](docs/network-coverage-plan.md) to prioritize supported privacy routing and recovery before gateway changes, with Suricata a separate later detection layer. No router, DNS, firewall, VPN, Hyper-V, account, loader or reporting runtime change was made; no provider, hardware purchase or new service was selected.

### 2026-10-05: Verify dashboard login and renewal timer setup
- After the user signed in, the existing private Wazuh overview was directly observed in an authenticated state. Its aggregate summary showed one Active agent and zero Disconnected agents; this is not a newly traced event or independently identified endpoint-health check.
- The user ran renewal configuration and supplied `HTTPS_RENEWAL_SETUP_VERIFIED`: the first manually invoked service run succeeded and the daily timer is enabled. Its next listed trigger is October 6 at 00:05:42 UTC (October 5 at 8:05:42 PM Eastern). The timer itself has not yet fired; actual replacement and recovery during a real renewal failure remain unproven.
- Post-setup Windows IPv4 HTTPS still returned HTTP 302 with normal trust verification. Local TCP 22/443 remained reachable and 9200/55000 unreachable. The latest loader task reports result zero, but its timing is not established relative to renewal setup; no post-renewal SQL audit or Power BI refresh is claimed.
- The phone is the only available off-network client and remains denied. A proposed temporary phone-only TCP 443 test needs current-policy review and separate approval, removal afterward and a fresh denial test. No phone grant, Funnel, firewall, loader, database or public-console runtime change was made in this follow-up. Stage 4c remains in progress. See [login and renewal evidence](docs/private-access-validation.md#authenticated-dashboard-and-renewal-timer).

### 2026-10-05: Install dashboard HTTPS and verify Windows trust
- The user ran the private one-time installer and reported both preflight and local HTTPS installation success, a new private rollback copy, and five active services. Only browser-facing certificate paths changed; original certificates and upstream TLS settings were retained, and only the dashboard restarted.
- Independent Windows checks resolved the expected tailnet IPv4 address, received HTTP 302 with normal HTTPS validation, and passed a separate default-validation TLS handshake. The served Let's Encrypt certificate expires January 3, 2027. No trust import, validation bypass or login credentials were used.
- A fresh local approved-source TCP check still reaches 22/443 and fails on 9200/55000. The latest scheduled loader task reports result zero; this is metadata, not a controlled event trace, SQL audit or Power BI refresh, and the host memory-pressure follow-up remains open.
- Prepared a separate root-owned renewal helper and daily timer setup. Eighteen additional offline tests passed; sixty total tests cover installation, renewal and publication. At this preparation point the helper was not yet deployed, and mocked rotation/rollback tests were not live Linux renewal proof.
- Browser login and renewal setup were next at this installation point; their subsequent results are recorded above. Approved off-LAN access, denied-path/revocation checks and reporting continuity remain open. No Funnel, network-policy, firewall, loader, SQL, Power BI or public-console change was made in this follow-up. See [installation evidence and limits](docs/private-access-validation.md#dashboard-https-installation-and-windows-verification).

### 2026-10-05: Stage Tailscale HTTPS and prepare the existing dashboard installation
- After the public certificate-name disclosure explanation, the user requested the approved certificate. The first attempt failed while HTTPS issuance was disabled; authenticated DNS settings subsequently confirmed it enabled, with MagicDNS already on.
- The user reported `CERTIFICATE_READY` from the block that verifies the chain, hostname and matching key. This is user-reported staging, not independently inspected certificate files, a dashboard installation or a trusted login.
- Prepared a private installer that changes only the two browser-facing TLS paths, retains original certificates and upstream TLS settings, keeps a root-only rollback copy, and restarts/checks only the existing dashboard. Sixteen offline installer tests and twenty-six publication-privacy tests passed; Linux installation and permissions remain unverified.
- At this staging point installation, browser login and scheduled renewal were pending; the subsequent installation is recorded above. No Funnel, access-rule, firewall, loader, SQL, Power BI or public-console runtime change was made during staging. The private-access milestone remains in progress. See [HTTPS preparation and limits](docs/private-access-validation.md#current-configuration-backup-and-https-preparation).

### 2026-10-04: Repair Hyper-V backup helper and create a recovery baseline
- A user-provided checkpoint list showed an October 1 recovery point predating VPN work. An initial production-only checkpoint attempt failed with "The operation is not supported"; no old checkpoint was applied or deleted and standard fallback remained disabled.
- Guest diagnostics found the backup device but no VSS helper unit/process. The user installed three kernel-matched Ubuntu cloud-tools packages after a no-upgrade/no-removal preview. The installed helper then stopped immediately while its device dependency lacked the expected systemd tag; reloading installed udev rules and issuing a targeted device change event resolved the observed startup issue.
- User-provided output showed the VSS helper running and all five guest services active before checkpoint creation was reported. A later screenshot confirmed Production-Only settings with standard fallback unchecked, and the user reported successful creation followed by five active guest services. The new checkpoint name/timestamp/type still need confirmation; separate backup/export and restore validation remain open.
- Recorded these user-performed integration-service and checkpoint changes without changing Wazuh, firewall, loader, certificates or tailnet permissions. The overall private-access milestone remains in progress; raw logs and screenshots stay private. See the [recovery follow-up](docs/private-access-validation.md#production-checkpoint-recovery-follow-up).
- A read-only Windows inventory found the original installer backup outside Git. Folder/archive ACLs inherit read access for a local group containing two local accounts. No backup contents were read or permissions changed; review intended readers/storage protection before creating fresh current configuration copies. See the [bounded backup review](docs/private-access-validation.md#private-backup-inventory-and-local-permissions).

### 2026-10-04: Complete supplied filter-table configuration review
- Reviewed the user's full IPv4/IPv6 filter exports, whose headers identify the nf_tables backend. Existing private IPv4 TCP 22/443/1514/1515 exceptions match the UFW summary; there are no user-defined IPv6 TCP service allowances. No reachable rule permitting new non-Tailscale TCP API/indexer access was found outside the loopback and established/related exceptions.
- Recorded Tailscale-before-UFW input and forwarding precedence. The default FORWARD DROP policy does not negate Tailscale's earlier forwarding accepts, and the presence of those rules does not establish enabled kernel routing, subnet advertising or exit-node use.
- The transcript reports an authenticated local SSH session, not authenticated off-LAN tailnet access. Kept the raw transcript, login links and private inventory out of publication. Configuration review is complete; recovery/backups, trusted HTTPS and live exposure tests remain open. No runtime setting changed. See [full filter-table follow-up](docs/private-access-validation.md#full-filter-table-follow-up).
- Fresh Windows TCP probes selected the local Hyper-V route for the existing local address and Tailscale for tailnet IPv4/IPv6. Local 22/443/1514 connected; 1515/9200/55000 did not. Tailnet results reproduce the earlier management-only table. The newly observed local enrollment-port gap needs listener/service diagnosis before enrollment; no service was enabled.
- A user-provided screenshot shows an authenticated Ubuntu console through Hyper-V VMConnect. Recorded console availability separately from unverified checkpoint/backups and restore capability; the raw screenshot remains private. See [fresh probes and console evidence](docs/private-access-validation.md#fresh-local-probes-and-console-evidence).
- A pre-push inventory check found internal addresses in an older public SSH case report. Added exact publication replacements using labeled documentation addresses, rejection checks for known private addresses and Tailscale login links, and regression tests. Retained original evidence privately and corrected the historical report's overbroad public-exposure claim. This sanitizes the current public copy, not earlier Git history.

### 2026-10-04: Read-only firewall rule review
- User-provided UFW output reported an active incoming-deny firewall with SSH/dashboard/agent allowances from broad private IPv4 ranges. These existing ranges accommodate Hyper-V Default Switch changes; no rules were narrowed or added.
- The reported IPv4/IPv6 INPUT policies are DROP, but Tailscale chains run before UFW and accept traffic on the Tailscale interface. Documented the separate role of the restricted tailnet policy, rather than treating UFW as an additional service restriction for that accepted traffic.
- Recorded configuration observations without private device addresses or raw terminal output. Full filter-rule review, public reachability, trusted HTTPS and recovery checks remain open; the private-access milestone is still in progress. See [firewall review](docs/private-access-validation.md#user-reported-firewall-rule-review).

### 2026-10-04: Phone enrollment and first off-LAN denial observation
- Verified an enrolled iPhone in the tailnet admin console and reread the unchanged Windows-to-VM TCP 22/443 policy. No phone permissions were added; a fresh Windows probe still reached dashboard TCP 443.
- The user reported a private dashboard timeout and explicitly confirmed Wi-Fi was off, Tailscale remained Connected, and public websites loaded over cellular. Recorded this as one user-performed IPv4 HTTPS denial observation, not full service-matrix, authenticated access or public-exposure proof.
- User-provided Ubuntu output showed all four SOC/Tailscale services active, the dashboard listening only on IPv4, the indexer on loopback, and SSH/API listeners on both families. The SSH route/trust and firewall enforcement remain unverified. No service, firewall, certificate or restricted-loader changes were made. See [access validation](docs/private-access-validation.md#phone-enrollment-and-off-lan-denial).
- Clarified the next execution order around whole-network SOC coverage: finish current access/health gates, verify the capture point, build a Suricata pilot, then expand measured coverage and separately evaluate whole-network browsing privacy. The phone remains a denied test client; no permanent phone grant, privacy provider, exit node, router or sensor deployment was added. See the [coverage plan](docs/network-coverage-plan.md).

### 2026-10-04: VPN recheck and runtime follow-up
- Reran all 23 publication tests, 15 loader/case tests and three mocked recovery paths successfully. Read the saved Tailscale policy and its four tests without editing; local IPv4/IPv6 port probes reproduce the approved management-only results.
- Verified TLS handshakes identified an untrusted issuer chain in system trust and certificate-name mismatches for tailnet IP/MagicDNS access with the existing Wazuh CA. No warning bypass, credential submission, certificate issuance or trust-store change was made. Trusted dashboard access remains open; public certificate-name disclosure needs review before choosing a certificate route.
- A read-only SQL connection initially timed out, then succeeded. Run 392 imported 117 new alerts but took over eight minutes. Low host memory and SQL paging event 17890 warrant a performance recheck after releasing nonessential workloads; no service restart or memory setting changes were made.
- Corrected two runbook summaries that still described the pre-restriction VPN state. Power BI refresh, current VM-console/checkpoint recovery, authenticated logins, off-network and unprivileged-device tests remain unverified. See [VPN results](docs/private-access-validation.md) and [runtime evidence](docs/reliability-validation.md#subsequent-runtime-follow-up).

### 2026-10-04: Reliability fixes after workspace review
- Removed historical rule verdicts from individual alerts; the exporter and publication validator keep alerts untriaged until event-specific evidence can be linked. Rule and ATT&CK views now label historical context; existing case verdicts remain intact.
- Loader errors for missing or incomplete indices preserve the previous vulnerability snapshot. Daily retained-index reconciliation and `--reconcile` recover late alerts within source retention, with document-ID deduplication and historical summary refresh.
- Publication rejects duplicate JSON keys before validation. New cases require a timezone-aware incident window. Hardening apply/revert attempts and verifies agent restart in a `finally` block, including on failure.
- Offline checks: 23 publication tests, 15 loader/case tests and three mocked PowerShell recovery paths. Removed 555 inherited verdicts from the existing snapshot without changing other values or its export date. No live hardening, case edits, SQL migration or tailnet policy change was executed. The scheduled loader can use the new source on its next run; timing and Power BI refresh still need verification. See [reliability validation](docs/reliability-validation.md).
- Read-only Indexer compatibility check: 21,249 retained alerts fetched in 22 pages, 10 exact vulnerability results, 1.58 seconds for the tunnel/query check; no SQL writes. Desktop/mobile console checks passed and its genuine preview image was regenerated. This is not a complete loader benchmark or an off-network VPN test.
- First scheduled reconciliation on the updated source: run 391 at 14:57:42 EDT succeeded in 30 seconds, fetched 21,276 alerts, inserted 96 and snapshotted 10 vulnerability findings. None of its inserts were outside the previous lookback window; controlled late-event evidence and Power BI refresh remain pending. The public snapshot was not refreshed from this run.

### 2026-10-04: Publication safeguards
- Added field-scoped exact approval for snapshot display text and a strict final schema; unfamiliar text is redacted, unreviewed report links omitted, and invalid snapshots rejected before existing files are replaced. Added offline regression tests, including the export flow with a fake SQL connection.
- Generated examples use neutral Windows profile and machine SID placeholders. Parsed the generated XML and verified all 21 rewritten FIM paths, including secret and startup paths under the user profile. Private deployed configurations were not edited.
- Migrated the existing snapshot to hashed event references without changing timestamps, counts or its export date. Corrected the console's exposure claim; external testing is still pending. See [publication safety](docs/publication-safety.md) for remaining limits.

### 2026-10-03: Public repository privacy audit
- Reviewed current public files, reachable Git history, commit email metadata, and ten distinct image versions. Gitleaks returned zero secret findings, but a separate inventory review identified historical username/hostname disclosures and current personal home-directory paths.
- Publication privacy remains in progress: free-text snapshot validation, path placeholders, accurate exposure claims, and account/external-access checks still need work. No history rewrite or credential changes were made. See [the bounded audit report](docs/public-privacy-audit.md).

### 2026-09-29: Planning and host prep
- Checked host capacity (Ryzen 9 8945HS, 28.8 GB RAM) against the Wazuh all-in-one minimum (4 vCPU, 8 GB RAM, 50 GB disk).
- Enabled Hyper-V with `Enable-SentinelGridHyperV.ps1`, downloaded Ubuntu Server 24.04.5, and verified the ISO's SHA-256 hash.
- Wrote `Create-SentinelGridWazuhVM.ps1` to build a Generation 2 VM with Secure Boot and fixed memory.

### 2026-09-30: Wazuh stack, endpoint telemetry, first triage
- Rebooted to activate Hyper-V, created the VM, and installed Ubuntu with OpenSSH.
- Installed Wazuh 4.14.8 with the assisted all-in-one installer (after fixing the failures below).
- Installed Sysmon with the SwiftOnSecurity configuration.
- Deployed the Wazuh Windows agent from the dashboard and confirmed it went from Pending to Active.
- Pushed the Sysmon collection config through the `default` group and confirmed Sysmon alerts in Threat Hunting: 31 alerts in 15 minutes, mapped to MITRE ATT&CK techniques T1105, T1059.001, T1070.004 and T1087.
- Investigated three level 15 alerts and closed them as false positives caused by the installers. See [the triage report](triage/2026-09-30-rule-92213-installer-false-positive.md).
- Hardened the VM (backup, admin password rotation, `ufw`, `wazuh-clean` checkpoint).

### 2026-09-30 (afternoon): Posture review, SQL warehouse, second triage
- **Vulnerability Detection baseline: 445 findings (99 Critical, 247 High, 91 Medium, 8 Low).** Firefox 146.0, unused since December 2025, caused 393 of them (88%).
- Uninstalled Firefox and the Mozilla Maintenance Service, upgraded pip, pypdf and idna, and installed Python 3.14 because Python 3.11 no longer gets Windows installers. **Result: 39 findings (0 Critical, 21 High, 16 Medium, 2 Low).** Remaining: Python 3.11.9 (16), Steam (8), and packages in the Python 3.11 environment (PyJWT, setuptools, cryptography, urllib3).
- Installed SQL Server 2025 Enterprise Developer (default instance `MSSQLSERVER`) and built `SentinelGridWarehouse` with idempotent scripts in `warehouse/sql/`.
- Wrote `loader/wazuh_to_sql.py`: incremental, keyed by Indexer document ID, with a 10-minute overlap window and a run log in `sg.load_runs`. First run loaded 2,306 alerts and 39 vulnerability findings; the second run fetched 473 overlapping alerts and inserted only the 1 new one.
- Warehouse analysis surfaced 506 level 15 alerts in 12 hours. 478 were PowerShell's own policy-test file, created every time three automation watchdog tasks started PowerShell every 5 minutes. See [the second triage report](triage/2026-09-30-rule-92213-powershell-policy-test-noise.md). A narrow tuning rule is proposed there.

### 2026-09-30 (night): Stage 4 trace, Defender telemetry, compromise sweep
- Stage 4 controlled test: traced one tagged `whoami` execution from Sysmon (event ID 1, record 44012) to Wazuh rule 92032 (0.5 seconds later), the Indexer, and the SQL warehouse (about a minute later), all joined by the Indexer document ID. Write-up: [docs/event-trace.md](docs/event-trace.md). Found two visibility gaps: Wazuh indexes only rule-matched events (Notepad's launch never reached it), and `nslookup` bypasses the DNS Client that Sysmon's DNS logging relies on.
- `GET _cat/indices/wazuh-*?v`: 18 indices, all green.
- Precautionary read-only compromise sweep: every startup entry, non-Microsoft scheduled task and auto-start service was signed by a known vendor or belonged to known software, and every live outbound connection was explained. Flagged three Chrome extensions with all-site access (one also reading cookies) for removal, and a discontinued startup app (Snap Camera).
- Added `Microsoft-Windows-Windows Defender/Operational` to the `default` group's `agent.conf`. The agent restarted itself and Wazuh then recorded the first full Defender scan end to end: rule 62108 "Antimalware scan finished" (Full Scan, 1:14:24, matching Windows Security), 66 cloud-lookup events, a platform health event, and no detection events. Windows Security agreed: 0 threats in 2,189,640 files.
### 2026-10-01: Full event archive and data lifecycle
- Grew the VM disk from 50 GB to 150 GB (`Grow-SentinelGridVMDisk.ps1` merged the two checkpoints, then expanded the VHDX online) and the Ubuntu filesystem to 145 GB (23 GB used).
- Turned on full event archiving (`logall_json` plus Filebeat archives). The first `wazuh-archives-*` index was green within minutes.
- Retention at every layer, so storage cannot grow without bound: ISM policies delete archive indices after 30 days and alert indices after 365 (all three existing indices confirmed managed); a nightly cron job recycles Wazuh's raw rotated logs (archives 7 days, alerts 90); the SQL warehouse keeps every alert row with permanent daily summaries under a 100 GB cap.
- Proof: Notepad launches now appear in Wazuh as Sysmon event ID 1, closing the visibility gap found in the Stage 4 trace.
- Observation: the Wazuh server's own dashboard web logs (one event per file the browser loads) are a large share of archive volume, and viewing the archive adds to it. Candidate for a filter.

### 2026-10-01: File integrity monitoring and archive noise filter
- **FIM on what matters most.** `wazuh/agent/default-agent.conf` (pushed through the `default` group) watches 21 paths with `whodata`, so every alert names the user and process behind a change. Tags: `sg-secrets` (automation app `.env` and API configs, loader `.env`, `.ssh`, the private Wazuh secrets folder), `sg-sched-exec` (every script Task Scheduler runs for the automation app), `sg-persistence` (both Startup folders, the user's Run and RunOnce keys). `report_changes` is deliberately off so secret contents never leave the PC. FIM sees changes, not reads.
- **Severity rules** in `wazuh/rules/sentinelgrid_fim.xml` raise those paths to level 12 (secrets, T1552.001; scheduled automation scripts, T1053.005) and level 10 (Startup folders and Run keys, T1547.001). Patterns were tested against all 24 monitored paths and 8 decoys first, which caught a regex bug (`runonce?` instead of `run(once)?`) before deployment.
- **Live test:** creating, editing and deleting a file in `.ssh` produced three alerts within about 2 seconds each: first at stock levels 5 and 7, then, after the rules, rule 100110 at level 12, each naming `Jordan` via `powershell.exe`.
- **Archive noise filter.** Measured first: journald was 22% of archived events, and the dashboard's own HTTP response logs were a large part of it, growing with every page viewed. Filtered at collection so logins, failed or denied requests (401/403) and dashboard errors are kept. Result while actively browsing and logging in: 14 dashboard lines in the archive versus 343 before, including the login. sshd and PAM events still arrive (verified with the loader's own SSH login).

### 2026-10-01: PowerShell script block logging
- Enabled with `windows/Set-PowerShellScriptBlockLogging.ps1` (run elevated; `-Disable` reverts): the Group Policy setting that records every PowerShell script block as event 4104, after deobfuscation, plus a larger local log (15 to 100 MB). Invocation logging (4105/4106) left off as noise.
- Collected through the `default` group's `agent.conf`, with an event channel query that ships only event 4104.
- Verified at every hop: the policy and log size on Windows, the agent receiving the new config, a tagged test command recorded locally as event 4104, and 61 script blocks in `wazuh-archives-*` within 15 minutes, including the full source of the automation app's watchdog scripts as Task Scheduler ran them.
- A harmless script block produces no alert, which is correct: Wazuh's PowerShell rules fire on suspicious content. The full event archive is what keeps every script block searchable for 30 days.
- Lesson: an index pattern caches its field list when it is created. `scriptBlockText` was unsearchable in Discover until the `wazuh-archives-*` field list was refreshed.
- Caveat recorded in the script: anything typed into a PowerShell command, including a secret, is now logged.

### 2026-10-01: CIS benchmark baseline and hardening
- Baseline from Wazuh SCA (CIS Microsoft Windows 11 Enterprise v3.0.0, 482 checks): **27.1%**. Triaged all 345 failures into changes worth making on a personal PC and changes accepted with a written reason. Full write-up: [docs/cis-baseline.md](docs/cis-baseline.md).
- `windows/Set-SentinelGridHardening.ps1` (run elevated, saves prior state, `-Revert` restores it): 16 audit subcategories, firewall drop logging, 5-attempt lockout, NTLM and SMB hardening, stricter UAC, LSASS plugin block, AutoPlay/AutoRun off, Print Spooler and UPnP Device Host disabled, Remote Assistance off.
- Result confirmed by Wazuh's own rescan: **37.0%**, 47 checks fixed, 0 regressions, 1 accepted (UEFI-locked LSASS protection; LSASS protection itself was already on).

### 2026-10-01 (afternoon): Power BI pages 2-4
- **Report as code.** Converted the .pbix to a Power BI Project ([powerbi/SentinelGrid.pbip](powerbi/SentinelGrid.pbip)): the model is TMDL and the pages are PBIR JSON, so the definitions live in Git while the data cache (`.pbi/cache.abf`) stays ignored. Removed 16 hidden auto date/time tables. Pages 2-4 and the new tables are generated by [powerbi/tools/](powerbi/tools/); their output is byte-identical to Power BI's own save, so a re-run on an unchanged report leaves Git clean. Every measure was checked with DAX queries against the open model.
- **Before numbers rebuilt from evidence** ([06_posture.sql](warehouse/sql/06_posture.sql)). The daily vulnerability snapshots began after the Firefox removal, but Wazuh had sent a "was solved" alert for each fixed CVE: 406 of them, plus 39 still open, is exactly 445 (Critical 99 to 0). The first CIS scan's per-check alerts (128 passed, 345 failed) rebuild the 27.1% baseline; summary alerts give 33.6%, 36.6%, 37.0%; every section matches [docs/cis-baseline.md](docs/cis-baseline.md). The loader extracts these events on every run.
- **ATT&CK** ([07_attack_coverage.sql](warehouse/sql/07_attack_coverage.sql)): 33 techniques fired here, each with the rule behind most of it and its triage verdict. "Coverage" needs to know which techniques the deployed rules can detect, which only the Wazuh server knows: [wazuh/manager/export_attack_catalog.py](wazuh/manager/export_attack_catalog.py) exports it and [warehouse/load_attack_catalog.py](warehouse/load_attack_catalog.py) loads it.
- **Pipeline health** ([08_pipeline_health.sql](warehouse/sql/08_pipeline_health.sql)): 99.0% loader success over 7 days, alert-to-SQL latency median 6.4 minutes and 95th percentile 14.9 (the 15-minute schedule), warehouse 69 MB of its 100 GB cap.
- Rule descriptions that embed event fields carried Wazuh's doubled backslashes (the same cause as problem 7). The loader now unescapes descriptions; the backfill cleaned 165 alert rows and 5 rules.
- Finding: rule 92217 (577 alerts, mapped to T1570 Lateral Tool Transfer) is installers and updates writing into System32 (SQL Server setup, AMD bug report tool, .NET native image compiler, Gaming Services). Very likely benign; not yet triaged, and the page says so.

### 2026-10-01 (evening): Detection validation and triage

- Took the Hyper-V checkpoint `sentinelgrid-pre-attack-2026-10-01` as the rollback point for attack testing.
- Controlled test: failed SSH logins against the Wazuh server. Wazuh raised rules 5710, 5503 and 5760 (T1110.001) and escalated to level 10 (rule 2502); the alerts were in SQL about 10.5 minutes later. The brute-force correlation rule did not fire because the test stayed under its threshold, which is documented as a gap. See [the report](triage/2026-10-01-ssh-failed-logins-wazuh-server.md).
- Traced every Critical alert since tuning (51) and every rule 92217 alert (577) to a named process. The AMD cluster turned up repeated graphics driver crashes on the host; the `Add-Type` cluster was the build tooling and stays at Critical on purpose. See [the report](triage/2026-10-01-rules-92213-92217-after-tuning.md).
- Baseline review of the 28 remaining rules behind fired techniques: 27 benign with a named source (Wazuh's own CIS checks, Windows state keys, the build tooling, installs), and one low-risk item whose source process is not confirmed (loopback admin-share access). Every fired technique on the ATT&CK page now carries a verdict. See [the report](triage/2026-10-01-baseline-review-remaining-rules.md).
- Case log: `sg.cases`, `sg.case_rules` and `sg.case_events`, managed with `warehouse/cases.py` (open, assign, note, close). Seeded with the six investigations and one open case split out of the baseline review. A fifth Power BI page, Cases, shows owner, verdict and hours from first alert to verdict (median 13.0). This meets the Stage 7 gate: assigning a case persists in SQL with its history, and `rpt.cases` returns case counts without any credentials.
- Triage verdicts are stored in `sg.rule_triage`, so the ATT&CK Coverage page shows each technique's verdict next to its alerts.
- This public copy is generated by a script kept in the private repo: it replaces details of a private automation workload, then fails if any private term survives or if the rewritten monitoring rules stop matching.

### 2026-10-02: Workload migration and FIM repoint

- The monitored automation workload moved to a new folder and from Python 3.11 to 3.13 (copy-and-keep-backup, verified by identical backtests). Its migration report was checked independently: every process and enabled scheduled task runs on 3.13, no enabled task uses 3.11, and all 16 monitored files exist at the new paths.
- File integrity monitoring and rules 100110/100111 were repointed to the new folder and tested against all 16 monitored paths plus 4 decoys (including the old folder and the new virtual environment's interpreter): 16 match, 0 decoys match. The first pass missed rule 100110 because its folder name sits inside a regex group; the test caught it.
- Deployed to the Wazuh server (rules and the `default` group's agent.conf, manager restarted, `active`); the Windows agent received the new config one minute later, watching all 16 new paths and none of the old ones.
- Python 3.11 uninstalled after confirming nothing used it (0 processes, no enabled task); the rollback stays possible by reinstalling 3.11.9 and restoring the saved package list. Its 16 interpreter findings should clear on Wazuh's next software inventory scan; Python 3.13.15 brought 1 new finding. Leftover Python 3.11 entries in the user PATH are being removed, since a missing user-writable folder on the PATH can be used to plant a fake `python.exe`.
- The new virtual environment carried over cryptography 47.0.0, PyJWT 2.12.1 and urllib3 2.6.3; upgrading them there is the next patch step.

### 2026-10-02: Renamed to Watchtide

- "SentinelGrid" collided with a managed security company of the same name and with Microsoft Sentinel, so the project became Watchtide (one other GitHub repository uses the name). Public branding, the console, docs, custom rule descriptions and links were renamed; internal identifiers kept the original name so nothing running had to change. The repository moved to github.com/jordan17133/Watchtide (GitHub redirects the old address) and the console to jordan17133.github.io/Watchtide.
- Case SG-009: rule 60228 (scheduled task created, T1053) was explained by a signed AMD software update and the documented migration's new tasks. All 37 fired techniques have a verdict.

### 2026-10-02 (evening): Vulnerability rescan after the Python retirement

- Wazuh's next inventory scan confirmed the result: open findings fell from 39 to 10 (zero Critical). Retiring Python 3.11 cleared its 16 interpreter findings and the 14 findings in libraries installed in it (cryptography, PyJWT, urllib3, setuptools). Two new findings appeared (Python 3.13.15, a newer ChatGPT build), so 447 have been found in total and 437 resolved.
- Remaining at that scan: Steam 8, Python 3.13.15 1, ChatGPT 1. The initial interpretation was that Steam needed a reinstall because its uninstall version had not changed; the October 5 [applicability review](docs/vulnerability-applicability-review.md) supersedes that blanket advice with component and permission evidence.
- Caveat: Wazuh's vulnerability detection reads the system-wide Python, not virtual environments. The migrated workload's virtual environment still carries the older cryptography, PyJWT and urllib3, so patching them there stays on the list even though the scanner cannot see them.
- The console gained link-preview tags and a preview image, so shared links (LinkedIn, chat apps) show a card.

### 2026-10-03: Private remote-access decision and next milestones

- Started the Tailscale setup chapter to add private remote administration of the Hyper-V/Ubuntu SOC. Installation on both devices, policy enforcement and reachability are still awaiting verification; this entry records the decision and plan, not a completed control.
- Added [docs/private-access-plan.md](docs/private-access-plan.md) with intended service access, a safe change sequence, allowed/denied tests, pipeline checks and rollback. Kept the existing loopback indexer, restricted loader tunnel and private SQL design as requirements.
- Put current work and the next milestones near the top of the README: private access, one remote endpoint, then more detection validation. Added Stage 4c to the runbook and reordered the roadmap around the same gates.
- Clarified the public/private boundary for the future live API: employers use the public sanitized snapshot; live administration and analyst actions stay private.
- Pending evidence: off-LAN admin access, denied unprivileged access, no direct public management access, and healthy agent/loader operation. No VPN test result or runtime configuration change is claimed by this documentation update.

### 2026-10-03 (continued): Tailscale enrollment and initial checks

- Corrected the install URL: `https://tailscale.com` is the homepage; the Linux installer is `https://tailscale.com/install.sh`. The earlier shell syntax error came from passing the webpage to `sh`. SSH was still reachable afterward.
- Windows admin host and Ubuntu VM enrolled successfully. Ubuntu's status output listed both devices; the Windows client independently confirmed its Running state and both devices online.
- Local TCP tests over the Tailscale path: 22 and 443 reachable; 9200 unreachable; 55000 reachable. Repeated the 55000 check with interface details to confirm it used Tailscale. This leaves an API restriction issue open, not a completed least-privilege result.
- The latest scheduled loader result was 0 (success). This is task-level continuity evidence, not a substitute for checking a new alert in SQL and a Power BI refresh.
- Published a [sanitized initial validation report](docs/private-access-validation.md) without actual addresses or account/device inventory. No policy or firewall changes were applied; authenticated login, off-LAN access, denied-source tests and full pipeline verification remain pending.

### 2026-10-03 (continued): Policy review remains the next VPN step

- Reconciled the private source with the published enrollment report. Device enrollment remains complete; the overall VPN security milestone remains in progress. Local port checks and a loader task result do not establish authenticated access, denied-source enforcement or a new event reaching Power BI.
- Made review of the current Access controls policy an explicit prerequisite before any change. The policy has not yet been supplied for review. The plan now calls out additive grants, legacy ACLs, preserved loader/internal service access, and a separate off-LAN client while the Hyper-V host remains running.
- Extended the private publisher's inventory redaction and rejection checks. Current public documentation uses a neutral local hostname and SSH account placeholder; literal tailnet addresses are rejected. This changes the current public copy, not previously published Git history.
- This update is documentation and publication work only. No tailnet policy, operating-system firewall or Wazuh service configuration was changed.

### 2026-10-03 (continued): Reviewed Tailscale restrictions and post-change ingestion

- Read the actual policy in the authenticated admin console before changing it. It contained a default all-device/all-port grant and default self-device Tailscale SSH authorization; only the Windows admin host and Ubuntu VM were enrolled. Saved the exact original outside Git.
- After explicit approval, replaced the broad grant with selected Windows-device-to-VM TCP 22/443 permissions using IPv4/IPv6 host aliases, and removed the unused default Tailscale SSH authorization rule. No tags, exit node, subnet route, OS firewall, listener, loader target or Wazuh settings were changed.
- The first save was rejected for mixed IPv4/IPv6 test destinations. Corrected the tests to the source's address family without changing the grant. Tailscale accepted the replacement and persisted four tests covering four allowed and sixteen denied TCP connections.
- Post-change local probes: IPv4 TCP 22/443 reachable; TCP 1514/1515/9200/55000 unreachable. IPv6 TCP 22 reachable and 1514/1515/9200/55000 unreachable. IPv6 dashboard TCP 443 failed both before and after the change; the policy permits it, so diagnose the service/listener path separately before claiming IPv6 dashboard access.
- The existing loader still uses the Hyper-V private-network hostname and restricted no-shell tunnel. The next scheduled run (323, 21:57-21:58 EDT) succeeded: 72 alerts fetched, 49 inserted, including 42 Sysmon alerts, and 10 vulnerability findings snapshotted. Sysmon, the Wazuh Windows service and Tailscale remained Running.
- Updated the README, roadmap, runbook, plan and [validation report](docs/private-access-validation.md) with sanitized results. Enrollment remains complete; the overall private-access security milestone remains in progress. Authenticated logins/HTTPS trust, separate off-LAN and unprivileged-device tests, public-access/revocation checks, a controlled event trace and Power BI refresh remain pending. Exact policies and review screenshots stay outside Git.

## Problems hit and how they were solved

### 1. Wazuh install failed: "No space left on device"
- **Symptom:** The installer got through the indexer, manager and Filebeat, then failed at the dashboard step and rolled everything back.
- **Cause:** Ubuntu's installer uses LVM and, by default, allocates only part of the disk to the root volume, leaving the rest unallocated.
- **Fix:** Grew the root volume into the free space: `sudo lvextend -r -l +100%FREE /dev/ubuntu-vg/ubuntu-lv` (root went to 47 GB).

### 2. Reinstall blocked: "Port 1515 / 55000 is being used by another process"
- **Cause:** The rollback could not finish because the disk was full, leaving `wazuh-authd` and the Wazuh API (`python3`) running.
- **Fix:** Found the processes with `sudo ss -tlnp`, then killed them by PID.

### 3. Reinstall failed: "wazuh-keystore: No such file or directory"
- **Cause:** The package database still listed `wazuh-manager` as installed even though its files were gone, so the installer skipped laying down files. Removing the package also failed, because its pre-removal script called binaries that no longer existed (exit status 127).
- **Fix:** Deleted the broken maintainer scripts in `/var/lib/dpkg/info/`, force-purged the package, deleted `/var/ossec`, confirmed with `dpkg -l` that nothing was left, rebooted, then reinstalled cleanly.

### 4. SSH stopped working after a VM reboot
- **Cause:** The Default Switch assigned the VM a new IP (172.26.185.55 became 172.26.183.222).
- **Fix:** Used the automatic `soc-vm.mshome.net` hostname for SSH, the dashboard, and agent enrollment.

### 5. The loader could not reach the Indexer on port 9200
- **Cause:** The all-in-one install binds the Indexer to `127.0.0.1` inside the VM (`ss -tlnp` showed `[::ffff:127.0.0.1]:9200`), so opening the firewall did nothing.
- **Fix:** Kept the Indexer private and closed 9200 again. The loader opens an SSH tunnel with a dedicated key that the VM restricts to that one port forward. This is safer than re-binding the Indexer to the network.

### 6. TLS failed: "CA cert does not include key usage extension"
- **Cause:** Python 3.13+ enables strict X.509 checks by default, and the Wazuh installer's self-generated root CA has no keyUsage extension.
- **Fix:** Trust only the Wazuh root CA and clear just the `VERIFY_X509_STRICT` flag. Chain and hostname verification stay on, and a deliberate wrong-hostname test is still rejected.

### 7. Windows paths loaded with doubled backslashes
- **Cause:** Wazuh keeps JSON escaping inside Windows eventdata strings (`C:\\Windows`, `\"`).
- **Fix:** The loader unescapes path and command fields, and `warehouse/sql/04_backfill_unescape.sql` cleaned the rows loaded before the fix.

### 8. After a Windows restart, the VM was unreachable and its firewall would have locked the host out
- **Symptom:** After the Defender offline scan rebooted the host, the dashboard and agent ports were down.
- **Cause:** Hyper-V's Default Switch moved from 172.26.176.0/20 to 192.168.160.0/20, and the VM resumed from saved state still holding its old address. Worse, `ufw` only allowed `172.16.0.0/12`, based on the wrong assumption that the Default Switch always uses that range, so even after the VM got a new address the host's traffic would have been blocked, SSH included.
- **Fix:** Restarted the VM, then from the Hyper-V console (which does not depend on the network) allowed the same four ports from `192.168.0.0/16` and `10.0.0.0/8`. Verified from Windows: 22, 443, 1514 and 1515 open; 9200 and 55000 still closed; the loader caught up on 326 alerts queued during the outage. The runbook now allows all three private ranges from the start.
### 9. The documented journald `ignore` option does not exist in this version
- **Symptom:** `wazuh-logcollector -t` warned: `log_format 'journald' does not support 'ignore' option. Option will be ignored.`
- **Cause:** The Wazuh reference says `ignore` applies to every log format except eventchannel; 4.14.8 does not support it for journald.
- **Fix:** Caught by the pre-restart config test, so nothing broke. Switched to journald's supported include `<filter>` with two collectors (see `wazuh/manager/journald-dashboard-ignore.xml`): everything except the dashboard, plus only the dashboard lines worth keeping.

### 10. The Wazuh agent silently undid the new audit policy
- **Symptom:** The hardening script set 16 audit subcategories and read them back as set, but Wazuh's CIS rescan still failed all 16, and `auditpol /get` later showed "No Auditing".
- **Cause:** With FIM `whodata` on, the agent saves the audit policy when it starts and restores that copy when it stops. Restarting the agent after the change put the old policy back.
- **Fix:** Stop the agent, change the audit policy, then start it, so the new policy becomes its restore point.

### 11. Changing the lockout policy reset two audit subcategories
- **Symptom:** With the agent stopped, all 16 verified as set, then Credential Validation and Application Group Management read "No Auditing" seconds later. The only step in between was `net accounts`.
- **Fix:** Apply the lockout policy before the audit policy. All 16 then held and Wazuh scored them as passing. The mechanism inside Windows was not determined; the required order is documented in the script.

### 12. Power BI refused the generated pages: 490 schema issues
- **Cause:** Inside filters and color selectors, a literal must be written `{"Literal": ...}`; the generator wrapped 11 of them in `{"expr": ...}` as formatting properties are. The validator lists every expression type each bad literal could have been, hence 490 issues from 11 values.
- **Fix:** A separate helper for query literals. Power BI's open-time validation, and its "apply external changes" banner, made the loop fast.

### 13. A KPI card showed "7K" instead of 7,450
- **Cause:** In this release the new card visual always abbreviates numbers and offers display units only for its header, not the value.
- **Fix:** A text measure (`FORMAT(..., "#,0")`), the same workaround page 1 already used for its Low count.

### 14. A count of 54 suspicious scripts came back as 0

- Cause: SQL Server's `JSON_VALUE` returns NULL, without an error, when the value is longer than 4,000 characters. PowerShell script blocks often are, so a filter on the script text silently matched nothing.
- Fix: search long fields in the raw JSON (`raw_json LIKE ...`) or read them with `OPENJSON` and an `nvarchar(max)` column. A zero result now gets a sanity check against the total before it goes in a report.

### 15. A case showed 0 alerts when it had 2

- Cause: `sg.cases.first_alert_utc` is `datetime2(0)`, so storing 05:36:33.692 rounded it up to 05:36:34, and the two alerts that opened case SG-008 fell "before" the case started.
- Fix: `rpt.cases` counts alerts from one second before the stored first-alert time. Found while checking screenshots for a LinkedIn post, which is a reminder to look at outputs, not only queries.

## Open items

### Hardening
- [x] Back up `~/wazuh-install-files.tar` (cluster certificates and original passwords) to a private folder outside the repo with `scp`. Never commit it.
- [x] Rotate the Wazuh `admin` password with `wazuh-passwords-tool.sh` (random, generated on the server) and store it in a password manager.
- [x] Enable `ufw`: deny all inbound by default, allow only 22, 443 and 1514-1515 from `172.16.0.0/12` (the range Hyper-V's Default Switch draws from). Verified from Windows that those ports are reachable and that 9200 (indexer) and 55000 (API) are blocked.
- [x] Take a Hyper-V checkpoint of the hardened VM, named `wazuh-clean`, as the rollback point for attack testing.
- [x] Ubuntu fully patched 2026-10-02 (0 updates pending). Keep patching weekly (see ROADMAP upkeep); stay on 24.04 until Wazuh supports a newer release.
- [ ] Stage 6: choose a private API placement and read-only account; prefer local access or a restricted tunnel before adding any narrow API-host exception for 55000/9200.

### Private remote access
- [x] Verify Tailscale enrollment on the admin device and Ubuntu VM; record initial local TCP connectivity ([results](docs/private-access-validation.md)).
- [x] Save/review the exact tailnet policy privately; apply approved device-scoped TCP 22/443 access and verify local TCP 55000 denial.
- [x] Verify accepted policy tests, local IPv4 management/data-port results and a successful post-change SQL load with new Sysmon alerts ([results](docs/private-access-validation.md)).
- [x] Enroll an iPhone test client and record its reported private HTTPS timeout over cellular with a working public-web control.
- [x] Identify the IPv6 dashboard gap: user-provided listener output shows no IPv6 dashboard listener.
- [x] Review supplied full IPv4/IPv6 filter tables and record user-provided authenticated Hyper-V console evidence.
- [x] Record user-reported new checkpoint creation after the backup-helper repair and a Production-Only settings screenshot.
- [x] Record the user's reported five active guest services after checkpoint creation.
- [x] Record the user's `BACKUP_CHECK_PASSED` result for a root-only, VM-local dashboard/UFW configuration copy; full recovery remains separate.
- [x] Inspect dashboard certificate metadata without accepting it or sending credentials; record loopback-only identity and incomplete Windows trust chain.
- [x] Enable the selected Tailscale HTTPS issuance route after public-name disclosure and record user-reported verified certificate staging.
- [x] Record reported certificate installation/five active services and independently verify trusted Windows IPv4 HTTPS with no credentials or validation bypass.
- [x] Verify trusted local dashboard login and record successful renewal setup/initial service run and enabled daily timer ([results](docs/private-access-validation.md#authenticated-dashboard-and-renewal-timer)).
- [ ] Observe the first automatic renewal check and, when due, actual certificate replacement; setup success is not evidence of a real rotation or live failure recovery.
- [ ] Confirm the new checkpoint metadata; review backup readers/storage protection, retain exact current configuration backups and validate separate backup/restore before further VM/firewall changes.
- [ ] Diagnose local enrollment TCP 1515 unreachability before new agent enrollment; do not open it automatically.
- [ ] Complete authenticated tailnet SSH and approved off-LAN dashboard tests; local dashboard login/trusted IPv4 HTTPS now pass, and IPv6 dashboard support is absent.
- [ ] Approved off-LAN administration deferred after the phone test was declined; remaining denied-service/public-access and device-revocation checks stay open.
- [ ] Confirm individual agent identity/health and a remote controlled event trace; the local six-page Power BI retest passes, but does not prove remote access ([plan](docs/private-access-plan.md)).
- [ ] Enroll one remote endpoint and publish a benign event trace through Wazuh, SQL and Power BI.

### Detection work
- [x] First controlled test: failed SSH logins against the Wazuh server, detected as T1110.001 and written up ([report](triage/2026-10-01-ssh-failed-logins-wazuh-server.md)). Wazuh's brute-force rule 5712 needs 8 failures from one IP in 120 seconds, so slow guessing only reaches level 10.
- [ ] Run more controlled attack simulations (for example, Atomic Red Team tests on a throwaway VM) and write a triage report for each one.
- [x] ATT&CK coverage map built: 115 of 447 Windows and Linux techniques have a deployed rule with a collected source, and all 36 that fired are triaged. Proving "detects vs. misses" per technique needs more tests (ROADMAP chapter 3).
- [x] Tuned only after a baseline existed: rules 100100 and 100101 were replayed against 674 stored alerts before deployment.

### Posture
- [x] Recorded Steam and desktop-app updates on October 2; that update action did not prove all findings cleared. October 5 review confirms newer Steam components but broad local permissions, and uncertain desktop-advisory scope. No blanket reinstall, acceptance or automatic-clearance claim is retained ([assessment](docs/vulnerability-applicability-review.md)).
- [x] Read-only applicability assessment of all ten October 5 scanner findings, with per-finding uncertainty retained; detector status and historical remediation counts unchanged.
- [x] Owner selected keeping Steam installed; retain its normal use rather than uninstalling it.
- [ ] Review supported Steam maintenance and bounded permission remediation; test and apply same-series Python security updates in a controlled window, then verify workload/loader health and fresh Wazuh inventory.
- [x] Python 3.11 retired 2026-10-02, after the automation workload that depended on it moved to 3.13 (see the timeline).
- [ ] Review cryptography, PyJWT, urllib3 and setuptools in the active workload environment; retiring global Python 3.11 does not prove these dependencies were patched. Preserve compatibility/rollback and verify workload health after any approved changes.
- [x] CIS baseline recorded and hardened: 27.1% to 37.0% (docs/cis-baseline.md).
- [ ] Review the remaining Administrative Templates failures in smaller batches; test Credential Guard and SmartScreen prevent-bypass.

### Detection tuning
- [x] Deployed `wazuh/rules/sentinelgrid_tuning.xml` (rules 100100 and 100101) after replaying them against 674 stored alerts: every watchdog and sdbinst event matched, every installer event still fired. Live check: the last watchdog alert at level 15 was 19:22:03; from 19:22:53 the same activity arrives as rule 100100 at level 3, with zero new 92213 alerts.
- [x] Confirmed rule 100101 live: 21 matches at level 3 since 2026-09-30 23:53, no new 92058 alerts.
- [x] Traced all 51 Critical (92213) alerts since tuning: AMD Bug Report Tool after graphics driver crashes, PowerShell `Add-Type` compiles by the build tooling (left at Critical on purpose), one Windows troubleshooter ([report](triage/2026-10-01-rules-92213-92217-after-tuning.md)). Host finding: update the AMD graphics driver.

### Archive volume
- [x] Filtered the dashboard's own web logs out of the archive (logins and denied requests kept).
- [ ] Measure archive growth per day after a full day of data.

### Platform
- [x] Stage 8: Power BI pages 2-4 on the `rpt` views (Endpoint Posture, ATT&CK Coverage, Pipeline Health).
- [x] Loaded the ATT&CK catalog from the Wazuh server (v4.14.8: 750 techniques, 1,062 rules with mappings). Of 447 Windows and Linux techniques, 115 (26%) have a deployed rule whose data source is collected here, 33 have fired, and 34 have a rule but no data source here. Rules are classified by an explicit list of collected rule files, and the loader fails if any rule that fired here is classified as not collected (it caught `0955-WEF-baseline_rules.xml` on the first run). Pattern matching had misfiled `mailscanner` and `netscaler` as SCA.
- [x] Layout: moved height from the middle row to the bottom row and shrank the CIS section labels so the first-scan and current labels no longer collide.
- [x] Screenshots of pages 2-4 in `docs/screenshots` and the README.
- [x] Rebuilt page 1 (SOC Overview) in the same design: severity colors, Critical and High triage table, and a "tuning in action" chart showing rule 92213's watchdog noise moving from Critical to Low the hour rule 100100 went live. All four pages are now generated.
- [x] Least-privilege reporting access (`10_reporting_access.sql`). SQL Server stays in Windows-authentication-only mode, Microsoft's recommended setting, so no SQL password exists to steal; switching to mixed mode just to add a password login would weaken that. Instead, a login-less `powerbi_reader` user in the `rpt_reader` role was tested with `EXECUTE AS`: reading `rpt.cases` is allowed; reading `sg.alerts`, updating `sg.cases` and deleting from `sg.case_events` are all denied (error 229). Power BI on this one-person lab still signs in as the analyst; a shared deployment would add its own Windows or Entra identity to the role.
- [x] Triaged rule 92217: all 577 Low alerts are software installs and updates (same report).
- [x] Moved the superseded `PowerBI-SOC.pbix` to the Recycle Bin (2026-10-02); the Power BI Project in `powerbi/` is the only copy.
- [x] Console switched from demo data to a scrubbed snapshot of real data, hosted on GitHub Pages; the demo-data prototype was removed.
- [ ] Stage 6, second part: a private live API/console with a read-only Wazuh account; public console stays on a sanitized snapshot (ROADMAP chapter 12).
