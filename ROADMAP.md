# Watchtide Roadmap

What is built, what comes next, and why. Each chapter ends the same way: build it, test it, write it up as a case or report, then publish.

## Done

- [x] Lab: Hyper-V VM, Ubuntu Server 24.04, Wazuh 4.14 all-in-one, hardened (firewall, rotated credentials, backups, checkpoints)
- [x] Endpoint telemetry: Sysmon, Windows Security and System logs, Microsoft Defender, PowerShell script-block logging, file integrity monitoring with who-did-it attribution
- [x] One event traced through every layer ([docs/event-trace.md](docs/event-trace.md))
- [x] Posture: 437 of 447 vulnerability findings resolved (10 open, zero Critical); CIS Benchmark 27.1% to 37.0% ([docs/cis-baseline.md](docs/cis-baseline.md))
- [x] Detection tuning with tested custom rules (100100, 100101) and FIM severity rules (100110-100113)
- [x] SQL Server warehouse with a scheduled loader (every 15 minutes, 99% success) and data lifecycle rules
- [x] Case log with history; nine investigations closed, one open ([triage/](triage/))
- [x] Documented baseline's 38 fired MITRE ATT&CK techniques triaged; later observations require fresh review
- [x] First controlled attack test: SSH password guessing, detected end to end
- [x] Least-privilege reporting role, tested
- [x] All six existing Power BI pages rendered after refresh; definitions and single-table refresh setting kept in Git, imported data excluded
- [x] Public read-only SOC console on a scrubbed snapshot ([console](https://jordan17133.github.io/Watchtide/))
- [x] Offline Suricata 8.0.7 marker-rule validation: one positive alert, zero alerts on two controls; that engine-only phase did not enable live capture or Wazuh collection ([evidence](docs/suricata-offline-validation.md))
- [x] Controlled Suricata EVE-to-Wazuh-to-SQL-to-Power BI trace: same labeled event and network fields verified; live coverage remains separate ([evidence](docs/suricata-wazuh-handoff.md))
- [x] Read-only network reporting view and existing sixth Power BI page verified; four metrics, event fields and context-filter reset checked. Saved model and available schemas checked with an explicit unpublished-schema limit ([evidence](docs/network-reporting-validation.md))

## Current Execution Order

The expanded [network SOC maturity plan](docs/soc-network-maturity-plan.md)
defines the device-coverage, routine-telemetry, correlation, analyst workflow,
monitoring and recovery checklist. These are evidence-gated targets, not newly
deployed features. Its phases extend, rather than renumber, the runbook stages.

The next network goal is a bounded Suricata pilot for traffic interpretation,
rules and reporting. Whole-home SOC coverage remains the longer-term goal.
The owner deferred extra VPN/router work; browsing-privacy routing is not a
prerequisite for this pilot. See the [pilot guide](docs/suricata-pilot.md) and
[network coverage plan](docs/network-coverage-plan.md).

**Owner-selected focus:** finish bounded hardening checks before adding capture.
Recovery was deferred, not passed; no database backup or restore drill ran.
Reviewed private-file permissions passed, with the next automatic ingestion
still successful. The administrator firewall-logging helper now passed, with
independent effective-policy readback. Owner-performed read-only checks also
confirmed actual dropped-packet log output and basic TPM readiness. Log
interpretation/SIEM collection and disk/boot protection remain open; recovery-key
custody and remaining firmware checks precede any separately approved change.
The system drive is still unencrypted and host Secure Boot remains off. See
[hardening results and gates](docs/hardening-validation.md).
The [ten-finding software assessment](docs/vulnerability-applicability-review.md)
is now complete as a read-only review, not remediation. Newer Python security
releases, Steam permission concerns and uncertain app/component mappings remain
open. Preserve current workloads; verify changes and fresh inventory before
closing these gates. No findings were suppressed or credited as newly resolved.
The following sequence describes the network work after these checks.

1. Preserve working Tailscale access and leave the phone denied. Check Ubuntu resources/package state; follow up recorded host memory pressure and loader/reporting health before adding sustained load.
2. Completed: test the alert-only marker rule with a short, isolated benign positive/negative replay. Offline success is not live capture proof.
3. Completed: collect a genuine saved EVE alert into Wazuh and trace the same record into SQL and the existing Power BI report. Keep raw network logs private and collection bounded.
4. Validate a limited live capture point, then plan a supported feed for wider coverage. Record each observed device/segment and gaps rather than assuming the NAT VM sees the whole home.

Suricata 8.0.7 is installed, and the starter rule passed isolated engine
validation in the owner's supplied output. An independent maintenance check
confirmed the installed package and five healthy SOC services.
The temporary maintenance connection passed actual allowed/denied local SSH
checks. Stable-source setup and a simulated installation passed: Suricata 8.0.7,
ten new packages, no upgrades/removals, and all five SOC services still active.
The separately approved offline job completed with one expected positive alert
and zero alerts on two controls. The service remains masked; synthetic packets
do not establish live coverage. Wazuh collection and existing SSH keys were
unchanged. The owner selected genuine EVE inspection and bounded Wazuh
integration. The first [handoff](docs/suricata-wazuh-handoff.md) stopped safely
at a folder guard; the corrected input placement and stopped-backup comparison
then passed. The owner supplied local-alert success, and an independent
read-only Indexer search verified exactly one matching labeled alert. The normal
scheduled loader collected the same record, independently matched in SQL with
its network fields and fixture time. Five SOC services are active. The dashboard
now visibly shows the exact alert-index record. The read-only network view is
deployed and verified; the sixth Power BI page now displays the matching record
and all four metrics. All six existing pages rendered after refresh, and the
new context filter was tested and saved back at All. This is controlled offline
end-to-end reporting proof, not a live feed or completed network-capture stage.
No whole-network privacy-egress change has been deployed.
Permanent phone dashboard access is not required; the phone currently serves
as a denied off-LAN test client. Other portfolio chapters remain planned work,
not prerequisites that must all precede the network pilot.

**Reliability checkpoint (October 4, 2026):** the six workspace-review findings have implementation fixes and offline regression checks. The first scheduled reconciliation succeeded in 30 seconds with 96 new alerts. A later incremental run succeeded but took over eight minutes; SQL timeout and host paging evidence make runtime/memory follow-up a prerequisite before sustained capture. A controlled late-event trace remains pending; the October 5 report retest is recorded below. The public console keeps individual alerts untriaged and historical rule reviews separate. See [validation and limits](docs/reliability-validation.md). This does not close the private-access security gates below.

**Refresh follow-up (October 5):** an actual Power BI attempt failed with a confirmed loader/read deadlock. Guarded committed-snapshot maintenance and isolated concurrency tests passed, and the approved quiet-window change is applied. All 18 report views passed a bounded read; the subsequent Desktop retest rendered all six pages, with single-table refresh persisted. Three recent automatic loads succeeded in 2.4-3.3 seconds. Sustained performance and refresh duration remain unproven: successful rendering and short loader runs are not a stable-load benchmark ([evidence](docs/report-refresh-reliability.md)).

**Network checkpoint (October 5, 2026):** the controlled offline event is verified through the existing dashboard, Indexer, SQL and Power BI. All six report pages render, and the new context filter resets to All ([reporting proof and schema limit](docs/network-reporting-validation.md)). After bounded hardening: resource checks and a separately reviewed limited live capture point. Extra VPN/router work remains deferred. The Windows-only management grant remains unchanged; the phone stays denied and approved off-LAN administration stays deferred/unverified. Local trusted dashboard access and reported renewal setup are retained; automatic renewal and actual replacement remain unproven. Remaining exposure/revocation, recovery and sustained loader-performance checks stay open. The [pilot guide](docs/suricata-pilot.md), [network plan](docs/network-coverage-plan.md) and [access results](docs/private-access-validation.md) keep these gates separate.

## Portfolio Chapters

This catalogue includes longer-term portfolio work; its row numbers are not
runbook stages or a requirement to delay the network pilot.

| # | Chapter | Why it matters | Done when |
|---|---|---|---|
| 1 | **Tailscale private remote access** (runbook Stage 4c; enrollment complete, validation in progress) | Practice secure remote administration and least privilege | Current policy reviewed; approved admin access works off-LAN; an unprivileged test device and unnecessary API access are denied; direct public access fails; the loader and local agent still work; sanitized results published |
| 2 | **One remote Wazuh endpoint** (planned) | Prove collection across networks | A benign event from a separate network reaches Wazuh, SQL and Power BI; timestamps and the access restrictions documented |
| 3 | **Attack simulations, round 2** on a separate test VM (Atomic Red Team) | Turns "a rule exists" into "a rule is proven" | 5+ techniques validated, each with a case; a "validated by test" status on the ATT&CK page |
| 4 | **Close SG-007** (loopback admin-share access) | Finish the open case | Detailed File Share auditing (event 5145) names the process; case closed |
| 5 | **Phishing analysis** | The most common Tier 1 task | 2+ sample emails analyzed (headers, links, attachments) and written up as cases |
| 6 | **Threat intel enrichment** | Faster, better verdicts | Case write-ups check hashes, IPs and domains against public reputation sources |
| 7 | **Second SIEM: Splunk** | Most SOC job posts name Splunk or Sentinel | Same logs searched in Splunk; Boss of the SOC practice questions solved |
| 8 | **Architecture diagram and demo video** | A 2-minute way in for busy reviewers | Diagram in the README; video showing alert to case to dashboard |
| 9 | **Active Directory lab** | Most companies run Windows domains | Small domain in Hyper-V; common AD attacks detected and written up |
| 10 | **EDR** (Microsoft Defender for Endpoint trial) | Endpoint detection and response is standard in SOCs | Defender alerts correlated with Wazuh in a case |
| 11 | **Network monitoring: Suricata** (runbook Stage 5) | Extend live endpoint telemetry with measured network visibility; offline-to-SIEM proof now passes | DNS and HTTP events visible and traced to Wazuh records; VPN visibility limits documented |
| 12 | **Private live API/console** (runbook Stage 6, second part) | Work cases from the console, not a script | Authenticated analysts open, assign and close cases over private access; public GitHub Pages remains a sanitized snapshot |
| 13 | **Alert notifications** for level 12 and above | Faster response | Optional; tested so it never floods |

## Ongoing upkeep

- Weekly: check Pipeline Health (loader success above 95%, data fresh within 30 minutes) and patch the VM.
- Before risky work: take a Hyper-V checkpoint.
- After a Wazuh upgrade: re-export the ATT&CK catalog and reload it.
- After any new case: review its public display text, update the field-scoped approval catalog privately, then validate and refresh the console snapshot. New live text must not be auto-approved.
- After a device or access-policy change: repeat the allowed/denied connection tests; review available authentication and policy-change records.
- Before publishing: run publication regression tests and snapshot validation, review new documentation/configuration/screenshots for secrets and personal data, and use the sanitized public-copy process. [Publication controls](docs/publication-safety.md) supplement the [bounded privacy audit](docs/public-privacy-audit.md); historical disclosures remain separate.
