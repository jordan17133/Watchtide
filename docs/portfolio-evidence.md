# Portfolio Evidence Index

The [README](../README.md) is the short employer-facing overview. This index keeps
the detailed results, investigations and gallery available without expanding it.
Dates and scope matter: historical research does not adjudicate later events.

## Pipeline And Platform Evidence

| Area | Evidence and boundary |
|---|---|
| Endpoint collection | [Original trace](event-trace.md), [October 7 recovery and health checks](collection-health-validation.md); outage recovery is not proof that all historical drops were recovered |
| Analyst understanding | [Plain-English L0 trace](L0-event-to-report-trace.md), [toolkit lessons](analyst-toolkit-runbook.md), [interaction/triage audit](triage-system-audit.md) |
| Network detection | [Offline validation](suricata-offline-validation.md), [controlled reporting handoff](suricata-wazuh-handoff.md), [bounded live trial](suricata-live-trial.md), [saved-live reporting](suricata-live-reporting-handoff.md); no continuous or phone/browsing coverage claim |
| Power BI | [Six-page report verification](network-reporting-validation.md), [refresh deadlock fix](report-refresh-reliability.md); imported caches private, fresh October 7 saved-live rendering deferred |
| Recovery | [SQL restore drill](sql-recovery-validation.md); same-PC/same-instance scope, not Wazuh or whole-PC disaster recovery |
| Private access | [Plan](private-access-plan.md), [validation](private-access-validation.md); selected local path tested, approved off-LAN/revocation gates remain |
| Hardening | [File/logging/access gates](hardening-validation.md), [host exposure](host-exposure-validation.md), [software batch](software-hardening-validation.md), [vulnerability applicability](vulnerability-applicability-review.md) |
| Detection maintenance | [Library plan](detection-library-plan.md), [held PowerShell expansion](powershell-policy-probe-tuning-review.md), [major attack lessons](attack-defense-reference.md) |
| Public boundary | [Publication safety](publication-safety.md), [earlier privacy audit](public-privacy-audit.md); the console is a dated snapshot, not live SIEM access |

## Historical Results

These are documented baselines, not a fresh posture scan or a guarantee that
Critical events cannot occur. The counts in older screenshots may differ.

| Measure | Historical result | Evidence |
|---|---|---|
| Vulnerability remediation | 445 initial findings, including 99 Critical; 10 open of 447 later found, zero Critical | [Forgotten-browser investigation](finding-forgotten-browser.md), [posture baseline](cis-baseline.md) |
| CIS Windows benchmark | 27.1% to 37.0%; remaining gaps recorded | [CIS baseline](cis-baseline.md) |
| Critical policy-test cluster | 94% reclassified by narrow tuning; unrelated installer/build events retained | [Scoped investigation](../triage/2026-09-30-rule-92213-powershell-policy-test-noise.md) |
| Stored-alert replay | Two child rules replayed against 674 stored alerts | [Build history](../BUILD-LOG.md), [tuning rules](../wazuh/rules/sentinelgrid_tuning.xml) |
| SQL recovery | 37,605 alerts restored with clean integrity check and readable views | [Recovery validation](sql-recovery-validation.md) |

## Investigations

These links describe reviewed historical activity or a named controlled test,
not automatic benign verdicts on all future alerts from those rules.

| Investigation | Scope |
|---|---|
| [Installer false positives](../triage/2026-09-30-rule-92213-installer-false-positive.md) | Wazuh/Sysmon installers writing to temporary paths |
| [PowerShell policy-test noise](../triage/2026-09-30-rule-92213-powershell-policy-test-noise.md) | Reviewed scheduled workload and narrow tuning |
| [Compatibility maintenance](../triage/2026-09-30-rule-92058-sdbinst-pca-maintenance.md) | Reviewed Microsoft maintenance activity |
| [Alerts remaining after tuning](../triage/2026-10-01-rules-92213-92217-after-tuning.md) | Several named causes; some events deliberately retained as Critical |
| [Baseline rule review](../triage/2026-10-01-baseline-review-remaining-rules.md) | Historical review; includes one unresolved-source, low-risk finding |
| [Autostart registry change](../triage/2026-10-02-rule-100113-edge-autostart-change.md) | Edge update investigated using writer/provenance evidence |
| [Scheduled-task creation](../triage/2026-10-02-rule-60228-scheduled-task-creation.md) | Reviewed update and authorized migration |
| [Failed Edge logons](../triage/2026-10-02-rule-60122-edge-password-prompt.md) | Owner-confirmed mistyped Windows password |
| [SSH password-guessing validation](../triage/2026-10-01-ssh-failed-logins-wazuh-server.md) | Controlled true-positive exercise; threshold gap documented |

## Screenshot Gallery

Power BI screenshots were captured October 1, 2026, before the sixth Network
Detection page. They are historical images, not current counts or new render checks.
The [public console](https://jordan17133.github.io/Watchtide/) has its own export date.

| Power BI | Power BI |
|---|---|
| ![SOC Overview](screenshots/powerbi-soc-overview.jpg) | ![Endpoint Posture](screenshots/powerbi-endpoint-posture.jpg) |
| ![ATT&CK Coverage](screenshots/powerbi-attack-coverage.jpg) | ![Pipeline Health](screenshots/powerbi-pipeline-health.jpg) |
| ![Cases](screenshots/powerbi-cases.jpg) | |

Earlier Wazuh build screenshots below are illustrative historical evidence;
their capture times are not independently reverified in this update.

| Wazuh | Wazuh |
|---|---|
| ![Vulnerabilities before cleanup](screenshots/wazuh-vulnerabilities-before.png) | ![Vulnerabilities after cleanup](screenshots/wazuh-vulnerabilities-after.png) |
| ![Initial Sysmon ATT&CK records](screenshots/wazuh-sysmon-mitre.png) | |
