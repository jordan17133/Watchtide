# Watchtide: A Home SOC Built on Wazuh, SQL Server and Power BI

An evidence-led security operations lab and analyst-learning portfolio.
**Windows/Sysmon -> Wazuh -> SQL Server -> Power BI**, with controlled Suricata
network tests and documented investigations.

**Author:** Jordan Carven-Bellace

*Formerly named SentinelGrid. Some internal identifiers (the `SentinelGridWarehouse` database, the `SentinelGrid-Wazuh` VM, scheduled task and rule-file names) keep the original name so the running system did not need to change.*

**[Open the Watchtide console](https://jordan17133.github.io/Watchtide/)**:
read-only, sanitized historical alerts, cases and ATT&CK coverage.
No live connection to the private SOC. Check the snapshot's date.

## At A Glance

Updated October 7, 2026. Results are dated observations, not a security guarantee.

| Result | Evidence / scope |
|---|---|
| **37,605 alerts recovered** | Copy-only SQL backup, disposable restore and clean CHECKDB; same-instance recovery only ([validation](docs/sql-recovery-validation.md)) |
| **99 Critical vulnerabilities reduced to zero** | Historical remediation baseline; later inventory requires fresh review ([investigation](docs/finding-forgotten-browser.md)) |
| **94% of the original Critical cluster reclassified** | Narrow tested tuning, not removal of every future Critical alert ([case](triage/2026-09-30-rule-92213-powershell-policy-test-noise.md)) |
| **Six Power BI pages** | All rendered October 5; fresh October 7 saved-live record rendering remains deferred ([report proof](docs/network-reporting-validation.md)) |
| **Network rule proved with controls** | One marked live request alerted, one unmarked request did not; no continuous capture ([trial](docs/suricata-live-trial.md)) |

[Current state and pickup map](STATUS.md) | [Execution roadmap](ROADMAP.md) |
[Daily analyst routine](docs/analyst-toolkit-runbook.md#a-daily-routine-you-can-explain)

![SOC Overview page in Power BI](docs/screenshots/powerbi-soc-overview.jpg)

*Screenshot captured October 1, 2026; values are historical.*

## Highlights

- **Traceable alerts:** source identity follows one event through the SIEM and warehouse ([endpoint trace](docs/event-trace.md), [plain-English packet lesson](docs/L0-event-to-report-trace.md)).
- **Investigation before suppression:** custom persistence detection, written verdicts and two child rules replayed against 674 stored alerts; unrelated installer alerts retained ([triage](triage/)).
- **Independent packet proof:** TShark verified the live controls; their saved alert agrees in Wazuh, Indexer and scheduled-loader SQL ([handoff](docs/suricata-live-reporting-handoff.md)).
- **Least-privilege access:** device-scoped Tailscale SSH/HTTPS and trusted local login, plus a loopback-bound, forwarding-only loader key and read-only Indexer account ([access limits](docs/private-access-validation.md)).
- **A real concurrency fault fixed:** diagnosed a Power BI/loader deadlock and validated committed-snapshot reads; performance monitoring remains open ([diagnosis](docs/report-refresh-reliability.md)).
- **Recovery checked, not assumed:** disposable SQL restore, integrity check and schema/payload comparisons, with backup hash and cleanup independently rechecked ([proof](docs/sql-recovery-validation.md)).

## Architecture

```text
Windows 11 endpoint (jordan-pc)
  Sysmon (SwiftOnSecurity config) -> Windows Event Log
  Wazuh agent ----------------------------------------+  TCP 1514/1515
                                                      v
Hyper-V VM: Ubuntu Server 24.04, ufw default-deny
  Suricata bounded tests -> saved eve.json (not continuous capture)
       |
       v
  Wazuh manager -> Filebeat -> Wazuh indexer -> Wazuh dashboard (HTTPS 443, Tailscale)
                                     ^ 127.0.0.1:9200 only
                                     | SSH tunnel, restricted key
Windows host                         |
  Task Scheduler, every 15 min:  loader/wazuh_to_sql.py (Python 3.14)
                                     |
                                     v
  SQL Server 2025: SentinelGridWarehouse
    sg.*  tables (alerts, agents, rules, MITRE, vulnerability snapshots, load runs)
    rpt.* views  ->  Power BI Desktop (6 pages; Git definitions, private import)
```

## What is in this repo

| Path | What it is |
|---|---|
| [SentinelGrid-Build-Runbook.md](SentinelGrid-Build-Runbook.md) | Stage-by-stage build guide with completion gates, revised with every lesson from the real build |
| [BUILD-LOG.md](BUILD-LOG.md) | What actually happened: timeline, every problem hit and how it was solved, open items |
| [ROADMAP.md](ROADMAP.md) | Upcoming work, its purpose and the evidence required to call each milestone done |
| [docs/private-access-plan.md](docs/private-access-plan.md) | Tailscale design decision, deployed management scope, remaining validation gates and rollback plan |
| [docs/private-access-validation.md](docs/private-access-validation.md) | Enrollment, reviewed policy, before/after TCP results and post-change SQL loader evidence; remaining limits explicit |
| [docs/suricata-pilot.md](docs/suricata-pilot.md) | Current network pilot, plain-English rule/event interpretation and separate deployment/reporting gates |
| [suricata/rules/watchtide-pilot.rules](suricata/rules/watchtide-pilot.rules) | Alert-only marker rule validated offline and in bounded live controls; sustained capture remains pending |
| [docs/suricata-offline-validation.md](docs/suricata-offline-validation.md) | Reported engine results, independent package/health verification and explicit capture/reporting limits |
| [docs/suricata-wazuh-handoff.md](docs/suricata-wazuh-handoff.md) | Completed controlled handoff and dashboard/Indexer/SQL/Power BI verification; live coverage still open |
| [docs/network-reporting-validation.md](docs/network-reporting-validation.md) | Exact network record verified in the existing six-page report; filter, model and available-schema checks, with remaining limits |
| [docs/report-refresh-reliability.md](docs/report-refresh-reliability.md) | Actual refresh deadlock diagnosis, guarded committed-snapshot fix and separate performance/retest gates |
| [triage/](triage/) | Alert investigation reports |
| [wazuh/rules/sentinelgrid_tuning.xml](wazuh/rules/sentinelgrid_tuning.xml) | Custom Wazuh rules deployed to the manager |
| [warehouse/](warehouse/) | Idempotent SQL Server schema, reporting views and the script that applies them; `cases.py` opens, assigns and closes cases with a full history |
| [loader/](loader/) | Incremental Wazuh-to-SQL loader and its settings template |
| [powerbi/](powerbi/) | Existing Power BI project: model (TMDL) and six page definitions (PBIR) in Git, imported data excluded. All six pages rendered after refresh; generators and schema checks are in [powerbi/tools/](powerbi/tools/) |
| `Enable-SentinelGridHyperV.ps1`, `Create-SentinelGridWazuhVM.ps1` | Host preparation and VM creation |
| [console/](console/) | The public SOC console (alerts, cases, ATT&CK matrix, pipeline). Static HTML and JavaScript reading `console/data/snapshot.json`: reviewed display text, aggregate metrics and hashed event references, with no raw events or command lines. Hosted on GitHub Pages. [Publication controls](docs/publication-safety.md) record deliberate disclosures and remaining limits. |

## Triage Reports

The documented baseline reviewed rules behind 38 observed techniques. New alerts
and later techniques require fresh review; a rule-level case is not a verdict
on every event that subsequently matches it.

| Report | Rule | Verdict |
|---|---|---|
| [Installer false positives](triage/2026-09-30-rule-92213-installer-false-positive.md) | 92213, level 15 | Benign: Wazuh agent and Sysmon installers writing to Temp |
| [PowerShell policy-test noise](triage/2026-09-30-rule-92213-powershell-policy-test-noise.md) | 92213, level 15 | Benign: scheduled watchdogs starting PowerShell 36 times an hour. Tuned. |
| [sdbinst / Program Compatibility Assistant](triage/2026-09-30-rule-92058-sdbinst-pca-maintenance.md) | 92058, level 12 | Benign: Microsoft-signed hourly Windows maintenance (looks like T1546.011). Tuned. |
| [Critical alerts left after tuning, and rule 92217](triage/2026-10-01-rules-92213-92217-after-tuning.md) | 92213, level 15; 92217, level 6 | Benign: AMD crash reporter after GPU driver crashes, build tooling compiling with `Add-Type` (kept Critical), installs and updates |
| [Baseline review of every remaining fired rule](triage/2026-10-01-baseline-review-remaining-rules.md) | 28 rules, levels 3-14 | 27 benign with a named source; 1 low risk, source not confirmed. Every fired ATT&CK technique now has a verdict. |
| [Run-key autostart change at 1:36 AM](triage/2026-10-02-rule-100113-edge-autostart-change.md) | 100113, level 10 (custom) | Benign: Microsoft Edge updated its own startup entry. Caught by Watchtide's own persistence rule, triaged in minutes. |
| [Eleven scheduled tasks created in one day](triage/2026-10-02-rule-60228-scheduled-task-creation.md) | 60228, level 4 | Benign: a signed AMD software update and an authorized, documented migration |
| [Two failed logons from Microsoft Edge](triage/2026-10-02-rule-60122-edge-password-prompt.md) | 60122, level 5 | Benign, confirmed with the user: a mistyped Windows password at Edge's saved-password prompt |
| [Failed SSH logins on the Wazuh server](triage/2026-10-01-ssh-failed-logins-wazuh-server.md) | 5710, 5760, 2502 (level 10) | True positive, controlled test of T1110.001. Detected end to end; one threshold gap documented. |

## Security design

The generated public configuration is an example, not a deployable copy of this
host: replace `SOC-USER` and `SOC-MACHINE-SID` with your own values before use.
The private deployed configuration is maintained separately. See
[publication safety](docs/publication-safety.md) for the current privacy boundary.

| Control | Implementation |
|---|---|
| Network exposure | Hyper-V NAT; no intentional public forwarding. Default-deny UFW and device-scoped Tailscale access. Indexer on VM loopback. The tested admin path permits 22/443 and filters 9200/55000; direct public exposure and revocation checks remain open. |
| Credentials | Installer-generated admin password rotated. A dedicated read-only indexer account for the loader. Secrets live in a git-ignored `.env` and a private backup outside the repo. |
| Loader access | SSH key limited in `authorized_keys` to `permitopen="127.0.0.1:9200"` with `command="/bin/false"`. Verified that it cannot run commands. |
| Transport | TLS verified against the Wazuh root CA, with hostname checking on. Only Python's strict-mode flag is relaxed, because the installer's CA lacks a keyUsage extension; a wrong-hostname test is still rejected. |
| Recovery | Checkpoints and VM-local config backup; same-instance SQL restore passed. Off-machine, Wazuh and whole-PC recovery remain separate ([status](STATUS.md#recovery)). |
| Data hygiene | The Power BI file, which embeds alert data, is kept out of Git. |

## Historical Results

These are the documented remediation/tuning baselines, not a fresh October 7
posture scan or a statement that all Critical alerts have disappeared.

| Measure | Before | After |
|---|---|---|
| Vulnerability findings | 445 (99 Critical, 247 High) | 10 open of 447 found (0 Critical, 7 High) |
| CIS Windows 11 benchmark score | 27.1% | 37.0% (47 fixes, every remaining gap documented) |
| Level 15 alerts per hour from known noise | about 36 | 0 (now level 3) |
| Level 12 alerts per hour from known noise | 1 | 0 (now level 3) |
| Alert history | Wazuh dashboard only | Every alert in SQL, keyed to its Indexer document ID, refreshed every 15 minutes |

## Screenshots

### Power BI

Screenshots captured October 1, 2026. The [console](https://jordan17133.github.io/Watchtide/)
has its own dated snapshot, not live numbers.

| | |
|---|---|
| ![SOC Overview](docs/screenshots/powerbi-soc-overview.jpg) | ![Endpoint Posture](docs/screenshots/powerbi-endpoint-posture.jpg) |
| **SOC Overview:** alert volume by severity, the newest Critical and High alerts, and tuning in action: watchdog noise moving from Critical to Low the hour the custom rule went live | **Endpoint Posture:** vulnerabilities 445 to 39 and CIS 27.1% to 37.0%, every number traced to a Wazuh alert |
| ![ATT&CK Coverage](docs/screenshots/powerbi-attack-coverage.jpg) | ![Pipeline Health](docs/screenshots/powerbi-pipeline-health.jpg) |
| **ATT&CK Coverage:** what the deployed rules can detect, what fired here, and the triage verdict behind it | **Pipeline Health:** data freshness, loader success, alert-to-SQL latency, warehouse size |
| ![Cases](docs/screenshots/powerbi-cases.jpg) | |
| **Cases:** every investigation as a case with an owner, a verdict and its time from first alert to verdict | |

### Wazuh

| | |
|---|---|
| ![Wazuh vulnerability detection, before](docs/screenshots/wazuh-vulnerabilities-before.png) | ![Wazuh vulnerability detection, after](docs/screenshots/wazuh-vulnerabilities-after.png) |
| Vulnerabilities before cleanup | Vulnerabilities after cleanup |
| ![Sysmon alerts with MITRE ATT&CK mapping](docs/screenshots/wazuh-sysmon-mitre.png) | |
| First Sysmon alerts, mapped to MITRE ATT&CK | |

## Roadmap

The full plan, with why each chapter matters and when it counts as done, is in [ROADMAP.md](ROADMAP.md).

| Work | Position |
|---|---|
| Core endpoint SOC, warehouse and reports | Built; health, updates and fresh-event checks continue |
| Analyst learning | Resume the [bounded TCP/Nmap lesson](docs/nmap-exposure-baseline.md); owner explanations stay separate from automated checks |
| New PowerShell policy-probe tune | [Reviewed and held](docs/powershell-policy-probe-tuning-review.md); filename-only exception is not deployed |
| Network reporting | Offline record displayed; saved-live dashboard/Indexer/SQL pass; fresh Power BI rendering deferred |
| Wider network visibility | Capture-path proof, routine DNS/flow collection, budgets and sustained performance before coverage claims |
| Platform protection | Off-machine/Wazuh recovery, disk encryption, Secure Boot, account/access review and firewall-log SIEM collection remain open |
| Later lab chapters | Separate Burp/sqlmap/Metasploit lessons, attack validation and private live API; no new tools installed by this handoff |

## Tools

Wazuh 4.14 · Sysmon · Ubuntu Server 24.04 · Hyper-V · SQL Server 2025 Developer · Python 3.14 (pyodbc, requests) · Power BI Desktop · PowerShell · Suricata · Tailscale · Wireshark/TShark · Nmap · ufw · OpenSSH

## Copyright

© 2026 Jordan Carven-Bellace. All rights reserved. The code and write-ups are shared to be read and evaluated; no license to reuse them is granted.
