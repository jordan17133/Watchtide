# Watchtide

**An evidence-led home SOC connecting security telemetry, investigation and reporting.**

Watchtide is Jordan Carven-Bellace's independent cybersecurity lab and analyst-learning
portfolio. It brings Windows telemetry into Wazuh, follows selected alerts through
SQL Server and Power BI, and documents what each investigation or controlled test
actually proves.

[Read the portfolio case study](https://jordan-portfolio-alpha.vercel.app/projects/watchtide) |
[Explore the historical console](https://jordan17133.github.io/Watchtide/) |
[Browse the evidence](docs/portfolio-evidence.md)

![Historical Watchtide SOC Overview: alert severity, hourly volume, busiest rules and a scoped tuning timeline](https://jordan-portfolio-alpha.vercel.app/images/watchtide-soc-overview-2026-10-12.png)

*Power BI evidence refreshed October 12, 2026. Local process paths are masked;
the original figures are retained. This is a static historical image, not live
telemetry. README reviewed November 2, 2026; no new lab run is implied.*

## What The Project Demonstrates

- **Investigate before tuning.** Trace an alert to its writer, context and cause;
  test narrow conditions instead of treating a familiar filename as benign.
- **Check the whole path.** A successful database load does not establish that
  endpoint collection is fresh. Follow event identity from source to reporting.
- **Use controls.** Compare a marked network request with an unmarked request,
  and distinguish a rule match from an actual incident.
- **Make the evidence usable.** Keep queryable records, reporting views, case
  notes, dated visuals and explicit recovery limits.

## Follow The Data

```text
Windows / Sysmon -> Wazuh agent -> Ubuntu Hyper-V SIEM
                                       |
                             Manager -> Filebeat -> Indexer
                                                      |
                                      restricted, TLS-verified read
                                                      |
                                             SQL Server -> Power BI

Controlled Suricata test -> EVE alert -> Wazuh -> the same reporting path
Public console          <- separately sanitized historical snapshot
```

The warehouse imports alert documents, not every raw event, packet or flow.
Power BI reflects its last import. The public console has no live connection to
the private SOC. [Read the system interaction map](docs/triage-system-audit.md).

## Selected Evidence

These are dated lab results, not current uptime or complete security coverage.

| Work | Recorded result | Evidence and limit |
| --- | --- | --- |
| Alert investigation | 478 of 506 alerts in the original Critical cluster shared one policy-test pattern | [September 30 investigation](triage/2026-09-30-rule-92213-powershell-policy-test-noise.md). A historical cluster, not a verdict on future events. |
| Collection troubleshooting | Two benign Sysmon records matched their Indexer, SQL and reporting-view identities after a bounded repair | [October 7 trace](docs/collection-health-validation.md). Does not recover earlier lost records or prove restart durability. |
| Network validation | One marked request alerted; one unmarked control did not | [October 7 Suricata trial](docs/suricata-live-trial.md). Two controlled requests, not continuous monitoring. |
| Recovery | 37,605 alert rows restored, clean integrity check and 20 readable SQL views | [October 7 SQL drill](docs/sql-recovery-validation.md). Same PC and SQL instance, not off-machine disaster recovery. |
| Reporting | Six-page Power BI project with security, case, pipeline and network-test views | [Reporting case study](https://jordan-portfolio-alpha.vercel.app/projects/security-data-pipeline). October 12 evidence; alert counts are not incident counts. |

## Start Where You Are Interested

| Area | Open |
| --- | --- |
| Overview and visual walkthrough | [Watchtide case study](https://jordan-portfolio-alpha.vercel.app/projects/watchtide), [public console](https://jordan17133.github.io/Watchtide/) |
| Investigations and analyst reasoning | [Evidence index](docs/portfolio-evidence.md), [triage reports](triage/), [daily analyst routine](docs/analyst-toolkit-runbook.md#a-daily-routine-you-can-explain) |
| Rules, ingestion and reporting | [Detection rules](wazuh/rules/), [loader](loader/), [SQL warehouse](warehouse/), [six-page Power BI project](powerbi/) |
| Scope, privacy and next work | [Publication controls](docs/publication-safety.md), [dated status](STATUS.md#current-snapshot), [roadmap](ROADMAP.md#current-execution-order) |

## Development Process

Built with substantial Claude and Codex assistance. My work includes lab setup,
operational context, scoped decisions, administrator/test steps and hands-on
investigation and reporting work. AI agents generated substantial supporting
code and documentation and performed much of the troubleshooting and testing.
[The contribution statement](docs/portfolio/watchtide-case-study.md#development-process)
separates owner-reported work from recorded technical verification.

## Boundaries And Ongoing Work

Watchtide is a learning lab, not a managed security service or production-ready
protection product. Collection reliability, source recovery, detection validation
and independent recovery retain separate verification gates. No current healthy-
collection or complete network-coverage claim is made by this README.

- Hyper-V NAT does not provide whole-home traffic visibility.
- Tailscale enrollment alone does not route ordinary browsing through a privacy VPN.
- Wireshark/TShark reviews packets; Nmap performs separately authorized checks.
  Neither is an automatic warehouse feed.
- Historical rule research does not classify later events or prove tested ATT&CK
  coverage. Stored case associations have their own documented limits.
- Public configurations are sanitized examples, not deployable copies of the
  private host. Credentials, raw captures and imported report caches stay private.

The [roadmap](ROADMAP.md) records the next checks and their completion criteria.
New results belong beside their evidence and date, not in an undated all-clear.

## Copyright

Copyright 2026 Jordan Carven-Bellace. All rights reserved. The code and write-ups
are shared to be read and evaluated; no license to reuse them is granted.
