# Watchtide: A Home SOC Built on Wazuh, SQL Server and Power BI

An evidence-led security operations lab and analyst-learning portfolio.
**Windows/Sysmon -> Wazuh -> SQL Server -> Power BI**, with controlled Suricata
network tests and documented investigations.

**Author:** Jordan Carven-Bellace

*Formerly SentinelGrid; existing database, VM, task and rule-file names retain that identity.*

**[Open the Watchtide console](https://jordan17133.github.io/Watchtide/)**:
read-only, sanitized historical alerts, cases and ATT&CK coverage.
No live connection to the private SOC. Check the snapshot's date.
[Evidence and investigations](docs/portfolio-evidence.md) |
[Current status](STATUS.md) | [Roadmap](ROADMAP.md)

## At A Glance

Updated October 7, 2026. Results are dated observations, not a security guarantee.

| Result | Evidence / scope |
|---|---|
| **37,605 alerts recovered** | Copy-only SQL backup, disposable restore and clean CHECKDB; same-instance recovery only ([validation](docs/sql-recovery-validation.md)) |
| **99 Critical vulnerabilities reduced to zero** | Historical remediation baseline; later inventory requires fresh review ([investigation](docs/finding-forgotten-browser.md)) |
| **94% of the original Critical cluster reclassified** | Narrow tested tuning, not removal of every future Critical alert ([case](triage/2026-09-30-rule-92213-powershell-policy-test-noise.md)) |
| **Six Power BI pages** | All rendered October 5; fresh October 7 saved-live record rendering remains deferred ([report proof](docs/network-reporting-validation.md)) |
| **Network rule proved with controls** | One marked live request alerted, one unmarked request did not; no continuous capture ([trial](docs/suricata-live-trial.md)) |

[Daily analyst routine](docs/analyst-toolkit-runbook.md#a-daily-routine-you-can-explain)

![SOC Overview page in Power BI](docs/screenshots/powerbi-soc-overview.jpg)

*Screenshot captured October 1, 2026; values are historical.*

## Engineering And Analyst Work

- **Investigation before suppression:** precise tested child rules, reviewed causes
  and written investigations; [evidence index](docs/portfolio-evidence.md#investigations).
- **Least-privilege access:** device-scoped private administration, trusted HTTPS,
  a forwarding-only loader key and read-only Indexer account;
  [access results and open gates](docs/private-access-validation.md).
- **Reporting reliability:** diagnosed a Power BI/loader deadlock and verified
  committed-snapshot reads; [diagnosis](docs/report-refresh-reliability.md).
- **Collection recovery:** fixed an obsolete VM-name mapping and matched two new
  Sysmon records through the normal loader to SQL. Manual health checks now flag
  fresh data and recent queue-pressure warnings separately; [proof and limits](docs/collection-health-validation.md).

## Architecture

```text
Windows: Sysmon / Security / Defender / PowerShell / file changes
    -> Wazuh agent -> Ubuntu Hyper-V VM
                     Wazuh manager -> Filebeat -> Indexer -> Wazuh dashboard
                                                  |
                               restricted, TLS-verified SSH forward
                                                  |
                               scheduled loader, every 15 minutes
                                                  v
                                         SQL Server -> Power BI

Suricata controlled capture -> EVE alert -> Wazuh -> same reporting pipeline
Public console <- separately reviewed, sanitized historical snapshot
```

Nmap checks selected services or generates authorized test traffic; Wireshark/TShark
explains saved packets. Neither is an automatic warehouse feed. Hyper-V NAT does
not provide whole-home visibility. [System interaction map](docs/triage-system-audit.md).

## Explore The Repository

| Area | Start here |
|---|---|
| Build and operation | [Runbook](SentinelGrid-Build-Runbook.md), [build log](BUILD-LOG.md), [daily analyst routine](docs/analyst-toolkit-runbook.md#a-daily-routine-you-can-explain) |
| Detection and investigation | [Wazuh rules](wazuh/rules/), [Suricata rule](suricata/rules/watchtide-pilot.rules), [library rollout](docs/detection-library-plan.md), [triage reports](triage/) |
| Data and reporting | [Loader](loader/), [warehouse](warehouse/), [existing six-page Power BI project](powerbi/) |
| Detailed evidence and images | [Results, investigations and gallery](docs/portfolio-evidence.md) |
| Privacy and review | [Static console](console/), [publication controls](docs/publication-safety.md), [repository review](docs/repository-review.md) |

Historical rule research is not a verdict on later events. Case counts currently
use inferred rule/time matches, not exact evidence membership. Public configurations
are sanitized examples, not deployable copies of this host. Credentials, captures
and imported Power BI caches stay private. Tailscale enrollment alone does not
route ordinary browsing through privacy VPN egress.

## Roadmap

The full plan, with why each chapter matters and when it counts as done, is in [ROADMAP.md](ROADMAP.md).

| Work | Position |
|---|---|
| Collection reliability | Manual freshness/queue check verified; real heartbeats, complete source-loss checks and tested local notification delivery remain open |
| Useful Suricata records | Explain bounded traffic on a proved path before routine DNS/flow or browsing-coverage claims |
| TCP/Nmap validation | Small maintained-rule batch, harmless controls and exact reporting trace; fresh saved-live Power BI check remains deferred |
| Broader analysis | Evaluate Zeek after a useful feed/resource budget, then forensic and isolated web/test-lab lessons |
| Platform protection | Account/MFA, disk/boot protection, access boundaries and separate recovery remain open or deferred |

The [completion checklist](docs/soc-completion-plan.md) retains the numbered stages.
The [27-example attack/defense reference](docs/attack-defense-reference.md) guides
layered prevention, detection, response and recovery, not 27 validated detections.
No total privacy or complete attack coverage is claimed.

## Copyright

© 2026 Jordan Carven-Bellace. All rights reserved. The code and write-ups are shared to be read and evaluated; no license to reuse them is granted.
