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
- [x] Every fired MITRE ATT&CK technique triaged to a verdict
- [x] First controlled attack test: SSH password guessing, detected end to end
- [x] Least-privilege reporting role, tested
- [x] Five Power BI dashboards kept as code in Git
- [x] Public read-only SOC console on a scrubbed snapshot ([console](https://jordan17133.github.io/Watchtide/))

## Current Execution Order

The immediate goal is a SOC covering the home network, with a separate
whole-network browsing-privacy design. Private SOC access, network detection,
and internet egress privacy are different controls; phone enrollment does not
complete any of them. See the [network coverage plan](docs/network-coverage-plan.md).

1. Finish the current Stage 4c access validation and recheck loader/reporting health.
2. Map the router, switches, Wi-Fi and Hyper-V paths; select and verify a traffic capture point and available sensor resources.
3. Build a Stage 5 Suricata pilot and trace a harmless network event into Wazuh and reporting.
4. Expand measured coverage across approved devices/segments and review whole-network privacy routing, DNS, IPv6 and failure behavior. Protect the resulting private logs.

No Suricata sensor or whole-network privacy-egress change has been deployed.
Permanent phone dashboard access is not required; the phone currently serves
as a denied off-LAN test client. Other portfolio chapters remain planned work,
not prerequisites that must all precede the network pilot.

**Reliability checkpoint (October 4, 2026):** the six workspace-review findings have implementation fixes and offline regression checks. The first scheduled reconciliation succeeded in 30 seconds with 96 new alerts. A later incremental run succeeded but took over eight minutes; SQL timeout and host paging evidence make runtime/memory follow-up the next prerequisite. A controlled late-event trace and Power BI refresh remain pending before expanding collection. The public console keeps individual alerts untriaged and historical rule reviews separate. See [validation and limits](docs/reliability-validation.md). This does not close the private-access security gates below.

**Current focus (October 4, 2026):** the Windows admin host, Ubuntu VM and an iPhone test client are enrolled in Tailscale. The reviewed policy still grants only Windows-to-VM TCP 22/443, with four accepted policy tests. [Access results](docs/private-access-validation.md) include local management/data-port checks, post-change SQL ingestion, and a user-confirmed phone HTTPS timeout over cellular with normal websites loading. The phone has no SOC grant. Supplied firewall tables were reviewed, the Hyper-V backup helper was repaired, and new checkpoint creation was reported after a Production-Only settings screenshot. Confirm its metadata/post-creation health and exact current private backups; separate backup/restore validation remains open. VM listener output explains the IPv6 dashboard gap; trusted HTTPS and approved off-LAN access remain next. Remaining denied-service tests, public-access/revocation checks, a controlled event trace and Power BI refresh are still open. The [private-access plan](docs/private-access-plan.md) records the remaining gates. Later chapters are planned work, with no promised delivery dates.

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
| 11 | **Network monitoring: Suricata** (runbook Stage 5) | Today the lab is endpoint-only | DNS and HTTP events visible and traced to Wazuh records; VPN visibility limits documented |
| 12 | **Private live API/console** (runbook Stage 6, second part) | Work cases from the console, not a script | Authenticated analysts open, assign and close cases over private access; public GitHub Pages remains a sanitized snapshot |
| 13 | **Alert notifications** for level 12 and above | Faster response | Optional; tested so it never floods |

## Ongoing upkeep

- Weekly: check Pipeline Health (loader success above 95%, data fresh within 30 minutes) and patch the VM.
- Before risky work: take a Hyper-V checkpoint.
- After a Wazuh upgrade: re-export the ATT&CK catalog and reload it.
- After any new case: review its public display text, update the field-scoped approval catalog privately, then validate and refresh the console snapshot. New live text must not be auto-approved.
- After a device or access-policy change: repeat the allowed/denied connection tests; review available authentication and policy-change records.
- Before publishing: run publication regression tests and snapshot validation, review new documentation/configuration/screenshots for secrets and personal data, and use the sanitized public-copy process. [Publication controls](docs/publication-safety.md) supplement the [bounded privacy audit](docs/public-privacy-audit.md); historical disclosures remain separate.
