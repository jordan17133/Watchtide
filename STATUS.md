# Watchtide: Detailed Status

This page holds the dated, evidence-level status notes for work in progress. The
[README](README.md) summarizes what is built; the [build log](BUILD-LOG.md) records
how each step happened; the [roadmap](ROADMAP.md) lists what comes next.

## Current milestones

Updated October 7, 2026. The pipeline and investigations are built; these next milestones have their own validation gates.

| Priority | Work | Status | Evidence to publish |
|---|---|---|---|
| Current | **Bounded hardening checks** | File/logging/software checks and strict loopback-only loader SSH verified; firewall sample interpreted, blocked-traffic SIEM gap confirmed; management/account, disk/boot and recovery gates remain open | [Hardening gates](docs/hardening-validation.md), [host exposure and visibility](docs/host-exposure-validation.md), [software evidence](docs/software-hardening-validation.md) |
| Current | **Suricata traffic, rules and reporting pilot** | Offline alert verified through dashboard/Indexer/SQL and Power BI; bounded live trial and packet review pass; saved-live alert verified in Wazuh dashboard, Indexer and normal-loader SQL; fresh Power BI check deferred; permanent service stays masked | [Engine validation](docs/suricata-offline-validation.md), [six-page reporting proof](docs/network-reporting-validation.md), [live trial measurements](docs/suricata-live-trial.md), [live reporting handoff and open gates](docs/suricata-live-reporting-handoff.md) |
| Retained | **Private SOC access with Tailscale** | Local trusted HTTPS/login verified; renewal setup reported successful; phone remains denied; approved off-LAN testing deferred | [Recorded access results and open gates](docs/private-access-validation.md), renewal upkeep and remaining recovery/reporting checks |
| Deferred | **Whole-home browsing-privacy routing** | Extra VPN/router work declined for now; no privacy-egress change deployed | A separately approved design and per-device routing/DNS/IPv6/failure tests before any coverage claim |

The [private-access plan](docs/private-access-plan.md) explains the VPN decision, remaining steps and completion tests. The [network SOC maturity plan](docs/soc-network-maturity-plan.md) adds a stage checklist for measured device coverage, routine telemetry, correlation, analyst workflows and tested recovery.

## Hardening

The owner selected hardening before additional capture and deferred recovery. Reviewed private-file, effective firewall-logging and software checks pass. The loader now explicitly binds its tunnel to loopback and requires a verified SSH host identity; actual socket/search/cleanup checks and the subsequent automatic load succeeded. An independent 2,000-record firewall sample was 98.9% UDP 5353 multicast, consistent with local discovery, not thousands of confirmed attacks. Actual agent/audit settings confirm blocked-traffic records are not yet collected into Wazuh. Broad Hyper-V management exceptions were reviewed privately but left unchanged pending the owner's usage details. The Windows system drive remains unencrypted and host Secure Boot off; account/MFA, resource budgets and recovery gates remain open ([host findings](docs/host-exposure-validation.md), [hardening checklist](docs/hardening-validation.md)).

## Software review (October 5)

All ten current scanner findings have a documented [applicability assessment](docs/vulnerability-applicability-review.md). The flagged Python CVE does not apply to the verified interpreter, but newer security releases are available for both runtime lines. Steam's client is newer than its uninstall version, yet broad local permissions were present; a blanket false-positive or reinstall claim is not justified. Desktop-app advisory scope also needs validation. Nothing was suppressed, patched or newly credited as resolved in this read-only pass.

## Applied software batch (October 5-6)

The SOC's existing environment now uses Python 3.14.8; candidate and installed-runtime tests passed, and fresh ingestion and trusted HTTPS remain successful. Steam stays installed with the reviewed broad Users folder/registry write grants removed; owners and five binary hashes are unchanged, and unelevated owner write probes pass. Actual Steam gameplay and updater checks are not claimed. The other Python installer is verified/staged, not run: six unrelated workloads remain active at the owner's request. No new vulnerability-resolution count or CIS score is inferred ([evidence and limits](docs/software-hardening-validation.md)).

## Network pilot (Suricata)

The offline marker-rule test and its Wazuh/SQL/Power BI trace pass. All six existing Power BI pages rendered during the October 5 check ([historical report proof and schema limit](docs/network-reporting-validation.md)). On October 7, a [bounded live VM-to-host trial](docs/suricata-live-trial.md) captured one request per control with zero drops: the marked request alerted and the unmarked request did not. Independent TShark inspection confirmed the actual packets, hashes and alert time; all five guest services were active afterward. Its [separate saved-live reporting handoff](docs/suricata-live-reporting-handoff.md) also completed. The exact document is verified in the authenticated Wazuh dashboard, TLS-verified Indexer and SQL via the normal scheduled loader, with original packet time preserved. The warehouse now contains one offline and one saved-live validation record. Existing Power BI definitions are updated; fresh Desktop verification is deferred while the owner uses the PC. Owner explanation, sustained capture, Windows browsing and iPhone coverage remain open. The permanent Suricata service stays masked. The [pilot guide](docs/suricata-pilot.md) and [network plan](docs/network-coverage-plan.md) separate proof from remaining scope.

## Private remote access (Tailscale)

The Windows admin host and Ubuntu VM are enrolled and online. The default allow-all grant was replaced with device-scoped TCP 22/443 permissions, and four policy tests were accepted on save. Local IPv4 SSH/dashboard reachability and API/indexer unreachability are verified; the post-policy SQL load succeeded with new Sysmon alerts. Trusted local HTTPS and authenticated dashboard access now pass, and renewal setup was reported successful. IPv6 SSH works, but the dashboard has no IPv6 listener. The [validation report](docs/private-access-validation.md) records the evidence and limits. Approved off-LAN access, remaining unprivileged-device/public-access/revocation checks and a remote controlled event trace remain open. Extra VPN/router work and phone dashboard access remain deferred. Tailscale enrollment is not ordinary browsing-privacy protection. A future live console/API will be private; GitHub Pages will continue to serve the sanitized snapshot.

## Recovery

Hyper-V console access demonstrated; checkpoint creation and five active guest services afterward reported after backup-helper repair. VM-local dashboard/UFW backup checks passed according to the user; checkpoint metadata, protected off-VM backups and separate restore validation remain pending.

## Reliability (October 4)

Workspace-review fixes have offline regression coverage for loader failures, late-alert reconciliation, scoped case start dates, publication parsing and agent restart recovery. Individual alerts no longer inherit a historical rule verdict. The first scheduled full reconciliation succeeded in 30 seconds with 96 new alerts. A subsequent incremental run succeeded but took over eight minutes; a SQL timeout and recorded host memory pressure require follow-up before expanding the lab. Controlled late-event validation remains pending. See [validation and limits](docs/reliability-validation.md).

## Report refresh (October 5)

The first actual six-page refresh failed with a confirmed loader/read deadlock. A guarded committed-snapshot fix passed isolated tests and was applied in the approved quiet window. All 18 SQL report sources passed a bounded read; the Desktop retest now shows all six pages populated, with single-table refresh persisted in Git. Three recent automatic loads completed in 2.4-3.3 seconds. Sustained performance and refresh duration remain unproven, especially under host memory pressure. See [diagnosis and safeguards](docs/report-refresh-reliability.md).
