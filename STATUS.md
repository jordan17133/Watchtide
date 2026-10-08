# Watchtide: Detailed Status

This page holds the dated, evidence-level status notes for work in progress. The
[README](README.md) summarizes what is built; the [build log](BUILD-LOG.md) records
how each step happened; the [roadmap](ROADMAP.md) lists what comes next.

## Active Work

No active source-edit claim. The October 7 repository review is complete:
concise README/evidence navigation, truthful public historical-review/inferred
case labels, level-16 compatibility, unavailable-metric handling and queue-aware
manual collection checks. See [review scope, tests and remaining gates](docs/repository-review.md).
Git history identifies the source/publication revisions; these source checks
do not imply deployment of new live rules, schema, notifications or capture.

Codex completed the authorized repair's
exact fresh-event trace, reconciled Claude's handoff and added a tested/manual
SQL collection check. Continue with the bounded heartbeat/source-health and
local notification phase in the [completion plan](docs/soc-completion-plan.md).
Scheduling, delivery and new permissions need their own reviewed scope.

The owner's [27-example attack/defense list](docs/attack-defense-reference.md)
is now retained and mapped to the existing completion packages, with primary-source
qualifications and current coverage limits. All 27 entries, 158 local links across
the five touched documents and 33 publication-privacy regression checks passed.
This was documentation only, not new detection validation or a live change.
The reference is included in this reviewed publication batch; it does not
change the execution order or approve new live operations.

At 9:54 PM Eastern, loader/Windows observations were recent, but the queue-aware
checker flagged five retained 24-hour warnings as attention. A later recovery
message does not prove missing events recovered. Complete source-loss health
remains open. The review passed 324 Python tests (13 optional SQL tests skipped),
151 Windows PowerShell assertions and all five console views on desktop/mobile,
including empty, nullable and level-16 fixtures. The historical public snapshot
is retained; no fresh Power BI import or live export was made.

October 7 recovery: an authenticated, identity-checked guest preflight confirmed
the intended target. The authorized repair removed one obsolete duplicate
manager-name entry, preserved the agent configuration and restarted only
WazuhSvc. The agent connected at 6:07 PM Eastern. Two benign Sysmon records
match their Indexer documents, SQL raw payloads and reporting-view identities;
the normal scheduled loader imported them at 6:12 PM. Protected evidence,
hashes and reader permissions pass. No firewall, tailnet or rule changes.

At 8:37 PM Eastern, new Windows records still arrived in the TLS-verified
Indexer; the authenticated dashboard showed Active. A new read-only collection
check passed against SQL at 8:40 PM. This closes the current outage/fresh-event
trace, not restart durability, earlier queue loss or every source's health.
An automatic watchdog and notification delivery are not deployed. The owner
selected local Windows notifications first; no external service is connected.

Verification: 163 focused checks passed (33 repair, 12 exact trace, 17 diagnostic,
25 collection health, 43 reliability/library and 33 publication privacy). All
372 checked local documentation links resolve. Protected evidence hashes/readers
and the existing sanitized snapshot validator pass; no new public snapshot or
Power BI import was generated.

The previous read-only classification/case/report audit and the plain-English
interaction map are documented. In that audit, no verdict, SQL
schema, rule, collection, service or UI behavior changed. Scope the collection
repair and triage improvements separately before deployment.

## Pickup And Execution Order

Claude's handoff commit `b067d36` was located in its separate workspace worktree,
not the main SOC checkout. Its drafts were reconciled with this repository;
this file remains the authoritative status, not the older side-workspace map.

| Order | Work | State / finish line |
|---|---|---|
| 0 | Restore current Windows collection | Closed for this outage: identity-checked bounded repair and exact Sysmon/Indexer/normal-loader SQL trace pass; [repair evidence](docs/collection-health-validation.md). Restart durability and historical loss remain separate |
| 0a | Monitor the monitoring | Read-only SQL freshness/queue check tested and manually verified; five retained warnings require review. Heartbeat/full source-loss checks, scheduling and notification delivery remain open. [Completion plan](docs/soc-completion-plan.md) reconciles Claude's handoff |
| 1 | Handoff and L0 explanation | Scannable README, private coordination agreement and corrected [packet-to-report lesson](docs/L0-event-to-report-trace.md) applied; 235 selected checks passed; owner explanation stays open |
| 2 | Triage integrity and PowerShell noise review | Public historical-review/inferred-count labels and level-16 handling corrected/tested; exact case memberships, dispositions and fresh Power BI gates remain open. [Audit](docs/triage-system-audit.md). Existing rule 100100 retained; filename-only expansion remains held |
| 3 | Resume TCP/Nmap learning | Build a harmless offline TCP rule/control test, then a separate bounded owned-VM exercise on a verified capture path; [existing baseline](docs/nmap-exposure-baseline.md) is already complete |
| 4 | Reporting and reliability | Fresh saved-live Power BI rendering when the PC is available; explain source/packet, Wazuh, SQL and refresh times; retain [loader duration follow-up](docs/loader-slow-run-investigation.md) |
| 5 | Expand network coverage | Supported feed, resource/drop/retention budgets and routine DNS/flow visibility before sustained capture or phone/home coverage claims |

The owner's maintained-library request now has a [separate inventory and rollout
guide](docs/detection-library-plan.md). All 147 observed alert types are indexed
privately; 40 have historical rule reviews and 107 do not, without inheriting
old verdicts. ET Open is downloaded and field-reviewed only, not deployed.
The earlier SQL/Indexer cutoff was a disconnection alert at 10:49:46.056 UTC,
despite running services and successful loader outcomes. That outage is now
repaired and traced independently. Explicit Sysmon drops still need a separate
cause/health review; missing records are not presumed recovered. Establish
source-health signals before increasing live detection load. Independent
offline TCP preparation can resume; TCP/Nmap remains the selected learning track.

Off-LAN administration, additional routers/VPN egress and separate web/test VMs
remain deferred or planned. They do not displace the owner's TCP/Nmap learning
focus. Resume that track after this reconciliation, rather than redoing the
completed ICMP trial or Nmap baseline.

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

### Windows Collection Gate (October 7)

**Later result:** the authorized repair and exact source/Indexer/normal-loader
SQL trace pass. The authenticated dashboard shows Active, and the subsequent
manual SQL health check passes. See the [repair and remaining gates](docs/collection-health-validation.md).
The following paragraphs record the earlier diagnostic, not current outage state.

At approximately 20:55-21:01 UTC, read-only SQL and TLS-verified Indexer checks
found the same Windows cutoff at 10:49:46.056 UTC, with 34,124 retained Windows
alerts; its latest rule 504 reports disconnection. New manager records continue
arriving and the latest twelve loader outcomes succeeded. The running Windows
Wazuh process owns a SYN-sent connection toward a stale VM address, while one
bounded handshake to the current LAN data port passed. Manager-name resolution
has both current-subnet and stale results. Protected agent files cannot be read
by the unelevated tool process; no permissions were bypassed.

A new administrator diagnostic passed 17 synthetic checks. At 21:29 UTC, the
owner ran it; independently checked private artifacts confirm the actual
hostname-based TCP configuration, pending state and repeated stale-address
connection errors. Its three evidence-file hashes and reader permissions pass.
The named VM is on the Default Switch, but its guest IP metadata is empty;
do not credit this as a complete guest-address identity check. No settings or
services changed. Historical Sysmon
Event 255 text explicitly reports dropped registry events; do not sum counters
or assume a shared cause with this outage. No live repair, new rules, scan or
capture was performed in that diagnostic batch. See [actual checks and completion gates](docs/collection-health-validation.md).
Verification: 17 helper, 43 reliability/library and 33 publication-privacy
checks passed (93 total); all 336 checked local documentation links resolve.
Private health evidence reader permissions and snapshot hashes were checked.

### Classification And Case Audit (October 7)

Bounded SQL/source review around 21:25 UTC: 37,656 retained alerts, 147 observed
rule types, 40 historical rule reviews; 10 cases, nine closed. There are 43
observed ATT&CK techniques, six without a review for the most frequent rule,
and 21 with at least one unreviewed fired rule (overlapping sets). Current
case counts infer membership from rules and first-alert-to-close windows;
424 alerts are counted in two cases, without explicit document membership.
The older public snapshot has 38 techniques and 792 selected alerts, all with
null event verdicts. No new verdicts were assigned. The [audit and interaction
map](docs/triage-system-audit.md) preserve these distinctions and add scoped
evidence links, clearer labels, level-16 handling and retention/prerequisite
gates to the existing Stage 7/8 and detection work, not a new parallel build.
Ninety-three existing focused checks pass; they are not remediation of these
new design findings or evidence that all historical verdicts are justified.

### Maintained Rule Library Preparation (October 7)

At 20:24 UTC, a bounded read-only warehouse query counted 37,641 retained alerts
and 147 observed rule IDs (highest per-ID bands: 1 Critical, 4 High, 29 Medium,
113 Low). The existing October 1 catalog remains a historical MITRE-tagged
export, not the current total installed-rule inventory. Detailed JSON/Markdown
with every observed ID and historical-review references stays owner-protected.

Official version-addressed ET Open archive downloaded over HTTPS and reviewed
with a hash-pinned, uninstalled OISF parser: 54 rule files, 72,100 unique parsed
entries; outside deleted files, 52,608 uncommented and 16,029 commented entries.
Field inspection is not Suricata 8 engine validation, source signature
authentication or tested coverage. No rules/configuration were rewritten or
deployed; no capture or service restart occurred. Earlier agent queue overflow
and Sysmon error warnings, followed by a normal-queue message, add a collection
health gate before sustained load. See [scope, results and gates](docs/detection-library-plan.md).

Twenty new helper regression tests passed; the selected cross-project suite
passed 244 checks, with 11 optional database-changing integration checks skipped
for this read-only scope. All 326 checked local documentation links resolve.
Detailed evidence-folder/file reader checks and snapshot hashes passed. Windows
Wazuh/Sysmon/SQL services are running. The latest five loader runs succeeded;
the last took 42.396 seconds and a preceding full reconciliation took 74.630
seconds. A host sample showed 695 MiB free physical memory. These are samples,
not a stable resource benchmark; no full-feed engine test started during gaming.

The offline marker-rule test and its Wazuh/SQL/Power BI trace pass. All six existing Power BI pages rendered during the October 5 check ([historical report proof and schema limit](docs/network-reporting-validation.md)). On October 7, a [bounded live VM-to-host trial](docs/suricata-live-trial.md) captured one request per control with zero drops: the marked request alerted and the unmarked request did not. Independent TShark inspection confirmed the actual packets, hashes and alert time; all five guest services were active afterward. Its [separate saved-live reporting handoff](docs/suricata-live-reporting-handoff.md) also completed. The exact document is verified in the authenticated Wazuh dashboard, TLS-verified Indexer and SQL via the normal scheduled loader, with original packet time preserved. The warehouse now contains one offline and one saved-live validation record. Existing Power BI definitions are updated; fresh Desktop verification is deferred while the owner uses the PC. Owner explanation, sustained capture, Windows browsing and iPhone coverage remain open. The permanent Suricata service stays masked. The [pilot guide](docs/suricata-pilot.md) and [network plan](docs/network-coverage-plan.md) separate proof from remaining scope.

## Private remote access (Tailscale)

The Windows admin host and Ubuntu VM are enrolled and online. The default allow-all grant was replaced with device-scoped TCP 22/443 permissions, and four policy tests were accepted on save. Local IPv4 SSH/dashboard reachability and API/indexer unreachability are verified; the post-policy SQL load succeeded with new Sysmon alerts. Trusted local HTTPS and authenticated dashboard access now pass, and renewal setup was reported successful. IPv6 SSH works, but the dashboard has no IPv6 listener. The [validation report](docs/private-access-validation.md) records the evidence and limits. Approved off-LAN access, remaining unprivileged-device/public-access/revocation checks and a remote controlled event trace remain open. Extra VPN/router work and phone dashboard access remain deferred. Tailscale enrollment is not ordinary browsing-privacy protection. A future live console/API will be private; GitHub Pages will continue to serve the sanitized snapshot.

## Recovery

Hyper-V console access demonstrated; checkpoint creation and five active guest
services afterward reported after backup-helper repair. VM-local dashboard/UFW
backup checks passed according to the user. Claude's October 7 same-instance SQL
drill recorded 37,605 restored alerts, 20 readable reporting views, clean CHECKDB,
matching schema/report grants and a matching controlled-event payload.
Independent handoff review matched the retained backup hash to both evidence
files, confirmed SQL backup/restore history, protected folder access, removal of
the disposable database and the live warehouse's online/multi-user snapshot-reading
state. No new restore was run. See [local SQL recovery validation](docs/sql-recovery-validation.md).
Checkpoint metadata, an off-machine copy, other-instance identity recovery,
Wazuh restoration and backup encryption remain unverified. This closes a local
SQL recovery test, not whole-PC recovery.

## Reliability (October 4)

Workspace-review fixes have offline regression coverage for loader failures, late-alert reconciliation, scoped case start dates, publication parsing and agent restart recovery. Individual alerts no longer inherit a historical rule verdict. The first scheduled full reconciliation succeeded in 30 seconds with 96 new alerts. A subsequent incremental run succeeded but took over eight minutes; a SQL timeout and recorded host memory pressure require follow-up before expanding the lab. Controlled late-event validation remains pending. See [validation and limits](docs/reliability-validation.md).

## Reliability Follow-Up (October 7)

October 7 handoff review: the SQL memory ceiling is already 4096 MB. Ten recent
loads succeeded, but one took 211.527 seconds and two others took 30.397 and
73.506 seconds; the latest two took 2.052 and 2.452 seconds. Earlier memory
pressure is documented, but current tail latency is not explained by that alone.
No memory, scheduler or loader setting changed. The [bounded follow-up](docs/loader-slow-run-investigation.md)
keeps representative performance and slow-run cause open before sustained capture.

## Report refresh (October 5)

The first actual six-page refresh failed with a confirmed loader/read deadlock. A guarded committed-snapshot fix passed isolated tests and was applied in the approved quiet window. All 18 SQL report sources passed a bounded read; the Desktop retest now shows all six pages populated, with single-table refresh persisted in Git. Three recent automatic loads completed in 2.4-3.3 seconds. Sustained performance and refresh duration remain unproven, especially under host memory pressure. See [diagnosis and safeguards](docs/report-refresh-reliability.md).
