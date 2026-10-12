# Watchtide: Detailed Status

This page holds the dated, evidence-level status notes for work in progress. The
[README](README.md) summarizes what is built; the [build log](BUILD-LOG.md) records
how each step happened; the [roadmap](ROADMAP.md) lists what comes next.

## Active Work

October 12, 2026, Codex source privacy/contribution/naming batch complete; claim
released. The [closeout checklist](docs/presentation-and-operator-checklist.md)
tracks fresh Power BI checks and remaining operations. Owner reports lab creation,
configuration, rule/SQL work, investigations and Power BI visuals with AI help;
this is owner-reported attribution, not independent proof of each historical step.
Power BI was saved/closed by the owner before project-file renaming. No database
rename, live collector/rule change or sustained capture is part of this batch.
470 Python tests pass; 13 database-changing tests skipped. Project/model links,
six-page identity and private cache/model hashes pass; actual Desktop refresh and
the later saved-live rendering remain open. GitHub publication is owner-approved
and has separate generated-copy/remote checks. Website integration remains with
the portfolio chat.

October 11, 2026, Codex watchdog review/preparation complete; source claim released.
[Engineering review](docs/watchdog-engineering-review.md) checks task identity,
current state permissions and owner-connection read scope. Owner selected the
isolated four-hour candidate for preparation, not activation. Runtime/SQL trust
boundaries, failure-reporting and reboot gates remain open. No live module, task,
permission/grant, popup, SSH, capture, firewall/VPN or report change.

October 11, 2026, Codex SOC publication content prepared; source-file claim
released. [Case study and website handoff](docs/portfolio/watchtide-publication-kit.md)
package dated evidence, not new coverage. Seven focused content checks pass;
private coordination stays excluded from the sanitized copy. The separate
website chat owns integration, hosting and indexing; none was changed here.
Watchdog policy/read-scope review remains the first open SOC task. No new capture,
data export, report refresh, notification or live SOC change.

October 11, 2026, Codex reconciliation complete; source-file claim released.
Current navigation, dated evidence and explicit VM-target parameters now agree.
433 Python tests and 69 focused PowerShell checks pass; 13 optional database
tests were deliberately skipped. Publication has its own sanitized-copy/secret
checks. No live rule, task, firewall, VPN, guest, report-refresh or popup change.

## Current Snapshot

Reconciled October 11, 2026. This section is the current pickup map; the dated
updates below preserve earlier states. Reported deployments are not credited as
newly engine-verified by this documentation pass. See the
[reconciliation record and verification limits](docs/current-state-reconciliation.md).

| Area | Latest supported state | Remaining gate |
|---|---|---|
| Lab identity | Hyper-V display name `Watchtide`, owner-reported October 10; October 12 Power BI project/report/model and runbook paths renamed to Watchtide with preserved identities | Existing database/disk/helper identifiers need reviewed migration; fresh Desktop verification remains open; no VM/disk/database operation run |
| Collection watchdog | Deployed October 8; October 11 task identity/action and effective state permissions checked; isolated four-hour eligibility proposal prepared/tested | Protected runtime/restricted SQL identity, candidate activation, failure reporting, real heartbeat/loss cause and reboot/logon proof; task exit alone is not monitoring proof |
| Loader route | Tailscale guard deployment/restart control reported October 10; October 11 services Running | Guard task metadata unreadable here; route resilience and off-PC observer remain open; backlog copying is not proof of no upstream event loss |
| Firewall records | Owner-deployed source/rules 100141-100146; reported 18/18 engine tests and outbound control 100144 | Live inbound control, volume and exact reporting trace; filtered discovery and unsupported ICMP records are visibility limits |
| Tuning | Rules 100100-100106 in source; owner-deployed new children reported October 10-11 with level-3 live matches | Stored-pattern replay is not installed-engine negative testing; historical reviews cannot classify later events; filename-only draft remains held |
| Hardening | Owner-reported Windows CIS 63.2%, VM 66.2%, keys-only guest SSH and audit-mode Defender additions | Fresh independent posture/access review, audit-to-block evaluation, disk/boot protection and off-PC recovery; scores are not security guarantees |
| Network/reporting | Bounded ICMP proofs and saved-live dashboard/Indexer/SQL trace retained; seven TCP controls prepared/decoded | TCP engine syntax/replay, fresh saved-live Power BI rendering and sustained/wider coverage remain open |
| Publication | Public console remains a sanitized historical snapshot, not live SOC access | No new snapshot or report import in this cleanup; publish reviewed source changes only |

## Pickup And Execution Order

| Order | Work | Finish line |
|---|---|---|
| 0 | Reconcile current documentation and VM targets | Source cleanup complete/tested: consistent current map, preserved history and parameterized helpers; publication remains separately checked |
| 1 | Review the deployed watchdog and notification policy | Verify identity/read scope and state handling; do not let a past rule review silence unrelated future high-priority events; separately test reboot/logon |
| 2 | Complete offline TCP engine validation | Prepare a bounded keys-authenticated guest job; syntax/replay all saved positive and negative controls in fresh processes; no capture or permanent sensor |
| 3 | Resume bounded TCP/Nmap learning | After source/resource gates, prove the chosen owned-device capture path and trace a labeled detection; existing four-port baseline is already complete |
| 4 | Reporting and analyst integrity | Fresh six-page Power BI check when available, exact case-alert links and event-specific dispositions |
| 5 | Useful routine telemetry, then broader analysis | Measured device/path, loss/resource/retention budgets before sustained DNS/flow, Zeek evaluation and forensic lessons |

Off-LAN access, whole-home privacy routing and off-PC recovery remain deferred
or separately scoped. Do not redeploy completed work from a historical draft.
The earlier Claude drafts were reconciled; this source status remains the
authoritative map. Private pickup details are in `publish/handoffs/`.

## Historical Updates

The entries below are dated evidence, not additional current instructions.
Earlier "not deployed", "unconfirmed" and collection-gap observations are
superseded where the current snapshot links a later result. Historical test
counts, addresses, case totals and posture values must retain their original scope.

October 11, 2026 18:20 Eastern, Claude (claim released; hand-over to Codex): **tunes 100105
and 100106 are live** (owner deployed at 17:53). 100105 quiets Codex's bundled PowerShell
writing its execution-policy probe file (child of 92213, level 15 to 3; 475 of 502 level 15
alerts in the prior 24 hours); 100106 quiets Phone Link's background task host (child of
61634, level 12 to 3; 95 of 95 stored). Stored-data replay: 3,691/3,691 and 95/95 matched, 0
others, 10 lookalikes still alert. Live check 21:53-22:12 UTC: 100105 and 100106 each fired at level 3, zero new 61634, and the only 92213 came from another program (EdgeWebView2), still at level 15. Case SG-014 (owner's lockout at a WebView2
password prompt) closed. Pickup note: `publish/handoffs/codex-2026-10-10.md`.

October 11, 2026 17:50 Eastern, Claude (claim released): **Windows Firewall packet logs now
reach Wazuh** (owner deployed; `wazuh/rules/sentinelgrid_firewall.xml`, firewall block in
`wazuh/agent/default-agent.conf`). The engine overturned two drafts: `wazuh-analysisd -t`
refused `<field>` on static fields, and `wazuh-logtest` showed the stock `windows-firewall`
decoder and rule 4101 already claim these lines, so the custom decoder was dropped and rules
100141-100146 became children of 4101 (18 of 18 logtest lines as expected, the scan rule on
the 12th attempt). Live positive control: a temporary outbound block on TCP 40001 was logged
by Windows and arrived as rule 100144. Agent: mDNS filtered, zero drops. ICMP lines carry no
ports, so analysisd discards them before archiving (stock `log_fw` behaviour). Open: a live
inbound test of 100142/100143 from a LAN device (VM knocks over the Hyper-V switch are dropped
unlogged; the phone could not reach the PC).

October 10, 2026 17:40 Eastern, Claude (claim released): **tuning rules 100102-100104
are live** (owner deployed at 17:12; `wazuh/rules/sentinelgrid_tuning.xml`). SYSTEM
PowerShell's policy-test file (100102, child of 92205), Tailscale re-adding its own inbound
firewall rules (100103, child of 92043) and the Codex Store app re-registering its Chrome
native-messaging host (100104, child of 92041) now arrive at level 3. Warehouse check: 3
matches each for 100102 and 100103 in the first 15 minutes, zero new 92205 or 92043; 100104
confirmed on its hourly event at 17:43. `wazuh-logtest` could not test them: fed on stdin, the
eventchannel JSON decodes as plain `json`, so no Windows rule fires. Same day: VM fully patched.

October 9, 2026 23:45 Eastern, Claude (claim released): watchdog no longer flaps
during an open outage. Two slow reads (HYT00) during the 7:59 PM Tailscale stop
turned attention into unknown and back, five popups in two hours; a change of
kind now needs two sightings. 34 runner, 17 security and 67 health tests pass;
both new tests fail on the old code; live dry run calm. Loader still failing
until the owner restarts Tailscale (Windows gave up after five crashes).
Same night: VM CIS batch 1 applied by the owner (36 checks, SSH forwarding unchanged).

October 9, 2026 00:30 Eastern, Claude (claim released): **the automatic watchdog
is deployed**, superseding the "not deployed" lines in the October 8 handoff
below. Health and security popups every 15 minutes since October 8, 1:34 PM;
five delivered and traced on the first day; Lock Pages in Memory stopped SQL
Server paging; two indexes cut its reads ~1,000x; case SG-011 closed. This pass
fixed confirmation during a growing outage (kind, not exact failing checks)
with two regression tests; 32 runner, 17 security and 67 health/notice tests
pass and a live dry run matches. Open for Codex: post-deployment review
(identity, read rights), logon/reboot test, and the loader's single Tailscale
route. Record: [collection watchdog](docs/collection-watchdog.md). No publication.
Later the same night, read-only: **firewall blocked-traffic logging has been off
since the October 6 restart** (policy-set file names, no service permission on
the folder); fix prepared for the owner, not applied. See the
[hardening record](docs/hardening-validation.md).

October 8, 2026 owner-requested handoff to Claude: Codex's claim is released;
no active Codex deployment or publication job remains after this wrap-up.
Private pickup notes are in `publish/handoffs/claude-2026-10-08.md` in the
source checkout, excluded from publication. Read the dated reports below before
continuing. This wrap-up changes documentation only, not runtime health.

Latest runtime observations remain October 7 Eastern (October 8 UTC), not a new
October 8 check. Continue actual heartbeat/source-loss review and bounded local
notice execution; the automatic watchdog is not deployed. The independent TCP
lesson is prepared and decoded, but its Ubuntu engine-check job is not yet
prepared or run. The pending preparation question was unanswered; the owner
requested this handoff instead. No new scan, capture or live change is authorized
by the handoff. The one generic notification test's visible delivery also remains
unconfirmed; do not repeat it merely to close that gate.

October 7, 2026 independent offline TCP preparation is complete; Codex's claim
is released. Seven synthetic files (31 packets), a separate SID 9000002 candidate
and twelve focused tests are prepared. Actual TShark decoded all seven; private
hashes/readers pass. Expected alert counts are not Suricata results. See the
[lesson and controls](docs/tcp-rule-lesson.md). The installed-engine check requires
a separately bounded authenticated Ubuntu step; no guest execution, scan,
capture, deployment, schedule, new permission or service change was made.

October 7, 2026 collection-loss/notification preparation is complete for this
bounded batch; Codex's file claim is released. The extended read-only checker
flags 40 retained Sysmon errors and five historical queue warnings while fresh
Windows records still arrive. Six named channels have alert observations, not
raw-source heartbeat proof. All 40 privately reviewed descriptions report
registry drops; cause and unique missing-event counts are not established.

Notice planning, cooldown/retry/recovery and temporary-icon cleanup are tested.
The owner approved one generic test: Windows accepted its API call; visual
delivery is unconfirmed. The SQL preview sends/saves nothing. No task, new
permission, restart, rule/buffer/network change or capture was made. See the
[dated results and remaining gates](docs/collection-loss-and-notifications.md).
Continue actual heartbeat/buffer/source review and a scoped, locked private-state
runner before approved scheduling. Offline TCP preparation can proceed separately.

The October 7 repository review is complete:
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

## October 7 Pickup Sequence (Historical)

Claude's handoff commit `b067d36` was located in its separate workspace worktree,
not the main SOC checkout. Its drafts were reconciled with this repository;
this file remains the authoritative status, not the older side-workspace map.

| Order | Work | State / finish line |
|---|---|---|
| 0 | Restore current Windows collection | Closed for this outage: identity-checked bounded repair and exact Sysmon/Indexer/normal-loader SQL trace pass; [repair evidence](docs/collection-health-validation.md). Restart durability and historical loss remain separate |
| 0a | Monitor the monitoring | Read-only freshness/queue/Sysmon/source observations verified; generic notice planning and one test API call pass. Visible delivery, actual heartbeat, loss cause, private-state runner and scheduling remain open. [Latest evidence](docs/collection-loss-and-notifications.md) |
| 1 | Handoff and L0 explanation | Scannable README, private coordination agreement and corrected [packet-to-report lesson](docs/L0-event-to-report-trace.md) applied; 235 selected checks passed; owner explanation stays open |
| 2 | Triage integrity and PowerShell noise review | Public historical-review/inferred-count labels and level-16 handling corrected/tested; exact case memberships, dispositions and fresh Power BI gates remain open. [Audit](docs/triage-system-audit.md). Existing rule 100100 retained; filename-only expansion remains held |
| 3 | Resume TCP/Nmap learning | Seven harmless TCP fixtures/candidate prepared and decoded; installed-engine syntax/replay remains open, then a separately bounded owned-VM exercise. [Lesson](docs/tcp-rule-lesson.md); [existing baseline](docs/nmap-exposure-baseline.md) already complete |
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

## October 7 Milestones (Historical)

Updated October 7, 2026. The pipeline and investigations are built; these next milestones have their own validation gates.

| Priority | Work | Status | Evidence to publish |
|---|---|---|---|
| Current | **Bounded hardening checks** | File/logging/software checks and strict loopback-only loader SSH verified; firewall sample interpreted, blocked-traffic SIEM gap confirmed; management/account, disk/boot and recovery gates remain open | [Hardening gates](docs/hardening-validation.md), [host exposure and visibility](docs/host-exposure-validation.md), [software evidence](docs/software-hardening-validation.md) |
| Current | **Suricata traffic, rules and reporting pilot** | Offline alert verified through dashboard/Indexer/SQL and Power BI; bounded live trial and packet review pass; saved-live alert verified in Wazuh dashboard, Indexer and normal-loader SQL; fresh Power BI check deferred; permanent service stays masked | [Engine validation](docs/suricata-offline-validation.md), [six-page reporting proof](docs/network-reporting-validation.md), [live trial measurements](docs/suricata-live-trial.md), [live reporting handoff and open gates](docs/suricata-live-reporting-handoff.md) |
| Retained | **Private SOC access with Tailscale** | Local trusted HTTPS/login verified; renewal setup reported successful; phone remains denied; approved off-LAN testing deferred | [Recorded access results and open gates](docs/private-access-validation.md), renewal upkeep and remaining recovery/reporting checks |
| Deferred | **Whole-home browsing-privacy routing** | Extra VPN/router work declined for now; no privacy-egress change deployed | A separately approved design and per-device routing/DNS/IPv6/failure tests before any coverage claim |

The [private-access plan](docs/private-access-plan.md) explains the VPN decision, remaining steps and completion tests. The [network SOC maturity plan](docs/soc-network-maturity-plan.md) adds a stage checklist for measured device coverage, routine telemetry, correlation, analyst workflows and tested recovery.

## October 6 Hardening Baseline (Historical)

At the October 6 audit, reviewed agent/audit settings confirmed a blocked-traffic collection gap. That historical finding is superseded by the owner-reported October 11 firewall-file deployment in the current snapshot, not by a claim of complete network coverage. The audit also verified loopback-only loader forwarding and reviewed broad Hyper-V management exceptions. Disk/boot, access, resource and recovery gates remain separate ([host findings](docs/host-exposure-validation.md), [hardening checklist](docs/hardening-validation.md)).

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
