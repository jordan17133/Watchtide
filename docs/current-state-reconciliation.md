# Current-State Reconciliation

October 11, 2026. This is a documentation/helper reconciliation, not a new live
deployment or a full security audit. [STATUS](../STATUS.md#current-snapshot) is
the authoritative current pickup map; dated reports retain their original scope.

## What Changed And Why

- Separated current status and execution order from historical updates. Older
  "not deployed" observations no longer serve as current instructions.
- Reconciled watchdog, firewall-file collection and tuning deployment records
  across the runbook, roadmap, completion plan and evidence navigation.
- Corrected active Hyper-V targets to `Watchtide`. Creation, disk-growth and
  diagnostic helpers accept an explicit `-VMName`; the default is `Watchtide`.
  Existing disk paths, database/report filenames and archived build names remain
  unchanged. Renaming a display name does not require moving its disk files.
- Preserved the short employer-facing README. Public figures and screenshots
  remain dated, not promoted into fresh counts or security guarantees.

## Reported Deployments Versus Independent Checks

| Item | Supported result | Limit |
|---|---|---|
| Collection watchdog | Claude records owner-approved deployment October 8 and traced first-day notices; owner confirmed the earlier test popup | Current permission/notification-policy review and actual reboot/logon test remain open |
| Current task metadata | October 11 read: enabled, Ready, Interactive/Limited, every 15 minutes, five-minute limit, IgnoreNew; last result 0 at 22:36:13 UTC | Success exit alone does not prove both tiers succeeded or every event was observed; no task run initiated by this review |
| Host services | October 11 read: WazuhSvc, Tailscale and MSSQLSERVER Running/Auto | Service state is not authenticated agent heartbeat, fresh ingestion or guest health |
| Tailscale guard | Owner deployment and controlled restart reported October 10 | Its task metadata was unreadable from this process; not independently verified or changed |
| Firewall source | Source has three profile log inputs and stock-decoder child rules; owner reports 18/18 engine tests and live outbound rule 100144 | No new engine/capture test here; live inbound control and complete reporting trace remain open |
| Tuning 100102-100106 | Source contains the five additional children; owner reports live level-3 matches October 10-11 | Stored-pattern positive/negative replay is not installed-engine negative validation; eventchannel stdin logtest did not exercise Windows rules |
| Posture/access | Owner reports CIS Windows 63.2% (299/473), VM 66.2% (157/237), keys-only SSH and Defender restrictions in audit | Not rescanned here; an audit setting is not blocking, and a CIS percentage is not proof of safety |
| VM recovery points | Owner reports deleting the five existing checkpoints October 9 and renaming the display name October 10 | Old checkpoint creation proof does not establish a current rollback point; merge/restore availability must be checked before risky work |

The older Defender/lockout case gaps now have named reports for SG-011 through
SG-014 in the [evidence index](portfolio-evidence.md#investigations). This does
not make inferred rule/time membership exact, or classify future matching alerts.
No new live case count is inferred from a snapshot or Markdown files.

## Boundaries That Still Matter

The deployed [security notice selector](../warehouse/security_notices.py) treats
any historical rule review or case link as sufficient to exclude that rule from
its unreviewed-high-priority tier. Its fixed watchlist is separate and continues
to qualify despite review. This is a notification-policy gap: a past benign case
is not evidence that later events are benign. Records remain in Wazuh/SQL; this
reconciliation does not alter the deployed selector or create a new verdict.
Review that policy before adding new detection load.

Firewall collection is selected Windows-host packet evidence, not continuous Suricata
monitoring or whole-home coverage. Agent-side discovery filters discard matching records before
delivery; level-0 rules do not produce normal alerts. Claude reports that the
stock decoder rejects ICMP lines without ports before archiving. Inbound tests,
volume/drop review and an exact source/Indexer/SQL trace retain separate gates.

Successful backlog copying from a held loader watermark demonstrates warehouse
catch-up for retained input, not recovery of records already lost by Sysmon or
the agent. No claim of "no alerts lost" is inferred for the entire pipeline.

The TCP lesson is still prepared/decoded only. The private handoff records the
owner's October 8 approval to prepare a bounded offline engine job, not execution
or deployment. Keys-only SSH now requires a verified administration key and local
sudo authentication; the forwarding-only loader key is not an administration key.
Older password-only activation jobs are historical and must not be rerun blindly.

## Verification Scope

The pickup review independently reran 118 focused Python tests: 34 watchdog,
17 security notice, 42 health and 25 notice-planner tests, all passing with fake
transport and temporary state. Passing tests describe current behavior, not
proof that the notification policy is complete or that it survived a real reboot.

The VM-name test evaluates PowerShell parameter binding and syntax trees only;
it does not invoke creation, resize, checkpoint deletion or any Hyper-V operation.
The diagnostic library tests do not read protected agent files. Structural and
publication checks are recorded in the [build log](../BUILD-LOG.md).

Cleanup regression: 433 Python tests passed, 13 database-changing tests skipped;
52 VM-target and 17 diagnostic checks passed under Windows PowerShell 5.1.
All 26 source PowerShell scripts parse. Structural review checked 310 files and
488 local links without errors; current navigation anchors have focused tests.
The publisher's tracked-text preflight includes the previously unpublished
Claude changes, and changes only a private workload description in the notice
module, not its executable logic. Separate secret scans are still required.

No live rule, service, scheduled task, firewall/VPN/SSH policy, disk, evidence
permission, capture or notification was changed. No fresh Power BI render or
public data export was performed. The public console retains its export date.

## Continuation

Finish watchdog identity/read-scope and notification-policy review; separately
validate reboot/logon behavior. Then complete bounded offline TCP engine checks,
followed by an owned-device Nmap lesson after source/resource gates. Routine
telemetry budgets precede Zeek and forensic lessons. The
[roadmap](../ROADMAP.md#current-execution-order) and
[completion packages](soc-completion-plan.md#stage-checklist) retain that order.
