# Collection Loss And Local Notifications

October 7, 2026 Eastern; SQL observations extend into October 8 UTC.
This follows the [collection repair](collection-health-validation.md) and
[repository review](repository-review.md). It advances the existing health
work, not the scope of network capture or detection-rule deployment.

## In Plain English

We are checking whether the monitoring system can notice its own blind spots.
"New alerts arrived" and "nothing was lost" are different statements.

```text
Windows activity
    -> Sysmon / Windows logs       Can lose records before delivery
    -> Wazuh agent queue           Can fill and drop events
    -> Wazuh manager rules         Produce alerts, not every raw event
    -> Indexer                     Stores those alert documents
    -> scheduled loader -> SQL     Successful copying can copy stale data
    -> Power BI import             Reflects its last successful refresh

Manual SQL health check: freshness + retained loss/error signals + source counts
Prepared notice planner: generic warning, cooldown, retry and recovery logic
Automatic monitor: not deployed
```

Suricata adds evidence only on its tested capture path. Neither this checker
nor a notification sees iPhone browsing or all home traffic. Rule severity is
priority, not an analyst verdict. The [triage map](triage-system-audit.md)
explains those separate layers.

## What Was Actually Checked

Read-only, parameterized SQL queries used the existing local analyst identity,
five-second connection and fifteen-second per-query limits, and connection
cleanup. No schema, grant, service, buffer or query-timeout setting changed.

| Observation | Checked result | Meaning / limit |
|---|---|---|
| Saved check, October 8 at 03:12:41 UTC | Last successful load 14.97 minutes old; latest endpoint alert 15.26 minutes old; current loader running for 0.01 minutes | Recent warehouse observations, not authenticated live agent status |
| Wazuh queue warnings, retained 24-hour window | Five: one 202, two 203 and two 204, October 7 at 05:49:42-05:51:22 UTC | Historical pressure/full/flooding reports; not five attacks |
| Later normal-queue message | Rule 205 at 05:51:46 UTC | Queue recovered its reported state; missing events are not restored by that message |
| Sysmon Event 255, retained window | 40 error records, October 7 at 05:46:12-05:52:08 UTC | All 40 reviewed descriptions explicitly reported dropped registry events; not a unique missing-event total |
| Overall manual result | Attention, exit 1 | Expected loss-review warning even while new data arrives |
| Source observations | Sysmon, Defender, PowerShell, Security, System and Application all have retained alerts | Does not prove every raw event or current source heartbeat |

The saved rolling source counts were Sysmon 2,015, Security 438, Application 93,
PowerShell 51, System 31 and Defender 14. Another 905 alerts had no channel value
and remain **uncategorized**; they are not automatically classified as FIM or a
seventh Windows channel. Quiet channel ages are observations, not disconnection
verdicts. Counts change with ingestion and the moving window.

The earlier JSON-based aggregation hit its bounded timeout. The checker now
uses the existing materialized event/channel columns for the Sysmon query;
the actual bounded reads succeeded. This is a query implementation improvement,
not a SQL configuration change or proof of representative sustained capacity.

The latest host boot was October 7 at 10:32:32 UTC, after the loss cluster. A
later memory sample had approximately 8,293 MiB free out of 29,525 MiB. Neither
establishes peak pressure, a shared root cause, or that reboot fixed the loss.
Sysmon64 and WazuhSvc were Running/Auto. Direct protected Windows source-log
reading was unavailable to this tool process; no permission was bypassed.

[Microsoft describes Event 255](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
as a Sysmon error with several possible causes. The reviewed records' own text
identifies registry drops; do not generalize every Event 255 to that cause.
[Wazuh's queue guidance](https://documentation.wazuh.com/current/user-manual/agent/agent-management/antiflooding.html)
distinguishes pressure, full, flooding and normal states, and explains that
flooding can drop events. Actual installed buffer values still need review;
vendor defaults are not verified host settings.

## Notification Work: Prepared Versus Deployed

[health_notifications.py](../warehouse/health_notifications.py) is a pure
planner plus a read-only preview. It does not write state, send a message or
create a task. Its default policy is:

- Start silently when checked observations are recent.
- Plan a generic attention or unavailable-evidence notice, never raw logs.
- Suppress unchanged accepted warnings for 60 minutes. Changing ages/counts
  alone do not generate new warnings.
- Limit attempts to one per five minutes, including changed problems and failed
  delivery. A failed API attempt is not recorded as successful delivery.
- Plan one recovery after an accepted warning, retaining it through retry
  cooldown/failure. Recovery does not mean earlier missing events reappeared.
- Reject corrupt state, unsupported fields and stale/future observations rather
  than silently reset deduplication. Serialized-state tests are not reboot tests.

[Show-WatchtideNotification.ps1](../windows/Show-WatchtideNotification.ps1)
provides four fixed generic texts and a temporary tray notification. **Preview**
is the default; **Test** attempts one test popup, then hides/disposes its icon.
No task, registry registration, new permissions or permanent tray process.

The owner approved exactly one real Test invocation after safety tests. It
returned `ONE_TIME_NOTIFICATION_API_ACCEPTED` with successful temporary-icon
cleanup. Windows API acceptance does **not** prove the popup was displayed or
seen; visual delivery remains unconfirmed. Games/notification settings may hide
it. This was not a health alert, an incident or authorization for recurring
delivery. No second popup was attempted.

The real SQL-backed notification preview planned **attention**, with
`state_saved`, `delivery_attempted` and `schedule_created` all false. Private
collection/preview evidence has two verified SHA-256 hashes and restricted
reader checks on the directory, both files and hash record. No raw payloads,
device addresses or account details appear in this report.

## How To Use The Current Slice

From the private source, inspect collection observations:

```powershell
.\.venv\Scripts\python.exe -B -m warehouse.check_collection_health --agent-id 001
```

Preview the planned notice without sending or saving anything:

```powershell
.\.venv\Scripts\python.exe -B -m warehouse.health_notifications --agent-id 001
```

Exit 0 means recent observations, 1 means review and 2 means unknown/unavailable.
Inspect the named checks before deciding whether there is an outage. An error
message count is neither an attack count nor a recovered-event count. These
commands do not refresh Power BI, capture traffic or change rules.

## Verification And Finish Lines

The collection checker passes 42 synthetic tests, the planner 25, and the
PowerShell notification helper 24 assertions with fake transport objects (no
popups). They cover recent/stale/unknown data, queue/Sysmon warnings, quiet
sources, redaction, bounded SELECTs, cooldown/retry/recovery, corrupt state,
clock bounds and temporary-icon cleanup. Actual SQL reads and the separately
approved one-time API test supplement those tests; they do not close every gate.

Full regression: 359 Python tests passed, with 13 opt-in database-changing tests
skipped. Ten PowerShell suites passed 175 checks; 21 PowerShell files parse.
The structural repository scan checked 290 files and 428 local file links with
no errors. It is not a line-by-line security audit or fresh application rendering.

- [x] Distinguish fresh data from retained queue and Sysmon loss/error evidence.
- [x] Query named-source alert observations without labeling silence an outage.
- [x] Prepare/test generic notice planning and temporary transport cleanup.
- [x] Run one approved test API invocation and a non-delivering SQL preview.
- [ ] Confirm visible Windows delivery; no repeated popup without scoped approval.
- [ ] Read actual agent status/heartbeat and installed buffer/source settings
  through a reviewed read identity; establish cause and representative health.
- [ ] Implement locked, atomic private state storage and a bounded runner;
  test concurrency, delivery failures, total execution budget and logon/reboot.
- [ ] Review execution identity, read permissions, delivery and scheduling scope
  before deploying an automatic watchdog. This PC cannot warn while powered off.
- [ ] Recheck repaired name resolution/reconnection after a planned restart.

Independent offline TCP preparation remains possible. Expanded live detection
and routine DNS/flow capture still require measured source/drop/resource and
retention gates. The [completion plan](soc-completion-plan.md) retains the order:
collection/health warnings -> useful traffic -> TCP/Nmap -> Zeek evaluation ->
forensic lessons.
