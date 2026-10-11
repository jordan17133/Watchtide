# Collection Watchdog: Deployment And Live Results

The automatic watchdog that warns about selected collection/SQL-read problems from
[collection loss and notifications](collection-loss-and-notifications.md). It is
a bounded runner around the existing, unchanged health checker
(`warehouse/check_collection_health.py`), notice planner
(`warehouse/health_notifications.py`) and fixed-text notifier
(`windows/Show-WatchtideNotification.ps1`). Built and deployed by Claude on
October 8, 2026 at the owner's request; Codex's post-deployment review is open.
Current metadata and documentation reconciled October 11; see the
[checked state and remaining gates](current-state-reconciliation.md).

## What It Does

| Part | Behavior |
|---|---|
| Schedule | Windows task every 15 minutes, owner account, interactive, limited rights, 5-minute limit, a second copy never starts while one runs |
| Health tier | Reads the collection checker. A **new** problem must be seen twice, 10-45 minutes apart, before a popup (filters one-off slow reads). Same problem: reminder every 4 hours. Recovery: one popup, no confirmation |
| Security tier | Popup for every new alert from a short watchlist (rules 100110-100113, 62123, 100130-100136) and, once, for any level 12+ rule that has never been triaged or linked to a case (reminder after 7 days if still unreviewed). Wazuh health rules 202-205 excluded. First run is a silent baseline |
| Popup text | Four fixed messages (Attention, Unknown, Recovery, Security). No rule IDs, paths, hosts or numbers reach the notification |
| State and log | Private folder outside the repository; atomic writes; corrupt or future-dated state is quarantined, never reused; run log redacted and capped at 2,000 lines |
| Diagnostics | Each run logs the failing error type and SQLSTATE (never the message) and how long each tier took |

Run by hand: `python -m warehouse.collection_watchdog --dry-run` (reads only,
writes nothing, never notifies). See what the security tier would show:
`python -m warehouse.security_notices --show --hours 24`.

## Deployment Record

| Commit | Change | Live since (Eastern) |
|---|---|---|
| `ecfedff` | Runner, lock, state, two-sighting confirmation; scheduled task | October 8, 1:34 PM |
| `b26eb35` | Security tier; `Security` kind added to the notifier | October 8, 2:05 PM |
| `a45585a` | Error-type and timing diagnostics | October 8, 2:19 PM |
| `f037d29` | Two indexes on `sg.alerts` (below) | October 8, 11:40 PM |
| this change | Confirmation matches the problem kind, not the exact failing checks | October 9 |

Rollback: unregister the task `Watchtide Collection Watchdog`, or revert the
commit. Neither touches collection, the loader or Wazuh.

## What Happened In The First Day

Every notice below was delivered and accepted by Windows. On October 8 the owner
confirmed the earlier test popup was visible; the watchdog uses the same notifier,
which closes the visible-delivery gate.

| Time (Eastern) | Popup | Cause |
|---|---|---|
| 2:06 PM | Unknown | The checker's SQL read failed twice; SQL Server memory was being paged out at the same moments (event 17890) |
| 2:21 PM | Recovery | Reads healthy again |
| 3:21 PM | Security | Rule 100110, four alerts: the owner's own approved permission change on private configuration files. Expected, correctly surfaced |
| 10:36 PM | Attention | Loader runs 796-802 failed: the SSH tunnel to the VM timed out after the Tailscale service on the PC crashed (a third-party application that disables VPNs was running) |
| 11:51 PM | Recovery | Tailscale restarted; run 803 loaded the 1,941-alert backlog from the held watermark. No alerts lost |

Silent but logged: security-tier timeouts at 4:06, 4:21, 8:36 and 8:51 PM, and
one unconfirmed Unknown at 5:06 PM (15.4-second read). Both traced to full
scans of `sg.alerts` (below).

## Fixes Made From The Live Results

**SQL Server paging (root cause of the 2:06 PM popup).** Windows logged event
17890 38-199 times a day from September 30. The owner granted Lock Pages in
Memory to the SQL Server service and restarted it at 2:38 PM; SQL Server now
reports `LOCK_PAGES`. Zero 17890 events since (checked at midnight).

**Missing indexes.** `raw_json` is stored in-row (about 351 MB), so every
unindexed filter read the whole table. `warehouse/sql/12_watchdog_indexes.sql`
adds `IX_alerts_loaded` and `IX_alerts_agent_ts` (`IF NOT EXISTS`, built
online). First tested on a disposable restore of the newest verified backup:
identical results before and after; re-running is a no-op; the copy was dropped.

| Query | Pages read before | After |
|---|---|---|
| Security tier (30 minutes of loads) | 21,379 | 18 |
| Health: 24-hour sources for the Windows agent | 19,108 | 83 |

Runs since: about 0.1 s per tier (before: up to 15 s, and one 60-second dry run
during paging).

**Confirmation restarted during a growing outage.** At 10:06 PM the first
sighting was held as designed. At 10:21 PM another check had gone stale, so
the set of failing checks changed and confirmation started over; the popup came
at 10:36 PM, 15 minutes late. Confirmation now requires two sightings of the
same **kind** (attention, or unknown) and ignores which checks are failing. An
unknown followed by an attention still does not confirm. Two regression tests
added; the growing-outage test fails on the old code and passes on the new.

**Popups flapping during a known outage (October 9).** Tailscale stopped again at
7:59 PM (five crashes, then a start timeout; Windows gave up). The watchdog
warned at 8:36 PM as designed, but two slow health reads (SQL query timeouts at
9:36 and 10:21 PM, while the PC was busy) turned an open "attention" into
"unknown" and back, and each flip popped immediately: five popups in two hours
instead of one. Now only reminders and same-kind changes skip confirmation while
a warning is open; a change of kind needs two sightings like a new problem. One
unreadable check stays quiet; a database that stays unreadable still warns on
the second run. Two regression tests; both fail on the old code.

## Tests

34 watchdog runner tests, 17 security-tier tests and the existing 67 health
and notice tests pass with fake transport and temporary folders: no real
popups, no SQL. A live `--dry-run` after each change matched the checker.

## Still Open

- [ ] Review notification policy: the unreviewed-high-priority tier currently
  excludes any rule with historical research or a case link. That must not be
  mistaken for an event-specific benign verdict. Stored alerts are retained;
  the fixed watchlist has separate eligibility.
- [ ] Codex review of the deployed runner, execution identity and read rights.
- [ ] Logon/reboot test: the task should resume after a restart without help.
- [ ] Single network route: the loader reaches the VM only over Tailscale. If
  that service stops, loads fail until it returns (October 8, and again October 9
  from 7:59 PM, when Windows gave up restarting it). Options for review: fall back
  to the local Hyper-V address, or Tailscale service recovery.
  Owner reports a separate guard/restart control October 10; its task metadata
  was unreadable here. That mitigation does not establish alternate routing.
- [ ] A powered-off or sleeping PC cannot warn; there is no off-PC observer yet.
