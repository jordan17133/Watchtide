# SOC Reliability: Review Fixes

Date: 2026-10-04. Status: implementation and offline regression checks complete;
the first scheduled reconciliation passed. Controlled late-event behavior,
reporting refresh, and VPN validation remain separate gates.

## Changes And Evidence

| Review finding | Change | Offline evidence |
|---|---|---|
| New alerts inherited a past rule verdict | Exported alerts remain untriaged; final validation rejects non-null alert verdicts until an event-specific evidence link exists. Rule and ATT&CK notes are labeled historical context; case verdicts remain intact. | A reviewed historical rule verdict cannot classify a new alert. Removed 555 inherited verdicts from the historical snapshot while preserving all other values. |
| A missing index cleared today's vulnerability snapshot | Missing-index HTTP errors now fail the load. Searches reject missing shards, timeouts, and shard failures; snapshot replacement requires an exact, complete result count. | Synthetic 404/403/500, incomplete searches, and truncated results perform no snapshot delete. A verified empty result remains valid. |
| Alerts older than the ten-minute overlap could be skipped indefinitely | Incremental loads retain the overlap, with a complete scan of retained alert indices at least daily and an explicit `--reconcile` option. Document-ID deduplication remains; daily summaries rebuild far enough back for reconciled events. | An old synthetic alert is included in reconciliation, an existing document is not inserted twice, and summaries include its historical date. |
| Duplicate JSON keys bypassed snapshot review | Strict parsing rejects duplicate keys at every object depth before publication. Diagnostics omit raw keys and values. | Nested duplicate-key snapshots are rejected; an existing public checkout is preserved. |
| New cases borrowed the earliest historical alert for a recurring rule | Opening a case requires `--since`, with optional `--until`, both timezone-aware. The first alert is selected only inside that incident window. | A recurring rule's earlier history is excluded; empty/reversed windows are rejected. Existing cases are not rewritten. |
| A hardening exception could leave the agent stopped | Apply and revert use a shared `try/finally` helper that attempts restart and waits for Running status. Unverified audit settings now fail explicitly. | Three isolated mocked paths cover success, an action failure, and a stop failure. No real hardening was executed. |

The Python suites contain 23 publication tests and 15 loader/case tests. The
PowerShell helper has three mocked recovery checks. They use fake HTTP, SQL,
and service objects, not the live SOC. The console snapshot migration is a
correction to historical display data, not a fresh SQL export.

## Read-Only Compatibility Check

A read-only check through the existing restricted loader tunnel fetched 21,249
retained alerts in 22 pages and verified 10 vulnerability results with an exact
total. The combined query/tunnel check took 1.58 seconds. No SQL rows were
written. This confirms the deployed Indexer accepts the changed search options;
it does not measure a complete loader run or prove Power BI refresh.

The error and exact-count handling follow the [OpenSearch Search API](https://docs.opensearch.org/latest/api-reference/search-apis/search/).
Desktop and mobile Playwright checks passed for all five console views, alert
selection, search, untriaged alert display, event references and page bounds.
The preview image was regenerated from the actual corrected console.

## First Scheduled Reconciliation

Run 391 started at 14:57:42 EDT on October 4 after the loader source update. It
succeeded in 30 seconds, fetched 21,276 alerts, inserted 96 new alerts, and
snapshotted 10 vulnerability findings. Its null starting watermark confirms a
full reconciliation, rather than the normal incremental query. The preceding
incremental run took two seconds; continue monitoring subsequent runtimes.

Read-only SQL checks found none of those 96 inserts outside the preceding run's
ten-minute lookback window. This run establishes operational compatibility and
deduplication continuity, not a live demonstration of late-event recovery. The
synthetic late-event regression passes; a controlled live trace and Power BI
refresh remain pending. The public snapshot was not refreshed from these rows.

## Subsequent Runtime Follow-Up

The repeat offline checks passed: 23 publication tests, 15 loader/case tests,
and three mocked PowerShell recovery paths. A later live read-only SQL
connection initially timed out, then succeeded on retry. Scheduled run 392
started at 15:12:44 EDT and finished at 15:20:52: 195 alerts fetched, 117
inserted, and about eight minutes elapsed, versus two seconds for the earlier
incremental run. Its eventual success does not establish acceptable ongoing
performance.

The Windows host had less than 1 GB free physical memory; SQL Server logged
event 17890 stating that significant process memory had been paged out. This
supports investigating host memory pressure, not attributing the slowdown to
the VPN or claiming a proven root cause. No services were restarted, unrelated
applications closed, or memory/VM settings changed. Release nonessential host
workloads, recheck SQL response and subsequent scheduled runtimes, and only
then attempt Power BI refresh or add endpoints. No controlled event trace or
new public snapshot was produced by this follow-up.

## Operating Changes

The scheduled loader uses this repository's source. Its next invocation can
pick up these changes without a service restart. The first run is verified;
continue checking later runs rather than treating one success as ongoing health.

- Review `sg.load_runs` for success, duration, counts, and errors after the
  first reconciliation; compare subsequent incremental runs. The daily full
  scan can take longer, particularly as retained indices grow. Measure before
  adding endpoints; it cannot recover data already deleted from the Indexer.
- If a vulnerability query fails, preserve the last valid snapshot and
  investigate the error. A successful empty query is not the same as a missing
  index. More than 10,000 findings now fails rather than publishing partial
  posture; pagination is required before scaling beyond that limit.
- Verify a controlled late event reaches SQL once and its historical daily
  summary updates. Refresh Power BI independently. No scheduled task, SQL
  schema, retention setting, SSH restriction, or network policy was changed.
- Open new cases with an explicit incident window. Counts in `rpt.cases` still
  use rule/time matching, not an exact document-to-case association. Future
  alert verdicts require that association; historical rule research is not it.
- Test full hardening/revert only in an approved isolated test environment.
  Cleanup attempts and reports restart failures; it cannot guarantee a broken
  operating-system service will start.

## Next Security Gate

Continue [Stage 4c](private-access-validation.md): authenticated SSH and trusted
HTTPS dashboard access, IPv6 diagnosis, approved off-network access, denial
from an unprivileged device, external exposure checks, revocation, a controlled
event trace, and Power BI refresh. Device enrollment and the existing narrow
policy remain complete; the full private-access milestone stays in progress.
