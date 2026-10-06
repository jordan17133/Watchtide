# Report Refresh Reliability

Updated October 5, 2026. The first refresh attempt of the six-page Power BI
project failed. The existing alert table was the SQL deadlock victim; other
tables, including the new network view, were cancelled afterward. A guarded
committed-snapshot fix passed isolated tests and was applied during the approved
quiet window. The next scheduled loader and all 18 SQL report sources passed
bounded checks. The subsequent Desktop retest completed: all six existing report
pages rendered, and the controlled network record matched. Sustained host/load
performance remains open.

## What Happened

The owner supplied the actual Power BI refresh error. A read-only examination
of SQL Server's existing `system_health` event file confirmed a deadlock at
18:30:50 UTC: two Power BI Mashup Engine reads and a Python write competed for
page locks on `sg.alerts`. The database used locking-based read committed,
with `READ_COMMITTED_SNAPSHOT` off. This is a reporting/ingestion concurrency
failure, not evidence that the synthetic Suricata event was an attack.

Windows was also under resource pressure: available memory fell below 1 GB,
committed memory was 88%, and a sample showed substantial paging. That may have
amplified the delay; it is not proven to be the sole cause of the deadlock.
Two report reads had exceeded seven minutes. The latest scheduled loader still
succeeded but took 113 seconds, compared with two seconds for each of the two
preceding runs. Sustained memory and loader-performance follow-up stays open.
After the failed report reads ended, the next scheduled loader succeeded in
1.764 seconds, before any snapshot-option change. That recovery is not credited
to the prepared fix.

An overlapping regression rerun timed out creating its disposable test database;
144 tests ran with one setup error. A subsequent quiet rerun passed 160
publication/setup tests, including 11 actual SQL tests. Another 15 reliability
tests and three mocked PowerShell recovery paths passed. A metadata check found
zero remaining disposable test databases. No production telemetry was used as test
storage. Cleanup is registered before test-database creation, including failures
where a database might have been created before the client timeout.

## Bounded Fix

[warehouse/reporting_snapshot.py](../warehouse/reporting_snapshot.py) is an
opt-in maintenance tool, separate from normal schema deployment:

- Default invocation only reports the current setting and connected clients.
- Enable/disable requires an autocommit connection to `master`, a known target,
  and an online, writable, multi-user database.
- The tool refuses schema-only memory-optimized tables to avoid their documented
  data-loss hazard when changing this option.
- It refuses connected clients and active target-database transactions. The
  final `WITH NO_WAIT` protects the race after preflight; no session kill,
  forced disconnect or rollback of another client is included.
- `--disable` is a quiet-window rollback, subject to the same guards.

Read-committed snapshot lets a statement read the committed version that existed
when it began, rather than taking shared row/page locks against the loader.
This does not allow dirty reads or guarantee every imported report table shares
one common timestamp. Row versions consume storage and need monitoring;
writer/writer deadlocks, schema locks and general memory pressure can still occur.
No `NOLOCK` hint or broader SQL/network permission was added.

Five offline guard tests and two disposable-database concurrency tests passed.
The latter prove that a reader sees old committed data while an update is
unfinished, sees the new value after commit, and remains connected when a
maintenance change is refused. These are isolated tests, not a successful
production refresh.

## Deployment And Retest

The owner approved testing and applying the fix only during a quiet window after
Power BI is closed. After the report closed, an empty Untitled Desktop window
remained, but the database preflight found no other warehouse connections or
transactions. The guarded change succeeded and independent status confirmed
`READ_COMMITTED_SNAPSHOT` enabled. No client was disconnected, transaction
forcibly rolled back, service restarted or loader manually invoked.

For future maintenance, close reporting clients normally, wait for the loader
to finish, inspect status, and apply only if the guards pass. Never terminate an
active loader to make the window quiet.

```powershell
.venv\Scripts\python.exe -m warehouse.reporting_snapshot
.venv\Scripts\python.exe -m warehouse.reporting_snapshot --enable
```

The next automatic loader succeeded in 2.537 seconds and inserted 91 alerts.
An initial network-context aggregate timed out; a later bounded repeat completed
in 0.432 seconds with one controlled-validation record. A separate sequential
read fetched every row from all 18 report sources in 1.872 seconds, including
26,846 alert rows and the one network record. These are point-in-time checks,
not a sustained benchmark or proof that intermittent resource pressure is gone.
At a later diagnostic sample, host memory available was about 4.2 GB and no
other user query was active; warehouse row-version space reported zero KB at
that instant, not a prediction of future storage use.

A quiet post-change regression rerun passed 160 publication/setup tests,
including 11 actual isolated SQL checks, another 15 reliability tests and three
mocked PowerShell recovery paths. The new page's 11 definitions again passed
published Microsoft schemas.

The existing PBIP's Current File / Data Load option
`One (disable parallel loading)` was confirmed and is persisted as
`maxParallelismPerRefresh: 1` in the parsed saved model. The later Desktop check
found all six pages populated with no observed visual errors. SOC Overview
showed 27,327 alerts, and Network Detection showed the expected one controlled
record with matching fields and all four metrics. Its context filter was tested
and corrected to allow clearing back to All. The existing project was saved at
8:17 PM Eastern; no original page was regenerated.

Pipeline Health's imported data time was 6:20 PM Eastern. The retry also
encountered host pressure, including a sample below 700 MB available memory and
91% committed memory. A reliable refresh completion time was not captured;
later successful rendering is not proof of a fast refresh or resolved memory
pressure. A subsequent sample had about 2.5 GB available. Three recent automatic
loader runs succeeded in 2.398, 3.257 and 2.435 seconds, and a fresh read-only
check confirmed snapshot reads still enabled. These remain bounded observations.

The saved model parsed again with 18 tables, 32 network columns and four measures.
The latest rerun passed 161 publication/setup tests (11 actual isolated SQL
checks), another 15 reliability tests and three mocked recovery paths. Ten
available-schema network definitions passed; Desktop upgraded the edited slicer
to an unpublished 2.13.0 schema, so no complete current-page schema pass is
claimed. See [report evidence](network-reporting-validation.md) for this limit.
Keep live capture disabled and the sustained performance gate open.

Raw deadlock XML, session identifiers, client account/host information and memory
diagnostics are not published. The public console snapshot was not refreshed.

References: [SQL deadlock diagnostics](https://learn.microsoft.com/en-us/sql/relational-databases/sql-server-deadlocks-guide),
[row-versioning behavior](https://learn.microsoft.com/en-us/sql/relational-databases/sql-server-transaction-locking-and-row-versioning-guide),
[database-option maintenance](https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-database-transact-sql-set-options),
[Power BI loading controls](https://learn.microsoft.com/en-us/power-bi/transform-model/desktop-evaluation-configuration).
