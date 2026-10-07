# Network Reporting Validation

Updated October 5, 2026. Status: the existing Wazuh dashboard visibly shows the
exact controlled Suricata alert; the new SQL reporting view is deployed and
verified. The existing six-page Power BI project has now refreshed and all six
pages were inspected with populated visuals. The first actual Desktop refresh failed
with a confirmed SQL read/write deadlock; a guarded fix is tested and now applied
in the quiet window ([reliability evidence](report-refresh-reliability.md)). Actual
Desktop retest passed, including the exact controlled network record and a
resettable context filter. Permanent capture remains disabled. The October 7
[bounded live trial and independent packet review](suricata-live-trial.md) later
passed; the [saved-live reporting handoff](suricata-live-reporting-handoff.md)
is prepared, not run. Its SQL context branch is deployed and existing Power BI
definitions updated; this later live event and Desktop refresh are not yet verified.

## What Changed And Why

The [controlled handoff](suricata-wazuh-handoff.md) already proved ingestion
into the Indexer and SQL. Reporting now exposes the saved network fields without
editing the telemetry or replacing the existing dashboards:

- [SQL view](../warehouse/sql/11_network_reporting.sql): `rpt.network_alerts`
  selects Suricata alert events from each record's own JSON, rather than applying
  the latest rule metadata to historical records. Invalid JSON and non-Suricata
  events are excluded; missing or invalid numeric fields remain null.
- Network fields include source/destination IP and port, protocol, application
  protocol, signature ID/revision, action, category and ICMP type/code.
- The original EVE packet timestamp is converted to UTC separately from Wazuh's
  processing time. The fixed January fixture time is not interpreted as a
  months-long ingestion delay. Flow IDs remain text to avoid numeric precision
  loss, and numeric identifiers/ports are not summed in Power BI.
- Observation context separates `Controlled validation`, other labeled
  validation, offline replay and `Unclassified`. The October 7 context update
  adds `Controlled live validation`, distinct from the earlier fixture. An unmarked event is not assumed
  live or malicious. These are alert-record counts, not incident counts or new
  ATT&CK coverage credit.
- The [existing Power BI project](../powerbi/SentinelGrid.pbip) gains a Network
  Detection page: context selector, four record/signature metrics, processing-hour
  volume, signature comparison and an event register with both severity scales
  and both timestamps. The original five pages were not regenerated.

## Measured Evidence

| Check | Result |
|---|---|
| Authenticated Wazuh dashboard | Threat Hunting / Events returned one SID 9000001 result; the alert-index document, rule 86601/level 3, test label, network fields and timestamps matched the earlier Indexer/SQL result |
| SQL deployment | Only the new reporting view was added, inside a validated transaction; zero stored telemetry rows modified |
| Real record comparison | Same document and Wazuh alert matched; controlled-validation context, synthetic addresses, ICMP type/code, SID, processing time and January packet time passed |
| Reporting access | Existing no-login reporting-user simulation read the view while direct `sg.alerts` SELECT permission remained absent; no user, role or grant changed |
| Bounded real-view check | One record returned; field/access verification took 0.45 seconds; not a sustained performance benchmark |
| Post-fix SQL sources | All 18 report views fetched successfully in 1.872 seconds, including one network record; an earlier aggregate timed out and a later repeat passed, so intermittent pressure remains open |
| Post-fix ingestion | Next automatic loader inserted 91 alerts in 2.537 seconds; no manual loader invocation or forced client disconnect |
| Regression suite | Latest rerun passed 161 publication/setup tests, including five report checks and 11 isolated actual SQL tests; another 15 reliability tests and three mocked recovery paths passed |
| SQL edge cases | Decoded string/native numeric values, IPv6/TCP, large flow/signature IDs, invalid JSON/numbers, duplicate groups, offsets and missing/other labels checked |
| Saved model definition | Microsoft Analysis Services 19.114.12 parsed 18 tables, 32 network columns and four network measures; saved `maxParallelismPerRefresh` is 1 |
| New page definitions | Initial 11-file schema check passed; after Desktop saved the filter correction, 10 available-schema files passed, while the edited slicer's 2.13.0 schema remains unpublished; offline layout/query/generation checks passed |
| Power BI Desktop | All six pages rendered populated charts/tables; the four network measures and event fields matched the controlled record; selecting the validation context and clearing back to All both worked |

The first test run exposed a query-alias assertion and pooled-connection cleanup
issue in the test harness. Both were corrected; the leftover test database was
checked as this run's synthetic fixture database and removed. The successful
rerun cleaned up its own database. Production telemetry was not used as test
fixture storage.

The Analysis Services validation library was obtained from Microsoft's NuGet
package and its SHA-512 checked against official registry catalog metadata.
Validation libraries and raw dashboard screenshots remain outside the public
repository. Parsed definitions alone are not proof of a completed Power BI refresh;
the subsequent Desktop inspection below supplies separate rendering evidence.

## Desktop Check Completed

The existing PBIP, not a replacement dashboard, displayed the following on
October 5. Pipeline Health reports imported data as of 6:20 PM US Eastern;
the report was inspected and saved later that evening. These are snapshot
values, not a claim that the report updates live or a measured refresh duration.

| Page | Observed populated result |
|---|---|
| SOC Overview | 27,327 alerts overall, 5,424 in its last-24-hour window; severity/rule charts and alert table rendered |
| Endpoint Posture | 448 historical findings, 10 open, zero Critical open; CIS 27.1% to 37.0% and 47 fixed checks; charts/table rendered |
| ATT&CK Coverage | 39 observed techniques, 11 active tactics and 115 ready-rule techniques; coverage charts/table rendered |
| Cases | 10 cases, nine closed and one open/in progress; charts/register rendered |
| Pipeline Health | 99.0% seven-day loader success, median alert-to-SQL 7.6 minutes, p95 15.0 minutes; freshness/load charts and tables rendered |
| Network Detection | One network record, one controlled validation, zero unclassified, one signature; both charts and event register rendered |

The network register matched SID 9000001, synthetic `192.0.2.10` to
`192.0.2.20`, ICMP, Suricata priority 3, Wazuh level 3, the original document
reference, October 5 processing time and January 1 UTC fixture packet time.
This demonstrates the existing network measures evaluating on imported data,
not an independent audit of every report measure or an incident verdict.

The context selector initially forced a selection, preventing a return to All.
Only this new selector was corrected, tested with Controlled validation and
cleared to All, then saved at 8:17 PM Eastern. Its generator now preserves the
resettable behavior; a regression test also protects the existing Endpoint
Posture selector from that change. The observed technique count is not proof
that every newly observed technique has been triaged.

Definitions can be checked independently of Desktop:

```powershell
.venv\Scripts\python.exe powerbi\tools\validate_report.py --page 21974aba9b2286fa371d
```

Install the validator's [requirements](../powerbi/tools/requirements.txt) in the
chosen validation environment first. Most new-page definitions use published
schema 2.12.0. Desktop upgraded the edited selector to 2.13.0, also used by the
existing pages; both Microsoft's CDN and source fallback returned 404 for that
visual schema at this check. The full-page command therefore cannot finish its
schema check. Ten remaining saved definitions passed a separate available-schema
check. Do not downgrade a working Desktop file or claim a full-page/full-report
schema pass to bypass the unavailable schema. Microsoft's source repository is
a fallback only when its schema CDN returns 404.

## Remaining Limits

No live packet feed, whole-home coverage, blocking, firewall/Tailscale change,
new SSH permission, loader change or public live-data connection was enabled.
The view stores no extra copy of telemetry. Imported Power BI data, personal
network destinations and raw evidence stay private; publishing definitions is
not permission to publish a report cache or live logs.

The October 7 view update preserved its 32-column contract and original offline
record; no stored telemetry or permissions changed. Its controlled-test measure
now includes both known contexts, with a separate live-test chart color. The
October 5 Desktop figures above remain historical, not a retest of these changes.

The reporting-role simulation is not a review of the actual Windows account
used by Desktop. Sustained host/loader load, refresh duration, capture loss,
retention and broader recovery remain separate gates. A supported VM-to-host
path passed the bounded trial; Windows browsing and iPhone visibility do not
follow from that result.

References: [SQL JSON extraction](https://learn.microsoft.com/en-us/sql/t-sql/functions/json-value-transact-sql),
[OPENJSON](https://learn.microsoft.com/en-us/sql/t-sql/functions/openjson-transact-sql),
[Microsoft TMDL parser](https://learn.microsoft.com/en-us/dotnet/api/microsoft.analysisservices.tabular.tmdlserializer),
[PBIR definitions](https://learn.microsoft.com/en-us/power-bi/developer/projects/projects-report),
[published schemas](https://github.com/microsoft/json-schemas/tree/main/fabric/item/report/definition).
