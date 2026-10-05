# Network Reporting Validation

Updated October 5, 2026. Status: the existing Wazuh dashboard visibly shows the
exact controlled Suricata alert; the new SQL reporting view is deployed and
verified. A sixth Network Detection page is defined in the existing Power BI
project and passes model/schema checks. The first actual Desktop refresh failed
with a confirmed SQL read/write deadlock; a guarded fix is tested and now applied
in the quiet window ([reliability evidence](report-refresh-reliability.md)). Actual
successful refresh and visual rendering remain open. Live capture is still disabled.

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
  validation, offline replay and `Unclassified`. An unmarked event is not assumed
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
| Regression suite | Initial 153-test run passed; a concurrent repeat timed out creating its test database; subsequent 160-test rerun passed, including four report checks and 11 isolated actual SQL tests |
| SQL edge cases | Decoded string/native numeric values, IPv6/TCP, large flow/signature IDs, invalid JSON/numbers, duplicate groups, offsets and missing/other labels checked |
| Model definition | Microsoft Analysis Services 19.114.12 parsed the complete model: 18 tables, 32 network columns and four network measures |
| New page definitions | All 11 page/visual files passed Microsoft's published JSON schemas; layout bounds, non-overlap, query references and idempotent page-only generation checked |
| Power BI Desktop | First refresh failed with a confirmed SQL deadlock; successful refresh, DAX evaluation and actual rendering still require verification |

The first test run exposed a query-alias assertion and pooled-connection cleanup
issue in the test harness. Both were corrected; the leftover test database was
checked as this run's synthetic fixture database and removed. The successful
rerun cleaned up its own database. Production telemetry was not used as test
fixture storage.

The Analysis Services validation library was obtained from Microsoft's NuGet
package and its SHA-512 checked against official registry catalog metadata.
Validation libraries and raw dashboard screenshots remain outside the public
repository. Parsed definitions are not proof of a completed Power BI refresh.

## Finish The Desktop Check

Open the existing `powerbi/SentinelGrid.pbip` project in Power BI Desktop, refresh
and select Network Detection. Expect one network record, one controlled test,
zero unclassified alerts and one signature before filtering. The register should
show SID 9000001, synthetic `192.0.2.10` to `192.0.2.20`, ICMP, processing on
October 5 and the January 1 UTC packet time. Verify the original five pages still
work. Report errors without credentials; do not rerun the guest activation.

Definitions can be checked independently of Desktop:

```powershell
.venv\Scripts\python.exe powerbi\tools\validate_report.py --page 21974aba9b2286fa371d
```

Install the validator's [requirements](../powerbi/tools/requirements.txt) in the
chosen validation environment first. The new page uses published visual schema
2.12.0. The existing five pages retain their Desktop-generated 2.13.0 references,
which were not yet available in Microsoft's public schema repository at this
check; no full-report schema pass is claimed. Microsoft's source repository is a
fallback only when its schema CDN returns 404.

## Remaining Limits

No live packet feed, whole-home coverage, blocking, firewall/Tailscale change,
new SSH permission, loader change or public live-data connection was enabled.
The view stores no extra copy of telemetry. Imported Power BI data, personal
network destinations and raw evidence stay private; publishing definitions is
not permission to publish a report cache or live logs.

The reporting-role simulation is not a review of the actual Windows account
used by Desktop. Sustained host/loader load, actual report refresh, capture loss,
retention and broader recovery remain separate gates. Next capture work must
identify and test one supported interface before making wider visibility claims.

References: [SQL JSON extraction](https://learn.microsoft.com/en-us/sql/t-sql/functions/json-value-transact-sql),
[OPENJSON](https://learn.microsoft.com/en-us/sql/t-sql/functions/openjson-transact-sql),
[Microsoft TMDL parser](https://learn.microsoft.com/en-us/dotnet/api/microsoft.analysisservices.tabular.tmdlserializer),
[PBIR definitions](https://learn.microsoft.com/en-us/power-bi/developer/projects/projects-report),
[published schemas](https://github.com/microsoft/json-schemas/tree/main/fabric/item/report/definition).
