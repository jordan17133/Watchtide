# Repository Review And Reporting Corrections

October 7, 2026, US Eastern. This batch continues reliable collection and
truthful reporting before routine network telemetry, TCP/Nmap validation,
evaluation of Zeek and forensic lessons. It does not start a second build.

## What Changed, Simply

| Change | Why it matters | Verification |
|---|---|---|
| Short README with a separate evidence index | Employers can find results without losing the investigations or older images | Local file links and retained evidence references checked |
| Historical-review and inferred-case labels | Research on a rule must not silently clear a later event; broad rule/time matches are not exact case membership | Real snapshot and synthetic console checks; event verdicts stay null |
| Level 16 accepted consistently | Wazuh permits levels 0-16; 15 and 16 both belong to the existing Critical band | Inventory/schema tests and browser fixtures; no level-16 live event generated |
| Missing metrics remain unavailable | Empty case timing or latency should neither crash publication nor become zero | Exporter regression and all-view browser checks |
| Queue warnings join manual freshness checks | A loader can succeed while the endpoint loses data | Seven new health tests and a bounded read of retained SQL warnings |
| Repository-wide structural check | Catch malformed source/data, broken file links and accidental private artifacts before publishing | Read-only parser plus five regression tests |

The rule-level range is documented in [Wazuh's rules syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html).
The existing SQL severity bands already handle level 16; no database migration
was necessary. The data-file limit is now explicitly described as a data-file
cap, not protection against filling the drive with logs, tempdb or other files.

## Review Coverage

The structural inventory covers root build scripts, documentation, loader,
warehouse, Wazuh, Suricata, Windows helpers, six-page Power BI definitions,
console, tests and private publication tooling. It parses Python, strict JSON
including Power BI project/report definitions, Wazuh XML fragments and local
Markdown file targets. All 285 tracked/pending files were inventoried: 51 Python
files, 89 JSON/project definitions, four XML fragments and 60 Markdown files,
with 416 local file links resolving. All 23 tracked PowerShell scripts also
passed syntax parsing.

Manual review focused on the collection checker, loader/report contracts,
severity mapping, case selection/count logic, historical triage rollups,
retention statements, publication boundaries, README navigation and console
labels. This is not a claim that every line is secure or every historical
judgment is correct. Binary screenshots, SQL/TMDL semantics, external links and
Markdown section anchors are not certified by the structural checker.

## Checks And Actual Observations

- Python: 76 root tests and 261 publication/tooling tests; 324 passed and 13
  optional disposable-database tests skipped. No new database was created.
- Windows PowerShell: nine existing safety suites passed 151 assertions.
  Their fixtures/mocks are not new live hardening operations.
- Headless browser: all five console views checked at 1440x1000 and 390x844,
  with the retained public snapshot plus nullable, empty and level-16 fixtures.
  No JavaScript errors or horizontal page overflow; selection/search still work.
- The genuine console preview image was regenerated from the real retained
  snapshot and inspected. Synthetic fixtures are not published evidence.
- Gitleaks found no secrets in the staged source changes or the 120-commit
  source history. The generated public tree/history require their separate
  scan before push; a clean scanner result is not a guarantee of anonymity.
- At 01:54:02 UTC October 8 (9:54 PM Eastern October 7), the last successful
  load was 11.3 minutes old and the latest Windows alert 12.0 minutes old.
  Five queue warnings existed in the preceding 24 hours. A later normal-queue
  record does not prove dropped events were recovered; overall status is
  **attention**, not a newly disconnected endpoint or confirmed incident.
- A separate bounded Sysmon-error query timed out; complete source-health
  aggregation remains unverified. That timeout did not change SQL settings.

Private screenshots and diagnostics remain outside both repositories. The
existing historical snapshot and approved-text catalog are retained: this batch
does not approve unreviewed live text or export new incident data.

## Still Open

Real agent heartbeats, full source-loss signals, causes of prior drops,
reboot durability, deduplicated local notifications and an approved execution
identity/schedule remain part of the collection-health package. Exact case
membership and event-specific dispositions need a separately tested schema
design; changing labels does not implement them. Fresh saved-live Power BI
rendering remains deferred while the owner uses the computer.

Suricata stays a bounded validation pilot, not a continuous home sensor.
DNS/flow records require a proved path and resource/drop/retention budgets.
The maintained library remains field-reviewed, not deployed. Disk/boot/account
protection and off-PC recovery retain their existing gates. No new permissions,
live rules, service restarts, firewall/VPN changes, installs or capture occurred
in this review batch. See [current status](../STATUS.md),
[completion checklist](soc-completion-plan.md) and
[system interaction map](triage-system-audit.md).
