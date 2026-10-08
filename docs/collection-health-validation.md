# Windows Collection Health

## Plain-English Result

October 7, 2026: the Windows collection outage is repaired. The agent was trying
an obsolete VM address because Windows had two entries for the manager's name.
After verifying the current guest's identity, we removed only the old entry and
restarted the Windows agent. It reconnected at 6:07 PM Eastern (22:07 UTC).
Two fresh benign events now match from original Sysmon records through Wazuh's
Indexer and the normal scheduled SQL loader. Earlier dropped-event reports and
restart durability remain separate open gates.

Think of the agent as the courier and SQL as the filing cabinet: a working
filing cabinet does not prove the courier is delivering Windows records.
There is no evidence here that an attacker caused this outage. The original
read-only outage observations below are retained as historical evidence.

## Original Outage Checks (20:55-21:01 UTC)

| Check | Actual result | What it does not prove |
|---|---|---|
| Windows Wazuh, Sysmon and SQL services | Running | Authenticated agent connection or fresh collection |
| Latest twelve loader outcomes | Succeeded | All monitored agents are still sending data |
| Windows records in SQL | Newest retained alert at 10:49:46.056 UTC; 34,124 retained records | Events after that cutoff were collected |
| Windows records in TLS-verified Indexer | Same cutoff; latest rule 504 reports agent disconnection | Current manager agent status without a separate authenticated status check |
| Manager records in Indexer | Newer records through 20:42:44.549 UTC | Windows endpoint health |
| Socket owned by Wazuh service process | SYN sent to the stale data-port destination, not Established | A successful connection or authentication |
| Local manager-name resolution | Two IPv4 results: one on the current Default Switch subnet, one stale | Which destination the current agent configuration specifies |
| Current VM data port | One bounded TCP connection on the current LAN path succeeded | Agent authentication or end-to-end event delivery |
| Host available physical memory | Approximately 6.2-6.7 GiB sampled | Sustained performance or the cause of earlier losses |

Real addresses, host details, raw events and diagnostic files stay outside the
repositories in owner-protected storage. The Indexer check used the existing
restricted loader tunnel and certificate verification; it did not open a new
API/indexer listener or grant administrative SSH access.

## Earlier Event Loss Is A Separate Finding

Retained Sysmon Event 255 records around 05:40-06:00 UTC explicitly report
registry events dropped from the driver queue. Nearby Wazuh messages also show
agent queue pressure/full/flooded states and later a normal-queue message.

- The drops are real historical loss reports, not merely a busy-service warning.
- Do not add the reported counters together as unique lost events: their reset
  and cumulative semantics have not been established.
- No warnings in a recent SQL window is not reassuring when Windows is silent.
- A normal-queue message does not restore lost events or explain their cause.
- Historical queue loss and the current stale-destination attempt are separate;
  a common cause has not been proven. Neither alone proves compromise.

[Microsoft's Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
describes Event 255 as an error event with several possible causes. Here, the
retained event's own text specifically identifies dropped registry events.

## Read-Only Administrator Diagnostic

[Get-WatchtideAgentDiagnostic.ps1](../windows/Get-WatchtideAgentDiagnostic.ps1)
requires an existing Administrator PowerShell session to read protected agent
files. It does not elevate itself or weaken their permissions.

It reads only the configured manager endpoints, agent state and a bounded agent
log tail, plus the service's sockets, manager-name resolution and named SOC VM
network metadata. It saves details and hashes privately, printing a small
summary. It does not read enrollment keys or loader credentials, change DNS or
configuration, restart services, capture packets or scan devices.

Seventeen synthetic helper checks passed, including XML/DTD rejection, bounded
configuration size, field selection and cautious state parsing. An earlier
unelevated read was denied. The owner subsequently ran the actual elevated
diagnostic at 21:29 UTC, without changing settings. Independent inspection of
its private output and three file hashes/reader permissions confirms:

- Actual manager configuration uses the local hostname, TCP port 1514.
- Agent state is pending, and the saved log repeatedly reports connection
  failure to the stale resolved address; its latest sample is also SYN-sent.
- The manager hostname resolves to current-subnet and stale IPv4 results.
- The named SOC VM is attached to the Default Switch, but its IP metadata is
  empty. This is not a complete current guest-address identity check.

The initial pasted command lacked a closing quote, so PowerShell waited at its
continuation prompt rather than running it. That was canceled and the complete
command ran. No diagnostic retry weakened file permissions or changed services.

[Wazuh's connection troubleshooting](https://documentation.wazuh.com/current/user-manual/agent/agent-management/agent-connection.html)
uses agent state, its local log and an Established data-port connection as
distinct checks. A service-running result alone is insufficient.

## Completion Gates

- [x] Independently compare endpoint freshness in SQL and the Indexer.
- [x] Attribute the attempted destination to the actual Wazuh service process.
- [x] Check current-path data-port reachability without opening permissions.
- [x] Prepare and test a read-only administrator diagnostic.
- [x] Read and privately verify the actual manager configuration, state and log.
- [x] Verify intended guest identity before repair: existing strict SSH host-key
  checks and trusted Indexer TLS/read access pass on the current guest address.
  Hyper-V IP metadata remains empty; do not credit that separate check.
- [x] Confirm the duplicate-name cause, preserve protected rollback evidence,
  remove only the obsolete entry and restart only WazuhSvc.
- [x] Verify authenticated reconnection and an exact benign source/Indexer/SQL
  trace through the normal loader; read-only reporting-view identities also pass.
- [x] Prepare/test a read-only SQL collection check and run it manually.
- [ ] Verify resolution/reconnection after a separately planned host/VM restart;
  automatic network-name regeneration can invalidate this point-in-time repair.
- [ ] Add actual heartbeat/source-loss checks and test local notification delivery
  with deduplication and recovery; a manual freshness check is not a watchdog.
- [ ] Review queue-loss causes and representative collection health, including
  important source freshness and warnings, before increasing detection load.
- [ ] Resume the small offline TCP rule/control lesson, then the separately
  scoped Nmap/capture exercise. Sustained and whole-home coverage remain open.

## Authorized Repair And Exact Trace

The current guest address passed authentication using the existing forwarding-only
loader key with its already-trusted SSH host identity, then the normal verified
Indexer certificate and read credentials. No administration shell was granted.
The live `hosts.ics` file contained exactly one current and one obsolete mapping
for the configured manager name. This corroborates the saved stale connection
attempts; a reachable port alone was not used as identity proof.

The first apply attempt stopped before any write or restart. A read-only
reproduction showed the parser rejected an unrelated nonmapping fragment already
present in the actual file. The corrected parser preserves unrelated bytes and
has a regression test for that input. It still rejects ambiguous manager entries,
changed hashes and shared aliases. The reviewed retry passed through normal UAC.

[Repair-WatchtideAgentResolution.ps1](../windows/Repair-WatchtideAgentResolution.ps1)
saved protected configuration/mapping backups and hashes, removed exactly one
obsolete line without replacing file permissions, cleared the DNS cache and
verified the single expected result. Only WazuhSvc restarted. Within the bounded
wait, both connected agent state and its Established data-port socket passed.
The agent configuration hash is unchanged; rollback was not needed.

One harmless marked `cmd`/`whoami` test generated two Sysmon Event ID 1 records.
[Get-WatchtideRecoveryTrace.ps1](../windows/Get-WatchtideRecoveryTrace.ps1)
later read only their exact protected record IDs. Provider, record IDs, process
GUIDs, source times and marker matched the TLS-verified Indexer documents. Both
SQL raw payloads equal those Indexer documents; IDs/rules/times and reporting-view
identities match. The existing scheduled loader did the importing, not a second
manual loader job. These are controlled validations, not malicious incidents.

| Record | Source UTC, October 7 | Wazuh alert UTC | SQL loaded UTC | Wazuh rule / level |
|---|---|---|---|---|
| Marked command | 22:08:52.225 | 22:08:53.658 | 22:12:42.995 | 92052 / 4 |
| Child identity query | 22:08:52.244 | 22:08:53.661 | 22:12:43.007 | 92032 / 3 |

At 00:37 UTC October 8 (8:37 PM Eastern October 7), Windows events still arrived
in the Indexer and the refreshed authenticated dashboard showed one Active agent,
zero Disconnected/Pending. The latest three checked loader runs succeeded in
2.235-3.873 seconds. Protected repair and trace hashes/reader checks passed.
No fresh Power BI refresh or recovery of every missing event is inferred.

## Read-Only Health Check

The new [collection checker](../warehouse/check_collection_health.py) separates
loader success from per-agent alert observations, using a 30-minute review
threshold. It also flags a newest disconnection record, failed/stuck loads,
missing evidence and excessive future timestamps. Database errors return unknown
without printing connection details. Only SELECT statements run, with bounded
query timeouts and parameterized agent IDs. The existing local analyst identity
is used; no new database grant is made.

```powershell
.\.venv\Scripts\python.exe -B -m warehouse.check_collection_health --agent-id 001
```

Exit 0 means recent observations, 1 needs review, 2 means unknown/unavailable
evidence. None means "all devices safe." A quiet endpoint can have no alerts
without being disconnected; actual heartbeats and source health remain necessary.
At 00:40 UTC (8:40 PM Eastern), the manual check passed: last successful load
12.75 minutes old, newest endpoint alert 13.43 minutes old. No scheduled task,
notification channel or background monitor was created. Local Windows delivery
is the owner's selected first channel; it remains to be implemented/tested.

Verification: 33 resolution-repair, 12 exact-source-trace and 17 diagnostic
synthetic checks pass. The collection checker has 25 checks; existing
reliability/library (43) and publication-privacy (33) checks also pass, 163 total.
These supplement the actual protected source/Indexer/SQL comparisons; they do
not simulate a completed reboot or recover dropped records. All 372 checked
local documentation links resolve and the retained public snapshot validates.

## Boundaries

The original diagnostic/audit changed nothing. The later authorized repair
changed only the obsolete mapping, DNS cache and Windows agent service state.
No rule deployment, installation, sustained capture, firewall/VPN change or port
scan was performed. The
Tailscale grant stays scoped to administration; the reachable LAN agent path
does not justify adding agent ports to the tailnet. Do not disable checks,
silence queue warnings or widen network access to make a status indicator green.
