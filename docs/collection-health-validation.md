# Windows Collection Health

## Plain-English Result

October 7, 2026, approximately 20:55-21:01 UTC: Windows monitoring is not
currently verified healthy. The agent program is running, but its connection
attempt targets an old VM address. The current VM's data port accepts a TCP
connection. Adding detection rules will not fix missing source data.

Think of the agent as the courier and SQL as the filing cabinet: a working
filing cabinet does not prove the courier is delivering Windows records.
There is no evidence here that an attacker caused this outage.

## Independently Checked

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
configuration size, field selection and cautious state parsing. These checks
are not an actual elevated diagnostic result. An earlier unelevated read was
denied; the local agent log therefore remains unreviewed.

[Wazuh's connection troubleshooting](https://documentation.wazuh.com/current/user-manual/agent/agent-management/agent-connection.html)
uses agent state, its local log and an Established data-port connection as
distinct checks. A service-running result alone is insufficient.

## Completion Gates

- [x] Independently compare endpoint freshness in SQL and the Indexer.
- [x] Attribute the attempted destination to the actual Wazuh service process.
- [x] Check current-path data-port reachability without opening permissions.
- [x] Prepare and test a read-only administrator diagnostic.
- [ ] Read the actual protected manager configuration, state and agent log;
  reconcile these with authoritative VM/network metadata.
- [ ] Confirm the cause, preserve protected rollback evidence and make only the
  necessary bounded repair. DNS cache, agent restart or a configuration edit
  are possibilities to review, not changes already approved or performed.
- [ ] Verify authenticated reconnection and a newly generated benign Windows
  event in Wazuh, the Indexer and SQL through the normal loader.
- [ ] Review queue-loss causes and representative collection health, including
  important source freshness and warnings, before increasing detection load.
- [ ] Resume the small offline TCP rule/control lesson, then the separately
  scoped Nmap/capture exercise. Sustained and whole-home coverage remain open.

## Boundaries

No agent repair, restart, rule deployment, installation, sustained capture,
firewall/VPN change or port scan was performed in this health review. The
Tailscale grant stays scoped to administration; the reachable LAN agent path
does not justify adding agent ports to the tailnet. Do not disable checks,
silence queue warnings or widen network access to make a status indicator green.
