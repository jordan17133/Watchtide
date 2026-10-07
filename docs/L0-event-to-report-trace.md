# L0: Follow One Packet To A Report

Adapted from Claude's October 7 lesson draft and checked against the completed
[live trial](suricata-live-trial.md) and [reporting handoff](suricata-live-reporting-handoff.md).
This is a learning guide, not a statement that the owner has already explained
every hop. No new traffic or report refresh was generated for this write-up.

## The Simple Version

We sent two harmless test requests. One contained the text our rule looks for;
the other did not. Suricata spotted the marked one, Wazuh turned its result into
an alert, and our loader stored that alert in SQL. Power BI can read that SQL row
after refreshing. The saved-live row's fresh Power BI display is still unverified.

```text
Packet -> Suricata rule -> EVE alert -> Wazuh -> Indexer -> SQL -> Power BI
             |                                               |
      TShark checks bytes                          report reads a saved import
```

The test proves a particular route and rule, not malware detection or all home
traffic. The sensor stops after the trial; the permanent service remains masked.

## The Nine Hops

| Hop | What happens | What we checked |
|---|---|---|
| 1. Packet | Ubuntu sends an IPv4 ICMP echo request to its Windows host | Two separate saved captures contain one request each; hashes and fields independently checked |
| 2. Decode | Suricata 8.0.7 reads packets during the bounded trial | Zero reported capture drops and clean shutdown |
| 3. Match | Signature 9000001 requires an echo request containing `WATCHTIDE-PILOT` | One positive alert; no alert on the unmarked control |
| 4. EVE | Suricata writes a structured JSON alert | Original packet time and network fields retained; the pipeline carries this record, not the full packet |
| 5. Wazuh | A separate one-time source reads the saved EVE alert | Wazuh rule 86601, level 3; all five guest services active after the manager-only restart |
| 6. Indexer / dashboard | The alert becomes a searchable document | Exact identity and fields independently checked in the Indexer and authenticated Wazuh dashboard |
| 7. Loader | The scheduled read-only loader searches through its restricted SSH tunnel | Normal scheduled load succeeded; no manual backfill needed |
| 8. Warehouse | SQL stores the document in `sg.alerts`; `rpt.network_alerts` exposes its fields | Full stored JSON equals the Indexer source; context is **Controlled live validation**, label `controlled-live-suricata-trial` |
| 9. Power BI | Network Detection imports reporting-view data on refresh | Definitions are updated; fresh rendering of this saved-live row remains deferred. The earlier **offline** row was actually displayed October 5 |

Wazuh level 3 describes this matched rule's severity; it does not itself establish
the verdict. The controlled activity, packet evidence and source label establish
that this is validation, not an incident. Suricata priority is a different scale.

## Four Different Clocks

| Time (UTC) | Meaning |
|---|---|
| October 7, 14:35:45.491168 | Original marked packet |
| October 7, 15:51:26.552 | Wazuh processed the later saved-event handoff |
| October 7, 15:57:43.530 | SQL loaded that alert |
| Power BI's own refresh time | When the report last imported its data; not necessarily the event time |

The first gap includes our deliberate wait before handing over saved evidence.
It is not measured live-sensor delay. The Indexer document ID connects the alert
to its SQL row; the original timestamp and packet hash tie it back to the trial.
A report card is an aggregate, not proof that a particular packet was displayed.

## Explain It Back

Answer in your own words before marking L0 understood:

1. Why did the marked request alert while the control did not?
2. What does Suricata do that Wazuh does not do in this path?
3. Does SQL contain the full packet capture or the Wazuh alert record?
4. Why can a Power BI screen be older than the data already in SQL?
5. What remains invisible: routine Windows browsing, iPhone traffic or both?

Both remain outside verified network coverage. Our [existing Windows event
trace](event-trace.md) provides a separate endpoint example; it is not the same
event or proof of every collected connection. See the [analyst runbook](analyst-toolkit-runbook.md)
for the daily health, evidence and verdict routine.
