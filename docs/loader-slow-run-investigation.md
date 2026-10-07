# Loader Duration Follow-Up

October 7, 2026. Adapted from Claude's read-only investigation and independently
rechecked against recent warehouse runs. No scheduler, SQL memory or loader
settings changed during this handoff.

## Finding

The earlier eight-minute run coincided with documented host memory pressure and
SQL paging. That is a plausible contributing cause, not proof that every later
slow run has the same cause or that the reliability gate can be closed.

| October 7 read-only check | Result |
|---|---|
| SQL configured memory ceiling | Already 4096 MB; no new cap applied |
| Ten latest recorded loads | All succeeded |
| Two latest durations | 2.052 and 2.452 seconds |
| Other slow runs in that sample | 30.397, 73.506 and **211.527 seconds** |
| The 211.527-second run | Began 17:57:41 UTC, fetched six alerts and inserted three |

The successful result establishes completion, not predictable latency. Small
input volume also does not explain a three-and-a-half-minute duration by itself.
One handoff review query timed out after fifteen seconds; a simpler bounded
read succeeded. Its cause was not captured, so it is not diagnosed as a deadlock.

## Follow-Up Before Sustained Capture

Record phase timings and overlapping workload for future slow runs: SSH readiness,
Indexer search, SQL writes/reconciliation, blocking waits, host/guest memory and
disk pressure. Avoid raising memory caps or changing schedules without that
evidence. A SQL memory setting is not a guarantee that all host workloads fit.

Use [Pipeline Health](../powerbi/) and `sg.load_runs` to review freshness and
durations. Preserve the existing [committed-snapshot fix](report-refresh-reliability.md);
it addresses the confirmed read/write deadlock, not every source of delay.
The [maturity plan](soc-network-maturity-plan.md) retains a representative
observation window and resource budget before permanent capture.

Claude's earlier "no fix needed" conclusion is retained as a dated hypothesis,
not adopted as a completed performance test. No new availability claim is added.
