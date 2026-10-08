# Dependable SOC Completion Plan

October 7, 2026. Claude's latest handoff joins the existing runbook, not a new
project. The immediate collection outage is now repaired and traced. This plan
sets ambitious, testable finish lines without promising complete privacy or
visibility into encrypted content. Ongoing patching and review never disappear.

## The System In Plain English

Windows activity is recorded by Sysmon/Windows logs. The Wazuh agent delivers
it to Ubuntu; the manager applies rules. The Indexer stores alert documents;
the dashboard lets you search them. The scheduled loader copies those documents
to SQL. Power BI imports reporting views when refreshed. An analyst reviews
the evidence and records a case/verdict separately.

Suricata contributes network evidence only on a tested capture path. Today its
proof is bounded ICMP tests and saved alert handoffs, not always-on home coverage.
Nmap checks selected services or produces authorized test traffic; Wireshark
helps explain the packets you actually have. Neither is an automatic SQL feed.
See the [full interaction/triage map](triage-system-audit.md).

## Reconcile The Handoff

- Preserved the owner's repair commit `0f73f6c`; its later verification is now
  [documented](collection-health-validation.md), not guessed from the commit.
- Unrelated application processes were left alone. A launcher and child are
  not, by themselves, duplicate independent workloads.
- The earlier filename-only PowerShell exception remains
  [held](powershell-policy-probe-tuning-review.md). A familiar filename or a
  historical benign cluster cannot approve every future event.
- "Three verified drafts" needs exact files, installed-engine results and live
  scope review. The supplied handoff does not identify all three; none was
  deployed from that sentence.
- The mentioned Defender event needs its exact identity, time, action and
  supporting evidence before a controlled-test case or incident verdict. No
  case was invented or closed from the summary.
- Use evidence states instead of the handoff's blanket "Strong" grade. The
  latest audit has 147 observed rule types, 40 historical reviews and 107
  without one; these are not 147 validated attack detections.

## Coverage Framework

Use [NIST CSF 2.0's six functions](https://www.nist.gov/news-events/news/2024/02/nist-releases-version-20-landmark-cybersecurity-framework),
including Govern. "Operate" is a useful engineering workstream below, not a
seventh NIST function. This is a planning map, not a certification or full
framework assessment.

| Function | Simple question | Current evidence / important remaining work |
|---|---|---|
| Govern | What are the rules and who approves changes? | Private/public separation, handoff and working agreement exist; record retention, accepted blind spots and notification scope |
| Identify | What are we protecting and what can we see? | PC and iPhone are the chosen scope, with Ubuntu inside the PC; device/address/source coverage matrix remains incomplete |
| Protect | Are access and stored data protected? | Reviewed private access/file/software controls; disk encryption, host boot protection, account/MFA and exposure gates remain open |
| Detect | Can we observe and validate suspicious behavior? | Windows flow repaired, historical SSH test and bounded Suricata controls pass; source-loss health and additional rule/control coverage remain open |
| Respond | Can we make and act on a supported verdict? | Case workflow exists; exact alert memberships, scoped verdicts, tested notifications and containment procedure need work |
| Recover | Can we restore what matters? | Same-PC SQL restore verified; off-PC copy and Wazuh/other-instance restore remain open |

## Stage Checklist

These work packages retain the original numbered build stages. Independent
offline work can proceed while a separately authorized deployment is waiting.

| Order | Existing stages | Work and finish line | State |
|---|---|---|---|
| 1 | 2-4, 7 | Fix the current delivery failure; verify guest identity, agent connection and exact new source/Indexer/normal-loader SQL event | Passed for this outage; reboot durability and missing-event review remain |
| 2 | 2-4, 7-8 / maturity I | Monitor source/loader/report health; test loss, stale/unknown states, recovery and notifications | Manual SQL freshness checker tested/live-read; automatic watchdog not deployed |
| 3 | 4, 7-8 | Exact case-alert links, event-specific dispositions and truthful historical-review/ATT&CK labels; correct level-16 compatibility | Audit complete, implementation gates open |
| 4 | Detection maintenance, 5 | Small maintained-rule batch with known data prerequisites, engine tests, positive/negative controls, rollback and measured noise | ET Open field-reviewed only; tuning draft held |
| 5 | 5, lessons L1-L4 | Offline TCP rule lesson, then owned-VM Nmap/capture test on an observed path; trace any alert and render existing Power BI | ICMP/port baseline passes; TCP detection and fresh saved-live Desktop check open |
| 6 | 4b-4c | Account/MFA, least-privilege exposure, protected credential custody, disk/boot protection, patches and measured capacity | Partial; never activate encryption/firmware changes without recovery preparation |
| 7 | 0-1, 7 / maturity A | Protected off-PC backup, separate Wazuh/SQL restore and an explained recovery procedure | Local SQL slice passes; separate recovery still deferred |
| 8 | 5 / maturity B-F | Device/path matrix, supported routine DNS/flow feed, drop/resource/retention budgets and measured sustained coverage | Planned; no phone/browsing or whole-home visibility claim |

## Monitor The Monitoring First

The new [manual collection checker](../warehouse/check_collection_health.py)
does not equate successful SQL loads with a reporting Windows endpoint. Synthetic
tests catch an eleven-hour stale endpoint even while the loader is succeeding.
The actual manual query passes after repair. This is useful groundwork, not a
working automatic watchdog.

The owner selected **local Windows notifications first**. No external service
or notification task is configured. Build and test the following bounded phase:

- Read real agent heartbeat/status and source-loss signals alongside per-agent
  alert observations; silence alone is not a disconnection verdict.
- Classify loader failure, agent disconnection, stale data, clock uncertainty
  and a stale imported report separately. Keep unknown evidence visible.
- Send generic local health/review messages with no raw command lines, users,
  destinations or credentials; distinguish health failures from security incidents.
- Use a state transition, cooldown and one recovery message; test duplicates,
  delivery failure, reboot/logon and cleanup. Notifications must not flood.
- Add reviewed high-priority detection notifications only after health delivery
  works. Rule level is priority, not a confirmed incident or permission to block.
- Verify execution identity and granted read scope before approving a schedule;
  do not give a notification helper unrestricted SSH or administrative rights.

A monitor on this PC cannot notify while this PC is off. Without an independently
running observer, that failure mode stays an accepted and documented blind spot.
The other available computer is a future recovery/observer option, not an assumed
online sensor or a newly approved endpoint.

## What Counts As Finished

A work package closes when its stated scope is implemented, tested with positive
and negative/failure controls, explained, recoverable and documented. A prepared
script is not a deployed feature; a successful test is not permanent availability.
Routine checks remain upkeep rather than reopening an undocumented build.

Do not expand capture load until loss/resource gates pass. Do not deploy every
vendor rule, disable warnings or invent benign verdicts to produce impressive
counts. The portfolio becomes stronger through measured scope and clear evidence.
