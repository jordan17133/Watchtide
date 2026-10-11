# Triage Report: Keyword Rule Matched the Analyst's Own Search

| Field | Value |
|---|---|
| Date | 2026-10-09 |
| Analyst | Claude |
| Host | jordan-pc |
| Rule | 91822, "PowerShell script used Invoke-Command cmdlet to execute sub script" (PowerShell event 4104, level 12) |
| Volume | 1 alert, 04:59:09 UTC |
| Notification | Watchdog security popup at 05:21 UTC (tier for level 12+ rules never reviewed before) |
| Case | SG-013 |
| Verdict | **Benign, controlled:** the script block was the analyst's own `sqlcmd` query, which searched stored alerts for the text `'Invoke-Command'`. |

## Investigation

The logged script block (1,310 characters) begins with the shell's standard output-encoding
preamble and then runs `sqlcmd` against the local warehouse. The words `Invoke-Command` appear
only inside a SQL string literal, as the search term for reviewing earlier rule 91823 alerts. No
`Invoke-Command` call ran. The alert time matches that review step exactly.

## What this shows

- Script-block keyword rules match text, not intent: an analyst searching for a keyword can trip
  the rule for it. Expect this during investigations; the timestamp and full script text settle it.
- The watchdog's "never reviewed" tier behaved as designed: one popup, 22 minutes after the event,
  for a level 12 rule with no prior review. This case now marks rule 91822 as reviewed.

## Verdict

Benign, controlled (analyst activity). No tuning: one event.
