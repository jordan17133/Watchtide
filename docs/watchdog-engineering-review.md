# Watchdog Engineering Review

October 11, 2026 Eastern; read observations extend into October 12 UTC.
This is a read-only deployed-system review and an isolated policy proposal,
not an activation, permission change or complete monitoring certification.
Detailed account/grant inventory stays in the private source handoff/evidence.

## In Plain English

The watchdog is a scheduled local checker. Its Windows task is configured to
run as the logged-on owner with limited Windows rights, rather than elevated
rights. That does not automatically constrain its database permissions or
make its editable source code a protected deployment.

The current security selector excludes some future high-priority events when
the rule has historical research or a case link. That is the wrong boundary:
reviewing a past event does not decide the next one. A candidate now removes
that exemption while limiting repeat popups. It is tested separately so the
scheduled task cannot pick up an unapproved edit to its live module.

## What Was Independently Checked

| Check | Result | Scope / open gate |
|---|---|---|
| Task identity/action | Owner identity matches; one expected Python executable/action and working directory | Configured identity confirmed, not a new SQL read-only identity |
| Windows execution | Enabled, Ready, Interactive/Limited, 15-minute repeat, five-minute stop, IgnoreNew | No task run initiated by this review; existing task later returned 0, not proof every tier succeeded |
| Private state | Directory and four existing files are owned, nonreparse and have only intended effective readers; current version-1 security state parses | Inheritance enabled; ongoing path/size/inheritance enforcement and reboot durability remain separate |
| Runtime trust boundary | Source-backed executable paths have additional local modify grants | Classify all grants and use a protected deployment boundary; do not blindly revoke access needed by approved tooling |
| Database scope | Owner-account connection can read and write; restricted SQL identity is not established | Windows limited rights and SELECT-only code are not enforced database least privilege; actual deployed token/new identity still needs its own check |
| Health dry run | SQL read timed out (HYT00); Unknown held for confirmation; health read 42.4 seconds | No delivery/state/log write by the preview. Per-query timeouts do not form a whole-run deadline; no root cause inferred |
| Security dry run | Earlier preview had 14 new candidates, no due notice, not truncated; later read had none after the normal scheduled run | Counts alone do not attribute every nonnotice to review history versus an existing cooldown, or classify events as benign |

Existing services/tasks, read permissions, code and state were not changed by
these checks. No new database grants, schema, index, account, SSH access or
unattended schedule was created. A SQL timeout is unavailable evidence, not a
healthy result or an incident verdict.

## Selected Candidate Policy

The owner selected **four-hour same-rule repeats** for preparation. It remains
outside the live import path in private publication tooling; no activation was
approved by that choice.

- Every new level-12+ record can qualify regardless of historical rule research
  or case links; health rules 202-205 remain in the health tier.
- The existing fixed watchlist still qualifies immediately at its existing
  levels. It does not inherit the general high-priority cooldown.
- One planner pass produces at most one grouped Security notice. A new different
  high-priority rule can qualify during another rule's four-hour repeat interval.
- Successful delivery deduplicates document identities; failed delivery keeps
  triggering records available for retry and does not start the reminder clock.
- Existing version-1 state is preserved. Its legacy `unreviewed_notified` key is
  a compatibility field, not permission to exclude reviewed rules.
- Truncated or over-limit input stops without checkpoint progress, rather than
  silently treating an incomplete batch as complete. End-to-end handling of
  that failure and paginated retrieval still need their own runner changes.
- Cooldown affects notifications, not stored evidence or verdicts. A different
  event under the same rule can wait during the interval; this is not every-event
  delivery, contextual incident grouping or continuous off-PC monitoring.

The existing deployed policy still uses its original review exclusion and
seven-day rule reminder. Do not describe the candidate as live.

## Tests And Remaining Engineering

Isolated fake-transport tests prove the historical-review counterexample against
the deployed planner, four-hour boundary, different-rule eligibility, unchanged
watchlist, version-1 compatibility, failed transport, deduplication, invalid data,
candidate limits and dry-run integration without state writes or a popup. Existing
deployed-policy tests still run unchanged; passing them does not endorse that policy.

Additional issues remain explicit: missing/corrupt security state currently
rebaselines silently, security-tier failures can be logged without their own
health warning, and a capped/overlapping reader is not a verified backlog
pagination design. The candidate is not credited with fixing those runner gaps.

### Activation Gates

1. Review the runtime writer grants and actual execution/read identity. Establish
   a protected versioned runtime and an appropriately restricted SQL credential
   boundary; do not blindly strip the operator's maintenance rights.
2. Preserve audited code/state/task metadata and a rollback path. Verify the
   candidate against one frozen input, with delivery disabled, before rollout.
3. Obtain a bounded activation window. Prevent a concurrent task pass while
   changing runtime files; preserve existing state and restore prior task state.
4. Verify the actual next scheduled run, both tier outcomes and generic delivery
   separately. No test popup or synthetic incident is authorized by this review.
5. Validate reboot/logon behavior and failure reporting; then return to the
   existing offline TCP track after source/resource gates.

The [current status](../STATUS.md#current-snapshot) and
[completion plan](soc-completion-plan.md#stage-checklist) retain that order.
