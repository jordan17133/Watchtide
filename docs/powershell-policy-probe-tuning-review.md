# PowerShell Policy-Probe Tuning Review

October 7, 2026. Claude's proposed rule 100120 was reviewed but **not deployed or
added to the active rules file**. Existing rules 100100 and 100101 are unchanged.

## What We Found

Rule 100100 requires both the Windows PowerShell writer's exact path and a
specific policy-probe filename in user Temp. Claude's draft expands to several
parent rules but checks only a filename suffix, anywhere on disk. A matching
filename can be chosen by another program; it is not an exclusive PowerShell
identity or evidence of benign intent.

The new noise is not just a duplicate of the old tune. A bounded read of stored
alerts from October 5, 00:00 UTC through the October 7 review found:

| Stored pattern | Result |
|---|---|
| Rule 100100, level 3 | 2,272 events match both existing field conditions |
| Rule 92213, level 15, policy-probe-shaped target | 1,410 events outside the existing writer condition |
| Writers of those 1,410 events | 1,408 `pwsh.exe`, two `powershell.exe` |

The target pattern matches in those Critical events; the writer condition does
not. This is a local regex comparison against stored Wazuh fields, not a fresh
Wazuh engine replay or a benign verdict for every event. A checked current
bundled `pwsh.exe` has a valid Microsoft signature; that does not establish every
historical process identity or protect a user-writable installation directory.

Claude reported 2,522 Critical events in a different rolling-week window. That
claim is not a measured post-deployment reduction, and our shorter window must
not be substituted for its denominator. No weekly reduction is credited here.

## Why The Draft Is Held

The proposed filename-only rule would also lower severity when an unrelated
executable writes the same name outside Temp. Local negative-control tests
demonstrate that behavior. Its warning that only PowerShell can create these
names is incorrect. Anchoring the filename helps precision but does not identify
the writer, folder trust or process intent.

## Safer Change Gate

1. Group actual events by exact writer path, target root, event ID, parent and
   known activity. Inspect archives/process evidence where the alert is insufficient.
2. Assess each executable's location and write permissions, not just its present
   signature. Do not whitelist every `pwsh.exe`, every Temp write or an AI-tool
   cache by name alone.
3. Draft explicit writer-and-target conjunctions for the justified cases. Confirm
   unused IDs and correct parent-rule behavior on the installed Wazuh version.
4. Use the installed engine to test real representative positives plus arbitrary
   writers, outside-Temp lookalikes, `.dll`/`Add-Type` activity, installers and
   wrong-length names. Unrelated suspicious activity must retain parent severity.
5. Back up, deploy only the reviewed change, verify manager health and ingestion,
   then measure future matched/unmatched events over a defined window.

Existing scope regression checks are useful guardrails, not a substitute for
`wazuh-logtest` on the actual ruleset. Wazuh documents [custom-rule placement](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
and [decoder/rule testing](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html).
The [original investigation](../triage/2026-09-30-rule-92213-powershell-policy-test-noise.md)
already records the residual risk even for the narrower deployed tune.

This is detection maintenance alongside Stage 5 learning. It does not require
enabling continuous capture, changing the VPN or suppressing network detections.
