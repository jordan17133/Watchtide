# Triage Report: Defender Flagged Detection-Drafting Files as Ransomware Content

| Field | Value |
|---|---|
| Date | 2026-10-07 |
| Analyst | Jordan Carven-Bellace |
| Host | windows-endpoint |
| Rules | 62123, "Windows Defender: Antimalware platform detected potentially unwanted software" (Defender event 1116, level 12); 62124, action taken (Defender event 1117, level 3) |
| Volume | 4 detections, 23:34:08 to 23:36:46 UTC, each followed by an action event 5 to 38 seconds later |
| MITRE ATT&CK | None applied by Wazuh to rule 62123. The flagged content described T1490 (Inhibit System Recovery); nothing was executed. |
| Verdict | **Benign, controlled (a benign true positive):** Defender correctly recognized ransomware-pattern text in files written while drafting a T1490 detection. No command ran. |

## Investigation

Defender's own fields, as stored by Wazuh for each detection:

| Field | Value | Meaning |
|---|---|---|
| Threat name | `Trojan:BAT/Donvibs.AP!MTB` (threat ID 2147910013) | A machine-learning signature for batch-style ransomware content |
| Severity / category | Severe (5) / Trojan | Defender's highest severity band |
| Source / origin | Real-Time Protection / Local machine | Caught as the files were written or opened |
| Detection user | the machine owner's local account | No other account involved |
| Remediation | Action event (1117) followed every detection; threat state not active afterward | Defender removed or blocked each file |

| Detection (UTC) | Process touching the file | File (leaf name only) |
|---|---|---|
| 23:34:07 | Claude Code (`claude.exe`) | temporary copy of `detect-shadow-copy-deletion.md` |
| 23:34:34 | Claude Code (`claude.exe`) | temporary copy of `verify-t1490.ps1` |
| 23:34:44 | Windows PowerShell (`powershell.exe`) | `verify-t1490.ps1` (blocked when PowerShell tried to open it) |
| 23:36:45 | Claude Code (`claude.exe`) | `detect-shadow-copy-deletion.md` |

**Root cause.** During detection-engineering work, an AI coding assistant (Claude Code) wrote a
draft detection document and a pattern-test script. Both contained literal examples of
shadow-copy and backup deletion commands as test data, side by side. Defender's model classifies
that combination as ransomware content. The test script only compared text against regular
expressions; it never invoked any of the commands, and Defender blocked it before it ran.

**Pipeline check (a useful side effect).** All four detections and four action events reached
Wazuh and the normal scheduled loader (run 691, 23:42:47 UTC): about 8 minutes from detection to
SQL, in line with the usual latency. This is an end-to-end proof of the Defender -> Wazuh -> SQL
path on a severe detection.

**Analyst note.** Wazuh's rule text says "potentially unwanted software," which understates
Defender's actual verdict (Severe, Trojan). Always read the source event's fields, not only the
SIEM's one-line description.

**What would have changed the verdict:** detections on files not written by the drafting
session; any process start of vssadmin, wbadmin, bcdedit, WMIC or PowerShell shadow-copy
deletion around that time (none in stored alerts); missing shadow copies afterward; or a threat
that stayed active after remediation.

## Actions Taken

- Detection examples are now defanged (dangerous word in brackets) in Windows-hosted documents.
- Attack-variation tests moved to `wazuh-logtest` on the Ubuntu VM, outside Defender's scope.
- The undefanged draft was left to Defender's remediation, not restored.

## Verdict

Benign, controlled. Defender and the Wazuh pipeline both worked as intended. No action needed
beyond the documentation changes above.
