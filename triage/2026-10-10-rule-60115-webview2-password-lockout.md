# Triage Report: Account Lockout from a WebView2 Password Prompt

| Field | Value |
|---|---|
| Date | 2026-10-10 (Eastern and UTC) |
| Analyst | Claude (review); confirmed by the owner |
| Host | jordan-pc |
| Rules | 60115, "User account locked out (multiple login errors)" (event 4740, level 9); 60122, logon failure (event 4625); 60104, credential validation failure (event 4776) |
| Volume | 5 failures 22:06:00 to 22:21:30 UTC, lockout at 22:21:30, one more refused attempt at 22:35:33 |
| Case | SG-014 |
| Verdict | **Benign, confirmed with the user:** the owner mistyped the Windows password at a Windows password prompt until the account locked. |

## Investigation

| Field | Value | Meaning |
|---|---|---|
| Account | the machine owner's local account | A real account, not guessed names |
| Logon type | 2 | Interactive: typed at this computer, not over the network |
| Status / sub-status | `0xc000006d` / `0xc000006a`; then `0xc0000234` | Wrong password; then "account locked" |
| Process | `msedgewebview2.exe` (Edge WebView2 runtime) | An app built on WebView2 asked Windows to verify the password, the same mechanism as Edge's saved-password prompt |
| Source IP | none | Local only |

This is the third case of the pattern after SG-010 and
[SG-012](2026-10-07-rule-60115-edge-password-lockout.md); the difference is the host process
(WebView2 instead of Edge itself). Because it again reached lockout, it was held for the owner's
confirmation rather than closed by similarity. The owner confirmed on 2026-10-11.

The lockout policy worked as designed, and every attempt reached the SOC.

## Verdict

Benign, user-confirmed. No action needed. If this pattern ever appears while the owner is away
from the computer, treat it as a hands-on-keyboard password guess, not as this case.
