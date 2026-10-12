# Triage Report: Account Lockout from Edge's Windows Password Prompt

| Field | Value |
|---|---|
| Date | 2026-10-07 (Eastern); 2026-10-08 UTC |
| Analyst | Claude (review); confirmed by the owner |
| Host | windows-endpoint |
| Rules | 60115, "User account locked out (multiple login errors)" (event 4740, level 9); 60122, logon failure (event 4625); 60104, credential validation failure (event 4776) |
| Volume | 5 failures 01:56:19 to 01:58:21 UTC about 30 seconds apart, lockout at 01:58:21, one more refused attempt at 02:08:13 |
| Case | SG-012 |
| Verdict | **Benign, confirmed with the user:** the owner mistyped the Windows password at Microsoft Edge's saved-password prompt until the account locked. |

## Investigation

| Field | Value | Meaning |
|---|---|---|
| Account | the machine owner's local account | A real account, not guessed names |
| Logon type | 2 | Interactive: typed at this computer, not over the network |
| Status / sub-status | `0xc000006d` / `0xc000006a`; then `0xc0000234` | Wrong password; then "account locked" |
| Process | `msedge.exe` | Edge asked Windows to verify the password before showing saved passwords |
| Source IP | none | Local only |

The same pattern was confirmed benign on October 2 (SG-010,
[report](2026-10-02-rule-60122-edge-password-prompt.md)). That report named "continuing until
lockout" as something that would change the verdict, so this one was held for the owner's
confirmation instead of being closed by similarity. The owner confirmed on 2026-10-09.

The lockout policy from CIS batch 1 (5 attempts, 15 minutes) worked as designed, and every
attempt reached the SOC.

## Verdict

Benign, user-confirmed. No action needed.
