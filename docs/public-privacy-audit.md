# Public Privacy Audit

Audit date: 2026-10-03. Reviewed public revision: `d37ea647c5fe9a842ba0c83dad682a91486ef23b`.

## Findings

1. Historical identity disclosure: older public revisions retain the original Ubuntu SSH username and local VM hostname. Current publication replacements remove these values from the latest files, not from Git history. These identifiers are not credentials; this audit does not establish compromise. No history rewrite or credential change was performed.
2. Current path disclosure: personal Windows home-directory paths remain in setup scripts, the runbook, example loader configuration, agent configuration, and some triage reports. The author's identity is intentionally public, but machine-specific paths should become documented placeholders before calling publication sanitization complete.
3. Future export risk: the snapshot exporter uses private-term replacements and a blacklist for free-text fields. This is not a complete boundary against previously unknown addresses, credentials, or paths. A synthetic test previously demonstrated this gap. Reviewed field allowlists, fail-closed validation, and regression tests remain required.
4. Claim accuracy: current and historical console preview images say the SIEM is never exposed to the internet. A static public console with no live SOC connection does not prove absence of exposure through other routes. External exposure testing remains pending; the wording and a genuine replacement screenshot need review.

## Checks Completed

- Gitleaks v8.30.1, downloaded from its official release with archive checksum verification, returned zero findings for current public files and all reachable public Git history. Allow comments were ignored; no repository Gitleaks configuration or ignore file was found, and no Gitleaks configuration environment variables were present.
- The checkout is not shallow. Git enumerated 24 reachable commits; Gitleaks reported 23 scanned commits. Scanner counts are not a guarantee that every possible secret format is detectable.
- A separate known-inventory search covered unique file blobs across reachable revisions. It found the historical username/hostname and personal paths above; the other checked private device addresses, account email, hardware identity, and security identifier did not match. Values are deliberately omitted here.
- Commit author/committer email metadata used a GitHub noreply identity.
- Visually reviewed nine current images and the one additional historical image version. No obvious credentials or private network/account details were observed. Endpoint display aliases, software posture, timestamps, and aggregate metrics remain deliberate portfolio disclosures.
- Pillow reported no EXIF tags in any of the ten image versions. Available metadata keys were limited to image format, density, gamma, and color-space information. This is not steganography analysis or exhaustive forensic inspection.

## Remaining Gates

- Replace personal paths with reviewed placeholders while preserving example configuration and FIM-rule consistency.
- Harden snapshot publication and add tests before exporting another live snapshot.
- Decide whether historical noncredential identifiers warrant a coordinated history rewrite. Rewriting cannot recall existing clones or screenshots and must not be done silently.
- Validate authenticated private administration, HTTPS trust, off-network access, unauthorized-device denial, revocation, and public exposure separately.
- Review GitHub/Tailscale account MFA, repository permissions, recovery methods, and backup restoration. Account settings were not audited in this pass.

## Limits

This is a bounded repository audit, not proof of complete privacy, complete security, or absence of compromise. It excludes unreachable/deleted Git objects, external clones, forks, caches, account sessions, router/cloud configuration, and live host forensics. No actual secret was identified that requires rotation on the evidence from this pass; discovery of one later requires revocation/rotation before repository cleanup.

Method references: [Gitleaks](https://github.com/gitleaks/gitleaks), [GitHub sensitive-data removal guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).
