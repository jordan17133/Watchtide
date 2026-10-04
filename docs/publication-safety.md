# Publication Safety

Updated: 2026-10-04. The public console remains a static, historical snapshot
with no live connection to Wazuh or the SQL warehouse.

## Publication Controls

- Display text is approved separately for each snapshot field. Unfamiliar rule
  descriptions, endpoint names, verdict text, and case details are redacted;
  unreviewed report links are omitted. New live text is never auto-approved.
- A strict final schema rejects extra fields, invalid identifiers, unreviewed
  text, incorrect types, and nonfinite numbers. Validation runs both during
  export and before generation of the public copy.
- Rejected snapshots leave the previous snapshot and public checkout unchanged.
  Diagnostics identify fields without echoing their contents.
- Public event references are SHA-256 digests instead of source document IDs.
  The October 3 snapshot was migrated without changing its event timestamps,
  collection counts, or export time; this was not a new live data refresh.
- Public configuration examples replace Windows profile names with `SOC-USER`
  and the machine-specific SID with `SOC-MACHINE-SID`. Substitute your own values
  before use. The private deployed configuration retains its actual paths.
- The generated FIM rules and agent XML are parsed and checked against every
  rewritten monitored path, including personal-profile secret and startup paths.

## Evidence And Limits

Offline regression tests cover synthetic addresses, identities, credentials,
paths, unknown fields, invalid structured values, catalog failures, rejected-file
preservation, and the export flow with a fake SQL connection. No live SOC
configuration, credentials, network policy, or firewall was changed for this work.

Playwright checks passed at 1440-pixel desktop and 390-pixel mobile widths for all
five console views, alert selection, search, hashed references, JavaScript errors,
and horizontal page bounds. The latest preview image is a genuine capture of the
corrected console, not an altered security screenshot.

The earlier [privacy audit](public-privacy-audit.md) remains a record of what was
public at that revision. Older commits retain their identifiers and screenshots;
no history rewrite was performed. The console's lack of a live connection does
not prove that the SOC has no exposure through other routes. External exposure,
account security, authenticated access, revocation, and backup tests remain open.

Allowlists supplement, not replace, secret scanning and manual review of public
documentation and images. Detection correctness and rule-level triage inheritance
need separate reliability work; this change does not validate every new alert.
