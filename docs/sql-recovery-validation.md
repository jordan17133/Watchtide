# Local SQL Recovery Validation

October 7, 2026. Claude's completed drill was reconciled from protected local
evidence, not rerun during the handoff. This is same-PC, same-instance SQL
recovery proof, not a complete disaster-recovery claim.

## Recorded Drill

| Check | Recorded result |
|---|---|
| Copy-only backup with checksums | Passed; retained file is 54,575,104 bytes |
| Separate disposable restoration | 37,605 alert rows restored |
| Database integrity | CHECKDB passed on the disposable copy |
| Reporting | 20 reporting views readable, including two network-validation records |
| Schema and report-role grants | Match the source baseline |
| Known controlled-event payload | Matches the source hash |
| Cleanup | Disposable database removed; live database identity/settings unchanged |
| Storage scope | Protected private folder on the same PC; encryption not verified |

The drill completed at 17:19:42 UTC. Twenty SQL views are not twenty Power BI
pages: the existing report has six pages and eighteen imported report sources.

## Independent Handoff Checks

- Recomputed the retained backup's SHA-256 and matched both private evidence files.
- Matched its recorded GUID to a SQL backup-history entry with copy-only and
  checksum flags, and found the corresponding disposable restore-history entry.
- Confirmed the disposable database is absent and the live warehouse remains
  online, multi-user and using committed-snapshot reads.
- Checked the folder has inheritance disabled and only the owner, SYSTEM,
  Administrators and the SQL service in its access list.

These corroborate the completed drill. The handoff did not restore the database
again, repeat CHECKDB or prove that the backup can be recovered on another PC.
Raw backup contents, private paths, hashes and instance metadata remain private.

## Still Open

- [ ] Protected off-machine copy and documented recovery-key custody.
- [ ] Backup encryption and recovery on another SQL instance, including identities.
- [ ] Wazuh manager/indexer/dashboard restoration and certificate/config recovery.
- [ ] Whole-PC or disk-failure recovery and measured recovery objectives.
- [ ] Recurring backup execution, retention and failure notification.

A copy on C: can survive damage to a database, but not the loss of that same
disk or PC. Do not remove the independent-recovery gate from the maturity plan.
