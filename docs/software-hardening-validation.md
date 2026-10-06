# Software Hardening Validation

Updated October 6, 2026. This records the applied October 5-6 software batch,
not completion of the entire hardening stage or proof of absence of compromise.
Private rollback metadata, installer logs and account identifiers stay outside Git.

## In Plain Terms

- The SOC's Python engine received a security update without replacing its
  environment or interrupting unrelated background work.
- Steam stays installed. Unrelated ordinary local accounts can read/run its
  reviewed installation files but no longer have the broad Users write grant.
  The owner keeps the access needed for normal use and updates.
- Tests and fresh ingestion check that the SOC still works after those changes.
  They do not guarantee future uptime or close every scanner finding.

## Applied And Verified

| Check | Evidence | Boundary |
|---|---|---|
| SOC runtime | Python 3.14.7 upgraded to 3.14.8; both base interpreter and existing project environment verified; OpenSSL reports 3.5.9 | A runtime patch is not a complete dependency or application audit |
| Official artifacts | New and prior installers matched reviewed PSF SHA-256 hashes and valid PSF publisher signatures; isolated candidate runtime checked before installation | Signatures establish provenance, not application compatibility by themselves |
| Quiet installation | Loader was Ready, its exact action verified, schedule temporarily disabled and restored; no affected process terminated, PATH preserved, installer exited zero, no reboot | Runtime file copy and previous installer retained privately; downgrade/restore was not exercised |
| Steam folder and registry | Broad explicit Users FullControl replaced on two reviewed roots; Users retain read/execute or read-key access; current account retains FullControl | Only the reviewed grants are changed; inherited/other broad writes and deny entries cause refusal rather than a blanket rewrite |
| Steam components | Five critical client/service-source files retain identical SHA-256 hashes; their broad-write checks pass; owners preserved | Installed Common Files service was not modified; this is not a complete audit of every game or descendant |
| Normal-account access | Unelevated account created/read/deleted isolated file and registry probes successfully; no existing Steam data changed | Actual Steam login, game launch and future updater behavior were not tested |
| Pipeline after change | Post-runtime automatic load inserted 66 alerts in 2.633 seconds; additional loader check inserted 187 in 3.748 seconds | Immediate continuity, not a sustained performance benchmark |
| Post-Steam continuity | October 6, 1:18 AM Eastern loader check inserted 102 alerts in 26.622 seconds; two preceding automatic runs succeeded in 1.791 and 1.920 seconds | Timing varies; the slower check does not establish its cause or close resource/performance follow-up |
| Trusted dashboard | Fresh HTTPS request returned HTTP 200 without TLS bypass; Sysmon, Wazuh agent and Tailscale remained running | No new authenticated session or Power BI refresh is claimed for this batch |
| SOC package advisories | Release-specific PyPI JSON queries succeeded for all twelve installed distributions; each returned an empty vulnerabilities list on October 6 | One advisory source and metadata versions, not artifact-provenance verification, native-library analysis or proof of absence of flaws |

The Steam service remains stopped with Manual startup. The six unrelated Python
processes remained running, as the owner requested. No firewall/routing/SSH/
Tailscale policy, credential, boot or encryption setting was changed in this batch.
Suricata live capture was not enabled.

## Safety And Regression Checks

`windows/Update-WatchtidePython.ps1` defaults to read-only Audit. Apply is pinned
to the reviewed per-user 3.14.7 baseline and official 3.14.8 installer. It requires
protected private staging, verifies the loader identity, rejects active or
unidentifiable Python processes, and restores the schedule in `finally` even
when installation fails. It does not automatically roll back the installer.

`windows/Protect-WatchtideSteam.ps1` also defaults to Audit. Apply requires
administrator approval, protected evidence, a stopped Steam client, no reviewed
path reparse points and valid Valve signatures on critical binaries. It saves
permission descriptors before changing access. Failure recovery restores only
the job's own expected policy, verifies the readback/owner, and refuses to
overwrite a concurrent edit. The registry API explicitly selects the 64-bit
view, independent of the caller's process architecture.

The initial elevated attempt stopped at a registry lookup before any policy
write. Explicit registry-view access corrected that lookup; the reviewed retry
succeeded and independent PowerShell-provider readback passed. No failed
attempt was bypassed by disabling its guards.

- 168 Python regression tests passed under the installed 3.14.8 environment;
  eleven opt-in SQL tests were skipped (179 tests considered).
- 14 Python-maintenance assertions passed, including active-runtime refusal,
  official-artifact checks and schedule restoration on failure.
- 22 Steam assertions passed, including policy transformation, owner preservation
  on an empty real fixture, original-policy restoration, ineffective-rollback
  detection and refusal to overwrite a concurrent change.
- The existing 13 private-permission and eight firewall assertions also passed.
  All four suites passed in Windows PowerShell 5.1 and PowerShell 7: 57 assertions
  per runtime. Fixture/mocked checks are not live exploit tests.
- A separate production SQL read confirmed successful ingestion. No disposable
  test database was created and no SQL schema/isolation setting changed here.

## Deferred And Unresolved

The official Python 3.13.16 Windows installer is downloaded into protected
private storage, with its release-page SHA-256 and PSF signature verified. It
was **not executed**: six running processes belong to other private workloads,
and the owner asked to leave them running. Their 3.13 runtime update requires
a separately agreed quiet window and workload-specific compatibility checks.

All twelve installed SOC distributions were inventoried and checked against
release-specific PyPI advisory records without changing dependencies. This
includes the loader's certifi 2026.7.22, charset-normalizer 3.5.2, idna 3.20,
pyodbc 5.3.0, requests 2.34.2 and urllib3 2.8.0. Each queried release returned
zero listed advisories; that result does not certify package contents or every
bundled/native library, and is not a guarantee against unknown vulnerabilities.
The [API's known-vulnerability field](https://docs.pypi.org/api/json/#known-vulnerabilities)
defines the source boundary. Saved responses/metadata remain private.

Selected security-library versions in two other environments were inventoried
read-only, without importing those applications or changing dependencies.
Their advisory/compatibility review remains open; an inventory alone is not a
clean bill of health.

The original [ten-finding assessment](vulnerability-applicability-review.md)
remains a dated baseline. This batch addresses verified broad Users permission
conditions, not proof that every older Steam CVE is fixed. Owner/admin malware,
service anti-downgrade behavior, installation races and game prerequisites have
separate limits. Recheck grants after future client maintenance.

No fresh post-batch vulnerability scan was verified. Do not change the historical
437-of-447 remediation metric, claim new resolved findings, suppress mappings or
infer a new CIS score from these changes.

## Completion Checklist

- [x] Verify/test the official SOC runtime patch, apply quietly and restore scheduling.
- [x] Verify actual patched runtime, tests, successful ingestion and trusted HTTPS.
- [x] Preserve Steam; fix the reviewed broad Users folder/registry write grants.
- [x] Independently check owners, selected binary hashes/access and normal-account writes.
- [x] Stage and authenticate the other Python installer without interrupting its workloads.
- [x] Query release-specific PyPI advisories for all twelve installed SOC distributions.
- [ ] Test Steam's actual login, game use and subsequent updater behavior.
- [ ] Agree a quiet window and validate the remaining 3.13 workload update.
- [ ] Complete other environments' dependency checks, native-component/provenance
  review and remaining CVE mappings; recheck advisories as part of upkeep.
- [ ] Verify refreshed Wazuh inventory and recheck permission drift after client updates.
- [ ] Close separate MFA/exposure, disk/boot, recovery and sustained-performance gates.

These applied checks can be closed as a tested baseline. Patching, drift checks
and monitoring health remain ongoing responsibilities, not defects that one
installation can eliminate. The [numbered stages](soc-network-maturity-plan.md)
retain live-capture and whole-home coverage as separate, unfinished milestones.

## Primary References

- [PSF Python 3.14.8 security release and artifact hashes](https://www.python.org/downloads/release/python-3148/)
- [PSF Python 3.13.16 release and artifact hashes](https://www.python.org/downloads/release/python-31316/)
- [Python unattended Windows installation options](https://docs.python.org/3.14/using/windows.html#installing-without-ui)
- [Microsoft Windows access-control model](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/access-control)
- [Microsoft explicit registry-view API](https://learn.microsoft.com/en-us/dotnet/api/microsoft.win32.registrykey.openbasekey)
