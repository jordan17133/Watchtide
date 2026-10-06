# Hardening Validation

Updated October 5, 2026. This closes the reviewed private-file permissions and
firewall-logging configuration checks, not the entire hardening stage. Recovery
work was deferred by the owner; no database backup or restore drill was performed
during this check.

## What This Means

- Private credentials and evidence should not be readable by unrelated local accounts.
- The firewall was already blocking unsolicited incoming connections. Its effective
  blocked-traffic logging was off, so investigating denied connections had a visibility gap.
- Git exclusion, local file permissions, disk encryption and tested recovery protect
  against different risks. One does not replace the others.

## Read-Only Baseline

Microsoft Defender antivirus, real-time protection, behavior monitoring and
tamper protection were enabled. UAC used the secure desktop; Remote Desktop was
disabled; PowerShell script-block logging was enabled. Remote Registry, Print
Spooler and UPnP Device Host remained stopped and disabled. Sysmon, the Wazuh
agent and Tailscale were running. These are configuration observations, not a
proof of absence of compromise or complete benchmark compliance.

## Private-File Check: Verified

| Reviewed target | Before | Result |
|---|---|---|
| Private evidence directory | Extra local automation/sandbox read permission | Restricted to owner, SYSTEM and Administrators |
| Installer backup directory | Inherited extra local read permission | Restricted to owner, SYSTEM and Administrators |
| Loader environment file | Inherited extra local allow entries, including modify | Restricted to owner, SYSTEM and Administrators |
| Loader SSH private key | Already protected with the intended readers | Verified; left unchanged |

All four targets passed the post-change metadata audit: protected inheritance,
no unrelated allow entries, no deny entries and explicit owner read access.
The three changed targets preserve their owner. No credential contents were
read or changed, and no accounts, SSH configuration, services, firewall rules
or Tailscale permissions were modified. Extra permissions alone are not
evidence that someone used them or that the system was hacked.

Prior permission descriptors and verification results are retained in protected
private storage, not Git. The helper supports read-only `Audit`, bounded `Apply`
and guarded `Rollback`; rollback refuses to overwrite a later permission change.

An additional descendant-metadata review inspected 1,963 objects. Remaining
extra readers were confined to 1,189 test-library/tool objects and one public
SSH key, rather than private evidence or credentials. Those nonsecret scoped
exceptions were not blindly rewritten. Protected child ACLs can differ from a
parent, so this does not claim every descendant has identical permissions.

The next real scheduled loader run after the change succeeded: 102 alerts
inserted in 2.895 seconds. No manual ingestion was required. The existing
restricted maintenance connection still worked and independently reported
five active guest services. This closes the reviewed permissions and immediate
compatibility check, not sustained performance or future drift monitoring.

The helper has 13 passing assertions on real empty fixtures, including extra-reader
detection, owner preservation, idempotence, inheritance, refusal to remove an
existing deny rule and restoration after a forced post-write verification failure.
These tests do not change live credentials.

Local ACLs do not protect against malware running as the owner, an administrator
or physical access to an unencrypted drive. Future secret files need their own
permission checks.

## Firewall Logging Configuration: Verified

Before the change, all three effective firewall profiles were enabled, with
incoming connections blocked by default and outgoing connections allowed.
`ActiveStore` reported blocked logging off and a 4 MB log limit. Earlier registry
settings recorded logging on and 16 MB, but effective policy did not match. The cause has not been
established; no new CIS score is inferred from either observation.

`windows/Set-WatchtideFirewallLogging.ps1` changes only local blocked-traffic
logging and its size limit. It keeps prior settings privately, verifies the
effective policy and attempts to restore prior logging values if verification
fails. It does not change connection rules, defaults, enabled state, allowed-
traffic logging, routing, VPN permissions or services.

- [x] Read-only effective-policy baseline captured.
- [x] Eight mocked assertions passed, including policy-override failure and restoration.
- [x] Non-elevated apply refused before changes.
- [x] Administrator-run apply and independent effective-policy readback.
- [x] Record owner-performed administrator read of actual log output without
  opening ports or disrupting the SOC.
- [ ] Interpret selected packet records and verify firewall-log collection into
  Wazuh separately before claiming end-to-end firewall telemetry.

The owner's administrator-run helper reported `FIREWALL_BLOCKED_LOGGING_VERIFIED`.
Independent effective-policy readback confirmed all three profiles still enabled,
blocked logging on and a 16 MB limit, with incoming/outgoing defaults and allowed-
traffic logging unchanged. The saved before/after metadata matched that result;
its private evidence directory passed the restricted-permissions audit. Sysmon,
the Wazuh agent and Tailscale remained running. The script does not modify rules
or restart services; this is not a full before/after audit of every firewall rule.

The first scheduled loader run after the logging change succeeded: 144 alerts
inserted in 2.788 seconds. This independently checks immediate ingestion
continuity, not sustained performance or a new Power BI refresh.

Reading the actual firewall log was denied to the normal automation account.
Its permissions were not weakened to bypass that restriction. The owner then
performed the read-only check from the administrator window. Reported evidence:
a 16,412-byte log, last written October 5 at 9:42:17 PM Eastern (after the apply),
and 163 `DROP` lines in the last 200 lines sampled. This closes the basic local
log-output check based on owner-supplied output, not independent inspection of
the raw records. It does not mean 163 attackers or confirmed attacks, identify
each packet's origin, or prove collection in Wazuh. Counts are from a bounded
sample, not an incident metric or a complete network-traffic inventory.

## Disk And Boot Findings: Open

The owner's administrator output reported the Windows system drive fully
decrypted with BitLocker protection off, and Secure Boot disabled. Independent
Windows registry readback also showed Secure Boot off; firmware inventory
reported UEFI and the installed Windows edition supports BitLocker. Disk state
is based on the owner's elevated output, not an independent encryption scan.

The owner's subsequent read-only `Get-Tpm` output reported `TpmPresent`,
`TpmReady`, `TpmEnabled` and `TpmActivated` all true. This passes basic TPM
readiness; it does not verify TPM version, attestation, encryption protectors
or complete firmware compatibility. These findings concern the Windows host,
not the Ubuntu VM's separate Hyper-V Secure Boot setting.

In simple terms, drive encryption protects stored files if the computer or drive
is accessed offline; Secure Boot checks trusted software during startup. Neither
finding establishes compromise. These protections do not replace monitoring,
patching, account security or backups.

Recovery-key custody, remaining firmware compatibility/current boot
certificates and a planned restart still need review. Do not enable encryption,
clear the TPM, reset boot keys or change firmware settings as an automatic next
step. On eligible systems, enabling Secure Boot may also make automatic device
encryption eligible; recovery arrangements should precede that change. No
encryption/boot change or restart was performed in this follow-up.

## Publication Safeguard

Database backups/files, private-key containers and packet captures are ignored
by Git. The private publisher also rejects tracked files with the reviewed
backup/database/key-container/capture extensions before replacing public files.
Public CA certificates and code remain publishable. Three regression tests
cover rejection, allowed source files and preservation of the prior public copy
after a rejected artifact. These guards do not detect every possible secret
format; sanitized text and snapshot checks remain necessary.

Final regression checks passed: 168 offline Python tests and 21 PowerShell
assertions. Both hardening assertion suites also passed under Windows PowerShell
5.1, the runtime used by the owner-facing command. Eleven opt-in live SQL tests
were skipped; no new database was created or altered for this pass. The broader
tests used the existing isolated test dependencies, not changes to the loader's
runtime environment.

## Remaining Hardening Gates

- [x] Complete a read-only assessment of all ten current vulnerability findings,
  with installed-product evidence, primary advisories and bounded dispositions
  ([review](vulnerability-applicability-review.md)). The verified Python interpreter
  is outside its flagged CVE's affected range; Steam permission concerns and
  uncertain mappings remain open. Detector findings were not suppressed.
- [ ] Apply compatible Python security updates in a controlled maintenance window;
  separately review active environment dependencies, Steam permissions/retention
  and uncertain product mappings. Verify health and fresh inventory afterward.
- [ ] Review account MFA, unused access and remaining host/guest exposure privately.
- [x] Record owner-reported unencrypted system drive and disabled Secure Boot;
  independently verify Secure Boot's Windows state and UEFI firmware mode.
- [x] Record owner-performed basic TPM readiness: present, ready, enabled and activated.
- [ ] Review remaining firmware/TPM details, establish independent recovery-key
  custody and schedule any separately approved disk-encryption/boot changes;
  verify their result afterward.
- [ ] Validate additional compatible controls in small batches, with analyst
  visibility and rollback. Use audit before blocking for new ASR restrictions.
- [ ] Refresh Wazuh posture evidence and document accepted exceptions.
- [ ] Retest the loader, dashboard and reporting after each meaningful change.

Recovery remains deferred, not passed. Live Suricata capture and wider network
coverage remain separate work; the existing service stays masked.

## References

- [Microsoft firewall profile configuration](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile)
- [Microsoft access-control overview](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/access-control)
- [Microsoft inherited-permissions caveat](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/inherited-permissions-not-automatically-update)
- [Microsoft .NET file-permission API](https://learn.microsoft.com/en-us/dotnet/api/system.io.filesystemaclextensions.setaccesscontrol)
- [Microsoft ASR deployment FAQ](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-faq)
- [Microsoft BitLocker overview and automatic-encryption behavior](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/)
- [Microsoft Secure Boot explanation and firmware guidance](https://support.microsoft.com/en-gb/windows/security/devicesecurity/windows-11-and-secure-boot)
- [Microsoft read-only TPM status command](https://learn.microsoft.com/en-us/powershell/module/trustedplatformmodule/get-tpm)
- [Microsoft recovery-key storage guidance](https://support.microsoft.com/en-us/windows/security/encryption/back-up-your-bitlocker-recovery-key)
