# Hardening Validation

Updated October 5, 2026. This closes the reviewed private-file permissions check,
not the entire hardening stage. Recovery work was deferred by the owner; no
database backup or restore drill was performed during this check.

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

## Firewall Logging: Prepared, Apply Pending

All three effective firewall profiles were enabled, with incoming connections
blocked by default and outgoing connections allowed. `ActiveStore` reported
blocked logging off and a 4 MB log limit. Earlier registry settings recorded
logging on and 16 MB, but effective policy did not match. The cause has not been
established; no new CIS score is inferred from either observation.

`windows/Set-WatchtideFirewallLogging.ps1` changes only local blocked-traffic
logging and its size limit. It keeps prior settings privately, verifies the
effective policy and attempts to restore prior logging values if verification
fails. It does not change connection rules, defaults, enabled state, allowed-
traffic logging, routing, VPN permissions or services.

- [x] Read-only effective-policy baseline captured.
- [x] Eight mocked assertions passed, including policy-override failure and restoration.
- [x] Non-elevated apply refused before changes.
- [ ] Administrator-run apply and independent effective-policy readback.
- [ ] Verify actual log output without opening ports or disrupting the SOC.

The helper also reads disk-encryption and Secure Boot status if available. It
does not enable encryption, print recovery keys or reboot Windows.

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

- [ ] Verify current vulnerability findings against the actual installed products
  and authoritative affected-version ranges before patching or suppressing them.
- [ ] Review account MFA, unused access and remaining host/guest exposure privately.
- [ ] Independently verify disk encryption, recovery-key custody and Secure Boot.
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
