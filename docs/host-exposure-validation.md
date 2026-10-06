# Host Exposure And Firewall Visibility

Checked October 6, 2026. This batch hardened the existing loader SSH client and
independently reviewed Windows firewall visibility and listening services. It
did not change firewall rules, audit policy, Wazuh collection, guest SSH policy
or Tailscale permissions. Detailed host metadata and raw logs remain private.

## In Plain English

- The loader uses a private connection to fetch alerts. Its local entrance is
  now explicitly restricted to this PC, and SSH refuses an unknown or changed
  server identity instead of automatically trusting a new one.
- The firewall is writing blocked-packet records. Most of the reviewed sample
  looks like local device-discovery traffic, not evidence of thousands of attacks.
- Those packet records are not yet part of the SIEM pipeline. Saving a log and
  collecting it into Wazuh are different steps.
- Some Hyper-V management exceptions are broad. We need to establish whether
  remote management is used before restricting them without breaking the lab.

## Loader Connection: Applied And Verified

`loader/wazuh_to_sql.py` now explicitly binds its temporary local forward to
`127.0.0.1`, sets `GatewayPorts=no`, uses `IdentitiesOnly=yes` and requires
`StrictHostKeyChecking=yes`. Noninteractive authentication and failure-on-forward
setup are retained, and standard input is disconnected. The existing restricted
key, destination, read-only Indexer identity and verified TLS CA are unchanged.

The existing verified host-key entry worked in a separate-port preflight before
the change. A subsequent test of the actual loader function confirmed:

- Only the IPv4 loopback listener was present, not a wildcard/network listener.
- An authenticated read-only Indexer search succeeded with zero failed shards.
- The temporary listener was gone after the context closed.
- The next normal scheduled load after the edit succeeded: 66 alerts inserted
  in 2.646 seconds at 9:12 AM Eastern. No manual load was required.

Six new regression tests cover explicit/default loopback binding, required SSH
options, refusal and timeout cleanup, downstream failure cleanup and preservation
of the existing direct-mode behavior. These are client-side safeguards, not a
new audit of every SSH setting or proof of public-network isolation.

If the VM is legitimately rebuilt or its host key changes, verify its fingerprint
through the trusted Hyper-V console before updating the SSH known-host entry.
Do not resolve a trust failure by blindly accepting a key or disabling checking.
The [OpenSSH client reference](https://man.openbsd.org/ssh.1) and
[configuration reference](https://man.openbsd.org/ssh_config.5) describe binding
and host-identity checking.

## Actual Firewall Sample: Independently Reviewed

The read-only administrator audit parsed the last 2,000 packet records available
at the check: October 6, 6:59:19-9:07:46 AM Eastern, with the log header declaring
local time. All 2,000 were valid `DROP` records; none were discarded as malformed.

| Records | Packet metadata | Interpretation boundary |
|---|---|---|
| 1,978 | UDP destination port 5353, received multicast, private/link-local source classes | Consistent with local mDNS discovery; application and payload were not verified |
| 16 | Received ICMP to multicast, source class `internet_or_other` | That broad parser label does not establish an Internet origin |
| 6 | Sent UDP destination port 137, shared-address source/destination classes | Shared address space does not by itself prove a Tailscale peer identity |

Thus 98.9% of this bounded sample was UDP 5353 multicast traffic. The
[mDNS specification](https://www.rfc-editor.org/info/rfc6762/) supports the
discovery interpretation; metadata alone does not establish benign intent.
These are packet counts, not attacker, device or incident counts. The sample
does not include all allowed traffic or inventory every device on the network.
No ports were opened to reduce discovery-related logging noise.

`windows/Get-WatchtideExposureAudit.ps1` requires administrator read access and
a protected private evidence directory. It reads reviewed agent configuration,
packet-log schema/sample, effective inbound exceptions, TCP listeners, audit
policy and Defender status without modifying those settings. It refuses
unprotected/reparse-point paths and overwriting a successful audit. Structured
XML parsing prohibits DTDs and external resolution; public summaries contain
classifications, not raw addresses. Twenty-nine assertions pass under both
Windows PowerShell 5.1 and PowerShell 7.

Two initial elevated attempts stopped at an unsupported audit-policy query.
The corrected read-only category query succeeded; no policy permissions were
weakened and no settings were changed by any attempt.

## SIEM Collection Gap: Confirmed, Not Fixed

The actual local and shared Windows agent configurations have no `pfirewall`
file source. The Security-channel query explicitly excludes events 5152 and
5157. Windows Filtering Platform Packet Drop and Connection auditing are both
off. Independent bounded searches found zero matching firewall-file or
5152/5157 alert records in the Indexer and SQL for the preceding 24 hours.

Missing alert records alone would not prove that collection was absent. Here,
the operating-system policy and actual agent configurations independently explain
the gap. Ordinary Windows, Sysmon, Defender and PowerShell collection remains
established; this finding concerns the specific blocked-traffic sources.

A future bounded collection change needs a volume budget, a protected backup,
rollback, a harmless positive/negative control and an exact event trace through
Wazuh and reporting. Connection-level failure events may offer process attribution
without collecting every dropped packet; that design is not deployed by this
audit. See Microsoft's [firewall logging guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-logging),
[event 5157 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5157)
and Wazuh's [log-source configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html).

## Exposure And Health Boundaries

- All three effective firewall profiles are enabled, with default incoming block,
  outgoing allow and bounded blocked logging. Allowed exceptions still matter.
- Ten enabled inbound Hyper-V management rules apply to any profile and remote
  address. They include RPC/WMI, VM console and live-migration permissions.
  The owner's actual remote-management workflow remains unconfirmed; no rule
  was disabled or restricted. Other observed exceptions also remain unchanged.
- A listening socket is not proof of Internet reachability. Gateway/WAN IPv6,
  router forwards and authorized external reachability remain separate checks.
- SQL listeners observed during this audit were loopback-only; this is not a
  complete SQL account, protocol or firewall audit.
- Defender antivirus, real-time protection, behavior monitoring and tamper
  protection were enabled. Windows Sysmon, Wazuh and Tailscale services were
  running; the existing restricted maintenance status check reported five active
  guest services. No new shell permission was granted.
- Point observations showed about 5.6 GiB host free memory and 4.6 GiB guest
  available memory, with about 115 GB free on the guest root filesystem. These
  are capacity observations, not a sustained capture-load benchmark.
- A rolling eight-hour SQL read found 33 completed successful loads: median
  1.965 seconds, 95th percentile 8.293 seconds and maximum 26.622 seconds.
  The successful subset can include manual checks; it is not a count of 33
  automatic scheduled runs or an SLA. The prior 24-hour read found 98 runs,
  zero failures; reported seven-day success was 99.1% at that point.

No new Power BI refresh, public snapshot refresh, vulnerability-remediation
credit, CIS score, disk encryption, boot change, router change or Suricata live
capture is claimed. Six unrelated Python workloads remain running as requested;
Steam remains installed. Recovery stays deferred, not passed.

## Completion Checklist

- [x] Harden and independently verify the existing loader's local bind and host-key checking.
- [x] Confirm subsequent automatic ingestion without changing guest access.
- [x] Independently interpret a bounded firewall-log sample with privacy-safe aggregates.
- [x] Inspect actual audit/agent settings and document the blocked-traffic collection gap.
- [x] Review current effective listeners/exceptions privately without equating them with public exposure.
- [ ] Confirm remote Hyper-V usage, then test any separately scoped management restrictions.
- [ ] Deploy and end-to-end validate bounded blocked-connection telemetry.
- [ ] Complete account/MFA, external exposure, resource-budget and deferred recovery gates.

Regression result for this batch: 174 offline Python tests passed, with eleven
opt-in SQL tests skipped; 86 PowerShell assertions passed per runtime across the
five hardening suites. No test database was created for these checks.
