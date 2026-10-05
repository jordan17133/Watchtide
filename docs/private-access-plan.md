# Private Remote Access: Tailscale Plan

**Owner:** Jordan Carven-Bellace

**Updated:** October 5, 2026

**Status:** Windows admin host, Ubuntu VM and test phone enrolled. The reviewed policy still permits only Windows-to-VM TCP 22/443, with four accepted policy tests. Local management/data-port checks and post-policy SQL ingestion passed. Trusted Windows IPv4 HTTPS and an authenticated dashboard overview are verified; the overview showed one Active agent and zero Disconnected agents. The user reported successful renewal setup, an initial service run and an enabled daily timer. Its first automatic trigger and actual replacement remain unverified. The owner declined temporary phone access; the phone stays denied and approved off-LAN administration is deferred/unverified. The current priority is the bounded [Suricata pilot](suricata-pilot.md); extra VPN/router work is deferred. Reported VM-local configuration-backup checks and checkpoint creation do not prove full recovery. Checkpoint metadata, backup-reader/storage review, remaining exposure/revocation and controlled SQL/Power BI checks stay open. IPv6 dashboard support is absent and local enrollment TCP 1515 needs diagnosis before new enrollment. See [private-access-validation.md](private-access-validation.md).

## Decision and purpose

Add Tailscale to the trusted admin device and the Ubuntu Wazuh VM so the lab can be administered from another network without forwarding management ports through the home router. This is the next security engineering exercise for Watchtide: define who needs access, restrict that access, prove both successful and blocked connections, and document the effect on the monitoring pipeline.

The existing documented baseline is a Hyper-V NAT lab, an indexer bound to loopback, a restricted SSH tunnel for the loader, and local SQL/Power BI reporting. The VPN adds a private route; it does not establish that every service is correctly restricted. Tailscale encrypts device traffic with [WireGuard](https://tailscale.com/docs/concepts/tailscale-encryption).

## Public portfolio and private lab

```text
Employers -> GitHub README, runbook, cases and roadmap
          -> GitHub Pages console -> sanitized snapshot only

Approved admin device -> Tailscale -> Ubuntu VM: SSH / Wazuh dashboard
Remote test endpoint  -> Tailscale -> Wazuh manager: event ingestion (later)

Existing local path:
Windows + Sysmon -> Wazuh agent -> manager -> indexer
Windows loader   -> restricted SSH tunnel -> loopback indexer -> SQL -> Power BI
```

Employers can review the public artifacts without lab credentials or a tailnet invitation. Any later live analyst console/API stays private. No Tailscale Funnel is planned for SOC services: [Funnel publishes a selected service to the internet](https://tailscale.com/docs/features/tailscale-funnel).

An exit node and subnet router are deferred. The first exercise only needs device-to-device access; [exit nodes](https://tailscale.com/docs/features/exit-nodes) route general internet traffic and are a separate decision.

## Intended access matrix

This is the target access matrix. Device-scoped administration on TCP 22/443 was deployed on October 3, 2026; remote endpoint ingestion/enrollment remains planned, not permitted by the current tailnet grant. Other rows describe existing local paths and remaining validation requirements. Verify configured service ports before changes; Wazuh defaults are listed in its [architecture documentation](https://documentation.wazuh.com/current/getting-started/architecture.html).

| Source | Destination | Intended access | Restriction |
|---|---|---|---|
| Approved admin devices | Ubuntu SOC VM | TCP 22 (OpenSSH), TCP 443 (dashboard) | Explicit device selection; retain application login and TLS verification |
| Remote monitored endpoint | Wazuh manager | TCP 1514 (events) | Ingestion only; no SSH, dashboard, SQL, indexer or API privileges |
| Approved enrolling endpoint | Wazuh manager | TCP 1515 (enrollment) | Temporary enrollment window; remove permission and test after registration |
| Existing local loader | Ubuntu SOC VM | Current restricted SSH tunnel | Preserve its no-shell key and loopback-only port forward; verify each scheduled load |
| Wazuh dashboard / local collector | Indexer and Wazuh API | Existing internal access | TCP 9200 remains on loopback; TCP 55000 is not exposed to remote endpoints |
| Power BI Desktop on Windows | Local SQL warehouse | Existing authenticated reporting path | No new remote SQL listener or inbound port rule needed for this milestone |
| Other tailnet devices / public internet | SOC management and data services | Denied | Test denied access independently of successful admin access |

Use [Tailscale grants](https://tailscale.com/docs/features/access-control/grants) for a new policy. Inspect the current policy for broad permissions before narrowing it. A user-group rule can authorize several devices owned by that user; choose selectors that actually enforce the intended device restriction. Limit who can assign privileged device tags, and include policy tests for approved and unprivileged sources.

Tailscale policy and the operating-system firewall control different paths. Review their effective behavior together; do not infer tailnet restrictions solely from `ufw status`. Preserve only the local agent/loader exceptions the lab needs. The [Ubuntu firewall guide](https://tailscale.com/docs/how-to/secure-ubuntu-server-with-ufw) describes restricting non-Tailscale access and testing from outside the private network.

## Policy review and next action

The actual Access controls policy was reviewed on October 3, 2026 before an approved replacement was saved. The original policy contained one allow-all grant and the default self-device Tailscale SSH rule, with no active legacy ACLs, groups, tag owners, posture conditions or policy tests. Only the Windows admin host and Ubuntu VM were enrolled. The exact original policy and replacement are stored outside Git; public documentation contains only sanitized roles and results.

The deployed replacement uses explicit host aliases for both devices' tailnet IPv4 and IPv6 addresses. One grant permits the selected Windows device to reach the VM on `tcp:22` and `tcp:443`; no user-wide, wildcard, ingestion/enrollment, indexer or API grant was added. The `ssh` section is empty, removing the default Tailscale SSH authorization rule without enabling or changing ordinary OpenSSH. An OpenSSH banner was observed before the change; authenticated shell access remains untested.

Four saved policy tests assert four allowed and sixteen denied same-address-family TCP connections: approved administration, blocked direct ingestion/enrollment/indexer/API access, and blocked new VM-to-Windows SSH/HTTPS/SQL/RDP connections. The first save was rejected because its tests paired IPv4 sources with IPv6 destinations; correcting the tests left the approved grant unchanged. Tailscale accepted the corrected policy and the persisted Tests page lists all four cases. Policy tests are not substitutes for actual connection, authentication or off-LAN tests.

The local loader still targets the Hyper-V private-network hostname, not a tailnet address. Its no-shell, loopback-only forwarding configuration was not edited. No operating-system firewall, service listener, subnet route, exit node, device tag or Wazuh configuration was changed. The post-change scheduled load succeeded and inserted 49 alerts, including 42 Sysmon alerts.

The supplied IPv4/IPv6 filter-table configuration review is complete: exports identify the nf_tables backend, Tailscale chains precede UFW, existing broad private IPv4 service allowances remain, and no new non-Tailscale TCP API/indexer allowance was found. This is not a complete exposure or recovery audit. Tailscale forwarding exceptions also mean the default FORWARD policy alone does not establish that routing is disabled. See the [full filter-table follow-up](private-access-validation.md#full-filter-table-follow-up).

The user's screenshot demonstrates an authenticated Ubuntu console through Hyper-V. Subsequent user-performed integration-tool installation and targeted backup-device registration repaired the VSS helper startup issue. The user reported new checkpoint creation after a screenshot confirmed Production-Only settings with standard fallback disabled, then reported five active guest services. New checkpoint metadata, exact current backups and restore capability remain unverified. The existing installer archive was found outside Git, but its inherited local-group read access needs review before fresh sensitive copies; no contents were read or permissions changed. See the [checkpoint recovery follow-up](private-access-validation.md#production-checkpoint-recovery-follow-up) and [backup inventory review](private-access-validation.md#private-backup-inventory-and-local-permissions). Fresh local Hyper-V probes reach TCP 22/443/1514 but not 1515/9200/55000; tailnet IPv4/IPv6 results reproduce the earlier table. The local enrollment-port gap needs diagnosis, not an automatic service or firewall change.

The user subsequently reported successful current dashboard/UFW backup checks. The copy remains inside the VM and does not cover alert databases, Windows SQL or the cloud tailnet policy; checkpoint metadata and separate backup/restore validation remain open. The original loopback-only certificate identity and incomplete Windows trust chain were addressed through the selected Tailscale-issued HTTPS route. On October 5 the user reported dashboard installation with five active services. Independent Windows IPv4 HTTPS checks pass default trust validation; the certificate expires January 3, 2027. An authenticated dashboard overview was then observed and renewal setup was reported successful, including the initial service run and enabled daily timer. Its first automatic trigger and future actual certificate replacement are not yet proven. See [login and renewal evidence](private-access-validation.md#authenticated-dashboard-and-renewal-timer).

The owner subsequently declined temporary phone dashboard access, then deferred extra VPN/router work and moved on to the [Suricata traffic/rules/reporting pilot](suricata-pilot.md). Leave the phone denied and defer approved off-LAN administration; it remains unverified, not complete. The [network plan](network-coverage-plan.md) records capture limits and separate deferred privacy work. Remaining exposure/revocation, backup recovery and controlled SQL/Power BI checks stay open. Observe the timer's automatic execution as upkeep; do not repeat certificate installation. Existing authenticated local SSH is not proof of off-LAN tailnet SSH, and the dashboard still supports IPv4 only. Keep Windows administration, the restricted loader and current network policy unchanged; do not enable Funnel or add a phone grant. A future remote-access exercise would require fresh review and approval.

For future changes, review existing `grants` and legacy `acls`, including broad permissions that reach the SOC VM. Check the source and destination selectors, groups, `tagOwners`, any Tailscale SSH rules, and other tailnet access that must be preserved. [Grants are additive](https://tailscale.com/docs/reference/syntax/grants): a narrow grant does not override a broader permission, and grants can coexist with legacy ACLs. Restricting direct TCP 55000 access requires reviewing every rule that could still allow that connection.

Prepare the reviewed change around the access matrix above: approved administration on TCP 22/443, the existing restricted loader tunnel, and the existing local agent connection. Keep dashboard-to-API and dashboard-to-indexer access working inside the VM. Remote ingestion and temporary enrollment permissions belong to the later endpoint exercise. Record proposed permissions separately from deployed permissions, and apply them only after the current policy and recovery path have been reviewed.

Use a separate approved client on another network for the off-LAN test while the Hyper-V host and Ubuntu VM remain running. An approved iPhone on cellular can test dashboard access, but that test does not also prove SSH login or denial of an unprivileged device.

## Implementation sequence

1. Record current agent status, a successful scheduled load and reporting freshness. Save firewall rules, service listeners and the existing tailnet policy outside Git. Take a Hyper-V checkpoint and verify VM-console access for recovery.
2. Install/enroll Tailscale on the trusted admin device and inside Ubuntu. Enrolling the Windows Hyper-V host alone does not enroll its guest. Verify both device identities privately; enable MFA at the sign-in provider and review device/key-expiry settings.
3. Confirm routing and the intended SSH/dashboard ports. Keep ordinary OpenSSH and the existing restricted loader key for this milestone; adopting Tailscale SSH would require a separate review of that tunnel restriction. Resolve dashboard hostname/certificate trust before using its tailnet address; do not disable certificate checking to make the test pass.
4. Review the saved current Access controls policy, then define the narrow grants in the matrix and test them. Account for existing broad grants and legacy ACLs; adding a narrower rule alone does not restrict a broader one. Keep a working VM-console session while changing access. Remove broad management exceptions only after the private route and necessary local loader access both work.
5. From another network, test successful admin access and failed access from an unprivileged tailnet test device. Also test direct public access with Tailscale off, review router forwarding and any public publishing settings, and record any limits of the external test, including unavailable IPv6.
6. Wait for the next scheduled load and verify the local agent remains Active, new alerts reach SQL, and Power BI can refresh. A working dashboard alone does not prove the pipeline survived the change.
7. Publish redacted results, update the build log, and only then mark the private-access milestone complete. Add a remote monitored endpoint as a separate exercise after the policy is validated.

## Completion and evidence

For every test, record the date, source role, destination/service, expected result, actual result and a sanitized screenshot or log excerpt. Keep real addresses, device identities and raw output in private notes. A failed prerequisite leaves its dependent gate open.

| Gate | Required evidence | Status |
|---|---|---|
| Admin device and Ubuntu VM enrolled | Ubuntu status output and Windows client status confirm both devices; private inventory reviewed | Verified 2026-10-03 |
| Current Access controls policy reviewed | Existing permissions and required access reviewed; exact original saved privately before an approved change | Verified 2026-10-03; narrow replacement saved with four policy tests; new checkpoint creation reported October 4; current backup/restore and live exposure verification remain open |
| Supplied VM filter-table configuration reviewed | Complete IPv4/IPv6 filter exports reviewed with rule precedence and exceptions recorded | Reviewed 2026-10-04 from user-provided output; live exposure, exact private backups and recovery validation remain pending |
| VM-console recovery route available | Authenticated Ubuntu console through Hyper-V VMConnect | Demonstrated in user-provided screenshot on October 4; separate backup/restore test still pending |
| Current production checkpoint | Production-Only settings and successful creation, checkpoint metadata and post-creation health recorded | Settings screenshot, user-reported creation and five active guest services afterward on October 4; name/timestamp/type pending |
| Current private configuration backups | Exact current copies with intended readers/storage protection reviewed and recovery tested | Current VM-local dashboard/UFW checks passed according to the user; original installer archive has extra local-group read access requiring review; protected off-VM copies and restore validation pending |
| Local trusted dashboard access and renewal setup | Normal HTTPS trust, authenticated overview, successful initial renewal-service run and enabled daily timer | Windows HTTPS and authenticated overview verified October 5; renewal setup reported successful; automatic trigger, actual rotation and live failure recovery unproven |
| Approved admin access off-LAN | Successful SSH login and dashboard login with verified HTTPS identity | Deferred/unverified: owner declined temporary phone access and moved on to the Suricata pilot |
| Unprivileged tailnet device denied | TCP 22/443 connection attempts fail from a device without admin permission | Partial: user-confirmed phone IPv4 HTTPS timeout over cellular with public-web control on October 4; other denied paths/address families pending |
| No direct public service access | External checks for TCP 22/443/1514/1515/9200/55000 fail; forwarding/publishing reviewed; IPv4/IPv6 scope recorded | Pending |
| Internal data services remain restricted | Direct TCP 9200/55000 access fails from remote test devices; loader tunnel still works | Local IPv4/IPv6 probes fail and post-change loader succeeds; separate remote/unprivileged-source proof pending |
| Existing collection/reporting stays healthy | Local agent Active, successful scheduled load, new event in SQL, Power BI refresh | Partial: authenticated overview showed one Active and zero Disconnected agents; post-policy ingestion and first reconciliation succeeded; individual agent identity, SQL timeout/paging follow-up, controlled event trace and Power BI refresh remain open |
| Device revocation works | Remove a disposable test device and confirm it loses private service access | Pending |
| Public documentation is sanitized | Access matrix and test outcomes published without credentials or private inventory | Sanitized enrollment/policy/local-test report maintained; remaining validation evidence not yet collected |

Keep this status honest: installing a client is a setup step; passing these tests is the evidence for the control.

## Later exercise: remote collection

This remains a portfolio exercise, not a prerequisite for the [next Suricata
pilot and whole-network coverage work](network-coverage-plan.md).

- [ ] Enroll one authorized test endpoint on a separate network with TCP 1515 allowed only for enrollment.
- [ ] Remove its enrollment permission, retain TCP 1514, and confirm ingestion continues.
- [ ] Generate one harmless event covered by the endpoint's logging and Wazuh rules.
- [ ] Trace its timestamp, rule and document identifier through Wazuh, SQL and Power BI; record reporting latency.
- [ ] Verify that endpoint cannot reach management/data services, and that a repeated enrollment connection is denied.
- [ ] Publish a sanitized event trace with any observed gap or unexpected result.

## Monitoring and reporting implications

Endpoint logging remains essential: encrypted VPN packets do not provide a LAN sensor with their inner contents. The Suricata chapter must identify its capture point and test what it can actually observe. Review available sign-in, device and policy-change records; confirm Tailscale plan availability before promising audit-log export or SIEM ingestion.

Power BI Desktop still uses the existing local SQL connection. If cloud refresh is added later, the Power BI service needs a supported route to private SQL, usually an [on-premises data gateway](https://learn.microsoft.com/en-us/power-bi/connect-data/service-gateway-onprem); installing Tailscale on a laptop does not give Microsoft's service a tailnet identity.

## Recovery and publication

If access fails, use the Tailscale admin console to recover the tailnet policy and the Hyper-V console to recover Ubuntu listener/firewall settings. The admin console is reached independently of the device-to-device grant. The original tailnet policy is stored privately; restoring its broad permissions is a temporary recovery decision, not the desired final state. Recheck the local agent and loader before retrying. No new firewall backup or checkpoint was created during the earlier policy-only change. A new checkpoint and five active guest services afterward were subsequently reported after the backup-helper repair; confirm checkpoint metadata and retain exact current configuration backups with reviewed local permissions before further VM/firewall work. Do not apply an older checkpoint merely to test availability. A checkpoint does not restore tailnet policy or Windows/SQL state, and separate backup/restore validation remains required. Revoke a lost or disposable device promptly.

Publish the design, test outcomes, sanitized policy examples and reporting screenshots. Keep credentials, auth keys, private keys, real device inventory, raw logs and private backups outside the public repo. If a published credential is discovered, revoke or rotate it; deleting the current file alone does not remove Git history. Use Watchtide's existing sanitized publishing process and review screenshots separately.

Until the gates pass, portfolio wording is: "The Windows admin host and Ubuntu SOC VM are enrolled in Tailscale. Device-scoped permissions, local trusted dashboard login and post-policy SQL ingestion are verified; renewal setup was reported successful. Approved off-LAN administration is deferred/unverified. A controlled offline Suricata event has been verified in the Wazuh Indexer and SQL; live capture and remaining reporting/security validation stay open." The [handoff report](suricata-wazuh-handoff.md) records that separate detection milestone. After further validation, replace open claims with measured results and link the relevant test report.
