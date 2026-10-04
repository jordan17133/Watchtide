# Tailscale Enrollment and Initial Connectivity Checks

**Date:** October 3, 2026

**Status:** partial validation; private-access milestone remains open.

## Scope and method

The Ubuntu client's status output listed both the Linux SOC VM and Windows admin host in the tailnet. A separate check with the Windows client's `status --json` confirmed the client is Running, the Windows device is online, and the SOC peer is online.

From the Windows admin host, TCP connection probes targeted the VM's Tailscale address using PowerShell `Test-NetConnection`. The detailed follow-up on TCP 55000 confirmed the connection used the Tailscale interface. Both machines were on the home network; this was not an off-LAN test. Actual addresses, account names and device inventory are omitted from this public report.

## Observed results

| Check | Expected for this milestone | Observed | Interpretation |
|---|---|---|---|
| Device enrollment | Admin host and SOC VM enrolled and online | Confirmed from both clients | Enrollment gate passed |
| SSH, TCP 22 | Admin host can connect | TCP connection succeeded | Port reachability confirmed; authenticated SSH login still pending |
| Dashboard, TCP 443 | Admin host can connect | TCP connection succeeded | Port reachability confirmed; HTTPS certificate and dashboard login still pending |
| Indexer, TCP 9200 | No direct tailnet connection | TCP connection failed | Consistent with the loopback-only design; remote and unprivileged tests still pending |
| Wazuh API, TCP 55000 | No direct tailnet connection needed by this admin path | TCP connection succeeded, repeated with interface details | Open restriction issue; narrow the policy and retest |
| Scheduled SQL loader | Scheduled task continues to run | Latest Task Scheduler result was 0 (success) | Useful continuity evidence; new-event flow and Power BI refresh still pending |

These probes do not establish authenticated application access or prove that all other sources are denied. The unsuccessful indexer probe establishes unreachability from this source at this time, not the exact listener or firewall configuration.

## Finding and next action

Adding the VPN created a path on which TCP 55000 is reachable from the Windows admin host. This is an authenticated private-network observation, not evidence of public-internet exposure or unauthorized API use. API authentication was not tested.

Review the existing tailnet policy before changing it. Apply narrowly selected SSH/dashboard permissions, preserve the restricted loader path, and exclude direct API/indexer access from devices that do not need it. Verify the operating-system firewall and service listeners where required, then repeat the port tests. Tailscale permissions are configured through [grants](https://tailscale.com/docs/features/access-control/grants); joining the tailnet alone is not proof of least privilege.

- [x] Enroll Windows admin host and Ubuntu SOC VM.
- [x] Record initial local TCP reachability and the open API restriction issue.
- [ ] Review the existing tailnet policy, apply narrow rules, and retest TCP 55000.
- [ ] Verify SSH login and dashboard login with a trusted HTTPS identity.
- [ ] Test allowed admin access from another network and denied access from an unprivileged device.
- [ ] Check direct public access, device revocation, new-event flow into SQL and Power BI refresh.

The remaining gates and recovery procedure are in [private-access-plan.md](private-access-plan.md). This update changes documentation only; it does not apply policy or firewall changes.
