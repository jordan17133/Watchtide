# Suricata Offline Detection Validation

Validated October 5, 2026. Result: the harmless marker rule passed isolated
engine testing. Live capture, Wazuh ingestion and network reporting remain open.

## Evidence And Scope

The owner supplied the one-time installer's terminal result, including
`OFFLINE_SURICATA_VALIDATION_PASSED`. A subsequent read-only maintenance check
independently confirmed installed package `1:8.0.7-0ubuntu0` and all five
existing SOC services active. Engine counts and masked-service state below
come from the supplied installer output, not a separate retrieval of raw logs.

The job installs a pinned Suricata package and nine reviewed dependencies,
prevents automatic service startup, and runs an isolated test configuration as
the non-root Suricata account. Its success marker follows a syntax test,
positive/negative replay, exact installed-version checks and final health
checks. The existing deployed Wazuh configuration and SSH keys were unchanged.

The input is synthetic Ethernet/IPv4/ICMP traffic, generated with Scapy without
sending packets. It uses documentation addresses, synthetic MACs and fixed
January 1, 2026 packet timestamps. This is not a capture of personal browsing
or proof that the network activity happened on the validation date.

## Test Results

| Input | Packets | Expected alerts | Reported alerts |
|---|---:|---:|---:|
| Echo request containing `WATCHTIDE-PILOT` | 1 | 1 | 1 |
| Controls: request without the marker; reply containing the marker | 2 | 0 | 0 |

- Signature ID: `9000001`, from the [starter rule](../suricata/rules/watchtide-pilot.rules).
- Package version: `1:8.0.7-0ubuntu0`; all ten pinned installed versions passed the job's checks.
- Suricata service: reported masked and idle after replay; it was not enabled for continuous capture.
- Existing services: Hyper-V VSS helper, Wazuh manager, indexer, dashboard and Tailscale active in both the supplied result and independent maintenance check.
- Live capture tested: no. Wazuh collection changed: no. Extra SSH keys created by this job: no.

The positive test proves that the intended packet produces a match. The controls
show that neither an ordinary ping without the marker nor a reply with the
marker passes this rule. A marker match is an expected validation result,
not a confirmed attack, new incident case or additional ATT&CK technique.

## Limits And Next Gate

This is a working offline detection proof, not completion of the network SOC:

- No verified live traffic feed or whole-home visibility; the VM still uses Hyper-V NAT.
- The engine's EVE record has not yet been inspected through the restricted connection, decoded/indexed by Wazuh, or traced into SQL and Power BI.
- Raw package/engine logs, PCAPs, EVE and activation details remain private. No screenshot or reconstructed example is presented as the missing raw event.
- Host-memory/loader performance, full recovery and remaining private-access tests are still open.

The recommended next gate, subject to owner approval, is to inspect the genuine
EVE record, test Wazuh decoding, then review a bounded local collection change
with backup, configuration validation and any necessary manager restart planned
explicitly. Keep continuous capture disabled while proving that event path.
See the [pilot guide](suricata-pilot.md) and [network scope](network-coverage-plan.md).
