# Maintained Detection Libraries

## Plain English

A **rule** is an instruction such as "tell me when this suspicious pattern
appears." An **alert** is a recorded match. Neither a rule's existence nor its
high severity proves that an attack occurred.

We want maintained libraries, visible data and tested detections together.
More rules cannot recover logs that were dropped or inspect traffic the sensor
never receives. No library covers every possible attack.

## Sources And Their Jobs

| Library | What it examines | Watchtide approach |
|---|---|---|
| Wazuh's maintained ruleset | Endpoint and server logs: processes, authentication, file changes, security-tool health | Already in use; preserve stock files and review local changes separately |
| Emerging Threats Open (ET Open) | Network packets/protocols: malware indicators, exploitation, scanning and other patterns | Official Suricata updater's default feed; downloaded privately for review, not deployed |
| SigmaHQ | Shareable log-detection and hunting logic | Later gap analysis; requires compatible conversion/field mapping and tests, not copying YAML into Wazuh |
| MITRE ATT&CK | Names and organizes adversary techniques | Coverage vocabulary, not an executable detection library or proof of detection |

Wazuh documents its maintained default rules and recommends keeping custom work
outside the stock ruleset. [Wazuh data analysis](https://documentation.wazuh.com/current/user-manual/ruleset/index.html).
Suricata recommends `suricata-update`; ET Open is its default source.
[Suricata 8.0.7 rule management](https://docs.suricata.io/en/suricata-8.0.7/rule-management/suricata-update.html).
Sigma provides generic detection logic and conversion tooling; Watchtide has
not installed or converted its library. [SigmaHQ](https://github.com/SigmaHQ/sigma).

## October 7 Inventory

The read-only SQL inventory at 20:24 UTC counted **37,641 retained alerts across
147 observed rule IDs**. This is retained history, not today's incident count.

| Highest observed severity per rule ID | Rule types |
|---|---:|
| Critical | 1 |
| High | 4 |
| Medium | 29 |
| Low | 113 |

Forty IDs have historical rule reviews; 107 do not. This is a **review backlog**,
not 107 confirmed threats. An older benign cluster does not adjudicate new
alerts from the same rule. The private inventory keeps every alert-type row's
current verdict unassigned and sorts by severity, then frequency.

The October 1 Wazuh export has 1,062 MITRE-tagged rules and 750 catalog
techniques. It is historical and limited to tagged rules: it is **not** a fresh
count of all installed or enabled rules. Sixty-nine observed IDs appear in that
export; an absent ID is not evidence that its detection is missing.

The private JSON and readable Markdown include all 147 observed IDs, counts,
severity ranges, descriptions, groups, first/last times and available historical
report references. Descriptions can contain private paths or device details;
neither full inventory is published.

### What We Review

| Alert family already observed | What the analyst asks |
|---|---|
| Process and PowerShell activity | Who ran it, what was executed, and does the surrounding activity support the explanation? |
| File/registry integrity and startup changes | What changed, which program wrote it, and can it persist or expose credentials? |
| Authentication and privileges | Was this expected access, a failed login, a new account or a privilege change? |
| Defender, vulnerability and CIS records | Did protection change, is the finding applicable, and does a fresh check verify remediation? |
| Agent/System/Sysmon health | Was telemetry delayed or lost, and is collection healthy now? |
| Suricata network alerts | What packet/protocol condition matched, on which visible path, and was it a labeled test? |

Observed agent rules 202/203/204 show queue pressure/full/flooded warnings around
05:49-05:51 UTC on October 7; rule 205 then reports normal load. Sysmon error
warnings occurred nearby. These historical messages do not prove a continuing
outage, but the cause, possible lost events and representative collection health
need review before adding sustained detection load. This is not an instruction
to enlarge queues or disable logging blindly.

## ET Open Staging Result

The HTTPS download used the official version-addressed ET Open endpoint for
Suricata 8.0.7. The exact archive and private review have local SHA-256 hashes.
TLS and a retained local hash provide transport/snapshot checks; **the local
hash is not an independently authenticated vendor signature**.

| Archive field review | Result |
|---|---:|
| Rule files | 54 |
| Parsed entries, including deleted-file entries | 72,100 |
| Unique generator/signature ID pairs | 72,100 |
| Entries outside updater-default excluded deleted files | 68,637 |
| Vendor-uncommented entries outside those files | 52,608 |
| Vendor-commented entries outside those files | 16,029 |

There were no duplicate generator/signature pairs in this snapshot. All entries
outside deleted files use the `alert` action, including the file named
`drop.rules`: a filename does not establish blocking behavior. Of the
uncommented entries, 426 use `noalert`; these may support other detections rather
than independently produce alerts. No dependency, deduplication or category
filter was applied or assumed complete.

The field reader uses the reviewed, hash-pinned **OISF suricata-update 1.3.3**
parser from its official source archive, without installing that package. This
specific parser is pinned for reproducible field inspection, not presented as
the latest updater or as Suricata 8 engine validation. Archive links, unsafe
paths, duplicate filenames and excessive expansion are rejected; nothing is
extracted to system paths. Rule text is data, not executed as a shell script.
[OISF project](https://github.com/OISF/suricata-update),
[pinned package](https://pypi.org/project/suricata-update/1.3.3/).

### Candidate Groups, Not Enabled Coverage

| Purpose | Example groups | Qualification |
|---|---|---|
| Malware and command-and-control | malware, botcc, coinminer, mobile_malware | Need visible matching traffic; an indicator match still needs investigation |
| Exploitation and phishing | exploit, exploit_kit, phishing, web_client | Select relevant protocols; encrypted application payloads are generally unavailable without decryption |
| Discovery and guessing | scan | Different rules target different tool/protocol behaviors; a basic Nmap connection scan is not guaranteed to match |
| DNS and infrastructure patterns | dns, dyn_dns | Only applies where DNS/related traffic is visible; encrypted DNS is not a readable domain list |
| Hunting and application policy | hunting, info, games, p2p, chat, tor | Presence or use is not automatically malicious; distinguish policy observations from incidents |
| Server/legacy/industrial protocols | web_server, SQL, FTP, Telnet, SCADA | Retain the inventory, but require an applicable service/asset and visible path before selecting |

The private review lists every file and every parsed signature. We have
inventoried the library, **not manually validated 72,100 detections**.

## Rollout Checklist

1. **Done: inventory and provenance.** Preserve all observed alert types and the
   staged feed/hash/category inventory. No live settings changed.
2. **Open: collection health.** Investigate the recorded overflow/error period;
   check fresh agent health, actual ingestion and resource headroom. Do not
   declare missing historical events recovered from a later normal message.
3. **Open: a small relevant test batch.** Continue the TCP/Nmap lesson. Inspect
   exact selected rule conditions, variable definitions and dependencies;
   preserve vendor-disabled state unless separately justified. Use the official
   updater's dependency handling rather than copying isolated rules blindly.
4. **Open: installed-engine validation.** Verify the guest's updater/version and
   source settings. Stage in a new protected directory with explicit alternate
   data/output/config/filter paths and no reload. Run Suricata 8.0.7 `-T` on
   an isolated configuration with measured resource/time limits. Field parsing
   alone does not close this gate.
5. **Open: harmless controls.** Offline positive and negative protocol fixtures
   must meet the actual selected rule's conditions. Then, only in a separately
   bounded owned-device exercise, verify the sensor sees the TCP path, packets,
   alerts/nonmatches, drops, resource use and clean shutdown.
6. **Open: explain and trace.** Follow the exact labeled test through Wazuh,
   Indexer, normal-loader SQL and the existing Power BI page; distinguish packet,
   ingestion and refresh times. Do not label a validation as an incident.
7. **Open: operational upkeep.** Before sustained capture, set measured retention,
   alert-volume and resource budgets, test rollback/health checks, and define
   reviewed update/diff/validation and failure notification procedures. No new
   scheduled updater has been created in this preparation.

Do not run the updater with its default paths merely to inspect a feed: it writes
the normal rules output. The official options provide alternate data/output,
config/filter files and `--no-reload`. `--no-test` skips validation; it is not
a passing test. [Updater CLI](https://suricata-update.readthedocs.io/en/latest/update.html).

The permanent Suricata service remains masked. Windows browsing and iPhone
traffic are not newly visible. Wider coverage still needs the separately
verified capture path in the [network plan](network-coverage-plan.md).
The roadmap retains the [TCP/Nmap learning sequence](analyst-toolkit-runbook.md)
and the held [PowerShell tune review](powershell-policy-probe-tuning-review.md).

## Repeatable Read-Only Tools

- [Alert inventory helper](../warehouse/inventory_detection_rules.py): one
  bounded aggregate SQL read, no raw JSON/commands or database writes.
- [Archive review helper](../suricata/review_rule_library.py): local staged
  inputs and explicit hashes; no downloads, package installation, extraction,
  configuration edits, rule rewriting, reloads or captures.
- [Regression tests](../tests/test_detection_library_review.py): synthetic data
  and hostile archives; no SQL connection or network operations.

Run helpers as modules from the source repository. Outputs must use fresh names
in an existing, owner-protected folder under `~/.watchtide-private`. Check the
folder's Windows ACL before running; the Python path guard does not replace
that permissions audit. Keep vendor rules/licenses, inventories and raw evidence
private; publish only reviewed code, aggregate results and the procedure.
