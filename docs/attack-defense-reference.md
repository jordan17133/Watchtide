# Major Attack Lessons And Watchtide Defenses

October 7, 2026. Retains all 27 examples supplied by the owner and connects them
to the existing [completion checklist](soc-completion-plan.md),
[roadmap](../ROADMAP.md) and [detection-library plan](detection-library-plan.md).
This is a planning reference, not evidence that Watchtide detects these attacks.
No software, rules, capture, blocking or notifications were enabled for this document.

## In Plain English

These examples help us ask three different questions:

1. **Prevent:** Can we make the attack harder, through updates, safer access or filtering?
2. **Detect and respond:** If something happens, can we see it, investigate it and act safely?
3. **Recover:** If prevention fails, can we restore the important systems and data?

An alert is a clue, not an antidote or a verdict. Suricata is not an email filter,
Wazuh is not a replacement for antivirus, and a dashboard is not a backup.
Buying or installing more tools does not automatically answer these questions.

## The Owner's Complete Reference List

The countermeasure themes below preserve the owner's supplied list. They are
starting points, not independently verified accounts of every incident or complete
remediation instructions. Confirm product/version/exposure and current vendor
guidance before acting. The screenshot's year-by-year chronology is not adopted.

| Reference | Countermeasure starting points | Where it fits in our existing work |
|---|---|---|
| ILOVEYOU | Email filtering, risky-attachment restrictions, phishing awareness | Email/execution and human-verification lessons |
| Code Red | Prompt patching of web servers, especially exposed services | Applicable vulnerabilities and service exposure |
| Nimda | Endpoint protection, email/web filtering, file-share hardening | Endpoint execution and lateral movement |
| SQL Slammer | Database updates, restrict unnecessary exposed ports | Database inventory and service exposure |
| MyDoom | Attachment sandboxing, spam filtering, phishing training | Email/execution lessons; no sandbox is deployed by this plan |
| Zotob | Windows updates, segmentation | Patch applicability and lateral movement |
| Conficker | Patch management, strong admin credentials, autorun controls | Account/access and removable-media review |
| Storm Worm | Botnet detection, spam filtering, reviewed C2 restrictions | Endpoint behavior and visible network indicators |
| Koobface | Social-media caution, MFA, browser security | Human verification and account/browser protection |
| Zeus | Banking/email MFA, endpoint detection, credential protection | Identity and suspicious credential/process activity |
| Stuxnet | Industrial-system isolation, USB controls, least-privilege access | Conditional OT/removable-media lesson, not current industrial coverage |
| RSA SecurID Breach | Rotate affected secrets/tokens, identity monitoring, phishing-resistant MFA | Identity incident response and recovery custody |
| Shamoon | Offline backups, endpoint detection, segmentation | Destructive activity and recovery |
| Target Data Breach | Vendor access controls, segmentation, payment-data monitoring | Access-boundary lesson; no payment-system monitoring claim |
| Heartbleed | Patch affected OpenSSL; replace exposed keys/certificates | Applicable software and affected-secret response, not blanket key rotation |
| BlackEnergy | Protect infrastructure, monitor remote access, segment OT | Conditional OT/remote-access lesson |
| Mirai | Replace default IoT credentials, update firmware, restrict admin panels | Device inventory; no IoT sensor coverage assumed |
| WannaCry | SMB patching, remove unnecessary SMBv1, offline backups | Lateral-movement controls and recovery |
| NotPetya | Updates, segmentation, tested recovery backups | Supply-chain, credential/lateral-movement and destructive-activity lessons |
| Emotet | Email security, macro restrictions, endpoint detection | Email-to-execution and persistence lessons |
| SolarWinds | Supply-chain review, signature checks plus behavior, vendor monitoring | Trusted-update and privileged-process review |
| Log4Shell | Identify affected software, emergency patching, applicable WAF mitigations | Product applicability; no WAF installation or universal protection claim |
| Lapsus$ | Strong MFA, help-desk identity checks, least privilege | Identity/social-engineering response |
| MOVEit Transfer Breach | Patch affected transfer tools, exfiltration monitoring, data minimization | Conditional exposed-application and data-access lessons |
| Change Healthcare Ransomware | Phishing-resistant MFA, backups, segmentation, practiced response | Identity, destructive activity and recovery |
| AI-Powered Phishing | Verify urgent requests separately, use passkeys/MFA | Human-verification practice; not a single dated incident |
| Deepfake-Based Attacks | Trusted callbacks, approval workflows, identity proofing, awareness | Human-verification practice; not a single dated incident |

## Important Qualifications

- **No single cure:** a control reduces a particular risk; it does not guarantee
  prevention, detection or recovery. The supplied list mixes malware, breaches,
  vulnerabilities and social-engineering methods, so it is not a rule catalog.
- **Chronology:** Microsoft's contemporary account dates the Petya/NotPetya
  outbreak to June 2017, not the screenshot's 2018 slot. Its analysis also describes
  stolen-credential spread; patching the SMB exploit alone is not the whole defense.
  [Microsoft's June 2017 investigation](https://www.microsoft.com/en-us/msrc/blog/2017/06/update-on-petya-malware-attacks/).
  Other screenshot dates are not independently validated here.
- **MFA strength matters:** ordinary codes/push prompts are not the same as
  phishing-resistant authentication. Prefer appropriately configured FIDO/WebAuthn
  passkeys or security keys where supported; retain protected account-recovery methods.
  [CISA phishing-resistant MFA guidance](https://www.cisa.gov/sites/default/files/2023-01/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf).
- **Signed is not synonymous with safe:** Microsoft's SolarWinds investigation
  found malicious code inside a signed DLL. A signature is useful evidence, but
  cannot replace provenance, vendor advisories and behavior review.
  [Microsoft's supply-chain analysis](https://www.microsoft.com/en-us/msrc/blog/2020/12/customer-guidance-on-recent-nation-state-cyber-attacks/).
- **Applicability first:** a named vulnerability does not mean our PC or VM has
  it. Match installed software and versions to current advisories. CISA's KEV
  catalog helps prioritize known-exploited findings; absence from it is not proof
  of safety. [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- **Human checks remain necessary:** a SIEM cannot certify that a convincing voice,
  video or urgent request is genuine. Practice verifying through contact details
  already trusted, not a number supplied by the suspicious message.

## The Six Recurring Defenses: Our Position

These are dated documentation-level assessments from existing evidence, not new
runtime tests. Current state stays in [STATUS](../STATUS.md). They support the
six-function [NIST CSF 2.0 framework](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1299.pdf);
they are not six formal NIST controls or a compliance assessment.

| Defense | What we have actually established | Remaining finish gate / existing work package |
|---|---|---|
| Patch promptly | A bounded SOC runtime/software batch and applicability review have evidence | Fresh asset/version/posture checks and recurring prioritized remediation; package 6, stages 4b-4c |
| Phishing-resistant MFA | Private SOC access is documented; account-wide MFA is not verified | Review important email, GitHub and remote-access accounts, supported methods and recovery custody; package 6 |
| Offline, tested backups | A same-PC SQL restore drill passed | Protected off-PC/offline copy plus Wazuh and separate-instance restore; package 7, stages 0-1/7; currently deferred |
| Segment and restrict access | Selected private-access and loader restrictions were tested | Record device/service boundaries and test allowed/denied paths; home segmentation is not established; packages 6/8 |
| Monitor endpoints and logs | Repaired Windows-to-Indexer-to-normal-loader SQL trace; bounded Suricata controls | Heartbeat/source-loss warnings, tested local delivery, exact triage evidence and useful sustained network feed; packages 2-5/8 |
| Verify suspicious requests separately | The owner has requested a learning workflow | Practice a trusted callback and sensitive-change approval checklist; link it to account incident response; package 6 and analyst learning |

Offline backup testing, access restrictions, patching, logging and phishing-resistant
MFA are complementary measures in the [CISA StopRansomware guide](https://www.cisa.gov/stopransomware/ransomware-guide).
A checkpoint or online copy on the same PC is not the off-PC/offline recovery gate.

## Turn Attack Names Into Testable Behaviors

Use these families to choose a small relevant library batch, not to enable every
vendor rule. Each row is a candidate validation scope, not a current detection claim.

| Behavior family | Evidence we would need | Detection/response work and present limit |
|---|---|---|
| Risky attachment, script or executable | Exact process/parent/command, file provenance and relevant Defender result | Review Wazuh/Sysmon/Defender conditions and benign controls; no mail-gateway telemetry is established |
| Credential theft, privilege or remote-access abuse | Relevant authentication/audit events, process context and account/session identity | Test specific conditions, then review session revocation/access restriction; cloud identity logs are not assumed collected |
| Persistence or protection tampering | Registry/task/service changes, writer attribution and security-tool state | Test a bounded fixture/control before live settings changes; a familiar filename or signer is not a benign verdict |
| Exploitation or lateral movement | Applicable service/version, authentication/process evidence and visible packets | Continue the chosen TCP/Nmap lesson; its observed path and controls must pass before scan detection is credited |
| Botnet/C2 or suspicious data transfer | Supported DNS/TLS/flow observations, endpoint/process context and relevant indicators | Suricata/ET Open are candidates; no routine PC/iPhone browsing feed exists yet. Encryption limits content visibility; an unfamiliar destination is not proof of C2 or theft |
| Ransomware or wiping behavior | Relevant file/process/protection events, asset scope and protected recovery evidence | Use safe fixtures and a response tabletop, not malware or destructive live tests; restore proof remains a separate gate |
| Compromised supplier or trusted update | Software provenance/advisory, execution behavior and access scope | Review vendor changes and anomalous privileges; trusted signatures alone cannot close the investigation |
| Social engineering, OT, IoT or payment systems | Human verification, or confirmed applicable assets and their own logs | Practice human checks now; other asset classes are conditional lessons, not invented current coverage |

For example, opening a suspicious attachment could produce a process event.
Sysmon records it; the Wazuh agent sends it; a manager rule may match; the Indexer
stores the alert. The dashboard supports investigation, and the loader/SQL/Power BI
report it. The analyst then assigns a supported disposition or case. If antivirus
blocks execution first, the evidence may instead be a protection event. Missing
telemetry or a nonmatching rule must stay visible as a limit, not a clean verdict.
See the [interaction and triage audit](triage-system-audit.md).

## Completion And Execution Order

Keep the existing sequence: collection-health warnings first, exact triage links,
small maintained-rule validation and the TCP/Nmap lesson, then measured routine
network coverage. Account/patch/recovery gates remain parallel or explicitly deferred.
This reference does not approve any live experiment, automatic blocking or schedule.

Before describing a family as validated, record all of the following:

- [ ] Applicable asset/software, required events/fields and observed capture path.
- [ ] Exact rule/version, intended match, harmless positive and meaningful negative controls.
- [ ] Installed-engine results, exact source/alert/report identities and timestamps.
- [ ] False-positive limits, missing data, drop/resource/retention budget where relevant.
- [ ] An explained response, approval boundary, rollback/cleanup and recovery scope.
- [ ] Dated evidence, open blind spots and the owner's explanation of what the test proves.

No family receives credit merely because an attack name, ATT&CK technique or rule
exists in a library. This list gives us a durable set of learning and defense goals;
it does not change the current coverage score or turn controlled tests into incidents.
