$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot '..\windows\Get-WatchtideAgentDiagnostic.ps1'
$tokens=$null;$errors=$null
[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $path),[ref]$tokens,[ref]$errors) | Out-Null
if ($errors.Count) {throw 'Agent diagnostic did not parse.'}
. $path -Mode Library
$script:checks=0
function Assert-Check {param([bool]$Condition) if(-not $Condition){throw 'Synthetic diagnostic check failed.'};$script:checks++}
function Assert-Rejected {param([scriptblock]$Action) $rejected=$false;try{& $Action | Out-Null}catch{$rejected=$true};Assert-Check $rejected}
$single='<ossec_config><client><server><address>manager.example</address><port>1514</port><protocol>tcp</protocol></server></client><password>not-exported</password></ossec_config>'
$servers=@(Read-WatchtideManagerSettings $single)
Assert-Check ($servers.Count -eq 1 -and $servers[0].address -eq 'manager.example')
Assert-Check ($servers[0].port -eq '1514' -and $servers[0].protocol -eq 'tcp')
Assert-Check (($servers[0].PSObject.Properties.Name -join ',') -eq 'address,port,protocol')
Assert-Check (@(Read-WatchtideManagerSettings ($single+'<ossec_config><localfile/></ossec_config>')).Count -eq 1)
Assert-Rejected {Read-WatchtideManagerSettings '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///C:/secret">]><ossec_config>&e;</ossec_config>'}
Assert-Rejected {Read-WatchtideManagerSettings '<ossec_config>'}
Assert-Rejected {Read-WatchtideManagerSettings '<ossec_config><client><server><address/></server></client></ossec_config>'}
Assert-Rejected {Read-WatchtideManagerSettings (' ' * (2MB+1))}
Assert-Rejected {Read-WatchtideManagerSettings ($single*9)}
Assert-Check ((Get-WatchtideAgentStateLabel @("status='connected'",'last_ack=1')) -eq 'connected')
Assert-Check ((Get-WatchtideAgentStateLabel @("status='disconnected'")) -eq 'disconnected')
Assert-Check ((Get-WatchtideAgentStateLabel @("status='connected'","status='pending'")) -eq 'unknown')
Assert-Check ((Get-WatchtideAgentStateLabel @("status='unexpected-secret'")) -eq 'unknown')
Assert-Check ((Get-WatchtideAgentStateLabel @()) -eq 'unknown')
Assert-Check ((Assert-WatchtideDiagnosticInput $path 2MB).Name -eq 'Get-WatchtideAgentDiagnostic.ps1')
Assert-Rejected {Assert-WatchtideDiagnosticInput $PSScriptRoot}
Assert-Rejected {Assert-WatchtideDiagnosticInput $path 1}
"Agent diagnostic: $script:checks synthetic checks passed; no protected files read or settings changed."
