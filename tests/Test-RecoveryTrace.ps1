$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot '..\windows\Get-WatchtideRecoveryTrace.ps1'
$tokens=$null;$errors=$null
[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $path),[ref]$tokens,[ref]$errors) | Out-Null
if ($errors.Count) {throw 'Trace helper did not parse.'}
. $path -Mode Library
$script:checks=0
function Assert-Check {param([bool]$Condition) if (-not $Condition) {throw 'Synthetic trace check failed.'};$script:checks++}
function Assert-Rejected {param([scriptblock]$Action) $bad=$false;try {& $Action | Out-Null} catch {$bad=$true};Assert-Check $bad}
$marker='WT-RECOVERY-fixture'
$xml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><EventRecordID>123</EventRecordID></System><EventData><Data Name="ProcessGuid">fixture-guid</Data><Data Name="UtcTime">2026-10-07 22:00:00.000</Data><Data Name="CommandLine">whoami /user</Data><Data Name="ParentCommandLine">cmd /c echo WT-RECOVERY-fixture</Data></EventData></Event>'
$r=Read-WatchtideSysmonTrace $xml $marker
Assert-Check ($r.record_id -eq 123 -and $r.event_id -eq 1)
Assert-Check ($r.marker_matched -and $r.process_guid -eq 'fixture-guid')
Assert-Check (($r.PSObject.Properties.Name -join ',') -eq 'event_id,record_id,process_guid,source_utc,marker_matched')
Assert-Rejected {Read-WatchtideSysmonTrace ($xml.Replace('>1<','>3<')) $marker}
Assert-Rejected {Read-WatchtideSysmonTrace ($xml.Replace('Microsoft-Windows-Sysmon','Other-Provider')) $marker}
Assert-Rejected {Read-WatchtideSysmonTrace ($xml.Replace('WT-RECOVERY-fixture','other-command')) $marker}
Assert-Rejected {Read-WatchtideSysmonTrace ($xml.Replace('fixture-guid','')) $marker}
Assert-Rejected {Read-WatchtideSysmonTrace $xml 'wildcard*'}
Assert-Rejected {Read-WatchtideSysmonTrace ($xml.Replace('<Data Name="ProcessGuid">','<Data Name="UtcTime">')) $marker}
Assert-Rejected {Read-WatchtideSysmonTrace ('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///C:/secret">]>'+ $xml) $marker}
Assert-Rejected {Read-WatchtideSysmonTrace '<Event>' $marker}
Assert-Rejected {Read-WatchtideSysmonTrace (' '*(1MB+1)) $marker}
"Recovery trace: $script:checks synthetic checks passed; no live records or settings read."
