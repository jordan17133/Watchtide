<# Read only the exact Sysmon record IDs for an already-generated recovery marker. #>
[CmdletBinding()]
param(
    [ValidateSet('Audit','Library')][string]$Mode='Audit',
    [string]$Marker,
    [long[]]$RecordIds,
    [string]$EvidenceDirectory
)
$ErrorActionPreference='Stop'

function Read-WatchtideSysmonTrace {
    param([string]$Xml,[string]$ExpectedMarker)
    if ($ExpectedMarker -notmatch '^WT-RECOVERY-[A-Za-z0-9-]{1,64}$' -or $Xml.Length -gt 1MB) {
        throw 'Unsupported marker or event size.'
    }
    $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing='Prohibit';$settings.XmlResolver=$null
    $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Xml),$settings)
    try {$event=[Xml.XmlDocument]::new();$event.XmlResolver=$null;$event.Load($reader)} finally {$reader.Dispose()}
    $ns=[Xml.XmlNamespaceManager]::new($event.NameTable)
    $ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
    $id=$event.SelectSingleNode('/e:Event/e:System/e:EventID',$ns)
    $record=$event.SelectSingleNode('/e:Event/e:System/e:EventRecordID',$ns)
    $provider=$event.SelectSingleNode('/e:Event/e:System/e:Provider',$ns)
    if (-not $id -or $id.InnerText -ne '1' -or -not $record -or
        $record.InnerText -notmatch '^[1-9][0-9]{0,17}$' -or -not $provider -or
        $provider.GetAttribute('Name') -ne 'Microsoft-Windows-Sysmon') {throw 'Expected a Sysmon process-create record.'}
    $fields=@{}
    foreach ($node in $event.SelectNodes('/e:Event/e:EventData/e:Data',$ns)) {
        $name=$node.GetAttribute('Name')
        if ($fields.ContainsKey($name)) {throw 'Duplicate event field.'}
        $fields[$name]=$node.InnerText
    }
    if (-not $fields.ProcessGuid -or -not $fields.UtcTime -or
        ($fields.CommandLine+' '+$fields.ParentCommandLine).IndexOf($ExpectedMarker,[StringComparison]::Ordinal) -lt 0) {
        throw 'Record does not contain the expected controlled marker.'
    }
    [pscustomobject]@{event_id=1;record_id=[long]$record.InnerText;process_guid=$fields.ProcessGuid
        source_utc=$fields.UtcTime;marker_matched=$true}
}

if ($Mode -eq 'Library') {return}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'Administrator is needed to read the protected Sysmon channel.'}
if ($Marker -notmatch '^WT-RECOVERY-[A-Za-z0-9-]{1,64}$' -or $RecordIds.Count -lt 1 -or
    $RecordIds.Count -gt 4 -or @($RecordIds | Where-Object {$_ -le 0}).Count -or
    @($RecordIds | Select-Object -Unique).Count -ne $RecordIds.Count) {throw 'Expected one to four distinct positive record IDs.'}
. (Join-Path $PSScriptRoot 'Protect-WatchtidePrivateFiles.ps1') -Mode Library
$dir=Assert-WatchtideOwnedPath $EvidenceDirectory
if (-not $dir.PSIsContainer -or $dir.Parent.FullName -ne (Join-Path $env:USERPROFILE '.watchtide-private') -or
    $dir.Name -notmatch '^hardening-[0-9a-f]{32}$' -or -not (Get-WatchtidePermissionAudit $dir.FullName).acceptable -or
    -not (Get-WatchtidePermissionAudit $dir.FullName).protected) {throw 'Expected an existing protected private evidence directory.'}
$resultPath=Join-Path $dir.FullName 'local-recovery-trace.json'
$hashPath=Join-Path $dir.FullName 'TRACE_SHA256SUMS.json'
if ((Test-Path -LiteralPath $resultPath) -or (Test-Path -LiteralPath $hashPath)) {throw 'Trace evidence already exists; no overwrite.'}
try {
    $predicate=($RecordIds | ForEach-Object {"EventRecordID=$_"}) -join ' or '
    $events=@(Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1 and ($predicate)]]" -MaxEvents $RecordIds.Count)
    $records=@($events | ForEach-Object {Read-WatchtideSysmonTrace $_.ToXml() $Marker})
    if ($records.Count -ne $RecordIds.Count -or
        @(Compare-Object ($RecordIds | Sort-Object) ($records.record_id | Sort-Object)).Count) {throw 'Exact source-record set differs.'}
    @{recorded_utc=[datetime]::UtcNow.ToString('o');marker=$Marker;records=$records;read_only=$true} |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    Get-FileHash -LiteralPath $resultPath -Algorithm SHA256 | Select-Object Hash,Path | ConvertTo-Json |
        Set-Content -LiteralPath $hashPath -Encoding UTF8
    foreach ($file in @($resultPath,$hashPath)) {
        if (-not (Get-WatchtidePermissionAudit $file).acceptable) {throw 'Trace reader permissions failed.'}
    }
    'LOCAL_SYSMON_RECOVERY_TRACE_VERIFIED'
} catch {
    @{recorded_utc=[datetime]::UtcNow.ToString('o');error=$_.Exception.Message;settings_changed=$false} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $dir.FullName 'local-trace-failure.json') -Encoding UTF8
    throw 'LOCAL_TRACE_STOPPED: inspect the protected result; no collection settings changed.'
}
