<#
Read-only host exposure and firewall-visibility audit. Requires administrator
read access; never changes firewall, auditing, services, accounts or Wazuh config.
Detailed metadata is written only to protected private evidence storage. The
console output contains counts and classifications, not addresses or raw logs.
#>
[CmdletBinding()]
param([ValidateSet('Audit','Library')][string]$Mode='Audit',[string]$StateDirectory)
$ErrorActionPreference='Stop'

function Get-WatchtideAddressClass {
    param([string]$Value)
    $address=$null
    if (-not [Net.IPAddress]::TryParse($Value,[ref]$address)) {throw 'Invalid packet address.'}
    if ([Net.IPAddress]::IsLoopback($address)) {return 'loopback'}
    if ($address.IsIPv4MappedToIPv6) {$address=$address.MapToIPv4()}
    if ([Net.IPAddress]::IsLoopback($address)) {return 'loopback'}
    $bytes=$address.GetAddressBytes()
    if ($bytes.Length -eq 16) {
        if ($address.IsIPv6Multicast) {return 'multicast'}
        if ($address.IsIPv6LinkLocal) {return 'link_local'}
        if (($bytes[0] -band 254) -eq 252) {return 'private'}
        return 'internet_or_other'
    }
    if (@($bytes | Where-Object {$_ -ne 255}).Count -eq 0) {return 'broadcast'}
    if ($bytes[0] -ge 224 -and $bytes[0] -le 239) {return 'multicast'}
    if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) {return 'link_local'}
    if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) {return 'shared_or_tailnet'}
    if ($bytes[0] -eq 10 -or ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168)) {return 'private'}
    return 'internet_or_other'
}

function Get-WatchtideFirewallSample {
    param([string[]]$Header,[string[]]$Lines)
    $fields=@($Header | Where-Object {$_.StartsWith('#Fields:')})
    if (-not $fields.Count) {throw 'Firewall field header is missing.'}
    $names=[regex]::Split($fields[-1].Substring(8).Trim(),'\s+')
    if (@($names | Select-Object -Unique).Count -ne $names.Count -or
        @('date','time','action','protocol','src-ip','dst-ip','dst-port' | Where-Object {$_ -notin $names}).Count) {
        throw 'Firewall field schema is unsupported.'
    }
    $valid=@();$invalid=0
    foreach($line in $Lines) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) {continue}
        try {
            $values=[regex]::Split($line.Trim(),'\s+')
            if ($values.Count -ne $names.Count) {throw 'Packet column count differs.'}
            $row=@{};for($i=0;$i -lt $names.Count;$i++) {$row[$names[$i]]=$values[$i]}
            if ($row.action -notin @('DROP','ALLOW') -or $row.protocol -notin @('TCP','UDP','ICMP','ICMPV6')) {
                throw 'Unsupported action or protocol.'
            }
            $timestamp=[datetime]::ParseExact(($row.date+' '+$row.time),'yyyy-MM-dd HH:mm:ss',
                [Globalization.CultureInfo]::InvariantCulture)
            if ($row.'dst-port' -ne '-' -and ($row.'dst-port' -notmatch '^\d{1,5}$' -or
                [int]$row.'dst-port' -gt 65535)) {throw 'Invalid destination port.'}
            $direction=if('path' -in $names){$row.path}else{'unspecified'}
            if ($direction -notin @('RECEIVE','SEND','FORWARD','-','unspecified')) {throw 'Unsupported direction.'}
            $valid+=,[pscustomobject]@{time=$timestamp;action=$row.action;protocol=$row.protocol;
                source_class=(Get-WatchtideAddressClass $row.'src-ip');
                destination_class=(Get-WatchtideAddressClass $row.'dst-ip');
                destination_port=$row.'dst-port';direction=$direction}
        } catch {$invalid++}
    }
    $groups=@($valid | Group-Object action,protocol,source_class,destination_class,destination_port,direction |
        Sort-Object Count -Descending | ForEach-Object {
            $first=$_.Group[0]
            [pscustomobject]@{records=$_.Count;action=$first.action;protocol=$first.protocol;
                source_class=$first.source_class;destination_class=$first.destination_class;
                destination_port=$first.destination_port;direction=$first.direction}
        })
    $times=@($valid.time | Sort-Object)
    [pscustomobject]@{valid_records=$valid.Count;invalid_records=$invalid;
        dropped_records=@($valid | Where-Object {$_.action -eq 'DROP'}).Count;
        time_format=(@($Header | Where-Object {$_.StartsWith('#Time Format:')}) -join ' ');
        oldest_record=$(if($times.Count){$times[0].ToString('s')}else{$null});
        newest_record=$(if($times.Count){$times[-1].ToString('s')}else{$null});groups=$groups}
}

function Read-WatchtideLogSources {
    param([string]$Path,[bool]$Fragment=$false)
    $text=Get-Content -LiteralPath $Path -Raw
    if ($text.Length -gt 2MB) {throw 'Unexpected agent configuration size.'}
    if ($Fragment) {$text='<root>'+$text+'</root>'}
    $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing='Prohibit';$settings.XmlResolver=$null
    $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($text),$settings)
    try {$xml=[Xml.XmlDocument]::new();$xml.XmlResolver=$null;$xml.Load($reader)} finally {$reader.Dispose()}
    @($xml.SelectNodes('//localfile') | ForEach-Object {
        [pscustomobject]@{location=[string]$_.location;format=[string]$_.log_format;
            query=[string]$_.query;only_future_events=[string]$_.SelectSingleNode('only-future-events').InnerText}
    })
}

if ($Mode -eq 'Library') {return}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'Administrator read access is required; this audit changes no settings.'}
. (Join-Path $PSScriptRoot 'Protect-WatchtidePrivateFiles.ps1') -Mode Library
if (-not $StateDirectory) {$StateDirectory=New-WatchtidePermissionStateDirectory}
Assert-WatchtideOwnedPath $StateDirectory | Out-Null
$state=Get-Item -LiteralPath $StateDirectory
if ($state.Parent.FullName -ne (Join-Path $env:USERPROFILE '.watchtide-private') -or
    $state.Name -notmatch '^hardening-[0-9a-f]{32}$' -or
    -not (Get-WatchtidePermissionAudit $StateDirectory).acceptable) {throw 'Evidence directory is not protected.'}
$output=Join-Path $StateDirectory 'host-exposure-audit.json'
if (Test-Path -LiteralPath $output) {throw 'Prior audit exists; use a fresh private evidence directory.'}
try {
if (-not [Environment]::Is64BitProcess) {throw 'Use 64-bit PowerShell for the reviewed host paths.'}
$agent=Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
$log=Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log'
foreach($path in @((Join-Path $agent 'ossec.conf'),(Join-Path $agent 'shared\agent.conf'),$log)) {
    $item=Get-Item -LiteralPath $path
    $cursor=$item.Directory
    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reviewed input is a reparse point.'}
    while($cursor){if($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reviewed input parent is a reparse point.'};$cursor=$cursor.Parent}
}
$local=@(Read-WatchtideLogSources (Join-Path $agent 'ossec.conf'))
$shared=@(Read-WatchtideLogSources (Join-Path $agent 'shared\agent.conf') $true)
$sample=Get-WatchtideFirewallSample @(Get-Content -LiteralPath $log -TotalCount 25) @(Get-Content -LiteralPath $log -Tail 2000)
$listeners=@(Get-NetTCPConnection -State Listen | ForEach-Object {
    [pscustomobject]@{port=$_.LocalPort;address=$_.LocalAddress;owner_pid=$_.OwningProcess}
})
$allow=@(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow | ForEach-Object {
    $ports=$_|Get-NetFirewallPortFilter;$address=$_|Get-NetFirewallAddressFilter;$app=$_|Get-NetFirewallApplicationFilter
    [pscustomobject]@{name=$_.Name;profile=$_.Profile.ToString();protocol=$ports.Protocol.ToString();
        ports=@($ports.LocalPort);remote_addresses=@($address.RemoteAddress);program=$app.Program;
        edge_traversal=$_.EdgeTraversalPolicy.ToString()}
})
$audit=& (Join-Path $env:SystemRoot 'System32\auditpol.exe') @('/get','/category:*','/r')
if($LASTEXITCODE -ne 0){throw 'Read-only audit-policy query failed.'}
$auditRows=@($audit|ConvertFrom-Csv)
if(-not $auditRows.Count){throw 'Audit-policy response is empty.'}
$defender=Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IsTamperProtected
$sources=@($local)+@($shared)
$result=[pscustomobject]@{recorded_utc=[datetime]::UtcNow.ToString('o');settings_changed=$false;
    firewall_sample=$sample;firewall_log_bytes=(Get-Item -LiteralPath $log).Length;
    local_sources=$local;shared_sources=$shared;listeners=$listeners;inbound_allow_rules=$allow;
    audit_policy=$auditRows;defender=$defender;
    firewall_log_source_configured=(@($sources|Where-Object {$_.location -match '(?i)pfirewall'}).Count -gt 0)}
$result|ConvertTo-Json -Depth 9|Set-Content -LiteralPath $output -Encoding UTF8
[pscustomobject]@{read_only_audit_complete=$true;blocked_sample_records=$sample.dropped_records;
    invalid_sample_records=$sample.invalid_records;packet_log_collection_configured=$result.firewall_log_source_configured;
    reviewed_inbound_allow_rules=$allow.Count;service_restarts=$false}|ConvertTo-Json -Compress
} catch {
    [pscustomobject]@{status='stopped';settings_changed=$false;process_is_64_bit=[Environment]::Is64BitProcess;
        error=$_.Exception.Message}|ConvertTo-Json -Compress|
        Set-Content -LiteralPath (Join-Path $StateDirectory 'host-exposure-audit-failure.json') -Encoding UTF8
    throw
}
