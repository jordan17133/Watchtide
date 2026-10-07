<#
Read-only Windows Wazuh connection diagnostic. Run as Administrator to read
protected agent files. Only new private evidence files are written; no agent,
DNS, service, firewall, VPN or existing-file permissions are changed.
#>
[CmdletBinding()]
param([ValidateSet('Audit','Library')][string]$Mode='Audit')
$ErrorActionPreference='Stop'

function Read-WatchtideManagerSettings {
    param([string]$Text)
    if ($Text.Length -gt 2MB) {throw 'Unexpected agent configuration size.'}
    $settings=[Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing='Prohibit';$settings.XmlResolver=$null
    # Some agent configurations contain multiple ossec_config fragments.
    $reader=[Xml.XmlReader]::Create([IO.StringReader]::new('<watchtide>'+ $Text +'</watchtide>'),$settings)
    try {
        $xml=[Xml.XmlDocument]::new();$xml.XmlResolver=$null;$xml.Load($reader)
    } finally {$reader.Dispose()}
    $servers=@($xml.SelectNodes('/watchtide/ossec_config/client/server') | ForEach-Object {
        [pscustomobject]@{address=[string]$_.address;port=[string]$_.port;protocol=[string]$_.protocol}
    })
    if (-not $servers.Count -or $servers.Count -gt 8 -or
        @($servers | Where-Object {[string]::IsNullOrWhiteSpace($_.address)}).Count) {
        throw 'Manager settings are missing or unsupported; inspect privately.'
    }
    return $servers
}

function Get-WatchtideAgentStateLabel {
    param([string[]]$Lines)
    $matches=@($Lines | Where-Object {$_ -match "^status='(connected|disconnected|pending|never_connected)'[;]?$"})
    if ($matches.Count -ne 1) {return 'unknown'}
    return ($matches[0] -split "'")[1]
}

function Assert-WatchtideDiagnosticInput {
    param([string]$Path,[long]$MaxBytes=0)
    $item=Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer) {throw 'Diagnostic input must be a regular file.'}
    $cursor=$item
    while ($cursor) {
        if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Diagnostic input or parent is a reparse point.'
        }
        $cursor=if ($cursor -is [IO.DirectoryInfo]) {$cursor.Parent} else {$cursor.Directory}
    }
    if ($MaxBytes -gt 0 -and $item.Length -gt $MaxBytes) {throw 'Diagnostic input exceeds its size limit.'}
    return $item
}

if ($Mode -eq 'Library') {return}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this read-only check in PowerShell as Administrator; it does not elevate itself.'
}
if (-not [Environment]::Is64BitProcess) {throw 'Use 64-bit PowerShell.'}
. (Join-Path $PSScriptRoot 'Protect-WatchtidePrivateFiles.ps1') -Mode Library
$directory=New-WatchtidePermissionStateDirectory
if (-not (Get-WatchtidePermissionAudit $directory).acceptable) {throw 'Evidence directory is not protected.'}
try {
    $agent=Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
    $config=Join-Path $agent 'ossec.conf'
    $state=Join-Path $agent 'wazuh-agent.state'
    $log=Join-Path $agent 'ossec.log'
    Assert-WatchtideDiagnosticInput $config 2MB | Out-Null
    Assert-WatchtideDiagnosticInput $state 1MB | Out-Null
    Assert-WatchtideDiagnosticInput $log | Out-Null
    $servers=@(Read-WatchtideManagerSettings (Get-Content -LiteralPath $config -Raw))
    $stateLines=@(Get-Content -LiteralPath $state)
    $stateLabel=Get-WatchtideAgentStateLabel $stateLines
    $service=Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'" |
        Select-Object Name,State,StartMode,ProcessId
    if (-not $service) {throw 'Wazuh service is missing.'}
    $connections=@(Get-NetTCPConnection | Where-Object {
        $service.ProcessId -gt 0 -and $_.OwningProcess -eq $service.ProcessId
    } | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess)
    $limitations=@()
    $dns=@(foreach ($server in $servers) {
        try {
            Resolve-DnsName -Name $server.address -Type A -ErrorAction Stop |
                Select-Object Name,Type,IPAddress
        } catch {$limitations+='A configured manager DNS lookup failed.'}
    })
    $adapters=@();$vm=@()
    try {
        $vm=@(Get-VMNetworkAdapter -VMName 'SentinelGrid-Wazuh' -ErrorAction Stop |
            Select-Object VMName,SwitchName,Status,IPAddresses)
        $adapters=@(Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4 |
            Select-Object InterfaceAlias,IPAddress,PrefixLength)
    } catch {$limitations+='Hyper-V guest or Default Switch metadata was unavailable.'}
    $report=[pscustomobject]@{
        recorded_utc=[datetime]::UtcNow.ToString('o');settings_changed=$false;service_restarts=$false
        config_sha256=(Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash
        managers=$servers;agent_state=$stateLabel;service=$service;connections=$connections
        manager_dns=$dns;guest_adapters=$vm;default_switch_addresses=$adapters;limitations=$limitations
    }
    $report | ConvertTo-Json -Depth 7 |
        Set-Content -LiteralPath (Join-Path $directory 'agent-diagnostic.json') -Encoding UTF8
    $stateLines | Set-Content -LiteralPath (Join-Path $directory 'agent-state.txt') -Encoding UTF8
    Get-Content -LiteralPath $log -Tail 160 |
        Set-Content -LiteralPath (Join-Path $directory 'agent-log-tail.txt') -Encoding UTF8
    $files=@(Get-ChildItem -LiteralPath $directory -File)
    foreach ($file in $files) {
        if (-not (Get-WatchtidePermissionAudit $file.FullName).acceptable) {throw 'Evidence file permissions failed.'}
    }
    $files | Get-FileHash -Algorithm SHA256 | Select-Object Hash,Path | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $directory 'SHA256SUMS.json') -Encoding UTF8
    if (-not (Get-WatchtidePermissionAudit (Join-Path $directory 'SHA256SUMS.json')).acceptable) {
        throw 'Hash record permissions failed.'
    }
    [pscustomobject]@{agent_state=$stateLabel;manager_entries=$servers.Count
        established_agent_connections=@($connections | Where-Object {$_.State -eq 'Established'}).Count
        limitations=$limitations.Count;settings_changed=$false;service_restarts=$false
        private_evidence_directory=$directory} | ConvertTo-Json -Compress
    'AGENT_DIAGNOSTIC_SAVED'
} catch {
    @{recorded_utc=[datetime]::UtcNow.ToString('o');error=$_.Exception.Message;settings_changed=$false} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'agent-diagnostic-failure.json') -Encoding UTF8
    Write-Output "Private diagnostic evidence: $directory"
    throw 'AGENT_DIAGNOSTIC_STOPPED: Inspect the private diagnostic before retrying; no settings changed.'
}
