<#
Remove exactly one reviewed obsolete hosts.ics mapping and restart WazuhSvc.
Caller must first authenticate the verified guest address through its known SSH
identity. No agent configuration, permissions, enrollment or firewall changes.
Apply requires Administrator and an existing owner-protected evidence directory.
#>
[CmdletBinding()]
param(
    [ValidateSet('Audit','Apply','Library')][string]$Mode='Audit',
    [string]$ManagerName,
    [string]$VerifiedAddress,
    [string]$StaleAddress,
    [string]$ExpectedIcsSHA256,
    [string]$ExpectedConfigSHA256,
    [string]$EvidenceDirectory
)
$ErrorActionPreference='Stop'

function Get-WatchtideBytesHash {
    param([byte[]]$Bytes)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {return [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','')}
    finally {$sha.Dispose()}
}

function Get-WatchtideResolutionPlan {
    param([byte[]]$Bytes,[string]$Name,[string]$CurrentAddress,[string]$ObsoleteAddress)
    if ($Bytes.Length -eq 0 -or $Bytes.Length -gt 1MB -or
        @($Bytes | Where-Object {$_ -gt 127 -or $_ -eq 0}).Count) {
        throw 'Only bounded ASCII hosts.ics input is supported; inspect other encodings.'
    }
    if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$' -or
        $Name.Contains('..') -or $Name.EndsWith('.')) {throw 'Unsupported manager name.'}
    foreach ($address in @($CurrentAddress,$ObsoleteAddress)) {
        $parsed=$null
        if (-not [Net.IPAddress]::TryParse($address,[ref]$parsed) -or
            $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
            $parsed.ToString() -ne $address -or [Net.IPAddress]::IsLoopback($parsed) -or
            $parsed.GetAddressBytes()[0] -ge 224 -or
            $address -eq '0.0.0.0' -or $address -eq '255.255.255.255') {
            throw 'Expected two canonical unicast IPv4 addresses.'
        }
    }
    if ($CurrentAddress -eq $ObsoleteAddress) {throw 'Current and obsolete addresses must differ.'}
    $text=[Text.Encoding]::ASCII.GetString($Bytes)
    $entries=@()
    foreach ($match in [regex]::Matches($text,'[^\r\n]*(?:\r\n|\r|\n|$)')) {
        $line=$match.Value
        $content=($line -split '#',2)[0].Trim()
        if (-not $content) {continue}
        $fields=[regex]::Split($content,'\s+')
        if ($fields.Count -lt 2) {
            if ($fields[0] -eq $Name) {throw 'Manager mapping has no address.'}
            # Preserve unrelated nonmapping fragments, including existing ICS artifacts.
            continue
        }
        $names=@($fields | Select-Object -Skip 1)
        if ($Name -notin $names) {continue}
        if ($names.Count -ne 1) {throw 'Manager entry shares aliases; no automatic removal.'}
        $entries += [pscustomobject]@{address=$fields[0];offset=$match.Index;length=$match.Length}
    }
    if ($entries.Count -ne 2 -or
        @($entries | Where-Object {$_.address -eq $CurrentAddress}).Count -ne 1 -or
        @($entries | Where-Object {$_.address -eq $ObsoleteAddress}).Count -ne 1) {
        throw 'Expected exactly one verified and one obsolete manager mapping.'
    }
    $old=@($entries | Where-Object {$_.address -eq $ObsoleteAddress})[0]
    $after=[Text.Encoding]::ASCII.GetBytes($text.Remove($old.offset,$old.length))
    return [pscustomobject]@{before_hash=(Get-WatchtideBytesHash $Bytes)
        after_hash=(Get-WatchtideBytesHash $after);after_bytes=$after;removed_entries=1}
}

function Assert-WatchtideResolutionHash {
    param([string]$Actual,[string]$Expected)
    if ($Expected -notmatch '^[0-9A-Fa-f]{64}$' -or $Actual -ne $Expected) {
        throw 'Input changed since the reviewed preflight; stop and inspect.'
    }
}

if ($Mode -eq 'Library') {return}
$operationMode=$Mode
. {
trap {
    $failure=$_.Exception.Message
    try {
        $candidate=Assert-WatchtideOwnedPath $EvidenceDirectory
        $expectedParent=[IO.Path]::GetFullPath((Join-Path $env:USERPROFILE '.watchtide-private'))
        if ($candidate.PSIsContainer -and $candidate.Parent.FullName -eq $expectedParent -and
            $candidate.Name -match '^hardening-[0-9a-f]{32}$' -and
            (Get-WatchtidePermissionAudit $candidate.FullName).acceptable -and
            (Get-WatchtidePermissionAudit $candidate.FullName).protected -and
            -not (Test-Path -LiteralPath (Join-Path $candidate.FullName 'repair-failure.json'))) {
            @{recorded_utc=[datetime]::UtcNow.ToString('o');error=$failure;mapping_write_attempted=[bool]$changed} |
                ConvertTo-Json | Set-Content -LiteralPath (Join-Path $candidate.FullName 'repair-preflight-failure.json') -Encoding UTF8
        }
    } catch {}
    Write-Output 'AGENT_RESOLUTION_REPAIR_STOPPED: inspect protected evidence before retrying.'
    exit 1
}
if (-not [Environment]::Is64BitProcess) {throw 'Use 64-bit PowerShell.'}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'Administrator approval is required.'}
. (Join-Path $PSScriptRoot 'Get-WatchtideAgentDiagnostic.ps1') -Mode Library
. (Join-Path $PSScriptRoot 'Protect-WatchtidePrivateFiles.ps1') -Mode Library
$ics=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts.ics'
$agent=Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
$config=Join-Path $agent 'ossec.conf'
$state=Join-Path $agent 'wazuh-agent.state'
$log=Join-Path $agent 'ossec.log'
foreach ($path in @($ics,$config,$state)) {Assert-WatchtideDiagnosticInput $path 2MB | Out-Null}
Assert-WatchtideDiagnosticInput $log | Out-Null
$original=[IO.File]::ReadAllBytes($ics)
$plan=Get-WatchtideResolutionPlan $original $ManagerName $VerifiedAddress $StaleAddress
Assert-WatchtideResolutionHash $plan.before_hash $ExpectedIcsSHA256
Assert-WatchtideResolutionHash (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash $ExpectedConfigSHA256
$servers=@(Read-WatchtideManagerSettings ([IO.File]::ReadAllText($config)))
if ($servers.Count -ne 1 -or $servers[0].address -ne $ManagerName -or
    $servers[0].port -ne '1514' -or $servers[0].protocol -ne 'tcp') {
    throw 'Agent manager configuration differs from the approved repair.'
}
$service=Get-Service -Name WazuhSvc
if ($service.Status -ne 'Running') {throw 'Expected the previously running agent service.'}
$client=[Net.Sockets.TcpClient]::new()
try {
    $attempt=$client.ConnectAsync($VerifiedAddress,1514)
    if (-not $attempt.Wait(5000) -or -not $client.Connected) {throw 'Verified LAN data port is unreachable.'}
} finally {$client.Dispose()}
if ($operationMode -eq 'Audit') {
    @{obsolete_entries_to_remove=1;agent_config_changed=$false;service_to_restart='WazuhSvc'} |
        ConvertTo-Json -Compress
    'RESOLUTION_REPAIR_PREFLIGHT_PASSED'
    return
}
$directory=Assert-WatchtideOwnedPath $EvidenceDirectory
$parent=[IO.Path]::GetFullPath((Join-Path $env:USERPROFILE '.watchtide-private'))
if (-not $directory.PSIsContainer -or $directory.Parent.FullName -ne $parent -or
    $directory.Name -notmatch '^hardening-[0-9a-f]{32}$' -or
    @(Get-ChildItem -LiteralPath $directory.FullName -Force).Count -ne 0 -or
    -not (Get-WatchtidePermissionAudit $directory.FullName).acceptable -or
    -not (Get-WatchtidePermissionAudit $directory.FullName).protected) {
    throw 'Expected an empty protected private evidence directory.'
}
$directory=$directory.FullName
$originalAcl=(Get-Acl -LiteralPath $ics).GetSecurityDescriptorSddlForm('Owner,Group,Access')
$changed=$false
$restartAttempted=$false
$result=[ordered]@{recorded_utc=[datetime]::UtcNow.ToString('o');mapping_changed=$false
    agent_config_changed=$false;service_restarted=$false;local_connection_verified=$false
    rollback_applied=$false;indexer_sql_verified=$false}
try {
    [IO.File]::WriteAllBytes((Join-Path $directory 'hosts.ics.before'),$original)
    Assert-WatchtideResolutionHash (Get-FileHash -LiteralPath (Join-Path $directory 'hosts.ics.before')).Hash $plan.before_hash
    Copy-Item -LiteralPath $config -Destination (Join-Path $directory 'ossec.conf.before')
    Assert-WatchtideResolutionHash (Get-FileHash -LiteralPath (Join-Path $directory 'ossec.conf.before')).Hash $ExpectedConfigSHA256
    $result.before_hash=$plan.before_hash;$result.expected_after_hash=$plan.after_hash
    $result.manager_name=$ManagerName;$result.verified_address=$VerifiedAddress;$result.stale_address=$StaleAddress
    $result.original_ics_descriptor=$originalAcl
    foreach ($file in @(Get-ChildItem -LiteralPath $directory -File)) {
        if (-not (Get-WatchtidePermissionAudit $file.FullName).acceptable) {throw 'Backup permissions failed.'}
    }
    $result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $directory 'repair-before.json') -Encoding UTF8
    # Keep the existing file/ACL; exclusive writer access rejects concurrent ICS updates.
    $stream=[IO.File]::Open($ics,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try {
        $actual=New-Object byte[] $stream.Length
        $offset=0
        while ($offset -lt $actual.Length) {
            $read=$stream.Read($actual,$offset,$actual.Length-$offset)
            if ($read -eq 0) {throw 'Incomplete hosts.ics read.'}
            $offset += $read
        }
        Assert-WatchtideResolutionHash (Get-WatchtideBytesHash $actual) $plan.before_hash
        Assert-WatchtideResolutionHash (Get-FileHash -LiteralPath $config).Hash $ExpectedConfigSHA256
        $changed=$true
        $stream.Position=0;$stream.Write($plan.after_bytes,0,$plan.after_bytes.Length)
        $stream.SetLength($plan.after_bytes.Length);$stream.Flush($true)
    } finally {$stream.Dispose()}
    $result.mapping_changed=$true
    Assert-WatchtideResolutionHash (Get-FileHash -LiteralPath $ics).Hash $plan.after_hash
    if ((Get-Acl -LiteralPath $ics).GetSecurityDescriptorSddlForm('Owner,Group,Access') -ne $originalAcl) {
        throw 'Mapping file permissions changed unexpectedly.'
    }
    Clear-DnsClientCache
    $resolved=@([Net.Dns]::GetHostAddresses($ManagerName) | ForEach-Object {$_.ToString()})
    if ($resolved.Count -ne 1 -or $resolved[0] -ne $VerifiedAddress) {throw 'Name resolution did not converge on the verified guest.'}
    $restartAttempted=$true
    Restart-Service -Name WazuhSvc
    $result.service_restarted=$true
    $deadline=[datetime]::UtcNow.AddSeconds(120)
    do {
        $svc=Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'"
        $label=Get-WatchtideAgentStateLabel @(Get-Content -LiteralPath $state)
        $connections=@(Get-NetTCPConnection -RemotePort 1514 -ErrorAction SilentlyContinue |
            Where-Object {$_.OwningProcess -eq $svc.ProcessId -and $_.RemoteAddress -eq $VerifiedAddress -and $_.State -eq 'Established'})
        if ($label -eq 'connected' -and $connections.Count -gt 0) {break}
        Start-Sleep -Seconds 2
    } while ([datetime]::UtcNow -lt $deadline)
    if ($label -ne 'connected' -or $connections.Count -eq 0) {throw 'Agent did not reconnect within the bounded check.'}
    Assert-WatchtideResolutionHash (Get-FileHash -LiteralPath $config).Hash $ExpectedConfigSHA256
    $result.local_connection_verified=$true;$result.agent_state=$label
    Get-Content -LiteralPath $state | Set-Content -LiteralPath (Join-Path $directory 'agent-state-after.txt') -Encoding UTF8
    Get-Content -LiteralPath $log -Tail 80 | Set-Content -LiteralPath (Join-Path $directory 'agent-log-after.txt') -Encoding UTF8
    $result.completed_utc=[datetime]::UtcNow.ToString('o')
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $directory 'repair-result.json') -Encoding UTF8
    foreach ($file in @(Get-ChildItem -LiteralPath $directory -File)) {
        if (-not (Get-WatchtidePermissionAudit $file.FullName).acceptable) {throw 'Evidence permissions failed.'}
    }
    Get-ChildItem -LiteralPath $directory -File | Get-FileHash -Algorithm SHA256 | Select-Object Hash,Path |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'SHA256SUMS.json') -Encoding UTF8
    'AGENT_RESOLUTION_REPAIRED_AND_LOCALLY_CONNECTED'
} catch {
    $result.error=$_.Exception.Message
    if ($changed) {
        try {
            $currentHash=(Get-FileHash -LiteralPath $ics).Hash
            if ($currentHash -eq $plan.after_hash -and
                (Get-Acl -LiteralPath $ics).GetSecurityDescriptorSddlForm('Owner,Group,Access') -eq $originalAcl) {
                $rollback=[IO.File]::Open($ics,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
                try {
                    $current=New-Object byte[] $rollback.Length
                    $read=$rollback.Read($current,0,$current.Length)
                    if ($read -ne $current.Length) {throw 'Incomplete rollback preflight.'}
                    Assert-WatchtideResolutionHash (Get-WatchtideBytesHash $current) $plan.after_hash
                    $rollback.Position=0;$rollback.Write($original,0,$original.Length)
                    $rollback.SetLength($original.Length);$rollback.Flush($true)
                } finally {$rollback.Dispose()}
                Clear-DnsClientCache
                if ($restartAttempted) {Restart-Service -Name WazuhSvc}
                $result.rollback_applied=$true
            } else {$result.rollback_held='File changed since repair; no concurrent update overwritten.'}
        } catch {$result.rollback_error=$_.Exception.Message}
    }
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $directory 'repair-failure.json') -Encoding UTF8
    throw 'AGENT_RESOLUTION_REPAIR_STOPPED: inspect protected evidence before retrying.'
}
}
