<#
Enable blocked-packet logging only. Does not change firewall rules, defaults,
enabled state, allowed-traffic logging, services, routing or VPN permissions.
Default Audit is read-only. Apply requires an elevated Windows account and
keeps prior logging settings in private permission-restricted storage.
#>
[CmdletBinding()]
param([ValidateSet('Audit','Apply','Library')][string]$Mode = 'Audit')
$ErrorActionPreference = 'Stop'

function Get-WatchtideFirewallRows {
    param([string]$Store)
    @(Get-NetFirewallProfile -PolicyStore $Store | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{
            Name=[string]$_.Name; Enabled=[string]$_.Enabled
            DefaultInboundAction=[string]$_.DefaultInboundAction
            DefaultOutboundAction=[string]$_.DefaultOutboundAction
            LogBlocked=[string]$_.LogBlocked; LogAllowed=[string]$_.LogAllowed
            LogMaxSizeKilobytes=[int]$_.LogMaxSizeKilobytes
        }
    })
}

function Invoke-WatchtideFirewallLogging {
    param([string]$StateDirectory)
    $local = @(Get-WatchtideFirewallRows 'PersistentStore')
    $active = @(Get-WatchtideFirewallRows 'ActiveStore')
    $expected = @('Domain','Private','Public')
    if ($active.Count -ne 3 -or $local.Count -ne 3 -or
        @(Compare-Object $expected @($active.Name)).Count -ne 0 -or
        @(Compare-Object $expected @($local.Name)).Count -ne 0 -or
        @($active | Where-Object { $_.Enabled -ne 'True' }).Count -gt 0) {
        throw 'Expected all three enabled firewall profiles; no change applied.'
    }
    @{ saved_utc=[DateTime]::UtcNow.ToString('o'); persistent=$local; active=$active } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $StateDirectory 'firewall-before.json') -Encoding UTF8
    try {
        Set-NetFirewallProfile -Profile Domain,Private,Public -PolicyStore PersistentStore `
            -LogBlocked True -LogMaxSizeKilobytes 16384
        $after = @(Get-WatchtideFirewallRows 'ActiveStore')
        if ($after.Count -ne 3) { throw 'Firewall profile inventory changed.' }
        foreach ($before in $active) {
            $row = @($after | Where-Object { $_.Name -eq $before.Name })
            if ($row.Count -ne 1) { throw 'Firewall profile identity changed.' }
            foreach ($field in @('Enabled','DefaultInboundAction','DefaultOutboundAction','LogAllowed')) {
                if ($row[0].$field -ne $before.$field) { throw 'An unrelated effective firewall setting changed.' }
            }
            if ($row[0].LogBlocked -ne 'True' -or $row[0].LogMaxSizeKilobytes -lt 16384) {
                throw 'Effective blocked-packet logging did not match; another policy may override it.'
            }
        }
        $after | ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath (Join-Path $StateDirectory 'firewall-after.json') -Encoding UTF8
        return $after
    } catch {
        foreach ($row in $local) {
            Set-NetFirewallProfile -Profile $row.Name -PolicyStore PersistentStore `
                -LogBlocked $row.LogBlocked -LogMaxSizeKilobytes $row.LogMaxSizeKilobytes
        }
        throw
    }
}

if ($Mode -eq 'Library') { return }
if ($Mode -eq 'Audit') {
    Get-WatchtideFirewallRows 'ActiveStore' | ConvertTo-Json -Depth 3
    return
}
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Open PowerShell as Administrator; this helper does not elevate itself.' }
. (Join-Path $PSScriptRoot 'Protect-WatchtidePrivateFiles.ps1') -Mode Library
$directory = New-WatchtidePermissionStateDirectory
$after = @(Invoke-WatchtideFirewallLogging $directory)
[pscustomobject]@{
    profiles_verified=$after.Count; blocked_logging_enabled=$true; per_profile_limit_kb=16384
    private_state_directory=$directory; connection_rules_changed=$false; service_restarts=$false
} | ConvertTo-Json -Compress
'FIREWALL_BLOCKED_LOGGING_VERIFIED'
try {
    $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    [pscustomobject]@{ disk_encryption_protection=[string]$vol.ProtectionStatus;
        disk_encryption_state=[string]$vol.VolumeStatus } | ConvertTo-Json -Compress
} catch { 'DISK_ENCRYPTION_STATUS_UNVERIFIED' }
try {
    [pscustomobject]@{ secure_boot_enabled=[bool](Confirm-SecureBootUEFI -ErrorAction Stop) } |
        ConvertTo-Json -Compress
} catch { 'SECURE_BOOT_STATUS_UNVERIFIED' }
