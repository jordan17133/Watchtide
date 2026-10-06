<#
Restrict existing private SOC files without reading their contents.
Default is read-only Audit. Apply saves permission metadata privately; Rollback
requires that metadata and refuses to overwrite a concurrent permission change.
No firewall, services, accounts, SSH configuration or secret values are changed.
#>
[CmdletBinding()]
param(
    [ValidateSet('Audit','Apply','Rollback','Library')][string]$Mode = 'Audit',
    [string]$StateFile
)
$ErrorActionPreference = 'Stop'

function Get-WatchtideTrustedSids {
    @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544')
}

function Assert-WatchtideOwnedPath {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    $cursor = $item
    while ($null -ne $cursor) {
        if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'A target or parent is a reparse point; review before applying.'
        }
        $cursor = if ($cursor -is [IO.DirectoryInfo]) { $cursor.Parent } else { $cursor.Directory }
    }
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) {
        throw 'Only private paths owned by the current Windows account may be changed.'
    }
    return $item
}

function Get-WatchtidePermissionAudit {
    param([string]$Path)
    $acl = Get-Acl -LiteralPath $Path
    $trusted = @(Get-WatchtideTrustedSids)
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $extra = @($rules | Where-Object {
        $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -notin $trusted
    })
    $denials = @($rules | Where-Object { $_.AccessControlType -eq 'Deny' })
    $ownerAllowed = @($rules | Where-Object {
        $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -eq $trusted[0] -and
        ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Read) -eq
            [Security.AccessControl.FileSystemRights]::Read
    }).Count -gt 0
    [pscustomobject]@{
        protected = $acl.AreAccessRulesProtected
        extra_allow_entries = $extra.Count
        deny_entries = $denials.Count
        owner_read_allowed = $ownerAllowed
        acceptable = ($extra.Count -eq 0 -and $denials.Count -eq 0 -and $ownerAllowed)
    }
}

function New-WatchtidePrivateAcl {
    param([bool]$Directory)
    $acl = if ($Directory) { [Security.AccessControl.DirectorySecurity]::new() }
        else { [Security.AccessControl.FileSecurity]::new() }
    $acl.SetAccessRuleProtection($true, $false)
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.SetOwner($owner)
    $inherit = if ($Directory) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($value in Get-WatchtideTrustedSids) {
        $sid = [Security.Principal.SecurityIdentifier]::new($value)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl, $inherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    return $acl
}

function Get-WatchtideComparableAccessDescriptor {
    param([string]$Descriptor)
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($Descriptor)
    # Windows may add this bookkeeping flag after a write; retain all ACEs and protection flags.
    $flags = $raw.ControlFlags -band (-bnot [Security.AccessControl.ControlFlags]::DiscretionaryAclAutoInherited)
    $raw.SetFlags($flags)
    return $raw.GetSddlForm('Access')
}

function Set-WatchtideAccessDescriptor {
    param([string]$Path, [string]$Descriptor)
    $item = Assert-WatchtideOwnedPath $Path
    $access = if ($item.PSIsContainer) { [Security.AccessControl.DirectorySecurity]::new() }
        else { [Security.AccessControl.FileSecurity]::new() }
    # Persist only DACL changes, leaving the owner, group and auditing section untouched.
    $access.SetSecurityDescriptorSddlForm($Descriptor, 'Access')
    if ($PSVersionTable.PSEdition -eq 'Core') {
        [IO.FileSystemAclExtensions]::SetAccessControl($item, $access)
    } else {
        $item.SetAccessControl($access)
    }
}

function Set-WatchtidePrivateAcl {
    param([string]$Path)
    $item = Assert-WatchtideOwnedPath $Path
    $before = Get-WatchtidePermissionAudit $Path
    if ($before.deny_entries -gt 0) { throw 'Existing deny entries require separate review.' }
    if ($before.acceptable -and $before.protected) { return $false }
    $policy = New-WatchtidePrivateAcl $item.PSIsContainer
    $acl = Get-Acl -LiteralPath $Path
    $original = $acl.GetSecurityDescriptorSddlForm('Access')
    $expected = $policy.GetSecurityDescriptorSddlForm('Access')
    try {
        Set-WatchtideAccessDescriptor $Path $expected
        $after = Get-WatchtidePermissionAudit $Path
        if (-not $after.acceptable -or -not $after.protected) {
            throw 'Private permission verification failed.'
        }
    } catch {
        $current = Get-Acl -LiteralPath $Path
        if ((Get-WatchtideComparableAccessDescriptor $current.GetSecurityDescriptorSddlForm('Access')) -eq
            (Get-WatchtideComparableAccessDescriptor $expected)) {
            Set-WatchtideAccessDescriptor $Path $original
        }
        throw
    }
    return $true
}

function Get-WatchtideSecretTargets {
    $repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $candidates = @(
        @{ label='Private evidence'; path=(Join-Path $env:USERPROFILE '.watchtide-private') },
        @{ label='Installer backup'; path=(Join-Path $env:USERPROFILE 'Documents\SentinelGrid-Private') },
        @{ label='Loader credentials'; path=(Join-Path $repo 'loader\.env') },
        @{ label='Loader SSH key'; path=(Join-Path $env:USERPROFILE '.ssh\sentinelgrid_loader') }
    )
    @($candidates | Where-Object { Test-Path -LiteralPath $_.path })
}

function New-WatchtidePermissionStateDirectory {
    $parent = Join-Path $env:USERPROFILE '.watchtide-private'
    Assert-WatchtideOwnedPath $parent | Out-Null
    $directory = Join-Path $parent ('hardening-' + [Guid]::NewGuid().ToString('N'))
    $acl = New-WatchtidePrivateAcl $true
    if ($PSVersionTable.PSEdition -eq 'Core') {
        [IO.FileSystemAclExtensions]::CreateDirectory($acl, $directory) | Out-Null
    } else {
        [IO.Directory]::CreateDirectory($directory, $acl) | Out-Null
    }
    return $directory
}

if ($Mode -eq 'Library') { return }
$targets = @(Get-WatchtideSecretTargets)
foreach ($target in $targets) { Assert-WatchtideOwnedPath $target.path | Out-Null }
if ($Mode -eq 'Audit') {
    @($targets | ForEach-Object {
        [pscustomobject]@{ label=$_.label; permissions=(Get-WatchtidePermissionAudit $_.path) }
    }) | ConvertTo-Json -Depth 4
    return
}

if ($Mode -eq 'Rollback') {
    $expectedParent = [IO.Path]::GetFullPath((Join-Path $env:USERPROFILE '.watchtide-private'))
    $file = Assert-WatchtideOwnedPath $StateFile
    if ($file.Name -ne 'permissions-before.json' -or
        $file.Directory.Parent.FullName -ne $expectedParent -or
        $file.Directory.Name -notmatch '^hardening-[0-9a-f]{32}$') {
        throw 'Rollback metadata must be an existing private hardening record.'
    }
    $state = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
    $completed = Get-Content -LiteralPath (Join-Path $file.Directory.FullName 'permissions-after.json') -Raw |
        ConvertFrom-Json
    foreach ($entry in $state.entries) {
        $target = @($targets | Where-Object { $_.path -eq $entry.path })
        if ($target.Count -ne 1) { throw 'Rollback contains a non-allowlisted target.' }
        $current = Get-Acl -LiteralPath $entry.path
        $record = @($completed.entries | Where-Object { $_.path -eq $entry.path })
        if ($record.Count -ne 1 -or $current.GetSecurityDescriptorSddlForm('Access') -ne $record[0].sddl) {
            throw 'Permissions changed since hardening; rollback requires a fresh review.'
        }
    }
    foreach ($entry in $state.entries) {
        Set-WatchtideAccessDescriptor $entry.path $entry.sddl
    }
    'PRIVATE_PERMISSION_ROLLBACK_APPLIED'
    return
}

$entries = @($targets | ForEach-Object {
    $audit = Get-WatchtidePermissionAudit $_.path
    if ($audit.deny_entries) { throw 'Existing deny entries require review; no changes applied.' }
    [pscustomobject]@{
        label=$_.label; path=$_.path
        sddl=(Get-Acl -LiteralPath $_.path).GetSecurityDescriptorSddlForm('Access')
    }
})
$directory = New-WatchtidePermissionStateDirectory
@{ saved_utc=[DateTime]::UtcNow.ToString('o'); entries=$entries } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $directory 'permissions-before.json') -Encoding UTF8
$changed = @()
try {
    foreach ($target in $targets) {
        if (Set-WatchtidePrivateAcl $target.path) { $changed += $target.label }
    }
    $afterEntries = @($targets | ForEach-Object {
        [pscustomobject]@{
            path=$_.path; sddl=(Get-Acl -LiteralPath $_.path).GetSecurityDescriptorSddlForm('Access')
        }
    })
    @{ entries=$afterEntries } | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $directory 'permissions-after.json') -Encoding UTF8
    $results = @($targets | ForEach-Object {
        [pscustomobject]@{ label=$_.label; permissions=(Get-WatchtidePermissionAudit $_.path) }
    })
    $results | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $directory 'verification.json') -Encoding UTF8
    [pscustomobject]@{
        changed=$changed; targets_checked=$targets.Count; all_targets_verified=$true
        private_state_directory=$directory
        secret_contents_read=$false; service_restarts=$false
    } | ConvertTo-Json -Depth 4
    'PRIVATE_PERMISSION_HARDENING_PASSED'
} catch {
    # Restore only ACLs still matching our own policy, never a concurrent edit.
    $expectedAclDirectory = (New-WatchtidePrivateAcl $true).GetSecurityDescriptorSddlForm('Access')
    $expectedAclFile = (New-WatchtidePrivateAcl $false).GetSecurityDescriptorSddlForm('Access')
    foreach ($entry in $entries) {
        if ($entry.label -notin $changed) { continue }
        $item = Get-Item -LiteralPath $entry.path -Force
        $acl = Get-Acl -LiteralPath $entry.path
        $expected = if ($item.PSIsContainer) { $expectedAclDirectory } else { $expectedAclFile }
        if ((Get-WatchtideComparableAccessDescriptor $acl.GetSecurityDescriptorSddlForm('Access')) -eq
            (Get-WatchtideComparableAccessDescriptor $expected)) {
            Set-WatchtideAccessDescriptor $entry.path $entry.sddl
        }
    }
    throw
}
