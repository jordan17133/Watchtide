<#
Keep Steam installed, limiting unrelated local accounts to read/execute access.
Changes only explicit Users grants on the reviewed Steam folder and registry key;
inheriting children follow the folder policy. The current account keeps FullControl.
Owner, other principals, installed service, network and boot settings are preserved.
Default Audit is read-only. Apply requires administrator rights and private evidence.
#>
[CmdletBinding()]
param(
    [ValidateSet('Audit','Apply','Library')][string]$Mode='Audit',
    [string]$StateDirectory
)
$ErrorActionPreference='Stop'

function Test-WatchtideBroadSteamWrite {
    param([object]$Acl,[ValidateSet('Directory','Registry')][string]$Kind)
    $broad=@('S-1-1-0','S-1-5-11','S-1-5-32-545')
    $mask=0x10000000L -bor 0x40000000L -bor 0x10000L -bor 0x40000L -bor 0x80000L -bor 2L -bor 4L
    if ($Kind -eq 'Directory') { $mask=$mask -bor 16L -bor 64L -bor 256L }
    foreach ($rule in $Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        $rights=if($Kind -eq 'Directory'){[long]$rule.FileSystemRights}else{[long]$rule.RegistryRights}
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -in $broad -and
            ($rights -band $mask)) { return $true }
    }
    return $false
}

function New-WatchtideSteamAccess {
    param([object]$Acl,[ValidateSet('Directory','Registry')][string]$Kind,[string]$AccountSid)
    $rules=@($Acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if (@($rules | Where-Object {$_.AccessControlType -eq 'Deny'}).Count) {
        throw 'Existing deny entries require review; no blanket rewrite.'
    }
    # Only the explicit Users grant is replaced; inherited/other broad writes stop the job.
    $probe=if($Kind -eq 'Directory'){[Security.AccessControl.DirectorySecurity]::new()}
        else{[Security.AccessControl.RegistrySecurity]::new()}
    $probe.SetSecurityDescriptorSddlForm($Acl.GetSecurityDescriptorSddlForm('Access'),'Access')
    foreach ($rule in $rules) {
        if (-not $rule.IsInherited -and $rule.IdentityReference.Value -eq 'S-1-5-32-545') {
            $probe.RemoveAccessRuleSpecific($rule)
        }
    }
    if (Test-WatchtideBroadSteamWrite $probe $Kind) {
        throw 'An inherited or different broad write grant requires separate review.'
    }
    $users=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $account=[Security.Principal.SecurityIdentifier]::new($AccountSid)
    $inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit
    if ($Kind -eq 'Directory') {
        $inherit=$inherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        $probe.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($users,
            [Security.AccessControl.FileSystemRights]::ReadAndExecute,$inherit,
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
        $probe.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($account,
            [Security.AccessControl.FileSystemRights]::FullControl,$inherit,
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    } else {
        $probe.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new($users,
            [Security.AccessControl.RegistryRights]::ReadKey,$inherit,
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
        $probe.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new($account,
            [Security.AccessControl.RegistryRights]::FullControl,$inherit,
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    }
    return $probe
}

function Get-WatchtideSteamAcl {
    param([string]$Path,[string]$Kind)
    if ($Kind -eq 'Directory') { return Get-Acl -LiteralPath $Path }
    $hive=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64)
    $key=$null
    try {
        $key=$hive.OpenSubKey('SOFTWARE\WOW6432Node\Valve\Steam',$false)
        if ($null -eq $key) {throw 'Reviewed 64-bit registry view has no Steam key.'}
        if ($PSVersionTable.PSEdition -eq 'Core') {return [Microsoft.Win32.RegistryAclExtensions]::GetAccessControl($key)}
        return $key.GetAccessControl()
    } finally {if($key){$key.Dispose()};$hive.Dispose()}
}

function Set-WatchtideSteamAccess {
    param([string]$Path,[string]$Kind,[string]$Descriptor)
    if ($Kind -eq 'Directory') {
        $item=Get-Item -LiteralPath $Path
        $acl=[Security.AccessControl.DirectorySecurity]::new()
        $acl.SetSecurityDescriptorSddlForm($Descriptor,'Access')
        if ($PSVersionTable.PSEdition -eq 'Core') {[IO.FileSystemAclExtensions]::SetAccessControl($item,$acl)}
        else {$item.SetAccessControl($acl)}
    } else {
        $acl=[Security.AccessControl.RegistrySecurity]::new()
        $acl.SetSecurityDescriptorSddlForm($Descriptor,'Access')
        $hive=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64)
        $key=$hive.OpenSubKey('SOFTWARE\WOW6432Node\Valve\Steam',
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [Security.AccessControl.RegistryRights]::ChangePermissions)
        if ($null -eq $key) { $hive.Dispose(); throw 'Reviewed Steam registry key is unavailable.' }
        try {
            if ($PSVersionTable.PSEdition -eq 'Core') {[Microsoft.Win32.RegistryAclExtensions]::SetAccessControl($key,$acl)}
            else {$key.SetAccessControl($acl)}
        } finally {$key.Dispose();$hive.Dispose()}
    }
}

function Restore-WatchtideSteamAccess {
    param([object[]]$Changed)
    $verified=$true
    for($i=$Changed.Count-1;$i -ge 0;$i--) {
        $row=$Changed[$i]
        try {
            $current=Get-WatchtideSteamAcl $row.path $row.kind
            $descriptor=Get-WatchtideComparableAccessDescriptor $current.GetSecurityDescriptorSddlForm('Access')
            $original=Get-WatchtideComparableAccessDescriptor $row.descriptor
            if ($descriptor -eq (Get-WatchtideComparableAccessDescriptor $row.expected)) {
                Set-WatchtideSteamAccess $row.path $row.kind $row.descriptor
                $current=Get-WatchtideSteamAcl $row.path $row.kind
                $descriptor=Get-WatchtideComparableAccessDescriptor $current.GetSecurityDescriptorSddlForm('Access')
            }
            if ($descriptor -ne $original -or
                $current.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $row.owner) {$verified=$false}
        } catch {$verified=$false}
    }
    return $verified
}

if ($Mode -eq 'Library') { return }
$operation=$Mode
$folder=Join-Path ${env:ProgramFiles(x86)} 'Steam'
$registry='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Valve\Steam'
$account=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$targets=@(@{Path=$folder;Kind='Directory'},@{Path=$registry;Kind='Registry'})
if ($operation -eq 'Audit') {
    @($targets | ForEach-Object {[pscustomobject]@{kind=$_.Kind;
        broad_write_present=(Test-WatchtideBroadSteamWrite (Get-WatchtideSteamAcl $_.Path $_.Kind) $_.Kind)}}) |
        ConvertTo-Json -Compress
    return
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator PowerShell is required.' }
. (Join-Path $PSScriptRoot 'Protect-WatchtidePrivateFiles.ps1') -Mode Library
if (-not $StateDirectory) {$StateDirectory=New-WatchtidePermissionStateDirectory}
Assert-WatchtideOwnedPath $StateDirectory | Out-Null
$state=Get-Item -LiteralPath $StateDirectory
if ($state.Parent.FullName -ne (Join-Path $env:USERPROFILE '.watchtide-private') -or
    $state.Name -notmatch '^hardening-[0-9a-f]{32}$' -or
    -not (Get-WatchtidePermissionAudit $StateDirectory).acceptable) { throw 'Evidence directory is not protected.' }
if (Test-Path -LiteralPath (Join-Path $StateDirectory 'steam-before.json')) {throw 'Prior apply evidence exists; audit before any rerun.'}
$changed=@()
try {
    $cursor=Get-Item -LiteralPath $folder
    while($cursor) {
        if($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Steam path contains a reparse point.'}
        $cursor=$cursor.Parent
    }
    if (@(Get-ChildItem -LiteralPath $folder -Directory -Recurse -Force | Where-Object {
        $_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count) {throw 'Steam descendant reparse points require review.'}
    if (@(Get-Process -Name steam,steamwebhelper -ErrorAction SilentlyContinue).Count) {
        throw 'Steam is active; no application will be terminated.'
    }
    $before=@($targets | ForEach-Object {
        $acl=Get-WatchtideSteamAcl $_.Path $_.Kind
        $expected=New-WatchtideSteamAccess $acl $_.Kind $account
        [pscustomobject]@{path=$_.Path;kind=$_.Kind;owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;
            descriptor=$acl.GetSecurityDescriptorSddlForm('Access');expected=$expected.GetSecurityDescriptorSddlForm('Access')}
    })
    $files=@('steam.exe','steamclient.dll','steamclient64.dll','bin\SteamService.exe','bin\SteamService.dll')
    $hashes=@($files | ForEach-Object {
        $path=Join-Path $folder $_
        if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'A critical Steam binary is a reparse point.'
        }
        $signature=Get-AuthenticodeSignature -LiteralPath $path
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Valve Corp\.(,|$)') {
            throw 'A critical Steam binary has no valid Valve signature.'
        }
        [pscustomobject]@{relative=$_;hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
    })
    @{targets=$before;binary_hashes=$hashes} | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $StateDirectory 'steam-before.json') -Encoding UTF8
    foreach($row in $before) {
        $current=(Get-WatchtideSteamAcl $row.path $row.kind).GetSecurityDescriptorSddlForm('Access')
        if ((Get-WatchtideComparableAccessDescriptor $current) -ne
            (Get-WatchtideComparableAccessDescriptor $row.descriptor)) {throw 'Permissions changed during preflight.'}
        $changed+=,$row
        Set-WatchtideSteamAccess $row.path $row.kind $row.expected
        $after=Get-WatchtideSteamAcl $row.path $row.kind
        if ((Test-WatchtideBroadSteamWrite $after $row.kind) -or
            $after.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $row.owner -or
            (Get-WatchtideComparableAccessDescriptor $after.GetSecurityDescriptorSddlForm('Access')) -ne
            (Get-WatchtideComparableAccessDescriptor $row.expected)) {throw 'Steam policy readback failed.'}
    }
    foreach($file in $hashes) {
        $path=Join-Path $folder $file.relative
        if ((Test-WatchtideBroadSteamWrite (Get-Acl -LiteralPath $path) 'Directory') -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $file.hash) {
            throw 'Critical Steam binary access or content changed unexpectedly.'
        }
    }
    $result=[pscustomobject]@{status='verified';targets_hardened=2;binary_checks=$hashes.Count;
        current_account_full_control=$true;application_removed=$false;service_changes=$false;
        normal_launch_tested=$false;old_cves_proven_fixed=$false}
    $result | ConvertTo-Json -Compress |
        Set-Content -LiteralPath (Join-Path $StateDirectory 'steam-result.json') -Encoding UTF8
    $result | ConvertTo-Json -Compress
    'STEAM_LOCAL_ACCESS_HARDENING_VERIFIED'
} catch {
    $rollback=Restore-WatchtideSteamAccess -Changed $changed
    [pscustomobject]@{status='stopped';guarded_rollback_completed=$rollback;error=$_.Exception.Message} |
        ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $StateDirectory 'steam-result.json') -Encoding UTF8
    throw
}
