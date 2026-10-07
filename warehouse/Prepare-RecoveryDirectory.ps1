param(
    [Parameter(Mandatory = $true)][string]$Directory,
    [switch]$Create,
    [switch]$SqlService
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $env:USERPROFILE '.watchtide-private\recovery'))
$target = [IO.Path]::GetFullPath($Directory)
$isRoot = $target -eq $root
$isRun = ([IO.Path]::GetDirectoryName($target) -eq $root) -and
    ([IO.Path]::GetFileName($target) -match '^sql-[0-9a-f]{32}$')
if (-not ($isRoot -or $isRun) -or ($isRoot -and $SqlService)) {
    throw 'Only the private recovery root or a fresh SQL drill folder is allowed.'
}

$cursor = [IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($target))
while ($null -ne $cursor) {
    if (-not $cursor.Exists -or ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'A recovery parent is missing or is a reparse point.'
    }
    $cursor = $cursor.Parent
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$readers = @($identity, $system, $admins)
if ($SqlService) {
    $readers += [Security.Principal.NTAccount]::new('NT Service', 'MSSQLSERVER').Translate(
        [Security.Principal.SecurityIdentifier])
}

if ($Create) {
    if ([IO.Directory]::Exists($target) -or [IO.File]::Exists($target)) {
        throw 'Refusing to change permissions or reuse an existing recovery directory.'
    }
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($identity)
    foreach ($sid in $readers) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
             [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }
    # Windows PowerShell's .NET Framework creates the directory with its ACL.
    [IO.Directory]::CreateDirectory($target, $security) | Out-Null
}

$item = Get-Item -LiteralPath $target -Force
if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Recovery storage must be a real directory.'
}
$acl = Get-Acl -LiteralPath $target
if (-not $acl.AreAccessRulesProtected -or
    $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $identity.Value) {
    throw 'Recovery ownership or inheritance does not match the approved readers.'
}
$expected = @($readers | ForEach-Object { $_.Value } | Sort-Object -Unique)
$rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
$actual = @($rules | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
if (@(Compare-Object $expected $actual).Count -ne 0) {
    throw 'Recovery storage has missing or additional readers.'
}
foreach ($rule in $rules) {
    if ($rule.AccessControlType -ne 'Allow' -or $rule.IsInherited -or
        $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
        $rule.InheritanceFlags -ne ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                                  [Security.AccessControl.InheritanceFlags]::ObjectInherit)) {
        throw 'Recovery access rules do not match the approved directory policy.'
    }
}
[pscustomobject]@{
    access_verified = $true
    sql_service_access = [bool]$SqlService
    encryption_verified = $false
} | ConvertTo-Json -Compress
