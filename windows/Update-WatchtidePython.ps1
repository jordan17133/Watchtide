<#
Update only the existing per-user SOC Python 3.14 runtime to the reviewed 3.14.8.
Requires pre-staged official installers and no active process using that runtime.
The existing loader schedule is paused, never terminated, and restored in finally.
No 3.13 workloads, launcher, firewall, credentials or boot settings are changed.
#>
[CmdletBinding()]
param(
    [ValidateSet('Audit','Apply','Library')][string]$Mode='Audit',
    [string]$StageDirectory
)
$ErrorActionPreference='Stop'

function Assert-WatchtidePythonIdle {
    param([string]$RuntimeDirectory,[string]$EnvironmentDirectory,[object[]]$Processes)
    foreach ($process in $Processes) {
        if ([string]::IsNullOrWhiteSpace($process.ExecutablePath)) {
            throw 'A Python process cannot be identified; refuse runtime replacement.'
        }
        $path=[IO.Path]::GetFullPath($process.ExecutablePath)
        foreach ($directory in @($RuntimeDirectory,$EnvironmentDirectory)) {
            if ($path.StartsWith($directory.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) {
                throw 'The SOC Python runtime is active; no process will be terminated.'
            }
        }
    }
}

function Assert-WatchtidePythonInstaller {
    param([string]$Path,[string]$Hash)
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Hash) {
        throw 'Installer hash differs from the reviewed official release.'
    }
    $signature=Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or
        $signature.SignerCertificate.Subject -notmatch 'CN=Python Software Foundation(?:,|$)') {
        throw 'Installer publisher signature is not verified.'
    }
}

function Invoke-WatchtideQuietPythonUpdate {
    param([string]$RuntimeDirectory,[string]$EnvironmentDirectory,[string]$Installer,
          [string]$Stage,[string]$Repo)
    $task=Get-ScheduledTask -TaskName 'SentinelGridLoader' -TaskPath '\SentinelGrid\'
    $expected=Join-Path $EnvironmentDirectory 'Scripts\pythonw.exe'
    if ([string]$task.State -ne 'Ready' -or $task.Actions.Count -ne 1 -or
        $task.Actions[0].Execute -ne $expected -or
        $task.Actions[0].WorkingDirectory -ne $Repo -or
        $task.Actions[0].Arguments -ne ('"'+(Join-Path $Repo 'loader\wazuh_to_sql.py')+'"')) {
        throw 'Loader identity or ready state changed; stop before maintenance.'
    }
    $paused=$false
    try {
        Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath | Out-Null
        $paused=$true
        if ([string](Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath).State -ne 'Disabled') {
            throw 'Loader schedule did not pause.'
        }
        Assert-WatchtidePythonIdle $RuntimeDirectory $EnvironmentDirectory @(
            Get-CimInstance Win32_Process | Where-Object {$_.Name -match '^pythonw?\.exe$'})
        $backup=Join-Path $Stage 'runtime-before'
        if (Test-Path -LiteralPath $backup) { throw 'Prior runtime copy exists; do not rerun this apply.' }
        Copy-Item -LiteralPath $RuntimeDirectory -Destination $backup -Recurse
        $beforePath=[Environment]::GetEnvironmentVariable('Path','User')
        $arguments=@('/quiet','/norestart','InstallAllUsers=0',('TargetDir="'+$RuntimeDirectory+'"'),
            'Include_launcher=0','InstallLauncherAllUsers=0','PrependPath=0','AppendPath=0',
            '/log',('"'+(Join-Path $Stage 'installer.log')+'"'))
        $result=Start-Process -FilePath $Installer -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
        if ($result.ExitCode -notin @(0,3010)) { throw 'Python installer failed; inspect the private installer log.' }
        # Preserve the prior PATH only when the installer changed this runtime's entries alone.
        $afterPath=[Environment]::GetEnvironmentVariable('Path','User')
        if ($beforePath -ne $afterPath) {
            $beforeOther=@($beforePath -split ';' | Where-Object {
                $_.TrimEnd('\') -notin @($RuntimeDirectory,$RuntimeDirectory+'\Scripts') })
            $afterOther=@($afterPath -split ';' | Where-Object {
                $_.TrimEnd('\') -notin @($RuntimeDirectory,$RuntimeDirectory+'\Scripts') })
            if (($beforeOther -join ';') -ne ($afterOther -join ';')) {
                throw 'Unrelated PATH entries changed; do not overwrite concurrent changes.'
            }
            [Environment]::SetEnvironmentVariable('Path',$beforePath,'User')
        }
        $base=& (Join-Path $RuntimeDirectory 'python.exe') -I -S -c 'import sys; print(sys.version.split()[0])'
        if ($LASTEXITCODE -ne 0 -or $base -ne '3.14.8') { throw 'Updated base runtime did not verify.' }
        $environment=& (Join-Path $EnvironmentDirectory 'Scripts\python.exe') -I -S -c 'import sys; print(sys.version.split()[0])'
        if ($LASTEXITCODE -ne 0 -or $environment -ne '3.14.8') { throw 'Existing SOC environment did not pick up the patched runtime.' }
        [pscustomobject]@{base_runtime=$base;environment_runtime=$environment;
            reboot_required=($result.ExitCode -eq 3010);old_runtime_copy=$backup;
            other_python_workloads_stopped=$false}
    } finally {
        if ($paused) {
            Enable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath | Out-Null
            if ([string](Get-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath).State -eq 'Disabled') {
                throw 'Loader schedule restoration failed; restore it before leaving maintenance.'
            }
        }
    }
}

if ($Mode -eq 'Library') { return }
$operation=$Mode
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runtime=Join-Path $env:LOCALAPPDATA 'Programs\Python\Python314'
$environment=Join-Path $repo '.venv'
$version=& (Join-Path $runtime 'python.exe') -I -S -c 'import sys; print(sys.version.split()[0])'
if ($LASTEXITCODE -ne 0) { throw 'Cannot verify current runtime.' }
if ($operation -eq 'Audit') {
    [pscustomobject]@{base_runtime=$version;target_runtime='3.14.8';changes_applied=$false} | ConvertTo-Json -Compress
    return
}
if ($version -ne '3.14.7') { throw 'Expected the reviewed 3.14.7 baseline; do not change another version.' }
. (Join-Path $PSScriptRoot 'Protect-WatchtidePrivateFiles.ps1') -Mode Library
foreach ($path in @($runtime,$environment,$StageDirectory)) { Assert-WatchtideOwnedPath $path | Out-Null }
$stageItem=Get-Item -LiteralPath $StageDirectory
if ($stageItem.Parent.FullName -ne (Join-Path $env:USERPROFILE '.watchtide-private') -or
    $stageItem.Name -notmatch '^hardening-[0-9a-f]{32}$' -or
    -not (Get-WatchtidePermissionAudit $StageDirectory).acceptable) {
    throw 'Staging directory is not protected private storage.'
}
if (@(Get-ChildItem -LiteralPath $runtime -Recurse -Force | Where-Object {
    $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
    throw 'Runtime contains a reparse point; stop before copying or installing.'
}
$installer=Join-Path $StageDirectory 'python-3.14.8-amd64.exe'
Assert-WatchtidePythonInstaller $installer '759be887b96e736a3ca886daf8d575f18fcae1a09efab6902f42d59e8999f8ef'
Assert-WatchtidePythonInstaller (Join-Path $StageDirectory 'python-3.14.7-amd64.exe') '9d9eb2709ef81bf5cd30db3c2096bdbc4ea10087c22e62f27d356b36f6ae9649'
$result=Invoke-WatchtideQuietPythonUpdate $runtime $environment $installer $StageDirectory $repo
$result | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $StageDirectory 'python-update-result.json') -Encoding UTF8
$result | ConvertTo-Json -Compress
'SOC_PYTHON_RUNTIME_UPDATED; production ingestion and full regression checks remain separate.'
