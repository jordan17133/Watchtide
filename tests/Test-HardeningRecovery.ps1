# Extract only the cleanup helper; never execute the elevated hardening script.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.ServiceProcess
$source = Join-Path $PSScriptRoot '..\windows\Set-SentinelGridHardening.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $source), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Hardening script failed parsing.' }
$helper = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-WithWazuhStopped'
}, $true)
if (-not $helper) { throw 'Recovery helper not found.' }
Invoke-Expression $helper.Extent.Text

$script:events = [System.Collections.Generic.List[string]]::new()
function Stop-Service { param($Name) $script:events.Add('stop') }
function Start-Service { param($Name, $ErrorAction) $script:events.Add('start') }
function Get-Service {
    param($Name, $ErrorAction)
    $fake = [pscustomobject]@{}
    $fake | Add-Member -MemberType ScriptMethod -Name WaitForStatus -Value {
        param($Status, $Timeout)
        $script:events.Add('verified')
    }
    $fake
}

Invoke-WithWazuhStopped { $script:events.Add('action') }
if (($script:events -join ',') -ne 'stop,action,start,verified') { throw 'Success path did not restart and verify the mocked agent.' }
$script:events.Clear()
$caught = $false
try { Invoke-WithWazuhStopped { throw 'synthetic action failure' } }
catch { $caught = $_.Exception.Message -eq 'synthetic action failure' }
if (-not $caught -or ($script:events -join ',') -ne 'stop,start,verified') { throw 'Failure path did not preserve the error and restore the mocked agent.' }
function Stop-Service { param($Name) throw 'synthetic stop failure' }
$script:events.Clear()
$caught = $false
try { Invoke-WithWazuhStopped { throw 'Action should not execute.' } }
catch { $caught = $_.Exception.Message -eq 'synthetic stop failure' }
if (-not $caught -or ($script:events -join ',') -ne 'start,verified') { throw 'Failed stop did not attempt recovery.' }
'Hardening recovery: 3 mocked paths passed; no services or registry settings changed.'
