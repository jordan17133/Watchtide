$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot '..\windows\Repair-WatchtideAgentResolution.ps1'
$tokens=$null;$errors=$null
[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $path),[ref]$tokens,[ref]$errors) | Out-Null
if ($errors.Count) {throw 'Repair helper did not parse.'}
. $path -Mode Library
$script:checks=0
function Assert-Check {param([bool]$Condition) if (-not $Condition) {throw 'Synthetic repair check failed.'};$script:checks++}
function Assert-Rejected {param([scriptblock]$Action) $rejected=$false;try {& $Action | Out-Null} catch {$rejected=$true};Assert-Check $rejected}
function Get-Plan {param([string]$Text) Get-WatchtideResolutionPlan ([Text.Encoding]::ASCII.GetBytes($Text)) 'soc.example.test' '192.168.50.2' '192.168.40.2'}
foreach ($newline in @("`r`n","`n","`r")) {
    $keep="192.168.50.2 soc.example.test # current$newline"
    $other="192.168.50.3 other.example.test$newline"
    $old="192.168.40.2 soc.example.test # obsolete$newline"
    foreach ($text in @("# header$newline$keep$other$old","# header$newline$old$keep$other")) {
        $plan=Get-Plan $text
        Assert-Check ($plan.removed_entries -eq 1)
        Assert-Check ([Text.Encoding]::ASCII.GetString($plan.after_bytes) -eq "# header$newline$keep$other")
        Assert-Check ($plan.before_hash -ne $plan.after_hash)
    }
}
$plan=Get-Plan "192.168.50.2 SOC.EXAMPLE.TEST`n192.168.40.2 soc.example.test"
Assert-Check ([Text.Encoding]::ASCII.GetString($plan.after_bytes) -eq "192.168.50.2 SOC.EXAMPLE.TEST`n")
Assert-Rejected {Get-Plan '192.168.50.2 soc.example.test'}
Assert-Rejected {Get-Plan "192.168.50.2 soc.example.test`n192.168.40.3 soc.example.test"}
Assert-Rejected {Get-Plan "192.168.50.2 soc.example.test`n192.168.40.2 soc.example.test`n192.168.40.2 soc.example.test"}
Assert-Rejected {Get-Plan "192.168.50.2 soc.example.test alias.example.test`n192.168.40.2 soc.example.test"}
Assert-Rejected {Get-Plan "192.168.50.2 soc.example.test`n192.168.40.2 soc.example.test alias.example.test"}
$fragment="123`r`n"
$preserved=Get-Plan ($fragment+"192.168.50.2 soc.example.test`r`n192.168.40.2 soc.example.test`r`n")
Assert-Check ([Text.Encoding]::ASCII.GetString($preserved.after_bytes) -eq ($fragment+"192.168.50.2 soc.example.test`r`n"))
Assert-Rejected {Get-Plan "soc.example.test`n192.168.50.2 soc.example.test`n192.168.40.2 soc.example.test"}
Assert-Rejected {Get-WatchtideResolutionPlan ([byte[]]@(255,0)) 'soc.example.test' '192.168.50.2' '192.168.40.2'}
Assert-Rejected {Get-WatchtideResolutionPlan ([Text.Encoding]::ASCII.GetBytes('x')) 'soc example' '192.168.50.2' '192.168.40.2'}
Assert-Rejected {Get-WatchtideResolutionPlan ([Text.Encoding]::ASCII.GetBytes('x')) 'soc.example.test' '127.0.0.1' '192.168.40.2'}
Assert-Rejected {Get-WatchtideResolutionPlan ([Text.Encoding]::ASCII.GetBytes('x')) 'soc.example.test' '192.168.50.2' '192.168.50.2'}
Assert-Rejected {Assert-WatchtideResolutionHash ('A'*64) ('B'*64)}
Assert-Rejected {Assert-WatchtideResolutionHash ('A'*64) 'bad'}
Assert-WatchtideResolutionHash ('A'*64) ('a'*64);Assert-Check $true
"Agent resolution repair: $script:checks synthetic checks passed; no real configuration or service changes."
