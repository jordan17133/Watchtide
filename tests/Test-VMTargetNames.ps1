$ErrorActionPreference = 'Stop'
$script:checks = 0
function Assert-Check {
    param([bool]$Condition)
    if (-not $Condition) { throw 'VM target contract check failed.' }
    $script:checks++
}

$root = Split-Path $PSScriptRoot -Parent
$specs = @(
    @{Path='Create-SentinelGridWazuhVM.ps1'; Commands=@{ 'Get-VM'='Name'; 'New-VM'='Name' }; Targets=2},
    @{Path='Grow-SentinelGridVMDisk.ps1'; Commands=@{ 'Get-VM'='Name'; 'Get-VMHardDiskDrive'='VMName'; 'Get-VMCheckpoint'='VMName' }; Targets=4},
    @{Path='windows\Get-WatchtideAgentDiagnostic.ps1'; Commands=@{ 'Get-VMNetworkAdapter'='VMName' }; Targets=1}
)

foreach ($spec in $specs) {
    $tokens=$null; $errors=$null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $root $spec.Path), [ref]$tokens, [ref]$errors)
    Assert-Check ($errors.Count -eq 0)
    $parameter = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'VMName' })
    Assert-Check ($parameter.Count -eq 1)
    Assert-Check ($parameter[0].DefaultValue.SafeGetValue() -eq 'Watchtide')

    # Evaluate only parameter binding, never the VM-creating/resizing script body.
    $binding = [scriptblock]::Create($ast.ParamBlock.Extent.Text + "`n`$VMName")
    Assert-Check ((& $binding) -eq 'Watchtide')
    Assert-Check ((& $binding -VMName 'Legacy-Lab') -eq 'Legacy-Lab')
    $rejected=$false
    try { & $binding -VMName '' | Out-Null } catch { $rejected=$true }
    Assert-Check $rejected
    foreach ($invalid in @('*','Lab?','Lab[1]','   ')) {
        $rejected=$false
        try { & $binding -VMName $invalid | Out-Null } catch { $rejected=$true }
        Assert-Check $rejected
    }

    $commands = $ast.FindAll({param($node)
        $node -is [Management.Automation.Language.CommandAst]
    }, $true)
    $targets = 0
    foreach ($command in $commands) {
        $name = $command.GetCommandName()
        if (-not $name -or -not $spec.Commands.ContainsKey($name)) { continue }
        $argument = $spec.Commands[$name]
        $elements = $command.CommandElements
        for ($i=0; $i -lt $elements.Count; $i++) {
            if ($elements[$i] -is [Management.Automation.Language.CommandParameterAst] -and
                $elements[$i].ParameterName -eq $argument) {
                $value = if ($elements[$i].Argument) { $elements[$i].Argument } else { $elements[$i+1] }
                Assert-Check ($value -is [Management.Automation.Language.VariableExpressionAst])
                Assert-Check ($value.VariablePath.UserPath -eq 'VMName')
                $targets++
            }
        }
    }
    Assert-Check ($targets -eq $spec.Targets)
    $assignments = @($ast.FindAll({param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and
        $node.Left.VariablePath.UserPath -eq 'VMName'
    }, $true))
    Assert-Check ($assignments.Count -eq 0)
}

$creation = Get-Content -LiteralPath (Join-Path $root 'Create-SentinelGridWazuhVM.ps1') -Raw
Assert-Check ($creation.Contains('C:\Hyper-V\SentinelGrid-Wazuh'))
Assert-Check ($creation.Contains('SentinelGrid-Wazuh.vhdx'))
"VM target names: $script:checks checks passed; parameter binding and AST only, no Hyper-V operations."
