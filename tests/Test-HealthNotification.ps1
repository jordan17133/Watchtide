$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot '..\windows\Show-WatchtideNotification.ps1'
$tokens=$null;$errors=$null
[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $path),[ref]$tokens,[ref]$errors) | Out-Null
if ($errors.Count) {throw 'Notification helper did not parse.'}
. $path -Mode Library
$script:checks=0
function Assert-Check {param([bool]$Condition) if(-not $Condition){throw 'Notification safety check failed.'};$script:checks++}
function Assert-Rejected {param([scriptblock]$Action) $rejected=$false;try{& $Action | Out-Null}catch{$rejected=$true};Assert-Check $rejected}
foreach ($kind in @('Test','Attention','Unknown','Recovery')) {
    $text=Get-WatchtideNotificationText $kind
    Assert-Check ($text.title.StartsWith('Watchtide') -and $text.title.Length -le 63)
    Assert-Check ($text.body.Length -le 255)
    Assert-Check (($text | ConvertTo-Json -Compress) -notmatch 'https?://|password=|[A-Z]:\\|100\.\d')
}
Assert-Check ((Get-WatchtideNotificationText Test).body -match 'No security incident')
Assert-Check ((Get-WatchtideNotificationText Recovery).body -match 'not proved recovered')
Assert-Rejected {Get-WatchtideNotificationText 'private-message'}
$script:waits=0;$script:icon=$null;$script:failShow=$false;$script:failWait=$false
function New-WatchtideNotificationIcon {
    $script:icon=[pscustomobject]@{Visible=$false;BalloonTipTitle='';BalloonTipText='';disposed=$false;calls=0}
    $script:icon | Add-Member -MemberType ScriptMethod -Name ShowBalloonTip -Value {
        param($Milliseconds)
        $this.calls++
        if($script:failShow){throw 'Synthetic API failure'}
    }
    $script:icon | Add-Member -MemberType ScriptMethod -Name Dispose -Value {$this.disposed=$true}
    return $script:icon
}
function Wait-WatchtideNotification {param($Seconds) $script:waits++;if($script:failWait){throw 'Synthetic wait failure'}}
$result=Show-WatchtideLocalNotification Test
Assert-Check ($script:icon.calls -eq 1 -and $script:waits -eq 1)
Assert-Check ($script:icon.disposed -and -not $script:icon.Visible)
Assert-Check ($result.api_accepted -and -not $result.display_confirmed -and -not $result.user_confirmed)
Assert-Check (-not $result.schedule_created -and -not $result.registry_registration -and -not $result.permissions_changed)
$script:failShow=$true
Assert-Rejected {Show-WatchtideLocalNotification Attention}
Assert-Check ($script:icon.disposed -and -not $script:icon.Visible)
$script:failShow=$false;$script:failWait=$true
Assert-Rejected {Show-WatchtideLocalNotification Unknown}
Assert-Check ($script:icon.disposed -and -not $script:icon.Visible)
Assert-Rejected {Show-WatchtideLocalNotification Test -DisplaySeconds 100}
"Local notification: $script:checks synthetic checks passed; no real notifications, registration or tasks."
