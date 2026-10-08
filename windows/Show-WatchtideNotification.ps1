<#
Preview is the default. Test shows one fixed generic notification, then disposes
the temporary tray icon. No task, registry registration, permissions or SOC
settings change. Windows notification settings can hide the balloon.
#>
[CmdletBinding()]
param([ValidateSet('Preview','Test','Library')][string]$Mode='Preview')
$ErrorActionPreference='Stop'

function Get-WatchtideNotificationText {
    param([ValidateSet('Test','Attention','Unknown','Recovery')][string]$Kind)
    $messages=@{
        Test=@{title='Watchtide notification test';body='One-time local delivery test. No security incident.'}
        Attention=@{title='Watchtide: collection needs review';body='A freshness or loss check needs review. This is not a confirmed security incident.'}
        Unknown=@{title='Watchtide: collection check unavailable';body='Some monitoring evidence is unavailable. Inspect the local check; no incident verdict is implied.'}
        Recovery=@{title='Watchtide: observations recovered';body='Checked observations are recent again. Earlier missing events are not proved recovered.'}
    }
    return [pscustomobject]$messages[$Kind]
}

function New-WatchtideNotificationIcon {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $icon=[Windows.Forms.NotifyIcon]::new()
    try {
        $icon.Icon=[Drawing.SystemIcons]::Information
        $icon.Text='Watchtide'
        return $icon
    } catch {$icon.Dispose();throw}
}

function Wait-WatchtideNotification {
    param([ValidateRange(1,10)][int]$Seconds)
    $timer=[Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt $Seconds) {
        [Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 100
    }
}

function Show-WatchtideLocalNotification {
    param([ValidateSet('Test','Attention','Unknown','Recovery')][string]$Kind,
          [ValidateRange(1,10)][int]$DisplaySeconds=8)
    if (-not [Environment]::UserInteractive) {throw 'An interactive user session is required.'}
    $text=Get-WatchtideNotificationText $Kind
    $icon=$null
    try {
        $icon=New-WatchtideNotificationIcon
        $icon.BalloonTipTitle=$text.title
        $icon.BalloonTipText=$text.body
        $icon.Visible=$true
        $icon.ShowBalloonTip($DisplaySeconds*1000)
        Wait-WatchtideNotification $DisplaySeconds
    } finally {
        if ($null -ne $icon) {
            try {$icon.Visible=$false} finally {$icon.Dispose()}
        }
    }
    return [pscustomobject]@{kind=$Kind;api_accepted=$true;display_confirmed=$false
        user_confirmed=$false;temporary_icon_disposed=$true;schedule_created=$false
        registry_registration=$false;permissions_changed=$false}
}

if ($Mode -eq 'Library') {return}
if ($Mode -eq 'Preview') {
    Get-WatchtideNotificationText Test | ConvertTo-Json -Compress
    return
}
try {
    Show-WatchtideLocalNotification Test | ConvertTo-Json -Compress
    'ONE_TIME_NOTIFICATION_API_ACCEPTED'
} catch {
    @{api_accepted=$false;display_confirmed=$false;schedule_created=$false;registry_registration=$false} |
        ConvertTo-Json -Compress
    throw 'Notification test unavailable; inspect locally. Do not assume delivery.'
}
