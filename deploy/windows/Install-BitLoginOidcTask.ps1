$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$taskName = 'BIT101-BIT-Login-OIDC-Pilot'
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$startScript = Join-Path $root 'Start-BitLoginOidc.ps1'
$arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $startScript
$action = New-ScheduledTaskAction -Execute $powershell -Argument $arguments -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\LOCAL SERVICE' -LogonType ServiceAccount
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings | Out-Null
Write-Output "Registered startup task $taskName."
