$ScriptPath = "update_signature.ps1"

$Action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -File `"$ScriptPath`""

$Trigger = New-ScheduledTaskTrigger -Daily -At 3am

Register-ScheduledTask -TaskName "ClamAV-Signature-Updater" `
    -Action $Action -Trigger $Trigger -RunLevel Highest -Force

Write-Host "Scheduled task installed successfully."