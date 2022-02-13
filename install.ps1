############################################################
# Author      : Jerzy 'Yuri' Kramarz (op7ic)               #
# Version     : 1.0                                        #
# Type        : PowerShell                                 #
# Description : Loki2WinEVTX. See README.md for details    # 
############################################################

# Create Program Files directories
$Loki2WindowsEventLogDir = "$env:ProgramFiles\Loki2WindowsEventLog"
$Loki2WindowsEventLogging = "$Loki2WindowsEventLogDir\logs"
If(!(test-path $Loki2WindowsEventLogDir)) {
  New-Item -ItemType Directory -Force -Path $Loki2WindowsEventLogDir
}

If(!(test-path $Loki2WindowsEventLogging)) {
  New-Item -ItemType Directory -Force -Path $Loki2WindowsEventLogging
}


$lokizipPath = "$Loki2WindowsEventLogDir\loki.zip"
if(!(test-path $lokizipPath)) {
  # Requires TLS 1.2
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri "https://github.com/Neo23x0/Loki/releases/download/v0.44.2/loki_0.44.2.zip" -OutFile "$lokizipPath"
}
Expand-Archive -Path $lokizipPath -DestinationPath $Loki2WindowsEventLogDir -Force
Set-Location -Path $Loki2WindowsEventLogDir\loki
$codebuffer = @'
# Author: Jerzy 'Yuri' Kramarz
# Setup our event log so Loki CSV events can go there directly. Ignore if already exist
$logfileExists = Get-Eventlog -list | Where-Object {$_.logdisplayname -eq "LokiEvents"}
if (! $logfileExists) {
  New-EventLog -LogName LokiEvents -Source LokiEvents
}

$Loki2WindowsEventLogDir = "$env:ProgramFiles\Loki2WindowsEventLog"
Set-Location -Path $Loki2WindowsEventLogDir\loki
$Loki2WindowsEventLogging = "$Loki2WindowsEventLogDir\logs"
$lokibin = "$Loki2WindowsEventLogDir\loki\loki.exe"
$lokiupgrader = "$Loki2WindowsEventLogDir\loki\loki-upgrader.exe"
$lokiparams = "--nolog --csv --nofilescan"
$lokioutputcsv = "$Loki2WindowsEventLogging\lokioutput.csv"

$proc = Start-Process -FilePath $lokibin -ArgumentList $lokiparams -RedirectStandardOut $lokioutputcsv -WindowStyle hidden -Passthru
$proc.WaitForExit()

$loki_csv_lines = Get-Content $lokioutputcsv

Foreach ($item in $loki_csv_lines) {
  $item = $(Write-Output $item  | Out-String -Width 1000 | Select-String -Pattern "NOTICE","ALERT","WARNING","RESULT")
  Write-EventLog -LogName LokiEvents -Source LokiEvents -EntryType Information -EventId 1 -Message $item
}
'@
$codebuffer | Out-File "$Loki2WindowsEventLogDir\loki2wineventlog.ps1"

$shortPath = (New-Object -ComObject Scripting.FileSystemObject).GetFile("$Loki2WindowsEventLogDir\loki2wineventlog.ps1").ShortPath 
# Setup reoccuring task for our execution of pesieve
$TASK = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle hidden -nop -exec bypass $shortPath"
$TRIGGER = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 180)
$TASK_PERMISSIONS = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest -LogonType ServiceAccount
Register-ScheduledTask -TaskName "LokiToWinEventLog" -Action $TASK -Trigger $TRIGGER -Principal $TASK_PERMISSIONS
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -RestartCount 1 -StartWhenAvailable
Set-ScheduledTask -TaskName "LokiToWinEventLog" -Settings $settings