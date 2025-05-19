# Author      : Jerzy 'Yuri' Kramarz (op7ic)
# Version     : 1.5
# Type        : PowerShell
# Description : Loki2WinEVTX - Installs and runs Loki scanner, logs results to Windows Event Log
# Notes       : Run as Administrator to ensure access to ProgramData directory
# Parameters  : Configurable options for paths, intervals, and Loki version

param (
    [string]$InstallDir = "$env:ProgramData\Loki2WindowsEventLog",
    [string]$LogDir = "$InstallDir\logs",
    [string]$LokiVersion = "latest", # Use "latest" or specific version (e.g., "0.51.0")
    [int]$TaskIntervalMinutes = 180,
    [int]$EventLogSizeMB = 100 # Size limit for LokiEvents log
)

# Logging function
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    $logFile = "$LogDir\loki2wineventlog.log"
    
    # Ensure log directory exists
    if (!(Test-Path $LogDir)) {
        try {
            New-Item -ItemType Directory -Force -Path $LogDir -ErrorAction Stop
        }
        catch {
            Write-Error "Cannot create log directory ${LogDir}: $_"
            return
        }
    }
    
    try {
        Write-Output $logMessage | Out-File -FilePath $logFile -Append -Encoding utf8 -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to write to log file ${logFile}: $_"
    }
    if ($Level -eq "ERROR") { Write-Error $logMessage }
    else { Write-Host $logMessage }
}

# Check for administrative privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Log "This script must be run as Administrator. Exiting." -Level ERROR
    exit 1
}

# Create directories
try {
    if (!(Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Force -Path $InstallDir -ErrorAction Stop
        Write-Log "Created directory: $InstallDir"
    }
    if (!(Test-Path $LogDir)) {
        New-Item -ItemType Directory -Force -Path $LogDir -ErrorAction Stop
        Write-Log "Created log directory: $LogDir"
    }
}
catch {
    Write-Log "Failed to create directories: $_" -Level ERROR
    Write-Error "Cannot proceed without creating $InstallDir or $LogDir. Ensure you have permissions."
    exit 1
}

# Create LokiEvents event log
try {
    $logfileExists = Get-Eventlog -List | Where-Object { $_.logdisplayname -eq "LokiEvents" }
    if (!$logfileExists) {
        Write-Log "Creating LokiEvents event log"
        New-EventLog -LogName LokiEvents -Source LokiEvents -ErrorAction Stop
        # Wait briefly to ensure log is registered
        Start-Sleep -Seconds 2
        # Verify creation
        $logfileExists = Get-Eventlog -List | Where-Object { $_.logdisplayname -eq "LokiEvents" }
        if (!$logfileExists) {
            throw "LokiEvents event log was not created successfully"
        }
        Write-Log "Created LokiEvents event log"
    }
    else {
        Write-Log "LokiEvents event log already exists"
    }
}
catch {
    Write-Log "Failed to create or verify LokiEvents event log: $_" -Level ERROR
    exit 1
}

# Configure Event Log size
try {
    Write-Log "Configuring LokiEvents log size to $EventLogSizeMB MB"
    $eventLog = Get-EventLog -LogName LokiEvents -ErrorAction Stop
    Limit-EventLog -LogName LokiEvents -MaximumSize ($EventLogSizeMB * 1MB) -ErrorAction Stop
    Write-Log "Set LokiEvents log size to $EventLogSizeMB MB"
}
catch {
    Write-Log "Cannot configure LokiEvents log size (log may not be fully registered yet): $_" -Level WARNING
}

# Download Loki
$lokiZipPath = "$InstallDir\loki.zip"
$lokibin = "$InstallDir\loki\loki.exe"
if (!(Test-Path $lokibin)) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if ($LokiVersion -eq "latest") {
            $releaseInfo = Invoke-RestMethod -Uri "https://api.github.com/repos/Neo23x0/Loki/releases/latest" -ErrorAction Stop
            $downloadUrl = $releaseInfo.assets | Where-Object { $_.name -like "loki_*.zip" } | Select-Object -ExpandProperty browser_download_url
            $LokiVersion = $releaseInfo.tag_name -replace "^v", ""
        }
        else {
            $downloadUrl = "https://github.com/Neo23x0/Loki/releases/download/v$LokiVersion/loki_$LokiVersion.zip"
        }
        Write-Log "Downloading Loki v$LokiVersion from $downloadUrl"
        Invoke-WebRequest -Uri $downloadUrl -OutFile $lokiZipPath -ErrorAction Stop
        Expand-Archive -Path $lokiZipPath -DestinationPath "$InstallDir\loki" -Force -ErrorAction Stop
        Write-Log "Extracted Loki to $InstallDir\loki"
    }
    catch {
        Write-Log "Failed to download or extract Loki: $_" -Level ERROR
        exit 1
    }
}
else {
    Write-Log "Loki already installed at $lokibin, skipping download"
}

# Create embedded script
$embeddedScript = @'
# Author: Jerzy 'Yuri' Kramarz
# Description: Runs Loki and logs results to Windows Event Log

param (
    [string]$InstallDir = "$env:ProgramData\Loki2WindowsEventLog",
    [string]$LogDir = "$InstallDir\logs"
)

# Logging function
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    $logFile = "$LogDir\loki2wineventlog.log"
    
    # Ensure log directory exists
    if (!(Test-Path $LogDir)) {
        try {
            New-Item -ItemType Directory -Force -Path $LogDir -ErrorAction Stop
        }
        catch {
            Write-Error "Cannot create log directory ${LogDir}: $_"
            return
        }
    }
    
    try {
        Write-Output $logMessage | Out-File -FilePath $logFile -Append -Encoding utf8 -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to write to log file ${logFile}: $_"
    }
}

# Run Loki
try {
    $lokibin = "$InstallDir\loki\loki.exe"
    $lokioutputcsv = "$LogDir\lokioutput_$((Get-Date).ToString('yyyyMMdd_HHmmss')).csv"
    $lokiparams = "--nolog --csv --nofilescan"
    
    Write-Log "Starting Loki with params: $lokiparams"
    $proc = Start-Process -FilePath $lokibin -ArgumentList $lokiparams -RedirectStandardOut $lokioutputcsv -WindowStyle Hidden -PassThru -ErrorAction Stop
    $proc.WaitForExit()
    
    if ($proc.ExitCode -ne 0) {
        Write-Log "Loki exited with code $($proc.ExitCode)" -Level ERROR
        exit $proc.ExitCode
    }
    Write-Log "Loki completed, output saved to $lokioutputcsv"
}
catch {
    Write-Log "Failed to run Loki: $_" -Level ERROR
    exit 1
}

# Process CSV output
try {
    $loki_csv = Import-Csv -Path $lokioutputcsv -ErrorAction Stop
    foreach ($item in $loki_csv) {
        if ($item.Type -in @("NOTICE", "ALERT", "WARNING", "RESULT")) {
            $eventMessage = "Type: $($item.Type)`nFile: $($item.File)`nMessage: $($item.Message)"
            $eventId = switch ($item.Type) {
                "ALERT" { 1001 }
                "WARNING" { 1002 }
                "NOTICE" { 1003 }
                "RESULT" { 1004 }
                default { 1 }
            }
            Write-EventLog -LogName LokiEvents -Source LokiEvents -EntryType Information -EventId $eventId -Message $eventMessage -ErrorAction Stop
            Write-Log "Logged event: $eventMessage"
        }
    }
}
catch {
    Write-Log "Failed to process CSV or write to Event Log: $_" -Level ERROR
    exit 1
}
'@
try {
    $embeddedScript | Out-File "$InstallDir\loki2wineventlog.ps1" -Encoding utf8 -ErrorAction Stop
    Write-Log "Created embedded script: $InstallDir\loki2wineventlog.ps1"
}
catch {
    Write-Log "Failed to create embedded script: $_" -Level ERROR
    exit 1
}

# Setup scheduled task
try {
    $shortPath = (New-Object -ComObject Scripting.FileSystemObject).GetFile("$InstallDir\loki2wineventlog.ps1").ShortPath
    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy RemoteSigned $shortPath" -ErrorAction Stop
    $taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $TaskIntervalMinutes) -ErrorAction Stop
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\NETWORK SERVICE" -LogonType ServiceAccount -ErrorAction Stop
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -ExecutionTimeLimit (New-TimeSpan -Hours 2) -RestartCount 1 -StartWhenAvailable -ErrorAction Stop
    
    Register-ScheduledTask -TaskName "LokiToWinEventLog" -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings -Force -ErrorAction Stop
    Write-Log "Registered scheduled task: LokiToWinEventLog"
}
catch {
    Write-Log "Failed to register scheduled task: $_" -Level ERROR
    exit 1
}

# Cleanup old CSV files (older than 30 days)
try {
    if (Test-Path $LogDir) {
        Get-ChildItem -Path $LogDir -Filter "lokioutput_*.csv" -ErrorAction Stop | 
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | 
            Remove-Item -Force -ErrorAction Stop
        Write-Log "Cleaned up old CSV files in $LogDir"
    }
    else {
        Write-Log "Log directory $LogDir does not exist, skipping cleanup"
    }
}
catch {
    Write-Log "Failed to clean up old CSV files: $_" -Level ERROR
}

Write-Log "Loki2WinEVTX setup completed successfully"
