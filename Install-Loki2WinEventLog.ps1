<#
.SYNOPSIS
    Loki to Windows Event Log Integration Tool
.DESCRIPTION
    Downloads, configures, and schedules Loki IOC scanner to scan the system
    and log results to Windows Event Log for security monitoring.
    
    This script integrates Loki (https://github.com/Neo23x0/Loki) by Florian Roth
    with Windows Event Log for continuous IOC (Indicators of Compromise) monitoring.
    
    Loki is licensed under the GNU General Public License v3.0.
.PARAMETER ScanIntervalMinutes
    Interval between scans in minutes (default: 180)
.PARAMETER InstallPath
    Installation directory (default: ProgramData\Loki2WindowsEventLog)
.PARAMETER SkipScheduledTask
    Skip creating the scheduled task
.PARAMETER UpdateOnly
    Only update Loki to latest version without full installation
.PARAMETER Uninstall
    Completely remove Loki2WinEventLog including all configurations and logs
.PARAMETER Status
    Check installation status without making changes
.PARAMETER EventLogSizeMB
    Size limit for LokiEvents log in MB (default: 100)
.EXAMPLE
    .\Install-Loki2WinEventLog.ps1
.EXAMPLE
    .\Install-Loki2WinEventLog.ps1 -ScanIntervalMinutes 360
.EXAMPLE
    .\Install-Loki2WinEventLog.ps1 -UpdateOnly
.EXAMPLE
    .\Install-Loki2WinEventLog.ps1 -Uninstall
.EXAMPLE
    .\Install-Loki2WinEventLog.ps1 -Status
.NOTES
    Original Author: Jerzy 'Yuri' Kramarz (op7ic)
    Version: 2.0
    
    Loki Author: Florian Roth (Neo23x0)
    Loki GitHub: https://github.com/Neo23x0/Loki
    Loki License: GNU General Public License v3.0
    
    Requires: Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(30, 1440)]
    [int]$ScanIntervalMinutes = 180,
    
    [Parameter()]
    [string]$InstallPath = "$env:ProgramFiles\Loki2WindowsEventLog",
    
    [Parameter()]
    [switch]$SkipScheduledTask,
    
    [Parameter()]
    [switch]$UpdateOnly,
    
    [Parameter()]
    [switch]$Uninstall,
    
    [Parameter()]
    [switch]$Status,
    
    [Parameter()]
    [ValidateRange(10, 1000)]
    [int]$EventLogSizeMB = 100
)

#Requires -RunAsAdministrator
#Requires -Version 5.1


# Parameter validation
if ($Uninstall -and ($UpdateOnly -or $SkipScheduledTask -or $Status)) {
    Write-Error "Cannot use -Uninstall with other operation parameters"
    exit 1
}

if ($Status -and ($UpdateOnly -or $SkipScheduledTask -or $Uninstall)) {
    Write-Error "Cannot use -Status with other operation parameters"
    exit 1
}

if ($UpdateOnly -and $SkipScheduledTask) {
    Write-Error "Cannot use -UpdateOnly with -SkipScheduledTask"
    exit 1
}

# Script configuration
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'Continue'

# Initialize logging
$scriptLog = "$env:TEMP\Loki2WinEventLog_Install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

#Add Exception
Add-MpPreference -ExclusionPath $InstallPath

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to console with color
    switch ($Level) {
        'Warning' { Write-Warning $Message }
        'Error' { Write-Error $Message -ErrorAction Continue }
        default { Write-Host $Message -ForegroundColor Green }
    }
    
    # Write to log file
    Add-Content -Path $scriptLog -Value $logEntry -Force
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-LokiLatestDownloadInfo {
    Write-Log "Fetching latest Loki release information from GitHub"
    
    try {
        # Enable TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        # Get latest release info from GitHub API
        $apiUrl = "https://api.github.com/repos/Neo23x0/Loki/releases/latest"
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "Loki2WinEventLog")
        $releaseJson = $webClient.DownloadString($apiUrl)
        $release = $releaseJson | ConvertFrom-Json
        
        # Find the Loki zip asset
        $asset = $release.assets | Where-Object { $_.name -like "loki_*.zip" }
        
        if (-not $asset) {
            throw "Could not find Loki zip file in latest release"
        }
        
        $version = $release.tag_name -replace "^v", ""
        Write-Log "Found latest version: $version"
        
        return @{
            Version = $version
            Url = $asset.browser_download_url
            FileName = "loki.zip"
            ReleaseDate = $release.published_at
        }
    }
    catch {
        Write-Log "Failed to fetch latest release info: $_" -Level Error
        throw
    }
    finally {
        if ($webClient) { $webClient.Dispose() }
    }
}

function Install-Loki {
    param(
        [string]$TargetPath
    )
    
    Write-Log "Installing latest Loki version"
    
    $downloadInfo = Get-LokiLatestDownloadInfo
    $zipFile = Join-Path $TargetPath $downloadInfo.FileName
    $lokiDir = Join-Path $TargetPath "loki"
    $lokiExe = Join-Path $lokiDir "loki.exe"
    $versionFile = Join-Path $TargetPath "loki.version"
    
    # Check if update is needed
    $needsUpdate = $true
    if (Test-Path $lokiExe) {
        Write-Log "Loki already exists at $lokiExe, checking for updates..." -Level Warning
        
        if (Test-Path $versionFile) {
            $currentVersion = Get-Content $versionFile -ErrorAction SilentlyContinue
            Write-Log "Current version: $currentVersion"
            Write-Log "Latest version: $($downloadInfo.Version)"
            
            if ($currentVersion -eq $downloadInfo.Version) {
                Write-Log "Already running latest version, skipping download"
                $needsUpdate = $false
            }
        } else {
            Write-Log "Version file not found, will download latest version"
        }
    }
    
    if ($needsUpdate) {
        try {
            Write-Log "Downloading Loki from $($downloadInfo.Url)"
            Write-Log "Version: $($downloadInfo.Version)"
            
            # Download to temp file first
            $tempFile = "$zipFile.tmp"
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($downloadInfo.Url, $tempFile)
            
            if (Test-Path $tempFile) {
                # Backup existing installation if present
                if (Test-Path $lokiDir) {
                    $backupDir = "$lokiDir.backup"
                    Write-Log "Creating backup of existing Loki installation"
                    if (Test-Path $backupDir) {
                        Remove-Item -Path $backupDir -Recurse -Force
                    }
                    Move-Item -Path $lokiDir -Destination $backupDir -Force
                }
                
                # Move temp file to zip file for extraction
                if (Test-Path $zipFile) {
                    Remove-Item -Path $zipFile -Force
                }
                Move-Item -Path $tempFile -Destination $zipFile -Force
                
                # Extract from zip file
                Write-Log "Extracting Loki..."
                Expand-Archive -Path $zipFile -DestinationPath $TargetPath -Force
                
                # Check if Loki was extracted to a subfolder (common with GitHub releases)
                $extractedFolders = Get-ChildItem -Path $TargetPath -Directory | Where-Object { $_.Name -like "loki*" -or $_.Name -like "Loki*" }
                if ($extractedFolders -and -not (Test-Path $lokiExe)) {
                    # Move contents from subfolder to loki directory
                    $sourceFolder = $extractedFolders[0].FullName
                    Write-Log "Moving Loki files from $sourceFolder to $lokiDir"
                    
                    if (-not (Test-Path $lokiDir)) {
                        New-Item -ItemType Directory -Path $lokiDir -Force | Out-Null
                    }
                    
                    Get-ChildItem -Path $sourceFolder -Recurse | Move-Item -Destination $lokiDir -Force
                    Remove-Item -Path $sourceFolder -Force -Recurse
                }
                
                # Verify extraction - check multiple possible locations
                $possibleExePaths = @(
                    (Join-Path $lokiDir "loki.exe"),
                    (Join-Path $TargetPath "loki.exe"),
                    (Join-Path $lokiDir "loki-windows.exe")
                )
                
                $lokiFound = $false
                foreach ($exePath in $possibleExePaths) {
                    if (Test-Path $exePath) {
                        $lokiFound = $true
                        # Rename to standard name if needed
                        if ($exePath -ne $lokiExe) {
                            Move-Item -Path $exePath -Destination $lokiExe -Force
                        }
                        break
                    }
                }
                
                if ($lokiFound) {
                    Write-Log "Successfully installed Loki to $lokiDir"
                    
                    # Store version info
                    $downloadInfo.Version | Out-File -FilePath $versionFile -Encoding UTF8
                    
                    # Remove backup if successful
                    if (Test-Path "$lokiDir.backup") {
                        Remove-Item -Path "$lokiDir.backup" -Recurse -Force
                    }
                    
                    Write-Log "Update completed successfully"
                } else {
                    throw "Loki.exe not found after extraction. Please check the archive structure."
                }
            } else {
                throw "Download completed but temp file not found"
            }
        }
        catch {
            Write-Log "Failed to download/install Loki: $_" -Level Error
            
            # Check for common issues
            if ($_.Exception.Message -like "*virus*" -or $_.Exception.Message -like "*threat*") {
                Write-Log "NOTE: Antivirus software may be blocking Loki. Please add an exclusion for: $TargetPath" -Level Warning
                Write-Host "`nIMPORTANT: Your antivirus software may be blocking Loki." -ForegroundColor Yellow
                Write-Host "Loki is a legitimate security tool but may trigger false positives." -ForegroundColor Yellow
                Write-Host "Please add an exclusion for: $TargetPath" -ForegroundColor Yellow
            }
            
            # Restore backup if exists
            if (Test-Path "$lokiDir.backup") {
                Write-Log "Restoring backup due to installation failure"
                if (Test-Path $lokiDir) {
                    Remove-Item -Path $lokiDir -Recurse -Force
                }
                Move-Item -Path "$lokiDir.backup" -Destination $lokiDir -Force
            }
            
            throw
        }
        finally {
            if ($webClient) { $webClient.Dispose() }
            
            # Clean up temp files
            if (Test-Path "$zipFile.tmp") {
                Remove-Item -Path "$zipFile.tmp" -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    return $lokiExe
}

function Initialize-EventLog {
    Write-Log "Initializing Windows Event Log for Loki"
    
    try {
        # Check if event log exists using Get-WinEvent
        $logExists = $false
        try {
            $null = Get-WinEvent -ListLog "LokiEvents" -ErrorAction Stop
            $logExists = $true
        }
        catch {
            # Log doesn't exist
        }
        
        if (-not $logExists) {
            Write-Log "Creating new event log: LokiEvents"
            New-EventLog -LogName "LokiEvents" -Source "LokiEvents" -ErrorAction Stop
            
            # Set log properties
            Start-Sleep -Seconds 2  # Wait for log to be registered
            Limit-EventLog -LogName "LokiEvents" -MaximumSize ($EventLogSizeMB * 1MB) -ErrorAction Stop
            
            Write-Log "Event log created successfully with size limit of $EventLogSizeMB MB"
        } else {
            Write-Log "Event log 'LokiEvents' already exists"
            # Update size if needed
            try {
                Limit-EventLog -LogName "LokiEvents" -MaximumSize ($EventLogSizeMB * 1MB) -ErrorAction Stop
                Write-Log "Updated event log size limit to $EventLogSizeMB MB"
            } catch {
                Write-Log "Could not update event log size limit" -Level Warning
            }
        }
    }
    catch {
        Write-Log "Failed to initialize event log: $_" -Level Error
        throw
    }
}

function New-ScannerScript {
    param([string]$TargetPath)
    
    Write-Log "Creating scanner script"
    
    $scriptContent = @'
<#
.SYNOPSIS
    Loki Scanner Script
.DESCRIPTION
    Runs Loki IOC scanner and logs results to Windows Event Log
#>

param(
    [string]$LokiPath = "$env:ProgramFiles\Loki2WindowsEventLog\loki\loki.exe",
    [string]$LogPath = "$env:ProgramFiles\Loki2WindowsEventLog\logs",
    [switch]$QuickScan,
    [switch]$UpdateSignatures
)

# Ensure log directory exists
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# Clean up old CSV files (older than 30 days)
Get-ChildItem -Path $LogPath -Filter "lokioutput_*.csv" -ErrorAction SilentlyContinue | 
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | 
    Remove-Item -Force

# Validate Loki exists
if (-not (Test-Path $LokiPath)) {
    Write-EventLog -LogName "LokiEvents" -Source "LokiEvents" -EntryType Error -EventId 9999 -Message "Loki executable not found at: $LokiPath"
    exit 1
}

# Update signatures if requested
if ($UpdateSignatures) {
    Write-EventLog -LogName "LokiEvents" -Source "LokiEvents" -EntryType Information -EventId 100 -Message "Updating Loki signatures..."
    
    try {
        $updateProcess = Start-Process -FilePath $LokiPath -ArgumentList "--update" -WindowStyle Hidden -PassThru -Wait
        if ($updateProcess.ExitCode -eq 0) {
            Write-EventLog -LogName "LokiEvents" -Source "LokiEvents" -EntryType Information -EventId 101 -Message "Loki signatures updated successfully"
        } else {
            Write-EventLog -LogName "LokiEvents" -Source "LokiEvents" -EntryType Warning -EventId 102 -Message "Loki signature update failed with exit code: $($updateProcess.ExitCode)"
        }
    }
    catch {
        Write-EventLog -LogName "LokiEvents" -Source "LokiEvents" -EntryType Error -EventId 103 -Message "Failed to update Loki signatures: $_"
    }
}

# Prepare Loki parameters
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$csvOutput = Join-Path $LogPath "lokioutput_$timestamp.csv"

# Base parameters
$lokiParams = @("--nolog", "--csv", "-p", $LogPath)

if ($QuickScan) {
    # Quick scan - only check running processes and key directories
    $lokiParams += @("--onlyrelevant", "--noprocscan", "--nofilescan")
    Write-EventLog -LogName "LokiEvents" -Source "LokiEvents" -EntryType Information -EventId 1100 -Message "Starting Loki quick scan"
} else {
    # Full scan - exclude file scanning for performance (can be customized)
    $lokiParams += "--nofilescan"
    Write-EventLog -LogName "LokiEvents" -Source "LokiEvents" -EntryType Information -EventId 1000 -Message "Starting Loki full system scan"
}

# Run Loki
try {
    $scanStart = Get-Date
    $proc = Start-Process -FilePath $LokiPath -ArgumentList $lokiParams -RedirectStandardOutput $csvOutput -WindowStyle Hidden -PassThru
    
    # Wait for completion with timeout (2 hours for full scan, 30 minutes for quick)
    $timeout = if ($QuickScan) { 1800 } else { 7200 }
    if (-not $proc.WaitForExit($timeout * 1000)) {
        $proc.Kill()
        throw "Loki scan timeout after $($timeout/60) minutes"
    }
    
    $scanDuration = (Get-Date) - $scanStart
    $exitCode = $proc.ExitCode
    
    if ($exitCode -ne 0) {
        Write-EventLog -LogName "LokiEvents" -Source "LokiEvents" -EntryType Warning -EventId 1999 `
            -Message "Loki scan completed with warnings. Exit code: $exitCode. Duration: $($scanDuration.TotalMinutes) minutes"
    }
}
catch {
    Write-EventLog -LogName "LokiEvents" -Source "LokiEvents" -EntryType Error -EventId 9998 -Message "Loki scan failed: $_"
    exit 1
}

# Process CSV output
try {
    if (Test-Path $csvOutput) {
        $csvData = Import-Csv -Path $csvOutput -ErrorAction Stop
        $alertCount = 0
        $warningCount = 0
        $noticeCount = 0
        
        foreach ($entry in $csvData) {
            if ($entry.Type -in @("NOTICE", "ALERT", "WARNING", "RESULT")) {
                $eventMessage = @"
Type: $($entry.Type)
Timestamp: $($entry.Timestamp)
Module: $($entry.Module)
Message: $($entry.Message)
File: $($entry.File)
Score: $($entry.Score)
Reference: $($entry.Reference)
"@
                
                # Determine event ID and type based on severity
                $eventId = switch ($entry.Type) {
                    "ALERT"   { $alertCount++; 2001 }
                    "WARNING" { $warningCount++; 2002 }
                    "NOTICE"  { $noticeCount++; 2003 }
                    "RESULT"  { 2004 }
                    default   { 2000 }
                }
                
                $entryType = switch ($entry.Type) {
                    "ALERT"   { "Error" }
                    "WARNING" { "Warning" }
                    default   { "Information" }
                }
                
                Write-EventLog -LogName "LokiEvents" -Source "LokiEvents" -EntryType $entryType -EventId $eventId -Message $eventMessage
            }
        }
        
        # Log summary
        $summaryMessage = @"
Loki scan completed successfully
Duration: $($scanDuration.TotalMinutes) minutes
Total Alerts: $alertCount
Total Warnings: $warningCount
Total Notices: $noticeCount
Output saved to: $csvOutput
"@
        
        $summaryEventId = if ($QuickScan) { 1101 } else { 1001 }
        Write-EventLog -LogName "LokiEvents" -Source "LokiEvents" -EntryType Information -EventId $summaryEventId -Message $summaryMessage
        
        # Remove CSV if no findings
        if ($alertCount -eq 0 -and $warningCount -eq 0 -and $noticeCount -eq 0) {
            Remove-Item -Path $csvOutput -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-EventLog -LogName "LokiEvents" -Source "LokiEvents" -EntryType Warning -EventId 1998 -Message "Loki CSV output file not found: $csvOutput"
    }
}
catch {
    Write-EventLog -LogName "LokiEvents" -Source "LokiEvents" -EntryType Error -EventId 9997 -Message "Failed to process Loki output: $_"
}
'@

    $scriptPath = Join-Path $TargetPath "LokiScannerJob.ps1"
    
    try {
        $scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8 -Force
        Write-Log "Scanner script created at: $scriptPath"
        return $scriptPath
    }
    catch {
        Write-Log "Failed to create scanner script: $_" -Level Error
        throw
    }
}

function Install-ScheduledTask {
    param(
        [string]$ScriptPath,
        [int]$IntervalMinutes
    )
    
    Write-Log "Installing scheduled task"
    
    $taskName = "LokiToWinEventLog"
    
    try {
        # Check if task exists
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        
        if ($existingTask) {
            Write-Log "Scheduled task already exists, updating..." -Level Warning
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
        
        # Create task action
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""
        
        # Create trigger
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
        
        # Create principal (using NETWORK SERVICE for Loki)
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\NETWORK SERVICE" -LogonType ServiceAccount
        
        # Create settings
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -Hidden `
            -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
            -RestartCount 3 `
            -RestartInterval (New-TimeSpan -Minutes 1) `
            -StartWhenAvailable
        
        # Register task
        $task = Register-ScheduledTask `
            -TaskName $taskName `
            -Action $action `
            -Trigger $trigger `
            -Principal $principal `
            -Settings $settings `
            -Description "Runs Loki IOC scanner and logs results to Windows Event Log"
        
        Write-Log "Scheduled task created successfully"
        
        # Don't start immediately - let it run on schedule
        Write-Log "Scheduled task will start at next scheduled time"
        Write-Log "To manually start the scan, run: Start-ScheduledTask -TaskName '$taskName'"
        
    }
    catch {
        Write-Log "Failed to create scheduled task: $_" -Level Error
        throw
    }
}

function Get-InstallationStatus {
    param([string]$InstallPath)
    
    Write-Host "`n=== Loki2WinEventLog Status Check ===" -ForegroundColor Cyan
    Write-Host "Installation path: $InstallPath" -ForegroundColor Gray
    Write-Host ""
    
    $status = @{
        InstallationExists = $false
        LokiVersion = "Not installed"
        ConfigurationValid = $false
        EventLogExists = $false
        ScheduledTaskExists = $false
        LastScanTime = "Never"
        NextScanTime = "N/A"
        AlertsLast24h = 0
        WarningsLast24h = 0
    }
    
    # Check installation directory
    if (Test-Path $InstallPath) {
        $status.InstallationExists = $true
        Write-Host "✓ Installation directory exists" -ForegroundColor Green
        
        # Check Loki version
        $versionFile = Join-Path $InstallPath "loki.version"
        if (Test-Path $versionFile) {
            $status.LokiVersion = Get-Content $versionFile
            Write-Host "✓ Loki version: $($status.LokiVersion)" -ForegroundColor Green
        }
        
        # Check Loki executable
        $lokiExe = Join-Path $InstallPath "loki\loki.exe"
        if (Test-Path $lokiExe) {
            $fileInfo = Get-Item $lokiExe
            Write-Host "✓ Loki executable exists (Size: $([math]::Round($fileInfo.Length/1MB, 2)) MB)" -ForegroundColor Green
        } else {
            Write-Host "✗ Loki executable not found" -ForegroundColor Red
        }
        
        # Check configuration
        $configPath = Join-Path $InstallPath "config\configuration.json"
        if (Test-Path $configPath) {
            try {
                $config = Get-Content $configPath | ConvertFrom-Json
                if ($config.Version -and $config.ScanInterval) {
                    $status.ConfigurationValid = $true
                    Write-Host "✓ Configuration valid (Scan interval: $($config.ScanInterval) minutes)" -ForegroundColor Green
                }
            } catch {}
        }
    } else {
        Write-Host "✗ Installation not found at $InstallPath" -ForegroundColor Red
        return $status
    }
    
    # Check Event Log
    try {
        $null = Get-WinEvent -ListLog "LokiEvents" -ErrorAction Stop
        $status.EventLogExists = $true
        Write-Host "✓ Event log exists" -ForegroundColor Green
        
        # Get alert/warning count
        $last24h = (Get-Date).AddDays(-1)
        $alerts = Get-WinEvent -FilterHashtable @{LogName='LokiEvents'; ID=2001; StartTime=$last24h} -ErrorAction SilentlyContinue
        $warnings = Get-WinEvent -FilterHashtable @{LogName='LokiEvents'; ID=2002; StartTime=$last24h} -ErrorAction SilentlyContinue
        
        if ($alerts) { $status.AlertsLast24h = $alerts.Count }
        if ($warnings) { $status.WarningsLast24h = $warnings.Count }
    }
    catch {
        Write-Host "✗ Event log not found" -ForegroundColor Red
    }
    
    # Check Scheduled Task
    try {
        $task = Get-ScheduledTask -TaskName "LokiToWinEventLog" -ErrorAction Stop
        $status.ScheduledTaskExists = $true
        Write-Host "✓ Scheduled task exists (State: $($task.State))" -ForegroundColor $(if ($task.State -eq 'Ready') { 'Green' } else { 'Yellow' })
        
        $taskInfo = Get-ScheduledTaskInfo -TaskName "LokiToWinEventLog" -ErrorAction SilentlyContinue
        if ($taskInfo) {
            $status.LastScanTime = $taskInfo.LastRunTime
            $status.NextScanTime = $taskInfo.NextRunTime
        }
    }
    catch {
        Write-Host "✗ Scheduled task not found" -ForegroundColor Red
    }
    
    # Summary
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Last Scan: $($status.LastScanTime)" -ForegroundColor White
    Write-Host "Next Scan: $($status.NextScanTime)" -ForegroundColor White
    Write-Host "Alerts (24h): $($status.AlertsLast24h)" -ForegroundColor $(if ($status.AlertsLast24h -gt 0) { 'Red' } else { 'White' })
    Write-Host "Warnings (24h): $($status.WarningsLast24h)" -ForegroundColor $(if ($status.WarningsLast24h -gt 0) { 'Yellow' } else { 'White' })
    
    if ($status.InstallationExists -and $status.ConfigurationValid -and $status.EventLogExists -and $status.ScheduledTaskExists) {
        Write-Host "`n✓ Loki2WinEventLog is fully operational" -ForegroundColor Green
    } else {
        Write-Host "`n⚠ Loki2WinEventLog has issues that need attention" -ForegroundColor Yellow
        Write-Host "  Run without parameters to reinstall or use -Uninstall to remove" -ForegroundColor Gray
    }
    
    return $status
}

function Uninstall-Loki2WinEventLog {
    param([string]$InstallPath)
    
    Write-Log "=== Loki2WinEventLog Uninstallation Started ==="
    Write-Host "`nUninstalling Loki2WinEventLog..." -ForegroundColor Yellow
    
    $errors = @()
    
    # Step 1: Stop and remove scheduled task
    Write-Host "`nStep 1: Removing scheduled task..." -ForegroundColor Cyan
    try {
        $task = Get-ScheduledTask -TaskName "LokiToWinEventLog" -ErrorAction SilentlyContinue
        if ($task) {
            # Stop if running
            if ($task.State -eq 'Running') {
                Stop-ScheduledTask -TaskName "LokiToWinEventLog" -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
            
            Unregister-ScheduledTask -TaskName "LokiToWinEventLog" -Confirm:$false
            Write-Log "Scheduled task removed successfully"
            Write-Host "  ✓ Scheduled task removed" -ForegroundColor Green
        } else {
            Write-Host "  - Scheduled task not found (already removed)" -ForegroundColor Gray
        }
    }
    catch {
        $errors += "Failed to remove scheduled task: $_"
        Write-Log "Failed to remove scheduled task: $_" -Level Error
        Write-Host "  ✗ Failed to remove scheduled task: $_" -ForegroundColor Red
    }
    
    # Step 2: Remove Windows Event Log
    Write-Host "`nStep 2: Removing Windows Event Log..." -ForegroundColor Cyan
    try {
        # Check if event log exists
        $eventLogExists = $false
        try {
            $null = Get-WinEvent -ListLog "LokiEvents" -ErrorAction Stop
            $eventLogExists = $true
        }
        catch {
            # Log doesn't exist
        }
        
        if ($eventLogExists) {
            # Export last 100 events before deletion (optional backup)
            $backupPath = Join-Path $env:TEMP "LokiEvents_EventLog_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').evtx"
            try {
                wevtutil export-log LokiEvents $backupPath /overwrite:true
                Write-Host "  - Event log backed up to: $backupPath" -ForegroundColor Gray
            }
            catch {
                Write-Host "  - Could not backup event log" -ForegroundColor Gray
            }
            
            # Remove the event log
            Remove-EventLog -LogName "LokiEvents" -Confirm:$false
            Write-Log "Event log removed successfully"
            Write-Host "  ✓ Event log removed" -ForegroundColor Green
        } else {
            Write-Host "  - Event log not found (already removed)" -ForegroundColor Gray
        }
    }
    catch {
        $errors += "Failed to remove event log: $_"
        Write-Log "Failed to remove event log: $_" -Level Error
        Write-Host "  ✗ Failed to remove event log: $_" -ForegroundColor Red
    }
    
    # Step 3: Remove installation directory
    Write-Host "`nStep 3: Removing installation directory..." -ForegroundColor Cyan
    if (Test-Path $InstallPath) {
        try {
            # Kill any running Loki processes
            $lokiPath = Join-Path $InstallPath "loki\loki.exe"
            if (Test-Path $lokiPath) {
                Get-Process | Where-Object { $_.Path -eq $lokiPath } | Stop-Process -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 1
            }
            
            # Remove directory
            Remove-Item -Path $InstallPath -Recurse -Force -ErrorAction Stop
            Write-Log "Installation directory removed successfully"
            Write-Host "  ✓ Installation directory removed" -ForegroundColor Green
        }
        catch {
            $errors += "Failed to remove installation directory: $_"
            Write-Log "Failed to remove installation directory: $_" -Level Error
            Write-Host "  ✗ Failed to remove installation directory: $_" -ForegroundColor Red
            Write-Host "    You may need to manually delete: $InstallPath" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  - Installation directory not found" -ForegroundColor Gray
    }
    
    # Step 4: Clean up any leftover registry entries
    Write-Host "`nStep 4: Cleaning registry..." -ForegroundColor Cyan
    try {
        # Check for any leftover event log registry entries
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\LokiEvents"
        if (Test-Path $regPath) {
            Remove-Item -Path $regPath -Recurse -Force
            Write-Host "  ✓ Registry entries cleaned" -ForegroundColor Green
        } else {
            Write-Host "  - No registry entries found" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  - Could not clean registry entries" -ForegroundColor Gray
    }
    
    # Summary
    Write-Host "`n=== Uninstallation Summary ===" -ForegroundColor Cyan
    if ($errors.Count -eq 0) {
        Write-Log "=== Loki2WinEventLog uninstalled successfully ==="
        Write-Host "✓ Loki2WinEventLog has been completely removed" -ForegroundColor Green
    } else {
        Write-Log "=== Uninstallation completed with errors ==="
        Write-Host "⚠ Uninstallation completed with some errors:" -ForegroundColor Yellow
        foreach ($error in $errors) {
            Write-Host "  - $error" -ForegroundColor Red
        }
    }
    
    Write-Host "`nUninstallation log saved to: $scriptLog" -ForegroundColor Gray
}

# Main installation flow
try {
    # Verify running as administrator
    if (-not (Test-Administrator)) {
        throw "This script must be run as Administrator"
    }
    
    # Handle status check mode
    if ($Status) {
        Get-InstallationStatus -InstallPath $InstallPath
        exit 0
    }
    
    # Handle uninstall mode
    if ($Uninstall) {
        Write-Host "`n=== LOKI2WINEVENTLOG UNINSTALL ===" -ForegroundColor Red
        Write-Host "This will remove all components of Loki2WinEventLog including:" -ForegroundColor Yellow
        Write-Host "  - Scheduled task" -ForegroundColor Yellow
        Write-Host "  - Windows Event Log (with backup)" -ForegroundColor Yellow
        Write-Host "  - Installation directory and all files" -ForegroundColor Yellow
        Write-Host "  - Configuration files and logs" -ForegroundColor Yellow
        Write-Host ""
        
        $confirm = Read-Host "Are you sure you want to uninstall? (YES/N)"
        if ($confirm -eq 'YES') {
            Uninstall-Loki2WinEventLog -InstallPath $InstallPath
        } else {
            Write-Host "Uninstall cancelled" -ForegroundColor Green
        }
        exit 0
    }
    
    Write-Log "=== Loki2WinEventLog Installation Started ==="
    Write-Log "Installation log: $scriptLog"
    
    # Handle update-only mode
    if ($UpdateOnly) {
        Write-Log "Running in update-only mode"
        
        if (-not (Test-Path $InstallPath)) {
            throw "Installation not found at $InstallPath. Please run full installation first."
        }
        
        $lokiPath = Install-Loki -TargetPath $InstallPath
        
        Write-Log "=== Update completed successfully ==="
        Write-Host "`nLoki has been updated to the latest version" -ForegroundColor Green
        Write-Host "Log file: $scriptLog" -ForegroundColor Yellow
        
        # Log update event
        try {
            $versionFile = Join-Path $InstallPath "loki.version"
            $version = if (Test-Path $versionFile) { Get-Content $versionFile } else { "unknown" }
            Write-EventLog -LogName "LokiEvents" -Source "LokiEvents" -EntryType Information -EventId 101 -Message "Loki updated to version: $version" -ErrorAction SilentlyContinue
        } catch {}
        
        exit 0
    }
    
    # Create directories
    Write-Log "Creating installation directories"
    $directories = @(
        $InstallPath,
        (Join-Path $InstallPath "logs"),
        (Join-Path $InstallPath "config")
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Log "Created directory: $dir"
        }
    }
    
    # Install Loki
    $lokiPath = Install-Loki -TargetPath $InstallPath
    
    # Get version info for configuration
    $versionFile = Join-Path $InstallPath "loki.version"
    $installedVersion = if (Test-Path $versionFile) { 
        # Use -Raw to get just the string content without PowerShell metadata
        (Get-Content $versionFile -Raw -ErrorAction SilentlyContinue).Trim()
    } else { 
        "unknown" 
    }
    
    # Initialize event log
    Initialize-EventLog
	
    # Create scanner script
    $scannerScriptPath = New-ScannerScript -TargetPath $InstallPath
	
    #Create configuration file
    $config = @{
        Version = "2.0"
        InstallDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        LokiVersion = $installedVersion
        ScanInterval = $ScanIntervalMinutes
        InstallPath = $InstallPath
        EventLogSizeMB = $EventLogSizeMB
    }
    
    $configPath = Join-Path $InstallPath "config\configuration.json"
    $config | ConvertTo-Json | Out-File -FilePath $configPath -Encoding UTF8
    Write-Log "Configuration saved to: $configPath"


    
    # Install scheduled task
    if (-not $SkipScheduledTask) {
        Install-ScheduledTask -ScriptPath $scannerScriptPath -IntervalMinutes $ScanIntervalMinutes
    } else {
        Write-Log "Skipping scheduled task creation as requested"
    }
    
    # Log installation complete
    Write-EventLog -LogName "LokiEvents" -Source "LokiEvents" -EntryType Information -EventId 100 -Message "Loki2WinEventLog installed successfully. Version: 2.0, Loki: $installedVersion"
    
    Write-Log "=== Installation completed successfully ==="
    Write-Log "Loki will scan the system every $ScanIntervalMinutes minutes"
    Write-Log "Check Windows Event Log 'LokiEvents' for scan results"
    
    # Display summary
    Write-Host "`nInstallation Summary:" -ForegroundColor Cyan
    Write-Host "  Install Path: $InstallPath" -ForegroundColor White
    Write-Host "  Loki Version: $installedVersion" -ForegroundColor White
    Write-Host "  Scan Interval: $ScanIntervalMinutes minutes" -ForegroundColor White
    Write-Host "  Event Log: LokiEvents" -ForegroundColor White
    Write-Host "  Event Log Size: $EventLogSizeMB MB" -ForegroundColor White
    Write-Host "  Log File: $scriptLog" -ForegroundColor White
    
    Write-Host "`nTo manually start a full scan, run:" -ForegroundColor Yellow
    Write-Host "  Start-ScheduledTask -TaskName 'LokiToWinEventLog'" -ForegroundColor White
    Write-Host "`nTo run a quick scan, run:" -ForegroundColor Yellow
    Write-Host "  & '$scannerScriptPath' -QuickScan" -ForegroundColor White
    Write-Host "`nTo update Loki signatures, run:" -ForegroundColor Yellow
    Write-Host "  & '$scannerScriptPath' -UpdateSignatures" -ForegroundColor White
    
}
catch {
    Write-Log "Installation failed: $_" -Level Error
    Write-EventLog -LogName "Application" -Source "Application" -EntryType Error -EventId 9999 -Message "Loki2WinEventLog installation failed: $_" -ErrorAction SilentlyContinue
    throw
}
finally {
    Write-Host "`nInstallation log saved to: $scriptLog" -ForegroundColor Yellow
}