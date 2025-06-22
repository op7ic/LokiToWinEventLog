# Loki2WinEventLog

A PowerShell-based integration tool that enables [Loki](https://github.com/Neo23x0/Loki) to log detection results directly to Windows Event Log for enterprise-scale IOC (Indicators of Compromise) monitoring and incident response.

## Overview

Loki2WinEventLog bridges the gap between Loki's powerful IOC scanning capabilities and enterprise security information and event management (SIEM) systems by providing automated, scheduled IOC scanning with structured Windows Event Log output.

### What is Loki?

[Loki](https://github.com/Neo23x0/Loki) is an open-source IOC scanner developed by [Florian Roth (Neo23x0)](https://github.com/Neo23x0) that helps detect indicators of compromise on Windows systems. It specializes in identifying:

- **Known Malware Signatures** - File hashes, filenames, and patterns
- **YARA Rule Matches** - Custom and community-provided detection rules
- **Suspicious Files** - Anomalous executables and scripts
- **Registry Indicators** - Malicious registry keys and values
- **Network Artifacts** - C2 server indicators and suspicious connections
- **Log Anomalies** - Suspicious entries in Windows logs

Loki is licensed under the GNU General Public License v3.0.

## Features

- **Automated Installation**: Single-script deployment with automatic latest version detection
- **Scheduled Scanning**: Configurable interval-based IOC scanning (default: 3 hours)
- **Windows Event Log Integration**: Native logging to dedicated 'LokiEvents' event log
- **Signature Updates**: Built-in capability to update Loki signatures
- **Quick Scan Mode**: Fast verification scans for testing
- **Automatic Updates**: Built-in update mechanism to maintain latest Loki version
- **Comprehensive Logging**: Detailed file and event logging for troubleshooting
- **CSV Output Management**: Automatic cleanup of old scan results
- **Clean Event Structure**: Organized event IDs for easy SIEM integration:
  - Event ID 100-103: Installation/update events
  - Event ID 1000-1001: Scan status events
  - Event ID 1100-1101: Quick scan events
  - Event ID 2001: Alert events (critical findings)
  - Event ID 2002: Warning events
  - Event ID 2003: Notice events
  - Event ID 2004: General results

## Requirements

- Windows 10/11 or Windows Server 2016/2019/2022
- PowerShell 5.1 or higher
- Administrator privileges
- Internet connection for initial download
- .NET Framework 4.5 or higher
- Minimum 500MB free disk space for Loki and signatures

## Installation

### Quick Install

From an elevated PowerShell console:

```powershell
.\Install-Loki2WinEventLog.ps1
```

### Custom Installation

```powershell
# Install with custom scan interval (6 hours)
.\Install-Loki2WinEventLog.ps1 -ScanIntervalMinutes 360

# Install to custom location
.\Install-Loki2WinEventLog.ps1 -InstallPath "D:\SecurityTools\Loki"

# Install with larger event log size
.\Install-Loki2WinEventLog.ps1 -EventLogSizeMB 200

# Install without creating scheduled task
.\Install-Loki2WinEventLog.ps1 -SkipScheduledTask
```

### Update Existing Installation

```powershell
# Update Loki to latest version
.\Install-Loki2WinEventLog.ps1 -UpdateOnly

# Check installation status
.\Install-Loki2WinEventLog.ps1 -Status
```

## Configuration

The installation creates the following structure:

```
C:\ProgramData\Loki2WindowsEventLog\
├── loki\                  # Loki scanner directory
│   ├── loki.exe          # Loki executable
│   ├── signature-base\   # YARA signatures
│   └── config\           # Loki configuration
├── loki.version          # Version tracking file
├── loki.zip             # Downloaded archive
├── LokiScannerJob.ps1   # Main scanner script
├── config\
│   └── configuration.json # Installation configuration
└── logs\                 # CSV output files (auto-cleaned)
    └── lokioutput_*.csv # Scan results
```

### Configuration File

The `configuration.json` file contains:
- Installation version and date
- Loki version
- Scan interval settings
- Installation paths
- Event log size configuration

## Usage

### Viewing Results

1. **Event Viewer**:
   - Open Event Viewer (`eventvwr.msc`)
   - Navigate to `Applications and Services Logs` → `LokiEvents`

2. **PowerShell**:
   ```powershell
   # View recent alerts
   Get-WinEvent -LogName LokiEvents -MaxEvents 50 | Where-Object {$_.Id -eq 2001}
   
   # View all warnings from last 24 hours
   Get-WinEvent -FilterHashtable @{LogName='LokiEvents'; ID=2002; StartTime=(Get-Date).AddDays(-1)}
   
   # Export events for analysis
   Get-WinEvent -LogName LokiEvents -StartTime (Get-Date).AddDays(-7) | 
       Export-Csv -Path "Loki_Weekly_Report.csv"
   ```

### Manual Operations

```powershell
# Run a full scan manually
Start-ScheduledTask -TaskName "LokiToWinEventLog"

# Run a quick scan
& "C:\ProgramData\Loki2WindowsEventLog\LokiScannerJob.ps1" -QuickScan

# Update Loki signatures
& "C:\ProgramData\Loki2WindowsEventLog\LokiScannerJob.ps1" -UpdateSignatures
```

## Monitoring and Maintenance

### Check Installation Status

```powershell
# Quick status check
.\Install-Loki2WinEventLog.ps1 -Status

# Detailed verification
Get-ScheduledTask -TaskName "LokiToWinEventLog"

# Check recent scan activity
Get-WinEvent -LogName LokiEvents -MaxEvents 10
```

### Log Retention

- CSV scan results are automatically cleaned after 30 days
- Windows Event Log retention follows configured size limits
- Configure via Event Viewer → LokiEvents → Properties

## Integration with SIEM

Loki2WinEventLog events can be collected by:
- **Windows Event Forwarding (WEF)**
- **Splunk Universal Forwarder**
- **Elastic Winlogbeat**
- **Azure Monitor Agent**
- **QRadar WinCollect**

### Example Splunk Query

```spl
index=windows source="WinEventLog:LokiEvents" EventCode=2001
| stats count by host, Message
| where count > 0
```

### Example Sigma Rule

```yaml
title: Loki High Severity Alert
id: a0a0a0a0-1111-2222-3333-444444444444
status: experimental
description: Detects high severity alerts from Loki scanner
logsource:
    product: windows
    service: lokievents
detection:
    selection:
        EventID: 2001
    condition: selection
level: high
```

## Troubleshooting

### Common Issues

1. **Installation Fails**
   - Ensure running as Administrator
   - Check internet connectivity
   - Verify TLS 1.2 is enabled
   - Check available disk space

2. **No Events Appearing**
   - Verify scheduled task is running: `Get-ScheduledTask -TaskName "LokiToWinEventLog"`
   - Check installation log: `$env:TEMP\Loki2WinEventLog_Install_*.log`
   - Verify Event Log exists: `Get-WinEvent -ListLog LokiEvents`

3. **Scan Takes Too Long**
   - Use quick scan mode for faster results
   - Adjust scan parameters in scanner script
   - Check system resources during scan

4. **False Positives**
   - Review Loki documentation for tuning
   - Customize YARA rules in signature-base directory
   - Use Loki's false positive filters

### Debug Mode

View detailed scan output:
```powershell
# Check recent CSV outputs
Get-ChildItem "C:\ProgramData\Loki2WindowsEventLog\logs" -Filter "*.csv" | 
    Sort-Object LastWriteTime -Descending | 
    Select-Object -First 5
```

## Uninstallation

To completely remove Loki2WinEventLog, use the built-in uninstall option:

```powershell
# Automated uninstall (recommended)
.\Install-Loki2WinEventLog.ps1 -Uninstall
```

This will:
- Stop and remove the scheduled task
- Export and remove the Windows Event Log (backup saved to temp folder)
- Delete the installation directory and all files
- Clean up registry entries

### Manual Uninstallation

If you prefer to uninstall manually:

```powershell
# Remove scheduled task
Unregister-ScheduledTask -TaskName "LokiToWinEventLog" -Confirm:$false

# Remove event log
Remove-EventLog -LogName "LokiEvents" -Confirm:$false

# Remove installation directory
Remove-Item -Path "C:\ProgramData\Loki2WindowsEventLog" -Recurse -Force
```

## Security Considerations

- Loki requires administrative privileges to scan system comprehensively
- Network Service account is used for scheduled task execution
- False positives may occur with legitimate software
- Regular signature updates are crucial for detection accuracy
- Consider network isolation during initial signature downloads
- Review and customize YARA rules based on your environment

## Performance Impact

- Full scans can be resource-intensive
- Default configuration excludes file scanning for performance
- Adjust scan intervals based on system load
- Use quick scan mode for routine checks

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

See LICENSE file

## Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.