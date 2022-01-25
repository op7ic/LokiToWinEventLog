# LokiToWinEventLog

This repository containing script which allow [Loki](https://github.com/Neo23x0/Loki) to log to Windows Event Log so it can be collected for scaled up incident response.

## What is Loki?

From [author's webpage](https://www.nextron-systems.com/loki/):

```
LOKI is a free and simple IOC scanner, a complete rewrite of main analysis modules of our full featured APT Scanner THOR. IOC stands for „Indicators of Compromise“. These indicators can be derived from published incident reports, forensic analyses or malware sample collections in your Lab.

LOKI offers a simple way to scan your systems for known IOCs.

It supports these different types of indicators:

MD5 / SHA1 / SHA256 hashes
Yara Rules (applied to file data and process memory)
Hard Indicator Filenames based on Regular Expression (e.g. \\pwdump\.exe)
Soft Indicator Filenames based on Regular Expressions (e.g. Windows\\[\w]\.exe)
```


## Installation Instructions

From an Admin Powershell console run ```.\Install.ps1```. 

## Script Activities:

This script does the following:

* Creates the directory structure at ```c:\Program Files\Loki2WindowsEventLog```.
* Write PowerShell code buffer to loki2wineventlog.ps1 in ```c:\Program Files\Loki2WindowsEventLog```.
* Downloads Loki Scanner from GitHub ```https://github.com/Neo23x0/Loki/releases/download/v0.44.2/loki_0.44.2.zip```.
* Sets up a scheduled task called ```LokiToWinEventLog``` to run the script every 3 hours and log to Windows Event Log called ```LokiEvents```.

## loki2wineventlog.ps1 Activities:

* Start Loki scanner using default rules.
* Log output to CSV file located in ```c:\Program Files\Loki2WindowsEventLog\logs```.
* Filter out INFO events and leave "NOTICE","ALERT","WARNING","RESULT" in for logging.
* Parse resulting CSV file into Windows Event Log called ```LokiEvents```.

## Output 

![](./pic/output.png)

![](./pic/rawoutput.png)
