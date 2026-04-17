#This script is designed to enumerate logging and log forwarding capability via powershell.
#This is intended to diagnose logging on a host and to enable hardening of by increasing visibility.
#
#This tool was created by SIG Roche and PO1 Mullins on 17APR2026
#
#
#Variables
#
$DTG = Get-date

$LoggingHealth = @()

$Hostname = $env:COMPUTERNAME

$Domain = (Get-CimInstance Win32_ComputerSystem).Domain

$Username = "$($env:USERDOMAIN)\$($env:USERNAME)"

$OS = Get-CimInstance Win32_OperatingSystem

$OSVersion = "$($OS.Caption) - Version $($OS.Version) Build $($OS.BuildNumber)"

$IPAddresses = Get-NetIPAddress | Select-Object -ExpandProperty IPAddress

#"==============================" | Out-File "${Hostname}_Logging.txt" -Append
#"Host Info" | Out-File "${Hostname}_Logging.txt" -Append
#"==============================" | Out-File "${Hostname}_Logging.txt" -Append

$Hostname = $env:COMPUTERNAME

$Domain = (Get-CimInstance Win32_ComputerSystem).Domain

$Username = "$($env:USERDOMAIN)\$($env:USERNAME)"

$OS = Get-CimInstance Win32_OperatingSystem

$OSVersion = "$($OS.Caption) - Version $($OS.Version) Build $($OS.BuildNumber)"

$IPAddresses = Get-NetIPAddress | Select-Object -ExpandProperty IPAddress

#"==============================" | Out-File "${Hostname}_Logging.txt" -Append
#"Windows Logs" | Out-File "${Hostname}_Logging.txt" -Append
#"==============================" | Out-File "${Hostname}_Logging.txt" -Append

$RequiredLogs = @(
    "Security",
    "System",
    "Microsoft-Windows-DNS-Client/Operational",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Directory Service", # DC only
    "DNS Server",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-Windows Defender/Operational"
)

$EventLogService = Get-Service -Name eventlog -ErrorAction SilentlyContinue

foreach ($Log in $RequiredLogs) {
    try {
        $LogInfo = Get-WinEvent -ListLog $Log -ErrorAction Stop

        $LoggingHealth += [PSCustomObject]@{
            Component    = "Windows Event Log"
            Name         = $Log
            Installed    = $true
            Enabled      = $LogInfo.IsEnabled
            ServiceState = $EventLogService.Status
            Status       = if ($LogInfo.IsEnabled -and $EventLogService.Status -eq "Running") { "Active" } else { "Inactive" }
            RecordCount  = $LogInfo.RecordCount
            LastWrite    = $LogInfo.LastWriteTime
        }
    }
    catch {
        $LoggingHealth += [PSCustomObject]@{
            Component    = "Windows Event Log"
            Name         = $Log
            Installed    = $false
            Enabled      = $false
            ServiceState = $EventLogService.Status
            Status       = "Missing"
            RecordCount  = 0
            LastWrite    = "N/A"
        }
    }
}

#"==============================" | Out-File "${Hostname}_Logging.txt" -Append
#"Sysmon Logs" | Out-File "${Hostname}_Logging.txt" -Append
#"==============================" | Out-File "${Hostname}_Logging.txt" -Append
$SysmonService = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
$SysmonDriver  = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -match "Sysmon" }

$SysmonEventCount = try {
    (Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop | Measure-Object).Count
} catch { 0 }

$SysmonStatus = if (
    $SysmonService -and
    $SysmonService.Status -eq "Running" -and
    $SysmonDriver -and
    $SysmonDriver.State -eq "Running" -and
    $SysmonEventCount -gt 0
) { "Active" } else { "Inactive" }

$LoggingHealth += [PSCustomObject]@{
    Component    = "Sysmon"
    Name         = "Sysmon64"
    Installed    = [bool]$SysmonService
    Enabled      = if ($SysmonService) { $SysmonService.StartType -ne "Disabled" } else { $false }
    ServiceState = if ($SysmonService) { $SysmonService.Status } else { "Not Installed" }
    Status       = $SysmonStatus
    RecordCount  = $SysmonEventCount
    LastWrite    = "Operational Log"
}
#"==============================" | Out-File "${Hostname}_Logging.txt" -Append
#"Splunk Forwarding" | Out-File " |${Hostname}_Logging.txt" -Append
#"==============================" | ${Hostname}_Logging.txt" -Append
$SplunkService = Get-Service -Name SplunkForwarder -ErrorAction SilentlyContinue
$SplunkExePath = "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe"
$SplunkInstalled = Test-Path $SplunkExePath

$LoggingHealth += [PSCustomObject]@{
    Component    = "Splunk Forwarder"
    Name         = "SplunkForwarder"
    Installed    = $SplunkInstalled
    Enabled      = [bool]$SplunkService
    ServiceState = if ($SplunkService) { $SplunkService.Status } else { "Not Installed" }
    Status       = if ($SplunkService -and $SplunkService.Status -eq "Running") { "Active" } else { "Inactive" }
    RecordCount  = "N/A"
    LastWrite    = "N/A"
}

#SCRIPT
#
"==============================" | Out-File "${Hostname}_Logging.txt"
"${Hostname} Log Status Report" | Out-File "${Hostname}_Logging.txt" -Append
"Report Date : $DTG" | Out-File "${Hostname}_Logging.txt" -Append
"==============================" | Out-File "${Hostname}_Logging.txt" -Append
#
"==============================" | Out-File "${Hostname}_Logging.txt" -Append
"Host Information" | Out-File "${Hostname}_Logging.txt" -Append
"==============================" | Out-File "${Hostname}_Logging.txt" -Append
#
"Hostname : " | Out-File "${Hostname}_Logging.txt" -Append
$Hostname  | Out-File "${Hostname}_Logging.txt" -Append
"Domain : " | Out-File "${Hostname}_Logging.txt" -Append
$Domain  | Out-File "${Hostname}_Logging.txt" -Append
"User : " | Out-File "${Hostname}_Logging.txt" -Append
$Username  | Out-File "${Hostname}_Logging.txt" -Append
"OS : " | Out-File "${Hostname}_Logging.txt" -Append
$OSVersion  | Out-File "${Hostname}_Logging.txt" -Append
"IP Addresses:" | Out-File "${Hostname}_Logging.txt" -Append
$IPAddresses | Out-File "${Hostname}_Logging.txt" -Append
#
"==============================" | Out-File "${Hostname}_Logging.txt" -Append
"Logging Configuration Status" | Out-File "${Hostname}_Logging.txt" -Append
"==============================" | Out-File "${Hostname}_Logging.txt" -Append
#
$LoggingHealth |
Sort-Object Component, Name |
Format-Table `
    Component,
    Name,
    Installed,
    Enabled,
    ServiceState,
    Status -AutoSize |
Out-File "${Hostname}.txt" -Append -Width 4096

Write-Host ""
Write-Host "================================================"
Write-Host " LOGGING & FORWARDING REMEDIATION ACTION"
Write-Host "================================================"
Write-Host ""

$EnableLogging = Read-Host "Would you like to ENABLE all required logging and forwarding capabilities? (yes/no)"

if ($EnableLogging -ne "yes") {
    Write-Host "Operator declined. No system settings were modified."
    return
}

Write-Host ""
Write-Host "WARNING:"
Write-Host "This action WILL modify system logging configuration,"
Write-Host "enable services, and start log forwarding components."
Write-Host "This may impact system performance and auditing posture."
Write-Host ""

$ConfirmProceed = Read-Host "Do you want to PROCEED? (yes/no)"

if ($ConfirmProceed -ne "yes") {
    Write-Host "Operator aborted. No system settings were modified."
    return
}

$RemediationActions = @()

$EventLogService = Get-Service -Name eventlog -ErrorAction SilentlyContinue

if ($EventLogService.Status -ne "Running") {
    Start-Service -Name eventlog
    $RemediationActions += "Started Windows Event Log service"
}

foreach ($LogName in $RequiredLogs) {
    try {
        $Log = Get-WinEvent -ListLog $LogName -ErrorAction Stop

        if (-not $Log.IsEnabled) {
            wevtutil sl $LogName /e:true
            $RemediationActions += "Enabled event log: $LogName"
        }
    }
    catch {
        $RemediationActions += "Log not present or cannot be modified: $LogName"
    }
}

$SysmonService = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue

if ($SysmonService) {
    if ($SysmonService.Status -ne "Running") {
        Start-Service -Name Sysmon64
        $RemediationActions += "Started Sysmon service"
    }
} else {
    $RemediationActions += "Sysmon not installed — no action taken"
}

$SplunkService = Get-Service -Name SplunkForwarder -ErrorAction SilentlyContinue

if ($SplunkService) {
    if ($SplunkService.Status -ne "Running") {
        Start-Service -Name SplunkForwarder
        $RemediationActions += "Started Splunk Forwarder service"
    }
} else {
    $RemediationActions += "Splunk Forwarder not installed — no action taken"
}

"==============================" | Out-File "${Hostname}.txt" -Append
"LOGGING REMEDIATION ACTIONS" | Out-File "${Hostname}.txt" -Append
"==============================" | Out-File "${Hostname}.txt" -Append

$RemediationActions | Out-File "${Hostname}.txt" -Append


"==============================" | Out-File "${Hostname}.txt" -Append
"UPDATED LOGGING STATUS" | Out-File "${Hostname}.txt" -Append
"==============================" | Out-File "${Hostname}.txt" -Append

$UpdatedLoggingHealth = @()

foreach ($Log in $RequiredLogs) {
    try {
        $LogInfo = Get-WinEvent -ListLog $Log -ErrorAction Stop

        $UpdatedLoggingHealth += [PSCustomObject]@{
            Component    = "Windows Event Log"
            Name         = $Log
            Installed    = $true
            Enabled      = $LogInfo.IsEnabled
            Status       = if ($LogInfo.IsEnabled) { "Active" } else { "Inactive" }
            RecordCount  = $LogInfo.RecordCount
            LastWrite    = $LogInfo.LastWriteTime
        }
    }
    catch {
        $UpdatedLoggingHealth += [PSCustomObject]@{
            Component   = "Windows Event Log"
            Name        = $Log
            Installed   = $false
            Enabled     = $false
            Status      = "Missing"
            RecordCount = 0
            LastWrite   = "N/A"
        }
    }
}

$UpdatedLoggingHealth |
Format-Table -AutoSize |
Out-File "${Hostname}.txt" -Append -Width 4096


#
"==============================" | Out-File "${Hostname}_Logging.txt" -Append
"END OF REPORT" | Out-File "${Hostname}_Logging.txt" -Append
"==============================" | Out-File "${Hostname}_Logging.txt" -Append
#
