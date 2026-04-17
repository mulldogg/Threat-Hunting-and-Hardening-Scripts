#This script is designed to enumerate logging and log forwarding capability via powershell.
#This is intended as a diagnostic tool for Threat Hunters and Administrators.
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
#
"==============================" | Out-File "${Hostname}_Logging.txt" -Append
"END OF REPORT" | Out-File "${Hostname}_Logging.txt" -Append
"==============================" | Out-File "${Hostname}_Logging.txt" -Append
#
