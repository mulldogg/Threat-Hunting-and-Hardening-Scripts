#This script is designed to Enumerate a given host.
#This is intended for use by Threat Hunters and Security Teams to search for MCA
#
#This script was created by SIG Roche and PO1 Mullins on 17APR2026
#
#
#Variables
#
$Hostname = $env:COMPUTERNAME

$Domain = (Get-CimInstance Win32_ComputerSystem).Domain

$Username = "$($env:USERDOMAIN)\$($env:USERNAME)"

$OS = Get-CimInstance Win32_OperatingSystem

$OSVersion = "$($OS.Caption) - Version $($OS.Version) Build $($OS.BuildNumber)"

$IPAddresses = Get-NetIPAddress | Select-Object -ExpandProperty IPAddress

$OpenPorts = Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select-Object LocalPort

$RegistryPaths =@(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)


$InstalledPrograms = foreach ($Path in $RegistryPaths) {
    Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object `
            DisplayName,
            DisplayVersion,
            Publisher
}

$Processes = Get-CimInstance Win32_Process | Select-Object `
    Name,
    ProcessId,
    ParentProcessId,
    CommandLine,
    ExecutablePath

$RunKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

$PersistenceEntries = foreach ($key in $RunKeys) {
    $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    if ($props) {
        $props.PSObject.Properties |
        Where-Object { $_.Name -notlike "PS*" } |
        ForEach-Object {
            [PSCustomObject]@{
                RegistryPath = $key
                Name         = $_.Name
                Command      = $_.Value
            }
        }
    }
}



$ScheduledTasks = try {
    Get-ScheduledTask | Select-Object TaskName, TaskPath, State
} catch {
    "Access Denied"
}

$ScheduledTaskInfo = try {
    Get-ScheduledTask | Get-ScheduledTaskInfo
} catch {
    "Access Denied"
}

$Services = Get-CimInstance Win32_Service |
    Select-Object Name, State, StartMode, PathName


$LoggedOnUsers = Get-CimInstance Win32_UserProfile |
    Where-Object { 
        $_.LocalPath -like "C:\Users\*" -and
        $_.Special -eq $false
    } |
    Select-Object @{Name="Username";Expression={Split-Path $_.LocalPath -Leaf}}, LocalPath, LastUseTime

$ActiveSessions = quser 2>$null

$AuthUsers = try {
    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id      = 4624
    } -MaxEvents 500 |
    Select-Object @{
        Name="Username";Expression={$_.Properties[5].Value}
    }, TimeCreated
} catch {
    "Access Denied"
}


$LocalUsers = try {
    Get-LocalUser
} catch {
    "Access Denied"
}

$NetConnections = Get-NetTCPConnection |
    Where-Object { $_.State -eq "Established" } |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

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

$DTG = Get-date


$DefenderStatus = try {
    Get-MpComputerStatus |
    Select-Object AMServiceEnabled, RealTimeProtectionEnabled, AntivirusEnabled, AntispywareEnabled
} catch {
    "Defender not available"
}

$DirectoryTree = Get-ChildItem -Path "C:\" -Recurse -Force -ErrorAction SilentlyContinue |
Select-Object `
    FullName,
    Name,
    Directory,
    Length,
    CreationTime,
    LastWriteTime,
    Attributes

$SuspiciousExtensions = @(
    ".exe",".dll",
    ".ps1",".bat",".cmd",".vbs",".js",".hta",
    ".doc",".docm",".docx",
    ".xls",".xlsm",".xlsx",
    ".ppt",".pptm",
    ".pdf",
    ".txt",".csv",".rtf",".xml",".ini"
)


$SearchPaths = @(
    "C:\Users",
    "C:\ProgramData",
    "C:\Windows\Temp"
)

$SuspiciousFiles = Get-ChildItem -Path $SearchPaths -Recurse -Force -File -ErrorAction SilentlyContinue |
Where-Object {
    $SuspiciousExtensions -contains $_.Extension.ToLower()
} |
ForEach-Object {
    try {
        $hash = Get-FileHash -Algorithm MD5 -Path $_.FullName -ErrorAction Stop
        [PSCustomObject]@{
            FilePath     = $_.FullName
            CreationTime = $_.CreationTime
            MD5          = $hash.Hash
        }
    }
    catch {
        # Handles access denied / locked files gracefully
        [PSCustomObject]@{
            FilePath     = $_.FullName
            CreationTime = $_.CreationTime
            MD5          = "Access Denied"
        }
    }
}

#
"==============================" | Out-File "${Hostname}.txt"
"${Hostname} Enumeration Report" | Out-File "${Hostname}.txt" -Append
"Report Date : $DTG" | Out-File "${Hostname}.txt" -Append
"==============================" | Out-File "${Hostname}.txt" -Append
#
"==============================" | Out-File "${Hostname}.txt" -Append
"Host Information" | Out-File "${Hostname}.txt" -Append
"==============================" | Out-File "${Hostname}.txt" -Append
"Hostname : " | Out-File "${Hostname}.txt" -Append
$Hostname  | Out-File "${Hostname}.txt" -Append
"Domain : " | Out-File "${Hostname}.txt" -Append
$Domain  | Out-File "${Hostname}.txt" -Append
"User : " | Out-File "${Hostname}.txt" -Append
$Username  | Out-File "${Hostname}.txt" -Append
"OS : " | Out-File "${Hostname}.txt" -Append
$OSVersion  | Out-File "${Hostname}.txt" -Append
"IP Addresses:" | Out-File "${Hostname}.txt" -Append
$IPAddresses | Out-File "${Hostname}.txt" -Append
#
"==============================" | Out-File "${Hostname}.txt" -Append
"Process Information" | Out-File "${Hostname}.txt" -Append
"==============================" | Out-File "${Hostname}.txt" -Append
"Running Processes:" | Out-File "${Hostname}.txt" -Append
$Processes | Format-Table -AutoSize | Out-File "${Hostname}.txt" -Append
#
"==============================" | Out-File "${Hostname}.txt" -Append
"Network Information" | Out-File "${Hostname}.txt" -Append
"==============================" | Out-File "${Hostname}.txt" -Append
"Open Ports :" | Out-File "${Hostname}.txt" -Append
$OpenPorts | Format-Table -AutoSize | Out-File "${Hostname}.txt" -Append
"Network Connections :" | Out-File "${Hostname}.txt" -Append
$NetConnections | Format-Table -AutoSize | Out-File "${Hostname}.txt" -Append
#
"==============================" | Out-File "${Hostname}.txt" -Append
"Registry Information" | Out-File "${Hostname}.txt" -Append
"==============================" | Out-File "${Hostname}.txt" -Append
"Run Keys : " | Out-File "${Hostname}.txt" -Append
$RunKeys | Format-Table -AutoSize | Out-File "${Hostname}.txt" -Append
"Installed Programs : " | Out-File "${Hostname}.txt" -Append
$InstalledPrograms | Sort-Object DisplayName | Format-Table -AutoSize | Out-File "${Hostname}.txt" -Append
"Persistence Entries :" | Out-File "${Hostname}.txt" -Append
$PersistenceEntries | Format-Table -AutoSize | Out-File "${Hostname}.txt" -Append
#
"==============================" | Out-File "${Hostname}.txt" -Append
"User Information" | Out-File "${Hostname}.txt" -Append
"==============================" | Out-File "${Hostname}.txt" -Append
"Logged on Users:" | Out-File "${Hostname}.txt" -Append
$LoggedOnUsers | Format-Table -AutoSize | Out-File "${Hostname}.txt" -Append
"Active Sessions : " | Out-File "${Hostname}.txt" -Append
$ActiveSessions | Out-File "${Hostname}.txt" -Append
"Authentications : " | Out-File "${Hostname}.txt" -Append
$AuthUsers | Format-Table -AutoSize | Out-File "${Hostname}.txt" -Append
"Local Users : " | Out-File "${Hostname}.txt" -Append
$LocalUsers | Format-Table -AutoSize | Out-File "${Hostname}.txt" -Append
#
"==============================" | Out-File "${Hostname}.txt" -Append
"Defender Status" | Out-File "${Hostname}.txt" -Append
"==============================" | Out-File "${Hostname}.txt" -Append

$DefenderStatus |
Format-Table -AutoSize |
Out-File "${Hostname}.txt" -Append


#
"==============================" | Out-File "${Hostname}.txt" -Append
"Logging Configuration Status" | Out-File "${Hostname}.txt" -Append
"==============================" | Out-File "${Hostname}.txt" -Append
foreach ($LogName in $RequiredLogs) {
    try {
        $LogInfo = Get-WinEvent -ListLog $LogName -ErrorAction Stop

        [PSCustomObject]@{
            LogName            = $LogInfo.LogName
            Enabled            = $LogInfo.IsEnabled
            RecordCount        = $LogInfo.RecordCount
            MaxSizeMB          = [math]::Round($LogInfo.MaximumSizeInBytes / 1MB, 2)
            Retention          = if ($LogInfo.IsLogFull) { "Overwrite as needed" } else { "Retain" }
            LastWriteTime      = $LogInfo.LastWriteTime
        } | Format-Table -AutoSize | Out-File "${Hostname}.txt" -Append
    }
    catch {
        "Log not present: $LogName" | Out-File "${Hostname}.txt" -Append
    }
}




#"==============================" | Out-File "${Hostname}_DirectoryTree.txt"
#"Directory Tree Enumeration"    | Out-File "${Hostname}_DirectoryTree.txt" -Append
#"==============================" | Out-File "${Hostname}_DirectoryTree.txt" -Append
#
#$DirectoryTree |
#Format-Table -AutoSize |
#Out-File "${Hostname}_DirectoryTree.txt" -Append

"==============================" | Out-File "${Hostname}_File_Enumeration.txt"
"File Enumeration"    | Out-File "${Hostname}_File_Enumeration.txt" -Append
"==============================" | Out-File "${Hostname}_File_Enumeration.txt" -Append


$SuspiciousFiles |
Format-Table FilePath, CreationTime, MD5 -AutoSize |
Out-File "${Hostname}_File_Enumeration.txt" -Width 4096


#
"==============================" | Out-File "${Hostname}.txt" -Append
"END OF REPORT" | Out-File "${Hostname}.txt" -Append
"==============================" | Out-File "${Hostname}.txt" -Append
#
