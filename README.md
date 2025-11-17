# PS-Functions
Frequently used Powershell functions for Maule Techs

We are using a **function-based system**. There are 2 ways to load the functions for a session:

### 1) Powershell method ###

**Run _either_:**
```powershell
irm ps.mauletech.com | iex
```

**--OR--**

```powershell
irm https://raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt | iex

# note that this may not work if SSL is not enabled in PowerShell.
```

If you get "irm : The request was aborted: Could not create SSL/TLS secure channel."
Run:
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 #Enables SSL Temporarily
irm https://raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt | iex
Enable-SSL #Enables SSL Permanently
```

### List of functions (can be entered as powershell commands): ###
```powershell

[Add]
-----
  Add-ChromeShortcut
  Add-FileFolderShortcut
  Add-IEShortcut
  Add-WebShortcut

[Backup]
--------
  Backup-LastUser

[Connect]
---------
  Connect-NetExtender
  Connect-O365AzureAD
  Connect-O365Exchange
  Connect-O365Sharepoint
  Connect-O365SharepointPNP
  Connect-Wifi

[Convert]
---------
  Convert-ComputerFleetReport
  Convert-ToSharedMailbox

[Debug]
-------
  Debug-ServerRebootScript
  Debug-SharedMailboxRestoreRequest
  Debug-UmbrellaDNS
  Debug-UmbrellaProxiedDnsServer

[Disable]
---------
  Disable-DailyReboot
  Disable-FastStartup
  Disable-LocalPasswordExpiration
  Disable-Sleep
  Disable-SleepOnAC

[Disconnect]
------------
  Disconnect-AllUsers
  Disconnect-NetExtender
  Disconnect-O365Exchange

[Enable]
--------
  Enable-DellSecureBoot
  Enable-DellWakeUpInMorning
  Enable-O365AuditLog
  Enable-Onedrive
  Enable-Sleep
  Enable-SSL
  Enable-WakeOnLAN

[Expand]
--------
  Expand-Terminal

[Export]
--------
  Export-365AllDistributionGroups
  Export-365DistributionGroup
  Export-LDAPSCertificate
  Export-UnifiDevicesToItGlue
  Export-UsersOneDrive

[Get]
-----
  Get-ADStaleComputers
  Get-ADStaleUsers
  Get-ADUserPassExpirations
  Get-BitLockerKey
  Get-ComputerEntraStatus
  Get-DellWarranty
  Get-DiskUsage
  Get-DomainInfo
  Get-FileDownload
  Get-InstalledApplication
  Get-InternetHealth
  Get-IPConfig
  Get-ITFunctions
  Get-ListeningPorts
  Get-LoginHistory
  Get-NetExtenderStatus
  Get-PSWinGetUpdatablePackages
  Get-RandomPassword
  Get-SharedMailboxRestoreRequest
  Get-SonicwallInterfaceIP
  Get-ThunderBolt
  Get-UserMailboxAccess
  Get-UserProfileSpace
  Get-VSSWriter

[Import]
--------
  Import-PPESenderLists
  Import-PPESingleUserSenderLists
  Import-WindowsInstallerDrivers

[Install]
---------
  Install-Action1
  Install-AppDefaults
  Install-Choco
  Install-ITS247Agent
  Install-NetExtender
  Install-NiniteApps
  Install-NinitePro
  Install-O2016STD
  Install-O365
  Install-O365ProofPointConnectors
  Install-ScreenConnect
  Install-SophosDnsCert
  Install-SophosEndpoint
  Install-UmbrellaDns
  Install-UmbrellaDNSasJob
  Install-UmbrellaDnsCert
  Install-WinGet
  Install-WinGetApps
  Install-WinRepairToolbox

[Invoke]
--------
  Invoke-IPv4NetworkScan
  Invoke-NDDCScan
  Invoke-Win10Decrap

[Join]
------
  Join-Domain

[Optimize]
----------
  Optimize-Powershell

[Remove]
--------
  Remove-ADStaleComputers
  Remove-DuplicateFiles
  Remove-ITS247InstallFolder
  Remove-PathForcefully
  Remove-StaleObjects

[Rename]
--------
  Rename-ClientComputer

[Repair]
--------
  Repair-O365AppIssues
  Repair-Volumes
  Repair-Windows

[Restart]
---------
  Restart-VSSWriter

[Restore]
---------
  Restore-LastUser

[Send]
------
  Send-WakeOnLan

[Set]
-----
  Set-AutoLogon
  Set-ComputerLanguage
  Set-DailyReboot
  Set-DailyRebootDelay
  Set-DnsMadeEasyDDNS
  Set-MountainTime
  Set-NumLock
  Set-PsSpeak
  Set-RunOnceScript
  Set-ServerRebootScriptPassword
  Set-WeeklyReboot

[Start]
-------
  Start-BackstageBrowser
  Start-CleanupOfSystemDrive
  Start-ImperialMarch
  Start-PPKGLog
  Start-PSWinGet
  Start-ServerMaintenance

[Uninstall]
-----------
  Uninstall-Application
  Uninstall-UmbrellaDNS

[Update]
--------
  Update-DattoAgent
  Update-DellPackages
  Update-DellServer
  Update-DnsServerRootHints
  Update-Edge
  Update-Everything
  Update-ITFunctions
  Update-ITS247Agent
  Update-NiniteApps
  Update-NTPDateTime
  Update-O365Apps
  Update-PowerShellModule
  Update-PowershellModules
  Update-PSWinGetPackages
  Update-PWSH
  Update-Windows
  Update-WindowsApps
  Update-WindowsTo11
  Update-WindowTitle


#This list can be updated with "Get-Command -Module PS-* | Select Name"
```
### For more information on a function, type:
```powershell 
Help <function-name> -Detailed
```


