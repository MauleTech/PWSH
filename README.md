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
  Add-EdgeShortcut
  Add-FileFolderShortcut
  Add-IEShortcut
  Add-RDPCertificate
  Add-RDPShortcut
  Add-WebShortcut
  Add-WiFiProfile

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
  Connect-SophosConnect
  Connect-Wifi

[Convert]
---------
  Convert-ComputerFleetReport
  Convert-ToSharedMailbox

[ConvertTo]
-----------
  ConvertTo-EncodedCommand

[Debug]
-------
  Debug-ServerRebootScript
  Debug-SharedMailboxRestoreRequest
  Debug-UmbrellaDNS
  Debug-UmbrellaProxiedDnsServer

[Disable]
---------
  Disable-DailyReboot
  Disable-EdgeOOBE
  Disable-FastStartup
  Disable-LocalPasswordExpiration
  Disable-Sleep
  Disable-SleepOnAC

[Disconnect]
------------
  Disconnect-AllUsers
  Disconnect-NetExtender
  Disconnect-O365Exchange
  Disconnect-SophosConnect

[Enable]
--------
  Enable-DellSecureBoot
  Enable-DellTPM
  Enable-DellWakeUpInMorning
  Enable-O365AuditLog
  Enable-Onedrive
  Enable-RDP
  Enable-RemoteManagement
  Enable-Sleep
  Enable-SSL
  Enable-WakeOnLAN

[Expand]
--------
  Expand-SystemPartition
  Expand-Terminal

[Export]
--------
  Export-365AllDistributionGroups
  Export-365DistributionGroup
  Export-ExchangeDistributionList
  Export-LDAPSCertificate
  Export-UsersOneDrive
  Export-WiFiProfiles

[Find]
------
  Find-CrocExe

[Get]
-----
  Get-ADLockedAccount
  Get-ADStaleComputers
  Get-ADStaleUsers
  Get-ADUserPassExpirations
  Get-ADUsersPasswordExpiring
  Get-BitLockerKey
  Get-ClaudeCodeStatus
  Get-ClientDiscovery
  Get-ComputerEntraStatus
  Get-ComputerLifecycleAgeBasis
  Get-ComputerLifecycleAssessment
  Get-ComputerLifecycleCheckAge
  Get-ComputerLifecycleCheckBootDrive
  Get-ComputerLifecycleCheckCpu
  Get-ComputerLifecycleCheckHealth
  Get-ComputerLifecycleCheckMemory
  Get-ComputerLifecycleCheckOSDrive
  Get-ComputerLifecycleCheckRepeatTickets
  Get-ComputerLifecycleCheckWarranty
  Get-ComputerLifecycleCheckWindows11
  Get-ComputerLifecycleData
  Get-ComputerLifecycleIdentity
  Get-ComputerLifecycleOutcome
  Get-ComputerLifecycleWarrantyInfo
  Get-CrocPath
  Get-DatacenterLocation
  Get-DecryptedConfig
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
  Get-NTPOffset
  Get-PSWinGetUpdatablePackages
  Get-RandomPassword
  Get-SharedMailboxRestoreRequest
  Get-SonicwallInterfaceIP
  Get-SophosConnectStatus
  Get-ThunderBolt
  Get-UserMailboxAccess
  Get-UserProfileSpace
  Get-VMByFQDN
  Get-VMHostName
  Get-VSSWriter

[Import]
--------
  Import-PPESenderLists
  Import-PPESingleUserSenderLists
  Import-WindowsInstallerDrivers
  Import-WiFiProfiles

[Install]
---------
  Install-Action1
  Install-AppDefaults
  Install-Choco
  Install-ClaudeCode
  Install-Croc
  Install-NetExtender
  Install-NiniteApps
  Install-NinitePro
  Install-O2016STD
  Install-O365
  Install-O365ProofPointConnectors
  Install-ScreenConnect
  Install-SophosConnect
  Install-SophosDnsCert
  Install-SophosEndpoint
  Install-SSLInspectionCert
  Install-UmbrellaDns
  Install-UmbrellaDNSasJob
  Install-UmbrellaDnsCert
  Install-WinGet
  Install-WinGetApps
  Install-WinRepairToolbox

[Invoke]
--------
  Invoke-BPARemediation
  Invoke-DHCPRemediation
  Invoke-DNSRemediation
  Invoke-IPv4NetworkScan
  Invoke-NDDCScan
  Invoke-OneDriveFreeUpSpace
  Invoke-SMBRemediation
  Invoke-ValidatedDownload
  Invoke-Win10Decrap
  Invoke-WinGetInstall

[Join]
------
  Join-Domain

[New]
-----
  New-BPAResultObject
  New-CrocCode

[Optimize]
----------
  Optimize-Powershell

[Protect]
---------
  Protect-ConfigFile

[Receive]
---------
  Receive-Item

[Remove]
--------
  Remove-ADStaleComputers
  Remove-ClaudeCode
  Remove-DuplicateFiles
  Remove-ITS247InstallFolder
  Remove-OrphanedInstallerFiles
  Remove-PathForcefully
  Remove-PpkgInstallFolder
  Remove-StaleObjects
  Remove-StaleProfiles
  Remove-UserProfile

[Rename]
--------
  Rename-ClientComputer

[Repair]
--------
  Repair-AdobeCreativeCloud
  Repair-DomainTrust
  Repair-ExchangeDAGCopies
  Repair-NTPConfiguration
  Repair-O365AppIssues
  Repair-RemoteWMI
  Repair-Volumes
  Repair-Windows

[Restart]
---------
  Restart-ComputerSafely
  Restart-VSSWriter

[Restore]
---------
  Restore-LastUser

[Send]
------
  Send-Item
  Send-WakeOnLan

[Set]
-----
  Set-AutoLogon
  Set-ChocolateySources
  Set-ComputerLanguage
  Set-DailyReboot
  Set-DailyRebootDelay
  Set-DnsMadeEasyDDNS
  Set-MountainTime
  Set-NumLock
  Set-PsSpeak
  Set-RDPSignature
  Set-RunOnceScript
  Set-ServerRebootScriptPassword
  Set-WeeklyReboot

[Start]
-------
  Start-BackstageBrowser
  Start-ClaudeCode
  Start-CleanupOfSystemDrive
  Start-ImperialMarch
  Start-PPKGLog
  Start-PSTaskManager
  Start-PSWinGet
  Start-ServerMaintenance

[Stop]
------
  Stop-StuckService

[Test]
------
  Test-PendingReboot
  Test-SmtpRelay

[Uninstall]
-----------
  Uninstall-Application
  Uninstall-UmbrellaDNS

[Unprotect]
-----------
  Unprotect-ConfigFile

[Update]
--------
  Update-ClaudeCode
  Update-DellPackages
  Update-DellServer
  Update-DnsServerRootHints
  Update-Edge
  Update-Everything
  Update-ITFunctions
  Update-NiniteApps
  Update-NTPDateTime
  Update-O365Apps
  Update-OEMDrivers
  Update-PowerShellModule
  Update-PowershellModules
  Update-PSWinGetPackages
  Update-PWSH
  Update-Windows
  Update-WindowsApps
  Update-WindowsTo11
  Update-WindowTitle


#This list can be updated with "Get-ITFunctions"
```
### For more information on a function, type:
```powershell 
Help <function-name> -Detailed
```


