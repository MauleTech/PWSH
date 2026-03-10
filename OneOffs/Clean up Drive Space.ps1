#[System.Net.ServicePointManager]::SecurityProtocol = 3072 -bor 768 -bor 192 ; Invoke-RestMethod 'https://raw.githubusercontent.com/MauleTech/PWSH/master/OneOffs/Clean%20up%20Drive%20Space.ps1' | Invoke-Expression
#Clean up Drive Space
#Enable SSL/TLS
Try {
	[System.Net.ServicePointManager]::SecurityProtocol = 3072 -bor 768 -bor 192
} Catch {
	Write-Output 'Unable to set PowerShell to use TLS 1.2 and TLS 1.1 due to old .NET Framework installed. If you see underlying connection closed or trust errors, you may need to upgrade to .NET Framework 4.5+ and PowerShell v3+.'
}

$VerbosePreference = "SilentlyContinue"
$DaysToDelete = 7
$ErrorActionPreference = "SilentlyContinue"

#region Helper Functions

# Returns current free space in GB on the system drive
Function Get-FreeSpaceGB {
	$disk = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object -Property DriveType -EQ 3 | Where-Object -Property DeviceID -EQ $Env:SystemDrive
	return [math]::Round($disk.FreeSpace / 1GB, 2)
}

# Tracks space freed per step and writes a status line
$Script:StepLog = [System.Collections.ArrayList]::new()
$Script:LastFreeSpace = $null

Function Write-StepStatus {
	param(
		[string]$StepName,
		[switch]$Start
	)
	$currentFree = Get-FreeSpaceGB
	if ($Start) {
		$Script:LastFreeSpace = $currentFree
		Write-Host "`n=== Starting: $StepName ===" -ForegroundColor Cyan
		return
	}
	$freed = [math]::Round($currentFree - $Script:LastFreeSpace, 2)
	$totalFreed = [math]::Round($currentFree - $Script:InitialFreeSpace, 2)
	[void]$Script:StepLog.Add([PSCustomObject]@{
		Step    = $StepName
		FreedGB = $freed
	})
	if ($freed -gt 0) {
		Write-Host "--- $StepName freed ${freed} GB (total so far: ${totalFreed} GB free) ---" -ForegroundColor Green
	} else {
		Write-Host "--- $StepName: no additional space freed (total so far: ${totalFreed} GB free) ---" -ForegroundColor Yellow
	}
	$Script:LastFreeSpace = $currentFree
}

Function Enable-NTFSCompression {
	param(
		[string]$Path
	)
	if (Test-Path $Path) {
		Write-Host "Compressing: $Path"
		$result = compact /C /S:"$Path" /I /Q 2>&1
		Write-Host "  $($result | Select-Object -Last 1)"
	} else {
		Write-Host "Path not found, skipping: $Path"
	}
}

Function Clear-DeliveryOptimizationCache {
	try {
		Delete-DeliveryOptimizationCache -Force -ErrorAction Stop
		Write-Host "Cleared Delivery Optimization cache via cmdlet."
	} catch {
		$doPath = Join-Path -Path $Env:SystemRoot -ChildPath "SoftwareDistribution\DeliveryOptimization"
		if (Test-Path $doPath) {
			Remove-PathForcefully -Path $doPath
			Write-Host "Cleared Delivery Optimization cache via manual deletion."
		}
	}
}

Function Invoke-OneDriveDehydration {
	param(
		[int]$InactiveDays = 14
	)

	Write-Host "Checking for OneDrive files to dehydrate for users inactive > $InactiveDays days"

	$InactiveProfiles = Get-CimInstance -ClassName Win32_UserProfile |
		Where-Object { $_.Loaded -eq $false } |
		Where-Object { $_.LastUseTime -lt (Get-Date).AddDays(-$InactiveDays) } |
		Where-Object { $_.LocalPath -notmatch 'admin|Remote Support|Default|Public|systemprofile|LocalService|NetworkService' }

	foreach ($profile in $InactiveProfiles) {
		$userName = Split-Path $profile.LocalPath -Leaf
		$OneDriveFolders = @()

		$bizFolders = Get-ChildItem -Path $profile.LocalPath -Directory -Filter "OneDrive -*" -ErrorAction SilentlyContinue
		if ($bizFolders) { $OneDriveFolders += $bizFolders.FullName }

		$personalPath = Join-Path $profile.LocalPath "OneDrive"
		if (Test-Path $personalPath) { $OneDriveFolders += $personalPath }

		foreach ($odPath in $OneDriveFolders) {
			Write-Host "Dehydrating OneDrive files for '$userName': $odPath"
			$dehydratedCount = 0
			Get-ChildItem -Path $odPath -Force -File -Recurse -ErrorAction SilentlyContinue |
				ForEach-Object {
					$null = attrib.exe $_.FullName +U -P /s 2>&1
					$dehydratedCount++
				}
			Write-Host "  Processed $dehydratedCount files in $odPath"
		}
	}
}

Function Reset-WindowsSearchIndex {
	Write-Host "Resetting Windows Search Index..."
	$searchService = Get-Service -Name WSearch -ErrorAction SilentlyContinue
	if ($null -eq $searchService) {
		Write-Host "  Windows Search service not found, skipping."
		return
	}
	Stop-Service -Name WSearch -Force -ErrorAction SilentlyContinue
	$edbPath = Join-Path -Path $Env:ProgramData -ChildPath "Microsoft\Search\Data\Applications\Windows\Windows.edb"
	if (Test-Path $edbPath) {
		$sizeMB = [math]::Round((Get-Item $edbPath -Force).Length / 1MB, 1)
		Write-Host "  Deleting Windows.edb ($sizeMB MB)"
		Remove-Item -Path $edbPath -Force -ErrorAction SilentlyContinue
	}
	Start-Service -Name WSearch -ErrorAction SilentlyContinue
	Write-Host "  Windows Search service restarted; index will rebuild."
}

#endregion Helper Functions

#region Existing Functions

Function Invoke-WindowsCleanMgr {
	# Set registry keys to check all Disk Cleanup boxes
	$SageSet = "StateFlags0097"
	$StateFlags = "StateFlags0097"
	$Base = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\"
	$VolCaches = Get-ChildItem $Base
	$Locations = @($VolCaches.PSChildName)
	ForEach ($VC in $VolCaches) { New-ItemProperty -Path "$($VC.PSPath)" -Name $StateFlags -Value 1 -Type DWORD -Force | Out-Null }
	ForEach ($Location in $Locations) { Set-ItemProperty -Path $($Base + $Location) -Name $SageSet -Type DWORD -Value 2 | Out-Null }
	$CleanMgrArgs = "/sagerun:$([string]([int]$SageSet.Substring($SageSet.Length - 4)))"
	function Watch-CleanMgr {
		$prevTicks = 0
		$sameTickCount = 0
		$WaitInterval = 30
		$SameTickMax = 8
		$process = Get-Process cleanmgr -ErrorAction SilentlyContinue

		if ($null -eq $process) {
			Write-Host "cleanmgr.exe is not running."
			return $false
		}

		while ($true) {
			Start-Sleep -Seconds $WaitInterval

			$process = Get-Process cleanmgr -ErrorAction SilentlyContinue
			if ($null -eq $process) {
				Write-Host "cleanmgr.exe has exited."
				return $false
			}
			$currentTicks = $process.TotalProcessorTime.Ticks
			Write-Host "Checking on cleanmgr CPU usage: $currentTicks"
			if ($currentTicks -eq $prevTicks) {
				$sameTickCount++
				Write-Host "Cleanmgr hasn't used the CPU in the last $WaitInterval seconds. If it does this $($SameTickMax - $sameTickCount) more times, we'll move on."
				if ($sameTickCount -eq $SameTickMax) { #CPU count hasn't changed for 4 minutes (30 seconds * 8)
					Write-Host "cleanmgr.exe appears to be inactive. Terminating process."
					Stop-Process -Name cleanmgr -Force
					return $true
				}
			} else {
				$sameTickCount = 0
			}

			$prevTicks = $currentTicks
		}
	}
	Write-Host "Starting cleanmgr.exe /verylowdisk for a first attempt."
	Start-Process "$env:SystemRoot\System32\cleanmgr.exe" -ArgumentList "/verylowdisk /d c" -WindowStyle Hidden
	$terminated = Watch-CleanMgr

	# Second attempt if the first one was terminated
	if ($terminated) {
		Write-Host "Restarting cleanmgr.exe for a second attempt."
		Start-Process "$env:SystemRoot\System32\cleanmgr.exe" -ArgumentList "/verylowdisk /d c" -WindowStyle Hidden
		Watch-CleanMgr
	}

	Write-Host "Starting cleanmgr.exe $CleanMgrArgs for a first attempt."
	Start-Process "$env:SystemRoot\System32\cleanmgr.exe" -ArgumentList $CleanMgrArgs -WindowStyle Hidden
	$terminated = Watch-CleanMgr

	# Second attempt if the first one was terminated
	if ($terminated) {
		Write-Host "Restarting cleanmgr.exe $CleanMgrArgs for a second attempt."
		Start-Process "$env:SystemRoot\System32\cleanmgr.exe" -ArgumentList $CleanMgrArgs -WindowStyle Hidden
		Watch-CleanMgr
	}
}

Function Remove-WindowsRestorePoints {
	# Windows Server uses its integrated scheduled backup feature as shadow copies removing them would actually delete the scheduled full disk backups that are created.
	If ((Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption) -notlike "Microsoft Windows Server*") {
		# Remove all system shadow copies if the -Include parameter with the 'RestorePoints' value is used and the running system is not a Windows Server.
		If (Get-CimInstance -ClassName Win32_ShadowCopy) {
			Get-CimInstance -ClassName Win32_ShadowCopy -Verbose:$false | ForEach-Object -Process {
				Write-Verbose ('Performing the operation "Delete ShadowCopy" on target "{0}"' -f $PSItem.ID) -Verbose
				$PSItem | Remove-CimInstance -Verbose:$false
			}
		}
	}
}

Function Remove-EventLogs {
	# Remove all event logs and event tracer log files if the -Include parameter with the 'EventLogs' value is used.
	Get-WinEvent -ListLog * | Where-Object { $PSItem.IsEnabled -eq $true -and $PSItem.RecordCount -gt 0 } | ForEach-Object -Process {
		Write-Verbose ('Performing the operation "ClearLog" on target "{0}"' -f $PSItem.LogName) -Verbose
		[Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($PSItem.LogName)
	} 2> $null
}

Function Remove-DuplicateDrivers {
	# Remove all outdated and duplicate drivers if the -Include parameter with the 'DuplicateDrivers' value is used.
	Write-Verbose "Compiling a list of any outdated and duplicate system drivers." -Verbose
	$AllDrivers = Get-WindowsDriver -Online -All | Where-Object -Property Driver -Like oem*inf | Select-Object -Property @{ Name = 'OriginalFileName'; Expression = { $PSItem.OriginalFileName | Split-Path -Leaf } }, Driver, ClassDescription, ProviderName, Date, Version
	$DuplicateDrivers = $AllDrivers | Group-Object -Property OriginalFileName | Where-Object -Property Count -GT 1 | ForEach-Object -Process { $PSItem.Group | Sort-Object -Property Date -Descending | Select-Object -Skip 1 }
	If ($DuplicateDrivers) {
		$DuplicateDrivers | ForEach-Object -Process {
			$Driver = $PSItem.Driver.Trim()
			Write-Verbose ('Performing the action "Delete Driver" on target {0}' -f $Driver) -Verbose
			Start-Process -FilePath PNPUTIL -ArgumentList ('/Delete-Driver {0} /Force' -f $Driver) -WindowStyle Hidden -Wait
		}
	}
}

Function Remove-StaleProfiles {
	$thresholdDays = 731 #Days
	Write-Host "Checking for stale profiles to clean up"
	# Get a list of user profiles
	$profiles = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-$thresholdDays) } | Where-Object { $_.Loaded -eq $False } | Where-Object { $_.LocalPath -notmatch 'Remote Support|admin' }
	If ($profiles) {
		foreach ($profile in $profiles) {
			$localPath = $profile.LocalPath
			Write-Host "Assessing $localPath"
			$directories = Get-ChildItem -Path $localPath -Directory
			if ($directories.Count -gt 0) {
				# Find the most recently modified directory
				$mostRecentDir = $directories | Sort-Object LastWriteTime -Descending | Select-Object -First 1
				# Calculate the age in days
				$ageInDays = (Get-Date) - $mostRecentDir.LastWriteTime
				Write-Host "$($mostRecentDir.FullName) was most recently updated $([int]$ageInDays.TotalDays) days ago."
				If ($ageInDays.TotalDays -gt 360) {
					Write-Host "Deleting $localPath (Last modified: $($mostRecentDir.LastWriteTime))"
					Write-Host "Deleting inactive profile: $($profile.LocalPath)"
					Write-Host "$profile"
					Remove-CimInstance $profile -Verbose -Confirm:$false
					$targetSID = $profile.SID

					# Construct the registry path for the user profile
					$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ProfileList\$targetSID"

					# Delete the registry key
					Remove-Item -Path $registryPath -Force
					Write-Host "User profile with SID $targetSID has been deleted from the registry."
					# Delete the Users Path
					Remove-PathForcefully -Path $Profile.LocalPath
				}
			}
		}
	} Else {
		Write-Host "No profiles older than $thresholdDays days found."
	}
}

#endregion Existing Functions

########################################
# PHASE 1: PRE-REQUISITES
########################################

# Record pre-cleanup disk state
$PreClean = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object -Property DriveType -EQ 3 | Where-Object -Property DeviceID -EQ $Env:SystemDrive | Select-Object -Property @{ Name = 'Drive'; Expression = { ($PSItem.DeviceID) } },
	@{ Name = 'Size (GB)'; Expression = { '{0:N1}' -f ($PSItem.Size / 1GB) } },
	@{ Name = 'FreeSpace (GB)'; Expression = { '{0:N1}' -f ($PSItem.Freespace / 1GB) } },
	@{ Name = 'PercentFree'; Expression = { '{0:P1}' -f ($PSItem.FreeSpace / $PSItem.Size) } }

Write-Host "`nBefore Clean-up:`n$(($PreClean | Format-Table | Out-String).Trim())"
Write-Host ((Get-Date).DateTime)
Write-Host $env:COMPUTERNAME
Start-Sleep -Seconds 10

$Script:InitialFreeSpace = Get-FreeSpaceGB

# Assign the local and global paths to their own variables for easier path building.
$GlobalAppData = $Env:APPDATA.Replace($Env:USERPROFILE, ($Env:Public).Replace('Public', '*'))
$LocalAppData = $Env:LOCALAPPDATA.Replace($Env:USERPROFILE, ($Env:Public).Replace('Public', '*'))
$RootAppData = "$(Split-Path -Path $LocalAppData)\*"

# Pre-requisite commands
Write-Host "Reclaim space from .NET Native Images" ; Get-Item "$Env:windir\Microsoft.NET\Framework\*\ngen.exe" -Force | ForEach-Object { & $($_.FullName) update } | Out-Null
Get-Service -Name wuauserv | Stop-Service -Force -Verbose #Stops Windows Update so we can clean it out.
$EdgePackageName = Get-AppxPackage -Name Microsoft.MicrosoftEdge | Select-Object -ExpandProperty PackageFamilyName

# Block Chrome on-device AI model downloads (Gemini Nano, ~4 GB per user)
Write-Host "Setting Chrome policy to block on-device AI model downloads"
New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "GenAILocalFoundationalModelSettings" -Value 1 -Type DWord

########################################
# PHASE 2: HIGHEST IMPACT (multi-GB each)
########################################

# --- Disable Hibernation (2-8+ GB, instant) ---
Write-StepStatus -StepName "Disable Hibernation" -Start
powercfg -h off
Write-StepStatus -StepName "Disable Hibernation"

# --- Delete Windows.old (~10-30 GB when present) ---
Write-StepStatus -StepName "Delete Windows.old" -Start
@(
	(Join-Path -Path $Env:SystemDrive -ChildPath "Windows.old")
) | ForEach-Object {
	if (Test-Path $_) { Remove-PathForcefully -Path $_ }
}
Write-StepStatus -StepName "Delete Windows.old"

# --- Delete Windows upgrade remnants (5-20 GB) ---
Write-StepStatus -StepName "Delete Windows upgrade remnants" -Start
@(
	(Join-Path -Path $Env:SystemDrive -ChildPath '$GetCurrent')
	(Join-Path -Path $Env:SystemDrive -ChildPath '$WINDOWS.~BT')
	(Join-Path -Path $Env:SystemDrive -ChildPath '$WINDOWS.~WS')
	(Join-Path -Path $Env:SystemDrive -ChildPath '$WinREAgent')
	(Join-Path -Path $Env:SystemDrive -ChildPath "Windows10Upgrade")
) | ForEach-Object {
	if (Test-Path $_) { Remove-PathForcefully -Path $_ }
}
Write-StepStatus -StepName "Delete Windows upgrade remnants"

# --- WinSxS cleanup via DISM (1-5+ GB) ---
Write-StepStatus -StepName "WinSxS cleanup (DISM)" -Start
Write-Host "Reducing the size of the WinSxS folder"
Dism.exe /online /Cleanup-Image /StartComponentCleanup
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
Dism.exe /online /Cleanup-Image /SPSuperseded
Write-StepStatus -StepName "WinSxS cleanup (DISM)"

# --- StartComponentCleanup scheduled task ---
Write-StepStatus -StepName "StartComponentCleanup task" -Start
Start-ScheduledTask -TaskPath "\Microsoft\Windows\Servicing" -TaskName "StartComponentCleanup" -Verbose:$false
Write-StepStatus -StepName "StartComponentCleanup task"

# --- Disable Reserved Storage (~7 GB) ---
Write-StepStatus -StepName "Disable Reserved Storage" -Start
DISM.exe /Online /Set-ReservedStorageState /State:Disabled
Write-StepStatus -StepName "Disable Reserved Storage"

# --- Remove stale user profiles (multi-GB per profile) ---
Write-StepStatus -StepName "Remove stale user profiles" -Start
If ((Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption) -notlike "Microsoft Windows Server*") {
	Remove-StaleProfiles
}
Write-StepStatus -StepName "Remove stale user profiles"

# --- Empty Recycle Bin (highly variable) ---
Write-StepStatus -StepName "Empty Recycle Bin" -Start
Write-Host "Emptying Recycle Bin" ; Clear-RecycleBin -Force
Get-ChildItem -Path 'C:\$Recycle.Bin' -Recurse -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path 'C:\$Recycle.Bin' -Recurse -Force | Remove-PathForcefully -ErrorAction SilentlyContinue
Write-StepStatus -StepName "Empty Recycle Bin"

# --- Delete MEMORY.dmp (can be full RAM size) ---
Write-StepStatus -StepName "Delete MEMORY.dmp" -Start
$memDmp = Join-Path -Path $Env:SystemRoot -ChildPath "MEMORY.dmp"
if (Test-Path $memDmp) { Remove-PathForcefully -Path $memDmp }
Write-StepStatus -StepName "Delete MEMORY.dmp"

# --- Delete MSOCache (Office install cache, 1-3 GB) ---
Write-StepStatus -StepName "Delete MSOCache" -Start
$msoCache = Join-Path -Path $Env:SystemDrive -ChildPath "MSOCache"
if (Test-Path $msoCache) { Remove-PathForcefully -Path $msoCache }
Write-StepStatus -StepName "Delete MSOCache"

# --- Clean Windows Update downloads (1-5 GB) ---
Write-StepStatus -StepName "Clean Windows Update downloads" -Start
@(
	(Join-Path -Path $Env:SystemRoot -ChildPath "SoftwareDistribution\Download")
	(Join-Path -Path $Env:SystemRoot -ChildPath "SoftwareDistribution\DataStore\Logs")
	(Join-Path -Path $Env:SystemRoot -ChildPath "Logs\WindowsUpdate")
	(Join-Path -Path $Env:ProgramData -ChildPath "USOShared\Logs")
) | ForEach-Object {
	if (Test-Path $_) { Remove-StaleObjects -targetDirectory $_ -DaysOld $DaysToDelete }
}
Write-StepStatus -StepName "Clean Windows Update downloads"

# --- Delivery Optimization Cache (1-5 GB) ---
Write-StepStatus -StepName "Delivery Optimization Cache" -Start
Clear-DeliveryOptimizationCache
Write-StepStatus -StepName "Delivery Optimization Cache"

# --- Chrome AI model files (~4 GB per user) ---
Write-StepStatus -StepName "Delete Chrome AI model files" -Start
@(Get-Item -Path (Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\OptGuideOnDeviceModel") -Force) | ForEach-Object {
	if ($_ -and (Test-Path $_.FullName)) { Remove-PathForcefully -Path $_.FullName }
}
Write-StepStatus -StepName "Delete Chrome AI model files"

########################################
# PHASE 3: MEDIUM IMPACT (hundreds of MB to a few GB)
########################################

# --- Temp folder cleanup ---
Write-StepStatus -StepName "Temp folder cleanup" -Start
@(
	"$Env:TEMP"
	(Join-Path -Path $LocalAppData -ChildPath "Temp")
	(Join-Path -Path $Env:SystemDrive -ChildPath "Temp")
) | ForEach-Object {
	if (@(Get-Item $_ -Force)) {
		Get-Item $_ -Force | ForEach-Object { Remove-StaleObjects -targetDirectory $_.FullName -DaysOld $DaysToDelete }
	}
}
Write-StepStatus -StepName "Temp folder cleanup"

# --- Browser caches (Chrome, Edge, Firefox, IE — combined 1-5 GB) ---
Write-StepStatus -StepName "Browser cache cleanup" -Start

# Age-based browser cache cleanup
$BrowserFoldersToClean = @(
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Windows\Temporary Internet Files")
	(Join-Path -Path $GlobalAppData -ChildPath "Microsoft\Windows\Cookies")
	(Join-Path -Path $LocalAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\Cache")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Cache")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Default\Cache")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Windows\Temporary Internet Files\Content.IE5")
	(Join-Path -Path $GlobalAppData -ChildPath "Macromedia\Flash Player\macromedia.com\support\flashplayer\sys")
	(Join-Path -Path $Env:SystemRoot -ChildPath "SysWOW64\config\systemprofile\AppData\Local\Microsoft\Windows\INetCache\IE")
)
$BrowserFoldersToClean | ForEach-Object {
	if (@(Get-Item $_ -Force)) {
		Get-Item $_ -Force | ForEach-Object { Remove-StaleObjects -targetDirectory $_.FullName -DaysOld $DaysToDelete }
	}
}

# Full browser cache deletions
$BrowserPathsToDelete = @(
	#Chrome
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\*.pma")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\BrowserMetrics\*.pma")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\CrashPad\metadata")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\BudgetDatabase")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Cache\*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Code Cache\js\*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Code Cache\wasm\*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Cookies")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\data_reduction_proxy_leveldb\*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Extension State\*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Favicons\*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Feature Engagement Package\AvailabilityDB\*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Feature Engagement Package\EventDB\*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\File System\000\*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\File System\Origins\*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\IndexedDB\*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Service Worker\CacheStorage\*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Service Worker\Database\*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Service Worker\ScriptCache\*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Current Tabs")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Last Tabs")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\History")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\History Provider Cache")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\History-journal")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Network Action Predictor")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Top Sites")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Visited Links")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Login Data")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\CURRENT")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\LOCK")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\MANIFEST-*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\*.log")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\*\*.log")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\*\*log*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\*\MANIFEST-*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Shortcuts")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\QuotaManager")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Web Data")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Current Session")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Last Session")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Session Storage\*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Site Characteristics Database\*")
	(Join-Path -Path $LocalAppData -ChildPath "Google\Chrome\User Data\Default\Sync Data\LevelDB\*")
	#FireFox
	(Join-Path -Path $RootAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\Cache*\*")
	(Join-Path -Path $LocalAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\Cache*\*")
	(Join-Path -Path $GlobalAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\Cache*\*")
	(Join-Path -Path $RootAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\jumpListCache\*")
	(Join-Path -Path $LocalAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\jumpListCache\*")
	(Join-Path -Path $GlobalAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\jumpListCache\*")
	(Join-Path -Path $RootAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\thumbnails\*")
	(Join-Path -Path $LocalAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\thumbnails\*")
	(Join-Path -Path $GlobalAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\*sqlite*")
	(Join-Path -Path $RootAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\*.log")
	(Join-Path -Path $LocalAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\*.log")
	(Join-Path -Path $GlobalAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\*.log")
	(Join-Path -Path $RootAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\storage\*")
	(Join-Path -Path $LocalAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\storage\*")
	(Join-Path -Path $GlobalAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\storage\*")
	(Join-Path -Path $RootAppData -ChildPath "Mozilla\Firefox\Crash Reports\*")
	(Join-Path -Path $LocalAppData -ChildPath "Mozilla\Firefox\Crash Reports\*")
	(Join-Path -Path $GlobalAppData -ChildPath "Mozilla\Firefox\Crash Reports\*")
	(Join-Path -Path $RootAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\startupCache\*")
	(Join-Path -Path $LocalAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\startupCache\*")
	(Join-Path -Path $GlobalAppData -ChildPath "Mozilla\Firefox\Profiles\*.default\datareporting\*")
	#Internet Explorer
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Internet Explorer\*.log")
	(Join-Path -Path $RootAppData -ChildPath "Microsoft\Internet Explorer\*.log")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Internet Explorer\*.txt")
	(Join-Path -Path $RootAppData -ChildPath "Microsoft\Internet Explorer\*.txt")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Internet Explorer\CacheStorage\*.*")
	(Join-Path -Path $RootAppData -ChildPath "Microsoft\Internet Explorer\CacheStorage\*.*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Windows\INetCache\*")
	(Join-Path -Path $RootAppData -ChildPath "Microsoft\Windows\INetCache\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Windows\Temporary Internet Files\*")
	(Join-Path -Path $RootAppData -ChildPath "Microsoft\Windows\Temporary Internet Files\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Windows\IECompatCache\*")
	(Join-Path -Path $RootAppData -ChildPath "Microsoft\Windows\IECompatCache\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Windows\IECompatUaCache\*")
	(Join-Path -Path $RootAppData -ChildPath "Microsoft\Windows\IECompatUaCache\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Windows\IEDownloadHistory\*")
	(Join-Path -Path $RootAppData -ChildPath "Microsoft\Windows\IEDownloadHistory\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Windows\INetCookies\*")
	(Join-Path -Path $RootAppData -ChildPath "Microsoft\Windows\INetCookies\*")
	(Join-Path -Path $Env:SystemRoot -ChildPath "SysWOW64\config\systemprofile\AppData\Local\Microsoft\Windows\INetCache\IE\*")
	#Edge
	(Join-Path -Path $RootAppData -ChildPath "Packages\$EdgePackageName\AC\#!00*")
	(Join-Path -Path $LocalAppData -ChildPath "Packages\$EdgePackageName\AC\#!00*")
	(Join-Path -Path $RootAppData -ChildPath "Packages\$EdgePackageName\AC\Temp\*")
	(Join-Path -Path $LocalAppData -ChildPath "Packages\$EdgePackageName\AC\Temp\*")
	(Join-Path -Path $RootAppData -ChildPath "Packages\$EdgePackageName\AC\Microsoft\Cryptnet*Cache\*")
	(Join-Path -Path $LocalAppData -ChildPath "Packages\$EdgePackageName\AC\Microsoft\Cryptnet*Cache\*")
	(Join-Path -Path $RootAppData -ChildPath "Packages\$EdgePackageName\AC\MicrosoftEdge\Cookies\*")
	(Join-Path -Path $LocalAppData -ChildPath "Packages\$EdgePackageName\AC\MicrosoftEdge\Cookies\*")
	(Join-Path -Path $RootAppData -ChildPath "Packages\$EdgePackageName\AC\MicrosoftEdge\UrlBlock\*.tmp")
	(Join-Path -Path $LocalAppData -ChildPath "Packages\$EdgePackageName\AC\MicrosoftEdge\UrlBlock\*.tmp")
	(Join-Path -Path $RootAppData -ChildPath "Packages\$EdgePackageName\AC\MicrosoftEdge\User\Default\ImageStore\*")
	(Join-Path -Path $LocalAppData -ChildPath "Packages\$EdgePackageName\AC\MicrosoftEdge\User\Default\ImageStore\*")
	(Join-Path -Path $RootAppData -ChildPath "Packages\$EdgePackageName\AC\MicrosoftEdge\User\Default\Recovery\Active\*.dat")
	(Join-Path -Path $LocalAppData -ChildPath "Packages\$EdgePackageName\AC\MicrosoftEdge\User\Default\Recovery\Active\*.dat")
	(Join-Path -Path $RootAppData -ChildPath "Packages\$EdgePackageName\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\*\DBStore\LogFiles\*")
	(Join-Path -Path $LocalAppData -ChildPath "Packages\$EdgePackageName\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\*\DBStore\LogFiles\*")
	(Join-Path -Path $RootAppData -ChildPath "Packages\$EdgePackageName\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\*\Favorites\*.ico")
	(Join-Path -Path $LocalAppData -ChildPath "Packages\$EdgePackageName\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\*\Favorites\*.ico")
	(Join-Path -Path $RootAppData -ChildPath "Packages\$EdgePackageName\AppData\User\Default\Indexed DB\*")
	(Join-Path -Path $LocalAppData -ChildPath "Packages\$EdgePackageName\AppData\User\Default\Indexed DB\*")
	(Join-Path -Path $RootAppData -ChildPath "Packages\$EdgePackageName\TempState\*")
	(Join-Path -Path $LocalAppData -ChildPath "Packages\$EdgePackageName\TempState\*")
	(Join-Path -Path $RootAppData -ChildPath "Packages\$EdgePackageName\LocalState\Favicons\PushNotificationGrouping\*")
	(Join-Path -Path $LocalAppData -ChildPath "Packages\$EdgePackageName\LocalState\Favicons\PushNotificationGrouping\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\*.pma")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\BrowserMetrics\*.pma")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\CrashPad\metadata")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\BudgetDatabase")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Cache\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Code Cache\js\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Code Cache\wasm\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Cookies")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\data_reduction_proxy_leveldb\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Extension State\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Favicons\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Feature Engagement Package\AvailabilityDB\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Feature Engagement Package\EventDB\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\File System\000\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\File System\Origins\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\IndexedDB\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Service Worker\CacheStorage\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Service Worker\Database\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Service Worker\ScriptCache\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Current Tabs")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Last Tabs")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\History")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\History Provider Cache")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\History-journal")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Network Action Predictor")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Top Sites")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Visited Links")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Login Data")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\CURRENT")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\LOCK")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\MANIFEST-*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\*.log")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\*\*.log")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\*\*log*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\*\MANIFEST-*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Shortcuts")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\QuotaManager")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Web Data")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Current Session")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Last Session")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Session Storage\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Site Characteristics Database\*")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Edge\User Data\Profile *\Sync Data\LevelDB\*")
	(Join-Path -Path $Env:ProgramData -ChildPath "Microsoft\EdgeUpdate\Log\*")
	(Join-Path -Path ${Env:ProgramFiles(x86)} -ChildPath "Microsoft\Edge\Application\SetupMetrics\*.pma")
	(Join-Path -Path ${Env:ProgramFiles(x86)} -ChildPath "Microsoft\EdgeUpdate\Download\*")
)
$BrowserPathsToDelete | ForEach-Object {
	if (@(Get-Item $_ -Force)) {
		ForEach ($SubItem in @($_)) {
			if (Get-Item $SubItem -Force) {
				Try {
					Get-Item $SubItem -Force | ForEach-Object { Remove-PathForcefully -Path $_.FullName }
				} Catch {
					Write-Host "Not worth it for $SubItem"
				}
			}
		}
	}
}
Write-StepStatus -StepName "Browser cache cleanup"

# --- cleanmgr.exe runs ---
Write-StepStatus -StepName "Windows Disk Cleanup Manager" -Start
Invoke-WindowsCleanMgr
Write-StepStatus -StepName "Windows Disk Cleanup Manager"

# --- Orphaned MSI/MSP installer files ---
Write-StepStatus -StepName "Orphaned installer files" -Start
Write-Host "Removing Orphaned Installer Files" ; Remove-OrphanedInstallerFiles
Write-StepStatus -StepName "Orphaned installer files"

# --- Stale Outlook OST/BAK files (1-10 GB each) ---
Write-StepStatus -StepName "Stale Outlook files" -Start
@($(Get-Item -Path (Join-Path -Path $LocalAppData -ChildPath "Microsoft\Outlook\*.ost") -Force) | Where-Object -Property "LastWriteTime" -lt $((Get-Date).AddDays(-30))) | ForEach-Object {
	if ($_ -and (Test-Path $_.FullName)) { Remove-PathForcefully -Path $_.FullName }
}
@($(Get-Item -Path (Join-Path -Path $LocalAppData -ChildPath "Microsoft\Outlook\*.bak") -Force) | Where-Object -Property "LastWriteTime" -lt $((Get-Date).AddDays(-30))) | ForEach-Object {
	if ($_ -and (Test-Path $_.FullName)) { Remove-PathForcefully -Path $_.FullName }
}
Write-StepStatus -StepName "Stale Outlook files"

# --- Outlook temp attachments (Content.Outlook) ---
Write-StepStatus -StepName "Outlook temp attachments" -Start
@(Get-Item -Path (Join-Path -Path $LocalAppData -ChildPath "Microsoft\Windows\INetCache\Content.Outlook\*") -Force) | ForEach-Object {
	if ($_ -and (Test-Path $_.FullName)) { Remove-PathForcefully -Path $_.FullName }
}
Write-StepStatus -StepName "Outlook temp attachments"

# --- Remove Restore Points / Shadow Copies ---
Write-StepStatus -StepName "Remove Restore Points" -Start
Write-Host "Removing Restore Points" ; Remove-WindowsRestorePoints
Write-StepStatus -StepName "Remove Restore Points"

# --- Downloads deduplication ---
Write-StepStatus -StepName "Downloads deduplication" -Start
$FoldersToDeDuplicate = @(
	(Join-Path -Path ($Env:Public).Replace('Public', '*') -ChildPath "Downloads")
)
$FoldersToDeDuplicate | ForEach-Object {
	if (@(Get-Item $_ -Force)) {
		ForEach ($SubItem in @($_)) {
			if (Get-Item $SubItem -Force) {
				Write-Host $SubItem
				Try {
					Get-Item $SubItem -Force | ForEach-Object {
						Write-Host "Searching $($_.FullName) for duplicate files"
						Remove-DuplicateFiles -Path $_.FullName
						Write-Host
					}
				} Catch {
					Write-Host "Not worth it for $SubItem"
				}
			}
		}
	}
}
Write-StepStatus -StepName "Downloads deduplication"

# --- Teams cache cleanup ---
Write-StepStatus -StepName "Teams cache cleanup" -Start
# Teams Classic
$TeamsClassicPaths = @(
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Teams\Cache")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Teams\blob_storage")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Teams\databases")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Teams\GPUCache")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Teams\IndexedDB")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Teams\Local Storage")
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Teams\tmp")
)
$TeamsClassicPaths | ForEach-Object {
	@(Get-Item $_ -Force) | ForEach-Object {
		if ($_ -and (Test-Path $_.FullName)) { Remove-PathForcefully -Path $_.FullName }
	}
}
# New Teams (ms-teams)
@(Get-Item -Path (Join-Path -Path $LocalAppData -ChildPath "Packages\MSTeams_*\LocalCache") -Force) | ForEach-Object {
	if ($_ -and (Test-Path $_.FullName)) { Remove-PathForcefully -Path $_.FullName }
}
Write-StepStatus -StepName "Teams cache cleanup"

# --- OneDrive dehydration for inactive users ---
Write-StepStatus -StepName "OneDrive dehydration" -Start
Invoke-OneDriveDehydration
Write-StepStatus -StepName "OneDrive dehydration"

########################################
# PHASE 4: LOWER IMPACT (tens to hundreds of MB)
########################################

# --- Crash dumps ---
Write-StepStatus -StepName "Crash dump cleanup" -Start
$CrashDumpPaths = @(
	(Join-Path -Path $Env:SystemRoot -ChildPath "*.dmp")
	(Join-Path -Path $Env:SystemDrive -ChildPath "*.dmp")
	(Join-Path -Path $Env:SystemDrive -ChildPath "LiveKernelReports\*.dmp")
	(Join-Path -Path $Env:SystemRoot -ChildPath "minidump")
	(Join-Path -Path $LocalAppData -ChildPath "CrashDumps")
	(Join-Path -Path $RootAppData -ChildPath "CrashDumps")
)
$CrashDumpPaths | ForEach-Object {
	@(Get-Item $_ -Force) | ForEach-Object {
		if ($_ -and (Test-Path $_.FullName)) { Remove-PathForcefully -Path $_.FullName }
	}
}
Write-StepStatus -StepName "Crash dump cleanup"

# --- Log file cleanup ---
Write-StepStatus -StepName "Log file cleanup" -Start
$LogPaths = @(
	(Join-Path -Path $Env:SystemRoot -ChildPath "debug\WIA\*.log")
	(Join-Path -Path $Env:SystemRoot -ChildPath "INF\*.log*")
	(Join-Path -Path $Env:SystemRoot -ChildPath "Logs\CBS\*Persist*")
	(Join-Path -Path $Env:SystemRoot -ChildPath "Logs\dosvc\*.*")
	(Join-Path -Path $Env:SystemRoot -ChildPath "Logs\MeasuredBoot\*.log")
	(Join-Path -Path $Env:SystemRoot -ChildPath "Logs\NetSetup\*.*")
	(Join-Path -Path $Env:SystemRoot -ChildPath "Logs\SIH\*.*")
	(Join-Path -Path $Env:SystemRoot -ChildPath "Logs\WindowsBackup\*.etl")
	(Join-Path -Path $Env:SystemRoot -ChildPath "Panther\UnattendGC\*.log")
	(Join-Path -Path $Env:SystemRoot -ChildPath "Logs\DISM")
	(Join-Path -Path $Env:SystemRoot -ChildPath "security\logs")
	(Join-Path -Path $Env:ProgramData -ChildPath "Microsoft\Windows\WER\ReportArchive")
	(Join-Path -Path $Env:ProgramData -ChildPath "Microsoft\Windows\WER\ReportQueue")
	(Join-Path -Path $RootAppData -ChildPath "Microsoft\Windows\WER")
)
$LogPaths | ForEach-Object {
	@(Get-Item $_ -Force) | ForEach-Object {
		if ($_ -and (Test-Path $_.FullName)) { Remove-PathForcefully -Path $_.FullName }
	}
}
Write-StepStatus -StepName "Log file cleanup"

# --- Duplicate driver removal ---
Write-StepStatus -StepName "Duplicate driver removal" -Start
Write-Host "Removing Duplicate Drivers" ; Remove-DuplicateDrivers
Write-StepStatus -StepName "Duplicate driver removal"

# --- WMI repository salvage ---
Write-StepStatus -StepName "WMI repository cleanup" -Start
Write-Host "Cleaning up the WMI Repository" ; Winmgmt /salvagerepository
Write-StepStatus -StepName "WMI repository cleanup"

# --- IE temp data via rundll32 ---
Write-StepStatus -StepName "IE temp data cleanup" -Start
Write-Host "Erasing IE Temp Data" ; Start-Process -FilePath rundll32.exe -ArgumentList 'inetcpl.cpl,ClearMyTracksByProcess 4351' -Wait -NoNewWindow
Write-StepStatus -StepName "IE temp data cleanup"

# --- Event log clearing ---
Write-StepStatus -StepName "Event log clearing" -Start
Write-Host "Clearing Event Logs" ; Remove-EventLogs
Write-StepStatus -StepName "Event log clearing"

# --- Prefetch cleanup ---
Write-StepStatus -StepName "Prefetch cleanup" -Start
$prefetchPath = Join-Path -Path $Env:SystemRoot -ChildPath "Prefetch"
if (Test-Path $prefetchPath) { Remove-StaleObjects -targetDirectory $prefetchPath -DaysOld $DaysToDelete }
Write-StepStatus -StepName "Prefetch cleanup"

# --- Java/Flash/Adobe caches ---
Write-StepStatus -StepName "Java/Flash/Adobe cache cleanup" -Start
$AppCachePaths = @(
	(Join-Path -Path ($Env:Public).Replace('Public', '*') -ChildPath "AppData\Locallow\sun\java\deployment\cache")
	(Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath "Common Files\Adobe\Reader\Temp")
	(Join-Path -Path $env:ProgramData -ChildPath "Adobe\ARM")
	(Join-Path -Path $Env:SystemDrive -ChildPath "adobeTemp")
)
$AppCachePaths | ForEach-Object {
	@(Get-Item $_ -Force) | ForEach-Object {
		if ($_ -and (Test-Path $_.FullName)) { Remove-PathForcefully -Path $_.FullName }
	}
}
Write-StepStatus -StepName "Java/Flash/Adobe cache cleanup"

# --- RDP cache files ---
Write-StepStatus -StepName "RDP cache cleanup" -Start
@(
	(Join-Path -Path $LocalAppData -ChildPath "Microsoft\Terminal Server Client\Cache")
	(Join-Path -Path $RootAppData -ChildPath "Microsoft\Terminal Server Client\Cache")
) | ForEach-Object {
	if (@(Get-Item $_ -Force)) {
		Get-Item $_ -Force | ForEach-Object { Remove-StaleObjects -targetDirectory $_.FullName -DaysOld $DaysToDelete }
	}
}
Write-StepStatus -StepName "RDP cache cleanup"

# --- WinSxS ManifestCache ---
Write-StepStatus -StepName "WinSxS ManifestCache" -Start
@(Get-Item -Path (Join-Path -Path $Env:SystemRoot -ChildPath "WinSxS\ManifestCache\*") -Force) | ForEach-Object {
	if ($_ -and (Test-Path $_.FullName)) { Remove-PathForcefully -Path $_.FullName }
}
Write-StepStatus -StepName "WinSxS ManifestCache"

# --- Misc system paths (Intel, PerfLogs, swsetup, swtools, etc.) ---
Write-StepStatus -StepName "Misc system folder cleanup" -Start
$MiscPaths = @(
	(Join-Path -Path $Env:HOMEDRIVE -ChildPath "Intel")
	(Join-Path -Path $Env:HOMEDRIVE -ChildPath "PerfLogs")
	(Join-Path -Path $Env:SystemDrive -ChildPath "swsetup")
	(Join-Path -Path $Env:SystemDrive -ChildPath "swtools")
	(Join-Path -Path $Env:SystemDrive -ChildPath "TMP")
	(Join-Path -Path $Env:SystemDrive -ChildPath "TempPath")
	(Join-Path -Path $Env:SystemDrive -ChildPath "OneDriveTemp")
	(Join-Path -Path $Env:SystemDrive -ChildPath "IT\NiniteDownloads")
	(Join-Path -Path $Env:SystemDrive -ChildPath "File*.chk")
	(Join-Path -Path $Env:SystemDrive -ChildPath "Found.*\*.chk")
	(Join-Path -Path $Env:SystemDrive -ChildPath "*.tmp")
	(Join-Path -Path $Env:SystemDrive -ChildPath "hiberfil.sys")
	(Join-Path -Path $Env:ProgramData -ChildPath "Microsoft\Windows\RetailDemo")
	(Join-Path -Path $LocalAppData -ChildPath "IsolatedStorage\")
	(Join-Path -Path $Env:HOMEDRIVE -ChildPath "inetpub\logs\LogFiles")
	(Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath "ITSPlatform\agentcore\download")
	#Quickbooks
	(Join-Path -Path $Env:ProgramData -ChildPath "Intuit\QuickBooks*\Components\DownloadQB*")
	(Join-Path -Path $Env:ProgramData -ChildPath "Intuit\QuickBooks*\Components\QBUpdateCache")
)
$MiscPaths | ForEach-Object {
	@(Get-Item $_ -Force) | ForEach-Object {
		if ($_ -and (Test-Path $_.FullName)) { Remove-PathForcefully -Path $_.FullName }
	}
}
Write-StepStatus -StepName "Misc system folder cleanup"

# --- GPU shader caches ---
Write-StepStatus -StepName "GPU shader cache cleanup" -Start
$GpuCachePaths = @(
	(Join-Path -Path $LocalAppData -ChildPath "NVIDIA\DXCache")
	(Join-Path -Path $LocalAppData -ChildPath "NVIDIA\GLCache")
	(Join-Path -Path $LocalAppData -ChildPath "AMD\DxCache")
	(Join-Path -Path $LocalAppData -ChildPath "AMD\GLCache")
)
$GpuCachePaths | ForEach-Object {
	@(Get-Item $_ -Force) | ForEach-Object {
		if ($_ -and (Test-Path $_.FullName)) { Remove-PathForcefully -Path $_.FullName }
	}
}
Write-StepStatus -StepName "GPU shader cache cleanup"

# --- Thumbnail caches ---
Write-StepStatus -StepName "Thumbnail cache cleanup" -Start
@(Get-Item -Path (Join-Path -Path $LocalAppData -ChildPath "Microsoft\Windows\Explorer\thumbcache_*.db") -Force) | ForEach-Object {
	if ($_ -and (Test-Path $_.FullName)) { Remove-PathForcefully -Path $_.FullName }
}
Write-StepStatus -StepName "Thumbnail cache cleanup"

# --- Font cache files ---
Write-StepStatus -StepName "Font cache cleanup" -Start
@(Get-Item -Path (Join-Path -Path $Env:SystemRoot -ChildPath "ServiceProfiles\LocalService\AppData\Local\FontCache\*.dat") -Force) | ForEach-Object {
	if ($_ -and (Test-Path $_.FullName)) { Remove-PathForcefully -Path $_.FullName }
}
Write-StepStatus -StepName "Font cache cleanup"

########################################
# PHASE 5: NTFS COMPRESSION (non-destructive, reclaims space in-place)
########################################

Write-StepStatus -StepName "NTFS Compression" -Start
Enable-NTFSCompression -Path "$Env:SystemRoot\Installer"
Enable-NTFSCompression -Path "$Env:SystemRoot\Logs"
Enable-NTFSCompression -Path "$Env:SystemRoot\WinSxS\Backup"
Enable-NTFSCompression -Path "$Env:SystemRoot\INF"
Enable-NTFSCompression -Path "$Env:SystemRoot\Help"
Write-StepStatus -StepName "NTFS Compression"

########################################
# PHASE 6: EMERGENCY — Windows Search Index (only if <10 GB free)
########################################

$currentFreeGB = Get-FreeSpaceGB
if ($currentFreeGB -lt 10) {
	Write-StepStatus -StepName "Windows Search Index reset (emergency)" -Start
	Write-Host "Free space is ${currentFreeGB} GB (< 10 GB). Resetting Windows Search Index as emergency measure."
	Reset-WindowsSearchIndex
	Write-StepStatus -StepName "Windows Search Index reset (emergency)"
} else {
	Write-Host "`n--- Skipping Windows Search Index reset: ${currentFreeGB} GB free (>= 10 GB threshold) ---" -ForegroundColor Yellow
}

########################################
# PHASE 7: POST-CLEANUP
########################################

Get-Service -Name wuauserv | Start-Service -Verbose #Starts Windows Update.

$PostClean = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object -Property DriveType -EQ 3 | Where-Object -Property DeviceID -EQ $Env:SystemDrive | Select-Object -Property @{ Name = 'Drive'; Expression = { ($PSItem.DeviceID) } },
	@{ Name = 'Size (GB)'; Expression = { '{0:N1}' -f ($PSItem.Size / 1GB) } },
	@{ Name = 'FreeSpace (GB)'; Expression = { '{0:N1}' -f ($PSItem.Freespace / 1GB) } },
	@{ Name = 'PercentFree'; Expression = { '{0:P1}' -f ($PSItem.FreeSpace / $PSItem.Size) } }

## Before and after info for ticketing purposes
Write-Host "`n========================================"
Write-Host "         CLEANUP COMPLETE"
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nBefore Clean-up:`n$(($PreClean | Format-Table | Out-String).Trim())"
Write-Host "`nAfter Clean-up:`n$(($PostClean | Format-Table | Out-String).Trim())"
Write-Host -ForegroundColor Green "`nFreed up: $($PostClean.'FreeSpace (GB)' - $PreClean.'FreeSpace (GB)') GB ($((($PostClean.PercentFree).Replace('%','')) - (($PreClean.PercentFree).Replace('%',''))) %)"

## Per-step summary
Write-Host "`n--- Space Freed Per Step ---" -ForegroundColor Cyan
$Script:StepLog | Where-Object { $_.FreedGB -gt 0 } | Sort-Object FreedGB -Descending | Format-Table -Property @{
	Name = 'Step'; Expression = { $_.Step }; Width = 45
}, @{
	Name = 'Freed (GB)'; Expression = { '{0:N2}' -f $_.FreedGB }; Width = 12
} | Out-String | Write-Host

$totalFreed = [math]::Round(($Script:StepLog | Measure-Object -Property FreedGB -Sum).Sum, 2)
Write-Host "Total freed across all steps: ${totalFreed} GB" -ForegroundColor Green

Write-Host ((Get-Date).DateTime)
Write-Host $env:COMPUTERNAME
