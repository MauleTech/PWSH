function Update-ClaudeCode {
	<#
	.SYNOPSIS
		Updates Claude Code to the latest version.
	.DESCRIPTION
		Checks for updates and reinstalls Claude Code if a newer version is available.
		Requires Administrator privileges for system-wide install.
	.PARAMETER Force
		Update even if already on latest version.
	.PARAMETER Quiet
		Suppress output, return $true/$false only.
	.EXAMPLE
		Update-ClaudeCode
	.EXAMPLE
		Update-ClaudeCode -Force
	.NOTES
		Requires: Administrator privileges for system-wide update
	#>
	[CmdletBinding()]
	param(
		[switch]$Force,
		[switch]$Quiet
	)

	# Paths
	if (-not $Global:ITFolder) { $Global:ITFolder = "$env:SystemDrive\IT" }
	$ClaudeFolder = "$Global:ITFolder\ClaudeCode"
	$ClaudeExe = "$ClaudeFolder\claude.exe"

	# Check if installed
	if (-not (Test-Path $ClaudeExe)) {
		if (-not $Quiet) {
			Write-Host "[!] Claude Code is not installed." -ForegroundColor Red
			Write-Host "    Run Install-ClaudeCode first." -ForegroundColor Yellow
		}
		return $false
	}

	# Ensure in PATH
	if ($env:Path -notlike "*$ClaudeFolder*") { $env:Path = "$env:Path;$ClaudeFolder" }

	# Get current version
	$CurrentVersion = $null
	try {
		$CurrentVersion = (& $ClaudeExe --version 2>$null).Trim()
	} catch { }

	# Get latest version
	$LatestVersion = $null
	try {
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
		$npmInfo = Invoke-RestMethod -Uri "https://registry.npmjs.org/@anthropic-ai/claude-code/latest" -UseBasicParsing -ErrorAction SilentlyContinue
		if ($npmInfo.version) { $LatestVersion = $npmInfo.version }
	} catch {
		if (-not $Quiet) {
			Write-Host "[!] Could not check for updates." -ForegroundColor Yellow
		}
	}

	# Compare versions
	$NeedsUpdate = $false
	if ($Force) {
		$NeedsUpdate = $true
	} elseif ($CurrentVersion -and $LatestVersion) {
		if ($CurrentVersion -ne $LatestVersion) {
			$NeedsUpdate = $true
		}
	} elseif (-not $CurrentVersion) {
		# Can't determine version, offer update
		$NeedsUpdate = $true
	}

	if (-not $NeedsUpdate) {
		if (-not $Quiet) {
			Write-Host "[OK] Claude Code is up to date ($CurrentVersion)" -ForegroundColor Green
		}
		return $true
	}

	if (-not $Quiet) {
		Write-Host "`n=== Updating Claude Code ===" -ForegroundColor Cyan
		if ($CurrentVersion) { Write-Host "Current version: $CurrentVersion" -ForegroundColor Gray }
		if ($LatestVersion) { Write-Host "Latest version:  $LatestVersion" -ForegroundColor Gray }
	}

	# Check admin for system-wide update
	$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = New-Object Security.Principal.WindowsPrincipal($identity)
	if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		if (-not $Quiet) {
			Write-Host "[!] Administrator privileges required for update." -ForegroundColor Red
			Write-Host "    Run PowerShell as Administrator and try again." -ForegroundColor Yellow
		}
		return $false
	}

	# Run install with force to update
	$result = Install-ClaudeCode -Force

	if ($result -and -not $Quiet) {
		# Get new version
		try {
			$NewVersion = (& $ClaudeExe --version 2>$null).Trim()
			Write-Host "Updated to version: $NewVersion" -ForegroundColor Green
		} catch { }
	}

	return $result
}

Function Update-DattoAgent {
	Enable-SSL
	$progressPreference = 'silentlyContinue'
	Invoke-WebRequest https://raw.githubusercontent.com/MauleTech/PWSH/master/Scripts/Datto-Agent-Update/DattoAgentUpdate.txt -usebasicparsing | Invoke-Expression
}

Function Update-DellPackages {
	<#
	.SYNOPSIS
		Uses the CLI version of Dell Command | Update to install any missing drivers/firmwares/Bios and update existing ones.
	.PARAMETER EnableAdvancedDriverRestore
		Enables Advanced Driver Restore feature in Dell Command Update, allowing restoration to any previously installed driver version.
	.LINK
		https://www.dell.com/support/kbdoc/en-us/000177325/dell-command-update
	.EXAMPLE
		Update-DellPackages
	.EXAMPLE
		Update-DellPackages -EnableAdvancedDriverRestore
	#>
	[CmdletBinding()]
	Param(
		[Parameter()]
		[switch]$EnableAdvancedDriverRestore
	)

	Write-Host "Dell Updates"
		$Manufact = (Get-CimInstance -Class Win32_ComputerSystem).Manufacturer
		If ( $Manufact -match "Dell" -or $Manufact -match "Alienware") {
			#Install and update Chocolatey if Needed
			If (Get-Command choco -errorAction SilentlyContinue) {
				choco upgrade chocolatey -y
			} Else { Install-Choco }

			Stop-Process -Name DellCommandUpdate -Force -ErrorAction SilentlyContinue
			$DCUx86 = Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath "Dell\CommandUpdate\dcu-cli.exe"
			$DCUx64 = Join-Path -Path $Env:ProgramFiles -ChildPath "Dell\CommandUpdate\dcu-cli.exe"

			Function Install-DCU {
				#Starts the IPMI Service if needed
				$IPMIService = (Get-Service -Name IPMIDRV -ErrorAction SilentlyContinue).Status
				If ($IPMIService -and $IPMIService -ne "Running") {Start-Service -Name IPMIDRV}
				#Install the latest
				Stop-Process -Name DellCommandUpdate -Force -ErrorAction SilentlyContinue
				If (Get-Command winget -ErrorAction SilentlyContinue) {
					winget source update
					winget install --id Dell.CommandUpdate -e -h --accept-package-agreements --accept-source-agreements --source winget
				} Else {
					Choco upgrade DellCommandUpdate --exact -y --force --forcedependencies -i --ignorechecksums
				}
			}

			If ((!(Test-Path $DCUx86)) -and (!(Test-Path $DCUx64))) {
				Write-Host "Checking if 'Dell Command | Update' is current."
				#Remove any Windows 10 "Apps"
				Get-ProvisionedAppPackage -Online -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like "*Dell*Update*"} | Remove-ProvisionedAppPackage -Online
				Uninstall-Application -AppToUninstall "Dell*Update"
				Get-Package "Dell*Windows 10" -ErrorAction SilentlyContinue | Uninstall-Package -AllVersions -Force
				Uninstall-Application -AppToUninstall "Alienware Update for Windows Universal" -ErrorAction SilentlyContinue
				If (Get-AppxPackage *Dell*Update*){
					$apps = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall,HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object {$_.DisplayName -like "Dell*Update*" } | Select-Object -Property DisplayName, UninstallString
					ForEach ($ver in $apps) {
						If ($ver.UninstallString) {
							$uninst = $ver.UninstallString
							Write-Host Uninstalling: $ver.DisplayName
							Start-Process cmd -ArgumentList "/c $uninst /quiet /norestart" -NoNewWindow -Wait -PassThru
						}
					}
				}
			}
			#Compare version numbers of any remaining installed version.
			$DCUInstalledVersion = (Get-Package -Provider Programs -IncludeWindowsInstaller -Name "Dell Command | Update" -ErrorAction SilentlyContinue).Version
			If (-not $DCUInstalledVersion -and (Test-Path $DCUx86 -ErrorAction SilentlyContinue)) {$DCUInstalledVersion = (Get-Item $DCUx86).VersionInfo.ProductVersion}
			If (-not $DCUInstalledVersion -and (Test-Path $DCUx64 -ErrorAction SilentlyContinue)) {$DCUInstalledVersion = (Get-Item $DCUx64).VersionInfo.ProductVersion}
			If (Get-Command winget -ErrorAction SilentlyContinue) {
				$DCUAvailableVersion = $(winget show --id Dell.CommandUpdate --accept-source-agreements | Select-String -SimpleMatch "Version:").Line.Replace("Version: ","")
			} Else {
				$DCUAvailableVersion = choco search DellCommandUpdate --exact #Gets all results
				$DCUAvailableVersion = ($DCUAvailableVersion | Select-String -Pattern "DellCommandUpdate " -SimpleMatch).Line #Isolates the desired result
				$DCUAvailableVersion = $DCUAvailableVersion.split(" ",[System.StringSplitOptions]::RemoveEmptyEntries)[1] #Isolates the version number
			}

			If (-not $DCUInstalledVersion) {
				Write-Host "'Dell Command | Update' is not installed, installing now."
				Install-DCU

			} ElseIf ($DCUAvailableVersion -and ([System.Version]$DCUInstalledVersion -lt [System.Version]$DCUAvailableVersion)) {
				Write-Host "'Dell Command | Update' is not current. Updating from version $DCUInstalledVersion to $DCUAvailableVersion."

				#Remove any programs listed through "Add and remove programs"
				Uninstall-Application -AppToUninstall "Dell Command | Update" -ErrorAction SilentlyContinue
				Install-DCU

			} Else {
				Write-Host -ForegroundColor Green "'Dell Command | Update' is current (version $DCUInstalledVersion)."
			}

			#Configure and run Dell Command Update
			If (Test-Path $DCUx86) {
				& $DCUx86 /configure -autoSuspendBitLocker=enable -advancedDriverRestore=enable -maxretry=3 -delayDays=14 -scheduleAuto -updatesNotification=disable -scheduleAction=DownloadInstallAndNotify -installationDeferral=disable

				& $DCUx86 /applyUpdates -reboot=disable -forceupdate=enable
			} ElseIf (Test-Path $DCUx64) {
				& $DCUx64 /configure -autoSuspendBitLocker=enable -advancedDriverRestore=enable -maxretry=3 -delayDays=14 -scheduleAuto -updatesNotification=disable -scheduleAction=DownloadInstallAndNotify -installationDeferral=disable

				& $DCUx64 /applyUpdates -reboot=disable -forceupdate=enable
			} Else { Write-Error "Dell Command Update CLI not found."}

		} Else { Write-Host "This is not a Dell Computer" }
	Write-Host "`nEnd of Dell Updates"
}

Function Update-DellServer {
	Write-Host "Please note, this function needs to be periodically updated. See https://downloads.dell.com/omimswac/dsu/ for the latest DSU version."
	Write-Warning "Update-Everything will have a visible impact to any logged in users,`nas it will update drivers and potentially interrupt network connectivity.`nYou have 10 seconds to press CTRL+C to cancel this function."
	$delay = 10

	while ($delay -ge 0)
	{
	  Write-Host "$delay seconds left to cancel"
	  Start-Sleep 1
	  $delay --
	}
	$delay = $null

	$URL = "https://dl.dell.com/FOLDER12418375M/1/Systems-Management_Application_03GC8_WN64_2.1.1.0_A00.EXE"
	$File = "$ITFolder\Dell System Update 2.1.1.0_A00.exe"
	Function Get-DSUInstall {
		Write-Host "Dell System Update is not installed, attempting to install."
		Write-Host "Download the installer to $File"
		Invoke-ValidatedDownload -Uri $URL -OutFile $File
		Write-Host "Download is complete, integrity verified by Invoke-ValidatedDownload."
	}

	Function Install-DSU {
		Write-Host "Attempting to install the program."
		& $File /f /s /i | Wait-Process -ErrorAction SilentlyContinue
	}

	Write-Host "Dell System Updates"
	$Manufact = (Get-CimInstance -Class Win32_ComputerSystem).Manufacturer
	$OSVersion = (get-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
	If( $Manufact -NotLike "*Dell*")
	{
		Write-Host "This is not a Dell Computer"
		Pause
		Exit
	} Else {
		If ( $OSVersion -NotLike "*Server*") {
			Write-Host "This is not a Server."
			Pause
			Exit
		} Else {
			Write-Host "Checkin if DSU is installed"
			If ((Get-WmiObject win32_product | Where-Object -Property Name -Like "*Dell System Update*").Version -NotLike "2.1.1.0*") {
				Write-Host "Dell System Update is either not installed or not version 2.1.1.0"
				Get-DSUInstall
				Install-DSU
			} Else {
				Write-Host "DSU is already installed."
			}

			Write-Host "Installing Dell System Updates"
			& "C:\Program Files\Dell\DELL System Update\DSU.exe" /d /u /n
		}
	}
}

Function Update-DnsServerRootHints{
	<#
	.SYNOPSIS
		Downloads the latest root hints from Public Information Regarding Internet Domain Name Registration Services and sets them. Only works on Windows DNS servers. Useful for resolving the error "DNS: Root hint server X.X.X.X must respond to NS queries for the root zone."
	.LINK
		https://www.internic.net/domain/named.root
	.EXAMPLE
		Update-DnsServerRootHints
	#>
	If (Get-Service -DisplayName "DNS Server" -ErrorAction SilentlyContinue) {
		$url = "https://www.internic.net/domain/named.root"
		$latestRootHints = @{}

		# Download the contents of the URL
		Write-Host "Fetching latest root hints from www.internic.net..." -ForegroundColor Cyan
		$content = Invoke-WebRequest -Uri $url

		# Split the content into lines
		$lines = $content.Content.Split("`r`n") | Where-Object {$_ -notmatch ";|NS|AAAA"}

		# Process each line to extract root hints
		foreach ($line in $lines) {
			if (!($line -like ";*") -and $line.Trim() -ne "") {
				$values = $line.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)
				if ($values.Count -ge 2) {
					$latestRootHints[$values[0]] = $values[-1]
				}
			}
		}

		# Get current root hints
		Write-Host "Retrieving current DNS root hints..." -ForegroundColor Cyan
		$currentRootHints = @{}
		$currentHints = Get-DNSServerRootHint
		foreach ($hint in $currentHints) {
			$nameServer = $hint.NameServer.RecordData.NameServer
			# Look through IP addresses for IPv4 addresses
			foreach ($ipRecord in $hint.IPAddress) {
				if ($ipRecord.RecordData.IPv4Address) {
					$ipAddress = $ipRecord.RecordData.IPv4Address.IPAddressToString
					if ($ipAddress) {
						$currentRootHints[$nameServer] = $ipAddress
						break  # Use the first IPv4 address
					}
				}
			}
		}

		# Create comparison table
		Write-Host "`nDNS Root Hints Comparison:" -ForegroundColor Yellow

		$comparisonTable = @()
		$changesNeeded = $false
		$upToDate = @()
		$needsUpdate = @()
		$missing = @()

		# Compare all root hints
		foreach ($server in ($latestRootHints.Keys | Sort-Object)) {
			$latestIP = $latestRootHints[$server]
			$currentIP = $currentRootHints[$server]

			$status = if ($currentIP -eq $latestIP) {
				$upToDate += $server
				"Up to date"
			} elseif ($null -eq $currentIP) {
				$changesNeeded = $true
				$missing += $server
				"Missing"
			} else {
				$changesNeeded = $true
				$needsUpdate += $server
				"Needs update"
			}

			$comparisonTable += [PSCustomObject]@{
				NameServer = $server
				CurrentIP = if ($currentIP) { $currentIP } else { "N/A" }
				LatestIP = $latestIP
				Status = $status
			}
		}

		# Display the comparison table using Format-Table
		$comparisonTable | Format-Table -AutoSize

		# Display summary with color coding
		Write-Host "Summary:" -ForegroundColor Yellow
		if ($upToDate.Count -gt 0) {
			Write-Host "  Up to date: $($upToDate.Count) root hint(s)" -ForegroundColor Green
		}
		if ($needsUpdate.Count -gt 0) {
			Write-Host "  Needs update: $($needsUpdate.Count) root hint(s) - $($needsUpdate -join ', ')" -ForegroundColor Yellow
		}
		if ($missing.Count -gt 0) {
			Write-Host "  Missing: $($missing.Count) root hint(s) - $($missing -join ', ')" -ForegroundColor Red
		}

		# Only make changes if needed
		if ($changesNeeded) {
			Write-Host "`nChanges detected. Updating DNS root hints..." -ForegroundColor Yellow
			$updatedCount = 0

			foreach ($entry in ($latestRootHints.GetEnumerator() | Sort-Object Name)) {
				$currentIP = $currentRootHints[$entry.Name]

				# Only update if different or missing
				if ($currentIP -ne $entry.Value) {
					# Remove old entry if it exists
					Remove-DnsServerRootHint -Force -NameServer ($entry.Name).ToLower() -ErrorAction SilentlyContinue

					# Add new entry
					Add-DnsServerRootHint -NameServer $entry.Name -IPAddress $entry.Value -Verbose
					$updatedCount++
				}
			}

			Write-Host "`nSuccessfully updated $updatedCount root hint(s)." -ForegroundColor Green
		} else {
			Write-Host "`nAll DNS root hints are already up to date. No changes needed." -ForegroundColor Green
		}

	} Else {
		Write-Warning "You can only run this command on a DNS server."
	}
}

Function Update-Edge {
	Write-Host "Updating Microsoft Edge"
	If (Get-Process MicrosoftEdge -ErrorAction SilentlyContinue) {Get-Process MicrosoftEdge | Stop-Process -Force}
	If (Get-Command winget -ErrorAction SilentlyContinue) {
		winget install --id Microsoft.Edge -e -h --accept-package-agreements --accept-source-agreements
	} Else {
		If (!(Get-Command choco -ErrorAction SilentlyContinue)) {Install-Choco}
		Choco upgrade microsoft-edge -y
	}
}

Function Update-Everything {
	Write-Warning "Update-Everything will have a visible impact to any logged in users,`nas it will update drivers and reboot the computer.`nYou have 10 seconds to press CTRL+C to cancel this function."
	$delay = 10

	while ($delay -ge 0)
	{
		Write-Host "$delay seconds left to cancel"
		Start-Sleep 1
		$delay --
	}
	$delay = $null
	If (Get-Command winget -ErrorAction SilentlyContinue) {
		Update-PSWinGetPackages
	} Else {
		If (Get-Command choco -ErrorAction SilentlyContinue) {choco upgrade all -y}
	}
	Update-Windows
	Update-OEMDrivers
	Update-Edge
	Update-NiniteApps
	Update-PWSH
	Update-PSWinGetPackages
	Restart-ComputerSafely -Force
}

# Update-ITFunctions is defined in LoadFunctions.txt using Sync-PWSHRepository
# (with Invoke-Git timeout protection, GIT_TERMINAL_PROMPT=0, and remote-branch fallback).
# Do NOT redefine it here — this module loads after the bootstrap and would shadow the better version.

Function Update-ITS247Agent {
	$DisplayVersion = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\SAAZOD).DisplayVersion
	$TYPE = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\SAAZOD).TYPE
	$AvailableVersion = ((Invoke-WebRequest https://raw.githubusercontent.com/MauleTech/PWSH/master/Scripts/ITS247Agent/DPMAVersion.txt -UseBasicParsing).Content).Trim()

	If(($DisplayVersion -ne $AvailableVersion) -and ($TYPE -eq "DPMA")) {
	 WRITE-HOST "Updating Agent from $DisplayVersion to $AvailableVersion"
		 $SaveFolder = '$ITFolder'
		 New-Item -ItemType Directory -Force -Path $SaveFolder
		 $PatchPath = $SaveFolder + '\DPMAPatch' + $AvailableVersion + '.exe'
		 Invoke-ValidatedDownload -Uri 'https://update.itsupport247.net/agtupdt/DPMAPatch.exe' -OutFile $PatchPath
		 & $PatchPath | Wait-Process
		 $DisplayVersion = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\SAAZOD).DisplayVersion
	 WRITE-HOST "Agent is now version $DisplayVersion"
	}

	If(($DisplayVersion -eq $AvailableVersion) -and ($TYPE -eq "DPMA")) {
	 WRITE-HOST "Agent appears to be up to date at version $DisplayVersion"
	}
<#
	.SYNOPSIS
		Updates the Continuum ITS247 Desktop agent to the latest available. No parameters are needed.
#>
}

Function Update-NiniteApps {
	<#
	.SYNOPSIS
		Uses NinitePro to immediately update all applications it is cabable of updating. The log will be at $ITFolder\NiniteReport.txt
	#>
	If (-not (Test-Path '$ITFolder\NinitePro.exe')) {Install-NinitePro}
	Write-Host "Install Ninite Apps, waiting for install to complete and logging the results."
		$NiniteCache = "\\adsaltoxl\data\Software\Ninite\NiniteDownloads"
		If(test-path $NiniteCache){
			& $ITFolder\NinitePro.exe /updateonly /cachepath $NiniteCache /silent '$ITFolder\NiniteReport.txt' | Wait-Process
		} ELSE {
			& $ITFolder\NinitePro.exe /updateonly /nocache /silent '$ITFolder\NiniteReport.txt' | Wait-Process
		}
	Get-Content '$ITFolder\NiniteReport.txt'
	Write-Host "End of Install Ninite Apps"
}

function Get-NTPOffset {
	<#
	.SYNOPSIS
		Queries an NTP server and returns time offset information without modifying the system clock.
	.DESCRIPTION
		Connects to an NTP server via UDP port 123, sends an NTP request, and calculates
		the time offset between the local system and the server. Returns a structured object
		with offset metrics. Does not call Set-Date.
	.PARAMETER Server
		The NTP server hostname or IP address to query.
	.PARAMETER TimeoutMs
		Socket send/receive timeout in milliseconds. Defaults to 5000.
	.EXAMPLE
		$result = Get-NTPOffset -Server 'north-america.pool.ntp.org'
		if ($result.Success) { Write-Host "Offset: $($result.OffsetMs)ms" }
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Server,

		[ValidateRange(500, 30000)]
		[int]$TimeoutMs = 5000
	)

	$Result = [PSCustomObject]@{
		Server     = $Server
		OffsetMs   = [double]0
		NTPTimeUtc = [datetime]::MinValue
		Success    = $false
		Error      = $null
	}

	$Socket = $null
	try {
		$StartOfEpoch = New-Object DateTime(1900,1,1,0,0,0,[DateTimeKind]::Utc)
		[Byte[]]$NtpData = ,0 * 48
		$NtpData[0] = 0x1B

		$Socket = New-Object Net.Sockets.Socket(
			[Net.Sockets.AddressFamily]::InterNetwork,
			[Net.Sockets.SocketType]::Dgram,
			[Net.Sockets.ProtocolType]::Udp)
		$Socket.SendTimeout    = $TimeoutMs
		$Socket.ReceiveTimeout = $TimeoutMs
		$Socket.Connect($Server, 123)

		$t1 = Get-Date
		[Void]$Socket.Send($NtpData)
		[Void]$Socket.Receive($NtpData)
		$t4 = Get-Date

		$IntPart  = [BitConverter]::ToUInt32($NtpData[43..40], 0)
		$FracPart = [BitConverter]::ToUInt32($NtpData[47..44], 0)
		$t3ms = $IntPart * 1000 + ($FracPart * 1000 / 0x100000000)

		$IntPart  = [BitConverter]::ToUInt32($NtpData[35..32], 0)
		$FracPart = [BitConverter]::ToUInt32($NtpData[39..36], 0)
		$t2ms = $IntPart * 1000 + ($FracPart * 1000 / 0x100000000)

		$t1ms = ([TimeZoneInfo]::ConvertTimeToUtc($t1) - $StartOfEpoch).TotalMilliseconds
		$t4ms = ([TimeZoneInfo]::ConvertTimeToUtc($t4) - $StartOfEpoch).TotalMilliseconds

		$Offset = (($t2ms - $t1ms) + ($t3ms - $t4ms)) / 2

		$Result.OffsetMs   = $Offset
		$Result.NTPTimeUtc = $StartOfEpoch.AddMilliseconds($t4ms + $Offset)
		$Result.Success    = $true
	} catch {
		$Result.Error = $_.Exception.Message
	} finally {
		if ($Socket) { try { $Socket.Dispose() } catch {} }
	}

	return $Result
}

Function Update-NTPDateTime {
	<#
	.SYNOPSIS
		Updates the system clock from an NTP server with sync diagnostics and optional scheduled task.
	.DESCRIPTION
		Queries a Network Time Protocol server to get the current accurate time and sets the
		local system clock. Before updating, performs a diagnostic comparison between the
		machine's currently configured Windows Time source and the specified NTP server to
		detect sync discrepancies (e.g., a domain controller that has drifted from the
		internet NTP pool).

		Optionally registers a self-contained Windows scheduled task for persistent,
		recurring NTP synchronization without requiring the MauleTech PWSH module.
	.PARAMETER NTPServer
		The NTP server to query. Defaults to 'north-america.pool.ntp.org'.
	.PARAMETER RegisterScheduledTask
		Creates a Windows scheduled task ('MauleTech-NTPSync') that runs the NTP sync at
		boot and on a recurring interval. The task is self-contained and does not require
		the MauleTech PWSH module.
	.PARAMETER UnregisterScheduledTask
		Removes the MauleTech-NTPSync scheduled task if it exists.
	.PARAMETER SyncIntervalHours
		The interval in hours between NTP syncs when using -RegisterScheduledTask.
		Defaults to 12. Valid range: 1-168 (one week).
	.PARAMETER SkipDiagnostics
		Skip the Windows Time source comparison diagnostic step.
	.EXAMPLE
		Update-NTPDateTime
		Syncs the clock with the default NTP server and shows diagnostics.
	.EXAMPLE
		Update-NTPDateTime -NTPServer 'time.nist.gov'
		Syncs the clock with a specific NTP server.
	.EXAMPLE
		Update-NTPDateTime -RegisterScheduledTask
		Creates a scheduled task that syncs NTP at boot and every 12 hours.
	.EXAMPLE
		Update-NTPDateTime -RegisterScheduledTask -SyncIntervalHours 6 -NTPServer 'time.nist.gov'
		Creates a scheduled task with a custom interval and NTP server.
	.EXAMPLE
		Update-NTPDateTime -UnregisterScheduledTask
		Removes the MauleTech-NTPSync scheduled task.
	.EXAMPLE
		Update-NTPDateTime -SkipDiagnostics
		Syncs the clock without comparing against the configured Windows Time source.
	.NOTES
		Requires Administrator privileges to set the system clock or manage scheduled tasks.
	#>
	[CmdletBinding(DefaultParameterSetName = 'Sync')]
	param(
		[Parameter(ParameterSetName = 'Sync')]
		[Parameter(ParameterSetName = 'Register')]
		[ValidateNotNullOrEmpty()]
		[string]$NTPServer = 'north-america.pool.ntp.org',

		[Parameter(Mandatory, ParameterSetName = 'Register')]
		[switch]$RegisterScheduledTask,

		[Parameter(Mandatory, ParameterSetName = 'Unregister')]
		[switch]$UnregisterScheduledTask,

		[Parameter(ParameterSetName = 'Register')]
		[ValidateRange(1, 168)]
		[int]$SyncIntervalHours = 12,

		[Parameter(ParameterSetName = 'Sync')]
		[switch]$SkipDiagnostics
	)

	$TaskName = 'MauleTech-NTPSync'

	# All parameter sets require admin (Set-Date, Register-ScheduledTask, Unregister-ScheduledTask)
	$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
		[Security.Principal.WindowsBuiltInRole]::Administrator)
	if (-not $isAdmin) {
		Write-Host "Administrator privileges are required." -ForegroundColor Red
		return
	}

	#region Unregister Scheduled Task
	if ($PSCmdlet.ParameterSetName -eq 'Unregister') {
		$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
		if ($existingTask) {
			try {
				Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
				Write-Host "Scheduled task '$TaskName' has been removed." -ForegroundColor Green
			} catch {
				Write-Host "Failed to remove scheduled task: $($_.Exception.Message)" -ForegroundColor Red
			}
		} else {
			Write-Host "Scheduled task '$TaskName' does not exist." -ForegroundColor Yellow
		}
		return
	}
	#endregion

	#region Register Scheduled Task
	if ($PSCmdlet.ParameterSetName -eq 'Register') {
		# Validate NTP server name to prevent injection in the encoded command
		if ($NTPServer -notmatch '^[a-zA-Z0-9._-]+$') {
			Write-Host "Invalid NTP server name: $NTPServer" -ForegroundColor Red
			return
		}

		# Build self-contained NTP sync script (no external dependencies)
		# NTPServer was already validated against ^[a-zA-Z0-9._-]+$ above
		$SyncScript = "`$Server = '$NTPServer'" + "`n" +
			'$StartOfEpoch = New-Object DateTime(1900,1,1,0,0,0,[DateTimeKind]::Utc)' + "`n" +
			'[Byte[]]$NtpData = ,0 * 48' + "`n" +
			'$NtpData[0] = 0x1B' + "`n" +
			'$Socket = $null' + "`n" +
			'try {' + "`n" +
			'    $Socket = New-Object Net.Sockets.Socket(' + "`n" +
			'        [Net.Sockets.AddressFamily]::InterNetwork,' + "`n" +
			'        [Net.Sockets.SocketType]::Dgram,' + "`n" +
			'        [Net.Sockets.ProtocolType]::Udp)' + "`n" +
			'    $Socket.SendTimeout    = 10000' + "`n" +
			'    $Socket.ReceiveTimeout = 10000' + "`n" +
			'    $Socket.Connect($Server, 123)' + "`n" +
			'    $t1 = Get-Date' + "`n" +
			'    [Void]$Socket.Send($NtpData)' + "`n" +
			'    [Void]$Socket.Receive($NtpData)' + "`n" +
			'    $t4 = Get-Date' + "`n" +
			'    $IntPart  = [BitConverter]::ToUInt32($NtpData[43..40], 0)' + "`n" +
			'    $FracPart = [BitConverter]::ToUInt32($NtpData[47..44], 0)' + "`n" +
			'    $t3ms = $IntPart * 1000 + ($FracPart * 1000 / 0x100000000)' + "`n" +
			'    $IntPart  = [BitConverter]::ToUInt32($NtpData[35..32], 0)' + "`n" +
			'    $FracPart = [BitConverter]::ToUInt32($NtpData[39..36], 0)' + "`n" +
			'    $t2ms = $IntPart * 1000 + ($FracPart * 1000 / 0x100000000)' + "`n" +
			'    $t1ms = ([TimeZoneInfo]::ConvertTimeToUtc($t1) - $StartOfEpoch).TotalMilliseconds' + "`n" +
			'    $t4ms = ([TimeZoneInfo]::ConvertTimeToUtc($t4) - $StartOfEpoch).TotalMilliseconds' + "`n" +
			'    $Offset = (($t2ms - $t1ms) + ($t3ms - $t4ms)) / 2' + "`n" +
			'    if ([Math]::Abs($Offset) -gt 1000) {' + "`n" +
			'        Set-Date ($StartOfEpoch.AddMilliseconds($t4ms + $Offset).ToLocalTime())' + "`n" +
			'    }' + "`n" +
			'} catch {' + "`n" +
			'} finally {' + "`n" +
			'    if ($Socket) { try { $Socket.Dispose() } catch {} }' + "`n" +
			'}'

		# Check for existing task
		$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
		if ($existingTask) {
			Write-Host "Scheduled task '$TaskName' already exists -- replacing it." -ForegroundColor Yellow
			try {
				Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
			} catch {
				Write-Host "Failed to remove existing task: $($_.Exception.Message)" -ForegroundColor Red
				return
			}
		}

		$encodedCmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($SyncScript))
		$Action = New-ScheduledTaskAction -Execute 'powershell.exe' `
			-Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand $encodedCmd"

		# Two triggers: at startup and repeating every N hours
		$TriggerBoot   = New-ScheduledTaskTrigger -AtStartup
		$TriggerRepeat = New-ScheduledTaskTrigger -Once -At (Get-Date) `
			-RepetitionInterval (New-TimeSpan -Hours $SyncIntervalHours)

		$Settings = New-ScheduledTaskSettingsSet `
			-AllowStartIfOnBatteries `
			-DontStopIfGoingOnBatteries `
			-StartWhenAvailable `
			-ExecutionTimeLimit (New-TimeSpan -Minutes 5)
		$Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

		try {
			Register-ScheduledTask -TaskName $TaskName `
				-Action $Action `
				-Trigger @($TriggerBoot, $TriggerRepeat) `
				-Settings $Settings `
				-Principal $Principal `
				-Description "MauleTech NTP time sync -- syncs clock with $NTPServer" `
				-ErrorAction Stop | Out-Null

			# Set repetition duration to indefinite (cannot be done via New-ScheduledTaskTrigger)
			$task = Get-ScheduledTask -TaskName $TaskName
			$task.Triggers[1].Repetition.Duration = ''
			$task | Set-ScheduledTask | Out-Null

			Write-Host "Scheduled task '$TaskName' created successfully." -ForegroundColor Green
			Write-Host "  NTP Server: $NTPServer" -ForegroundColor Cyan
			Write-Host "  Triggers:   At startup + every $SyncIntervalHours hour(s)" -ForegroundColor Cyan
			Write-Host "  To remove:  Update-NTPDateTime -UnregisterScheduledTask" -ForegroundColor Cyan
		} catch {
			Write-Host "Failed to create scheduled task: $($_.Exception.Message)" -ForegroundColor Red
		}
		return
	}
	#endregion

	#region Sync -- NTP Diagnostics
	$ntpQuery = $null
	$SyncThresholdMs = 2000

	if (-not $SkipDiagnostics) {
		$ConfiguredSource = $null
		try {
			$w32tmOutput = & w32tm /query /source 2>&1
			if ($LASTEXITCODE -eq 0 -and "$w32tmOutput" -notmatch 'error') {
				$ConfiguredSource = ("$w32tmOutput").Trim()
			}
		} catch {}

		# Detect domain membership and VM status
		$computerSystem = $null
		try { $computerSystem = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop } catch {}
		$isDomainJoined = $computerSystem -and $computerSystem.PartOfDomain
		$domainName     = if ($isDomainJoined) { $computerSystem.Domain } else { $null }
		$vmicRunning    = (Get-Service 'vmictimesync' -ErrorAction SilentlyContinue).Status -eq 'Running'

		# Cache PDC and NTP results so each is queried at most once
		$pdcHost = $null
		if ($isDomainJoined) {
			try {
				$pdcHost = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).PdcRoleOwner.Name
			} catch {}
		}
		$ntpQuery  = Get-NTPOffset -Server $NTPServer -TimeoutMs 5000
		$pdcResult = if ($pdcHost) { Get-NTPOffset -Server $pdcHost -TimeoutMs 5000 } else { $null }

		# Helper: compare two NTP results and write output
		function Write-NTPComparison {
			param($ResultA, $NameA, $ResultB, $NameB, [string]$DriftWarning)
			if ($ResultA.Success -and $ResultB.Success) {
				$discrepancyMs  = [Math]::Abs(($ResultA.NTPTimeUtc - $ResultB.NTPTimeUtc).TotalMilliseconds)
				$discrepancySec = [Math]::Round($discrepancyMs / 1000, 2)
				if ($discrepancyMs -gt $SyncThresholdMs) {
					Write-Host "WARNING: '$NameA' is $discrepancySec seconds out of sync with '$NameB'." -ForegroundColor Yellow
					if ($DriftWarning) { Write-Host $DriftWarning -ForegroundColor Yellow }
				} else {
					Write-Host "'$NameA' is in sync with '$NameB' (discrepancy: ${discrepancySec}s)." -ForegroundColor Green
				}
			} else {
				if (-not $ResultA.Success) {
					Write-Host "Could not query '$NameA': $($ResultA.Error)" -ForegroundColor Yellow
				}
				if (-not $ResultB.Success) {
					Write-Host "Could not query '$NameB': $($ResultB.Error)" -ForegroundColor Yellow
				}
			}
		}

		Write-Host "`n=== NTP Sync Diagnostics ===" -ForegroundColor Cyan

		if ($isDomainJoined) {
			Write-Host "Machine is domain-joined: $domainName" -ForegroundColor Cyan
		}
		if ($vmicRunning) {
			Write-Host "Hyper-V Time Synchronization service is running (VM guest)." -ForegroundColor Cyan
		}

		if (-not $ConfiguredSource) {
			Write-Host "Could not query Windows Time source (W32Time service may not be running)." -ForegroundColor Yellow
			if ($isDomainJoined) {
				Write-Host "This machine is domain-joined but W32Time is not responding." -ForegroundColor Yellow
				Write-Host "It should be syncing time from a domain controller." -ForegroundColor Yellow
				if ($pdcHost) {
					Write-Host "PDC emulator: $pdcHost" -ForegroundColor Cyan
					Write-NTPComparison $pdcResult $pdcHost $ntpQuery $NTPServer `
						'The domain controller itself appears to have drifted.'
				}
			}
		} elseif ($ConfiguredSource -eq 'VM IC Time Synchronization Provider') {
			Write-Host "Windows Time source: $ConfiguredSource" -ForegroundColor Cyan
			Write-Host "This machine is syncing time from its Hyper-V host." -ForegroundColor Cyan

			Write-Host "Comparing system time against '$NTPServer' to check for host drift..." -ForegroundColor Cyan
			if ($ntpQuery.Success) {
				$driftMs  = [Math]::Abs($ntpQuery.OffsetMs)
				$driftSec = [Math]::Round($driftMs / 1000, 2)
				if ($driftMs -gt $SyncThresholdMs) {
					Write-Host "WARNING: System clock is $driftSec seconds offset from '$NTPServer'." -ForegroundColor Yellow
					Write-Host "The Hyper-V host may be providing inaccurate time." -ForegroundColor Yellow
				} else {
					Write-Host "System clock is in sync with '$NTPServer' (offset: ${driftSec}s)." -ForegroundColor Green
				}
			} else {
				Write-Host "Could not query NTP server '$NTPServer': $($ntpQuery.Error)" -ForegroundColor Yellow
			}

			if ($pdcHost -and $pdcResult -and $ntpQuery.Success) {
				Write-NTPComparison $pdcResult $pdcHost $ntpQuery $NTPServer
			}
		} elseif ($ConfiguredSource -match '^(Local CMOS Clock|Free-running System Clock)$') {
			Write-Host "Windows Time source: $ConfiguredSource" -ForegroundColor Cyan

			if ($isDomainJoined) {
				Write-Host "WARNING: This machine is domain-joined ($domainName) but is NOT syncing time from a domain controller." -ForegroundColor Yellow
				Write-Host "The Windows Time service may not be configured correctly." -ForegroundColor Yellow

				if ($pdcHost) {
					Write-Host "PDC emulator: $pdcHost" -ForegroundColor Cyan
					Write-NTPComparison $pdcResult $pdcHost $ntpQuery $NTPServer `
						'The domain controller itself appears to have drifted.'
					if ($pdcResult.Success -and $ntpQuery.Success) {
						$discrepancyMs = [Math]::Abs(($pdcResult.NTPTimeUtc - $ntpQuery.NTPTimeUtc).TotalMilliseconds)
						if ($discrepancyMs -le $SyncThresholdMs) {
							Write-Host "The issue is that this machine is not configured to sync from the DC." -ForegroundColor Yellow
						}
					}
				} else {
					Write-Host "Could not discover the PDC emulator for $domainName." -ForegroundColor Yellow
				}
			} elseif ($vmicRunning) {
				Write-Host "Hyper-V Time Sync service is running but W32Time is using Local CMOS Clock." -ForegroundColor Yellow
				Write-Host "VM may be configured to not sync time from the host." -ForegroundColor Yellow
			} else {
				Write-Host "No network time source is configured -- this machine is not using NTP." -ForegroundColor Yellow
			}
		} elseif ($ConfiguredSource -eq $NTPServer -or $ConfiguredSource -match "^$([regex]::Escape($NTPServer)),") {
			Write-Host "Windows Time source: $ConfiguredSource" -ForegroundColor Cyan
			Write-Host "Configured source matches the specified NTP server." -ForegroundColor Green
		} else {
			Write-Host "Configured Windows Time source: $ConfiguredSource" -ForegroundColor Cyan
			Write-Host "Specified NTP server:           $NTPServer" -ForegroundColor Cyan

			$sourceResult = Get-NTPOffset -Server $ConfiguredSource -TimeoutMs 5000
			Write-NTPComparison $sourceResult $ConfiguredSource $ntpQuery $NTPServer `
				'This may indicate your time source (e.g., a domain controller) has drifted.'
		}
		Write-Host ""
	}
	#endregion

	#region Sync -- Set Clock
	Write-Host "Current system date/time is:"
	Write-Host (Get-Date).DateTime

	# Reuse the NTP query from diagnostics if available, otherwise query now
	if (-not $ntpQuery) {
		$ntpQuery = Get-NTPOffset -Server $NTPServer -TimeoutMs 5000
	}
	if (-not $ntpQuery.Success) {
		Write-Host "Failed to query NTP server '$NTPServer': $($ntpQuery.Error)" -ForegroundColor Red
		return
	}

	[String]$NTPDateTime = $ntpQuery.NTPTimeUtc.ToLocalTime()
	$newTime = Set-Date $NTPDateTime
	Write-Host "`nSystem date/time has been set to: $($newTime.DateTime)"

	if ([Math]::Abs($ntpQuery.OffsetMs) -gt 10000) {
		Write-Host "There was an offset of $([Math]::Round($ntpQuery.OffsetMs / 1000, 2)) seconds." -ForegroundColor Yellow
	} else {
		Write-Host "The offset was negligible." -ForegroundColor Green
	}
	#endregion
}

Function Update-O365Apps {
	$global:O365CurrentCdn = ""
	If (-not (Test-Path 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe')) {
		Write-Host "Office 365 Click2Run is not installed. This script does not apply."
	} Else {
		$Apps = @('Excel','Outlook','WinWord','PowerPoint','MsAccess','MSPub','OneNote')
		$OpenApps = @('')
		$Apps | ForEach-Object {
			If (Get-Process $_ -ErrorAction SilentlyContinue) {
				$OpenApps = $OpenApps += $_
			}
		}

		If ($OpenApps) {
			Write-Host "Aborting update, the following Office Apps are open:"
			$OpenApps | Format-List | Out-String
			Write-Host "Please close these programs and try again."
			} Else {
			Function Get-Office365Version {
				$O365CurrentVer = ""
				$O365CurrentCdn = ""
				$O365CurrentPol = ""
				$O365CurrentVer = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" -ErrorAction SilentlyContinue).VersionToReport
				$O365CurrentCdn = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" -ErrorAction SilentlyContinue).CDNBaseUrl
				$O365CurrentPol = (Get-ItemProperty -Path "HKLM:\SOFTWARE\policies\microsoft\office\16.0\common\officeupdate" -ErrorAction SilentlyContinue).updatebranch
				if ($O365CurrentVer.Length -eq 0) {
					Write-Host "Office 365 (C2R) is not installed on this PC."
				} else {
					Write-Host "Office 365 (C2R) Current Version: "$O365CurrentVer
					switch ($O365CurrentCdn) {
						"http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60" {$O365CurrentCdn = "Monthly Channel"}
						"http://officecdn.microsoft.com/pr/7ffbc6bf-bc32-4f92-8982-f9dd17fd3114" {$O365CurrentCdn = "Semi-Annual Channel"}
						"http://officecdn.microsoft.com/pr/b8f9b850-328d-4355-9145-c59439a0c4cf" {$O365CurrentCdn = "Semi-Annual Channel (Targeted)"}
					}
					Write-Host "Office 365 Update Channel (Local Setting): "$O365CurrentCdn
					if ($O365CurrentPol.length -eq 0) {
						$O365CurrentPol = "None"
					} else {
						switch ($O365CurrentPol) {
							"Current" {$O365CurrentPol = "Monthly Channel"}
							"Deferred" {$O365CurrentPol = "Semi-Annual Channel"}
							"FirstReleaseDeferred" {$O365CurrentPol = "Semi-Annual Channel (Targeted)l"}
						}
					}
					Write-Host "Office 365 Update Channel (Policy Setting): "$O365CurrentPol
					Write-Host "`n"
				}
			}

			Function Wait-UpdateStop {
				param
				(
					[Parameter(Mandatory=$False)]
					[string]$Process
				)

				Function Get-SpecificProcess {
					Get-Process OfficeClickToRun -ErrorAction SilentlyContinue | Where-Object -Property Path -Like "*Microsoft Shared\ClickToRun\Updates\*"
				}

				$Timeout = 190 ## seconds
				Try {
					$timer = [Diagnostics.Stopwatch]::StartNew()
					while (($timer.Elapsed.TotalSeconds -lt $Timeout) -and (-not (Get-SpecificProcess))) {
						Start-Sleep -Seconds 2
						$totalSecs = [math]::Round($timer.Elapsed.TotalSeconds, 0)
						Write-Verbose -Message "Still waiting for action to complete after [$totalSecs] seconds..."
					}
					$timer.Stop()
					if ($timer.Elapsed.TotalSeconds -gt $Timeout) {
						Write-Host "Office update either failed or is already up to date"
					} else {
						Do {
							If (!(Get-SpecificProcess)) {
								   Write-Host "Waiting for $Process to Start"
								   Start-Sleep -Seconds 2
							} Else {
							   Write-Host "$Process has Started"
							   While (Get-SpecificProcess) {
										[String]$CPU = (Get-SpecificProcess).CPU
										If ($CPU.Length -gt 4) {$CPU = $CPU.substring(0,4)}
										Write-Host -NoNewLine "`rWaiting for $Process to stop. CPU time = $CPU"
										Start-Sleep -Seconds 5
							   }
							   Write-Host "`n`n$Process Stopped" ; $Status = 'Done'
							}
						} Until ($Status)
					}
				} Catch {
					Write-Error -Message $_.Exception.Message
				}
			}

			Get-Office365Version

			If (!($O365CurrentCdn -like "*monthlty*")) {
				Write-Host "Setting update channel to monthly"
				& "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe" /changesetting Channel=Current
			}

			Write-Host "Updating Office, please wait 120 seconds to see further progress."
				& "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe" /update user updatepromptuser=false forceappshutdown=true displaylevel=false
				Restart-Service -Name "ClickToRunSvc" -Force -ErrorAction SilentlyContinue
				Wait-UpdateStop OfficeClickToRun

				Write-Host "`n"

			Get-Office365Version
		}
	}
}

Function Update-OEMDrivers {
	<#
	.SYNOPSIS
		Detects computer manufacturer and runs appropriate driver/firmware/BIOS update utility.
	.DESCRIPTION
		Automatically detects the computer manufacturer and runs the appropriate update utility:
		- Dell/Alienware: Uses Update-DellPackages (Dell Command Update)
		- HP: Uses OSD module's Invoke-HPIA (HP Image Assistant)
		- Lenovo: Uses OSD module's Lenovo System Updater
		Attempts to suppress reboots where possible.
	.PARAMETER NoReboot
		Suppress automatic reboots after updates (where supported by the utility). This parameter is for future use; current implementation already suppresses reboots.
	.EXAMPLE
		Update-OEMDrivers
		Detects manufacturer and updates drivers/firmware/BIOS
	.EXAMPLE
		Update-OEMDrivers -NoReboot
		Updates drivers/firmware/BIOS without rebooting
	.LINK
		https://github.com/OSDeploy/OSD
	.NOTES
		Requires: Administrator privileges, Internet access
	#>
	[CmdletBinding()]
	Param(
		[Parameter()]
		[switch]$NoReboot
	)

	Write-Host "`n=== OEM Driver/Firmware/BIOS Update ===" -ForegroundColor Cyan

	# Detect manufacturer
	$Manufacturer = (Get-CimInstance -Class Win32_ComputerSystem).Manufacturer
	Write-Host "Detected Manufacturer: $Manufacturer" -ForegroundColor Yellow

	# Dell/Alienware Detection
	If ($Manufacturer -match "Dell" -or $Manufacturer -match "Alienware") {
		Write-Host "`nUsing Dell Command Update via Update-DellPackages..." -ForegroundColor Green
		Update-DellPackages
		Write-Host "`nDell updates completed." -ForegroundColor Green
		return
	}

	# For non-Dell manufacturers, use OSD module
	Write-Host "`nUsing OSD module for manufacturer-specific updates..." -ForegroundColor Yellow

	# Check if OSD module is installed
	If (-not (Get-Module -ListAvailable -Name OSD)) {
		Write-Host "OSD module not found. Installing from PowerShell Gallery..." -ForegroundColor Yellow
		Try {
			Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue
			Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
			Install-Module -Name OSD -Force -AllowClobber -Scope CurrentUser
			Write-Host "OSD module installed successfully." -ForegroundColor Green
		} Catch {
			Write-Error "Failed to install OSD module: $_"
			Write-Host "Please install manually: Install-Module -Name OSD" -ForegroundColor Red
			return
		}
	}

	# Import OSD module
	Try {
		Import-Module OSD -Force -ErrorAction Stop
		Write-Host "OSD module loaded successfully." -ForegroundColor Green
	} Catch {
		Write-Error "Failed to import OSD module: $_"
		return
	}

	# HP Detection
	If ($Manufacturer -match "HP" -or $Manufacturer -match "Hewlett") {
		Write-Host "`nHP system detected. Running HP Image Assistant..." -ForegroundColor Green
		Try {
			# Check if HP device is supported
			If (Get-Command Test-HPIASupport -ErrorAction SilentlyContinue) {
				$HPSupported = Test-HPIASupport
				If (-not $HPSupported) {
					Write-Warning "This HP device may not be fully supported by HP Image Assistant."
				}
			}

			# Run HPIA for drivers, firmware, and BIOS
			# Operation: DownloadSoftPaqs to download and install
			# Category: Drivers, Firmware, BIOS
			# Action: Install to apply updates
			# SilentMode: Suppress UI prompts
			Write-Host "Installing HP Image Assistant and scanning for updates..." -ForegroundColor Cyan
			Write-Host "This may take several minutes..." -ForegroundColor Yellow

			Invoke-HPIA -Operation DownloadSoftPaqs `
						-Category @("Drivers", "Firmware", "BIOS") `
						-Selection All `
						-Action Install `
						-SilentMode `
						-NoninteractiveMode

			Write-Host "`nHP updates completed." -ForegroundColor Green

			# Note: HPIA sets script-level variables for reboot status
			# But since we're in a function, we'll just inform the user
			Write-Host "Note: Some updates may require a system reboot to complete." -ForegroundColor Yellow

		} Catch {
			Write-Error "HP Image Assistant failed: $_"
			Write-Host "You may need to run Windows Update manually or use HP Support Assistant." -ForegroundColor Yellow
		}
		return
	}

	# Lenovo Detection
	If ($Manufacturer -match "Lenovo") {
		Write-Host "`nLenovo system detected. Running Lenovo System Updater..." -ForegroundColor Green
		Try {
			# Install Lenovo System Updater if not present
			Write-Host "Checking for Lenovo System Updater..." -ForegroundColor Cyan

			If (Get-Command Install-LenovoSystemUpdater -ErrorAction SilentlyContinue) {
				Install-LenovoSystemUpdater
			}

			# Run Lenovo System Updater (includes -noreboot flag)
			Write-Host "Running Lenovo System Updater..." -ForegroundColor Cyan
			Write-Host "This may take several minutes..." -ForegroundColor Yellow

			If (Get-Command Invoke-LenovoSystemUpdater -ErrorAction SilentlyContinue) {
				Invoke-LenovoSystemUpdater
			} Else {
				Write-Warning "Invoke-LenovoSystemUpdater command not found in OSD module."
				Write-Host "Attempting alternative Lenovo update method..." -ForegroundColor Yellow

				# Try using Install-LenovoApps as fallback
				If (Get-Command Install-LenovoApps -ErrorAction SilentlyContinue) {
					Install-LenovoApps
				} Else {
					Throw "No Lenovo update functions available in OSD module."
				}
			}

			Write-Host "`nLenovo updates completed." -ForegroundColor Green
			Write-Host "Note: Some updates may require a system reboot to complete." -ForegroundColor Yellow

		} Catch {
			Write-Error "Lenovo System Updater failed: $_"
			Write-Host "You may need to run Windows Update manually or use Lenovo Vantage." -ForegroundColor Yellow
		}
		return
	}

	# Unsupported manufacturer
	Write-Warning "`nManufacturer '$Manufacturer' is not currently supported by this function."
	Write-Host "Supported manufacturers:" -ForegroundColor Yellow
	Write-Host "  - Dell / Alienware" -ForegroundColor Cyan
	Write-Host "  - HP / Hewlett-Packard" -ForegroundColor Cyan
	Write-Host "  - Lenovo" -ForegroundColor Cyan
	Write-Host "`nFor other manufacturers, please use:" -ForegroundColor Yellow
	Write-Host "  - Windows Update (Update-Windows)" -ForegroundColor Cyan
	Write-Host "  - Manufacturer-specific update tools" -ForegroundColor Cyan
}

Function Update-PowerShellModule {
	param (
		[Parameter(Mandatory=$true)]
		[string]$ModuleName
	)

	# Get the currently installed version of the module - handle multiple versions
	$InstalledModules = Get-Module -ListAvailable -Name $ModuleName
	if ($InstalledModules) {
		# If multiple versions exist, get the highest one
		if ($InstalledModules -is [array]) {
			$ModVer = ($InstalledModules | Sort-Object Version -Descending)[0].Version
		} else {
			# Single module
			$ModVer = $InstalledModules.Version
		}

		# Try to find the module in PSGallery
		try {
			$AvailableModule = Find-Module $ModuleName -Repository PSGallery -ErrorAction Stop
			$AvailableModVer = $AvailableModule.Version

			# Compare versions and proceed with update if needed
			if ($ModVer -ne $AvailableModVer) {
				# Inform user about the available update
				Write-Host "$ModuleName has an update from $ModVer to $AvailableModVer.`nInstalling the update."

				# Set PSGallery as trusted repository
				Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

				# Ensure NuGet package provider is installed
				if (!(Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
					Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser
				}

				# Remove the module from current session if loaded
				Remove-Module -Name $ModuleName -Force -ErrorAction SilentlyContinue

				# Uninstall all existing versions of the module
				Uninstall-Module -Name $ModuleName -AllVersions -Force -ErrorAction SilentlyContinue

				# Check if module files still exist and remove them forcefully if necessary
				$RemainingModules = Get-Module -Name $ModuleName -ListAvailable
				if ($RemainingModules) {
					foreach ($Module in $RemainingModules) {
						$ModPath = $Module.ModuleBase

						# Check if Remove-PathForcefully is available
						if (Get-Command -Name Remove-PathForcefully -ErrorAction SilentlyContinue) {
							Remove-PathForcefully -Path $ModPath
						} else {
							# Fallback if Remove-PathForcefully is not available
							try {
								Remove-Item -Path $ModPath -Recurse -Force -ErrorAction Stop
							} catch {
								Write-Warning "Could not remove module path $ModPath. You may need to remove it manually."

								# Create command line arguments for forceful removal
								$ArgumentList = '/C "taskkill /IM powershell.exe /F & rd /s /q "' + $ModPath + '" & start powershell -NoExit -ExecutionPolicy Bypass'

								# Use cmd to force removal
								Start-Process "cmd.exe" -ArgumentList $ArgumentList

								# Exit the function as we've launched a new PowerShell session
								return
							}
						}
					}
				}

				# Install the latest version of the module
				Install-Module -Name $ModuleName -AllowClobber -Force -Scope CurrentUser
			} else {
				# Inform user if module is already up to date
				Write-Host "$ModuleName is already up to date at version $AvailableModVer."
			}
		} catch {
			Write-Error "Failed to find module $ModuleName in PSGallery. Error: $_"
		}
	} else {
		Write-Host "Module $ModuleName is not currently installed. Installing from PSGallery..."

		# Set PSGallery as trusted repository
		Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

		# Ensure NuGet package provider is installed
		if (!(Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
			Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser
		}

		# Install the module
		Install-Module -Name $ModuleName -AllowClobber -Force -Scope CurrentUser
	}
}

Function Update-PowershellModules {
	Set-ExecutionPolicy RemoteSigned -Scope Process -Force
	[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
	$Providers = (Get-PackageProvider).Name
	If ($Providers -NotContains "Nuget") {
		Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue
	}
	Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
	$ModulesToInstall = @("PSReadline","PowerShellGet","AdvancedHistory")
	$ModulesToInstall | ForEach-Object {
		$Mod = $_
		Write-Host "Processing $Mod"
		If (Get-Module -Name $Mod -ListAvailable) {
			Try {
				Remove-Module $Mod -Force -ErrorAction Stop -WarningAction SilentlyContinue
				Uninstall-Module $Mod -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
			} Catch {
				Uninstall-Module $Mod -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
			}
		}
		Install-Module -Name $Mod -Scope AllUsers -Force -AllowClobber -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
		Try {
			Import-Module -Name $Mod -Scope AllUsers -Force -ErrorAction Stop -WarningAction SilentlyContinue
		} Catch {
			Import-Module -Name $Mod -Force -WarningAction SilentlyContinue
		}
		Clear-Variable -Name Mod -Force
	}
	Write-Host "Updating all modules"
	Try {
		Update-Module -Scope AllUsers -Force -WarningAction SilentlyContinue
	} Catch {
		Update-Module -Force -WarningAction SilentlyContinue
	}
	Write-Host "Settings Prediction Source"
	Try {
		Set-PSReadLineOption -PredictionSource HistoryAndPlugin -ErrorAction Stop
	} Catch {
		Set-PSReadLineOption -PredictionSource History
	}
	Get-Module | Select-Object Name, Version, Description
}

Function Update-PSWinGetPackages {
	If (Get-Command -Name "winget.exe" -ErrorAction SilentlyContinue) {
		& winget.exe update --all --silent  --accept-package-agreements --accept-source-agreements --include-unknown --force
	} Else {
		Start-PSWinGet -Command 'Get-WinGetPackage | Where {$_.IsUpdateAvailable -eq $True} | Update-WinGetPackage -Mode Silent -Verbose'
	}
}

Function Update-PWSH {
	Write-Host "Updating PWSH"
	If (Get-Command winget -ErrorAction SilentlyContinue) {
		winget source update
		winget install --id Microsoft.PowerShell -e -h --accept-package-agreements --accept-source-agreements
	} Else {
		If (!(Get-Command choco -ErrorAction SilentlyContinue)) {Install-Choco}
		Choco upgrade pwsh -y -force
	}
	# Update the system PATH env to correct previous install logic.
	$folderToSearch = "C:\Program Files\PowerShell\"

	# Find the folder containing pwsh.exe
	$pwshFolder = If (Test-Path $folderToSearch -ErrorAction SilentlyContinue) {Get-ChildItem -Path $folderToSearch -Recurse -Filter "pwsh.exe" | Select-Object -ExpandProperty Directory -First 1}

	# If the folder was found
	if ($pwshFolder) {
		# Get the current PATH
		$path = [Environment]::GetEnvironmentVariable("Path", "Machine")

		# Split the PATH into an array of folders
		$pathFolders = $path -split ";"

		# Find the index of the folder in the PATH that contains the string "C:\Program Files\Powershell\"
		$indexToUpdate = $pathFolders.IndexOf(($pathFolders | Where-Object { $_ -like "$folderToSearch*" }))

		# If the folder was found in the PATH
		if ($indexToUpdate -ge 0) {
			# Update the folder path in the PATH
			$pathFolders[$indexToUpdate] = $pwshFolder.FullName
		} else {
			# If the folder was not found in the PATH, add it
			$pathFolders += $pwshFolder.FullName
		}

		# Join the folders back into a string and update the PATH
		[Environment]::SetEnvironmentVariable("Path", ($pathFolders -join ";"), "Machine")
	} else {
		Write-Host "pwsh.exe not found in $folderToSearch"
	}
	$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

}

Function Update-Windows {
	param
	(
		[Parameter(Mandatory=$False)]
		[switch]$NoSoftware,
		
		[Parameter(Mandatory=$False)]
		[switch]$NoDrivers
	)

	Function RegMU {
		Write-Host "Checking Microsoft Update Service"
		If ((Get-WUServiceManager).Name -like "Microsoft Update") {
			Write-Host "Microsoft Update Service found, it's good to go."
		} else {
			Write-Host "Microsoft Update Service not found, registering it."
			Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
		}
	}
	Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force -ErrorAction SilentlyContinue
	Install-PackageProvider -Name NuGet -MinimumVersion 3.0.0.1 -Force -ErrorAction SilentlyContinue

	
	If ($PSVersionTable.PSVersion.Major -lt "5") {
		Write-Host "Powershell needs an update, installing now"
		If (!(Test-Path "C:\ProgramData\chocolatey\bin\choco.exe" -ErrorAction SilentlyContinue) ){Install-Choco}
		& "C:\ProgramData\chocolatey\bin\choco.exe" install dotnet4.5.2 -y
		& "C:\ProgramData\chocolatey\bin\choco.exe" install powershell -y
		Write-Host "Reboot computer and run script again"
	} Else {
		If ((Get-Command Get-WUInstall -ErrorAction SilentlyContinue) -And ((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Major -lt "2")) {
			$Module = Get-Module -Name PSWindowsUpdate
			Write-Host "Removing an out of date PSWindowsUpdate"
			Uninstall-Module $Module.Name
			Remove-Module $Module.Name
			Remove-Item $Module.ModuleBase -Recurse -Force
		}
	
		If (-Not (((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Major -ge "2") -and ((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Minor -ge "1"))) {
			Write-Host "Attempting automatic installation of PSWUI 2.2.1.5"
			Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force -ErrorAction SilentlyContinue
			Install-PackageProvider -Name NuGet -MinimumVersion 3.0.0.1 -Force -ErrorAction SilentlyContinue
			Install-Module -Name PSWindowsUpdate -MinimumVersion 2.2.1.5 -Force -ErrorAction SilentlyContinue
			Import-Module PSWindowsUpdate
			RegMU
			If (-Not (((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Major -ge "2") -and ((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Minor -ge "1"))) {
				Write-Host "Attempting Manual installation of PSWUI 2.2.1.5"
				New-Item -ItemType Directory -Force -Path '$ITFolder' -ErrorAction Stop
				Invoke-ValidatedDownload -Uri 'https://cdn.powershellgallery.com/packages/pswindowsupdate.2.2.1.5.nupkg' -OutFile '$ITFolder\pswindowsupdate.2.2.1.5.zip'
				New-Item -ItemType Directory -Force -Path 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate\2.2.1.5' -ErrorAction Stop
				Expand-Archive -LiteralPath '$ITFolder\pswindowsupdate.2.2.1.5.zip' -DestinationPath 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate\2.2.1.5' -ErrorAction Stop
				Import-Module PSWindowsUpdate -ErrorAction Stop
				RegMU
			}
		}
	
		If (((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Major -ge "2") -and ((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Minor -ge "1")) {
			Write-Host "PSWindowsUpdate is installed! Attempting Updates"
			If ($NoDrivers -ne $True) {
				Write-Host "Checking for DRIVER Updates..."
				try {
					Get-WUInstall -MicrosoftUpdate -AcceptAll -Install -UpdateType Driver -IgnoreReboot -ErrorAction Stop -Verbose
				}
				catch {
					Write-Warning "Driver update check failed. Running Reset-WUComponents..."
					Reset-WUComponents
					Write-Host "Retrying DRIVER Updates..."
					Get-WUInstall -MicrosoftUpdate -AcceptAll -Install -UpdateType Driver -IgnoreReboot -ErrorAction Stop -Verbose
				}
			}

			If ($NoSoftware -ne $True) {
				Write-Host "Checking for SOFTWARE Updates..."
				try {
					Get-WUInstall -MicrosoftUpdate -AcceptAll -Install -UpdateType Software -IgnoreReboot -ErrorAction Stop -Verbose
				}
				catch {
					Write-Warning "Software update check failed. Running Reset-WUComponents..."
					Reset-WUComponents
					Write-Host "Retrying SOFTWARE Updates..."
					Get-WUInstall -MicrosoftUpdate -AcceptAll -Install -UpdateType Software -IgnoreReboot -ErrorAction Stop -Verbose
				}
			}
		} Else {
			Write-Host "PSWindowsUpdate is failing to install, please investigate"
		}
	}
	Write-Host "End of Install Windows Updates"
}

Function Update-WindowsApps {
	Write-Host "Updating Windows Apps"
		Start-Process ms-windows-store:
		Start-Sleep -Seconds 5
		(Get-WmiObject -Namespace "root\cimv2\mdm\dmmap" -Class "MDM_EnterpriseModernAppManagement_AppManagement01").UpdateScanMethod()
	Write-Host "Update Windows Apps initiated"
}

Function Update-WindowsTo11 {
	<#
	.SYNOPSIS
	Upgrade Windows 10 to Windows 11 via network share or ISO download.

	.DESCRIPTION
	Checks eligibility (TPM, Secure Boot, RAM, disk space), detects policy blockers,
	then attempts the upgrade from a network share first, falling back to ISO download.
	Bypasses hardware requirement checks via registry for unsupported machines.

	.PARAMETER LogPath
	Path for structured log file. Defaults to $ITFolder\Logs with timestamped filename.

	.PARAMETER Force
	Force the upgrade even if the system appears to already be running Windows 11 25H2+.

	.PARAMETER DownloadOnly
	Only download the Windows 11 ISO without installing. Saved to $ITFolder\Downloads.

	.PARAMETER ShowProgress
	Run setup.exe with visible progress UI instead of quiet mode (/quiet flag omitted).

	.PARAMETER DownloadUrl
	A manually-provided direct download URL for the Windows 11 ISO. When specified,
	the Fido URL-generation step is skipped entirely and this URL is used instead.
	Useful when auto-generation via Fido fails.

	.PARAMETER ScheduleAt
	Schedule the upgrade to run at a future date/time instead of immediately.
	Accepts any valid [datetime] value. Creates a one-time Windows Scheduled Task
	that runs as SYSTEM with highest privileges, surviving logoffs and reboots.
	All other parameters (Force, ShowProgress, etc.) are forwarded to the scheduled run.

	Examples:
	  -ScheduleAt "11:00 PM"           # Tonight (or tomorrow if past 11pm)
	  -ScheduleAt "3/28/2026 8:00 PM"  # Specific date and time

	.PARAMETER ScheduledTaskName
	Name for the scheduled task. Defaults to "MauleTech-UpdateWindowsTo11".
	Use to customize the task name or avoid conflicts with existing tasks.

	.PARAMETER NetworkPaths
	Array of UNC paths to check for setup.exe in priority order.

	.EXAMPLE
	Update-WindowsTo11 -ScheduleAt "11:00 PM"
	Schedule the upgrade for tonight at 11 PM (or tomorrow if 11 PM has passed).

	.EXAMPLE
	Update-WindowsTo11 -ScheduleAt "3/28/2026 8:00 PM" -ShowProgress
	Schedule the upgrade for a specific date with visible progress UI.

	.EXAMPLE
	Update-WindowsTo11 -ScheduleAt "2:00 AM" -ScheduledTaskName "Win11-Upgrade-PC42"
	Schedule with a custom task name for easier identification.

	.NOTES
	Requires: PowerShell as Administrator, Internet access or WSUS/network share.
	Dependencies: MauleTech PWSH functions (loaded via irm ps.mauletech.com | iex).
	#>

	[CmdletBinding()]
	param(
		[string]$LogPath,
		[switch]$Force,
		[switch]$DownloadOnly,
		[switch]$ShowProgress,
		[string]$DownloadUrl,
		[datetime]$ScheduleAt,
		[string]$ScheduledTaskName = "MauleTech-UpdateWindowsTo11",
		[string[]]$NetworkPaths = @(
			"\\zeus\Win11Install$\Win11_25H2_English_x64.10.25\setup.exe",
			"\\dc0\Win11$\setup.exe",
			"\\fileserver\Images\Win11\setup.exe"
		)
	)

	#region Helpers
	# Known setup.exe exit codes and whether they are retryable
	$SetupExitCodes = @{
		[int]0x00000000 = @{ Message = "Success";                                                    Retryable = $false }
		[int]0xC1900210 = @{ Message = "No compatibility issues found";                              Retryable = $false }
		[int]0xC1900208 = @{ Message = "Compatibility issues found (actionable)";                    Retryable = $false }
		[int]0xC1900204 = @{ Message = "Migration choice not available";                             Retryable = $false }
		[int]0xC1900200 = @{ Message = "Machine does not meet minimum requirements";                 Retryable = $false }
		[int]0xC190020E = @{ Message = "Machine does not meet minimum requirements (disk space)";    Retryable = $false }
		[int]0x80070005 = @{ Message = "Access denied -- insufficient privileges";                   Retryable = $false }
		[int]0x80070070 = @{ Message = "Not enough disk space";                                      Retryable = $false }
		[int]0x80070002 = @{ Message = "File not found";                                             Retryable = $false }
		[int]0x8007007F = @{ Message = "ERROR_PROC_NOT_FOUND -- DLL version mismatch (wdscore.dll / wimgapi.dll)"; Retryable = $true  }
		[int]0xC06D007F = @{ Message = "Delay-load DLL failure (ERROR_PROC_NOT_FOUND) -- wimgapi.dll version mismatch"; Retryable = $true  }
		[int]0x80070490 = @{ Message = "Element not found";                                          Retryable = $false }
		[int]0x800704DD = @{ Message = "User cancelled the operation";                               Retryable = $false }
		[int]0xC1900101 = @{ Message = "SAFE_OS phase error -- driver or hardware issue";            Retryable = $false }
		[int]0xC1420127 = @{ Message = "Disk space error during installation";                       Retryable = $false }
	}

	function Write-Log {
		param(
			[Parameter(Mandatory)]
			[string]$Message,
			[ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
			[string]$Level = "INFO"
		)
		$LogEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
		Add-Content -Path $script:LogFile -Value $LogEntry -ErrorAction SilentlyContinue

		switch ($Level) {
			"ERROR"   { Write-Host "[ERROR]   $Message" -ForegroundColor Red }
			"WARNING" { Write-Host "[WARN]    $Message" -ForegroundColor Yellow }
			"SUCCESS" { Write-Host "[OK]      $Message" -ForegroundColor Green }
			default   { Write-Host "[INFO]    $Message" -ForegroundColor Cyan }
		}
	}

	function Get-SetupExitInfo {
		param([int]$ExitCode)
		# Convert to unsigned for lookup (PowerShell treats large hex as negative int)
		$UnsignedCode = [uint32]("0x{0:X8}" -f $ExitCode)
		$info = $SetupExitCodes[[int]$UnsignedCode]
		if ($info) { return $info }
		# Unknown code -- assume not retryable
		return @{ Message = "Unknown exit code: 0x$("{0:X8}" -f $UnsignedCode)"; Retryable = $false }
	}

	function Start-Win11Setup {
		<#
		.DESCRIPTION
		Runs setup.exe with registry bypasses and returns a result object
		with .Success (bool) and .BitLockerSuspended (bool).
		#>
		param(
			[Parameter(Mandatory)]
			[string]$SetupPath,
			[switch]$ShowProgress
		)

		$Result = [PSCustomObject]@{
			Success            = $false
			BitLockerSuspended = $false
		}

		Write-Log "Attempting Windows 11 setup with path: $SetupPath"

		if (-not (Test-Path $SetupPath)) {
			Write-Log "setup.exe not found at $SetupPath" -Level "ERROR"
			return $Result
		}

		# Verify Authenticode signature before execution
		$sig = Get-AuthenticodeSignature -FilePath $SetupPath -ErrorAction SilentlyContinue
		if (-not $sig -or $sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
			Write-Log "setup.exe Authenticode signature validation failed (Status: $($sig.Status)). Aborting." -Level "ERROR"
			return $Result
		}
		Write-Log "Authenticode signature verified: $($sig.SignerCertificate.Subject)"

		try {
			# FIX: Remove stale C:\$WINDOWS.~BT before running setup.
			# A prior failed upgrade leaves behind old DLLs (e.g. SetupCore.dll from a different
			# build) that setup.exe re-uses on the next run, causing CAutomationManager to load
			# a mismatched DLL and fail with 0x8007007F (ERROR_PROC_NOT_FOUND).
			$BtPath = 'C:\$WINDOWS.~BT'
			if (Test-Path -LiteralPath $BtPath) {
				Write-Log "Removing stale $BtPath to prevent DLL version conflicts..." -Level "WARNING"
				& takeown /f $BtPath /a /r /d y 2>&1 | Out-Null
				& icacls $BtPath /grant "administrators:F" /t /q 2>&1 | Out-Null
				& icacls $BtPath /grant "SYSTEM:F" /t /q 2>&1 | Out-Null
				Remove-Item -LiteralPath $BtPath -Recurse -Force -ErrorAction SilentlyContinue
				if (Test-Path -LiteralPath $BtPath) {
					Write-Log "$BtPath could not be fully removed (locked files may remain). Setup may reuse stale DLLs." -Level "WARNING"
				} else {
					Write-Log "Stale upgrade cache cleared" -Level "SUCCESS"
				}
			}

			# Suspend BitLocker if active
			Write-Log "Checking BitLocker status..."
			$BitLockerVolume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
			if ($BitLockerVolume -and $BitLockerVolume.ProtectionStatus -eq 'On') {
				Write-Log "BitLocker active -- suspending for 5 reboots..." -Level "WARNING"
				try {
					Suspend-BitLocker -MountPoint "C:" -RebootCount 5 -ErrorAction Stop | Out-Null
					$Result.BitLockerSuspended = $true
					Write-Log "BitLocker suspended successfully" -Level "SUCCESS"
				} catch {
					Write-Log "Failed to suspend BitLocker: $($_.Exception.Message). Manual intervention may be needed." -Level "WARNING"
				}
			} else {
				Write-Log "BitLocker not active or not found"
			}

			# Set registry keys to bypass hardware requirement checks
			$AppCompatBase = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags"
			Remove-Item -Path "$AppCompatBase\CompatMarkers" -Recurse -Force -ErrorAction SilentlyContinue
			Remove-Item -Path "$AppCompatBase\Shared" -Recurse -Force -ErrorAction SilentlyContinue
			Remove-Item -Path "$AppCompatBase\TargetVersionUpgradeExperienceIndicators" -Recurse -Force -ErrorAction SilentlyContinue

			$HwReqChkPath = "$AppCompatBase\HwReqChk"
			if (-not (Test-Path $HwReqChkPath)) {
				New-Item -Path $HwReqChkPath -Force | Out-Null
			}
			Set-ItemProperty -Path $HwReqChkPath -Name "HwReqChkVars" -Type MultiString -Force -Value @(
				"SQ_SecureBootCapable=TRUE",
				"SQ_SecureBootEnabled=TRUE",
				"SQ_TpmVersion=2",
				"SQ_RamMB=8192"
			)

			$MoSetupPath = "HKLM:\SYSTEM\Setup\MoSetup"
			if (-not (Test-Path $MoSetupPath)) {
				New-Item -Path $MoSetupPath -Force | Out-Null
			}
			Set-ItemProperty -Path $MoSetupPath -Name "AllowUpgradesWithUnsupportedTPMOrCPU" -Value 1 -Type DWord -Force

			Write-Log "Hardware bypass registry keys applied" -Level "SUCCESS"

# Fix: copy wdscore.dll from the sources directory (sibling to setup.exe) into
			# System32 so that CAutomationManager finds the correct Win11 version at init time.
			# Uses Split-Path -Parent so this works for both mounted ISOs and UNC network paths.
			$script:WdscoreSeeded     = $false
			$script:WdscoreBackupPath = $null
			$SourcesDir = Join-Path (Split-Path $SetupPath -Parent) "sources"
			$WdsSrc     = Join-Path $SourcesDir "wdscore.dll"
			$WdsDst     = "$env:SystemRoot\System32\wdscore.dll"

			if (Test-Path $WdsSrc) {
				$srcVer = (Get-Item $WdsSrc).VersionInfo.FileVersion
				$dstVer = (Get-Item $WdsDst -ErrorAction SilentlyContinue).VersionInfo.FileVersion
				Write-Log "wdscore.dll: sources=$srcVer, System32=$dstVer"

				if ($srcVer -ne $dstVer) {
					try {
						# Backup the existing System32 copy so we can restore it if setup fails
						if (Test-Path $WdsDst) {
							$script:WdscoreBackupPath = "$env:SystemRoot\System32\wdscore.dll.win10bak"
							Copy-Item $WdsDst $script:WdscoreBackupPath -Force -ErrorAction SilentlyContinue
						}
						# Replace with Win11 version -- requires taking ownership of the system file
						& takeown /f $WdsDst 2>&1 | Out-Null
						& icacls $WdsDst /grant "administrators:F" 2>&1 | Out-Null
						try {
							Copy-Item $WdsSrc $WdsDst -Force -ErrorAction Stop
						} catch {
							# File is likely locked by another process -- try to release and retry
							Write-Log "Copy failed (file likely locked): $($_.Exception.Message) -- attempting to release lock" -Level "WARNING"

							# Stop any Windows services that have wdscore.dll loaded. Stopping
							# the service (rather than killing the host process) avoids tearing
							# down unrelated services that share the same svchost instance.
							$WdsDstNorm = [System.IO.Path]::GetFullPath($WdsDst)
							$lockers = Get-Process | Where-Object {
								try {
									$_.Modules -and ($_.Modules | Where-Object {
										[System.IO.Path]::GetFullPath($_.FileName) -eq $WdsDstNorm
									})
								} catch { $false }
							}

							$stoppedServices = @()
							foreach ($proc in $lockers) {
								# Prefer stopping the owning service over killing the process
								$svc = Get-CimInstance Win32_Service -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue |
									Where-Object { $_.State -eq 'Running' }
								if ($svc) {
									foreach ($s in $svc) {
										Write-Log "Stopping service '$($s.Name)' (PID $($proc.Id)) to release wdscore.dll" -Level "WARNING"
										Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
										$stoppedServices += $s.Name
									}
								} else {
									Write-Log "Stopping process $($proc.Name) (PID $($proc.Id)) to release wdscore.dll" -Level "WARNING"
									Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
								}
							}

							if (-not $lockers) {
								Write-Log "No process found with wdscore.dll loaded as a module -- lock may be held by a file handle (AV, indexer, etc.)" -Level "WARNING"
							}

							# Always wait before retry -- gives time for AV / indexer / transient locks to clear
							Start-Sleep -Seconds 2
							Copy-Item $WdsSrc $WdsDst -Force -ErrorAction Stop

							# Restart any services we stopped
							foreach ($svcName in $stoppedServices) {
								Start-Service -Name $svcName -ErrorAction SilentlyContinue
							}
						}
						$script:WdscoreSeeded = $true
						Write-Log "Win11 wdscore.dll ($srcVer) seeded into System32" -Level "SUCCESS"
					} catch {
						Write-Log "Failed to seed wdscore.dll into System32: $($_.Exception.Message). Continuing without DLL replacement -- setup may still succeed." -Level "WARNING"
					}
				} else {
					Write-Log "wdscore.dll already matches ISO version -- no seeding needed"
				}
			} else {
				Write-Log "wdscore.dll not found at $WdsSrc -- seeding skipped" -Level "WARNING"
			}

			# Fix: copy wimgapi.dll from the sources directory into System32.
			# SetupPlatform.dll delay-loads WIMExtractImagePathByWimHandle from wimgapi.dll.
			# If the System32 copy is too old (Win10 RTM-era) the procedure isn't exported,
			# causing 0xC06D007F and a fatal SetupHost.exe crash.
			$script:WimgapiSeeded     = $false
			$script:WimgapiBackupPath = $null
			$WimSrc = Join-Path $SourcesDir "wimgapi.dll"
			$WimDst = "$env:SystemRoot\System32\wimgapi.dll"

			if (Test-Path $WimSrc) {
				$wimSrcVer = (Get-Item $WimSrc).VersionInfo.FileVersion
				$wimDstVer = (Get-Item $WimDst -ErrorAction SilentlyContinue).VersionInfo.FileVersion
				Write-Log "wimgapi.dll: sources=$wimSrcVer, System32=$wimDstVer"

				if ($wimSrcVer -ne $wimDstVer) {
					try {
						# Backup the existing System32 copy so we can restore it if setup fails
						if (Test-Path $WimDst) {
							$script:WimgapiBackupPath = "$env:SystemRoot\System32\wimgapi.dll.win10bak"
							Copy-Item $WimDst $script:WimgapiBackupPath -Force -ErrorAction SilentlyContinue
						}
						# Replace with Win11 version -- requires taking ownership of the system file
						& takeown /f $WimDst 2>&1 | Out-Null
						& icacls $WimDst /grant "administrators:F" 2>&1 | Out-Null
						try {
							Copy-Item $WimSrc $WimDst -Force -ErrorAction Stop
						} catch {
							# File is likely locked by another process -- try to release and retry
							Write-Log "Copy failed (file likely locked): $($_.Exception.Message) -- attempting to release lock" -Level "WARNING"

							$WimDstNorm = [System.IO.Path]::GetFullPath($WimDst)
							$lockers = Get-Process | Where-Object {
								try {
									$_.Modules -and ($_.Modules | Where-Object {
										[System.IO.Path]::GetFullPath($_.FileName) -eq $WimDstNorm
									})
								} catch { $false }
							}

							$stoppedServices = @()
							foreach ($proc in $lockers) {
								# Prefer stopping the owning service over killing the process
								$svc = Get-CimInstance Win32_Service -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue |
									Where-Object { $_.State -eq 'Running' }
								if ($svc) {
									foreach ($s in $svc) {
										Write-Log "Stopping service '$($s.Name)' (PID $($proc.Id)) to release wimgapi.dll" -Level "WARNING"
										Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
										$stoppedServices += $s.Name
									}
								} else {
									Write-Log "Stopping process $($proc.Name) (PID $($proc.Id)) to release wimgapi.dll" -Level "WARNING"
									Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
								}
							}

							if (-not $lockers) {
								Write-Log "No process found with wimgapi.dll loaded as a module -- lock may be held by a file handle (AV, indexer, etc.)" -Level "WARNING"
							}

							# Always wait before retry -- gives time for AV / indexer / transient locks to clear
							Start-Sleep -Seconds 2
							Copy-Item $WimSrc $WimDst -Force -ErrorAction Stop

							# Restart any services we stopped
							foreach ($svcName in $stoppedServices) {
								Start-Service -Name $svcName -ErrorAction SilentlyContinue
							}
						}
						$script:WimgapiSeeded = $true
						Write-Log "Win11 wimgapi.dll ($wimSrcVer) seeded into System32" -Level "SUCCESS"
					} catch {
						Write-Log "Failed to seed wimgapi.dll into System32: $($_.Exception.Message). Continuing without DLL replacement -- setup may still succeed." -Level "WARNING"
					}
				} else {
					Write-Log "wimgapi.dll already matches ISO version -- no seeding needed"
				}
			} else {
				Write-Log "wimgapi.dll not found at $WimSrc -- seeding skipped" -Level "WARNING"
			}

			# Build setup arguments -- /auto Upgrade handles decisions non-interactively.
			$SetupArgs = [System.Collections.ArrayList]@("/auto", "Upgrade")
			if (-not $ShowProgress) {
				$SetupArgs.Add("/quiet") | Out-Null
			}
			$SetupArgs.AddRange(@(
				"/product", "server",
				"/DynamicUpdate", "Disable",
				"/ShowOOBE", "None",
				"/Telemetry", "Disable",
				"/MigrateDrivers", "All",
				"/Compat", "IgnoreWarning",
				"/copylogs", "C:\IT",
				"/EULA", "Accept"
			))

			Write-Log "Starting Windows 11 upgrade..."
			Write-Log "Setup arguments: $($SetupArgs -join ' ')"

			$SetupProcess = Start-Process -FilePath $SetupPath -ArgumentList $SetupArgs -Wait -PassThru
			$ExitInfo = Get-SetupExitInfo -ExitCode $SetupProcess.ExitCode

			if ($SetupProcess.ExitCode -eq 0) {
				Write-Log "Setup completed successfully" -Level "SUCCESS"
				$Result.Success = $true
				return $Result
			}

			Write-Log "Setup exited with code 0x$("{0:X8}" -f ([uint32]$SetupProcess.ExitCode)): $($ExitInfo.Message)" -Level "WARNING"

			# Only retry with minimal arguments if the exit code is retryable
			if (-not $ExitInfo.Retryable) {
				Write-Log "Exit code is terminal -- skipping fallback retry." -Level "ERROR"
				return $Result
			}

			# FIX: Retry with minimal validated argument set.
			# Some builds reject unrecognized switches like /product, /Telemetry, /MigrateDrivers.
			Write-Log "Retrying with minimal arguments..." -Level "WARNING"
			$FallbackArgs = [System.Collections.ArrayList]@("/auto", "Upgrade")
			if (-not $ShowProgress) {
				$FallbackArgs.Add("/quiet") | Out-Null
			}
			$FallbackArgs.AddRange(@(
				"/DynamicUpdate", "Disable",
				"/ShowOOBE", "None",
				"/Compat", "IgnoreWarning",
				"/copylogs", "C:\IT",
				"/EULA", "Accept"
			))
			Write-Log "Fallback setup arguments: $($FallbackArgs -join ' ')"
			$SetupProcess = Start-Process -FilePath $SetupPath -ArgumentList $FallbackArgs -Wait -PassThru
			$ExitInfo = Get-SetupExitInfo -ExitCode $SetupProcess.ExitCode

			if ($SetupProcess.ExitCode -eq 0) {
				Write-Log "Setup completed successfully (fallback arguments)" -Level "SUCCESS"
				$Result.Success = $true
			} else {
				Write-Log "Setup failed with code 0x$("{0:X8}" -f ([uint32]$SetupProcess.ExitCode)): $($ExitInfo.Message)" -Level "ERROR"
			}
			return $Result
		} catch {
			Write-Log "Setup execution failed: $($_.Exception.Message)" -Level "ERROR"
			return $Result
		} finally {
			# Clean up .local redirection directory if created
			if ($LocalDir -and (Test-Path $LocalDir)) {
				Remove-Item $LocalDir -Recurse -Force -ErrorAction SilentlyContinue
			}
		}
	}
	#endregion

	#region Pre-flight
	# Ensure $ITFolder is set
	if (-not $Global:ITFolder) { $Global:ITFolder = "$env:SystemDrive\IT" }

	# Check for admin privileges
	if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
		[Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Write-Host "[ERROR]   This function requires administrative privileges." -ForegroundColor Red
		return
	}

	# Set up log file for structured logging
	$LogFolder = Join-Path $ITFolder "Logs"
	if (-not (Test-Path $LogFolder)) {
		New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
	}
	if (-not $LogPath) {
		$LogPath = Join-Path $LogFolder "Win11Setup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
	}
	$script:LogFile = $LogPath

	Write-Log "Starting Update-WindowsTo11"
	Write-Log "Log file: $($script:LogFile)"
	#endregion

	#region Version Check
	$os = Get-CimInstance Win32_OperatingSystem
	$buildNumber = [int]$os.BuildNumber
	$osCaption = $os.Caption

	if (-not $Force -and $osCaption -match 'Windows 11' -and $buildNumber -ge 26100) {
		Write-Log "Already running Windows 11 24H2+ (Build $buildNumber) -- no upgrade needed." -Level "SUCCESS"
		return
	}

	if ($Force) {
		Write-Log "Force specified -- skipping version check. Current: $osCaption (Build $buildNumber)" -Level "WARNING"
	}
	#endregion

	#region Scheduled Execution
	if ($PSBoundParameters.ContainsKey('ScheduleAt')) {
		# Capture current time once to avoid TOCTOU issues at midnight
		$now = Get-Date

		# If only a time was given and it's already past, assume tomorrow
		if ($ScheduleAt -le $now) {
			if ($ScheduleAt.Date -eq $now.Date) {
				$ScheduleAt = $ScheduleAt.AddDays(1)
				Write-Log "Specified time already passed today -- scheduling for tomorrow: $($ScheduleAt.ToString('g'))" -Level "WARNING"
			} else {
				Write-Log "ScheduleAt value '$($ScheduleAt.ToString('g'))' is in the past." -Level "ERROR"
				return
			}
		}

		# Build forwarded parameters from $PSBoundParameters (escape single quotes for safety)
		$ExcludeParams = @('ScheduleAt', 'ScheduledTaskName')
		$ForwardedParams = @()
		foreach ($key in $PSBoundParameters.Keys) {
			if ($key -in $ExcludeParams) { continue }
			$val = $PSBoundParameters[$key]
			if ($val -is [bool]) {
				if ($val) { $ForwardedParams += "-$key" }
			} elseif ($val -is [array]) {
				$escaped = ($val | ForEach-Object { "'$($_ -replace "'", "''")'" }) -join ','
				$ForwardedParams += "-$key @($escaped)"
			} else {
				$escaped = "$val" -replace "'", "''"
				$ForwardedParams += "-$key '$escaped'"
			}
		}
		$ParamString = $ForwardedParams -join ' '

		$TaskCommand = "irm ps.mauletech.com | iex; Update-WindowsTo11 $ParamString"

		# Check for existing task with the same name
		$existingTask = Get-ScheduledTask -TaskName $ScheduledTaskName -ErrorAction SilentlyContinue
		if ($existingTask) {
			Write-Log "Scheduled task '$ScheduledTaskName' already exists -- replacing it." -Level "WARNING"
			Unregister-ScheduledTask -TaskName $ScheduledTaskName -Confirm:$false -ErrorAction Stop
		}

		# Use -EncodedCommand to avoid all quoting/injection issues in the scheduled task
		$encodedCmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($TaskCommand))
		$Action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCmd"
		$Trigger = New-ScheduledTaskTrigger -Once -At $ScheduleAt
		# 10-hour execution time limit as a safety cap; task only runs at scheduled time
		$Settings = New-ScheduledTaskSettingsSet -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 10)
		$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

		try {
			Register-ScheduledTask -TaskName $ScheduledTaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -ErrorAction Stop | Out-Null
			Write-Log "Windows 11 upgrade scheduled for $($ScheduleAt.ToString('f'))" -Level "SUCCESS"
			Write-Log "Task name: $ScheduledTaskName -- visible in Task Scheduler"
			Write-Log "To cancel: Unregister-ScheduledTask -TaskName '$ScheduledTaskName' -Confirm:`$false"
			return
		} catch {
			Write-Log "Failed to create scheduled task: $($_.Exception.Message)" -Level "ERROR"
			return
		}
	}
	#endregion

	#region Eligibility Checks
	$elig = [ordered]@{
		OS              = $osCaption
		OSVersion       = $os.Version
		Architecture    = $os.OSArchitecture
		RAM_GB          = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
		FreeSysDrive_GB = [math]::Round((Get-PSDrive -Name $env:SystemDrive.TrimEnd(':')).Free / 1GB, 1)
		TPM_Present     = $false
		TPM_Ready       = $false
		TPM_VersionOK   = $false
		SecureBoot      = $false
	}

	# TPM detection
	try {
		$tpm = Get-Tpm -ErrorAction Stop
		if ($tpm) {
			$elig.TPM_Present = $true
			$elig.TPM_Ready   = $tpm.TpmReady
			if ($tpm.ManufacturerVersion) {
				$elig.TPM_VersionOK = $tpm.ManufacturerVersion -match '^2\.'
			} elseif ($tpm.SpecVersion) {
				$specStr = if ($tpm.SpecVersion -is [array]) { $tpm.SpecVersion[0] } else { $tpm.SpecVersion }
				$elig.TPM_VersionOK = $specStr -match '^2\.'
			} else {
				$elig.TPM_VersionOK = $tpm.TpmReady
			}
		}
	} catch {}

	# Secure Boot detection
	try {
		$elig.SecureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
	} catch {}

	Write-Log "Eligibility snapshot:"
	$elig.GetEnumerator() | ForEach-Object {
		Write-Host ("   - {0}: {1}" -f $_.Key, $_.Value)
		Add-Content -Path $script:LogFile -Value ("   {0}: {1}" -f $_.Key, $_.Value) -ErrorAction SilentlyContinue
	}

	# Warnings (non-blocking)
	if ($elig.OS -notmatch 'Windows 10' -and $elig.OS -notmatch 'Windows 11') {
		Write-Log "This script is intended for Windows 10/11 upgrades. Current OS: $($elig.OS)" -Level "WARNING"
	}
	if ($elig.RAM_GB -lt 4) {
		Write-Log "RAM under 4 GB may block the upgrade." -Level "WARNING"
	}

	# Disk space check with auto-cleanup
	if ($elig.FreeSysDrive_GB -lt 32) {
		Write-Log "Low free space ($($elig.FreeSysDrive_GB) GB). Attempting cleanup..." -Level "WARNING"
		try {
			if (Get-Command Start-CleanupOfSystemDrive -ErrorAction SilentlyContinue) {
				Start-CleanupOfSystemDrive
				$elig.FreeSysDrive_GB = [math]::Round((Get-PSDrive -Name $env:SystemDrive.TrimEnd(':')).Free / 1GB, 1)
				Write-Log "Free space after cleanup: $($elig.FreeSysDrive_GB) GB"
			} else {
				Write-Log "Start-CleanupOfSystemDrive not available. Ensure sufficient space manually." -Level "WARNING"
			}
		} catch {
			Write-Log "Cleanup failed: $($_.Exception.Message)" -Level "WARNING"
		}
	}

	if (-not $elig.TPM_Present -or -not $elig.TPM_VersionOK) {
		Write-Log "TPM 2.0 not detected. Bypass will be attempted via registry." -Level "WARNING"
	}
	if (-not $elig.SecureBoot) {
		Write-Log "Secure Boot not detected. Bypass will be attempted via registry." -Level "WARNING"
	}
	#endregion

	#region Policy Blocker Detection
	$wuPolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
	$auPolicy = Join-Path $wuPolicy 'AU'

	try {
		$wsus = Get-ItemProperty -Path $wuPolicy -Name WUServer -ErrorAction SilentlyContinue
		if ($wsus) {
			Write-Log "WSUS detected: $($wsus.WUServer)"
		}

		$trlv = Get-ItemProperty -Path $wuPolicy -Name TargetReleaseVersion -ErrorAction SilentlyContinue
		$trlvInfo = Get-ItemProperty -Path $wuPolicy -Name TargetReleaseVersionInfo -ErrorAction SilentlyContinue
		if ($trlv -and $trlv.TargetReleaseVersion -eq 1) {
			Write-Log "TargetReleaseVersion pin is set (Value: '$($trlvInfo.TargetReleaseVersionInfo)'). This can block feature upgrades." -Level "WARNING"
		}

		$defer = Get-ItemProperty -Path $auPolicy -Name DeferFeatureUpdatesPeriodInDays -ErrorAction SilentlyContinue
		if ($defer) {
			Write-Log "Feature update deferral set to $($defer.DeferFeatureUpdatesPeriodInDays) days." -Level "WARNING"
		}
	} catch {}
	#endregion

	#region Main Upgrade Logic
	$SetupSuccessful = $false
	$BitLockerWasSuspended = $false
	$IsoPath = $null
	$TempFidoScript = $null
	$ExistingISO = $null
	$MountedIsoPath = $null

	try {
		# --- Attempt 1: Network share (skipped when -DownloadUrl is provided) ---
		$NetworkSetupPath = $null
		if (-not $DownloadUrl) {
			foreach ($Path in $NetworkPaths) {
				Write-Log "Checking network path: $Path"
				if (Test-Path $Path -ErrorAction SilentlyContinue) {
					$NetworkSetupPath = $Path
					Write-Log "Found network setup: $NetworkSetupPath" -Level "SUCCESS"
					break
				}
			}

			if ($NetworkSetupPath -and -not $DownloadOnly) {
				Write-Log "Using network installation" -Level "SUCCESS"
				$SetupResult = Start-Win11Setup -SetupPath $NetworkSetupPath -ShowProgress:$ShowProgress
				$SetupSuccessful = $SetupResult.Success
				if ($SetupResult.BitLockerSuspended) { $BitLockerWasSuspended = $true }
			}
		}

		# --- Attempt 2: ISO download (fallback or DownloadOnly or DownloadUrl) ---
		if (-not $SetupSuccessful -or $DownloadOnly) {
			if ($DownloadOnly) {
				Write-Log "DownloadOnly mode -- proceeding with ISO download" -Level "SUCCESS"
			} elseif ($DownloadUrl) {
				Write-Log "Using provided download URL for ISO..." -Level "SUCCESS"
			} elseif ($NetworkSetupPath) {
				Write-Log "Network setup failed. Falling back to ISO download..." -Level "WARNING"
			} else {
				Write-Log "No usable network path found. Falling back to ISO download..." -Level "WARNING"
			}

			# Check for an existing ISO first
			Write-Log "Checking for existing Windows 11 ISO in $ITFolder\Downloads..."
			$ExistingISO = Get-ChildItem -Path "$ITFolder\Downloads" -Filter "Win11*.iso" -ErrorAction SilentlyContinue |
				Where-Object { $_.Length -gt 4GB } |
				Sort-Object LastWriteTime -Descending |
				Select-Object -First 1

			if ($ExistingISO) {
				$IsoPath = $ExistingISO.FullName
				$IsoSizeGB = [math]::Round($ExistingISO.Length / 1GB, 2)
				Write-Log "Found existing ISO: $IsoPath ($IsoSizeGB GB) -- skipping download" -Level "SUCCESS"
			} else {
				Write-Log "No suitable existing ISO found. Downloading..."

				$UsedMirrorFallback = $false
				if ($DownloadUrl) {
					# Use the manually-provided download URL directly
					Write-Log "Using user-provided download URL: $DownloadUrl" -Level "SUCCESS"
					$Win11URL = $DownloadUrl
				} else {
					# Get download URL via Fido
					$TempFidoScript = Join-Path $env:TEMP "Fido_$(Get-Date -Format 'yyyyMMddHHmmss').ps1"
					$FidoUrl = "https://github.com/pbatard/Fido/raw/refs/heads/master/Fido.ps1"

					Write-Log "Downloading Fido script for ISO URL generation..."
					$null = Get-FileDownload -URL $FidoUrl -SaveToFolder (Split-Path $TempFidoScript -Parent) -ShowProgress:$ShowProgress
					# Rename to our temp name if needed
					$DownloadedFido = Join-Path (Split-Path $TempFidoScript -Parent) "Fido.ps1"
					if (Test-Path $DownloadedFido) {
						if ($DownloadedFido -ne $TempFidoScript) {
							Move-Item -Path $DownloadedFido -Destination $TempFidoScript -Force
						}
					} else {
						throw "Failed to download Fido script"
					}

					Write-Log "Generating Windows 11 download URL via Fido..."
					$FidoOutput = & $TempFidoScript -Win "Windows 11" -Rel "25H2" -Ed "Pro" -Lang "English" -Arch "x64" -PlatformArch "x64" -GetUrl $true -Locale "en-US"
					# Fido may emit multiple lines; extract the last one as the URL
					$Win11URL = if ($FidoOutput -is [array]) { $FidoOutput[-1] } else { $FidoOutput }
					$UsedMirrorFallback = $false

					if (-not $Win11URL) {
						Write-Log "Fido failed to generate URL. Using MauleTech mirror as fallback." -Level "WARNING"
						$Win11URL = "https://files.mauletech.com/files/ISOs/Win11_25H2_English_x64.iso?dl"
						$UsedMirrorFallback = $true
					}
				}

				Write-Log "Downloading Windows 11 ISO (this may take a while)..."
				$DownloadArgs = @{
					URL          = $Win11URL
					SaveToFolder = "$ITFolder\Downloads"
					ShowProgress = $ShowProgress.IsPresent
				}
				if ($UsedMirrorFallback) {
					# Only validate checksum when using the known MauleTech mirror
					$DownloadArgs.Checksum     = "D141F6030FED50F75E2B03E1EB2E53646C4B21E5386047CB860AF5223F102A32"
					$DownloadArgs.ChecksumType = "SHA256"
				}
				$DownloadResult = Get-FileDownload @DownloadArgs

				# Get-FileDownload returns the path(s) -- grab the last element
				if ($DownloadResult -is [array]) {
					$IsoPath = $DownloadResult[-1]
				} else {
					$IsoPath = $DownloadResult
				}

				if (-not $IsoPath -or -not (Test-Path $IsoPath)) {
					throw "ISO download failed or file not found"
				}

				Write-Log "ISO downloaded: $IsoPath" -Level "SUCCESS"
			}

			# DownloadOnly stops here
			if ($DownloadOnly) {
				Write-Log "DownloadOnly complete. ISO location: $IsoPath" -Level "SUCCESS"
				$SetupSuccessful = $true
			} else {
				# Mount and run setup from ISO
				Write-Log "Mounting ISO..."
				$MountResult = Mount-DiskImage -ImagePath $IsoPath -PassThru -ErrorAction Stop
				$MountedIsoPath = $IsoPath
				# Brief delay to allow volume registration after mount
				Start-Sleep -Seconds 3
				$DriveLetter = ($MountResult | Get-Volume).DriveLetter
				# Fallback query in case piped Get-Volume returns null
				if (-not $DriveLetter) {
					$DriveLetter = (Get-DiskImage -ImagePath $IsoPath | Get-Volume).DriveLetter
				}

				if (-not $DriveLetter) {
					throw "Failed to get drive letter for mounted ISO"
				}

				Write-Log "ISO mounted to ${DriveLetter}:" -Level "SUCCESS"
				$SetupPath = "${DriveLetter}:\setup.exe"

				$SetupResult = Start-Win11Setup -SetupPath $SetupPath -ShowProgress:$ShowProgress
				$SetupSuccessful = $SetupResult.Success
				if ($SetupResult.BitLockerSuspended) { $BitLockerWasSuspended = $true }

				Write-Log "Dismounting ISO..."
				try {
					Dismount-DiskImage -ImagePath $IsoPath -ErrorAction Stop
					$MountedIsoPath = $null
					Write-Log "ISO dismounted" -Level "SUCCESS"
				} catch {
					Write-Log "Failed to dismount ISO: $($_.Exception.Message)" -Level "WARNING"
				}
			}
		}
	} catch {
		Write-Log "Critical error: $($_.Exception.Message)" -Level "ERROR"
	} finally {
		# Dismount ISO if still mounted (exception safety)
		if ($MountedIsoPath) {
			try {
				Dismount-DiskImage -ImagePath $MountedIsoPath -ErrorAction SilentlyContinue
				Write-Log "ISO dismounted during cleanup" -Level "WARNING"
			} catch {}
		}

		# Restore BitLocker if it was suspended and the upgrade failed
		if ($BitLockerWasSuspended -and -not $SetupSuccessful) {
			try {
				Resume-BitLocker -MountPoint "C:" -ErrorAction Stop
				Write-Log "BitLocker re-enabled after failed upgrade" -Level "SUCCESS"
			} catch {
				Write-Log "Failed to re-enable BitLocker: $($_.Exception.Message)" -Level "WARNING"
			}
		}

		# Cleanup temp Fido script (both the renamed and original copies)
		if ($TempFidoScript -and (Test-Path $TempFidoScript)) {
			Remove-Item $TempFidoScript -Force -ErrorAction SilentlyContinue
		}
		$OriginalFido = Join-Path $env:TEMP "Fido.ps1"
		if (Test-Path $OriginalFido) {
			Remove-Item $OriginalFido -Force -ErrorAction SilentlyContinue
		}

		# Cleanup ISO only on success (preserve on failure for retry); never cleanup in DownloadOnly mode
		if ($SetupSuccessful -and (-not $DownloadOnly) -and $IsoPath -and ($null -eq $ExistingISO)) {
			if (Test-Path $IsoPath) {
				Write-Log "Cleaning up downloaded ISO..."
				Remove-Item $IsoPath -Force -ErrorAction SilentlyContinue
			}
		} elseif (-not $SetupSuccessful -and $IsoPath -and (Test-Path $IsoPath)) {
			Write-Log "Preserving ISO for retry: $IsoPath" -Level "WARNING"
		}

		# Final summary
		if ($SetupSuccessful -and $DownloadOnly) {
			Write-Log "ISO download completed successfully! Location: $IsoPath" -Level "SUCCESS"
		} elseif ($SetupSuccessful) {
			Write-Log "Windows 11 upgrade process completed successfully!" -Level "SUCCESS"
			Write-Log "A restart may be required to finish the upgrade."
		} else {
			Write-Log "Windows 11 upgrade process failed or completed with warnings." -Level "ERROR"
			Write-Log "Check setup logs in C:\IT and log file: $($script:LogFile)"
		}
	}
	#endregion
}

Function Update-WindowTitle ([String] $PassNumber) {
	Write-Host "Changing window title"
		$host.ui.RawUI.WindowTitle = "$SiteCode Provisioning | $env:computername | Pass $PassNumber | Please Wait"
}

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB86jJdlu8Ak4mx
# tmPWSPvSp1S2BTU2eETmpGwY51J3PqCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggahMIIEiaADAgECAhAHhD2tAcEVwnTuQacoIkZ5MA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMjA2MjMwMDAwMDBaFw0zMjA2MjIyMzU5NTlaMFox
# CzAJBgNVBAYTAkxWMRkwFwYDVQQKExBFblZlcnMgR3JvdXAgU0lBMTAwLgYDVQQD
# EydHb0dldFNTTCBHNCBDUyBSU0E0MDk2IFNIQTI1NiAyMDIyIENBLTEwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCtHvQHskNmiqJndyWVCqX4FtYp5FfJ
# LO9Sh0BuwXuvBeNYt21xf8h/pLJ/7YzeKcNq9z4zEhecqtD0xhbvSB8ksBAfWBMZ
# O0NLfOT0j7WyNuD7rv+ZFza+mxIQ79s1dCiwUMwGonaoDK7mqZfDpKEExR6UyKBh
# 3aatT73U2Imx/x+fYTmQFq+N8FrLs6Fh6YEGWJTgsxyw1fAChCfgtEcZkdtcgK7q
# uqskHtW6PJ9l5VNJ7T3WXpznsOOxrz3qx0CzWjwK8+3Kv2X6piWvd8YRfAOycSrT
# 4/PM0cHLFc5xs/4m/ek4FCnYSem43doFftBxZBQkHKoPW3Bt6VIrhVIwvO7hrUjh
# chJJZYdSld3bANDviJ5/ToP7ENv97U9MtKFvmC5dzd1p4HxFR0p5wWmYQbW+y3RF
# m0np6H9m57MUMNp0ysmdJjb0f7+dVLX3OEBUb6H+r1LRLZT/xEOTuwOxGg2S4w25
# KGL9SCBUW4nkBljPHeJToU+THt0P8ZQf4B9IFlGxtLK0g3uOAnwSFgKtmNjhkTl8
# caLAQwbgEINCqrhc0b6k2Z8+QwgVAL0nIuzM9ckKP8xtIcWg85L3/l0cTkHQde+j
# KGDG2CdxBHtflLIUtwqD7JA2uCxWlIzRNgwT0kH2en0+QV8KziSGaqO2r06kwboq
# 2/xy4e98CEfSYwIDAQABo4IBWTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNV
# HQ4EFgQUyfwQ71DIy2t/vQhE7zpik+1bXpowHwYDVR0jBBgwFoAU7NfjgtJxXWRM
# 3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
# cnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAc
# BgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEEATANBgkqhkiG9w0BAQsFAAOCAgEA
# C9sK17IdmKTCUatEs7+yewhJnJ4tyrLwNEnfl6HrG8Pm7HZ0b+5Jc+GGqJT8kRc7
# mihuVrdsYNHdicueDL9imhtCusI/rUmjwhtflp+XgLkmgLGrmsEho1b+lGiRp7LC
# /10di8SAOilDkHj5Zx142xRvBrrWj9eOdSGHwYubAsEd6CDojwcaVz9pfXMzYO3k
# c0O6PXg1TkcgkYlCUAuDHuk/sZx68W0FVj1P2iMh+VUq9lL1puroAydoeWVUh/+c
# MXeqfgpBqlAW+r8ma5F6yKL0stVQH8vYb1ES0mJSIPyIfkIjC1V0pbZS3p0QWsKa
# afEor8fLfLNfSxntVI/ugut0+6ekluPWRpEXH+JAiNdRjbLbZchCREe3/Xl0Ylwk
# A+eQVJfM0A7XiuFtY/mOpK2AN+E25t5mQYFhpdxZX5LTDKWgDnb+A6QnEt4iNyuk
# cLaJuS8IPgPz0E2ALZLt3Rqs+lXifK/GwnNIWQNbf7FmLDB9ph8i8dvsR1hsjc2K
# PEW4bAsbvLcz8hN1zE1/QbOV92vDGoFjwZOi2koQ+UyEh0e8jDFHAKJeTI+p8EPE
# /mqvojLFAnt31yXIA2tjt0ERtsjkhBNmZY6SEOfnIoOwvyqavLPya1Ut3/2cOFLu
# NQ8Ql6HaZsNQErnnzn+ZEAaUTkPZaeVyoHIkODECLzkwgga0MIIEnKADAgECAhAN
# x6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUw
# EwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20x
# ITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAw
# MDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3Rh
# bXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMs
# VO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4
# kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8
# BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2
# Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwF
# t+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9o
# HRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq
# 6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+r
# x3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvU
# BDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl
# 9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwID
# AQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunk
# Bnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08w
# DgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEB
# BGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsG
# AQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgG
# BmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4H
# PRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qE
# JPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy
# 9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe
# 9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1U
# H410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6
# A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjs
# Yg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0
# vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/D
# Jbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHb
# xtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAP
# vIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC
# 0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGlt
# ZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAw
# MFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1l
# c3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA
# 69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6w
# W2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00
# Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOM
# A3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmot
# uQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1O
# pbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeH
# VZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1r
# oSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSURO
# wnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+giAwW0
# 0aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGV
# MIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM
# 6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMC
# B4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKG
# UWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRp
# bWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSg
# UqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRU
# aW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcE
# ua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/Ym
# RDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8
# AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/E
# ABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQ
# VTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gV
# utDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85
# EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hg
# gt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJ
# gKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLv
# UxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7P
# OGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzCCBzMwggUboAMCAQICEA2lFIZwJJS8
# c3wtEmMVlPEwDQYJKoZIhvcNAQELBQAwWjELMAkGA1UEBhMCTFYxGTAXBgNVBAoT
# EEVuVmVycyBHcm91cCBTSUExMDAuBgNVBAMTJ0dvR2V0U1NMIEc0IENTIFJTQTQw
# OTYgU0hBMjU2IDIwMjIgQ0EtMTAeFw0yNjAzMDIwMDAwMDBaFw0yNzA2MDMyMzU5
# NTlaMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcgTWV4aWNvMREwDwYDVQQH
# EwhDb3JyYWxlczEgMB4GA1UEChMXTWF1bGUgVGVjaG5vbG9naWVzLCBMTEMxIDAe
# BgNVBAMTF01hdWxlIFRlY2hub2xvZ2llcywgTExDMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEA405RMEf+gTALcHgTvYpBVK47g85sfrdA7AcQMhlEgvnQ
# D0CKFGJslMouuo6t1kJho1IGE+w+JILQ11wz9TNaGq20eTPuC6dtXaZe8mIHMiOQ
# /gXQiDgP/b74T0xZzUe8PvK8ZVH+CRxGmgvY3Gwd+UkFe+XlA5WW7FZJljriACEY
# +FJay6Gk9y16Ghb6J5utjQJEeKXGAsjJp+GDx9LNhMZEW2mKw10warcZmzU6PAk6
# Bj/huN5h99RrV3s+4IpazdQmjlI5nuvF1BaH4XP6/nMzRVSqGYV7ANekkZTaa5Fu
# QUppuj2FgM7sIVZkzqEF1uQJrxSK0/loEWtefCAgXil8ZIFWl/PUMnO/ks2uPLoa
# EgPWeEjNZT8yN9SmgCfNESpb9voJFOw8NMIR6IqWM5UEQYU0A5xnAeBhibtP2BOa
# 4bH9s8KdGG+DsZpuCPMDv/9LS2YUsnGwNLtzvfnOx81O34OceAMT4Eo5wAfxYGlP
# Tsl4KHmtP0jaoD9RXI8VQhQvCSA49naI/Zahn1DdVf7ix64792CMqveW/LFY/FYl
# lLV4F96t8jcvi23bOasqPIPHxO1SDHhO4tGTbS5tq50AYZOLWrb7U899LEn/LfTU
# XcToPN4RfW/Pg3SB7Q+pI5V2vemteIZuVLBJ9yh70PrChpY0O8T3LzPkwmIReCkC
# AwEAAaOCAdQwggHQMB8GA1UdIwQYMBaAFMn8EO9QyMtrf70IRO86YpPtW16aMB0G
# A1UdDgQWBBS4gw5O24Kh4dLnb/qbH2fxlwUijjA+BgNVHSAENzA1MDMGBmeBDAEE
# ATApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMIGXBgNVHR8EgY8wgYww
# RKBCoECGPmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9Hb0dldFNTTEc0Q1NSU0E0
# MDk2U0hBMjU2MjAyMkNBLTEuY3JsMESgQqBAhj5odHRwOi8vY3JsNC5kaWdpY2Vy
# dC5jb20vR29HZXRTU0xHNENTUlNBNDA5NlNIQTI1NjIwMjJDQS0xLmNybDCBgwYI
# KwYBBQUHAQEEdzB1MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wTQYIKwYBBQUHMAKGQWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9Hb0dl
# dFNTTEc0Q1NSU0E0MDk2U0hBMjU2MjAyMkNBLTEuY3J0MAkGA1UdEwQCMAAwDQYJ
# KoZIhvcNAQELBQADggIBAACeH7mDMx2b2AunxE/pho1rcPKjLwGv2WECIUXDOF7M
# 7P9nPsZNuE1u93ztEFFxc8tkYwIXRoXweQ7tW8BlJoVHxA4Bxi7ZozZPMEUrhUc2
# SdJAPXBd/k0UIl+Zj1KzpBkWiFV5MyXNv0N0YpBGt36GB2v9yOfUIxDk6y95rs7k
# 8oQZ/HdELvnoUPhIN+65H01japtITcGO13/cvFcE2lAuSXyy+oT7qRV4QQyp1ykx
# AGK3uS+lTqCcojTTm1lw2MgtVpA2TzK80P7XBWA62cSu1PtULULTCNibKvHimYSI
# wcboxm4Lqe6dF8MYkAO0n1zUeI3dxq4DtKc1JsZ7xF9mQevuso299AfuCeD35sRo
# FVcdx4OxrULLIaelOEv4xap5wjQZLaNEI7N354AQfBucgohvytE2sQ7vcPomaJEM
# V0+vc0TvZ/qwY2vnWPBqw8Q7SMidZ+7sk6YQ5IiyILphytDVTBz/878UqNofpn5D
# RHxt6EaBao81BX9EgbAnPKbsFAzVcm/uzt2oBYlrGccG+DQi0/k+6XzylWmQVu3y
# oAtIOSF7UClzvRae6JsWEUi/4KFNGA9zxQRQD+IEjhv2nSxQQDlKGWzoMqGM+aGR
# 9nEGH6cXzRujUpFBlKxNupzobg9gjDXSLkP234HOeDCS2WGSU2C1CQvjybdp/rxZ
# MYIGSjCCBkYCAQEwbjBaMQswCQYDVQQGEwJMVjEZMBcGA1UEChMQRW5WZXJzIEdy
# b3VwIFNJQTEwMC4GA1UEAxMnR29HZXRTU0wgRzQgQ1MgUlNBNDA5NiBTSEEyNTYg
# MjAyMiBDQS0xAhANpRSGcCSUvHN8LRJjFZTxMA0GCWCGSAFlAwQCAQUAoIGEMBgG
# CisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIE
# IEmLz98mYKZ90JhzfaCnk+8n1zS7FxiA8sCxHTdSofmzMA0GCSqGSIb3DQEBAQUA
# BIICAFbpcE0RXlBWvSfdQbRvVcnuHc+niUTyEGwsSsUhqYtsCYTPPryp9jappUe/
# Pjbm2iGDXgUL1MvUyWZOvX6bUx4oNi8ZtLLt1C8S+sHzm6QzEWMaFUs5eiVQCtTB
# yABYVXLd527hBISvssoW3wyXS2mIdfac0Vb+DFNB2nH/w6xiIpd/kgU3NT6bL2ZQ
# P56SALfWe1OkC3kJv5i0oeJ6bCEByuLXcuLCRxgLvbhdGyDqkvk+HjsDjkLpRLEL
# rUdJifh/k2bh5LvvhFXChMkc2JHEJecQzCSAF8LHFtrZtcTrw/q+qpyFpqX8kK9r
# yNp9aPEXIR6N9AvUob0KQVaiJQkoks6BwUsJtHzXZICU8NktoI+HHKfheZ+BWu7K
# MnlmlH4wpmbqbnhmzjkNlsGbeVfa4e/6UTKorLE5IjIpd2cexBn/ukgFN37+tFKd
# lo9H5qEBPMFVYdViSeZ2nu7vyhyoZJLt/OyLmEmN4iO7zhpdWhkTi3C/V9uM9u2y
# xqaE7YCYWmZVTjgtgDWsCCJaZOUiPVTs/8DcyHyUTDsQ3cdRlb3mJ0uxODfxmBcj
# fV9YsImKTYU7rFvDVGl2GrylSz8B1NVLJss+4qJC8eLuxc2YfjbWtlNEZQAZ8StL
# D190X8fozH3kHgPvdwj645nA6wFyw8uUcO5FQJnWFPR3OzL4oYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDQwNzIxMDQyM1owLwYJKoZIhvcNAQkEMSIEIAUv4K3R
# mp6uZybNS2dh6avKilrcYOJeUrXImZkllAodMA0GCSqGSIb3DQEBAQUABIICABr+
# 1tKiy+HqWij+37u3g6hm+61p/QD0IoJ8NWP6a5+ccuTCW4RiYnYTUI4rZvnrQHcD
# oNQiOuFjJRyUojTca4ApH8kOxtyqJMNSQ80lQKcZVHpDUDVDosIYZwTgX2zk+ysY
# mJpMxIG/fKGrhC+nVigSldwRjQgACtcmMmgqnCPq89U16sB34dLySDKnEYVjYnw/
# oDRcv2GTEH+Zb6R/iQi9I/3+lXrp+VZ1Z/UZ8FuSK0uDhh/8pB6+B4IL5TUbGEd8
# HshlF39VyKwAnhLz7W01sXtlW6SILWWcbgYXC4j57+BMCVqyCLyGs9LP3YNcHNQO
# XbKt0+xEE2ygfjVwCbkFI4fYjMEVOd3ZhoDABPry2Ayn0VwZH9cKltJiiVgAjRko
# gj+fTrl7psQD4FXeeb8hoVw9FcXQPdeiiqaMsXHLKtYvSHEvHZeTJC+jfTWVkLz9
# 2wFWQ1ohuDDGuEljnVkiqPWeQOuy9Jiwoo2Ic/8EPd7b4d0CC7k+iT59vOhzHDY6
# QE9Z7hgt8PmoLVzZuE6ii2n0Iw2pzWIE3wDmTzhqrEQmU5Kk85qIRjLWjU4o+rce
# yQv0RPt0z3orK+ZZE/fdYSGS4KqpTuubDaHCFC9PPe+N8ABKTtNXxdOgY19SdxXA
# STJn3RKCudO01WENajZefsx6XD3Hiyarqqv74+SA
# SIG # End signature block
