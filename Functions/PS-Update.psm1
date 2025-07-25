Function Update-DattoAgent {
	Enable-SSL
	$progressPreference = 'silentlyContinue'
	Invoke-WebRequest https://raw.githubusercontent.com/MauleTech/PWSH/master/Scripts/Datto-Agent-Update/DattoAgentUpdate.txt -usebasicparsing | Invoke-Expression
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
		$hashtable = @{}

		# Download the contents of the URL
		$content = Invoke-WebRequest -Uri $url

		# Split the content into lines
		$lines = $content.Content.Split("`r`n") | Where-Object {$_ -notmatch ";|NS|AAAA"}  # Use `"`r`n" for Windows-style newlines

		# Process each line, ignoring lines starting with ;
		foreach ($line in $lines) {
			if (!($line -like ";*")) {
				$values = $line.Split(" ")
				$hashtable[$values[0]] = $values[-1]  # Store only the last string
			}
		}
		#$hashtable = $($hashtable.GetEnumerator() | Sort Name | Select Name,Value | Format-Table)
		Write-Host "Currently set DNS Root Hints:";$(Get-DNSServerRootHint)
		# Display the hashtable (optional)
		Write-Host "Latest root hints from www.internic.net :";$($hashtable.GetEnumerator() | Sort Name | Select Name,Value | Format-Table)

		# Remove the old entries and add the updated entries. Does not check if old is still up to date.
		Write-Host "Replacing current set with updates"
		foreach ($entry in $($hashtable.GetEnumerator()| Sort Name)) {
			Remove-DnsServerRootHint -Force -NameServer ($entry.Name).ToLower() -ErrorAction SilentlyContinue
			Add-DnsServerRootHint -NameServer $entry.Name -IPAddress $entry.Value -Verbose
		}
		Write-Host "DNS Root Hints are now set to:";$(Get-DNSServerRootHint)
		
	} Else {
		Write-Warning "You can only run this command on a DNS server."
	}
}

Function Update-DellPackages {
	<#
	.SYNOPSIS
		Uses the CLI version of Dell Command | Update to install any missing drivers/firmwares/Bios and update existing ones.
		There are no parameters to use.
	.LINK
		https://www.dell.com/support/kbdoc/en-us/000177325/dell-command-update
	.EXAMPLE
		Update-DellPackages
	#>

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
					winget install --id Dell.CommandUpdate -e -h --accept-package-agreements --accept-source-agreements
				} Else {
					Choco upgrade DellCommandUpdate --exact -y --force -i --ignorechecksums
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

				}  ElseIf ($DCUAvailableVersion -notmatch $DCUInstalledVersion) {
					Write-Host "'Dell Command | Update' is not current. Updating from version $DCUInstalledVersion to $DCUAvailableVersion."

					#Remove any programs listed through "Add and remove programs"
					Uninstall-Application -AppToUninstall "Dell Command | Update" -ErrorAction SilentlyContinue
					Install-DCU

				} ElseIf ($DCUInstalledVersion -eq $DCUAvailableVersion) {
					Write-Host -ForegroundColor Green "'Dell Command | Update' is current."
				}

			#Configure and run Dell Command Update
			If (Test-Path $DCUx86) {
				& $DCUx86 /configure -autoSuspendBitLocker=enable
				& $DCUx86 /applyUpdates -reboot=disable
			} ElseIf (Test-Path $DCUx64) {
				& $DCUx64 /configure -autoSuspendBitLocker=enable
				& $DCUx64 /applyUpdates -reboot=disable
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
	$File = "$ITFolder\Dell System Update 2.0.1.exe"
	$Hash = 'dc3d740bcdbf89d0a8dcbf8b57e21d6369455e2efe5313fc73233aeefa381cd5'
	Function Get-DSUInstall {
		Write-Host "Dell System Update is not installed, attempting to install."
		Write-Host "Download the installer to $File"
		(New-Object System.Net.WebClient).DownloadFile($URL,$File) #Download the URL to the File.
				Write-Host "Download is complete, checking the integrity."
	}

	Function Test-DSUInstall {IF ((Get-FileHash -Path $File -Algorithm SHA256).Hash -eq $Hash) {
			Write-Host "It's a match!"
		} Else {
			Write-Host "Uh oh, there were issues downloading a non-corrupt file. Please attempt manually."
			Write-Host "Download is available at https://downloads.dell.com/omimswac/dsu/"
			Pause
			Exit
		}
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
			If ((Get-WmiObject win32_product | Where-Object -Property Name -Like "*Dell System Update*").Version -NotLike "2.0.1.0*") {
				Write-Host "Dell System Update is either not installed or not version 2.0.1.0"
				Get-DSUInstall
				Test-DSUInstall
				Install-DSU
			} Else {
				Write-Host "DSU is already installed."
			}

			Write-Host "Installing Dell System Updates"
			& "C:\Program Files\Dell\DELL System Update\DSU.exe" /d /u /n
		}
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
		winget source update
		winget upgrade --all -h
	} Else {
		If (Get-Command choco -ErrorAction SilentlyContinue) {choco upgrade all -y}
	}
	Update-Windows
	Update-DellPackages
	Update-Edge
	Update-NiniteApps
	Update-PWSH
	Update-PSWinGetPackages
	Restart-Computer -Force
}

Function Global:Update-ITFunctions {
    Write-Host "Updating IT Functions from GitHub..." -ForegroundColor Yellow
    if (Test-Path $PWSHFolder) {
        try {
            Push-Location $PWSHFolder
            
            # Determine which git to use
            $GitCommand = if (Test-Path $GitExePath) { $GitExePath } else { "git" }
            
            # Show current status
            Write-Host "Current status:" -ForegroundColor Yellow
            & $GitCommand status --porcelain
            
            # Fetch all remotes
            Write-Host "Fetching latest changes..." -ForegroundColor Yellow
            & $GitCommand fetch origin
            
            # Check what branch we're on
            $CurrentBranch = (& $GitCommand branch --show-current).Trim()
            Write-Host "Current branch: $CurrentBranch" -ForegroundColor Yellow
            
            # Reset to the remote version of current branch
            Write-Host "Resetting to origin/$CurrentBranch..." -ForegroundColor Yellow
            & $GitCommand reset --hard "origin/$CurrentBranch"
            
            # Show final status
            Write-Host "Updated successfully! Current commit:" -ForegroundColor Green
            & $GitCommand log --oneline -1
            
            Pop-Location
            
            # Reload functions
            $FunctionFiles = Get-ChildItem -Path $FunctionsFolder -Filter "*.psm1" -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
            $FunctionFiles | ForEach-Object {
                If (Test-Path $_ -ErrorAction SilentlyContinue) {
                    Import-Module $_ -Global -Force
                }
            }
            Write-Host "IT Functions updated and reloaded successfully!" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to update functions: $_" -ForegroundColor Red
            if ((Get-Location).Path -eq $PWSHFolder) {
                Pop-Location
            }
        }
    } else {
        Write-Host "PowerShell Functions repository not found. Please run the main script again." -ForegroundColor Red
    }
}


Function Update-ITS247Agent {
	$DisplayVersion = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\SAAZOD).DisplayVersion
	$TYPE = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\SAAZOD).TYPE
	$AvailableVersion = ((Invoke-WebRequest https://raw.githubusercontent.com/MauleTech/PWSH/master/Scripts/ITS247Agent/DPMAVersion.txt -UseBasicParsing).Content).Trim()

	If(($DisplayVersion -ne $AvailableVersion) -and ($TYPE -eq "DPMA")) {
	 WRITE-HOST "Updating Agent from $DisplayVersion to $AvailableVersion"
		 $SaveFolder = '$ITFolder'
		 New-Item -ItemType Directory -Force -Path $SaveFolder
		 $PatchPath = $SaveFolder + '\DPMAPatch' + $AvailableVersion + '.exe'
		 (New-Object System.Net.WebClient).DownloadFile('http://update.itsupport247.net/agtupdt/DPMAPatch.exe', $PatchPath)
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

Function Update-NTPDateTime {
	<#
	.SYNOPSIS
		Immediately updates the clock based on the time received from a Network Time Provider. 'north-america.pool.ntp.org' is used by default.
	#>
	param
	(
		[Parameter(Mandatory=$False)]
		[string]$sNTPServer = 'north-america.pool.ntp.org'
	)
	
	# Displays the current system date and time
	Write-Host "Current system date/time is:"
	$(Get-Date).DateTime
	
	# Pre-emptively writes the output label for the new time, so it won't interupt the calculations.
	Write-Host -NoNewLine "`nSystem date/time has been set to: "
	
	# Creates a DateTime object representing the start of the epoch
	$StartOfEpoch=New-Object DateTime(1900,1,1,0,0,0,[DateTimeKind]::Utc)   
	# Creates a byte array of length 48 and initializes all elements to 0
	[Byte[]]$NtpData = ,0 * 48
	# Sets the first byte of the byte array to 0x1B, which is the NTP request header
	$NtpData[0] = 0x1B
	# Creates a new socket object for sending and receiving data over the network
	$Socket = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)
	# Connects the socket to the specified NTP server and port number
	$Socket.Connect($sNTPServer,123)
	 
	# Sends an NTP request to the server and receives an NTP response
	$t1 = Get-Date    # Start of transaction... the clock is ticking...
	[Void]$Socket.Send($NtpData)
	[Void]$Socket.Receive($NtpData)  
	$t4 = Get-Date    # End of transaction time
	$Socket.Close()
	
	# Calculates the offset between the local system time and the NTP server time
	$IntPart = [BitConverter]::ToUInt32($NtpData[43..40],0)   # t3
	$FracPart = [BitConverter]::ToUInt32($NtpData[47..44],0)
	$t3ms = $IntPart * 1000 + ($FracPart * 1000 / 0x100000000)
 
	$IntPart = [BitConverter]::ToUInt32($NtpData[35..32],0)   # t2
	$FracPart = [BitConverter]::ToUInt32($NtpData[39..36],0)
	$t2ms = $IntPart * 1000 + ($FracPart * 1000 / 0x100000000)
 
	$t1ms = ([TimeZoneInfo]::ConvertTimeToUtc($t1) - $StartOfEpoch).TotalMilliseconds
	$t4ms = ([TimeZoneInfo]::ConvertTimeToUtc($t4) - $StartOfEpoch).TotalMilliseconds
  
	$Offset = (($t2ms - $t1ms) + ($t3ms-$t4ms))/2
	
	# Sets the local system time to the NTP server time
	[String]$NTPDateTime = $StartOfEpoch.AddMilliseconds($t4ms + $Offset).ToLocalTime() 
	Set-Date $NTPDateTime
	
	# Checks if the offset is greater than 10 seconds and prints a message accordingly
	If ([Math]::Abs($Offset) -gt 10000) {
	Write-Host "There was an offset of $($Offset / 1000) seconds."
	} Else {
		Write-Host "The offset was negligible."
	}
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
                    Install-PackageProvider -Name NuGet -Force -Scope CurrentUser
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
            Install-PackageProvider -Name NuGet -Force -Scope CurrentUser
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
		Install-PackageProvider -Name NuGet -MinimumVersion 3.0.0.1 -Force -ErrorAction SilentlyContinue
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

Function Update-PSWinGetPackages {
	Start-PSWinGet -Command 'Get-WinGetPackage | Where {$_.IsUpdateAvailable -eq $True} | Update-WinGetPackage -Mode Silent -Verbose'
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
	
	Write-Host "Checking Chocolatey Installation"
	If (-NOT (Test-Path "C:\ProgramData\chocolatey\bin\choco.exe")) {
		Write-Host "Choco is not installed. Installing Choco."
		Install-Choco
	}
	
	Write-Host "Choco is installed. Checking for powershell version."
	If ($PSVersionTable.PSVersion.Major -lt "5") {
		Write-Host "Powershell needs an update, installing now"
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
			Write-Host "Attempting automatic installation of PSWUI 2.2.0.3"
			Install-PackageProvider -Name NuGet -MinimumVersion 3.0.0.1 -Force -ErrorAction SilentlyContinue
			Install-Module -Name PSWindowsUpdate -MinimumVersion 2.2.0.3 -Force -ErrorAction SilentlyContinue
			RegMU
			If (-Not (((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Major -ge "2") -and ((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Minor -ge "1"))) {
				Write-Host "Auto install Failed, Attempting Manual installation of PSWUI 2.2.0.3"
				New-Item -ItemType Directory -Force -Path '$ITFolder' -ErrorAction Stop
				(New-Object System.Net.WebClient).DownloadFile('https://psg-prod-eastus.azureedge.net/packages/pswindowsupdate.2.2.0.3.nupkg', '$ITFolder\pswindowsupdate.2.2.0.3.zip')
				New-Item -ItemType Directory -Force -Path 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate\2.2.0.3' -ErrorAction Stop
				Expand-Archive -LiteralPath '$ITFolder\pswindowsupdate.2.2.0.3.zip' -DestinationPath 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate\2.2.0.3' -ErrorAction Stop
				Import-Module PSWindowsUpdate -ErrorAction Stop
				RegMU
			}
		}
	
		If (((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Major -ge "2") -and ((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Minor -ge "1")) {
			Write-Host "PSWindowsUpdate is installed! Attempting Updates"
			If ($NoDrivers -ne $True) {
				Write-Host "Checking for DRIVER Updates..."
				Get-WUInstall -MicrosoftUpdate -AcceptAll -Install -UpdateType Driver -IgnoreReboot -ErrorAction SilentlyContinue -Verbose
			}
			If ($NoSoftware -ne $True) {
				Write-Host "Checking for SOFTWARE Updates..."
				Get-WUInstall -MicrosoftUpdate -AcceptAll -Install -UpdateType Software -IgnoreReboot -ErrorAction SilentlyContinue -Verbose
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

Function Update-WindowTitle ([String] $PassNumber) {
	Write-Host "Changing window title"
		$host.ui.RawUI.WindowTitle = "$SiteCode Provisioning | $env:computername | Pass $PassNumber | Please Wait"
}

If (Get-Module -Name ATGPS -ErrorAction SilentlyContinue){
	# List imported functions from ATGPS
	Write-Host `n====================================================
	Write-Host "The below functions are now loaded and ready to use:"
	Write-Host ====================================================

	Get-Command -Module ATGPS | Format-Wide -Column 3

	Write-Host ====================================================
	Write-Host "Type: 'Help <function name> -Detailed' for more info"
	Write-Host ====================================================
}


# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUAKdpvNxVWazSeXoYJqrvYD86
# VM6gggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
# AQsFADA7MQswCQYDVQQGEwJVUzEYMBYGA1UECgwPVGVjaG5vbG9neUdyb3VwMRIw
# EAYDVQQDDAlBbWJpdGlvbnMwHhcNMjQwNTE3MjEzNjE0WhcNMjUwNTE3MjE0NjE0
# WjA7MQswCQYDVQQGEwJVUzEYMBYGA1UECgwPVGVjaG5vbG9neUdyb3VwMRIwEAYD
# VQQDDAlBbWJpdGlvbnMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCc
# sesiq3h/qYB2H80J5kTzMdmjIWe/BHmnUDv2JHBGdxp+ZOT+J9RpPtHNQDXB3Lca
# aL4YjAWC4H+UqJDJJpFj8OXBns9zfpR5coV5+eR6YjRvos9TILNwdErlLrp5CcxN
# vtNR99GyXGsfzrvxc4uWwRc4/fjCPgYHs1BmFyxzSneTlr4CZ56wPJZ1yGRHKn0y
# H5O26/af7stiGZ2GLmXF8VMpEqGE/xWs31aM8xzYBN5FAQjAwoJTGZvm13kukR1t
# 6Uq3huPX5lUpTasPJ3qLXnePKYtIr+390aNzj2+sDt3lcH51vP46nFMQrpzD/Xaz
# K/7UP+9I4J8goswNTrZRAgMBAAGjRjBEMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUE
# DDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUuS0+jvyX95p7+tTFuzZ+ulXo7jQwDQYJ
# KoZIhvcNAQELBQADggEBAF4DPkvlELNjrIUYtWMsFjn+VU6vXENJ3lktFShfL8IS
# 1GDlNZFu+vuJJ2nzLuSNERzdfWa6Pd5qIP05eeinJJtN/sqCPVoLjmA1Td4K6Rau
# Cg8WlxgemTDr3IwqejUlGq8h5AYIw1ike7Q70m9UWyIWT8XNILcXXK0UKUylHRl/
# f+fPinhW56qDDmL+7ctECrTBtm8d1aZOtLEijEbZTg72N2SwaKF7mUVmycT5MuN7
# 46w+V1w/i46wPcf0hkTazvISgUevjXj7dM04U+htX+mDwpvjP/QvQjo37ozOYdQR
# pIjjnNPZIFXprVXI2PRvM/YqP6KTiyKPqOuI+TA9RmkxggHwMIIB7AIBATBPMDsx
# CzAJBgNVBAYTAlVTMRgwFgYDVQQKDA9UZWNobm9sb2d5R3JvdXAxEjAQBgNVBAMM
# CUFtYml0aW9ucwIQFhG2sMJplopOBSMb0j7zpDAJBgUrDgMCGgUAoHgwGAYKKwYB
# BAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAc
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUudZQ
# 9otRQ/9Y64/c94ffloj0yxswDQYJKoZIhvcNAQEBBQAEggEAZpkKkrNn6Q1w3p28
# eZKYyHEPOTZ3GKnWEQPi8gK3s43B01692QKMVrsCamEtc9H7cA5AR5JytNHl/hig
# WcOHnMq0u+1qIVro5FNW+Z4qf5QrnBYubXkb9wSR2fQ3FXt20/XRfrUdr9GaG3Vt
# 4/ScOctAGIAePLosi1fiZ+59Uwxg2nCGTFo4MulNUzGFwmfIHoKxhSOSbLxW+I2O
# hIO3ClJ/zdkRHynXYTgaerKjyTjSU6MHFZp9JD1DvzqF9V07iy8xONXuwNKY5zwi
# O799pl5w+MVM+EkZ1JZFogq4VCWqPcn5gT5zLuDWuDDwZxVICuNGOJ+HYJckcQGG
# R6QKsw==
# SIG # End signature block
