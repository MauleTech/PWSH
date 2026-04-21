Function Add-ChromeShortcut{
	param
	(
		[Parameter(Mandatory=$true)]
		[string]$Label,

		[Parameter(Mandatory=$true)]
		[string]$Url
	)

	If (Test-Path -Path 'C:\Program Files\Google\Chrome\Application\chrome.exe') {
		$TargetFile = "C:\Program Files\Google\Chrome\Application\chrome.exe"
	} ElseIf (Test-Path -Path 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe') {
		$TargetFile = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
	} Else {
		Write-Host "Google Chrome was not found. Please install manually or with Chocolatey:"
		Write-Host "   Install-Choco"
		Write-Host "   choco install GoogleChrome"
	}

	If ($TargetFile) {
		$ShortcutFile = "$env:Public\Desktop\" + $Label + ".lnk"
		$WScriptShell = New-Object -ComObject WScript.Shell
		$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
		$Shortcut.TargetPath = $TargetFile
		$Shortcut.Arguments = $Url
		$Shortcut.Save()
	}
	<#
	.SYNOPSIS
		Creates a Google Chrome Shortcut on the "All Users" Desktop.
		If Google Chrome is not found, prompts to install the program using Chocolatey.
	.PARAMETER Label
		The file name of the shortcut; ".lnk" is automatically appended.
	.PARAMETER Url
		The full URL that the shortcut intends to open: "https://www.google.com/"
	.EXAMPLE
		Add-ChromeShortcut -Label "Github PWSH" -Url "https://github.com/MauleTech/PWSH/"
	#>
}

Function Add-FileFolderShortcut {
	param
	(
		[Parameter(Mandatory=$true)]
		[string]$SourceLnk,

		[Parameter(Mandatory=$true)]
		[string]$DestinationPath,

		[Parameter(Mandatory=$false)]
		[string]$StartIn
	)

	$WshShell = New-Object -comObject WScript.Shell
	$Shortcut = $WshShell.CreateShortcut($SourceLnk)
	$Shortcut.TargetPath = $DestinationPath
	If ($StartIn) {$Shortcut.WorkingDirectory = $StartIn}
	$Shortcut.Save()

	<#
	.SYNOPSIS
		Creates a shortcut to a file or folder.
	.PARAMETER SourceLnk
		The file name of the shortcut. Must end with ".lnk"
	.PARAMETER DestinationPath
		What the shortcut is pointing to. "$ITFolder\RyanIsAwesome.txt"
	.EXAMPLE
		Add-FileFolderShortcut -SourceLnk "$env:Public\Desktop\IT Folder.lnk" -DestinationPath "$ITFolder"
		This example puts a shortcut on the desktop called "IT Folder" and points to $ITFolder.
	.EXAMPLE
		Add-FileFolderShortcut -SourceLnk "$env:Public\Desktop\ProLaw.lnk" -DestinationPath "\\rradb.robles.law\ProLaw\ProLaw.exe" -StartIn "\\rradb.robles.law\ProLaw"
		This example puts a shortcut on the desktop called ProLaw and with the working directory filled out.
	#>
}

Function Add-IEShortcut {
	param
	(
		[Parameter(Mandatory=$true)]
		[string]$Label,

		[Parameter(Mandatory=$true)]
		[string]$Url
	)

	$TargetFile = "C:\Program Files\Internet Explorer\iexplore.exe"
	$ShortcutFile = "$env:Public\Desktop\" + $Label + ".lnk"
	$WScriptShell = New-Object -ComObject WScript.Shell
	$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
	$Shortcut.TargetPath = $TargetFile
	$Shortcut.Arguments = $Url
	$Shortcut.Save()

	<#
	.SYNOPSIS
		Creates an Internet Explorer Shortcut on the "All Users" Desktop.
	.PARAMETER Label
		The file name of the shortcut; ".lnk" is automatically appended.
	.PARAMETER Url
		The full URL that the shortcut intends to open: "https://www.google.com/"
	.EXAMPLE
		Add-ChromeShortcut -Label "Github PWSH" -Url "https://github.com/MauleTech/PWSH/"
	#>

}

Function Add-RDPShortcut {
	<#
	.SYNOPSIS
		This script will create an rdp desktop shortcut with your specified options. It can create a shortcut for all users (including new ones) or existing ones only.
	.DESCRIPTION
		This script will create an rdp desktop shortcut with your specified options.
		It can create a shortcut for all users (including new ones) or existing ones only.
		Supports importing client configurations from a CSV file using the -Code parameter.
		Automatically detects and handles OneDrive folder redirection for Desktop locations.
		When an RD Gateway is specified, it will be explicitly used for all connections.
		If no name is specified, auto-generates name based on gateway/target and user.
	.EXAMPLE
		To Create a windowed RDP Shortcut simply specify the size, the name of the shortcut and which users the shortcut is for. You can also specify "MultiMon" for multi-monitor support. Or a gateway to use.

		PS C:> New-RDPShortcut -Name "Test" -RDPTarget "SRV19-TEST" -RDPUser "TEST\jsmith" -Width "1920" -Height "1080" -AllExistingUsers

		Creating Shortcut at C:\Users\JohnSmith\Desktop\Test.rdp

	.EXAMPLE
		To create an RDP shortcut using a client code from the CSV configuration:

		PS C:> New-RDPShortcut -Code "RHCO" -AllUsers

		Creates: rhcocpa.firmdesktop.com - AllUsers.rdp

	.EXAMPLE
		To create an RDP shortcut for a specific user with auto-naming:

		PS C:> New-RDPShortcut -Code "OSOL" -User "ryans"

		Creates: osol.firmdesktop.com - ryans.rdp

	.PARAMETER Code
		Client code to import settings from the CSV configuration file.

	.PARAMETER NAME
		Name of the shortcut ex. "Login Portal". If not specified, auto-generates based on gateway/target and user.

	.PARAMETER RDPtarget
		IP Address or DNS Name and port to the RDS Host ex. "TEST-RDSH:28665".

	.PARAMETER RDPuser
		Username to autofill in username field.

	.PARAMETER AlwaysPrompt
		Always Prompt for credentials.

	.PARAMETER Gateway
		IP Address or DNS Name and port of the RD Gateway ex. "TEST\rdp.example.com:4433".

	.PARAMETER SeperateGateWayCreds
		If the RDS Gateway uses different creds than the Session Host use this parameter.

	.PARAMETER LoadBalanceInfo
		Load balance info string for RDS collections ex. "tsv://MS Terminal Services Plugin.1.RDN".

	.PARAMETER FullScreen
		RDP Shortcut should open window in 'FullScreen' mode.

	.PARAMETER MultiMon
		RDP Shortcut should open window with Multi-Monitor Support enabled.

	.PARAMETER Width
		Width of RDP Window should open ex. "1920".

	.PARAMETER Height
		Height of RDP Window shortcut should open ex. "1080".

	.PARAMETER EnableDrives
		Enable drive redirection. Default is all drives except C:.

	.PARAMETER EnableLocation
		Enable location redirection. Default is true.

	.PARAMETER EnableVideoCapture
		Enable video capture devices. Default is true.

	.PARAMETER EnablePnPDevices
		Enable other PnP devices. Default is true.

	.PARAMETER AllExistingUsers
		Create the Shortcut for all existing users but not new users ex. C:\Users\*\Desktop\shortcut.lnk.

	.PARAMETER ExcludeUsers
		Comma seperated list of users to exclude from shortcut placement.

	.PARAMETER AllUsers
		Create the Shortcut in C:\Users\Public\Desktop.

	.PARAMETER PassThru
		Return the paths of created RDP files.

	.OUTPUTS
		System.String[]
		When using -PassThru, returns an array of created RDP file paths.

	.NOTES
		This function requires administrative privileges to create shortcuts in Public or other user directories.
		The function automatically detects OneDrive folder redirection and creates shortcuts in the correct location.
		If a user's Desktop is redirected to OneDrive, the shortcut will be created in the OneDrive Desktop folder.

		Auto-naming behavior when -Name is not specified:
		- Uses Gateway address if specified, otherwise uses RDPTarget
		- Appends user designation: username, "AllUsers", or "AllExistingUsers"
		- Example: "gateway.domain.com:443 - username.rdp"
	#>

	[CmdletBinding()]
	param (
		[Parameter()]
		[String]$Code,
		[Parameter()]
		[String]$Name,
		[Parameter()]
		[String]$RDPtarget,
		[Parameter()]
		[String]$RDPuser,
		[Parameter()]
		[Switch]$AlwaysPrompt = [System.Convert]::ToBoolean($env:alwaysPromptForRdpCredentials),
		[Parameter()]
		[String]$Gateway,
		[Parameter()]
		[Switch]$SeparateGateWayCreds = [System.Convert]::ToBoolean($env:separateRdpGatewayCredentials),
		[Parameter()]
		[String]$LoadBalanceInfo,
		[Parameter()]
		[Switch]$FullScreen,
		[Parameter()]
		[Switch]$MultiMon = $true,
		[Parameter()]
		[Int]$Width,
		[Parameter()]
		[Int]$Height,
		[Parameter()]
		[String]$EnableDrives = "AllButC",
		[Parameter()]
		[Switch]$EnableLocation = $true,
		[Parameter()]
		[Switch]$EnableVideoCapture = $true,
		[Parameter()]
		[Switch]$EnablePnPDevices = $true,
		[Parameter()]
		[Switch]$AllExistingUsers,
		[Parameter()]
		[Switch]$AllUsers,
		[Parameter()]
		[String]$User,
		[Parameter()]
		[Switch]$PassThru
	)

	begin {
		# Import configuration from CSV if Code parameter is provided
		if ($Code) {
			try {
				Write-Verbose "Fetching client configuration for code: $Code"
				$csvUrl = "https://raw.githubusercontent.com/MauleTech/BinCache/refs/heads/main/RDP_Codes.csv"
				$csvData = Invoke-RestMethod -Uri $csvUrl -Method Get
				$clients = $csvData | ConvertFrom-Csv

				$clientConfig = $clients | Where-Object { $_.Code -eq $Code }

				if ($clientConfig) {
					Write-Host "Found configuration for client code: $Code" -ForegroundColor Green

					# Apply CSV values only if the parameter wasn't explicitly provided
					if (!$PSBoundParameters.ContainsKey('Name') -and $clientConfig.Name) {
						$Name = $clientConfig.Name
					}
					if (!$PSBoundParameters.ContainsKey('RDPtarget') -and $clientConfig.RDPTarget) {
						$RDPtarget = $clientConfig.RDPTarget
					}
					if (!$PSBoundParameters.ContainsKey('RDPuser') -and $clientConfig.RDPUser) {
						$RDPuser = $clientConfig.RDPUser
					}
					if (!$PSBoundParameters.ContainsKey('Gateway') -and $clientConfig.Gateway) {
						$Gateway = $clientConfig.Gateway
					}
					if (!$PSBoundParameters.ContainsKey('LoadBalanceInfo') -and $clientConfig.LoadBalanceInfo) {
						$LoadBalanceInfo = $clientConfig.LoadBalanceInfo
					}
					if (!$PSBoundParameters.ContainsKey('AlwaysPrompt') -and $clientConfig.AlwaysPrompt) {
						$AlwaysPrompt = [System.Convert]::ToBoolean($clientConfig.AlwaysPrompt)
					}
					if (!$PSBoundParameters.ContainsKey('SeparateGateWayCreds') -and $clientConfig.SeparateGateWayCreds) {
						$SeparateGateWayCreds = [System.Convert]::ToBoolean($clientConfig.SeparateGateWayCreds)
					}
					if (!$PSBoundParameters.ContainsKey('FullScreen') -and $clientConfig.FullScreen) {
						$FullScreen = [System.Convert]::ToBoolean($clientConfig.FullScreen)
					}
					if (!$PSBoundParameters.ContainsKey('MultiMon') -and $clientConfig.MultiMon) {
						$MultiMon = [System.Convert]::ToBoolean($clientConfig.MultiMon)
					}
					if (!$PSBoundParameters.ContainsKey('Width') -and $clientConfig.Width) {
						$Width = [int]$clientConfig.Width
					}
					if (!$PSBoundParameters.ContainsKey('Height') -and $clientConfig.Height) {
						$Height = [int]$clientConfig.Height
					}
					if (!$PSBoundParameters.ContainsKey('EnableDrives') -and $clientConfig.EnableDrives) {
						$EnableDrives = $clientConfig.EnableDrives
					}
				}
				else {
					Write-Warning "No configuration found for client code: $Code"
				}
			}
			catch {
				Write-Error "Failed to fetch or parse CSV configuration: $_"
			}
		}

		# Replace existing params with form variables if they're used
		if ($env:shortcutName -and $env:shortcutName -notlike "null") { $Name = $env:shortcutName }
		if ($env:createTheShortcutFor -and $env:createTheShortcutFor -notlike "null") {
			if ($env:createTheShortcutFor -eq "All Users") { $AllUsers = $True }
			if ($env:createTheShortcutFor -eq "All Existing Users") { $AllExistingUsers = $True }
		}
		if ($env:rdpServerAddress -and $env:rdpServerAddress -notlike "null") { $RDPtarget = $env:rdpServerAddress }
		if ($env:rdpUsername -and $env:rdpUsername -notlike "null") { $RDPuser = $env:rdpUsername }
		if ($env:rdpGatewayServerAddress -and $env:rdpGatewayServerAddress -notlike "null") { $Gateway = $env:rdpGatewayServerAddress }
		if ($env:rdpWindowSize -and $env:rdpWindowSize -notlike "null") {
			if ($env:rdpWindowSize -eq "Fullscreen Multiple Monitor Mode") { $MultiMon = $True }
			if ($env:rdpWindowSize -eq "Fullscreen") { $FullScreen = $True }
		}
		if ($env:customRdpWindowWidth -and $env:customRdpWindowWidth -notlike "null") { $Width = $env:customRdpWindowWidth }
		if ($env:customRdpWindowHeight -and $env:customRdpWindowHeight -notlike "null") { $Height = $env:customRdpWindowHeight }

		# Output warnings for conflicting options
		if (($Width -and -not $Height ) -or ($Height -and -not $Width)) {
			Write-Warning "You forgot to include both the width and height. RDP Window will be in fullscreen mode."
		}

		if (($Width -or $Height) -and ($FullScreen -or $MultiMon)) {
			if ($MultiMon) {
				Write-Warning "Conflicting Display Option selected. Using Fullscreen Multi-monitor."
			}
			else {
				Write-Warning "Conflicting Display Option selected. Using Fullscreen."
			}
		}

		# Double-check that a user is specified for shortcut creation
		if (-not $AllUsers -and -not $AllExistingUsers -and -not $User) {
			Write-Error "You must specify which desktop to create the shortcut on!"
			return
		}

		# Double-check that a shortcut name was provided or can be generated
		if (-not $Name) {
			# Auto-generate name based on Gateway or RDPTarget
			if ($Gateway) {
				# Use gateway as base name (keep port for uniqueness)
				$Name = $Gateway
			} elseif ($RDPTarget) {
				# Use RDP target as base name (keep port for uniqueness)
				$Name = $RDPTarget
			} else {
				Write-Error "You must specify a name or have a target/gateway for auto-naming!"
				return
			}

			# Append user designation
			if ($AllUsers) {
				$Name = "$Name - AllUsers"
			} elseif ($AllExistingUsers) {
				$Name = "$Name - AllExistingUsers"
			} elseif ($User) {
				$Name = "$Name - $User"
			} else {
				$Name = "$Name - $env:USERNAME"
			}

			Write-Verbose "Auto-generated shortcut name: $Name"
		}

		if (-not $RDPtarget) {
			Write-Error "You must specify an RDP target!"
			return
		}

		# Creating a shortcut at C:\Users\Public\Desktop requires admin rights
		function Test-IsElevated {
			$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
			$p = New-Object System.Security.Principal.WindowsPrincipal($id)
			$p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
		}

		if (!(Test-IsElevated)) {
			Write-Error -Message "Access Denied. Please run with Administrator privileges."
			return
		}

		# Get the actual Desktop folder path for a user (handles OneDrive redirection)
		function Get-UserDesktopPath {
			param (
				[Parameter(Mandatory=$true)]
				[String]$UserSID,
				[Parameter()]
				[String]$DefaultPath
			)

			try {
				# Try to get the actual Desktop path from the user registry
				$regPath = "Registry::HKEY_USERS\$UserSID\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
				if (Test-Path $regPath) {
					$desktopPath = (Get-ItemProperty -Path $regPath -Name "Desktop" -ErrorAction SilentlyContinue).Desktop
					if ($desktopPath) {
						# Expand environment variables
						$desktopPath = [Environment]::ExpandEnvironmentVariables($desktopPath)
						# If path contains %USERPROFILE%, replace with actual path
						if ($desktopPath -like "*%USERPROFILE%*" -and $DefaultPath) {
							$userProfilePath = Split-Path -Parent $DefaultPath
							$desktopPath = $desktopPath -replace '%USERPROFILE%', $userProfilePath
						}
						if (Test-Path $desktopPath) {
							Write-Verbose "Found redirected Desktop for SID ${UserSID} at: $desktopPath"
							return $desktopPath
						}
						else {
							Write-Verbose "Redirected path doesn't exist, using default: $DefaultPath"
						}
					}
				}
			}
			catch {
				Write-Verbose "Could not read registry for SID ${UserSID}: $_"
			}

			# Fallback to default path
			Write-Verbose "Using default Desktop path for SID ${UserSID}: $DefaultPath"
			return $DefaultPath
		}

		# Retrieve all registry paths for actual users (excluding system or network service accounts)
		function Get-UserHives {
			param (
				[Parameter()]
				[ValidateSet('AzureAD', 'DomainAndLocal', 'All')]
				[String]$Type = "All",
				[Parameter()]
				[String[]]$ExcludedUsers,
				[Parameter()]
				[switch]$IncludeDefault
			)

			# User account SIDs follow a particular pattern
			$Patterns = switch ($Type) {
				"AzureAD" { "S-1-12-1-(\d+-?){4}$" }
				"DomainAndLocal" { "S-1-5-21-(\d+-?){4}$" }
				"All" { "S-1-12-1-(\d+-?){4}$" ; "S-1-5-21-(\d+-?){4}$" }
			}

			# Get NTuser.dat file to load each users registry hive
			$UserProfiles = Foreach ($Pattern in $Patterns) {
				Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
					Where-Object { $_.PSChildName -match $Pattern } |
					Select-Object @{Name = "SID"; Expression = { $_.PSChildName } },
					@{Name = "UserHive"; Expression = { "$($_.ProfileImagePath)\NTuser.dat" } },
					@{Name = "UserName"; Expression = { "$($_.ProfileImagePath | Split-Path -Leaf)" } },
					@{Name = "Path"; Expression = { $_.ProfileImagePath } },
					@{Name = "DesktopPath"; Expression = {
						$defaultDesktop = "$($_.ProfileImagePath)\Desktop"
						Get-UserDesktopPath -UserSID $_.PSChildName -DefaultPath $defaultDesktop
					}}
			}

			# In some cases, retrieve the .Default user information
			switch ($IncludeDefault) {
				$True {
					$DefaultProfile = "" | Select-Object UserName, SID, UserHive, Path, DesktopPath
					$DefaultProfile.UserName = "Default"
					$DefaultProfile.SID = "DefaultProfile"
					$DefaultProfile.Userhive = "$env:SystemDrive\Users\Default\NTUSER.DAT"
					$DefaultProfile.Path = "C:\Users\Default"
					$DefaultProfile.DesktopPath = "C:\Users\Default\Desktop"

					$DefaultProfile | Where-Object { $ExcludedUsers -notcontains $_.UserName }
				}
			}

			$UserProfiles | Where-Object { $ExcludedUsers -notcontains $_.UserName }
		}
	}
	process {
		$script:hasErrors = $false
		$ShortcutPath = New-Object System.Collections.Generic.List[String]

		# Create the filenames for the path
		if ($RDPTarget) { $File = "$Name.rdp" }

		# Build the paths and add them to the ShortcutPath list
		if ($AllUsers) {
			# For All Users, check if Public Desktop is redirected
			$publicDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
			if (-not $publicDesktop) {
				$publicDesktop = "$env:Public\Desktop"
			}
			$ShortcutPath.Add("$publicDesktop\$File")
		}

		if ($AllExistingUsers) {
			$UserProfiles = Get-UserHives
			# Loop through each user profile, using their actual Desktop path
			$UserProfiles | ForEach-Object {
				$ShortcutPath.Add("$($_.DesktopPath)\$File")
			}
		}

		if ($User) {
			# First check if we're targeting the current user (easier detection)
			if ($env:USERNAME -like $User -or $env:USERNAME -eq $User) {
				$currentUserDesktop = [Environment]::GetFolderPath('Desktop')
				if ($currentUserDesktop -and (Test-Path $currentUserDesktop)) {
					Write-Verbose "Using current user's Desktop: $currentUserDesktop"
					$ShortcutPath.Add("$currentUserDesktop\$File")
				}
				else {
					Write-Error "Could not determine current user's Desktop path"
					return
				}
			}
			else {
				# For other users, use the profile lookup
				$UserProfile = Get-UserHives | Where-Object { $_.Username -like $User }
				if ($UserProfile) {
					$ShortcutPath.Add("$($UserProfile.DesktopPath)\$File")
				}
				else {
					Write-Error "User profile for '$User' not found"
					return
				}
			}
		}

		$RDPFile = New-Object System.Collections.Generic.List[String]

		# Enhanced template with MSP-specific defaults
		# FIX 1: Changed gatewaycredentialssource from 4 to 0
		# FIX 2: Changed use redirection server name from 0 to 1
		$Template = @"
session bpp:i:24
compression:i:1
keyboardhook:i:2
audiocapturemode:i:1
videoplaybackmode:i:1
connection type:i:7
networkautodetect:i:1
bandwidthautodetect:i:1
displayconnectionbar:i:1
enableworkspacereconnect:i:0
disable wallpaper:i:0
allow font smoothing:i:1
allow desktop composition:i:0
disable full window drag:i:1
disable menu anims:i:1
disable themes:i:0
disable cursor setting:i:0
bitmapcachepersistenable:i:1
audiomode:i:0
redirectprinters:i:1
redirectcomports:i:0
redirectsmartcards:i:0
redirectwebauthn:i:0
redirectclipboard:i:1
redirectposdevices:i:0
autoreconnection enabled:i:1
authentication level:i:2
negotiate security layer:i:1
remoteapplicationmode:i:0
alternate shell:s:
shell working directory:s:
gatewaycredentialssource:i:0
gatewaybrokeringtype:i:0
use redirection server name:i:1
rdgiskdcproxy:i:0
kdcproxyname:s:
enablerdsaadauth:i:0
prompt for credentials on client:i:1
server port:i:3389
"@
		$RDPFile.Add($Template)

		# Process drive redirection settings
		# FIX 4: Added redirectdrives:i:1 for drive redirection
		$driveList = ""
		switch ($EnableDrives) {
			"All" {
				$RDPFile.Add("drivestoredirect:s:*")
				$RDPFile.Add("redirectdrives:i:1")
			}
			"None" {
				$RDPFile.Add("drivestoredirect:s:")
				$RDPFile.Add("redirectdrives:i:0")
			}
			"AllButC" {
				# Get all drive letters except C
				$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -ne 'C' } | ForEach-Object { $_.Name }
				if ($drives) {
					$driveList = ($drives | ForEach-Object { "${_}:" }) -join ";"
					$RDPFile.Add("drivestoredirect:s:$driveList")
				} else {
					$RDPFile.Add("drivestoredirect:s:*")
				}
				$RDPFile.Add("redirectdrives:i:1")
			}
			default {
				# Specific drives provided
				$RDPFile.Add("drivestoredirect:s:$EnableDrives")
				$RDPFile.Add("redirectdrives:i:1")
			}
		}

		# Add location redirection
		if ($EnableLocation) {
			$RDPFile.Add("redirectlocation:i:1")
		} else {
			$RDPFile.Add("redirectlocation:i:0")
		}

		# Add video capture redirection
		if ($EnableVideoCapture) {
			$RDPFile.Add("camerastoredirect:s:*")
			$RDPFile.Add("devicestoredirect:s:*")
		} else {
			$RDPFile.Add("camerastoredirect:s:")
			$RDPFile.Add("devicestoredirect:s:")
		}

		# Add PnP device redirection
		if ($EnablePnPDevices) {
			$RDPFile.Add("usbdevicestoredirect:s:*")
		} else {
			$RDPFile.Add("usbdevicestoredirect:s:")
		}

		# This will generate the actual .rdp file
		$CreatedFiles = New-Object System.Collections.Generic.List[String]

		$ShortcutPath | ForEach-Object {
			# Create a fresh RDP file for each shortcut path
			$CurrentRDPFile = New-Object System.Collections.Generic.List[String]
			$CurrentRDPFile.AddRange($RDPFile)

			$CurrentRDPFile.Add("full address:s:$RDPTarget")

			# FIX 3: Add workspace id and alternate full address for RD Connection Broker support
			$CurrentRDPFile.Add("alternate full address:s:$RDPTarget")
			$CurrentRDPFile.Add("workspace id:s:$RDPTarget")

			if ($Gateway) {
				$CurrentRDPFile.Add("gatewayhostname:s:$Gateway")
			}

			if ($LoadBalanceInfo) {
				$CurrentRDPFile.Add("loadbalanceinfo:s:$LoadBalanceInfo")
			}

			if ($Width) { $CurrentRDPFile.Add("desktopwidth:i:$Width") }
			if ($Height) { $CurrentRDPFile.Add("desktopheight:i:$Height") }
			if ($MultiMon) { $CurrentRDPFile.Add("use multimon:i:1") } else { $CurrentRDPFile.Add("use multimon:i:0") }
			if ($FullScreen -or $MultiMon -or !$Height -or !$Width) {
				$CurrentRDPFile.Add("screen mode id:i:2")
			} else {
				$CurrentRDPFile.Add("screen mode id:i:1")
			}
			if ($AlwaysPrompt) {
				$CurrentRDPFile.Add("prompt for credentials:i:1")
			} else {
				$CurrentRDPFile.Add("prompt for credentials:i:0")
			}

			# Gateway usage method settings
			if ($Gateway) {
				# When Gateway is specified, always use it explicitly
				$CurrentRDPFile.Add("gatewayusagemethod:i:1")
				$CurrentRDPFile.Add("gatewayprofileusagemethod:i:1")
			} else {
				# When no Gateway specified, don't use one
				$CurrentRDPFile.Add("gatewayusagemethod:i:0")
			}

			if ($SeparateGateWayCreds) {
				$CurrentRDPFile.Add("promptcredentialonce:i:0")
			}
			else {
				$CurrentRDPFile.Add("promptcredentialonce:i:1")
			}

			if ($RDPUser) {
				$CurrentRDPFile.Add("username:s:$RDPUser")
			}

			# Add window position string
			$CurrentRDPFile.Add("winposstr:s:0,3,0,0,800,600")

			# Add remote app mouse move inject
			$CurrentRDPFile.Add("remoteappmousemoveinject:i:1")

			Write-Host "Creating Shortcut at $_"

			# Write RDP file with UTF8 encoding
			$CurrentRDPFile | Out-File $_ -Encoding UTF8

			if (!(Test-Path $_ -ErrorAction SilentlyContinue)) {
				Write-Error "Unable to create Shortcut at $_"
				$script:hasErrors = $true
			}
			else {
				$CreatedFiles.Add($_)
			}
		}

		if ($script:hasErrors) {
			Write-Error "One or more shortcuts failed to create"
			if (-not $PassThru) {
				return
			}
		}
		else {
			Write-Host "Successfully created RDP shortcuts" -ForegroundColor Green
		}

		# Return created file paths if PassThru is specified
		if ($PassThru) {
			return $CreatedFiles.ToArray()
		}
	}
	end {
	}
}

Function Add-WebShortcut{
	param
	(
		[string]$Label,
		[string]$Url
	)

	Write-Host "Adding a shortcut to $Label to the desktop"
	$Shell = New-Object -ComObject ("WScript.Shell")
	$URLFilePath = $env:Public + "\Desktop\" + $Label + ".url"
	$Favorite = $Shell.CreateShortcut($URLFilePath)
	$Favorite.TargetPath = $Url
	$Favorite.Save()
}

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB9Hl415cOPtH5I
# FkDqYjm9vOe/dtSSpQ+NXRFt3p/Kj6CCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IGCRsxTxUvtNVICHPVaTITYp2n0RxHUn/PBqgYbFMLu3MA0GCSqGSIb3DQEBAQUA
# BIICACMB0Kza8aE3BXM93I6gIrmrQ8fitm6DT378eFTgvU9rSyjTWYQH/7gsHX0O
# 16+9tJog+acKzymJ0V7SYtvxWRF+y/L+9ZqbWVyuGgFRP0qNrA8rIWz6ZgPxE1Xp
# 6GBnxauBP4MRYbfD0WkcfuqPijgDuVMBatZCdN9h2HeuGpmsnUFJnNkFMyED/nAf
# KCpmWguhaa0vQOobV07dIYNQdjYmP69Jw8Mfm9paM03oiA+VOyjmtLcZTjHxa/DK
# CV3mBZpq+OHgVMU9P4YlpXCPX7AVrB6sxh/uuGuPaLq3lGjF0XsXlMpb2q0ptGjR
# gABg5q+agMrJrh8nlOfojKiHUItjMNYXATfOXF4rdhthVKsj9PtOFS7dp1mMtJXc
# EsxXbW/e7MrfDAm1CsL5iRB6VGnkmj7rMRcAC3qYGjnL/RZUhUHas6cro7ADy3OW
# GNWjvpOrQrrHfAqIbFmPcZ3ovcxpVl5lKb3mYaOCkgVTdv02XV/6TQKpmaLkeuNJ
# XfDK88XuStr6vUvGb5ozaEYxJYzHxPJjMvlESEIuNgZemsxieoW19hjf3FHOQKTy
# +KHIbDPFXYlCcwlBkzJI5yN9yzZG4iAtmSt+iRvgPwAQqakysu2lUa7DgMAC9bpy
# 11PsQoQtZlU8ROPZf1pb7fmXJKSRzY914fpeTF9SyBBJooI0oYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDQyMTE3NTEzMlowLwYJKoZIhvcNAQkEMSIEIKsqMPSx
# /ujD+imncEZBOjTY/1ifzCv5pZqIzEBQJedgMA0GCSqGSIb3DQEBAQUABIICAMRX
# c7jbS1wt3Evks+A+NDq4oossSAOgw9qYwa2fe5urnW8ZvGwN/NwPAs47JUSHMoXH
# iOT7/xdILwXmfefebT8KtqRrvbAJjbda56XyZAhdVxKWB12o+cpJtu618FtJUQeT
# I5YRqZ3SPqB6MBm3k7gUbm5rZOhe+9CrSlVYzd4PDIEKyjNO947fUPzzbUDDLHLx
# dXz2C4GaFln85dJY4zFRtAW07DLptSAfQDXRC5eCCeHcDR40xohWRShrL2L3PLyg
# 3WrXpSPZEiAw0N2t8XHPpy+vD/w+g1YJ6zS190vGGiQEPyhCNcAyLfidlW6ouEg4
# MOblRYFSTqX6ieHPKYllpihr+tYHw+SBdrdfgz+1qc6fxWanrAj+OUANbu9BB/hx
# nJl4yKRFbabUH/TVOofEJG+QdEkZ6JCZn1Y130J3Rdoq+08MbJ6JM7IX269f5jX/
# /Rv2tBfLlGnEnDXsDCqOIU4KGwlFRknweHEv94ukR9UUskLn7zXnKHWebmmuja4e
# XMlSR7aoSKIMvLzqGGKkLIGcmC3LI10thrPGNbNb4h1tvk/abLiCrL0rwkDc5g2A
# tdHs/Eu5G1hxqDaJTfN/fEWz3/FXCkdM0/qx+ImFxPKbgiF36S657QAquTZeMFcR
# C94vgyvYIVd4uTJgEWO3RgwkYrp6viFIgzT2KErO
# SIG # End signature block
