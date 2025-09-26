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
		If Google Chrome is not found, prompts to install the program using ATG-PS scripts + Chocolately.
	.PARAMETER Label
		The file name of the shortcut; ".lnk" is automatically appended.
	.PARAMETER Url
		The full URL that the shortcut intends to open: "https://www.google.com/"
	.EXAMPLE
		Add-ChromeShortcut -Label "Github ATG-PS" -Url "https://github.com/MauleTech/PWSH/"
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
		Add-FileFolderShortcut -SourceLnk "$env:Public\Desktop\Ambitions Folder.lnk" -DestinationPath "$ITFolder"
		This example puts a shortcut on the desktop called "Ambitions Folder" and points to $ITFolder.
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
		Add-ChromeShortcut -Label "Github ATG-PS" -Url "https://github.com/MauleTech/PWSH/"
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
allow desktop composition:i:1
disable full window drag:i:0
disable menu anims:i:0
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
gatewaycredentialssource:i:4
gatewaybrokeringtype:i:0
use redirection server name:i:0
rdgiskdcproxy:i:0
kdcproxyname:s:
enablerdsaadauth:i:0
"@
		$RDPFile.Add($Template)

		# Process drive redirection settings
		$driveList = ""
		switch ($EnableDrives) {
			"All" { 
				$RDPFile.Add("drivestoredirect:s:*")
			}
			"None" { 
				$RDPFile.Add("drivestoredirect:s:")
			}
			"AllButC" { 
				# Get all drive letters except C
				$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -ne 'C' } | ForEach-Object { $_.Name }
				if ($drives) {
					$driveList = ($drives | ForEach-Object { "${_}:" }) -join ";"
					$RDPFile.Add("drivestoredirect:s:$driveList")
				}
			}
			default { 
				# Specific drives provided
				$RDPFile.Add("drivestoredirect:s:$EnableDrives")
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

			Write-Host "Creating Shortcut at $_"
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
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUeD6IvvNtkFdUUUNKRmRenFw+
# hz+gggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUY9cs
# MQQwQB5TurtF5sRQGYIsAWUwDQYJKoZIhvcNAQEBBQAEggEADXIeLFG/GhTtbqC4
# jDnF0BJIMk936A4y1pvd1j6dgGkfxmzAj8eMvNsR42cQJEt7e07fC0i9P2NgxUxK
# 6X6KGxyWxpJ+svSkvsBaf1rUibF5ILmeKqILDbyYj0r/HUhgoUK6cPZ0GZG12ZVW
# I4Ma9xQ/2rmJTJM27vX2xOI8TE6SoaXDZoulwRA+4eLtAeCPCMasYBgzrR7/Yr3a
# hvI47dRoJULk2g43loa7M3qzareaCdU82loBT1JVA5VR4MTANfGFgHtmcqC9IVs5
# dB8jl+2DkIZ/+iLT+8rg3vCsrBFnZHfAlRrV1tqB2H8bPxexzW1+PAAQY0XkZ3uE
# LieM2A==
# SIG # End signature block
