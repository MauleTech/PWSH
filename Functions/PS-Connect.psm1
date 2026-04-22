Function Connect-NetExtender {
	param
	(
		[Parameter(Mandatory = $False)]
		[string]$DC,
		[Parameter(Mandatory = $true)]
		[string]$VPNuri,
		[Parameter(Mandatory = $true)]
		[string]$VPNuser,
		[Parameter(Mandatory = $true)]
		[string]$VPNpassword,
		[Parameter(Mandatory = $true)]
		[string]$VPNdomain
	)

	# Define possible paths
	$possiblePaths = @(
		"${env:ProgramFiles(x86)}\SonicWALL\SSL-VPN\NetExtender\NEClI.exe"
		"${env:ProgramFiles(x86)}\SonicWall\SSL-VPN\NetExtender\nxcli.exe"
		"${env:ProgramFiles}\SonicWall\SSL-VPN\NetExtender\nxcli.exe"
	)

	# Find the first valid path
	$NEPath = $possiblePaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Last 1

	If (([string]::IsNullOrWhiteSpace($DC)) -or (-not (Test-Connection -comp $DC -quiet))) {
		If (!$NEPath) {
			Install-NetExtender
			# After installation, check paths again
			$NEPath = $possiblePaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Last 1
			if (!$NEPath) {
				Write-Error "NetExtender executable not found after installation"
				return
			}
		}

		Write-host "Initiating VPN connection"
		If ($NEPath -match "NEClI.exe") { #Older version
			echo y | & "$NEPath" connect -s $VPNuri -u $VPNuser -p $VPNpassword -d $VPNdomain
			Write-Host ""
			Get-NetExtenderStatus
		} elseif ($NEPath -match "nxcli.exe") { #Newer version
			echo T | & "$NEPath" connect -s $VPNuri -u $VPNuser -p $VPNpassword -d $VPNdomain
			Write-Host ""
			Get-NetExtenderStatus
		}
		Write-Host 'Try "Disconnect-NetExtender" or "Get-NetExtenderStatus"'
	}
	<#
	.SYNOPSIS
	Initiates an SSLVPN connection to a site using Sonicwall NetExtender
	.PARAMETER DC
	(Optional) A domain controller whose connection to can be tested to see if the vpn connection is needed. Example -DC "tsdc"
	.PARAMETER VPNuri
	The connection URL and port. Example -VPNuri "vpn.ambitinsgroup.com:4433"
	.PARAMETER VPNuser
	The vpn enable user to be used. Example -VPNuser "vpnuser"
	.PARAMETER VPNpassword
	The vpn user's password to be used. Example -VPNpassword "s0m3Gr3@tPw"
	.PARAMETER VPNdomain
	The SSLVPN domain to be used, found in the sonicwall settings. Example -VPNdomain "LocalDomain"
	.EXAMPLE
	Connect-NetExtender -DC "TSDC" -VPNuri "vpn.ts.com:4433" -VPNuser "tsadmin" -VPNpassword "R@nD0m!" -VPNdomain "LocalDomain"
	This example connects to the client Test Site, if such a client were to exist.
	#>
}

Function Connect-O365AzureAD {
	<#
	.SYNOPSIS
		[DEPRECATED] Initiates an Office 365 Azure AD connection using the legacy AzureAD module.
	.DESCRIPTION
		This function is DEPRECATED. The AzureAD PowerShell module is retired as of March 30, 2024.
		Microsoft recommends migrating to Microsoft Graph PowerShell SDK.
		Use Connect-MgGraph from the Microsoft.Graph module instead.
		See: https://learn.microsoft.com/en-us/powershell/azure/active-directory/migration-faq
	.LINK
		https://docs.microsoft.com/en-us/microsoft-365/enterprise/connect-to-microsoft-365-powershell?view=o365-worldwide
	.EXAMPLE
		Connect-O365AzureAD
		Connects using the deprecated AzureAD module.
	.EXAMPLE
		# Recommended replacement:
		# Install-Module Microsoft.Graph -Scope CurrentUser
		# Connect-MgGraph -Scopes "User.Read.All","Group.Read.All"
	#>
	Write-Warning "DEPRECATED: The AzureAD module is retired. Please migrate to Microsoft.Graph module."
	Write-Warning "Use 'Connect-MgGraph' instead. See: https://learn.microsoft.com/en-us/powershell/microsoftgraph/migration-steps"

	If (-not (Get-Command Connect-AzureAD -ErrorAction SilentlyContinue)) {
		Write-Host "Installing the Azure AD module"
		Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
		Install-Module -Name AzureAD -AllowClobber -Force
		$ModVer = (Get-Command Connect-AzureAD).Version
		If ($ModVer) {
			Write-Host "Azure AD module version $ModVer has been installed."
		} Else {
			Write-Host "Azure AD module failed to install."
			Break
		}
	} Else {
		$Readhost = 'N'
		$Readhost = Read-Host "Do you want to check for module updates? This should be done periodically. `n(y/N)"
		Switch ($ReadHost) {
			Y {
				$ModVer = (Get-Command Connect-AzureAD).Version
				$AvailableModVer = (Find-Module AzureAD -Repository PSGallery).Version
				If ($ModVer -ne $AvailableModVer) {
					Write-host "AzureAD has an update from $ModVer to $AvailableModVer.`nInstalling the update."
					Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
					Install-Module -Name AzureAD -AllowClobber -Force
				} Else {
					Write-host "AzureAD is already up to date at version $AvailableModVer."
				}
			}
			N { Write-Host "Skipping update check." }
			Default { Write-Host "Skipping update check." }
		}
	}

	Connect-AzureAD

	Write-Host -ForegroundColor White -BackgroundColor DarkRed @"
		Be sure to disconnect the remote PowerShell session when you're finished.
		If you close the Windows PowerShell window without disconnecting the session,
		you could use up all the remote PowerShell sessions available to you,
		and you'll need to wait for the sessions to expire.
		To disconnect the remote PowerShell session, run the following command.

		Disconnect-AzureAD
"@
}

Function Connect-O365Exchange {
	param
	(
		[Parameter(Mandatory = $False)]
		[switch]$Quiet
	)
	If (-not (Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue)) {
		Write-Host "Installing the Exchange Online Management module"
		Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
		Install-Module -Name ExchangeOnlineManagement -AllowClobber -Force
		$ModVer = (Get-Command Connect-ExchangeOnline).Version
		If ($ModVer) {
			Write-Host "Exchange Online Management module version $ModVer has been installed."
		}
		Else {
			Write-Host "Exchange Online Management module failed to install."
			Break
		}
	}
 Else {
		If (-not $Quiet) {
			$Readhost = 'N'
			$Readhost = Read-Host "Do you want to check for module updates? This should be done periodically. n(y/N)"
		}
		Else { $Readhost = 'Y' }
		Switch ($ReadHost) {
			Y {
				$ModVer = (Get-Command Connect-ExchangeOnline).Version
				$AvailableModVer = (Find-Module ExchangeOnlineManagement -Repository PSGallery).Version
				If ($ModVer -ne $AvailableModVer) {
					Write-host "ExchangeOnlineManagement has an update from $ModVer to $AvailableModVer.`nInstalling the update."
					Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
					Remove-Module -Name ExchangeOnlineManagement -Force -ErrorAction SilentlyContinue
					Uninstall-Module -Name ExchangeOnlineManagement -AllVersions -Force -ErrorAction SilentlyContinue
					If (Get-Module -Name ExchangeOnlineManagement -ListAvailable) {
						$ModPath = (Get-Module -Name ExchangeOnlineManagement -ListAvailable).ModuleBase
						$ArgumentList = '/C "taskkill /IM powershell.exe /F & rd /s /q "' + $ModPath + '" & start powershell -NoExit -ExecutionPolicy Bypass -Command "irm raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt | iex ; Connect-O365Exchange"'
						Start-Process "cmd.exe" -ArgumentList $ArgumentList
					}
					Install-Module -Name ExchangeOnlineManagement -AllowClobber -Force
				}
				Else {
					Write-host "ExchangeOnlineManagement is already up to date at version $AvailableModVer."
				}
			}
			N { Write-Host "Skipping update check." }
			Default { Write-Host "Skipping update check." }
		}
	}
	
	If ($PSVersionTable.PSEdition -like "Desktop") {
		Connect-ExchangeOnline -ShowBanner:$false
	
	}
 Else {
		Write-Host -ForegroundColor Green -BackgroundColor DarkRed "Warning! You are using a CORE edition of Powershell. You will need to authenticate via a browser window."
		Connect-ExchangeOnline -ShowBanner:$false -Device
	}
	
	If (-not $Quiet) {
		Write-Host -ForegroundColor White -BackgroundColor DarkRed @"
	Be sure to disconnect the remote PowerShell session when you're finished.
	If you close the Windows PowerShell window without disconnecting the session,
	you could use up all the remote PowerShell sessions available to you,
	and you'll need to wait for the sessions to expire.
	To disconnect the remote PowerShell session, run the following command.
	
	Disconnect-O365Exchange
"@
	}
	
	<#
	.SYNOPSIS
	Initiates an Office 365 Exchange connection that is compatible with MFA.
	
	.LINK
	https://docs.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell?view=exchange-ps
	
	.EXAMPLE
	Connect-O365Exchange
	Yup, that's it!
	#>
}

Function Connect-O365Sharepoint {
	param
	(
		[Parameter(Mandatory = $false)]
		[string]$url,

		[Parameter(Mandatory = $False)]
		[switch]$Quiet
	)
	If (-not (Get-Command Connect-SPOService -ErrorAction SilentlyContinue)) {
		Write-Host "Installing the SharePoint Online Management Shell module"
		Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
		Install-Module -Name Microsoft.Online.SharePoint.PowerShell -AllowClobber -Force
		$ModVer = (Get-Command Connect-SPOService).Version
		If ($ModVer) {
			Write-Host "Exchange Online Management module version $ModVer has been installed."
		}
		Else {
			Write-Host "Exchange Online Management module failed to install."
			Break
		}
	}
 Else {
		If (-not $Quiet) {
			$Readhost = 'N'
			$Readhost = Read-Host "Do you want to check for module updates? This should be done periodically. n(y/N)"
		}
		Else { $Readhost = 'Y' }
		Switch ($ReadHost) {
	
			Y {
				$ModVer = (Get-Command Connect-SPOService).Version
				$AvailableModVer = (Find-Module Microsoft.Online.SharePoint.PowerShell -Repository PSGallery).Version
				If ($ModVer -ne $AvailableModVer) {
					Write-host "Microsoft.Online.SharePoint.PowerShell has an update from $ModVer to $AvailableModVer.nInstalling the update."
					Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
					Install-Module -Name Microsoft.Online.SharePoint.PowerShell -AllowClobber -Force
				}
				Else {
					Write-host "Microsoft.Online.SharePoint.PowerShell is already up to date at version $AvailableModVer."
				}
			}
			N { Write-Host "Skipping update check." }
			Default { Write-Host "Skipping update check." }
		}
	}

	If (-not $url) {
		Write-Host -ForegroundColor Yellow 'A Sharepoint URL is needed. To obtain the URL, login to https://admin.microsoft.com/Adminportal/Home#/alladmincenters as a global admin for the client. Then right-click on "SharePoint" and select "Copy URL".'
		$url = Read-Host "SharePoint Url"
	}

	If ($PSVersionTable.PSEdition -like "Desktop") {
		Connect-SPOService -Url $url

	}
 Else {
		Write-Host -ForegroundColor Green -BackgroundColor DarkRed "Warning! You are using a CORE edition of Powershell. You will need to authenticate via a browser window."
		Connect-SPOService -Url $url
	}

	If (-not $Quiet) {
		Write-Host -ForegroundColor White -BackgroundColor DarkRed @"
	Be sure to disconnect the remote PowerShell session when you're finished.
	If you close the Windows PowerShell window without disconnecting the session,
	you could use up all the remote PowerShell sessions available to you,
	and you'll need to wait for the sessions to expire.
	To disconnect the remote PowerShell session, run the following command.
	Disconnect-SPOService
"@
	}

	<#
	.SYNOPSIS
	Initiates an Office 365 SharePoint Online connection that is compatible with MFA.
	.LINK
	https://learn.microsoft.com/en-us/powershell/sharepoint/sharepoint-online/connect-sharepoint-online
	.EXAMPLE
	Connect-O365Sharepoint -url https://client-admin.sharepoint.com
	#>
	# New-SPOSite -Url https://pbwslaw.sharepoint.com/sites/ArchivedOneDrives -Owner "admin@pbwslaw.onmicrosoft.com" -Title "Archived User OneDrives" -StorageQuota 1048576 -Template "BDR#0"
}

Function Connect-O365SharepointPNP {
	param
	(
		[Parameter(Mandatory = $false)]
		[string]$url,

		[Parameter(Mandatory = $False)]
		[switch]$Quiet
	)
	If (-not (Get-Command Connect-PnPOnline -ErrorAction SilentlyContinue)) {
		Write-Host "Installing the SharePoint Online Management Shell module"
		Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
		Install-Module -Name PnP.PowerShell -AllowClobber -Force
		$ModVer = (Get-Command Connect-PnPOnline).Version
		If ($ModVer) {
			Write-Host "O365SharepointPNP module version $ModVer has been installed."
		}
		Else {
			Write-Host "O365SharepointPNP module failed to install."
			Break
		}
	}
 Else {
		If (-not $Quiet) {
			$Readhost = 'N'
			$Readhost = Read-Host "Do you want to check for module updates? This should be done periodically. n(y/N)"
		}
		Else { $Readhost = 'Y' }
		Switch ($ReadHost) {
			Y {
				$ModVer = (Get-Command Connect-PnPOnline).Version
				$AvailableModVer = (Find-Module PnP.PowerShell -Repository PSGallery).Version
				If ($ModVer -ne $AvailableModVer) {
					Write-host "PnP.PowerShell has an update from $ModVer to $AvailableModVer.nInstalling the update."
					Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
					Install-Module -Name PnP.PowerShell -AllowClobber -Force
				}
				Else {
					Write-host "PnP.PowerShell is already up to date at version $AvailableModVer."
				}
			}
			N { Write-Host "Skipping update check." }
			Default { Write-Host "Skipping update check." }
		}
	}

	If (-not $url) {
		Write-Host -ForegroundColor Yellow 'nA Sharepoint Site URL is needed.'
		$url = Read-Host "SharePoint Url"
	}

	If ($PSVersionTable.PSEdition -like "Desktop") {
		Connect-PnPOnline -Url $url -Interactive
	}
 Else {
		Write-Host -ForegroundColor Green -BackgroundColor DarkRed "Warning! You are using a CORE edition of Powershell. You will need to authenticate via a browser window."
		Connect-PnPOnline -Url $url -Interactive
	}

	If (-not $Quiet) {
		Write-Host -ForegroundColor White -BackgroundColor DarkRed @"
		Be sure to disconnect the remote PowerShell session when you're finished.
		If you close the Windows PowerShell window without disconnecting the session,
		you could use up all the remote PowerShell sessions available to you,
		and you'll need to wait for the sessions to expire.
		To disconnect the remote PowerShell session, run the following command.
		DisConnect-PnPOnline
"@
	}

	<#
		.SYNOPSIS
		Initiates an Office 365 SharePoint Online connection that is compatible with MFA.
		.LINK
		https://learn.microsoft.com/en-us/powershell/sharepoint/sharepoint-online/connect-sharepoint-online
		.EXAMPLE
		Connect-O365SharepointPnP -url https://client-admin.sharepoint.com
	#>
	# New-SPOSite -Url https://pbwslaw.sharepoint.com/sites/ArchivedOneDrives -Owner "admin@pbwslaw.onmicrosoft.com" -Title "Archived User OneDrives" -StorageQuota 1048576 -Template "BDR#0"
}

Function Connect-SophosConnect {
	param
	(
		[Parameter(Mandatory = $false)]
		[string]$ConnectionName,
		[Parameter(Mandatory = $false)]
		[string]$VPNuser,
		[Parameter(Mandatory = $false)]
		[string]$VPNpassword,
		[Parameter(Mandatory = $false)]
		[string]$OvpnFilePath
	)

	# Define possible paths for sccli.exe
	$possiblePaths = @(
		"${env:ProgramFiles(x86)}\Sophos\Connect\sccli.exe"
		"${env:ProgramFiles}\Sophos\Connect\sccli.exe"
		"${env:ProgramFiles(x86)}\Sophos\Sophos SSL VPN Client\sccli.exe"
		"${env:ProgramFiles}\Sophos\Sophos SSL VPN Client\sccli.exe"
	)

	# Find the first valid path
	$SCPath = $possiblePaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

	If (!$SCPath) {
		Write-Host "Sophos Connect is not installed or sccli.exe was not found." -ForegroundColor Red
		Write-Host "Run 'Install-SophosConnect' to install the client." -ForegroundColor Yellow
		return
	}

	# Handle .ovpn file import if provided
	If (![string]::IsNullOrWhiteSpace($OvpnFilePath)) {
		# Validate file exists
		If (!(Test-Path -Path $OvpnFilePath)) {
			Write-Host "Error: The specified .ovpn file does not exist: $OvpnFilePath" -ForegroundColor Red
			return
		}

		# Validate file extension
		If ([System.IO.Path]::GetExtension($OvpnFilePath) -ne ".ovpn") {
			Write-Host "Error: The specified file is not a .ovpn file: $OvpnFilePath" -ForegroundColor Red
			return
		}

		# If ConnectionName not provided, derive from filename
		If ([string]::IsNullOrWhiteSpace($ConnectionName)) {
			$ConnectionName = [System.IO.Path]::GetFileNameWithoutExtension($OvpnFilePath)
			Write-Host "Using connection name from filename: $ConnectionName" -ForegroundColor Cyan
		}

		Write-Host "Importing .ovpn configuration file: $OvpnFilePath" -ForegroundColor Cyan
		Write-Host "Connection name: $ConnectionName" -ForegroundColor Cyan

		# Import the .ovpn file
		Try {
			$importArgs = @("import", "-c", $ConnectionName, "-f", $OvpnFilePath)
			$result = & "$SCPath" $importArgs 2>&1

			If ($LASTEXITCODE -eq 0) {
				Write-Host "Successfully imported VPN configuration." -ForegroundColor Green
			}
			Else {
				Write-Host "Import completed with warnings or the connection may already exist." -ForegroundColor Yellow
				Write-Host "Result: $result" -ForegroundColor Yellow
			}
		}
		Catch {
			Write-Host "Error importing .ovpn file: $_" -ForegroundColor Red
			return
		}
	}

	# If no connection name provided, list available connections
	If ([string]::IsNullOrWhiteSpace($ConnectionName)) {
		Write-Host "Listing available Sophos Connect VPN connections:" -ForegroundColor Cyan
		& "$SCPath" list -d
		Write-Host ""
		$ConnectionName = Read-Host "Enter the connection name to connect to"
		If ([string]::IsNullOrWhiteSpace($ConnectionName)) {
			Write-Host "Connection name is required." -ForegroundColor Red
			return
		}
	}

	Write-Host "Initiating VPN connection to: $ConnectionName" -ForegroundColor Cyan

	# Build the enable command
	$enableArgs = @("enable", "-n", $ConnectionName)

	# Add username if provided
	If (![string]::IsNullOrWhiteSpace($VPNuser)) {
		$enableArgs += @("-u", $VPNuser)
	}

	# Add password if provided
	If (![string]::IsNullOrWhiteSpace($VPNpassword)) {
		$enableArgs += @("-p", $VPNpassword)
	}

	# Connect to VPN
	Try {
		& "$SCPath" $enableArgs
		Start-Sleep -Seconds 2
		Write-Host ""
		Get-SophosConnectStatus
	}
	Catch {
		Write-Host "Error connecting to VPN: $_" -ForegroundColor Red
	}

	Write-Host 'Try "Disconnect-SophosConnect" or "Get-SophosConnectStatus"' -ForegroundColor Yellow

	<#
	.SYNOPSIS
		Initiates an SSL VPN connection using Sophos Connect
	.PARAMETER ConnectionName
		The name of the Sophos Connect VPN connection to use. If not provided, will list available connections.
		When importing an .ovpn file, this will be the name assigned to the imported connection.
		If not provided with an .ovpn file, the filename will be used as the connection name.
	.PARAMETER VPNuser
		(Optional) The VPN username. If not provided, may prompt during connection.
	.PARAMETER VPNpassword
		(Optional) The VPN password. If not provided, may prompt during connection.
	.PARAMETER OvpnFilePath
		(Optional) Path to a .ovpn configuration file to import before connecting.
		If provided, the file will be imported and then a connection will be attempted.
	.EXAMPLE
		Connect-SophosConnect -ConnectionName "Company VPN"
		Connects to a VPN connection named "Company VPN", prompting for credentials if needed.
	.EXAMPLE
		Connect-SophosConnect -ConnectionName "Company VPN" -VPNuser "jdoe" -VPNpassword "MyP@ssw0rd"
		Connects to a VPN connection with specified credentials.
	.EXAMPLE
		Connect-SophosConnect
		Lists available VPN connections and prompts for selection.
	.EXAMPLE
		Connect-SophosConnect -OvpnFilePath "C:\VPN\client-vpn.ovpn"
		Imports the .ovpn file as a connection named "client-vpn" and connects to it.
	.EXAMPLE
		Connect-SophosConnect -OvpnFilePath "C:\VPN\client-vpn.ovpn" -ConnectionName "Company VPN" -VPNuser "jdoe" -VPNpassword "MyP@ssw0rd"
		Imports the .ovpn file as "Company VPN" and connects with specified credentials.
	.NOTES
		Sophos Connect uses sccli.exe for command-line operations.
		Connection profiles can be pre-configured or imported using .ovpn files.
		When importing an .ovpn file, if the connection name already exists, it may be overwritten or cause an error.
	#>
}

Function Connect-Wifi {
	<#
	.SYNOPSIS
		Connects to a WiFi network or stores the profile for automatic connection when the network is available.
	.DESCRIPTION
		Creates a Windows WLAN profile for the specified network with the given credentials and security settings.
		If the network is currently visible, attempts to connect immediately.
		If the network is not visible, the profile is stored so Windows will automatically connect when the network becomes available.
		This function supports WPA/WPA2/WPA3 Personal (PSK) networks. Enterprise (802.1X) networks are not supported.
	.PARAMETER NetworkSSID
		The SSID (name) of the WiFi network to connect to. This parameter is required.
	.PARAMETER NetworkPassword
		The password/passphrase for the WiFi network. Required for secured networks, optional for Open networks.
	.PARAMETER Authentication
		The authentication method. Valid values: WPA2PSK (default), WPA3SAE, WPAPSK, Open.
		- WPA2PSK: WPA2-Personal, the most common for home/business networks
		- WPA3SAE: WPA3-Personal, newer and more secure
		- WPAPSK: Legacy WPA-Personal (not recommended)
		- Open: No authentication (public networks)
	.PARAMETER Encryption
		The encryption type. Valid values: AES (default), TKIP, None.
		- AES: Required for WPA2/WPA3, recommended for all secured networks
		- TKIP: Legacy encryption for older WPA networks (not recommended)
		- None: No encryption (only valid with Open authentication)
	.EXAMPLE
		Connect-Wifi -NetworkSSID "MyHomeNetwork" -NetworkPassword "MySecurePassword123"
		Connects to "MyHomeNetwork" using WPA2-PSK with AES encryption (defaults).
	.EXAMPLE
		Connect-Wifi -NetworkSSID "OfficeWifi" -NetworkPassword "WorkPassword" -Authentication WPA3SAE
		Connects to "OfficeWifi" using WPA3-Personal authentication.
	.EXAMPLE
		Connect-Wifi -NetworkSSID "LegacyNetwork" -NetworkPassword "OldPassword" -Authentication WPAPSK -Encryption TKIP
		Connects to an older network using WPA-PSK with TKIP encryption.
	.EXAMPLE
		Connect-Wifi -NetworkSSID "CoffeeShopFreeWifi" -Authentication Open
		Connects to an open (unsecured) public WiFi network.
	.NOTES
		Requires administrative privileges to add WiFi profiles.
		The profile is configured for automatic connection when the network is in range.
	#>
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$NetworkSSID,

		[Parameter(Mandatory = $false)]
		[string]$NetworkPassword,

		[ValidateSet('Open', 'WPAPSK', 'WPA2PSK', 'WPA3SAE')]
		[Parameter(Mandatory = $false)]
		[string]$Authentication = 'WPA2PSK',

		[ValidateSet('AES', 'TKIP', 'None')]
		[Parameter(Mandatory = $false)]
		[string]$Encryption = 'AES'
	)

	# Validate password is provided for secured networks
	If ($Authentication -ne 'Open' -and [string]::IsNullOrEmpty($NetworkPassword)) {
		Write-Error "NetworkPassword is required for $Authentication authentication."
		return
	}

	# Validate encryption compatibility with authentication
	If ($Authentication -eq 'WPA3SAE' -and $Encryption -ne 'AES') {
		Write-Warning "WPA3 requires AES encryption. Overriding encryption setting to AES."
		$Encryption = 'AES'
	}
	If ($Authentication -eq 'WPA2PSK' -and $Encryption -eq 'TKIP') {
		Write-Warning "WPA2 with TKIP is deprecated and less secure. Consider using AES encryption."
	}
	If ($Authentication -eq 'WPAPSK' -and $Encryption -eq 'AES') {
		Write-Warning "WPA with AES is an unusual combination. Standard WPA uses TKIP. Proceeding anyway."
	}
	If ($Authentication -eq 'Open') {
		If (-not [string]::IsNullOrEmpty($NetworkPassword)) {
			Write-Warning "Password is ignored for Open authentication."
		}
		If ($Encryption -ne 'None') {
			Write-Warning "Open authentication uses no encryption. Setting encryption to None."
			$Encryption = 'None'
		}
	}

	# Escape XML special characters in SSID and password to prevent malformed XML
	$XmlEscapedSSID = [System.Security.SecurityElement]::Escape($NetworkSSID)
	$XmlEscapedPassword = if ($NetworkPassword) { [System.Security.SecurityElement]::Escape($NetworkPassword) } else { "" }

	# Build the security section based on authentication type
	If ($Authentication -eq 'Open') {
		$SecurityXml = @"
		<security>
			<authEncryption>
				<authentication>open</authentication>
				<encryption>none</encryption>
				<useOneX>false</useOneX>
			</authEncryption>
		</security>
"@
	} Else {
		$SecurityXml = @"
		<security>
			<authEncryption>
				<authentication>$Authentication</authentication>
				<encryption>$Encryption</encryption>
				<useOneX>false</useOneX>
			</authEncryption>
			<sharedKey>
				<keyType>passPhrase</keyType>
				<protected>false</protected>
				<keyMaterial>$XmlEscapedPassword</keyMaterial>
			</sharedKey>
		</security>
"@
	}

	# Create the WiFi profile XML with auto-connect enabled
	$WirelessProfile = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>$XmlEscapedSSID</name>
	<SSIDConfig>
		<SSID>
			<name>$XmlEscapedSSID</name>
		</SSID>
	</SSIDConfig>
	<connectionType>ESS</connectionType>
	<connectionMode>auto</connectionMode>
	<MSM>
$SecurityXml
	</MSM>
</WLANProfile>
"@

	# Create a temporary XML file for the profile
	$random = Get-Random -Minimum 1111 -Maximum 99999999
	$tempProfileXML = Join-Path -Path $env:TEMP -ChildPath "tempProfile$random.xml"

	Try {
		# Write the profile XML to the temp file using UTF-8 without BOM for netsh compatibility
		# PowerShell 5.1's -Encoding UTF8 includes BOM which can cause issues
		$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
		[System.IO.File]::WriteAllText($tempProfileXML, $WirelessProfile, $Utf8NoBom)

		# Add the WiFi profile using netsh (run synchronously to ensure completion)
		# Use user=all to make profile available to all users on this computer
		Write-Host "Adding WiFi profile for SSID: $NetworkSSID"
		$addResult = & netsh wlan add profile filename="$tempProfileXML" user=all 2>&1
		$addResultString = $addResult | Out-String

		# Check both exit code and output for errors (netsh exit codes can be unreliable)
		If ($LASTEXITCODE -ne 0 -or $addResultString -match "is not valid|error|failed") {
			Write-Error "Failed to add WiFi profile: $addResultString"
			return
		}
		Write-Host "WiFi profile added successfully." -ForegroundColor Green

		# Check if the network is currently visible
		$WifiNetworks = & netsh wlan show networks 2>&1
		If ($WifiNetworks -match [regex]::Escape($NetworkSSID)) {
			Write-Host "Found SSID: $NetworkSSID - Attempting to connect..."

			$connectResult = & netsh wlan connect name="$NetworkSSID" 2>&1
			$connectResultString = $connectResult | Out-String

			# Check both exit code and output for errors
			If ($LASTEXITCODE -ne 0 -or $connectResultString -match "error|failed") {
				Write-Error "Failed to connect to WiFi network: $connectResultString"
				return
			}

			# Wait for connection to establish
			Write-Host "Waiting for connection to establish..."
			Start-Sleep -Seconds 5

			# Verify connection status
			$interfaceStatus = & netsh wlan show interfaces 2>&1
			$escapedSSID = [regex]::Escape($NetworkSSID)
			If ($interfaceStatus -match "State\s*:\s*connected" -and $interfaceStatus -match $escapedSSID) {
				Write-Host "Successfully connected to $NetworkSSID" -ForegroundColor Green
			} Else {
				Write-Warning "Connection command sent, but connection state is uncertain. Check your network status."
			}

			# Display interface information
			& netsh interface show interface
		} Else {
			Write-Host "SSID '$NetworkSSID' is not currently visible." -ForegroundColor Yellow
			Write-Host "The WiFi profile has been stored. Windows will automatically connect when the network is in range." -ForegroundColor Cyan
		}
	}
	Catch {
		Write-Error "An error occurred: $_"
	}
	Finally {
		# Clean up the temporary XML file
		If (Test-Path -Path $tempProfileXML) {
			Remove-Item -Path $tempProfileXML -Force -ErrorAction SilentlyContinue
		}
	}
}

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDBF83CNFNFmhgr
# RDnw/5WxhDuqWC0BhgQbx1dmT1sOEaCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IPgfEtKSC39lSgHOJ+kBV+GQtrgtVqZs8m7GweDxEuhKMA0GCSqGSIb3DQEBAQUA
# BIICAHHoKEUb3nH2fqsc8EcBWxmw/ki7DSHDrDWElwCGaoIexN9tf2qVfPEcJUUC
# drHj3ueIQatWzPbMgleQC2qLBqxqQm/paKOXuKXvqWsoXZ64YlMXxFxdlSwxLLAI
# pqGyvGciUtvTo/GGPI9RYFgZ/F1Rj8dK45LCTa+KzAdiGBe53kyHb2yC/5FhbmFM
# hhVNYY+d5LPq4pGwugUw2yZnXOebnBcvvPCmm9cmORpVao8ds7P68oHwnv83oINH
# BXXL/ndzo4AxmrsmfPq0GU0IrZxyJGjK170r/ndvmW6XTjaYz4s1I62ge7dXAPOi
# QoCIeIgyXnRLHksDx447/Kf+LLlmCel71y4aJHQT2oNCvcAg8p3KBQAjLEDvSOyh
# 5isU/xdmv5Y3U1vcEjKh+M+LOfoyeh3SXJZVKnB/bAcCSFIOW6PAcsMDWouBC1A3
# rcbudDvjbKW+UJEBzECuZDe9xdUqmL6yF9cP2oo+ZwmPTvLVR4E48S5s2Jb3CMED
# c0AQyFKX080N16v6+KTcp58kpk6uzF4j7ZPKtMVcOk0kh38BJDrb0h5hW0J9/BKP
# MsoUy/W16/535kFS5WzT/F0En1WkxXxe8fCU8Q/evFYiOuG3S9nX8YaLuSnB9FBd
# 42XSMv3OkLUNoShP01Me1utr4VSaXfnZU102Ft6TSvq7gRsBoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDQyMjAzMTMwMlowLwYJKoZIhvcNAQkEMSIEIBsA+fb9
# gBLXLflfWzBZr1cFVK4sqzGMEWt1SPBgVojYMA0GCSqGSIb3DQEBAQUABIICAEXS
# sDJ8JoZBGdZnVSzz22yUfH2nbKzypY0FGJKAlNPTywzc9rIUAKGlxVKTCE+eoebV
# MQCCjH5xqH+ALitbHEBr0JSdWU8dAl2v2RZPYp5UilOc79tSGEMxuIhetFaoFGCR
# G/sBjdSPjrJmx6KylcmvdBzquza3FGPP0/uCiUYi58ORNsJ0bvNgTck5I2j7fwUb
# 9Jtn1PYacfcZseFYogi8ZTuw/9X/LZ2tZ9gEwBHpy+FCDb5gGLtLTuT60CRmFAWD
# BdRj+iFVoBYcNn9BtEsu6LKprLp+nfFaYMrzimMc/MpYsWgMlCaxHXKwsed4uvHT
# qWHOx8jzzc0D2XufWTDbJL6J4ChUsEZzJUHv6aSy0IP3ofj0lCitx5TkTkBgoroa
# H9jM2swk2GiwJevbRUrqsYso3rV9yfb05E1jeCDYTFypvDfA96aKNs+3v2QujS8z
# osUaRAh5ODSHSpAIKq/oWc9V8LiZ19kxnW/1pt9uxQK67OKXpTyX1KLhmLXg8NOM
# UKEvjjHDACbT86RDQnUTn+UzwmaUyJqT2XmqG1lf/44b5K3E8LVXjObbVzxC1k1I
# fPystaZcpm9ZDYvXinTe+vphnWXC8dTZpQvHal1zHM681PQtroR96pObQlYMEVxu
# GB9P65+HnOBu7lfABVyF/jB9heCtkwfHvBTSIaaZ
# SIG # End signature block
