Function Connect-O365AzureAD {
	If (-not (Get-Command Connect-AzureAD -ErrorAction SilentlyContinue)) {
		Write-Host "Installing the Azure AD module"
		Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
		Install-Module -Name AzureAD -AllowClobber -Force
		$ModVer = (Get-Command Connect-AzureAD).Version
		If ($ModVer) {
			Write-Host "Azure AD module version $ModVer has been installed."
		}
		Else {
			Write-Host "Azure AD module failed to install."
			Break
		}
	}
 Else {
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
				}
				Else {
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

	<#
	.SYNOPSIS
		Initiates an Office 365 Azure AD connection.

	.LINK
		https://docs.microsoft.com/en-us/microsoft-365/enterprise/connect-to-microsoft-365-powershell?view=o365-worldwide

	.EXAMPLE
		Connect-O365AzureAD
		Yup, that's it!
#>
}

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

Function Connect-Wifi {
	param
	(
		[Parameter(Mandatory = $False)]
		[string]$NetworkSSID,

		[Parameter(Mandatory = $true)]
		[string]$NetworkPassword,

		[ValidateSet('WEP', 'WPA', 'WPA2', 'WPA2PSK')]
		[Parameter(Mandatory = $False)]
		[string]$Authentication = 'WPA2PSK',

		[ValidateSet('AES', 'TKIP')]
		[Parameter(Mandatory = $False)]
		[string]$Encryption = 'AES'
	)

	# Create the WiFi profile, set the profile to auto connect
	$WirelessProfile = @'
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>{0}</name>
	<SSIDConfig>
		<SSID>
			<name>{0}</name>
		</SSID>
	</SSIDConfig>
	<connectionType>ESS</connectionType>
	<connectionMode>auto</connectionMode>
	<MSM>
		<security>
			<authEncryption>
				<authentication>{2}</authentication>
				<encryption>{3}</encryption>
				<useOneX>false</useOneX>
			</authEncryption>
			<sharedKey>
				<keyType>passPhrase</keyType>
				<protected>false</protected>
				<keyMaterial>{1}</keyMaterial>
			</sharedKey>
		</security>
	</MSM>
</WLANProfile>
'@ -f $NetworkSSID, $NetworkPassword, $Authentication, $Encryption

	# Create the XML file locally
	$random = Get-Random -Minimum 1111 -Maximum 99999999
	$tempProfileXML = "$env:TEMP\tempProfile$random.xml"
	$WirelessProfile | Out-File $tempProfileXML

	# Add the WiFi profile and connect
	Start-Process netsh ('wlan add profile filename={0}' -f $tempProfileXML)

	# Connect to the WiFi network - only if you need to
	$WifiNetworks = (netsh wlan show network)
	$NetworkSSIDSearch = '*' + $NetworkSSID + '*'
	If ($WifiNetworks -like $NetworkSSIDSearch) {
		Try {
			Write-Host "Found SSID: $NetworkSSID `nAttempting to connect"
			Start-Process netsh ('wlan connect name="{0}"' -f $NetworkSSID)
			Start-Sleep 5
			netsh interface show interface
		}
		Catch {
			Remove-Item -Force $tempProfileXML
		}
	}
 Else {
		Write-Host "Did not find SSID: $NetworkSSID `nConnection profile stored for later use."
	}
	Remove-Item -Force $tempProfileXML
}


# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUvHm3HlGmgiKu9ZgHzwKmzNp3
# G96gggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUk2F4
# 0vSKGe07k7mSKaBWfblKtPUwDQYJKoZIhvcNAQEBBQAEggEABH51hYjn8RZJH/co
# ggPHn53shZF9f7N5qErh+VSUZoEj62hCzVTXzIGsA3nQlfyyxNM6rNAAdXwEZULd
# FvGvKTUXf/TSMghJqX0kqDM4C7vBfGC989TTWH7SaoV1bLejNB2ZQOJ3qzov0i50
# qRAHiW3E8aHIzd27jcwFsJ+yrOkWCJkLGxHBkI8HQTaNk15twsvktXs1ZW1dpIJy
# CBktm1dtoPeBx8HtBVts/EEdbfgjydUO7XOygEB8yWAWUF+QHUwZDoXCsEWqDF72
# DakeY6tbU/UYsbWWYBz1P1sODweXTR/d5VmNiyjP5w64koZXRKxs3hwqiYPKwrRZ
# 9X/s2Q==
# SIG # End signature block
