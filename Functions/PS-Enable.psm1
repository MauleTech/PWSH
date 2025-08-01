Function Enable-DellSecureBoot {
	$Manufact = (Get-CimInstance -Class Win32_ComputerSystem -ErrorAction SilentlyContinue).Manufacturer
	If ( $Manufact -match "Dell" -or $Manufact -match "Alienware") {
		If ($env:firmware_type -eq 'UEFI') {
			$AllowSecureBoot = $True
		} Else {
			# Redirect error stream to success stream to also capture any errors
			Write-Host "Legacy boot detected. Checking if we can convert to UEFI."
			$MBRVAL = MBR2GPT.EXE /allowfullos /validate 2>&1

			# Check if any error records exist and capture these in variable $errors
			If ( $($MBRVAL | Select-String "Failed") ) {
				Write-Host "We are unable to convert to UEFI, not proceeding with Secure boot since it'll break boot."
				$AllowSecureBoot = $False
			} Else {
				Write-Host "Validation passed. Attempting to convert to UEFI."
				$MBRCONVERT = MBR2GPT.EXE /allowfullos /convert 2>&1

				# Check if any error records exist and capture these in variable $errors
				If ( $($MBRCONVERT | Select-String "Conversion Failed") ) {
					Write-Host "Convertion to UEFI failed, not proceeding with Secure boot since it'll break boot."
					$AllowSecureBoot = $False
				} Else {
					"Convertion to UEFI succeeded, proceeding with Secure boot."
					$AllowSecureBoot = $True
				}
			}
		}
		If (-not (Get-Module -Name DellBIOSProvider -ErrorAction SilentlyContinue) ) {
			Import-Module PowerShellGet -Force
			Install-Module DellBIOSProvider -Force -ErrorAction SilentlyContinue
			Import-Module DellBIOSProvider -Force
		}
		If ($AllowSecureBoot -eq $True) {

		# Get the current Secure Boot setting
			$SecureBootSetting = Get-Item -Path DellSmbios:\SecureBoot\SecureBoot -ErrorAction SilentlyContinue
			If ($SecureBootSetting) {
				if ($SecureBootSetting.CurrentValue -eq "Disabled") {
					Write-Output "Secure Boot is currently disabled. Enabling it now..."
					
					# Enable Secure Boot
					Set-Item -Path DellSmbios:\SecureBoot\SecureBoot -Value Enabled -ErrorAction Stop
					# Confirm the change
					$SecureBootSetting = Get-Item -Path DellSmbios:\SecureBoot\SecureBoot -ErrorAction SilentlyContinue
					$SecureBootSetting
					if ($SecureBootSetting.CurrentValue -eq "Enabled") {
						Write-Output "Secure Boot has been successfully enabled."
					} else {
						Write-Output "Failed to enable Secure Boot."
					}
				} else {
					Write-Output "Secure Boot is already enabled."
				}
			} Else {
				Write-Output "Secure Boot is not able to be set via powershell on this computer."
			}
		} Else {
			Write-Host "Ensuring Secure Boot is disabled."
			Set-Item -Path DellSmbios:\SecureBoot\SecureBoot -Value Disabled -ErrorAction SilentlyContinue -Verbose
			Set-Item -Path DellSmbios:\AdvancedBootOptions\LegacyOrom -Value Enabled -ErrorAction SilentlyContinue -Verbose
			Set-Item -Path DellSmbios:\BootSequence\BootList -Value 'Legacy' -ErrorAction SilentlyContinue -Verbose
		}
	} Else { Write-Host "This is not a Dell Computer" }
}

# Function to check and enable Wake Up
Function Enable-DellWakeUpInMorning {
	<#
		.SYNOPSIS
			Sets Dell Desktop Computers to wake up every morning at 5am. Allows for remote workers and maintenance.
	#>
	$GCI = Get-ComputerInfo -Property BiosManufacturer,CsPCSystemType
	If (($GCI.BiosManufacturer -Match "Dell") -And ($GCI.CsPCSystemType -in "Desktop", "Workstation")){
		If (-not (Get-Module -Name DellBIOSProvider -ErrorAction SilentlyContinue) ) {
			Install-Module DellBIOSProvider -Force
			Import-Module DellBIOSProvider -Force
		}
		# Get the current Wake Up setting
		$WakeUpSetting = Get-Item -Path DellSmbios:\PowerManagement\AutoOn -ErrorAction SilentlyContinue
		If ($WakeUpSetting) {
			if ($WakeUpSetting.CurrentValue -ne "Everyday") {
				Write-Output "Wake Up is currently disabled. Enabling it now..."
				
				# Enable Wake Up
				Set-Item -Path DellSmbios:\PowerManagement\AutoOn -Value "Everyday" -ErrorAction Stop
				Set-Item -Path DellSmbios:\PowerManagement\AutoOnHr -Value "5" -ErrorAction Stop
				# Confirm the change
				$WakeUpSetting = @(Get-Item -Path DellSmbios:\PowerManagement\AutoOn -ErrorAction SilentlyContinue;Get-Item -Path DellSmbios:\PowerManagement\AutoOnHr -ErrorAction SilentlyContinue)
				$WakeUpSetting
				if ($WakeUpSetting.CurrentValue -eq "Everyday") {
					Write-Output "Wake Up has been successfully enabled."
				} else {
					Write-Output "Failed to enable Wake Up."
				}
			} else {
				Write-Output "Wake Up is already enabled."
			}
		} Else {
			Write-Output "Wake Up is not able to be set via powershell on this computer."
		}
	} Else { Write-Host "This is not a Dell Desktop Computer" }
}

Function Enable-O365AuditLog {
	<#
		.SYNOPSIS
			Sets auditig on all mailboxes in the organization as well as sets the default setting.
	
		.LINK
			https://docs.microsoft.com/en-us/microsoft-365/compliance/enable-mailbox-auditing
	
		.LINK
			https://support.microsoft.com/en-us/help/4026501/office-auditing-in-office-365-for-admins
	#>
		If (Get-Command Get-Mailbox -ErrorAction SilentlyContinue){
			Write-Host "Enabling Auditing for all existing mailboxes"
			Get-Mailbox -ResultSize Unlimited -Filter {RecipientTypeDetails -eq "UserMailbox"} | Set-Mailbox -AuditEnabled $true -Verbose
			Write-Host "Enabling Auditing for the organization as a whole"
			Set-OrganizationConfig -AuditDisabled $False
			Write-Host "Checking the orginazation config. If auditing is enabled, this setting should show as 'False'"
			Get-OrganizationConfig | Format-List AuditDisabled
		} Else {
			Write-Host "You are not connected to an exchange server. Try the command 'Connect-O365Exchange'"
		}
	}
	
	Function Enable-Onedrive {
		#Enables usage of OneDrive local GP - Computer Config\Admin Templates\Windows Components\OneDrive    
		Reg Add    "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /T REG_DWORD /V "DisableFileSyncNGSC" /D 0 /F
		Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /T REG_DWORD /V "DisableFileSync" /D 0 /F
		#Adds OneDrive to File Explorer
		Reg Add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /T REG_DWORD /V "System.IsPinnedToNameSpaceTree" /D 1 /F
		Reg Add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /T REG_DWORD /V "System.IsPinnedToNameSpaceTree" /D 1 /F
		irm raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt | iex
		Install-Choco
		choco upgrade onedrive --exact -y
	}
	
	Function Enable-Sleep {
		If (Get-Process -Name "DontSleep_x64_p") {
			Write-Host "Resuming power management plan"
			Stop-Process -Name "DontSleep_x64_p" -Force
		} Else {
			Write-Host "Disable-Sleep wasn't running. Did you run 'Disable-Sleep'?"
		}
	}
	
	Function Enable-SSL {
		Write-Host "Enabling SSL"
		try {
		# Set TLS 1.2 (3072), then TLS 1.1 (768), then TLS 1.0 (192)
		# Use integers because the enumeration values for TLS 1.2 and TLS 1.1 won't
		# exist in .NET 4.0, even though they are addressable if .NET 4.5+ is
		# installed (.NET 4.5 is an in-place upgrade).
		[System.Net.ServicePointManager]::SecurityProtocol = 3072 -bor 768 -bor 192
		} catch {
		Write-Output 'Unable to set PowerShell to use TLS 1.2 and TLS 1.1 due to old .NET Framework installed. If you see underlying connection closed or trust errors, you may need to upgrade to .NET Framework 4.5+ and PowerShell v3+.'
		}
	}

	Function Enable-WakeOnLAN {
		If (-not (Get-Module -Name DellBIOSProvider -ErrorAction SilentlyContinue) ) {
			Try {
			Install-Module DellBIOSProvider -Force -ErrorAction Stop
			Import-Module DellBIOSProvider -Force -ErrorAction Stop
			} Catch {
				Write-Output "WakeOnLAN is not able to be set via powershell on this computer."
			}
		}
		# Get the current Wake on LAN setting
		$wolSetting = Get-Item -Path DellSmbios:\PowerManagement\WakeOnLan -ErrorAction SilentlyContinue
		If ($wolSetting) {
			if ($wolSetting.CurrentValue -eq "Disabled") {
				Write-Output "Wake on LAN is currently disabled. Enabling it now..."
				
				# Enable Wake on LAN
				Try {
					Set-Item -Path DellSmbios:\PowerManagement\WakeOnLan -Value LanWlan -ErrorAction Stop
				} Catch {
					Set-Item -Path DellSmbios:\PowerManagement\WakeOnLan -Value LanOnly -ErrorAction Stop
				}
				# Confirm the change
				$wolSetting = Get-Item -Path DellSmbios:\PowerManagement\WakeOnLan -ErrorAction SilentlyContinue
				$wolSetting
				if ($wolSetting.CurrentValue -Match "Lan") {
					Write-Output "Wake on LAN has been successfully enabled."
				} else {
					Write-Output "Failed to enable Wake on LAN."
				}
			} else {
				Write-Output "Wake on LAN is already enabled."
			}
		} Else {
			Write-Output "WakeOnLAN is not able to be set via powershell on this computer."
		}
	}
	
	
	# SIG # Begin signature block
	# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
	# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
	# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUnJxoH1oATrf50NZF0VhY/fFS
	# 2XKgggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
	# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUx99M
	# MTq2hTASVpsXv0g6uULY9SQwDQYJKoZIhvcNAQEBBQAEggEAStQZRu5rGnu7SMYm
	# Cr+Yi/oUXihrhayjr8RUzZMYi+Y1S7gutVAe3xkAxzdDYAInm/b8dIjArXfmFtRQ
	# ra+z8SWS31+CKL/DRRYXvk2kh0dB8NwpzLlddi8GXN1Mmo60S3LPANS5EV3UEPgf
	# yXteDQJjYLH4K1I691ONtnGsRUXC+/0+GoXxoDxEB+bD7bn7KWvKrkHAQMplocIb
	# gjffLizCdsRkEKahiKYwDr1T9nffp5l/xLvHpdPJLgoQ+OwcKN3o05Z38/qKAUSP
	# +Qbr7OG841sMkehTVEvM6f5T/W3oZbDs8bKV/J4iWrlYIt/eQznynrHXF6SWMrqm
	# tpfRHg==
	# SIG # End signature block
	