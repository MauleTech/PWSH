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

Function Enable-RDP {
	<#
		.SYNOPSIS
			Enables Remote Desktop Protocol (RDP) on a computer, configures firewall rules, resolves common issues, and lists users/groups with RDP access.

		.DESCRIPTION
			This function performs the following actions:
			- Enables Remote Desktop connections via registry
			- Configures Network Level Authentication (NLA)
			- Enables and starts required RDP services
			- Configures Windows Firewall rules for RDP
			- Lists all users and groups with Remote Desktop access
			- Proactively resolves common issues that prevent RDP from working

		.EXAMPLE
			Enable-RDP

		.NOTES
			Requires Administrator privileges
	#>

	# Check for Administrator privileges
	$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	If (-not $IsAdmin) {
		Write-Warning "This function requires Administrator privileges. Please run as Administrator."
		return
	}

	Write-Host "=== Enabling Remote Desktop Protocol ===" -ForegroundColor Cyan

	# 1. Enable Remote Desktop via Registry
	Write-Host "`nStep 1: Configuring Remote Desktop registry settings..." -ForegroundColor Yellow
	Try {
		$RDPPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
		$CurrentValue = Get-ItemProperty -Path $RDPPath -Name "fDenyTSConnections" -ErrorAction SilentlyContinue

		If ($CurrentValue.fDenyTSConnections -eq 0) {
			Write-Host "  [OK] Remote Desktop is already enabled in registry" -ForegroundColor Green
		} Else {
			Set-ItemProperty -Path $RDPPath -Name "fDenyTSConnections" -Value 0 -ErrorAction Stop
			Write-Host "  [SUCCESS] Remote Desktop enabled in registry" -ForegroundColor Green
		}

		# Enable Network Level Authentication (more secure)
		$NLAPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
		$NLAValue = Get-ItemProperty -Path $NLAPath -Name "UserAuthentication" -ErrorAction SilentlyContinue

		If ($NLAValue.UserAuthentication -eq 1) {
			Write-Host "  [OK] Network Level Authentication is already enabled" -ForegroundColor Green
		} Else {
			Set-ItemProperty -Path $NLAPath -Name "UserAuthentication" -Value 1 -ErrorAction Stop
			Write-Host "  [SUCCESS] Network Level Authentication enabled" -ForegroundColor Green
		}
	} Catch {
		Write-Warning "  [ERROR] Failed to configure registry: $_"
	}

	# 2. Enable and Start RDP Services
	Write-Host "`nStep 2: Configuring Remote Desktop services..." -ForegroundColor Yellow
	$Services = @("TermService", "SessionEnv", "UmRdpService")

	ForEach ($ServiceName in $Services) {
		Try {
			$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
			If ($Service) {
				# Set service to Automatic startup
				If ($Service.StartType -ne "Automatic") {
					Set-Service -Name $ServiceName -StartupType Automatic -ErrorAction Stop
					Write-Host "  [SUCCESS] $ServiceName set to Automatic startup" -ForegroundColor Green
				} Else {
					Write-Host "  [OK] $ServiceName already set to Automatic" -ForegroundColor Green
				}

				# Start service if not running
				If ($Service.Status -ne "Running") {
					Start-Service -Name $ServiceName -ErrorAction Stop
					Write-Host "  [SUCCESS] $ServiceName started" -ForegroundColor Green
				} Else {
					Write-Host "  [OK] $ServiceName is already running" -ForegroundColor Green
				}
			}
		} Catch {
			Write-Warning "  [WARNING] Issue with service $ServiceName : $_"
		}
	}

	# 3. Configure Windows Firewall Rules
	Write-Host "`nStep 3: Configuring Windows Firewall rules..." -ForegroundColor Yellow
	Try {
		# Enable predefined Remote Desktop firewall rules
		$FirewallRules = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue

		If ($FirewallRules) {
			ForEach ($Rule in $FirewallRules) {
				If ($Rule.Enabled -eq $false) {
					Enable-NetFirewallRule -Name $Rule.Name -ErrorAction Stop
					Write-Host "  [SUCCESS] Enabled firewall rule: $($Rule.DisplayName)" -ForegroundColor Green
				} Else {
					Write-Host "  [OK] Firewall rule already enabled: $($Rule.DisplayName)" -ForegroundColor Green
				}
			}
		} Else {
			# Fallback: Create firewall rules manually
			Write-Host "  [INFO] Predefined rules not found, creating custom rules..." -ForegroundColor Cyan

			# TCP Rule
			$TCPRule = Get-NetFirewallRule -Name "RemoteDesktop-UserMode-In-TCP" -ErrorAction SilentlyContinue
			If (-not $TCPRule) {
				New-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)" `
					-Name "RemoteDesktop-UserMode-In-TCP" `
					-Protocol TCP `
					-LocalPort 3389 `
					-Direction Inbound `
					-Action Allow `
					-Enabled True `
					-ErrorAction Stop | Out-Null
				Write-Host "  [SUCCESS] Created TCP firewall rule for RDP" -ForegroundColor Green
			} Else {
				Enable-NetFirewallRule -Name "RemoteDesktop-UserMode-In-TCP" -ErrorAction Stop
				Write-Host "  [SUCCESS] Enabled existing TCP firewall rule" -ForegroundColor Green
			}

			# UDP Rule
			$UDPRule = Get-NetFirewallRule -Name "RemoteDesktop-UserMode-In-UDP" -ErrorAction SilentlyContinue
			If (-not $UDPRule) {
				New-NetFirewallRule -DisplayName "Remote Desktop - User Mode (UDP-In)" `
					-Name "RemoteDesktop-UserMode-In-UDP" `
					-Protocol UDP `
					-LocalPort 3389 `
					-Direction Inbound `
					-Action Allow `
					-Enabled True `
					-ErrorAction Stop | Out-Null
				Write-Host "  [SUCCESS] Created UDP firewall rule for RDP" -ForegroundColor Green
			} Else {
				Enable-NetFirewallRule -Name "RemoteDesktop-UserMode-In-UDP" -ErrorAction Stop
				Write-Host "  [SUCCESS] Enabled existing UDP firewall rule" -ForegroundColor Green
			}
		}
	} Catch {
		Write-Warning "  [ERROR] Failed to configure firewall rules: $_"
	}

	# 4. Check RDP Port Availability
	Write-Host "`nStep 4: Checking RDP port availability..." -ForegroundColor Yellow
	Try {
		$RDPPort = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -ErrorAction SilentlyContinue
		$Port = $RDPPort.PortNumber
		If (-not $Port) { $Port = 3389 }
		Write-Host "  [INFO] RDP is configured to use port: $Port" -ForegroundColor Cyan

		# Check if port is listening
		$Listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
		If ($Listener) {
			Write-Host "  [OK] Port $Port is listening for connections" -ForegroundColor Green
		} Else {
			Write-Warning "  [WARNING] Port $Port is not listening yet. Services may still be starting..."
		}
	} Catch {
		Write-Warning "  [WARNING] Could not verify port status: $_"
	}

	# 5. List Users and Groups with RDP Access
	Write-Host "`nStep 5: Users and Groups with Remote Desktop Access" -ForegroundColor Yellow
	Write-Host "========================================" -ForegroundColor Cyan

	Try {
		# Get Remote Desktop Users group members
		$RDPUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue

		Write-Host "`n  Remote Desktop Users Group Members:" -ForegroundColor White
		If ($RDPUsers) {
			ForEach ($User in $RDPUsers) {
				Write-Host "    - $($User.Name) ($($User.ObjectClass))" -ForegroundColor Green
			}
		} Else {
			Write-Host "    - No users explicitly added to Remote Desktop Users group" -ForegroundColor Yellow
		}

		# Get Administrators group members (they automatically have RDP access)
		Write-Host "`n  Administrators Group Members (automatic RDP access):" -ForegroundColor White
		$Admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
		If ($Admins) {
			ForEach ($Admin in $Admins) {
				Write-Host "    - $($Admin.Name) ($($Admin.ObjectClass))" -ForegroundColor Green
			}
		}
	} Catch {
		Write-Warning "  [ERROR] Failed to enumerate user groups: $_"
	}

	# 6. Final Summary
	Write-Host "`n========================================" -ForegroundColor Cyan
	Write-Host "=== Remote Desktop Configuration Complete ===" -ForegroundColor Green
	Write-Host "`nTo add users to Remote Desktop access, run:" -ForegroundColor Cyan
	Write-Host "  Add-LocalGroupMember -Group 'Remote Desktop Users' -Member 'DOMAIN\Username'" -ForegroundColor White
	Write-Host "`nTo connect to this computer remotely, use:" -ForegroundColor Cyan
	Write-Host "  mstsc /v:$($env:COMPUTERNAME)" -ForegroundColor White
	Write-Host "========================================`n" -ForegroundColor Cyan
}

Function Enable-RemoteManagement {
	<#
		.SYNOPSIS
			Enables remote management capabilities on a Windows computer including Remote Registry, Admin Shares, PowerShell Remoting, WMI, PSExec support, and PRTG monitoring access. Also calls Enable-RDP.

		.DESCRIPTION
			This function configures a Windows computer to accept common remote management protocols:
			- Remote Registry service (started and set to Automatic)
			- Administrative Shares (ADMIN$, C$) via registry and Server service restart
			- PowerShell Remoting (WinRM via Enable-PSRemoting)
			- WMI firewall rules for remote management
			- File and Printer Sharing firewall rules (required for PSExec)
			- ICMP (ping) firewall rules for PRTG and general monitoring
			- Remote Desktop Protocol via Enable-RDP

		.EXAMPLE
			Enable-RemoteManagement

		.NOTES
			Requires Administrator privileges.
			Should be run locally on the target machine.
	#>

	# Check for Administrator privileges
	$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	If (-not $IsAdmin) {
		Write-Warning "This function requires Administrator privileges. Please run as Administrator."
		return
	}

	Write-Host "=== Enabling Remote Management ===" -ForegroundColor Cyan

	# 1. Enable Remote Registry
	Write-Host "`nStep 1: Enabling Remote Registry service..." -ForegroundColor Yellow
	Try {
		$RemoteRegistry = Get-Service -Name "RemoteRegistry" -ErrorAction Stop
		If ($RemoteRegistry.StartType -ne "Automatic") {
			Set-Service -Name "RemoteRegistry" -StartupType Automatic -ErrorAction Stop
			Write-Host "  [SUCCESS] RemoteRegistry set to Automatic startup" -ForegroundColor Green
		} Else {
			Write-Host "  [OK] RemoteRegistry already set to Automatic" -ForegroundColor Green
		}
		If ($RemoteRegistry.Status -ne "Running") {
			Start-Service -Name "RemoteRegistry" -ErrorAction Stop
			Write-Host "  [SUCCESS] RemoteRegistry service started" -ForegroundColor Green
		} Else {
			Write-Host "  [OK] RemoteRegistry service is already running" -ForegroundColor Green
		}
	} Catch {
		Write-Warning "  [ERROR] Failed to configure Remote Registry: $_"
	}

	# 2. Enable Administrative Shares (ADMIN$, C$)
	Write-Host "`nStep 2: Enabling Administrative Shares..." -ForegroundColor Yellow
	Try {
		$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
		$ShareSettingChanged = $false

		$CurrentValue = Get-ItemProperty -Path $RegPath -Name "AutoShareWks" -ErrorAction SilentlyContinue

		# AutoShareWks = 1 enables admin shares on workstations, absence of the value also means enabled (default)
		If ($CurrentValue.AutoShareWks -eq 0) {
			Set-ItemProperty -Path $RegPath -Name "AutoShareWks" -Value 1 -Type DWord -ErrorAction Stop
			Write-Host "  [SUCCESS] Administrative Shares enabled via AutoShareWks registry value" -ForegroundColor Green
			$ShareSettingChanged = $true
		} Else {
			Write-Host "  [OK] Administrative Shares are already enabled (AutoShareWks)" -ForegroundColor Green
		}

		# Also check AutoShareServer for server OS
		$ServerValue = Get-ItemProperty -Path $RegPath -Name "AutoShareServer" -ErrorAction SilentlyContinue
		If ($ServerValue.AutoShareServer -eq 0) {
			Set-ItemProperty -Path $RegPath -Name "AutoShareServer" -Value 1 -Type DWord -ErrorAction Stop
			Write-Host "  [SUCCESS] Administrative Shares enabled via AutoShareServer registry value" -ForegroundColor Green
			$ShareSettingChanged = $true
		} Else {
			Write-Host "  [OK] Administrative Shares are already enabled (AutoShareServer)" -ForegroundColor Green
		}

		# Only restart the Server service if we changed a registry value
		If ($ShareSettingChanged) {
			$LanmanServer = Get-Service -Name "LanmanServer" -ErrorAction SilentlyContinue
			If ($LanmanServer -and $LanmanServer.Status -eq "Running") {
				Restart-Service -Name "LanmanServer" -Force -ErrorAction Stop
				Write-Host "  [SUCCESS] Server service restarted to apply share settings" -ForegroundColor Green
			}
		}

		# Verify shares exist
		$AdminShare = Get-SmbShare -Name "ADMIN$" -ErrorAction SilentlyContinue
		$CShare = Get-SmbShare -Name "C$" -ErrorAction SilentlyContinue
		If ($AdminShare -and $CShare) {
			Write-Host "  [OK] ADMIN$ and C$ shares are present" -ForegroundColor Green
		} Else {
			Write-Warning "  [WARNING] Admin shares may require a reboot to appear"
		}
	} Catch {
		Write-Warning "  [ERROR] Failed to configure Administrative Shares: $_"
	}

	# 3. Enable PowerShell Remoting (WinRM)
	Write-Host "`nStep 3: Enabling PowerShell Remoting (WinRM)..." -ForegroundColor Yellow
	Try {
		$WinRM = Get-Service -Name "WinRM" -ErrorAction Stop
		If ($WinRM.Status -eq "Running") {
			# Test if PSRemoting is already functional
			$SessionConfig = Get-PSSessionConfiguration -Name "Microsoft.PowerShell" -ErrorAction SilentlyContinue
			If ($SessionConfig) {
				Write-Host "  [OK] PowerShell Remoting is already enabled and configured" -ForegroundColor Green
			} Else {
				Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction Stop
				Write-Host "  [SUCCESS] PowerShell Remoting enabled" -ForegroundColor Green
			}
		} Else {
			Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction Stop
			Write-Host "  [SUCCESS] PowerShell Remoting enabled and WinRM started" -ForegroundColor Green
		}

		# Refresh service object since Enable-PSRemoting may have changed startup type
		$WinRM = Get-Service -Name "WinRM" -ErrorAction Stop
		If ($WinRM.StartType -ne "Automatic") {
			Set-Service -Name "WinRM" -StartupType Automatic -ErrorAction Stop
			Write-Host "  [SUCCESS] WinRM set to Automatic startup" -ForegroundColor Green
		}
	} Catch {
		Write-Warning "  [ERROR] Failed to configure PowerShell Remoting: $_"
	}

	# 4. Enable WMI Through Firewall
	Write-Host "`nStep 4: Enabling WMI firewall rules..." -ForegroundColor Yellow
	Try {
		$WMIRules = Get-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" -ErrorAction SilentlyContinue

		If ($WMIRules) {
			ForEach ($Rule in $WMIRules) {
				If ($Rule.Enabled -eq $false) {
					Enable-NetFirewallRule -Name $Rule.Name -ErrorAction Stop
					Write-Host "  [SUCCESS] Enabled firewall rule: $($Rule.DisplayName)" -ForegroundColor Green
				} Else {
					Write-Host "  [OK] Firewall rule already enabled: $($Rule.DisplayName)" -ForegroundColor Green
				}
			}
		} Else {
			Write-Warning "  [WARNING] WMI firewall rule group not found"
		}
	} Catch {
		Write-Warning "  [ERROR] Failed to configure WMI firewall rules: $_"
	}

	# 5. Enable File and Printer Sharing (required for PSExec and admin share access)
	Write-Host "`nStep 5: Enabling File and Printer Sharing firewall rules (PSExec support)..." -ForegroundColor Yellow
	Try {
		$FPSRules = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue

		If ($FPSRules) {
			ForEach ($Rule in $FPSRules) {
				If ($Rule.Enabled -eq $false) {
					Enable-NetFirewallRule -Name $Rule.Name -ErrorAction Stop
					Write-Host "  [SUCCESS] Enabled firewall rule: $($Rule.DisplayName)" -ForegroundColor Green
				} Else {
					Write-Host "  [OK] Firewall rule already enabled: $($Rule.DisplayName)" -ForegroundColor Green
				}
			}
		} Else {
			Write-Warning "  [WARNING] File and Printer Sharing firewall rule group not found"
		}
	} Catch {
		Write-Warning "  [ERROR] Failed to configure File and Printer Sharing firewall rules: $_"
	}

	# 6. Enable ICMP (Ping) for PRTG and monitoring tools
	Write-Host "`nStep 6: Enabling ICMP (Ping) for PRTG and monitoring..." -ForegroundColor Yellow
	Try {
		# Enable ICMPv4 Echo Request
		$ICMPv4Rule = Get-NetFirewallRule -Name "CoreNet-Diag-ICMP4-EchoRequest-In" -ErrorAction SilentlyContinue
		If ($ICMPv4Rule) {
			If ($ICMPv4Rule.Enabled -eq $false) {
				Enable-NetFirewallRule -Name "CoreNet-Diag-ICMP4-EchoRequest-In" -ErrorAction Stop
				Write-Host "  [SUCCESS] Enabled ICMPv4 Echo Request (Ping)" -ForegroundColor Green
			} Else {
				Write-Host "  [OK] ICMPv4 Echo Request (Ping) already enabled" -ForegroundColor Green
			}
		} Else {
			# Create the rule if it doesn't exist
			New-NetFirewallRule -DisplayName "Allow ICMPv4 Echo Request" `
				-Name "Custom-ICMPv4-EchoRequest-In" `
				-Protocol ICMPv4 `
				-IcmpType 8 `
				-Direction Inbound `
				-Action Allow `
				-Enabled True `
				-ErrorAction Stop | Out-Null
			Write-Host "  [SUCCESS] Created ICMPv4 Echo Request firewall rule" -ForegroundColor Green
		}

		# Enable Remote Event Log Management for PRTG WMI sensors
		$EventLogRules = Get-NetFirewallRule -DisplayGroup "Remote Event Log Management" -ErrorAction SilentlyContinue
		If ($EventLogRules) {
			ForEach ($Rule in $EventLogRules) {
				If ($Rule.Enabled -eq $false) {
					Enable-NetFirewallRule -Name $Rule.Name -ErrorAction Stop
					Write-Host "  [SUCCESS] Enabled firewall rule: $($Rule.DisplayName)" -ForegroundColor Green
				} Else {
					Write-Host "  [OK] Firewall rule already enabled: $($Rule.DisplayName)" -ForegroundColor Green
				}
			}
		}
	} Catch {
		Write-Warning "  [ERROR] Failed to configure ICMP/monitoring firewall rules: $_"
	}

	# 7. Enable Remote Desktop via Enable-RDP
	Write-Host "`nStep 7: Enabling Remote Desktop..." -ForegroundColor Yellow
	Try {
		Enable-RDP
	} Catch {
		Write-Warning "  [ERROR] Failed to run Enable-RDP: $_"
	}

	# Final Summary
	Write-Host "`n========================================" -ForegroundColor Cyan
	Write-Host "=== Remote Management Configuration Complete ===" -ForegroundColor Green
	Write-Host "`nThe following remote management capabilities have been configured:" -ForegroundColor Cyan
	Write-Host "  - Remote Registry (service running, set to Automatic)" -ForegroundColor White
	Write-Host "  - Administrative Shares (ADMIN$, C$)" -ForegroundColor White
	Write-Host "  - PowerShell Remoting (WinRM)" -ForegroundColor White
	Write-Host "  - WMI (firewall rules enabled)" -ForegroundColor White
	Write-Host "  - PSExec (File and Printer Sharing enabled)" -ForegroundColor White
	Write-Host "  - PRTG Monitoring (ICMP, WMI, Remote Event Log)" -ForegroundColor White
	Write-Host "  - Remote Desktop (RDP)" -ForegroundColor White
	Write-Host "========================================`n" -ForegroundColor Cyan
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
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
	# Enable TLS 1.2 system-wide for .NET applications
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord

	# For 64-bit systems, also set the Wow6432Node keys
	if ([Environment]::Is64BitOperatingSystem) {
		Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
		Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord
	}
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
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCQMmjW9gjAeopU
# isG7dPcvnEDv2bbMjAgRSIorwGLodaCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IEo4+DlzPxofu0pkjVu9UM7t9qhugniiubG4RDFdi+P/MA0GCSqGSIb3DQEBAQUA
# BIICADuPnUjf/A4lYy6IBoTiCCq3xVS63tWUvRxTJW26Vo3OLdxnPq+k3o96g3dh
# 1BGdPIxtLO3CwP9fwDuZWuiFIYDVkJXJJen78Eg2K+QiJlhrPCiR5YZCoKC7+YT+
# GetCxEBk00hZxkU4g4S9876s96g0jvp3E4rGgbwdoWFyBqyVycZ6sWRsKNbhNj/n
# GjhswYFdhezPu1ocTE//UK70Kl7KeUOwnJ0vVA0weQnZ2tP7kjTqWzeCORGDzg3+
# sXdfSp2R7G7LYCXQd1NJr5IR0llUugfv8t8vu2aC8WhSlpgKz9GXDo/PxnYvxIKN
# MN1O0w5KbNTSvkRPT2W8Z3Y+hhnu7qelDCKo+h1JXLFHAes8uL0XjhpL74u4jJVa
# v85be1PiwTxADVevaWCqWb1xnRnHYFmPSe1NgtKVXLeYz9d4645H5E3N2MJQvIQM
# W7RA9rfTr4kq97s7rxMynsOJFSgZBJWV9nzbQaHnq/lzoGXjCSYd2Q5pFW4WZYwj
# 9Q4HlrMe/45YDmelDys+VPEudaMLFak6Jz7xIllQP7q0VMCEVmjxRBF7b1u7XRnr
# jA9Qoh4zNmE/ZD8bX0buWu3qs58POHYadT9iI3hlwkzZ3lyu6wMQHMu/TuPcoJkI
# HOwStT3zRadnhO7j/KP0uS1isYObkFHJy6ubEl1lxVoTsGoqoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDMyNTE2NTgxN1owLwYJKoZIhvcNAQkEMSIEIHhi5Lz1
# KOZ1L+I9Wzwp4ESzthIZLHLiQJmpZw/OhTKXMA0GCSqGSIb3DQEBAQUABIICAKk8
# pu1DJn7xCoDjnxz2uAb26BlkLE+QfUQUqjFs1nrkMwMBDGzWe42mIsYPakJS0dLk
# FHaBOpY7JtjYhMMmd46yChT/tWNpSS9+4U5MqZQqzW51Ne+WNhc5e248ok4a3oaR
# dRlPLY7b88sDTxvMV/CgO01Dg0PRAmRDjFzhqfWtr3UhLpBtUVphFv26n1I7EjCG
# aQeiHvmVqoKViztYTuIQDnm5Bo2+x/n2QVf3905HQC1WTJQ2qM2xfHk30kB2w4DL
# ng6wmV+2PThYARzdIJnCZobdhYI3EH1NVySM8CsDQJq0sxdaAqybnbhpo5Z0Ytho
# XoZZvUOTMH6DC3b9Qi51f2s/S+nqLwXxXiJPET8sNI0f0s5dE52V93jrICIp6LWr
# 4QHJIYW0uo0M9Uva3uXSZUPzjWBG1K2/RmgRUs1HVdQfIjlUIAkLCawFVwXgQec+
# RnjEA4NIx7q8wnpBkKsW1qiwt9YyCHQ2kaE8itsYehsx8Tm3MnQiNG3c5+2C3x3h
# AKbWDSf1Q5qPvQpuB6+SA57MYiQ5Qq/wyN5QtKC6N3cb9e4fDz367lXVu+hBwlqj
# 7g13trVx/c9uuDfn9kdblAxD1ZjpDdcrlEEpWQ2i2kzzK4yzc1K2O3FHhu/IX12C
# RqLtPsP3NW6pJ5fj36icXQyOf9PAj/T0mR717zNF
# SIG # End signature block
