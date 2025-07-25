Function Set-AutoLogon ([String] $SiteCode) {
	Write-Host "Set autologon"
		#Registry path declaration
		$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
		[String]$DefaultUsername = 'ATGLocal'
		[String]$DefaultPassword = $SiteCode + 'T3mpP@ss'
		#setting registry values
		Set-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String
		Set-ItemProperty $RegPath "DefaultUsername" -Value $DefaultUsername -type String
		Set-ItemProperty $RegPath "DefaultPassword" -Value $DefaultPassword -type String
		Set-ItemProperty $RegPath "AutoLogonCount" -Value "1" -type DWord
	Write-Host "End of Set autologon"
}

function Set-ComputerLanguage {
	param (
		[string]$Language = "en-US"
	)
	$LanguageUpdated = $False
	# Check if the OS language is not set to the specified language
	$osLanguage = Get-SystemPreferredUILanguage
	if ($osLanguage -ne $Language) {
		Write-Host "OS language is currently set to $osLanguage. Changing to $Language..."
		Install-Language -Language $Language -CopyToSettings
		Set-SystemPreferredUILanguage -Language $Language
		$LanguageUpdated = $True
	}

	# Check if the keyboard layout is not set to the specified language
	$keyboardLayout = Get-WinUserLanguageList | Where-Object { $_.LanguageTag -ne $Language }
	if ($keyboardLayout) {
		Write-Host "Keyboard layout is currently set to $($keyboardLayout.LanguageTag). Changing to $Language..."
		Set-WinUserLanguageList -LanguageList $Language -Force
		$LanguageUpdated = $True
	}

	$CultureLanguage = (Get-Culture).Name
	if ($CultureLanguage -ne $Language) {
		Write-Host "OS Culture is currently set to $CultureLanguage. Changing to $Language..."
		Set-Culture -CultureInfo $Language
		$LanguageUpdated = $True
	}

	if ((Get-WinSystemLocale).Name -ne $Language){
		Set-WinSystemLocale -SystemLocale $Language
		$LanguageUpdated = $True
	}

	function Get-GeoIdLanguageMapping {
		$cultures = [System.Globalization.CultureInfo]::GetCultures([System.Globalization.CultureTypes]::AllCultures)
		$geoIdLanguageMapping = @()

		foreach ($culture in $cultures) {
			try {
				$region = [System.Globalization.RegionInfo]$culture.Name
				$geoIdLanguageMapping += [PSCustomObject]@{
					GeoId        = $region.GeoId
					LanguageCode = $culture.Name
					DisplayName  = $region.DisplayName
				}
			} catch {
				# Ignore cultures that do not have a corresponding RegionInfo
			}
		}

		return $geoIdLanguageMapping | Sort-Object GeoId | Select-Object GeoId, LanguageCode, DisplayName
	}
	$NewLanguageGeoId = (Get-GeoIdLanguageMapping | ?{$_.LanguageCode -eq $Language}).GeoId
	If (-not ((Get-WinHomeLocation).GeoId -match $NewLanguageGeoId)) {
		Set-WinHomeLocation -GeoId $NewLanguageGeoId
		$LanguageUpdated = $True
	}

	If ($LanguageUpdated) {
		# Inform the user that changes have been made
		Set-WinUILanguageOverride -Language $Language
		Write-Host "Language and keyboard layout have been updated to $Language. A reboot is required to take effect."
	} Else {
		# Inform the user that changes have been made
		Write-Host "Language and keyboard layout are already set to $Language. No further action is required."
	}
}

Function Set-DailyReboot {
<#
	.SYNOPSIS
		Creates a scheduled task to restart the computer daily at 3am, if no one is using the computer.
		Helpful for maintaining updated and stability.
#>
	Write-Host "Schedule Daily Restart"
		$Action = New-ScheduledTaskAction -Execute 'shutdown.exe' -Argument '-f -r -t 0'
		$Trigger = New-ScheduledTaskTrigger -Daily -At 3am
		$Idle = New-ScheduledTaskSettingsSet -RunOnlyIfIdle -IdleDuration 00:30:00 -IdleWaitTimeout 02:00:00
		$User = "NT AUTHORITY\SYSTEM"
		Register-ScheduledTask -Action $action -Trigger $trigger -User $User -Settings $Idle -TaskName "Daily Restart" -Description "Daily restart" -Force | Out-Null
		$NewDate = (Get-ScheduledTask -TaskName "Daily Restart").Triggers.StartBoundary.subString(0,16)
	Write-Host "The next scheduled 'Daily Restart' task will happen at $([Datetime]::ParseExact($NewDate, 'yyyy-MM-ddTHH:mm', $null))"
}

Function Set-DailyRebootDelay {
<#
	.SYNOPSIS
		Delays the "Daily Restart" scheduled task by the specified numer of days
	.PARAMETER Days
		The number of days to delay the reboot
	.EXAMPLE
		'Set-DailyRebootDelay -Days 80' will delay nightly reboots for 80 days!
#>
	param
	(
		[Parameter(Mandatory=$true)]
		[Int32]$Days
	)
	$DailyRebootTask = Get-ScheduledTask -TaskName "Daily Restart" -ErrorAction SilentlyContinue
	If (! $DailyRebootTask) {
		Set-DailyReboot
	}
	$DelayedStart = (Get-Date).AddDays($Days).ToString('yyyy-MM-dd') + "T03:00:00-06:00"
	$Trigger = New-ScheduledTaskTrigger -Daily -At 3am
	$Trigger.StartBoundary = $DelayedStart
	$DailyRebootTask.Triggers = $Trigger
	$DailyRebootTask | Set-ScheduledTask | Out-Null
	$NewDate = (Get-ScheduledTask -TaskName "Daily Restart").Triggers.StartBoundary.subString(0,16)
	Write-Host "The next scheduled 'Daily Restart' task will happen at $([Datetime]::ParseExact($NewDate, 'yyyy-MM-ddTHH:mm', $null))"
}

Function Set-DnsMadeEasyDDNS {
	[CmdletBinding(DefaultParameterSetName = 'Direct')]
	param
	(
		[Parameter(Mandatory=$True,
			ParameterSetName = 'ToFile')]
		[System.IO.FileInfo]$ToFile,

		[Parameter(Mandatory=$True,
			ParameterSetName = 'FromFile')]
		[System.IO.FileInfo]$FromFile,

		[Parameter(Mandatory=$True,
			ParameterSetName = 'Direct')]
		[Parameter(Mandatory=$True,
			ParameterSetName = 'ToFile')]
		[string]$Username,

		[Parameter(Mandatory=$True,
			ParameterSetName = 'Direct')]
		[Parameter(Mandatory=$True,
			ParameterSetName = 'ToFile')]
		[string]$Password,

		[Parameter(Mandatory=$True,
			ParameterSetName = 'Direct')]
		[Parameter(Mandatory=$True,
			ParameterSetName = 'ToFile')]
		[string]$RecordID,

		[Parameter(Mandatory=$False,
			ParameterSetName = 'Direct')]
		[Parameter(Mandatory=$False,
			ParameterSetName = 'FromFile')]
		[string]$IPAddress
	)

	<#
	.DESCRIPTION
		This command updates a DnsMadeEasy Dynamic DNS entry. For easy re-use, all settings including the password can also be stored in an encrypted file and be reused.
	.EXAMPLE
		Set-DnsMadeEasyDDNS -Username "ambitions" -Password "kee89" -RecordID "2348"
			Uses credentials to update a dns record with the detected public IP.
	.EXAMPLE
		Set-DnsMadeEasyDDNS -Username "ambitions" -Password "kee89" -RecordID "2348" -IPAddress "127.0.0.1"
			Uses credentials to update a dns record with a predetermined key.
	.EXAMPLE
		Set-DnsMadeEasyDDNS -ToFile "$ITFolder\Scripts\DnsMadeEasyDDNS-4411mont.beyond-health.txt" -Username "ambitions" -Password "kee89" -RecordID "2348"
			Stores all fo the needed settings in an encrypted file.
	.EXAMPLE
		Set-DnsMadeEasyDDNS -FromFile "$ITFolder\Scripts\DnsMadeEasyDDNS-4411mont.beyond-health.txt"
			Retrieves all needed settings from an encrypted file.
	.LINK
		Documentation: https://dnsmadeeasy.com/technology/dynamic-dns

#>

	If ($FromFile) {
		$encryptedstring = Get-Content -Path $FromFile
		$securestring = $encryptedstring | ConvertTo-SecureString
		$Marshal = [System.Runtime.InteropServices.Marshal]
		$Bstr = $Marshal::SecureStringToBSTR($securestring)
		$string = $Marshal::PtrToStringAuto($Bstr)
		$FinalUrl = $string
		$Marshal::ZeroFreeBSTR($Bstr)
	} Else {
		$BaseUrl = "https://cp.dnsmadeeasy.com/servlet/updateip?"
		$FinalUrl = $Baseurl + `
		"Username=" + $Username + `
		"&password=" + $Password + `
		"&id=" + $RecordID
		If ($ToFile) {
			$securestring = $FinalUrl | ConvertTo-SecureString -AsPlainText -Force
			$encryptedstring = $securestring | ConvertFrom-SecureString
			$encryptedstring | Set-Content -Path $ToFile -Force
		}
	}

	If (-not $ToFile) {
		If (-Not $IPAddress) {
			$IPAddress = (Invoke-WebRequest -Uri http://myip.dnsmadeeasy.com/ -UseBasicParsing).Content
		}
		$FinalUrl = $FinalUrl + "&ip=" + $IpAddress

		Write-Host $FinalUrl
		(Invoke-WebRequest -Uri $FinalUrl -UseBasicParsing).Content
	}
}

Function Set-MountainTime {
	Write-Host "Setting local time zone to Mountain Time"
	Set-TimeZone -Name "Mountain Standard Time"
	net start W32Time
	W32tm /resync /force
}

Function Set-NumLock {
	Write-Host "Setting Numlock on keyboard as default"
	Set-ItemProperty -Path 'Registry::HKU\.DEFAULT\Control Panel\Keyboard' -Name "InitialKeyboardIndicators" -Value "2" -Force -PassThru
}

Function Set-PsSpeak {
	param (
			[string]$Text,
			[ValidateSet("Male", "Female")]
			[string]$Gender = "Male",
			[ValidateRange(1, 100)]
			[int]$Volume = 100
		)
	
		Add-Type -AssemblyName System.Speech
		$SpeechSynthesizer = New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer
	
		If ($SpeechSynthesizer.Voice.Gender -ne $Gender) {
			$VoiceToInstall = (($SpeechSynthesizer.GetInstalledVoices()).VoiceInfo | Where-Object -Property Gender -eq $Gender)[0].Name
			$SpeechSynthesizer.SelectVoice($VoiceToInstall)
		}
		
		If ($SpeechSynthesizer.Volume -ne $Volume) {
			$SpeechSynthesizer.Volume = $Volume
		}
		if (-not ([System.Management.Automation.PSTypeName]'Audio').Type) {
			Add-Type -TypeDefinition @'
			using System.Runtime.InteropServices;
			[Guid("5CDF2C82-841E-4546-9722-0CF74078229A"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
			interface IAudioEndpointVolume {
				// f(), g(), ... are unused COM method slots. Define these if you care
				int f(); int g(); int h(); int i();
				int SetMasterVolumeLevelScalar(float fLevel, System.Guid pguidEventContext);
				int j();
				int GetMasterVolumeLevelScalar(out float pfLevel);
				int k(); int l(); int m(); int n();
				int SetMute([MarshalAs(UnmanagedType.Bool)] bool bMute, System.Guid pguidEventContext);
				int GetMute(out bool pbMute);
			}
			[Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
			interface IMMDevice {
				int Activate(ref System.Guid id, int clsCtx, int activationParams, out IAudioEndpointVolume aev);
			}
			[Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
			interface IMMDeviceEnumerator {
				int f(); // Unused
				int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice endpoint);
			}
			[ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")] class MMDeviceEnumeratorComObject { }
		
			public class Audio {
				static IAudioEndpointVolume Vol() {
					var enumerator = new MMDeviceEnumeratorComObject() as IMMDeviceEnumerator;
					IMMDevice dev = null;
					Marshal.ThrowExceptionForHR(enumerator.GetDefaultAudioEndpoint(/*eRender*/ 0, /*eMultimedia*/ 1, out dev));
					IAudioEndpointVolume epv = null;
					var epvid = typeof(IAudioEndpointVolume).GUID;
					Marshal.ThrowExceptionForHR(dev.Activate(ref epvid, /*CLSCTX_ALL*/ 23, 0, out epv));
					return epv;
				}
				public static float Volume {
					get {float v = -1; Marshal.ThrowExceptionForHR(Vol().GetMasterVolumeLevelScalar(out v)); return v;}
					set {Marshal.ThrowExceptionForHR(Vol().SetMasterVolumeLevelScalar(value, System.Guid.Empty));}
				}
				public static bool Mute {
					get { bool mute; Marshal.ThrowExceptionForHR(Vol().GetMute(out mute)); return mute; }
					set { Marshal.ThrowExceptionForHR(Vol().SetMute(value, System.Guid.Empty)); }
				}
			}
'@
		}
	 If ([Audio]::Volume -lt .5) {[Audio]::Volume = 0.5}
	 If ([Audio]::Mute -eq $True) {[Audio]::Mute = $False}
		
		$SpeechSynthesizer.SpeakAsync($Text)
}

Function Set-RunOnceScript {
	param
	(
		[string]$Label,
		[string]$Script
	)

	$RunOnceValue = 'PowerShell.exe -ExecutionPolicy Bypass -File "' + $Script + '"'
	Write-Host "Install After Reboot"
	Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name $Label -Value $RunOnceValue
}

Function Set-ServerRebootScriptPassword {
	If ($(whoami) -match 'system') {
	$User = Get-Content -Path $ITFolder\scripts\server_reboot_user.txt
	Write-Host "Enter the current password for the user $User"
	$Password = Read-Host -AsSecureString
	$Password | ConvertFrom-SecureString | Out-File "$ITFolder\Scripts\Server_Reboot_Cred.txt"
	} Else {
		Write-Error "You must run this command as the system user via ConnectWise Backstage or PSExec.exe."
	}
}

Function Set-WeeklyReboot {
<#
	.SYNOPSIS
		Creates a scheduled task to restart the computer Weekly on Sunday at 3am, if no one is using the computer.
		Helpful for maintaining updated and stability.
#>
	Write-Host "Schedule Weekly Restart"
		$Action = New-ScheduledTaskAction -Execute 'shutdown.exe' -Argument '-f -r -t 0'
		$Trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek Sunday -At 3am
		$Idle = New-ScheduledTaskSettingsSet -RunOnlyIfIdle -IdleDuration 00:30:00 -IdleWaitTimeout 02:00:00
		$User = "NT AUTHORITY\SYSTEM"
		Register-ScheduledTask -Action $action -Trigger $trigger -User $User -Settings $Idle -TaskName "Weekly Restart" -Description "Weekly restart" -Force | Out-Null
		$NewDate = (Get-ScheduledTask -TaskName "Weekly Restart").Triggers.StartBoundary.subString(0,16)
	Write-Host "The next scheduled 'Weekly Restart' task will happen at $([Datetime]::ParseExact($NewDate, 'yyyy-MM-ddTHH:mm', $null))"
}

# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU3WXdo0r2bTb/77C0YVpTjPpR
# QgKgggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUiV40
# Hhj697gOdD9geGUfwmiYGfwwDQYJKoZIhvcNAQEBBQAEggEARJ8pDgpSDIqTrmlY
# 5t6wp+8CIm9JKbkotsVDC7uLT7aOVlNycalMxbccYtoW66/JUTOcsZ3cPuh3ZJpj
# Tuamn32F5YXL87e4niPnAhWiSyZpGxRd3fyuBlsIFOBOHa8UvyTnm4NwvIREgZmp
# OQ6w3p8rLxalbK0Gt+cOG7aUvfvdyIS/dF6w6fe4NZR8VnFc1Omx8gS74n6IoGcb
# ca0NyeD1FCxDAr3dZv251kWXx23NErc1ms2mLNX7kOjGHOYmK1hBx9ouZbqW6El7
# xx0eMSrzEnoUwQZdUzunAKPjQgSRKgC5M2kPIpEERVNEKtA0VEgzC+etXTQM1pP3
# QaQA1g==
# SIG # End signature block