Function Set-AutoLogon {
	param (
		[String]$Username = 'MTLocal',
		[String]$Password
	)
	Write-Host "Set autologon"
	#Registry path declaration
	$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
	#setting registry values
	Set-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String
	Set-ItemProperty $RegPath "DefaultUsername" -Value $Username -type String
	Set-ItemProperty $RegPath "DefaultPassword" -Value $Password -type String
	Set-ItemProperty $RegPath "AutoLogonCount" -Value "1" -type DWord
	Write-Host "End of Set autologon"
}

function Set-ChocolateySources {
    # Check if Chocolatey is installed
    if (-not (Get-Command choco.exe -ErrorAction SilentlyContinue)) {
        Write-Warning "Chocolatey is not installed"
        return
    }
    
    # Define desired sources
    $desiredSources = @(
        @{
            Name     = 'chocolatey'
            Source   = 'https://community.chocolatey.org/api/v2/'
            Priority = 100
            Disabled = $false
        }
        @{
            Name     = 'MauleCache'
            Source   = 'https://cache.mauletech.com/nuget/choco/'
            Priority = 0
            Disabled = $false
        }
    )
    
    Write-Host "Setting Chocolatey sources to desired state..." -ForegroundColor Cyan
    
    # Get current sources
    $currentSources = choco source list --limit-output | ForEach-Object {
        $parts = $_ -split '\|'
        
        # Try to find priority - it should be a numeric value
        $priority = 0
        for ($i = 0; $i -lt $parts.Count; $i++) {
            if ($parts[$i] -match '^\d+$') {
                $priority = [int]$parts[$i]
                break
            }
        }
        
        [PSCustomObject]@{
            Name     = $parts[0]
            Source   = $parts[1]
            Disabled = $parts[2] -eq 'True'
            Priority = $priority
        }
    }
    
    # Remove sources not in desired state
    $currentSources | Where-Object { $_.Name -notin $desiredSources.Name } | ForEach-Object {
        Write-Host "  Removing source: $($_.Name)" -ForegroundColor Yellow
        choco source remove --name="$($_.Name)" | Out-Null
    }
    
    # Add or update desired sources
    foreach ($desired in $desiredSources) {
        $existing = $currentSources | Where-Object Name -eq $desired.Name
        
        if ($existing) {
            # Check if update needed
            if ($existing.Source -ne $desired.Source -or 
                $existing.Disabled -ne $desired.Disabled -or 
                $existing.Priority -ne $desired.Priority) {
                
                Write-Host "  Updating source: $($desired.Name)" -ForegroundColor Yellow
                choco source remove --name="$($desired.Name)" | Out-Null
                choco source add --name="$($desired.Name)" --source="$($desired.Source)" --priority=$($desired.Priority) | Out-Null
                
                if ($desired.Disabled) {
                    choco source disable --name="$($desired.Name)" | Out-Null
                } else {
                    choco source enable --name="$($desired.Name)" | Out-Null
                }
            } else {
                Write-Host "  Source already configured: $($desired.Name)" -ForegroundColor Green
            }
        } else {
            # Add new source
            Write-Host "  Adding source: $($desired.Name)" -ForegroundColor Green
            choco source add --name="$($desired.Name)" --source="$($desired.Source)" --priority=$($desired.Priority) | Out-Null
            
            if ($desired.Disabled) {
                choco source disable --name="$($desired.Name)" | Out-Null
            }
        }
    }
    
    Write-Host "`nCurrent Chocolatey sources:" -ForegroundColor Cyan
    choco source list
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
        Creates a scheduled task to restart the computer daily at a specified time.
        Suspends BitLocker if enabled before reboot to prevent recovery prompts.
    
    .PARAMETER Time
        The time of day to perform the restart. Defaults to 3am.
    
    .EXAMPLE
        Set-DailyReboot
        Creates a daily restart task for 3am.
    
    .EXAMPLE
        Set-DailyReboot -Time "2am"
        Creates a daily restart task for 2am.
#>
    [CmdletBinding()]
    param (
        [Parameter()]
        [DateTime]$Time = "3:00 AM"
    )
    
    Write-Host "Schedule Daily Restart"
    
    # Create the resume BitLocker script
    $ResumeScript = @'
Start-Sleep -Seconds 30
$Volume = Get-BitLockerVolume -MountPoint C:
if ($Volume.ProtectionStatus -eq 'Off') {
    Resume-BitLocker -MountPoint C:
    New-Item -Path 'HKLM:\SOFTWARE\MauleTech' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\MauleTech' -Name 'BitLockerResumedDate' -Value (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') -Force
}
'@
    
    # Save the resume script to a known location
    $ScriptPath = "$env:ProgramData\MauleTech\ResumeBitLocker.ps1"
    New-Item -Path "$env:ProgramData\MauleTech" -ItemType Directory -Force | Out-Null
    $ResumeScript | Out-File -FilePath $ScriptPath -Encoding ASCII -Force
    
    # Build the main command
    $Command = "if ((Get-BitLockerVolume -MountPoint C:).ProtectionStatus -eq 'On') { Suspend-BitLocker -MountPoint C: -RebootCount 5; New-Item -Path 'HKLM:\SOFTWARE\MauleTech' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\MauleTech' -Name 'BitLockerSuspendedDate' -Value (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') -Force; Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'ResumeBitLocker' -Value 'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $ScriptPath' -Force }; Restart-Computer -Force"
    
    # Create the scheduled task action using PowerShell
    $Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -Command `"$Command`""
    
    # Create the trigger with specified time
    $Trigger = New-ScheduledTaskTrigger -Daily -At $Time
    
    # Configure to run only when idle
    $Idle = New-ScheduledTaskSettingsSet -RunOnlyIfIdle -IdleDuration 00:30:00 -IdleWaitTimeout 02:00:00
    
    $User = "NT AUTHORITY\SYSTEM"
    
    Register-ScheduledTask -Action $Action -Trigger $Trigger -User $User -Settings $Idle -TaskName "Daily Restart" -Description "Daily restart with BitLocker suspension" -Force | Out-Null
    
    # Get the actual next run time from the task
    $NextRun = (Get-ScheduledTaskInfo -TaskName "Daily Restart").NextRunTime
    
    if ($NextRun) {
        Write-Host "The next scheduled 'Daily Restart' task will happen at $NextRun"
    } else {
        Write-Host "Daily Restart task created, but next run time could not be determined."
    }
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
		Set-DnsMadeEasyDDNS -Username "myuser" -Password "kee89" -RecordID "2348"
			Uses credentials to update a dns record with the detected public IP.
	.EXAMPLE
		Set-DnsMadeEasyDDNS -Username "myuser" -Password "kee89" -RecordID "2348" -IPAddress "127.0.0.1"
			Uses credentials to update a dns record with a predetermined key.
	.EXAMPLE
		Set-DnsMadeEasyDDNS -ToFile "$ITFolder\Scripts\DnsMadeEasyDDNS-4411mont.beyond-health.txt" -Username "myuser" -Password "kee89" -RecordID "2348"
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
			$IPAddress = (Invoke-WebRequest -Uri https://myip.dnsmadeeasy.com/ -UseBasicParsing).Content
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
        Creates a scheduled task to restart the computer weekly at a specified time and day.
        Suspends BitLocker if enabled before reboot to prevent recovery prompts.
    
    .PARAMETER Time
        The time of day to perform the restart. Defaults to 3am.
    
    .PARAMETER Day
        The day of the week to perform the restart. Defaults to Sunday.
    
    .EXAMPLE
        Set-WeeklyReboot
        Creates a weekly restart task for Sunday at 3am.
    
    .EXAMPLE
        Set-WeeklyReboot -Time "2am" -Day Monday
        Creates a weekly restart task for Monday at 2am.
#>
    [CmdletBinding()]
    param (
        [Parameter()]
        [DateTime]$Time = "3:00 AM",
        
        [Parameter()]
        [ValidateSet('Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday')]
        [string]$Day = 'Sunday'
    )
    
    Write-Host "Schedule Weekly Restart"
    
    # Create the resume BitLocker script
    $ResumeScript = @'
Start-Sleep -Seconds 30
$Volume = Get-BitLockerVolume -MountPoint C:
if ($Volume.ProtectionStatus -eq 'Off') {
    Resume-BitLocker -MountPoint C:
    New-Item -Path 'HKLM:\SOFTWARE\MauleTech' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\MauleTech' -Name 'BitLockerResumedDate' -Value (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') -Force
}
'@
    
    # Save the resume script to a known location
    $ScriptPath = "$env:ProgramData\MauleTech\ResumeBitLocker.ps1"
    New-Item -Path "$env:ProgramData\MauleTech" -ItemType Directory -Force | Out-Null
    $ResumeScript | Out-File -FilePath $ScriptPath -Encoding ASCII -Force
    
    # Build the main command
    $Command = "if ((Get-BitLockerVolume -MountPoint C:).ProtectionStatus -eq 'On') { Suspend-BitLocker -MountPoint C: -RebootCount 5; New-Item -Path 'HKLM:\SOFTWARE\MauleTech' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\MauleTech' -Name 'BitLockerSuspendedDate' -Value (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') -Force; Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'ResumeBitLocker' -Value 'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $ScriptPath' -Force }; Restart-Computer -Force"
    
    # Create the scheduled task action using PowerShell
    $Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -Command `"$Command`""
    
    # Create the trigger with specified day and time
    $Trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek $Day -At $Time
    
    # Configure to run only when idle
    $Idle = New-ScheduledTaskSettingsSet -RunOnlyIfIdle -IdleDuration 00:30:00 -IdleWaitTimeout 02:00:00
    
    $User = "NT AUTHORITY\SYSTEM"
    
    Register-ScheduledTask -Action $Action -Trigger $Trigger -User $User -Settings $Idle -TaskName "Weekly Restart" -Description "Weekly restart with BitLocker suspension" -Force | Out-Null
    
    # Get the actual next run time from the task
    $NextRun = (Get-ScheduledTaskInfo -TaskName "Weekly Restart").NextRunTime
    
    if ($NextRun) {
        Write-Host "The next scheduled 'Weekly Restart' task will happen at $NextRun"
    } else {
        Write-Host "Weekly Restart task created, but next run time could not be determined."
    }
}

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDTCmgIvttnLNnK
# WlH2NivqxjO/UUgB5EKEwGa5DG1h0KCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IIZiFzjNMyF61ObbKQvsWfDi1z2YzbbbKH3kMNXjgwhOMA0GCSqGSIb3DQEBAQUA
# BIICAC3AYinVD4zwCfOS1dLigVV9Tu5srhJNnZ27NeDxUQqwPwPaXMzBvbCby+EM
# 39kG+jlfnpsbldReNKRNWsOWCCICsiAJKhjbNzoKDPtEdEAafSV/lhlMEwTyeBaw
# kTEz/+R+dhJ+yc80qPcidlce9sJ5Tz1LKxY7Z9xBilDddCIT4Epzfc6GA8w1ABOu
# XdmoPb2iCOOMzZVcyC5AtwvcHp0dTBMw7dudsFVtezoBTnSfzi+qUTwLDwylBddd
# J+ivh1P89mca4PxBPGQa+1kbIdvdTuUZ66KenK+0w1U0P6WluEPFbps9buocFiLp
# ds9kqYL6n7qD7IRlHchRy0FhevutLz8YSREmA7kD1AtODlhXTtdy9vfJDi5lXCA4
# KVG3AeFcRvkMUiOSw2eimXOjVXZ76n4aMPpeSaYLOLurwDLAxHreWQaKMCbtlann
# j3CJDGYIE3cCFHi46R9rbMpGCjqUOFjKnBGISw8CE/XjLms5yLOCVjztCooagKUp
# 82yjJs73y3kPv/QYbcuu56xmoR5wDaaDVL/6o4vJaPbFfqZ3Gjljz/COVpXrHKsl
# JYJOI9Ct3Ygy1++1UvaN7n8V7LagOq6rIxmkyJotPqSKUQE4h0FOCJUeSamNv2MV
# nzIr5z8u/GsrhBOaReadbatvb2qgMYNL2M6KpvpTs4gF2uYToYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDQwNjE1MTAwNlowLwYJKoZIhvcNAQkEMSIEIPg5S2Fz
# F5roONoJXw3s9Wi2aQ5FxnWpSicPJYcsN4h6MA0GCSqGSIb3DQEBAQUABIICAGDc
# X95DgUqU2zA7bVe5ZOo9nGFMVmINCjBwHGe2/hJyKkP8uZ1IK+FWqh3pfDASv3Lz
# nmVWkdcUIaOsGlwzaB6YQ/VmwzPtA6hTTpJsr2SHB9yF7EiVssuSxGYdg/huWCgF
# s+GcgXeYfaGr7CW7TM69W67ZHL+EqvQ6hUM5H90CpwBIrD5WVBujU/VLFpOVtd0q
# wYYqQI3W7HgpOOZXIw97N38D5acFILLZBdjvz2C58Z6lp/OEk0y/KKhPGK5Owff7
# xDrW0uFJN8WXLJz/6vqwx2WHczd5cFhXJuCerYbqQ+vLTeeG5TSsmCerD2527214
# 8LlC+nFamGMV2uREVIGTdJw+uFTCIgPC/xCeawOxWkn//NMivje43kubQkjz51k7
# rf2lWXSvGNGuqQr9D+sv77ZkOmEP83v460Oq2/K0nFZ2OiLjL5uaTztBWm1mF7lg
# Fn3Mm8shQrQGZdgAGQdbxv4+SWXX6D5SGC/MnMABA9ABMglnwTmgLVDhvyFeyev0
# uTnGIHOZ37Vtpx2Csi6ooY9OzY/ECMZFgBpRbLr863jxYVOo8etpwUPb/b2+IoL9
# jTtgo235RzXWYMvaIEbPw3HmPCbsPTf8L8p/M2Vp9OIhhT2j9v06kqc3sXB93JEJ
# WwA7xoLt+SsOdTTLpp8MjYuxrCXbv1/BB1nkX6iV
# SIG # End signature block
