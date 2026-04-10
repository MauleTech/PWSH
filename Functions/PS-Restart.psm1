Function Restart-ComputerSafely {
<#
    .SYNOPSIS
        Restarts the computer immediately with BitLocker protection.
        Suspends BitLocker if enabled to prevent recovery prompts, then resumes after reboot.
    
    .PARAMETER Force
        Forces applications to close without warning.
    
    .PARAMETER Delay
        Seconds to wait before restarting. Defaults to 10 seconds.
    
    .EXAMPLE
        Restart-ComputerSafely
        Restarts the computer after 10 seconds, handling BitLocker automatically.
    
    .EXAMPLE
        Restart-ComputerSafely -Force -Delay 0
        Immediately restarts the computer without delay, forcing apps to close.
#>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [ValidateRange(0, 3600)]
        [int]$Delay = 10
    )

    Write-Host "Preparing safe restart with BitLocker handling..."

    # Check if BitLocker is enabled
    try {
        $Volume = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop
    } catch {
        Write-Host "BitLocker not available on this system. Skipping BitLocker handling."
        $Volume = $null
    }

    # Remove any stale RunOnce entry from previous versions of this function
    Remove-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'ResumeBitLocker' -ErrorAction SilentlyContinue

    if ($Volume -and $Volume.ProtectionStatus -eq 'On') {
        Write-Host "BitLocker is enabled. Suspending for 1 reboot..."

        # Suspend BitLocker for 1 reboot only - the scheduled task will re-suspend if updates need more reboots
        try {
            Suspend-BitLocker -MountPoint C: -RebootCount 1 -ErrorAction Stop
        } catch {
            Write-Warning "Failed to suspend BitLocker: $_"
            Write-Warning "Aborting restart to avoid BitLocker recovery prompt."
            return
        }

        try {
        # Log the suspension and reset the re-suspension counter for this new cycle
        New-Item -Path 'HKLM:\SOFTWARE\MauleTech' -Force -ErrorAction Stop | Out-Null
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\MauleTech' -Name 'BitLockerSuspendedDate' -Value (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') -Force -ErrorAction Stop
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\MauleTech' -Name 'BitLockerResuspendCount' -Value 0 -Force -ErrorAction Stop

        # Resolve paths now so the scheduled task doesn't depend on $ITFolder at runtime
        if ($ITFolder) {
            $ResolvedITFolder = $ITFolder
        } else {
            $ResolvedITFolder = "$env:SystemDrive\IT"
        }
        $LogFolder = "$ResolvedITFolder\Logs"
        $ScriptPath = "$ResolvedITFolder\Scripts\ResumeBitLocker.ps1"

        # Create the resume BitLocker script that checks for pending updates before resuming
        $ResumeScript = @"
`$LogPath = "$LogFolder\ResumeBitLocker.log"
`$ScriptPath = "$ScriptPath"
`$MaxResuspensions = 10
`$RegPath = 'HKLM:\SOFTWARE\MauleTech'

New-Item -Path (Split-Path `$LogPath) -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

function Write-Log {
    param([string]`$Message)
    `$Entry = "`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - `$Message"
    Add-Content -Path `$LogPath -Value `$Entry -ErrorAction SilentlyContinue
}

Write-Log "ResumeBitLocker task started. Waiting 60 seconds for services to stabilize..."
Start-Sleep -Seconds 60

try {

# Track re-suspension count in the registry to prevent infinite loops
`$CountValue = (Get-ItemProperty -Path `$RegPath -Name 'BitLockerResuspendCount' -ErrorAction SilentlyContinue).BitLockerResuspendCount
if (`$null -eq `$CountValue) { `$CountValue = 0 }

# Check if a reboot is still pending for Windows Update
`$PendingReboot = `$false

# Check Component-Based Servicing
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
    `$PendingReboot = `$true
    Write-Log "Pending reboot detected: Component Based Servicing"
}

# Check Windows Update (classic AU agent)
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
    `$PendingReboot = `$true
    Write-Log "Pending reboot detected: Windows Update"
}

# Check Windows Update Orchestrator (modern Windows 10/11)
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\RebootRequired') {
    `$PendingReboot = `$true
    Write-Log "Pending reboot detected: Windows Update Orchestrator"
}

`$Volume = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop

if (`$PendingReboot -and `$CountValue -lt `$MaxResuspensions) {
    Write-Log "System still has pending reboots (resuspension `$CountValue of `$MaxResuspensions). Re-suspending BitLocker for 1 more reboot."
    if (`$Volume.ProtectionStatus -eq 'On') {
        Suspend-BitLocker -MountPoint C: -RebootCount 1 -ErrorAction Stop
        Write-Log "BitLocker re-suspended for 1 reboot."
    } else {
        Write-Log "BitLocker already suspended, no action needed."
    }
    Set-ItemProperty -Path `$RegPath -Name 'BitLockerResuspendCount' -Value (`$CountValue + 1) -Force
} else {
    if (`$CountValue -ge `$MaxResuspensions) {
        Write-Log "WARNING: Max re-suspension count (`$MaxResuspensions) reached. Resuming BitLocker regardless of pending reboots."
    }
    Write-Log "Resuming BitLocker."
    if (`$Volume.ProtectionStatus -eq 'Off') {
        Resume-BitLocker -MountPoint C: -ErrorAction Stop
        Set-ItemProperty -Path `$RegPath -Name 'BitLockerResumedDate' -Value (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') -Force
        Write-Log "BitLocker resumed successfully."
    } else {
        Write-Log "BitLocker already enabled, no action needed."
    }
    # Clean up: remove the scheduled task, script file, and counter
    Unregister-ScheduledTask -TaskName 'MauleTech-ResumeBitLocker' -Confirm:`$false -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path `$RegPath -Name 'BitLockerResuspendCount' -ErrorAction SilentlyContinue
    Remove-Item -Path `$ScriptPath -Force -ErrorAction SilentlyContinue
    Write-Log "Scheduled task and script removed. Cleanup complete."
}

} catch {
    Write-Log "ERROR: `$_"
    # Increment a failure counter so we don't loop forever on persistent errors
    `$FailCount = (Get-ItemProperty -Path `$RegPath -Name 'BitLockerResuspendCount' -ErrorAction SilentlyContinue).BitLockerResuspendCount
    if (`$null -eq `$FailCount) { `$FailCount = 0 }
    `$FailCount++
    Set-ItemProperty -Path `$RegPath -Name 'BitLockerResuspendCount' -Value `$FailCount -Force -ErrorAction SilentlyContinue
    if (`$FailCount -ge `$MaxResuspensions) {
        Write-Log "ERROR: Max attempts (`$MaxResuspensions) reached with failures. Cleaning up task. BitLocker may need manual attention."
        Unregister-ScheduledTask -TaskName 'MauleTech-ResumeBitLocker' -Confirm:`$false -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path `$RegPath -Name 'BitLockerResuspendCount' -ErrorAction SilentlyContinue
        Remove-Item -Path `$ScriptPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-Log "Will retry on next boot (attempt `$FailCount of `$MaxResuspensions)."
    }
}
"@

        # Write the resume script to $ITFolder\Scripts (inherits IT folder permissions)
        New-Item -Path (Split-Path $ScriptPath) -ItemType Directory -Force -ErrorAction Stop | Out-Null
        $ResumeScript | Out-File -FilePath $ScriptPath -Encoding UTF8 -Force -ErrorAction Stop

        # Create a scheduled task that runs at startup (before logon) to check and resume BitLocker
        $TaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`"" -ErrorAction Stop
        $TaskTrigger = New-ScheduledTaskTrigger -AtStartup -ErrorAction Stop
        $TaskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest -ErrorAction Stop
        $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ErrorAction Stop

        Register-ScheduledTask -TaskName 'MauleTech-ResumeBitLocker' -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskPrincipal -Settings $TaskSettings -Description 'Resumes BitLocker after safe restart once all pending reboots are complete' -Force -ErrorAction Stop | Out-Null

        Write-Host "BitLocker suspended. Scheduled task created to resume after all reboots complete."

        } catch {
            # Any failure after Suspend-BitLocker (registry, ACL, script write, task registration) — roll back
            Write-Warning "Failed to set up BitLocker resume task: $_"
            Write-Warning "Rolling back BitLocker suspension and aborting restart."
            try {
                Resume-BitLocker -MountPoint C: -ErrorAction Stop
            } catch {
                Write-Warning "CRITICAL: Failed to roll back BitLocker suspension: $_"
                Write-Warning "BitLocker is suspended with no resume task. Run 'Resume-BitLocker -MountPoint C:' manually."
            }
            return
        }
    } elseif ($Volume) {
        Write-Host "BitLocker is not enabled or already suspended."
    }

    # Send notification to users if there's a delay
    if ($Delay -gt 0) {
        $Message = "SYSTEM RESTART: This computer will restart in $Delay seconds. Please save your work immediately."
        if (Get-Command msg -ErrorAction SilentlyContinue) {
            msg * $Message 2>$null
            Write-Host "User notification sent."
        } else {
            Write-Host "msg.exe not available on this system. User notification skipped."
        }

        Write-Host "Restarting in $Delay seconds..."
        Start-Sleep -Seconds $Delay
    }

    try {
        if ($Force) {
            Restart-Computer -Force -ErrorAction Stop
        } else {
            Restart-Computer -ErrorAction Stop
        }
    } catch {
        Write-Warning "Failed to restart computer: $_"
        if ($Volume -and $Volume.ProtectionStatus -eq 'On') {
            Write-Warning "BitLocker has been suspended and a resume task is registered."
            Write-Warning "Either restart manually or run 'Resume-BitLocker -MountPoint C:' to re-enable protection."
        }
    }
}

Function Restart-VSSWriter {
	[CmdletBinding()]

	Param (
		[Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Mandatory = $True)]
		[String[]]
		$Name
	) #Param

	BEGIN { Write-Verbose "BEGIN: Restart-KPVSSWriter"} #BEGIN

	PROCESS {

		Write-Verbose "Working on VSS Writer: $Name"

		Switch ($Name) {
			'ASR Writer' { $Service = 'VSS' }
			'BITS Writer' { $Service = 'BITS' }
			'Certificate Authority' { $Service = 'EventSystem' }
			'COM+ REGDB Writer' { $Service = 'VSS' }
			'DFS Replication service writer' { $Service = 'DFSR' }
			'DHCP Jet Writer' { $Service = 'DHCPServer' }
			'FRS Writer' { $Service = 'NtFrs' }
			'FSRM writer' { $Service = 'srmsvc' }
			'IIS Config Writer' { $Service = 'AppHostSvc' }
			'IIS Metabase Writer' { $Service = 'IISADMIN' }
			'Microsoft Exchange Replica Writer' { $Service = 'MSExchangeRepl' }
			'Microsoft Exchange Writer' { $Service = 'MSExchangeIS' }
			'Microsoft Hyper-V VSS Writer' { $Service = 'vmms' }
			'MSMQ Writer (MSMQ)' { $Service = 'MSMQ' }
			'MSSearch Service Writer' { $Service = 'WSearch' }
			'NPS VSS Writer' { $Service = 'EventSystem' }
			'NTDS' { $Service = 'NTDS' }
			'OSearch VSS Writer' { $Service = 'OSearch' }
			'OSearch14 VSS Writer' { $Service = 'OSearch14' }
			'Registry Writer' { $Service = 'VSS' }
			'Shadow Copy Optimization Writer' { $Service = 'VSS' }
			'SMS Writer' { $Service = 'SMS_SITE_VSS_WRITER' }
			'SPSearch VSS Writer' { $Service = 'SPSearch' }
			'SPSearch4 VSS Writer' { $Service = 'SPSearch4' }
			'SqlServerWriter' { $Service = 'SQLWriter' }
			'System Writer' { $Service = 'CryptSvc' }
			'TermServLicensing' { $Service = 'TermServLicensing' }
			'WDS VSS Writer' { $Service = 'WDSServer' }
			'WIDWriter' { $Service = 'WIDWriter' }
			'WINS Jet Writer' { $Service = 'WINS' }
			'WMI Writer' { $Service = 'Winmgmt' }
			default {$Null = $Service}
		} #Switch

		IF ($Service) {
			Write-Verbose "Found matching service"
			$S = Get-Service -Name $Service
			Write-Host "Restarting service $(($S).DisplayName)"
			$S | Restart-Service -Force
		}
		ELSE {
			Write-Warning "No service associated with VSS Writer: $Name"
		}
	} #PROCESS
	END { } #END
}

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAGbb9KT5OFxZam
# IIDICA+V6ctcBmzqdP7DCAdFBPZ3NKCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IFc2NIUSqx/4Ru7V3JgU77YcueY8gOH2uNdVqxmlkIhqMA0GCSqGSIb3DQEBAQUA
# BIICACi6i8mCV/6wHyX44yOXtBmz8yY7yrORdCQa2LQYcBYjlUM5VfdIkSGfBjme
# 3NF/YbAxKAK6xhsb6QRw0hiqM8Sj6WeSXJ4ZvnkoEvHU5ndR/RuL4nPP413DSuxP
# 3bO3P5djolNOlwfngh9CJi1LVQjc9U51x79TmToscFb0NGdHrp9FQXsUd0kY5hJa
# cXBd/eRMiq9qIZk3k+zJ8PdKnZ1yMyN949nBj49tknZfgCKi5P01MRxAcpCrOFzz
# T96MoFm09mLZoDmMhalB0Jx0uYhqeO6U7B/GGveH5ApdRK/sAec/4A+lcOP+hKuA
# nXOloOMz1TCCz49+/1qz5hITPKaKmZ9rMit3BxIYiMYvHSihRFdw3aolJsMKR7SY
# 6cSfq12/5ZCxmSS13bF/Sw4lq0K2qsxAcUHYGF/r+ZaV6B9IdAA+f4nn8XEw6CYE
# 2n/Z5xRKk0EfNui64dakEvDlJRhED6AUQ+Y5la7oCp0E417N7PvyTxlYOWA2hbBv
# bYhfdkO8LI7KnH7lwmUTYDVlgbO4/G6kDtdf1Ovfj5sbEVCexhWcgErwW3+Bb9jM
# UF1PMqdaoSr4O966i+ffoN4Rshf8M+DFNMF+wbDbTiZHlAgQiBcepqaqmNnkTOQ5
# /TPeECyz7tIQFASvLoggpLt9Vb2e57NT5+NHd/MLa/QTtkkQoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDQxMDIyMTIzMVowLwYJKoZIhvcNAQkEMSIEIO76mD4Q
# sVb4yUBnTVsa53MICSuKyINP/ov3t9MQFYUPMA0GCSqGSIb3DQEBAQUABIICAGU1
# /2p7h3e4E63paLgK2ket4bCOhUmXiqOO3JVEgUmfbUO/3iIG/79fZe9fNRNf5ZmU
# dJmqQZ346BDfg47DAq3WaeGoYmb5yEI82ZVcTBUgpV9T49fCfY0QeyrDBHenI2pr
# VCO5Ymh7dgwJdAiHhnmRq7ZrA3RcxuXs8mfALTMw/b49+FlqOp0a+YntoDdfsxjS
# M9sP30oP3KsJ5cN7mttMYpeWD1+sbscyxkzOrmm4UEEDQRte7IAAnfnv1IL1ri9T
# e28DzuGpJBuVTt+uykun9q1MJT3WtQYMZW0/qWHwuzBPw0zvVvMvIzZT7omv4BYu
# B0DQUOiI7P2laTiXxn7PXWrc+icemKUdPjWYZSg3OM4PlP/jm53rEMI5IpSaOaXJ
# UGbqMB9biPHz2dOUlOjSXKSjQsAKCAgl1vTWFf/QoA/zFNf4kcRU4JnwWw1Yn8Bx
# Fmm+gCLXi6s2RST/rpHLM3lK1VGEhEhb51UYYIQa7JxCE2Ph8BLX4TQPfornlnD6
# qBiThw6sFyR5znXFTkMiZYm/KZvDehLcW/eW7TkCJ1yERMNtAy/lHoJyiw8W9qlb
# /etwtziTU37KfCtrbDOAoIJ0WNGaHnNgzgJSPr5K/0HCO7SLgEsbWY8g9GOZSn3i
# l9kfPv+do5ZC4VTQIlM6un0wBF+wSSjlxbnn0Mw2
# SIG # End signature block
