Function Optimize-Powershell {
	If ((Get-ExecutionPolicy -Scope CurrentUser) -ne 'RemoteSigned') {
    	Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction SilentlyContinue
	}
	$Commands = @()
		$Commands = @'
		$profileTimer = [System.Diagnostics.Stopwatch]::StartNew()
		$stepTimer = [System.Diagnostics.Stopwatch]::New()
		$profileTimings = [System.Collections.Generic.List[string]]::new()

		Function Get-HorizontalLine {
			param (
				[string]$InputString = "-",
				[parameter(Mandatory = $false)][alias("c")]$Count = 1,
				[parameter(Mandatory = $false)][alias("fg")]$ForeColor=$null,
				[parameter(Mandatory = $false)][alias("bg")]$BackColor=$null
			)
			$ColorSplat = @{}
			if ($ForeColor -ne $null) { $ColorSplat.ForegroundColor = $ForeColor }
			if ($BackColor -ne $null) { $ColorSplat.BackgroundColor = $BackColor }

			# How long to make the hr
			$width = if ($host.Name -match "ISE") {
				$host.UI.RawUI.BufferSize.Width - 1
			} else {
				$host.UI.RawUI.BufferSize.Width - 4
			}
			# How many times to repeat $Character in full
			$repetitions = [System.Math]::Floor($width/$InputString.Length)
			# How many characters of $InputString to add to fill each line
			$remainder = $width - ($InputString.Length * $repetitions)
			# Make line(s)
			1..$Count | % {
				Write-Host ($InputString * $repetitions) + $InputString.Substring(0,$remainder) @ColorSplat
			}
		}
		# Custom prompt function
		Function prompt {
		    $curdir = $ExecutionContext.SessionState.Path.CurrentLocation
		    if ($curdir.Path.Length -eq 0) {
		        $curdir = "$($ExecutionContext.SessionState.Drive.Current.Name):\"
		    }

		    Get-HorizontalLine -ForeColor Cyan
			Write-Host "| " -NoNewLine -BackgroundColor Black -ForegroundColor Cyan
		    Write-Host "$env:USERNAME/$env:COMPUTERNAME" -NoNewLine -BackgroundColor Black -ForegroundColor DarkCyan
			Write-Host " | " -NoNewLine -BackgroundColor Black -ForegroundColor Cyan
			Write-Host "$(Get-Date -Format 'yyyy-MM-dd') $((Get-Date).ToString("HH:mm:ss"))" -NoNewLine -BackgroundColor Black -ForegroundColor Magenta
			Write-Host " |" -BackgroundColor Black -ForegroundColor Cyan
			Write-Host "| " -NoNewLine -BackgroundColor Black -ForegroundColor Cyan
			Write-Host "DIR: $($curdir.Path)" -BackgroundColor Black -ForegroundColor Yellow
		    "[Command]: "
		}

		# Module installation and configuration
		$ErrorActionPreference = 'SilentlyContinue'

		# Try importing AdvancedHistory directly (skip slow Get-Module -ListAvailable check)
		$stepTimer.Restart()
		$advHistoryLoaded = $false
		try {
		    Import-Module AdvancedHistory -Force -ErrorAction Stop
		    $advHistoryLoaded = $true
		} catch {
		    # Module not installed - need PackageManagement for install
		    if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
		        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force | Out-Null
		    }
		    if ((Get-PSRepository -Name "PSGallery").InstallationPolicy -eq "Untrusted") {
		        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
		    }
		    try {
		        Install-Module AdvancedHistory -Force -AllowClobber
		        Import-Module AdvancedHistory -Force -ErrorAction Stop
		        $advHistoryLoaded = $true
		    } catch {}
		}
		if ($advHistoryLoaded) {
		    try { Enable-AdvancedHistory -Unique } catch {}
		}
		$profileTimings.Add("AdvancedHistory: $("{0:N0}ms" -f $stepTimer.Elapsed.TotalMilliseconds)")

		# Try importing PSReadLine directly (skip slow Get-Module -ListAvailable check)
		$stepTimer.Restart()
		$psrlLoaded = $false
		try {
		    Import-Module PSReadline -Force -ErrorAction Stop
		    $psrlLoaded = $true
		} catch {
		    # Module not installed - ensure PackageManagement is ready
		    if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
		        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force | Out-Null
		    }
		    if ((Get-PSRepository -Name "PSGallery").InstallationPolicy -eq "Untrusted") {
		        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
		    }
		    try {
		        Install-Module PSReadline -Force -AllowClobber
		        Import-Module PSReadline -Force -ErrorAction Stop
		        $psrlLoaded = $true
		    } catch {}
		}
		$profileTimings.Add("PSReadLine: $("{0:N0}ms" -f $stepTimer.Elapsed.TotalMilliseconds)")

		# Configure PSReadLine prediction source
		if ($psrlLoaded) {
		    try {
		        Set-PSReadLineOption -PredictionSource HistoryAndPlugin
		    } catch {
		        try {
		            Set-PSReadLineOption -PredictionSource History
		        } catch {
		            Set-PSReadLineOption -PredictionSource None
		        }
		    }
		}

		# Execute additional configurations
		$stepTimer.Restart()
		irm https://raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt | iex
		$profileTimings.Add("LoadFunctions: $("{0:N0}ms" -f $stepTimer.Elapsed.TotalMilliseconds)")

		if ($PSScriptRoot -notlike "C:\Program Files (x86)\ITSPlatform\tmp\scripting\*") {
		    Expand-Terminal
		}

		$profileTimer.Stop()
		Write-Host " Profile loaded in $("{0:N1}s" -f $profileTimer.Elapsed.TotalSeconds) [$($profileTimings -join ' | ')]" -ForegroundColor DarkGray
'@

	$WinVer = [System.Environment]::OSVersion.Version.Major

	If ($WinVer -ge 10) {

		If((Test-Path -LiteralPath "HKCU:\Console") -ne $true) {  New-Item "HKCU:\Console" -force -ea SilentlyContinue }
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CurrentPage' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'PopupColors' -Value 245 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'InsertMode' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'QuickEdit' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'ScreenBufferSize' -Value 7864440 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'WindowSize' -Value 3932280 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FontSize' -Value 917504 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FontFamily' -Value 54 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FontWeight' -Value 400 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FaceName' -Value 'Lucida Console' -PropertyType String -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CursorSize' -Value 25 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'HistoryBufferSize' -Value 25 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'NumberOfHistoryBuffers' -Value 4 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'HistoryNoDup' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'LineWrap' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FilterOnPaste' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CtrlKeyShortcutsDisabled' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'LineSelection' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'WindowAlpha' -Value 255 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'ForceV2' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'ExtendedEditKey' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CursorType' -Value 3 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CursorColor' -Value -1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'InterceptCopyPaste' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'TerminalScrolling' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'DefaultForeground' -Value -1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'DefaultBackground' -Value -1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'WindowPosition' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		#Write-Output "Windows 10"
	} Else {

		if((Test-Path -LiteralPath "HKCU:\Console") -ne $true) {  New-Item "HKCU:\Console" -force -ea SilentlyContinue }
	if((Test-Path -LiteralPath "HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe") -ne $true) {  New-Item "HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe" -force -ea SilentlyContinue };
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CurrentPage' -Value 2 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'ForceV2' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'ExtendedEditKey' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'PopupColors' -Value 245 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'InsertMode' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'QuickEdit' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'ScreenBufferSize' -Value 327680120 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'WindowSize' -Value 3932280 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FontSize' -Value 786432 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FontFamily' -Value 54 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FontWeight' -Value 400 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FaceName' -Value 'Lucida Console' -PropertyType String -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CursorSize' -Value 25 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'HistoryBufferSize' -Value 25 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'NumberOfHistoryBuffers' -Value 4 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'HistoryNoDup' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'LineWrap' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FilterOnPaste' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CtrlKeyShortcutsDisabled' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'LineSelection' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'WindowAlpha' -Value 255 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CursorType' -Value 3 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CursorColor' -Value -1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'InterceptCopyPaste' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'TerminalScrolling' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'DefaultForeground' -Value -1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'DefaultBackground' -Value -1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'WindowPosition' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe' -Name 'ScreenBufferSize' -Value 671088790 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe' -Name 'FaceName' -Value 'Lucida Console' -PropertyType String -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe' -Name 'HistoryNoDup' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe' -Name 'WindowSize' -Value 3932310 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe' -Name 'FontSize' -Value 786439 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	Write-Output "Not Windows 10"
	}

	If (-Not (Test-Path $PROFILE -EA SilentlyContinue)) {
		New-Item -Type File -Force $PROFILE
	} Else {
		Remove-Item -Path $PROFILE -Force -EA SilentlyContinue
		New-Item -Type File -Force $PROFILE
	}

	$Commands | Out-File -FilePath $Profile -Force

	If ($PSVersionTable.PSEdition -like "Desktop") {
		Start-Process C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ArgumentList "-NoExit -Mta"
	} Else {
		Start-Process 'pwsh.exe' -ArgumentList "-NoExit -Mta"
	}
}

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCxmeDZ/b7LQnYm
# l9uIe8klPJAvFenYcT8YOlygCkdQj6CCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# ILUgNVP48pykWMOc7f3hAdIGOG2yHxUGB2elLUvYVySxMA0GCSqGSIb3DQEBAQUA
# BIICAIRWkA5FMlgh3XZ8VRvSzDzS5RvxK1OQF9pft7bcZlpQGiPTGzCwZVUqQrVi
# jc/dJTj9YOeAAdSyh0v8Zu/qPUlDwDVUFSOe48tlXVvi9NGrjCXM1gYe9Cp1tfMa
# tw1DCsD5zchqCqkOld8nTzCOJ+Wq4lABpZqerB9/SJzh/FYEutwQyLdoLX554iOM
# +SrKrRzpw9jr3rCdFCGohjbvjo+xrF8r6D1XixaKqVJi7QJKRSLyBFaxI0EpbO23
# e1UCXMXlCGpOxa8C1DmC3BvY0w9pztzvlqzIcwZguZXo3rN//SHVfqCFCfU6CbaD
# iIQDq5iJyAPiu1XLWjxn0xv+JPs6wsmkRNqJoqEyhgIQjKevq0wR0o/9nkIeEHK5
# 4+oPgJTMIzo5lzGQkflrTg/hHBJs+f1zu4bSt6PAq1/4yafA40CmrD4/DYYsKFoE
# tgrSDxOoPI+8FhKkjhwKzGRb47Gi2MgTsY32wRZwXMRJ25SsJsXhIndw3tIep+iP
# 8KUwgVG7TGUR5prShdfeRwLP/DKVHdQ1dm6a0EsKRkmvwdglwZSbAVau2d6gV3hF
# kx9RhNjpxD2WAfgq1lipQKQ9zMkCnTNpXxRnufV9Q8H2x9G0gpzm2j4TXi+IPoI0
# I2FPn6S0PM2E/BoJJUxWyYZeKsyMdSTURenROMKJpPXrSREYoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDQwNjE1MTU1N1owLwYJKoZIhvcNAQkEMSIEIAwA1Fek
# XV+/TkiycN6vOqSmbL0eEwTLYrRcjfEy7DpVMA0GCSqGSIb3DQEBAQUABIICAERt
# ZNCJyl1CeVDRURp3UQbFrGjt1w9DnmVDjQxWBhQARya0A5y1CRySTwBCZWZughJS
# dyfjkDYQhIRoasB9NAOeFZ16hF4SOOucGYFLKOIdN++hpFFltb9ONcwwvA92wxsw
# 1VTZGtJgUwDskb72+JMZl8Jdtiz5tyt6ueYQ8ZG6Qx90v9wyoQ1zWZiG3Ku+QEZ9
# efwW1NJghFJ9HgR427r0xz9KJtiuNRLSZA/3iYE/gP+EkwukCPZ8PDp2db71JkAY
# /xUZH8bNJlAQ5I4V4SnC7ro+UjGohQq4zXvLnEUH750m5xXWhbrTR4XCDFnub1nM
# 0UTpPf45WXdylcaCeHK4WlQwIxTD4hhjkGanzJD7HMWeq24l2i8rTMdKBGokDScQ
# +l9ipNRJ5IaNPGKeP6ITplS7X9YWfbgzYjfIHsk04eg8hYYFagEbTaAJItJ0Ls+i
# NrO7tqXaEWsYVACqcqh/YhCQKPo+3oEInhLArFk/NgI+mSwqJtguqou4N9UWEsal
# UuX7dtSVXmwetN8pBhtM7wvHlB2B8lwngT8lLzBmS39J+54a3eKc2IMLWH7K6+Ng
# URh/Mtqb9hqJ14VxvqJr8qAaXmC5bZjayQOxeSeApebJyaTzf6TDZgc1SBvc0Bg4
# 7dEtvwGibGa27K+MyKrv6cFxcAMdIdvUynakiDyU
# SIG # End signature block
