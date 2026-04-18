Function Start-BackstageBrowser {
	# Define the URL for the Pale Moon x64 standalone version (self-extracting)
	#$downloadUrl = "https://www.palemoon.org/download.php?mirror=us&bits=64&type=portable" ##64bit broke for some reason.
	$downloadUrl = "https://www.palemoon.org/download.php?mirror=us&bits=32&type=portable"
	# Define the paths
	$downloadPath = "$ITFolder\PaleMoon\Palemoon-Portable-SFX.exe"
	$extractPath = "$ITFolder\PaleMoon"
	$argumentList = "-o" + $extractPath + " -y"
	$executablePath = "$ITFolder\PaleMoon\Palemoon-Portable.exe"

	# Function to download and extract Pale Moon
	function DownloadAndExtractPaleMoon {
		# Create the destination directory if it does not exist
		if (-Not (Test-Path -Path $extractPath)) {
			New-Item -Path $extractPath -ItemType Directory
		}

		# Download the Pale Moon self-extracting executable
		Get-FileDownload -URL $downloadUrl -SaveToFolder $extractPath -FileName "Palemoon-Portable-SFX.exe"

		# Extract the self-extracting executable using 7-Zip arguments
		Start-Process -FilePath $downloadPath -ArgumentList $argumentList -Wait
	}

	# Check if the executable exists
	if (-Not (Test-Path -Path $executablePath)) {
		DownloadAndExtractPaleMoon
	}

	# Launch Pale Moon Portable
	Start-Process -FilePath $executablePath
	Start-Sleep 1
	If (-not (Get-Process -ProcessName Palemoon-Portable -ErrorAction SilentlyContinue)) {
		Write-Host "Corrupt browser detected, repairing."
		DownloadAndExtractPaleMoon
		Start-Process -FilePath $executablePath
	}
}

function Start-ClaudeCode {
	<#
	.SYNOPSIS
		Launches Claude Code, installing or updating if needed.
	.DESCRIPTION
		Smart launcher for Claude Code:
		- Installs if not present (requires admin)
		- Checks for updates and prompts to update
		- Launches Claude Code

		Browser will open for authentication if not logged in.
	.PARAMETER SkipUpdateCheck
		Skip the update check and launch immediately.
	.PARAMETER NoLaunch
		Install/update only, don't launch Claude Code.
	.EXAMPLE
		Start-ClaudeCode
	.EXAMPLE
		Start-ClaudeCode -SkipUpdateCheck
	.NOTES
		When done, run Remove-ClaudeCode to logout from this machine.
	#>
	[CmdletBinding()]
	param(
		[switch]$SkipUpdateCheck,
		[switch]$NoLaunch
	)

	# Paths
	if (-not $Global:ITFolder) { $Global:ITFolder = "$env:SystemDrive\IT" }
	$ClaudeFolder = "$Global:ITFolder\ClaudeCode"
	$ClaudeExe = "$ClaudeFolder\claude.exe"

	# Check if installed
	if (-not (Test-Path $ClaudeExe)) {
		Write-Host "`nClaude Code is not installed." -ForegroundColor Yellow

		# Check admin
		$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
		$principal = New-Object Security.Principal.WindowsPrincipal($identity)
		if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
			Write-Host "[!] Administrator privileges required to install." -ForegroundColor Red
			Write-Host "    Run PowerShell as Administrator and try again." -ForegroundColor Yellow
			return
		}

		$install = Read-Host "Install Claude Code now? (Y/N)"
		if ($install -eq "Y" -or $install -eq "y") {
			$result = Install-ClaudeCode
			if (-not $result) {
				Write-Host "[!] Installation failed." -ForegroundColor Red
				return
			}
		} else {
			return
		}
	}

	# Ensure in PATH
	if ($env:Path -notlike "*$ClaudeFolder*") { $env:Path = "$env:Path;$ClaudeFolder" }

	# Check for updates (unless skipped)
	if (-not $SkipUpdateCheck) {
		Write-Host "Checking for updates..." -ForegroundColor Gray

		$CurrentVersion = $null
		$LatestVersion = $null

		try {
			$CurrentVersion = (& $ClaudeExe --version 2>$null).Trim()
		} catch { }

		try {
			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
			$npmInfo = Invoke-RestMethod -Uri "https://registry.npmjs.org/@anthropic-ai/claude-code/latest" -UseBasicParsing -ErrorAction SilentlyContinue -TimeoutSec 5
			if ($npmInfo.version) { $LatestVersion = $npmInfo.version }
		} catch { }

		if ($CurrentVersion -and $LatestVersion -and $CurrentVersion -ne $LatestVersion) {
			Write-Host "Update available: $CurrentVersion -> $LatestVersion" -ForegroundColor Yellow

			# Check admin for update
			$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
			$principal = New-Object Security.Principal.WindowsPrincipal($identity)
			if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
				$update = Read-Host "Update now? (Y/N)"
				if ($update -eq "Y" -or $update -eq "y") {
					Update-ClaudeCode -Force
				}
			} else {
				Write-Host "Run as Administrator to update." -ForegroundColor Gray
			}
		} elseif ($CurrentVersion) {
			Write-Host "Claude Code is up to date ($CurrentVersion)" -ForegroundColor Green
		}
	}

	# Launch
	if (-not $NoLaunch) {
		Write-Host "`nLaunching Claude Code..." -ForegroundColor Cyan
		Write-Host "Browser will open for authentication if not logged in." -ForegroundColor Gray
		Write-Host "When done, run: Remove-ClaudeCode" -ForegroundColor Yellow
		Write-Host ""

		& $ClaudeExe
	}
}

Function Start-CleanupOfSystemDrive {
	Invoke-RestMethod 'https://raw.githubusercontent.com/MauleTech/PWSH/master/OneOffs/Clean%20up%20Drive%20Space.ps1' | Invoke-Expression
}

Function Start-ImperialMarch {
	[console]::beep(440,500)
	[console]::beep(440,500)
	[console]::beep(440,500)
	[console]::beep(349,350)
	[console]::beep(523,150)
	[console]::beep(440,500)
	[console]::beep(349,350)
	[console]::beep(523,150)
	[console]::beep(440,1000)
	[console]::beep(659,500)
	[console]::beep(659,500)
	[console]::beep(659,500)
	[console]::beep(698,350)
	[console]::beep(523,150)
	[console]::beep(415,500)
	[console]::beep(349,350)
	[console]::beep(523,150)
	[console]::beep(440,1000)
	[console]::beep(880,500)
	[console]::beep(440,350)
	[console]::beep(440,150)
	[console]::beep(880,500)
	[console]::beep(830,250)
	[console]::beep(784,250)
	[console]::beep(740,125)
	[console]::beep(698,125)
	[console]::beep(740,250)
	[console]::beep(455,250)
	[console]::beep(622,500)
	[console]::beep(587,250)
	[console]::beep(554,250)
	[console]::beep(523,125)
	[console]::beep(466,125)
	[console]::beep(523,250)
	[console]::beep(349,125)
	[console]::beep(415,500)
	[console]::beep(349,375)
	[console]::beep(440,125)
	[console]::beep(523,500)
	[console]::beep(440,375)
	[console]::beep(523,125)
	[console]::beep(659,1000)
	[console]::beep(880,500)
	[console]::beep(440,350)
	[console]::beep(440,150)
	[console]::beep(880,500)
	[console]::beep(830,250)
	[console]::beep(784,250)
	[console]::beep(740,125)
	[console]::beep(698,125)
	[console]::beep(740,250)
	[console]::beep(455,250)
	[console]::beep(622,500)
	[console]::beep(587,250)
	[console]::beep(554,250)
	[console]::beep(523,125)
	[console]::beep(466,125)
	[console]::beep(523,250)
	[console]::beep(349,250)
	[console]::beep(415,500)
	[console]::beep(349,375)
	[console]::beep(523,125)
	[console]::beep(440,500)
	[console]::beep(349,375)
	[console]::beep(261,125)
	[console]::beep(440,1000)
	$i = 40
	do {
		$T = $i + $(Get-Random -Minimum -2 -Maximum 500)

		[console]::beep($T,$(Get-Random -Minimum 500 -Maximum 1500))
		$i = $i+$(Get-Random -Minimum -20 -Maximum 50)
	} until ($i -gt 576)
}

Function Start-PPKGLog ([String] $LogLabel) {
	Write-Host "Making a log file for debugging"
		$LogPath = "$ITFolder\Logs\" + $SiteCode + "-" + $LogLabel + ".log"
		Start-Transcript -path $LogPath -Force -Append
}

Function Start-PSWinGet {
<#
	.SYNOPSIS
		Allows Winget to be run as system or on servers.
	.LINK
		https://github.com/microsoft/winget-cli
	.PARAMETER Command
		Useful for deployments. If you have a prebuilt Install-WinGetPackage, Uninstall-WinGetPackage, or Update-WinGetPackage command, you can pass it along in RMM.
	.EXAMPLE
		Start-PSWinGet will install any prerequisites and launch Powershell Core with multithreading, then give a list of useful commands.
	.EXAMPLE
		Start-PSWinget -Command 'Uninstall-WinGetPackage "Notepad++"' will install prerequisites, launch Powershell Core, then uninstall Notepad++.
#>
	param
	(
		[Parameter(Mandatory = $false)]
		[String] $Command
	)
	
	#Baseline install and run
	$ScriptBlock = 'irm raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt | iex ; '
	If ($Command) {	$ScriptBlock = $ScriptBlock + $Command }
	
	#Running as Powershell 5, need to switch to core
	If ($PSEdition -eq "Desktop") {
		Install-Choco | Out-Null
		Update-pwsh
		Update-PowerShellModule -ModuleName Microsoft.WinGet.Client

			
		If ($PSSCriptRoot) { #If running as a script, exit after done.
			pwsh.exe -MTA -Command $ScriptBlock
		} Else { #If not running as a script, let tech continue in powershell core. Look for the -NoExit
			
			#Give a human some friendly prompts if they haven't given an already composed command.
			If (-not $Command) {
				$CoreWarning = '"You are now running powershell core.`nPS Winget Commands available:"'
				$ScriptBlock = $ScriptBlock + "Write-Warning 'You are now running powershell core. | PS Winget Commands available:';(Get-Command '*-wingetpackage').Name"
			}
			pwsh.exe -MTA -NoExit -Command $ScriptBlock
		}
		
	} Else { #Already running as pwsh Core
		Update-PowerShellModule -ModuleName Microsoft.WinGet.Client
		Invoke-Expression $ScriptBlock
		
		#Give a human some friendly prompts if they haven't given an already composed command.
		If (-not $PSSCriptRoot) {
			Write-Host "PS Winget Commands available:"
			(Get-Command "*-wingetpackage").Name
		}
	}
}

Function Start-ServerMaintenance {
	If ($PSVersionTable.PSEdition -eq "Desktop") {
		If (-Not (Get-Command "pwsh" -ErrorAction SilentlyContinue)) { Update-PWSH }
		pwsh -Command {(Invoke-WebRequest https://raw.githubusercontent.com/MauleTech/PWSH/master/Scripts/Maintenance-Checks/Server-Maintenance-Checks.txt -UseBasicParsing).Content | Invoke-Expression}
	} Else {
		(Invoke-WebRequest https://raw.githubusercontent.com/MauleTech/PWSH/master/Scripts/Maintenance-Checks/Server-Maintenance-Checks.txt -UseBasicParsing).Content | Invoke-Expression
	}
}

Function Start-PSTaskManager {
<#
	.SYNOPSIS
		Installs and launches pstop, a terminal-based task manager for Windows.
	.DESCRIPTION
		Checks if pstop is already installed and runs it. If not installed, attempts
		installation via winget, Start-PSWinGet (for SYSTEM context), Chocolatey, or
		direct download from GitHub releases as a fallback.

		WARNING: This function downloads and runs third-party software (pstop by psmux).
		Only run this if you trust the source. Use -Force to skip the disclaimer prompt.
	.PARAMETER Force
		Bypasses the disclaimer prompt and proceeds with install/run automatically.
	.LINK
		https://github.com/psmux/pstop
	.EXAMPLE
		Start-PSTaskManager
		Prompts for confirmation, then installs (if needed) and launches pstop.
	.EXAMPLE
		Start-PSTaskManager -Force
		Skips the disclaimer and installs/runs pstop immediately.
#>
	param (
		[Switch] $Force
	)

	# --- Disclaimer ---
	If (-not $Force) {
		Write-Host ""
		Write-Host "  DISCLAIMER: pstop is third-party software not maintained by MauleTech." -ForegroundColor Yellow
		Write-Host "  Source: https://github.com/psmux/pstop" -ForegroundColor Yellow
		Write-Host "  Only proceed if you trust this software and its source." -ForegroundColor Yellow
		Write-Host ""
		$Confirm = Read-Host "  Type 'yes' to continue, or press Enter to cancel"
		If ($Confirm -ne 'yes') {
			Write-Host "Cancelled." -ForegroundColor Gray
			Return
		}
	}

	# --- Check if already installed ---
	$PstopCmd = Get-Command pstop -ErrorAction SilentlyContinue
	If ($PstopCmd) {
		Write-Host "[OK] pstop found at $($PstopCmd.Source). Launching..." -ForegroundColor Green
		& pstop
		Return
	}

	# Check for pstop in $ITFolder\Downloads (manual/zip installs)
	If ($ITFolder -and (Test-Path "$ITFolder\Downloads\pstop\pstop.exe")) {
		Write-Host "[OK] pstop found in ITFolder. Launching..." -ForegroundColor Green
		& "$ITFolder\Downloads\pstop\pstop.exe"
		Return
	}

	Write-Host "pstop not found. Attempting installation..." -ForegroundColor Cyan

	# Reused launch logic - avoids duplicating the PATH-vs-ITFolder decision
	$LaunchPstop = {
		$Cmd = Get-Command pstop -ErrorAction SilentlyContinue
		If ($Cmd) {
			Write-Host "[OK] Launching pstop..." -ForegroundColor Green
			& pstop
		} ElseIf ($ITFolder -and (Test-Path "$ITFolder\Downloads\pstop\pstop.exe")) {
			Write-Host "[OK] Launching pstop from ITFolder..." -ForegroundColor Green
			& "$ITFolder\Downloads\pstop\pstop.exe"
		} Else {
			Write-Warning "Installation reported success but pstop.exe could not be located. Check your PATH or $ITFolder\Downloads\pstop."
		}
	}

	$Installed    = $false
	$IsSystem     = $(whoami) -eq "nt authority\system"
	$WingetAvail  = [bool](Get-Command winget -ErrorAction SilentlyContinue)

	If (-not $IsSystem -and $WingetAvail) {
		Write-Host "[1/4] Trying winget..." -ForegroundColor Cyan
		Try {
			Invoke-WinGetInstall -Id marlocarlo.pstop
			# winget modifies PATH but the current session doesn't see it yet - refresh before checking
			$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
			If (Get-Command pstop -ErrorAction SilentlyContinue) { $Installed = $true }
		} Catch {
			Write-Warning "winget install failed: $_"
		}
	}

	If (-not $Installed -and ($IsSystem -or -not $WingetAvail)) {
		Write-Host "[2/4] Running as SYSTEM or winget unavailable. Trying Start-PSWinGet..." -ForegroundColor Cyan
		Try {
			Start-PSWinGet -Command 'Install-WinGetPackage "marlocarlo.pstop"'
			If (Get-Command pstop -ErrorAction SilentlyContinue) { $Installed = $true }
			If ($ITFolder -and (Test-Path "$ITFolder\Downloads\pstop\pstop.exe")) { $Installed = $true }
		} Catch {
			Write-Warning "Start-PSWinGet failed: $_"
		}
	}

	If (-not $Installed) {
		Write-Host "[3/4] Trying Chocolatey..." -ForegroundColor Cyan
		Try {
			If (-not (Get-Command choco -ErrorAction SilentlyContinue)) { Install-Choco }
			choco install pstop -y
			If (Get-Command pstop -ErrorAction SilentlyContinue) { $Installed = $true }
		} Catch {
			Write-Warning "Chocolatey install failed: $_"
		}
	}

	If (-not $Installed) {
		Write-Host "[4/4] Falling back to direct GitHub download..." -ForegroundColor Cyan
		Try {
			$Release  = Invoke-RestMethod -Uri "https://api.github.com/repos/psmux/pstop/releases/latest" -UseBasicParsing
			$ZipAsset = $Release.assets | Where-Object { $_.name -like "*windows*x86_64*.zip" -or $_.name -like "*win*.zip" } | Select-Object -First 1
			If (-not $ZipAsset) {
				$ZipAsset = $Release.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1
			}

			If (-not $ZipAsset) {
				Write-Error "Could not find a zip asset in the latest pstop release. Please install manually: https://github.com/psmux/pstop/releases"
				Return
			}

			$DestFolder = "$ITFolder\Downloads\pstop"
			$ZipPath    = "$DestFolder\pstop.zip"

			New-Item -ItemType Directory -Force -Path $DestFolder | Out-Null

			Write-Host "  Downloading $($ZipAsset.name) from GitHub..." -ForegroundColor Gray
			Invoke-WebRequest -Uri $ZipAsset.browser_download_url -OutFile $ZipPath -UseBasicParsing

			Expand-Archive -Path $ZipPath -DestinationPath $DestFolder -Force
			Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue

			$PstopExe = Get-ChildItem -Path $DestFolder -Recurse -Filter "pstop.exe" | Select-Object -First 1
			If ($PstopExe) {
				If ($PstopExe.DirectoryName -ne $DestFolder) {
					Move-Item -Path $PstopExe.FullName -Destination "$DestFolder\pstop.exe" -Force
				}
				$Installed = $true
			} Else {
				Write-Error "pstop.exe not found after extraction. Check $DestFolder manually."
				Return
			}
		} Catch {
			Write-Error "Direct download failed: $_"
			Return
		}
	}

	If ($Installed) { & $LaunchPstop }
}

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAo8qg6ZoBXKaDb
# NoU57FZymwh990CLE47lQgG/EDpl2qCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IKDLX06c+dXerHzZQp7Gn75ktsXUUl/fQRY+Lz2U596+MA0GCSqGSIb3DQEBAQUA
# BIICAAwbXcy5bhqnHSBUcXxFf4W4pp3dPfij3X7kDqpncbSCqrMnYKuNj2iVKJ9U
# p78RHcyROPbdOOIsuKQrBuiCo1MK//UZHwpa/r1v7hP+oYALsyaUy46pljI2m2QW
# i+e1rcFK3qHXl7YOZbDsbvcLf+Df8nJwTJN8SkQSgSmaSPjCMloadVCDXdI5Jm33
# gPx3pxLpAkBzYnkb3/VzMdFY6MgP9/PnO0pjl4ZlOrk//fyTVwVr1Ok3VPdwVVrv
# Gc7scpFRo5ec4gdkJvdWO6QeKeIoMuXu84mmUgHWXXu8RxVKwMXPLSZVJDNaPe7Y
# Ld5e3f8AgvWc6MjR6AEvnU/FtGQgxqQuYOgUhC6tbRdl6GCRfGJPbqUxUuPdUvUi
# /ADduFBCt6W2x5EsYJMNyQT20CxGb2nwcjh8RKscFLGhGGea3g/eqqqLNACzbeeT
# KeENPKGSEO1WaIhM6HBfMuv6Fa2aiDQwrHr8kP4wiAEHSa9D4jfSvC0gSvL2wBX9
# AyV7WnCbIeZsMFx/u4nfveWx8hvc0lMO0+Fj9gDVC8AtZOJy5jWTsX/NNFWf3dgM
# PSMGu909Az25AY+wVc/pVJN7ifBC3GTpZk3PAk5uh7B+LU3Rl7FpFbu37YfQfMR9
# 05AFiQybXuGwlK5LjlIIaF7K/q65QikFqEg0HWDtimainARcoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDQxODE0MjgwMFowLwYJKoZIhvcNAQkEMSIEINMrOFhn
# kl8rcTAFTDpclBPX6FmpDGplcMpWVl50T1LbMA0GCSqGSIb3DQEBAQUABIICAIC4
# G251kyUH9j7UAqsERpwLhXyJa2KcbnOKjSfBKTXuiUC3wqk35ae3zVRPWSauT1hI
# I30h9JiLOVZMzTWf1/ihkAkp80FQ8bOUuhXbSvCnUqwEMxcWX4aCCR+Mwlg0k0G6
# hpM1ZrO20qklx9XTR0s4r1z4FN5yKDP4EoDUmR6v1X1EWSyMxYqa+UEUR+kyBYrF
# xAwy98lLpjA6PIiVi+qnYGj23RBllTb2O6kV6dpkVao+2P7i8NLg41HLUX1zK5sJ
# 7+2GCLmhRwVgtgybVq7jTiSfiSgQMzrJoWsOiqdguE2Pxh2hSNCIo9FJ2UrMpY81
# d/30tc7zU+MmwRq5RBc1Ppx5kt3Zj08y1uJRSIxt2cGfbPUt4+lojVT3nwXiwiH7
# H90yUgNc3gOk5SlG6qbK41m1QGOYfDi6Ck/0gB/NCowJ+MH+tiqBAr79NyasbAkc
# AnEYh1iH1noCZT7jJMNGAsQdydMrCWgp6LUwQyCxFSF/dTTwH+ByMT+jiUnbzUlg
# YVpXlE+Cc9hP6LNP7+yL08QCr2TtoWkABmdhiTabT0P6QJsTTfOrHP5YNHKtLOPR
# AfD05ROijYSw8uku7G3z9f+O22FL0KffVijUiPEF7ekc2H3kCjBsElaC8QgT+QYm
# zU8VYgTZl0dJPqHJmnJKSJWFvFlIbc6gSXv2bRft
# SIG # End signature block
