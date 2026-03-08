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
		$LogPath = "$ITFolder\" + $SiteCode + "-" + $LogLabel + ".log"
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
