Function Start-BackstageBrowser {
	# Define the URL for the Pale Moon x64 standalone version (self-extracting)
	$downloadUrl = "https://www.palemoon.org/download.php?mirror=us&bits=64&type=portable"
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
}

Function Start-CleanupOfSystemDrive {
	Invoke-RestMethod 'https://raw.githubusercontent.com/MauleTech/PWSH/master/OneOffs/Clean%20up%20Drive%20Space.ps1' | Invoke-Expression
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



# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUYLsfUJd/KEWxb4MLTQ4zLfxg
# enagggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUanK0
# +jHk39ghZZOmMXEfF9JbPG4wDQYJKoZIhvcNAQEBBQAEggEASvcCsbZmf2HA4hio
# Di6v0XRApolQsj74uWK2SLst6JE1b1V4BU9UNGasyRI0QpTHAis451fkhvJY9uHj
# rsW9BhvYFO7ELokpT3S6MsHEJL1whK/v7Ra57SMpiN8u2ZJmxt6A93qzkvLCWpa1
# fpZN2B0Lr6sK41uf4jLGNLYUoDsOa43xuQtwY6MwBCaWgxJ49lvFITZjfFQxdaqm
# xvH0d1coITytbRxYHUR9DhVYdB9/DJA/ct/eVHO4SHW1ch31EcD1Et4ijdU85Ktk
# jw6l+z2jLqNeOzvuoXoiNtWc+ItVAsP6fLs8QtT/WbiK717hQLyhsdpUWTI1VEAP
# KE6+SA==
# SIG # End signature block