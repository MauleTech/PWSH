Function Uninstall-Application {
	<#
	.SYNOPSIS
		Uninstall Application
	.DESCRIPTION
		Allows to Uninstall Application from system
	.EXAMPLE
		Uninstall-Application -AppToUninstall "Microsoft Office 2010 Primary Interop Assemblies"
	.PARAMETER AppToUninstall
		Application name (Or application name format)
	#>

	param(

	  [Parameter(Mandatory=$False, ValueFromPipeline=$True,
	  ValueFromPipelineByPropertyName=$True, HelpMessage='Enter the Application to uninstall.')]
	  [Alias('Application')]
	  [string] $AppToUninstall

	)

	Write-Host '[Scanning All App sources]'
	Write-Host '--[Scanning Wmi Repository]'
	$Global:WmiApps = (Get-WmiObject -Class Win32_Product).Name | Select-Object -Unique | Sort-Object
	Write-Host '--[Scanning Native Powershell Repository]'
	$Global:PowershellApps = (Get-Package -Provider Programs -IncludeWindowsInstaller).Name | Select-Object -Unique | Sort-Object
	Write-Host '--[Scanning Registry UninstallString Repository]'
	$Global:uninstallX86RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
	$Global:uninstallX64RegPath = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
	$Global:RegistryApps = (Get-ChildItem $uninstallX86RegPath | ForEach-Object { Get-ItemProperty $_.PSPath }).DisplayName
	$RegistryApps += (Get-ChildItem $uninstallX64RegPath | ForEach-Object { Get-ItemProperty $_.PSPath }).DisplayName
	$Global:AllApps = $WmiApps + $PowershellApps + $RegistryApps | Select-Object -Unique | Sort-Object
	$Global:Uninstalled = $False


	Function Uninstall-WmiApp {
		Write-Host -NoNewLine "Attempting Wmi method. "
		$AppWmi = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Where-Object {$_.Name -match $AppToUninstall}
		$AppWmiName = $AppWmi.Name
		If ($AppWmi) {
			If ($AppWmi) {
				$AppWmi.Uninstall()
				$AppWmi = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Where-Object {$_.Name -match $AppToUninstall}
			}
			If (-not $AppWmi) {
				Write-Host -ForegroundColor Green "$AppToUninstall appears to have been successfully uninstalled via Wmi method.`n$AppWmiName"
				$Global:Uninstalled = $True
			} Else {
				Write-Host -ForegroundColor Yellow "Uninstalling via `(Get-WmiObject`).Uninstall`(`) method didn`'t work."
			}
		}
	}

	Function Uninstall-PowershellApp {
		Write-Host -NoNewLine "Attempting Uninstall-Package method. "
		$Package = Get-Package -Provider Programs -IncludeWindowsInstaller | Where-Object -Property 'Name' -Match $AppToUninstall
		Get-Package -Provider Programs -IncludeWindowsInstaller | Where-Object -Property 'Name' -Match $AppToUninstall | Uninstall-Package -Force -AllVersions
		If (-not (Get-Package -Provider Programs -IncludeWindowsInstaller | Where-Object -Property 'Name' -Match $AppToUninstall)){
			Write-Host -ForegroundColor Green "$AppToUninstall appears to have been successfully uninstalled via Uninstall-Package method.`n$Package"
			$Global:Uninstalled = $True
		} Else {
			Write-Host -ForegroundColor Yellow "Uninstalling via Uninstall-Package method didn't work."

		}
	}

	Function Uninstall-RegistryApp {
		Write-Host -NoNewLine "Attempting Registry UninstallString method. "

		# Get registry entries for the application (Select-Object -First 1 ensures single entry)
		$regEntry32 = Get-ChildItem $uninstallX86RegPath -ErrorAction SilentlyContinue | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.DisplayName -Match $AppToUninstall } | Select-Object -First 1
		$regEntry64 = Get-ChildItem $uninstallX64RegPath -ErrorAction SilentlyContinue | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.DisplayName -Match $AppToUninstall } | Select-Object -First 1

		# Prefer 64-bit entry over 32-bit if available
		$regEntry = If ($regEntry64) { $regEntry64 } ElseIf ($regEntry32) { $regEntry32 } Else { $null }

		If (-not $regEntry) {
			Write-Host -ForegroundColor Yellow "Application not found in registry."
			return
		}

		# Prefer QuietUninstallString if available
		$uninstallString = $null
		$IsQuietString = $False

		If ($regEntry.QuietUninstallString) {
			$uninstallString = $regEntry.QuietUninstallString
			$IsQuietString = $True
			Write-Host -NoNewLine "(Using QuietUninstallString) "
		} ElseIf ($regEntry.UninstallString) {
			$uninstallString = $regEntry.UninstallString
		}

		If (-not $uninstallString) {
			Write-Host -ForegroundColor Yellow "No uninstall string found."
			return
		}

		# Determine if this is an MSI or EXE uninstaller (case-insensitive, match GUID anywhere in string)
		$IsMsi = $uninstallString -match '(?i)msiexec|\.msi|\{[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\}'

		If ($IsMsi) {
			# Handle MSI uninstaller
			Write-Host -NoNewLine "(MSI detected) "
			$guid = $uninstallString -Replace "(?i)msiexec\.exe","" -Replace "/I","" -Replace "/X","" -Replace '"',''
			$guid = $guid.Trim()

			# Extract GUID if present (case-insensitive)
			If ($guid -match '(?i)(\{[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\})') {
				$guid = $Matches[1]
			}

			$process = Start-Process "msiexec.exe" -ArgumentList "/X $guid /qn /norestart" -Wait -NoNewWindow -PassThru
			If ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
				Write-Host -NoNewLine "(Exit code: $($process.ExitCode)) "
			} Else {
				Write-Host -ForegroundColor Yellow "(Exit code: $($process.ExitCode)) "
			}
		} Else {
			# Handle EXE uninstaller
			Write-Host -NoNewLine "(EXE detected) "

			# If we already have a quiet string, use it directly
			If ($IsQuietString) {
				$exitCode = Invoke-UninstallString -UninstallString $uninstallString
				If ($exitCode -eq 0 -or $exitCode -eq 3010 -or $exitCode -eq 1605) {
					Write-Host -NoNewLine "(Exit code: $exitCode) "
				} Else {
					Write-Host -ForegroundColor Yellow "(Exit code: $exitCode - may indicate failure) "
				}
			} Else {
				# Try to add silent switches for common installer types
				Invoke-SilentExeUninstall -UninstallString $uninstallString
			}
		}

		# Verify uninstall success (wait for registry to update)
		Start-Sleep -Seconds 5
		$RegistryApps = (Get-ChildItem $uninstallX86RegPath -ErrorAction SilentlyContinue | ForEach-Object { Get-ItemProperty $_.PSPath }).DisplayName
		$RegistryApps += (Get-ChildItem $uninstallX64RegPath -ErrorAction SilentlyContinue | ForEach-Object { Get-ItemProperty $_.PSPath }).DisplayName
		If (-not ($RegistryApps -Match $AppToUninstall)) {
			Write-Host -ForegroundColor Green "$AppToUninstall appears to have been successfully uninstalled via Registry method."
			$Global:Uninstalled = $True
		} Else {
			Write-Host -ForegroundColor Yellow "Uninstalling via Registry UninstallString method didn't work."
		}
	}

	Function Invoke-UninstallString {
		param([string]$UninstallString)

		# Parse the uninstall string to separate executable from arguments
		$process = $null
		If ($UninstallString -match '^"([^"]+)"\s*(.*)$') {
			$exe = $Matches[1]
			$argList = $Matches[2]
		} ElseIf ($UninstallString -match '^(\S+\.exe)\s*(.*)$') {
			$exe = $Matches[1]
			$argList = $Matches[2]
		} Else {
			# Fallback: run as-is via cmd
			$process = Start-Process "cmd.exe" -ArgumentList "/c `"$UninstallString`"" -Wait -NoNewWindow -PassThru
			return $process.ExitCode
		}

		If ($argList) {
			$process = Start-Process $exe -ArgumentList $argList -Wait -NoNewWindow -PassThru
		} Else {
			$process = Start-Process $exe -Wait -NoNewWindow -PassThru
		}
		return $process.ExitCode
	}

	Function Invoke-SilentExeUninstall {
		param([string]$UninstallString)

		# Parse executable path from uninstall string
		$exe = $null
		$existingArgs = ""

		If ($UninstallString -match '^"([^"]+)"\s*(.*)$') {
			$exe = $Matches[1]
			$existingArgs = $Matches[2]
		} ElseIf ($UninstallString -match '^(\S+\.exe)\s*(.*)$') {
			$exe = $Matches[1]
			$existingArgs = $Matches[2]
		}

		# Validate executable exists and has .exe extension
		If (-not $exe -or -not ($exe -match '\.exe$') -or -not (Test-Path $exe -ErrorAction SilentlyContinue)) {
			# Fallback to running the string as-is
			$exitCode = Invoke-UninstallString -UninstallString $UninstallString
			return $exitCode
		}

		# Try to detect installer type by reading first 10MB of the executable (memory-safe)
		$preferredSwitch = $null
		$detectedType = $null
		$maxBytesToRead = 10MB
		Try {
			$fileStream = [System.IO.File]::OpenRead($exe)
			Try {
				$fileSize = $fileStream.Length
				$bytesToRead = [Math]::Min($fileSize, $maxBytesToRead)
				$buffer = New-Object byte[] $bytesToRead
				$null = $fileStream.Read($buffer, 0, $bytesToRead)
				$exeContent = [System.Text.Encoding]::ASCII.GetString($buffer)

				# Detect installer type from signatures in the binary
				If ($exeContent -match 'Nullsoft|NSIS') {
					$preferredSwitch = '/S'
					$detectedType = 'NSIS'
				} ElseIf ($exeContent -match 'Inno Setup') {
					$preferredSwitch = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
					$detectedType = 'Inno Setup'
				} ElseIf ($exeContent -match 'InstallShield') {
					$preferredSwitch = '/s'
					$detectedType = 'InstallShield'
				} ElseIf ($exeContent -match 'WiX') {
					$preferredSwitch = '/quiet /uninstall'
					$detectedType = 'WiX'
				}
			} Finally {
				$fileStream.Close()
				$fileStream.Dispose()
			}
		} Catch {
			# If we can't read the file, continue without detection
		}

		# Build the argument list
		$argsToUse = $existingArgs

		If ($preferredSwitch) {
			# Check if key silent flags already exist (case-insensitive, check individual flags)
			$flagsToAdd = @()
			ForEach ($flag in ($preferredSwitch -split '\s+')) {
				If (-not $argsToUse -or $argsToUse -notmatch "(?i)$([regex]::Escape($flag))") {
					$flagsToAdd += $flag
				}
			}
			If ($flagsToAdd.Count -gt 0) {
				$argsToUse = ("$argsToUse " + ($flagsToAdd -join ' ')).Trim()
			}
			Write-Host -NoNewLine "(Detected: $detectedType, using: $preferredSwitch) "
		} Else {
			# Unknown installer type - use /S as most common silent switch (single attempt only)
			Write-Host -NoNewLine "(Unknown installer type, trying /S) "
			If (-not $argsToUse -or $argsToUse -notmatch '(?i)/S\b') {
				$argsToUse = ("$argsToUse /S").Trim()
			}
		}

		# Execute the uninstaller once and capture exit code
		$process = Start-Process $exe -ArgumentList $argsToUse -Wait -NoNewWindow -PassThru
		$exitCode = $process.ExitCode

		# Report exit code (0 = success, 3010 = reboot required, 1605 = not installed)
		If ($exitCode -eq 0 -or $exitCode -eq 3010 -or $exitCode -eq 1605) {
			Write-Host -NoNewLine "(Exit code: $exitCode) "
		} Else {
			Write-Host -ForegroundColor Yellow "(Exit code: $exitCode - may indicate failure) "
		}

		return $exitCode
	}

	If (-Not $AppToUninstall) {
		Write-Host "Review the applications available to uninstall, then enter it verbatim."
		Write-Host -ForegroundColor Yellow "Note: You can use the '-AppToUninstall' options to specify the app without interaction or pipe in the name."
		Pause
		$AllApps | More
		$AppToUninstall = Read-Host "App to Uninstall: "
	}

	If ($AppToUninstall){
		If ($AllApps -Match $AppToUninstall) {
			Write-Host "$AppToUninstall found. Attempting uninstall. "
			If ($WmiApps -Match $AppToUninstall) {Uninstall-WmiApp}
			If ((-Not $Uninstalled) -and ($PowershellApps -Match $AppToUninstall)) {Uninstall-PowershellApp}
			If ((-Not $Uninstalled) -and ($RegistryApps -Match $AppToUninstall)) {Uninstall-RegistryApp}
			If (-Not $Uninstalled) {Write-Host -ForegroundColor Red "Uninstall Failed. Please try uninstalling via Windows Settings Menus."}
		} Else {
			Write-Host -ForegroundColor Yellow "$AppToUninstall was not found."
		}
	} Else {
		Write-Host -ForegroundColor Red "No application specified."
	}
	#Cleanup!
	@("WmiApps", "PowershellApps", "uninstallX86RegPath", "uninstallX64RegPath", "RegistryApps", "AllApps", "Uninstalled") | ForEach-Object {
		Clear-Variable $_ -Force -ErrorAction SilentlyContinue
	}
}

Function Uninstall-UmbrellaDNS {
	Uninstall-Application -AppToUninstall "Cisco Secure Client"
}

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBFTh0Aev4T0Z0v
# OTqFvKFMulkVk6797bN/rgHLE1crS6CCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IMOwmWuQTwUj4iQfTbHjmzH4NdCO63chs1SSWJ9WQZJ1MA0GCSqGSIb3DQEBAQUA
# BIICAJx+yc2mgfs2NtAFVDcsRcOxToN/aq2MKq9AauFPVjCJXXAZ/8Hs+eDTmKwA
# +WRDrxKF4viHqsb4VAkEVt+4mV7/sNLnIOmHNaUHaVGnhRAgwqjKu6XTjQCYTdYt
# I35nMa9uNrBHM9m9hUyeznMQ73aCae7Bf+Wi+FMoWvcldsHd7CWMhPGj5qVzcY69
# hlFUKg48aA/nC8tuAdgBgWfXPktswBAL5j6LbdnjT9QePMzsCQAF3W5MpJhSnfkU
# eIfNcFpY40/Xdoq4JGj1sF++F1itWB2SV2afVIL3uYoBeOjSsYmQfXY+RnJrYEIe
# BYLCuCXOITwTAuQN47gi0rmi3WiLtLHzzfvQQLsyNb0HbJs+ZjsL4359bqH/0B5H
# 53EP5eBKgzNkXd14EPnolaof2y/Px5C2qalhPnPWVnHRu7t68uEYMH7reZlIdVtP
# 86lWJE64tokNJTVHgFuBk7Pyfxz0lhqB8ACTQ1ZdlcRNvPUiDRUwyBoGiG8lbIxp
# PoNM8t2M6/3n8jlyQTBIBsMvX/0jqaReQT5ivSFwMWrbV7QXYIrBvz5qvdwvoFcp
# Um5hotw284Bjq4xAuJ9BrhtHZD+iEOqml+FnnS3KSnrzCvCIcXBKGgpB6P4EJeSE
# hLlpt0jNjFo7IahwkPqdsBYSC8sYd+2mPrq4XuTJFxUn1gAXoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDQyMjAzMTMwNVowLwYJKoZIhvcNAQkEMSIEICTWu6dc
# 5ZIcLl4qo80Fk2mb9KjdNe19a8ADtmzUJbdnMA0GCSqGSIb3DQEBAQUABIICAMHf
# RZzsmZ4FjVVHaJzaeH1uqzzdlgipLDxwgMR/53GxiEeRH/l7Hgf0OlWwzISuSPz+
# xTWYoYbw0lQ1oh2ycEotEuEAZTFC+FzODV1qAfNwsObp0PD3DUfmmLGSw5d3E06d
# Mjmpbzb1lQzo0ql9OcZqJs3RX+t3u+q84FOx1U7j79ci/IWNectfkrY+oNdajlir
# yWxHF3AXaemVfeY253YHIsNaM5+2f6IMfgUOmQ4RsGxnNP7O3XCkpIe9r/2Jy7AB
# 36XGnPbkL7/yqbgNdhZWzOCRRs0K+03bpt7MVCv7kmqUSceoEuGjYGB9B5EsuYwr
# 45qLiGU1yT4imKrs4kRi2CB/UTYx2TMNsx6oHTULHDTwoySKoFjdaV9dN7+Jmr4F
# e7DDpc8f3mKObj5LtvdjLwQyKcr99r4DoXthaEhFFtozGI8LJJrdNS4HOkFz5j+k
# bsxrvMjbA7KEVoGRlXq3b8Ehl56cFfO/mHwMCbfYVenrO/GA7Z3KsYipTXL+WRj8
# a54nd1ImriBU2WrwTtM5yCLC3kjb0B94swl8Q1NT/3oK3h0eUSZTavlUKUH/8coP
# U9maZngR13k4LZYB3p+DJyg0lBUKVnpR4cdemnWcjtclXr2u4xv4JgZbaZDxmRdA
# NcRbGEw7jalGpCiYRgK8LEUo+lR9CnXgzmjfuvOf
# SIG # End signature block
