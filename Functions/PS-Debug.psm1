Function Debug-ServerRebootScript {
	# All scripts and funtions are now run from ps.mauletech.com (github)
	Write-Host "Checking Scheduled Task"
	$Task = Get-ScheduledTask -TaskName "IT*Scheduled*Server*Reboot*"
	$ServerRebootScriptPath = "$ITFolder\scripts\ServerReboots.ps1"
	If ($Task) {
		Write-Host -NoNewLine "Task State: $($Task.State)"
		#$Task | Format-List State
		$Task | Get-ScheduledTaskInfo | Format-List LastRunTime, LastTaskResult, NextRunTime
		If ($Task.Actions.Execute -eq 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe') {
			Write-Host -ForegroundColor Green "Scheduled Program Path looks correct."
		} Else {
			Write-Host -ForegroundColor Red "Scheduled Program looks incorrect."
			Write-Host -ForegroundColor Yellow "$($Task.Actions.Execute)"
			Write-Host -ForegroundColor Red "It should be `'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`'"
		}

		If ($Task.Actions.Arguments -eq "-ExecutionPolicy Bypass -NoProfile -File `"$ServerRebootScriptPath`"") {
			Write-Host -ForegroundColor Green "Scheduled Program arguments looks correct."
		} Else {
			Write-Host -ForegroundColor Red "Scheduled Program arguments looks incorrect."
			Write-Host -ForegroundColor Yellow "$($Task.Actions.Arguments)"
			Write-Host -ForegroundColor Red "It should be `'-ExecutionPolicy Bypass -NoProfile -File `"$ITFolder\scripts\ServerReboots.ps1`"`'"
		}
	} Else {
		Write-Warning "Scheduled task does not exist!"
	}
	Pause
	$VMAutoStart = Get-VM -ErrorAction SilentlyContinue | Select-Object VMname, AutomaticStartAction, AutomaticStartDelay
	If ($VMAutoStart) {
		Write-Host "Checking virtual machine auto start settings. Make sure everything in use is set to Start."
		$VMAutoStart
	}
	If ($VMAutoStart) {
		Pause
	}
	Write-Host "Checking Server List"
	$ServerList = Get-Content -Path $ITFolder\Scripts\Server_Reboots.csv -ErrorAction SilentlyContinue | ConvertFrom-Csv
	If (!($ServerList)) {
		Write-Warning "Server List CSV File does not exist!"
	} Else {
		$ServerList | Format-Table
		Pause
		Write-Host -NoNewLine "`n - Retrieving Server Reboot Script -"
		$greenCheck = @{
			Object          = [Char]8730
			ForegroundColor = 'Green'
			NoNewLine       = $true
		}
		$progressPreference = 'silentlyContinue'
		[System.Net.ServicePointManager]::SecurityProtocol = 3072 -bor 768 -bor 192
		Set-ExecutionPolicy Bypass -Scope Process -Force
		(Invoke-WebRequest "https://raw.githubusercontent.com/MauleTech/PWSH/master/Scripts/Server-Reboots/ServerReboots_WhatIf.txt" -UseBasicParsing).Content | Invoke-Expression
	}
}

Function Debug-SharedMailboxRestoreRequest {
	<#
	.SYNOPSIS
		Draft function. Investigates why a mailbox restore shows as Investigate.
	#>
	$Stats = Get-MailboxRestoreRequest -Status "Failed" | Get-MailboxRestoreRequestStatistics -IncludeReport
	Write-Host "$Stats.Name"
	$stats.Report.Failures | Format-List FailureType, Message
	$stats.Report.MailboxVerification | Where-Object { $_.DataConsistencyScore -ne "Perfect" } | Format-List TargetFolder, MissingItemsInTargetBucket
}

Function Debug-UmbrellaDNS {

	#Policy exposer:
	$Lookup = Resolve-DnsName -Name debug.opendns.com -Type txt
	$OrgID = ($Lookup | Where-Object -Property Strings -Match "orgid").Strings -replace "[^0-9]" , ''
	$Bundle = ($Lookup | Where-Object -Property Strings -Match "bundle").Strings -replace "[^0-9]" , ''
	$PolicyURL = 'https://dashboard.umbrella.com/o/' + $OrgID + '/#/configuration/policy/' + $Bundle
	Write-Output "Organization ID: $OrgID"
	Write-Output "Policy ID: $Bundle"
	Write-Output "Umbrella DNS Policy applied to this computer:`n`n$PolicyURL"
	
	#Diagnostic executable:
	$X64exe = ${Env:ProgramFiles(x86)} + "\OpenDNS\Umbrella Roaming Client\UmbrellaDiagnostic.exe"
	$X86exe = $ENV:ProgramFiles + "\OpenDNS\Umbrella Roaming Client\UmbrellaDiagnostic.exe"
	If (Test-Path $X64exe -ea SilentlyContinue) {
		$UDexe = $X64exe
	}
 ElseIf (Test-Path $X86exe -ea SilentlyContinue) {
		$UDexe = $X86exe
	}
 ElseIf (Get-Service csc_umbrellaagent) {
		$CSCAgent = (Get-Service csc_umbrellaagent)
		Write-Warning "The new $($CSCAgent.DisplayName) is installed and it is $($CSCAgent.Status).`nThis troubleshooting command does not apply."
		Break
	}
 Else {
		Write-Warning "Umbrella Diagnostics do not appear to be installed."
		Break
	}
	Write-Host "Here is the help file for UmbrellaDiagnostic.exe:"
	Write-Host @"

  -d, --domain=VALUE         A specific URL to target with tests (e.g.
							   opendns.com)
  -s, --silent               Automatically run tests in silent mode (will not
							   show the UI or new windows; defaults to -i
							   output)
  -i, --internet             Output all results to diagnostic.opendns.com;
							   destination URL will print to console as
							   'url=URL'
  -o, --output=VALUE         Output to a file, which will print to console as
							   'outputFile=FILE'; can be a full path, make sure
							   to use "quotes" if needed
  -c, --console              Output all results to console as text
	  --erc                  Force the Roaming Client tests to be performed
	  --noerc                Skip the Roaming Client tests even if it's
							   installed
  -h, -?, --help             Display this usage statement

If run without -o or -c arguments, -i is the default output; if run with -o or -c, then -i must be explicitly set if desired as additional output.

"@
	Write-Host "Recommend running with arguments '--silent --internet --console'.`nAdd --domain=<domain> to test internal or external targets.`n"
	$Arggs = Read-Host "What arguments would you like to add? Just press enter if you wish to launch the window.`n"
	If ($Arggs) {
		Start-Process $UDexe -ArgumentList $Arggs
	}
 Else {
		Start-Process $UDexe
	}
}

Function Debug-UmbrellaProxiedDnsServer {
	$IsInstalled = Get-Service -Name Umbrella_RC -ErrorAction SilentlyContinue
	If ($IsInstalled) {
		Write-Host "------------------------------------------------------------------"
		Write-Host -ForegroundColor Green "Umbrella DNS client is installed."
		$OpenDnsPath = $Env:ProgramData + "\OpenDNS\ERC"
		Write-Host "------------------------------------------------------------------`nProxied DNS servers:"
		$Servers = Get-ChildItem -Path $OpenDnsPath -Filter "Resolver*.conf"
		ForEach ($Server in $Servers) {
			If ($Server -ne $Servers[-1]) {
				$Server | Get-Content
				Write-Host "########################"
			}
			Else {
				$Server | Get-Content
			}
		}
		$OpenDnsPath = $Env:ProgramData + "\OpenDNS\ERC"
		$Servers = ($Servers | Select-String -Pattern '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b').Line -replace 'nameserver '
		$Servers = $Servers | Sort-Object | Get-Unique
		Write-Host "------------------------------------------------------------------`nTesting Proxied DNS Servers"
		ForEach ($Server in $Servers) {
			Write-Host -NoNewline "Testing $Server`: "
			Try {
				$FQDN = $((Resolve-DnsName -Name $Server -Server $Server -DnsOnly -QuickTimeout -ErrorAction Stop).NameHost)
				Write-Host -ForegroundColor Green "$Server is responsive. FQDN: $FQDN"
				Clear-Variable FQDN -Force -ErrorAction SilentlyContinue
			}
			Catch {
				Write-Host -ForegroundColor Red "$Server is unresponsive."
			}
		}
		Write-Host "------------------------------------------------------------------`nExcluded IP / DNS values:"
		Get-ChildItem -Path $OpenDnsPath -Filter "*list.txt" | Get-Content
	}
 ElseIf (Get-Service csc_umbrellaagent) {
		$CSCAgent = (Get-Service csc_umbrellaagent)
		Write-Host "The new $($CSCAgent.DisplayName) is installed and it is $($CSCAgent.Status).`nThis troubleshooting command does not apply."
	}
 Else {
		Write-Host -ForegroundColor Red "Umbrella DNS client is NOT installed."
	}
}

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAndZu4lnLrjDGm
# 8e+1Zgh45f+qf2lLB0Js1VC9JLkWiqCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IKSmlRfA7eOuQNTZK09LPAX352vQWzZ9/Eqdr2G6+lGLMA0GCSqGSIb3DQEBAQUA
# BIICAC8yZJ3OK5gb4qraohgqMlJ8kxlAPOQP3vGP0J1imn2IUMAgMJbZvf/lfeci
# z2sdkSuysyA12zNnhdznY86zFzeLukYdhtFy3I0veXsTi44S/l8EBK4yjqlLGnWQ
# aEfd4Ih5orI62yp4poX/o8nyRbjZ8fD43s7oKJv3MxEDqnTMcbkcE+GkNxJ+uqxa
# /q4hpZB819ZC5A+sFCRbTKYTnKIn4YNOnLQAdJKaBLIWvalSbxwxElIHPndP988C
# ImRqSLaPw3OTsd4uKPhcajqSxDTQABDa03Jcn0tmWXX+g5jVhutWiPKAmW2grJnS
# WDQ/lm5U8SACydzkDk0aRvmQ5QNMtOyWQbqCW0NhTB6hj9CKHEeBUgXTFQXCAFli
# f5i2K7nND3cis7ZWA1H8YPT3Dt79UFGpM49cysKrpPnhSkP0l6BIqkwydjw/zgeS
# YJ0ov3jcbNYX+VEteB/U+euB9Lmk0+ofE5YM9MktJVBfSBg5w0kbTfo/4Ujxc25p
# bqdDOCvj0+709OGIk6fGOamD3klYc5oTYpbKUqRtt1DGvf0W0l3y/nf8rOhzMRh6
# ijtFdnfBLnQzqlC/DnWVRldsiH0tVwFlL2cQwaxso9HLQHOj4Cp+H6c/qr1P3iYK
# jrtHQlhEiWXjPEOy/Esm9Nh/pzgJNJQXPshyxIx1IxlfNctwoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDQxMDIyMTIyOFowLwYJKoZIhvcNAQkEMSIEIDnj4mpF
# Vtj2j4BjeDChwmZhHL5kLxD0yy5BHdDx/eGPMA0GCSqGSIb3DQEBAQUABIICAKpo
# rAJS+h1qnuzTrT2zwa6b8AcbuJme9Fq+gPgM/wh3Tp7CjfOeP09VXfWiPBmN6NNb
# xtPbDMwb0/B4JaFq2vPbhDQT0rXNQMhQiXO07oZ53DqXraLLhOvc99LUkNTL3T1v
# fmCG+1conxngZ7inFL/1EjNgeWo/0I7GURSN6KS2hMBdaIC9htM0z2lSYg8gxVKH
# XRlDGfUJ3qZeBsNBDApKwx4CApqFVDRwt3lDodes+2u8S+Fw762TaPibEWxji9ar
# XwjP4eYkoI7FysjEBjE7u3dH7E8ep+es2n2Ic0XO2YzB3imrbz/71VrpfmTc3Lla
# 5nSs8woxjQuTFDZ3E7Zx+DA9yBLEeIHE3BQ5mN9g9K2eAciCXR01vzcA8KWXsz2I
# B29BBXNbwU18W0Deq9JTyO9P799/o27blb4oF7g/PiqKF9RyQ9FpZalOVD6PLOUU
# efnSdAbzxRBrOrs9TfkJQoYcZc+F5Th49oyKV+mJwBDzZ/1l0daFnaODFxZBPYkv
# H5TUtmsU38Xair6TzQCEaFyF5JQuMAwvtv8SFnnj97nbic7ieBO5NM/ZQ1L3Zqtp
# 5OHB7v5gwAzcyNMQnxSIesGReVa13ngL5jGVy6Xi7EWAi2OoH+Sfq9A/GK4MkWXu
# CU2FllztXd7Qt01MEjeCbiWd38ehivFxvmoIddwD
# SIG # End signature block
