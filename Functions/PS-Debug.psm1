Function Debug-UmbrellaDNS {

	#Policy exposer:
	$Lookup = Resolve-DnsName -Name debug.opendns.com -Type txt
	$OrgID = ($Lookup | Where-Object -Property Strings -Match "orgid").Strings -replace "[^0-9]" , ''
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

Function Debug-ServerRebootScript {
	# All scripts and funtions are now run from ps.ambitionsgroup.com (github)
	Write-Host "Checking Scheduled Task"
	$Task = Get-ScheduledTask -TaskName "IT*Scheduled*Server*Reboot*"
	If ($Task) {
		Write-Host -NoNewLine "Task State: $($Task.State)"
		#$Task | Format-List State
		$Task | Get-ScheduledTaskInfo | Format-List LastRunTime, LastTaskResult, NextRunTime
		If ($Task.Actions.Execute -eq 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe') {
			Write-Host -ForegroundColor Green "Scheduled Program Path looks correct."
		}
		Else {
			Write-Host -ForegroundColor Red "Scheduled Program looks incorrect."
			Write-Host -ForegroundColor Yellow "$($Task.Actions.Execute)"
			Write-Host -ForegroundColor Red "It should be `'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`'"
		}

		If ($Task.Actions.Arguments -eq '-ExecutionPolicy Bypass -NoProfile -File "$ITFolder\scripts\ServerReboots.ps1"') {
			Write-Host -ForegroundColor Green "Scheduled Program arguments looks correct."
		}
		Else {
			Write-Host -ForegroundColor Red "Scheduled Program arguments looks incorrect."
			Write-Host -ForegroundColor Yellow "$($Task.Actions.Arguments)"
			Write-Host -ForegroundColor Red "It should be `'-ExecutionPolicy Bypass -NoProfile -File `"$ITFolder\scripts\ServerReboots.ps1`"`'"
		}
	}
 Else {
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
	}
 Else {
		$ServerList | Format-Table
		Pause
		Write-Host -NoNewLine "`n - Retrieving Ambitions Server Reboot Script -"
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
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUwCDTyswFOLEiddXBclv4tObf
# ZG6gggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUWgKu
# Zf20Et5NZlK171uw/OwVieowDQYJKoZIhvcNAQEBBQAEggEAL2K3KVww8o5SOVMw
# RzFg89qbkNT1jr7gy4WNqLw9hemXL83RRzdQLhOiAakE5jE3VaBdfKcZ0rdZF6b7
# pVnX0sXCTbOyEh2f+lX7zcmIUIWVQDlCn7ZadlHwg0+B8KR3hmoTvqn2Ts97u6WW
# /NytyUAQfxXp7mJB3ITTsX15pRrJsffjUhPP108loZ+DLjvO/pIijO+2Z80sPaYs
# ypr9sqrWDosuCPITSNvmR2auH0cs1BT3Djs5IzXbcAwneGFzD9ijCzjMtfCBesZF
# A5UDMhyjgMonz/V+EXhm/ftruCkdQnOdPaO8HSROI8Cdkz5lRIq+xkKheK8E47Lj
# +fDPeA==
# SIG # End signature block