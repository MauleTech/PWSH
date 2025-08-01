Function Disable-LocalPasswordExpiration {
	param(
		[Parameter(Mandatory=$true)]
		[string]$UserName
	)
	Write-Host "Set local $UserName account to never expire"
	Set-LocalUser -Name $UserName -PasswordNeverExpires $True
}

Function Disable-DailyReboot {
	<#
	.SYNOPSIS
		Permanently deletes the scheduled task named "Daily Restart"
#>
	$DailyRebootTask = Get-ScheduledTask -TaskName "Daily Restart" -ErrorAction SilentlyContinue
	If ($DailyRebootTask) {
		$DailyRebootTask | Unregister-ScheduledTask -Confirm:$false
	}
	If (!(Get-ScheduledTask -TaskName "Daily Restart" -ErrorAction SilentlyContinue)) {
		Write-Host "The task 'Daily Restart' has been successfully removed."
	}
 Else {
		Write-Host "The task 'Daily Restart' has NOT been successfully removed. Please investigate!"
	}
}

Function Disable-FastStartup {
	Write-Host "Disable Windows Fast Startup"
	REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d "0" /f
	powercfg -h off
}

Function Disable-Sleep {
	<#
.Synopsis
	Function to suspend your current Power Plan settings when running a PowerShell script.
.SYNOPSIS
	Function to suspend your current Power Plan settings when running a PowerShell script.
	Scenario: When downloading files using Robocopy from PowerShell you don't want your
	laptop to go into sleep mode.
.EXAMPLE
	Disable-Sleep
	Run mylongrunningscript with Display idle timeout prevented and verbose messages
#>

	If (!(Test-Path "C:\ProgramData\chocolatey\lib\dontsleep.portable\tools\DontSleep_x64_p.exe")) {
		If (!(Get-Command choco -ErrorAction SilentlyContinue)) { Install-Choco }
		choco install dontsleep.portable -y
	}
	& C:\ProgramData\chocolatey\lib\dontsleep.portable\tools\DontSleep_x64_p.exe -bg please_sleep_mode=0 enable=1
}

Function Disable-SleepOnAC {
	<#
.Synopsis
	Function to adjust the windows power plan to prevent a computer from going to sleep. Ever.
	Still allows the monitor to sleep to prevent burnin.
#>

	# Prevent sleep when plugged in (AC)
	powercfg /change standby-timeout-ac 0
	powercfg /change hibernate-timeout-ac 0
}


# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU0QZbpxaAhAqiexISstu4tegZ
# v1mgggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUPgT6
# m72G6yT9puNkm45NT0Su910wDQYJKoZIhvcNAQEBBQAEggEAOBDA2okyalQINmsR
# JW07agX3ESz0+96jLVG3djDhwGw/LAUcHNjG094Ks9uqtF2tkvn9o3T6JB00Yzz/
# iE5jNVTtJSFAbwe+SxQrR9aVs+8e4gE9An5cBYTwYaatxKnw1bxjjv1kxKuKU6v1
# gETjAPoLfjeev1bFXXKhsPS3LKo8WYxOBdgTnwaETZyphf1Q9ZVSVuZK+eoA+5GV
# zDe5H9zT+rsx44SeCa//NR0E3GEx7Nc6MLCjTYtr9bSgiqwnyewvTpTWK5LWqblr
# LB58Xw79OSAXgfFN7vzwOiSH04CariVC5ocQpB1bYXXo+WvWdmqjLaQlXauMJiLm
# GeFwKA==
# SIG # End signature block