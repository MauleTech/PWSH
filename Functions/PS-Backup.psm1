Function Backup-LastUser {
	$RegKey = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
	$RegFile = "$ITFolder\LastLoggedOnUser.reg"
	Write-Host "Backuping up last logged on user"
	reg export $RegKey $RegFile /y
	Write-Host "Trimming export"
	(Get-Content $RegFile)[0..10] | Out-File -FilePath $RegFile -Force
	$User = (Select-String -Path $RegFile -Pattern '"LastLoggedOnUser"' -SimpleMatch).Line
	Write-Host "$User has been backed up to $RegFile"
	Write-Host "`nTry the command Restore-LastUser"
	<#
	.SYNOPSIS
		Backup-LastUser affects the user listed on the Windows Logon screen. If Sally is the last one that logged in, and she's use to just turning on her computer and entering her password because she's always the last one that used the computer, it'll really mess her up if you log in to fix something. Then she'll be entering her password on the admin account without ever looking to see that she needs to switch user back to herself.
		Use the command "Backup-LastUser". This saves Sally as a registry key.
		You login, do your stuff, then reboot or log out.
		Use the command "Restore-LastUser". This will change the default user at the login screen from "ATGAdmin" back to "Sally" or whatever user was backed up.
	.EXAMPLE
		Backup-LastUser
			Backuping up last logged on user
			The operation completed successfully.
			Trimming export
			"LastLoggedOnUser"=".\\Sally" has been backed up to $ITFolder\LastLoggedOnUser.reg
			Try the command Restore-LastUser
#>
}

# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUEyiyAEHON5XkxxguDBikqdC8
# ZQGgggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUKakv
# JayV8UHArpsVDEZtKDxmuGQwDQYJKoZIhvcNAQEBBQAEggEAI++UAuAuV9+Ww057
# vbvC7vY3ccS0sEmQev8JavAwCfcgbit2BFowclavL9Gs9etlsUNHoMLbxbp7xPWJ
# B0uZc2oYCfJtbmFtoQYxfGHi/0xDxwiOF5uh9bv6cBXx/1Q0M5CmD6TrWWIw1HLQ
# FMgGxu0e7Lj1xoep55YVqvNR8yBJXW1EYhfTYFWF6K8tklE/1HJMJrtOsIhfWdAM
# PDCMU6wVWDhBjCoAkKd0Cgee5zuvwPuuROqWWldxPL35p3dFuMygkqccIH5euZRc
# hUcqnhw2sFcTSWUbYg0ohwTt4JN1jCZo3Lah4EHuQhmnCYWrr8nsceYDXJrU7j8A
# 4gJA4A==
# SIG # End signature block
