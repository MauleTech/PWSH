Function Restore-LastUser {
	$RegKey = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
	$RegKeyPS = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
	$RegFile = "$ITFolder\LastLoggedOnUser.reg"
	$InitUser = (Get-ItemProperty $RegKeyPS).LastLoggedOnUser

	If (Test-Path -Path $RegFile){
		$User = (Select-String -Path $RegFile -Pattern '"LastLoggedOnUser"' -SimpleMatch).Line
		Write-Host "Restoring:`n$User"
		REG IMPORT $RegFile
		$NewUser = (Get-ItemProperty $RegKeyPS).LastLoggedOnUser
		Write-Host "Last Logged On User has been restored from $InitUser to $NewUser"
		Write-Host "Refreshing the Logon Screen."
		Get-Process -Name LogonUI -ErrorAction SilentlyContinue | Stop-Process -Force
	} Else {
		Write-Host "Error: No backup exists. Try the command Backup-LastUser to create a backup."
	}
}

# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUMyhCOPTJLRZcdMdxYrbLCJ0O
# fx6gggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQURI1g
# eNa/RBxrPUz+IjrkoSfDtzwwDQYJKoZIhvcNAQEBBQAEggEAF0SFOcN7tlAcDyTj
# 2Y+ixtipvbaeRQg02YU8OmfwZ5rpgkw5dlBM23xUzdDKve3DRcI7e4xB23juAR8l
# gDIpIhTmV9asLS/cg/0ytQlG8V1/GaOpiFZyuh/TMw1G3eUn4mfSP7ZifI+NX/Pc
# +Y89U4ZcCqBefHOxU7VG7Wy3TBrRY3QeHUfN8uKAhwJDa4VPbKyavfZ5oJpHUv11
# AZkO/EkdM298zL7kytKJxk1LDcjlGEoq1DKIjGMhBsUMq7Zg5TGVFh7e1GB83xio
# 8OovmTHos2DHlbIoS6TJ1OM+u5EnIMDJePCJZKBm+OA6L8yPHMxzgsBKLamNlaTW
# W4Wu/w==
# SIG # End signature block