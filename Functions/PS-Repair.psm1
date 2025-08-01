Function Repair-O365AppIssues {
	Write-Host "Please note this is an interactive tools, to be run from a user's session."
	If (-not (Test-Path '$ITFolder')) {New-Item -ItemType Directory -Force -Path $ITFolder\ | Out-Null}
	(New-Object System.Net.WebClient).DownloadFile('https://aka.ms/SaRASetup', '$ITFolder\SaraSetup.exe')
	& $ITFolder\SaraSetup.exe
	Write-Host "SaRA should now be installing, please wait a moment as it launces."
<#
	.SYNOPSIS
		Downloads and runs the Microsoft Support and Recovery Assistant (SaRA) tool.
		Please note this is an interactive tools, to be run from a user's session.
	.LINK
		https://www.thewindowsclub.com/microsoft-support-and-recovery-assistant
	.LINK
		https://www.microsoft.com/en-us/download/100607
#>
}

Function Repair-Windows {
	$StartTime = (Get-Date)
	(Get-Date).DateTime | Out-Host
	Write-Host Repair-Volume -DriveLetter $Env:SystemDrive.SubString(0,1) -Scan
	$chdksk = Repair-Volume -DriveLetter $Env:SystemDrive.SubString(0,1) -Scan
	If ($chdksk -ne "NoErrorsFound") {Repair-Volume -DriveLetter $Env:SystemDrive.SubString(0,1) -SpotFix}
	Write-Host Dism /Online /Cleanup-Image /StartComponentCleanup
	Dism /Online /Cleanup-Image /StartComponentCleanup
	Write-Host ...
	(Get-Date).DateTime | Out-Host
	Write-Host Dism /Online /Cleanup-Image /RestoreHealth
	Dism /Online /Cleanup-Image /RestoreHealth
	Write-Host ...
	(Get-Date).DateTime | Out-Host
	Write-Host SFC /scannow
	SFC /scannow
	(Get-Date).DateTime | Out-Host
	$EndTime = (Get-Date) - $StartTime
	Write-Host "This process took:"
	$EndTime | FT | Out-Host
	Write-Host "Run this function repeately until no errors show up. If this fails after 3 tries, upgrade or reinstall windows"
}

Function Repair-Volumes {
<#
	.SYNOPSIS
		Sequentially checks and repairs each volume.
#>
	$Drives = Get-Volume | Where-Object {
		(($_.DriveType -eq "Fixed") -or ($_.DriveType -eq "3"))`
		-and $(If ($_.OperationalStatus){$_.OperationalStatus -eq "OK"} Else {Return $True})`
		-and !($_.FileSystem -Match "FAT")
	}
	ForEach ($Drive in $Drives){
		If ($Drive.DriveLetter) {$Letter = ($Drive.DriveLetter).ToString()}
		If ($Drive.FriendlyName) {$FN = $Drive.FriendlyName}
		$ObjectId = $Drive.ObjectId
		Write-Host -NoNewLine "Scanning Volume:"
		$Drive | FT
		$chkdsk = Repair-Volume -ObjectId $ObjectId -Scan
		Write-Host $chkdsk
		If ($chkdsk -ne "NoErrorsFound") {
			Write-Host "Errors found on drive $Letter - $FN. Attempting to repair."
			$Repair = Repair-Volume -ObjectId $ObjectId -SpotFix
			Write-Host $Repair
		}
		Clear-Variable Letter,ObjectId,FN -ErrorAction SilentlyContinue
		Write-Host -ForegroundColor Yellow "-_-_-_-_-_-_-_-_-_-_-_-_-"
	}
}

# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUOBtIRoni+eXcPQLja7yHBjs9
# DECgggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUFCR1
# KhtpoBZbQSbpkz3UPslip40wDQYJKoZIhvcNAQEBBQAEggEAda++obkfnvy99mlH
# n5YPhfUX9G2fJFAfk4ie0C+32kIUignoitkGqgOP3cLV2qqVkjYZRL5uOeDqHz5R
# 9gyJ3KJL2AiUxO8JQ8dvpbf6stesomCZwLuY4nieFd1TYxMKYSki3ihZqj4uZ40w
# xfmIdJSAN7uUKqrMm9qUCb9x+RUm3/rOaif6KMnRt7Flf+WH1/AxfS43HBgU0IC6
# dB9x5wKDVzzJ+lJ3LhMb/H1AxU9z3eNr9s4QuCQIA47cdveB6So5WsAlvVz0fdAl
# 56kepnzFiRsca9H+ymKOekuQNCSye2rti0VuOsrJdpTk44pSNAPEmMtqAidwQo3Q
# gjUwLg==
# SIG # End signature block