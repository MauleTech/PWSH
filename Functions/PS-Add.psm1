Function Add-ChromeShortcut{
	param
	(
		[Parameter(Mandatory=$true)]
		[string]$Label,

		[Parameter(Mandatory=$true)]
		[string]$Url
	)

	If (Test-Path -Path 'C:\Program Files\Google\Chrome\Application\chrome.exe') {
		$TargetFile = "C:\Program Files\Google\Chrome\Application\chrome.exe"
	} ElseIf (Test-Path -Path 'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe') {
		$TargetFile = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
	} Else {
		Write-Host "Google Chrome was not found. Please install manually or with Chocolatey:"
		Write-Host "   Install-Choco"
		Write-Host "   choco install GoogleChrome"
	}

	If ($TargetFile) {
		$ShortcutFile = "$env:Public\Desktop\" + $Label + ".lnk"
		$WScriptShell = New-Object -ComObject WScript.Shell
		$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
		$Shortcut.TargetPath = $TargetFile
		$Shortcut.Arguments = $Url
		$Shortcut.Save()
	}
	<#
	.SYNOPSIS
		Creates a Google Chrome Shortcut on the "All Users" Desktop.
		If Google Chrome is not found, prompts to install the program using ATG-PS scripts + Chocolately.
	.PARAMETER Label
		The file name of the shortcut; ".lnk" is automatically appended.
	.PARAMETER Url
		The full URL that the shortcut intends to open: "https://www.google.com/"
	.EXAMPLE
		Add-ChromeShortcut -Label "Github ATG-PS" -Url "https://github.com/MauleTech/PWSH/"
	#>
}

Function Add-FileFolderShortcut {
	param
	(
		[Parameter(Mandatory=$true)]
		[string]$SourceLnk,

		[Parameter(Mandatory=$true)]
		[string]$DestinationPath,

		[Parameter(Mandatory=$false)]
		[string]$StartIn
	)

	$WshShell = New-Object -comObject WScript.Shell
	$Shortcut = $WshShell.CreateShortcut($SourceLnk)
	$Shortcut.TargetPath = $DestinationPath
	If ($StartIn) {$Shortcut.WorkingDirectory = $StartIn}
	$Shortcut.Save()

	<#
	.SYNOPSIS
		Creates a shortcut to a file or folder.
	.PARAMETER SourceLnk
		The file name of the shortcut. Must end with ".lnk"
	.PARAMETER DestinationPath
		What the shortcut is pointing to. "$ITFolder\RyanIsAwesome.txt"
	.EXAMPLE
		Add-FileFolderShortcut -SourceLnk "$env:Public\Desktop\Ambitions Folder.lnk" -DestinationPath "$ITFolder"
		This example puts a shortcut on the desktop called "Ambitions Folder" and points to $ITFolder.
	.EXAMPLE
		Add-FileFolderShortcut -SourceLnk "$env:Public\Desktop\ProLaw.lnk" -DestinationPath "\\rradb.robles.law\ProLaw\ProLaw.exe" -StartIn "\\rradb.robles.law\ProLaw"
		This example puts a shortcut on the desktop called ProLaw and with the working directory filled out.
	#>
}

Function Add-IEShortcut {
	param
	(
		[Parameter(Mandatory=$true)]
		[string]$Label,

		[Parameter(Mandatory=$true)]
		[string]$Url
	)

	$TargetFile = "C:\Program Files\Internet Explorer\iexplore.exe"
	$ShortcutFile = "$env:Public\Desktop\" + $Label + ".lnk"
	$WScriptShell = New-Object -ComObject WScript.Shell
	$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
	$Shortcut.TargetPath = $TargetFile
	$Shortcut.Arguments = $Url
	$Shortcut.Save()

	<#
	.SYNOPSIS
		Creates an Internet Explorer Shortcut on the "All Users" Desktop.
	.PARAMETER Label
		The file name of the shortcut; ".lnk" is automatically appended.
	.PARAMETER Url
		The full URL that the shortcut intends to open: "https://www.google.com/"
	.EXAMPLE
		Add-ChromeShortcut -Label "Github ATG-PS" -Url "https://github.com/MauleTech/PWSH/"
	#>

}

Function Add-WebShortcut{
	param
	(
		[string]$Label,
		[string]$Url
	)

	Write-Host "Adding a shortcut to $Label to the desktop"
	$Shell = New-Object -ComObject ("WScript.Shell")
	$URLFilePath = $env:Public + "\Desktop\" + $Label + ".url"
	$Favorite = $Shell.CreateShortcut($URLFilePath)
	$Favorite.TargetPath = $Url
	$Favorite.Save()
}

# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUeD6IvvNtkFdUUUNKRmRenFw+
# hz+gggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUY9cs
# MQQwQB5TurtF5sRQGYIsAWUwDQYJKoZIhvcNAQEBBQAEggEADXIeLFG/GhTtbqC4
# jDnF0BJIMk936A4y1pvd1j6dgGkfxmzAj8eMvNsR42cQJEt7e07fC0i9P2NgxUxK
# 6X6KGxyWxpJ+svSkvsBaf1rUibF5ILmeKqILDbyYj0r/HUhgoUK6cPZ0GZG12ZVW
# I4Ma9xQ/2rmJTJM27vX2xOI8TE6SoaXDZoulwRA+4eLtAeCPCMasYBgzrR7/Yr3a
# hvI47dRoJULk2g43loa7M3qzareaCdU82loBT1JVA5VR4MTANfGFgHtmcqC9IVs5
# dB8jl+2DkIZ/+iLT+8rg3vCsrBFnZHfAlRrV1tqB2H8bPxexzW1+PAAQY0XkZ3uE
# LieM2A==
# SIG # End signature block
