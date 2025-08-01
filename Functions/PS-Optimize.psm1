Function Optimize-Powershell {
	If ((Get-ExecutionPolicy -Scope CurrentUser) -ne 'RemoteSigned') {
    	Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
	}
	$Commands = @()
		$Commands = @'
		Function Get-HorizontalLine {
			param (
				[string]$InputString = "-", 
				[parameter(Mandatory = $false)][alias("c")]$Count = 1, 
				[parameter(Mandatory = $false)][alias("fg")]$ForeColor=$null, 
				[parameter(Mandatory = $false)][alias("bg")]$BackColor=$null
			) 
			$ColorSplat = @{}
			if ($ForeColor -ne $null) { $ColorSplat.ForegroundColor = $ForeColor }
			if ($BackColor -ne $null) { $ColorSplat.BackgroundColor = $BackColor }
			
			# How long to make the hr
			$width = if ($host.Name -match "ISE") {
				$host.UI.RawUI.BufferSize.Width - 1
			} else { 
				$host.UI.RawUI.BufferSize.Width - 4
			}
			# How many times to repeat $Character in full
			$repetitions = [System.Math]::Floor($width/$InputString.Length)
			# How many characters of $InputString to add to fill each line
			$remainder = $width - ($InputString.Length * $repetitions)
			# Make line(s)
			1..$Count | % { 
				Write-Host ($InputString * $repetitions) + $InputString.Substring(0,$remainder) @ColorSplat 
			}
		}
		# Custom prompt function
		Function prompt {
		    $curdir = $ExecutionContext.SessionState.Path.CurrentLocation
		    if ($curdir.Path.Length -eq 0) {
		        $curdir = "$($ExecutionContext.SessionState.Drive.Current.Name):\"
		    }
		    
		    Get-HorizontalLine -ForeColor Cyan
			Write-Host "| " -NoNewLine -BackgroundColor Black -ForegroundColor Red
		    Write-Host "$env:USERNAME/$env:COMPUTERNAME" -NoNewLine -BackgroundColor Black -ForegroundColor DarkCyan
			Write-Host " | " -NoNewLine -BackgroundColor Black -ForegroundColor Red
			Write-Host "$(Get-Date -Format 'yyyy-MM-dd') $((Get-Date).ToString("HH:mm:ss"))" -NoNewLine -BackgroundColor Black -ForegroundColor Magenta
			Write-Host " |" -BackgroundColor Black -ForegroundColor Red
			Write-Host "| " -NoNewLine -BackgroundColor Black -ForegroundColor Red
			Write-Host "DIR: $($curdir.Path)" -BackgroundColor Black -ForegroundColor Yellow
		    "[Command]: "
		}
		
		# Module installation and configuration
		$ErrorActionPreference = 'SilentlyContinue'
		
		# Configure PSGallery
		if ((Get-PSRepository -Name "PSGallery").InstallationPolicy -eq "Untrusted") {
		    Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
		}
		
		# Install and configure AdvancedHistory
		if (!(Get-Module -Name AdvancedHistory -ListAvailable)) {
		    Install-Module AdvancedHistory -Force -AllowClobber
		}
		Import-Module AdvancedHistory -Force
		try {
		    Enable-AdvancedHistory -Unique
		} catch {}
		
		# Install and configure PSReadline
		if (!(Get-Module -Name PSReadline -ListAvailable)) {
		    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
		        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force
		    }
		    Install-Module PSReadline -Force -AllowClobber
		}
		Import-Module PSReadline -Force
		
		# Configure PSReadLine prediction source
		try {
		    Set-PSReadLineOption -PredictionSource HistoryAndPlugin
		} catch {
		    try {
		        Set-PSReadLineOption -PredictionSource History
		    } catch {
		        Set-PSReadLineOption -PredictionSource None
		    }
		}
		
		# Execute additional configurations
		irm rb.gy/0kyfn2 | iex
		
		if ($PSScriptRoot -notlike "C:\Program Files (x86)\ITSPlatform\tmp\scripting\*") {
		    Expand-Terminal
		}
'@

	$WinVer = [System.Environment]::OSVersion.Version.Major

	If ($WinVer -ge 10) {

		If((Test-Path -LiteralPath "HKCU:\Console") -ne $true) {  New-Item "HKCU:\Console" -force -ea SilentlyContinue }
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CurrentPage' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'PopupColors' -Value 245 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'InsertMode' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'QuickEdit' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'ScreenBufferSize' -Value 7864440 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'WindowSize' -Value 3932280 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FontSize' -Value 917504 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FontFamily' -Value 54 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FontWeight' -Value 400 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FaceName' -Value 'Lucida Console' -PropertyType String -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CursorSize' -Value 25 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'HistoryBufferSize' -Value 25 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'NumberOfHistoryBuffers' -Value 4 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'HistoryNoDup' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'LineWrap' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FilterOnPaste' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CtrlKeyShortcutsDisabled' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'LineSelection' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'WindowAlpha' -Value 255 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'ForceV2' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'ExtendedEditKey' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CursorType' -Value 3 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CursorColor' -Value -1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'InterceptCopyPaste' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'TerminalScrolling' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'DefaultForeground' -Value -1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'DefaultBackground' -Value -1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'WindowPosition' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
		#Write-Output "Windows 10"
	} Else {

		if((Test-Path -LiteralPath "HKCU:\Console") -ne $true) {  New-Item "HKCU:\Console" -force -ea SilentlyContinue }
	if((Test-Path -LiteralPath "HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe") -ne $true) {  New-Item "HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe" -force -ea SilentlyContinue };
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CurrentPage' -Value 2 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'ForceV2' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'ExtendedEditKey' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'PopupColors' -Value 245 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'InsertMode' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'QuickEdit' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'ScreenBufferSize' -Value 327680120 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'WindowSize' -Value 3932280 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FontSize' -Value 786432 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FontFamily' -Value 54 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FontWeight' -Value 400 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FaceName' -Value 'Lucida Console' -PropertyType String -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CursorSize' -Value 25 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'HistoryBufferSize' -Value 25 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'NumberOfHistoryBuffers' -Value 4 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'HistoryNoDup' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'LineWrap' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'FilterOnPaste' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CtrlKeyShortcutsDisabled' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'LineSelection' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'WindowAlpha' -Value 255 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CursorType' -Value 3 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'CursorColor' -Value -1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'InterceptCopyPaste' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'TerminalScrolling' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'DefaultForeground' -Value -1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'DefaultBackground' -Value -1 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console' -Name 'WindowPosition' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe' -Name 'ScreenBufferSize' -Value 671088790 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe' -Name 'FaceName' -Value 'Lucida Console' -PropertyType String -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe' -Name 'HistoryNoDup' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe' -Name 'WindowSize' -Value 3932310 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe' -Name 'FontSize' -Value 786439 -PropertyType DWord -Force -ea SilentlyContinue | Out-Null
	Write-Output "Not Windows 10"
	}

	If (-Not (Test-Path $PROFILE -EA SilentlyContinue)) {
		New-Item -Type File -Force $PROFILE
	} Else {
		Remove-Item -Path $PROFILE -Force -EA SilentlyContinue
		New-Item -Type File -Force $PROFILE
	}

	$Commands | Out-File -FilePath $Profile -Force

	If ($PSVersionTable.PSEdition -like "Desktop") {
		Start-Process C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ArgumentList "-NoExit -Mta"
	} Else {
		Start-Process 'pwsh.exe' -ArgumentList "-NoExit -Mta"
	}
}

# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUuNtlQG+Ei4bPM4lz7prkRJWH
# Ru6gggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUSPjh
# XYFFY6bYdTI1LwsVbjNOH10wDQYJKoZIhvcNAQEBBQAEggEAO+sAl+HFId1zZ4FC
# FXi2BmxiRi7FtLOXVr68sf1ZGWvQiIaWzdycPa8jd05rlS8+q1Q1vGnTdSYRgnH+
# T9/OWk7iX4VI/pm+UabBVSFC9G/ADxmhezaM3Awv91F75KOoK+5JO0iVtZdIyv8T
# VCf3A3jgWnqvWi0mCzBRo6Dp0cFmZzq9jUjqGNib75LTBnThGa+oCc7TPSPNL6vB
# pF0QaTRBojpRPq7ox8FkEZfEdheG/ScpvpjthWes7POJKtkSnh+eKVAQc+aN/2LV
# /vTk8MtzQgn64RtLHUQ43DwPCmE5FpvgYRQzA434rwFyPHEvoniAN3VW3OVG2haB
# ivnx+g==
# SIG # End signature block
