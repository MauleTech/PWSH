Function Optimize-Powershell {
	If ((Get-ExecutionPolicy -Scope CurrentUser) -ne 'RemoteSigned') {
    	Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction SilentlyContinue
	}
	$Commands = @()
		$Commands = @'
		$profileTimer = [System.Diagnostics.Stopwatch]::StartNew()
		$stepTimer = [System.Diagnostics.Stopwatch]::New()
		$profileTimings = [System.Collections.Generic.List[string]]::new()

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
			Write-Host "| " -NoNewLine -BackgroundColor Black -ForegroundColor Cyan
		    Write-Host "$env:USERNAME/$env:COMPUTERNAME" -NoNewLine -BackgroundColor Black -ForegroundColor DarkCyan
			Write-Host " | " -NoNewLine -BackgroundColor Black -ForegroundColor Cyan
			Write-Host "$(Get-Date -Format 'yyyy-MM-dd') $((Get-Date).ToString("HH:mm:ss"))" -NoNewLine -BackgroundColor Black -ForegroundColor Magenta
			Write-Host " |" -BackgroundColor Black -ForegroundColor Cyan
			Write-Host "| " -NoNewLine -BackgroundColor Black -ForegroundColor Cyan
			Write-Host "DIR: $($curdir.Path)" -BackgroundColor Black -ForegroundColor Yellow
		    "[Command]: "
		}

		# Module installation and configuration
		$ErrorActionPreference = 'SilentlyContinue'

		# Try importing AdvancedHistory directly (skip slow Get-Module -ListAvailable check)
		$stepTimer.Restart()
		$advHistoryLoaded = $false
		try {
		    Import-Module AdvancedHistory -Force -ErrorAction Stop
		    $advHistoryLoaded = $true
		} catch {
		    # Module not installed - need PackageManagement for install
		    if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
		        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force | Out-Null
		    }
		    if ((Get-PSRepository -Name "PSGallery").InstallationPolicy -eq "Untrusted") {
		        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
		    }
		    try {
		        Install-Module AdvancedHistory -Force -AllowClobber
		        Import-Module AdvancedHistory -Force -ErrorAction Stop
		        $advHistoryLoaded = $true
		    } catch {}
		}
		if ($advHistoryLoaded) {
		    try { Enable-AdvancedHistory -Unique } catch {}
		}
		$profileTimings.Add("AdvancedHistory: $("{0:N0}ms" -f $stepTimer.Elapsed.TotalMilliseconds)")

		# Try importing PSReadLine directly (skip slow Get-Module -ListAvailable check)
		$stepTimer.Restart()
		$psrlLoaded = $false
		try {
		    Import-Module PSReadline -Force -ErrorAction Stop
		    $psrlLoaded = $true
		} catch {
		    # Module not installed - ensure PackageManagement is ready
		    if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
		        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force | Out-Null
		    }
		    if ((Get-PSRepository -Name "PSGallery").InstallationPolicy -eq "Untrusted") {
		        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
		    }
		    try {
		        Install-Module PSReadline -Force -AllowClobber
		        Import-Module PSReadline -Force -ErrorAction Stop
		        $psrlLoaded = $true
		    } catch {}
		}
		$profileTimings.Add("PSReadLine: $("{0:N0}ms" -f $stepTimer.Elapsed.TotalMilliseconds)")

		# Configure PSReadLine prediction source
		if ($psrlLoaded) {
		    try {
		        Set-PSReadLineOption -PredictionSource HistoryAndPlugin
		    } catch {
		        try {
		            Set-PSReadLineOption -PredictionSource History
		        } catch {
		            Set-PSReadLineOption -PredictionSource None
		        }
		    }
		}

		# Execute additional configurations
		$stepTimer.Restart()
		irm https://raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt | iex
		$profileTimings.Add("LoadFunctions: $("{0:N0}ms" -f $stepTimer.Elapsed.TotalMilliseconds)")

		if ($PSScriptRoot -notlike "C:\Program Files (x86)\ITSPlatform\tmp\scripting\*") {
		    Expand-Terminal
		}

		$profileTimer.Stop()
		Write-Host " Profile loaded in $("{0:N1}s" -f $profileTimer.Elapsed.TotalSeconds) [$($profileTimings -join ' | ')]" -ForegroundColor DarkGray
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
