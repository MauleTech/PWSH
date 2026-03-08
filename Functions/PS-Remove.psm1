Function Remove-ADStaleComputers {
	# Ask for the number of days without contact to disable a computer
	$disableDays = Read-Host -Prompt "Enter the number of days without contact to disable a computer (default: 180)"
	if (-not $disableDays) { $disableDays = 180 }

	# Ask for the number of days without contact to delete a computer
	$deleteDays = Read-Host -Prompt "Enter the number of days without contact to delete a computer (default: 365)"
	if (-not $deleteDays) { $deleteDays = 365 }

	# Get the cutoff dates for disabling and deleting computers
	$disableDate = (Get-Date).AddDays(-$disableDays)
	$deleteDate = (Get-Date).AddDays(-$deleteDays)

	# Get the list of computers that haven't been contacted since the cutoff dates
	$computersToDisable = Get-ADComputer -Filter { LastLogonTimeStamp -lt $disableDate -and Enabled -eq $true } -Properties LastLogonTimeStamp
	$computersToDelete = Get-ADComputer -Filter { LastLogonTimeStamp -lt $deleteDate -and Enabled -eq $false } -Properties LastLogonTimeStamp

	# Display the list of computers that will be disabled
	Write-Host "The following computers will be disabled:"
	$computersToDisable | Select-Object Name, @{Name = "LastLogonTimeStamp"; Expression = { [datetime]::FromFileTime($_.LastLogonTimeStamp).ToString("yyyy-MM-dd HH:mm:ss") } } | Format-Table

	# Display the list of computers that will be deleted
	Write-Host "The following computers will be deleted:"
	$computersToDelete | Select-Object Name, @{Name = "LastLogonTimeStamp"; Expression = { [datetime]::FromFileTime($_.LastLogonTimeStamp).ToString("yyyy-MM-dd HH:mm:ss") } } | Format-Table

	# Ask for confirmation before proceeding
	$confirm = Read-Host -Prompt "Do you want to proceed with disabling and deleting these computers? (y/n)"
	if ($confirm.ToLower() -ne 'y') {
		Write-Host "Operation cancelled."
		return
	}

	# Disable the computers
	foreach ($computer in $computersToDisable) {
		Disable-ADAccount -Identity $computer.SamAccountName
		Write-Host "Disabled computer: $($computer.Name)"
	}

	# Delete the computers from Active Directory
	foreach ($computer in $computersToDelete) {
		Remove-ADObject -Identity $computer.DistinguishedName -Recursive -Confirm:$false
		Write-Host "Deleted computer from Active Directory: $($computer.Name)"
	}
}

function Remove-ClaudeCode {
	<#
	.SYNOPSIS
		Removes Claude Code credentials and/or installation.
	.DESCRIPTION
		By default, removes only the current user's credentials (logout).
		Use -Full to completely uninstall (requires admin).

		Credentials are per-user, so logging out only affects the current account.
		The system-wide installation remains for other users.
	.PARAMETER Full
		Completely uninstall Claude Code (requires admin).
		Removes program files, PATH entry, and current user credentials.
	.PARAMETER Force
		Skip confirmation prompts.
	.EXAMPLE
		Remove-ClaudeCode
		# Removes credentials for current user only
	.EXAMPLE
		Remove-ClaudeCode -Full
		# Complete uninstall (admin required)
	.EXAMPLE
		Remove-ClaudeCode -Full -Force
		# Complete uninstall without prompts
	.NOTES
		Run this when done using Claude Code on a client machine.
	#>
	[CmdletBinding()]
	param(
		[switch]$Full,
		[switch]$Force
	)

	# Paths
	if (-not $Global:ITFolder) { $Global:ITFolder = "$env:SystemDrive\IT" }
	$ClaudeFolder = "$Global:ITFolder\ClaudeCode"
	$ClaudeExe = "$ClaudeFolder\claude.exe"
	$ClaudeConfig = "$env:USERPROFILE\.claude"
	$ClaudeJson = "$env:USERPROFILE\.claude.json"

	Write-Host "`n=== Removing Claude Code ===" -ForegroundColor Cyan

	# Try to logout via CLI first
	if (Test-Path $ClaudeExe) {
		if ($env:Path -notlike "*$ClaudeFolder*") { $env:Path = "$env:Path;$ClaudeFolder" }
		Write-Host "Running logout command..." -ForegroundColor Gray
		try { & $ClaudeExe auth logout 2>$null } catch { }
	}

	# Remove user credentials
	$CredsRemoved = $false
	if (Test-Path $ClaudeConfig) {
		Remove-Item -Path $ClaudeConfig -Recurse -Force -ErrorAction SilentlyContinue
		Write-Host " [OK] Removed credentials folder (.claude)" -ForegroundColor Green
		$CredsRemoved = $true
	}
	if (Test-Path $ClaudeJson) {
		Remove-Item -Path $ClaudeJson -Force -ErrorAction SilentlyContinue
		Write-Host " [OK] Removed config file (.claude.json)" -ForegroundColor Green
		$CredsRemoved = $true
	}

	if (-not $CredsRemoved) {
		Write-Host " [-] No credentials found for current user" -ForegroundColor Yellow
	}

	# Full uninstall
	if ($Full) {
		# Check admin
		$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
		$principal = New-Object Security.Principal.WindowsPrincipal($identity)
		if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
			Write-Host "`n[!] Administrator privileges required for full uninstall." -ForegroundColor Red
			Write-Host "    Run PowerShell as Administrator and try again." -ForegroundColor Yellow
			Write-Host "    Credentials for current user have been removed." -ForegroundColor Gray
			return
		}

		# Confirm unless forced
		if (-not $Force) {
			$confirm = Read-Host "`nCompletely remove Claude Code from this machine? (Y/N)"
			if ($confirm -ne "Y" -and $confirm -ne "y") {
				Write-Host "Cancelled. Credentials removed, program still installed." -ForegroundColor Yellow
				return
			}
		}

		# Remove program folder
		if (Test-Path $ClaudeFolder) {
			Remove-Item -Path $ClaudeFolder -Recurse -Force -ErrorAction SilentlyContinue
			Write-Host " [OK] Removed program folder ($ClaudeFolder)" -ForegroundColor Green
		}

		# Remove from system PATH
		$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
		if ($currentPath -like "*$ClaudeFolder*") {
			$newPath = ($currentPath -split ";" | Where-Object { $_ -ne $ClaudeFolder -and $_ -ne "" }) -join ";"
			[Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
			Write-Host " [OK] Removed from system PATH" -ForegroundColor Green
		}

		# Clean up any user-local installs too
		$UserClaudeFolder = "$env:LOCALAPPDATA\Programs\claude-code"
		$UserClaudeExe = "$env:LOCALAPPDATA\Microsoft\WindowsApps\claude.exe"
		if (Test-Path $UserClaudeFolder) {
			Remove-Item -Path $UserClaudeFolder -Recurse -Force -ErrorAction SilentlyContinue
			Write-Host " [OK] Removed user-local install" -ForegroundColor Green
		}
		if (Test-Path $UserClaudeExe) {
			Remove-Item -Path $UserClaudeExe -Force -ErrorAction SilentlyContinue
		}

		Write-Host "`nClaude Code completely uninstalled." -ForegroundColor Green
	} else {
		Write-Host "`nCredentials removed. Program still installed for other users." -ForegroundColor Green
		Write-Host "For full uninstall, run: Remove-ClaudeCode -Full (as admin)" -ForegroundColor Gray
	}
}

Function Remove-DuplicateFiles {
	param (
		[string]$Path = $PWD.Path,
		[switch]$Recurse = $False
	)
	If (-not(Get-Command "Remove-PathForcefully" -ErrorAction SilentlyContinue)) { irm raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt | iex }
	Function Remove-DuplicateFilesInt {
		$DuplicateFiles = @((Get-ChildItem -Path $Path -Force | Get-FileHash -ErrorAction SilentlyContinue | Group-Object -property hash | Where-Object { $_.count -gt 1 } | ForEach-Object { $_.group | Sort-Object { $_.Path.Length } | Select-Object -Skip 1 }).Path)
		If ($DuplicateFiles) {
			ForEach ($File in $DuplicateFiles) { Remove-PathForcefully -Path $file }
		}
		Else {
			Write-Host "No duplicate files found in $Path"
		}
	}
	If ($Recurse) {
		# Get all directories recursively and run Remove-DuplicateFiles for each directory
		Get-ChildItem -Directory -Recurse | ForEach-Object { Remove-DuplicateFilesInt -Path $_.FullName }
	}
 Else {
		Remove-DuplicateFilesInt
	}
}

Function Remove-ITS247InstallFolder {
	[Alias("Remove-PpkgInstallFolder")]
	[CmdletBinding()]
	param()
	Write-Host "Cleaning up install folders"
	Remove-PathForcefully -Path "$ITFolder\ITS247Agent"
	Remove-PathForcefully -Path "$ITFolder\PPKG"
	Remove-PathForcefully -Path "$ITFolder\Apps"
}

function Remove-OrphanedInstallerFiles {
    <#
    .SYNOPSIS
        Identifies and removes orphaned MSI/MSP files from the Windows Installer cache.

    .DESCRIPTION
        Compares files in C:\Windows\Installer against registry-registered packages.
        Files not registered are considered orphaned and removed by default.
        Displays associated product names where possible.

    .PARAMETER WhatIf
        Shows what would be deleted without actually removing files.

    .PARAMETER Verbose
        Shows detailed progress information.

    .EXAMPLE
        Remove-OrphanedInstallerFiles
        Deletes all orphaned installer files.

    .EXAMPLE
        Remove-OrphanedInstallerFiles -WhatIf
        Shows what would be deleted without removing anything.

    .NOTES
        Requires administrator privileges.
        Assumes backups exist for disaster recovery.
    #>

    [CmdletBinding(SupportsShouldProcess)]
    param()

    # Check for admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warning "This function requires administrator privileges. Please run as admin."
        return
    }

    function Get-MsiProductName {
        param([string]$MsiPath)

        try {
            $installer = New-Object -ComObject WindowsInstaller.Installer
            $database = $installer.GetType().InvokeMember(
                "OpenDatabase",
                [System.Reflection.BindingFlags]::InvokeMethod,
                $null, $installer, @($MsiPath, 0)
            )

            $query = "SELECT Value FROM Property WHERE Property = 'ProductName'"
            $view = $database.GetType().InvokeMember(
                "OpenView",
                [System.Reflection.BindingFlags]::InvokeMethod,
                $null, $database, @($query)
            )

            $view.GetType().InvokeMember("Execute", [System.Reflection.BindingFlags]::InvokeMethod, $null, $view, $null)
            $record = $view.GetType().InvokeMember("Fetch", [System.Reflection.BindingFlags]::InvokeMethod, $null, $view, $null)

            if ($record) {
                $productName = $record.GetType().InvokeMember("StringData", [System.Reflection.BindingFlags]::GetProperty, $null, $record, @(1))
                [System.Runtime.Interopservices.Marshal]::ReleaseComObject($record) | Out-Null
            }

            $view.GetType().InvokeMember("Close", [System.Reflection.BindingFlags]::InvokeMethod, $null, $view, $null)
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($view) | Out-Null
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($database) | Out-Null
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($installer) | Out-Null

            return $productName
        } catch {
            return $null
        }
    }

    function Get-MspProductName {
        param([string]$MspPath)

        try {
            $installer = New-Object -ComObject WindowsInstaller.Installer
            $summaryInfo = $installer.GetType().InvokeMember(
                "SummaryInformation",
                [System.Reflection.BindingFlags]::GetProperty,
                $null, $installer, @($MspPath, 0)
            )

            $title = $summaryInfo.GetType().InvokeMember("Property", [System.Reflection.BindingFlags]::GetProperty, $null, $summaryInfo, @(2))

            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($summaryInfo) | Out-Null
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($installer) | Out-Null

            return $title
        } catch {
            return $null
        }
    }

    # Build hashtable of registered packages with their product names
    Write-Verbose "Enumerating registered packages from registry..."
    $registeredPackages = @{}

    # Get products and their names
    $productBase = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products"
    Get-ChildItem $productBase -ErrorAction SilentlyContinue | ForEach-Object {
        $installProps = Join-Path $_.PSPath "InstallProperties"

        if (Test-Path $installProps) {
            $props = Get-ItemProperty $installProps -ErrorAction SilentlyContinue
            $localPkg = $props.LocalPackage
            $displayName = $props.DisplayName

            if ($localPkg) {
                $registeredPackages[$localPkg.ToLower()] = @{
                    Path = $localPkg
                    ProductName = $displayName
                    Type = "Product"
                }
            }
        }
    }

    # Get patches
    $patchBase = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Patches"
    Get-ChildItem $patchBase -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        $localPkg = $props.LocalPackage
        $displayName = $props.DisplayName

        if ($localPkg) {
            $registeredPackages[$localPkg.ToLower()] = @{
                Path = $localPkg
                ProductName = $displayName
                Type = "Patch"
            }
        }
    }

    Write-Verbose "Found $($registeredPackages.Count) registered packages"

    # Get all installer files
    Write-Verbose "Scanning C:\Windows\Installer..."
    $installerFiles = Get-ChildItem "C:\Windows\Installer\*.msi", "C:\Windows\Installer\*.msp" -ErrorAction SilentlyContinue

    # Separate into registered and orphaned
    $orphanedFiles = @()
    $registeredFiles = @()

    foreach ($file in $installerFiles) {
        $filePath = $file.FullName.ToLower()

        if ($registeredPackages.ContainsKey($filePath)) {
            $info = $registeredPackages[$filePath]
            $registeredFiles += [PSCustomObject]@{
                Name = $file.Name
                FullName = $file.FullName
                SizeMB = [math]::Round($file.Length / 1MB, 2)
                ProductName = $info.ProductName
                Type = $info.Type
                Status = "Registered"
            }
        } else {
            # Orphaned - try to extract product name from the file itself
            $productName = $null
            if ($file.Extension -eq ".msi") {
                $productName = Get-MsiProductName -MsiPath $file.FullName
            } elseif ($file.Extension -eq ".msp") {
                $productName = Get-MspProductName -MspPath $file.FullName
            }

            $orphanedFiles += [PSCustomObject]@{
                Name = $file.Name
                FullName = $file.FullName
                SizeMB = [math]::Round($file.Length / 1MB, 2)
                ProductName = if ($productName) { $productName } else { "(Unknown)" }
                Type = if ($file.Extension -eq ".msi") { "Product" } else { "Patch" }
                Status = "Orphaned"
            }
        }
    }

    # Display summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Windows Installer Cache Analysis" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $totalFiles = $installerFiles.Count
    $totalSizeMB = [math]::Round(($installerFiles | Measure-Object Length -Sum).Sum / 1MB, 2)
    $orphanedSizeMB = [math]::Round(($orphanedFiles | Measure-Object SizeMB -Sum).Sum, 2)
    $registeredSizeMB = [math]::Round(($registeredFiles | Measure-Object SizeMB -Sum).Sum, 2)

    Write-Host "`nTotal files in Installer folder: " -NoNewline
    Write-Host "$totalFiles" -ForegroundColor Yellow -NoNewline
    Write-Host " ($totalSizeMB MB)"

    Write-Host "Registered (in use):             " -NoNewline
    Write-Host "$($registeredFiles.Count)" -ForegroundColor Green -NoNewline
    Write-Host " ($registeredSizeMB MB)"

    Write-Host "Orphaned (safe to remove):       " -NoNewline
    Write-Host "$($orphanedFiles.Count)" -ForegroundColor Red -NoNewline
    Write-Host " ($orphanedSizeMB MB)"

    if ($orphanedFiles.Count -eq 0) {
        Write-Host "`nNo orphaned files found. Nothing to clean up." -ForegroundColor Green
        return
    }

    # Display orphaned files with product names
    Write-Host "`n----------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Orphaned Files to Remove" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor DarkGray

    $orphanedFiles | Sort-Object SizeMB -Descending | ForEach-Object {
        $sizeStr = "{0,8:N2} MB" -f $_.SizeMB
        $typeStr = if ($_.Type -eq "Product") { "[MSI]" } else { "[MSP]" }

        Write-Host "  $typeStr " -ForegroundColor DarkCyan -NoNewline
        Write-Host $sizeStr -ForegroundColor White -NoNewline
        Write-Host "  $($_.Name)" -ForegroundColor Gray -NoNewline
        Write-Host "  ->  " -ForegroundColor DarkGray -NoNewline
        Write-Host $_.ProductName -ForegroundColor Cyan
    }

    Write-Host "`n----------------------------------------" -ForegroundColor DarkGray

    # Process deletions
    $deletedCount = 0
    $deletedSize = 0
    $failedCount = 0

    if ($WhatIfPreference) {
        Write-Host "`n[WhatIf] Would delete $($orphanedFiles.Count) files, freeing $orphanedSizeMB MB" -ForegroundColor Magenta
    } else {
        Write-Host "`nDeleting orphaned files..." -ForegroundColor Yellow

        foreach ($file in $orphanedFiles) {
            if ($PSCmdlet.ShouldProcess($file.FullName, "Delete")) {
                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    $deletedCount++
                    $deletedSize += $file.SizeMB
                    Write-Verbose "Deleted: $($file.Name)"
                } catch {
                    $failedCount++
                    Write-Warning "Failed to delete $($file.Name): $($_.Exception.Message)"
                }
            }
        }

        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  Cleanup Complete" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "Files deleted:  " -NoNewline
        Write-Host $deletedCount -ForegroundColor Green
        Write-Host "Space freed:    " -NoNewline
        Write-Host "$([math]::Round($deletedSize, 2)) MB" -ForegroundColor Green

        if ($failedCount -gt 0) {
            Write-Host "Failed:         " -NoNewline
            Write-Host $failedCount -ForegroundColor Red
        }
    }

    Write-Host ""
}

Function Remove-PathForcefully {
	param(
		[parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias("FullName", "PSPath")]
		[string] $Path
	)
	process {
	<# the code below has been used from
		- https://blogs.technet.com/b/heyscriptingguy/archive/2013/10/19/weekend-scripter-use-powershell-and-pinvoke-to-remove-stubborn-files.aspx
	with inspiration from
		- http://www.leeholmes.com/blog/2009/02/17/moving-and-deleting-really-locked-files-in-powershell/
	and error handling from
		- https://blogs.technet.com/b/heyscriptingguy/archive/2013/06/25/use-powershell-to-interact-with-the-windows-api-part-1.aspx
	#>
	Add-Type -ErrorAction Ignore @'
		using System;
		using System.Text;
		using System.Runtime.InteropServices;

		public class Posh
		{
			public enum MoveFileFlags
			{
				MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
			}

			[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
			static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, MoveFileFlags dwFlags);

			public static bool MarkFileDelete (string sourcefile)
			{
				return MoveFileEx(sourcefile, null, MoveFileFlags.MOVEFILE_DELAY_UNTIL_REBOOT);
			}
		}
'@
	Function Remove-SubPath {
		param(
			[parameter(Mandatory = $true)]
			[string] $SubPath
		)
		$SubPath = (Resolve-Path $SubPath -ErrorAction SilentlyContinue).Path
		If ($SubPath) {
			try {
				Remove-Item $SubPath -Force -Recurse -ErrorAction Stop
				Write-Host -ForegroundColor Green -BackgroundColor Black "Deletion of $SubPath succeeded."
			}
			catch {
				$deleteResult = [Posh]::MarkFileDelete($SubPath)
				if ($deleteResult -eq $false) {
					throw ($Error[0]) # calls GetLastError
				}
				else {
					Write-Host -ForegroundColor Red -BackgroundColor Yellow "Deletion of ||$SubPath|| failed. Deleting at next boot."#`n$($_.Exception.Message)"
				}
			}
		}
	}
	If (Test-Path -Path $Path -Verbose) {
		$SubFiles = Get-ChildItem -Path $Path -Recurse -Force -File
		$SubFolders = Get-ChildItem -Path $Path -Recurse -Force -Directory
		If ($SubFiles -or $SubFolders) {
			$SubFiles | ForEach-Object { Remove-SubPath -SubPath $_.FullName }
			$SubFolders | ForEach-Object { Remove-SubPath -SubPath $_.FullName }
			Remove-SubPath -SubPath $Path
		}
		Else {
			Remove-SubPath -SubPath $Path
		}
	}
 Else {
		Write-Warning "$Path was not found."
	}
	}
	<#
	.SYNOPSIS
		Deletes all files and folders given immediately if they are not locked.
		If locked files are found, queues them up to be deleted upon next reboot.
		Recurse is assumed.
	.PARAMETER Path
		The file system path of the folder or file to be deleted.
	.EXAMPLE
		Remove-PathForcefully -Path "C:\Temp" # Deletes the folder C:\Temp and all files or folders within, queuing up any locked files for deletion on next reboot.
	#>
}

Function Remove-StaleObjects {
	param(
		[parameter(Mandatory = $true)]
		[string] $targetDirectory,
		[parameter(Mandatory = $true)]
		[Int] $DaysOld
	)
	# PowerShell script to delete files or folders older than 30 days in a specific directory
	#$targetDirectory = "C:\Program Files (x86)\ITSPlatform\agentcore\download"
	#$DaysOld = 30
	$thresholdDate = (Get-Date).AddDays(-$DaysOld)
	
	If (! $(Test-Path $targetDirectory -ErrorAction SilentlyContinue)) {
		Write-Warning "$targetDirectory does not exist."
		Break
	}
	# Recursively get all files and folders in the target directory
	$itemsToDelete = Get-ChildItem -Path $targetDirectory -Recurse -ErrorAction SilentlyContinue | Where-Object {
		$_.LastWriteTime -lt $thresholdDate
	}
	#$itemsToDelete.FullName
	#$itemsToDelete.Count
	foreach ($item in $itemsToDelete) {
		if ($item.PSIsContainer) {
			# If it's a folder, remove it recursively
			Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
			If ( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ) { Write-Verbose "Deleted folder: $($item.FullName)" }
		}
		else {
			# If it's a file, remove it
			Remove-Item -Path $item.FullName -Force -ErrorAction SilentlyContinue
			If ( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ) { Write-Verbose "Deleted file: $($item.FullName)" }
		}
	}

	# Get all empty folders recursively
	$emptyFolders = Get-ChildItem -Path $targetDirectory -Recurse -ErrorAction SilentlyContinue | Where-Object {
		$_.PSIsContainer -and @(Get-ChildItem -Path $_.FullName -Force -ErrorAction SilentlyContinue).Count -eq 0
	}

	foreach ($folder in $emptyFolders) {
		Remove-Item -Path $folder.FullName -Force -ErrorAction SilentlyContinue
		If ( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ) { Write-Host "Deleted empty folder: $($folder.FullName)" }
	}
	$itemsUnableToDelete = Get-ChildItem -Path $targetDirectory -Recurse -ErrorAction SilentlyContinue | Where-Object {
		$_.LastWriteTime -lt $thresholdDate
	}

	#Try again for stubborn items.
	ForEach ($StubbornItem in $itemsUnableToDelete) {
		Remove-PathForcefully -Path $StubbornItem.PSPath -Verbose
	}

	# Get all empty folders recursively
	$emptyFolders = Get-ChildItem -Path $targetDirectory -Recurse -ErrorAction SilentlyContinue | Where-Object {
		$_.PSIsContainer -and @(Get-ChildItem -Path $_.FullName -Force -ErrorAction SilentlyContinue).Count -eq 0
	}

	foreach ($folder in $emptyFolders) {
		Remove-PathForcefully -Path $folder.FullName -Verbose
		If ( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ) { Write-Host "Deleted empty folder: $($folder.FullName)" }
	}
	$itemsUnableToDelete = Get-ChildItem -Path $targetDirectory -Recurse -ErrorAction SilentlyContinue | Where-Object {
		$_.LastWriteTime -lt $thresholdDate
	}

	$SuccessfulDelete = $(($itemsToDelete).Count - ($itemsUnableToDelete).Count)
	If ($SuccessfulDelete) {
		Write-Host "Removed $($SuccessfulDelete.Count) objects."
		Write-Host "Cleanup of the directory $targetDirectory complete!"
	}
 Else {
		Write-Host "No objects older then $DaysOld days were deleted from $targetDirectory."
	}
	If ($itemsUnableToDelete) {
		Write-Warning "$($($itemsUnableToDelete).count) objects were found but were not able to be deleted"
	}
}

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBn4eAUsG7zGp/C
# YHKVP4n5HSw6979PT/cF+k+aOK2O1aCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# ILnpjfq+IQMxxMKYeR7GyiPHyfFNZmAetM1ZjgmyChZlMA0GCSqGSIb3DQEBAQUA
# BIICAAiV0IYvZS/C13ZoD2lQ+QmBYKTez1+3qogrEoqrpbTlA1bcuyHTvEoqeVn0
# hdN437YcffC9q1OwPwWCPURdSoGVq9dkuw2kpchU4HFMy5fseSpjwJ/8k7/Rimim
# Pey+2DWI6hKk3S7Z6TYsN9MA0IayXoLe2pr2aUZ3PYLa+rjQas0VgrMJ02bAp9eS
# 4efq4MJaYPv1jgjZuB0Oq1paKENO4Hegglsrdn72+x8j2CvA5QZey68aQr6KfMHi
# sb/Rc2DnTsijlP21r7zEcFs9UsKJQ6FeyVe+dGQhqDxQ84YpKDiRdNVurALnZzSb
# qMdJeUgNXxF5Uv4Ggd7kuMQPZnBNNvvv0DG6qLNlQ2s8WxAyz+NAKADN1SMSQNKI
# f+9/QwmR6MqVZXaLIc5Ty98Udy1WbSGlw6iHB9UI9G3NLRMyncL13xOa97q3bqu5
# 6fxV/VEaMXUJv5ZpvifQGu2GMFUFzG9w8O5fagOYTC53+LZOafvxxNR7MngTnPzY
# rWLVWVaptbc2MjT+zY+6GH70cyfmXUpubRFsl1Kl0QzkkGrmjF93v9/VLLI4dXg4
# bzVG4St59XC6B85EWZljqHv7lkM8Lio4c+XyJSMzKen0YZKOKwafcD7WtGx2vg2d
# vblJWpQvL5GF0h6dB/AumdILBwosORpkHE0SqVK7zWUj1U1aoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDMwODIzMjIyNVowLwYJKoZIhvcNAQkEMSIEINSVvZN3
# 5c0d/1nVOiT/PUs/G9hspvy7Vwj8x4liazmwMA0GCSqGSIb3DQEBAQUABIICACBs
# iZVJhpZ1RXMmsqitEC9SrnMnMUAVnrYknfMMFF1sWBOnrBnKz6hcRFlQkWmINHIz
# Q0r80/xJtat9DV75+vo/W4q+swsZbfXdmgUxHHhYh7WOD0sRkCqjCznVnpimjn0j
# y52FXfvpCeeh5oSFl4urQzaCZyxnj33x3cQCmwlrrIcEBkvcMjfPu+gbRdciRK2s
# qpyukr8pbnKNiC2ftpzU6V09HvjXepeG72OeF0NI5tNOfgLfcGn23oQQUj0SBCpK
# Ijm9gLjE1Cb4x+BtVJJ9qTC/Yh3FWYWS0L6IWjSn7EJAdkfT30YsASv5sZlCpgrL
# RGklXMteVZzbWPfkv/aEOxWw6JI/X9HCxB3S1cOpVZBfH2HKgpQa65NxtbhhnRlP
# BqukbcJFcnsKx+Ujclz58UgHe8Hi5v0/pLeLQ5dnGpah5zku9SuBIBkAda9s69O5
# lpyET2reJn2Wo0TJTwUc2v25EP3uhja+QuI5pqmbtWjRFPPtlYr22mLfhDjMZAYS
# MADndU6kpm+j3fk8Cy7G3KkQUMoz/RLZR4/3laDXpI9aNYpJg+Luto4miUuRsLd7
# utZfuAqbPc7PTVH+ThklZVLDvdxqablHFZXZfiiRFaHmm7sugRZTcgKSVaTtTrnn
# OQH6zJ+R5s+NoQwpbEfIAeKjSV+2rsF8WXfQtmxU
# SIG # End signature block
