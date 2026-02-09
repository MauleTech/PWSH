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

# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUyejJE+GiyFFX88e0vQCrVAE4
# AqCgggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUfKWh
# valPX4n2jyYuN2FOeVQ6L0IwDQYJKoZIhvcNAQEBBQAEggEAi89DjvVdqD4fIv1m
# GhlCNbN3sqW+DIKz7QbP1V+J4LCcNGbu2aUR9rYl2d/aG3YKzYz50dPQpXgbCF8U
# ucj1/PY40zSCRQ9I8QWG+KY/xeOnGSkjdfj0jAfx6B9hl7Ua5V8THC4AVO9jfAcc
# 4GAB+8NzwznOfbwmj2vV7mXvhHqlpHC7ydisQnkfVkO/IW1BXUQokymU7KZea393
# 9UVNwZzZL+ZgJnZg1rmWevUMpZvcLd01js+6mUHgUQVxcztsQDcAoszKuo+xJg7s
# TZlTflsKABIZac5PaGqUC0HGaSCuAVIODGY6P3FCQOcwrxJ2viEWQscaS4OxyC/9
# AaLCsQ==
# SIG # End signature block