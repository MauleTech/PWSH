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
	Write-Host "Cleaning up install folder"
	Remove-PathForcefully -Path '$ITFolder\ITS247Agent'
}

Function Remove-PathForcefully {
	param(
		[parameter(Mandatory = $true)]
		[string] $Path
	)
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
	$itemsToDelete = Get-ChildItem -Path $targetDirectory -Recurse | Where-Object {
		$_.LastWriteTime -lt $thresholdDate
	}
	#$itemsToDelete.FullName
	#$itemsToDelete.Count
	foreach ($item in $itemsToDelete) {
		if ($item.PSIsContainer) {
			# If it's a folder, remove it recursively
			Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
			Write-Host $VerbosePreference
			If ( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ) { Write-Verbose "Deleted folder: $($item.FullName)" }
		}
		else {
			# If it's a file, remove it
			Remove-Item -Path $item.FullName -Force -ErrorAction SilentlyContinue
			If ( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ) { Write-Verbose "Deleted file: $($item.FullName)" }
		}
	}

	# Get all empty folders recursively
	$emptyFolders = Get-ChildItem -Path $targetDirectory -Recurse | Where-Object {
		$_.PSIsContainer -and @(Get-ChildItem -Path $_.FullName -Force).Count -eq 0
	}

	foreach ($folder in $emptyFolders) {
		Remove-Item -Path $folder.FullName -Force -ErrorAction SilentlyContinue
		If ( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ) { Write-Host "Deleted empty folder: $($folder.FullName)" }
	}
	$itemsUnableToDelete = Get-ChildItem -Path $targetDirectory -Recurse | Where-Object {
		$_.LastWriteTime -lt $thresholdDate
	}

	#Try again for stubborn items.
	ForEach ($StubbornItem in $itemsUnableToDelete) {
		Remove-PathForcefully -Path $StubbornItem.PSPath -Verbose
	}

	# Get all empty folders recursively
	$emptyFolders = Get-ChildItem -Path $targetDirectory -Recurse | Where-Object {
		$_.PSIsContainer -and @(Get-ChildItem -Path $_.FullName -Force).Count -eq 0
	}

	foreach ($folder in $emptyFolders) {
		Remove-PathForcefully -Path $folder.FullName -Verbose
		If ( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ) { Write-Host "Deleted empty folder: $($folder.FullName)" }
	}
	$itemsUnableToDelete = Get-ChildItem -Path $targetDirectory -Recurse | Where-Object {
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