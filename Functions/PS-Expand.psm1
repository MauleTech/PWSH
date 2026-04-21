Function Expand-SystemPartition {
<#
	.SYNOPSIS
		Expands a system partition by relocating the Windows recovery partition to the end of the disk.

	.DESCRIPTION
		This function detects and relocates a Windows recovery partition that exists after the system
		partition, then expands the system partition to fill the available space. It is designed for
		Hyper-V VMs where the VHDX has been expanded but the guest partition cannot grow due to the
		recovery partition placement.

		The function performs the following steps:
		1. Verifies Administrator privileges
		2. Detects the disk number from the specified drive letter
		3. Finds the recovery partition that blocks expansion
		4. Disables Windows RE using reagentc /disable
		5. Deletes the recovery partition using diskpart
		6. Expands the system partition, leaving room for the new recovery partition
		7. Creates a new recovery partition at the end with proper GUID and GPT attributes
		8. Re-enables Windows RE using reagentc /enable or /setreimage

	.PARAMETER DriveLetter
		The drive letter of the system partition to expand. Defaults to "C".

	.PARAMETER RecoveryPartitionSizeMB
		The size in MB for the recreated recovery partition. Defaults to 1000 MB.

	.PARAMETER Force
		Skips confirmation prompts. Use with caution.

	.EXAMPLE
		Expand-SystemPartition
		Expands the C: drive using default settings with confirmation prompts.

	.EXAMPLE
		Expand-SystemPartition -DriveLetter "D" -RecoveryPartitionSizeMB 2000 -Force
		Expands the D: drive with a 2000 MB recovery partition without confirmation prompts.

	.EXAMPLE
		Expand-SystemPartition -WhatIf
		Shows what would happen without making any changes.

	.NOTES
		IMPORTANT: This operation carries risk and should be tested before production use.

		This function is designed for Hyper-V VMs where the VHDX has already been expanded
		but the guest partition cannot grow due to the recovery partition placement.

		Requires Administrator privileges to run.
		Uses diskpart for partition deletion as PowerShell cmdlets do not reliably delete recovery partitions.
#>
	[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
	param (
		[Parameter(Mandatory=$false)]
		[ValidatePattern('^[A-Za-z]$')]
		[string]$DriveLetter = "C",

		[Parameter(Mandatory=$false)]
		[ValidateRange(500, 10000)]
		[int]$RecoveryPartitionSizeMB = 1000,

		[Parameter(Mandatory=$false)]
		[switch]$Force
	)

	# Check for Administrator privileges
	$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	If (-not $IsAdmin) {
		Write-Error "This function requires Administrator privileges. Please run as Administrator."
		return
	}

	# Normalize drive letter
	$DriveLetter = $DriveLetter.ToUpper().TrimEnd(':')
	Write-Verbose "Checking drive letter: ${DriveLetter}:"

	# Verify the drive letter exists
	$SystemPartition = Get-Partition -DriveLetter $DriveLetter -ErrorAction SilentlyContinue
	If (-not $SystemPartition) {
		Write-Error "Drive letter ${DriveLetter}: does not exist."
		return
	}

	# Get disk number and partition information
	$DiskNumber = $SystemPartition.DiskNumber
	$OriginalSizeGB = [math]::Round($SystemPartition.Size / 1GB, 2)
	Write-Verbose "System partition ${DriveLetter}: is on Disk $DiskNumber and is currently $OriginalSizeGB GB"

	# Get all partitions on this disk
	$AllPartitions = Get-Partition -DiskNumber $DiskNumber | Sort-Object Offset
	Write-Verbose "Found $($AllPartitions.Count) partitions on Disk $DiskNumber"

	# Find the recovery partition that comes after the system partition
	$SystemPartitionOffset = $SystemPartition.Offset
	$RecoveryPartition = $AllPartitions | Where-Object {
		$_.Offset -gt $SystemPartitionOffset -and $_.Type -eq 'Recovery'
	} | Select-Object -First 1

	If (-not $RecoveryPartition) {
		Write-Warning "No recovery partition found after the system partition. The system partition may already be expanded or there may be no unallocated space."

		# Check for unallocated space
		$Disk = Get-Disk -Number $DiskNumber
		$TotalSize = $Disk.Size
		$UsedSize = ($AllPartitions | Measure-Object -Property Size -Sum).Sum
		$UnallocatedSpace = $TotalSize - $UsedSize
		$UnallocatedSpaceGB = [math]::Round($UnallocatedSpace / 1GB, 2)

		If ($UnallocatedSpaceGB -gt 0.1) {
			Write-Host "There is $UnallocatedSpaceGB GB of unallocated space available. You can expand the partition directly using Disk Management or the Resize-Partition cmdlet."
		} else {
			Write-Host "There is no significant unallocated space on the disk."
		}
		return
	}

	$RecoveryPartitionNumber = $RecoveryPartition.PartitionNumber
	$RecoveryPartitionSizeGB = [math]::Round($RecoveryPartition.Size / 1GB, 2)
	Write-Verbose "Found recovery partition: Partition $RecoveryPartitionNumber (Size: $RecoveryPartitionSizeGB GB)"

	# Calculate available space after removing recovery partition
	$Disk = Get-Disk -Number $DiskNumber
	$TotalDiskSize = $Disk.Size
	$UsedSpaceWithoutRecovery = ($AllPartitions | Where-Object { $_.PartitionNumber -ne $RecoveryPartitionNumber } | Measure-Object -Property Size -Sum).Sum
	$AvailableSpaceGB = [math]::Round(($TotalDiskSize - $UsedSpaceWithoutRecovery) / 1GB, 2)
	$ExpectedNewSizeGB = [math]::Round($OriginalSizeGB + $AvailableSpaceGB - ($RecoveryPartitionSizeMB / 1024), 2)

	Write-Host "`nCurrent Configuration:"
	Write-Host "  System Partition (${DriveLetter}:): $OriginalSizeGB GB"
	Write-Host "  Recovery Partition: $RecoveryPartitionSizeGB GB"
	Write-Host "  Available Space: $AvailableSpaceGB GB"
	Write-Host "  Expected New Size: $ExpectedNewSizeGB GB"
	Write-Host ""

	If ($AvailableSpaceGB -lt 1) {
		Write-Warning "Expanding the partition will not gain significant space (less than 1 GB). Aborting."
		return
	}

	# Confirmation prompt (unless -Force is specified)
	If (-not $Force -and -not $PSCmdlet.ShouldProcess("Drive ${DriveLetter}: on Disk $DiskNumber", "Relocate recovery partition and expand system partition")) {
		Write-Host "Operation cancelled by user."
		return
	}

	# Initialize result tracking
	$RecoveryPartitionRecreated = $false
	$WindowsREEnabled = $false
	$ErrorOccurred = $false

	Try {
		# Step 1: Disable Windows RE
		Write-Verbose "Disabling Windows RE..."
		$ReagentOutput = reagentc /disable 2>&1
		Write-Verbose "Reagentc output: $ReagentOutput"

		If ($LASTEXITCODE -ne 0) {
			Write-Warning "Failed to disable Windows RE. This may not be critical. Continuing..."
		} else {
			Write-Verbose "Windows RE disabled successfully."
		}

		# Step 2: Delete the recovery partition using diskpart
		Write-Verbose "Deleting recovery partition using diskpart..."
		$DiskpartScript = @"
select disk $DiskNumber
select partition $RecoveryPartitionNumber
delete partition override
"@

		$DiskpartScriptPath = "$env:TEMP\diskpart_script_$(Get-Random).txt"
		$DiskpartScript | Out-File -FilePath $DiskpartScriptPath -Encoding ASCII -Force

		$DiskpartOutput = diskpart /s $DiskpartScriptPath 2>&1 | Out-String
		Remove-Item -Path $DiskpartScriptPath -Force -ErrorAction SilentlyContinue

		Write-Verbose "Diskpart output: $DiskpartOutput"

		If ($DiskpartOutput -match "error|failed") {
			Throw "Diskpart failed to delete the recovery partition. Output: $DiskpartOutput"
		}

		Write-Verbose "Recovery partition deleted successfully."

		# Step 3: Expand the system partition
		Write-Verbose "Expanding system partition ${DriveLetter}:..."

		# Calculate the maximum size we can expand to (leaving room for recovery partition)
		$RecoveryPartitionSizeBytes = $RecoveryPartitionSizeMB * 1MB
		$MaxSize = $SystemPartition.Size + ($RecoveryPartition.Size) + ($TotalDiskSize - ($AllPartitions | Measure-Object -Property Size -Sum).Sum) - $RecoveryPartitionSizeBytes - (100MB)

		# Resize the partition
		Resize-Partition -DriveLetter $DriveLetter -Size $MaxSize -ErrorAction Stop
		Write-Verbose "System partition expanded successfully."

		# Step 4: Create new recovery partition at the end
		Write-Verbose "Creating new recovery partition..."

		# Create diskpart script for recovery partition
		$RecoveryDiskpartScript = @"
select disk $DiskNumber
create partition primary
format quick fs=ntfs label="Recovery"
set id="de94bba4-06d1-4d40-a16a-bfd50179d6ac"
gpt attributes=0x8000000000000001
"@

		$RecoveryScriptPath = "$env:TEMP\diskpart_recovery_$(Get-Random).txt"
		$RecoveryDiskpartScript | Out-File -FilePath $RecoveryScriptPath -Encoding ASCII -Force

		$RecoveryDiskpartOutput = diskpart /s $RecoveryScriptPath 2>&1 | Out-String
		Remove-Item -Path $RecoveryScriptPath -Force -ErrorAction SilentlyContinue

		Write-Verbose "Recovery partition diskpart output: $RecoveryDiskpartOutput"

		If ($RecoveryDiskpartOutput -match "error|failed") {
			Write-Warning "Failed to create recovery partition. Output: $RecoveryDiskpartOutput"
		} else {
			Write-Verbose "Recovery partition created successfully."
			$RecoveryPartitionRecreated = $true
		}

		# Step 5: Re-enable Windows RE
		Write-Verbose "Re-enabling Windows RE..."
		$ReenableOutput = reagentc /enable 2>&1 | Out-String
		Write-Verbose "Reagentc enable output: $ReenableOutput"

		If ($LASTEXITCODE -ne 0) {
			Write-Warning "Failed to enable Windows RE with /enable. Trying /setreimage..."
			$SetreimageOutput = reagentc /setreimage /path C:\Windows\System32\Recovery 2>&1 | Out-String
			Write-Verbose "Reagentc setreimage output: $SetreimageOutput"

			If ($LASTEXITCODE -eq 0) {
				$WindowsREEnabled = $true
				Write-Verbose "Windows RE enabled using /setreimage."
			} else {
				Write-Warning "Failed to enable Windows RE. Manual intervention may be required."
				Write-Warning "You can try manually running: reagentc /setreimage /path C:\Windows\System32\Recovery"
			}
		} else {
			$WindowsREEnabled = $true
			Write-Verbose "Windows RE enabled successfully."
		}

	} Catch {
		$ErrorOccurred = $true
		Write-Error "An error occurred during partition expansion: $_"

		# Attempt to recreate recovery partition if we deleted it but failed to expand
		If (-not $RecoveryPartitionRecreated) {
			Write-Warning "Attempting to recreate recovery partition to restore system state..."
			Try {
				$EmergencyRecoveryScript = @"
select disk $DiskNumber
create partition primary
format quick fs=ntfs label="Recovery"
set id="de94bba4-06d1-4d40-a16a-bfd50179d6ac"
gpt attributes=0x8000000000000001
"@
				$EmergencyScriptPath = "$env:TEMP\diskpart_emergency_$(Get-Random).txt"
				$EmergencyRecoveryScript | Out-File -FilePath $EmergencyScriptPath -Encoding ASCII -Force

				$EmergencyOutput = diskpart /s $EmergencyScriptPath 2>&1 | Out-String
				Remove-Item -Path $EmergencyScriptPath -Force -ErrorAction SilentlyContinue

				If ($EmergencyOutput -notmatch "error|failed") {
					$RecoveryPartitionRecreated = $true
					Write-Host "Emergency recovery partition creation succeeded."
				} else {
					Write-Warning "Emergency recovery partition creation failed. Manual recovery required."
				}
			} Catch {
				Write-Warning "Emergency recovery partition creation encountered an error: $_"
			}
		}
	}

	# Get final size
	$FinalPartition = Get-Partition -DriveLetter $DriveLetter -ErrorAction SilentlyContinue
	$NewSizeGB = If ($FinalPartition) { [math]::Round($FinalPartition.Size / 1GB, 2) } else { $OriginalSizeGB }

	# Output summary
	Write-Host "`n========================================" -ForegroundColor Cyan
	Write-Host "Partition Expansion Complete" -ForegroundColor Green
	Write-Host "========================================" -ForegroundColor Cyan
	Write-Host "Original Size: $OriginalSizeGB GB"
	Write-Host "New Size: $NewSizeGB GB"
	Write-Host "Space Gained: $([math]::Round($NewSizeGB - $OriginalSizeGB, 2)) GB"
	Write-Host "Recovery Partition Recreated: $RecoveryPartitionRecreated"
	Write-Host "Windows RE Enabled: $WindowsREEnabled"
	Write-Host "========================================`n" -ForegroundColor Cyan

	If ($ErrorOccurred) {
		Write-Warning "The operation completed with errors. Please review the output above."
	}

	# Return result object
	return [PSCustomObject]@{
		DriveLetter = "${DriveLetter}:"
		OriginalSizeGB = $OriginalSizeGB
		NewSizeGB = $NewSizeGB
		RecoveryPartitionRecreated = $RecoveryPartitionRecreated
		WindowsREEnabled = $WindowsREEnabled
	}
}

Function Expand-Terminal {
	mode con: cols=120 lines=60
	$host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size(120,10240)
}

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCRxcSa1c8F1Me9
# a6WykSoey7erSF3KybajxgSV76S1Q6CCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IHVeZyjiAg0eFm57oV+8jJhnFrcgG1f+bIHdsHaexCj6MA0GCSqGSIb3DQEBAQUA
# BIICAEOGTnifjNT77cJ4nyJfPjwE4jyl3mTo9kDYR0gIJ15+FuGPQF1UF5Ck4Ets
# UtqcR0Z5K9mHyd7jcFliQN26tiMAiEUi9dWbwN744DyZI44Myp4j5/xrQoxkYuyM
# TT9mnUnW6S+N8jhoaopAOJbeySxAfuAPQQznV6dZOe+7UN241qOEhFaWFVToeOGD
# Xmwvu/HgeSh3e2hTr8gU1grWh/iAeaV+BULu/pquIuSWDe2+xDiVSaoLTMVIqDlE
# JRKi6+e0jwTu4j2QHXBSlY0JRPNrei5B+aK6YJae9Z5M7cVw8LOnk9UVu7wSCY/Q
# aeuuZpVW3LKOJC89P8UVLuZRsgFz+jhWvf6zbrSEi3t7IBN345S2LZqA9Yr3VVKQ
# s1QQu67z49I6JzXVZ6pKcGfzyWAsYXDEvVecjng8xGWB04tQ33QopnF7iyOB7Oz0
# 11nlS4HSzOwd+QodACaRbVimBk1qx7HkFnwoy5UjEM1BjB/GLGDcgyDxj2JTr6vL
# DE90L3ozIn29U0Ux2eyjgANReLvFzejQu9dfLaJfKLw/qLokTa5STll4/WvC+hpx
# +V8Hlcq//Z69IqQhUXsZTk/Py8OX9lAB1eHijs6qyNupIhpHinw5kKIRJq6AxXBr
# 9l+Ji5bpQoPOzjhfF3MAdKhx0s0pJ9GPuihQPCBpmA/jwvasoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDQyMTE1MDE1MFowLwYJKoZIhvcNAQkEMSIEIIb3cBWv
# O/dX88RyPdldrdi9/Pz8ij/m28VgoNJJpeu6MA0GCSqGSIb3DQEBAQUABIICAAk6
# vq1AcTfZSCr85i2Gmp8Go1dthSpuDJ7F4ze034s3uYzjoDjT9nGirxd4r419ljdt
# k8CCssif3Zm6ksGXBtfF/MdPtqhTL/FXiYyulcRBVtNH3zdieIDGRDQK6hcM1oqk
# /+b9GE8bgoxiMJ4DFq2Zx7FNhne7pL9NJVsRh4Ok5Waq+VufMhhFnVU+oTKOu83Y
# qjH60C4TidHc4hgOfVfdnIsgt0y88O5QRPbtrEDEzEDZnw32T9D6oRC/OJUp5Ei/
# tREgfH1xrdkGGrOj/wvt7K2+RNSmaZWgilc8fP1xXCWq52rTYhmGNC2strQImLkS
# YkIcCpa9yoxcdxSs/cLbb6ov1fM3IfhFx4jEQM13dOUr7PmuDxRkOQpBaXAvhAd4
# NN8wdlt8FbG2BaRxbl7A7+Ee4c8aZiM8ibou2YhU251Dmyl0Rp/PB/YKYMPRki/k
# OnI4t5FhLHIDmjoA2n0Zr/5xNmyS//UYwE6axm3GTzI9DNbQZtkVeEfphEtznLxb
# z5kWg/97BIEtFCWBckAv50RdTvC2nNsomcMHkjFJP03mcOjWCLRFU4sGG4zHWjVv
# UGA8lhcMliZiv7DOg5pQPcdTfQXCFM24JjdYcDV4PWBtB+YJ/DaKYQoIUaRnPPjZ
# hfivyS8YLCWOY/X+v/P4gvBT7brlA8GKfuQAqCG+
# SIG # End signature block
