Function Convert-ComputerFleetReport {
<#
.SYNOPSIS
    Creates a formatted Excel report from a system information CSV file with hardware and warranty details.

.DESCRIPTION
    This function processes a CSV file containing system inventory information, performs data cleanup,
    checks for Dell/Alienware warranty information, and creates a formatted Excel report.
    
    The function performs the following operations:
    - Removes unnecessary columns
    - Moves the serial number column to the far right
    - Removes duplicate entries based on device name
    - For Dell/Alienware systems, retrieves warranty information
    - Formats the data in Excel with conditional formatting based on warranty status
    - Renames columns and cleans up text for better readability

.PARAMETER InputFile
    Path to the input CSV file containing system information data.

.PARAMETER OutputFile
    Path where the output Excel file will be saved. If not specified, the output will use the
    same filename as the input but with a .xlsx extension.

.EXAMPLE
    Convert-ComputerFleetReport -InputFile "C:\Data\SystemInfo.csv"
    
    Processes the SystemInfo.csv file and creates SystemInfo.xlsx in the same folder with
    formatted warranty information.

.EXAMPLE
    Convert-ComputerFleetReport -InputFile "C:\Data\SystemInfo.csv" -OutputFile "C:\Reports\FleetReport.xlsx"
    
    Processes the SystemInfo.csv file and saves the formatted report to the specified output path.

.NOTES
    Requires:
    - The ImportExcel PowerShell module (will attempt to install if not present)
    - The Get-DellWarranty function to be available in the environment
    
    Output formatting:
    - Expired warranties: Red background
    - Warranties expiring within a year: Yellow background
    - Valid warranties with more than a year remaining: Green background
    - Systems with no warranty information: Blue background
    
    Author: Ryan C Shoemaker
    Last Updated: February 2025
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$InputFile,
        
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$OutputFile = [System.IO.Path]::ChangeExtension($InputFile, ".xlsx")
    )

    # Columns to remove
    $columnsToRemove = @(
        "Device Type",
        "Company Name",
        "Company Friendly Name",
        "Site Name",
        "Site Friendly Name",
        "OS Architecture",
        "OS Language",
        "IP Address",
        "External IP Address",
        "System Domain Role",
        "Installed Date",
        "Processor Type",
        "Number Of Processors",
        "Disk Manufacturer/Model",
        "Disk Interface Type",
        "Partitions",
        "BIOS Version",
        "BIOS Manufacturer",
        "BIOS Serial No",
        "Bios Product",
        "Device Time Zone"
    )

    # Import the CSV
    $data = Import-Csv -Path $InputFile

    # Identify all column names in the CSV
    $allColumns = $data[0].PSObject.Properties.Name

    # Create a list of columns to keep (excluding both the ones to remove and Device Serial Number)
    $columnsToKeep = $allColumns | Where-Object {
        ($_ -notin $columnsToRemove) -and ($_ -ne "Device Serial Number")
    }

    # Add Device Serial Number as the last column
    $newColumnOrder = $columnsToKeep + @("Device Serial Number")

    # Process data to handle duplicates by "Name" property
    $groupedData = $data | Group-Object -Property "Name"
    $uniqueData = @()

    foreach ($group in $groupedData) {
        if ($group.Count -eq 1) {
            # No duplicates, add the single entry
            $uniqueData += $group.Group
        } else {
            # First, remove entries with "Disk Volume (GB)" of 0
            $filteredEntries = $group.Group | Where-Object {
                try {
                    [double]$_."Disk Volume (GB)" -ne 0
                } catch {
                    $true # Keep entries where we can't convert to number
                }
            }
            
            # If all entries had 0 disk volume or we filtered everything out, keep original entries
            if ($filteredEntries.Count -eq 0) {
                $filteredEntries = $group.Group
            }
            
            # If we still have duplicates, keep the one with the smallest disk volume
            if ($filteredEntries.Count -gt 1) {
                # Sort by disk volume (converted to number) and take the first (smallest)
                $filteredEntries = $filteredEntries | Sort-Object -Property @{
                    Expression = {
                        try { [double]$_."Disk Volume (GB)" }
                        catch { [double]::MaxValue } # If conversion fails, treat as maximum value
                    }
                } | Select-Object -First 1
            }
            
            $uniqueData += $filteredEntries
        }
    }

    # Add the new warranty columns to each entry
    $uniqueData = $uniqueData | ForEach-Object {
        $_ | Add-Member -NotePropertyName "OriginalShipDate" -NotePropertyValue "" -PassThru |
              Add-Member -NotePropertyName "WarrantyStartDate" -NotePropertyValue "" -PassThru |
              Add-Member -NotePropertyName "WarrantyEndDate" -NotePropertyValue "" -PassThru |
              Add-Member -NotePropertyName "WarrantyExpired" -NotePropertyValue "" -PassThru |
              Add-Member -NotePropertyName "WarrantySupportLevel" -NotePropertyValue ""
        $_
    }

    # Get warranty information for Dell and Alienware systems
    Write-Host "Getting warranty information for Dell and Alienware systems..."
    $dellSystems = $uniqueData | Where-Object {
        $_."Base Board Manufacturer" -match "Dell|Alienware" -and
        -not [string]::IsNullOrWhiteSpace($_."Device Serial Number")
    }

    if ($dellSystems.Count -gt 0) {
        Write-Host "Found $($dellSystems.Count) Dell/Alienware systems. Retrieving warranty information..."
        foreach ($system in $dellSystems) {
            try {
                Write-Host "Processing warranty for system: $($system.Name) with Serial: $($system."Device Serial Number")"
                $warrantyInfo = Get-DellWarranty -ServiceTags $system."Device Serial Number" -ReturnObject
                
                if ($warrantyInfo) {
                    # Update the warranty fields in the original data
                    $systemInData = $uniqueData | Where-Object { $_.Name -eq $system.Name }
                    if ($systemInData) {
                        $systemInData.OriginalShipDate = $warrantyInfo.OriginalShipDate
                        $systemInData.WarrantyStartDate = $warrantyInfo.WarrantyStartDate
                        $systemInData.WarrantyEndDate = $warrantyInfo.WarrantyEndDate
                        $systemInData.WarrantyExpired = $warrantyInfo.WarrantyExpired
                        $systemInData.WarrantySupportLevel = $warrantyInfo.WarrantySupportLevel
                        
                        Write-Host "Updated warranty information for $($system.Name)"
                    }
                } else {
                    Write-Host "No warranty information found for $($system.Name)" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Error retrieving warranty information for $($system.Name): $_" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No Dell or Alienware systems found in the data."
    }

    # Remove OriginalShipDate and WarrantySupportLevel from the column order
    $newColumnOrder = $newColumnOrder | Where-Object { $_ -ne "OriginalShipDate" -and $_ -ne "WarrantySupportLevel" }
    
    # Select the data with the new column order including only the warranty columns we want to keep
    $newColumnOrder += @("WarrantyStartDate", "WarrantyEndDate", "WarrantyExpired")

    # Create the final dataset with the specified column order
    $newData = $uniqueData | Select-Object -Property $newColumnOrder

    # Clean up data
    foreach ($item in $newData) {
        # Clean up processor description
        if ($item.Processor) {
            # Remove (R) and Core(TM)
            $item.Processor = $item.Processor -replace '\(R\)', '' -replace ' Core\(TM\)', ''
            
            # Keep only the string before "CPU" if it exists, otherwise before "@"
            if ($item.Processor -match "(.+?)\s+CPU") {
                $item.Processor = $matches[1].Trim()
            } elseif ($item.Processor -match "(.+?)\s+@") {
                $item.Processor = $matches[1].Trim()
            }
        }
        
        # Clean up OS name
        if ($item.OS) {
            $item.OS = $item.OS -replace 'Microsoft ', ''
        }
        
        # Clean up manufacturer name
        if ($item."Base Board Manufacturer") {
            $item."Base Board Manufacturer" = $item."Base Board Manufacturer" -replace ' Corporation', ''
        }
        
        # Format date fields
        if ($item."Last Check Date") {
            try {
                # Get only the date part (before first space)
                $datePart = $item."Last Check Date".Split(' ')[0]
                # Parse and reformat as m/d/yyyy
                $parsedDate = [DateTime]::Parse($datePart)
                $item."Last Check Date" = $parsedDate.ToString('M/d/yyyy')
            } catch {
                # Keep original if parsing fails
            }
        }
        
        if ($item."WarrantyStartDate") {
            try {
                # If there's a space in the date string, get only the part before the space
                if ($item."WarrantyStartDate" -match " ") {
                    $datePart = $item."WarrantyStartDate".Split(' ')[0]
                } else {
                    $datePart = $item."WarrantyStartDate"
                }
                # Parse and reformat as m/d/yyyy
                $parsedDate = [DateTime]::Parse($datePart)
                $item."WarrantyStartDate" = $parsedDate.ToString('M/d/yyyy')
            } catch {
                # Keep original if parsing fails
            }
        }
        
        if ($item."WarrantyEndDate") {
            try {
                # If there's a space in the date string, get only the part before the space
                if ($item."WarrantyEndDate" -match " ") {
                    $datePart = $item."WarrantyEndDate".Split(' ')[0]
                } else {
                    $datePart = $item."WarrantyEndDate"
                }
                # Parse and reformat as m/d/yyyy
                $parsedDate = [DateTime]::Parse($datePart)
                $item."WarrantyEndDate" = $parsedDate.ToString('M/d/yyyy')
            } catch {
                # Keep original if parsing fails
            }
        }
    }

    # Rename columns
    $columnMappings = @{
        'Number of Cores' = 'Cores'
        'Disk Volume (GB)' = 'Disk Size'
        'Device Serial Number' = 'Serial #'
        'Base Board Manufacturer' = 'Manufacturer'
        'WarrantyStartDate' = 'Warranty Start'
        'WarrantyEndDate' = 'Warranty End'
        'WarrantyExpired' = 'Status'
        'Last Check Date' = 'Last Check'
    }

    # Clean up and adjust column names in the column order list
    $adjustedColumnOrder = $newColumnOrder | ForEach-Object {
        if ($columnMappings.ContainsKey($_)) {
            $columnMappings[$_]
        } else {
            $_
        }
    }

    # Create a collection with renamed properties
    $renamedData = $newData | ForEach-Object {
        $obj = New-Object PSObject
        foreach ($prop in $_.PSObject.Properties) {
            $newName = if ($columnMappings.ContainsKey($prop.Name)) { $columnMappings[$prop.Name] } else { $prop.Name }
            $obj | Add-Member -MemberType NoteProperty -Name $newName -Value $prop.Value
        }
        $obj
    }

    # Export to Excel with formatting
    Write-Host "Creating Excel file with formatting..."

    # Check if Excel module is available, if not, attempt to install it
    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
        Write-Host "ImportExcel module not found. Attempting to install..."
        try {
            Install-Module -Name ImportExcel -Force -Scope CurrentUser
            Import-Module ImportExcel
            Write-Host "ImportExcel module installed successfully."
        } catch {
            Write-Host "Unable to install ImportExcel module. Exiting." -ForegroundColor Red
            exit
        }
    }

    # Calculate the date one year from now for warranty comparisons
    $oneYearFromNow = (Get-Date).AddYears(1)

    # Export data to Excel with conditional formatting
    $excelParams = @{
        Path = $OutputFile
        TableName = "SystemInformation"
        TableStyle = "Medium15"
        AutoSize = $true
        FreezeTopRow = $true
        WorksheetName = "System Information"
    }

    $renamedData | Export-Excel @excelParams -PassThru | ForEach-Object {
        # Get the worksheet
        $workSheet = $_.Workbook.Worksheets["System Information"]
        
        # Get the row count (excluding header)
        $rowCount = $workSheet.Dimension.Rows
        
        # Find column indexes
        $statusCol = $null
        $warrantyEndCol = $null
        $serialNumberCol = $null
        $warrantyStartCol = $null
        $lastCheckCol = $null
        
        for ($col = 1; $col -le $workSheet.Dimension.Columns; $col++) {
            $headerValue = $workSheet.Cells[1, $col].Value
            
            if ($headerValue -eq "Status") {
                $statusCol = $col
            }
            elseif ($headerValue -eq "Warranty End") {
                $warrantyEndCol = $col
            }
            elseif ($headerValue -eq "Serial #") {
                $serialNumberCol = $col
            }
            elseif ($headerValue -eq "Warranty Start") {
                $warrantyStartCol = $col
            }
            elseif ($headerValue -eq "Last Check") {
                $lastCheckCol = $col
            }
        }
        
        # Format the Serial Number column as text to preserve leading zeros
        if ($serialNumberCol) {
            for ($row = 2; $row -le $rowCount; $row++) {
                $workSheet.Cells[$row, $serialNumberCol].Style.Numberformat.Format = "@"
            }
        }
        
        # Format date columns with short date format
        foreach ($dateCol in @($warrantyStartCol, $warrantyEndCol, $lastCheckCol)) {
            if ($dateCol) {
                for ($row = 2; $row -le $rowCount; $row++) {
                    $workSheet.Cells[$row, $dateCol].Style.Numberformat.Format = "m/d/yyyy"
                }
            }
        }
        
        # Apply conditional formatting based on warranty status
        if ($statusCol -and $warrantyEndCol) {
            for ($row = 2; $row -le $rowCount; $row++) {
                $statusValue = $workSheet.Cells[$row, $statusCol].Value
                $endDateValue = $workSheet.Cells[$row, $warrantyEndCol].Value
                
                # Convert end date from string if needed
                if ($endDateValue -and $endDateValue -is [string]) {
                    try {
                        $endDateValue = [DateTime]::Parse($endDateValue)
                    } catch {
                        $endDateValue = $null
                    }
                }
                
                # Apply styles based on conditions
                $entireRow = $workSheet.Cells[$row, 1, $row, $workSheet.Dimension.Columns]
                
                if ([string]::IsNullOrWhiteSpace($statusValue)) {
                    # Empty warranty - Note style (light blue)
                    $entireRow.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                    $entireRow.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(218, 238, 243))
                } elseif ($statusValue -eq "Expired") {
                    # Expired warranty - Bad style (light red)
                    $entireRow.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                    $entireRow.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(255, 199, 206))
                } elseif ($statusValue -eq "Not Expired" -and $endDateValue) {
                    if ($endDateValue -le $oneYearFromNow) {
                        # Less than a year left - Neutral style (light yellow)
                        $entireRow.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                        $entireRow.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(255, 235, 156))
                    } else {
                        # More than a year left - Good style (light green)
                        $entireRow.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                        $entireRow.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(198, 239, 206))
                    }
                }
            }
        }
        
        # Save the workbook
        $_.Save()
        $_.Dispose()
    }

    Write-Host "Excel file has been created and saved to: $OutputFile"
    Write-Host "Original row count: $($data.Count)"
    Write-Host "Final row count after removing duplicates: $($newData.Count)"
}

Function Convert-ToSharedMailbox {
	param
	(
		[Parameter(Mandatory = $false)]
		[string]$DateLeft,

		[Parameter(Mandatory = $false)]
		[string]$Alias,

		[Parameter(Mandatory = $false)]
		[string]$GiveAccessTo,

		[Parameter(Mandatory = $false)]
		[ValidateSet('FullAccess', 'ReadPermission')]
		[string]$GiveAccessPermission,

		[Parameter(Mandatory = $false)]
		[string]$DirectEmailTo,

		[Parameter(Mandatory = $false)]
		[switch]$NoAccess = $False,

		[Parameter(Mandatory = $false)]
		[switch]$NoReply = $False
	)

	If (-not $DateLeft) { $DateLeft = Read-Host "Please enter the date this person left in DDMMMYYY format, i.e. 01JAN2001" }
	If (-not $Alias) { $Alias = Read-Host "Please enter the persons alias, the part of their email before the @ sign." }
	$DeletedMailbox = Get-EXOMailbox -SoftDeletedMailbox -Identity $Alias -ErrorAction SilentlyContinue
	If (-not $DeletedMailbox) {
		Do {
			#Active User Check
			If ($(Get-EXOMailbox -Identity $Alias -ErrorAction SilentlyContinue)) {
				Write-Host "That mailbox appears to be for an active user."
				$Response = Read-Host -Prompt "Do you want to forcefully delete the user and proceed? (y/N)"
				If (-not $Response) { $Response = "else" }
				If ($Response -like "y*") {
					Write-Host "Forcefully deleting the mailbox for $($DeletedMailbox.DisplayName)."
					Write-Host "Please ensure sync is disabled for the user."
					Remove-Mailbox -Identity $Alias
				}
				Else { Break }
			}
			#Retry the alias
			$Alias = Read-Host "That alias didn't work. Enter another one or type QUIT to stop:`n"
			If ($Alias -match "QUIT") { Break }
			$DeletedMailbox = Get-EXOMailbox -SoftDeletedMailbox -Identity $Alias -ErrorAction SilentlyContinue
		} While (-not $DeletedMailbox)
	}

	If ($DeletedMailbox) {
		$Name = $DeletedMailbox.DisplayName
		$DeletedMailboxSize = ($DeletedMailbox | Get-MailboxStatistics -IncludeSoftDeletedRecipients).TotalItemSize.Value
		Write-Host "Deleted mailbox for $Name found. It is $DeletedMailboxSize"
		If ([int64]($DeletedMailboxSize -replace '.+\(|bytes\)') -gt "50GB") {
			Write-Warning -Message "$Name has a mailbox larger then 50GB, the restored shared mailbox needs to be assigned an Office 365 Enterprise E3 or E5 license."
			Write-Host -NoNewLine 'Press any key to acknowledge and continue...';
			$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
		}
		$SmtpAddress = $DeletedMailbox.PrimarySmtpAddress
		Write-Host "Creating Shared Mailbox."
		New-Mailbox -Name "SHARED $Name LEFT $DateLeft" -Alias $Alias -PrimarySmtpAddress $SmtpAddress -Shared
		Write-Host "Waiting 30 seconds for mailbox to fully initialize."
		Start-Sleep -Seconds 30
		$NewSharedMailbox = Get-EXOMailbox -Identity $Alias
		$NewSharedMailbox | Select-Object DisplayName, RecipientTypeDetails
		Write-Host "Hiding the mailbox from address lists."
		$NewSharedMailbox | Set-Mailbox -HiddenFromAddressListsEnabled:$true -MaxSendSize 150MB -MaxReceiveSize 150MB
		
		Write-Host "Restoring deleted mailbox to new shared mailbox."
		$RestoreName = $Alias + "_" + $(Get-Date -uFormat %T_%d%b%Y)
		New-MailboxRestoreRequest -Name $RestoreName -SourceMailbox $DeletedMailbox.GUID.GUID -TargetMailbox $NewSharedMailbox.GUID.GUID -AllowLegacyDNMismatch -ConflictResolutionOption ForceCopy -AssociatedMessagesCopyOption DoNotCopy
		Write-Host "Retrieving Restore Status"
		Get-SharedMailboxRestoreRequest
		Write-Host -ForegroundColor Yellow -BackgroundColor Black "Run Get-SharedMailboxRestoreRequest to see the progress of the restore."

		#Mailbox Permissions
		If (-not $NoAccess) {
			Do {
				If ($GiveAccessPermission) {
					$Permission = $GiveAccessPermission
				}
				Else {
					$Response = Read-Host -Prompt "Do you want to add any permissions to the shared mailbox? (Y/n)"
					If (-not $Response) { $Response = "y" }
					If ($Response -like "y*") {
						$Rights = "FullAccess", "ReadPermission", "QUIT"
						$Rights | Select-Object @{N = 'Index'; E = { $Rights.IndexOf($_) } }, @{N = 'Permission'; E = { $_ } } | Out-Host -Paging -ErrorAction SilentlyContinue
						$Permission = Read-Host "Please enter the number of the permission you wish to assign."
						$Permission = $Rights[$Permission]
					}
				}
				If ($Permission -ne "QUIT" -and $Response -notlike "n*") {
					If ($GiveAccessTo) {
						$AddUser = $GiveAccessTo
					}
					Else {
						$AddUser = Read-Host "Alias of the user to grant access"
					}
					If (-not $(Get-EXOMailbox -Identity $AddUser)) {
						Do {
							$AddUser = Read-Host "That alias didn't work. Enter another one or type QUIT to stop:`n"
							If ($AddUser -match "QUIT") { Break }
						} While (-not $(Get-EXOMailbox -Identity $AddUser))
					}
					Write-Host "Giving $AddUser $Permission to the mailbox."
					$NewSharedMailbox | Add-MailboxPermission -User $AddUser -AccessRights $Permission -InheritanceType All -Verbose
					$NewSharedMailbox | Get-MailboxPermission | Format-Table
					If ($GiveAccessPermission) { $Response = "no" }
				}
				Else { Break }
			} While ($Response -notlike "n*")
		}

		#AutoReply
		If (-not $NoReply) {
			If ($DirectEmailTo) {
				$ReplyTo = $DirectEmailTo
			}
			Else {
				$Response = Read-Host -Prompt "Do you want to an auto reply? (Y/n)"
				If (-not $Response) { $Response = "y" }
				If ($Response -like "y*") {
					$ReplyTo = Read-Host "Alias of the user to direct emails to"
					If (-not $(Get-EXOMailbox -Identity $ReplyTo)) {
						Do {
							$ReplyTo = Read-Host "That alias didn't work. Enter another one or type QUIT to stop:`n"
							If ($ReplyTo -match "QUIT") { Break }
						} While (-not $(Get-EXOMailbox -Identity $ReplyTo))
					}
					$ReplyTo = Get-EXOMailbox -Identity $ReplyTo
					$ReplyToName = $ReplyTo.DisplayName
					$ReplyToEmail = $ReplyTo.PrimarySmtpAddress
					$NewSharedMailbox | Set-MailboxAutoReplyConfiguration -InternalMessage "$Name is no longer with the organization. Please direct communications to $ReplyToName at $ReplyToEmail" -ExternalMessage "$Name is no longer with the organization. Please direct communications to $ReplyToName at $ReplyToEmail" -Verbose
					$NewSharedMailbox | Set-MailboxAutoReplyConfiguration -AutoReplyState enabled
					$NewSharedMailbox | Get-MailboxAutoReplyConfiguration | Select-Object Identity, AutoReplyState, ExternalMessage | FL
					Clear-Variable -Name ReplyTo -Force -ErrorAction SilentlyContinue
					Clear-Variable -Name ReplyToName -Force -ErrorAction SilentlyContinue
					Clear-Variable -Name ReplyToEmail -Force -ErrorAction SilentlyContinue
				}
			}
		}

		# Forward Email
		If (-not $NoForward) {
			If ($DirectEmailTo) {
				$ForwardTo = $DirectEmailTo
			}
			Else {
				$Response = Read-Host -Prompt "Do you want to forward emails? (Y/n)"
				If (-not $Response) { $Response = "y" }
				If ($Response -like "y*") {
					$ForwardTo = Read-Host "Alias of the user to forward emails to"
					If (-not $(Get-EXOMailbox -Identity $ForwardTo)) {
						Do {
							$ForwardTo = Read-Host "That alias didn't work. Enter another one or type QUIT to stop:`n"
							If ($ForwardTo -match "QUIT") { Break }
						} While (-not $(Get-EXOMailbox -Identity $ForwardTo))
					}
					$ForwardTo = Get-EXOMailbox -Identity $ForwardTo
					$ForwardToName = $ForwardTo.DisplayName
					$ForwardToEmail = $ForwardTo.PrimarySmtpAddress
					$NewSharedMailbox | Set-Mailbox -DeliverToMailboxAndForward $true -ForwardingSMTPAddress $ForwardToEmail
					$NewSharedMailbox | Format-List ForwardingSMTPAddress, DeliverToMailboxandForward
					Clear-Variable -Name ForwardTo -Force -ErrorAction SilentlyContinue
					Clear-Variable -Name ForwardToName -Force -ErrorAction SilentlyContinue
					Clear-Variable -Name ForwardToEmail -Force -ErrorAction SilentlyContinue
				}
			}
		}
	}
	Clear-Variable -Name NewSharedMailbox -Force -ErrorAction SilentlyContinue
	$(
		Write-Host -NoNewLine "Obtaining progress, which can be repeated with the "
		Write-Host -ForegroundColor Yellow -NoNewLine "Get-SharedMailboxRestoreRequest"
		Write-Host " command."
	)
	Get-SharedMailboxRestoreRequest

	Write-Host -ForegroundColor Yellow "Remember, you can also copy over a user's OneDrive files with 'Export-UsersOneDrive'."

	<#
	.SYNOPSIS
		Takes a deleted user, and converts their email to a shared mailbox. Can add permissions and an autoreply.
	.PARAMETER Alias
		Please enter the persons alias, the part of their email before the @ sign.
	.PARAMETER DateLeft
		Please enter the date this person left in DDMMMYYY format, i.e. 01JAN2001
	.PARAMETER GiveAccessTo
		Please enter the alias of the person who needs access to the shared mailbox. Leave blank to be prompted for multiple names.
	.PARAMETER GiveAccessPermission
		Please enter the permission level to give. Acceptible values are 'FullAccess' and 'ReadPermission'.
	.PARAMETER DirectEmailTo
		Please enter the alias of the person who people should be directed to in the auto reply.
	.PARAMETER NoAccess
		Add this switch if you do not want to be prompted for giving access.
	.PARAMETER NoReply
		Add this switch if you do not want to be prompted for setting up an autoreply.
	.EXAMPLE
		Convert-ToSharedMailbox -DateLeft "30SEP2021" -Alias cscippio
	.EXAMPLE
		Convert-ToSharedMailbox -DateLeft DEC2021 -Alias kelli -GiveAccessTo javila -GiveAccessPermission ReadPermission -DirectEmailTo javila
	.EXAMPLE
		Convert-ToSharedMailbox -DateLeft DEC2021 -Alias rich -NoAccess -NoReply
	#>
}

function ConvertTo-EncodedCommand {
    <#
    .SYNOPSIS
        Converts a PowerShell script to base64 encoding for use with powershell.exe -EncodedCommand
    
    .DESCRIPTION
        Takes a PowerShell script (as string or from file) and converts it to base64-encoded 
        UTF-16LE format required by the -EncodedCommand parameter.
    
    .PARAMETER ScriptBlock
        The PowerShell code as a string to encode
    
    .PARAMETER Path
        Path to a .ps1 file to encode
    
    .PARAMETER ToClipboard
        Copy the encoded command to clipboard
    
    .EXAMPLE
        ConvertTo-EncodedCommand -ScriptBlock "Get-Process | Where-Object CPU -gt 100"
        
    .EXAMPLE
        ConvertTo-EncodedCommand -Path "C:\Scripts\MyScript.ps1" -ToClipboard
        
    .EXAMPLE
        $encoded = ConvertTo-EncodedCommand -ScriptBlock "Write-Host 'Hello World'"
        powershell.exe -EncodedCommand $encoded
    
    .EXAMPLE
        # Multi-line script block
        $script = @"
        `$services = Get-Service | Where-Object Status -eq 'Running'
        `$services | Export-Csv -Path C:\Temp\services.csv -NoTypeInformation
        Write-Host "Exported `$(`$services.Count) services"
        "@
        ConvertTo-EncodedCommand -ScriptBlock $script -ToClipboard
    #>
    
    [CmdletBinding(DefaultParameterSetName = 'ScriptBlock')]
    param(
        [Parameter(Mandatory = $true, 
                   ParameterSetName = 'ScriptBlock',
                   ValueFromPipeline = $true,
                   Position = 0)]
        [string]$ScriptBlock,
        
        [Parameter(Mandatory = $true, 
                   ParameterSetName = 'Path')]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [switch]$ToClipboard
    )
    
    process {
        try {
            # Get the script content
            if ($PSCmdlet.ParameterSetName -eq 'Path') {
                $ScriptBlock = Get-Content -Path $Path -Raw
            }
            
            # Convert to UTF-16LE bytes (required for -EncodedCommand)
            $bytes = [System.Text.Encoding]::Unicode.GetBytes($ScriptBlock)
            
            # Convert to base64
            $encodedCommand = [Convert]::ToBase64String($bytes)
            
            # Copy to clipboard if requested
            if ($ToClipboard) {
                $encodedCommand | Set-Clipboard
                Write-Host "Encoded command copied to clipboard!" -ForegroundColor Green
            }
            
            # Return the encoded string
            return $encodedCommand
        }
        catch {
            Write-Error "Failed to encode command: $_"
        }
    }
}


# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCa1DcJNvexmzCp
# fZWXvoZFMpOIwvd3WoJ9MHLBu3n9AaCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IHIdR7gXM9+D4IqS53tiHHeN4yUklz6Qki2HKtxHOjOrMA0GCSqGSIb3DQEBAQUA
# BIICALqnegCLuYFMGhcIFzrPxNMtWnRoQt70gTgsaCKOpzaMrKNleQ2w88KES4yh
# vFq9PGcS7zrfJlX7ciHSyZm3/vpBySnVh+i+BblwlEf4NjQhjjX8pzz/GeVBEboX
# 0V8ErBLSI6GU1cLHclaVcokRCPXtvKTRoA93x7PgjtH977KBdErgCZUWw3595UWt
# whflcntAUdyOfYaoQIzqA2xbn9SO4G1aD+Usut4/vp5Xl8AJjXpDj7uT4yDP3gON
# BCuCQwwdKuHxjYjZL/nA68pvGcUbV5HEqC5y0WF7D/wlVgWInGiIy8KCo+mjCMNi
# IqHZQrSg9QuOCycEmLH9hEbEamUuYftUcPQpGNnLnr/QExiPV9TVwd2Vj9xzMYbL
# gz9hBjeXUckhooKSmUa6XPWMP49u8UT+IPw+qaL8myQI7PVo/KhS4B5szTNPboHq
# JN102VYVI/req/yzdvGG2vz5RpegD4NpfzNvHEslrbev77/lCrlnjfeyqX1hzCh/
# yAXhEFTnruuz7bVgR/IrOLX5mM89YPtA/Z+MdMk1x131+Vmyahbrc+nZnwhTyNRN
# fRhuB4PFr2+uYf8WxUBzGHddIiw8pdwwgUmWhqFmAgUAiAEpkBoLxfPq3e9ZQli+
# WvKMJdRTREjnzlb3CczWU/Z3JfZ/kNkne2gURDYoXn+3DqBqoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDQyMTE1MDE1MFowLwYJKoZIhvcNAQkEMSIEIN/UrMXb
# fa88ZVok/bF2GSlRCQZ4fhvJkgaMaNlo11S6MA0GCSqGSIb3DQEBAQUABIICAIWr
# IbeOfcQUliHfDjY4dhHESLlG/1CmDcaTV6ZFWz5d02faqTMjplEdP7+RK+Wn2L1H
# XLIqszliT7jt1uasOOAcanMM2vjg7J0omDh7qGKqPpfKvs4JZDwPbjY8TcRvDMoX
# kuw/2PlP83KELK8dspdyX49MHp0g/+R3GqXJyhEKuY3hIFE5UVgkSeWfJgugNPrX
# FEVDk1msr88bPxtMhO7gjluyo7UXxGn0Esm4r+l5g5Ck5db7i6vm0K0pqMoIgtpV
# Syrh6VWBSipGF8/UCWeG2vkf/GxFUyDF3tJq32Ldv5LlqajOSZQ5Kl9e5GgamaCC
# I+TDGHKSNypBHFtY7WcS4ZD45awSXXVRoggs11lxERW8SGB81/zw9Rxqx9d9spJ7
# F/dkpJDRrKvuPrOT08KXRSI3+1/uvdcXzrX/97DvMNwXtXt1eVfTu3nUiMPjOXRa
# wh2Hcb9c3t9B+KkPUK8BXLWRI2lxQZGg9ah4FMiYW61hxBa2VrL2jnxuxPVfzxfp
# 6kYrb2SAzsf96/kLOFmzlT9GzhGojLqRWVaD62w6hMZZ2JZNRea6CXkSuN74QIh8
# d7H85UtUpXAv0xq0pa5PE9qdKNcY4+r3WR54pcOc1Z9CIAQpOas2AbtdMW5pth7N
# holUkg6gaeOx7NShpDP0JaHJn5H0GIon1rbeyZt2
# SIG # End signature block
