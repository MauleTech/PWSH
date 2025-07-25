Function Export-LDAPSCertificate {
	<#
	.SYNOPSIS
		If the server responds to requests on the LDAPS port 636, the function will attempt to isolate the Certificate in use and export it to $ITFolder\LDAPScerExport.cer
	#>
	If (Test-NetConnection -ComputerName localhost -Port 636 -InformationLevel Quiet) {
		$Cert = (Get-ChildItem -Path Cert:\LocalMachine -Recurse | Where-Object {$_.NotAfter -Gt (Get-Date) -and $_.Subject -like "*$env:computername.$env:userdnsdomain*" -and $_.NotAfter -eq ($_.NotBefore).AddYears(1)})
		$Cert | Select-Object Subject, NotBefore, NotAfter | Format-List
		$Path = "$ITFolder\LDAPScerExport.cer"
		Write-Host "Exporting current likely LDAPS Certificate to $Path"
		$Cert | Export-Certificate -Type cer -FilePath $ITFolder\LDAPScerExport.cer -Force | Out-Null
	} Else {
		Write-Warning "This computer does not appear to be serving LDAPS requests."
		Break
	}
}

Function Export-365AllDistributionGroups {
	param
	(
		[Parameter(Mandatory=$True)]
		[string]$SaveToFolder
	)

	If (-not $(Get-ConnectionInformation)) {Connect-O365Exchange;$DisconnectWhenDoneALL = $True}
	$AllDistributionGroups = Get-DistributionGroup
	$AllDistributionGroups.DisplayName | ForEach-Object {
		Write-Host $_
		Export-365DistributionGroup -DistributionGroup $_ -SavePath $(Join-Path -Path $SaveToFolder -ChildPath $($_ + ".csv"))
	}
	If ($DisconnectWhenDoneALL -eq $True) {
		Write-Host "Disconnecting from Exchange Online"
		Disconnect-O365Exchange
	}
}
Function Export-365DistributionGroup {
	param
	(
		[Parameter(Mandatory=$false)]
		[string]$DistributionGroup,
		[Parameter(Mandatory=$false)]
		[string]$SavePath
	)

	Function Save-File([string] $initialDirectory ) {

		[System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
	
		$OpenFileDialog = New-Object System.Windows.Forms.SaveFileDialog
		$OpenFileDialog.initialDirectory = $initialDirectory
		$OpenFileDialog.filter = "All files (*.csv)| *.csv"
		$OpenFileDialog.ShowDialog() |  Out-Null
	
		return $OpenFileDialog.filename
	}
	
	Function Get-DistributionGroups {
		$DistributionGroups = Get-DistributionGroup
		If ($DistributionGroup) {
			If ($DistributionGroups.DisplayName -Match $DistributionGroup) {
				$Global:SelectedDG = Get-DistributionGroup $DistributionGroup
				Write-Host "You've selected $SelectedDG"
			} Else {
				Write-Host -ForegroundColor Yellow "$DistributionGroup is not a valid group."
			}
		}
	
		If (-not $SelectedDG) {
			$DistributionGroups | Select-Object @{N='Index'; E={$DistributionGroups.IndexOf($_)}}, DisplayName, PrimarySmtpAddress | Out-Host -Paging -ErrorAction SilentlyContinue
			$selection = Read-Host "Please enter the number of the Distribution Group you wish to select."
			$Global:SelectedDG = $DistributionGroups[$selection]
			Write-Host "You've selected $SelectedDG"
		}
	
	}
	
	Function Export-DistributionGroupMembers {
		$DGMembers = $SelectedDG | ForEach-Object {Get-DistributionGroupMember -Identity $_.Identity | Select-Object Name, PrimarySmtpAddress }
		Write-Host "$SelectedDG`nGetting members of list."
		function Show-Menu {
			param (
				[string]$Title = "$($DGMembers.count) members found in $SelectedDG"
			)
			Clear-Host
			Write-Host "================ $Title ================"
			Write-Host "What would you like to do with the list?"
			Write-Host
			Write-Host "1: View list of members."
			Write-Host "2: Copy list of members."
			Write-Host "3: Save list of members."
			Write-Host "Q: Press 'Q' to quit"
		}
	
		If (-not $SavePath) {
			do {
				Show-Menu
				$selection = Read-Host "Please make a selection"
				switch ($selection) {
					'1' {
	
						'================ You chose option #1: View List ================'
						Write-Host $SelectedDG
						$DGMembers | Format-Table | Out-Host | More
						Write-Host
						Pause
					} '2' {
	
						'================ You chose option #2: Copy list ================'
						$DGMembers | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation | Set-Clipboard
						Write-Host "Results have been copied to the clipboard. You may paste in another program."
						Write-Host
						Pause
					} '3' {
	
						'================ You chose option #3: Save list ================'
	
						$SavePath = Save-File $env:USERPROFILE
						"sep=;" | Out-File -FilePath $SavePath -Force
						$DGMembers | ConvertTo-Csv -Delimiter ";" -NoTypeInformation | Out-File -FilePath $SavePath -Append -Force
						Write-Host "The file has been saved to $SavePath"
						Write-Host
						Pause
					} 'q' {
						#exit
					}
				}
				#pause
			} until ($selection -eq 'q')
		} Else {
			"sep=;" | Out-File -FilePath $SavePath -Force
			$DGMembers | ConvertTo-Csv -Delimiter ";" -NoTypeInformation | Out-File -FilePath $SavePath -Append -Force
			Write-Host "The file has been saved to $SavePath"
			Write-Host
		}
	}
	
	################################
	If (-not $(Get-ConnectionInformation)) {Connect-O365Exchange;$DisconnectWhenDone = $True}
	Get-DistributionGroups
	Export-DistributionGroupMembers
	Clear-Variable SelectedDG -Force -ErrorAction SilentlyContinue
	Clear-Variable DGMembers -Force -ErrorAction SilentlyContinue
	Clear-Variable DistributionGroup -Force -ErrorAction SilentlyContinue
	Clear-Variable DistributionGroups -Force -ErrorAction SilentlyContinue
	If ($DisconnectWhenDone -eq $True) {
		Write-Host "Disconnecting from Exchange Online"
		Disconnect-O365Exchange
	}
}

Function Export-UnifiDevicesToItGlue {
	<#
.SYNOPSIS
	Exports Unifi device information to a CSV file formatted for ITGlue import.

.DESCRIPTION
	This function retrieves device information from a Unifi controller via the UI.com API
	and formats it for ITGlue import. It includes device details such as name, model,
	IP address, MAC address, installation date, and warranty information.

.PARAMETER ApiKey
	The API key for accessing the UI.com API. If not provided, the user will be 
	directed to retrieve it from ITGlue.

.EXAMPLE
	Export-UnifiDevicesToItGlue -ApiKey "YourApiKeyHere"

.EXAMPLE
	Export-UnifiDevicesToItGlue

.NOTES
	Author: [Your Name]
	Last Modified: 2024-01-27
	Requires: PowerShell 5.1 or later
#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$false)]
		[string]$ApiKey
	)

	# If API key is not provided, guide user to retrieve it
	if (-not $ApiKey) {
		Write-Host "Please retrieve the API key from: https://ambitions.itglue.com/806129/passwords/29782233"
		$ApiKey = Read-Host -Prompt "Enter your UI.com API key"
	}

	# Set up API headers with authentication
	$Headers = @{
		'X-API-KEY' = $ApiKey
	}

	# Retrieve list of Unifi controllers
	try {
		$Hosts = (Invoke-RestMethod -Uri 'https://api.ui.com/ea/hosts' -Method Get -Headers $Headers).data
	}
	catch {
		Write-Error "Failed to retrieve hosts: $_"
		return
	}

	# Display available controllers in numbered format
	$HostsList = $Hosts | Select-Object `
		@{Name = 'Index'; Expression = {[array]::IndexOf($Hosts, $_) + 1}},`
		@{Name = 'Name' ; Expression = {$_.ReportedState.HostName}},`
		@{Name = 'Model'; Expression = {$_.ReportedState.hardware.name}},`
		@{Name = 'IP Address'; Expression = {$_.ipAddress}},`
		@{Name = 'id'; Expression = {$_.id}}

	# Display the numbered list
	$HostsList | Format-Table

	# Get user selection by number and convert to ID
	do {
		$Selection = Read-Host -Prompt "Enter the number of the controller to use (1-$($HostsList.Count))"
		if ($Selection -match '^\d+$' -and [int]$Selection -ge 1 -and [int]$Selection -le $HostsList.Count) {
			$GetID = $HostsList[$Selection - 1].id
			break
		} else {
			Write-Host "Invalid selection. Please enter a number between 1 and $($HostsList.Count)"
		}
	} while ($true)

	# Construct URI for device retrieval
	$GetDevicesUri = 'https://api.ui.com/ea/devices?hostIds[]=' + $GetID

	# Retrieve devices from specified controller
	try {
		$UIDevices = (Invoke-RestMethod -Uri $GetDevicesUri -Method Get -Headers $Headers).Data.devices
	}
	catch {
		Write-Error "Failed to retrieve devices: $_"
		return
	}

	#Show how many devices found.
	Write-Host "$($UIDevices.Count) found."
	
	# Find console device name for reference
	$Console = ($UIDevices | Where-Object -Property isConsole -eq True).Name

	# Get organization name from user
	$OrganizationName = Read-Host -Prompt "Enter the exact Organization Name from ITGlue for device $Console"

	# Format device data for ITGlue import 
	$ITGlueExport = $UIDevices | Select-Object `
		@{Name = 'Organization'; Expression = {$OrganizationName}},`
		@{Name = 'Name'; Expression = {$_.name}},`
		@{Name = 'configuration_type'; Expression = {'Network Device'}},`
		@{Name = 'configuration_status'; Expression = {
			if ($_.status -eq 'online') {'Active'}
			else {'Inactive'}
		}},`
		@{Name = 'primary_ip'; Expression = {$_.ip}},`
		@{Name = 'mac_address'; Expression = {$_.mac}},`
		@{Name = 'serial_number'; Expression = {$_.id}},`
		@{Name = 'manufacturer'; Expression = {'Unifi'}},`
		@{Name = 'model'; Expression = {$_.model}},`
		@{Name = 'installed_at'; Expression = {Get-Date $_.adoptionTime -Format "yyyy-MM-dd"}},`
		@{Name = 'warranty_expires_at'; Expression = {Get-Date ((Get-Date $_.adoptionTime).AddYears(1)) -Format "yyyy-MM-dd"}}

	# Generate default file name
	$DefaultFileName = "Unifi-ITGlue-$OrganizationName-export.csv"

	# Prompt for save folder
	$SaveFolder = Read-Host -Prompt "Enter folder path to save file"

	# Check if input includes a filename
	if ($SaveFolder -match '\.[^\.]+$') {
	   # Full path with filename was provided
	   $SavePath = $SaveFolder
	} else {
	   # Only folder path provided, append default filename
	   $SavePath = Join-Path -Path $SaveFolder -ChildPath $DefaultFileName
	}

	# Ensure directory exists
	$Directory = Split-Path -Path $SavePath -Parent
	if (-not (Test-Path -Path $Directory)) {
	   New-Item -ItemType Directory -Path $Directory -Force | Out-Null
	}

	# Export to CSV
	try {
	   $ITGlueExport | ConvertTo-Csv -Delimiter "," | Out-File -Path $SavePath
	   Write-Host "Export completed successfully to: $SavePath"
	}
	catch {
	   Write-Error "Failed to export CSV: $_"
	}
}

Function Export-UsersOneDrive {
	param
	(
		[Parameter(Mandatory=$True)]
		[string]$departinguser,

		[Parameter(Mandatory=$True)]
		[string]$destinationuser,
		
		[Parameter(Mandatory=$True)]
		[string]$globaladmin
	)
	
	Write-Host -ForegroundColor Yellow "Please note:`n- This process will require you to log in as the global admin in several windows.`n- This will take quite some time if there are extensive amounts of files.`n- This cannot copy files larger then 250mb."
	If (-not $departinguser) {$departinguser = Read-Host "Enter departing user's email"}
	If (-not $departinguser) {$destinationuser = Read-Host "Enter destination user's email"}
	If (-not $departinguser) {$globaladmin = Read-Host "Enter the username of your Global Admin account"}
	Connect-O365AzureAD -Quiet
	 
	$InitialDomain = Get-AzureADDomain | Where-Object {$_.IsInitial -eq $true}
	  
	$SharePointAdminURL = "https://$($InitialDomain.Name.Split(".")[0])-admin.sharepoint.com"
	  
	$departingUserUnderscore = $departinguser -replace "[^a-zA-Z]", "_"
	$destinationUserUnderscore = $destinationuser -replace "[^a-zA-Z]", "_"
	  
	$departingOneDriveSite = "https://$($InitialDomain.Name.Split(".")[0])-my.sharepoint.com/personal/$departingUserUnderscore"
	$destinationOneDriveSite = "https://$($InitialDomain.Name.Split(".")[0])-my.sharepoint.com/personal/$destinationUserUnderscore"
	Write-Host "`nConnecting to SharePoint Online" -ForegroundColor Blue
	Connect-O365SharePoint -Url $SharePointAdminURL -Quiet
	  
	Write-Host "`nAdding $globaladmin as site collection admin on both OneDrive site collections" -ForegroundColor Blue
	# Set current admin as a Site Collection Admin on both OneDrive Site Collections
	If ($(Get-SPODeletedSite -IncludeOnlyPersonalSite).Url -match $departingOneDriveSite) {
		Write-Host "$departingOneDriveSite has be deleted. Temporarily undeleting it for recovery."
		Restore-SPODeletedSite -Identity $departingOneDriveSite
		$WasDeleted = $True
	}
	Set-SPOUser -Site $departingOneDriveSite -LoginName $globaladmin -IsSiteCollectionAdmin $true
	Set-SPOUser -Site $destinationOneDriveSite -LoginName $globaladmin -IsSiteCollectionAdmin $true
	  
	Write-Host "`nConnecting to $departinguser's OneDrive via SharePoint Online PNP module" -ForegroundColor Blue
	  
	Connect-O365SharepointPNP -Url $departingOneDriveSite -Quiet
	  
	Write-Host "`nGetting display name of $departinguser" -ForegroundColor Blue
	# Get name of departing user to create folder name.https://pbwslaw-admin.sharepoint.com/
	$departingOwner = Get-PnPSiteCollectionAdmin | Where-Object {$_.loginname -match $departinguser}
	  
	# If there's an issue retrieving the departing user's display name, set this one.
	If ($departingOwner -contains $null) {
		$departingOwner = @{
			Title = "Departing User"
		}
	}
	  
	# Define relative folder locations for OneDrive source and destination
	$departingOneDrivePath = "/personal/$departingUserUnderscore/Documents"
	$destinationOneDrivePath = "/personal/$destinationUserUnderscore/Documents/$($departingOwner.Title)'s Files"
	$destinationOneDriveSiteRelativePath = "Documents/$($departingOwner.Title)'s Files"
	  
	Write-Host "`nGetting all items from $($departingOwner.Title)" -ForegroundColor Blue
	# Get all items from source OneDrive
	$items = Get-PnPListItem -List Documents -PageSize 1000
	  
	$largeItems = $items | Where-Object {[long]$_.fieldvalues.SMTotalFileStreamSize -ge 261095424 -and $_.FileSystemObjectType -contains "File"}
	If ($largeItems) {
		$largeexport = @()
		foreach ($item in $largeitems) {
			$largeexport += "$(Get-Date) - Size: $([math]::Round(($item.FieldValues.SMTotalFileStreamSize / 1MB),2)) MB Path: $($item.FieldValues.FileRef)"
			Write-Host "File too large to copy: $($item.FieldValues.FileRef)" -ForegroundColor DarkYellow
		}
		New-Item -Path $Env:SystemDrive\temp -ItemType Directory -Force
		$largeexport | Out-file $Env:SystemDrive\temp\largefiles.txt -Append
		Write-Host "A list of files too large to be copied from $($departingOwner.Title) have been exported to C:\temp\LargeFiles.txt" -ForegroundColor Yellow
	}
	  
	$rightSizeItems = $items | Where-Object {[long]$_.fieldvalues.SMTotalFileStreamSize -lt 261095424 -or $_.FileSystemObjectType -contains "Folder"}
	  
	Write-Host "`nConnecting to $destinationuser via SharePoint PNP PowerShell module" -ForegroundColor Blue
	Connect-O365SharepointPNP -Url $destinationOneDriveSite -Quiet
	  
	Write-Host "`nFilter by folders" -ForegroundColor Blue
	# Filter by Folders to create directory structure
	$folders = $rightSizeItems | Where-Object {$_.FileSystemObjectType -contains "Folder"}
	  
	Write-Host "`nCreating Directory Structure" -ForegroundColor Blue
	foreach ($folder in $folders) {
		$path = ('{0}{1}' -f $destinationOneDriveSiteRelativePath, $folder.fieldvalues.FileRef).Replace($departingOneDrivePath, '')
		Write-Host "Creating folder in $path" -ForegroundColor Green
		$newfolder = Resolve-PnPFolder -SiteRelativePath $path
	}
	   
	Write-Host "`nCopying Files" -ForegroundColor Blue
	$files = $rightSizeItems | Where-Object {$_.FileSystemObjectType -contains "File"}
	$fileerrors = ""
	foreach ($file in $files) {
		  
		$destpath = ("$destinationOneDrivePath$($file.fieldvalues.FileDirRef)").Replace($departingOneDrivePath, "")
		Write-Host "Copying $($file.fieldvalues.FileLeafRef) to $destpath" -ForegroundColor Green
		$newfile = Copy-PnPFile -SourceUrl $file.fieldvalues.FileRef -TargetUrl $destpath -OverwriteIfAlreadyExists -Force -ErrorVariable errors -ErrorAction SilentlyContinue
		$fileerrors += $errors
	}
	If ($fileerrors) {
		Write-Host -ForegroundColor Red "Errors were detected. A log is being saved at $Env:SystemDrive\temp\fileerrors.txt"
		New-Item -Path $Env:SystemDrive\temp -ItemType Directory -Force
		$fileerrors | Out-File $Env:SystemDrive\temp\fileerrors.txt
	}
	  
	# Remove Global Admin from Site Collection Admin role for both users
	Write-Host "`nRemoving $globaladmin from OneDrive site collections" -ForegroundColor Blue
	Set-SPOUser -Site $departingOneDriveSite -LoginName $globaladmin -IsSiteCollectionAdmin $false
	If ($globaladmin -ne $destinationuser) {
		Set-SPOUser -Site $destinationOneDriveSite -LoginName $globaladmin -IsSiteCollectionAdmin $false
	}
	
	If ($WasDeleted) {
		Write-Host "$departingOneDriveSite was previously deleted. Re-deleting it."
		Remove-SPOSite -Identity $departingOneDriveSite -Confirm:$false
	}
	Write-Host "`nDisconnecting from all services" -ForegroundColor Blue
	Disconnect-AzureAD
	Disconnect-SPOService
	Disconnect-PnPOnline -ErrorAction SilentlyContinue
	Write-Host "`nComplete!" -ForegroundColor Green
}

# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUqDkVxAr45rnBJ0wFUxhiI2KW
# xDigggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQULO43
# VYWYtJXtxdSrGlmbZ/52/y8wDQYJKoZIhvcNAQEBBQAEggEAmYH1AHg4744u0zNe
# s86xD+4/b4SEE75nL1SeFhg6yBDHBdyeD+Zs4CqgbNgDwDvhs0NBb35jsHNVQ7j6
# 9qjEDAHt0teANX7VacamzIFzqpEV/huzo2bfm7x6kYUHy03B8VshO4x1SuLa1XxI
# XVKMis3WcNBOs5tn49biShSyxsP7JQ1iHa6hKik9vdiaqrEu3MSW0Yqpx87N9mLw
# oehMNmGJfkApdMAy8NEHQl+V7A+ArQLyE7T8FWJS/Zt4Vi0sco1BBNfg7aj5Bwv+
# MuvnRXZrXaqawgQbim6D1NslBarZl89Sr2NUlicApNaSwR0Czfo2QYcxFlQYDmrK
# LLv74Q==
# SIG # End signature block
