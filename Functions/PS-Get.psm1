Function Get-ADStaleUsers {
	<#
	.SYNOPSIS
		Retrieves a list of (enabled) Active Directory Users that haven't logged in recently.
	#>

	# check the name of the parent process.  If it's LogMeIn, we can't use the Out-GridView UI
	$parentProcessName = (Get-Process -Id ((Get-WmiObject Win32_Process -Filter "processid='$PID'").ParentProcessId)).Name

	# check to see whether Get-AdUser is available
	If (Get-Command ActiveDirectory\Get-AdUser -ErrorAction SilentlyContinue) {
		$Stale = [DateTime]::Today.AddDays(-180)
		$SemiStale = [DateTime]::Today.AddDays(-30)
		$adStaleUserInfo = Get-ADUser -Filter '(LastLogonTimestamp -lt $Stale) -and (Enabled -eq $True) -and (Name -notlike "HealthMailbox*") -and (Description -notlike "DNI*")' -Properties LastLogonTimestamp, Description, Title | Format-Table Name, @{N = "LastLogonTimestamp"; E = { [datetime]::FromFileTime($_.LastLogonTimestamp) } }, Description, Title -AutoSize
		$adSemiStaleUserInfo = Get-ADUser -Filter '(LastLogonTimestamp -lt $SemiStale) -and (LastLogonTimestamp -gt $Stale) -and (Enabled -eq $True) -and (Name -notlike "HealthMailbox*") -and (Description -notlike "DNI*")' -Properties LastLogonTimestamp, Description, Title | Format-Table Name, @{N = "LastLogonTimestamp"; E = { [datetime]::FromFileTime($_.LastLogonTimestamp) } }, Description, Title -AutoSize
		If ($adStaleUserInfo) {
			Write-Host
			Write-Output "Stale user accounts that haven't logged on within the last 180 days:"
			$adStaleUserInfo | Format-Table -AutoSize
		}
		Else {
			Write-Host
			Write-Output "No Stale user accounts found that haven't logged on within the last 180 days."
		}
		If ($adSemiStaleUserInfo) {
			Write-Output "Semi-Stale user accounts that haven't logged on within the last 30 days (but have within 180 days):"
			$adSemiStaleUserInfo | Format-Table -AutoSize
		}
		Else {
			Write-Host
			Write-Output "No Semi-Stale user accounts found that haven't logged on within the last 30 days (but have within 180 days)."
		}
	}
 else {
		# cannot continue, Get-AdUser is not available
		Write-Host "`n [!] This command must be run on a system with Active Directory Powershell Modules (i.e. a domain controller)`n"
	}
}

Function Get-ADStaleComputers {
	<#
	.SYNOPSIS
		Retrieves a list of (enabled) Active Directory Computers that haven't logged in recently.
	#>

	# check the name of the parent process.  If it's LogMeIn, we can't use the Out-GridView UI
	$parentProcessName = (Get-Process -Id ((Get-WmiObject Win32_Process -Filter "processid='$PID'").ParentProcessId)).Name

	# check to see whether Get-AdComputer is available
	If (Get-Command -Module ActiveDirectory -Name Get-AdComputer -ErrorAction SilentlyContinue) {
		$Stale = [DateTime]::Today.AddDays(-180)
		$SemiStale = [DateTime]::Today.AddDays(-30)
		$adStaleComputerInfo = Get-ADComputer -Filter '(LastLogonTimestamp -lt $Stale)' -Properties LastLogonTimestamp, Description, Title | Format-Table Name, @{N = "LastLogonTimestamp"; E = { [datetime]::FromFileTime($_.LastLogonTimestamp) } }, Description, Title -AutoSize
		$adSemiStaleComputerInfo = Get-ADComputer -Filter '(LastLogonTimestamp -lt $SemiStale) -and (LastLogonTimestamp -gt $Stale) -and (Enabled -eq $True) -and (Name -notlike "HealthMailbox*") -and (Description -notlike "DNI*")' -Properties LastLogonTimestamp, Description, Title | Format-Table Name, @{N = "LastLogonTimestamp"; E = { [datetime]::FromFileTime($_.LastLogonTimestamp) } }, Description, Title -AutoSize
		If ($adStaleComputerInfo) {
			Write-Host
			Write-Output "Stale Computer accounts that haven't logged on within the last 180 days:"
			$adStaleComputerInfo | Format-Table -AutoSize
		}
		Else {
			Write-Host
			Write-Output "No Stale Computer accounts found that haven't logged on within the last 180 days."
		}
		If ($adSemiStaleComputerInfo) {
			Write-Output "Semi-Stale Computer accounts that haven't logged on within the last 30 days (but have within 180 days):"
			$adSemiStaleComputerInfo | Format-Table -AutoSize
		}
		Else {
			Write-Host
			Write-Output "No Semi-Stale Computer accounts found that haven't logged on within the last 30 days (but have within 180 days)."
		}
	}
 else {
		# cannot continue, Get-AdComputer is not available
		Write-Host "`n [!] This command must be run on a system with Active Directory Powershell Modules (i.e. a domain controller)`n"
	}
}

Function Get-ADUserPassExpirations {
	<#
	.SYNOPSIS
		Retrieves a list of (enabled) Active Directory Users and shows their password expiration times.
	#>

	# check the name of the parent process.  If it's LogMeIn, we can't use the Out-GridView UI
	$parentProcessName = (Get-Process -Id ((Get-WmiObject Win32_Process -Filter "processid='$PID'").ParentProcessId)).Name

	# check to see whether Get-AdUser is available
	If (Get-Command ActiveDirectory\Get-AdUser -ErrorAction SilentlyContinue) {

		$adUserInfo = Get-ADUser -Filter { Enabled -eq $True -and PasswordNeverExpires -eq $False } `
			-Properties "DisplayName", "userPrincipalName", "msDS-UserPasswordExpiryTimeComputed" | `
			Select-Object -Property "Displayname", "userPrincipalName", @{Name = "ExpiryDate"; Expression = { [datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed") } }

		# if the parent process of this powershell instance is not explorer.exe, output to PowerShell table.
		If ($parentProcessName -ne "explorer") {
			$adUserInfo | Format-Table -AutoSize
		}
		Else {
			# otherwise, grid view UI
			$adUserInfo | Out-GridView -Title "ATG Powershell --> User Password Expirations"
		}

	}
 else {
		# cannot continue, Get-AdUser is not available
		Write-Host "`n [!] This command must be run on a system with Active Directory Powershell Modules (i.e. a domain controller)`n"
	}
}

Function Get-ITFunctions {
    param
    (
        [Parameter(Mandatory = $false)]
        [switch] $Force
    )
    
    If ($Force) {
        Write-Host "-Force specified. Force loading latest functions."
        Update-ITFunctions
    }
    
    If (-not (Get-Module -Name "PS-*" -ErrorAction SilentlyContinue)) {
        $progressPreference = 'silentlyContinue'
        irm raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt | iex
    }
    
    # Get all commands from PS-* modules
    $commands = Get-Command -Module "PS-*" | Sort-Object Name
    
    If ($commands) {
        # Group commands by verb
        $groupedCommands = $commands | Group-Object { $_.Name.Split('-')[0] } | Sort-Object Name
        
        Write-Host "`n===================================================="
        Write-Host "The below functions are now loaded and ready to use:"
        Write-Host "===================================================="
        
        # Display each verb group
        foreach ($verbGroup in $groupedCommands) {
            Write-Host "`n[$($verbGroup.Name)]" -ForegroundColor Cyan
            Write-Host ("-" * ($verbGroup.Name.Length + 2)) -ForegroundColor DarkGray
            
            # List functions for each verb group
            $verbGroup.Group | ForEach-Object { 
                Write-Host "  $($_.Name)" 
            }
        }
        
        Write-Host "`n===================================================="
        Write-Host "Total Functions: $($commands.Count)" -ForegroundColor Green
        Write-Host "Type: 'Help <function name> -Detailed' for more info"
        Write-Host "===================================================="
    }
    else {
        Write-Host "No functions found in PS-* modules." -ForegroundColor Yellow
    }
}

function Get-BitLockerKey {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias('Name', 'DistinguishedName')]
		[string]$Computer
	)
	
	begin {
		# Check if BitLocker Drive Encryption Administration Utilities are installed
		$featureName = "RSAT-Feature-Tools-BitLocker"
		$feature = Get-WindowsFeature -Name $featureName
		
		# If not installed, install silently
		if (-not $feature.Installed) {
			Write-Verbose "BitLocker Drive Encryption Administration Utilities not installed. Installing now..."
			try {
				Install-WindowsFeature -Name $featureName -ErrorAction Stop | Out-Null
				Write-Verbose "BitLocker Drive Encryption Administration Utilities installed successfully."
			}
			catch {
				Write-Error "Failed to install BitLocker Drive Encryption Administration Utilities: $_"
				return
			}
		}
		
		# Initialize array for results if processing multiple computers
		$AllComputers = @()
	}
	
	process {
		try {
			# If a specific computer is provided via pipeline or parameter
			if ($Computer) {
				# Determine if we received a distinguished name
				if ($Computer -like "*DC=*") {
					try {
						$Computer_Object = Get-ADComputer -Identity $Computer -Property msTPM-OwnerInformation, msTPM-TpmInformationForComputer -ErrorAction Stop
						$ComputerName = $Computer_Object.Name
					}
					catch {
						Write-Error "Failed to retrieve computer from Distinguished Name: $_"
						return
					}
				}
				else {
					# Assume it's a computer name
					$ComputerName = $Computer
					$Computer_Object = Get-ADComputer -Filter { Name -eq $ComputerName } -Property msTPM-OwnerInformation, msTPM-TpmInformationForComputer -ErrorAction Stop
				}
				
				if ($null -eq $Computer_Object) {
					Write-Error "Computer '$ComputerName' not found in Active Directory."
					return
				}
				
				# Get BitLocker information
				$Bitlocker_Object = Get-ADObject -Filter { objectclass -eq 'msFVE-RecoveryInformation' } -SearchBase $Computer_Object.DistinguishedName -Properties 'Name','msFVE-RecoveryPassword' | Sort-Object -Property Name | Select-Object -Last 1
				
				if ($Bitlocker_Object.'msFVE-RecoveryPassword') {
					$BitLocker_ID = $Bitlocker_Object.'Name'
					$BitLocker_Key = $Bitlocker_Object.'msFVE-RecoveryPassword'
					
					$ComputerInfo = [PSCustomObject]@{
						Computer     = $ComputerName
						BitLockerID  = $BitLocker_ID
						BitLockerKey = $BitLocker_Key
					}
					
					# Display and copy to clipboard
					$ComputerInfo | Format-List
					Write-Host "The BitLocker key has been copied to the clipboard.`n"
					$ComputerInfo.BitLockerKey | Clip
				} else {
					Write-Host "There is no BitLocker key for computer '$ComputerName'."
				}
			}
			# If no computer specified, get all computers
			else {
				$Computers = Get-ADComputer -Filter 'ObjectClass -eq "computer"' -ErrorAction Stop
				
				$Computers | ForEach-Object {
					$CurrentComputer = $_.Name
					
					# Check if BitLocker recovery information exists
					try {
						$Bitlocker_Object = Get-ADObject -Filter { objectclass -eq 'msFVE-RecoveryInformation' } -SearchBase $_.DistinguishedName -Properties 'Name','msFVE-RecoveryPassword' | Sort-Object -Property Name | Select-Object -Last 1
						
						if ($Bitlocker_Object.'msFVE-RecoveryPassword') {
							$BitLocker_ID = $Bitlocker_Object.'Name'
							$BitLocker_Key = $Bitlocker_Object.'msFVE-RecoveryPassword'
						} else {
							$BitLocker_ID = "None"
							$BitLocker_Key = "None"
						}
					}
					catch {
						$BitLocker_ID = "Error"
						$BitLocker_Key = "Error: $_"
					}
					
					$ComputerInfo = [PSCustomObject]@{
						Computer     = $CurrentComputer
						BitLockerID  = $BitLocker_ID
						BitLockerKey = $BitLocker_Key
					}
					
					$AllComputers += $ComputerInfo
				}
				
				# Return all computers sorted
				$AllComputers | Sort-Object -Property "Computer"
			}
		}
		catch {
			Write-Error "An error occurred: $_"
		}
	}
	
	<#
	.SYNOPSIS
		Searches for and retrieves a BitLocker recovery key for the specified computer(s) in Active Directory.
	.DESCRIPTION
		This function retrieves BitLocker recovery keys from Active Directory. If the BitLocker Drive Encryption
		Administration Utilities are not installed, it will install them automatically.
	.PARAMETER Computer
		[Optional] Specify the name of the computer or a computer object from Get-ADComputer to retrieve the BitLockerKey for. 
		Will copy the key to the clipboard if specified. If omitted, returns all computer BitLocker keys.
	.EXAMPLE
		Get-BitLockerKey -Computer "ACG-Desktop23"
		
		Retrieves the BitLocker key for ACG-Desktop23 and copies it to the clipboard.
	.EXAMPLE
		Get-BitLockerKey
		
		Returns BitLocker keys for all computers in Active Directory.
	.EXAMPLE
		Get-ADComputer "ACG-Desktop23" | Get-BitLockerKey
		
		Retrieves the BitLocker key for ACG-Desktop23 using pipeline input from Get-ADComputer.
	.EXAMPLE
		Get-ADComputer -Filter {Name -like "ACG-*"} | Get-BitLockerKey
		
		Retrieves BitLocker keys for all computers with names starting with "ACG-".
	.NOTES
		Requires Active Directory PowerShell module and appropriate permissions.
	#>
}

function Get-ComputerEntraStatus {
	# Capture the command output as an array of strings
	# The @() ensures we always get an array, even if there's only one line
	$joinStatus = @(dsregcmd.exe /status)
	
	# Initialize our status object with default values
	$statusObject = @{
		EntraIDJoined = $false
		WorkplaceJoined = $false
		DomainJoined = $false
		TenantName = ""
		TenantId = ""
	}

	# Only process if we actually got output
	if ($joinStatus) {
		# Check each property using safer pattern matching
		$statusObject.EntraIDJoined = ($joinStatus | Where-Object { $_ -match "AzureAdJoined\s+:\s+YES" }).Length -gt 0
		$statusObject.WorkplaceJoined = ($joinStatus | Where-Object { $_ -match "WorkplaceJoined\s+:\s+YES" }).Length -gt 0
		$statusObject.DomainJoined = ($joinStatus | Where-Object { $_ -match "DomainJoined\s+:\s+YES" }).Length -gt 0
		
		# Extract tenant information more safely
		$tenantNameLine = $joinStatus | Where-Object { $_ -match "TenantName\s+:\s+(.+)" }
		if ($tenantNameLine) {
			$statusObject.TenantName = $matches[1].Trim()
		}
		
		$tenantIdLine = $joinStatus | Where-Object { $_ -match "TenantId\s+:\s+(.+)" }
		if ($tenantIdLine) {
			$statusObject.TenantId = $matches[1].Trim()
		}
	}
	
	# Convert to a proper PowerShell object and return
	return [PSCustomObject]$statusObject
}

Function Global:Get-DellWarranty {
<#
.SYNOPSIS
	Retrieves warranty information for Dell systems using the Dell API.

.DESCRIPTION
	This function queries the Dell API to retrieve warranty information for one or more Dell systems
	identified by their Service Tags. It can process the local system's Service Tag, a provided list
	of Service Tags, or Service Tags pasted by the user.

.PARAMETER Brand
	Currently not used, reserved for future functionality.

.PARAMETER Local
	Switch to use the local system's Service Tag. This is the default if no ServiceTags are provided.

.PARAMETER ServiceTags
	An array of Service Tags to query. Can be passed from the pipeline.

.PARAMETER Paste
	Prompts the user to paste a list of Service Tags, one per line.

.PARAMETER Show
	Displays the results in a formatted table.

.PARAMETER CopyToClipBoard
	Copies the results to the clipboard in a tab-delimited format.

.PARAMETER ReturnObject
	Returns the results as a PowerShell object that can be stored in a variable for further processing.

.EXAMPLE
	Get-DellWarranty -Local -Show
	Queries the warranty information for the local system and displays the results.

.EXAMPLE
	Get-DellWarranty -ServiceTags "1234ABC","5678DEF" -CopyToClipBoard
	Queries warranty information for the specified Service Tags and copies the results to the clipboard.

.EXAMPLE
	Get-DellWarranty -Paste -Show
	Prompts the user to paste a list of Service Tags and displays the results.

.EXAMPLE
	$warrantyInfo = Get-DellWarranty -ServiceTags "1234ABC" -ReturnObject
	Queries warranty information for the specified Service Tag and stores the results in the $warrantyInfo variable.

.NOTES
	Requires Dell API credentials to be stored in:
	- $env:appdata\Microsoft\Windows\PowerShell\DellKey.txt
	- $env:appdata\Microsoft\Windows\PowerShell\DellSec.txt

	For more information on setting up Dell API credentials, refer to:
	https://ambitions.itglue.com/806129/docs/10204492
#>
	Param(
		# Currently not used, reserved for future functionality
		[Switch] $Brand,

		# Use the local system's Service Tag
		[Parameter(ParameterSetName = "seta",
			Position = 0)]
		[Switch] $Local,

		# Array of Service Tags to query
		[Parameter(
			ParameterSetName = "setb",
			Mandatory = $false,
			ValueFromPipelineByPropertyName = $true,
			ValueFromPipeline = $true,
			Position = 1)]
		[String[]] $ServiceTags,

		# Prompt user to paste a list of Service Tags
		[Parameter(ParameterSetName = "setc")]
		[Switch] $Paste,

		# Display results in a formatted table
		[Switch] $Show,

		# Copy results to clipboard
		[Switch] $CopyToClipBoard,

		# Return results as a PowerShell object
		[Switch] $ReturnObject
	)

	# Check for required API credentials
	If ((Test-Path "$env:appdata\Microsoft\Windows\PowerShell\DellKey.txt") -ne $true) {
		Write-Host "Authentication Needed. Please refer to https://ambitions.itglue.com/806129/docs/10204492" -ForegroundColor White -BackgroundColor Red
		Break
	}
	If ((Test-Path "$env:appdata\Microsoft\Windows\PowerShell\DellSec.txt") -ne $true) {
		Write-Host "Authentication Needed. Please refer to https://ambitions.itglue.com/806129/docs/10204492" -ForegroundColor White -BackgroundColor Red
		Break
	}

	# Initialize result array
	$FinalObj = @()

	# Determine which Service Tags to process
	If (-not $ServiceTags) {
		If ($Paste) {
			# Prompt user to paste Service Tags
			Write-Host -ForegroundColor Yellow "Paste or enter a list of service tags, one per line.`n`nIf copying from Excel: After you paste here, click into Excel then press ESC a couple of times.`nThen press enter 2x to continue:"
			$ServiceTags = @()
			While ($a = read-host) {
				$ServiceTags += $a
			}
			$Local = $False
		}
		Else {
			# Default to local system if no Service Tags provided
			$Local = $True
		}
	}

	# Get local system's Service Tag if specified
	If ($Local) {
		$ServiceTags = ((Get-WmiObject -Class "Win32_Bios").SerialNumber)
	}

	Write-Host "Getting Warranties for $($ServiceTags.Count) Service Tag(s)."

	# Process each Service Tag
	Foreach ($ServiceTag in $ServiceTags) {
		# Show processing status if requested
		If ($Show) { Write-Host "Processing $ServiceTag" }

		# Get API credentials
		$ApiKey = Get-Content "$env:appdata\Microsoft\Windows\PowerShell\DellKey.txt"
		$ApiSecret = Get-Content "$env:appdata\Microsoft\Windows\PowerShell\DellSec.txt"

		# Set TLS 1.2 for API security
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

		# Authenticate to Dell API
		$Auth = Invoke-WebRequest $('https://apigtwb2c.us.dell.com/auth/oauth/v2/token?client_id=' + ${ApiKey} + '&client_secret=' + ${ApiSecret} + '&grant_type=client_credentials') -Method Post
		$AuthSplit = $Auth.Content -split ('"')
		$AuthKey = $AuthSplit[3]

		# Build API query parameters
		$body = "?servicetags=" + $ServiceTag + "&Method=Get"

		# Query Dell API for warranty information
		$response = Invoke-WebRequest -uri https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-entitlements${body} -Headers @{"Authorization" = "bearer ${AuthKey}"; "Accept" = "application/json" }
		$content = $response.Content | ConvertFrom-Json

		# Sort entitlements by end date (Dell doesn't list in order)
		$sortedEntitlements = $content.entitlements | Sort-Object endDate

		# Extract warranty dates from response
		$WarrantyEndDateRaw = (($sortedEntitlements.endDate | Select-Object -Last 1).split("T"))[0]
		$WarrantyEndDate = [datetime]::ParseExact($WarrantyEndDateRaw, "yyyy-MM-dd", $null)

		$WarrantyStartDateRaw = (($sortedEntitlements.startDate | Select-Object -First 1).split("T"))[0]
		$WarrantyStartDate = [datetime]::ParseExact($WarrantyStartDateRaw, "yyyy-MM-dd", $null)

		# Get support level
		$WarrantyLevel = ($sortedEntitlements.serviceLevelDescription | Select-Object -Last 1)

		# Get ship date
		$ShipDateRaw = (($content.shipDate).split("T"))[0]
		$ShipDate = [datetime]::ParseExact($ShipDateRaw, "yyyy-MM-dd", $null)

		# Get system model - try systemDescription first, fallback to productLineDescription
		If ($content.systemDescription) {
			$Model = $content.systemDescription
		}
		Else {
			$Model = $content.productLineDescription # Sometimes Dell blanks the systemDescription
		}

		# Check if warranty is expired
		$Today = get-date
		If ($Today -ge $WarrantyEndDate) {
			$WarrantyExpired = "Expired"
		}
		Else {
			$WarrantyExpired = "Not Expired"
		}

		# Create result object with warranty information
		$Obj = New-Object psobject
		$Obj | Add-Member -Type NoteProperty -Name 'ServiceTag' -Value $ServiceTag
		$Obj | Add-Member -Type NoteProperty -Name 'Model' -Value $Model
		$Obj | Add-Member -Type NoteProperty -Name 'OriginalShipDate' -Value $ShipDate
		$Obj | Add-Member -Type NoteProperty -Name 'WarrantyStartDate' -Value $WarrantyStartDate
		$Obj | Add-Member -Type NoteProperty -Name 'WarrantyEndDate' -Value $WarrantyEndDate
		$Obj | Add-Member -Type NoteProperty -Name 'WarrantyExpired' -Value $WarrantyExpired
		$Obj | Add-Member -Type NoteProperty -Name 'WarrantySupportLevel' -Value $WarrantyLevel

		# Add to results array
		$FinalObj += $Obj
	}

	# Display results if requested
	If ($Show) {
		$FinalObj | Format-Table -AutoSize
	}

	# Copy results to clipboard if requested
	If ($CopyToClipBoard) {
		$Path = $Env:Temp + '\' + [guid]::NewGuid().ToString() + '.csv'
		$FinalObj | Export-CSV -Delimiter "`t" -NoTypeInformation -Path $Path
		Get-Content -Path $Path | Set-Clipboard
		Remove-Item -Path $Path -Force
		Write-Host "Results have been copied to the clipboard."
	}

	# Return the object if requested
	If ($ReturnObject) {
		return $FinalObj
	}

	# Clean up variables
	Clear-Variable Show, FinalObj, Path, CopyToClipBoard -Force -ErrorAction SilentlyContinue
}

Function Get-DiskUsage($Path = ".") {
	Write-Host -ForegroundColor Cyan "  (large folders may take long to calculate...)"
	Get-ChildItem $path | ForEach-Object {
		$file = $_
		Get-ChildItem -r $_.FullName |
		Measure-Object -property length -sum -ErrorAction SilentlyContinue |
		Select-Object @{Name = "Name"; Expression = { $file } },
		@{Name = "Space Used (MB)"; Expression = { ([math]::Round(($_.Sum / 1024 / 1024), 2)) } }
	} | Format-Table -AutoSize

	<#
	.SYNOPSIS
		Either in the current directory or the given path, find all child items
		and calculate their cumulative size. Output the name of the folder
		and the space used in Megabytes. If this function is loaded by normal
		means for this repository, it will be available by its assigned alias 'du'.
	.PARAMETER Path
		[Optional] Path to the folder to calculate size of child items.
	.EXAMPLE
		Get-DiskUsage "C:\Users"
	.EXAMPLE
		Get-DiskUsage $env:OneDrive\Documents
	#>
}
Set-Alias -Name du -Value Get-DiskUsage

Function Get-DomainInfo {
	<#
	.SYNOPSIS
		Obtains useful information about the domain a computer is connected to.
	#>
	Write-Host "Obtaining Domain Info..."
	$ComputerInfo = Get-ComputerInfo
	If ($ComputerInfo.CsDomainRole -ne "StandaloneWorkstation") {
		$Domain = ($ComputerInfo).CSDomain
		Write-Host "`nDomain: "$Domain
		$DomainControllerIP = (Resolve-DnsName $Domain).IpAddress
		Write-Host "`nDomain Controller(s):"
		$DomainControllerIP | % {
			Write-Host "IP: $_ | FQDN: $((Resolve-DnsName $_).NameHost) | Pingable: $(Test-NetConnection -ComputerName $_ -InformationLevel Quiet) "
		}
		Write-Host "`nLocal Network Info:"
		Get-IpConfig
	}
 Else {
		Write-Host "`nComputer is not joined to a domain. Showing network info instead."
		Get-IpConfig
	}
}

Function Get-FileDownload {
	<#
	.SYNOPSIS
		Takes a URL for a file and downloads it to the specified directory.
		Parses the file name from the URL so you don't have to manually specify the file name.
	.PARAMETER URL
		URL of the file to download, i.e. 'http://download.ambitionsgroup.com/Software/migwiz.zip'
	.PARAMETER SaveToFolder
		Folder of where to save the file, i.e. 'C:\Temp
	.EXAMPLE
		#The following downloads the variable "$Link" to "$ITFolder\"

		Get-FileDownload -URL $Link -SaveToFolder '$ITFolder\'

	.EXAMPLE
		The following downloads the file 'migwiz.zip' to '$ITFolder'.
		It then exports the FileName 'migwiz.zip' to the variable $DownloadFileName.
		It also exports the full file path '$ITFolder\migwiz.zip' to the variable '$DownloadFilePath'.
		$DownloadFileInfo = Get-FileDownload -URL 'http://download.ambitionsgroup.com/Software/migwiz.zip' -SaveToFolder '$ITFolder\'
		$DownloadFileName = $DownloadFileInfo[0]
		$DownloadFilePath = $DownloadFileInfo[-1]
	#>
	param(
		[Parameter(Mandatory = $True)]
		[uri]$URL,
		[Parameter(Mandatory = $False)]
		[string]$SaveToFolder,
		[Parameter(Mandatory = $False)]
		[string]$FileName
	)

	#Isolate file name from URL
	If (-not $FileName) {
		[string]$FileName = $URL.Segments[-1]
	}

	#Set's SaveToFolder to current directory if one wasn't supplied.
	If (-not $SaveToFolder) {
		$SaveToFolder = (Get-Location).Path
	}

	#Add a '\' to the end of the folder only if needed.
	If ($SaveToFolder -notmatch '\\$'){	$SaveToFolder += '\'}
	
	#Create the destination folder if it doesn't exist.
	New-Item -Path $SaveToFolder -ItemType Directory -Force | Out-Null

	#Create full download path
	[string]$FilePath = $SaveToFolder + $FileName

	#Write-Host "Enabling SSL"
	Try {
		# Set TLS 1.2 (3072), then TLS 1.1 (768), then TLS 1.0 (192)
		# Use integers because the enumeration values for TLS 1.2 and TLS 1.1 won't
		# exist in .NET 4.0, even though they are addressable if .NET 4.5+ is
		# installed (.NET 4.5 is an in-place upgrade).
		[System.Net.ServicePointManager]::SecurityProtocol = 3072 -bor 768 -bor 192
	} Catch {
		Write-Output 'Unable to set PowerShell to use TLS 1.2 and TLS 1.1 due to old .NET Framework installed. If you see underlying connection closed or trust errors, you may need to upgrade to .NET Framework 4.5+ and PowerShell v3+.'
	}

	#Delete destination file if found.
	If (Test-Path -Path $FilePath -ErrorAction SilentlyContinue) {Remove-Item -Path $FilePath -Force}

	Write-Host "Beginning download to $FilePath"
	Try {
		Invoke-RestMethod -Uri $URL -OutFile $FilePath
		Return $FileName, $FilePath
	} Catch {
		Try {
			Invoke-WebRequest -Uri $URL -OutFile $FilePath -UseBasicParsing
			Return $FileName, $FilePath
		} Catch {
			(New-Object System.Net.WebClient).DownloadFile($URL, $FilePath)
			Return $FileName, $FilePath
		}
	}
}

Function Get-InternetHealth {
	######### Absolute monitoring values ##########
	$maxpacketloss = 2 #how much % packetloss until we alert.
	$MinimumDownloadSpeed = 100 #What is the minimum expected download speed in Mbit/ps
	$MinimumUploadSpeed = 20 #What is the minimum expected upload speed in Mbit/ps
	$MaxJitter = 30
	######### End absolute monitoring values ######

	#Replace the Download URL to where you've uploaded the ZIP file yourself. We will only download this file once.
	#Latest version can be found at: https://www.speedtest.net/nl/apps/cli
	$DownloadURL = "https://install.speedtest.net/app/cli/ookla-speedtest-1.0.0-win64.zip"
	$DownloadLocation = "$($Env:ProgramData)\SpeedtestCLI"
	$SpeedTestExe = Join-Path -Path $DownloadLocation -ChildPath "\speedtest.exe"
	Try {
		If (!$(Test-Path $SpeedTestExe)) {
			Write-Host "Preparing Internet Health Test."
			New-Item $DownloadLocation -ItemType Directory -force
			Invoke-WebRequest -Uri $DownloadURL -OutFile "$($DownloadLocation)\speedtest.zip"
			Expand-Archive "$($DownloadLocation)\speedtest.zip" -DestinationPath $DownloadLocation -Force
		}
	}
 Catch {
		Write-Host "The download and extraction of SpeedtestCLI failed. Error: $($_.Exception.Message)"
		#exit 1
		Return
	}
	$PreviousResults = If (test-path "$($DownloadLocation)\LastResults.txt") { get-content "$($DownloadLocation)\LastResults.txt" | ConvertFrom-Json }
	Write-Host "Running Internet Health Test."
	$SpeedtestResults = & $SpeedTestExe --format=json --accept-license --accept-gdpr
	$SpeedtestResults | Out-File "$($DownloadLocation)\LastResults.txt" -Force
	$SpeedtestResults = $SpeedtestResults | ConvertFrom-Json

	#creating object
	[PSCustomObject]$SpeedtestObj = @{
		downloadspeed = [math]::Round($SpeedtestResults.download.bandwidth / 1000000 * 8, 2)
		uploadspeed   = [math]::Round($SpeedtestResults.upload.bandwidth / 1000000 * 8, 2)
		packetloss    = [math]::Round($SpeedtestResults.packetLoss)
		isp           = $SpeedtestResults.isp
		ExternalIP    = $SpeedtestResults.interface.externalIp
		InternalIP    = $SpeedtestResults.interface.internalIp
		UsedServer    = $SpeedtestResults.server.host
		ResultsURL    = $SpeedtestResults.result.url
		Jitter        = [math]::Round($SpeedtestResults.ping.jitter)
		Latency       = [math]::Round($SpeedtestResults.ping.latency)
	}
	$SpeedtestHealth = @()
	#Comparing against previous result. Alerting is download or upload differs more than 20%.
	If ($PreviousResults) {
		Write-Host "Comparing against previous results."
		If ($PreviousResults.download.bandwidth / $SpeedtestResults.download.bandwidth * 100 -le 80) { $SpeedtestHealth += "Download speed difference is more than 20%" } Else { $SpeedtestHealth += "Download speed appears stable" }
		If ($PreviousResults.upload.bandwidth / $SpeedtestResults.upload.bandwidth * 100 -le 80) { $SpeedtestHealth += "Upload speed difference is more than 20%" } Else { $SpeedtestHealth += "Upload speed appears stable" }
	}

	#Comparing against preset variables.
	Write-Host "Analyzing Results"
	If ($SpeedtestObj.downloadspeed -lt $MinimumDownloadSpeed) { $SpeedtestHealth += "Download speed is lower than $MinimumDownloadSpeed Mbit/ps" ; $HealthIssue = $True } Else { $SpeedtestHealth += "Download speed is acceptable" }
	If ($SpeedtestObj.uploadspeed -lt $MinimumUploadSpeed) { $SpeedtestHealth += "Upload speed is lower than $MinimumUploadSpeed Mbit/ps"  ; $HealthIssue = $True }Else { $SpeedtestHealth += "Upload speed is acceptable" }
	If ($SpeedtestObj.packetloss -gt $MaxPacketLoss) { $SpeedtestHealth += "Packetloss is higher than $maxpacketloss%"  ; $HealthIssue = $True } Else { $SpeedtestHealth += "Packet Loss is acceptable" }
	If ($SpeedtestObj.Jitter -gt $MaxJitter) { $SpeedtestHealth += "Jitter is higher than $MaxJitter%"  ; $HealthIssue = $True } Else { $SpeedtestHealth += "Jitter is acceptable" }

	Write-Host "Internet Health Test Results:"
	$SpeedtestObj | Format-Table -AutoSize -HideTableHeaders
	Write-Host "Internet Health Summary:"
	If ($HealthIssue) { Write-Host -ForegroundColor Yellow -BackgroundColor Black "There appears to be issues!" } Else { Write-Host -ForegroundColor Green -BackgroundColor Black "All tests results are optimal!" }
	$SpeedtestHealth
}

Function Get-InstalledApplication {
	param(

	  [Parameter(Mandatory=$False, ValueFromPipeline=$True,
	  ValueFromPipelineByPropertyName=$True, HelpMessage='Enter the name of the application to check.')]
	  [Alias('Application')]
	  [string] $Name
	)

	If ( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ) {
		Write-Verbose '[Scanning All App sources]'
		Write-Verbose '--[Scanning Wmi Repository]'
	}
	$Global:WmiApps = (Get-WmiObject -Class Win32_Product).Name | Select-Object -Unique | Sort-Object
	If ( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ) {
		Write-Verbose '--[Scanning Native Powershell Repository]'
	}
	$Global:PowershellApps = (Get-Package -Provider Programs -IncludeWindowsInstaller).Name | Select-Object -Unique | Sort-Object
	If ( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ) {
		Write-Verbose '--[Scanning MSIExec UninstallString Repository]'
	}
	$Global:uninstallX86RegPath="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" | Select-Object -Unique | Sort-Object
	$Global:uninstallX64RegPath="HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" | Select-Object -Unique | Sort-Object
	$Global:MsiApps = (Get-ChildItem $uninstallX86RegPath | ForEach-Object { Get-ItemProperty $_.PSPath }).DisplayName
	$MsiApps += (Get-ChildItem $uninstallX64RegPath | ForEach-Object { Get-ItemProperty $_.PSPath }).DisplayName
	$Global:AllApps = $WmiApps + $PowershellApps + $MsiApps | Select-Object -Unique | Sort-Object
	$Global:Uninstalled = $False

	If ($Name) {
		If ($AllApps -match $Name) {
			If ( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ) {
				Write-Verbose "$($AllApps -match $Name) is installed."
			}
			Return $True
		} Else {
			If ( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ) {
				Write-Verbose "$Name is NOT installed."
			}
			Return $False
		}
	} Else {
		If ( $PSBoundParameters['Verbose'] -or $VerbosePreference -eq 'Continue' ) {
				Write-Verbose "Installed Applications:`n`n"
			}
		Return $AllApps
	}
}

Function Get-IPConfig {
	<#
	.DESCRIPTION
		Get-IPConfig attempts to extract only useful information from network adapters and display it in an easy to reay way.
		This is only IPv4 for now.
	#>

	Get-netipaddress -AddressFamily IPv4 -PrefixOrigin Dhcp, Manual | Sort InterfaceIndex | Format-Table -AutoSize -Property `
		InterfaceAlias, `
	@{Name = 'Domain' ; Expression = { $($_ | Get-NetIPConfiguration).NetProfile.Name } }, `
	@{Name = 'Status' ; Expression = { $($_ | Get-NetIPConfiguration).NetAdapter.Status } }, `
	@{Name = 'IP Address' ; Expression = { $($_.IPAddress + "/" + $_.PrefixLength) } }, `
	@{Name = 'DefaultGateway' ; Expression = { $($_ | Get-NetIPConfiguration).IPv4DefaultGateway.NextHop } }, `
	@{Name = 'DNS Server(s)' ; Expression = { $(($_ | Get-NetIPConfiguration).DNSServer | Where-Object -Property AddressFamily -eq 2).ServerAddresses } }
}

Function Get-ListeningPorts {
	<#

	.SYNOPSIS
		Checks for processes that are listening on an open port. Useful for troubleshooting firewall issues.
		For svchost.exe processes, identifies the associated service with the listening port.

	 .EXAMPLE
		Get-ListeningPorts

	.EXAMPLE
		Get-ListeningPorts -IncludeIp6

	.PARAMETER IncludeIp6
		Include this switch to include the IPv6 adapter addresses that have listening ports

	.LINK
		https://azega.org/list-open-ports-using-powershell/

	#>

	Param(
		[Parameter(Mandatory = $false)]
		[Switch]$IncludeIp6
	)

	$IpAddresses = (Get-NetIPAddress).IPAddress | Where-Object { $_ -notmatch "::" }
	$IpAddresses += "0.0.0.0"

	If ($IncludeIp6) { $IpAddresses += "::" }

	Get-NetTcpConnection | Where-Object { ($_.State -eq "Listen") -and ( $IpAddresses -contains $_.LocalAddress) } | `
		Select-Object LocalAddress,
	LocalPort,
	@{Name = "Process Name"; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName } },
	@{Name = "Service Name"; Expression = { If ((Get-Process -Id $_.OwningProcess).ProcessName -eq "svchost") {
				$p = $_.OwningProcess
						  (Get-WmiObject Win32_Service | Where-Object { $_.ProcessId -eq $p }).Name
			}
			Else { $null } }
	},
	State | Sort LocalPort | Format-Table
}

Function Get-LoginHistory {
	<#

	.SYNOPSIS
		This script reads the event log "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" from
		multiple servers and outputs the human-readable results to a CSV/Table. This data is not filterable in the
		native Windows Event Viewer.

		Version: November 9, 2016


	.SYNOPSIS
		This script reads the event log "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" from
		multiple servers and outputs the human-readable results to a CSV/Table.  This data is not filterable in
		the native Windows Event Viewer.

		NOTE: Despite this log's name, it includes both RDP logins as well as regular console logins1.

		Author:
		Mike Crowley
		https://BaselineTechnologies.com

	 .EXAMPLE

		Get-LoginHistory -ServersToQuery Server1, Server2 -StartTime "November 1"

	.LINK
		https://MikeCrowley.us/tag/powershell

	#>

	Param(
		[array]$ServersToQuery = (hostname),
		[datetime]$StartTime = "January 1, 1970"
	)

	Foreach ($Server in $ServersToQuery) {

		$LogFilter = @{
			LogName   = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
			ID        = 21, 23, 24, 25
			StartTime = $StartTime
		}

		$AllEntries = Get-WinEvent -FilterHashtable $LogFilter -ComputerName $Server

		$AllEntries | ForEach-Object {
			$entry = [xml]$_.ToXml()
			[array]$Output += New-Object PSObject -Property @{
				TimeCreated = $_.TimeCreated
				User        = $entry.Event.UserData.EventXML.User
				IPAddress   = $entry.Event.UserData.EventXML.Address
				EventID     = $entry.Event.System.EventID
				ServerName  = $Server
			}
		}
	}

	$FilteredOutput += $Output | Select-Object TimeCreated, User, ServerName, IPAddress, @{Name = 'Action'; Expression = {
			if ($_.EventID -eq '21') { "Logon" }
			if ($_.EventID -eq '22') { "Shell Start" }
			if ($_.EventID -eq '23') { "Logoff" }
			if ($_.EventID -eq '24') { "Disconnected" }
			if ($_.EventID -eq '25') { "Reconnection" }
		}
	}

	$FilteredOutput | Sort-Object -Property TimeCreated | Format-Table -AutoSize
}

Function Get-NetExtenderStatus {

	# Definte the possible paths where NetExtender can exist.
	$possiblePaths = @(
		"${env:ProgramFiles(x86)}\SonicWALL\SSL-VPN\NetExtender\NECli.exe"
		"${env:ProgramFiles(x86)}\SonicWall\SSL-VPN\NetExtender\nxcli.exe"
		"${env:ProgramFiles}\SonicWall\SSL-VPN\NetExtender\nxcli.exe"
	)

	$NEPath = $possiblePaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Last 1

	If (!(Test-Path -LiteralPath $NEpath)) {
	Write-Host "This command only works if you have Sonicwall NetExtender installed."
	}
	If ($NEPath -match "NECli.exe") { #Older version
		& $NEPath showstatus
		} elseif ($NEPath -match "nxcli.exe") { #Newer version
		& $NEPath status
		}
		Write-Host 'Try "Connect-NetExtender" or "Disconnect-NetExtender"'
	
	<#
	.SYNOPSIS
	Displays the connection status of Sonicwall NetExtender
	.EXAMPLE
	Get-NetExtenderStatus
	#>
	}
	
Function Get-PSWinGetUpdatablePackages {
	Start-PSWinGet -Command 'Get-WinGetPackage | Where {$_.IsUpdateAvailable -eq $True}'
}

Function Get-RandomPassword {
	[CmdletBinding()]
	param(
		[switch]$silent
	)

	# Function to get a random word from a list
	function Get-RandomWord($wordList) {
		return $wordList | Get-Random
	}

	# Function to replace a random character with a leet speak symbol
	function Replace-WithLeetSpeak($word) {
		$leetMap = @{
			'a' = '@'; 'c' = '('; 'e' = '&'; 'i' = '!'; 'o' = '*'; 's' = '$'; 't' = '+';
			'l' = '|'; 'z' = '%'; 'h' = '#'; 'x' = ')('; 'v' = '\/'; 'j' = ']'; 'f' = '='; 'k' = '<'
		}
		$chars = $word.ToCharArray()
		$replaceable = $chars | Where-Object { $leetMap.ContainsKey($_.ToString().ToLower()) }

		if ($replaceable.Count -gt 0) {
			$replaceChar = $replaceable | Get-Random
			$replaceIndex = [Array]::IndexOf($chars, $replaceChar)
			$chars[$replaceIndex] = $leetMap[$replaceChar.ToString().ToLower()]
		}

		return -join $chars
	}

	# Lists of words (all between 4 and 7 characters long, without spaces)
	$adjectives = @('happy', 'silly', 'funny', 'brave', 'clever', 'quiet', 'smart',
					'strong', 'shiny', 'smooth', 'rough', 'sweet', 'clean', 'dirty', 'joyful',
					'eager', 'proud', 'active', 'calm', 'daring', 'gentle', 'humble', 'kind',
					'lively', 'merry', 'nice', 'polite', 'quick', 'shy', 'tough', 'witty',
					'zesty', 'bold', 'bright', 'cheery', 'dapper', 'eager', 'fair', 'fine',
					'fresh', 'grand', 'keen', 'neat', 'perky', 'prime', 'spry', 'super',
					'swift', 'trim', 'zippy', 'alert', 'apt', 'brisk', 'chipper', 'dandy',
					'deft', 'earthy', 'flash', 'game', 'gutsy', 'hardy', 'hip', 'peppy',
					'plush', 'punchy', 'sassy', 'savvy', 'snappy', 'spunky', 'staunch',
					'sturdy', 'sunny', 'upbeat', 'vivid', 'zappy', 'blithe', 'breezy',
					'bubbly', 'chirpy', 'comfy', 'cool', 'crisp', 'cushy', 'cute', 'droll',
					'fluffy', 'frisky', 'genial', 'giddy', 'giggly', 'groovy', 'hearty',
					'jolly', 'jaunty', 'jazzy', 'keen', 'nifty', 'perky', 'plucky', 'primo',
					'spiffy', 'sporty', 'spruce', 'stellar', 'swank', 'swell', 'tidy')

	$animals = @('rabbit', 'turtle', 'panda', 'lion', 'tiger', 'monkey', 'koala', 'horse', 'sheep',
				'zebra', 'jaguar', 'camel', 'coyote', 'donkey', 'hyena', 'iguana', 'jackal',
				'lemur', 'llama', 'lynx', 'otter', 'sloth', 'tapir', 'toucan', 'walrus', 'weasel',
				'alpaca', 'beagle', 'bison', 'cicada', 'dingo', 'falcon', 'gecko', 'gopher',
				'ibex', 'impala', 'kiwi', 'liger', 'mole', 'newt', 'puffin', 'quail', 'raven',
				'seal', 'shark', 'skunk', 'swan', 'viper', 'wasp', 'wolf', 'bass', 'bear',
				'bull', 'carp', 'clam', 'crab', 'crow', 'deer', 'dove', 'duck', 'apple', 'buffalo',
				'raccoon', 'flea', 'fowl', 'frog', 'goat', 'hare', 'hawk', 'heron', 'lark', 'mink',
				'moth', 'mule', 'reptile', 'pike', 'pony', 'hippo', 'sole', 'stag', 'stork', 'swift',
				'teal', 'trout', 'wren', 'calf', 'chick', 'dugong', 'colt', 'kitten', 'fawn', 'lamb',
				'hound', 'finch', 'toad', 'mole', 'snail', 'boar', 'hare')

	# Generate password components
	$adjective = Get-RandomWord $adjectives
	$animal = Get-RandomWord $animals
	$number = Get-Random -Minimum 10 -Maximum 100

	# Apply transformations
	$wordToLeet = Get-Random -InputObject @($adjective)
	$wordToCapitalize = if ($wordToLeet -eq $adjective) { $animal } else { $adjective }

	$leetWord = Replace-WithLeetSpeak $wordToLeet
	if ($leetWord -notmatch '[!@#$%^&*()_+\-=\[\]{};:''",.<>?/]') {
		$specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?/'
		$leetWord += $specialChars[(Get-Random -Maximum $specialChars.Length)]
	}
	$capitalizedWord = (Get-Culture).TextInfo.ToTitleCase($wordToCapitalize)

	# Construct the password
	$password = "$leetWord$capitalizedWord$number"

	# Ensure password is at least 10 characters long
	while ($password.Length -lt 10) {
		$extraChar = Get-Random -InputObject @('!', '@', '#', '$', '%', '&', '*', '?')
		$password += $extraChar
	}

	if (!$silent) {
		# Output the generated password
		Write-Host "$password"

		# Offer to copy the password to the clipboard
		$copyToClipboard = Read-Host "Do you want to copy the password to the clipboard? (Y/n)"

		if ($copyToClipboard -eq '' -or $copyToClipboard -eq 'y' -or $copyToClipboard -eq 'Y') {
			$password | Set-Clipboard
			Write-Host "Password copied to clipboard."
		} else {
			Write-Host "Password not copied to clipboard."
		}
	} else {
		return $password
	}
}

Function Get-SharedMailboxRestoreRequest {
	Get-MailboxRestoreRequest | Get-MailboxRestoreRequestStatistics -IncludeReport | FT TargetAlias, Status, StatusDetail, PercentComplete, DataConsistencyScore -AutoSize
	<#
	.SYNOPSIS
		Shows the status of current or recently run Mailbox Restore Requests. Must be connected to Exchange Online to Run.
		Used in conjunction with the Convert-ToSharedMailbox command.
	#>
}

Function Get-SonicwallInterfaceIP {
	param(
		[Parameter(Mandatory = $True,
			ParameterSetName = 'Direct')]
		[Parameter(Mandatory = $True,
			ParameterSetName = 'ToFile')]
		[string]$SonicWallAddress,

		[Parameter(Mandatory = $True,
			ParameterSetName = 'Direct')]
		[Parameter(Mandatory = $True,
			ParameterSetName = 'ToFile')]
		[string]$Username,

		[Parameter(Mandatory = $True,
			ParameterSetName = 'Direct')]
		[Parameter(Mandatory = $True,
			ParameterSetName = 'ToFile')]
		[string]$Password,

		[Parameter(Mandatory = $False,
			ParameterSetName = 'Direct')]
		[Parameter(Mandatory = $False,
			ParameterSetName = 'ToFile')]
		[int]$Port = '22',

		[Parameter(Mandatory = $True,
			ParameterSetName = 'Direct')]
		[Parameter(Mandatory = $True,
			ParameterSetName = 'ToFile')]
		[string]$Interface,

		[Parameter(Mandatory = $True,
			ParameterSetName = 'FromFile')]
		[System.IO.FileInfo]$FromFile,

		[Parameter(Mandatory = $True,
			ParameterSetName = 'ToFile')]
		[System.IO.FileInfo]$ToFile,

		[Parameter(Mandatory = $False,
			ParameterSetName = 'Direct')]
		[Parameter(Mandatory = $False,
			ParameterSetName = 'FromFile')]
		[Parameter(Mandatory = $False,
			ParameterSetName = 'ToFile')]
		[System.IO.FileInfo]$SetDnsMadeEasyFile
	)

	#Work with settings file.
	If ($FromFile) {
		$encryptedstring = Get-Content -Path $FromFile
		$securestring = $encryptedstring | ConvertTo-SecureString
		$Marshal = [System.Runtime.InteropServices.Marshal]
		$Bstr = $Marshal::SecureStringToBSTR($securestring)
		$string = $Marshal::PtrToStringAuto($Bstr)
		$string | Invoke-Expression
		$Marshal::ZeroFreeBSTR($Bstr)
	} Else {
		If ($ToFile) {
			$ParamArray = @(
				$('[string]$SonicWallAddress = "' + $SonicWallAddress + '"')
				$('[string]$Username = "' + $Username + '"')
				$('[string]$Password = "' + $Password + '"')
				$('[string]$Interface = "' + $Interface + '"')
				$('[int]$Port = "' + $Port + '"')
			)
			If ($SetDnsMadeEasyFile) { $ParamArray += $('[System.IO.FileInfo]$SetDnsMadeEasyFile = "' + $SetDnsMadeEasyFile + '"') }
			$securestring = $ParamArray | Out-String | ConvertTo-SecureString -AsPlainText -Force
			$encryptedstring = $securestring | ConvertFrom-SecureString
			$encryptedstring | Set-Content -Path $ToFile -Force
		}
	}

	If (-Not ($ToFile)) {
		# Check if our module loaded properly
		Update-PowerShellModule -ModuleName 'Posh-SSH'


		# Includes
		Import-Module Posh-SSH

		#Configure the command
		[string]$Command = "show interface $Interface IP"

		# Generate credentials object for authentication
		$nopasswd = $Password | ConvertTo-SecureString -AsPlainText -Force
		$Credential = New-Object System.Management.Automation.PSCredential ($Username, $nopasswd)
		$Session = New-SSHSession -Computername $SonicWallAddress -Credential $Credential -Acceptkey -Port $Port -OutVariable Session

		$stream = New-SSHShellStream -SSHSession $Session
		$stream.WriteLine($Command)
		Start-Sleep 1
		# Store the output of the command
		$Output = $stream.Read()

		# Remove the session after we're done
		Remove-SSHSession -Name $Session | Out-Null

		# return the actual output
		#Write-Host $Output.Trim();

		# Automatically update the fingerprint for the given host.
		Remove-SSHTrustedHost $SonicWallAddress | Out-Null

		$IP = ($Output.tostring().split("`n").trim() | Select-String -SimpleMatch "IP Address").Line.split(":").Trim()[-1]
		$IP

		If ($SetDnsMadeEasyFile) {
			Set-DnsMadeEasyDDNS -FromFile $SetDnsMadeEasyFile -IPAddress $IP
		}
	}
}

Function Get-UserMailboxAccess {
	param
	(
		[Parameter(Mandatory = $True)]
		[string]$User
	)

	$progressPreference = 'Continue'
	Write-Progress -Activity "Validating user: $User"
	$ValidatedUser = Get-EXOMailbox -Identity $User -ErrorAction SilentlyContinue
	If (-not $ValidatedUser) {
		Do {
			#Retry the User
			$User = Read-Host "Entry `"$User`" didn't work. Check your spelling and try again or type QUIT to stop:`n"
			If ($User -match "QUIT") { Break }
			$ValidatedUser = Get-EXOMailbox -Identity $User -ErrorAction SilentlyContinue
			#Active User Check
			If ($ValidatedUser) {
				Write-Host "Entry `"$User`" has been validated!"
			}
		} While (-not $ValidatedUser)
		$User = $ValidatedUser.Identity
		Write-Host $User
	}
 Else { $User = $ValidatedUser.Identity }

	Write-Progress -Activity "Collecting list of mailboxes"
	$Mailboxes = Get-ExoMailbox -ResultSize Unlimited

	Write-Progress -Activity "Gathering mailbox access permissions"
	$Access = $Mailboxes | Get-MailboxPermission -User $User

	Write-Progress -Activity "Gathering 'Send As' permissions"
	$SendAs = $Mailboxes | Get-RecipientPermission -Trustee $User

	Write-Progress -Activity "Gathering 'Send On Behalf' permissions"
	$SendOnBehalf = $Mailboxes | ? { $_.GrantSendOnBehalfTo -match $User }

	Write-Progress -Activity * -Completed

	Write-Host "-----Results for $User-----"
	If ($Access) {
		Write-Host "$User has mailbox access to:"
		Write-Host -ForegroundColor Yellow "$(($Access | FT Identity,AccessRights -HideTableHeaders | Out-String).Trim())"
	}
 Else {
		Write-Host "$User does not have direct access to any other mailboxes."
	}

	If ($SendAs) {
		Write-Host "$User has 'Send As' permissions for:"
		Write-Host -ForegroundColor Yellow "$($SendAs.Identity)"
	}
 Else {
		Write-Host "$User does not have Send As access to any other mailboxes."
	}

	If ($SendOnBehalf) {
		Write-Host "$User has 'Send As' permissions for:"
		Write-Host -ForegroundColor Yellow "$($SendOnBehalf.Identity)"
	}
 Else {
		Write-Host "$User does not have Send On Behalf access to any other mailboxes."
	}

	<#
	.DESCRIPTION
		Check's what permissions a user has over other mailboxes including Direct Access, Send As, and Send on Behalf.
	.PARAMETER User
		[Require] Specify the alias or name of the person to check.
	.EXAMPLE
		[Command]: Get-UserMailboxAccess -User Marcus

		-----Results for Marcus Rael-----
		Marcus Smarcus does not have direct access to any other mailboxes.
		Marcus Smarcus does not have Send As access to any other mailboxes.
		Marcus Smarcus does not have Send On Behalf access to any other mailboxes.
	.EXAMPLE
		[Command]: Get-UserMailboxAccess -User Marcus

		-----Results for Chelsea Sandoval-----
		Chelsea Scott has mailbox access to:
		Brian Davidson    {FullAccess}
		Christopher McChrisFace  {FullAccess}
		David Burger      {FullAccess}
		Faxes             {FullAccess}
		Tasks             {FullAccess}
		George E. Boy     {FullAccess}
		Randy Rascal      {FullAccess}
		Simmone Biles     {FullAccess}
		Chelsea Scott does not have Send As access to any other mailboxes.
		Chelsea Scott does not have Send On Behalf access to any other mailboxes.
	#>
}

Function Get-ThunderBolt {
	$Thunderbolt = Get-WmiObject Win32_SystemDriver | Where-Object -Property DisplayName -Like "*Thunder*"
	If ($Thunderbolt) {
		Write-Host "The following ThunderBolt controllers have been detected:"
		$Thunderbolt
	}
 Else {
		Write-Host "No Thunderbolt Controllers have been detected"
	}
}

Function Get-UserProfileSpace {
	$Profiles = (Get-CimInstance win32_userprofile | ? { $_.Special -eq $False })
	#$Profiles | Select -Property LocalPath, @{Name = 'Last Activity' ; Expression = {(Get-Item ($_.LocalPath + "\AppData\Local")).LastWriteTime}} | Sort-Object "Last Activity"
	$ActiveProfiles = @()
	$FolderSizes = @{}
	#$FinalExport.add('HostName','User','Desktop(MB)','Documents(MB)','Pictures(MB)'
	$StaleLimit = (Get-date).AddDays(-90)
	$ProfilePaths = $Profiles.LocalPath
	$global:Desktop = 0
	$global:Documents = 0
	$global:Pictures = 0
	$global:BigObject = $()

	ForEach ($ProfilePath in $ProfilePaths) {
		#$ProfilePath = "C:\Users\rshoemaker"
		$LastActivity = If (Test-Path -Path $($ProfilePath + "\AppData") -ErrorAction SilentlyContinue) {
			(Get-ChildItem -Path $($ProfilePath + "\AppData") | Sort LastWriteTime -Descending)[0].LastWriteTime
		}
		Else { Return 0 }
		If ($LastActivity -gt $StaleLimit) {
			#Write-Host $ProfilePath is recent with an activity date of $LastActivity
			$ActiveProfiles += $ProfilePath
		}
		Else {
			#Write-Host $ProfilePath is old with an activity date of $LastActivity
		}
	}
	#Write-Host $($ActiveProfiles.Count) active profiles found.
	#$ActiveProfiles

	If ($ActiveProfiles) {
		Update-PowerShellModule -ModuleName 'PSFolderSize'
		ForEach ($ActiveProfile in $ActiveProfiles) {
			[Decimal]$FolderSizeSum = 0.00
			#Write-Host $($ActiveProfile | split-path -leaf)
			$Folders = @("Desktop", "Documents", "Pictures")
			$FolderSizes = [PSCustomObject]@{}
			ForEach ($Folder in $Folders) {
				If (Test-Path -Path $($ActiveProfile + "\" + "$Folder")) {
					$GetSize = (Get-FolderSize -Path $ActiveProfile -FolderName $Folder).SizeMB
					If ($GetSize.Count -gt 1) {
						[Decimal]$Size = $($GetSize)[0] | Out-String
					}
					Else {
						[Decimal]$Size = $($GetSize) | Out-String
					}
					#Write-Host `t$Folder $Size
					Set-Variable -Name $Folder -Value $Size -Force
				}
				Else {
					Set-Variable -Name $Folder -Value 0 -Force
				}

			} #ForEach ($Folder in $Folders)
			$FolderSizes = [PSCustomObject]@{
				"User"      = $($ActiveProfile | split-path -leaf).ToLower()
				"Host"      = $env:computername
				"Date"      = $(Get-Date -Format "yyyyMMdd")

				"Desktop"   = $Desktop
				"Documents" = $Documents
				"Pictures"  = $Pictures
				"Total"     = $Desktop + $Documents + $Pictures
			}
			#$FolderSizes
			If ($BigObject.Count -eq 0) {
				$BigObject = ($FolderSizes | ConvertTo-Csv -NoTypeInformation)
			}
			Else {
				$BigObject += ($FolderSizes | ConvertTo-Csv -NoTypeInformation)[-1]
			}
			$global:Desktop = 0
			$global:Documents = 0
			$global:Pictures = 0
		} #ForEach ($ActiveProfile in $ProfilePaths)
	} #If (ActiveProfiles)

	Return $BigObject
}

Function Get-VSSWriter {
	[CmdletBinding()]

	Param (
		[ValidateSet('Stable', 'Failed', 'Waiting for completion')]
		[String]
		$Status
	) #Param

	BEGIN { Write-Verbose "BEGIN: Get-KPVSSWriter" } #BEGIN

	PROCESS {
		#Command to retrieve all writers, and split them into groups
		Write-Verbose "Retrieving VSS Writers"
		VSSAdmin list writers |
		Select-String -Pattern 'Writer name:' -Context 0, 4 |
		ForEach-Object {

			#Removing clutter
			Write-Verbose "Removing clutter "
			$Name = $_.Line -replace "^(.*?): " -replace "'"
			$Id = $_.Context.PostContext[0] -replace "^(.*?): "
			$InstanceId = $_.Context.PostContext[1] -replace "^(.*?): "
			$State = $_.Context.PostContext[2] -replace "^(.*?): "
			$LastError = $_.Context.PostContext[3] -replace "^(.*?): "

			#Create object
			Write-Verbose "Creating object"
			foreach ($Prop in $_) {
				$Obj = [pscustomobject]@{
					Name       = $Name
					Id         = $Id
					InstanceId = $InstanceId
					State      = $State
					LastError  = $LastError
				}
			}#foreach
			#Change output based on Status provided
			If ($PSBoundParameters.ContainsKey('Status')) {
				Write-Verbose "Filtering out the results"
				$Obj | Where-Object { $_.State -like "*$Status" }
			} #if
			else {
				$Obj
			} #else
		}#foreach-object
	} #PROCESS
	END { } #END
}


# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUrIn+ILH20I92yNcV/wJ9ySyK
# ayCgggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUyvWS
# oZ+/XTIv6YuU6tAbuZrK0qYwDQYJKoZIhvcNAQEBBQAEggEAQFvI3ESUJhq+M/9X
# Ct4wKW4PWDysRA6pKGrpYky0OgR+vm2Md91juZUk1J94Rsb3CDikcNOSi9jZ5DZJ
# gZ/a+eQ/q0A+fF3oBJf14/gYa1iYjUi/OxC1NsxhLeYgoNW8R7OhY7WjY6fL/t3R
# a8YoiJcIqJb5n2HXta4gaLnrxgo2TgwG/43DtYPfzNg4mPZnJu0xif6QK+iqQFLF
# 2pfMIEPeUgeLmOAfpS9oTKm6mLGBho2ayIZQ2tp+pySsg4yK4vtE0mFRHEvYPEQm
# C72iDgAhPfCsOtkwJ0Ntytjbq/r5QJwSrwF83MGzeTYxyUyrIPkre6LUPvusiYO2
# M/MlMQ==
# SIG # End signature block
