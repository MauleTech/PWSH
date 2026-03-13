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
			$adUserInfo | Out-GridView -Title "Powershell --> User Password Expirations"
		}

	}
 else {
		# cannot continue, Get-AdUser is not available
		Write-Host "`n [!] This command must be run on a system with Active Directory Powershell Modules (i.e. a domain controller)`n"
	}
}

function Get-ADUsersPasswordExpiring {
	<#
	.SYNOPSIS
		Retrieves Active Directory users whose passwords will expire within a specified number of days.
	.DESCRIPTION
		This function queries Active Directory for enabled user accounts that have password expiration
		enabled and whose passwords will expire within the specified threshold. It returns details
		including the user's name, when their password was last set, when it expires, and how many
		days remain until expiration.

		When the Specops.SpecopsPasswordPolicy module is available, the function uses the SpecOps
		password policy MaximumPasswordAge setting for accurate expiration calculation. Otherwise,
		it falls back to the standard msDS-UserPasswordExpiryTimeComputed attribute which calculates
		expiration based on the default domain password policy.
	.PARAMETER DaysUntilExpiration
		The number of days to look ahead for expiring passwords. Users whose passwords expire
		within this many days from today will be included in the results. Defaults to 60 days.
	.EXAMPLE
		Get-ADUsersPasswordExpiring
		Returns all users whose passwords expire within the next 60 days.
	.EXAMPLE
		Get-ADUsersPasswordExpiring -DaysUntilExpiration 14
		Returns all users whose passwords expire within the next 14 days.
	.EXAMPLE
		Get-ADUsersPasswordExpiring -DaysUntilExpiration 7 | Export-Csv -Path ".\ExpiringSoon.csv" -NoTypeInformation
		Exports users with passwords expiring in the next week to a CSV file.
	.OUTPUTS
		PSCustomObject with properties:
		- SamAccountName: The user's login name
		- Name: The user's display name
		- PasswordLastSet: When the password was last changed
		- ExpiresOn: The date/time the password will expire
		- DaysRemaining: Number of days until expiration
	.NOTES
		Requires the ActiveDirectory PowerShell module.
		Must be run with permissions to query AD user objects.
		Supports SpecOps Password Policy when the Specops.SpecopsPasswordPolicy module is installed.
	#>
	[CmdletBinding()]
	param(
		[Parameter(HelpMessage = "Number of days to look ahead for expiring passwords")]
		[ValidateRange(1, 365)]
		[int]$DaysUntilExpiration = 60
	)

	# Verify Active Directory module is available
	if (-not (Get-Command ActiveDirectory\Get-ADUser -ErrorAction SilentlyContinue)) {
		Write-Error "This function requires the ActiveDirectory PowerShell module. Please run on a domain controller or install RSAT."
		return
	}

	$today = Get-Date
	$threshold = $today.AddDays($DaysUntilExpiration)

	# Check if SpecOps Password Policy module is available
	$useSpecOps = $false
	$specopsMaxAge = $null
	if (Get-Module -ListAvailable -Name "Specops.SpecopsPasswordPolicy" -ErrorAction SilentlyContinue) {
		try {
			Import-Module Specops.SpecopsPasswordPolicy -ErrorAction Stop
			$specopsPolicy = Get-PasswordPolicy -ErrorAction Stop
			if ($specopsPolicy -and $specopsPolicy.Policy -and $specopsPolicy.Policy.MaximumPasswordAge) {
				$specopsMaxAge = $specopsPolicy.Policy.MaximumPasswordAge
				$useSpecOps = $true
				Write-Verbose "Using SpecOps Password Policy. MaximumPasswordAge: $specopsMaxAge days"
			}
		} catch {
			Write-Verbose "SpecOps module found but failed to get policy: $_. Falling back to standard AD method."
		}
	}

	if ($useSpecOps) {
		# Use SpecOps password policy for expiration calculation
		Get-ADUser -Filter {Enabled -eq $true -and PasswordNeverExpires -eq $false} -Properties PasswordLastSet |
		Where-Object { $_.PasswordLastSet } |
		ForEach-Object {
			$expiryDate = $_.PasswordLastSet.AddDays($specopsMaxAge)
			if ($expiryDate -gt $today -and $expiryDate -le $threshold) {
				[PSCustomObject]@{
					SamAccountName  = $_.SamAccountName
					Name            = $_.Name
					PasswordLastSet = $_.PasswordLastSet
					ExpiresOn       = $expiryDate
					DaysRemaining   = ($expiryDate - $today).Days
				}
			}
		} | Sort-Object DaysRemaining
	} else {
		# Standard AD method using msDS-UserPasswordExpiryTimeComputed
		Write-Verbose "Using standard AD password expiration (msDS-UserPasswordExpiryTimeComputed)"
		Get-ADUser -Filter {Enabled -eq $true -and PasswordNeverExpires -eq $false} `
			-Properties PasswordLastSet, PasswordNeverExpires, msDS-UserPasswordExpiryTimeComputed |
		Where-Object { $_.'msDS-UserPasswordExpiryTimeComputed' } |
		ForEach-Object {
			$expiryDate = [DateTime]::FromFileTime($_.'msDS-UserPasswordExpiryTimeComputed')
			if ($expiryDate -gt $today -and $expiryDate -le $threshold) {
				[PSCustomObject]@{
					SamAccountName  = $_.SamAccountName
					Name            = $_.Name
					PasswordLastSet = $_.PasswordLastSet
					ExpiresOn       = $expiryDate
					DaysRemaining   = ($expiryDate - $today).Days
				}
			}
		} | Sort-Object DaysRemaining
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
		Get-BitLockerKey -Computer "PC-Desktop23"

		Retrieves the BitLocker key for PC-Desktop23 and copies it to the clipboard.
	.EXAMPLE
		Get-BitLockerKey

		Returns BitLocker keys for all computers in Active Directory.
	.EXAMPLE
		Get-ADComputer "PC-Desktop23" | Get-BitLockerKey

		Retrieves the BitLocker key for PC-Desktop23 using pipeline input from Get-ADComputer.
	.EXAMPLE
		Get-ADComputer -Filter {Name -like "PC-*"} | Get-BitLockerKey

		Retrieves BitLocker keys for all computers with names starting with "PC-".
	.NOTES
		Requires Active Directory PowerShell module and appropriate permissions.
	#>
}

function Get-ClaudeCodeStatus {
	<#
	.SYNOPSIS
		Gets the installation and authentication status of Claude Code.
	.DESCRIPTION
		Returns an object with installation status, version, paths, and auth status.
		Useful for checking before running Start-ClaudeCode or Update-ClaudeCode.
	.PARAMETER Quiet
		Returns just $true/$false for installed status (for scripting).
	.EXAMPLE
		Get-ClaudeCodeStatus
	.EXAMPLE
		if (Get-ClaudeCodeStatus -Quiet) { Start-ClaudeCode }
	#>
	[CmdletBinding()]
	param(
		[switch]$Quiet
	)

	# Paths
	if (-not $Global:ITFolder) { $Global:ITFolder = "$env:SystemDrive\IT" }
	$ClaudeFolder = "$Global:ITFolder\ClaudeCode"
	$ClaudeExe = "$ClaudeFolder\claude.exe"
	$ClaudeConfig = "$env:USERPROFILE\.claude"
	$ClaudeJson = "$env:USERPROFILE\.claude.json"

	$Installed = Test-Path $ClaudeExe
	$HasCredentials = (Test-Path $ClaudeConfig) -or (Test-Path $ClaudeJson)

	if ($Quiet) {
		return $Installed
	}

	# Get version if installed
	$Version = $null
	$LatestVersion = $null
	$UpdateAvailable = $false

	if ($Installed) {
		# Ensure in PATH for this session
		if ($env:Path -notlike "*$ClaudeFolder*") { $env:Path = "$env:Path;$ClaudeFolder" }

		try {
			$Version = (& $ClaudeExe --version 2>$null).Trim()
		} catch { }

		# Check latest version from npm
		try {
			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
			$npmInfo = Invoke-RestMethod -Uri "https://registry.npmjs.org/@anthropic-ai/claude-code/latest" -UseBasicParsing -ErrorAction SilentlyContinue
			if ($npmInfo.version) {
				$LatestVersion = $npmInfo.version
				if ($Version -and $LatestVersion -and $Version -ne $LatestVersion) {
					$UpdateAvailable = $true
				}
			}
		} catch { }
	}

	# Build status object
	$Status = [PSCustomObject]@{
		Installed       = $Installed
		Path            = if ($Installed) { $ClaudeExe } else { $null }
		Version         = $Version
		LatestVersion   = $LatestVersion
		UpdateAvailable = $UpdateAvailable
		HasCredentials  = $HasCredentials
		ConfigPath      = $ClaudeConfig
	}

	# Display if not quiet
	Write-Host "`n=== Claude Code Status ===" -ForegroundColor Cyan

	if ($Installed) {
		Write-Host " [OK] Installed: $ClaudeExe" -ForegroundColor Green
		if ($Version) { Write-Host "      Version: $Version" -ForegroundColor Gray }
		if ($LatestVersion) { Write-Host "      Latest:  $LatestVersion" -ForegroundColor Gray }
		if ($UpdateAvailable) { Write-Host "      Update available! Run Update-ClaudeCode" -ForegroundColor Yellow }
	} else {
		Write-Host " [X] Not installed" -ForegroundColor Red
		Write-Host "     Run Install-ClaudeCode (as admin) to install." -ForegroundColor Yellow
	}

	if ($HasCredentials) {
		Write-Host " [OK] Credentials found for current user" -ForegroundColor Green
	} else {
		Write-Host " [-] No credentials (not logged in)" -ForegroundColor Yellow
	}

	Write-Host ""
	return $Status
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

function Get-DatacenterLocation {
	<#
	.SYNOPSIS
	Detects which datacenter a computer is in based on ping response times.
	
	.DESCRIPTION
	Pings gateway IPs in Albuquerque and Phoenix datacenters and determines location
	based on which has lower latency.
	
	.PARAMETER AlbuquerqueIP
	IP address of Albuquerque datacenter gateway. Default: 140.82.177.82
	
	.PARAMETER PhoenixIP
	IP address of Phoenix datacenter gateway. Default: 207.38.71.50
	
	.PARAMETER Count
	Number of ping attempts. Default: 2
	
	.EXAMPLE
	Get-DatacenterLocation
	Returns: Albuquerque (or Phoenix)
	
	.EXAMPLE
	Get-DatacenterLocation -Count 8
	Uses 8 pings for more accurate average
	
	.NOTES
	Used for stretched VLAN environments to determine physical location.
	#>
	
	[CmdletBinding()]
	param(
		[string]$AlbuquerqueIP = "140.82.177.82",
		[string]$PhoenixIP = "207.38.71.50",
		[int]$Count = 2
	)
	
	Write-Verbose "Pinging Albuquerque gateway: $AlbuquerqueIP"
	$abqPing = Test-Connection -ComputerName $AlbuquerqueIP -Count $Count -ErrorAction SilentlyContinue
	
	Write-Verbose "Pinging Phoenix gateway: $PhoenixIP"
	$phxPing = Test-Connection -ComputerName $PhoenixIP -Count $Count -ErrorAction SilentlyContinue
	
	if (-not $abqPing -and -not $phxPing) {
		Write-Warning "Unable to reach either datacenter gateway"
		return "Unknown"
	} elseif (-not $abqPing) {
		Write-Verbose "Albuquerque gateway unreachable, defaulting to Phoenix"
		return "Phoenix"
	} elseif (-not $phxPing) {
		Write-Verbose "Phoenix gateway unreachable, defaulting to Albuquerque"
		return "Albuquerque"
	}
	
	$abqAvg = ($abqPing | Measure-Object -Property ResponseTime -Average).Average
	$phxAvg = ($phxPing | Measure-Object -Property ResponseTime -Average).Average
	
	Write-Verbose "Albuquerque average: $abqAvg ms"
	Write-Verbose "Phoenix average: $phxAvg ms"
	
	if ($abqAvg -lt $phxAvg) {
		return "Albuquerque"
	} else {
		return "Phoenix"
	}
}

Function Get-DecryptedConfig {
	<#
	.Synopsis
	Downloads and decrypts an encrypted configuration file from a URL
	.Description
	Fetches an encrypted .enc file via HTTPS and decrypts it using Unprotect-ConfigFile.
	Returns the plaintext content as a string.
	.Parameter Url
	The URL of the encrypted .enc file
	.Parameter Password
	The password to decrypt the file
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$Url,
		[Parameter(Mandatory = $true)]
		[string]$Password
	)

	$content = (Invoke-WebRequest -Uri $Url -Headers @{"Cache-Control"="no-cache"} -UseBasicParsing).Content.Trim()
	return Unprotect-ConfigFile -EncryptedContent $content -Password $Password
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

	For more information on setting up Dell API credentials, check documentation.
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
		Write-Host "Authentication Needed. Please check documentation for Dell API credential setup." -ForegroundColor White -BackgroundColor Red
		Break
	}
	If ((Test-Path "$env:appdata\Microsoft\Windows\PowerShell\DellSec.txt") -ne $true) {
		Write-Host "Authentication Needed. Please check documentation for Dell API credential setup." -ForegroundColor White -BackgroundColor Red
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
		Downloads a file from a URL to the specified directory using the fastest available method.
		Parses the file name from the URL so you don't have to manually specify the file name.
		Supports multi-segment parallel downloading, checksum validation, and auto-detection of hash algorithm.
	.DESCRIPTION
		Attempts download methods in order of speed:
		0. Parallel segmented download with HttpClient (fastest for large files >= 20 MB on servers supporting Range requests)
		1. System.Net.Http.HttpClient with stream-to-file (fastest single-stream; no memory buffering, no progress bar overhead)
		2. Invoke-WebRequest with progress suppressed (fast, widely compatible)
		3. System.Net.WebClient (legacy, very reliable)
		4. curl.exe (native on Windows 10 1803+, fast and battle-tested)
		5. certutil -urlcache (available on all Windows versions, reliable deep fallback)
		6. BITS Transfer (last resort; handles intermittent connections)
		If a Checksum is provided, the downloaded file is validated and removed on mismatch.
	.PARAMETER URL
		URL of the file to download, e.g. 'https://files.mauletech.com/Software/migwiz.zip?dl'
	.PARAMETER SaveToFolder
		Folder to save the file to, e.g. 'C:\Temp'. Defaults to the current directory.
	.PARAMETER FileName
		Override the file name parsed from the URL.
	.PARAMETER Checksum
		Expected hash of the downloaded file. If supplied, the file is validated after download.
	.PARAMETER ChecksumType
		Hash algorithm to use for validation: MD5, SHA1, SHA256, SHA384, or SHA512.
		If omitted, the algorithm is auto-detected from the checksum string length.
		If auto-detection fails, you will be prompted.
	.PARAMETER ShowProgress
		Show download progress when possible. Note: enabling progress will slow down the download.
		Progress is throttled to update every 10 seconds to minimize performance impact.
	.PARAMETER ParallelSegments
		Number of parallel segments to use when downloading large files. Default is 10.
		Only used when the server supports HTTP Range requests and the file is >= 20 MB.
		Set to 0 to disable parallel downloading entirely.
		Falls back to standard single-stream methods if parallel download fails.
	.EXAMPLE
		Get-FileDownload -URL $Link -SaveToFolder '$ITFolder\'

	.EXAMPLE
		$DownloadFileInfo = Get-FileDownload -URL 'https://files.mauletech.com/Software/migwiz.zip?dl' -SaveToFolder '$ITFolder\'
		$DownloadFileName = $DownloadFileInfo[0]
		$DownloadFilePath = $DownloadFileInfo[-1]

	.EXAMPLE
		# Download with SHA256 checksum validation (auto-detected from 64-char hash)
		Get-FileDownload -URL $Link -SaveToFolder 'C:\Temp' -Checksum 'A1B2C3...'

	.EXAMPLE
		# Download with explicit checksum type
		Get-FileDownload -URL $Link -SaveToFolder 'C:\Temp' -Checksum 'A1B2C3...' -ChecksumType 'SHA256'

	.EXAMPLE
		# Download with progress display (updates every 10 seconds)
		Get-FileDownload -URL $Link -SaveToFolder 'C:\Temp' -ShowProgress
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)]
		[uri]$URL,
		[Parameter(Mandatory = $False)]
		[string]$SaveToFolder,
		[Parameter(Mandatory = $False)]
		[string]$FileName,
		[Parameter(Mandatory = $False)]
		[string]$Checksum,
		[Parameter(Mandatory = $False)]
		[ValidateSet('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')]
		[string]$ChecksumType,
		[switch]$ShowProgress,
		[Parameter(Mandatory = $False)]
		[ValidateRange(0, 32)]
		[int]$ParallelSegments = 10
	)

	# Isolate file name from URL, decoding percent-encoded characters (e.g. %20 -> space)
	If (-not $FileName) {
		[string]$FileName = [System.Uri]::UnescapeDataString($URL.Segments[-1])
	}

	# Default to current directory if SaveToFolder wasn't supplied
	If (-not $SaveToFolder) {
		$SaveToFolder = (Get-Location).Path
	}

	# Normalize trailing separator and create destination folder
	$SaveToFolder = $SaveToFolder.TrimEnd('\', '/') + '\'
	$null = New-Item -Path $SaveToFolder -ItemType Directory -Force

	# Build full file path using Join-Path for robustness
	[string]$FilePath = Join-Path -Path $SaveToFolder -ChildPath $FileName

	# Ensure modern TLS protocols are available
	# Use integers because the TLS 1.2 (3072) and TLS 1.1 (768) enum values
	# don't exist in .NET 4.0, even though they work if .NET 4.5+ is installed.
	Try {
		[System.Net.ServicePointManager]::SecurityProtocol = 3072 -bor 768 -bor 192
	} Catch {
		Write-Warning 'Unable to set TLS 1.2/1.1 due to old .NET Framework. Upgrade to .NET 4.5+ and PowerShell v3+ if you see connection errors.'
	}

	# Load System.Net.Http assembly for HttpClient (not loaded by default on Windows PowerShell 5.1)
	Try {
		Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
	} Catch {
		Write-Verbose 'System.Net.Http assembly not available. HttpClient-based methods will be skipped.'
	}

	# Remove existing file to avoid stale data
	If (Test-Path -Path $FilePath) { Remove-Item -Path $FilePath -Force }

	If ($ShowProgress) {
		Write-Warning 'Progress display is enabled. This may slow down the download slightly. Progress updates are throttled to every 10 seconds to minimize impact.'
	}

	Write-Host "Beginning download to $FilePath"

	$Downloaded = $false
	$DownloadErrors = [System.Collections.Generic.List[string]]::new()

	# Method 0: Parallel segmented download
	# Downloads the file in multiple segments simultaneously using HTTP Range requests,
	# then merges the segments into the final file. Similar to how download managers like
	# Free Download Manager accelerate downloads by splitting them into parallel streams.
	# Prerequisites: server supports Accept-Ranges: bytes, Content-Length >= 20 MB.
	If (-not $Downloaded -and $ParallelSegments -ge 2) {
		$HeadClient    = $null
		$HeadRequest   = $null
		$HeadResponse  = $null
		$RunspacePool  = $null
		$SegmentJobs   = $null
		$SegmentPaths  = @()

		Try {
			Write-Verbose 'Method 0: Checking server prerequisites for parallel download...'

			# HEAD request to check server capabilities without downloading the file
			# Use ResponseHeadersRead to avoid HttpClient's 2 GB MaxResponseContentBufferSize limit
			# which rejects large Content-Length values even on HEAD requests with no body
			$HeadClient  = [System.Net.Http.HttpClient]::new()
			$HeadClient.Timeout = [TimeSpan]::FromSeconds(30)
			$HeadRequest = [System.Net.Http.HttpRequestMessage]::new(
				[System.Net.Http.HttpMethod]::Head,
				$URL.AbsoluteUri
			)
			$HeadResponse = $HeadClient.SendAsync(
				$HeadRequest,
				[System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
			).GetAwaiter().GetResult()
			$null = $HeadResponse.EnsureSuccessStatusCode()

			# Check if server supports byte-range requests
			$ParallelEligible = $true
			$AcceptRangesValues = $null
			If ($HeadResponse.Headers.TryGetValues('Accept-Ranges', [ref]$AcceptRangesValues)) {
				$AcceptRanges = $AcceptRangesValues -join ','
			} Else {
				$AcceptRanges = ''
			}
			If ($AcceptRanges -notmatch 'bytes') {
				Write-Verbose 'Method 0: Server does not support byte-range requests. Skipping parallel download.'
				$ParallelEligible = $false
			}

			# Check Content-Length
			$ContentLength = $HeadResponse.Content.Headers.ContentLength
			If ($ParallelEligible -and (-not $ContentLength -or $ContentLength -le 0)) {
				Write-Verbose 'Method 0: Server did not report Content-Length. Skipping parallel download.'
				$ParallelEligible = $false
			}

			# Check minimum file size (20 MB threshold — below this the overhead isn't worthwhile)
			If ($ParallelEligible -and $ContentLength -lt 20MB) {
				Write-Verbose ('Method 0: File is {0:N2} MB, below 20 MB threshold. Skipping parallel download.' -f ($ContentLength / 1MB))
				$ParallelEligible = $false
			}

			If ($ParallelEligible) {
				Write-Host ('Parallel download: {0} segments, {1:N2} MB total' -f $ParallelSegments, ($ContentLength / 1MB))

				# Calculate byte ranges for each segment
				$SegmentSize = [Math]::Floor($ContentLength / $ParallelSegments)
				$Segments = [System.Collections.Generic.List[object]]::new()
				For ($i = 0; $i -lt $ParallelSegments; $i++) {
					$Start = $i * $SegmentSize
					# Last segment absorbs remainder bytes to avoid gaps
					$End = If ($i -eq ($ParallelSegments - 1)) { $ContentLength - 1 } Else { $Start + $SegmentSize - 1 }
					$TempPath = Join-Path $env:TEMP "dlseg_${i}_$(Get-Random).part"
					$Segments.Add([pscustomobject]@{
						Index    = $i
						Start    = $Start
						End      = $End
						TempPath = $TempPath
					})
				}

				# Keep a flat list of temp paths for guaranteed cleanup in Finally
				$SegmentPaths = $Segments | ForEach-Object { $_.TempPath }

				# Self-contained scriptblock that runs in each runspace
				# No access to outer scope — all values passed via parameters
				[System.Management.Automation.ScriptBlock]$SegmentScriptBlock = {
					Param(
						[string]$SegmentURL,
						[long]$RangeStart,
						[long]$RangeEnd,
						[string]$TempPath,
						[int]$SegmentIndex
					)

					$LocalClient   = $null
					$LocalRequest  = $null
					$LocalResponse = $null
					$LocalStream   = $null
					$LocalFile     = $null
					$Success       = $false
					$ErrorMessage  = ''

					Try {
						$LocalClient = [System.Net.Http.HttpClient]::new()
						$LocalClient.Timeout = [TimeSpan]::FromMinutes(30)

						$LocalRequest = [System.Net.Http.HttpRequestMessage]::new(
							[System.Net.Http.HttpMethod]::Get,
							$SegmentURL
						)
						$LocalRequest.Headers.Range = [System.Net.Http.Headers.RangeHeaderValue]::new($RangeStart, $RangeEnd)

						$LocalResponse = $LocalClient.SendAsync(
							$LocalRequest,
							[System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
						).GetAwaiter().GetResult()
						$null = $LocalResponse.EnsureSuccessStatusCode()

						# Validate server actually returned a partial response (206), not the full file (200)
						If ($LocalResponse.StatusCode -ne [System.Net.HttpStatusCode]::PartialContent) {
							Throw "Server returned $($LocalResponse.StatusCode) instead of 206 PartialContent. Range requests may not be supported."
						}

						$LocalStream = $LocalResponse.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
						$LocalFile = [System.IO.FileStream]::new(
							$TempPath,
							[System.IO.FileMode]::Create,
							[System.IO.FileAccess]::Write,
							[System.IO.FileShare]::None,
							81920
						)
						$LocalStream.CopyTo($LocalFile, 81920)
						$Success = $true
					} Catch {
						$ErrorMessage = $_.ToString()
					} Finally {
						If ($LocalFile)     { $LocalFile.Dispose() }
						If ($LocalStream)   { $LocalStream.Dispose() }
						If ($LocalResponse) { $LocalResponse.Dispose() }
						If ($LocalRequest)  { $LocalRequest.Dispose() }
						If ($LocalClient)   { $LocalClient.Dispose() }
						If (-not $Success -and (Test-Path $TempPath)) {
							Remove-Item $TempPath -Force -ErrorAction SilentlyContinue
						}
					}

					[pscustomobject]@{
						Index        = $SegmentIndex
						TempPath     = $TempPath
						Success      = $Success
						ErrorMessage = $ErrorMessage
					}
				}

				# Create RunspacePool and queue all segment downloads
				$RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(
					1, $ParallelSegments, $Host
				)
				$RunspacePool.Open()

				$SegmentJobs = [System.Collections.ArrayList]::new()
				ForEach ($Seg in $Segments) {
					$ScriptParams = @{
						SegmentURL   = $URL.AbsoluteUri
						RangeStart   = $Seg.Start
						RangeEnd     = $Seg.End
						TempPath     = $Seg.TempPath
						SegmentIndex = $Seg.Index
					}
					$Job = [System.Management.Automation.PowerShell]::Create()
					$null = $Job.AddScript($SegmentScriptBlock).AddParameters($ScriptParams)
					$Job.RunspacePool = $RunspacePool
					$null = $SegmentJobs.Add([pscustomobject]@{
						Pipe   = $Job
						Result = $Job.BeginInvoke()
					})
				}

				# Wait for all segment jobs, reporting progress on 10-second intervals
				$Jobs_Total      = $SegmentJobs.Count
				$SegmentResults  = [System.Collections.Generic.List[object]]::new()
				$ProgressStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
				$LastProgressUpdate = [long]-10000

				Do {
					$Completed = $SegmentJobs | Where-Object { $_.Result.IsCompleted }
					$Remaining = @($SegmentJobs | Where-Object { -not $_.Result.IsCompleted }).Count

					If ($ShowProgress -and ($ProgressStopwatch.ElapsedMilliseconds - $LastProgressUpdate -ge 10000)) {
						$LastProgressUpdate = $ProgressStopwatch.ElapsedMilliseconds
						$DonePct = If ($Jobs_Total -gt 0) { [int](100 * ($Jobs_Total - $Remaining) / $Jobs_Total) } Else { 100 }
						Write-Progress -Activity "Downloading $FileName (Parallel, $Jobs_Total segments)" `
							-Status "$($Jobs_Total - $Remaining) of $Jobs_Total segments complete" `
							-PercentComplete $DonePct
					}

					If ($null -eq $Completed) {
						Start-Sleep -Milliseconds 250
						Continue
					}

					ForEach ($Job in @($Completed)) {
						Try {
							$JobOutput = $Job.Pipe.EndInvoke($Job.Result)
							# EndInvoke returns a PSDataCollection — unwrap to the single result object
							If ($JobOutput -and $JobOutput.Count -gt 0) { $SegmentResults.Add($JobOutput[0]) }
						} Catch {
							Write-Verbose "Method 0: EndInvoke failed for a segment: $_"
						}
						$Job.Pipe.Dispose()
						$SegmentJobs.Remove($Job)
					}
				} While ($SegmentJobs.Count -gt 0)

				If ($ShowProgress) {
					Write-Progress -Activity "Downloading $FileName (Parallel, $Jobs_Total segments)" -Completed
				}

				$RunspacePool.Close()
				$RunspacePool.Dispose()
				$RunspacePool = $null

				# Evaluate segment results — if any failed, fall through to single-stream methods
				$SegmentErrors = [System.Collections.Generic.List[string]]::new()
				ForEach ($R in $SegmentResults) {
					If (-not $R.Success) {
						$SegmentErrors.Add("Segment $($R.Index): $($R.ErrorMessage)")
					}
				}

				If ($SegmentErrors.Count -gt 0) {
					$ErrSummary = $SegmentErrors -join '; '
					Write-Verbose "Method 0: $($SegmentErrors.Count) segment(s) failed: $ErrSummary"
					$DownloadErrors.Add("ParallelDownload: $ErrSummary")
				} ElseIf ($SegmentResults.Count -ne $ParallelSegments) {
					Write-Verbose "Method 0: Expected $ParallelSegments results, got $($SegmentResults.Count). Aborting merge."
					$DownloadErrors.Add("ParallelDownload: incomplete segment results ($($SegmentResults.Count)/$ParallelSegments)")
				} Else {
					# All segments succeeded — merge temp files into the final file in order
					Write-Verbose 'Method 0: All segments downloaded. Merging...'
					$MergeStream = $null
					$MergeSuccess = $false
					Try {
						$MergeStream = [System.IO.FileStream]::new(
							$FilePath,
							[System.IO.FileMode]::Create,
							[System.IO.FileAccess]::Write,
							[System.IO.FileShare]::None,
							81920
						)
						$SortedResults = $SegmentResults | Sort-Object -Property Index
						ForEach ($R in $SortedResults) {
							$PartStream = $null
							Try {
								$PartStream = [System.IO.FileStream]::new(
									$R.TempPath,
									[System.IO.FileMode]::Open,
									[System.IO.FileAccess]::Read,
									[System.IO.FileShare]::Read,
									81920
								)
								$PartStream.CopyTo($MergeStream, 81920)
							} Finally {
								If ($PartStream) { $PartStream.Dispose() }
							}
						}
						$MergeSuccess = $true
					} Catch {
						Write-Verbose "Method 0: Merge failed: $_"
						$DownloadErrors.Add("ParallelDownload merge: $_")
					} Finally {
						If ($MergeStream) { $MergeStream.Dispose() }
						If (-not $MergeSuccess -and (Test-Path $FilePath)) {
							Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
						}
					}

					If ($MergeSuccess) {
						# Verify merged file size matches expected Content-Length
						$ActualSize = (Get-Item $FilePath).Length
						If ($ActualSize -ne $ContentLength) {
							Write-Verbose "Method 0: Final file size ($ActualSize) does not match Content-Length ($ContentLength). Discarding corrupt file."
							$DownloadErrors.Add("ParallelDownload: size mismatch (expected $ContentLength, got $ActualSize)")
							Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
						} Else {
							$Downloaded = $true
							Write-Verbose 'Method 0: Parallel download and merge completed successfully.'
							Write-Host ('Parallel download complete ({0} segments merged, {1:N2} MB).' -f $ParallelSegments, ($ContentLength / 1MB))
						}
					}
				}
			}
		} Catch {
			Write-Verbose "Method 0: Unexpected error: $_"
			$DownloadErrors.Add("ParallelDownload setup: $_")
		} Finally {
			# Guaranteed cleanup: stop/drain remaining jobs, then dispose RunspacePool, then delete temp files
			If ($SegmentJobs) {
				ForEach ($Job in @($SegmentJobs)) {
					Try {
						If (-not $Job.Result.IsCompleted) {
							$Job.Pipe.Stop()
						}
						$null = $Job.Pipe.EndInvoke($Job.Result)
						$Job.Pipe.Dispose()
					} Catch {}
				}
			}
			If ($RunspacePool) {
				Try { $RunspacePool.Close() }   Catch {}
				Try { $RunspacePool.Dispose() } Catch {}
			}
			If ($SegmentPaths) {
				ForEach ($TempPath in $SegmentPaths) {
					If (Test-Path $TempPath) {
						Remove-Item $TempPath -Force -ErrorAction SilentlyContinue
					}
				}
			}
			If ($HeadResponse) { $HeadResponse.Dispose() }
			If ($HeadRequest)  { $HeadRequest.Dispose() }
			If ($HeadClient)   { $HeadClient.Dispose() }
		}
	}

	# Method 1: HttpClient with stream-to-file
	# Fastest option: streams directly to disk with an 80 KB buffer, no memory buffering
	# of the full response, and no progress-bar rendering overhead.
	# When -ShowProgress is used, progress updates are throttled to every 10 seconds.
	If (-not $Downloaded) {
		$HttpClient = $null
		$Response = $null
		$ResponseStream = $null
		$FileStream = $null
		Try {
			$HttpClient = [System.Net.Http.HttpClient]::new()
			$HttpClient.Timeout = [TimeSpan]::FromMinutes(30)
			$Response = $HttpClient.GetAsync(
				$URL.AbsoluteUri,
				[System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
			).GetAwaiter().GetResult()
			$null = $Response.EnsureSuccessStatusCode()
			$ResponseStream = $Response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
			$FileStream = [System.IO.FileStream]::new(
				$FilePath,
				[System.IO.FileMode]::Create,
				[System.IO.FileAccess]::Write,
				[System.IO.FileShare]::None,
				81920
			)
			If ($ShowProgress) {
				$TotalBytes = $Response.Content.Headers.ContentLength
				$Buffer = [byte[]]::new(81920)
				$TotalRead = [long]0
				$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
				$LastUpdate = [long]-10000  # Force immediate first update
				While (($BytesRead = $ResponseStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
					$FileStream.Write($Buffer, 0, $BytesRead)
					$TotalRead += $BytesRead
					If ($Stopwatch.ElapsedMilliseconds - $LastUpdate -ge 10000) {
						$LastUpdate = $Stopwatch.ElapsedMilliseconds
						$ProgressParams = @{
							Activity = "Downloading $FileName (HttpClient)"
							Status   = '{0:N2} MB downloaded' -f ($TotalRead / 1MB)
						}
						If ($TotalBytes -and $TotalBytes -gt 0) {
							$Pct = [Math]::Min(100, [int](($TotalRead / $TotalBytes) * 100))
							$ProgressParams['PercentComplete'] = $Pct
							$ProgressParams['Status'] = '{0:N2} / {1:N2} MB ({2}%)' -f ($TotalRead / 1MB), ($TotalBytes / 1MB), $Pct
						}
						Write-Progress @ProgressParams
					}
				}
				Write-Progress -Activity "Downloading $FileName (HttpClient)" -Completed
			} Else {
				$ResponseStream.CopyTo($FileStream, 81920)
			}
			$Downloaded = $true
			Write-Verbose 'Downloaded using HttpClient stream method.'
		} Catch {
			$DownloadErrors.Add("HttpClient: $_")
			Write-Verbose "HttpClient method failed: $_"
		} Finally {
			If ($FileStream)     { $FileStream.Dispose() }
			If ($ResponseStream) { $ResponseStream.Dispose() }
			If ($Response)       { $Response.Dispose() }
			If ($HttpClient)     { $HttpClient.Dispose() }
			# Clean up partial file after streams are closed to avoid file-lock failures
			If (-not $Downloaded -and (Test-Path $FilePath)) {
				Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
			}
		}
	}

	# Method 2: Invoke-WebRequest
	# Disabling the progress bar avoids the massive rendering overhead that can
	# slow Invoke-WebRequest by 10-50x on large files.
	# When -ShowProgress is used, the native progress bar is left enabled.
	If (-not $Downloaded) {
		$PreviousProgressPref = $ProgressPreference
		Try {
			If (-not $ShowProgress) {
				$ProgressPreference = 'SilentlyContinue'
			}
			Invoke-WebRequest -Uri $URL -OutFile $FilePath -UseBasicParsing
			$Downloaded = $true
			Write-Verbose 'Downloaded using Invoke-WebRequest.'
		} Catch {
			$DownloadErrors.Add("Invoke-WebRequest: $_")
			Write-Verbose "Invoke-WebRequest failed: $_"
			If (Test-Path $FilePath) {
				Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
			}
		} Finally {
			$ProgressPreference = $PreviousProgressPref
		}
	}

	# Method 3: System.Net.WebClient (legacy, very reliable on older .NET)
	If (-not $Downloaded) {
		$WebClient = $null
		Try {
			$WebClient = [System.Net.WebClient]::new()
			$WebClient.DownloadFile($URL.AbsoluteUri, $FilePath)
			$Downloaded = $true
			Write-Verbose 'Downloaded using WebClient.'
		} Catch {
			$DownloadErrors.Add("WebClient: $_")
			Write-Verbose "WebClient failed: $_"
		} Finally {
			If ($WebClient) { $WebClient.Dispose() }
			If (-not $Downloaded -and (Test-Path $FilePath)) {
				Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
			}
		}
	}

	# Method 4: curl.exe (native on Windows 10 1803+ and Server 2019+)
	# Fast, battle-tested, and supports resume on intermittent connections.
	If (-not $Downloaded) {
		Try {
			$CurlExe = Get-Command 'curl.exe' -ErrorAction Stop
			$CurlArgs = @('-L', '-o', $FilePath, '--fail', '--connect-timeout', '30', '--max-time', '1800')
			If ($ShowProgress) {
				$CurlArgs += '--progress-bar'
			} Else {
				# --show-error keeps error messages visible even in silent mode
				$CurlArgs += '--silent'
				$CurlArgs += '--show-error'
			}
			$CurlArgs += $URL.AbsoluteUri
			& $CurlExe.Source @CurlArgs
			If ($LASTEXITCODE -eq 0 -and (Test-Path $FilePath)) {
				$Downloaded = $true
				Write-Verbose 'Downloaded using curl.exe.'
			} Else {
				Throw "curl.exe exited with code $LASTEXITCODE"
			}
		} Catch {
			$DownloadErrors.Add("curl.exe: $_")
			Write-Verbose "curl.exe method failed: $_"
			If (-not $Downloaded -and (Test-Path $FilePath)) {
				Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
			}
		}
	}

	# Method 5: certutil -urlcache (available on all Windows versions)
	# A well-known sysadmin trick, extremely reliable as a deep fallback on legacy systems.
	If (-not $Downloaded) {
		Try {
			$CertutilExe = Get-Command 'certutil.exe' -ErrorAction Stop
			If ($ShowProgress) {
				& $CertutilExe.Source -urlcache -split -f $URL.AbsoluteUri $FilePath
			} Else {
				$null = & $CertutilExe.Source -urlcache -split -f $URL.AbsoluteUri $FilePath 2>&1
			}
			If ($LASTEXITCODE -eq 0 -and (Test-Path $FilePath)) {
				$Downloaded = $true
				Write-Verbose 'Downloaded using certutil.'
			} Else {
				Throw "certutil exited with code $LASTEXITCODE"
			}
		} Catch {
			$DownloadErrors.Add("certutil: $_")
			Write-Verbose "certutil method failed: $_"
			If (-not $Downloaded -and (Test-Path $FilePath)) {
				Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
			}
		}
	}

	# Method 6: BITS Transfer (last resort; handles resume on intermittent connections)
	If (-not $Downloaded) {
		Try {
			Start-BitsTransfer -Source $URL.AbsoluteUri -Destination $FilePath -ErrorAction Stop
			$Downloaded = $true
			Write-Verbose 'Downloaded using BITS Transfer.'
		} Catch {
			$DownloadErrors.Add("BITS: $_")
			Write-Verbose "BITS Transfer failed: $_"
			If (Test-Path $FilePath) {
				Remove-Item $FilePath -Force -ErrorAction SilentlyContinue
			}
		}
	}

	If (-not $Downloaded) {
		$ErrorDetail = $DownloadErrors -join "`n  "
		Throw "All download methods failed for URL: $URL`n  $ErrorDetail"
	}

	# Checksum validation
	If ($Checksum) {
		# Auto-detect algorithm from hash string length if not specified
		If (-not $ChecksumType) {
			$ChecksumType = Switch ($Checksum.Length) {
				32  { 'MD5'    }
				40  { 'SHA1'   }
				64  { 'SHA256' }
				96  { 'SHA384' }
				128 { 'SHA512' }
				Default { $null }
			}
			If ($ChecksumType) {
				Write-Verbose "Auto-detected checksum type: $ChecksumType (from $($Checksum.Length)-character hash)"
			} Else {
				$ChecksumType = Read-Host "Cannot determine checksum type from length ($($Checksum.Length)). Enter type (MD5, SHA1, SHA256, SHA384, SHA512)"
				If ($ChecksumType -notin @('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')) {
					Write-Warning "Invalid checksum type '$ChecksumType'. Skipping validation."
					Return $FileName, $FilePath
				}
			}
		}

		$FileHash = (Get-FileHash -Path $FilePath -Algorithm $ChecksumType).Hash
		If ($FileHash -ne $Checksum.ToUpper()) {
			Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
			Throw "Checksum mismatch for $FileName! Expected ($ChecksumType): $($Checksum.ToUpper()), Got: $FileHash. Downloaded file has been removed."
		}
		Write-Verbose "Checksum validated successfully: $ChecksumType = $FileHash"
	}

	Return $FileName, $FilePath
}

Function Get-InstalledApplication {
	<#
	.SYNOPSIS
		Gets installed applications from multiple sources including WMI, PowerShell Package Provider, and Registry.

	.DESCRIPTION
		Scans multiple application repositories to find installed applications.
		Returns PSCustomObjects with Name and Version properties. When -Name is specified,
		writes matching applications to host and returns $True if found, $False otherwise.

		Note: This is a breaking change from earlier versions which returned plain strings.

	.PARAMETER Name
		Optional. The name (or partial name) of the application to check.
		Supports PowerShell regex matching (e.g., "Office.*365", "Chrome|Firefox").

	.EXAMPLE
		Get-InstalledApplication
		Returns all installed applications with their versions as PSCustomObjects.

	.EXAMPLE
		Get-InstalledApplication -Name "Chrome"
		Writes matching applications to host and returns $True if found.

	.EXAMPLE
		Get-InstalledApplication -Name "Office.*365"
		Uses regex to find Office 365 applications.

	.EXAMPLE
		Get-InstalledApplication -Name "Office" -Verbose
		Shows verbose output while searching for Office applications.
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $False, HelpMessage = 'Enter the name of the application to check (supports regex).')]
		[Alias('Application')]
		[string] $Name
	)

	# Use List<T> for efficient collection building
	$AllApps = [System.Collections.Generic.List[PSCustomObject]]::new()

	Write-Verbose '[Scanning All App sources]'

	# Scan CIM/WMI Repository (using Get-CimInstance instead of deprecated Get-WmiObject)
	# Note: Win32_Product can be slow and may trigger MSI repairs on scanned applications
	Write-Verbose '--[Scanning CIM Repository (this may take a moment)]'
	Try {
		Get-CimInstance -Class Win32_Product -ErrorAction SilentlyContinue |
			Where-Object { $_.Name } |
			ForEach-Object {
				$AllApps.Add([PSCustomObject]@{
					Name    = $_.Name
					Version = $_.Version
				})
			}
	} Catch {
		Write-Verbose "Failed to query CIM repository: $_"
	}

	# Scan Native PowerShell Package Repository
	Write-Verbose '--[Scanning Native PowerShell Repository]'
	Try {
		Get-Package -Provider Programs -IncludeWindowsInstaller -ErrorAction SilentlyContinue |
			Where-Object { $_.Name } |
			ForEach-Object {
				$AllApps.Add([PSCustomObject]@{
					Name    = $_.Name
					Version = $_.Version
				})
			}
	} Catch {
		Write-Verbose "Failed to query PowerShell Package repository: $_"
	}

	# Scan Registry Uninstall Keys (both machine-wide and current user)
	Write-Verbose '--[Scanning Registry Uninstall Keys]'
	$RegistryPaths = @(
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
		"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
		"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
	)

	ForEach ($RegPath in $RegistryPaths) {
		If (Test-Path $RegPath) {
			Try {
				Get-ChildItem $RegPath -ErrorAction SilentlyContinue | ForEach-Object {
					$Props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
					If ($Props.DisplayName) {
						$AllApps.Add([PSCustomObject]@{
							Name    = $Props.DisplayName
							Version = $Props.DisplayVersion
						})
					}
				}
			} Catch {
				Write-Verbose "Failed to query registry path ${RegPath}: $_"
			}
		}
	}

	# Remove duplicates by Name|Version key and sort by name
	# Note: Sort-Object -Unique doesn't work correctly for PSCustomObjects,
	# so we use Group-Object to deduplicate by a composite key
	$AllApps = $AllApps |
		Where-Object { $_.Name } |
		Group-Object { "$($_.Name)|$($_.Version)" } |
		ForEach-Object { $_.Group[0] } |
		Sort-Object Name

	If ($Name) {
		Try {
			$MatchedApps = $AllApps | Where-Object { $_.Name -match $Name }
		} Catch {
			Write-Host "Invalid search pattern '$Name'. Error: $_" -ForegroundColor Red
			Return $False
		}

		If ($MatchedApps) {
			Write-Host "Found installed application(s) matching '$Name':" -ForegroundColor Green
			ForEach ($App in $MatchedApps) {
				$VersionDisplay = If ($App.Version) { $App.Version } Else { "(version unknown)" }
				Write-Host "  - $($App.Name) [$VersionDisplay]" -ForegroundColor Cyan
			}
			Return $True
		} Else {
			Write-Host "No installed application found matching '$Name'." -ForegroundColor Yellow
			Return $False
		}
	} Else {
		Write-Verbose "Returning all installed applications ($($AllApps.Count) found)"
		Return $AllApps
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
	$DownloadURL = "https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-win64.zip"
	$DownloadLocation = "$($Env:ProgramData)\SpeedtestCLI"
	$SpeedTestExe = Join-Path -Path $DownloadLocation -ChildPath "\speedtest.exe"
	Try {
		If (!$(Test-Path $SpeedTestExe)) {
			Write-Host "Preparing Internet Health Test."
			New-Item $DownloadLocation -ItemType Directory -force
			Invoke-ValidatedDownload -Uri $DownloadURL -OutFile "$($DownloadLocation)\speedtest.zip"
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

Function Get-SophosConnectStatus {
	# Define possible paths for sccli.exe
	$possiblePaths = @(
		"${env:ProgramFiles(x86)}\Sophos\Connect\sccli.exe"
		"${env:ProgramFiles}\Sophos\Connect\sccli.exe"
		"${env:ProgramFiles(x86)}\Sophos\Sophos SSL VPN Client\sccli.exe"
		"${env:ProgramFiles}\Sophos\Sophos SSL VPN Client\sccli.exe"
	)

	# Find the first valid path
	$SCPath = $possiblePaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

	If (!$SCPath) {
		Write-Host "This command only works if you have Sophos Connect installed." -ForegroundColor Red
		return
	}

	Write-Host "Sophos Connect VPN Status:" -ForegroundColor Cyan
	Write-Host ""

	# Show detailed list of connections with their status
	& "$SCPath" list -d

	Write-Host ""
	Write-Host 'Try "Connect-SophosConnect" or "Disconnect-SophosConnect"' -ForegroundColor Yellow

	<#
	.SYNOPSIS
		Displays the connection status of Sophos Connect VPN
	.DESCRIPTION
		Shows detailed information about all configured Sophos Connect VPN connections
		including their current status (connected/disconnected).
	.EXAMPLE
		Get-SophosConnectStatus
		Displays the status of all Sophos Connect VPN connections.
	.NOTES
		Uses sccli.exe list command to display connection information.
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

function Get-VMByFQDN {
	param(
		[Parameter(Mandatory=$true)]
		[string]$FQDN,
		[switch]$Detailed
	)

	Write-Verbose "Searching for VM with FQDN: $FQDN"

	# Method 1: Try Integration Services/KVP data first (most reliable for Windows VMs)
	Write-Verbose "Attempting Integration Services lookup..."
	$VMs = Get-VM | Where-Object {$_.State -eq 'Running'}

	foreach ($VM in $VMs) {
		try {
			# Get KVP Exchange Component data
			$VMID = $VM.Id
			$KvpData = Get-CimInstance -Namespace root\virtualization\v2 -ClassName Msvm_KvpExchangeComponent -Filter "SystemName='$VMID'"

			if ($KvpData.GuestIntrinsicExchangeItems) {
				# Parse XML KVP data
				foreach ($Item in $KvpData.GuestIntrinsicExchangeItems) {
					$XmlItem = [xml]$Item
					if ($XmlItem.Instance.Property | Where-Object {$_.Name -eq 'Name' -and $_.Value -eq 'FullyQualifiedDomainName'}) {
						$GuestFQDN = ($XmlItem.Instance.Property | Where-Object {$_.Name -eq 'Data'}).Value
						if ($GuestFQDN -eq $FQDN) {
							Write-Verbose "Found VM via Integration Services: $($VM.Name)"
							$NetworkInfo = Get-VMNetworkAdapter -VM $VM | Select-Object -First 1
							return [PSCustomObject]@{
								VMName = $VM.Name
								VMID = $VM.Id
								State = $VM.State
								FQDN = $GuestFQDN
								IPAddresses = $NetworkInfo.IPAddresses -join ', '
								MACAddress = $NetworkInfo.MacAddress
								Method = 'IntegrationServices'
								Host = $env:COMPUTERNAME
							}
						}
					}
				}
			}
		} catch {
			Write-Verbose "Integration Services lookup failed for $($VM.Name): $_"
		}
	}

	# Method 2: Fallback to IP resolution and matching
	Write-Verbose "Falling back to IP resolution method..."
	try {
		$ResolvedIPs = [System.Net.Dns]::GetHostAddresses($FQDN) | Where-Object {$_.AddressFamily -eq 'InterNetwork'} | Select-Object -ExpandProperty IPAddressToString
		Write-Verbose "Resolved $FQDN to: $($ResolvedIPs -join ', ')"
	} catch {
		Write-Warning "Unable to resolve FQDN: $FQDN"
		$ResolvedIPs = @()
	}

	if ($ResolvedIPs.Count -gt 0) {
		# Check all VMs (including stopped ones for IP matching)
		$AllVMs = Get-VM
		foreach ($VM in $AllVMs) {
			$VMNetAdapters = Get-VMNetworkAdapter -VM $VM
			foreach ($Adapter in $VMNetAdapters) {
				$AdapterIPs = $Adapter.IPAddresses | Where-Object {$_ -notlike '*:*'}  # IPv4 only
				foreach ($IP in $ResolvedIPs) {
					if ($IP -in $AdapterIPs) {
						Write-Verbose "Found VM via IP match: $($VM.Name)"
						return [PSCustomObject]@{
							VMName = $VM.Name
							VMID = $VM.Id
							State = $VM.State
							FQDN = $FQDN
							IPAddresses = $AdapterIPs -join ', '
							MACAddress = $Adapter.MacAddress
							Method = 'IPResolution'
							Host = $env:COMPUTERNAME
						}
					}
				}
			}
		}
	}

	# Method 3: Last resort - check if hostname matches VM name
	Write-Verbose "Checking for hostname match..."
	$Hostname = $FQDN.Split('.')[0]
	$PossibleVM = Get-VM | Where-Object {$_.Name -eq $Hostname -or $_.Name -eq $Hostname.ToUpper()}
	if ($PossibleVM) {
		Write-Warning "Found VM with matching hostname but couldn't verify FQDN: $($PossibleVM.Name)"
		if ($Detailed) {
			$NetworkInfo = Get-VMNetworkAdapter -VM $PossibleVM | Select-Object -First 1
			return [PSCustomObject]@{
				VMName = $PossibleVM.Name
				VMID = $PossibleVM.Id
				State = $PossibleVM.State
				FQDN = "$Hostname (unverified)"
				IPAddresses = $NetworkInfo.IPAddresses -join ', '
				MACAddress = $NetworkInfo.MacAddress
				Method = 'HostnameOnly'
				Host = $env:COMPUTERNAME
			}
		}
	}

	return $null
}

Function Get-VMHostName {
	<#
	.SYNOPSIS
		Retrieves the Hyper-V host name from a VM's registry.
	.DESCRIPTION
		Checks the registry key that contains the physical host name for a Hyper-V virtual machine.
	.EXAMPLE
		Get-VMHostName
	#>
	[CmdletBinding()]
	param()
	
	try {
		$regPath = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"
		
		if (Test-Path $regPath) {
			$hostName = Get-ItemProperty -Path $regPath -Name "PhysicalHostName" -ErrorAction SilentlyContinue
			
			if ($hostName) {
				return $hostName.PhysicalHostName
			} else {
				Write-Warning "PhysicalHostName value not found in registry."
				return $null
			}
		} else {
			Write-Warning "This does not appear to be a Hyper-V virtual machine."
			return $null
		}
	} catch {
		Write-Error "Failed to retrieve host information: $_"
		return $null
	}
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
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD/qAIukZt9cMPH
# IainzfgPJdqci/9UlARDcTeKRjJGRKCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IIBIkZuOWcEJSszDb2twFHvfaPQZjE/pK4QSjps/xOMuMA0GCSqGSIb3DQEBAQUA
# BIICAK0UK4ofM8HCBoJSZgdFZbpj5eMXzbBKqoeROgXjn3hwEoBjvDtm17iHonnr
# kGmVk1fQ3YrlWX3PcYybJOtxweZPjj+33fiT5AxFEeYWD57kt10cJWwC08yvr+uy
# s6WxHdnncaj3SqOk/wPcIRAIrOHfZKhDXoZ60LZKR4UWAsTQi324ITqVGT4wBRgp
# XxMT9/Gr0PkqQIwGRmFKTfpGAPgpCZ84wZYaY+BBKTODbHk12RMvjbGd5hB4/Hp4
# werMrBr8gxVQ3SWMmDgYMfESagykhwDcKlyTVNTHu0CkM4KcWl1Mt2nwGcS30s4g
# CQd2a/tdjXY/01i2hnecHhRaTNPzk0Def2gb6UOp2CE/5d+WBxMk3caWivrKQfvL
# 33Pny3DOXFa1ZTj0Z1ynVGBlLCOLs12qBOlD1iZCa6YvWl6boOlIWYyeQPNxesoE
# T+294zEqLJEuEp/c1OfrEMXHrVxHCQ2kktfHA3y5Lzxerf9zZZGR1UCjoUiQ9Ei7
# +4rDy7hynxX2qpSOALHb1lGauCU0uTfWB2Ujji7RQtGjEax/tSfveHC4qLMaAJqa
# pKznHPBSQIyfo5yRRR/mntmo8FMUzoUlCyOxlRyqetd0CrXB/+xRf3GiXmqWuj25
# YzcwCmRZVJJ+MZwt+lGV2ydxCO78J1xLG1hG66mrtpRXaXDmoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDMxMzE1MjUzM1owLwYJKoZIhvcNAQkEMSIEIMfTAn3l
# Rh81mp4XV+cZaq/whBC9Wh9oEcm+ECYchVi0MA0GCSqGSIb3DQEBAQUABIICAJEv
# eiyPJZfgG4Viu6ipUViWXktKtW1Cx0XEoHzmeM60V9VilZXwgogXVfJ9+BnxZfVg
# PqN/n6tfg1T/MehfMM6xg16pWJaOKsoe50vqmBiUjtnI5zwSlkKE4SxnNdeuyOkS
# igvkI1viW/+WvRw8D7vgrH6622/Q2VcQbbXoVFNIVdXbeak3Vs6rIH5+KH2tmXRC
# BDG2gu5DNglsBGtSs1FLF60MaFFdreL9Lp3HG1dj6o3MHD8aYc9OmiW3xMjFVDHL
# O7vFLPEN3pxCkrwkK6tg0BYN03IMsUnVlolvakzXV2H6gg8fbFNlf0/t6CJ1Gb9F
# HOnPNIYT0QciyqXuxK6ffBs31zMQmJ/y8vMN5IwLamZNHpRWz5IKcDyQq5SN9dkz
# 3UxmzO7KYr1iMqljUn1D3JOus+xVMsCnaPHY03tcWXPVmQJD2nyki5bnUq2jK7tc
# prR67m36hv2d8RaO/mhvNkttlEDSEGY1NQInTlkz6VtP1aLrQ3UODINHQmcr7Ime
# gH6ddINIdlZXCJaKtiTl2TqPCswRtSQO+Ag/XOt2AVcOX0nXKeWWpFhulHeJ+Xja
# FDpjLolkpFhMTPA4/miRq1sdYXOxbEzjfmJjOL9IQ8rwjxTabLOnnXa78hs46Zvh
# 2YNPAOyrS5+CZeVNJFwBF3tis2jww/sAPQL/xass
# SIG # End signature block
