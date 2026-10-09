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

function Get-ADLockedAccount {
	<#
	.SYNOPSIS
		Finds locked-out Active Directory accounts and displays details about lock state, bad password attempts, and timing.
	.DESCRIPTION
		Queries Active Directory for locked-out user accounts and returns details including when the account
		was locked, how many bad password attempts occurred, the last bad password time, and user metadata
		(department, title, email). Optionally unlocks matched accounts and verifies the unlock succeeded.

		By default queries the PDC Emulator for the most accurate and up-to-date lockout information.
		Supports filtering by SamAccountName, email address, or display name with wildcard support.
	.PARAMETER Identity
		Filter by SamAccountName. Supports wildcards (e.g. "john*", "*smith*"). Defaults to "*" (all locked accounts).
	.PARAMETER EmailAddress
		Filter by email address. Supports wildcards (e.g. "*@contoso.com").
	.PARAMETER DisplayName
		Filter by display name. Supports wildcards (e.g. "John*").
	.PARAMETER Unlock
		Unlock each matched account, then re-query to verify the account is no longer locked.
		Supports -WhatIf and -Confirm for safe bulk operations.
	.PARAMETER IncludeDisabled
		Include disabled accounts in results. By default only enabled accounts are returned.
	.PARAMETER Server
		Target a specific domain controller. Defaults to the PDC Emulator for accurate lockout data.
	.EXAMPLE
		Get-ADLockedAccount
		Returns all currently locked-out enabled accounts.
	.EXAMPLE
		Get-ADLockedAccount -Identity "jdoe"
		Returns lockout details for the account with SamAccountName "jdoe".
	.EXAMPLE
		Get-ADLockedAccount -Identity "john*"
		Returns all locked accounts whose username starts with "john".
	.EXAMPLE
		Get-ADLockedAccount -EmailAddress "*@contoso.com"
		Returns all locked accounts with a contoso.com email address.
	.EXAMPLE
		Get-ADLockedAccount -DisplayName "John*" -Unlock
		Finds all locked accounts with a display name starting with "John" and unlocks them, then verifies.
	.EXAMPLE
		Get-ADLockedAccount -Identity "jdoe" -Unlock -WhatIf
		Shows what would happen without actually unlocking the account.
	.EXAMPLE
		Get-ADLockedAccount -IncludeDisabled
		Returns all locked accounts including disabled ones.
	.OUTPUTS
		PSCustomObject with properties:
		- SamAccountName: Login name
		- DisplayName: Full display name
		- EmailAddress: Email address
		- Department: Department
		- Title: Job title
		- Enabled: Whether the account is enabled
		- LockedOut: Current lock state
		- LockoutTime: When the account was locked (null if not locked or no data)
		- BadLogonCount: Number of consecutive bad password attempts
		- LastBadPasswordAttempt: Timestamp of the most recent bad password attempt
		- PasswordLastSet: When the password was last changed
	.NOTES
		Requires the ActiveDirectory PowerShell module (RSAT or on a domain controller).
		The -Unlock operation requires sufficient AD permissions (Account Operators or higher).
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
	param(
		[Parameter(HelpMessage = "SamAccountName to search for. Supports wildcards.")]
		[string]$Identity = '*',

		[Parameter(HelpMessage = "Email address to filter by. Supports wildcards.")]
		[string]$EmailAddress,

		[Parameter(HelpMessage = "Display name to filter by. Supports wildcards.")]
		[string]$DisplayName,

		[Parameter(HelpMessage = "Unlock matched accounts and verify the unlock succeeded.")]
		[switch]$Unlock,

		[Parameter(HelpMessage = "Include disabled accounts (default: enabled accounts only).")]
		[switch]$IncludeDisabled,

		[Parameter(HelpMessage = "Target domain controller. Defaults to PDC Emulator.")]
		[string]$Server
	)

	# Verify Active Directory module is available
	if (-not (Get-Command ActiveDirectory\Get-ADUser -ErrorAction SilentlyContinue)) {
		Write-Error "This function requires the ActiveDirectory PowerShell module. Please run on a domain controller or install RSAT."
		return
	}

	# Default to PDC Emulator for most accurate lockout information
	$dc = if ($Server) {
		$Server
	} else {
		try {
			(Get-ADDomain -ErrorAction Stop).PDCEmulator
		} catch {
			Write-Warning "Could not determine PDC Emulator: $_. Querying default DC."
			$null
		}
	}

	$searchParams = @{ LockedOut = $true; UsersOnly = $true }
	if ($dc) { $searchParams['Server'] = $dc }

	$propList = @(
		'DisplayName', 'GivenName', 'Surname', 'EmailAddress',
		'Department', 'Title', 'Enabled', 'LockedOut',
		'lockoutTime', 'BadLogonCount', 'LastBadPasswordAttempt',
		'PasswordLastSet'
	)

	Write-Verbose "Querying $(if ($dc) { $dc } else { 'default DC' }) for locked accounts..."

	try {
		$lockedUsers = Search-ADAccount @searchParams | ForEach-Object {
			$getParams = @{ Identity = $_.DistinguishedName; Properties = $propList }
			if ($dc) { $getParams['Server'] = $dc }
			Get-ADUser @getParams
		}
	} catch {
		Write-Error "Failed to query Active Directory: $_"
		return
	}

	# Apply client-side filters for wildcard support across all three search fields
	$filtered = $lockedUsers | Where-Object {
		$matchIdentity    = $_.SamAccountName -like $Identity
		$matchEmail       = -not $EmailAddress  -or ($_.EmailAddress -like $EmailAddress)
		$matchDisplayName = -not $DisplayName   -or ($_.DisplayName  -like $DisplayName)
		$matchEnabled     = $IncludeDisabled    -or $_.Enabled

		$matchIdentity -and $matchEmail -and $matchDisplayName -and $matchEnabled
	}

	if (-not $filtered) {
		Write-Warning "No locked accounts found matching the specified criteria."
		return
	}

	# Build output objects
	$results = $filtered | ForEach-Object {
		$lockoutTime = if ($_.lockoutTime -and $_.lockoutTime -ne 0) {
			[datetime]::FromFileTime($_.lockoutTime)
		} else {
			$null
		}

		[PSCustomObject]@{
			SamAccountName         = $_.SamAccountName
			DisplayName            = $_.DisplayName
			EmailAddress           = $_.EmailAddress
			Department             = $_.Department
			Title                  = $_.Title
			Enabled                = $_.Enabled
			LockedOut              = $_.LockedOut
			LockoutTime            = $lockoutTime
			BadLogonCount          = $_.BadLogonCount
			LastBadPasswordAttempt = $_.LastBadPasswordAttempt
			PasswordLastSet        = $_.PasswordLastSet
		}
	}

	if (-not $Unlock) {
		$results
		return
	}

	# Unlock flow - emit post-unlock state so pipeline reflects actual lock state after operation
	foreach ($user in $results) {
		$sam = $user.SamAccountName

		if ($PSCmdlet.ShouldProcess($sam, "Unlock AD account")) {
			try {
				$unlockParams = @{ Identity = $sam }
				if ($dc) { $unlockParams['Server'] = $dc }
				Write-Host "Attempting to unlock: $sam..." -ForegroundColor Cyan
				Unlock-ADAccount @unlockParams -ErrorAction Stop

				# Re-query to get post-unlock state and emit updated object
				$verifyParams = @{ Identity = $sam; Properties = @('LockedOut', 'lockoutTime') }
				if ($dc) { $verifyParams['Server'] = $dc }
				$verify = Get-ADUser @verifyParams -ErrorAction Stop

				$user.LockedOut = $verify.LockedOut
				$user.LockoutTime = if ($verify.lockoutTime -and $verify.lockoutTime -ne 0) {
					[datetime]::FromFileTime($verify.lockoutTime)
				} else { $null }

				if (-not $verify.LockedOut) {
					Write-Host "Unlocked: $sam" -ForegroundColor Green
				} else {
					Write-Host "Failed to unlock: $sam (still locked after attempt)" -ForegroundColor Red
				}
			} catch {
				Write-Error "Failed to unlock ${sam}: $_"
			}
		}
		# Emit object (pre-unlock on WhatIf/error, post-unlock on success)
		$user
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

function Get-ClientDiscovery {
	<#
	.SYNOPSIS
		Read-only discovery of a small business Windows server and its LAN for client onboarding documentation.

	.DESCRIPTION
		Run from an elevated PowerShell window on the client's main server (file server, DC, or Hyper-V host).
		The function only READS configuration. It does not change settings, install anything, or modify client files.
		The only things it writes are its own output folder and zip, which it restricts to Administrators and SYSTEM.

		It collects system, disk, network, share, user, Active Directory, DHCP, DNS server, Hyper-V, IIS, software,
		security, update, backup, SQL, printer, event log, public DNS, and LAN device information. It then writes
		one CSV per section, discovery.json, findings.csv (prioritized onboarding issues), and summary.txt to
		<OutputRoot>\<COMPUTERNAME>_<timestamp>\ and zips the folder.

		What it does NOT collect: passwords, product keys, BitLocker recovery keys, LAPS passwords, Wi-Fi keys,
		or file contents. It DOES collect account names, group memberships, share and folder names, computer names,
		IP/MAC addresses, and installed software. Treat the zip as confidential client data and delete both the
		folder and the zip from the server once delivered.

		Network activity:
		* The public IP lookup sends one HTTPS request to ipinfo.io (falls back to api.ipify.org).
		* -PublicDomain lookups query 1.1.1.1 directly (so split-brain internal zones do not mask public
		  records), falling back to the server's own resolver if outbound DNS is blocked.
		* The optional LAN scan pings the server's own subnet (/24 maximum), runs a short TCP connect test against
		  about 25 common ports on live hosts, and requests the web page title from any web interface it finds.
		  Use -SkipSubnetScan to skip it.

	.PARAMETER OutputRoot
		Folder where the results folder and zip are created. Default: $ITFolder\Discovery (normally C:\IT\Discovery).

	.PARAMETER PublicDomain
		One or more public email/web domains to look up (MX, SPF, DKIM, DMARC, NS, A, autodiscover, Intune).

	.PARAMETER EventDays
		How many days of event log history to summarize (1-365). Default 30.

	.PARAMETER SkipSubnetScan
		Skip the ping/port scan of the local subnet.

	.PARAMETER SkipFileScan
		Skip share sizing, file type totals, and the search for notable database/backup/PST files.
		Use this if the shares are very large.

	.PARAMETER SkipUpdateSearch
		Skip the Windows Update pending-updates search (can take a few minutes).

	.EXAMPLE
		Get-ClientDiscovery -PublicDomain contoso.com
		Full discovery including public DNS checks for contoso.com.

	.EXAMPLE
		Get-ClientDiscovery -PublicDomain contoso.com, contoso.net -SkipFileScan -Verbose
		Skips the (slow) share sizing and file search and shows verbose detail.

	.EXAMPLE
		$d = Get-ClientDiscovery -SkipSubnetScan
		$d.Findings | Where-Object Severity -eq 'High'
		Runs without the LAN scan and lists the high-severity findings from the returned object.

	.NOTES
		Requires an elevated session. Domain queries run as the current user, so run it as a domain admin
		on domain-joined servers to get the Active Directory sections.
	#>
	[CmdletBinding()]
	param(
		[string]$OutputRoot,
		[ValidatePattern('^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$')]
		[string[]]$PublicDomain = @(),
		[ValidateRange(1, 365)]
		[int]$EventDays = 30,
		[switch]$SkipSubnetScan,
		[switch]$SkipFileScan,
		[switch]$SkipUpdateSearch
	)

	$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
	if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
		Write-Host 'Run this from an elevated (Run as administrator) PowerShell window.' -ForegroundColor Red
		return
	}

	if (-not $OutputRoot) {
		if (-not $Global:ITFolder) { $Global:ITFolder = "$env:SystemDrive\IT" }
		$OutputRoot = Join-Path $Global:ITFolder 'Discovery'
	}

	$started = Get-Date
	$since = $started.AddDays(-1 * $EventDays)
	$outDir = Join-Path $OutputRoot ('{0}_{1}' -f $env:COMPUTERNAME, $started.ToString('yyyyMMdd-HHmm'))
	try {
		New-Item -ItemType Directory -Path $outDir -Force -ErrorAction Stop | Out-Null
	} catch {
		Write-Host ('Could not create output folder {0}: {1}' -f $outDir, $_.Exception.Message) -ForegroundColor Red
		return
	}
	$result = [ordered]@{}
	$errors = New-Object System.Collections.ArrayList
	$extTable = @{}
	$userShares = @()
	$adInfo = $null
	$zip = $null
	$transcriptOn = $false

	# ---------------------------------------------------------------- helpers
	function Protect-DiscoveryPath {
		# Restrict our own output to Administrators and SYSTEM. It holds account lists and security posture.
		param([string]$Path, [switch]$Container)
		$grant = if ($Container) { '(OI)(CI)F' } else { 'F' }
		$null = & icacls.exe $Path /inheritance:r /grant:r ('*S-1-5-32-544:{0}' -f $grant) ('*S-1-5-18:{0}' -f $grant) 2>&1
		if ($LASTEXITCODE -ne 0) {
			Write-Host ('    Could not restrict permissions on {0}. Delete it promptly after delivery.' -f $Path) -ForegroundColor Yellow
		}
	}

	function Invoke-Section {
		param([string]$Name, [scriptblock]$Code)
		Write-Host ('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Name) -ForegroundColor Cyan
		try {
			$data = & $Code
			$result[$Name] = $data
			if ($null -ne $data) {
				$items = @($data)
				if ($items.Count -gt 0 -and $items[0] -is [System.Management.Automation.PSCustomObject]) {
					$items | Export-Csv -Path (Join-Path $outDir ('{0}.csv' -f $Name)) -NoTypeInformation -Encoding UTF8
				}
			}
		} catch {
			[void]$errors.Add(('{0}: {1}' -f $Name, $_.Exception.Message))
			Write-Host ('    failed: {0}' -f $_.Exception.Message) -ForegroundColor Yellow
		}
	}

	function Get-SectionRows {
		param([string]$Name)
		if ($result.Contains($Name)) { @($result[$Name] | Where-Object { $null -ne $_ }) } else { @() }
	}

	function New-NotApplicable {
		param([string]$Reason)
		[pscustomobject]@{ Note = $Reason }
	}

	function Get-Prop {
		param($Row, [string]$Name)
		if ($Row.Properties[$Name].Count -gt 0) { $Row.Properties[$Name][0] } else { $null }
	}

	function Convert-FileTimeValue {
		param($Value)
		if ($Value -and [int64]$Value -gt 0 -and [int64]$Value -lt [int64]::MaxValue) { [datetime]::FromFileTime([int64]$Value) } else { $null }
	}

	function ConvertTo-LdapFilterValue {
		# RFC 4515 escaping for values placed inside an LDAP filter
		param([string]$Value)
		$Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
	}

	function Search-Ad {
		param([string]$Filter, [string[]]$Props, [string]$Root, [switch]$Base)
		$s = New-Object System.DirectoryServices.DirectorySearcher
		if (-not $Root) { $Root = $adInfo.DomainDn }
		$s.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry ('LDAP://{0}' -f $Root)
		if ($Base) { $s.SearchScope = [System.DirectoryServices.SearchScope]::Base }
		$s.Filter = $Filter
		$s.PageSize = 500
		foreach ($p in $Props) { [void]$s.PropertiesToLoad.Add($p) }
		$found = $s.FindAll()
		try {
			foreach ($r in $found) { $r }
		} finally {
			$found.Dispose()
			$s.SearchRoot.Dispose()
			$s.Dispose()
		}
	}

	function Get-AdObjectSid {
		param([string]$Dn)
		$r = @(Search-Ad -Filter '(objectClass=*)' -Props @('objectsid') -Root $Dn -Base)
		if ($r.Count -gt 0) { (New-Object System.Security.Principal.SecurityIdentifier ([byte[]](Get-Prop $r[0] 'objectsid'), 0)).Value }
	}

	function Get-DnLeaf {
		param([string]$Dn)
		(($Dn -split '(?<!\\),')[0] -replace '^(CN|OU)=', '') -replace '\\,', ','
	}

	function ConvertFrom-EventRecord {
		param($EventRecord)
		$x = [xml]$EventRecord.ToXml()
		$d = @{}
		foreach ($n in $x.Event.EventData.Data) {
			if ($n.Name) { $d[$n.Name] = $n.'#text' }
		}
		$d
	}

	function ConvertFrom-DbNull {
		param($Value)
		if ($Value -is [System.DBNull]) { $null } else { $Value }
	}

	function Test-PublicIp {
		# True only for a parseable, routable, non-private address
		param([string]$Ip)
		$addr = $null
		if (-not [System.Net.IPAddress]::TryParse([string]$Ip, [ref]$addr)) { return $false }
		if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
			if ($addr.IsIPv4MappedToIPv6) { return (Test-PublicIp $addr.MapToIPv4().ToString()) }
			return -not ($addr.IsIPv6LinkLocal -or $addr.IsIPv6SiteLocal -or [System.Net.IPAddress]::IsLoopback($addr) -or $Ip -match '^(fc|fd)' -or $Ip -eq '::')
		}
		$b = $addr.GetAddressBytes()
		-not ($b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -eq 0 -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168) -or ($b[0] -eq 169 -and $b[1] -eq 254) -or ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or $b[0] -ge 224)
	}

	function ConvertTo-UInt32Ip {
		param([string]$Ip)
		$bytes = [System.Net.IPAddress]::Parse($Ip).GetAddressBytes()
		[Array]::Reverse($bytes)
		[BitConverter]::ToUInt32($bytes, 0)
	}

	function ConvertFrom-UInt32Ip {
		param([uint32]$Number)
		$bytes = [BitConverter]::GetBytes($Number)
		[Array]::Reverse($bytes)
		(New-Object System.Net.IPAddress (, $bytes)).ToString()
	}

	function Get-OpenPorts {
		param([string]$Ip, [int[]]$Ports, [int]$TimeoutMs = 1200)
		$items = foreach ($port in $Ports) {
			$c = New-Object System.Net.Sockets.TcpClient
			[pscustomobject]@{ Port = $port; Client = $c; Task = $c.ConnectAsync($Ip, $port) }
		}
		try {
			[void][System.Threading.Tasks.Task]::WaitAll(@($items | ForEach-Object { $_.Task }), $TimeoutMs)
		} catch {
			Write-Verbose 'port wait finished with errors (expected for closed ports)'
		}
		$open = @()
		foreach ($i in $items) {
			if ($i.Task.Status -eq 'RanToCompletion' -and $i.Client.Connected) { $open += $i.Port }
			$i.Client.Close()
		}
		$open
	}

	function Get-WebBanner {
		param([string]$Ip, [int]$Port)
		$scheme = 'http'
		if ($Port -eq 443 -or $Port -eq 8443 -or $Port -eq 5001 -or $Port -eq 8006) { $scheme = 'https' }
		$out = [ordered]@{ Url = ('{0}://{1}:{2}/' -f $scheme, $Ip, $Port); Status = $null; Server = $null; AuthRealm = $null; Title = $null }
		$iwr = @{ Uri = $out.Url; UseBasicParsing = $true; TimeoutSec = 4; ErrorAction = 'Stop' }
		# PowerShell 7 ignores ServicePointManager, so device self-signed certs need the explicit switch
		if ($PSVersionTable.PSEdition -eq 'Core') { $iwr['SkipCertificateCheck'] = $true }
		try {
			$r = Invoke-WebRequest @iwr
			$out.Status = [int]$r.StatusCode
			$out.Server = [string]$r.Headers['Server']
			if ($r.Content -match '(?is)<title[^>]*>(.*?)</title>') { $out.Title = ($Matches[1] -replace '\s+', ' ').Trim() }
		} catch {
			$resp = $_.Exception.Response
			if ($resp) {
				try {
					$out.Status = [int]$resp.StatusCode
					$out.Server = [string]$resp.Headers['Server']
					$out.AuthRealm = [string]$resp.Headers['WWW-Authenticate']
				} catch {
					Write-Verbose 'banner header read failed'
				}
			}
		}
		[pscustomobject]$out
	}

	function Get-LikelyType {
		param($Open, [bool]$IsGateway)
		if ($IsGateway) { return 'Router/Firewall (gateway)' }
		if ($Open -contains 9100 -or $Open -contains 515 -or $Open -contains 631) { return 'Printer/MFP (probable)' }
		if ($Open -contains 37777 -or $Open -contains 554 -or $Open -contains 8000) { return 'Camera/NVR (probable)' }
		if ($Open -contains 902) { return 'VMware ESXi host (probable)' }
		if ($Open -contains 8006) { return 'Proxmox host (probable)' }
		if ($Open -contains 5000 -or $Open -contains 5001) { return 'NAS (Synology or similar, probable)' }
		if ($Open -contains 3389 -or $Open -contains 135 -or $Open -contains 445) { return 'Windows host or NAS (probable)' }
		if ($Open -contains 22) { return 'Linux/NAS/network device (SSH)' }
		if (@($Open).Count -gt 0) { return 'Web-managed device' }
		'Unknown (no scanned ports open)'
	}

	# Lock the folder down before anything sensitive (including the transcript) is written into it
	Protect-DiscoveryPath -Path $outDir -Container
	try {
		Start-Transcript -Path (Join-Path $outDir 'transcript.txt') | Out-Null
		$transcriptOn = $true
	} catch {
		Write-Verbose 'Transcript not started'
	}

	try {
		Write-Host ('Discovery started on {0}. Output: {1}' -f $env:COMPUTERNAME, $outDir) -ForegroundColor Green
		$computerSystem = Get-CimInstance Win32_ComputerSystem

		# ------------------------------------------------------------ system
		Invoke-Section 'System' {
			$os = Get-CimInstance Win32_OperatingSystem
			$cs = $computerSystem
			$bios = Get-CimInstance Win32_BIOS
			$cpus = @(Get-CimInstance Win32_Processor)
			$ver = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
			$tz = $null
			try { $tz = (Get-TimeZone).Id } catch { $tz = [System.TimeZoneInfo]::Local.Id }
			$virtual = [bool](($cs.Model -match 'Virtual|VMware|KVM|HVM|Xen|QEMU') -or ($cs.Manufacturer -match 'VMware|QEMU|Xen'))
			[pscustomobject]@{
				ComputerName = $env:COMPUTERNAME
				DnsHostName = $cs.DNSHostName
				PartOfDomain = $cs.PartOfDomain
				DomainOrWorkgroup = $cs.Domain
				DomainRole = $cs.DomainRole
				ProductType = $os.ProductType
				OSCaption = $os.Caption
				OSVersion = $os.Version
				BuildNumber = $os.BuildNumber
				ReleaseId = $ver.ReleaseId
				DisplayVersion = $ver.DisplayVersion
				UBR = $ver.UBR
				OSArchitecture = $os.OSArchitecture
				OSInstallDate = $os.InstallDate
				LastBoot = $os.LastBootUpTime
				UptimeDays = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
				Manufacturer = $cs.Manufacturer
				Model = $cs.Model
				SerialNumber = $bios.SerialNumber
				BiosVersion = $bios.SMBIOSBIOSVersion
				BiosDate = $bios.ReleaseDate
				CpuName = ($cpus | Select-Object -First 1).Name
				CpuSockets = $cpus.Count
				CpuCores = ($cpus | Measure-Object -Property NumberOfCores -Sum).Sum
				LogicalProcessors = $cs.NumberOfLogicalProcessors
				RamGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
				TimeZone = $tz
				LooksVirtual = $virtual
				PSVersion = $PSVersionTable.PSVersion.ToString()
				ScriptRunBy = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
			}
		}

		Invoke-Section 'WindowsLicense' {
			$statusText = @{ 0 = 'Unlicensed'; 1 = 'Licensed'; 2 = 'OOBGrace'; 3 = 'OOTGrace'; 4 = 'NonGenuineGrace'; 5 = 'Notification'; 6 = 'ExtendedGrace' }
			Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationId='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" | ForEach-Object {
				[pscustomobject]@{ Name = $_.Name; Description = $_.Description; LicenseStatus = $_.LicenseStatus; LicenseStatusText = $statusText[[int]$_.LicenseStatus] }
			}
		}

		Invoke-Section 'TimeSync' {
			$src = (w32tm /query /source 2>&1 | Out-String).Trim()
			[pscustomobject]@{ TimeSource = $src }
		}

		Invoke-Section 'EntraJoinStatus' { Get-ComputerEntraStatus }

		# ------------------------------------------------------------ disks
		Invoke-Section 'Volumes' {
			Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
				$pct = $null
				if ($_.Size) { $pct = [math]::Round(100 * $_.FreeSpace / $_.Size, 1) }
				[pscustomobject]@{
					Drive = $_.DeviceID
					Label = $_.VolumeName
					FileSystem = $_.FileSystem
					SizeGB = [math]::Round($_.Size / 1GB, 1)
					FreeGB = [math]::Round($_.FreeSpace / 1GB, 1)
					PctFree = $pct
				}
			}
		}

		Invoke-Section 'DiskDrives' {
			Get-CimInstance Win32_DiskDrive | ForEach-Object {
				[pscustomobject]@{ Model = $_.Model; Serial = ([string]$_.SerialNumber).Trim(); Interface = $_.InterfaceType; MediaType = $_.MediaType; SizeGB = [math]::Round($_.Size / 1GB, 1); Status = $_.Status; Partitions = $_.Partitions }
			}
		}

		Invoke-Section 'PhysicalDiskHealth' {
			Get-PhysicalDisk | ForEach-Object {
				[pscustomobject]@{ Name = $_.FriendlyName; MediaType = [string]$_.MediaType; BusType = [string]$_.BusType; Health = [string]$_.HealthStatus; Operational = ($_.OperationalStatus -join ','); SizeGB = [math]::Round($_.Size / 1GB, 1) }
			}
		}

		Invoke-Section 'StorageControllers' {
			Get-CimInstance Win32_SCSIController | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Manufacturer = $_.Manufacturer; DriverName = $_.DriverName } }
		}

		Invoke-Section 'BitLocker' {
			if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { return (New-NotApplicable 'BitLocker feature not installed') }
			Get-BitLockerVolume | ForEach-Object {
				[pscustomobject]@{ Mount = $_.MountPoint; Status = [string]$_.VolumeStatus; Protection = [string]$_.ProtectionStatus; Method = [string]$_.EncryptionMethod; Protectors = (($_.KeyProtector | ForEach-Object { [string]$_.KeyProtectorType }) -join ',') }
			}
		}

		# ------------------------------------------------------------ network
		Invoke-Section 'NetConfig' {
			Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | ForEach-Object {
				[pscustomobject]@{
					Adapter = $_.Description
					MAC = $_.MACAddress
					IPAddress = ($_.IPAddress -join ', ')
					SubnetMask = ($_.IPSubnet -join ', ')
					DefaultGateway = ($_.DefaultIPGateway -join ', ')
					DnsServers = ($_.DNSServerSearchOrder -join ', ')
					DnsDomain = $_.DNSDomain
					DhcpEnabled = $_.DHCPEnabled
					DhcpServer = $_.DHCPServer
					LeaseObtained = $_.DHCPLeaseObtained
					LeaseExpires = $_.DHCPLeaseExpires
					NetBIOSOption = $_.TcpipNetbiosOptions
				}
			}
		}

		Invoke-Section 'NetAdapters' {
			Get-NetAdapter | ForEach-Object {
				[pscustomobject]@{ Name = $_.Name; Description = $_.InterfaceDescription; Status = [string]$_.Status; LinkSpeed = $_.LinkSpeed; MAC = $_.MacAddress; Virtual = $_.Virtual }
			}
		}

		Invoke-Section 'NicTeams' {
			if (-not (Get-Command Get-NetLbfoTeam -ErrorAction SilentlyContinue)) { return $null }
			Get-NetLbfoTeam -ErrorAction SilentlyContinue | ForEach-Object {
				[pscustomobject]@{ Name = $_.Name; Members = ($_.Members -join ','); Mode = [string]$_.TeamingMode; LoadBalancing = [string]$_.LoadBalancingAlgorithm; Status = [string]$_.Status }
			}
		}

		Invoke-Section 'Routes' {
			Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -notmatch '^(127\.|224\.|255\.)' -and $_.DestinationPrefix -notmatch '/32$' } | ForEach-Object {
				[pscustomobject]@{ Destination = $_.DestinationPrefix; NextHop = $_.NextHop; Metric = $_.RouteMetric; Interface = $_.InterfaceAlias }
			}
		}

		Invoke-Section 'HostsFile' {
			Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') } | ForEach-Object {
				[pscustomobject]@{ Entry = $_.Trim() }
			}
		}

		Invoke-Section 'PublicIP' {
			$prev = [Net.ServicePointManager]::SecurityProtocol
			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
			try {
				try {
					$r = Invoke-RestMethod -Uri 'https://ipinfo.io/json' -UseBasicParsing -TimeoutSec 10
					[pscustomobject]@{ Ip = $r.ip; ReverseDns = $r.hostname; Org = $r.org; City = $r.city; Region = $r.region; Source = 'ipinfo.io' }
				} catch {
					$ip = Invoke-RestMethod -Uri 'https://api.ipify.org' -UseBasicParsing -TimeoutSec 10
					[pscustomobject]@{ Ip = $ip; ReverseDns = $null; Org = $null; City = $null; Region = $null; Source = 'ipify.org' }
				}
			} finally {
				[Net.ServicePointManager]::SecurityProtocol = $prev
			}
		}

		Invoke-Section 'ListeningPorts' {
			$procs = @{}
			Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }
			Get-NetTCPConnection -State Listen | Sort-Object LocalPort | ForEach-Object {
				[pscustomobject]@{ LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort; ProcessId = $_.OwningProcess; Process = $procs[[int]$_.OwningProcess] }
			}
		}

		Invoke-Section 'ExternalConnections' {
			$procs = @{}
			Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName }
			Get-NetTCPConnection -State Established | Where-Object { Test-PublicIp $_.RemoteAddress } | Select-Object -First 200 | ForEach-Object {
				[pscustomobject]@{ RemoteAddress = $_.RemoteAddress; RemotePort = $_.RemotePort; LocalPort = $_.LocalPort; Process = $procs[[int]$_.OwningProcess] }
			}
		}

		# ------------------------------------------------------------ server roles (DHCP, DNS, Hyper-V, IIS)
		Invoke-Section 'DhcpScopes' {
			if (-not (Get-Service DHCPServer -ErrorAction SilentlyContinue) -or -not (Get-Command Get-DhcpServerv4Scope -ErrorAction SilentlyContinue)) { return $null }
			# DNS/router options are often set server-wide, so fall back to server-level values
			$serverOpt = @{}
			Get-DhcpServerv4OptionValue -ErrorAction SilentlyContinue | ForEach-Object { $serverOpt[[int]$_.OptionId] = ($_.Value -join ', ') }
			Get-DhcpServerv4Scope | ForEach-Object {
				$scope = $_
				$opt = $serverOpt.Clone()
				Get-DhcpServerv4OptionValue -ScopeId $scope.ScopeId -All -ErrorAction SilentlyContinue | ForEach-Object { $opt[[int]$_.OptionId] = ($_.Value -join ', ') }
				$stats = Get-DhcpServerv4ScopeStatistics -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue
				[pscustomobject]@{
					ScopeId = [string]$scope.ScopeId
					Name = $scope.Name
					SubnetMask = [string]$scope.SubnetMask
					StartRange = [string]$scope.StartRange
					EndRange = [string]$scope.EndRange
					LeaseDuration = [string]$scope.LeaseDuration
					State = [string]$scope.State
					Router = $opt[3]
					DnsServers = $opt[6]
					DnsDomain = $opt[15]
					InUse = $stats.InUse
					Free = $stats.Free
					PercentInUse = $stats.PercentageInUse
				}
			}
		}

		Invoke-Section 'DhcpReservations' {
			foreach ($scope in (Get-SectionRows 'DhcpScopes')) {
				Get-DhcpServerv4Reservation -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue | ForEach-Object {
					[pscustomobject]@{ ScopeId = $scope.ScopeId; IPAddress = [string]$_.IPAddress; ClientId = $_.ClientId; Name = $_.Name; Description = $_.Description }
				}
			}
		}

		Invoke-Section 'DnsZones' {
			if (-not (Get-Service DNS -ErrorAction SilentlyContinue) -or -not (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue)) { return $null }
			Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' } | ForEach-Object {
				[pscustomobject]@{ Zone = $_.ZoneName; Type = [string]$_.ZoneType; AdIntegrated = $_.IsDsIntegrated; Reverse = $_.IsReverseLookupZone; DynamicUpdate = [string]$_.DynamicUpdate; ReplicationScope = [string]$_.ReplicationScope }
			}
		}

		Invoke-Section 'DnsServerSettings' {
			if (-not (Get-Service DNS -ErrorAction SilentlyContinue) -or -not (Get-Command Get-DnsServerForwarder -ErrorAction SilentlyContinue)) { return $null }
			$fwd = Get-DnsServerForwarder
			$scav = $null
			try { $scav = Get-DnsServerScavenging -ErrorAction Stop } catch { Write-Verbose 'Scavenging settings unavailable' }
			[pscustomobject]@{
				Forwarders = (@($fwd.IPAddress | ForEach-Object { [string]$_ }) -join ', ')
				UseRootHint = $fwd.UseRootHint
				ScavengingEnabled = $(if ($scav) { $scav.ScavengingState } else { $null })
				ScavengingInterval = $(if ($scav) { [string]$scav.ScavengingInterval } else { $null })
			}
		}

		Invoke-Section 'HyperVVMs' {
			if (-not (Get-Service vmms -ErrorAction SilentlyContinue) -or -not (Get-Command Get-VM -ErrorAction SilentlyContinue)) { return $null }
			Get-VM | ForEach-Object {
				$vm = $_
				$disks = @(Get-VMHardDiskDrive -VM $vm -ErrorAction SilentlyContinue | ForEach-Object {
					$size = $null
					try { $size = [math]::Round((Get-VHD -Path $_.Path -ErrorAction Stop).FileSize / 1GB, 1) } catch { $size = '?' }
					'{0} ({1} GB)' -f $_.Path, $size
				})
				[pscustomobject]@{
					Name = $vm.Name
					State = [string]$vm.State
					Generation = $vm.Generation
					Version = $vm.Version
					vCPU = $vm.ProcessorCount
					MemoryStartupGB = [math]::Round($vm.MemoryStartup / 1GB, 1)
					MemoryAssignedGB = [math]::Round($vm.MemoryAssigned / 1GB, 1)
					DynamicMemory = $vm.DynamicMemoryEnabled
					Uptime = [string]$vm.Uptime
					AutomaticStartAction = [string]$vm.AutomaticStartAction
					ReplicationState = [string]$vm.ReplicationState
					Checkpoints = @(Get-VMSnapshot -VM $vm -ErrorAction SilentlyContinue).Count
					Switches = ((Get-VMNetworkAdapter -VM $vm -ErrorAction SilentlyContinue | ForEach-Object { $_.SwitchName }) -join ', ')
					Disks = ($disks -join '; ')
				}
			}
		}

		Invoke-Section 'HyperVSwitches' {
			if (-not (Get-Service vmms -ErrorAction SilentlyContinue) -or -not (Get-Command Get-VMSwitch -ErrorAction SilentlyContinue)) { return $null }
			Get-VMSwitch | ForEach-Object {
				[pscustomobject]@{ Name = $_.Name; Type = [string]$_.SwitchType; Adapter = $_.NetAdapterInterfaceDescription; AllowManagementOS = $_.AllowManagementOS }
			}
		}

		Invoke-Section 'IISSites' {
			$appcmd = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
			if (-not (Get-Service W3SVC -ErrorAction SilentlyContinue) -or -not (Test-Path $appcmd)) { return $null }
			& $appcmd list site 2>&1 | ForEach-Object { [pscustomobject]@{ Line = ([string]$_).Trim() } } | Where-Object { $_.Line }
		}

		# ------------------------------------------------------------ shares and file data
		Invoke-Section 'Shares' {
			Get-SmbShare | ForEach-Object {
				[pscustomobject]@{ Name = $_.Name; Path = $_.Path; Description = $_.Description; Special = $_.Special; CurrentUsers = $_.CurrentUsers; EncryptData = $_.EncryptData; FolderEnumerationMode = [string]$_.FolderEnumerationMode; CachingMode = [string]$_.CachingMode }
			}
		}

		try {
			$userShares = @(Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special -and $_.Path })
		} catch {
			Write-Verbose 'Get-SmbShare unavailable'
		}

		Invoke-Section 'SharePermissions' {
			foreach ($s in $userShares) {
				Get-SmbShareAccess -Name $s.Name | ForEach-Object {
					[pscustomobject]@{ Share = $s.Name; Account = $_.AccountName; Type = [string]$_.AccessControlType; Right = [string]$_.AccessRight }
				}
			}
		}

		Invoke-Section 'FolderPermissions' {
			foreach ($s in $userShares) {
				$targets = @($s.Path)
				$targets += @(Get-ChildItem -LiteralPath $s.Path -Directory -Force -ErrorAction SilentlyContinue | Select-Object -First 100 | ForEach-Object { $_.FullName })
				foreach ($t in $targets) {
					try {
						(Get-Acl -LiteralPath $t).Access | Where-Object { $t -eq $s.Path -or -not $_.IsInherited } | ForEach-Object {
							[pscustomobject]@{ Share = $s.Name; Path = $t; Identity = [string]$_.IdentityReference; Rights = [string]$_.FileSystemRights; Type = [string]$_.AccessControlType; Inherited = $_.IsInherited }
						}
					} catch {
						Write-Verbose ('ACL read failed: {0}' -f $t)
					}
				}
			}
		}

		if (-not $SkipFileScan) {
			Invoke-Section 'ShareSizes' {
				function Measure-Tree {
					param([string]$Path, [hashtable]$Ext)
					$count = 0
					$bytes = [int64]0
					$newest = $null
					Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
						$count++
						$bytes += $_.Length
						if ($null -eq $newest -or $_.LastWriteTime -gt $newest) { $newest = $_.LastWriteTime }
						$e = $_.Extension.ToLower()
						if (-not $e) { $e = '(none)' }
						if ($Ext.ContainsKey($e)) {
							$Ext[$e].Count++
							$Ext[$e].Bytes += $_.Length
						} else {
							$Ext[$e] = [pscustomobject]@{ Extension = $e; Count = 1; Bytes = [int64]$_.Length }
						}
					}
					[pscustomobject]@{ Files = $count; Bytes = $bytes; Newest = $newest }
				}
				# Measure each path once. A share nested inside another share is listed but not re-counted.
				$measured = @()
				foreach ($s in ($userShares | Sort-Object { $_.Path.Length })) {
					$root = $s.Path.TrimEnd('\') + '\'
					$parent = $measured | Where-Object { $root.StartsWith($_.Root, [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
					if ($parent) {
						[pscustomobject]@{ Share = $s.Name; Folder = ('(inside share {0}, counted there)' -f $parent.Name); Files = $null; SizeGB = $null; NewestFile = $null }
						continue
					}
					$measured += [pscustomobject]@{ Name = $s.Name; Root = $root }
					$top = @(Get-ChildItem -LiteralPath $s.Path -Force -ErrorAction SilentlyContinue)
					foreach ($d in ($top | Where-Object { $_.PSIsContainer })) {
						$m = Measure-Tree -Path $d.FullName -Ext $extTable
						[pscustomobject]@{ Share = $s.Name; Folder = $d.Name; Files = $m.Files; SizeGB = [math]::Round($m.Bytes / 1GB, 2); NewestFile = $m.Newest }
					}
					$rootFiles = @($top | Where-Object { -not $_.PSIsContainer })
					if ($rootFiles.Count -gt 0) {
						$sum = ($rootFiles | Measure-Object -Property Length -Sum).Sum
						[pscustomobject]@{ Share = $s.Name; Folder = '(files in share root)'; Files = $rootFiles.Count; SizeGB = [math]::Round($sum / 1GB, 2); NewestFile = ($rootFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime }
					}
				}
			}

			Invoke-Section 'FileTypes' {
				$extTable.Values | Sort-Object Bytes -Descending | Select-Object -First 40 | ForEach-Object {
					[pscustomobject]@{ Extension = $_.Extension; Files = $_.Count; SizeMB = [math]::Round($_.Bytes / 1MB, 1) }
				}
			}

			Invoke-Section 'NotableFiles' {
				$skip = @('Windows', 'Program Files', 'Program Files (x86)', '$Recycle.Bin', 'System Volume Information', 'Recovery', 'PerfLogs')
				# Databases, mail stores, and backup/image formats that usually need a migration or backup plan
				$inc = '*.mdf', '*.ldf', '*.sdf', '*.mdb', '*.accdb', '*.qbw', '*.qbb', '*.qbm', '*.tlg', '*.pst', '*.ost', '*.bak', '*.vhd', '*.vhdx', '*.vmdk', '*.dbf', '*.adb', '*.vbk', '*.vib', '*.tib', '*.tibx', '*.spf', '*.mrimg', '*.bkf'
				$limit = 500
				$found = 0
				foreach ($drv in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) {
					$root = $drv.DeviceID + '\'
					foreach ($d in (Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue)) {
						if ($found -ge $limit) { break }
						if ($d.PSIsContainer -and ($skip -contains $d.Name)) { continue }
						if ($d.PSIsContainer) {
							Get-ChildItem -LiteralPath $d.FullName -Recurse -File -Force -Include $inc -ErrorAction SilentlyContinue | Select-Object -First ($limit - $found) | ForEach-Object {
								$found++
								[pscustomobject]@{ Path = $_.FullName; SizeMB = [math]::Round($_.Length / 1MB, 1); Modified = $_.LastWriteTime }
							}
						} elseif ($inc | Where-Object { $d.Name -like $_ }) {
							$found++
							[pscustomobject]@{ Path = $d.FullName; SizeMB = [math]::Round($d.Length / 1MB, 1); Modified = $d.LastWriteTime }
						}
					}
				}
				if ($found -ge $limit) { Write-Host ('    stopped after {0} files' -f $limit) -ForegroundColor DarkCyan }
			}
		}

		Invoke-Section 'SmbSessions' {
			Get-SmbSession | ForEach-Object {
				[pscustomobject]@{ Client = $_.ClientComputerName; User = $_.ClientUserName; Opens = $_.NumOpens; IdleSeconds = $_.SecondsIdle; Dialect = $_.Dialect }
			}
		}

		Invoke-Section 'SmbOpenFilesSummary' {
			Get-SmbOpenFile | Group-Object ClientComputerName, ClientUserName | ForEach-Object {
				[pscustomobject]@{ Client = $_.Group[0].ClientComputerName; User = $_.Group[0].ClientUserName; OpenFiles = $_.Count }
			}
		}

		Invoke-Section 'SmbServerConfig' {
			$c = Get-SmbServerConfiguration
			[pscustomobject]@{ SMB1Enabled = $c.EnableSMB1Protocol; SMB2Enabled = $c.EnableSMB2Protocol; RequireSigning = $c.RequireSecuritySignature; EncryptData = $c.EncryptData; RejectUnencrypted = $c.RejectUnencryptedAccess }
		}

		# ------------------------------------------------------------ local accounts
		Invoke-Section 'LocalUsers' {
			try {
				Get-LocalUser -ErrorAction Stop | ForEach-Object {
					[pscustomobject]@{ Name = $_.Name; Enabled = $_.Enabled; FullName = $_.FullName; Description = $_.Description; LastLogon = $_.LastLogon; PasswordLastSet = $_.PasswordLastSet; PasswordRequired = $_.PasswordRequired; PasswordExpires = $_.PasswordExpires }
				}
			} catch {
				Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | ForEach-Object {
					[pscustomobject]@{ Name = $_.Name; Enabled = (-not $_.Disabled); FullName = $_.FullName; Description = $_.Description; LastLogon = $null; PasswordLastSet = $null; PasswordRequired = $_.PasswordRequired; PasswordExpires = $_.PasswordExpires }
				}
			}
		}

		Invoke-Section 'LocalGroupMembers' {
			foreach ($gn in 'Administrators', 'Remote Desktop Users', 'Backup Operators', 'Power Users') {
				try {
					$g = [ADSI]('WinNT://{0}/{1},group' -f $env:COMPUTERNAME, $gn)
					foreach ($m in @($g.Invoke('Members'))) {
						$path = $m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
						[pscustomobject]@{ Group = $gn; Member = ($path -replace '^WinNT://', '') }
					}
				} catch {
					Write-Verbose ('Group not readable: {0}' -f $gn)
				}
			}
		}

		Invoke-Section 'UserProfiles' {
			Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special } | ForEach-Object {
				$prof = $_
				$acct = $null
				try { $acct = ([System.Security.Principal.SecurityIdentifier]$prof.SID).Translate([System.Security.Principal.NTAccount]).Value } catch { $acct = $prof.SID }
				[pscustomobject]@{ Account = $acct; LocalPath = $prof.LocalPath; LastUse = $prof.LastUseTime; Loaded = $prof.Loaded }
			}
		}

		Invoke-Section 'LoggedOnSessions' {
			quser 2>&1 | ForEach-Object { [pscustomobject]@{ Line = ([string]$_).Trim() } }
		}

		Invoke-Section 'PasswordPolicy' {
			net accounts 2>&1 | ForEach-Object { [pscustomobject]@{ Line = ([string]$_).Trim() } } | Where-Object { $_.Line }
		}

		# ------------------------------------------------------------ Active Directory
		if ($computerSystem.PartOfDomain) {
			try {
				# GetComputerDomain uses the server's domain, not the domain of whoever is running the function
				$dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
				$rootDse = [ADSI]('LDAP://{0}/RootDSE' -f $dom.Name)
				$adInfo = [pscustomobject]@{
					Domain = $dom
					DomainDn = [string]$rootDse.Properties['defaultNamingContext'].Value
					RootDn = [string]$rootDse.Properties['rootDomainNamingContext'].Value
					ConfigDn = [string]$rootDse.Properties['configurationNamingContext'].Value
				}
				$rootDse.Dispose()
			} catch {
				[void]$errors.Add(('ActiveDirectory: {0}' -f $_.Exception.Message))
				Write-Host ('    Active Directory not reachable: {0}' -f $_.Exception.Message) -ForegroundColor Yellow
			}
		}

		if ($adInfo) {
			Invoke-Section 'ADDomain' {
				$dom = $adInfo.Domain
				$forest = $dom.Forest
				$head = @(Search-Ad -Filter '(objectClass=*)' -Props @('minpwdlength', 'pwdhistorylength', 'maxpwdage', 'lockoutthreshold', 'ms-ds-machineaccountquota') -Root $adInfo.DomainDn -Base)[0]
				$maxAge = Get-Prop $head 'maxpwdage'
				$maxAgeDays = $null
				if ($null -ne $maxAge) {
					if ([int64]$maxAge -eq [int64]::MinValue -or [int64]$maxAge -eq 0) { $maxAgeDays = 'Never' } else { $maxAgeDays = [math]::Round([math]::Abs([double]$maxAge) / 864000000000, 0) }
				}
				$recycleBin = $null
				try {
					$rb = @(Search-Ad -Filter '(objectClass=*)' -Props @('msds-enabledfeaturebl') -Root ('CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,{0}' -f $adInfo.ConfigDn) -Base)
					$recycleBin = ($rb.Count -gt 0 -and $rb[0].Properties['msds-enabledfeaturebl'].Count -gt 0)
				} catch {
					Write-Verbose 'Recycle Bin state not readable'
				}
				$dcs = @(foreach ($dc in $dom.DomainControllers) {
					$ip = $null
					try { $ip = $dc.IPAddress } catch { $ip = '?' }
					'{0} ({1}, {2})' -f $dc.Name, $ip, $dc.OSVersion
				})
				$sites = @()
				try { $sites = @($forest.Sites | ForEach-Object { '{0}: {1}' -f $_.Name, (($_.Subnets | ForEach-Object { $_.Name }) -join ', ') }) } catch { Write-Verbose 'Sites not readable' }
				[pscustomobject]@{
					Domain = $dom.Name
					DomainDn = $adInfo.DomainDn
					DomainMode = [string]$dom.DomainMode
					Forest = $forest.Name
					ForestMode = [string]$forest.ForestMode
					PdcRoleOwner = $dom.PdcRoleOwner.Name
					RidRoleOwner = $dom.RidRoleOwner.Name
					InfrastructureRoleOwner = $dom.InfrastructureRoleOwner.Name
					SchemaRoleOwner = $forest.SchemaRoleOwner.Name
					NamingRoleOwner = $forest.NamingRoleOwner.Name
					DomainControllers = ($dcs -join '; ')
					Sites = ($sites -join '; ')
					RecycleBinEnabled = $recycleBin
					MinPasswordLength = Get-Prop $head 'minpwdlength'
					PasswordHistory = Get-Prop $head 'pwdhistorylength'
					MaxPasswordAgeDays = $maxAgeDays
					LockoutThreshold = Get-Prop $head 'lockoutthreshold'
					MachineAccountQuota = Get-Prop $head 'ms-ds-machineaccountquota'
				}
			}

			Invoke-Section 'ADUsers' {
				Search-Ad '(&(objectCategory=person)(objectClass=user))' @('samaccountname', 'displayname', 'mail', 'title', 'department', 'description', 'useraccountcontrol', 'lastlogontimestamp', 'pwdlastset', 'whencreated', 'memberof') | ForEach-Object {
					$uac = [int](Get-Prop $_ 'useraccountcontrol')
					$last = Convert-FileTimeValue (Get-Prop $_ 'lastlogontimestamp')
					[pscustomobject]@{
						Account = (Get-Prop $_ 'samaccountname')
						DisplayName = (Get-Prop $_ 'displayname')
						Email = (Get-Prop $_ 'mail')
						Title = (Get-Prop $_ 'title')
						Department = (Get-Prop $_ 'department')
						Description = (Get-Prop $_ 'description')
						Enabled = (-not ($uac -band 2))
						PasswordNeverExpires = [bool]($uac -band 65536)
						PasswordNotRequired = [bool]($uac -band 32)
						LastLogon = $last
						DaysSinceLogon = $(if ($last) { [int]((Get-Date) - $last).TotalDays } else { $null })
						PasswordLastSet = (Convert-FileTimeValue (Get-Prop $_ 'pwdlastset'))
						Created = (Get-Prop $_ 'whencreated')
						GroupCount = $_.Properties['memberof'].Count
					}
				}
			}

			Invoke-Section 'ADComputers' {
				Search-Ad '(objectCategory=computer)' @('name', 'dnshostname', 'operatingsystem', 'operatingsystemversion', 'description', 'lastlogontimestamp', 'whencreated', 'useraccountcontrol') | ForEach-Object {
					$uac = [int](Get-Prop $_ 'useraccountcontrol')
					$last = Convert-FileTimeValue (Get-Prop $_ 'lastlogontimestamp')
					[pscustomobject]@{
						Name = (Get-Prop $_ 'name')
						DnsHostName = (Get-Prop $_ 'dnshostname')
						OS = (Get-Prop $_ 'operatingsystem')
						OSVersion = (Get-Prop $_ 'operatingsystemversion')
						Description = (Get-Prop $_ 'description')
						Enabled = (-not ($uac -band 2))
						LastLogon = $last
						DaysSinceLogon = $(if ($last) { [int]((Get-Date) - $last).TotalDays } else { $null })
						Created = (Get-Prop $_ 'whencreated')
					}
				}
			}

			Invoke-Section 'ADPrivilegedUsers' {
				# Resolve groups by well-known SID so renamed, moved, or non-English groups are still found
				$domSid = Get-AdObjectSid $adInfo.DomainDn
				$rootSid = Get-AdObjectSid $adInfo.RootDn
				$groups = [ordered]@{
					'Domain Admins' = ('{0}-512' -f $domSid)
					'Enterprise Admins' = ('{0}-519' -f $rootSid)
					'Schema Admins' = ('{0}-518' -f $rootSid)
					'Administrators (built-in)' = 'S-1-5-32-544'
					'Account Operators' = 'S-1-5-32-548'
					'Server Operators' = 'S-1-5-32-549'
					'Backup Operators' = 'S-1-5-32-551'
				}
				foreach ($label in $groups.Keys) {
					try {
						$g = [ADSI]('LDAP://<SID={0}>' -f $groups[$label])
						$gdn = [string]$g.Properties['distinguishedName'].Value
						$g.Dispose()
						if (-not $gdn) { continue }
						$f = '(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={0}))' -f (ConvertTo-LdapFilterValue $gdn)
						Search-Ad $f @('samaccountname', 'useraccountcontrol', 'lastlogontimestamp') | ForEach-Object {
							$uac = [int](Get-Prop $_ 'useraccountcontrol')
							[pscustomobject]@{ Group = $label; Account = (Get-Prop $_ 'samaccountname'); Enabled = (-not ($uac -band 2)); PasswordNeverExpires = [bool]($uac -band 65536); LastLogon = (Convert-FileTimeValue (Get-Prop $_ 'lastlogontimestamp')) }
						}
					} catch {
						Write-Verbose ('Privileged group not readable: {0}' -f $label)
					}
				}
			}

			Invoke-Section 'ADGroups' {
				Search-Ad '(objectCategory=group)' @('samaccountname', 'description', 'grouptype', 'member', 'whencreated') | ForEach-Object {
					$gt = [int](Get-Prop $_ 'grouptype')
					$scope = 'Global'
					if ($gt -band 4) { $scope = 'DomainLocal' } elseif ($gt -band 8) { $scope = 'Universal' } elseif ($gt -band 1) { $scope = 'BuiltinLocal' }
					$members = @($_.Properties['member'])
					[pscustomobject]@{
						Group = (Get-Prop $_ 'samaccountname')
						Type = $(if ($gt -lt 0) { 'Security' } else { 'Distribution' })
						Scope = $scope
						Description = (Get-Prop $_ 'description')
						MemberCount = $members.Count
						Members = (($members | Select-Object -First 50 | ForEach-Object { Get-DnLeaf ([string]$_) }) -join '; ')
						Created = (Get-Prop $_ 'whencreated')
					}
				}
			}

			Invoke-Section 'ADOUs' {
				Search-Ad '(objectCategory=organizationalUnit)' @('distinguishedname', 'description', 'gplink', 'gpoptions') | ForEach-Object {
					$link = [string](Get-Prop $_ 'gplink')
					[pscustomobject]@{ OU = (Get-Prop $_ 'distinguishedname'); Description = (Get-Prop $_ 'description'); LinkedGpos = ([regex]::Matches($link, '\[LDAP://').Count); BlocksInheritance = ([int](Get-Prop $_ 'gpoptions') -eq 1) }
				}
			}

			Invoke-Section 'ADGroupPolicies' {
				# Map each GPO GUID to the domain root / OUs it is linked to
				$links = @{}
				$containers = @(Search-Ad -Filter '(objectClass=*)' -Props @('distinguishedname', 'gplink') -Root $adInfo.DomainDn -Base)
				$containers += @(Search-Ad '(&(objectCategory=organizationalUnit)(gplink=*))' @('distinguishedname', 'gplink'))
				foreach ($c in $containers) {
					$where = [string](Get-Prop $c 'distinguishedname')
					foreach ($m in [regex]::Matches([string](Get-Prop $c 'gplink'), '(?i)\[LDAP://cn=(\{[0-9a-f-]+\}),[^;]*;(\d)\]')) {
						$guid = $m.Groups[1].Value.ToUpper()
						$state = if ($m.Groups[2].Value -eq '1' -or $m.Groups[2].Value -eq '3') { ' (link disabled)' } else { '' }
						if (-not $links.ContainsKey($guid)) { $links[$guid] = @() }
						$links[$guid] += ($where + $state)
					}
				}
				$flagText = @{ 0 = 'Enabled'; 1 = 'User settings disabled'; 2 = 'Computer settings disabled'; 3 = 'All settings disabled' }
				Search-Ad '(objectClass=groupPolicyContainer)' @('displayname', 'cn', 'flags', 'whencreated', 'whenchanged') | ForEach-Object {
					$guid = ([string](Get-Prop $_ 'cn')).ToUpper()
					[pscustomobject]@{
						Name = (Get-Prop $_ 'displayname')
						Guid = $guid
						Status = $flagText[[int](Get-Prop $_ 'flags')]
						LinkedTo = $(if ($links.ContainsKey($guid)) { $links[$guid] -join '; ' } else { '(not linked)' })
						Created = (Get-Prop $_ 'whencreated')
						Changed = (Get-Prop $_ 'whenchanged')
					}
				}
			}
		} elseif (-not $computerSystem.PartOfDomain) {
			$result['ADDomain'] = New-NotApplicable ('Not domain joined. Workgroup: {0}' -f $computerSystem.Domain)
		}

		# ------------------------------------------------------------ roles, services, software
		Invoke-Section 'WindowsFeatures' {
			if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
				Get-WindowsFeature | Where-Object { $_.Installed } | ForEach-Object { [pscustomobject]@{ Name = $_.Name; DisplayName = $_.DisplayName } }
			} else {
				Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq 'Enabled' } | ForEach-Object { [pscustomobject]@{ Name = $_.FeatureName; DisplayName = $_.FeatureName } }
			}
		}

		Invoke-Section 'Services' {
			Get-CimInstance Win32_Service | ForEach-Object {
				[pscustomobject]@{ Name = $_.Name; DisplayName = $_.DisplayName; State = $_.State; StartMode = $_.StartMode; RunAs = $_.StartName; Path = $_.PathName }
			} | Sort-Object Name
		}

		Invoke-Section 'ScheduledTasks' {
			Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
				$info = $null
				try { $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction Stop } catch { $info = $null }
				$lastRun = $null
				$lastResult = $null
				if ($info) { $lastRun = $info.LastRunTime; $lastResult = $info.LastTaskResult }
				[pscustomobject]@{
					TaskName = $_.TaskName
					TaskPath = $_.TaskPath
					State = [string]$_.State
					RunAs = $_.Principal.UserId
					LogonType = [string]$_.Principal.LogonType
					RunLevel = [string]$_.Principal.RunLevel
					Actions = (($_.Actions | ForEach-Object { ('{0} {1}' -f $_.Execute, $_.Arguments).Trim() }) -join ' | ')
					LastRun = $lastRun
					LastResult = $lastResult
				}
			}
		}

		Invoke-Section 'StartupCommands' {
			Get-CimInstance Win32_StartupCommand | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Command = $_.Command; Location = $_.Location; User = $_.User } }
		}

		Invoke-Section 'InstalledSoftware' {
			$paths = @(
				@('Machine', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'),
				@('Machine', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
			)
			# Per-user installs (Zoom, Teams, Dropbox, etc.) for users whose hives are currently loaded
			Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } | ForEach-Object {
				$paths += , @(('User:{0}' -f $_.PSChildName), ('Registry::HKEY_USERS\{0}\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -f $_.PSChildName))
			}
			$rows = foreach ($p in $paths) {
				Get-ItemProperty $p[1] -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
					[pscustomobject]@{ DisplayName = $_.DisplayName; DisplayVersion = $_.DisplayVersion; Publisher = $_.Publisher; InstallDate = $_.InstallDate; Scope = $p[0] }
				}
			}
			$rows | Sort-Object DisplayName -Unique
		}

		Invoke-Section 'NotableSoftware' {
			$cats = [ordered]@{
				Security = 'Sophos|SentinelOne|CrowdStrike|Carbon Black|Webroot|Malwarebytes|McAfee|Trellix|Norton|Symantec|Kaspersky|\bESET\b|Trend Micro|Bitdefender|Cylance|Huntress|Defender|Avast|\bAVG\b|Vipre|Blackpoint|ThreatLocker|Arctic Wolf|Rapid7|Cisco Secure|Umbrella|DNSFilter|Todyl|Heimdal|Cortex XDR|Wazuh'
				RemoteAccess = 'ScreenConnect|ConnectWise|TeamViewer|AnyDesk|LogMeIn|\bGoTo|Splashtop|RemotePC|\bVNC\b|Action1|Ninja|Datto|Kaseya|Atera|Zoho Assist|Chrome Remote|Pulseway|Syncro|N-able|SolarWinds|Take Control|Bomgar|BeyondTrust|Dameware|RustDesk|Radmin|SimpleHelp|Tactical RMM|Mesh ?Agent|LabTech'
				Backup = 'Veeam|Acronis|Datto|Backblaze|Carbonite|CrashPlan|IDrive|Macrium|Cobian|SyncBack|StorageCraft|ShadowProtect|Barracuda|Unitrends|Axcient|Altaro|NovaBackup|NovaStor|Duplicati|\bCove\b|Backup Manager|Arcserve|Retrospect|BackupAssist|MSP360|CloudBerry|Druva|Commvault|Active Backup'
				CloudSync = 'OneDrive|Google Drive|Drive for desktop|Dropbox|Box Drive|Box Sync|Egnyte|Syncthing|ShareFile|Nextcloud|ownCloud|LucidLink|Panzura|Nasuni|CTERA|Resilio'
				Identity = 'Azure AD Connect|Entra Connect|\bDuo\b|Okta|JumpCloud|AuthLite|Imprivata|ADSelfService|Specops|Netwrix'
				DatabaseEngines = 'SQL Server|MySQL|MariaDB|PostgreSQL|Pervasive|Actian|Btrieve|FileMaker|Firebird|SQL Anywhere|Oracle Database|MongoDB|Advantage Database'
				PowerProtection = 'PowerChute|\bAPC\b|Schneider Electric|Eaton|Intelligent Power|CyberPower|PowerPanel|Liebert|Vertiv|Tripp ?Lite|PowerAlert'
				BusinessApps = 'QuickBooks|Intuit|\bACT!|Swiftpage|\bSage\b|Relius|ftwilliam|Corbel|Datair|PlanConnect|Pension|ERISA|Adobe|Acrobat|Foxit|Nitro|Bluebeam|DocuSign|Microsoft 365|Microsoft Office|Outlook|Zoom|Teams|Slack|\bJava\b|CCH|Lacerte|Drake|Chrome|Firefox'
			}
			$sw = Get-SectionRows 'InstalledSoftware'
			$svc = Get-SectionRows 'Services'
			foreach ($cat in $cats.Keys) {
				$rx = $cats[$cat]
				foreach ($s in $sw) {
					if ($s.DisplayName -match $rx) { [pscustomobject]@{ Category = $cat; Name = $s.DisplayName; Version = $s.DisplayVersion; Source = 'Software' } }
				}
				foreach ($s in $svc) {
					if ($s.DisplayName -match $rx -or $s.Name -match $rx) { [pscustomobject]@{ Category = $cat; Name = ('{0} ({1})' -f $s.DisplayName, $s.Name); Version = $s.State; Source = 'Service' } }
				}
			}
		}

		Invoke-Section 'Hotfixes' {
			Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 30 | ForEach-Object {
				[pscustomobject]@{ HotFixID = $_.HotFixID; Description = $_.Description; InstalledOn = $_.InstalledOn; InstalledBy = $_.InstalledBy }
			}
		}

		Invoke-Section 'WindowsUpdatePolicy' {
			$policy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
			$au = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
			[pscustomobject]@{
				WSUSServer = $policy.WUServer
				WSUSStatusServer = $policy.WUStatusServer
				TargetGroup = $policy.TargetGroup
				UseWUServer = $au.UseWUServer
				NoAutoUpdate = $au.NoAutoUpdate
				AUOptions = $au.AUOptions
				ScheduledInstallDay = $au.ScheduledInstallDay
				ScheduledInstallTime = $au.ScheduledInstallTime
			}
		}

		$wuSearcher = $null
		try {
			$wuSearcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
		} catch {
			[void]$errors.Add(('WindowsUpdate: {0}' -f $_.Exception.Message))
		}

		if ($wuSearcher) {
			Invoke-Section 'WindowsUpdateHistory' {
				$resultText = @{ 0 = 'NotStarted'; 1 = 'InProgress'; 2 = 'Succeeded'; 3 = 'SucceededWithErrors'; 4 = 'Failed'; 5 = 'Aborted' }
				$count = $wuSearcher.GetTotalHistoryCount()
				if ($count -gt 0) {
					@($wuSearcher.QueryHistory(0, [math]::Min($count, 25))) | Where-Object { $_.Title } | ForEach-Object {
						[pscustomobject]@{ Date = $_.Date; Title = $_.Title; Result = $resultText[[int]$_.ResultCode] }
					}
				}
			}

			if (-not $SkipUpdateSearch) {
				Invoke-Section 'PendingUpdates' {
					Write-Host '    searching for pending updates (this can take a few minutes)...' -ForegroundColor DarkCyan
					$found = $wuSearcher.Search('IsInstalled=0 and IsHidden=0')
					@($found.Updates) | ForEach-Object {
						[pscustomobject]@{ Title = $_.Title; KB = (@($_.KBArticleIDs) -join ','); Severity = $_.MsrcSeverity; Downloaded = $_.IsDownloaded }
					}
				}
			}
		}

		Invoke-Section 'PendingReboot' {
			[pscustomobject]@{
				ComponentBasedServicing = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
				WindowsUpdate = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
				PendingFileRename = [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue).PendingFileRenameOperations
			}
		}

		# ------------------------------------------------------------ security posture
		Invoke-Section 'Defender' {
			if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { return (New-NotApplicable 'Microsoft Defender not installed') }
			$s = Get-MpComputerStatus
			$p = Get-MpPreference
			[pscustomobject]@{
				AntivirusEnabled = $s.AntivirusEnabled
				RealTimeProtection = $s.RealTimeProtectionEnabled
				AMRunningMode = $s.AMRunningMode
				SignatureVersion = $s.AntivirusSignatureVersion
				SignatureLastUpdated = $s.AntivirusSignatureLastUpdated
				QuickScanEnd = $s.QuickScanEndTime
				FullScanEnd = $s.FullScanEndTime
				TamperProtected = $s.IsTamperProtected
				ExclusionPaths = (@($p.ExclusionPath) -join '; ')
				ExclusionExtensions = (@($p.ExclusionExtension) -join '; ')
				ExclusionProcesses = (@($p.ExclusionProcess) -join '; ')
			}
		}

		Invoke-Section 'DefenderThreats' {
			if (-not (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue)) { return $null }
			$names = @{}
			try { Get-MpThreat | ForEach-Object { $names[[string]$_.ThreatID] = $_.ThreatName } } catch { Write-Verbose 'Get-MpThreat unavailable' }
			Get-MpThreatDetection | ForEach-Object {
				[pscustomobject]@{ Detected = $_.InitialDetectionTime; Threat = $names[[string]$_.ThreatID]; ThreatID = $_.ThreatID; Resources = (@($_.Resources) -join '; '); Process = $_.ProcessName; ActionSuccess = $_.ActionSuccess }
			}
		}

		Invoke-Section 'SecurityCenterAV' {
			# root/SecurityCenter2 only exists on client OS (Windows 10/11)
			if ([int]$computerSystem.DomainRole -ge 2) { return $null }
			Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct | ForEach-Object {
				[pscustomobject]@{ Name = $_.displayName; State = $_.productState; Path = $_.pathToSignedProductExe }
			}
		}

		Invoke-Section 'FirewallProfiles' {
			Get-NetFirewallProfile | ForEach-Object {
				[pscustomobject]@{ Profile = [string]$_.Name; Enabled = [string]$_.Enabled; DefaultInbound = [string]$_.DefaultInboundAction; DefaultOutbound = [string]$_.DefaultOutboundAction }
			}
		}

		Invoke-Section 'SecuritySettings' {
			$smb1 = $null
			try { $smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol } catch { $smb1 = $null }
			$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
			$pol = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
			$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
			$ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
			$rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
			$wdigest = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue
			$dnsClient = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
			# Windows LAPS policy roots in precedence order, then legacy Microsoft LAPS
			$laps = 'None found'
			foreach ($k in @(
					@('Windows LAPS (CSP/Intune)', 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS'),
					@('Windows LAPS (GPO)', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'),
					@('Legacy Microsoft LAPS (GPO)', 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd')
				)) {
				if ((Test-Path $k[1]) -and @((Get-Item $k[1]).Property).Count -gt 0) { $laps = $k[0]; break }
			}
			$secureBoot = 'n/a'
			try { $secureBoot = [string](Confirm-SecureBootUEFI) } catch { $secureBoot = 'n/a' }
			$tpm = 'n/a'
			try { $t = Get-Tpm; $tpm = ('Present={0};Ready={1}' -f $t.TpmPresent, $t.TpmReady) } catch { $tpm = 'n/a' }
			$winrm = (Get-Service WinRM -ErrorAction SilentlyContinue).Status
			[pscustomobject]@{
				SMB1Enabled = $smb1
				LmCompatibilityLevel = $lsa.LmCompatibilityLevel
				NoLMHash = $lsa.NoLMHash
				RunAsPPL = $lsa.RunAsPPL
				WDigestUseLogonCredential = $wdigest.UseLogonCredential
				LlmnrDisabledByPolicy = ($dnsClient.EnableMulticast -eq 0)
				EnableLUA = $pol.EnableLUA
				AutoAdminLogon = $wl.AutoAdminLogon
				DefaultPasswordStoredInRegistry = [bool]($null -ne $wl.DefaultPassword)
				RdpEnabled = ($ts.fDenyTSConnections -eq 0)
				RdpPort = $rdp.PortNumber
				RdpNLA = $rdp.UserAuthentication
				RdpSecurityLayer = $rdp.SecurityLayer
				LapsPolicy = $laps
				SecureBoot = $secureBoot
				Tpm = $tpm
				WinRMService = [string]$winrm
			}
		}

		Invoke-Section 'Certificates' {
			Get-ChildItem Cert:\LocalMachine\My | ForEach-Object {
				[pscustomobject]@{ Subject = $_.Subject; Issuer = $_.Issuer; NotAfter = $_.NotAfter; DaysLeft = [int]($_.NotAfter - (Get-Date)).TotalDays; HasPrivateKey = $_.HasPrivateKey; Thumbprint = $_.Thumbprint }
			}
		}

		Invoke-Section 'EventLogs' {
			Get-WinEvent -ListLog Security, System, Application | ForEach-Object {
				[pscustomobject]@{ Log = $_.LogName; MaxSizeMB = [math]::Round($_.MaximumSizeInBytes / 1MB, 0); Records = $_.RecordCount; Enabled = $_.IsEnabled }
			}
		}

		Invoke-Section 'AuditPolicy' {
			# category:* avoids localized category names and the comma-list quoting problem
			auditpol /get /category:* 2>&1 | ForEach-Object { [pscustomobject]@{ Line = ([string]$_).Trim() } } | Where-Object { $_.Line }
		}

		Invoke-Section 'FailedLogons' {
			$evts = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $since } -MaxEvents 5000 -ErrorAction SilentlyContinue
			$rows = foreach ($e in $evts) {
				$d = ConvertFrom-EventRecord $e
				[pscustomobject]@{ Time = $e.TimeCreated; User = $d['TargetUserName']; Ip = $d['IpAddress']; LogonType = $d['LogonType'] }
			}
			$rows | Group-Object User, Ip, LogonType | ForEach-Object {
				$f = $_.Group[0]
				[pscustomobject]@{ User = $f.User; Ip = $f.Ip; PublicIp = (Test-PublicIp $f.Ip); LogonType = $f.LogonType; Count = $_.Count; First = ($_.Group | Measure-Object Time -Minimum).Minimum; Last = ($_.Group | Measure-Object Time -Maximum).Maximum }
			} | Sort-Object Count -Descending | Select-Object -First 100
		}

		Invoke-Section 'RecentLogons' {
			$ms = [int64]$EventDays * 86400000
			$xp = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[(Data[@Name='LogonType']='2') or (Data[@Name='LogonType']='3') or (Data[@Name='LogonType']='10')]]"
			$evts = Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents 20000 -ErrorAction SilentlyContinue
			$rows = foreach ($e in $evts) {
				$d = ConvertFrom-EventRecord $e
				$u = $d['TargetUserName']
				if ($u -and $u -notmatch '\$$|^(SYSTEM|ANONYMOUS LOGON|LOCAL SERVICE|NETWORK SERVICE)$|^(DWM|UMFD)-') {
					[pscustomobject]@{ Time = $e.TimeCreated; User = $u; Ip = $d['IpAddress']; LogonType = $d['LogonType']; Workstation = $d['WorkstationName'] }
				}
			}
			$rows | Group-Object LogonType, User, Ip | ForEach-Object {
				$f = $_.Group[0]
				[pscustomobject]@{ LogonType = $f.LogonType; User = $f.User; Ip = $f.Ip; Workstation = $f.Workstation; Count = $_.Count; First = ($_.Group | Measure-Object Time -Minimum).Minimum; Last = ($_.Group | Measure-Object Time -Maximum).Maximum }
			} | Sort-Object LogonType, User
		}

		Invoke-Section 'RdpConnections' {
			$evts = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id = 1149; StartTime = $since } -MaxEvents 2000 -ErrorAction SilentlyContinue
			$rows = foreach ($e in $evts) {
				[pscustomobject]@{ Time = $e.TimeCreated; User = [string]$e.Properties[0].Value; Domain = [string]$e.Properties[1].Value; Ip = [string]$e.Properties[2].Value }
			}
			$rows | Group-Object User, Ip | ForEach-Object {
				$f = $_.Group[0]
				[pscustomobject]@{ User = $f.User; Domain = $f.Domain; Ip = $f.Ip; PublicIp = (Test-PublicIp $f.Ip); Count = $_.Count; Last = ($_.Group | Measure-Object Time -Maximum).Maximum }
			}
		}

		Invoke-Section 'ServiceInstalls' {
			Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $since } -MaxEvents 200 -ErrorAction SilentlyContinue | ForEach-Object {
				[pscustomobject]@{ Time = $_.TimeCreated; Service = [string]$_.Properties[0].Value; Image = [string]$_.Properties[1].Value; StartType = [string]$_.Properties[3].Value; Account = [string]$_.Properties[4].Value }
			}
		}

		Invoke-Section 'AccountChanges' {
			Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4720, 4722, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4740, 4756, 4757, 1102; StartTime = $since } -MaxEvents 300 -ErrorAction SilentlyContinue | ForEach-Object {
				$msg = ([string]$_.Message -split "`n")[0].Trim()
				[pscustomobject]@{ Time = $_.TimeCreated; EventId = $_.Id; Summary = $msg }
			}
		}

		Invoke-Section 'SystemHealthEvents' {
			Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 41, 1074, 6008, 7, 11, 51, 55, 98, 129, 153, 157; StartTime = $since } -MaxEvents 2000 -ErrorAction SilentlyContinue | Group-Object Id, ProviderName | ForEach-Object {
				$latest = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
				[pscustomobject]@{ EventId = $latest.Id; Provider = $latest.ProviderName; Count = $_.Count; Last = $latest.TimeCreated; Sample = (([string]$latest.Message -split "`n")[0]).Trim() }
			}
		}

		# ------------------------------------------------------------ backup and sync
		Invoke-Section 'ShadowCopies' {
			Get-CimInstance Win32_ShadowCopy | ForEach-Object { [pscustomobject]@{ Volume = $_.VolumeName; Created = $_.InstallDate; Persistent = $_.Persistent } }
		}

		Invoke-Section 'ShadowStorage' {
			vssadmin list shadowstorage 2>&1 | ForEach-Object { [pscustomobject]@{ Line = ([string]$_).Trim() } } | Where-Object { $_.Line }
		}

		Invoke-Section 'VssWriters' { Get-VSSWriter }

		Invoke-Section 'WindowsServerBackup' {
			if (-not (Get-Command Get-WBSummary -ErrorAction SilentlyContinue)) { return (New-NotApplicable 'Windows Server Backup not installed') }
			$s = Get-WBSummary
			[pscustomobject]@{ LastSuccessfulBackup = $s.LastSuccessfulBackupTime; LastBackupResult = $s.LastBackupResultHR; NextBackup = $s.NextBackupTime; NumberOfVersions = $s.NumberOfVersions }
		}

		Invoke-Section 'OneDrive' {
			$hives = Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' }
			foreach ($h in $hives) {
				$k = 'Registry::HKEY_USERS\{0}\Software\Microsoft\OneDrive\Accounts' -f $h.PSChildName
				if (Test-Path $k) {
					Get-ChildItem $k | ForEach-Object {
						$p = Get-ItemProperty $_.PSPath
						[pscustomobject]@{ UserSid = $h.PSChildName; Account = $_.PSChildName; Email = $p.UserEmail; Folder = $p.UserFolder; Business = $p.Business }
					}
				}
			}
		}

		# ------------------------------------------------------------ SQL and printers
		Invoke-Section 'SqlInstances' {
			foreach ($hive in 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server') {
				$key = Join-Path $hive 'Instance Names\SQL'
				if (-not (Test-Path $key)) { continue }
				$names = Get-ItemProperty $key
				foreach ($p in ($names.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
					$setup = Get-ItemProperty (Join-Path $hive ('{0}\Setup' -f $p.Value)) -ErrorAction SilentlyContinue
					$svcName = if ($p.Name -eq 'MSSQLSERVER') { 'MSSQLSERVER' } else { 'MSSQL$' + $p.Name }
					$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
					[pscustomobject]@{ Instance = $p.Name; InstanceId = $p.Value; Edition = $setup.Edition; Version = $setup.Version; PatchLevel = $setup.PatchLevel; DataRoot = $setup.SQLDataRoot; ServiceState = $(if ($svc) { [string]$svc.Status } else { $null }); Bitness = $(if ($hive -match 'WOW6432Node') { '32-bit' } else { '64-bit' }) }
				}
			}
		}

		Invoke-Section 'SqlDatabases' {
			$query = @'
SELECT d.name, d.state_desc, d.recovery_model_desc, d.compatibility_level, d.create_date,
 CAST(SUM(CASE WHEN mf.type = 0 THEN CAST(mf.size AS bigint) ELSE 0 END) * 8.0 / 1024 AS decimal(18,1)) AS data_mb,
 CAST(SUM(CASE WHEN mf.type = 1 THEN CAST(mf.size AS bigint) ELSE 0 END) * 8.0 / 1024 AS decimal(18,1)) AS log_mb,
 (SELECT MAX(b.backup_finish_date) FROM msdb.dbo.backupset b WHERE b.database_name = d.name AND b.type = 'D') AS last_full,
 (SELECT MAX(b.backup_finish_date) FROM msdb.dbo.backupset b WHERE b.database_name = d.name AND b.type = 'I') AS last_diff,
 (SELECT MAX(b.backup_finish_date) FROM msdb.dbo.backupset b WHERE b.database_name = d.name AND b.type = 'L') AS last_log
FROM sys.databases d LEFT JOIN sys.master_files mf ON mf.database_id = d.database_id
GROUP BY d.name, d.state_desc, d.recovery_model_desc, d.compatibility_level, d.create_date
'@
			foreach ($inst in (Get-SectionRows 'SqlInstances')) {
				$server = '.'
				if ($inst.Instance -ne 'MSSQLSERVER') { $server = '.\' + $inst.Instance }
				$cn = New-Object System.Data.SqlClient.SqlConnection ('Server={0};Database=master;Integrated Security=SSPI;Connect Timeout=5;TrustServerCertificate=True' -f $server)
				try {
					$cn.Open()
					$cmd = $cn.CreateCommand()
					$cmd.CommandText = $query
					$rd = $cmd.ExecuteReader()
					try {
						while ($rd.Read()) {
							[pscustomobject]@{ Instance = $inst.Instance; Edition = $inst.Edition; Database = $rd['name']; State = $rd['state_desc']; Recovery = $rd['recovery_model_desc']; CompatLevel = $rd['compatibility_level']; Created = (ConvertFrom-DbNull $rd['create_date']); DataMB = (ConvertFrom-DbNull $rd['data_mb']); LogMB = (ConvertFrom-DbNull $rd['log_mb']); LastFull = (ConvertFrom-DbNull $rd['last_full']); LastDiff = (ConvertFrom-DbNull $rd['last_diff']); LastLog = (ConvertFrom-DbNull $rd['last_log']) }
						}
					} finally {
						$rd.Close()
					}
				} catch {
					[pscustomobject]@{ Instance = $inst.Instance; Edition = $inst.Edition; Database = ('(could not query: {0})' -f $_.Exception.Message); State = $null; Recovery = $null; CompatLevel = $null; Created = $null; DataMB = $null; LogMB = $null; LastFull = $null; LastDiff = $null; LastLog = $null }
				} finally {
					$cn.Dispose()
				}
			}
		}

		Invoke-Section 'Printers' {
			$ports = @{}
			try { Get-PrinterPort | ForEach-Object { $ports[$_.Name] = $_.PrinterHostAddress } } catch { Write-Verbose 'Get-PrinterPort unavailable' }
			Get-Printer | ForEach-Object {
				[pscustomobject]@{ Name = $_.Name; Driver = $_.DriverName; Port = $_.PortName; PortAddress = $ports[$_.PortName]; Shared = $_.Shared; ShareName = $_.ShareName; Status = [string]$_.PrinterStatus }
			}
		}

		# ------------------------------------------------------------ public DNS
		if ($PublicDomain.Count -gt 0) {
			Invoke-Section 'PublicDns' {
				# Prefer a public resolver so an internal zone with the same name does not hide the real records
				$dnsArgs = @{ DnsOnly = $true; ErrorAction = 'Stop' }
				$resolver = 'system resolver'
				try {
					Resolve-DnsName -Name 'www.microsoft.com' -Type A -Server 1.1.1.1 -DnsOnly -QuickTimeout -ErrorAction Stop | Out-Null
					$dnsArgs['Server'] = '1.1.1.1'
					$resolver = '1.1.1.1'
				} catch {
					Write-Verbose 'Outbound DNS to 1.1.1.1 blocked, using the system resolver'
				}
				foreach ($d in $PublicDomain) {
					$queries = @(
						@($d, 'MX'), @($d, 'TXT'), @($d, 'NS'), @($d, 'A'), @($d, 'SOA'),
						@(('www.' + $d), 'A'), @(('_dmarc.' + $d), 'TXT'), @(('google._domainkey.' + $d), 'TXT'),
						@(('selector1._domainkey.' + $d), 'CNAME'), @(('selector2._domainkey.' + $d), 'CNAME'),
						@(('autodiscover.' + $d), 'CNAME'), @(('enterpriseenrollment.' + $d), 'CNAME'), @(('enterpriseregistration.' + $d), 'CNAME')
					)
					foreach ($q in $queries) {
						$hit = $false
						try {
							Resolve-DnsName -Name $q[0] -Type $q[1] @dnsArgs | Where-Object { $_.Section -eq 'Answer' } | ForEach-Object {
								$rec = $_
								$val = switch ([string]$rec.Type) {
									'MX' { '{0} {1}' -f $rec.Preference, $rec.NameExchange }
									'TXT' { $rec.Strings -join '' }
									'NS' { $rec.NameHost }
									'CNAME' { $rec.NameHost }
									'A' { $rec.IPAddress }
									'SOA' { '{0} {1}' -f $rec.PrimaryServer, $rec.NameAdministrator }
									default { [string]$rec }
								}
								$hit = $true
								[pscustomobject]@{ Domain = $d; Query = $q[0]; Type = [string]$rec.Type; Value = $val; Resolver = $resolver }
							}
						} catch {
							Write-Verbose ('DNS query failed: {0} {1}' -f $q[0], $q[1])
						}
						if (-not $hit) { [pscustomobject]@{ Domain = $d; Query = $q[0]; Type = $q[1]; Value = '(no record)'; Resolver = $resolver } }
					}
				}
			}
		}

		# ------------------------------------------------------------ LAN scan
		if (-not $SkipSubnetScan) {
			Invoke-Section 'LanHosts' {
				$cfg = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -and $_.DefaultIPGateway } | Select-Object -First 1
				if (-not $cfg) { return (New-NotApplicable 'No adapter with a default gateway') }
				$rx = '^\d+\.\d+\.\d+\.\d+$'
				$myIp = @($cfg.IPAddress | Where-Object { $_ -match $rx })[0]
				$mask = @($cfg.IPSubnet | Where-Object { $_ -match $rx })[0]
				$gw = @($cfg.DefaultIPGateway | Where-Object { $_ -match $rx })[0]
				$dhcp = $cfg.DHCPServer
				if (-not $myIp -or -not $mask) { return (New-NotApplicable 'No IPv4 address on the gateway adapter') }
				$bits = 0
				foreach ($b in [System.Net.IPAddress]::Parse($mask).GetAddressBytes()) {
					$v = [int]$b
					while ($v -gt 0) { $bits += ($v -band 1); $v = $v -shr 1 }
				}
				# Never scan more than a /24, even on a larger subnet
				if ($bits -lt 24) { $bits = 24 }
				$size = [math]::Pow(2, 32 - $bits)
				$net = [math]::Floor([double](ConvertTo-UInt32Ip $myIp) / $size) * $size
				$ips = New-Object System.Collections.ArrayList
				for ($n = $net + 1; $n -le ($net + $size - 2); $n++) { [void]$ips.Add((ConvertFrom-UInt32Ip ([uint32]$n))) }
				Write-Host ('    scanning {0} addresses around {1}/{2}' -f $ips.Count, $myIp, $bits) -ForegroundColor DarkCyan

				$pings = foreach ($ip in $ips) {
					$p = New-Object System.Net.NetworkInformation.Ping
					[pscustomobject]@{ Ip = $ip; Pinger = $p; Task = $p.SendPingAsync($ip, 800) }
				}
				try {
					[void][System.Threading.Tasks.Task]::WaitAll(@($pings | ForEach-Object { $_.Task }), 20000)
				} catch {
					Write-Verbose 'ping wait finished with errors'
				}
				$live = @{}
				foreach ($p in $pings) {
					try {
						if ($p.Task.Status -eq 'RanToCompletion' -and $p.Task.Result.Status -eq 'Success') { $live[$p.Ip] = $true }
					} catch {
						Write-Verbose 'ping result read failed'
					}
					$p.Pinger.Dispose()
				}
				# Hosts that block ping usually still show up in the ARP cache after the sweep
				$mac = @{}
				try {
					Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -notmatch '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF|01-00-5E)' -and [string]$_.State -notin 'Unreachable', 'Incomplete' } | ForEach-Object {
						if ($ips -contains $_.IPAddress) { $mac[$_.IPAddress] = $_.LinkLayerAddress; $live[$_.IPAddress] = $true }
					}
				} catch {
					Write-Verbose 'Get-NetNeighbor unavailable'
				}
				if ($gw) { $live[$gw] = $true }
				$live[$myIp] = $true

				$prevPolicy = $null
				$prevProto = [System.Net.ServicePointManager]::SecurityProtocol
				$isDesktop = ($PSVersionTable.PSEdition -ne 'Core')
				if ($isDesktop) {
					# Windows PowerShell only: accept self-signed device certificates for the banner grab, restored in finally
					$prevPolicy = [System.Net.ServicePointManager]::CertificatePolicy
					if (-not ('MTTrustAll' -as [type])) {
						Add-Type -TypeDefinition 'using System.Net; using System.Security.Cryptography.X509Certificates; public class MTTrustAll : ICertificatePolicy { public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; } }'
					}
					[System.Net.ServicePointManager]::CertificatePolicy = New-Object MTTrustAll
					[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]'Tls12,Tls11,Tls'
				}
				$ports = 21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 515, 554, 631, 902, 3389, 5000, 5001, 5900, 8000, 8006, 8080, 8443, 9100, 37777
				$hostList = @($live.Keys | Sort-Object { ConvertTo-UInt32Ip $_ })
				$idx = 0
				try {
					foreach ($ip in $hostList) {
						$idx++
						Write-Progress -Activity 'LAN scan' -Status ('{0} ({1} of {2})' -f $ip, $idx, $hostList.Count) -PercentComplete (100 * $idx / [math]::Max(1, $hostList.Count))
						$open = @(Get-OpenPorts -Ip $ip -Ports $ports)
						$dnsName = $null
						try { $dnsName = [System.Net.Dns]::GetHostEntry($ip).HostName } catch { $dnsName = $null }
						$nb = $null
						if ($open -contains 445 -or $open -contains 139) {
							try {
								$m = nbtstat -A $ip 2>&1 | Select-String -Pattern '^\s+(\S+)\s+<00>\s+UNIQUE' | Select-Object -First 1
								if ($m) { $nb = $m.Matches[0].Groups[1].Value }
							} catch {
								$nb = $null
							}
						}
						$banner = $null
						foreach ($wp in 443, 80, 8443, 8080, 5001, 5000, 8006) {
							if (-not $banner -and $open -contains $wp) { $banner = Get-WebBanner -Ip $ip -Port $wp }
						}
						$macAddr = $mac[$ip]
						if (-not $macAddr -and $ip -eq $myIp) { $macAddr = $cfg.MACAddress }
						$isGw = [bool]($ip -eq $gw)
						$oui = $null
						if ($macAddr) { $oui = (($macAddr -replace '[:\-]', '').Substring(0, 6)).ToUpper() }
						[pscustomobject]@{
							IP = $ip
							MAC = $macAddr
							OUI = $oui
							Hostname = $dnsName
							NetBIOS = $nb
							IsThisServer = [bool]($ip -eq $myIp)
							IsGateway = $isGw
							IsDhcpServer = [bool]($ip -eq $dhcp)
							OpenPorts = ($open -join ',')
							WebUrl = $(if ($banner) { $banner.Url } else { $null })
							WebStatus = $(if ($banner) { $banner.Status } else { $null })
							WebServer = $(if ($banner) { $banner.Server } else { $null })
							WebAuthRealm = $(if ($banner) { $banner.AuthRealm } else { $null })
							WebTitle = $(if ($banner) { $banner.Title } else { $null })
							LikelyType = (Get-LikelyType -Open $open -IsGateway $isGw)
						}
					}
				} finally {
					Write-Progress -Activity 'LAN scan' -Completed
					if ($isDesktop) {
						[System.Net.ServicePointManager]::CertificatePolicy = $prevPolicy
						[System.Net.ServicePointManager]::SecurityProtocol = $prevProto
					}
				}
			}
		}

		# ------------------------------------------------------------ findings
		Invoke-Section 'Findings' {
			$list = New-Object System.Collections.ArrayList
			$add = {
				param([string]$Severity, [string]$Area, [string]$Finding, [string]$Detail)
				[void]$list.Add([pscustomobject]@{ Severity = $Severity; Area = $Area; Finding = $Finding; Detail = $Detail })
			}
			$now = Get-Date

			$sys = Get-SectionRows 'System' | Select-Object -First 1
			if ($sys) {
				$build = [int]$sys.BuildNumber
				if ([int]$sys.ProductType -ne 1) {
					if ($build -lt 14393) { & $add 'High' 'OS' 'Server OS is past end of support' $sys.OSCaption }
					elseif ($build -eq 14393) {
						$sev = if ($now -ge [datetime]'2027-01-12') { 'High' } else { 'Medium' }
						& $add $sev 'OS' 'Windows Server 2016 extended support ends 2027-01-12' $sys.OSCaption
					}
				} elseif ($build -lt 22000 -and $sys.OSCaption -match 'LTS') {
					& $add 'Low' 'OS' 'Windows 10 LTSC/LTSB edition (confirm its lifecycle date)' $sys.OSCaption
				} elseif ($build -lt 22000) {
					& $add 'High' 'OS' 'Windows 10 or older client OS (Windows 10 support ended 2025-10-14)' $sys.OSCaption
				}
				if ($sys.UptimeDays -gt 60) { & $add 'Medium' 'Patching' ('No reboot in {0} days' -f [int]$sys.UptimeDays) 'Monthly updates usually require a reboot' }
			}

			foreach ($l in (Get-SectionRows 'WindowsLicense')) { if ($l.LicenseStatus -ne 1) { & $add 'Medium' 'OS' 'Windows is not activated' ('{0}: {1}' -f $l.Name, $l.LicenseStatusText) } }
			$ts = Get-SectionRows 'TimeSync' | Select-Object -First 1
			if ($ts -and $ts.TimeSource -match 'Local CMOS Clock|Free-running') { & $add 'Medium' 'Time' 'Time source is the local clock' $ts.TimeSource }

			$pr = Get-SectionRows 'PendingReboot' | Select-Object -First 1
			if ($pr -and ($pr.ComponentBasedServicing -or $pr.WindowsUpdate -or $pr.PendingFileRename)) { & $add 'Low' 'Patching' 'Reboot pending' '' }

			foreach ($v in (Get-SectionRows 'Volumes')) {
				if ($null -ne $v.PctFree -and $v.PctFree -lt 5) { & $add 'High' 'Storage' ('{0} has {1}% free' -f $v.Drive, $v.PctFree) ('{0} GB free of {1} GB' -f $v.FreeGB, $v.SizeGB) }
				elseif ($null -ne $v.PctFree -and $v.PctFree -lt 15) { & $add 'Medium' 'Storage' ('{0} has {1}% free' -f $v.Drive, $v.PctFree) ('{0} GB free of {1} GB' -f $v.FreeGB, $v.SizeGB) }
			}
			foreach ($p in (Get-SectionRows 'PhysicalDiskHealth')) { if ($p.Health -and $p.Health -ne 'Healthy') { & $add 'High' 'Storage' ('Physical disk {0} is {1}' -f $p.Name, $p.Health) $p.Operational } }
			foreach ($e in (Get-SectionRows 'SystemHealthEvents')) {
				if (@(7, 11, 51, 129, 153, 157) -contains [int]$e.EventId) { & $add 'Medium' 'Storage' ('Disk/controller event {0} ({1}) x{2}' -f $e.EventId, $e.Provider, $e.Count) $e.Sample }
				if (@(41, 6008) -contains [int]$e.EventId) { & $add 'Medium' 'Stability' ('Unexpected shutdowns (event {0}) x{1}' -f $e.EventId, $e.Count) ('Last: {0}' -f $e.Last) }
			}

			$notable = Get-SectionRows 'NotableSoftware'
			# Only real AV/EDR engines count here, not DNS filters or other security add-ons
			$avRx = 'Sophos|SentinelOne|CrowdStrike|Carbon Black|Webroot|Malwarebytes|McAfee|Trellix|Norton|Symantec|Kaspersky|\bESET\b|Trend Micro|Bitdefender|Cylance|Avast|\bAVG\b|Vipre|Cortex XDR|Blackpoint'
			$thirdPartyAv = @($notable | Where-Object { $_.Category -eq 'Security' -and $_.Name -match $avRx })
			$def = Get-SectionRows 'Defender' | Select-Object -First 1
			$defOn = ($def -and $def.RealTimeProtection -eq $true)
			if ($thirdPartyAv.Count -eq 0 -and -not $defOn) { & $add 'High' 'Security' 'No active antivirus detected' 'No third-party security product found and Defender real-time protection is off or missing' }
			if ($defOn -and $def.SignatureLastUpdated -and ($now - [datetime]$def.SignatureLastUpdated).TotalDays -gt 7) { & $add 'Medium' 'Security' 'Defender signatures older than 7 days' ('Last updated {0}' -f $def.SignatureLastUpdated) }
			if ($def -and ($def.ExclusionPaths -or $def.ExclusionProcesses -or $def.ExclusionExtensions)) { & $add 'Low' 'Security' 'Defender exclusions configured (review)' ('Paths: {0} | Processes: {1} | Extensions: {2}' -f $def.ExclusionPaths, $def.ExclusionProcesses, $def.ExclusionExtensions) }
			$threats = @(Get-SectionRows 'DefenderThreats')
			if ($threats.Count -gt 0) { & $add 'Medium' 'Security' ('{0} Defender threat detections on record' -f $threats.Count) (($threats | Select-Object -First 5 | ForEach-Object { $_.Threat }) -join '; ') }

			foreach ($f in (Get-SectionRows 'FirewallProfiles')) { if ($f.Enabled -eq 'False') { & $add 'Medium' 'Security' ('Windows Firewall {0} profile is disabled' -f $f.Profile) '' } }
			$smb = Get-SectionRows 'SmbServerConfig' | Select-Object -First 1
			if ($smb -and $smb.SMB1Enabled) { & $add 'High' 'Security' 'SMBv1 server protocol is enabled' 'Disable after confirming no legacy devices (old copiers/NAS) depend on it' }
			$sec = Get-SectionRows 'SecuritySettings' | Select-Object -First 1
			if ($sec) {
				if ([string]$sec.AutoAdminLogon -eq '1') { & $add 'High' 'Security' 'Automatic logon (AutoAdminLogon) is enabled' '' }
				if ($sec.DefaultPasswordStoredInRegistry) { & $add 'High' 'Security' 'A plain-text DefaultPassword is stored in the Winlogon registry key' 'Value not collected' }
				if ([string]$sec.WDigestUseLogonCredential -eq '1') { & $add 'High' 'Security' 'WDigest stores logon credentials in memory' 'UseLogonCredential=1' }
				if ($sec.RdpEnabled -and [string]$sec.RdpNLA -ne '1') { & $add 'Medium' 'Security' 'RDP is enabled without Network Level Authentication' '' }
				if ($null -ne $sec.LmCompatibilityLevel -and [int]$sec.LmCompatibilityLevel -lt 3) { & $add 'Medium' 'Security' ('LmCompatibilityLevel is {0} (LM/NTLMv1 allowed)' -f $sec.LmCompatibilityLevel) '' }
				if ([string]$sec.EnableLUA -eq '0') { & $add 'Medium' 'Security' 'UAC is disabled (EnableLUA=0)' '' }
				if (-not $sec.LlmnrDisabledByPolicy) { & $add 'Low' 'Security' 'LLMNR is not disabled by policy' '' }
				if ($computerSystem.PartOfDomain -and $sec.LapsPolicy -eq 'None found') { & $add 'Low' 'Security' 'No LAPS policy applied to this server' '' }
			}
			$publicRdp = @(Get-SectionRows 'RdpConnections' | Where-Object { $_.PublicIp })
			if ($publicRdp.Count -gt 0) { & $add 'High' 'Security' 'RDP logons from public IP addresses (RDP may be exposed to the internet)' (($publicRdp | Select-Object -First 10 | ForEach-Object { '{0} from {1}' -f $_.User, $_.Ip }) -join '; ') }
			$publicFail = @(Get-SectionRows 'FailedLogons' | Where-Object { $_.PublicIp })
			if ($publicFail.Count -gt 0) { & $add 'High' 'Security' 'Failed logons from public IP addresses' ('{0} user/IP combinations, {1} attempts' -f $publicFail.Count, ($publicFail | Measure-Object Count -Sum).Sum) }
			if (@(Get-SectionRows 'AccountChanges' | Where-Object { $_.EventId -eq 1102 }).Count -gt 0) { & $add 'Medium' 'Security' 'Security event log was cleared (event 1102)' '' }
			foreach ($c in (Get-SectionRows 'Certificates')) {
				if ($c.HasPrivateKey -and $c.DaysLeft -lt 30 -and $c.Issuer -ne $c.Subject) { & $add $(if ($c.DaysLeft -lt 0) { 'Medium' } else { 'Low' }) 'Certificates' ('Certificate expires in {0} days' -f $c.DaysLeft) $c.Subject }
			}
			$svcAccts = @(Get-SectionRows 'Services' | Where-Object { $_.RunAs -and $_.RunAs -notmatch '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\|\.\\LocalSystem)' -and $_.RunAs -notmatch '^(LocalService|NetworkService)$|\$$' })
			if ($svcAccts.Count -gt 0) { & $add 'Low' 'Accounts' 'Services run under named accounts (password changes will break them)' (($svcAccts | ForEach-Object { '{0} as {1}' -f $_.Name, $_.RunAs }) -join '; ') }
			$taskAccts = @(Get-SectionRows 'ScheduledTasks' | Where-Object { $_.LogonType -eq 'Password' })
			if ($taskAccts.Count -gt 0) { & $add 'Low' 'Accounts' 'Scheduled tasks store account passwords' (($taskAccts | ForEach-Object { '{0} as {1}' -f $_.TaskName, $_.RunAs }) -join '; ') }

			$remote = @($notable | Where-Object { $_.Category -eq 'RemoteAccess' -and $_.Source -eq 'Software' } | ForEach-Object { $_.Name } | Sort-Object -Unique)
			if ($remote.Count -gt 0) { & $add 'Info' 'Onboarding' 'Remote access / RMM tools present (remove the previous provider''s tools)' ($remote -join '; ') }

			$backupSw = @($notable | Where-Object { $_.Category -eq 'Backup' })
			$wsb = Get-SectionRows 'WindowsServerBackup' | Select-Object -First 1
			$wsbOk = ($wsb -and $wsb.LastSuccessfulBackup -and ($now - [datetime]$wsb.LastSuccessfulBackup).TotalDays -le 2)
			if ($backupSw.Count -eq 0 -and -not $wsbOk) { & $add 'High' 'Backup' 'No backup software or recent Windows Server Backup detected' 'Cloud sync tools (OneDrive, Dropbox) are not backups' }
			if ($wsb -and $wsb.LastSuccessfulBackup -and -not $wsbOk) { & $add 'Medium' 'Backup' 'Windows Server Backup last succeeded more than 2 days ago' ([string]$wsb.LastSuccessfulBackup) }
			if (@(Get-SectionRows 'ShadowCopies').Count -eq 0) { & $add 'Low' 'Backup' 'No shadow copies (Previous Versions) on any volume' '' }
			foreach ($w in (Get-SectionRows 'VssWriters')) { if ($w.State -notmatch 'Stable' -or $w.LastError -notmatch 'No error') { & $add 'Medium' 'Backup' ('VSS writer {0} is {1}' -f $w.Name, $w.State) $w.LastError } }
			foreach ($db in (Get-SectionRows 'SqlDatabases')) {
				if (-not $db.State -or $db.Database -eq 'tempdb') { continue }
				if (-not $db.LastFull -or ($now - [datetime]$db.LastFull).TotalDays -gt 7) { & $add 'High' 'SQL' ('{0}\{1} has no full backup in 7 days' -f $db.Instance, $db.Database) ('Last full: {0}' -f $db.LastFull) }
				if ($db.Recovery -eq 'FULL' -and (-not $db.LastLog -or ($now - [datetime]$db.LastLog).TotalDays -gt 2)) { & $add 'Medium' 'SQL' ('{0}\{1} is in FULL recovery without recent log backups (log growth)' -f $db.Instance, $db.Database) ('Log size {0} MB' -f $db.LogMB) }
				if ($db.Edition -match 'Express' -and $db.DataMB -gt 8192) { & $add 'Medium' 'SQL' ('{0}\{1} is near the SQL Express 10 GB data limit' -f $db.Instance, $db.Database) ('{0} MB' -f $db.DataMB) }
			}
			foreach ($q in (Get-SectionRows 'SqlDatabases' | Where-Object { -not $_.State })) { & $add 'Info' 'SQL' ('Could not query SQL instance {0}' -f $q.Instance) $q.Database }

			$pending = @(Get-SectionRows 'PendingUpdates')
			if ($pending.Count -gt 0) { & $add 'Medium' 'Patching' ('{0} updates pending' -f $pending.Count) (($pending | Select-Object -First 5 | ForEach-Object { $_.Title }) -join '; ') }
			$hf = Get-SectionRows 'Hotfixes' | Where-Object { $_.InstalledOn } | Sort-Object { [datetime]$_.InstalledOn } -Descending | Select-Object -First 1
			if ($hf -and ($now - [datetime]$hf.InstalledOn).TotalDays -gt 60) { & $add 'Medium' 'Patching' ('Last update installed {0} days ago' -f [int]($now - [datetime]$hf.InstalledOn).TotalDays) $hf.HotFixID }
			$wup = Get-SectionRows 'WindowsUpdatePolicy' | Select-Object -First 1
			if ($wup -and $wup.WSUSServer) { & $add 'Info' 'Patching' 'Updates are pointed at a WSUS server' $wup.WSUSServer }
			if ($wup -and [string]$wup.NoAutoUpdate -eq '1') { & $add 'Medium' 'Patching' 'Automatic updates are disabled by policy' '' }

			foreach ($s in (Get-SectionRows 'DhcpScopes')) { if ($s.PercentInUse -gt 90) { & $add 'Medium' 'Network' ('DHCP scope {0} is {1}% used' -f $s.ScopeId, [int]$s.PercentInUse) ('{0} free' -f $s.Free) } }
			foreach ($vm in (Get-SectionRows 'HyperVVMs')) { if ($vm.Checkpoints -gt 0) { & $add 'Medium' 'Hyper-V' ('VM {0} has {1} checkpoint(s)' -f $vm.Name, $vm.Checkpoints) 'Old checkpoints grow differencing disks and hurt performance' } }
			$legacy = @(Get-SectionRows 'LanHosts' | Where-Object { $_.OpenPorts -match '(^|,)(21|23)(,|$)' })
			if ($legacy.Count -gt 0) { & $add 'Low' 'Network' 'LAN devices with Telnet or FTP open' (($legacy | ForEach-Object { '{0} ({1})' -f $_.IP, $_.LikelyType }) -join '; ') }

			if ($adInfo) {
				$users = Get-SectionRows 'ADUsers' | Where-Object { $_.Enabled }
				$da = @(Get-SectionRows 'ADPrivilegedUsers' | Where-Object { $_.Group -eq 'Domain Admins' -and $_.Enabled })
				if ($da.Count -gt 5) { & $add 'Medium' 'AD' ('{0} enabled Domain Admins' -f $da.Count) (($da | ForEach-Object { $_.Account }) -join ', ') }
				$pne = @($users | Where-Object { $_.PasswordNeverExpires })
				if ($pne.Count -gt 0) { & $add 'Low' 'AD' ('{0} enabled users with password never expires' -f $pne.Count) (($pne | Select-Object -First 25 | ForEach-Object { $_.Account }) -join ', ') }
				$pnr = @($users | Where-Object { $_.PasswordNotRequired })
				if ($pnr.Count -gt 0) { & $add 'Medium' 'AD' ('{0} enabled users flagged password-not-required' -f $pnr.Count) (($pnr | ForEach-Object { $_.Account }) -join ', ') }
				$staleU = @($users | Where-Object { $null -eq $_.DaysSinceLogon -or $_.DaysSinceLogon -gt 90 })
				if ($staleU.Count -gt 0) { & $add 'Low' 'AD' ('{0} enabled users with no logon in 90 days' -f $staleU.Count) (($staleU | Select-Object -First 25 | ForEach-Object { $_.Account }) -join ', ') }
				$staleC = @(Get-SectionRows 'ADComputers' | Where-Object { $_.Enabled -and ($null -eq $_.DaysSinceLogon -or $_.DaysSinceLogon -gt 90) })
				if ($staleC.Count -gt 0) { & $add 'Low' 'AD' ('{0} enabled computers with no logon in 90 days' -f $staleC.Count) (($staleC | Select-Object -First 25 | ForEach-Object { $_.Name }) -join ', ') }
				$oldOs = @(Get-SectionRows 'ADComputers' | Where-Object { $_.Enabled -and $null -ne $_.DaysSinceLogon -and $_.DaysSinceLogon -le 90 -and $_.OS -match 'Windows (XP|Vista|7|8|2000|Server 2003|Server 2008|Server 2012)' })
				if ($oldOs.Count -gt 0) { & $add 'High' 'AD' ('{0} active computers on unsupported Windows versions' -f $oldOs.Count) (($oldOs | ForEach-Object { '{0} ({1})' -f $_.Name, $_.OS }) -join '; ') }
				$addom = Get-SectionRows 'ADDomain' | Select-Object -First 1
				if ($addom) {
					if ($addom.RecycleBinEnabled -eq $false) { & $add 'Low' 'AD' 'AD Recycle Bin is not enabled' '' }
					if ($null -ne $addom.MachineAccountQuota -and [int]$addom.MachineAccountQuota -gt 0) { & $add 'Low' 'AD' ('ms-DS-MachineAccountQuota is {0} (any user can join computers)' -f $addom.MachineAccountQuota) '' }
					if ($null -ne $addom.MinPasswordLength -and [int]$addom.MinPasswordLength -lt 12) { & $add 'Medium' 'AD' ('Domain minimum password length is {0}' -f $addom.MinPasswordLength) '' }
					if ([string]$addom.LockoutThreshold -eq '0') { & $add 'Medium' 'AD' 'No account lockout threshold' '' }
				}
			}

			foreach ($d in $PublicDomain) {
				$recs = @(Get-SectionRows 'PublicDns' | Where-Object { $_.Domain -eq $d })
				if (-not ($recs | Where-Object { $_.Query -eq $d -and $_.Type -eq 'TXT' -and $_.Value -match '^v=spf1' })) { & $add 'Medium' 'Email' ('{0} has no SPF record' -f $d) '' }
				$dmarc = $recs | Where-Object { $_.Query -like '_dmarc.*' -and $_.Value -match '^v=DMARC1' } | Select-Object -First 1
				if (-not $dmarc) { & $add 'Medium' 'Email' ('{0} has no DMARC record' -f $d) '' }
				elseif ($dmarc.Value -match 'p=none') { & $add 'Low' 'Email' ('{0} DMARC policy is p=none (monitor only)' -f $d) $dmarc.Value }
			}

			$order = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
			$list | Sort-Object { $order[$_.Severity] }, Area
		}

		# ------------------------------------------------------------ write results
		Write-Host 'Writing summary and JSON...' -ForegroundColor Cyan
		$sys = Get-SectionRows 'System' | Select-Object -First 1
		$findings = Get-SectionRows 'Findings'
		$lines = New-Object System.Collections.ArrayList
		[void]$lines.Add('CLIENT DISCOVERY SUMMARY')
		[void]$lines.Add(('Run: {0} by {1}\{2}' -f $started.ToString('yyyy-MM-dd HH:mm'), $env:USERDOMAIN, $env:USERNAME))
		if ($sys) {
			[void]$lines.Add(('Host: {0}  Domain/Workgroup: {1}  Joined: {2}' -f $sys.ComputerName, $sys.DomainOrWorkgroup, $sys.PartOfDomain))
			[void]$lines.Add(('OS: {0} ({1}) build {2}.{3}  Uptime: {4} days' -f $sys.OSCaption, $sys.OSVersion, $sys.BuildNumber, $sys.UBR, $sys.UptimeDays))
			[void]$lines.Add(('Hardware: {0} {1}  Serial: {2}  Virtual: {3}' -f $sys.Manufacturer, $sys.Model, $sys.SerialNumber, $sys.LooksVirtual))
			[void]$lines.Add(('CPU: {0}  Cores: {1}  RAM: {2} GB' -f $sys.CpuName, $sys.CpuCores, $sys.RamGB))
		}
		foreach ($n in (Get-SectionRows 'NetConfig')) { [void]$lines.Add(('NIC: {0}  IP {1}  Mask {2}  GW {3}  DNS {4}  DHCP {5}' -f $n.Adapter, $n.IPAddress, $n.SubnetMask, $n.DefaultGateway, $n.DnsServers, $n.DhcpServer)) }
		$pub = Get-SectionRows 'PublicIP' | Select-Object -First 1
		if ($pub) { [void]$lines.Add(('Public IP: {0}  Org: {1}  Reverse DNS: {2}' -f $pub.Ip, $pub.Org, $pub.ReverseDns)) }
		foreach ($v in (Get-SectionRows 'Volumes')) { [void]$lines.Add(('Volume {0} {1}: {2} GB, {3} GB free' -f $v.Drive, $v.Label, $v.SizeGB, $v.FreeGB)) }
		foreach ($s in $userShares) { [void]$lines.Add(('Share: {0} -> {1}' -f $s.Name, $s.Path)) }
		$addom = Get-SectionRows 'ADDomain' | Select-Object -First 1
		if ($addom -and $addom.Domain) { [void]$lines.Add(('AD: {0} ({1})  Users: {2}  Computers: {3}  DCs: {4}' -f $addom.Domain, $addom.DomainMode, @(Get-SectionRows 'ADUsers').Count, @(Get-SectionRows 'ADComputers').Count, $addom.DomainControllers)) }
		foreach ($vm in (Get-SectionRows 'HyperVVMs')) { [void]$lines.Add(('VM: {0}  {1}  {2} vCPU  {3} GB' -f $vm.Name, $vm.State, $vm.vCPU, $vm.MemoryStartupGB)) }
		[void]$lines.Add(('Installed software entries: {0}' -f @(Get-SectionRows 'InstalledSoftware').Count))
		foreach ($x in (Get-SectionRows 'NotableSoftware')) { if ($x.Source -eq 'Software') { [void]$lines.Add(('  [{0}] {1} {2}' -f $x.Category, $x.Name, $x.Version)) } }
		foreach ($i in (Get-SectionRows 'SqlInstances')) { [void]$lines.Add(('SQL instance: {0}  {1}  {2}' -f $i.Instance, $i.Edition, $i.Version)) }
		[void]$lines.Add(('LAN hosts found: {0}' -f @(Get-SectionRows 'LanHosts' | Where-Object { $_.IP }).Count))
		[void]$lines.Add('')
		[void]$lines.Add(('FINDINGS: {0} High, {1} Medium, {2} Low, {3} Info' -f @($findings | Where-Object { $_.Severity -eq 'High' }).Count, @($findings | Where-Object { $_.Severity -eq 'Medium' }).Count, @($findings | Where-Object { $_.Severity -eq 'Low' }).Count, @($findings | Where-Object { $_.Severity -eq 'Info' }).Count))
		foreach ($f in $findings) {
			$line = '  [{0}] {1}: {2}' -f $f.Severity, $f.Area, $f.Finding
			if ($f.Detail) { $line += (' -- {0}' -f $f.Detail) }
			[void]$lines.Add($line)
		}
		[void]$lines.Add('')
		[void]$lines.Add(('Sections with errors: {0}' -f $errors.Count))
		foreach ($e in $errors) { [void]$lines.Add(('  {0}' -f $e)) }
		$lines | Set-Content -Path (Join-Path $outDir 'summary.txt') -Encoding UTF8
		if ($errors.Count -gt 0) { $errors | Set-Content -Path (Join-Path $outDir 'errors.txt') -Encoding UTF8 }

		try {
			$json = $result | ConvertTo-Json -Depth 6
			$json = [regex]::Replace($json, '\\/Date\((-?\d+)([+-]\d{4})?\)\\/', [System.Text.RegularExpressions.MatchEvaluator] {
					param($m)
					([datetime]::SpecifyKind([datetime]'1970-01-01', [DateTimeKind]::Utc)).AddMilliseconds([double]$m.Groups[1].Value).ToString('s') + 'Z'
				})
			Set-Content -Path (Join-Path $outDir 'discovery.json') -Value $json -Encoding UTF8
		} catch {
			Write-Host ('JSON export failed: {0}' -f $_.Exception.Message) -ForegroundColor Yellow
		}

		foreach ($f in ($findings | Where-Object { $_.Severity -eq 'High' })) { Write-Host ('  [High] {0}: {1}' -f $f.Area, $f.Finding) -ForegroundColor Red }
	} finally {
		if ($transcriptOn) {
			try { Stop-Transcript | Out-Null } catch { Write-Verbose 'Transcript stop failed' }
		}
	}

	$zip = Join-Path $OutputRoot ('{0}.zip' -f (Split-Path $outDir -Leaf))
	try {
		Compress-Archive -Path (Join-Path $outDir '*') -DestinationPath $zip -Force -ErrorAction Stop
		Protect-DiscoveryPath -Path $zip
		Write-Host ('DONE. Send this file: {0}' -f $zip) -ForegroundColor Green
	} catch {
		Write-Host ('Zip failed ({0}). Send the folder: {1}' -f $_.Exception.Message, $outDir) -ForegroundColor Yellow
		$zip = $null
	}
	Write-Host 'The output contains account names, group memberships, share names, computer names, and IP/MAC addresses.' -ForegroundColor Yellow
	Write-Host ('Delete both {0} and the zip from the server after delivery.' -f $outDir) -ForegroundColor Yellow

	Write-Output ([pscustomobject]@{
			OutputFolder = $outDir
			ZipFile = $zip
			Findings = @(Get-SectionRows 'Findings')
			Errors = @($errors)
		})
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

			# Check minimum file size (20 MB threshold - below this the overhead isn't worthwhile)
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
				# No access to outer scope - all values passed via parameters
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
							# EndInvoke returns a PSDataCollection - unwrap to the single result object
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

				# Evaluate segment results - if any failed, fall through to single-stream methods
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
					# All segments succeeded - merge temp files into the final file in order
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
	# Skipped if Sophos is running: certutil downloading files triggers Sophos false-positive detections.
	If (-not $Downloaded) {
		$SophosActive = [bool](Get-Service -Name '*Sophos*' -ErrorAction SilentlyContinue |
			Where-Object { $_.Status -eq 'Running' })
		If ($SophosActive) {
			Write-Verbose 'Skipping certutil method: Sophos antivirus is active (certutil download flagged as malicious).'
		} Else {
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
		Gets installed applications from the PowerShell Package Provider and Registry uninstall keys.

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

Function Get-DotNetFrameworkVersion {
	<#
	.SYNOPSIS
		Returns the highest installed .NET Framework 4.x version on the local machine.
	.DESCRIPTION
		Reads the Release DWORD from the .NET Framework Setup registry key and maps it to a friendly
		version number using Microsoft's documented Release thresholds (greater-than-or-equal match).
	.EXAMPLE
		Get-DotNetFrameworkVersion
	.OUTPUTS
		PSCustomObject with Release (int) and Version (string) properties.
	#>
	[CmdletBinding()]
	Param()

	$RegPath = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
	$Release = $null
	If (Test-Path $RegPath) {
		$Release = (Get-ItemProperty -Path $RegPath -Name Release -ErrorAction SilentlyContinue).Release
	}

	If ($null -eq $Release) {
		Return [PSCustomObject]@{ Release = $null; Version = 'Not detected (.NET 4.x missing)' }
	}

	# Newest first so the first qualifying threshold wins. Values are Microsoft's
	# documented minimum Release keys for each version.
	$Map = [ordered]@{
		533320 = '4.8.1'
		528040 = '4.8'
		461808 = '4.7.2'
		461308 = '4.7.1'
		460798 = '4.7'
		394802 = '4.6.2'
		394254 = '4.6.1'
		393295 = '4.6'
		379893 = '4.5.2'
		378675 = '4.5.1'
		378389 = '4.5'
	}

	$Version = "Unknown (Release $Release)"
	ForEach ($Key in $Map.Keys) {
		If ($Release -ge $Key) { $Version = $Map[$Key]; break }
	}

	[PSCustomObject]@{ Release = [int]$Release; Version = $Version }
}

Function Get-PowerShellHealth {
	<#
	.SYNOPSIS
		Runs a set of health and configuration checks against the local Windows PowerShell 5.1 environment.
	.DESCRIPTION
		Get-PowerShellHealth inspects engine version and patch level, .NET Framework version, execution
		policy (all scopes), language mode, TLS / strong crypto, PSModulePath integrity, PowerShellGet /
		PackageManagement / NuGet provider state, the PSGallery repository, PSReadLine, PowerShell logging
		policy, WinRM / remoting, profile scripts, free disk space, console encoding, session errors, and
		pending reboot.

		Each check is isolated in its own try / catch so one failure never aborts the rest of the report.
		By default a color coded report is written to the host. Use -PassThru to emit the result objects to
		the pipeline instead.
	.PARAMETER PassThru
		Returns the individual check results as objects on the pipeline instead of the console report.
	.EXAMPLE
		Get-PowerShellHealth
		Runs all checks and prints a color coded report to the console.
	.EXAMPLE
		Get-PowerShellHealth -PassThru | Where-Object { $_.Status -eq 'WARN' -or $_.Status -eq 'FAIL' }
		Returns only the checks that need attention.
	.EXAMPLE
		Get-PowerShellHealth -PassThru | Export-Csv C:\IT\Logs\PSHealth.csv -NoTypeInformation
		Captures the full result set to CSV.
	.OUTPUTS
		PSCustomObject (Category, Check, Status, Detail) when -PassThru is used.
	.NOTES
		Read only. Safe to run unelevated, though a few checks (WSMan listeners) report more detail when
		run from an elevated session.
		Related library functions: Enable-SSL (TLS 1.2 / strong crypto), Update-PowerShellModules,
		Test-IsElevated, Repair-Windows.
	#>
	[CmdletBinding()]
	Param(
		[switch]$PassThru
	)

	# Snapshot the session error count up front. The probing below uses -ErrorAction
	# SilentlyContinue and try / catch, both of which still append to $Error, so reading
	# $Error.Count after the checks would mostly reflect this function's own activity.
	$InitialErrorCount = $Error.Count

	$Results = [System.Collections.Generic.List[object]]::new()

	# Nested helper: record one result row into $Results.
	Function Add-Result {
		Param([string]$Category, [string]$Check, [string]$Status, [string]$Detail)
		$Results.Add([PSCustomObject]@{
			Category = $Category
			Check    = $Check
			Status   = $Status
			Detail   = $Detail
		})
	}

	# Elevation state (a few checks report more detail when elevated).
	$IsElevated = $false
	Try {
		$IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	} Catch { }

	#region Engine
	Try {
		$PSV = $PSVersionTable.PSVersion
		$Edition = If ($PSVersionTable.PSEdition) { $PSVersionTable.PSEdition } Else { 'Desktop' }
		If ($PSV.Major -eq 5 -and $PSV.Minor -eq 1) {
			Add-Result 'Engine' 'PowerShell version' 'PASS' "$PSV ($Edition edition), host $($Host.Name)"
		} ElseIf ($PSV.Major -eq 5) {
			Add-Result 'Engine' 'PowerShell version' 'WARN' "$PSV detected. WMF 5.1 (5.1.x) is recommended on Windows."
		} Else {
			Add-Result 'Engine' 'PowerShell version' 'INFO' "$PSV ($Edition). This check targets Windows PowerShell 5.1."
		}
		Write-Verbose "Detected PowerShell $PSV ($Edition)"
		Add-Result 'Engine' 'CLR version' 'INFO' "$($PSVersionTable.CLRVersion)"
	} Catch {
		Add-Result 'Engine' 'PowerShell version' 'FAIL' $_.Exception.Message
	}
	#endregion

	#region .NET Framework
	Try {
		$Net = Get-DotNetFrameworkVersion
		If ($null -eq $Net.Release) {
			Add-Result '.NET' '.NET Framework 4.x' 'FAIL' 'No .NET Framework 4.x detected. WMF 5.1 requires at least 4.5.2.'
		} ElseIf ($Net.Release -lt 379893) {
			Add-Result '.NET' '.NET Framework 4.x' 'WARN' "Version $($Net.Version) (Release $($Net.Release)). Below the 4.5.2 minimum for WMF 5.1."
		} ElseIf ($Net.Release -lt 461808) {
			Add-Result '.NET' '.NET Framework 4.x' 'WARN' "Version $($Net.Version). Meets minimum, but 4.7.2 or newer is recommended."
		} Else {
			Add-Result '.NET' '.NET Framework 4.x' 'PASS' "Version $($Net.Version) (Release $($Net.Release))."
		}
	} Catch {
		Add-Result '.NET' '.NET Framework 4.x' 'FAIL' $_.Exception.Message
	}
	#endregion

	#region Execution policy
	Try {
		ForEach ($P in (Get-ExecutionPolicy -List)) {
			$St = 'INFO'
			If (($P.ExecutionPolicy -eq 'Unrestricted' -or $P.ExecutionPolicy -eq 'Bypass') -and ($P.Scope -eq 'LocalMachine' -or $P.Scope -eq 'CurrentUser')) { $St = 'WARN' }
			Add-Result 'ExecutionPolicy' "Scope $($P.Scope)" $St "$($P.ExecutionPolicy)"
		}
		$Effective = Get-ExecutionPolicy
		If ($Effective -eq 'Restricted') {
			Add-Result 'ExecutionPolicy' 'Effective policy' 'WARN' "$Effective (scripts blocked; RemoteSigned is typical for managed endpoints)."
		} Else {
			Add-Result 'ExecutionPolicy' 'Effective policy' 'PASS' "$Effective"
		}
	} Catch {
		Add-Result 'ExecutionPolicy' 'Execution policy' 'FAIL' $_.Exception.Message
	}
	#endregion

	#region Language mode
	Try {
		$Lang = $ExecutionContext.SessionState.LanguageMode
		If ($Lang -eq 'FullLanguage') {
			Add-Result 'Security' 'Language mode' 'PASS' "$Lang"
		} Else {
			Add-Result 'Security' 'Language mode' 'WARN' "$Lang. Constrained or restricted language usually means AppLocker or WDAC is active and may block scripts."
		}
	} Catch {
		Add-Result 'Security' 'Language mode' 'FAIL' $_.Exception.Message
	}
	#endregion

	#region TLS / strong crypto
	Try {
		$Protocols = [Net.ServicePointManager]::SecurityProtocol
		If ($Protocols -band [Net.SecurityProtocolType]::Tls12) {
			Add-Result 'TLS' 'Session security protocol' 'PASS' "Includes TLS 1.2 ($Protocols)."
		} ElseIf ([int]$Protocols -eq 0) {
			Add-Result 'TLS' 'Session security protocol' 'INFO' 'SystemDefault. The OS selects the protocol (TLS 1.2 / 1.3 on current Windows).'
		} Else {
			Add-Result 'TLS' 'Session security protocol' 'WARN' "$Protocols. TLS 1.2 not enabled in this session. Run Enable-SSL or set [Net.ServicePointManager]::SecurityProtocol."
		}

		$CryptoPaths = @(
			'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
			'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319'
		)
		$Missing = @()
		ForEach ($CP in $CryptoPaths) {
			If (Test-Path $CP) {
				$Val = (Get-ItemProperty -Path $CP -Name 'SchUseStrongCrypto' -ErrorAction SilentlyContinue).SchUseStrongCrypto
				If ($Val -ne 1) { $Missing += $CP }
			}
		}
		If ($Missing.Count -eq 0) {
			Add-Result 'TLS' 'SchUseStrongCrypto (machine)' 'PASS' 'Strong crypto enabled for .NET 4.x.'
		} Else {
			Add-Result 'TLS' 'SchUseStrongCrypto (machine)' 'WARN' "Not set on: $($Missing -join '; '). Run Enable-SSL to set this persistently."
		}
	} Catch {
		Add-Result 'TLS' 'TLS / strong crypto' 'FAIL' $_.Exception.Message
	}
	#endregion

	#region PSModulePath
	Try {
		$Paths = $env:PSModulePath -split ';' | Where-Object { $_ }
		$Bad = @()
		ForEach ($Pa in $Paths) {
			If (-not (Test-Path $Pa)) { $Bad += $Pa }
		}
		If ($Bad.Count -eq 0) {
			Add-Result 'Modules' 'PSModulePath' 'PASS' "$($Paths.Count) path(s), all present."
		} Else {
			Add-Result 'Modules' 'PSModulePath' 'WARN' "$($Bad.Count) of $($Paths.Count) path(s) missing: $($Bad -join '; ')"
		}
	} Catch {
		Add-Result 'Modules' 'PSModulePath' 'FAIL' $_.Exception.Message
	}
	#endregion

	#region PowerShellGet / PackageManagement
	Try {
		$PSGet = Get-Module PowerShellGet -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
		If ($PSGet) {
			If ($PSGet.Version -lt [version]'2.2.5') {
				Add-Result 'Modules' 'PowerShellGet' 'WARN' "v$($PSGet.Version). Inbox version is old; v2.2.5+ is recommended for reliable Gallery and TLS support."
			} Else {
				Add-Result 'Modules' 'PowerShellGet' 'PASS' "v$($PSGet.Version)"
			}
		} Else {
			Add-Result 'Modules' 'PowerShellGet' 'WARN' 'Not found.'
		}

		$PkgMgmt = Get-Module PackageManagement -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
		If ($PkgMgmt) {
			If ($PkgMgmt.Version -lt [version]'1.4.7') {
				Add-Result 'Modules' 'PackageManagement' 'WARN' "v$($PkgMgmt.Version). v1.4.7+ is recommended."
			} Else {
				Add-Result 'Modules' 'PackageManagement' 'PASS' "v$($PkgMgmt.Version)"
			}
		} Else {
			Add-Result 'Modules' 'PackageManagement' 'WARN' 'Not found.'
		}
	} Catch {
		Add-Result 'Modules' 'PowerShellGet / PackageManagement' 'FAIL' $_.Exception.Message
	}
	#endregion

	#region NuGet provider
	Try {
		$Nuget = Get-PackageProvider -ListAvailable -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'NuGet' } | Sort-Object Version -Descending | Select-Object -First 1
		If ($Nuget) {
			Add-Result 'Modules' 'NuGet provider' 'PASS' "v$($Nuget.Version) installed (required for Install-Module)."
		} Else {
			Add-Result 'Modules' 'NuGet provider' 'WARN' 'Not installed. Install-Module will prompt to bootstrap it.'
		}
	} Catch {
		Add-Result 'Modules' 'NuGet provider' 'INFO' 'Could not query package providers in this session.'
	}
	#endregion

	#region PSGallery
	Try {
		$Gallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
		If ($Gallery) {
			If ($Gallery.InstallationPolicy -eq 'Trusted') {
				Add-Result 'Modules' 'PSGallery repository' 'PASS' 'Registered, InstallationPolicy=Trusted.'
			} Else {
				Add-Result 'Modules' 'PSGallery repository' 'INFO' "Registered, InstallationPolicy=$($Gallery.InstallationPolicy)."
			}
		} Else {
			Add-Result 'Modules' 'PSGallery repository' 'WARN' 'PSGallery is not registered.'
		}
	} Catch {
		Add-Result 'Modules' 'PSGallery repository' 'INFO' 'Could not query PSRepository.'
	}
	#endregion

	#region PSReadLine
	Try {
		$PSRL = Get-Module PSReadLine -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
		If ($PSRL) {
			If ($PSRL.Version -lt [version]'2.0.0') {
				Add-Result 'Console' 'PSReadLine' 'WARN' "v$($PSRL.Version). Older 1.x builds have known console rendering bugs; v2.x is recommended."
			} Else {
				Add-Result 'Console' 'PSReadLine' 'PASS' "v$($PSRL.Version)"
			}
		} Else {
			Add-Result 'Console' 'PSReadLine' 'INFO' 'Not available.'
		}
	} Catch {
		Add-Result 'Console' 'PSReadLine' 'INFO' $_.Exception.Message
	}
	#endregion

	#region Logging policy
	Try {
		$Base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
		$SBL = (Get-ItemProperty -Path "$Base\ScriptBlockLogging" -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging
		$Trans = (Get-ItemProperty -Path "$Base\Transcription" -Name 'EnableTranscripting' -ErrorAction SilentlyContinue).EnableTranscripting
		$ModLog = (Get-ItemProperty -Path "$Base\ModuleLogging" -Name 'EnableModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging
		Add-Result 'Logging' 'Script block logging' 'INFO' $(If ($SBL -eq 1) { 'Enabled' } Else { 'Not enabled' })
		Add-Result 'Logging' 'Transcription' 'INFO' $(If ($Trans -eq 1) { 'Enabled' } Else { 'Not enabled' })
		Add-Result 'Logging' 'Module logging' 'INFO' $(If ($ModLog -eq 1) { 'Enabled' } Else { 'Not enabled' })
	} Catch {
		Add-Result 'Logging' 'PowerShell logging policy' 'INFO' 'Could not read logging policy.'
	}
	#endregion

	#region WinRM / remoting
	Try {
		$WinRM = Get-Service -Name WinRM -ErrorAction SilentlyContinue
		If ($WinRM -and $WinRM.Status -eq 'Running') {
			$Detail = 'Service running'
			If ($IsElevated) {
				$ListenerCount = 0
				Try { $ListenerCount = @(Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue).Count } Catch { }
				$Detail += ", $ListenerCount listener(s)"
			} Else {
				$Detail += ' (run elevated to enumerate listeners)'
			}
			Add-Result 'Remoting' 'WinRM / PSRemoting' 'PASS' $Detail
		} ElseIf ($WinRM) {
			Add-Result 'Remoting' 'WinRM / PSRemoting' 'INFO' "WinRM service is $($WinRM.Status). Remoting not active (often expected on workstations)."
		} Else {
			Add-Result 'Remoting' 'WinRM / PSRemoting' 'INFO' 'WinRM service not present.'
		}
	} Catch {
		Add-Result 'Remoting' 'WinRM / PSRemoting' 'INFO' $_.Exception.Message
	}
	#endregion

	#region Profiles
	Try {
		$ProfileMap = [ordered]@{
			'AllUsersAllHosts'       = $PROFILE.AllUsersAllHosts
			'AllUsersCurrentHost'    = $PROFILE.AllUsersCurrentHost
			'CurrentUserAllHosts'    = $PROFILE.CurrentUserAllHosts
			'CurrentUserCurrentHost' = $PROFILE.CurrentUserCurrentHost
		}
		$Found = @()
		ForEach ($Name in $ProfileMap.Keys) {
			If (Test-Path $ProfileMap[$Name]) { $Found += $Name }
		}
		If ($Found.Count -eq 0) {
			Add-Result 'Profiles' 'Profile scripts' 'INFO' 'No profile scripts present.'
		} Else {
			Add-Result 'Profiles' 'Profile scripts' 'INFO' "Present: $($Found -join ', '). Review these if the session behaves oddly at startup."
		}
	} Catch {
		Add-Result 'Profiles' 'Profile scripts' 'INFO' $_.Exception.Message
	}
	#endregion

	#region Disk space
	Try {
		$SysDrive = $env:SystemDrive.TrimEnd('\', ':')
		$Drive = Get-PSDrive -Name $SysDrive -ErrorAction SilentlyContinue
		If ($Drive) {
			$FreeGB = [math]::Round($Drive.Free / 1GB, 1)
			$TotalGB = [math]::Round(($Drive.Free + $Drive.Used) / 1GB, 1)
			$PctFree = If ($TotalGB -gt 0) { [math]::Round($Drive.Free / ($Drive.Free + $Drive.Used) * 100, 0) } Else { 0 }
			If ($FreeGB -lt 5 -or $PctFree -lt 10) {
				Add-Result 'System' 'System drive free space' 'WARN' "$FreeGB GB free of $TotalGB GB ($PctFree%). Low space can cause module and update failures."
			} Else {
				Add-Result 'System' 'System drive free space' 'PASS' "$FreeGB GB free of $TotalGB GB ($PctFree%)."
			}
		}
	} Catch {
		Add-Result 'System' 'System drive free space' 'INFO' $_.Exception.Message
	}
	#endregion

	#region Console encoding
	Try {
		$OutEnc = [Console]::OutputEncoding.WebName
		Add-Result 'Console' 'Console output encoding' 'INFO' "$OutEnc (pipeline OutputEncoding: $($OutputEncoding.WebName))"
	} Catch {
		Add-Result 'Console' 'Console output encoding' 'INFO' $_.Exception.Message
	}
	#endregion

	#region Session errors
	Try {
		Add-Result 'Session' 'Errors before health check' 'INFO' "$InitialErrorCount error(s) were already recorded in this session before the health check ran."
	} Catch { }
	#endregion

	#region Pending reboot
	Try {
		$Reasons = @()
		If (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $Reasons += 'CBS' }
		If (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $Reasons += 'WindowsUpdate' }
		$PFRO = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue).PendingFileRenameOperations
		If ($PFRO) { $Reasons += 'PendingFileRename' }
		If ($Reasons.Count -gt 0) {
			Add-Result 'System' 'Pending reboot' 'WARN' "Reboot pending ($($Reasons -join ', ')). WMF / .NET changes may not be fully applied until reboot."
		} Else {
			Add-Result 'System' 'Pending reboot' 'PASS' 'No pending reboot detected.'
		}
	} Catch {
		Add-Result 'System' 'Pending reboot' 'INFO' $_.Exception.Message
	}
	#endregion

	# ---- Output ----
	If ($PassThru) {
		$Results
		Return
	}

	$ColorMap = @{ PASS = 'Green'; WARN = 'Yellow'; FAIL = 'Red'; INFO = 'Cyan' }

	Write-Host ''
	Write-Host 'Windows PowerShell 5.1 Health Check' -ForegroundColor White
	Write-Host ('Computer: {0}    User: {1}\{2}    Elevated: {3}' -f $env:COMPUTERNAME, $env:USERDOMAIN, $env:USERNAME, $IsElevated)
	Write-Host ('Engine:   {0}    Date: {1}' -f $PSVersionTable.PSVersion, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
	Write-Host ('=' * 78)

	$LastCategory = ''
	ForEach ($R in $Results) {
		If ($R.Category -ne $LastCategory) {
			Write-Host ''
			Write-Host ("-- {0} --" -f $R.Category) -ForegroundColor Gray
			$LastCategory = $R.Category
		}
		$Color = If ($ColorMap.ContainsKey($R.Status)) { $ColorMap[$R.Status] } Else { 'White' }
		Write-Host ("  [{0}] {1,-26} {2}" -f $R.Status, $R.Check, $R.Detail) -ForegroundColor $Color
	}

	$Pass = @($Results | Where-Object { $_.Status -eq 'PASS' }).Count
	$Warn = @($Results | Where-Object { $_.Status -eq 'WARN' }).Count
	$Fail = @($Results | Where-Object { $_.Status -eq 'FAIL' }).Count
	$Info = @($Results | Where-Object { $_.Status -eq 'INFO' }).Count

	Write-Host ''
	Write-Host ('=' * 78)
	$SummaryColor = If ($Fail -gt 0) { 'Red' } ElseIf ($Warn -gt 0) { 'Yellow' } Else { 'Green' }
	Write-Host ("Summary: {0} PASS, {1} WARN, {2} FAIL, {3} INFO" -f $Pass, $Warn, $Fail, $Info) -ForegroundColor $SummaryColor
	If ($Warn -gt 0 -or $Fail -gt 0) {
		Write-Host 'Tip: pipe -PassThru into Where-Object to capture just the WARN and FAIL items.' -ForegroundColor Gray
	}
	Write-Host ''
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

Function Find-CrocExe {
    <#
    .SYNOPSIS
        Searches PATH and known WinGet install locations for croc.exe.
    .DESCRIPTION
        Refreshes the PATH environment variable, then checks for croc via
        Get-Command and known WinGet package installation directories.
        Returns the full path to croc.exe if found, or $null.
    .EXAMPLE
        Find-CrocExe
        Returns "C:\Users\user\AppData\Local\...\croc.exe" or $null
    #>
    [CmdletBinding()]
    param()

    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    $cmd = Get-Command croc -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $knownPaths = @(
        "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\schollz.croc_Microsoft.Winget.Source_8wekyb3d8bbwe\croc.exe",
        "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\WinGet\Packages\schollz.croc_Microsoft.Winget.Source_8wekyb3d8bbwe\croc.exe"
    )
    foreach ($p in $knownPaths) { if (Test-Path $p) { return $p } }

    # Targeted search: only look inside schollz.croc_* directories, not a full recursive scan
    foreach ($root in @("$env:LOCALAPPDATA\Microsoft\WinGet\Packages", "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\WinGet\Packages")) {
        if (Test-Path $root) {
            $match = Get-ChildItem -Path $root -Filter 'schollz.croc_*' -Directory -ErrorAction SilentlyContinue |
                     ForEach-Object { Join-Path $_.FullName 'croc.exe' } |
                     Where-Object { Test-Path $_ } |
                     Select-Object -First 1
            if ($match) { return $match }
        }
    }
    return $null
}

Function Get-CrocPath {
    <#
    .SYNOPSIS
        Returns the path to the croc executable, installing it if needed.
    .DESCRIPTION
        Searches for croc.exe using Find-CrocExe. If not found, calls
        Install-Croc to install it automatically. Throws if the executable
        cannot be found or installed.
    .EXAMPLE
        Get-CrocPath
        Returns "C:\Users\user\AppData\Local\...\croc.exe"
    #>
    [CmdletBinding()]
    param()

    $path = Find-CrocExe
    if ($path) { return $path }

    $path = Install-Croc
    if (-not $path -or -not (Test-Path $path)) {
        throw "croc installation completed but executable not found. Try running Install-Croc manually."
    }
    return $path
}

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCIvhv64pGi8nYt
# puUq/qOeCmKSz8AbBJizUCp5nszvrqCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# vIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCE/cM09+RU7b
# ww+P+ZIYNTANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGlt
# ZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI2MDgwNTAwMDAw
# MFoXDTM3MTEwNDIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1l
# c3RhbXAgUmVzcG9uZGVyIDIwMjYgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBALZ7pvLJ/s1K+NSbTGWz/TjGMPh8CQ6RucZCLv5anHzWJjF/NWJrFIhy
# 24fcpKXlgRiky4WAawDfU3YP0BMxt9l3Dm5oCG5Z69AqEN1kgHg2epx+l+lZBcmJ
# CcN0ASURML5uFIS80sZsDwO3BSkUxDjLJhBI+qiZP3aixAC/qEGLjsBNlLol9VZ7
# pfGEXiMlneJIC5/YKuizVzNFKZZEeoy/0B8Zm+nzKBgSWG52lCO1w+nCg6XpCtkl
# TJXeIg283hw7TmmsZXR+SMbjbrEOvZ3fP2VxIgeR28Y90ZStd3F9VuA5RVynb/wh
# ITPAo9b75Zr4Ta6Mj3URm26QZYMn/FnbuTegcoRcFEZ9FOqM5T6MTdtr/n74lIT/
# ug0eeOzmZ6QTFg33otX+bFRsIolvykE1jive4PuESaT8zzVeFWDAMDtozNgLctkG
# D1ZjkEyZtJrLl5ya0m5doH/ScpaZCZVl6pNUOCybMc/kxC6EAmSJY24L0yYKD1Nk
# ddsnb/ItVKi/2nXpQNMu1PT5prW83vV8d67WowuUs0HdY4H8AMLGvdL/WHEj3Znq
# MqAQQP9u3Ai9t+5eQ02GDwy0ODjdzi0xlp70W+ow63/0++YDEX1M0iwgUHwbrJvf
# pklkZQvw3+kv3vUPItdwroczk9icflf55W1zOEKAcJVAIXpcMCU9AgMBAAGjggGV
# MIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQUyWOKMC7USvtulPPm40B+9ezN
# 4jAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMC
# B4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQG
# CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKG
# UWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRp
# bWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSg
# UqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRU
# aW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQCNxTphHp1S
# Ct+ZrAmAfn0oQLFr0mLywSLaDXQIENoyKqxrFbJblzCVP/pkXmwXOdrOpWygLzlT
# 12os5ipDCy35RBCg2UMeApEtrfGhz45F4Wt4WGdNdIbRWt3YTYJmpR+b7lr4d7Uw
# n+H600u4D7RnOGf8Wj4UNgAdZkfHhHv1mx9EVh71SJelcEN/oORSjXzdjfw1iZH9
# d8Nh/thn6hH23d+VsPAr6GAYyzSA02nXD1nYLI7Ijmiv+xLCiYC41DSFYL3GhTiy
# 0PxpawPtGRyaBVGzq+UiTfM8pD7KVyF5aQyWP4KhVGUUTnmm/RlYJoW3TiXA/+t0
# YcT2oRVBm3JETjajHug2AL+v5jhtKVnd3D0rbHXEu27o+Q8p4sEWPMqKDB+qbceb
# 6T/6WcwTwXmQ9lOCLLYcsQeSWmvKqzpAec9etE14jOQAzLKWdE3w/TCaKtLRaRT7
# LCkRYVnhA2D73FLje1O5b3HR5eHs0NzU/+xX7NbEdcofy0W3Wdwd1XOqtlpg/Jgw
# tKfZM5dqO94lbUveOiJBI+xZEbGRsMNbXmMREUTgu+Oca7Y73MPWcslIx2VhkSKS
# XjDbD6rgg39H5Mh7QfieAIjWagkJNt68Yfim6cjEzVSiLSeZfdkr5dtFPTW6jATl
# WJdYeeDRGCyatf8R1hSjzSvdN8yWQPT9gzCCBzMwggUboAMCAQICEA2lFIZwJJS8
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
# INpQFsJ+ddHJPRDyUDaVifH2weyUMN8ScAa4P8xiQ5pvMA0GCSqGSIb3DQEBAQUA
# BIICAFPLSWqNgA2N64mE23JPI/etUDxXit9RpALn8KFIbDsFilIkLs8sx8TciLGI
# p2X+k9tD9ab0DyGTjO9z8lPSkl1bDydEXlxXTNBe34S+S1cppb892D5QpSjs1JuP
# T+CPNAg9YET8PyYhqNL+7qWJtdDsoEiki6YXOP8khjBxbTmxGTjNH2/vRwrUB32m
# zkYQzOxC4kxpU3hhu90Gwqqq+Kmz64RkMJ9udl2nacl3FEVqbMINCb4QNt1Etpw/
# aQvAsxgz5a4OQmnWaNh8YjG9mhw/sPn3mQ6vi/cTHocJmLc2JqiYhrrrT/IWyfqo
# MTxT1Q+S2XcU1V3uDblQvOhY+VjOYzNBfOP7nf/n/4aN8bCjj0AfqIQ+x5n2WeCw
# DIyP1NTQdGb55+631NSBr7NPNXesUM6C7+7GHh5Fj0sqsA7WjDYqP3u3yOxB6THE
# Nzx0Coby6/67Iz2EXtG4frzI6BkewESiN937PVpRLqD8FEQnDzqSx18j746d1eMJ
# eL8KIK8Wda3OKevpQrsfsLty6qewAYA+VDgLnCBv/udMMVZEOl3pOdGLFZiFPOCE
# Lzc3RsgUnC4hDFCLRQKVEQIq4MiBkAGhWn52Oi5gZ9b0EZ/gzeQolPrCz7MgTxFJ
# eomKzte4TJUy+eGxqtjH/cj22fRiYhLfUYeN8Cw8YTidk/4FoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCE/cM09+RU7bww+P+ZIY
# NTANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MTAwNzIxMzk1MVowLwYJKoZIhvcNAQkEMSIEIGhbII7O
# I6dqkckM8esfolvADSXsna9yaYadRoU8ocysMA0GCSqGSIb3DQEBAQUABIICAKlt
# gbnC1513rLKrSvbZQiQLd6AblQc2JInc8hfkOuS5yTmr22hDY9eysEPwb7C6rvjr
# 7mVA3SRg2WUThGhYqkVV0U9+8P9/L7aBqPGodsrfIJhbYI5ECt+sj9LrUL4G26oA
# ZmeIl4vE7S4xDizk5N7gDn4Yn+hRB2dhkS3ZM0fkUfke9AGrekAXBgV7tYe6WIt+
# dlhZEK+YarVMb4IY2lWHpydoAsHK2D1CKaSG9m4VOQkiryZssxEEogwQYsZjCE7x
# 9vpvqbB06dWgZpz8oHbMk5FaI6cpMinCkp7Twsi9wdSrQ9iYEnvD9SJDzhRI/f+1
# EKxjPKKOqV3It5uLcLzorASb0Qx30kH/UImsqCHLuORMGgoVDCzkIgQTx9EHWs2z
# 7fiogkFgeEUEMIKWmKXIs4r+JCsC/3nuHST9bwRGDgxumhKBBVuvRUyhM77Yul5O
# Ure41utWVDFLKAVuX5vok2wiI6t068tV5ujhx4G3b9K7svhBhEK590WH4FbQtHn7
# +FKBhqNcNk9TjqmO1S/bnLw38guFJZJjl/AMYEGU1rYWT6OOBzMeaoK9WmKbfy2J
# Qe7kPaYG3fHSmtEzvMtjEzx62j857pc6bgEOzdDt/M/RWBP3oQ6wzrtRktHTqI+a
# CYTKuweSrLEASYrM+ZSIoU3qUSZHWvd5/KgCkzAV
# SIG # End signature block
