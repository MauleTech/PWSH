Function Invoke-BPARemediation {
<#
	.SYNOPSIS
		Automatically remediates common, safe BPA (Best Practices Analyzer) findings on Windows Servers.

	.DESCRIPTION
		This function scans for BPA issues using Get-BpaResult and automatically remediates
		known safe fixes. It reports what was fixed, what was skipped, and what requires
		manual attention.

		The function uses a configuration hashtable that makes it easy to add new remediation
		rules. Only safe, non-destructive changes are applied automatically.

		Things that are explicitly SKIPPED (flagged for manual review):
		- Anything requiring new accounts/credentials (like DHCP DNS credentials)
		- Anything involving AD schema or forest-wide changes
		- Anything involving certificates
		- Network adapter/IP configuration changes
		- Anything the script cannot verify is safe for the environment

	.PARAMETER ComputerName
		The target server to remediate. Defaults to localhost.

	.PARAMETER Category
		Optional filter to remediate specific categories only (e.g., 'Configuration', 'Security').
		If not specified, all categories are processed.

	.PARAMETER OutputPath
		Optional path to export a remediation report. Supports .csv and .html extensions.
		If not specified, no report file is generated.

	.PARAMETER ModelId
		Optional BPA Model ID to scan. If not specified, attempts to detect installed server roles.

	.EXAMPLE
		Invoke-BPARemediation -WhatIf
		Preview what changes would be made without actually making them.

	.EXAMPLE
		Invoke-BPARemediation -Category 'Configuration'
		Remediate only Configuration category findings.

	.EXAMPLE
		Invoke-BPARemediation -OutputPath "C:\Reports\BPA-Remediation.csv"
		Run remediation and export results to a CSV file.

	.EXAMPLE
		Invoke-Command -ComputerName "SERVER01" -ScriptBlock { Invoke-BPARemediation -OutputPath "C:\Reports\BPA-Report.html" }
		Remediate a remote server via PowerShell remoting and export an HTML report.

	.NOTES
		Requires Administrator privileges to run.
		Requires the BestPractices PowerShell module (included in Windows Server).
		Some remediations require the SmbServer, DnsServer, or DhcpServer modules.

		Author: Maule Technologies
#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
	param(
		[Parameter(Mandatory = $false)]
		[string]$ComputerName = 'localhost',

		[Parameter(Mandatory = $false)]
		[ValidateSet('Configuration', 'Security', 'Performance', 'Policy', 'Operation', 'PreDeployment', 'PostDeployment')]
		[string[]]$Category,

		[Parameter(Mandatory = $false)]
		[ValidateScript({
			if ($_ -match '\.(csv|html)$') { return $true }
			throw "OutputPath must end with .csv or .html"
		})]
		[string]$OutputPath,

		[Parameter(Mandatory = $false)]
		[string]$ModelId
	)

	begin {
		# Check for Administrator privileges
		$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
		if (-not $IsAdmin) {
			throw "This function requires Administrator privileges. Please run as Administrator."
		}

		# Block remote execution - remediation commands only work locally.
		# BPA scan can run remotely, but Set-SmbServerConfiguration/Set-DnsServerZone execute locally.
		# To remediate a remote server, run this function directly on that server or use Invoke-Command.
		$LocalFqdn = if ($env:USERDNSDOMAIN) { "$env:COMPUTERNAME.$env:USERDNSDOMAIN" } else { $null }
		$IsLocalTarget = ($ComputerName -eq 'localhost' -or $ComputerName -eq '.' -or
			$ComputerName -eq $env:COMPUTERNAME -or
			($LocalFqdn -and $ComputerName -eq $LocalFqdn))
		if (-not $IsLocalTarget) {
			throw "Remote remediation is not supported. Remediation commands (Set-SmbServerConfiguration, Set-DnsServerZone) only execute locally. To remediate '$ComputerName', run this function directly on that server or use: Invoke-Command -ComputerName '$ComputerName' -ScriptBlock { Invoke-BPARemediation }"
		}

		# Check for BestPractices module
		if (-not (Get-Module -ListAvailable -Name BestPractices)) {
			throw "BestPractices module not found. This function requires Windows Server with the BestPractices module."
		}

		Import-Module BestPractices -ErrorAction Stop

		Write-Verbose "Starting BPA Remediation on $ComputerName"

		# Define safe remediations - add new entries here to expand coverage
		# Format: Key = @{ Type; Property; Value; Description }
		$SafeRemediations = @{
			# SMB Server Settings
			'SMB.AutoDisconnectTimeout' = @{
				Type = 'SMB'
				Property = 'AutoDisconnectTimeout'
				Value = 0
				Description = 'Set AutoDisconnectTimeout to 0 (disabled)'
			}
			'SMB.DurableHandleV2TimeoutInSeconds' = @{
				Type = 'SMB'
				Property = 'DurableHandleV2TimeoutInSeconds'
				Value = 30
				Description = 'Set DurableHandleV2TimeoutInSeconds to 30'
			}
			'SMB.AsynchronousCredits' = @{
				Type = 'SMB'
				Property = 'AsynchronousCredits'
				Value = 512
				Description = 'Set AsynchronousCredits to 512'
			}
			'SMB.Smb2CreditsMin' = @{
				Type = 'SMB'
				Property = 'Smb2CreditsMin'
				Value = 512
				Description = 'Set Smb2CreditsMin to 512'
			}
			'SMB.Smb2CreditsMax' = @{
				Type = 'SMB'
				Property = 'Smb2CreditsMax'
				Value = 8192
				Description = 'Set Smb2CreditsMax to 8192'
			}
		}

		# Patterns that indicate issues requiring manual attention.
		# Word-boundary anchors (\b) prevent false matches on common substrings.
		$ManualReviewPatterns = @(
			'credential',
			'certificate',
			'schema',
			'forest',
			'network adapter',
			'IP address',
			'IP configuration',
			'\baccount\b',
			'password',
			'\bauthentication\b',
			'domain controller',
			'\breplication\b'
		)

		# Cache SMB configuration once per execution to avoid repeated queries for
		# multiple SMB findings in the same scan session.
		# Note: If multiple SMB properties are remediated, PreviousValue in result objects
		# for subsequent findings will reflect the pre-remediation state (stale cache).
		# The property-equality check remains accurate; only logged PreviousValue is affected.
		$SmbConfig = $null
		if (Get-Module -ListAvailable -Name SmbServer -ErrorAction SilentlyContinue) {
			try {
				$SmbConfig = Get-SmbServerConfiguration -ErrorAction Stop
				Write-Verbose "SMB Server configuration loaded and cached"
			} catch {
				Write-Warning "Could not retrieve SMB Server configuration: $_"
			}
		}

		# Initialize results collection
		$Results = [System.Collections.ArrayList]::new()
	}

	process {
		# Get available BPA models if not specified
		if (-not $ModelId) {
			Write-Verbose "Detecting installed BPA models..."
			$Models = Get-BpaModel -ErrorAction SilentlyContinue
			if (-not $Models) {
				Write-Warning "No BPA models found. Ensure server roles are installed."
				return
			}
			Write-Verbose "Found $($Models.Count) BPA model(s)"
		} else {
			$Models = Get-BpaModel -Id $ModelId -ErrorAction SilentlyContinue
			if (-not $Models) {
				Write-Warning "BPA model '$ModelId' not found."
				return
			}
		}

		foreach ($Model in $Models) {
			Write-Verbose "Processing BPA model: $($Model.Id)"

			# Invoke BPA scan (always local since remote remediation is blocked in begin block)
			try {
				Write-Verbose "Running BPA scan for $($Model.Id)..."
				$null = Invoke-BpaModel -Id $Model.Id -ErrorAction Stop
			} catch {
				Write-Warning "Failed to invoke BPA scan for $($Model.Id): $_"
				continue
			}

			# Get BPA results
			try {
				$BpaResults = @(Get-BpaResult -ModelId $Model.Id -ErrorAction Stop)
				if ($Category) {
					$BpaResults = @($BpaResults | Where-Object { $Category -contains $_.Category })
				}
				# Filter to non-compliant, actionable results
				$BpaResults = @($BpaResults | Where-Object { $_.Compliance -ne $true -and $_.Severity -ne 'Informational' })
			} catch {
				Write-Warning "Failed to get BPA results for $($Model.Id): $_"
				continue
			}

			Write-Verbose "Found $($BpaResults.Count) non-compliant BPA finding(s) for $($Model.Id)"

			foreach ($Finding in $BpaResults) {
				# Check manual review patterns before attempting remediation
				$MatchedPattern = $null
				foreach ($Pattern in $ManualReviewPatterns) {
					if ($Finding.Title -match $Pattern -or $Finding.Problem -match $Pattern -or $Finding.Resolution -match $Pattern) {
						$MatchedPattern = $Pattern
						break
					}
				}

				if ($MatchedPattern) {
					Write-Verbose "Manual review required for $($Finding.RuleId): matched pattern '$MatchedPattern'"
					$null = $Results.Add((New-BPAResultObject -Finding $Finding -Model $Model -ComputerName $ComputerName `
						-Status 'ManualRequired' -Reason "Matched sensitive pattern '$MatchedPattern' - requires manual review"))
					continue
				}

				# Each handler returns an array of partial result objects (empty if not applicable).
				# Helpers are tried in priority order; the first that produces results wins.
				$HandlerResults = @()

				if ($HandlerResults.Count -eq 0 -and ($Finding.Title -match 'SMB|Server Message Block|file server' -or $Model.Id -match 'FileServices')) {
					$HandlerResults = @(Invoke-SMBRemediation -Finding $Finding -SafeRemediations $SafeRemediations `
						-SmbConfig $SmbConfig -WhatIf:$WhatIfPreference -Verbose:$VerbosePreference)
				}

				if ($HandlerResults.Count -eq 0 -and ($Finding.Title -match 'DNS' -or $Model.Id -match 'DNS')) {
					$HandlerResults = @(Invoke-DNSRemediation -Finding $Finding -WhatIf:$WhatIfPreference -Verbose:$VerbosePreference)
				}

				if ($HandlerResults.Count -eq 0 -and ($Finding.Title -match 'DHCP' -or $Model.Id -match 'DHCP')) {
					$HandlerResults = @(Invoke-DHCPRemediation -Finding $Finding -WhatIf:$WhatIfPreference -Verbose:$VerbosePreference)
				}

				if ($HandlerResults.Count -gt 0) {
					# A handler matched - add one result row per partial result returned
					foreach ($Partial in $HandlerResults) {
						$null = $Results.Add((New-BPAResultObject -Finding $Finding -Model $Model -ComputerName $ComputerName `
							-Status $Partial.Status -Target $Partial.Target `
							-PreviousValue $Partial.PreviousValue -NewValue $Partial.NewValue -Reason $Partial.Reason))
					}
				} else {
					# No handler matched this finding
					$null = $Results.Add((New-BPAResultObject -Finding $Finding -Model $Model -ComputerName $ComputerName `
						-Status 'Skipped' -Reason 'No safe automated remediation available'))
				}
			}
		}
	}

	end {
		# Display summary
		$RemediatedItems = @($Results | Where-Object { $_.Status -eq 'Remediated' })
		$SkippedItems = @($Results | Where-Object { $_.Status -eq 'Skipped' })
		$ManualItems = @($Results | Where-Object { $_.Status -eq 'ManualRequired' })
		$FailedItems = @($Results | Where-Object { $_.Status -eq 'Failed' })

		Write-Host "`n========================================" -ForegroundColor Cyan
		Write-Host "BPA Remediation Summary" -ForegroundColor Cyan
		Write-Host "========================================" -ForegroundColor Cyan
		Write-Host "Computer: $ComputerName"
		Write-Host "Total Results: $($Results.Count)"
		Write-Host "  Remediated:      $($RemediatedItems.Count)" -ForegroundColor Green
		Write-Host "  Skipped:         $($SkippedItems.Count)" -ForegroundColor Yellow
		Write-Host "  Manual Required: $($ManualItems.Count)" -ForegroundColor Red
		Write-Host "  Failed:          $($FailedItems.Count)" -ForegroundColor Red
		Write-Host "========================================`n" -ForegroundColor Cyan

		# Show details for manual required items
		if ($ManualItems.Count -gt 0) {
			Write-Host "Items Requiring Manual Attention:" -ForegroundColor Yellow
			foreach ($Item in $ManualItems) {
				Write-Host "  - $($Item.Title)" -ForegroundColor Yellow
				Write-Host "    Reason: $($Item.Reason)" -ForegroundColor Gray
			}
			Write-Host ""
		}

		# Export report if requested
		if ($OutputPath) {
			try {
				$Extension = [System.IO.Path]::GetExtension($OutputPath).ToLower()
				if ($Extension -eq '.csv') {
					$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Force
					Write-Host "Report exported to: $OutputPath" -ForegroundColor Green
				} elseif ($Extension -eq '.html') {
					$PreContent = "<h1>BPA Remediation Report</h1><p>Generated: $(Get-Date)</p><p>Computer: $ComputerName</p>"
					$HtmlContent = $Results | ConvertTo-Html -Title "BPA Remediation Report" -PreContent $PreContent | Out-String
					$HtmlContent | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
					Write-Host "Report exported to: $OutputPath" -ForegroundColor Green
				}
			} catch {
				Write-Error "Failed to export report: $_"
			}
		}

		return $Results
	}
}

Function Invoke-DHCPRemediation {
	[CmdletBinding(SupportsShouldProcess = $true)]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$Finding
	)

	if (-not (Get-Module -ListAvailable -Name DhcpServer -ErrorAction SilentlyContinue)) {
		return @([PSCustomObject]@{
			Target = $null
			Status = 'Skipped'
			PreviousValue = $null
			NewValue = $null
			Reason = 'DhcpServer module not available - DHCP role may not be installed'
		})
	}

	# DNS dynamic update findings require manual attention (credential patterns already
	# caught by ManualReviewPatterns in the main function, so only check non-overlapping patterns)
	if ($Finding.Title -match 'dynamic update|DHCP.*DNS' -or $Finding.Problem -match 'dynamic update|DHCP.*DNS') {
		return @([PSCustomObject]@{
			Target = $null
			Status = 'ManualRequired'
			PreviousValue = $null
			NewValue = $null
			Reason = 'DHCP DNS configuration requires manual setup'
		})
	}

	return @([PSCustomObject]@{
		Target = $null
		Status = 'Skipped'
		PreviousValue = $null
		NewValue = $null
		Reason = 'DHCP remediation requires manual review for environment safety'
	})
}

Function Invoke-DNSRemediation {
	[CmdletBinding(SupportsShouldProcess = $true)]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$Finding
	)

	if (-not (Get-Module -ListAvailable -Name DnsServer -ErrorAction SilentlyContinue)) {
		return @([PSCustomObject]@{
			Target = $null
			Status = 'Skipped'
			PreviousValue = $null
			NewValue = $null
			Reason = 'DnsServer module not available - DNS role may not be installed'
		})
	}

	# Only handle notify/secondary zone findings
	if (-not ($Finding.Title -match 'notify|secondary|zone transfer')) {
		return @()
	}

	$PartialResults = [System.Collections.ArrayList]::new()

	try {
		# Single call returns full zone objects - no second per-zone query needed
		$Zones = Get-DnsServerZone -ErrorAction Stop | Where-Object { $_.ZoneType -eq 'Primary' -and -not $_.IsAutoCreated }
	} catch {
		return @([PSCustomObject]@{
			Target = $null
			Status = 'Failed'
			PreviousValue = $null
			NewValue = $null
			Reason = "Failed to query DNS zones: $_"
		})
	}

	$ZonesChecked = 0
	$ZonesAlreadyCompliant = 0

	foreach ($Zone in $Zones) {
		# Only adjust zones that have no secondary servers configured
		if (-not ($null -eq $Zone.SecondaryServers -or $Zone.SecondaryServers.Count -eq 0)) {
			continue
		}

		$ZonesChecked++

		if ($Zone.Notify -eq 'NoNotify') {
			Write-Verbose "DNS: Zone $($Zone.ZoneName) already set to NoNotify"
			$ZonesAlreadyCompliant++
			continue
		}

		if ($PSCmdlet.ShouldProcess("DNS Zone: $($Zone.ZoneName)", "Set Notify to NoNotify (no secondaries configured)")) {
			try {
				Set-DnsServerZone -Name $Zone.ZoneName -Notify 'NoNotify' -ErrorAction Stop
				$null = $PartialResults.Add([PSCustomObject]@{
					Target = $Zone.ZoneName
					Status = 'Remediated'
					PreviousValue = $Zone.Notify
					NewValue = 'NoNotify'
					Reason = 'Set zone notify to NoNotify - no secondary servers configured'
				})
				Write-Verbose "Remediated DNS zone $($Zone.ZoneName): Set Notify to NoNotify"
			} catch {
				$null = $PartialResults.Add([PSCustomObject]@{
					Target = $Zone.ZoneName
					Status = 'Failed'
					PreviousValue = $Zone.Notify
					NewValue = 'NoNotify'
					Reason = "Failed to set zone notify: $_"
				})
			}
		} else {
			$null = $PartialResults.Add([PSCustomObject]@{
				Target = $Zone.ZoneName
				Status = 'Skipped'
				PreviousValue = $Zone.Notify
				NewValue = 'NoNotify'
				Reason = 'WhatIf mode - no changes made'
			})
		}
	}

	# If we checked zones but all were already compliant, report that
	if ($ZonesChecked -gt 0 -and $PartialResults.Count -eq 0) {
		return @([PSCustomObject]@{
			Target = $null
			Status = 'Skipped'
			PreviousValue = 'NoNotify'
			NewValue = 'NoNotify'
			Reason = "All $ZonesChecked applicable DNS zone(s) already set to NoNotify"
		})
	}

	return @($PartialResults)
}

Function Invoke-IPv4NetworkScan {
	###############################################################################################################
	# Language     :  PowerShell 4.0
	# Filename     :  IPv4NetworkScan.ps1 
	# Autor        :  BornToBeRoot (https://github.com/BornToBeRoot)
	# Description  :  Powerful asynchronus IPv4 Network Scanner
	# Repository   :  https://github.com/BornToBeRoot/PowerShell_IPv4NetworkScanner
	###############################################################################################################

	<#
		.SYNOPSIS
		Powerful asynchronus IPv4 Network Scanner

		.DESCRIPTION
		This powerful asynchronus IPv4 Network Scanner allows you to scan every IPv4-Range you want (172.16.1.47 to 172.16.2.5 would work). But there is also the possibility to scan an entire subnet based on an IPv4-Address withing the subnet and a the subnetmask/CIDR.

		The default result will contain the the IPv4-Address, Status (Up or Down) and the Hostname. Other values can be displayed via parameter.

		.EXAMPLE
		.\IPv4NetworkScan.ps1 -StartIPv4Address 192.168.178.0 -EndIPv4Address 192.168.178.20

		IPv4Address   Status Hostname
		-----------   ------ --------
		192.168.178.1 Up     fritz.box

		.EXAMPLE
		.\IPv4NetworkScan.ps1 -IPv4Address 192.168.178.0 -Mask 255.255.255.0 -DisableDNSResolving

		IPv4Address    Status
		-----------    ------
		192.168.178.1  Up
		192.168.178.22 Up

		.EXAMPLE
		.\IPv4NetworkScan.ps1 -IPv4Address 192.168.178.0 -CIDR 25 -EnableMACResolving

		IPv4Address    Status Hostname           MAC               Vendor
		-----------    ------ --------           ---               ------
		192.168.178.1  Up     fritz.box          XX-XX-XX-XX-XX-XX AVM Audiovisuelles Marketing und Computersysteme GmbH
		192.168.178.22 Up     XXXXX-PC.fritz.box XX-XX-XX-XX-XX-XX ASRock Incorporation

		.LINK
		https://github.com/BornToBeRoot/PowerShell_IPv4NetworkScanner/blob/master/README.md
	#>

	[CmdletBinding(DefaultParameterSetName = 'CIDR')]
	Param(
		[Parameter(
			ParameterSetName = 'Range',
			Position = 0,
			Mandatory = $true,
			HelpMessage = 'Start IPv4-Address like 192.168.1.10')]
		[IPAddress]$StartIPv4Address,

		[Parameter(
			ParameterSetName = 'Range',
			Position = 1,
			Mandatory = $true,
			HelpMessage = 'End IPv4-Address like 192.168.1.100')]
		[IPAddress]$EndIPv4Address,
		
		[Parameter(
			ParameterSetName = 'CIDR',
			Position = 0,
			Mandatory = $true,
			HelpMessage = 'IPv4-Address which is in the subnet')]
		[Parameter(
			ParameterSetName = 'Mask',
			Position = 0,
			Mandatory = $true,
			HelpMessage = 'IPv4-Address which is in the subnet')]
		[IPAddress]$IPv4Address,

		[Parameter(
			ParameterSetName = 'CIDR',        
			Position = 1,
			Mandatory = $true,
			HelpMessage = 'CIDR like /24 without "/"')]
		[ValidateRange(0, 31)]
		[Int32]$CIDR,
	
		[Parameter(
			ParameterSetName = 'Mask',
			Position = 1,
			Mandatory = $true,
			Helpmessage = 'Subnetmask like 255.255.255.0')]
		[ValidateScript({
				if ($_ -match "^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(254|252|248|240|224|192|128|0)$") {
					return $true
				}
				else {
					throw "Enter a valid subnetmask (like 255.255.255.0)!"    
				}
			})]
		[String]$Mask,

		[Parameter(
			Position = 2,
			HelpMessage = 'Maxmium number of ICMP checks for each IPv4-Address (Default=2)')]
		[Int32]$Tries = 2,

		[Parameter(
			Position = 3,
			HelpMessage = 'Maximum number of threads at the same time (Default=256)')]
		[Int32]$Threads = 256,
		
		[Parameter(
			Position = 4,
			HelpMessage = 'Resolve DNS for each IP (Default=Enabled)')]
		[Switch]$DisableDNSResolving,

		[Parameter(
			Position = 5,
			HelpMessage = 'Resolve MAC-Address for each IP (Default=Disabled)')]
		[Switch]$EnableMACResolving,

		[Parameter(
			Position = 6,
			HelpMessage = 'Get extendend informations like BufferSize, ResponseTime and TTL (Default=Disabled)')]
		[Switch]$ExtendedInformations,

		[Parameter(
			Position = 7,
			HelpMessage = 'Include inactive devices in result')]
		[Switch]$IncludeInactive
	)

	Begin {
		Write-Verbose -Message "Script started at $(Get-Date)"
		
		$OUIListPath = "$ITFolder\oui.txt"

		function Convert-Subnetmask {
			[CmdLetBinding(DefaultParameterSetName = 'CIDR')]
			param( 
				[Parameter( 
					ParameterSetName = 'CIDR',       
					Position = 0,
					Mandatory = $true,
					HelpMessage = 'CIDR like /24 without "/"')]
				[ValidateRange(0, 32)]
				[Int32]$CIDR,

				[Parameter(
					ParameterSetName = 'Mask',
					Position = 0,
					Mandatory = $true,
					HelpMessage = 'Subnetmask like 255.255.255.0')]
				[ValidateScript({
						if ($_ -match "^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(255|254|252|248|240|224|192|128|0)$") {
							return $true
						}
						else {
							throw "Enter a valid subnetmask (like 255.255.255.0)!"    
						}
					})]
				[String]$Mask
			)

			Begin {

			}

			Process {
				switch ($PSCmdlet.ParameterSetName) {
					"CIDR" {                          
						# Make a string of bits (24 to 11111111111111111111111100000000)
						$CIDR_Bits = ('1' * $CIDR).PadRight(32, "0")
						
						# Split into groups of 8 bits, convert to Ints, join up into a string
						$Octets = $CIDR_Bits -split '(.{8})' -ne ''
						$Mask = ($Octets | ForEach-Object -Process { [Convert]::ToInt32($_, 2) }) -join '.'
					}

					"Mask" {
						# Convert the numbers into 8 bit blocks, join them all together, count the 1
						$Octets = $Mask.ToString().Split(".") | ForEach-Object -Process { [Convert]::ToString($_, 2) }
						$CIDR_Bits = ($Octets -join "").TrimEnd("0")

						# Count the "1" (111111111111111111111111 --> /24)                     
						$CIDR = $CIDR_Bits.Length             
					}               
				}

				[pscustomobject] @{
					Mask = $Mask
					CIDR = $CIDR
				}
			}

			End {
				
			}
		}

		# Helper function to convert an IPv4-Address to Int64 and vise versa
		function Convert-IPv4Address {
			[CmdletBinding(DefaultParameterSetName = 'IPv4Address')]
			param(
				[Parameter(
					ParameterSetName = 'IPv4Address',
					Position = 0,
					Mandatory = $true,
					HelpMessage = 'IPv4-Address as string like "192.168.1.1"')]
				[IPaddress]$IPv4Address,

				[Parameter(
					ParameterSetName = 'Int64',
					Position = 0,
					Mandatory = $true,
					HelpMessage = 'IPv4-Address as Int64 like 2886755428')]
				[long]$Int64
			) 

			Begin {

			}

			Process {
				switch ($PSCmdlet.ParameterSetName) {
					# Convert IPv4-Address as string into Int64
					"IPv4Address" {
						$Octets = $IPv4Address.ToString().Split(".") 
						$Int64 = [long]([long]$Octets[0] * 16777216 + [long]$Octets[1] * 65536 + [long]$Octets[2] * 256 + [long]$Octets[3]) 
					}
			
					# Convert IPv4-Address as Int64 into string 
					"Int64" {            
						$IPv4Address = (([System.Math]::Truncate($Int64 / 16777216)).ToString() + "." + ([System.Math]::Truncate(($Int64 % 16777216) / 65536)).ToString() + "." + ([System.Math]::Truncate(($Int64 % 65536) / 256)).ToString() + "." + ([System.Math]::Truncate($Int64 % 256)).ToString())
					}      
				}

				[pscustomobject] @{   
					IPv4Address = $IPv4Address
					Int64       = $Int64
				}
			}

			End {

			}
		}

		# Helper function to create a new Subnet
		function Get-IPv4Subnet {
			[CmdletBinding(DefaultParameterSetName = 'CIDR')]
			param(
				[Parameter(
					Position = 0,
					Mandatory = $true,
					HelpMessage = 'IPv4-Address which is in the subnet')]
				[IPAddress]$IPv4Address,

				[Parameter(
					ParameterSetName = 'CIDR',
					Position = 1,
					Mandatory = $true,
					HelpMessage = 'CIDR like /24 without "/"')]
				[ValidateRange(0, 31)]
				[Int32]$CIDR,

				[Parameter(
					ParameterSetName = 'Mask',
					Position = 1,
					Mandatory = $true,
					Helpmessage = 'Subnetmask like 255.255.255.0')]
				[ValidateScript({
						if ($_ -match "^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(254|252|248|240|224|192|128|0)$") {
							return $true
						}
						else {
							throw "Enter a valid subnetmask (like 255.255.255.0)!"    
						}
					})]
				[String]$Mask
			)

			Begin {
			
			}

			Process {
				# Convert Mask or CIDR - because we need both in the code below
				switch ($PSCmdlet.ParameterSetName) {
					"CIDR" {                          
						$Mask = (Convert-Subnetmask -CIDR $CIDR).Mask            
					}
					"Mask" {
						$CIDR = (Convert-Subnetmask -Mask $Mask).CIDR          
					}                  
				}
				
				# Get CIDR Address by parsing it into an IP-Address
				$CIDRAddress = [System.Net.IPAddress]::Parse([System.Convert]::ToUInt64(("1" * $CIDR).PadRight(32, "0"), 2))
			
				# Binary AND ... this is how subnets work.
				$NetworkID_bAND = $IPv4Address.Address -band $CIDRAddress.Address

				# Return an array of bytes. Then join them.
				$NetworkID = [System.Net.IPAddress]::Parse([System.BitConverter]::GetBytes([UInt32]$NetworkID_bAND) -join ("."))
				
				# Get HostBits based on SubnetBits (CIDR) // Hostbits (32 - /24 = 8 -> 00000000000000000000000011111111)
				$HostBits = ('1' * (32 - $CIDR)).PadLeft(32, "0")
				
				# Convert Bits to Int64
				$AvailableIPs = [Convert]::ToInt64($HostBits, 2)

				# Convert Network Address to Int64
				$NetworkID_Int64 = (Convert-IPv4Address -IPv4Address $NetworkID.ToString()).Int64

				# Convert add available IPs and parse into IPAddress
				$Broadcast = [System.Net.IPAddress]::Parse((Convert-IPv4Address -Int64 ($NetworkID_Int64 + $AvailableIPs)).IPv4Address)
				
				# Change useroutput ==> (/27 = 0..31 IPs -> AvailableIPs 32)
				$AvailableIPs += 1

				# Hosts = AvailableIPs - Network Address + Broadcast Address
				$Hosts = ($AvailableIPs - 2)
					
				# Build custom PSObject
				[pscustomobject] @{
					NetworkID = $NetworkID
					Broadcast = $Broadcast
					IPs       = $AvailableIPs
					Hosts     = $Hosts
				}
			}

			End {

			}
		}     
	}

	Process {
		# Calculate Subnet (Start and End IPv4-Address)
		if ($PSCmdlet.ParameterSetName -eq 'CIDR' -or $PSCmdlet.ParameterSetName -eq 'Mask') {
			# Convert Subnetmask
			if ($PSCmdlet.ParameterSetName -eq 'Mask') {
				$CIDR = (Convert-Subnetmask -Mask $Mask).CIDR     
			}

			# Create new subnet
			$Subnet = Get-IPv4Subnet -IPv4Address $IPv4Address -CIDR $CIDR

			# Assign Start and End IPv4-Address
			$StartIPv4Address = $Subnet.NetworkID
			$EndIPv4Address = $Subnet.Broadcast
		}

		# Convert Start and End IPv4-Address to Int64
		$StartIPv4Address_Int64 = (Convert-IPv4Address -IPv4Address $StartIPv4Address.ToString()).Int64
		$EndIPv4Address_Int64 = (Convert-IPv4Address -IPv4Address $EndIPv4Address.ToString()).Int64

		# Check if range is valid
		if ($StartIPv4Address_Int64 -gt $EndIPv4Address_Int64) {
			Write-Error -Message "Invalid IP-Range... Check your input!" -Category InvalidArgument -ErrorAction Stop
		}

		# Calculate IPs to scan (range)
		$IPsToScan = ($EndIPv4Address_Int64 - $StartIPv4Address_Int64)
		
		Write-Verbose -Message "Scanning range from $StartIPv4Address to $EndIPv4Address ($($IPsToScan + 1) IPs)"
		Write-Verbose -Message "Running with max $Threads threads"
		Write-Verbose -Message "ICMP checks per IP: $Tries"

		# Properties which are displayed in the output
		$PropertiesToDisplay = @()
		$PropertiesToDisplay += "IPv4Address", "Status"

		if ($DisableDNSResolving -eq $false) {
			$PropertiesToDisplay += "Hostname"
		}

		if ($EnableMACResolving) {
			$PropertiesToDisplay += "MAC"
		}

		# Check if it is possible to assign vendor to MAC --> import CSV-File 
		if ($EnableMACResolving) {
			$LatestOUIs = (Invoke-WebRequest -Uri "https://standards-oui.ieee.org/oui/oui.txt" -UseBasicParsing).Content
			$Output = ""

			foreach($Line in $LatestOUIs -split '[\r\n]')
			{
				if($Line -match "^[A-F0-9]{6}")
				{        
					# Line looks like: 2405F5     (base 16)		Integrated Device Technology (Malaysia) Sdn. Bhd.
					$Output += ($Line -replace '\s+', ' ').Replace(' (base 16) ', '|').Trim() + "`n"
				}
			}

			Out-File -InputObject $Output -FilePath "$ITFolder\oui.txt"
			if (Test-Path -Path $OUIListPath -PathType Leaf) {
				$OUIHashTable = @{ }

				Write-Verbose -Message "Read oui.txt and fill hash table..."

				foreach ($Line in Get-Content -Path $OUIListPath) {
					if (-not([String]::IsNullOrEmpty($Line))) {
						try {
							$HashTableData = $Line.Split('|')
							$OUIHashTable.Add($HashTableData[0], $HashTableData[1])
						}
						catch [System.ArgumentException] { } # Catch if mac is already added to hash table
					}
				}

				$AssignVendorToMAC = $true

				$PropertiesToDisplay += "Vendor"
			}
			else {
				$AssignVendorToMAC = $false

				Write-Warning -Message "No OUI-File to assign vendor with MAC-Address found! Execute the script ""Create-OUIListFromWeb.ps1"" to download the latest version. This warning does not affect the scanning procedure."
			}
		}  
		
		if ($ExtendedInformations) {
			$PropertiesToDisplay += "BufferSize", "ResponseTime", "TTL"
		}

		# Scriptblock --> will run in runspaces (threads)...
		[System.Management.Automation.ScriptBlock]$ScriptBlock = {
			Param(
				$IPv4Address,
				$Tries,
				$DisableDNSResolving,
				$EnableMACResolving,
				$ExtendedInformations,
				$IncludeInactive
			)
	
			# +++ Send ICMP requests +++
			$Status = [String]::Empty

			for ($i = 0; $i -lt $Tries; i++) {
				try {
					$PingObj = New-Object System.Net.NetworkInformation.Ping
					
					$Timeout = 1000
					$Buffer = New-Object Byte[] 32
					
					$PingResult = $PingObj.Send($IPv4Address, $Timeout, $Buffer)

					if ($PingResult.Status -eq "Success") {
						$Status = "Up"
						break # Exit loop, if host is reachable
					}
					else {
						$Status = "Down"
					}
				}
				catch {
					$Status = "Down"
					break # Exit loop, if there is an error
				}
			}
				
			# +++ Resolve DNS +++
			$Hostname = [String]::Empty     

			if ((-not($DisableDNSResolving)) -and ($Status -eq "Up" -or $IncludeInactive)) {   	
				try { 
					$Hostname = ([System.Net.Dns]::GetHostEntry($IPv4Address).HostName)
				} 
				catch { } # No DNS      
			}
		
			# +++ Get MAC-Address +++
			$MAC = [String]::Empty 

			if (($EnableMACResolving) -and (($Status -eq "Up") -or ($IncludeInactive))) {
				$Arp_Result = (arp -a).ToUpper().Trim()

				foreach ($Line in $Arp_Result) {                
					if ($Line.Split(" ")[0] -eq $IPv4Address) {                    
						$MAC = [Regex]::Matches($Line, "([0-9A-F][0-9A-F]-){5}([0-9A-F][0-9A-F])").Value
					}
				}
			}

			# +++ Get extended informations +++
			$BufferSize = [String]::Empty 
			$ResponseTime = [String]::Empty 
			$TTL = $null

			if ($ExtendedInformations -and ($Status -eq "Up")) {
				try {
					$BufferSize = $PingResult.Buffer.Length
					$ResponseTime = $PingResult.RoundtripTime
					$TTL = $PingResult.Options.Ttl
				}
				catch { } # Failed to get extended informations
			}	
		
			# +++ Result +++        
			if (($Status -eq "Up") -or ($IncludeInactive)) {
				[pscustomobject] @{
					IPv4Address  = $IPv4Address
					Status       = $Status
					Hostname     = $Hostname
					MAC          = $MAC   
					BufferSize   = $BufferSize
					ResponseTime = $ResponseTime
					TTL          = $TTL
				}
			}
			else {
				$null
			}
		} 

		Write-Verbose -Message "Setting up RunspacePool..."

		# Create RunspacePool and Jobs
		$RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Threads, $Host)
		$RunspacePool.Open()
		[System.Collections.ArrayList]$Jobs = @()

		Write-Verbose -Message "Setting up jobs..."

		# Set up jobs for each IP...
		for ($i = $StartIPv4Address_Int64; $i -le $EndIPv4Address_Int64; $i++) { 
			# Convert IP back from Int64
			$IPv4Address = (Convert-IPv4Address -Int64 $i).IPv4Address                

			# Create hashtable to pass parameters
			$ScriptParams = @{
				IPv4Address          = $IPv4Address
				Tries                = $Tries
				DisableDNSResolving  = $DisableDNSResolving
				EnableMACResolving   = $EnableMACResolving
				ExtendedInformations = $ExtendedInformations
				IncludeInactive      = $IncludeInactive
			}       

			# Catch when trying to divide through zero
			try {
				$Progress_Percent = (($i - $StartIPv4Address_Int64) / $IPsToScan) * 100 
			} 
			catch { 
				$Progress_Percent = 100 
			}

			Write-Progress -Activity "Setting up jobs..." -Id 1 -Status "Current IP-Address: $IPv4Address" -PercentComplete $Progress_Percent
							
			# Create new job
			$Job = [System.Management.Automation.PowerShell]::Create().AddScript($ScriptBlock).AddParameters($ScriptParams)
			$Job.RunspacePool = $RunspacePool
			
			$JobObj = [pscustomobject] @{
				RunNum = $i - $StartIPv4Address_Int64
				Pipe   = $Job
				Result = $Job.BeginInvoke()
			}

			# Add job to collection
			[void]$Jobs.Add($JobObj)
		}

		Write-Verbose -Message "Waiting for jobs to complete & starting to process results..."

		# Total jobs to calculate percent complete, because jobs are removed after they are processed
		$Jobs_Total = $Jobs.Count

		# Process results, while waiting for other jobs
		Do {
			# Get all jobs, which are completed
			$Jobs_ToProcess = $Jobs | Where-Object -FilterScript { $_.Result.IsCompleted }
	
			# If no jobs finished yet, wait 500 ms and try again
			if ($null -eq $Jobs_ToProcess) {
				Write-Verbose -Message "No jobs completed, wait 250ms..."

				Start-Sleep -Milliseconds 250
				continue
			}
			
			# Get jobs, which are not complete yet
			$Jobs_Remaining = ($Jobs | Where-Object -FilterScript { $_.Result.IsCompleted -eq $false }).Count

			# Catch when trying to divide through zero
			try {            
				$Progress_Percent = 100 - (($Jobs_Remaining / $Jobs_Total) * 100) 
			}
			catch {
				$Progress_Percent = 100
			}

			Write-Progress -Activity "Waiting for jobs to complete... ($($Threads - $($RunspacePool.GetAvailableRunspaces())) of $Threads threads running)" -Id 1 -PercentComplete $Progress_Percent -Status "$Jobs_Remaining remaining..."
		
			Write-Verbose -Message "Processing $(if($null -eq $Jobs_ToProcess.Count){"1"}else{$Jobs_ToProcess.Count}) job(s)..."

			# Processing completed jobs
			foreach ($Job in $Jobs_ToProcess) {       
				# Get the result...     
				$Job_Result = $Job.Pipe.EndInvoke($Job.Result)
				$Job.Pipe.Dispose()

				# Remove job from collection
				$Jobs.Remove($Job)
			
				# Check if result contains status
				if ($Job_Result.Status) {        
					if ($AssignVendorToMAC) {           
						$Vendor = [String]::Empty

						# Check if MAC is null or empty
						if (-not([String]::IsNullOrEmpty($Job_Result.MAC))) {
							# Split it, so we can search the vendor (XX-XX-XX-XX-XX-XX to XXXXXX)
							$MAC_VendorSearch = $Job_Result.MAC.Replace("-", "").Substring(0, 6)
									
							$Vendor = $OUIHashTable.Get_Item($MAC_VendorSearch)
						}

						[pscustomobject] @{
							IPv4Address  = $Job_Result.IPv4Address
							Status       = $Job_Result.Status
							Hostname     = $Job_Result.Hostname
							MAC          = $Job_Result.MAC
							Vendor       = $Vendor  
							BufferSize   = $Job_Result.BufferSize
							ResponseTime = $Job_Result.ResponseTime
							TTL          = $ResuJob_Resultlt.TTL
						} | Select-Object -Property $PropertiesToDisplay
					}
					else {
						$Job_Result | Select-Object -Property $PropertiesToDisplay
					}                            
				}
			} 

		} While ($Jobs.Count -gt 0)

		Write-Verbose -Message "Closing RunspacePool and free resources..."

		# Close the RunspacePool and free resources
		$RunspacePool.Close()
		$RunspacePool.Dispose()

		Write-Verbose -Message "Script finished at $(Get-Date)"
	}

	End {
	}
}

Function Invoke-NDDCScan {
	# Webhook URL loaded from local config file: $ITFolder\Config\webhooks.json
	# Example config: { "TeamsWebhookUri": "https://your-webhook-url-here" }
	Function Send-To-Teams{
		$date = Get-Date -Format g
		$webhookConfig = "$ITFolder\Config\webhooks.json"
		if (-not (Test-Path $webhookConfig)) {
			Write-Warning "Teams webhook config not found at $webhookConfig - notifications disabled."
			return
		}
		$config = Get-Content $webhookConfig -Raw | ConvertFrom-Json
		$uri = $config.TeamsWebhookUri
		if (-not $uri) {
			Write-Warning "TeamsWebhookUri not set in $webhookConfig - notifications disabled."
			return
		}

		$body = ConvertTo-Json -Depth 4 @{
			themeColor = $color
			title = $title
			text = "$env:computername at $env:userdomain says"
			sections = @(
				@{
					facts = @(
						@{
						name = 'Date'
						value = $date
						},
						@{
						name = 'Server'
						value = $server
						},
						@{
						name = 'Message'
						value = $message
						}
					)
				}
			)
		}
		Invoke-RestMethod -uri $uri -Method Post -body $body -ContentType 'application/json'
	}
	#Sets default title and color for notifications
	$title = $env:userdomain + ': Automated NDDC Upload Notification'
	$color = '808080'

Write-Host "Checking for NDDC Utility"
	[version]$ModVer = (Get-Module -ListAvailable -Name Posh-SSH).Version
	[version]$AvailableModVer = (Find-Module Posh-SSH -Repository PSGallery).Version
	If ($ModVer -ne $AvailableModVer) {
		Write-host "Posh-SSH has an update from $ModVer to $AvailableModVer.`nInstalling the update."
		Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
		Install-PackageProvider -Name NuGet -Force
		Remove-Module -Name Posh-SSH -Force -ErrorAction SilentlyContinue
		Uninstall-Module -Name Posh-SSH -AllVersions -Force -ErrorAction SilentlyContinue
		If (Get-Module -Name Posh-SSH -ListAvailable) {
			$ModPath = (Get-Module -Name Posh-SSH -ListAvailable).ModuleBase
			$ArgumentList = '/C "taskkill /IM powershell.exe /F & rd /s /q "' + $ModPath + '" & start powershell -NoExit -ExecutionPolicy Bypass -Command "irm raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt | iex ; Invoke-NDDCScan"'
			Remove-PathForcefully -Path $ModPath
			If (Get-Item -Path $ModPath -ErrorAction SilentlyContinue) {
				Start-Process "cmd.exe" -ArgumentList $ArgumentList
			}
		}
		Install-Module -Name Posh-SSH -AllowClobber -Force
	}	Else {
		Write-host "Posh-SSH is already up to date at version $AvailableModVer."
	}

Write-Host "Downloading the NDDC Utility"
	$NddcURL = "https://s3.amazonaws.com/networkdetective/download/NetworkDetectiveDataCollector.exe"
	$NddcFolder = $ITFolder + '\NddcAuto'
	$null = (New-Item -ItemType Directory -Force -Path $NddcFolder)
	$NddcDownloadPath = $NddcFolder + '\NetworkDetectiveDataCollector.zip'
	$Nddcexe = $NddcFolder + '\nddc.exe'
	Remove-Item $NddcDownloadPath -ea SilentlyContinue
	Invoke-ValidatedDownload -Uri $NddcURL -OutFile $NddcDownloadPath
	Expand-Archive -Path $NddcDownloadPath -DestinationPath $NddcFolder -Force

Write-Host "Optimizing Run Settings based on previous manual run."
	$PCInfo = Get-ComputerInfo
	$RunNdp = Get-Content "$ITFolder\nddc\run.ndp"

	$OutbaseLine = $($RunNdp | Select-String -Pattern '-outbase').LineNumber
	$nddcountbase = "nddc_" + $($PCInfo.CsDomain) + "_" + $($PCInfo.CsName) + "_" + $(Get-date -Format yyyy-MM-dd)
	$RunNdp[$OutbaseLine] = $nddcountbase

	$outdirLine = $($RunNdp | Select-String -Pattern '-outdir').LineNumber
	$outputfolder = $NddcFolder + '\' + $nddcountbase
	$null = (New-Item -ItemType Directory -Force -Path $outputfolder)
	$nddcoutdir = $outputfolder
	$RunNdp[$outdirLine] = $nddcoutdir

	If (Test-Path "$ITFolder\scripts\Server_Reboot_Cred.txt") {
		$CredUserLine = $($RunNdp | Select-String -Pattern '-credsuser').LineNumber
		$RunNdp[$CredUserLine] = gc $ITFolder\scripts\server_reboot_user.txt

		$credsepwd2Line = $($RunNdp | Select-String -Pattern '-credsepwd2').LineNumber
		$RunNdp[$($credsepwd2Line -1)] = '-credsepwd'
		$RunNdp[$credsepwd2Line] = (pwsh -command "Get-Content '$ITFolder\Scripts\Server_Reboot_Cred.txt' | ConvertTo-SecureString | ConvertFrom-SecureString -asplaintext")
	}

	$RunNdpFile = $NddcFolder + '\run.ndp'
	$RunNdp | Set-Content -Path $RunNdpFile -Force


Write-Host "Running NDDC"
	& $Nddcexe -file $RunNdpFile
	Clear-Content -Path $RunNdpFile -Force
	$ExportedFile = $($outputfolder + "\" + $nddcountbase + ".ndf")

# Check for credentials
	$SshKeyPath = $ITFolder + '\.ssh\nddc.id_rsa'
	If (-not (Test-Path $SshKeyPath)) {
		Write-Error "ERROR: .SSH Key not found at $ITFolder\.ssh\nddc.id_rsa. - - Check documentation for remedy."
		Write-Host "Send to Teams"
		$Message = "ERROR: .SSH Key not found at $ITFolder\.ssh\nddc.id_rsa. - - Check documentation for remedy."
		$server = "$env:computername"
		$color = 'ff0000'
		Send-To-Teams

	Write-Host "Logging the attempt"
		$date = Get-Date
		$date = $date.ToShortDateString()
		Add-Content "$ITFolder\NDDC Auto Scan Log.txt" "$date | .SSH Key not found at $ITFolder\.ssh\nddc.id_rsa. - - Check documentation for remedy."
	} Else {
	
	# Set local file path, SFTP path, and the backup location path which I assume is an SMB path
		$UploadID = $($PCInfo.CsDomain) + "_" + $($PCInfo.CsName)
		$SftpPath = "/home/dh_wu6qvp/<nddc.upload.server>/Uploads/" + $UploadID
		$SftpLink = "sftp://ftp.<nddc.upload.server>/Uploads/" + $UploadID

	# Set the IP of the SFTP server
		$SftpIp = 'ftp.<nddc.upload.server>'
		# Set the credentials
		$User = 'dh_wu6qvp'
		$Password = New-Object System.Security.SecureString
		$Credential = New-Object System.Management.Automation.PSCredential ('dh_wu6qvp', $Password)

	Write-Host "Establishing the SFTP connection"
		Get-SSHTrustedHost -HostName "ftp.<nddc.upload.server>" | Remove-SSHTrustedHost #Clears previously stored keys. They change over time with Dreamhost.
		$ThisSession = New-SFTPSession -KeyFile $SshKeyPath -ComputerName $SftpIp -Credential $Credential -AcceptKey

	Write-Host "Uploading the file to the SFTP path"
		New-SFTPItem -SessionId ($ThisSession).SessionId -Path $SftpPath -ItemType Directory -ErrorAction SilentlyContinue
		Set-SFTPItem -SessionId ($ThisSession).SessionId -Path $ExportedFile -Destination $SftpPath -Force

	Write-Host "Disconnecting all SFTP connections"
		Get-SFTPSession | Remove-SFTPSession -ErrorAction SilentlyContinue

	Write-Host "Send to Teams"
		$Message = "NDDC has scanned and uploaded to $SftpLink Check documentation for access credentials."
		If (Select-String -Path $ExportedFile -SimpleMatch "Invalid Active Directory username") {
			$Message = $Message + " The stored username and password appear to be incorrect. Please run NDDC manually at least once in $ITFolder\nddc and get to the point where the scan begins. You can cancel it after that."
			$Color = 'ff0000'
		}
		$server = "$env:computername"
		Send-To-Teams

	Write-Host "Logging the attempt"
		$date = Get-Date
		$date = $date.ToShortDateString()
		Add-Content "$ITFolder\NDDC Auto Scan Log.txt" "$date | NDDC has scanned and uploaded to $SftpLink Check documentation for access credentials."
		If (Select-String -Path $ExportedFile -SimpleMatch "Invalid Active Directory username") {
			Add-Content "$ITFolder\NDDC Auto Scan Log.txt" "$date | ERROR: The stored username and password appear to be incorrect. Please run NDDC manually at least once in $ITFolder\nddc and get to the point where the scan begins. You can cancel it after that."
		}

	Write-Host "Cleaning up"
		Remove-Item -Recurse -Force $outputfolder
	}
}

Function Invoke-SMBRemediation {
	[CmdletBinding(SupportsShouldProcess = $true)]
	param(
		[Parameter(Mandatory = $true)]
		[psobject]$Finding,

		[Parameter(Mandatory = $true)]
		[hashtable]$SafeRemediations,

		[Parameter(Mandatory = $false)]
		[psobject]$SmbConfig
	)

	if ($null -eq $SmbConfig) {
		return @([PSCustomObject]@{
			Target = 'SMB Server'
			Status = 'Skipped'
			PreviousValue = $null
			NewValue = $null
			Reason = 'SMB Server configuration not available (SmbServer module missing or query failed)'
		})
	}

	$PartialResults = [System.Collections.ArrayList]::new()

	foreach ($Key in $SafeRemediations.Keys) {
		if ($Key -notmatch '^SMB\.') { continue }

		$Rule = $SafeRemediations[$Key]
		$Property = $Rule.Property

		# Match this rule against the finding text
		if (-not ($Finding.Title -match $Property -or $Finding.Problem -match $Property -or $Finding.Resolution -match $Property)) {
			continue
		}

		$CurrentValue = $SmbConfig.$Property
		$TargetValue = $Rule.Value

		if ($CurrentValue -eq $TargetValue) {
			Write-Verbose "SMB: $Property is already at target value $TargetValue"
			continue
		}

		if ($PSCmdlet.ShouldProcess("SMB Server Configuration", "Set $Property from $CurrentValue to $TargetValue")) {
			try {
				$Params = @{ $Property = $TargetValue; Force = $true; Confirm = $false }
				Set-SmbServerConfiguration @Params -ErrorAction Stop
				$null = $PartialResults.Add([PSCustomObject]@{
					Target = 'SMB Server'
					Status = 'Remediated'
					PreviousValue = $CurrentValue
					NewValue = $TargetValue
					Reason = $Rule.Description
				})
				Write-Verbose "Remediated SMB: $($Rule.Description)"
			} catch {
				$null = $PartialResults.Add([PSCustomObject]@{
					Target = 'SMB Server'
					Status = 'Failed'
					PreviousValue = $CurrentValue
					NewValue = $TargetValue
					Reason = "Failed to set ${Property}: $_"
				})
			}
		} else {
			$null = $PartialResults.Add([PSCustomObject]@{
				Target = 'SMB Server'
				Status = 'Skipped'
				PreviousValue = $CurrentValue
				NewValue = $TargetValue
				Reason = 'WhatIf mode - no changes made'
			})
		}
	}

	return @($PartialResults)
}

Function Invoke-ValidatedDownload {
	<#
	.SYNOPSIS
		Downloads a file from an external URL and validates its SHA256 hash against a known-good manifest.
	.DESCRIPTION
		Wraps Invoke-WebRequest with integrity verification. Downloads the content to a temp file,
		computes its SHA256 hash, and compares it against DownloadManifest.json in the repo root.

		If the hash matches, the content or file path is returned.
		If the hash does not match (or the URL has no recorded hash), the operator is warned and
		prompted to proceed or abort. Non-interactive sessions (scheduled tasks, RMM) will block
		by default on mismatch.

		All download events (pass/fail) are logged to $ITFolder\ValidatedDownload.log.
	.PARAMETER Uri
		The URL to download from.
	.PARAMETER OutFile
		Optional file path to save the download to. If omitted, returns the downloaded content
		as a string (useful for piping to Invoke-Expression).
	.PARAMETER Force
		Skip the hash validation prompt and proceed even on mismatch.
	.EXAMPLE
		Invoke-ValidatedDownload -Uri "https://community.chocolatey.org/install.ps1" | Invoke-Expression
	.EXAMPLE
		Invoke-ValidatedDownload -Uri "https://example.com/tool.exe" -OutFile "$ITFolder\tool.exe"
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory=$true)]
		[string]$Uri,

		[Parameter(Mandatory=$false)]
		[string]$OutFile,

		[switch]$Force
	)

	# Locate manifest
	$ManifestPath = Join-Path $Global:PWSHFolder "DownloadManifest.json"
	$ManifestEntries = @{}
	if (Test-Path $ManifestPath) {
		try {
			$ManifestEntries = Get-Content $ManifestPath -Raw | ConvertFrom-Json
		} catch {
			Write-Warning "[Invoke-ValidatedDownload] Failed to parse manifest: $_"
		}
	} else {
		Write-Warning "[Invoke-ValidatedDownload] Manifest not found at $ManifestPath. Proceeding without validation."
	}

	# Download to temp file
	$TempFile = [System.IO.Path]::GetTempFileName()
	$prevPref = $ProgressPreference
	try {
		$ProgressPreference = 'SilentlyContinue'
		Invoke-WebRequest -Uri $Uri -OutFile $TempFile -UseBasicParsing
	} catch {
		Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
		throw "Failed to download from ${Uri}: $_"
	} finally {
		$ProgressPreference = $prevPref
	}

	# Compute hash of downloaded content
	$ActualHash = (Get-FileHash -Path $TempFile -Algorithm SHA256).Hash

	# Look up expected hash in manifest
	$Entry = $ManifestEntries.PSObject.Properties | Where-Object { $_.Name -eq $Uri } | Select-Object -First 1
	$Expected = if ($Entry) { $Entry.Value } else { $null }

	$Validated = $false

	if ($Expected -and $Expected.SHA256) {
		if ($Expected.SHA256 -eq "UPDATE_WITH_ACTUAL_HASH") {
			Write-Warning "[Invoke-ValidatedDownload] No hash recorded yet for: $Uri"
			Write-Warning "  Computed SHA256: $ActualHash"
			Write-Warning "  Update DownloadManifest.json with this hash after manual verification."
		} elseif ($Expected.SHA256 -eq $ActualHash) {
			$Validated = $true
			Write-Verbose "[Invoke-ValidatedDownload] Hash verified for: $Uri"
		} else {
			Write-Warning "[Invoke-ValidatedDownload] HASH MISMATCH for: $Uri"
			Write-Warning "  Expected: $($Expected.SHA256)"
			Write-Warning "  Actual:   $ActualHash"
		}
	} else {
		Write-Warning "[Invoke-ValidatedDownload] URL not in manifest: $Uri"
		Write-Warning "  Computed SHA256: $ActualHash"
	}

	# Log every download attempt
	$LogPath = Join-Path $Global:ITFolder "ValidatedDownload.log"
	$Status = if ($Validated) { "PASS" } else { "MISMATCH" }
	$ExpectedHash = if ($Expected -and $Expected.SHA256) { $Expected.SHA256 } else { "NOT_IN_MANIFEST" }
	$LogEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $Status | $Uri | Expected: $ExpectedHash | Actual: $ActualHash"
	try { Add-Content -Path $LogPath -Value $LogEntry -Force } catch { }

	# Decide whether to proceed on mismatch
	if (-not $Validated -and -not $Force) {
		if ([Environment]::UserInteractive) {
			Write-Host ""
			Write-Host "  [SECURITY] Hash validation failed for:" -ForegroundColor Red
			Write-Host "    $Uri" -ForegroundColor Yellow
			Write-Host "  Expected: $ExpectedHash" -ForegroundColor Yellow
			Write-Host "  Actual:   $ActualHash" -ForegroundColor Yellow
			Write-Host ""
			$response = Read-Host "Proceed anyway? (Y/N)"
			if ($response -ne 'Y' -and $response -ne 'y') {
				Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
				throw "Download aborted by operator due to hash mismatch: $Uri"
			}
		} else {
			# Non-interactive (scheduled task, RMM) - block for safety
			Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
			throw "Download blocked (non-interactive, hash validation failed): $Uri. Update DownloadManifest.json with the new hash to proceed."
		}
	}

	# Return content or save to file
	if ($OutFile) {
		$OutDir = Split-Path -Path $OutFile -Parent
		if ($OutDir -and -not (Test-Path $OutDir)) {
			New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
		}
		Copy-Item -Path $TempFile -Destination $OutFile -Force
		Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
		return $OutFile
	} else {
		$Content = Get-Content -Path $TempFile -Raw
		Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
		return $Content
	}
}

Function Invoke-Win10Decrap {
	Write-Host "Windows 10 Decrapifier"
	$progressPreference = 'silentlyContinue'
	Set-ExecutionPolicy Bypass -Scope Process -Force
	Enable-SSL
	Invoke-WebRequest https://raw.githubusercontent.com/MauleTech/PWSH/master/Scripts/Win-10-DeCrapifier/Windows10Decrapifier.txt -UseBasicParsing | Invoke-Expression
}
