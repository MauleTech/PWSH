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
	<#
		.SYNOPSIS
		Asynchronous IPv4 Network Scanner with auto-detection and MAC/vendor resolution.

		.DESCRIPTION
		Scans IPv4 networks using parallel ICMP requests via runspace pools. When called
		with no parameters, auto-detects active local network adapters and scans each subnet.
		Supports explicit IP ranges, CIDR notation, and subnet masks.

		By default, resolves DNS hostnames and MAC addresses with vendor lookup (OUI).
		The OUI database is downloaded from IEEE with fallback to Wireshark and maclookup.app
		mirrors. Results are sorted by IP address and displayed as a table.

		Security: Downloaded OUI data is only used as string lookups in a hash table.
		It is never passed to Invoke-Expression or evaluated as code, so a compromised
		OUI source cannot inject executable content.

		.EXAMPLE
		Invoke-IPv4NetworkScan

		Auto-detects local networks and scans all active subnets with DNS and MAC resolution.

		.EXAMPLE
		Invoke-IPv4NetworkScan -StartIPv4Address 192.168.1.0 -EndIPv4Address 192.168.1.50

		Scans a specific IP range.

		.EXAMPLE
		Invoke-IPv4NetworkScan -IPv4Address 192.168.1.0 -CIDR 24 -DisableMACResolving

		Scans a /24 subnet without MAC/vendor resolution.

		.EXAMPLE
		Invoke-IPv4NetworkScan -Force

		Auto-detects and scans without prompting, even if the network has more than 1000 IPs.

		.EXAMPLE
		Invoke-IPv4NetworkScan -DetectHiddenDevices

		Auto-detects local networks. Devices blocking ICMP are probed with ARP,
		TCP port scanning, and NetBIOS queries. A DetectionMethod column shows
		how each device was ultimately detected.
	#>

	[CmdletBinding(DefaultParameterSetName = 'Auto', SupportsShouldProcess = $true)]
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
			HelpMessage = 'Disable MAC-Address and vendor resolution (Default=Enabled)')]
		[Switch]$DisableMACResolving,

		[Parameter(
			Position = 6,
			HelpMessage = 'Get extendend informations like BufferSize, ResponseTime and TTL (Default=Disabled)')]
		[Switch]$ExtendedInformations,

		[Parameter(
			Position = 7,
			HelpMessage = 'Include inactive devices in result')]
		[Switch]$IncludeInactive,

		[Parameter(
			Position = 8,
			HelpMessage = 'Bypass confirmation prompt when auto-detecting networks with more than 1000 IPs')]
		[Switch]$Force,

		[Parameter(
			Position = 9,
			HelpMessage = 'Detect devices that block ICMP using ARP, TCP, and NetBIOS probes')]
		[Switch]$DetectHiddenDevices
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
		# Build list of networks to scan
		$NetworksToScan = @()

		if ($PSCmdlet.ParameterSetName -eq 'Auto') {
			# Auto-detect local networks
			Write-Verbose -Message "Auto-detecting local networks..."

			# Get active adapters and their IPs, filtering out disconnected and loopback
			$ActiveAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
			$LocalAddresses = @(Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp, Manual -ErrorAction SilentlyContinue |
				Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.InterfaceIndex -in $ActiveAdapters.ifIndex })

			if ($LocalAddresses.Count -eq 0) {
				Write-Error -Message "No active IPv4 network interfaces found for auto-detection. Specify an IP range manually." -Category ObjectNotFound -ErrorAction Stop
			}

			$TotalIPs = 0
			$SeenNetworks = @{}

			foreach ($Addr in $LocalAddresses) {
				$AddrSubnet = Get-IPv4Subnet -IPv4Address $Addr.IPAddress -CIDR $Addr.PrefixLength

				# Deduplicate overlapping subnets (e.g. Ethernet and Wi-Fi on the same network)
				$NetworkKey = "$($AddrSubnet.NetworkID)/$($Addr.PrefixLength)"
				if ($SeenNetworks.ContainsKey($NetworkKey)) {
					Write-Verbose -Message "Skipping $($Addr.InterfaceAlias) ($($Addr.IPAddress)) - same subnet as $($SeenNetworks[$NetworkKey])"
					continue
				}
				$SeenNetworks[$NetworkKey] = $Addr.InterfaceAlias

				$TotalIPs += ($AddrSubnet.IPs)
				$NetworksToScan += [pscustomobject] @{
					InterfaceAlias   = $Addr.InterfaceAlias
					StartIPv4Address = $AddrSubnet.NetworkID
					EndIPv4Address   = $AddrSubnet.Broadcast
				}
			}

			if ($TotalIPs -gt 1000 -and -not $Force) {
				if (-not $PSCmdlet.ShouldContinue("Auto-detected $($NetworksToScan.Count) network(s) with $TotalIPs total IPs. Continue?", "Large Network Scan")) {
					Write-Warning -Message "Scan cancelled by user."
					return
				}
			}
		}
		else {
			# Calculate Subnet (Start and End IPv4-Address) for CIDR/Mask parameter sets
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

			$NetworksToScan += [pscustomobject] @{
				InterfaceAlias   = $null
				StartIPv4Address = $StartIPv4Address
				EndIPv4Address   = $EndIPv4Address
			}
		}

		# Properties which are displayed in the output
		$PropertiesToDisplay = @()
		$PropertiesToDisplay += "IPv4Address", "Status"

		if ($DetectHiddenDevices) {
			$PropertiesToDisplay += "DetectionMethod"
		}

		if ($DisableDNSResolving -eq $false) {
			$PropertiesToDisplay += "Hostname"
		}

		if (-not $DisableMACResolving) {
			$PropertiesToDisplay += "MAC"
		}

		$AssignVendorToMAC = $false

		# Check if it is possible to assign vendor to MAC --> download and import OUI list
		# Security: OUI data is only used as string lookups in a hash table - never evaluated as code.
		if (-not $DisableMACResolving) {
			$OUI_Sources = @(
				@{ Uri = "https://standards-oui.ieee.org/oui/oui.txt"; Name = "IEEE" },
				@{ Uri = "https://www.wireshark.org/download/automated/data/manuf"; Name = "Wireshark" },
				@{ Uri = "https://maclookup.app/downloads/json-database/get-db"; Name = "maclookup.app" }
			)
			$OUILines = $null
			$PreviousSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
			try {
				[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls13
			}
			catch {
				[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
			}

			foreach ($Source in $OUI_Sources) {
				for ($RetryCount = 1; $RetryCount -le 2; $RetryCount++) {
					try {
						$RawData = Invoke-RestMethod -Uri $Source.Uri -ErrorAction Stop
						$OUILines = [System.Collections.Generic.List[string]]::new()

						switch ($Source.Name) {
							"IEEE" {
								# Lines: "2405F5     (base 16)		Vendor Name"
								foreach ($Line in $RawData -split '[\r\n]') {
									if ($Line -match "^[A-F0-9]{6}") {
										$OUILines.Add(($Line -replace '\s+', ' ').Replace(' (base 16) ', '|').Trim())
									}
								}
							}
							"Wireshark" {
								# Lines: "00:00:0C\tShortName\tFull Vendor Name"
								foreach ($Line in $RawData -split '[\r\n]') {
									if ($Line -match "^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\t") {
										$Parts = $Line -split "`t"
										$MAC = $Parts[0].Replace(":", "").ToUpper()
										$Vendor = if ($Parts.Count -ge 3 -and $Parts[2]) { $Parts[2] } else { $Parts[1] }
										$OUILines.Add("$MAC|$Vendor")
									}
								}
							}
							"maclookup.app" {
								# JSON array of objects with macPrefix and vendorName
								foreach ($Entry in $RawData) {
									if ($Entry.macPrefix -and $Entry.vendorName) {
										$MAC = $Entry.macPrefix.Replace(":", "").ToUpper()
										$OUILines.Add("$MAC|$($Entry.vendorName)")
									}
								}
							}
						}

						if ($OUILines.Count -gt 0) { break }
					}
					catch {
						if ($RetryCount -lt 2) {
							Write-Warning "OUI download from $($Source.Name) failed: $($_.Exception.Message). Retrying..."
							Start-Sleep -Seconds 2
						}
					}
				}
				if ($OUILines -and $OUILines.Count -gt 0) {
					Write-Verbose -Message "Downloaded OUI data from $($Source.Name) ($($OUILines.Count) entries)"
					break
				}
				Write-Warning "Failed to download OUI data from $($Source.Name), trying next source..."
			}

			[Net.ServicePointManager]::SecurityProtocol = $PreviousSecurityProtocol

			if ($OUILines -and $OUILines.Count -gt 0) {
				Out-File -InputObject ($OUILines -join "`n") -FilePath "$ITFolder\oui.txt"
			}

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
				$DisableMACResolving,
				$ExtendedInformations,
				$IncludeInactive,
				$DetectHiddenDevices
			)

			# +++ Wave 1: Send ICMP requests +++
			$Status = [String]::Empty
			$DetectionMethod = [String]::Empty

			for ($i = 0; $i -lt $Tries; $i++) {
				try {
					$PingObj = New-Object System.Net.NetworkInformation.Ping

					$Timeout = 1000
					$Buffer = New-Object Byte[] 32

					$PingResult = $PingObj.Send($IPv4Address, $Timeout, $Buffer)

					if ($PingResult.Status -eq "Success") {
						$Status = "Up"
						$DetectionMethod = "ICMP"
						break
					}
					else {
						$Status = "Down"
					}
				}
				catch {
					$Status = "Down"
					break
				}
			}

			# +++ Hidden device detection waves (only when ICMP failed) +++
			if ($DetectHiddenDevices -and $Status -eq "Down") {

				# --- Wave 2: ARP probe via SendARP P/Invoke ---
				try {
					$arpMAC = [Win32.Network]::GetMAC($IPv4Address)
					if ($arpMAC) {
						$Status = "Up"
						$DetectionMethod = "ARP"
					}
				}
				catch { }

				# --- Wave 3: TCP port probe on common ports ---
				if ($Status -eq "Down") {
					$CommonPorts = @(445, 80, 443, 3389, 22, 139, 8080)
					foreach ($Port in $CommonPorts) {
						try {
							$tcp = New-Object System.Net.Sockets.TcpClient
							$ar = $tcp.BeginConnect($IPv4Address, $Port, $null, $null)
							$waited = $ar.AsyncWaitHandle.WaitOne(500, $false)
							if ($waited -and $tcp.Connected) {
								$Status = "Up"
								$DetectionMethod = "TCP:$Port"
								$tcp.Close()
								break
							}
							$tcp.Close()
						}
						catch [System.Net.Sockets.SocketException] {
							# Connection refused (RST) means the host IS alive
							if ($_.Exception.SocketErrorCode -eq 'ConnectionRefused') {
								$Status = "Up"
								$DetectionMethod = "TCP:$Port"
								break
							}
						}
						catch { }
						finally {
							if ($tcp) { $tcp.Dispose() }
						}
					}
				}

				# --- Wave 4: NetBIOS name query (UDP 137) ---
				if ($Status -eq "Down") {
					try {
						$udp = New-Object System.Net.Sockets.UdpClient
						$udp.Client.ReceiveTimeout = 1000
						# NBNS wildcard query packet
						[byte[]]$nbQuery = @(
							0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4B, 0x41,
							0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
							0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
							0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
							0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
							0x00, 0x01
						)
						$ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($IPv4Address), 137)
						[void]$udp.Send($nbQuery, $nbQuery.Length, $ep)
						$remoteEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
						$response = $udp.Receive([ref]$remoteEp)
						if ($response.Length -gt 0) {
							$Status = "Up"
							$DetectionMethod = "NetBIOS"
						}
						$udp.Close()
					}
					catch { }
					finally {
						if ($udp) { $udp.Dispose() }
					}
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

			if ((-not $DisableMACResolving) -and (($Status -eq "Up") -or ($IncludeInactive))) {
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
					IPv4Address     = $IPv4Address
					Status          = $Status
					DetectionMethod = $DetectionMethod
					Hostname        = $Hostname
					MAC             = $MAC
					BufferSize      = $BufferSize
					ResponseTime    = $ResponseTime
					TTL             = $TTL
				}
			}
			else {
				$null
			}
		}

		# Compile SendARP P/Invoke for hidden device detection (loaded into AppDomain, visible to all runspaces)
		if ($DetectHiddenDevices) {
			Write-Warning "DetectHiddenDevices is enabled - devices that block ICMP will be probed using ARP, TCP, and NetBIOS. This may significantly increase scan time."

			if (-not ([System.Management.Automation.PSTypeName]'Win32.Network').Type) {
				$SendArpSource = @"
using System;
using System.Net;
using System.Runtime.InteropServices;

namespace Win32 {
    public static class Network {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(uint DestIP, uint SrcIP, byte[] macAddr, ref int macAddrLen);

        public static string GetMAC(string ipAddress) {
            try {
                uint ip = BitConverter.ToUInt32(IPAddress.Parse(ipAddress).GetAddressBytes(), 0);
                byte[] mac = new byte[6];
                int macLen = mac.Length;
                if (SendARP(ip, 0, mac, ref macLen) == 0)
                    return BitConverter.ToString(mac, 0, macLen);
            } catch { }
            return null;
        }
    }
}
"@
				Add-Type -TypeDefinition $SendArpSource -ErrorAction SilentlyContinue
			}
		}

		# Create shared RunspacePool for all networks
		Write-Verbose -Message "Setting up RunspacePool..."
		$RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Threads, $Host)
		$RunspacePool.Open()

		# Register table format view so results always display as a table regardless of property count
		$HeaderXml = ($PropertiesToDisplay | ForEach-Object { "<TableColumnHeader><Label>$_</Label></TableColumnHeader>" }) -join "`n                        "
		$ColumnXml = ($PropertiesToDisplay | ForEach-Object { "<TableColumnItem><PropertyName>$_</PropertyName></TableColumnItem>" }) -join "`n                                "
		$FormatXml = @"
<?xml version="1.0" encoding="utf-8" ?>
<Configuration>
    <ViewDefinitions>
        <View>
            <Name>IPv4NetworkScan.Result</Name>
            <ViewSelectedBy>
                <TypeName>IPv4NetworkScan.Result</TypeName>
            </ViewSelectedBy>
            <TableControl>
                <AutoSize/>
                <TableHeaders>
                    $HeaderXml
                </TableHeaders>
                <TableRowEntries>
                    <TableRowEntry>
                        <TableColumnItems>
                            $ColumnXml
                        </TableColumnItems>
                    </TableRowEntry>
                </TableRowEntries>
            </TableControl>
        </View>
    </ViewDefinitions>
</Configuration>
"@
		$FormatFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "IPv4NetworkScan.format.ps1xml")
		$FormatXml | Out-File -FilePath $FormatFile -Encoding UTF8
		Update-FormatData -PrependPath $FormatFile

		# Scan each network
		foreach ($NetworkToScan in $NetworksToScan) {
			$StartIPv4Address = $NetworkToScan.StartIPv4Address
			$EndIPv4Address = $NetworkToScan.EndIPv4Address

			if ($NetworkToScan.InterfaceAlias) {
				Write-Host "Scanning $($NetworkToScan.InterfaceAlias): $StartIPv4Address - $EndIPv4Address" -ForegroundColor Cyan
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
					DisableMACResolving  = $DisableMACResolving
					ExtendedInformations = $ExtendedInformations
					IncludeInactive      = $IncludeInactive
					DetectHiddenDevices  = $DetectHiddenDevices
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
			[System.Collections.ArrayList]$NetworkResults = @()

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

							$Result = [pscustomobject] @{
								IPv4Address     = $Job_Result.IPv4Address
								Status          = $Job_Result.Status
								DetectionMethod = $Job_Result.DetectionMethod
								Hostname        = $Job_Result.Hostname
								MAC             = $Job_Result.MAC
								Vendor          = $Vendor
								BufferSize      = $Job_Result.BufferSize
								ResponseTime    = $Job_Result.ResponseTime
								TTL             = $Job_Result.TTL
							} | Select-Object -Property $PropertiesToDisplay
						}
						else {
							$Result = $Job_Result | Select-Object -Property $PropertiesToDisplay
						}

						# Tag with custom type so the registered format view forces table output
						$Result.PSObject.TypeNames.Insert(0, 'IPv4NetworkScan.Result')

						# Collect result for sorting
						[void]$NetworkResults.Add($Result)
					}
				}

			} While ($Jobs.Count -gt 0)

			# Emit results sorted by IPv4 address
			$NetworkResults | Sort-Object -Property { (Convert-IPv4Address -IPv4Address $_.IPv4Address).Int64 }
		}

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

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBhwdHeAm/sfCdS
# 3QE9OmeSPHxX1/bqbo0/Hp9K8UbhCqCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IOSir63+bdRcy6rKHzpqzevIN4iITm0ANtnGqTxiiggaMA0GCSqGSIb3DQEBAQUA
# BIICAFJhKcUSt53a5HXESGyEDoUHjkvvhopDxTzt2ZPHUCj5FwnpnDK/GlJ+oUZY
# 2icB/NDbTBE6cD9lqZlqLERLscvxV809jpZGUaIGRHcVOQmCuCMYx/O8BSPYEpfD
# OW6lB9AJqShyHjEhBUcFpjfsenaEIDO8+xMrwJmE068MpkRF2kPYsIZJtU3MJJRH
# EnFg1bhSNOLz4Bwx89SnZSdfrdA6/Fqap39merkEKww0ft2x19subG1T/CjDTaea
# hTqfj45PmKG7EuSJ811PS98ibyUTEldHSKmoH9sr0VaahKxQvnCZA9Tuvtvjk8pQ
# jFCgvacrUWLr6mDknXWON8eb2IfaqLV+uJCPwwOujyN5SDiwy6Dp1lGDGXZIcwtj
# fgOwFjMOrKkRQF/aZeFHB/izlaHSPE4tIhLSRYPp8rM13Z+p8ySuN0uWtMMyq+og
# sdxuS9u8VeHi35gYRgO8WzNs+q6JYSpDlPNjP3cDsauYcvmfxJghX8aVtHo+6ehC
# GOJRPuvw06C+oOp8JfRCu/BMZ4HhHaH4KgFqzy/K/t6g5FnBkcwTOypCz0JqbnRK
# Pmy9AgVjB4l0V07NzW+jE1Z05ZULhicMRcxGVemLd7awPm10hzhi0kDCFwhSzybH
# Dz5vcb8LazOAQ4ob6c8fERnnVZHx1RVYNTKQwsAKxeCTxVXSoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDQwNzIxNDUyM1owLwYJKoZIhvcNAQkEMSIEIOjDJ6rP
# Hk/j+d7bWcbsXxpQtf5zUWhraAGFUeNlyKJrMA0GCSqGSIb3DQEBAQUABIICABEk
# o/SWHnCZ7i+30ERJUXcQnbv0aUhBR1imA2Qj0XwTsIf0wDd4glix3ED1l6SgTiBT
# L9DoyQGDZuvDaYrja0PA3vhE26TRYHMJJoYfFRVkiQeA6TlLGjNrY9pVdkc78VIw
# RaL3wzpWHSZ//DCRZq0MYjGGtPwo3TPsosffPgiLHYB0+EMtjxbr1J2ysynZBzAM
# Uf9hzeNsO/HOMukIqmPQRZee3ZY4bUncHAvUj1YRcZcFhoEyDaHp/p02cIjJyQbZ
# ht/LI8+tWaf5ni88Z3PwZ2x2yyDdbYkOAAKxHwHaJQD0qsisqKZB+kpmStRJFJB+
# sJmX3YTfntISP7g7T90vWSyCqJNnAnTyV+w8q0CKOcGFf1UbWHmLg3jHrqGENCi3
# X31FOVUw3jkPZsbJF8fSFLHEyNWR80AcR/0sy/qHQj6uOfwggpmRK63a5YWJd1UA
# zKxu9R5/HfpjEforAhOAJgYXm43b0yRCD5LKoancshhC1K7nLIbERGjETHo50oiK
# XnB0ZiTxGFXf5XWPZsCmSvEqooBbEfpv6ZDip9BS0Zx8nJllCy1xvMNJ/323cukU
# 2ukf7wlzT3tijzx/vPKm2P9+mnl9MWEkonGERbTy1EWMP8l0yYei31FeyxEYKAio
# m8kccvHFt590RqZV/I0yC0g5qHE53SzrYyZNx1zS
# SIG # End signature block
