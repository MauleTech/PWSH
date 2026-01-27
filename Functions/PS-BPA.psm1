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
		Invoke-BPARemediation -ComputerName "SERVER01" -OutputPath "C:\Reports\BPA-Report.html"
		Remediate a remote server and export an HTML report.

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

		# Check for BestPractices module
		if (-not (Get-Module -ListAvailable -Name BestPractices)) {
			throw "BestPractices module not found. This function requires Windows Server with the BestPractices module."
		}

		Import-Module BestPractices -ErrorAction Stop

		Write-Verbose "Starting BPA Remediation on $ComputerName"

		# Define safe remediations - structure allows easy expansion
		# Format: RuleId/Pattern = @{ Type = 'Registry'|'SMB'|'DNS'|'Manual'; Action = scriptblock or description }
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

		# Patterns that indicate issues requiring manual attention
		$ManualReviewPatterns = @(
			'credential',
			'certificate',
			'schema',
			'forest',
			'network adapter',
			'IP address',
			'IP configuration',
			'DHCP.*DNS.*credential',
			'account',
			'password',
			'authentication',
			'domain controller',
			'replication'
		)

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

			# Invoke BPA scan
			try {
				Write-Verbose "Running BPA scan for $($Model.Id)..."
				if ($ComputerName -eq 'localhost' -or $ComputerName -eq $env:COMPUTERNAME) {
					$null = Invoke-BpaModel -Id $Model.Id -ErrorAction Stop
				} else {
					$null = Invoke-BpaModel -Id $Model.Id -ComputerName $ComputerName -ErrorAction Stop
				}
			} catch {
				Write-Warning "Failed to invoke BPA scan for $($Model.Id): $_"
				continue
			}

			# Get BPA results
			try {
				$BpaResults = Get-BpaResult -ModelId $Model.Id -ErrorAction Stop
				if ($Category) {
					$BpaResults = $BpaResults | Where-Object { $Category -contains $_.Category }
				}
				# Filter to non-compliant results
				$BpaResults = $BpaResults | Where-Object { $_.Compliance -ne $true -and $_.Severity -ne 'Informational' }
			} catch {
				Write-Warning "Failed to get BPA results for $($Model.Id): $_"
				continue
			}

			Write-Verbose "Found $($BpaResults.Count) non-compliant BPA finding(s) for $($Model.Id)"

			foreach ($Finding in $BpaResults) {
				$ResultObj = [PSCustomObject]@{
					Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
					ComputerName = $ComputerName
					ModelId = $Model.Id
					RuleId = $Finding.RuleId
					Title = $Finding.Title
					Category = $Finding.Category
					Severity = $Finding.Severity
					Status = 'Pending'
					PreviousValue = $null
					NewValue = $null
					Reason = $null
				}

				# Check if this requires manual review
				$RequiresManualReview = $false
				foreach ($Pattern in $ManualReviewPatterns) {
					if ($Finding.Title -match $Pattern -or $Finding.Problem -match $Pattern -or $Finding.Resolution -match $Pattern) {
						$RequiresManualReview = $true
						$ResultObj.Status = 'ManualRequired'
						$ResultObj.Reason = "Contains sensitive pattern: $Pattern - requires manual review"
						break
					}
				}

				if ($RequiresManualReview) {
					Write-Verbose "Skipping $($Finding.RuleId): Requires manual review"
					$null = $Results.Add($ResultObj)
					continue
				}

				# Try to find a matching safe remediation
				$Remediated = $false

				# Check SMB-related findings
				if ($Finding.Title -match 'SMB|Server Message Block|file server' -or $Model.Id -match 'FileServices') {
					$Remediated = Invoke-SMBRemediation -Finding $Finding -ResultObj $ResultObj -SafeRemediations $SafeRemediations -WhatIf:$WhatIfPreference -Verbose:$VerbosePreference
				}

				# Check DNS-related findings
				if ((-not $Remediated) -and ($Finding.Title -match 'DNS' -or $Model.Id -match 'DNS')) {
					$Remediated = Invoke-DNSRemediation -Finding $Finding -ResultObj $ResultObj -WhatIf:$WhatIfPreference -Verbose:$VerbosePreference
				}

				# Check DHCP-related findings
				if ((-not $Remediated) -and ($Finding.Title -match 'DHCP' -or $Model.Id -match 'DHCP')) {
					$Remediated = Invoke-DHCPRemediation -Finding $Finding -ResultObj $ResultObj -WhatIf:$WhatIfPreference -Verbose:$VerbosePreference
				}

				# If no specific remediation found, mark as skipped
				if (-not $Remediated -and $ResultObj.Status -eq 'Pending') {
					$ResultObj.Status = 'Skipped'
					$ResultObj.Reason = 'No safe automated remediation available'
				}

				$null = $Results.Add($ResultObj)
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
		Write-Host "Total Findings: $($Results.Count)"
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
					$HtmlContent = $Results | ConvertTo-Html -Title "BPA Remediation Report" -PreContent "<h1>BPA Remediation Report</h1><p>Generated: $(Get-Date)</p><p>Computer: $ComputerName</p>" | Out-String
					$HtmlContent | Out-File -FilePath $OutputPath -Encoding ASCII -Force
					Write-Host "Report exported to: $OutputPath" -ForegroundColor Green
				}
			} catch {
				Write-Error "Failed to export report: $_"
			}
		}

		# Return results
		return $Results
	}
}

Function Invoke-SMBRemediation {
	<#
	.SYNOPSIS
		Internal helper function to remediate SMB-related BPA findings.
	#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	param(
		[Parameter(Mandatory = $true)]
		$Finding,

		[Parameter(Mandatory = $true)]
		[PSCustomObject]$ResultObj,

		[Parameter(Mandatory = $true)]
		[hashtable]$SafeRemediations
	)

	# Check if SmbServer module is available
	if (-not (Get-Module -ListAvailable -Name SmbServer -ErrorAction SilentlyContinue)) {
		$ResultObj.Status = 'Skipped'
		$ResultObj.Reason = 'SmbServer module not available'
		return $false
	}

	try {
		$SmbConfig = Get-SmbServerConfiguration -ErrorAction Stop
	} catch {
		$ResultObj.Status = 'Failed'
		$ResultObj.Reason = "Failed to get SMB configuration: $_"
		return $false
	}

	# Check each SMB remediation rule
	foreach ($Key in $SafeRemediations.Keys) {
		if ($Key -notmatch '^SMB\.') { continue }

		$Rule = $SafeRemediations[$Key]
		$Property = $Rule.Property

		# Check if this finding relates to this property
		if ($Finding.Title -match $Property -or $Finding.Problem -match $Property -or $Finding.Resolution -match $Property) {
			$CurrentValue = $SmbConfig.$Property
			$TargetValue = $Rule.Value

			if ($CurrentValue -ne $TargetValue) {
				$ResultObj.PreviousValue = $CurrentValue
				$ResultObj.NewValue = $TargetValue

				if ($PSCmdlet.ShouldProcess("SMB Server Configuration", "Set $Property from $CurrentValue to $TargetValue")) {
					try {
						$Params = @{ $Property = $TargetValue; Force = $true; Confirm = $false }
						Set-SmbServerConfiguration @Params -ErrorAction Stop
						$ResultObj.Status = 'Remediated'
						$ResultObj.Reason = $Rule.Description
						Write-Verbose "Remediated: $($Rule.Description)"
						return $true
					} catch {
						$ResultObj.Status = 'Failed'
						$ResultObj.Reason = "Failed to set $Property : $_"
						return $false
					}
				} else {
					$ResultObj.Status = 'Skipped'
					$ResultObj.Reason = 'WhatIf mode - no changes made'
					return $true
				}
			}
		}
	}

	return $false
}

Function Invoke-DNSRemediation {
	<#
	.SYNOPSIS
		Internal helper function to remediate DNS-related BPA findings.
	#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	param(
		[Parameter(Mandatory = $true)]
		$Finding,

		[Parameter(Mandatory = $true)]
		[PSCustomObject]$ResultObj
	)

	# Check if DnsServer module is available
	if (-not (Get-Module -ListAvailable -Name DnsServer -ErrorAction SilentlyContinue)) {
		$ResultObj.Status = 'Skipped'
		$ResultObj.Reason = 'DnsServer module not available - DNS role may not be installed'
		return $false
	}

	# Handle zone notify settings
	if ($Finding.Title -match 'notify|secondary|zone transfer') {
		try {
			$Zones = Get-DnsServerZone -ErrorAction Stop | Where-Object { $_.ZoneType -eq 'Primary' -and -not $_.IsAutoCreated }

			foreach ($Zone in $Zones) {
				# Check if there are secondary servers configured
				$ZoneInfo = Get-DnsServerZone -Name $Zone.ZoneName -ErrorAction SilentlyContinue

				if ($ZoneInfo -and ($null -eq $ZoneInfo.SecondaryServers -or $ZoneInfo.SecondaryServers.Count -eq 0)) {
					$ResultObj.PreviousValue = $ZoneInfo.Notify
					$ResultObj.NewValue = 'NoNotify'

					if ($ZoneInfo.Notify -ne 'NoNotify') {
						if ($PSCmdlet.ShouldProcess("DNS Zone: $($Zone.ZoneName)", "Set Notify to NoNotify (no secondaries configured)")) {
							try {
								Set-DnsServerZone -Name $Zone.ZoneName -Notify 'NoNotify' -ErrorAction Stop
								$ResultObj.Status = 'Remediated'
								$ResultObj.Reason = "Set zone notify to NoNotify - no secondary servers configured"
								Write-Verbose "Remediated DNS zone $($Zone.ZoneName): Set Notify to NoNotify"
								return $true
							} catch {
								$ResultObj.Status = 'Failed'
								$ResultObj.Reason = "Failed to set zone notify: $_"
								return $false
							}
						} else {
							$ResultObj.Status = 'Skipped'
							$ResultObj.Reason = 'WhatIf mode - no changes made'
							return $true
						}
					}
				}
			}
		} catch {
			$ResultObj.Status = 'Failed'
			$ResultObj.Reason = "Failed to query DNS zones: $_"
			return $false
		}
	}

	return $false
}

Function Invoke-DHCPRemediation {
	<#
	.SYNOPSIS
		Internal helper function to handle DHCP-related BPA findings.
		Note: Most DHCP remediations require manual attention due to credential requirements.
	#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	param(
		[Parameter(Mandatory = $true)]
		$Finding,

		[Parameter(Mandatory = $true)]
		[PSCustomObject]$ResultObj
	)

	# Check if DhcpServer module is available
	if (-not (Get-Module -ListAvailable -Name DhcpServer -ErrorAction SilentlyContinue)) {
		$ResultObj.Status = 'Skipped'
		$ResultObj.Reason = 'DhcpServer module not available - DHCP role may not be installed'
		return $false
	}

	# DHCP DNS credential findings - always flag for manual attention
	if ($Finding.Title -match 'DNS.*credential|credential.*DNS|dynamic update|DHCP.*DNS') {
		$ResultObj.Status = 'ManualRequired'
		$ResultObj.Reason = 'DHCP DNS credential configuration requires manual setup - cannot auto-configure credentials'
		return $true
	}

	# Other DHCP findings - mark for review
	$ResultObj.Status = 'Skipped'
	$ResultObj.Reason = 'DHCP remediation requires manual review for environment safety'
	return $false
}

# SIG # Begin signature block
# SIG # End signature block
