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
				# Filter to non-compliant, actionable results
				$BpaResults = $BpaResults | Where-Object { $_.Compliance -ne $true -and $_.Severity -ne 'Informational' }
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

# Internal helper: constructs a complete result object from a BPA finding and partial handler output.
Function New-BPAResultObject {
	param(
		[psobject]$Finding,
		[psobject]$Model,
		[string]$ComputerName,
		[string]$Status,
		[string]$Target = $null,
		$PreviousValue = $null,
		$NewValue = $null,
		[string]$Reason = $null
	)
	return [PSCustomObject]@{
		Timestamp     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
		ComputerName  = $ComputerName
		ModelId       = $Model.Id
		RuleId        = $Finding.RuleId
		Title         = $Finding.Title
		Category      = $Finding.Category
		Severity      = $Finding.Severity
		Target        = $Target
		Status        = $Status
		PreviousValue = $PreviousValue
		NewValue      = $NewValue
		Reason        = $Reason
	}
}

# Internal helper: remediates SMB-related BPA findings.
# Accepts a pre-fetched $SmbConfig to avoid redundant server queries across multiple findings.
# Returns an array of partial result objects (empty if no rule matched the finding).
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

# Internal helper: remediates DNS-related BPA findings.
# Returns one partial result object per DNS zone processed (all zones, not just the first).
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

	foreach ($Zone in $Zones) {
		# Only adjust zones that have no secondary servers configured
		if (-not ($null -eq $Zone.SecondaryServers -or $Zone.SecondaryServers.Count -eq 0)) {
			continue
		}

		if ($Zone.Notify -eq 'NoNotify') {
			Write-Verbose "DNS: Zone $($Zone.ZoneName) already set to NoNotify"
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

	return @($PartialResults)
}

# Internal helper: handles DHCP-related BPA findings.
# Most DHCP remediations require manual attention due to credential requirements.
# Returns a single partial result object.
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

	# DNS credential findings always require manual attention
	if ($Finding.Title -match 'DNS.*credential|credential.*DNS|dynamic update|DHCP.*DNS') {
		return @([PSCustomObject]@{
			Target = $null
			Status = 'ManualRequired'
			PreviousValue = $null
			NewValue = $null
			Reason = 'DHCP DNS credential configuration requires manual setup - cannot auto-configure credentials'
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

# Restrict module exports to the public-facing function only.
# Internal helpers (New-BPAResultObject, Invoke-SMBRemediation, etc.) are not exported.
Export-ModuleMember -Function 'Invoke-BPARemediation'

# SIG # Begin signature block
# SIG # End signature block
