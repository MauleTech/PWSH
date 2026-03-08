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

# Restrict module exports to the public-facing function only.
# Internal helpers (New-BPAResultObject, Invoke-SMBRemediation, etc.) are not exported.
Export-ModuleMember -Function 'Invoke-BPARemediation'

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA/qIVnrfDI3nru
# /DPmkeCa5oqK4ks6Ort+is6S5Yn9D6CCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IDG8wtEPGDyBy80ZPyNdOPtNrtBFTPweA89N1gydo3ptMA0GCSqGSIb3DQEBAQUA
# BIICAD0lJGoS0xtahiOyd47EWVSTN28O95U1FYiys4wK3Tr88Ug2Y/rSZwkvHycC
# wQtbQw5Wr4L1TVZXo+jwdZV/5L39WIfi494WznSgw9fIZZvz8bvn6XfXcRMicARC
# 9UnR0tSn+iW6QMbAc3dQB87vwPpPy/1IruAiI9mPDN39aOW1SbOi3KnMHxQqWwpl
# /1dfwH7a/gOzbgBY9rIdMG491DEMzgRzkLsa8HNSNvqoHIFvJHB/6yYjxVXk0EmS
# X+DHKNuh2A0yYHTsNZ6Z0A9aFm8Oe3y6qMWvhLjUYTo/SAvfl8omtBNuY6gyIjrE
# //OcvjmMhsijFqAkyadz/9fKDB7/Y3zrP6FTjgD3ekKPXcDloVTjlVS+or4M61ff
# F+9CztGkMaEnNmWbtHRwOHHvZnZIWO2+xIxj3rH8J78mAaqitpjewn3EJme8RzA0
# gb9KU4qPWh/YXUlFYGv4VteVBI+oYmpG4k1Fkl991YPgN2yys5sBe1N/LBNbA7xl
# O3o2OSxqWhNJ4cAxA/w9yiFGdbkd3kAS9I9SwQTTNh5841rXSwn/q4kuAavMJmh2
# cCJkUJYgUqI7Tjlx3mn29TZjV+IpPdBSd6HdCIOh8iSIfMk7FkghtxQcroYGiSug
# SYVfUmSFOXk53fcwkRYygzN0kMNyVD32uftXzm8zPyppgNyDoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDMwODE0MjMzOFowLwYJKoZIhvcNAQkEMSIEIDOm9hHQ
# BsnQYAEABUETBCi401NMvHx3VjnJJ5rQ8pTuMA0GCSqGSIb3DQEBAQUABIICAMnQ
# Hy6opHVoJ2IEJ6UvTZN0wxIds2M093HWLyC91J+Mf/HWj4YAUnWmURUvXe7IfecS
# oLPPgXX7ctqX7mlKOLrOosXScLYsWQuWoUEs6GNoUMF4PO+aLQ53P5rL6MHGvmkB
# T1uEUao3X+UtlzSvJsTaLA2edj+9pBMWXnezVOwXkDyuk4kIh57Z6DzLD55tNINm
# ZbhQM7DWJBms3giJow46v8DngF3qVyyRrB9z7TDHO1vrg8Not8q4Sp84eyy0eOGg
# 2uu2PxFGK51AUs3yz5LqXrCMr8VfXF6+N5a4c6sKebUwgA6NF2+FgAJ+sF1xUFDZ
# oTUuTOw9Dr5oniucrVyEKnF5cN8MAWFOu0Dz4xB37ipyDXOYHUyph7HgFCXFLdrV
# TEZ0iLystsg3JqQItTyb6fknfOLH7YQpB2T66YTIBBJ7RJ3XpjEitMHwKwexW85T
# RDvM9sD0VxdkH4PsxKbQoulq7dejak+PkjXf98Ub0SgUrH7EH28+3o/PWf+5VCW4
# dp4GyE4K/nnhM034IQbPPByPYzT7XRi3mexZ8XzTfMLtea8qoBrUy/ojo/3vT5QK
# K+3L0pj288bwaXkkivzjzxzUDcMw7rImaglGDXaXdtea5H3ycXZq7p9v43DiF3cm
# SUd7injns7W+VpFdpsAbYYRR70L56Pm/Jw/j+VJl
# SIG # End signature block
