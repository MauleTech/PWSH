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
