Function Repair-O365AppIssues {
	Write-Host "Please note this is an interactive tools, to be run from a user's session."
	If (-not (Test-Path '$ITFolder')) {New-Item -ItemType Directory -Force -Path $ITFolder\ | Out-Null}
	Invoke-ValidatedDownload -Uri 'https://aka.ms/SaRASetup' -OutFile "$ITFolder\SaraSetup.exe"
	& $ITFolder\SaraSetup.exe
	Write-Host "SaRA should now be installing, please wait a moment as it launces."
<#
	.SYNOPSIS
		Downloads and runs the Microsoft Support and Recovery Assistant (SaRA) tool.
		Please note this is an interactive tools, to be run from a user's session.
	.LINK
		https://www.thewindowsclub.com/microsoft-support-and-recovery-assistant
	.LINK
		https://www.microsoft.com/en-us/download/100607
#>
}

Function Repair-Volumes {
<#
	.SYNOPSIS
		Sequentially checks and repairs each volume.
#>
	$Drives = Get-Volume | Where-Object {
		(($_.DriveType -eq "Fixed") -or ($_.DriveType -eq "3"))`
		-and $(If ($_.OperationalStatus){$_.OperationalStatus -eq "OK"} Else {Return $True})`
		-and !($_.FileSystem -Match "FAT")
	}
	ForEach ($Drive in $Drives){
		If ($Drive.DriveLetter) {$Letter = ($Drive.DriveLetter).ToString()}
		If ($Drive.FriendlyName) {$FN = $Drive.FriendlyName}
		$ObjectId = $Drive.ObjectId
		Write-Host -NoNewLine "Scanning Volume:"
		$Drive | FT
		$chkdsk = Repair-Volume -ObjectId $ObjectId -Scan
		Write-Host $chkdsk
		If ($chkdsk -ne "NoErrorsFound") {
			Write-Host "Errors found on drive $Letter - $FN. Attempting to repair."
			$Repair = Repair-Volume -ObjectId $ObjectId -SpotFix
			Write-Host $Repair
		}
		Clear-Variable Letter,ObjectId,FN -ErrorAction SilentlyContinue
		Write-Host -ForegroundColor Yellow "-_-_-_-_-_-_-_-_-_-_-_-_-"
	}
}

Function Repair-Windows {
	$StartTime = (Get-Date)
	(Get-Date).DateTime | Out-Host
	Write-Host Repair-Volume -DriveLetter $Env:SystemDrive.SubString(0,1) -Scan
	$chdksk = Repair-Volume -DriveLetter $Env:SystemDrive.SubString(0,1) -Scan
	If ($chdksk -ne "NoErrorsFound") {Repair-Volume -DriveLetter $Env:SystemDrive.SubString(0,1) -SpotFix}
	Write-Host Dism /Online /Cleanup-Image /StartComponentCleanup
	Dism /Online /Cleanup-Image /StartComponentCleanup
	Write-Host ...
	(Get-Date).DateTime | Out-Host
	Write-Host Dism /Online /Cleanup-Image /RestoreHealth
	Dism /Online /Cleanup-Image /RestoreHealth
	Write-Host ...
	(Get-Date).DateTime | Out-Host
	Write-Host SFC /scannow
	SFC /scannow
	(Get-Date).DateTime | Out-Host
	$EndTime = (Get-Date) - $StartTime
	Write-Host "This process took:"
	$EndTime | FT | Out-Host
	Write-Host "Run this function repeately until no errors show up. If this fails after 3 tries, upgrade or reinstall windows"
}

Function Repair-DomainTrust {
<#
	.SYNOPSIS
		Attempts to repair a broken domain trust relationship without unjoining/rejoining.
	.DESCRIPTION
		Runs through a progressive series of fixes for the "no computer account for this
		workstation trust relationship" error. Starts with the least invasive fixes and
		works down the list. Reboot-required fixes are saved for last.
		Assumes all MauleTech PWSH functions are already loaded via:
			irm ps.mauletech.com | iex
	.EXAMPLE
		Repair-DomainTrust
#>
	[CmdletBinding()]
	Param()

	# Require elevation -- most operations need local admin
	$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
		[Security.Principal.WindowsBuiltInRole]::Administrator)
	If (-not $isAdmin) {
		Write-Host "    [XX] This function must be run as Administrator." -ForegroundColor Red
		Return
	}

	$localComputer = $env:COMPUTERNAME

	#region Helpers
	Function Test-DomainConnectivity {
		Try {
			$result = Test-ComputerSecureChannel -ErrorAction Stop
			Return $result
		} Catch {
			Return $false
		}
	}

	Function Write-Step {
		Param([string]$Message)
		Write-Host "`n[*] $Message" -ForegroundColor Cyan
	}

	Function Write-Pass {
		Param([string]$Message)
		Write-Host "    [OK] $Message" -ForegroundColor Green
	}

	Function Write-Fail {
		Param([string]$Message)
		Write-Host "    [!!] $Message" -ForegroundColor Yellow
	}

	Function Write-Fatal {
		Param([string]$Message)
		Write-Host "    [XX] $Message" -ForegroundColor Red
	}
	#endregion

	#region Step 0 - Fix system time first (Kerberos is time-sensitive)
	Write-Step "Step 0: Syncing system time via Update-NTPDateTime..."
	Try {
		Update-NTPDateTime
		Write-Pass "Time sync complete."
	} Catch {
		Write-Fail "Update-NTPDateTime failed: $_"
		Write-Verbose "Falling back to w32tm resync..."
		$null = w32tm /resync /force 2>&1
		If ($LASTEXITCODE -eq 0) {
			Write-Pass "w32tm resync succeeded as fallback."
		} Else {
			Write-Fail "w32tm fallback also failed (exit code $LASTEXITCODE). Continuing anyway."
		}
	}
	#endregion

	#region Step 1 - Test if time sync alone fixed it
	Write-Step "Step 1: Testing domain connectivity after time sync..."
	If (Test-DomainConnectivity) {
		Write-Pass "Domain trust is healthy after time sync. No further action needed."
		Return
	}
	Write-Fail "Still broken. Continuing..."
	#endregion

	#region Step 2 - Gather environment info
	Write-Step "Step 2: Detecting domain and available domain controllers..."
	$detectedDomain = $null
	Try {
		$detectedDomain = (Get-CimInstance Win32_ComputerSystem).Domain
		Write-Pass "Machine reports domain: $detectedDomain"
	} Catch {
		Write-Fatal "Could not detect domain from Win32_ComputerSystem: $_"
	}

	If (-not $detectedDomain -or $detectedDomain -eq 'WORKGROUP') {
		Write-Fatal "Machine does not appear to be domain-joined (reports: $detectedDomain). Cannot continue."
		Return
	}

	# Validate domain name format to prevent injection into native commands
	If ($detectedDomain -notmatch '^[a-zA-Z0-9._-]+$') {
		Write-Fatal "Detected domain name contains unexpected characters: $detectedDomain. Aborting."
		Return
	}

	# Discover DCs
	$dcs = @()
	Try {
		$dcs = @([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers |
			Select-Object -ExpandProperty Name)
		Write-Pass "Found $($dcs.Count) domain controller(s): $($dcs -join ', ')"
	} Catch {
		Write-Fail "Could not enumerate DCs via DirectoryServices. Trying nltest..."
		$nltestOut = nltest /dclist:$detectedDomain 2>&1
		If ($LASTEXITCODE -eq 0) {
			$dcs = @($nltestOut | Where-Object { $_ -match '\\\\' } |
				ForEach-Object { ($_ -split '\\\\')[1].Trim().Split()[0] } |
				Where-Object { $_ -and $_ -match '^\w' })
			Write-Pass "nltest found DC(s): $($dcs -join ', ')"
		} Else {
			Write-Fatal "Could not enumerate DCs via nltest either (exit code $LASTEXITCODE)."
			Write-Step "Falling back to DNS SRV records to discover domain controllers..."
			Try {
				# SRV avoids filtering out the resolver's own IP (common when DC == DNS server).
				$srvRecords = Resolve-DnsName -Name "_ldap._tcp.$detectedDomain" -Type SRV -ErrorAction Stop
				$dcs = @($srvRecords | Where-Object { $_.Type -eq 'SRV' } |
					Select-Object -ExpandProperty NameTarget)
				Write-Pass "DNS SRV returned $($dcs.Count) DC(s): $($dcs -join ', ')"
			} Catch {
				Write-Fatal "DNS SRV fallback failed: $($_.Exception.Message)"
			}
		}
	}

	$targetDC = $dcs | Select-Object -First 1
	If (-not $targetDC) {
		Write-Fatal "No domain controllers found. Cannot proceed."
		Return
	}
	#endregion

	#region Step 3 - Prompt for domain admin credentials
	Write-Step "Step 3: Prompting for domain admin credentials..."
	$cred = $null
	Try {
		$cred = Get-Credential -Message "Enter Domain Admin credentials for $detectedDomain"
		If (-not $cred) { Throw "No credentials provided." }
		Write-Pass "Credentials captured for: $($cred.UserName)"
	} Catch {
		Write-Fatal "Credential prompt failed or was cancelled: $_"
		Return
	}
	#endregion

	#region Step 4 - Try Test-ComputerSecureChannel -Repair (no reboot)
	Write-Step "Step 4: Attempting Test-ComputerSecureChannel -Repair..."
	Try {
		$repaired = Test-ComputerSecureChannel -Repair -Credential $cred -ErrorAction Stop
		If ($repaired) {
			Write-Pass "Secure channel repaired successfully."
			If (Test-DomainConnectivity) {
				Write-Pass "Domain trust verified. Done! (No reboot needed)"
				Return
			} Else {
				Write-Fail "Repair reported success but trust test still failing. Continuing..."
			}
		} Else {
			Write-Fail "Test-ComputerSecureChannel -Repair returned false."
		}
	} Catch {
		Write-Fail "Test-ComputerSecureChannel -Repair threw an error: $_"
	}
	#endregion

	#region Step 5 - Reset-ComputerMachinePassword (no reboot)
	If ($targetDC) {
		Write-Step "Step 5: Attempting Reset-ComputerMachinePassword against $targetDC..."
		Try {
			Reset-ComputerMachinePassword -Server $targetDC -Credential $cred -ErrorAction Stop
			Write-Pass "Machine password reset complete."
			If (Test-DomainConnectivity) {
				Write-Pass "Domain trust verified. Done! (No reboot needed)"
				Return
			} Else {
				Write-Fail "Password reset done but trust test still failing. Continuing..."
			}
		} Catch {
			Write-Fail "Reset-ComputerMachinePassword failed: $_"
		}
	}
	#endregion

	#region Step 6 - Remote into DC: check & toggle computer account (no reboot)
	If ($targetDC) {
		Write-Step "Step 6: Remoting into DC ($targetDC) to check computer account in AD..."
		$dcSession = $null
		Try {
			$sessionOpts = New-PSSessionOption -OpenTimeout 30000 -OperationTimeout 60000
			$dcSession = New-PSSession -ComputerName $targetDC -Credential $cred -SessionOption $sessionOpts -ErrorAction Stop
			Write-Pass "PSSession to $targetDC established."

			$acctStatus = Invoke-Command -Session $dcSession -ScriptBlock {
				Param($cn)
				Import-Module ActiveDirectory -ErrorAction Stop
				$acct = Get-ADComputer $cn -Properties Enabled, PasswordLastSet -ErrorAction Stop
				[pscustomobject]@{
					Enabled           = $acct.Enabled
					PasswordLastSet   = $acct.PasswordLastSet
					DistinguishedName = $acct.DistinguishedName
				}
			} -ArgumentList $localComputer

			Write-Verbose "AD account status: Enabled=$($acctStatus.Enabled) | PasswordLastSet=$($acctStatus.PasswordLastSet)"

			# If account is disabled, enable it
			If (-not $acctStatus.Enabled) {
				Write-Fail "Computer account is DISABLED. Re-enabling..."
				Invoke-Command -Session $dcSession -ScriptBlock {
					Param($cn)
					Enable-ADAccount -Identity $cn
				} -ArgumentList $localComputer
				Write-Pass "Computer account re-enabled."
			}

			# Only cycle the account if trust is still broken after fixing state
			If (-not (Test-DomainConnectivity)) {
				Write-Step "Step 6b: Cycling AD computer account disable/enable to reset trust..."
				Invoke-Command -Session $dcSession -ScriptBlock {
					Param($cn)
					Set-ADComputer -Identity $cn -Enabled $false
					Start-Sleep -Seconds 2
					Set-ADComputer -Identity $cn -Enabled $true
				} -ArgumentList $localComputer
				Write-Pass "Account disable/enable cycle complete."
			}
		} Catch {
			Write-Fail "Remote DC operations failed: $_"
		} Finally {
			If ($dcSession) { Remove-PSSession $dcSession -ErrorAction SilentlyContinue }
		}

		# Give replication a moment then test
		Start-Sleep -Seconds 3
		If (Test-DomainConnectivity) {
			Write-Pass "Domain trust verified after AD account operations. Done! (No reboot needed)"
			Return
		} Else {
			Write-Fail "AD account operations complete but trust still failing. Continuing..."
		}
	} Else {
		Write-Fail "No DC available for remote operations. Skipping Step 6."
	}
	#endregion

	#region Step 7 - nltest /sc_reset (no reboot, more aggressive channel reset)
	Write-Step "Step 7: Attempting nltest /sc_reset to force secure channel reset..."
	$nltestResult = nltest /sc_reset:$detectedDomain 2>&1
	Write-Verbose "nltest sc_reset completed with exit code: $LASTEXITCODE"
	If ($nltestResult -match 'NERR_Success') {
		Write-Pass "nltest sc_reset succeeded."
	} Else {
		Write-Fail "nltest sc_reset output did not indicate clear success: $nltestResult"
	}
	If (Test-DomainConnectivity) {
		Write-Pass "Domain trust verified after nltest sc_reset. Done! (No reboot needed)"
		Return
	} Else {
		Write-Fail "Still failing after nltest sc_reset. Continuing to reboot-required fixes..."
	}
	#endregion

	#region Step 8 - Reboot-required: netdom resetpwd
	Write-Host "`n--- Non-reboot fixes exhausted. Trying reboot-required fixes. ---" -ForegroundColor Magenta
	Write-Step "Step 8: Running netdom resetpwd to reset machine password (requires reboot)..."
	If ($targetDC) {
		$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
		Try {
			$plain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
			$null = netdom resetpwd /server:$targetDC /userd:$($cred.UserName) /passwordd:$plain 2>&1
			Write-Verbose "netdom resetpwd completed with exit code: $LASTEXITCODE"
			If ($LASTEXITCODE -eq 0) {
				Write-Pass "netdom resetpwd completed. A reboot will be required."
			} Else {
				Write-Fail "netdom resetpwd returned exit code $LASTEXITCODE."
			}
		} Catch {
			Write-Fail "netdom resetpwd failed: $_"
		} Finally {
			[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
			Remove-Variable plain -ErrorAction SilentlyContinue
		}
	} Else {
		Write-Fail "No DC available for netdom resetpwd. Skipping."
	}
	#endregion

	# Clean up credentials
	Remove-Variable cred -ErrorAction SilentlyContinue

	#region Final summary
	Write-Host "`n========================================" -ForegroundColor White
	Write-Host " Repair-DomainTrust: All steps complete." -ForegroundColor White
	Write-Host "========================================" -ForegroundColor White
	If (Test-DomainConnectivity) {
		Write-Pass "Domain trust is NOW HEALTHY. You may or may not need a reboot depending on which step resolved it."
	} Else {
		Write-Fatal "Domain trust could NOT be automatically repaired."
		Write-Host @"

Next manual steps to try:
  1. Reboot the machine (if netdom resetpwd ran, this may resolve it)
  2. If still broken after reboot, manually unjoin and rejoin the domain
  3. Verify DNS is pointing at a DC (ipconfig /all, nslookup $detectedDomain)
  4. Verify no duplicate computer accounts exist in AD for $localComputer
"@ -ForegroundColor Yellow
	}
	#endregion
}

Function Repair-RemoteWMI {
    <#
    .SYNOPSIS
        Attempts to repair WMI connectivity on a remote host without rebooting.

    .DESCRIPTION
        Targets the PRTG PE015 error ("Cannot initiate WMI connections to host").
        Runs a progressive series of repair steps on the remote machine:
          0. Pre-flight check for DCOM port connectivity (TCP 135)
          1. Restart the WMI (Winmgmt) service and dependent services,
             kill orphaned WMI provider host processes
          2. Test WMI -- if Step 1 fixed it, skip heavier repairs (unless -Force)
          3. Re-register WMI provider DLLs and recompile core Windows MOFs
          4. Reset DCOM permissions on the WMI namespace
          5. Verify WMI repository consistency and salvage if corrupt
          6. Final WMI connectivity validation via DCOM CIM session,
             including a PRTG-style uptime (LastBootUpTime) query

        If all WMI tests pass but PRTG is still reporting PE015, the issue is
        likely a hung connection on the PRTG probe. When running locally on the
        probe server, the function will prompt to restart the PRTGProbeService.

        Requires Stop-StuckService from the MauleTech PWSH library when using
        -RestartProbe (load via: irm ps.mauletech.com | iex).

    .PARAMETER ComputerName
        One or more remote hostnames or IPs to repair.

    .PARAMETER Credential
        Optional PSCredential for authentication to the remote host.

    .PARAMETER SkipPortCheck
        Skip the TCP 135 pre-flight check (useful if ICMP/Test-NetConnection
        is blocked but WMI traffic is actually allowed).

    .PARAMETER Force
        Run all repair steps even if early WMI tests pass. Use this when
        the sensor is intermittently failing.

    .PARAMETER RestartProbe
        After successful WMI repair, restart the local PRTG probe service
        to clear any hung connections. Only works when running on the probe
        server. Prompts for confirmation before restarting.

    .EXAMPLE
        Repair-RemoteWMI -ComputerName RD7 -Verbose

    .EXAMPLE
        Repair-RemoteWMI -ComputerName RD7 -Force -RestartProbe -Verbose

    .EXAMPLE
        Repair-RemoteWMI -ComputerName RD7, RD8 -Credential (Get-Credential)
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$ComputerName,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [switch]$SkipPortCheck,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$RestartProbe
    )

    begin {
        $sessionParams = @{
            ErrorAction = 'Stop'
        }
        if ($Credential) {
            $sessionParams['Credential'] = $Credential
        }

        # Validate Stop-StuckService is available if -RestartProbe was requested
        if ($RestartProbe -and -not (Get-Command -Name Stop-StuckService -ErrorAction SilentlyContinue)) {
            Write-Warning 'Stop-StuckService not found. Load MauleTech functions first: irm ps.mauletech.com | iex'
            Write-Warning '-RestartProbe will fall back to Stop-Service only (no stuck-service kill).'
        }

        # Helper: stop WMI dependent services, return their names for restart
        $stopDependentsBlock = {
            $deps = Get-Service -Name Winmgmt -DependentServices -ErrorAction SilentlyContinue |
                Where-Object { $_.Status -eq 'Running' } |
                Select-Object -ExpandProperty Name
            if ($deps) {
                foreach ($svc in $deps) {
                    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                }
            }
            return $deps
        }

        # Helper: restart dependent services by name
        $startDependentsBlock = {
            param([string[]]$ServiceNames)
            if ($ServiceNames) {
                foreach ($svc in $ServiceNames) {
                    Start-Service -Name $svc -ErrorAction SilentlyContinue
                }
            }
        }

        # Pre-convert scriptblocks to strings once for remote invocation
        $stopDependentsStr  = $stopDependentsBlock.ToString()
        $startDependentsStr = $startDependentsBlock.ToString()

        # Helper: test WMI via DCOM CIM session including uptime query
        function Test-WMIConnectivity {
            param(
                [string]$Target,
                [PSCredential]$Cred
            )
            $cimSession = $null
            try {
                $cimParams = @{
                    ComputerName = $Target
                    ErrorAction  = 'Stop'
                }
                if ($Cred) {
                    $cimParams['Credential'] = $Cred
                }
                $dcomOption = New-CimSessionOption -Protocol Dcom
                $cimSession = New-CimSession @cimParams -SessionOption $dcomOption
                $os = Get-CimInstance -CimSession $cimSession -ClassName Win32_OperatingSystem -ErrorAction Stop

                if (-not $os) {
                    return @{ Pass = $false; Detail = 'NoResultsReturned'; Uptime = $null }
                }

                # Compute uptime the same way PRTG's WMI System Uptime sensor does
                $lastBoot = $os.LastBootUpTime
                if ($lastBoot) {
                    $uptime = (Get-Date) - $lastBoot
                    $uptimeStr = '{0}d {1}h {2}m' -f $uptime.Days, $uptime.Hours, $uptime.Minutes
                } else {
                    $uptimeStr = 'LastBootUpTime was null'
                }

                return @{ Pass = $true; Detail = 'Success'; Uptime = $uptimeStr }
            } catch {
                return @{ Pass = $false; Detail = "Failed: $_"; Uptime = $null }
            } finally {
                if ($cimSession) {
                    Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
                }
            }
        }

        # Helper: restart PRTG probe service with 60s timeout
        # Uses Stop-StuckService from MauleTech PWSH library if the service gets stuck
        function Restart-LocalProbeService {
            [CmdletBinding(SupportsShouldProcess)]
            param()

            $serviceName = 'PRTGProbeService'
            $timeoutSec = 60

            $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if (-not $svc) {
                Write-Warning "PRTGProbeService not found on this machine. If the probe runs on a different server, restart it there manually."
                return 'NotFound'
            }

            Write-Verbose "PRTGProbeService found locally (Status: $($svc.Status))"

            if (-not $PSCmdlet.ShouldProcess($serviceName, 'Restart PRTG Probe Service')) {
                return 'SkippedByUser'
            }

            if ($svc.Status -eq 'Running') {
                Write-Verbose "Stopping PRTGProbeService (timeout: ${timeoutSec}s)..."
                try {
                    $svc.Stop()
                } catch {
                    Write-Verbose "Stop() call threw: $_"
                }

                try {
                    $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds($timeoutSec))
                    Write-Verbose "PRTGProbeService stopped gracefully"
                } catch {
                    Write-Warning "PRTGProbeService did not stop within ${timeoutSec}s -- attempting Stop-StuckService..."

                    if (Get-Command -Name Stop-StuckService -ErrorAction SilentlyContinue) {
                        try {
                            Stop-StuckService -Name $serviceName
                            Start-Sleep -Seconds 3
                            $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                            if ($svc.Status -ne 'Stopped') {
                                Write-Warning "Stop-StuckService ran but service status is: $($svc.Status)"
                                return 'StuckKillFailed'
                            }
                            Write-Verbose "Stop-StuckService successfully killed the stuck probe process"
                        } catch {
                            Write-Warning "Stop-StuckService failed: $_"
                            return 'StuckKillFailed'
                        }
                    } else {
                        Write-Warning "Stop-StuckService not available. Load MauleTech functions (irm ps.mauletech.com | iex) and retry, or manually kill the probe process."
                        return 'StuckNoKill'
                    }
                }
            }

            Write-Verbose "Starting PRTGProbeService..."
            try {
                Start-Service -Name $serviceName -ErrorAction Stop
            } catch {
                Write-Warning "Start-Service failed: $_"
                return 'StartFailed'
            }

            try {
                $svc = Get-Service -Name $serviceName
                $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds($timeoutSec))
                Write-Verbose "PRTGProbeService restarted successfully"
                return 'Restarted'
            } catch {
                Write-Warning "PRTGProbeService did not reach Running state within ${timeoutSec}s: $_"
                return 'StartTimeout'
            }
        }

        $repairedComputers = [System.Collections.Generic.List[string]]::new()
    }

    process {
        foreach ($computer in $ComputerName) {
            Write-Verbose "[$computer] Starting WMI repair sequence$(if ($Force) { ' (Force mode)' })"

            $result = [PSCustomObject]@{
                ComputerName    = $computer
                PortCheck       = 'Skipped'
                ServiceRestart  = 'Skipped'
                WmiprvseCleanup = 'Skipped'
                EarlyTest       = 'Skipped'
                DLLReregister   = 'Skipped'
                MOFRecompile    = 'Skipped'
                DCOMPermissions = 'Skipped'
                RepoConsistency = 'Skipped'
                RepoSalvage     = 'Skipped'
                FinalTest       = 'Skipped'
                Uptime          = $null
                Status          = 'Unknown'
            }

            if (-not $SkipPortCheck) {
                Write-Verbose "[$computer] Step 0 - Testing TCP 135 (DCOM/RPC endpoint mapper)"
                try {
                    $portTest = Test-NetConnection -ComputerName $computer -Port 135 -WarningAction SilentlyContinue
                    if ($portTest.TcpTestSucceeded) {
                        $result.PortCheck = 'Open'
                        Write-Verbose "[$computer] TCP 135 is open"
                    } else {
                        $result.PortCheck = 'Blocked'
                        $result.Status = 'PortBlocked'
                        Write-Warning "[$computer] TCP 135 is blocked. This is likely a firewall issue, not a WMI service issue. Verify DCOM/WMI firewall rules."
                        $result
                        continue
                    }
                } catch {
                    $result.PortCheck = "TestFailed: $_"
                    Write-Verbose "[$computer] Port check failed, continuing with repair anyway"
                }
            }

            try {
                Write-Verbose "[$computer] Establishing PSRemoting session"
                $session = New-PSSession -ComputerName $computer @sessionParams
            } catch {
                Write-Warning "[$computer] Failed to establish PSRemoting session: $_"
                $result.Status = 'RemotingFailed'
                $result
                continue
            }

            try {
                Write-Verbose "[$computer] Step 1 - Restarting WMI service, dependencies, and cleaning up wmiprvse"
                $step1 = Invoke-Command -Session $session -ScriptBlock {
                    param($stopBlock, $startBlock)
                    $svcResult = 'Skipped'
                    $cleanResult = 'Skipped'
                    try {
                        $deps = & $([ScriptBlock]::Create($stopBlock))
                        Restart-Service -Name Winmgmt -Force -ErrorAction Stop
                        Start-Sleep -Seconds 3
                        if ($deps) {
                            & $([ScriptBlock]::Create($startBlock)) -ServiceNames $deps
                        }
                        $svcResult = 'Success'
                    } catch {
                        $svcResult = "Failed: $_"
                    }
                    try {
                        $procs = Get-Process -Name wmiprvse -ErrorAction SilentlyContinue
                        if ($procs) {
                            $count = $procs.Count
                            $procs | Stop-Process -Force -ErrorAction SilentlyContinue
                            Start-Sleep -Seconds 2
                            $cleanResult = "Killed $count orphaned wmiprvse.exe process(es)"
                        } else {
                            $cleanResult = 'NoneFound'
                        }
                    } catch {
                        $cleanResult = "Failed: $_"
                    }
                    return @{ ServiceRestart = $svcResult; WmiprvseCleanup = $cleanResult }
                } -ArgumentList $stopDependentsStr, $startDependentsStr
                $result.ServiceRestart = $step1.ServiceRestart
                $result.WmiprvseCleanup = $step1.WmiprvseCleanup
                Write-Verbose "[$computer] Service restart: $($step1.ServiceRestart), wmiprvse cleanup: $($step1.WmiprvseCleanup)"

                Write-Verbose "[$computer] Step 2 - Early WMI connectivity test"
                $earlyTest = Test-WMIConnectivity -Target $computer -Cred $Credential
                $earlyTestPassed = $earlyTest.Pass

                if ($earlyTestPassed -and -not $Force) {
                    $result.EarlyTest = $earlyTest.Detail
                    $result.Uptime = $earlyTest.Uptime
                    $result.FinalTest = $earlyTest.Detail
                    $result.Status = 'Repaired'
                    Write-Verbose "[$computer] WMI responded after service restart (uptime: $($earlyTest.Uptime)) -- skipping heavier repairs"
                } else {
                    if ($earlyTestPassed) {
                        $result.EarlyTest = "$($earlyTest.Detail) (continuing due to -Force)"
                        Write-Verbose "[$computer] WMI responded but -Force specified -- running all repairs"
                    } else {
                        $result.EarlyTest = $earlyTest.Detail
                        Write-Verbose "[$computer] WMI still failing after restart, continuing with deeper repairs"
                    }

                    Write-Verbose "[$computer] Step 3 - Re-registering WMI provider DLLs and recompiling MOFs"
                    $step3 = Invoke-Command -Session $session -ScriptBlock {
                        $sysDir = "$env:SystemRoot\System32\wbem"
                        $dllResult = 'Skipped'
                        $mofResult = 'Skipped'

                        try {
                            $dlls = @(
                                'scrcons.dll', 'unsecapp.dll', 'wmiprvsd.dll',
                                'wmiprvse.dll', 'wmisvc.dll', 'wbemcomn.dll',
                                'wbemprox.dll', 'wbemcore.dll', 'wbemsvc.dll',
                                'fastprox.dll', 'mofd.dll', 'cimwin32.dll',
                                'wmiutils.dll', 'repdrvfs.dll', 'wmipiprt.dll'
                            )
                            $errors = @()
                            foreach ($dll in $dlls) {
                                $dllPath = Join-Path $sysDir $dll
                                if (Test-Path $dllPath) {
                                    & regsvr32.exe /s $dllPath 2>&1 | Out-Null
                                    if ($LASTEXITCODE -ne 0) {
                                        $errors += "$dll (exit $LASTEXITCODE)"
                                    }
                                }
                            }
                            if ($errors.Count -gt 0) {
                                $dllResult = "PartialSuccess ($($errors -join ', '))"
                            } else {
                                $dllResult = 'Success'
                            }
                        } catch {
                            $dllResult = "Failed: $_"
                        }

                        try {
                            $coreMofs = @(
                                'cimwin32.mof', 'cimwin32.mfl',
                                'win32_encryptablevolume.mof',
                                'rsop.mof', 'rsop.mfl',
                                'wmi.mof', 'wmi.mfl',
                                'wmitimep.mof',
                                'regevent.mof',
                                'ntevt.mof', 'ntevt.mfl',
                                'secrcw32.mof', 'secrcw32.mfl',
                                'dsprov.mof', 'dsprov.mfl',
                                'scrcons.mof',
                                'tscfgwmi.mof', 'tscfgwmi.mfl',
                                'rdpdr.mof'
                            )
                            $compiled = 0
                            $failed = 0
                            foreach ($mofName in $coreMofs) {
                                $mofPath = Join-Path $sysDir $mofName
                                if (Test-Path $mofPath) {
                                    & mofcomp.exe $mofPath 2>&1 | Out-Null
                                    if ($LASTEXITCODE -eq 0) {
                                        $compiled++
                                    } else {
                                        $failed++
                                    }
                                }
                            }
                            $mofResult = "Compiled: $compiled, Failed: $failed"
                        } catch {
                            $mofResult = "Failed: $_"
                        }

                        return @{ DLLReregister = $dllResult; MOFRecompile = $mofResult }
                    }
                    $result.DLLReregister = $step3.DLLReregister
                    $result.MOFRecompile = $step3.MOFRecompile
                    Write-Verbose "[$computer] DLL re-register: $($step3.DLLReregister), MOF recompile: $($step3.MOFRecompile)"

                    Write-Verbose "[$computer] Step 4 - Resetting DCOM/WMI namespace permissions"
                    $dcomResult = Invoke-Command -Session $session -ScriptBlock {
                        try {
                            $namespace = [wmiclass]'root\cimv2:__SystemSecurity'
                            $sd = $namespace.GetSD()
                            if ($sd.ReturnValue -eq 0) {
                                $setResult = $namespace.SetSD($sd.SD)
                                if ($setResult.ReturnValue -eq 0) {
                                    return 'Success'
                                } else {
                                    return "SetSD returned $($setResult.ReturnValue)"
                                }
                            } else {
                                return "GetSD returned $($sd.ReturnValue)"
                            }
                        } catch {
                            return "Failed: $_"
                        }
                    }
                    $result.DCOMPermissions = $dcomResult
                    Write-Verbose "[$computer] DCOM permissions reset: $dcomResult"

                    Write-Verbose "[$computer] Step 5 - Checking WMI repository consistency (salvage if needed)"
                    $step5 = Invoke-Command -Session $session -ScriptBlock {
                        param($stopBlock, $startBlock)
                        $consistency = 'Skipped'
                        $salvage = 'Skipped'
                        try {
                            $output = & winmgmt /verifyrepository 2>&1
                            $outputStr = ($output | Out-String).Trim()
                            if ($outputStr -match 'is consistent' -and $outputStr -notmatch 'not consistent') {
                                $consistency = 'Consistent'
                            } else {
                                $consistency = "Inconsistent: $outputStr"
                                # Salvage: stop Winmgmt, repair, restart
                                $deps = $null
                                try {
                                    $deps = & $([ScriptBlock]::Create($stopBlock))
                                    Stop-Service -Name Winmgmt -Force -ErrorAction Stop
                                    & winmgmt /salvagerepository 2>&1 | Out-Null
                                    Start-Service -Name Winmgmt -ErrorAction Stop
                                    Start-Sleep -Seconds 3
                                    if ($deps) {
                                        & $([ScriptBlock]::Create($startBlock)) -ServiceNames $deps
                                    }
                                    $verify = & winmgmt /verifyrepository 2>&1
                                    $verifyStr = ($verify | Out-String).Trim()
                                    if ($verifyStr -match 'is consistent' -and $verifyStr -notmatch 'not consistent') {
                                        $salvage = 'SalvagedSuccessfully'
                                    } else {
                                        $salvage = "SalvageFailed: $verifyStr"
                                    }
                                } catch {
                                    # Ensure Winmgmt is restarted even if salvage fails
                                    try { Start-Service -Name Winmgmt -ErrorAction SilentlyContinue } catch {}
                                    if ($deps) {
                                        try { & $([ScriptBlock]::Create($startBlock)) -ServiceNames $deps } catch {}
                                    }
                                    $salvage = "Failed: $_"
                                }
                            }
                        } catch {
                            $consistency = "Failed: $_"
                        }
                        return @{ RepoConsistency = $consistency; RepoSalvage = $salvage }
                    } -ArgumentList $stopDependentsStr, $startDependentsStr
                    $result.RepoConsistency = $step5.RepoConsistency
                    $result.RepoSalvage = $step5.RepoSalvage
                    Write-Verbose "[$computer] Repository: $($step5.RepoConsistency), Salvage: $($step5.RepoSalvage)"

                    Write-Verbose "[$computer] Step 6 - Final WMI connectivity test (DCOM + uptime)"
                    $finalTest = Test-WMIConnectivity -Target $computer -Cred $Credential
                    $result.FinalTest = $finalTest.Detail
                    $result.Uptime = $finalTest.Uptime
                    if ($finalTest.Pass) {
                        $result.Status = 'Repaired'
                    } else {
                        $result.Status = 'VerificationFailed'
                    }
                    Write-Verbose "[$computer] Final WMI test: $($finalTest.Detail), Uptime: $($finalTest.Uptime)"
                }

            } finally {
                if ($session) {
                    Remove-PSSession -Session $session -ErrorAction SilentlyContinue
                }
            }

            if ($result.Status -eq 'Repaired') {
                $repairedComputers.Add($computer)
                Write-Verbose "[$computer] WMI repair completed successfully. Rescan the PRTG sensor to confirm."
            } else {
                Write-Warning "[$computer] WMI repair completed but verification failed. A reboot may still be needed."
            }

            $result
        }
    }

    end {
        if ($repairedComputers.Count -eq 0) {
            return
        }

        if ($RestartProbe) {
            Write-Host ''
            Write-Host "WMI is working on: $($repairedComputers -join ', ')" -ForegroundColor Green
            Write-Host 'If PRTG sensors are still showing PE015, the probe likely has a hung connection.' -ForegroundColor Yellow
            Write-Host ''

            $probeResult = Restart-LocalProbeService
            Write-Host "Probe restart result: $probeResult" -ForegroundColor Cyan
        } else {
            # Check if probe is local and suggest -RestartProbe if so
            $localProbe = Get-Service -Name PRTGProbeService -ErrorAction SilentlyContinue
            if ($localProbe) {
                Write-Host ''
                Write-Host "WMI is working on: $($repairedComputers -join ', ')" -ForegroundColor Green
                Write-Host 'TIP: If the PRTG sensor still shows PE015, the probe may have a hung connection.' -ForegroundColor Yellow
                Write-Host 'Run again with -RestartProbe to restart the local PRTGProbeService.' -ForegroundColor Yellow
            }
        }
    }
}

Function Repair-NTPConfiguration {
<#
.SYNOPSIS
    Repairs Windows Time Service (w32time) configuration based on domain role.
.DESCRIPTION
    Detects whether the machine is a PDC Emulator, additional domain controller,
    domain-joined member, or standalone, then applies the appropriate NTP fix:

      PDC Emulator        -- Unregisters/re-registers w32time, then configures
                             Tier 3 NTP pool peers and forces a resync.
      Additional DC       -- Unregisters/re-registers w32time, then configures
                             NT5DS domain-hierarchy sync toward the PDC Emulator.
      Domain member       -- Option A: quick 'net time' sync from the PDC.
                             Falls through to Option B (full reset) if the
                             Windows Time source is still bad after Option A.
                             Use -Force to skip Option A entirely.
      Standalone          -- Unregisters/re-registers w32time and configures
                             the Tier 3 NTP pool directly.

    Domain members get their time from domain controllers, which get their time
    from north-america.pool.ntp.org (Tier 3). Do not configure Tier 1 or Tier 2
    servers directly.

    NOTE: Allow 30+ seconds after starting w32time before trusting
    'w32tm /query /source' output. This function includes that wait automatically.
.PARAMETER NTPPool
    The Tier 3 NTP pool base name to use for PDC Emulator and standalone
    configuration. Defaults to 'north-america.pool.ntp.org'. Four numbered
    sub-pools (0. through 3.) are configured automatically.
.PARAMETER Force
    On domain-joined members, skip Option A (quick sync) and go directly to
    the full Option B reset sequence.
.EXAMPLE
    Repair-NTPConfiguration
    Detects role and applies the appropriate NTP fix automatically.
.EXAMPLE
    Repair-NTPConfiguration -Force
    On a domain member, skips the quick sync attempt and runs the full reset.
.EXAMPLE
    Repair-NTPConfiguration -NTPPool 'pool.ntp.org'
    Uses a custom NTP pool for PDC Emulator or standalone configuration.
.NOTES
    Requires Administrator privileges. Restarts the Windows Time Service as part
    of the repair sequence. Schedule a maintenance window if needed.
    WARNING: Only Tier 3 NTP pool servers are appropriate for direct configuration.
    Tier 1 and Tier 2 servers are reserved for authorized NTP infrastructure only.
#>
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$NTPPool = 'north-america.pool.ntp.org',

        [switch]$Force
    )

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "Administrator privileges are required." -ForegroundColor Red
        return
    }

    if ($NTPPool -notmatch '^[a-zA-Z0-9._-]+$') {
        Write-Host "Invalid NTP pool name: $NTPPool" -ForegroundColor Red
        return
    }

    # DomainRole values from Win32_ComputerSystem:
    #   0 = Standalone Workstation, 1 = Member Workstation,
    #   2 = Standalone Server,      3 = Member Server,
    #   4 = Backup/Additional DC,   5 = PDC Emulator
    $computerSystem = $null
    try {
        $computerSystem = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
    } catch {
        Write-Host "Failed to query Win32_ComputerSystem: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $domainRole = [int]$computerSystem.DomainRole
    $domainName = $computerSystem.Domain
    $isPDC      = $domainRole -eq 5
    $isAddlDC   = $domainRole -eq 4
    $isMember   = $domainRole -in @(1, 3)

    Write-Host ""
    switch ($domainRole) {
        5       { Write-Host "=== Role: PDC Emulator ===" -ForegroundColor Cyan }
        4       { Write-Host "=== Role: Additional Domain Controller ===" -ForegroundColor Cyan }
        3       { Write-Host "=== Role: Domain Member Server ===" -ForegroundColor Cyan }
        1       { Write-Host "=== Role: Domain Member Workstation ===" -ForegroundColor Cyan }
        2       { Write-Host "=== Role: Standalone Server ===" -ForegroundColor Cyan }
        0       { Write-Host "=== Role: Standalone Workstation ===" -ForegroundColor Cyan }
        default { Write-Host "=== Role: Unknown (DomainRole=$domainRole) ===" -ForegroundColor Cyan }
    }
    if ($domainRole -ge 1 -and $domainRole -le 5) {
        Write-Host "Domain: $domainName" -ForegroundColor Cyan
    }
    Write-Host ""

    #region Helper -- discover PDC emulator
    $pdcHost = $null
    if ($isAddlDC -or $isMember) {
        try {
            $pdcHost = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).PdcRoleOwner.Name
            Write-Host "PDC Emulator: $pdcHost" -ForegroundColor Cyan
        } catch {
            Write-Host "WARNING: Could not discover PDC emulator: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    #endregion

    #region PDC Emulator -- configure external Tier 3 NTP pool
    if ($isPDC) {
        $peerList = "0.$NTPPool 1.$NTPPool 2.$NTPPool 3.$NTPPool"
        Write-Host "NTP peers: $peerList" -ForegroundColor Cyan
        Write-Host ""

        Write-Host "Step 1 -- Current time source:" -ForegroundColor Cyan
        $src = & w32tm /query /source 2>&1
        Write-Host "  $src"

        Write-Host "`nStep 2 -- Stop and unregister w32time:" -ForegroundColor Cyan
        & net stop w32time 2>&1 | ForEach-Object { Write-Host "  $_" }
        & w32tm /unregister 2>&1 | ForEach-Object { Write-Host "  $_" }

        Write-Host "`nStep 3 -- Register and start w32time:" -ForegroundColor Cyan
        & w32tm /register 2>&1 | ForEach-Object { Write-Host "  $_" }
        & net start w32time 2>&1 | ForEach-Object { Write-Host "  $_" }

        Write-Host "`nStep 4 -- Configure NTP peers (first pass):" -ForegroundColor Cyan
        & w32tm /config /manualpeerlist:$peerList /syncfromflags:manual /reliable:YES /update 2>&1 |
            ForEach-Object { Write-Host "  $_" }

        Write-Host "`nStep 5 -- Stop, restart, apply config (second pass), resync:" -ForegroundColor Cyan
        & net stop w32time 2>&1 | ForEach-Object { Write-Host "  $_" }
        & net start w32time 2>&1 | ForEach-Object { Write-Host "  $_" }
        # Second /config pass after service is running -- /update uses RPC and
        # requires the service to be active. Both passes ensure the config
        # survives the stop/start cycle.
        & w32tm /config /manualpeerlist:$peerList /syncfromflags:manual /reliable:YES /update 2>&1 |
            ForEach-Object { Write-Host "  $_" }

        Write-Host "`nWaiting 30 seconds for w32time to settle..." -ForegroundColor Cyan
        Start-Sleep -Seconds 30

        & w32tm /resync 2>&1 | ForEach-Object { Write-Host "  $_" }
        $finalSrc    = & w32tm /query /source 2>&1
        $finalSrcStr = "$finalSrc"
        $stillBad    = $finalSrcStr -match '(Local CMOS Clock|Free-running System Clock|error)' -or
                       $finalSrcStr -eq ''
        if ($stillBad) {
            Write-Host "`nFinal time source: $finalSrc" -ForegroundColor Yellow
            Write-Host "WARNING: PDC Emulator is still not syncing from the NTP pool." -ForegroundColor Yellow
            Write-Host "  - Verify outbound UDP 123 is not blocked to the internet" -ForegroundColor Yellow
            Write-Host "  - Check for Group Policy overrides: w32tm /query /configuration" -ForegroundColor Yellow
            Write-Host "  - Check Event Log: Applications and Services -> Microsoft -> Windows -> Time-Service" -ForegroundColor Yellow
        } else {
            Write-Host "`nFinal time source: $finalSrc" -ForegroundColor Green
            Write-Host "PDC Emulator NTP configuration complete." -ForegroundColor Green
        }
        return
    }
    #endregion

    #region Additional DC -- sync via NT5DS domain hierarchy toward PDC
    if ($isAddlDC) {
        Write-Host "Step 1 -- Current time source:" -ForegroundColor Cyan
        $src = & w32tm /query /source 2>&1
        Write-Host "  $src"

        Write-Host "`nStep 2 -- Stop and unregister w32time:" -ForegroundColor Cyan
        & net stop w32time 2>&1 | ForEach-Object { Write-Host "  $_" }
        & w32tm /unregister 2>&1 | ForEach-Object { Write-Host "  $_" }

        Write-Host "`nStep 3 -- Register and start w32time:" -ForegroundColor Cyan
        & w32tm /register 2>&1 | ForEach-Object { Write-Host "  $_" }
        & net start w32time 2>&1 | ForEach-Object { Write-Host "  $_" }

        Write-Host "`nStep 4 -- Configure NT5DS domain hierarchy sync:" -ForegroundColor Cyan
        & w32tm /config /syncfromflags:domhier /reliable:NO /update 2>&1 |
            ForEach-Object { Write-Host "  $_" }

        Write-Host "`nWaiting 30 seconds for w32time to settle..." -ForegroundColor Cyan
        Start-Sleep -Seconds 30

        & w32tm /resync 2>&1 | ForEach-Object { Write-Host "  $_" }
        $finalSrc = & w32tm /query /source 2>&1
        Write-Host "`nFinal time source: $finalSrc" -ForegroundColor Green
        if ($pdcHost) {
            Write-Host "This DC should now be syncing from the PDC emulator ($pdcHost) via domain hierarchy." -ForegroundColor Green
        }
        Write-Host "Domain Controller NTP configuration complete." -ForegroundColor Green
        return
    }
    #endregion

    #region Domain members -- Option A (quick) then Option B (full reset)
    if ($isMember) {
        if (-not $pdcHost) {
            Write-Host "Cannot proceed: PDC emulator not discovered. Domain member time sync requires a reachable DC." -ForegroundColor Red
            return
        }

        if (-not $Force) {
            Write-Host "Option A: Quick sync from PDC (try this first)" -ForegroundColor Cyan
            & net time "\\$pdcHost" /set /y 2>&1 | ForEach-Object { Write-Host "  $_" }

            $src = & w32tm /query /source 2>&1
            Write-Host "  Time source: $src" -ForegroundColor Cyan

            $srcStr = "$src"
            $isBadSource = $srcStr -match '(Local CMOS Clock|Free-running System Clock|error)' -or
                           $srcStr -eq ''

            if (-not $isBadSource) {
                Write-Host "`nOption A succeeded -- time synced from domain." -ForegroundColor Green
                return
            }

            Write-Host "`nTime source still reports: $src" -ForegroundColor Yellow
            Write-Host "Option A did not resolve the issue. Proceeding to Option B (full reset)..." -ForegroundColor Yellow
            Write-Host ""
        } else {
            Write-Host "Skipping Option A -- running Option B full reset directly." -ForegroundColor Yellow
            Write-Host ""
        }

        Write-Host "Option B: Full reset sequence" -ForegroundColor Cyan

        Write-Host "`n  Stopping w32time..." -ForegroundColor Cyan
        & net stop w32time 2>&1 | ForEach-Object { Write-Host "    $_" }

        Write-Host "`n  Unregistering w32time..." -ForegroundColor Cyan
        & w32tm /unregister 2>&1 | ForEach-Object { Write-Host "    $_" }

        Write-Host "`n  Sync from PDC (pass 1 -- before register)..." -ForegroundColor Cyan
        & net time "\\$pdcHost" /set /y 2>&1 | ForEach-Object { Write-Host "    $_" }

        Write-Host "`n  Registering w32time..." -ForegroundColor Cyan
        & w32tm /register 2>&1 | ForEach-Object { Write-Host "    $_" }

        Write-Host "`n  Sync from PDC (pass 2 -- after register)..." -ForegroundColor Cyan
        & net time "\\$pdcHost" /set /y 2>&1 | ForEach-Object { Write-Host "    $_" }

        Write-Host "`n  Starting w32time..." -ForegroundColor Cyan
        & net start w32time 2>&1 | ForEach-Object { Write-Host "    $_" }

        # w32tm /config uses RPC and requires the service to be running.
        # Must come after net start w32time -- not before.
        Write-Host "`n  Configuring domain hierarchy sync (NT5DS)..." -ForegroundColor Cyan
        & w32tm /config /syncfromflags:domhier /reliable:NO /update 2>&1 |
            ForEach-Object { Write-Host "    $_" }

        Write-Host "`n  Sync from PDC (pass 3 -- after start)..." -ForegroundColor Cyan
        & net time "\\$pdcHost" /set /y 2>&1 | ForEach-Object { Write-Host "    $_" }

        $src = & w32tm /query /source 2>&1
        Write-Host "  Time source: $src" -ForegroundColor Cyan

        Write-Host "`nWaiting 30 seconds for w32time to settle..." -ForegroundColor Cyan
        Start-Sleep -Seconds 30

        Write-Host "`n  Final sync from PDC (pass 4)..." -ForegroundColor Cyan
        & net time "\\$pdcHost" /set /y 2>&1 | ForEach-Object { Write-Host "    $_" }

        & w32tm /resync /force 2>&1 | ForEach-Object { Write-Host "    $_" }

        $finalSrc = & w32tm /query /source 2>&1
        $finalSrcStr = "$finalSrc"
        $stillBad = $finalSrcStr -match '(Local CMOS Clock|Free-running System Clock|error)' -or
                    $finalSrcStr -eq ''

        if (-not $stillBad) {
            Write-Host "  Final time source: $finalSrc" -ForegroundColor Green
            Write-Host "`nDomain member NTP reset complete." -ForegroundColor Green
            return
        }

        Write-Host "  Final time source: $finalSrc" -ForegroundColor Yellow
        Write-Host ""

        # Check whether Group Policy is locking the NTP configuration.
        # w32tm /config writes to HKLM\SYSTEM\...\Services\W32Time but the service
        # reads HKLM\SOFTWARE\Policies\Microsoft\W32Time preferentially when GPO
        # has written values there. Anything tagged (Policy) in /query /configuration
        # cannot be overridden by w32tm /config.
        $configOutput = (& w32tm /query /configuration 2>&1) | Out-String
        $hasPolicySettings = $configOutput -match '\(Policy\)'

        if ($hasPolicySettings) {
            $policyType      = $null
            $policyNtpServer = $null
            if ($configOutput -match 'Type:\s+(\S+)\s+\(Policy\)') {
                $policyType = $Matches[1]
            }
            if ($configOutput -match 'NtpServer:\s+(\S+)\s+\(Policy\)') {
                # Strip NTP flags (e.g. ",0x8") to get the bare hostname
                $policyNtpServer = ($Matches[1]) -replace ',.*$', ''
            }

            Write-Host "Group Policy is overriding w32time configuration:" -ForegroundColor Yellow
            if ($policyType)      { Write-Host "  Type (Policy):      $policyType" -ForegroundColor Yellow }
            if ($policyNtpServer) { Write-Host "  NtpServer (Policy): $policyNtpServer" -ForegroundColor Yellow }
            Write-Host "  'w32tm /config' cannot override Policy-tagged settings." -ForegroundColor Yellow

            # Test whether the GPO-specified NTP server is actually reachable
            if ($policyNtpServer -and (Get-Command Get-NTPOffset -ErrorAction SilentlyContinue)) {
                Write-Host "`nTesting NTP reachability of '$policyNtpServer'..." -ForegroundColor Cyan
                $ntpTest = Get-NTPOffset -Server $policyNtpServer -TimeoutMs 5000
                if ($ntpTest.Success) {
                    Write-Host "  '$policyNtpServer' is reachable (offset: $([Math]::Round($ntpTest.OffsetMs / 1000, 2))s)." -ForegroundColor Green
                    Write-Host "  The server is responding -- w32time may need more time to sync." -ForegroundColor Yellow
                    Write-Host "  Try 'w32tm /resync /rediscover' in a few minutes." -ForegroundColor Yellow
                } else {
                    Write-Host "  '$policyNtpServer' is NOT reachable: $($ntpTest.Error)" -ForegroundColor Red
                    Write-Host "  The GPO is pointing at an NTP server that is not responding." -ForegroundColor Red
                }
            }

            # Run gpupdate in case an admin already corrected the GPO but it hasn't been pulled yet
            Write-Host "`nRunning 'gpupdate /force' in case the GPO was already corrected..." -ForegroundColor Cyan
            & gpupdate /force 2>&1 | ForEach-Object { Write-Host "  $_" }

            Start-Sleep -Seconds 5
            & w32tm /resync /rediscover 2>&1 | ForEach-Object { Write-Host "  $_" }

            $postGPUSrc    = & w32tm /query /source 2>&1
            $postGPUSrcStr = "$postGPUSrc"
            $stillBadAfterGPU = $postGPUSrcStr -match '(Local CMOS Clock|Free-running System Clock|error)' -or
                                $postGPUSrcStr -eq ''

            if (-not $stillBadAfterGPU) {
                Write-Host "  Time source after gpupdate: $postGPUSrc" -ForegroundColor Green
                Write-Host "`nDomain member NTP resolved after Group Policy refresh." -ForegroundColor Green
                return
            }

            Write-Host "  Time source after gpupdate: $postGPUSrc" -ForegroundColor Yellow
            Write-Host "`nGroup Policy is still preventing correct NTP sync. A GPO change is required:" -ForegroundColor Yellow
            Write-Host "  Path: Computer Configuration -> Administrative Templates -> System -> Windows Time Service -> Time Providers" -ForegroundColor Yellow
            Write-Host "  Options:" -ForegroundColor Yellow
            if ($policyNtpServer) {
                Write-Host "    a. Fix NtpServer in the GPO -- '$policyNtpServer' is not responding." -ForegroundColor Yellow
                Write-Host "       Recommended: point to the PDC emulator ($pdcHost) or remove the policy." -ForegroundColor Yellow
            } else {
                Write-Host "    a. Fix the NtpServer value in the GPO or remove the policy." -ForegroundColor Yellow
            }
            Write-Host "    b. Set 'Configure Windows NTP Client' to 'Not Configured' to let" -ForegroundColor Yellow
            Write-Host "       domain members sync via NT5DS (domain hierarchy) automatically." -ForegroundColor Yellow
            Write-Host "  After updating the GPO, run 'gpupdate /force' then 'w32tm /resync /rediscover'." -ForegroundColor Yellow
            Write-Host "`n  Diagnostic commands:" -ForegroundColor Cyan
            Write-Host "    gpresult /r                  -- which GPOs are applied to this machine" -ForegroundColor Cyan
            Write-Host "    w32tm /query /configuration  -- all settings with (Policy) vs (Local) tags" -ForegroundColor Cyan
            Write-Host "    w32tm /query /status         -- sync status and last successful sync time" -ForegroundColor Cyan
        } else {
            Write-Host "WARNING: w32time source is still not syncing from the domain." -ForegroundColor Yellow
            Write-Host "No Group Policy override detected. Check the following:" -ForegroundColor Yellow
            Write-Host "  - The PDC emulator ($pdcHost) is online and responding to NTP (UDP 123)" -ForegroundColor Yellow
            Write-Host "  - No firewall is blocking UDP 123 between this machine and the DC" -ForegroundColor Yellow
            Write-Host "  Run 'w32tm /query /configuration' and 'w32tm /query /status' for details." -ForegroundColor Yellow
        }
        return
    }
    #endregion

    #region Standalone -- configure Tier 3 NTP pool directly
    $peerList = "0.$NTPPool 1.$NTPPool 2.$NTPPool 3.$NTPPool"
    Write-Host "NTP peers: $peerList" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "Step 1 -- Stop and unregister w32time:" -ForegroundColor Cyan
    & net stop w32time 2>&1 | ForEach-Object { Write-Host "  $_" }
    & w32tm /unregister 2>&1 | ForEach-Object { Write-Host "  $_" }

    Write-Host "`nStep 2 -- Register and start w32time:" -ForegroundColor Cyan
    & w32tm /register 2>&1 | ForEach-Object { Write-Host "  $_" }
    & net start w32time 2>&1 | ForEach-Object { Write-Host "  $_" }

    Write-Host "`nStep 3 -- Configure NTP peers:" -ForegroundColor Cyan
    & w32tm /config /manualpeerlist:$peerList /syncfromflags:manual /reliable:YES /update 2>&1 |
        ForEach-Object { Write-Host "  $_" }

    Write-Host "`nWaiting 30 seconds for w32time to settle..." -ForegroundColor Cyan
    Start-Sleep -Seconds 30

    & w32tm /resync 2>&1 | ForEach-Object { Write-Host "  $_" }
    $finalSrc = & w32tm /query /source 2>&1
    Write-Host "`nFinal time source: $finalSrc" -ForegroundColor Green
    Write-Host "Standalone NTP configuration complete." -ForegroundColor Green
    #endregion
}

Function Repair-ExchangeDAGCopies {
	<#
	.SYNOPSIS
		Attempts to repair failed or suspended Exchange DAG database copies using an escalating strategy.
	.DESCRIPTION
		For each failed/suspended copy matching the filters, tries in order:
		  1. Resume (gentle - for transient failures or manual suspensions)
		  2. Reseed with -DeleteExistingFiles (standard reseed)
		  3. Manual temp-seeding folder cleanup + reseed (handles filesystem/locked file errors)
		Waits between each step to allow replication to stabilize before checking if further
		action is needed.

		Optionally registers a Windows scheduled task to run this repair once a week at a
		specified after-hours time. The scheduled task runs as SYSTEM, which on an Exchange
		server is a member of the Exchange Trusted Subsystem and has the rights needed for
		these operations.

		Must be run from a server with the Exchange Management Tools installed.
	.PARAMETER ServerFilter
		Wildcard filter for the server name portion of the copy identity. Default: '*' (all servers).
		Example: 'EX2016-3' to target only copies on EX2016-3.
	.PARAMETER DatabaseFilter
		Wildcard filter for the database name portion of the copy identity. Default: '*' (all databases).
		Example: '2016-MailStoreDBAttorneys-*'
	.PARAMETER ResumeWaitSeconds
		Seconds to wait after a Resume attempt before checking if replication recovered. Default: 60.
	.PARAMETER StaggerSeconds
		Seconds to wait between initiating operations on different databases. Default: 10.
	.PARAMETER Parallel
		If specified, all reseeds are kicked off in rapid succession (separated only by
		-StaggerSeconds). Use with caution on WAN links: 9 simultaneous reseeds across a
		shared link will saturate it and slow every copy to a crawl.
		Default behavior (when -Parallel is omitted) is serial: after each reseed is initiated,
		the function waits for the copy's status to return to Healthy/Mounted before moving
		on to the next copy. This is the safe choice for WAN-connected DAG members.
	.PARAMETER ReseedTimeoutHours
		In serial mode (default), the maximum time to wait for a single reseed to complete
		before giving up and moving to the next copy. Default: 24 hours. Range: 1-168.
	.PARAMETER ReseedPollMinutes
		In serial mode (default), how often to poll Get-MailboxDatabaseCopyStatus while
		waiting for a reseed to complete. Default: 5 minutes. Range: 1-60.
	.PARAMETER AutoFilesystemRepair
		If specified, when a reseed fails with NTFS corruption symptoms (error 1392 or
		'Corruption in the filesystem has been detected'), the function extracts the
		affected drive letter from the error message, runs Repair-Volume -Scan on the
		target server, and (if the scan reports errors) Repair-Volume -SpotFix. Each
		volume is repaired at most once per session and the OS volume is always skipped.
		Note: -SpotFix briefly dismounts the volume, which momentarily disrupts any
		other databases hosted on it. After a successful repair the reseed is retried.
		Off by default; opt in explicitly when you understand the dismount tradeoff.
	.PARAMETER RegisterScheduledTask
		Registers a Windows scheduled task ('MauleTech-RepairExchangeDAGCopies') that runs this
		repair once a week at the configured day/time. All repair-mode parameters
		(-ServerFilter, -DatabaseFilter, -ResumeWaitSeconds, -StaggerSeconds, -Parallel,
		-ReseedTimeoutHours, -ReseedPollMinutes, -AutoFilesystemRepair) are captured into
		the wrapper script so the scheduled run uses the same scope and behavior.
	.PARAMETER UnregisterScheduledTask
		Removes the MauleTech-RepairExchangeDAGCopies scheduled task if it exists.
	.PARAMETER ScheduledDay
		Day of the week for the scheduled task to run. Default: Saturday.
	.PARAMETER ScheduledTime
		Time of day for the scheduled task to run. Default: 11:00 PM (after hours).
	.EXAMPLE
		Repair-ExchangeDAGCopies -ServerFilter 'EX2016-3'
		Repairs every failed/suspended copy on server EX2016-3.
	.EXAMPLE
		Repair-ExchangeDAGCopies -ServerFilter 'EX2016-3' -DatabaseFilter '2016-MailStoreDBAttorneys-*' -WhatIf
		Previews the repair actions for matching copies without making changes.
	.EXAMPLE
		Repair-ExchangeDAGCopies -ServerFilter 'EX2016-3' -Parallel
		Kicks off reseeds in parallel for all failed copies on EX2016-3 (faster on a LAN, but
		don't use over a WAN with multiple copies - it will saturate the link).
	.EXAMPLE
		Repair-ExchangeDAGCopies -ServerFilter 'EX2016-3' -AutoFilesystemRepair
		If a reseed fails because of NTFS corruption (error 1392 or 'Corruption in the
		filesystem...'), runs Repair-Volume -Scan and -SpotFix on the affected volume and
		retries the reseed. Skips the OS volume.
	.EXAMPLE
		Repair-ExchangeDAGCopies -RegisterScheduledTask
		Schedules a weekly repair at the default day/time (Saturday 11:00 PM) covering all servers
		and databases. Runs serial by default (waits for each reseed to finish before starting
		the next), suitable for WAN-connected DAG members.
	.EXAMPLE
		Repair-ExchangeDAGCopies -RegisterScheduledTask -ScheduledDay Sunday -ScheduledTime '1:00 AM' -ServerFilter 'EX2016-3'
		Schedules a weekly repair Sunday at 1 AM scoped to EX2016-3.
	.EXAMPLE
		Repair-ExchangeDAGCopies -UnregisterScheduledTask
		Removes the scheduled task.
	.NOTES
		Output from the scheduled run is appended to:
		  $env:ProgramData\MauleTech\Logs\Repair-ExchangeDAGCopies.log
		The wrapper script lives at:
		  $env:ProgramData\MauleTech\Repair-ExchangeDAGCopies.ps1
	#>
	[CmdletBinding(DefaultParameterSetName = 'Repair', SupportsShouldProcess)]
	param(
		[Parameter(ParameterSetName = 'Repair')]
		[Parameter(ParameterSetName = 'Register')]
		[string]$ServerFilter = '*',

		[Parameter(ParameterSetName = 'Repair')]
		[Parameter(ParameterSetName = 'Register')]
		[string]$DatabaseFilter = '*',

		[Parameter(ParameterSetName = 'Repair')]
		[Parameter(ParameterSetName = 'Register')]
		[ValidateRange(0, 3600)]
		[int]$ResumeWaitSeconds = 60,

		[Parameter(ParameterSetName = 'Repair')]
		[Parameter(ParameterSetName = 'Register')]
		[ValidateRange(0, 3600)]
		[int]$StaggerSeconds = 10,

		[Parameter(ParameterSetName = 'Repair')]
		[Parameter(ParameterSetName = 'Register')]
		[switch]$Parallel,

		[Parameter(ParameterSetName = 'Repair')]
		[Parameter(ParameterSetName = 'Register')]
		[ValidateRange(1, 168)]
		[int]$ReseedTimeoutHours = 24,

		[Parameter(ParameterSetName = 'Repair')]
		[Parameter(ParameterSetName = 'Register')]
		[ValidateRange(1, 60)]
		[int]$ReseedPollMinutes = 5,

		[Parameter(ParameterSetName = 'Repair')]
		[Parameter(ParameterSetName = 'Register')]
		[switch]$AutoFilesystemRepair,

		[Parameter(Mandatory, ParameterSetName = 'Register')]
		[switch]$RegisterScheduledTask,

		[Parameter(Mandatory, ParameterSetName = 'Unregister')]
		[switch]$UnregisterScheduledTask,

		[Parameter(ParameterSetName = 'Register')]
		[ValidateSet('Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday')]
		[string]$ScheduledDay = 'Saturday',

		[Parameter(ParameterSetName = 'Register')]
		[DateTime]$ScheduledTime = '11:00 PM'
	)

	$TaskName = 'MauleTech-RepairExchangeDAGCopies'

	#region Unregister Scheduled Task
	if ($PSCmdlet.ParameterSetName -eq 'Unregister') {
		$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
		if (-not $existingTask) {
			Write-Host "Scheduled task '$TaskName' does not exist." -ForegroundColor Yellow
			return
		}
		if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister-ScheduledTask')) {
			try {
				Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
				Write-Host "Scheduled task '$TaskName' has been removed." -ForegroundColor Green
			} catch {
				Write-Host "Failed to remove scheduled task: $($_.Exception.Message)" -ForegroundColor Red
			}
		}
		return
	}
	#endregion

	#region Register Scheduled Task
	if ($PSCmdlet.ParameterSetName -eq 'Register') {
		$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
			[Security.Principal.WindowsBuiltInRole]::Administrator)
		if (-not $isAdmin) {
			Write-Host "Administrator privileges are required to register a scheduled task." -ForegroundColor Red
			return
		}

		# Validate filter inputs - allow PowerShell wildcards plus standard identifier chars,
		# and reject anything else so the values are safe to embed in the wrapper script string.
		foreach ($pair in @(
			@{ Name = 'ServerFilter';   Value = $ServerFilter   },
			@{ Name = 'DatabaseFilter'; Value = $DatabaseFilter }
		)) {
			if ($pair.Value -notmatch '^[A-Za-z0-9._\-*?]+$') {
				Write-Host "Invalid $($pair.Name) value: '$($pair.Value)'. Allowed: letters, digits, dot, dash, underscore, * and ?." -ForegroundColor Red
				return
			}
		}

		$ScriptDir  = Join-Path $env:ProgramData 'MauleTech'
		$LogDir     = Join-Path $ScriptDir       'Logs'
		$ScriptPath = Join-Path $ScriptDir       'Repair-ExchangeDAGCopies.ps1'
		$LogPath    = Join-Path $LogDir          'Repair-ExchangeDAGCopies.log'

		# Wrapper script body. Single-quoted here-string keeps the body literal; the parameter
		# header above it is interpolated and validated. Filter values are validated above.
		$parallelLiteral = if ($Parallel) { '$true' } else { '$false' }
		$autoFsLiteral   = if ($AutoFilesystemRepair) { '$true' } else { '$false' }
		$WrapperHeader = @"
`$LogPath              = '$LogPath'
`$ServerFilter         = '$ServerFilter'
`$DatabaseFilter       = '$DatabaseFilter'
`$ResumeWaitSeconds    = $ResumeWaitSeconds
`$StaggerSeconds       = $StaggerSeconds
`$Parallel             = $parallelLiteral
`$ReseedTimeoutHours   = $ReseedTimeoutHours
`$ReseedPollMinutes    = $ReseedPollMinutes
`$AutoFilesystemRepair = $autoFsLiteral
"@

		$WrapperBody = @'
$ErrorActionPreference = 'Continue'
New-Item -Path (Split-Path $LogPath -Parent) -ItemType Directory -Force | Out-Null

$Stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
"=== Repair-ExchangeDAGCopies run at $Stamp ===" | Out-File -FilePath $LogPath -Append -Encoding ASCII

try {
	if (-not (Get-PSSnapin -Registered -Name 'Microsoft.Exchange.Management.PowerShell.SnapIn' -ErrorAction SilentlyContinue)) {
		throw 'Exchange Management Shell snap-in is not registered on this server.'
	}
	if (-not (Get-PSSnapin -Name 'Microsoft.Exchange.Management.PowerShell.SnapIn' -ErrorAction SilentlyContinue)) {
		Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop
	}

	[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
	try {
		Invoke-RestMethod -Uri 'https://ps.mauletech.com' | Invoke-Expression
	} catch {
		Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt' | Invoke-Expression
	}

	Repair-ExchangeDAGCopies `
		-ServerFilter $ServerFilter `
		-DatabaseFilter $DatabaseFilter `
		-ResumeWaitSeconds $ResumeWaitSeconds `
		-StaggerSeconds $StaggerSeconds `
		-Parallel:$Parallel `
		-ReseedTimeoutHours $ReseedTimeoutHours `
		-ReseedPollMinutes $ReseedPollMinutes `
		-AutoFilesystemRepair:$AutoFilesystemRepair *>&1 |
		Tee-Object -FilePath $LogPath -Append
} catch {
	"[ERROR] $($_.Exception.Message)" | Out-File -FilePath $LogPath -Append -Encoding ASCII
}
'@

		$Wrapper = $WrapperHeader + "`r`n" + $WrapperBody

		if ($PSCmdlet.ShouldProcess($ScriptPath, 'Write wrapper script')) {
			New-Item -Path $ScriptDir -ItemType Directory -Force | Out-Null
			$Wrapper | Out-File -FilePath $ScriptPath -Encoding ASCII -Force
		}

		$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
		if ($existingTask) {
			Write-Host "Scheduled task '$TaskName' already exists -- replacing." -ForegroundColor Yellow
			if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister existing task before replacing')) {
				try {
					Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
				} catch {
					Write-Host "Failed to remove existing task: $($_.Exception.Message)" -ForegroundColor Red
					return
				}
			}
		}

		$Action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
			-Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""
		$Trigger   = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek $ScheduledDay -At $ScheduledTime
		# 72h gives serial mode enough headroom to step through several large reseeds back-to-back
		# (default 24h per-copy timeout x worst-case stuck copies). Tasks that exceed this are killed
		# by the scheduler; the remaining copies will be retried on the next weekly run.
		$Settings  = New-ScheduledTaskSettingsSet `
			-AllowStartIfOnBatteries `
			-DontStopIfGoingOnBatteries `
			-StartWhenAvailable `
			-ExecutionTimeLimit (New-TimeSpan -Hours 72)
		$Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

		$timeStr = $ScheduledTime.ToString('h:mm tt')
		if ($PSCmdlet.ShouldProcess($TaskName, "Register-ScheduledTask weekly $ScheduledDay $timeStr")) {
			try {
				Register-ScheduledTask -TaskName $TaskName `
					-Action $Action `
					-Trigger $Trigger `
					-Settings $Settings `
					-Principal $Principal `
					-Description "MauleTech: Repairs failed/suspended Exchange DAG database copies weekly. Filters: Server='$ServerFilter' Database='$DatabaseFilter'." `
					-ErrorAction Stop | Out-Null

				$modeStr = if ($Parallel) { 'Parallel (no wait between reseeds)' } else { "Serial (wait per copy, ${ReseedTimeoutHours}h timeout, ${ReseedPollMinutes}min poll)" }
				$fsStr   = if ($AutoFilesystemRepair) { 'Enabled (will run Repair-Volume on corrupt non-OS volumes)' } else { 'Disabled' }
				Write-Host "Scheduled task '$TaskName' created successfully." -ForegroundColor Green
				Write-Host "  Schedule:       Weekly on $ScheduledDay at $timeStr" -ForegroundColor Cyan
				Write-Host "  Mode:           $modeStr" -ForegroundColor Cyan
				Write-Host "  AutoFsRepair:   $fsStr" -ForegroundColor Cyan
				Write-Host "  ServerFilter:   $ServerFilter"   -ForegroundColor Cyan
				Write-Host "  DatabaseFilter: $DatabaseFilter" -ForegroundColor Cyan
				Write-Host "  Wrapper script: $ScriptPath"     -ForegroundColor Cyan
				Write-Host "  Log file:       $LogPath"        -ForegroundColor Cyan
				Write-Host "  To remove:      Repair-ExchangeDAGCopies -UnregisterScheduledTask" -ForegroundColor Cyan
			} catch {
				Write-Host "Failed to create scheduled task: $($_.Exception.Message)" -ForegroundColor Red
			}
		}
		return
	}
	#endregion

	#region Repair pass
	if (-not (Get-Command Get-MailboxDatabaseCopyStatus -ErrorAction SilentlyContinue)) {
		Write-Host "Exchange Management Shell cmdlets are not loaded." -ForegroundColor Red
		Write-Host "Run from EMS, or load the snap-in first:" -ForegroundColor Red
		Write-Host "  Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn" -ForegroundColor Red
		return
	}

	# Polls Get-MailboxDatabaseCopyStatus until the copy is Healthy/Mounted, the timeout fires,
	# or the status is stuck in a failure state across multiple polls. Used in serial mode to
	# avoid kicking off concurrent reseeds across a WAN link. Terminates without throwing so
	# the outer loop can move on to the next copy regardless of outcome.
	$waitForReseed = {
		param([string]$Id, [int]$TimeoutHours, [int]$PollMinutes)

		$start    = Get-Date
		$deadline = $start.AddHours($TimeoutHours)
		$badStates       = @('Failed','FailedAndSuspended','Suspended','ServiceDown','Disconnected')
		$consecutiveBads = 0

		Write-Host "    Waiting for $Id (poll every $PollMinutes min, timeout $TimeoutHours h)..." -ForegroundColor Cyan

		do {
			Start-Sleep -Seconds ($PollMinutes * 60)

			$cur = Get-MailboxDatabaseCopyStatus -Identity $Id -ErrorAction SilentlyContinue
			if (-not $cur) {
				Write-Host "    [!] Could not query status for $Id. Continuing to next copy." -ForegroundColor Yellow
				return
			}

			$elapsed = '{0:hh\:mm\:ss}' -f ((Get-Date) - $start)
			Write-Host "    [+$elapsed] Status: $($cur.Status), CopyQueue: $($cur.CopyQueueLength)"

			if ($cur.Status -in @('Healthy','Mounted')) {
				Write-Host "    [OK] Reseed complete for $Id (elapsed $elapsed)." -ForegroundColor Green
				return
			}

			if ($cur.Status -in $badStates) {
				$consecutiveBads++
				# 3 consecutive bad polls = ~$($PollMinutes * 3) min stuck. Bail out so the outer
				# loop can move on rather than waiting the full timeout on a copy that isn't moving.
				if ($consecutiveBads -ge 3) {
					Write-Host "    [!!] Status stuck at $($cur.Status) over $consecutiveBads polls. Continuing to next copy." -ForegroundColor Red
					return
				}
			} else {
				$consecutiveBads = 0
			}

			if ((Get-Date) -gt $deadline) {
				Write-Host "    [!] Timeout after $TimeoutHours hours for $Id. Continuing to next copy." -ForegroundColor Yellow
				return
			}
		} while ($true)
	}

	# Tracks volumes already repaired during this session keyed by "<server>|<DriveLetter>"
	# so 9 failing copies on the same I: drive only trigger one chkdsk pass.
	$repairedVolumes = @{}

	# Runs Repair-Volume -Scan on the target server, then -SpotFix only if the scan reports
	# anything other than NoErrorsFound. Refuses to touch the OS volume. Returns the string
	# 'Repaired' if a SpotFix completed, 'Clean' if scan reported no errors, 'Skipped' if
	# the volume is the OS volume, or 'Failed' on any error path.
	$runFilesystemRepair = {
		param([string]$Server, [string]$Volume)

		Write-Host "    Running Repair-Volume scan on $Server volume ${Volume}:..." -ForegroundColor Magenta
		try {
			$result = Invoke-Command -ComputerName $Server -ScriptBlock {
				param([string]$v)
				$osLetter = $env:SystemDrive.TrimEnd(':')
				if ($v -ieq $osLetter) {
					return [pscustomobject]@{ Outcome = 'Skipped'; Detail = "Refusing to chkdsk OS volume ${v}: on $env:COMPUTERNAME" }
				}
				try {
					$scan = Repair-Volume -DriveLetter $v -Scan -ErrorAction Stop
				} catch {
					return [pscustomobject]@{ Outcome = 'Failed'; Detail = "Scan threw: $($_.Exception.Message)" }
				}
				if ($scan -eq 'NoErrorsFound') {
					return [pscustomobject]@{ Outcome = 'Clean'; Detail = "Scan: $scan" }
				}
				try {
					# -SpotFix dismounts the volume briefly; this affects every database
					# whose files live on it. Only acceptable because the caller opted in
					# via -AutoFilesystemRepair.
					$fix = Repair-Volume -DriveLetter $v -SpotFix -ErrorAction Stop
					return [pscustomobject]@{ Outcome = 'Repaired'; Detail = "Scan: $scan; SpotFix: $fix" }
				} catch {
					return [pscustomobject]@{ Outcome = 'Failed'; Detail = "Scan: $scan; SpotFix threw: $($_.Exception.Message)" }
				}
			} -ArgumentList $Volume -ErrorAction Stop

			switch ($result.Outcome) {
				'Clean'    { Write-Host "    [OK] Volume ${Volume}: scan clean. $($result.Detail)" -ForegroundColor Green }
				'Repaired' { Write-Host "    [OK] Volume ${Volume}: $($result.Detail)" -ForegroundColor Green }
				'Skipped'  { Write-Host "    [!!] $($result.Detail)" -ForegroundColor Red }
				'Failed'   { Write-Host "    [!!] Volume ${Volume}: $($result.Detail)" -ForegroundColor Red }
			}
			return $result.Outcome
		} catch {
			Write-Host "    [!!] Filesystem repair invocation failed: $($_.Exception.Message)" -ForegroundColor Red
			return 'Failed'
		}
	}

	# Resolve target copies. Wrapping in @(...) ensures .Count works correctly when only
	# one copy matches (PowerShell unwraps single-item collections by default).
	$failedCopies = @(Get-MailboxDatabaseCopyStatus * |
		Where-Object {
			$_.Status -match 'Failed|Suspended' -and
			$_.Name -like "*\$ServerFilter" -and
			($_.Name -split '\\')[0] -like $DatabaseFilter
		})

	if ($failedCopies.Count -eq 0) {
		Write-Host "No failed/suspended copies found matching filters." -ForegroundColor Green
		return
	}

	Write-Host "Found $($failedCopies.Count) failed/suspended copy(s) to process." -ForegroundColor Cyan

	foreach ($copy in $failedCopies) {
		$identity = $copy.Name
		$dbName   = ($identity -split '\\')[0]
		$server   = ($identity -split '\\')[1]

		Write-Host "`n[$identity] Status: $($copy.Status) | CopyQueue: $($copy.CopyQueueLength)" -ForegroundColor Yellow

		# --- Step 1: Resume ---
		Write-Host "  [1/3] Attempting Resume..." -ForegroundColor Cyan
		if ($PSCmdlet.ShouldProcess($identity, 'Resume-MailboxDatabaseCopy')) {
			try {
				Resume-MailboxDatabaseCopy -Identity $identity -ErrorAction Stop
				Write-Verbose "Resume command issued for $identity. Waiting $ResumeWaitSeconds seconds..."
				Start-Sleep -Seconds $ResumeWaitSeconds

				$status = (Get-MailboxDatabaseCopyStatus -Identity $identity).Status
				if ($status -in @('Healthy','Mounted')) {
					Write-Host "  [OK] Resume succeeded. Status: $status" -ForegroundColor Green
					Start-Sleep -Seconds $StaggerSeconds
					continue
				} else {
					Write-Host "  [--] Resume did not recover copy. Status: $status. Escalating..." -ForegroundColor Yellow
				}
			} catch {
				Write-Host "  [--] Resume failed: $($_.Exception.Message)" -ForegroundColor Yellow
			}
		}

		# --- Step 2: Standard Reseed ---
		Write-Host "  [2/3] Attempting standard reseed (-DeleteExistingFiles)..." -ForegroundColor Cyan
		$needsManualCleanup = $false
		if ($PSCmdlet.ShouldProcess($identity, 'Update-MailboxDatabaseCopy -DeleteExistingFiles')) {
			try {
				Update-MailboxDatabaseCopy -Identity $identity -DeleteExistingFiles -Confirm:$false -ErrorAction Stop
				Write-Host "  [OK] Reseed initiated for $identity." -ForegroundColor Green
				if (-not $Parallel) {
					& $waitForReseed -Id $identity -TimeoutHours $ReseedTimeoutHours -PollMinutes $ReseedPollMinutes
				}
				Start-Sleep -Seconds $StaggerSeconds
				continue
			} catch {
				$errMsg = $_.Exception.Message
				Write-Host "  [--] Standard reseed failed: $errMsg" -ForegroundColor Yellow

				# Escalate to manual cleanup when the error suggests stale temp-seeding
				# files, locked files, or filesystem corruption. '1392' is
				# ERROR_FILE_CORRUPT; 'Corruption in the filesystem' / 'consistent with
				# corruption of the filesystem' are the strings Exchange surfaces when
				# NTFS reports trouble; 'JET_errFileAccessDenied' covers locked files.
				if ($errMsg -match '1392|temp-seeding|JET_errFileAccessDenied|prerequisite check|Corruption in the filesystem|consistent with corruption of the filesystem') {
					Write-Host "  [!] Detected temp-seeding or filesystem error. Escalating to manual cleanup..." -ForegroundColor Magenta
					$needsManualCleanup = $true
				} else {
					Write-Host "  [!!] Unrecognized reseed error on $identity. Skipping to avoid further damage. Review manually." -ForegroundColor Red
					continue
				}
			}
		}

		if (-not $needsManualCleanup) {
			# Either ShouldProcess was false (-WhatIf) or the reseed succeeded/skipped.
			# Don't proceed to destructive cleanup unless the prior step explicitly asked for it.
			continue
		}

		# --- Step 3: Manual temp-seeding cleanup + reseed ---
		Write-Host "  [3/3] Attempting manual temp-seeding folder cleanup on $server..." -ForegroundColor Cyan

		# Resolve temp-seeding path from the database object's EdbFilePath
		$tempSeedingPath = $null
		try {
			$db = Get-MailboxDatabase -Identity $dbName -Status -ErrorAction Stop
			$dbDir = Split-Path $db.EdbFilePath.ToString() -Parent
			$tempSeedingPath = Join-Path $dbDir 'temp-seeding'
		} catch {
			Write-Host ("  [!!] Could not resolve DB path for {0}: {1}" -f $dbName, $_.Exception.Message) -ForegroundColor Red
			continue
		}

		Write-Verbose "Temp-seeding path resolved: $tempSeedingPath on $server"

		$cleanupTarget = "{0}:{1}" -f $server, $tempSeedingPath
		if ($PSCmdlet.ShouldProcess($cleanupTarget, 'Remove temp-seeding folder')) {
			try {
				Invoke-Command -ComputerName $server -ScriptBlock {
					param($path)
					if (Test-Path $path) {
						Write-Host "    Removing: $path"
						Remove-Item $path -Recurse -Force -ErrorAction Stop
						Write-Host "    Removed successfully."
					} else {
						Write-Host "    Path not found (may already be gone): $path"
					}
				} -ArgumentList $tempSeedingPath -ErrorAction Stop

				Write-Host "  [OK] Temp-seeding folder cleared. Retrying reseed..." -ForegroundColor Cyan

				if ($PSCmdlet.ShouldProcess($identity, 'Update-MailboxDatabaseCopy after manual cleanup')) {
					Update-MailboxDatabaseCopy -Identity $identity -DeleteExistingFiles -Confirm:$false -ErrorAction Stop
					Write-Host "  [OK] Reseed initiated after manual cleanup." -ForegroundColor Green
					if (-not $Parallel) {
						& $waitForReseed -Id $identity -TimeoutHours $ReseedTimeoutHours -PollMinutes $ReseedPollMinutes
					}
				}
			} catch {
				$step3Err = $_.Exception.Message
				Write-Host ("  [!!] Manual cleanup or reseed failed for {0}: {1}" -f $identity, $step3Err) -ForegroundColor Red

				$looksLikeFsCorruption = $step3Err -match '1392|Corruption in the filesystem|consistent with corruption of the filesystem'

				if (-not $AutoFilesystemRepair) {
					if ($looksLikeFsCorruption) {
						Write-Host "       Filesystem corruption suspected on $server. Re-run with -AutoFilesystemRepair, or investigate chkdsk on the hosting volume manually." -ForegroundColor Red
					}
					Start-Sleep -Seconds $StaggerSeconds
					continue
				}

				if (-not $looksLikeFsCorruption) {
					Write-Host "       Error does not match a known filesystem-corruption pattern; skipping chkdsk to be safe." -ForegroundColor Red
					Start-Sleep -Seconds $StaggerSeconds
					continue
				}

				# Extract drive letter from the first absolute path mentioned in the error
				$driveLetter = $null
				if ($step3Err -match '\b([A-Za-z]):\\') {
					$driveLetter = $Matches[1].ToUpper()
				}
				if (-not $driveLetter) {
					Write-Host "       Could not extract a drive letter from the error message; skipping chkdsk." -ForegroundColor Red
					Start-Sleep -Seconds $StaggerSeconds
					continue
				}

				$volKey = "{0}|{1}" -f $server, $driveLetter
				if ($repairedVolumes.ContainsKey($volKey)) {
					Write-Host "       Volume ${driveLetter}: on $server already repaired this run; retrying reseed without rescanning." -ForegroundColor Cyan
				} else {
					if (-not $PSCmdlet.ShouldProcess("$server volume ${driveLetter}:", 'Repair-Volume -Scan/-SpotFix')) {
						Start-Sleep -Seconds $StaggerSeconds
						continue
					}
					$outcome = & $runFilesystemRepair -Server $server -Volume $driveLetter
					$repairedVolumes[$volKey] = $outcome
					if ($outcome -notin @('Clean','Repaired')) {
						Write-Host "       Filesystem repair did not complete cleanly (outcome: $outcome). Skipping further retries on this copy." -ForegroundColor Red
						Start-Sleep -Seconds $StaggerSeconds
						continue
					}
				}

				if ($PSCmdlet.ShouldProcess($identity, 'Update-MailboxDatabaseCopy after filesystem repair')) {
					try {
						Write-Host "       Retrying reseed after filesystem repair..." -ForegroundColor Cyan
						Update-MailboxDatabaseCopy -Identity $identity -DeleteExistingFiles -Confirm:$false -ErrorAction Stop
						Write-Host "  [OK] Reseed initiated after filesystem repair." -ForegroundColor Green
						if (-not $Parallel) {
							& $waitForReseed -Id $identity -TimeoutHours $ReseedTimeoutHours -PollMinutes $ReseedPollMinutes
						}
					} catch {
						Write-Host "       Reseed still fails after filesystem repair: $($_.Exception.Message)" -ForegroundColor Red
						Write-Host "       This copy may need manual intervention beyond chkdsk (e.g. chkdsk /F offline, or a full reseed from a different source server)." -ForegroundColor Red
					}
				}
			}
		}

		Start-Sleep -Seconds $StaggerSeconds
	}

	Write-Host "`nRepair pass complete. Run Get-MailboxDatabaseCopyStatus to review current state." -ForegroundColor Cyan
	#endregion
}

Function Repair-ChocoDependency {
<#
	.SYNOPSIS
		Repairs "unresolved package dependency constraints" errors that block Chocolatey installs and upgrades.
	.DESCRIPTION
		Chocolatey v2.x refuses to install or upgrade ANY package while one or more
		already-installed packages declare a dependency that is not present in the
		lib folder. The blocking error reads:

			"One or more unresolved package dependency constraints detected in the
			 Chocolatey lib folder. All dependency constraints must be resolved to
			 add or update packages."

		This commonly happens on machines where packages such as
		dotnet-8.0-desktopruntime or dellcommandupdate were installed without their
		chocolatey-core.extension and vcredist140 dependencies. Until those missing
		dependencies are present, even unrelated operations (upgrading pwsh or
		microsoft-edge, "choco upgrade all", etc.) fail.

		This function installs the missing dependency packages in a single
		"choco install" call so Chocolatey resolves them as a group. Installing them
		one at a time can fail, because each pass still sees the others as unresolved
		(for example "choco install chocolatey-core.extension" fails while vcredist140
		is still missing). The well-known culprits (chocolatey-core.extension and
		vcredist140) are always included, and any additional dependency names found in
		supplied choco output are added to the repair set.
	.PARAMETER ChocoOutput
		Optional captured output from a failed "choco install" / "choco upgrade"
		operation. Any package names referenced by the unresolved-dependency errors
		are parsed out and added to the repair set.
	.PARAMETER AdditionalPackage
		Optional extra package id(s) to include in the repair install.
	.EXAMPLE
		Repair-ChocoDependency
	.EXAMPLE
		$Output = choco upgrade pwsh -y --force 2>&1
		If ($Output -match 'Unable to resolve dependency') { Repair-ChocoDependency -ChocoOutput $Output }
	.NOTES
		Requires Chocolatey. If choco.exe is missing it is installed first via Install-Choco.
#>
	[CmdletBinding()]
	Param(
		[Parameter(ValueFromPipeline = $true)]
		[string[]]$ChocoOutput,

		[Parameter()]
		[string[]]$AdditionalPackage
	)

	# Make sure choco is available before trying to repair anything.
	If (!(Get-Command choco -ErrorAction SilentlyContinue)) {
		Write-Host "Chocolatey not found. Installing it first." -ForegroundColor Yellow
		Install-Choco
	}
	If (!(Get-Command choco -ErrorAction SilentlyContinue)) {
		Write-Host "Chocolatey is still not available, cannot repair dependencies." -ForegroundColor Red
		Return $false
	}

	# chocolatey-core.extension and vcredist140 are by far the most common missing
	# constraints. vcredist140 itself depends on chocolatey-core.extension, so listing
	# both in one install lets choco resolve the whole group at once.
	$RepairSet = New-Object System.Collections.Generic.List[string]
	ForEach ($Pkg in @('chocolatey-core.extension', 'vcredist140')) { $RepairSet.Add($Pkg) }

	# Pull any other unresolved dependency names out of the choco output we were handed.
	# The blocking errors look like:
	#   Unable to resolve dependency 'vcredist140'.
	#   Unable to find a version of 'chocolatey-core.extension' that is compatible...
	If ($ChocoOutput) {
		$Text = $ChocoOutput -join "`n"
		$Patterns = @(
			"Unable to resolve dependency '([^']+)'",
			"Unable to find a version of '([^']+)'"
		)
		ForEach ($Pattern in $Patterns) {
			ForEach ($Match in [regex]::Matches($Text, $Pattern)) {
				$Name = $Match.Groups[1].Value.Trim()
				If ($Name -and ($RepairSet -notcontains $Name)) { $RepairSet.Add($Name) }
			}
		}
	}

	# Caller-specified extras.
	ForEach ($Pkg in $AdditionalPackage) {
		If ($Pkg -and ($RepairSet -notcontains $Pkg)) { $RepairSet.Add($Pkg) }
	}

	Write-Host "Repairing Chocolatey dependency constraints by installing: $($RepairSet -join ', ')" -ForegroundColor Cyan

	# Install the whole set in one call so choco resolves them together. Packages that
	# are already present at a satisfying version are skipped, so this is a safe no-op
	# when nothing is actually broken.
	$ChocoArgs = @('install') + $RepairSet + @('-y')
	$RepairOutput = & choco @ChocoArgs 2>&1
	$RepairText = $RepairOutput | Out-String
	Write-Host $RepairText

	If ($RepairText -match 'packages failed') {
		Write-Host "Dependency repair reported one or more failures. Review C:\ProgramData\chocolatey\logs\chocolatey.log." -ForegroundColor Red
		Return $false
	}

	Write-Host "Chocolatey dependency constraints repaired." -ForegroundColor Green
	Return $true
}

Function Repair-AdobeCreativeCloud {
	<#
	.SYNOPSIS
		Clears the Adobe Creative Cloud OOBE cache to fix sign-in loops and startup failures.
	.DESCRIPTION
		Resets the Creative Cloud desktop app by stopping its background processes and renaming
		the per-user OOBE folders out of the way. Creative Cloud rebuilds them on next launch,
		which clears the state behind the usual crop of complaints:

		- Creative Cloud asks for a sign in every launch, or loops back to the sign in screen
		- "Unable to reach Adobe servers" on an otherwise healthy internet connection
		- The desktop app opens to a permanent spinner or a blank white window
		- Apps show as not installed when they are installed, or the Apps tab never populates
		- The app stays signed in to a stale account after the user's email or plan changed

		Two folders hold that state, and both are reset:

		- <profile>\AppData\Local\Adobe\OOBE
		- <profile>\AppData\Roaming\Adobe\OOBE

		Each is renamed to OOBE.old rather than deleted, so the original is still on disk if a
		reset turns out not to have been the problem. Nothing is ever deleted: on a machine that
		has been reset before, where OOBE.old already exists, the new backup takes a timestamped
		name instead, so the first backup (the one holding the state from before any reset) is
		never overwritten.

		Nothing is uninstalled, no licensing data is touched, and installed apps are left alone.
		The only cost to the user is signing in to Creative Cloud once more.

		By default the function works on the profile it is running under. That is the wrong
		profile when the toolbox is launched from an RMM tool such as ScreenConnect, which runs
		as SYSTEM: the SYSTEM profile has no Creative Cloud state, so the run would report
		nothing to do on a machine that needs the reset. Running as SYSTEM without a target is
		therefore refused with a pointer to -AllUsers or -UserName rather than quietly doing
		nothing useful.
	.PARAMETER UserName
		Reset the named profiles instead of the current one. Matches on the profile folder name
		or the account name, so both "jdoe" and "CONTOSO\jdoe" resolve, as does the profile folder
		jdoe.CONTOSO that a second domain logon creates. A name that matches no profile exactly is
		reported with what it did match rather than acted on, so "rob" does not silently reset
		rob.smith; name that profile exactly, or add -Force. A name that matches several profiles
		is treated the same way. Requires an elevated session.
	.PARAMETER AllUsers
		Reset every real user profile on the machine. Service and built in profiles (SYSTEM,
		LOCAL SERVICE, NETWORK SERVICE, Default, Public) are skipped. This is the switch to use
		from an RMM or remote support tool running as SYSTEM. Requires an elevated session.
	.PARAMETER SkipProcessStop
		Leave the Creative Cloud processes running. Only useful when they have already been
		stopped by hand, or on a machine where stopping them is not wanted. A running CoreSync
		or Adobe Desktop Service holds an open handle on the OOBE folder, so the rename will
		usually fail with the processes up.
	.PARAMETER StopAllSessions
		Stop matching Adobe processes no matter which account owns them. By default only
		processes owned by a targeted user are stopped, so that resetting one profile on a
		terminal server or shared workstation does not kill Creative Cloud for everyone else
		signed in. Use this switch when process ownership cannot be read, which shows up as a
		rename that fails because the folder is in use.
	.PARAMETER Force
		Proceed past the cases that are otherwise refused:

		- -AllUsers on a machine with more than one user signed in at once, where the sweep would
		  kill Creative Cloud in every live session on a terminal server. Resetting one signed in
		  user, the ordinary workstation case, is not refused and does not need this switch.
		- a -UserName value that matches no profile exactly and only matches one on folder prefix,
		  where "rob" would otherwise reach into rob.smith.
		- a -UserName value that matches several profiles outright, such as a local jdoe and a
		  domain CONTOSO\jdoe. With -Force all of them are reset; without it, qualify the name.

		A name that matches several profiles on folder prefix alone is refused even with -Force,
		since there is nothing there to tell the operator's intent from a coincidence. Name one
		of the profiles exactly.

		This switch does not override the junction and symlink refusal. That one has its own
		switch, -AllowJunctions, deliberately: the shared machine message above tells an operator
		to rerun with -Force, and a -Force that also waved through a redirected path would turn
		routine advice into a way to get an elevated rename pointed at C:\Windows.
	.PARAMETER AllowJunctions
		Reset through a junction, symlink, or unreadable folder in the path instead of refusing.

		Somebody who moved their Adobe folder onto another drive with a junction hits that refusal
		legitimately, and this is how they get past it. So does an attempt to make an elevated
		rename land somewhere else, which is why it is a separate switch and why the path is
		printed either way. Read the reported path before using this.
	.PARAMETER ProcessWaitSeconds
		How long to wait for the stopped processes to actually exit before renaming, in seconds.
		Default 20. Adobe Desktop Service in particular takes a moment to release its handles.
		Applies per pass, and there are at most two, so this is half the worst case wait.
	.PARAMETER PassThru
		Return a result object per folder instead of only printing the report, for logging or
		for feeding into a wider maintenance script.
	.OUTPUTS
		None by default; the report is written to the host.

		[PSCustomObject] per folder with -PassThru, carrying UserName, SID, Scope (Local or
		Roaming), Path, Action, BackupPath, Warning, and Error. Warning is normally $null and
		carries the path that was reset through when -AllowJunctions was used, so a log cannot
		hide that one from a reset that was simply clean. Action is one of Renamed, NotPresent,
		Skipped (declined at a -Confirm prompt, or previewed under -WhatIf), Failed (the rename did
		not go through, almost always a lock), Redirected (a junction or symlink stands in the path
		and the rename was refused), or Unreadable (a folder in the path would not report its
		attributes, so a junction could not be ruled out and the rename was refused).
	.NOTES
		Requires an elevated session for -AllUsers and -UserName, since those reach into other
		users' profiles. Resetting the current profile does not need elevation.

		Nothing is ever deleted, so the OOBE.old folders stay on disk until someone removes them.
		Once the user has confirmed Creative Cloud signs in and behaves, they are safe to delete
		by hand. They are the only thing this function leaves behind.

		The user should be signed out of Creative Cloud, or at least not mid sync, before this
		runs. Files already synced to the cloud are safe; the OOBE folder holds sign in state
		and desktop app configuration, not user documents.

		For a profile other than the current one, the AppData paths are derived from the profile
		folder. If Roaming AppData has been redirected to a network share by Group Policy, the
		derived path will not be the live one and the roaming folder will be reported as not
		present. Run the reset in the user's own session, or under -UserName from a machine that
		can see the redirected path, when folder redirection is in play.

		Deliberately not touched: the SLStore and SLCache licensing folders, which some older
		walkthroughs also rename. Those carry activation state, and clearing them turns a sign
		in nuisance into a licensing problem. If the OOBE reset does not fix it, the next step
		is the Adobe Creative Cloud Cleaner Tool, not more folder renaming.

		Creative Cloud restarts its own background processes on next launch. No reboot needed.
	.EXAMPLE
		Repair-AdobeCreativeCloud
		Resets Creative Cloud for the account running the command. This is the form to use from
		the user's own session.
	.EXAMPLE
		Repair-AdobeCreativeCloud -AllUsers
		Resets every user profile on the machine. This is the form to use from ScreenConnect or
		any other tool that runs as SYSTEM.
	.EXAMPLE
		Repair-AdobeCreativeCloud -UserName jdoe
		Resets a single named profile, leaving other signed in users alone.
	.EXAMPLE
		Repair-AdobeCreativeCloud -AllUsers -WhatIf
		Shows which folders would be renamed and which processes would be stopped, without
		changing anything.
	.EXAMPLE
		Repair-AdobeCreativeCloud -AllUsers -PassThru | Export-Csv "$ITFolder\AdobeReset.csv" -NoTypeInformation
		Logs the outcome per folder for a maintenance record.
	.LINK
		https://helpx.adobe.com/x-productkb/global/adobe-background-processes.html
	.LINK
		https://helpx.adobe.com/creative-cloud/kb/creative-cloud-desktop-app-troubleshooting.html
	#>
	[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'CurrentUser')]
	[OutputType([PSCustomObject])]
	param (
		[Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'UserName')]
		[ValidateNotNullOrEmpty()]
		[string[]] $UserName,

		[Parameter(Mandatory = $true, ParameterSetName = 'AllUsers')]
		[switch] $AllUsers,

		[switch] $SkipProcessStop,

		[switch] $StopAllSessions,

		[switch] $Force,

		[switch] $AllowJunctions,

		[ValidateRange(0, 300)]
		[int] $ProcessWaitSeconds = 20,

		[switch] $PassThru
	)

	# Platform is absent on Windows PowerShell 5.1 and 'Win32NT' on PowerShell 7 for Windows,
	# so this catches PowerShell 7 on Linux or macOS without touching the $IsWindows automatic
	# variable, which does not exist under 5.1 and would trip Set-StrictMode.
	If ($PSVersionTable.PSVersion.Major -ge 6 -and $PSVersionTable.Platform -ne 'Win32NT') {
		Throw 'Repair-AdobeCreativeCloud resets Windows user profiles and requires Windows.'
	}

	# Creative Cloud desktop and its background helpers. Any of these can hold an open handle on
	# the OOBE folder. The licensing side (AGSService and its AdobeGCClient, AdobeUpdateService)
	# is deliberately left running: those are service launched, they read SLStore and SLCache
	# rather than OOBE, and stopping them only earns a restart from the service control manager.
	$AdobeProcessNames = @(
		'Creative Cloud',
		'Creative Cloud Helper',
		'Adobe Desktop Service',
		'AdobeIPCBroker',
		'AdobeNotificationClient',
		'Adobe CEF Helper',
		'CoreSync',
		'CCXProcess',
		'CCLibrary'
	)
	$ProtectedSIDs = @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')
	$ProtectedNames = @('All Users', 'Default', 'Default User', 'LocalService', 'NetworkService', 'Public')

	Function Get-AncestorChain {
		# $Path and the parents above it, stopping below $StopAt or after $MaxDepth entries.
		#
		# $StopAt is the profile folder and is deliberately excluded, not just used as a stop
		# sign. The profile root is created by Windows and its owner cannot replace it, so it
		# buys no protection to scan, and scanning it breaks real machines: an FSLogix profile
		# container mounts at C:\Users\<user> as a reparse point by design, and every profile on
		# such a host would be refused as tampered with.
		#
		# The depth cap covers the case where $StopAt is never reached, which is what a
		# GPO-redirected AppData does: without it, the walk would climb to the volume or UNC
		# root and start judging shares nobody in this function has any business judging. Four
		# levels is the whole user-writable span of the path being renamed: OOBE, Adobe, Local
		# or Roaming, and AppData.
		param ([string] $Path, [string] $StopAt, [int] $MaxDepth = 4)
		$Chain = @()
		$Current = $Path
		While ($Current -and ($Chain.Count -lt $MaxDepth)) {
			If ($StopAt -and ($Current.TrimEnd('\') -ieq $StopAt.TrimEnd('\'))) { Break }
			$Chain += $Current
			$Parent = Split-Path -Path $Current -Parent
			If (-not $Parent -or ($Parent -eq $Current)) { Break }
			$Current = $Parent
		}
		Return $Chain
	}

	Function Find-ReparsePoint {
		# Returns the first junction or symlink among the given paths, or $null.
		#
		# This runs elevated, and under -AllUsers it runs as SYSTEM against folders inside profile
		# directories the owning user can write. A user who replaces AppData\Local\Adobe with a
		# junction to C:\Windows turns the rename below into "rename C:\Windows\OOBE", performed
		# with privileges they do not have. Every link in the chain is checked, not just the final
		# folder, since the OOBE folder can be perfectly ordinary while a parent is the redirect.
		#
		# Best effort, and worth being clear about why: this is a path check, so a user who plants
		# the junction in the window between this scan and the rename still wins the race. Closing
		# that properly needs the rename done against a handle opened with FILE_FLAG_OPEN_REPARSE_
		# POINT, which is out of reach from Windows PowerShell 5.1 without P/Invoke. What this does
		# buy is that a junction sitting there in advance, the version of the trick that does not
		# require the attacker to be watching, does not work.
		param ([string[]] $Paths)
		ForEach ($Path in $Paths) {
			If (-not $Path) { Continue }
			Try {
				$Item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
			} Catch {
				# A folder whose attributes will not read is not a folder that has been cleared.
				# The owner of a profile can deny FILE_READ_ATTRIBUTES on a folder inside it while
				# leaving traverse allowed, and treating that as clean would hand back exactly the
				# redirect this function exists to catch.
				Return [PSCustomObject]@{ Path = $Path; Kind = 'Unreadable'; Reason = "could not be inspected ($($_.Exception.Message))" }
			}
			If ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
				Return [PSCustomObject]@{ Path = $Path; Kind = 'Reparse'; Reason = 'is a junction or symlink' }
			}
		}
		Return $null
	}

	Function Resolve-AccountName {
		param ([string] $ProfileSID)
		If (-not $ProfileSID) { Return $null }
		Try {
			Return (New-Object System.Security.Principal.SecurityIdentifier($ProfileSID)).Translate([System.Security.Principal.NTAccount]).Value
		} Catch {
			# Deleted domain accounts and unreachable domains both land here. The profile is
			# still resettable by path, so an unresolvable SID is not fatal.
			Write-Verbose "Could not translate SID $ProfileSID - $($_.Exception.Message)"
			Return $null
		}
	}

	Function Get-ProfileNameMatchRank {
		# 2 for an exact match on the profile folder or the account name, 1 for a domain style
		# suffix (a second logon by the same user produces jdoe.CONTOSO or jdoe.000 next to
		# jdoe), 0 for no match. The ranks exist so an exact match wins outright: on a machine
		# with both a jdoe and a john.smith profile, -UserName john must not reach into
		# john.smith, which the suffix pattern on its own would happily match.
		param ([string] $Name, [string] $Account, [string] $Path)
		$Leaf = $(If ($Path) { Split-Path -Path $Path -Leaf } Else { $null })
		If ($Leaf -and ($Leaf -ieq $Name)) { Return 2 }
		If ($Account) {
			If ($Account -ieq $Name) { Return 2 }
			If (($Account -split '\\')[-1] -ieq $Name) { Return 2 }
		}

		# DOMAIN\jdoe has to fall back to matching the folder against jdoe, because the profile of
		# a deleted or unreachable domain account is exactly the one whose SID will not translate,
		# and the one most likely to be named in full. Only for profiles that failed to translate,
		# though: doing it unconditionally would let -UserName CONTOSO\jdoe reach a local jdoe that
		# resolved perfectly well and belongs to somebody else.
		$Names = @($Name)
		If (-not $Account) {
			$ShortName = ($Name -split '\\')[-1]
			If ($ShortName -ne $Name) {
				If ($Leaf -and ($Leaf -ieq $ShortName)) { Return 2 }
				$Names += $ShortName
			}
		}

		If ($Leaf) {
			ForEach ($Candidate in $Names) {
				If ($Leaf -ilike ([System.Management.Automation.WildcardPattern]::Escape($Candidate) + '.*')) { Return 1 }
			}
		}
		Return 0
	}

	$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$CurrentSID = $Identity.User.Value
	$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
	$IsElevated = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

	# Binding -AllUsers:$false still selects the AllUsers parameter set, so a wrapper passing the
	# switch from a variable would sweep the whole machine while asking for the opposite. Refused
	# rather than reinterpreted, because either reading of the intent could be the wrong one.
	If ($PSCmdlet.ParameterSetName -eq 'AllUsers' -and -not $AllUsers) {
		Write-Host "-AllUsers was passed as false. Omit it to reset the current profile, or use -UserName." -ForegroundColor Red
		Write-Error 'Repair-AdobeCreativeCloud: -AllUsers:$false is not a valid request.'
		Return
	}

	# --- Resolve which profiles to work on ---
	$Targets = [System.Collections.ArrayList]::new()
	# Interactive desktop sessions found on the machine, or $null when they could not be counted.
	$SessionCount = $null

	If ($PSCmdlet.ParameterSetName -eq 'CurrentUser') {
		# SYSTEM is what an RMM tool runs as, but a scheduled task can just as easily arrive as
		# LOCAL SERVICE, NETWORK SERVICE, a virtual service account (NT SERVICE\..., S-1-5-80-*)
		# or a gMSA, whose account name ends in $. None of them has a Creative Cloud profile, so
		# every one of them would report a clean machine while the affected user stayed broken.
		$IsServiceAccount = ($ProtectedSIDs -contains $CurrentSID) -or
			($CurrentSID -like 'S-1-5-80-*') -or
			($Identity.Name -like 'NT SERVICE\*') -or
			($Identity.Name -like 'NT AUTHORITY\*') -or
			($Identity.Name.EndsWith('$'))
		If ($IsServiceAccount) {
			Write-Host "Running as $($Identity.Name), a service account with no Creative Cloud state of its own." -ForegroundColor Red
			Write-Host "Use -AllUsers to reset every profile, or -UserName <name> for one." -ForegroundColor Yellow
			# Written to the error stream as well as the host, so a scripted caller can tell a
			# refused run from a machine that simply had nothing to reset. Both produce no output
			# objects, and only this sets $? to false.
			Write-Error "Repair-AdobeCreativeCloud: running as a service account without -AllUsers or -UserName."
			Return
		}
		# The live environment variables are used here rather than paths built from the profile
		# folder, so a redirected AppData is followed correctly for the account we are in.
		[void]$Targets.Add([PSCustomObject]@{
			UserName       = $Identity.Name
			SID            = $CurrentSID
			Loaded         = $true
			ProfileRoot    = $env:USERPROFILE
			LocalAppData   = $env:LOCALAPPDATA
			RoamingAppData = $env:APPDATA
		})
	} Else {
		If (-not $IsElevated) {
			Write-Host "Resetting another user's profile requires an elevated session. Run as Administrator." -ForegroundColor Red
			Write-Error "Repair-AdobeCreativeCloud: -AllUsers and -UserName require an elevated session."
			Return
		}

		Try {
			$AllProfiles = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop)
		} Catch {
			Write-Host "Failed to enumerate user profiles: $($_.Exception.Message)" -ForegroundColor Red
			Write-Error "Repair-AdobeCreativeCloud: could not enumerate user profiles. $($_.Exception.Message)"
			Return
		}

		# Win32_UserProfile rather than the ProfileList registry key: it is not subject to WOW64
		# redirection, so this still works when an RMM tool launches the 32-bit powershell.exe.
		$Candidates = @($AllProfiles | Where-Object {
			$_.LocalPath -and
			-not $_.Special -and
			($ProtectedSIDs -notcontains $_.SID) -and
			($ProtectedNames -notcontains (Split-Path -Path $_.LocalPath -Leaf))
		})

		# Translated once per profile rather than once per profile per name, since each lookup can
		# cost a domain round trip.
		$AccountNameBySID = @{}
		ForEach ($Candidate in $Candidates) {
			If ($Candidate.SID -and -not $AccountNameBySID.ContainsKey($Candidate.SID)) {
				$AccountNameBySID[$Candidate.SID] = Resolve-AccountName -ProfileSID $Candidate.SID
			}
		}

		If ($PSCmdlet.ParameterSetName -eq 'UserName') {
			$Matched = [System.Collections.ArrayList]::new()
			# Names that resolved to nothing. Collected rather than acted on one at a time so that
			# -UserName alice,bob with a typo in bob still resets alice, and still reports a
			# failure a scripted caller can see.
			$Unresolved = [System.Collections.ArrayList]::new()
			ForEach ($RawName in $UserName) {
				$Name = "$RawName".Trim()
				If (-not $Name) { Continue }
				$Ranked = @($Candidates | ForEach-Object {
					[PSCustomObject]@{
						Profile = $_
						Rank    = Get-ProfileNameMatchRank -Name $Name -Account $AccountNameBySID[$_.SID] -Path $_.LocalPath
					}
				} | Where-Object { $_.Rank -gt 0 })

				If ($Ranked.Count -eq 0) {
					Write-Host "No profile found for '$Name'." -ForegroundColor Yellow
					[void]$Unresolved.Add($Name)
					Continue
				}

				$BestRank = ($Ranked | Measure-Object -Property Rank -Maximum).Maximum
				$Hits = @($Ranked | Where-Object { $_.Rank -eq $BestRank } | ForEach-Object { $_.Profile })
				$Leaves = @($Hits | ForEach-Object { Split-Path -Path $_.LocalPath -Leaf })

				If ($BestRank -lt 2) {
					# No profile is named '$Name'; only the folder prefix matched. rob and
					# rob.smith are different people at least as often as jdoe and jdoe.CONTOSO
					# are the same one, so the guess is never acted on unasked. The matches are
					# named, which is usually all the operator needs to retype it exactly.
					If ($Hits.Count -gt 1) {
						Write-Host "'$Name' is ambiguous. It matches $($Leaves -join ', '). Name one of those exactly." -ForegroundColor Red
					} ElseIf ($Force) {
						Write-Host "No profile is named exactly '$Name'. Matching on folder prefix instead: $($Leaves -join ', ')" -ForegroundColor Yellow
					} Else {
						Write-Host "No profile is named exactly '$Name'. Did you mean $($Leaves -join ', ')? Name it exactly, or add -Force." -ForegroundColor Red
					}
					If ($Hits.Count -gt 1 -or -not $Force) {
						[void]$Unresolved.Add($Name)
						Continue
					}
				} ElseIf ($Hits.Count -gt 1) {
					# One name, several profiles that all match it outright: a local jdoe and a
					# domain CONTOSO\jdoe are two different people who happen to share a short
					# name. Qualifying the name picks one of them, so that is what is asked for.
					If ($Force) {
						Write-Host "'$Name' matches $($Hits.Count) profiles: $($Leaves -join ', '). Resetting all of them." -ForegroundColor Yellow
					} Else {
						Write-Host "'$Name' matches $($Hits.Count) profiles: $($Leaves -join ', '). Qualify it (DOMAIN\$Name or $env:COMPUTERNAME\$Name), or use -Force to reset all of them." -ForegroundColor Red
						[void]$Unresolved.Add($Name)
						Continue
					}
				}
				ForEach ($Hit in $Hits) { [void]$Matched.Add($Hit) }
			}

			# Reported at the end rather than here: -UserName alice,bob with a typo in bob must
			# still reset alice, and an -ErrorAction Stop caller would abort the whole run if the
			# error were raised before any work happened.
			$Selected = @($Matched | Sort-Object -Property SID -Unique)
		} Else {
			$Selected = $Candidates
		}

		# Owners of explorer.exe, one per interactive desktop session. Win32_UserProfile.Loaded is
		# the obvious signal here and the wrong one: elevating with a separate admin account loads
		# that account's hive, so an ordinary single user workstation reports two loaded profiles
		# and would trip the shared machine guard below. A desktop shell is what actually marks a
		# user as sitting in front of Creative Cloud.
		$InteractiveSIDs = @()
		$InteractiveSessionIds = @()
		Try {
			# rdpshell.exe as well as explorer.exe: a RemoteApp or published application host runs
			# no desktop shell, so an explorer-only query comes back empty on a session host with
			# a dozen people working in it.
			$Shells = @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'explorer.exe' OR Name = 'rdpshell.exe'" -ErrorAction Stop)
		} Catch {
			# Nothing at all was read, so there is no session list to work from. The coarse
			# profile load state takes over, which over reports (an elevating admin's hive counts
			# as loaded) and so errs toward refusing the sweep. That costs a -Force; the opposite
			# error costs somebody their Creative Cloud session mid use.
			Write-Verbose "Could not enumerate interactive sessions, falling back to profile load state - $($_.Exception.Message)"
			$Shells = @()
			$InteractiveSIDs = $null
		}

		If ($Shells.Count -eq 0) {
			# Either nobody is signed in, or the shell on this host is something else again. Those
			# two are indistinguishable from here and they call for opposite answers, so the
			# question goes back to the coarse profile load state, which errs toward refusing.
			$InteractiveSIDs = $null
		}

		$UnidentifiedSessionIds = @()
		ForEach ($Shell in $Shells) {
			$ShellOwner = $null
			Try {
				# GetOwnerSid reports access denied through ReturnValue rather than by throwing,
				# and hands back a null Sid, so the return code has to be checked explicitly.
				$OwnerResult = Invoke-CimMethod -InputObject $Shell -MethodName 'GetOwnerSid' -ErrorAction Stop
				If ($OwnerResult.ReturnValue -eq 0) { $ShellOwner = $OwnerResult.Sid }
			} Catch {
				# One session logging off mid loop must not discard the sessions already read.
				Write-Verbose "Could not read the owner of PID $($Shell.ProcessId) - $($_.Exception.Message)"
			}

			If ($ShellOwner) {
				If ($InteractiveSIDs -notcontains $ShellOwner) { $InteractiveSIDs += $ShellOwner }
				If ($InteractiveSessionIds -notcontains $Shell.SessionId) { $InteractiveSessionIds += $Shell.SessionId }
			} ElseIf ($UnidentifiedSessionIds -notcontains $Shell.SessionId) {
				$UnidentifiedSessionIds += $Shell.SessionId
			}
		}

		# People, not sessions. One person with a console session and a disconnected RDP session to
		# the same machine is one person, and counting the sessions would refuse the sweep on a
		# single user workstation. Sessions whose owner would not read are added on top, since one
		# of those could be anybody; a session that also produced a readable shell is not counted
		# twice.
		If ($null -ne $InteractiveSIDs) {
			$SessionCount = $InteractiveSIDs.Count +
				@($UnidentifiedSessionIds | Where-Object { $InteractiveSessionIds -notcontains $_ }).Count
		}

		ForEach ($UserProfile in $Selected) {
			$ProfilePath = $UserProfile.LocalPath.TrimEnd('\')
			If (-not (Test-Path -LiteralPath $ProfilePath)) {
				Write-Verbose "Skipping $ProfilePath - the profile folder no longer exists."
				# Under -AllUsers a registered profile with no folder is ordinary debris. Under
				# -UserName it is the answer to a question somebody asked, so it goes on the
				# unresolved list and gets reported instead of vanishing into -Verbose.
				If ($PSCmdlet.ParameterSetName -eq 'UserName') {
					[void]$Unresolved.Add("$(Split-Path -Path $ProfilePath -Leaf) (profile folder is gone)")
				}
				Continue
			}
			$Account = $AccountNameBySID[$UserProfile.SID]
			[void]$Targets.Add([PSCustomObject]@{
				UserName       = $(If ($Account) { $Account } Else { Split-Path -Path $ProfilePath -Leaf })
				SID            = $UserProfile.SID
				Loaded         = $(If ($null -ne $InteractiveSIDs) { $InteractiveSIDs -contains $UserProfile.SID } Else { [bool]$UserProfile.Loaded })
				ProfileRoot    = $ProfilePath
				LocalAppData   = Join-Path -Path $ProfilePath -ChildPath 'AppData\Local'
				RoamingAppData = Join-Path -Path $ProfilePath -ChildPath 'AppData\Roaming'
			})
		}
	}

	If ($Targets.Count -eq 0) {
		Write-Host "No matching user profiles to reset." -ForegroundColor Yellow
		# Nothing resolved at all, so there is no work to preserve and the error can be raised
		# here. The second message covers a name that matched a profile whose folder has since
		# been deleted, and keeps both distinguishable from -AllUsers on a machine that genuinely
		# has no profiles to reset.
		If ($PSCmdlet.ParameterSetName -eq 'UserName') {
			# $Unresolved carries the reason per name. It is empty only when every name was blank,
			# in which case the names as given are the most useful thing to echo back.
			$Detail = $(If ($Unresolved.Count -gt 0) { $Unresolved.ToArray() -join ', ' } Else { $UserName -join ', ' })
			Write-Error "Repair-AdobeCreativeCloud: no profile resolved for $Detail."
		}
		Return
	}

	# Resetting a signed in user is the ordinary workstation case and is fine. Several at once is
	# a terminal server, where an -AllUsers sweep would kill Creative Cloud in every live session
	# at whatever moment the sweep happened to run.
	# -WhatIf is exempt: a preview changes nothing, and a terminal server is precisely the machine
	# an operator would want to preview before committing to the sweep.
	$LoadedTargets = @($Targets | Where-Object { $_.Loaded })
	# When the sessions could not be counted, the coarse profile load state stands in. It over
	# reports, so it errs toward refusing the sweep, which costs a -Force rather than somebody's
	# Creative Cloud session.
	$SignedInCount = $(If ($null -ne $SessionCount) { $SessionCount } Else { $LoadedTargets.Count })
	If ($PSCmdlet.ParameterSetName -eq 'AllUsers' -and $SignedInCount -gt 1 -and -not $Force -and -not $WhatIfPreference) {
		$SessionNames = @($LoadedTargets | ForEach-Object { $_.UserName })
		$Unidentified = $SignedInCount - $SessionNames.Count
		If ($Unidentified -gt 0) { $SessionNames += "$Unidentified unidentified" }
		Write-Host "$SignedInCount users are signed in right now: $($SessionNames -join ', ')" -ForegroundColor Red
		Write-Host "-AllUsers would stop Creative Cloud in every one of those sessions. Use -UserName for the affected user, or -Force to sweep the machine anyway." -ForegroundColor Yellow
		Write-Error "Repair-AdobeCreativeCloud: $SignedInCount users signed in; -AllUsers needs -Force on a shared machine."
		Return
	}

	Write-Host "Resetting Adobe Creative Cloud for $($Targets.Count) profile(s):" -ForegroundColor Cyan
	$Targets | ForEach-Object {
		Write-Host "  $($_.UserName)$(If ($_.Loaded) { ' (signed in)' })"
	}

	# --- Work out what there is to reset, before anything is stopped ---
	# Stopping first and looking afterwards would mean that -UserName jdoe on a machine where
	# Creative Cloud was never installed still kills jdoe's session and any Libraries sync in
	# flight, only to report that there was nothing to reset. The redirect check runs here too,
	# and for the same reason: a profile that will be refused should not cost the user a session
	# on the way to being refused.
	$WorkItems = [System.Collections.ArrayList]::new()
	ForEach ($Target in $Targets) {
		ForEach ($Scope in @(
			[PSCustomObject]@{ Name = 'Local'; Root = $Target.LocalAppData },
			[PSCustomObject]@{ Name = 'Roaming'; Root = $Target.RoamingAppData }
		)) {
			$FolderPath = $(If ($Scope.Root) { Join-Path -Path $Scope.Root -ChildPath 'Adobe\OOBE' } Else { $null })
			$Exists = [bool]($FolderPath -and (Test-Path -LiteralPath $FolderPath))
			[void]$WorkItems.Add([PSCustomObject]@{
				Target   = $Target
				Scope    = $Scope.Name
				Path     = $FolderPath
				Exists   = $Exists
				Redirect = $(If ($Exists) { Find-ReparsePoint -Paths (Get-AncestorChain -Path $FolderPath -StopAt $Target.ProfileRoot) } Else { $null })
			})
		}
	}
	$PresentCount = @($WorkItems | Where-Object { $_.Exists -and ((-not $_.Redirect) -or $AllowJunctions) }).Count

	# --- Stop the processes holding the OOBE folder open ---
	If ($PresentCount -eq 0) {
		If (@($WorkItems | Where-Object { $_.Exists }).Count -gt 0) {
			Write-Host "`nEvery OOBE cache found is behind a junction or an unreadable folder, so nothing was stopped." -ForegroundColor Yellow
		} Else {
			Write-Host "`nNo OOBE caches to reset, so nothing was stopped." -ForegroundColor Yellow
		}
	} ElseIf ($SkipProcessStop) {
		Write-Host "`nSkipping process stop as requested." -ForegroundColor Yellow
	} Else {
		Write-Host "`nStopping Creative Cloud processes..." -ForegroundColor Cyan
		# Only the users who actually have something to reset. -UserName alice,bob where only
		# alice has a cache must not cost bob his session and whatever Libraries sync was in
		# flight, and neither must a target whose only folder is about to be refused.
		$TargetSIDs = @($WorkItems |
			Where-Object { $_.Exists -and ((-not $_.Redirect) -or $AllowJunctions) } |
			ForEach-Object { $_.Target.SID } |
			Where-Object { $_ } |
			Select-Object -Unique)
		$StoppedAny = $false

		# Two passes, because these processes supervise each other: Adobe Desktop Service and
		# AdobeIPCBroker relaunch the Creative Cloud desktop app, so a single snapshot can stop a
		# process and leave the thing that starts it again running one entry later in the list.
		# The second pass catches whatever came back, and stops early when nothing did.
		For ($Pass = 1; $Pass -le 2; $Pass++) {
			$Running = @(Get-Process -Name $AdobeProcessNames -ErrorAction SilentlyContinue)

			If ($Running.Count -eq 0) {
				If ($Pass -eq 1) { Write-Host "  None running." -ForegroundColor Green }
				Break
			}
			If ($Pass -eq 2) { Write-Verbose "Second pass: $($Running.Count) Adobe process(es) came back or were missed." }

			$OwnerSIDByPid = @{}

			If (-not $StopAllSessions) {
				# One filtered query rather than a query per PID or a full process listing. Owner
				# lookup scopes the kill to the accounts being reset, so a reset on a terminal
				# server does not take Creative Cloud down for every other signed in user. The
				# filter is built from Get-Process IDs, which are integers, so there is nothing
				# to escape.
				$ProcessFilter = ($Running | ForEach-Object { "ProcessId = $($_.Id)" }) -join ' OR '
				Try {
					$CimProcesses = @(Get-CimInstance -ClassName Win32_Process -Filter $ProcessFilter -ErrorAction Stop)
				} Catch {
					Write-Host "  Could not read process ownership: $($_.Exception.Message)" -ForegroundColor Yellow
					$CimProcesses = @()
				}
				ForEach ($CimProcess in $CimProcesses) {
					Try {
						# As above, a non-zero ReturnValue means the owner could not be read. The
						# process is then left alone rather than stopped on a guess.
						$OwnerResult = Invoke-CimMethod -InputObject $CimProcess -MethodName 'GetOwnerSid' -ErrorAction Stop
						If ($OwnerResult.ReturnValue -eq 0) {
							$OwnerSIDByPid[[int]$CimProcess.ProcessId] = $OwnerResult.Sid
						}
					} Catch {
						Write-Verbose "Could not read owner of PID $($CimProcess.ProcessId) - $($_.Exception.Message)"
					}
				}
			}

			$StoppedIds = [System.Collections.ArrayList]::new()
			ForEach ($Process in $Running) {
				$OwnerSID = $null
				If ($OwnerSIDByPid.ContainsKey($Process.Id)) { $OwnerSID = $OwnerSIDByPid[$Process.Id] }

				If (-not $StopAllSessions) {
					If (-not $OwnerSID) {
						If ($Pass -eq 1) {
							Write-Host "  Leaving $($Process.ProcessName) (PID $($Process.Id)) - owner unknown. Use -StopAllSessions if the rename fails." -ForegroundColor Yellow
						}
						Continue
					}
					If ($TargetSIDs -notcontains $OwnerSID) {
						Write-Verbose "Leaving $($Process.ProcessName) (PID $($Process.Id)) - owned by another user."
						Continue
					}
				}

				# -WhatIf is honored explicitly rather than through ShouldProcess. ShouldProcess
				# shares one Yes-to-All / No-to-All answer across every call in the function, so
				# a "No to All" at a process prompt would silently cancel all the renames that
				# follow, and the run would report that it changed nothing without saying why.
				# Stopping these processes is a prerequisite of the operation the operator asked
				# for. The renames are the part worth confirming, and they are the only part that
				# prompts, when -Confirm is passed: ConfirmImpact is Medium against a default
				# $ConfirmPreference of High, so nothing prompts on its own.
				If ($WhatIfPreference) {
					Write-Host "  What if: Stopping $($Process.ProcessName) (PID $($Process.Id))"
				} Else {
					Try {
						Stop-Process -Id $Process.Id -Force -Confirm:$false -ErrorAction Stop
						[void]$StoppedIds.Add($Process.Id)
						$StoppedAny = $true
						Write-Host "  Stopped $($Process.ProcessName) (PID $($Process.Id))" -ForegroundColor Green
					} Catch {
						# A process that exited on its own between the enumeration and here is not
						# a failure, and neither is one already gone by the time we reach it.
						If (Get-Process -Id $Process.Id -ErrorAction SilentlyContinue) {
							Write-Host "  Could not stop $($Process.ProcessName) (PID $($Process.Id)): $($_.Exception.Message)" -ForegroundColor Red
						}
					}
				}
			}

			If ($StoppedIds.Count -gt 0 -and $ProcessWaitSeconds -gt 0) {
				$Deadline = (Get-Date).AddSeconds($ProcessWaitSeconds)
				While ((Get-Date) -lt $Deadline) {
					If (@(Get-Process -Id $StoppedIds.ToArray() -ErrorAction SilentlyContinue).Count -eq 0) { Break }
					Start-Sleep -Milliseconds 500
				}
			}
			# Nothing was stopped this pass, so nothing can have respawned from it.
			If ($StoppedIds.Count -eq 0) { Break }
		}

		If (-not $StoppedAny) { Write-Verbose 'No Adobe processes were stopped.' }
	}

	# --- Rename the OOBE folders ---
	Write-Host "`nResetting OOBE caches..." -ForegroundColor Cyan
	$Results = [System.Collections.ArrayList]::new()
	$RenamedCount = 0
	$FailedCount = 0
	$SkippedCount = 0
	$RedirectCount = 0
	$UnreadableCount = 0

	ForEach ($Item in $WorkItems) {
		$Target = $Item.Target
		$FolderPath = $Item.Path
		$Action = 'NotPresent'
		$ErrorText = $null
		$WarningText = $null
		$BackupPath = $(If ($FolderPath) { "$FolderPath.old" } Else { $null })

		# Tested once, and both the redirect check and the rename hang off that one answer. Two
		# separate existence tests would let a folder that appeared in between them reach the
		# rename without ever being checked. Re-tested rather than trusting the pre-scan, because
		# stopping the Creative Cloud processes happened in between and can change the picture.
		$Exists = [bool]($FolderPath -and (Test-Path -LiteralPath $FolderPath))

		If ($Exists) {
			$Redirect = Find-ReparsePoint -Paths (Get-AncestorChain -Path $FolderPath -StopAt $Target.ProfileRoot)
			If ($Redirect -and $AllowJunctions) {
				# Relocating a folder onto another drive with a junction is a thing people do on
				# purpose, and in the current-profile case nobody is crossing a privilege boundary
				# anyway. Still said out loud, and recorded on the result, since it is the same
				# shape as the attack and a log that hid it would be worse than useless.
				$WarningText = "$($Redirect.Path) $($Redirect.Reason). Reset anyway because -AllowJunctions was given."
				Write-Host "  [$($Target.UserName)] $($Item.Scope): $WarningText" -ForegroundColor Yellow
			} ElseIf ($Redirect) {
				# A confirmed link and a folder that would not answer are both refusals, but they
				# send a tech to different places, so they are not reported as the same thing.
				$Action = $(If ($Redirect.Kind -eq 'Reparse') { 'Redirected' } Else { 'Unreadable' })
				$ErrorText = "$($Redirect.Path) $($Redirect.Reason). Refusing to rename through it, since it may lead somewhere other than this profile."
			}
		}

		If ($Exists -and ($Action -eq 'NotPresent')) {
			# Rename-Item will not overwrite an existing target, and deleting the old backup
			# to make room would destroy the only pre-reset copy: after the first reset the
			# live OOBE folder is one Creative Cloud rebuilt, so a second run would trade the
			# real original for a regenerated one. A repeat run gets a timestamped name
			# instead, and nothing on disk is thrown away.
			If (Test-Path -LiteralPath $BackupPath) {
				$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
				$BackupPath = "$FolderPath.old-$Stamp"
				$Suffix = 1
				While (Test-Path -LiteralPath $BackupPath) {
					$BackupPath = "$FolderPath.old-$Stamp-$Suffix"
					$Suffix++
				}
			}

			If ($PSCmdlet.ShouldProcess($FolderPath, "Rename to $(Split-Path -Path $BackupPath -Leaf)")) {
				# Handles on the OOBE folder are not always released the instant a process
				# exits, so a locked folder is retried before it is called a failure.
				For ($Attempt = 1; $Attempt -le 3; $Attempt++) {
					Try {
						Rename-Item -LiteralPath $FolderPath -NewName (Split-Path -Path $BackupPath -Leaf) -Force -Confirm:$false -ErrorAction Stop
						$Action = 'Renamed'
						$ErrorText = $null
						Break
					} Catch {
						$Action = 'Failed'
						$ErrorText = $_.Exception.Message
						If ($Attempt -lt 3) { Start-Sleep -Seconds 2 }
					}
				}
			} Else {
				$Action = 'Skipped'
			}
		}

		Switch ($Action) {
			'Renamed' {
				$RenamedCount++
				Write-Host "  [$($Target.UserName)] $($Item.Scope): reset $FolderPath -> $(Split-Path -Path $BackupPath -Leaf)" -ForegroundColor Green
			}
			'Failed' {
				$FailedCount++
				Write-Host "  [$($Target.UserName)] $($Item.Scope): FAILED on $FolderPath" -ForegroundColor Red
				Write-Host "      $ErrorText" -ForegroundColor Red
			}
			'Redirected' {
				$RedirectCount++
				Write-Host "  [$($Target.UserName)] $($Item.Scope): REFUSED on $FolderPath" -ForegroundColor Red
				Write-Host "      $ErrorText" -ForegroundColor Red
			}
			'Unreadable' {
				$UnreadableCount++
				Write-Host "  [$($Target.UserName)] $($Item.Scope): REFUSED on $FolderPath" -ForegroundColor Red
				Write-Host "      $ErrorText" -ForegroundColor Red
			}
			'Skipped' {
				$SkippedCount++
			}
			'NotPresent' {
				Write-Verbose "[$($Target.UserName)] $($Item.Scope): no OOBE folder present."
			}
		}

		[void]$Results.Add([PSCustomObject]@{
			UserName   = $Target.UserName
			SID        = $Target.SID
			Scope      = $Item.Scope
			Path       = $FolderPath
			Action     = $Action
			BackupPath = $(If ($Action -eq 'Renamed') { $BackupPath } Else { $null })
			Warning    = $WarningText
			Error      = $ErrorText
		})
	}

	# --- Report ---
	$ProblemCount = $FailedCount + $RedirectCount + $UnreadableCount
	Write-Host ""
	If ($SkippedCount -gt 0 -and $RenamedCount -eq 0 -and $ProblemCount -eq 0) {
		# A preview and a declined prompt both leave everything in place, but only one of them
		# means the operator said no. Reported differently, and the declined one sets $? false,
		# so a wrapper cannot read a refusal as a dry run.
		If ($WhatIfPreference) {
			Write-Host "$SkippedCount folder(s) would be reset. Nothing was changed." -ForegroundColor Yellow
		} Else {
			Write-Host "$SkippedCount folder(s) were declined at the prompt. Nothing was changed." -ForegroundColor Yellow
			Write-Error "Repair-AdobeCreativeCloud: all $SkippedCount folder(s) were declined."
		}
	} ElseIf ($RenamedCount -eq 0 -and $ProblemCount -eq 0) {
		Write-Host "No Adobe OOBE caches were found. Creative Cloud may not be installed for the profiles checked." -ForegroundColor Yellow
		If ($PSCmdlet.ParameterSetName -eq 'CurrentUser') {
			# Elevating with a separate admin account puts this session in that account's profile,
			# not the signed in user's, and the empty result above looks identical to a clean bill
			# of health for the machine.
			Write-Host "Only $($Identity.Name) was checked. If you elevated with a different account than the signed in user, use -AllUsers or -UserName <name>." -ForegroundColor Yellow
		}
	} Else {
		If ($RenamedCount -gt 0) {
			Write-Host "Adobe Creative Cloud cache reset complete. $RenamedCount folder(s) reset." -ForegroundColor Green
		} ElseIf ($WhatIfPreference) {
			# A refusal is found before any ShouldProcess call, so it shows up under -WhatIf too.
			# Calling that a failed reset would be wrong: a preview did not reset anything.
			Write-Host "Nothing was changed. $ProblemCount folder(s) would be refused; see above." -ForegroundColor Yellow
		} Else {
			Write-Host "Adobe Creative Cloud cache reset FAILED. No folders were reset." -ForegroundColor Red
		}
		If ($FailedCount -gt 0) {
			Write-Host "$FailedCount folder(s) could not be reset. The usual cause is a Creative Cloud process still holding the folder open." -ForegroundColor Red
			If ($SkipProcessStop) {
				Write-Host "This run used -SkipProcessStop, so nothing was stopped. Run it again without that switch." -ForegroundColor Yellow
			} ElseIf (-not $StopAllSessions) {
				Write-Host "Signing the user out and running it again is the safe fix." -ForegroundColor Yellow
				Write-Host "-StopAllSessions also clears it, but it drops the per-owner scoping and stops Creative Cloud for everyone signed in. Fine on a single user workstation; check who else is on before using it on a session host." -ForegroundColor Yellow
			} Else {
				Write-Host "Sign the user out, or reboot, and run it again." -ForegroundColor Yellow
			}
		}
		If ($RedirectCount -gt 0) {
			# Kept apart from the lock failures above: no amount of stopping processes or signing
			# users out will move a junction, and sending a tech round that loop wastes their time.
			Write-Host "$RedirectCount folder(s) were refused because a junction or symlink stands in the path. That is not a lock, and retrying will not clear it." -ForegroundColor Red
			Write-Host "Check who placed the link before going further. Inside a user-writable profile it is a way to get a privileged process to rename something else." -ForegroundColor Yellow
		}
		If ($UnreadableCount -gt 0) {
			Write-Host "$UnreadableCount folder(s) were refused because a folder in the path would not report its attributes, so a junction could not be ruled out." -ForegroundColor Red
			Write-Host "Usually a permissions problem on the profile. Check the ACLs on the path shown above; retrying will not clear it either." -ForegroundColor Yellow
		}
		If ($SkippedCount -gt 0) {
			# A declined -Confirm prompt, or a -WhatIf mixed with real work. Either way the folder
			# is still there, and a report that only counted the successes would read as complete.
			Write-Host "$SkippedCount folder(s) were left alone." -ForegroundColor Yellow
		}
		If ($RenamedCount -gt 0) {
			Write-Host "Have the user launch Creative Cloud and sign in again. The old caches are kept beside the originals, named on each line above." -ForegroundColor Cyan
		}
	}

	If ($PassThru) { Write-Output $Results.ToArray() }

	# Last, so they do not break up the report above. A run where every rename failed still emits
	# result objects, so the error stream is the only thing separating it from a clean run.
	If ($PSCmdlet.ParameterSetName -eq 'UserName' -and $Unresolved.Count -gt 0) {
		Write-Error "Repair-AdobeCreativeCloud: no profile resolved for $($Unresolved.ToArray() -join ', ')."
	}
	# Not under -WhatIf: a preview that changed nothing has not failed at anything, and an
	# -ErrorAction Stop caller would have its dry run aborted by a refusal it was asking about.
	If ($ProblemCount -gt 0 -and -not $WhatIfPreference) {
		Write-Error "Repair-AdobeCreativeCloud: $ProblemCount of $($RenamedCount + $ProblemCount) folder(s) could not be reset."
	}
}

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAc272e+DeBG4BM
# XiQhTirwEA85+OJaxXbmEm2auvfpl6CCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IAnqBhoLBilvbeek4Slk1eXKe91lrOOWWvSmrszNxwzuMA0GCSqGSIb3DQEBAQUA
# BIICAGBDw6a700xdA29xOn+BHw6gXUc0ygFYug57iSnrb6JC6ixm+mI0Fh8xTHLe
# /yvi6j39ifZs/3wIj0WCNHcVJZ8HZUQAZe1t8JS7KF/U59JbLR4VefKLl8thd89p
# fBbngbByLSQLU1fkpoKyFEooscL18rD3aRBKrDefVYydKbTu2NN9PXYt+a87HKVw
# ltKdtnxjTcXducgGRW+ITxIpKvc2G+f4yNhAUJYx2gycAoVjWh1PfSOj1IJ6LjLX
# NrNxPbjmATQPM08+r0iCwk8wB7HM+5Xg1mrUuMTFGknw0clPY6LkcEpJMMe3iGpk
# fCQp35b9dB8avhjB2m5ZF8FGT1jVsSVm+3x5duguIVnJekuJM8C2PxffBZ1Ttero
# ANE1xUiX4ys/EQla60Tie2n84/bVEkgRHhKOveYjukjKCc6pEvOnQetLgpBc57VL
# AdPto/X/2z2WYFNh/eG1OZRYGLlaUIW3xJKt4Dzmf0AhJhjVGGphqw2nc6DnGmAI
# GOLiRLv0B5dS3lzISCKkpoH7UOGjNAqCrGXAf1UffjOev4wvgFZugnvAYDVmVNRN
# put5EH3W/wYX55kzYDuO7XU1x9iTFoTHJ92K4OEejMUYaImcxbpIFGrdJ/6412Nm
# TyIeEZvcLKjgQtEWCk+SOeYcyzknrjTScliuqM/oFuxVgLqnoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDgxNTE2NDI0NVowLwYJKoZIhvcNAQkEMSIEICF46s4y
# RQdZPoBYcoz1NSFY3jNc2nCpnI7+GJZNsRzWMA0GCSqGSIb3DQEBAQUABIICALSl
# sPPGL71AWLxgB87mUlbZJp1DXz5yK6VcaRGAo23tFUnIrb1/fa7ME1cMFrv9UgO1
# y4xB6vPRCjDTVJY4O7p0oJ6Iod1U0qnl1+GbWL1hRupE4whi6VdM1zZy9t94lcsr
# RY2hsr4yjcYWlJfzO45ock13aRgmshnG3l75AcYgxWT5Li85EK6/CtDrUe/Z9fH3
# WolQkEkdG4g+pEBCUwuu5CE/3B20W1cIo0lDJMwOoL09DFybpE9GZcJsRb0RzOYr
# qAFKkz8UCWppJtNoUp7vRtdhzKPl37TCigy7toCu1vcHIR71D0NFM8r+sQdzYFrY
# yzXTzDxoCqBmqRY3uDaz3U2fzkYi8F18Y15uGGKQtT+gnmhgA3kVAUzxj4P0BHXn
# qqbg69iCE05q6Ztnt9qKrxLY5Tnh1HUDmnhOLcukeYqgFWPVf0LDe3DiCMSbdMPm
# 9fUoucypQ9LuQ2k6lel2DyWQLy4jZGfo47ybHoIb3bV2rw6TWvnAQjzwsvLSayHG
# jkVoa57G0xyWgqsUtMLqQNWlYEc8xrMwmwTLmTSBLa2v5xBDbC5pdbRYSsUYLZ0s
# 1FkRKDUe+RMYRtIaOx6b/c0v/rUesgCzfSSjLPX9++J/SiewEnLqgheFyG8pXD48
# j9D/6P20IqxJYfb3JwxHGgQrM1Sn4YM6bM3QzAfA
# SIG # End signature block
