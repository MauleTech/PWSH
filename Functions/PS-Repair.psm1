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

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAsS9Ks+/gRXD8V
# /RlRSccFvKRM5z2ETsrE7ppeGU97LaCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IIDx6UdYdDiExxKgMpxKY+2BD6gTBuTuP5sgzKJrY1+dMA0GCSqGSIb3DQEBAQUA
# BIICAFhrCPI8vifCEQ6aODpKmsQn19wLy01dGWaDj7Z5ZuOGbJxPhPQhHurvwo/G
# QKRTRSRgnIjx2p2n11D8wD0MNed3Tb+DduHWvzMs1VLw5roWyjUWyY/NhIMO18vN
# YHOzN+AmoJrXDf5lisWd8ToKa91OCubyad0o6c+zEbGvJ1cnWy3JY6bb70CF5adg
# JTtLtcydp5ImvjGiSxQ9LoYi99uDdyILRblYkqgO1NvxtRCG9KC92H5V734iqQat
# qnSe1ulMzf8ZQk/gsPSTtRQCkHI1XdvFiLdLaoUbUzMI6ODiX/DSOFEp9KbEXnRr
# d2/8zHEGKy0i5PCV4bYs14s+4aditacE9ZiPgcQg245iaZ3eJfauEkYKk8YuRXYu
# OIKLBrxbP+4h0aTuin39lYXPvdg4aUnqlYI52EIid2BlHNFyz/sZ1mrdmh0dOzwS
# vc2Sn6urytSaw2JCBpsiX6+DLS6yP2CeVFKZ0MFoQieJDhQoOvDlD5boY+41QPyX
# EK1mC3Dd2/jzf+2bvsKDWvsLZEPTLDv4HaTwavruB65p+oX0SMUQYit2+YkZGh94
# SD9TDUa7NvzPi42ivuqOOvtQ+I9hmb3WXh+c4u3unigvLx4P9cc9uYpETVVfw2nd
# 9C4b3cN43TN1el8QD3TKmk1WRu6nE3KFEZ56Nhwwp8yF1SGroYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDQyMTE3NTEzNVowLwYJKoZIhvcNAQkEMSIEIH3kolND
# mhVfREDF+uypTKL2Ex9nra1YO7wcNlLHCW8qMA0GCSqGSIb3DQEBAQUABIICACSM
# UbOw+HKhykYM18Bql7jugaeuOMWM3W06TlkByf2xlavLfrRtl7l+k0vPLT7ys8Um
# Buxo869kKME+/PCwtJ31wJmCjPYSjUy/II8+Ivr50mMMtzez4s8eSOjqWrtepZfJ
# AIi8KYklOD+JGSAoBnucVACi0C6CAA6VXLRMuXt3L+ygc99gzN/qi+1hwPzZbjAM
# bjo04cr62QTJIR8nL1mYrXhAPt7qBBt5cSjBZawQFErm43AP5FWtZm4K8DN/B1hS
# q0Jq3wUUTOfkGztlu8MQRUqQMkyJNYhmeWS06eO55XDx2qdzLkJK9cA3Jhr1pxaQ
# 5cQfkFxvqg85dmd7HWk4jeC3SzTt4q4jpaKn8FjNLQjyD7BeVbH63souMGRGUHre
# erc9BDtWIMeDSCqLzss8n5EnJXwIBue+0O++MmpNIl4VjdkclUpyhZXDd3Gv4Fms
# LQEQomjWJuv/YgkErP+VPSVfkqnOy+2aDOOuJ1nh61nRrgMgBxGeqQDHgezsBa2b
# xJoVGn4mMoEfEvL60irzwQLTScZh9CJ2ExmKNUkfQo35uzFRedT24ZHW3pkfJ8CV
# q55wSe6Gex4Xrr5cV4A81lWm0XPJcKDEw98aCRRwiIM92aR85q+7cYMVLsOD0RZ4
# x2S8O5+CK9wmeEOH5cvhTKSJQsjaclxQFls8nOf7
# SIG # End signature block
