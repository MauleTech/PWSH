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
			$dcSession = New-PSSession -ComputerName $targetDC -Credential $cred -ErrorAction Stop
			Write-Pass "PSSession to $targetDC established."

			$acctStatus = Invoke-Command -Session $dcSession -ScriptBlock {
				Param($cn)
				Import-Module ActiveDirectory -ErrorAction Stop
				$acct = Get-ADComputer $cn -Properties Enabled, PasswordLastSet, LockedOut -ErrorAction Stop
				[pscustomobject]@{
					Enabled           = $acct.Enabled
					PasswordLastSet   = $acct.PasswordLastSet
					LockedOut         = $acct.LockedOut
					DistinguishedName = $acct.DistinguishedName
				}
			} -ArgumentList $localComputer

			Write-Verbose "AD account status: Enabled=$($acctStatus.Enabled) | PasswordLastSet=$($acctStatus.PasswordLastSet) | LockedOut=$($acctStatus.LockedOut)"

			# If account is disabled, enable it
			If (-not $acctStatus.Enabled) {
				Write-Fail "Computer account is DISABLED. Re-enabling..."
				Invoke-Command -Session $dcSession -ScriptBlock {
					Param($cn)
					Enable-ADAccount -Identity $cn
				} -ArgumentList $localComputer
				Write-Pass "Computer account re-enabled."
			}

			# If account is locked, unlock it
			If ($acctStatus.LockedOut) {
				Write-Fail "Computer account is LOCKED OUT. Unlocking..."
				Invoke-Command -Session $dcSession -ScriptBlock {
					Param($cn)
					Unlock-ADAccount -Identity $cn
				} -ArgumentList $localComputer
				Write-Pass "Computer account unlocked."
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
			$netdomResult = netdom resetpwd /server:$targetDC /userd:$($cred.UserName) /passwordd:$plain 2>&1
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

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDWX0jq1FQZjSxX
# NPVpSa5sKxXapA2lOcGlsN52FuQUwqCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IEhtX91rYW3TYRHFaMnOacdcXM4vncrEWpQNVwYW4KjNMA0GCSqGSIb3DQEBAQUA
# BIICAITGWAPtPpl7zxyA6z1NxmiwTn7iFBXcsQRxjeENI8hsTuT/z1Fa/l2Wfz+E
# UlZHGkyOR9EVpIg3fIo64MMZJM3KHbVtDufTDsDB2Pc0B9FEDamSKBtxx5y8GHCf
# M5wpsjhIy96XS4cN+0QhNVw9c2EaFp9x/Xh8ZHkPNyYcMAol6r0qoZpWVcGWSech
# SqwaccGSfgNJXPKRx/JRMQ7S4tc6hgxb1Vqg2NPMyVLEmaA+GdI9fAcbOTkan8sT
# prNq+daf9YxUS6scFMfpVuJUxm5V9z35LnZRDsY8kSKuw6sFL70GPCHm5yJTnAv7
# sgqEcHUdEoDPS0+xfPJ9pMnwRdC+PWKZzQX3r+HiWTp8TLWLHEFIIuz1NGulncOV
# 8s8wQE/sdy+mb09AdIW570i7FdafSWV+8jWn7IMxi+im89IQNwAYsg0C+N48wie0
# wZAqhGw178CoiAE/l23XL9IZhftYoXjSRp01mmDtIQMPeNzMqOam7jn0H1Wyik47
# sdLP/z5FffksGujm7Iakq7HGGl6qA3Idba4vYNVsHWdvcO3yph8pyoSR7yrkb5is
# 6HbTnU/OztPGUkFg13MMs8kxNcbyPlW9S2IP1CFCGHFXDt8QQtBYyiZ1SYA6gT4h
# RkBgTml4wUW6vnoC5UEvvc7VoxRo5NmrGlEq42AZA6lNx5seoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDQwMzE5MTUwOFowLwYJKoZIhvcNAQkEMSIEIBNotsi3
# 7175B1Ivd7KPjVvjLsDYa0rMkioB+iOOD3KDMA0GCSqGSIb3DQEBAQUABIICADuE
# vwg0S1TAvTetSTLExz+bqo1OWLqYA8T680SgAt3YVfUuJRjMqIQS8OyzoY+cOlhR
# nT4ypq8f506y2e9n9PkfMRAIU4bEUaGRWNIQY71jXsJpuhHry1CymzCm7XNC6bR9
# 5UtYdDuYsCy54/siEw49oiGL3ABXn9T6ryJAtc2nGuG1+iF3DMnQQRMV/Hz5zmV8
# aVSsjMgWtc7SlfaoYoZ8q2Z/2uQeBR6/KQRoLKKCdFMQKwtO8T/hXmzJ/YMcTTT8
# lAcyX+QZralfmsyN5OwTMyHsDOax+9C4rjiUfdYgsP/ppMnkeFQen1zL+y4ljal7
# k+lvFCo7KkHbDwyMx22ILvU/VDvPRJSZt5i/1DvxbYaC2EC2LXyTzXa5fMsTzEH3
# ibAA1l08UppSJkacoplZRVxo4n8Ku6xv0pXOE/WjCZkihpHdI40HNqVAYnoUP021
# I/+ixEBSDqYzb/97zFSACahYZilgecSHTMeAM+2egLB7sa+gUkGv42VxqXDLsnpp
# q4TRzz6ht6XPw3zp9wBSbep4euykw1vneI4V/3inMPvVSBlLrwKptd82mMATLlR+
# Tsl4blS3SXewsziKYAgobveWXt9Ux1LDfM2YJSl6bj+hvvx+jH3ADs/AMmrbMW6u
# WGoYKjP92XZj/DrB2Gkd7eOE0ZVTz4LrkS4PY/vn
# SIG # End signature block
