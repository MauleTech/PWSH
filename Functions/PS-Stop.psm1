Function Stop-StuckService {
<#
.SYNOPSIS
    Force-kills the process behind a stuck service (e.g. stuck in Starting or Stopping state).

.DESCRIPTION
    Retrieves detailed information about a service and its underlying process, then uses
    Stop-Process -Force to forcefully terminate the process. Accepts service name, display name,
    or pipeline input from Get-Service.

    WARNING: If the service runs in a shared svchost.exe process, all services sharing that
    process will be affected. The function detects this and lists co-hosted services before
    proceeding.

.PARAMETER Name
    The service name or display name of the stuck service.

.EXAMPLE
    Stop-StuckService -Name wuauserv

.EXAMPLE
    Stop-StuckService -Name "Windows Update"

.EXAMPLE
    Get-Service wuauserv | Stop-StuckService

.EXAMPLE
    Stop-StuckService -Name wuauserv -WhatIf
    Shows detailed information about the service without killing the process.
#>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
        [String[]]$Name
    )

    PROCESS {
        ForEach ($SvcIdentifier in $Name) {
            # Try to find the service by Name first, then by DisplayName
            $Service = Get-Service -Name $SvcIdentifier -ErrorAction SilentlyContinue
            If (-not $Service) {
                $Service = Get-Service -DisplayName $SvcIdentifier -ErrorAction SilentlyContinue
            }
            If (-not $Service) {
                Write-Warning "Service not found: $SvcIdentifier"
                Continue
            }

            # Get the CIM service object for the PID and path info
            $CimService = Get-CimInstance Win32_Service -Filter "Name='$($Service.ServiceName)'"
            $ProcessId = $CimService.ProcessId

            # Display detailed service information
            Write-Host "`n===== Service Details =====" -ForegroundColor Cyan
            Write-Host "Service Name  : $($Service.ServiceName)"
            Write-Host "Display Name  : $($Service.DisplayName)"
            Write-Host "Status        : $($Service.Status)"
            Write-Host "Start Type    : $($Service.StartType)"
            Write-Host "Service Type  : $($CimService.ServiceType)"
            Write-Host "Path          : $($CimService.PathName)"
            Write-Host "Process ID    : $ProcessId"

            If ($ProcessId -and $ProcessId -ne 0) {
                Try {
                    $Process = Get-Process -Id $ProcessId -ErrorAction Stop
                    Write-Host "`n----- Process Details -----" -ForegroundColor Yellow
                    Write-Host "Process Name  : $($Process.ProcessName)"
                    Write-Host "PID           : $($Process.Id)"

                    $CpuDisplay = If ($null -ne $Process.CPU) { "$([math]::Round($Process.CPU, 2))" } Else { "N/A" }
                    Write-Host "CPU (seconds) : $CpuDisplay"
                    Write-Host "Memory (MB)   : $([math]::Round($Process.WorkingSet64 / 1MB, 2))"
                    Write-Host "Threads       : $($Process.Threads.Count)"

                    Try {
                        Write-Host "Start Time    : $($Process.StartTime)"
                    } Catch {
                        Write-Host "Start Time    : N/A (access denied)"
                    }

                    Write-Host "Handle Count  : $($Process.HandleCount)"

                    # Warn about shared svchost.exe processes
                    If ($Process.ProcessName -eq 'svchost') {
                        $SharedServices = Get-CimInstance Win32_Service -Filter "ProcessId=$ProcessId" |
                            Where-Object { $_.Name -ne $Service.ServiceName }
                        If ($SharedServices) {
                            Write-Host "`n----- WARNING: Shared Process -----" -ForegroundColor Red
                            Write-Host "This service runs in a shared svchost.exe process." -ForegroundColor Red
                            Write-Host "Killing PID $ProcessId will also stop these services:" -ForegroundColor Red
                            $SharedServices | ForEach-Object {
                                Write-Host "  $($_.Name) ($($_.DisplayName)) - $($_.State)" -ForegroundColor Red
                            }
                        }
                    }
                } Catch {
                    Write-Host "`nCould not retrieve process details: $_" -ForegroundColor Red
                }
            } Else {
                Write-Host "`nNo running process found for this service." -ForegroundColor Yellow
            }

            # Show dependent services
            If ($Service.DependentServices) {
                Write-Host "`n----- Dependent Services -----" -ForegroundColor Yellow
                $Service.DependentServices | ForEach-Object {
                    Write-Host "  $($_.ServiceName) ($($_.DisplayName)) - $($_.Status)"
                }
            }

            # Show services this depends on
            If ($Service.ServicesDependedOn) {
                Write-Host "`n----- Dependencies -----" -ForegroundColor Yellow
                $Service.ServicesDependedOn | ForEach-Object {
                    Write-Host "  $($_.ServiceName) ($($_.DisplayName)) - $($_.Status)"
                }
            }

            # Kill the process unless -WhatIf
            If ($ProcessId -and $ProcessId -ne 0) {
                If ($PSCmdlet.ShouldProcess("$($Service.ServiceName) (PID: $ProcessId)", "Stop-Process -Force")) {
                    Write-Host "`nForce-killing process $ProcessId for service '$($Service.ServiceName)'..." -ForegroundColor Red
                    Try {
                        Stop-Process -Id $ProcessId -Force -ErrorAction Stop
                        Write-Host "Process $ProcessId terminated successfully." -ForegroundColor Green

                        Start-Sleep -Seconds 2
                        $CheckService = Get-Service -Name $Service.ServiceName -ErrorAction SilentlyContinue
                        Write-Host "Service status after kill: $($CheckService.Status)" -ForegroundColor Cyan
                    } Catch {
                        Write-Host "Failed to kill process $ProcessId`: $_" -ForegroundColor Red
                    }
                }
            } Else {
                Write-Host "`nNo process to kill - service has no running process." -ForegroundColor Yellow
            }
        }
    }
}
