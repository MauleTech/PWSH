Function Stop-StuckService {
<#
.SYNOPSIS
    Force-kills the process behind a stuck service (e.g. stuck in Starting or Stopping state).

.DESCRIPTION
    Retrieves detailed information about a service and its underlying process, then uses
    taskkill /F to forcefully terminate the process. Accepts service name, display name,
    or pipeline input from Get-Service.

.PARAMETER Name
    The service name or display name of the stuck service.

.PARAMETER WhatIf
    Shows detailed service and process information without killing the process.

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
                $Service = Get-Service | Where-Object { $_.DisplayName -eq $SvcIdentifier }
            }
            If (-not $Service) {
                Write-Warning "Service not found: $SvcIdentifier"
                Continue
            }

            # Get the WMI service object for the PID and path info
            $WmiService = Get-WmiObject Win32_Service -Filter "Name='$($Service.ServiceName)'"
            $ProcessId = $WmiService.ProcessId

            # Display detailed service information
            Write-Host "`n===== Service Details =====" -ForegroundColor Cyan
            Write-Host "Service Name  : $($Service.ServiceName)"
            Write-Host "Display Name  : $($Service.DisplayName)"
            Write-Host "Status        : $($Service.Status)"
            Write-Host "Start Type    : $($Service.StartType)"
            Write-Host "Service Type  : $($WmiService.ServiceType)"
            Write-Host "Path          : $($WmiService.PathName)"
            Write-Host "Process ID    : $ProcessId"

            If ($ProcessId -and $ProcessId -ne 0) {
                Try {
                    $Process = Get-Process -Id $ProcessId -ErrorAction Stop
                    Write-Host "`n----- Process Details -----" -ForegroundColor Yellow
                    Write-Host "Process Name  : $($Process.ProcessName)"
                    Write-Host "PID           : $($Process.Id)"
                    Write-Host "CPU (seconds) : $([math]::Round($Process.CPU, 2))"
                    Write-Host "Memory (MB)   : $([math]::Round($Process.WorkingSet64 / 1MB, 2))"
                    Write-Host "Threads       : $($Process.Threads.Count)"
                    Write-Host "Start Time    : $($Process.StartTime)"
                    Write-Host "Handle Count  : $($Process.HandleCount)"
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
                If ($PSCmdlet.ShouldProcess("$($Service.ServiceName) (PID: $ProcessId)", "taskkill /F")) {
                    Write-Host "`nForce-killing process $ProcessId for service '$($Service.ServiceName)'..." -ForegroundColor Red
                    $Result = taskkill /F /PID $ProcessId 2>&1
                    Write-Host $Result

                    Start-Sleep -Seconds 2
                    $CheckService = Get-Service -Name $Service.ServiceName -ErrorAction SilentlyContinue
                    Write-Host "Service status after kill: $($CheckService.Status)" -ForegroundColor Cyan
                }
            } Else {
                Write-Host "`nNo process to kill - service has no running process." -ForegroundColor Yellow
            }
        }
    }
}
