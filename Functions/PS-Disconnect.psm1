Function Disconnect-AllUsers {
	<#
		.SYNOPSIS
			Logs off all users from a machine.
	#>
		(quser) -replace ">"," " -replace "\s+","," -replace "IDLE,TIME","IDLE TIME" -replace "LOGON,TIME","LOGON TIME" | ConvertFrom-Csv -Delimiter "," | foreach {
			logoff ($_.ID)
		}
	}

Function Disconnect-NetExtender {

    # Define the possible paths where NetExtender can exist.
    $possiblePaths = @(
        "${env:ProgramFiles(x86)}\SonicWALL\SSL-VPN\NetExtender\NEClI.exe"
        "${env:ProgramFiles(x86)}\SonicWall\SSL-VPN\NetExtender\nxcli.exe"
        "${env:ProgramFiles}\SonicWall\SSL-VPN\NetExtender\nxcli.exe"
    )
	
    $NEPath = $possiblePaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Last 1

    If (!(Test-Path -LiteralPath $NEPath)) {
        Write-Host "This command only works if you have Sonicwall NetExtender installed."
    }
    Write-host "Initiating VPN disconnection"
    & $NEPath disconnect
    & $NEPath disconnect
    Write-Host ""
    Get-NetExtenderStatus

<#
.SYNOPSIS
    Disconnects an existing SSLVPN connection to a site using Sonicwall NetExtender
.EXAMPLE
    Disconnect-NetExtender
    This example disconnects from the VPN session.
#>
}

Function Disconnect-O365Exchange {
	Disconnect-ExchangeOnline -Confirm:$false
}

Function Disconnect-SophosConnect {
	param
	(
		[Parameter(Mandatory = $false)]
		[string]$ConnectionName
	)

	# Define possible paths for sccli.exe
	$possiblePaths = @(
		"${env:ProgramFiles(x86)}\Sophos\Connect\sccli.exe"
		"${env:ProgramFiles}\Sophos\Connect\sccli.exe"
		"${env:ProgramFiles(x86)}\Sophos\Sophos SSL VPN Client\sccli.exe"
		"${env:ProgramFiles}\Sophos\Sophos SSL VPN Client\sccli.exe"
	)

	# Find the first valid path
	$SCPath = $possiblePaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

	If (!$SCPath) {
		Write-Host "This command only works if you have Sophos Connect installed." -ForegroundColor Red
		return
	}

	# If no connection name provided, list active connections
	If ([string]::IsNullOrWhiteSpace($ConnectionName)) {
		Write-Host "Listing available Sophos Connect VPN connections:" -ForegroundColor Cyan
		& "$SCPath" list -d
		Write-Host ""
		$ConnectionName = Read-Host "Enter the connection name to disconnect"
		If ([string]::IsNullOrWhiteSpace($ConnectionName)) {
			Write-Host "Connection name is required." -ForegroundColor Red
			return
		}
	}

	Write-Host "Initiating VPN disconnection from: $ConnectionName" -ForegroundColor Cyan

	# Disconnect from VPN
	Try {
		& "$SCPath" disable -n $ConnectionName
		Start-Sleep -Seconds 2
		Write-Host ""
		Get-SophosConnectStatus
	}
	Catch {
		Write-Host "Error disconnecting from VPN: $_" -ForegroundColor Red
	}

	<#
	.SYNOPSIS
		Disconnects an existing SSL VPN connection using Sophos Connect
	.PARAMETER ConnectionName
		The name of the Sophos Connect VPN connection to disconnect. If not provided, will list available connections.
	.EXAMPLE
		Disconnect-SophosConnect -ConnectionName "Company VPN"
		Disconnects from the VPN connection named "Company VPN".
	.EXAMPLE
		Disconnect-SophosConnect
		Lists available VPN connections and prompts for selection to disconnect.
	#>
}
