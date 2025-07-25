param
	(
		[Parameter(Mandatory=$False)]
		$NoSofware,
		
		[Parameter(Mandatory=$False)]
		$NoDrivers
	)

Function RegMU {
	Write-Host "Checking Microsoft Update Service"
	If ((Get-WUServiceManager).Name -like "Microsoft Update") {
		Write-Host "Microsoft Update Service found, it's good to go."
	} else {
		Write-Host "Microsoft Update Service not found, registering it."
		Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false
	}
}

Write-Host "Checking Chocolatey Installation"
If (-NOT (Test-Path "C:\ProgramData\chocolatey\bin\choco.exe")) {
	Write-Host "Choco is not installed. Installing Choco."
	Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('http://download.ambitionsgroup.com/Scripts/installchoco.ps1'))
}

Write-Host "Choco is installed. Checking for powershell version."
If ($PSVersionTable.PSVersion.Major -lt "5") {
	Write-Host "Powershell needs an update, installing now"
	& "C:\ProgramData\chocolatey\bin\choco.exe" install dotnet4.5.2 -y
	& "C:\ProgramData\chocolatey\bin\choco.exe" install powershell -y
	Write-Host "Reboot computer and run script again"
} Else {
	If ((Get-Command Get-WUInstall -ErrorAction SilentlyContinue) -And ((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Major -lt "2")) {
		$Module = Get-Module -Name PSWindowsUpdate
		Write-Host "Removing an out of date PSWindowsUpdate"
		Uninstall-Module $Module.Name
		Remove-Module $Module.Name
		Remove-Item $Module.ModuleBase -Recurse -Force
	}

	If (-Not (((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Major -ge "2") -and ((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Minor -ge "1"))) {
		Write-Host "Attempting automatic installation of PSWUI 2.2.0.3"
		Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force -ErrorAction SilentlyContinue
		Install-Module -Name PSWindowsUpdate -MinimumVersion 2.2.1.4 -Force -ErrorAction SilentlyContinue
		RegMU
		If (-Not (((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Major -ge "2") -and ((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Minor -ge "1"))) {
			Write-Host "Auto install Failed, Attempting Manual installation of PSWUI 2.2.0.3"
			New-Item -ItemType Directory -Force -Path '$ITFolder' -ErrorAction Stop
			(New-Object System.Net.WebClient).DownloadFile('https://psg-prod-eastus.azureedge.net/packages/pswindowsupdate.2.2.0.3.nupkg', '$ITFolder\pswindowsupdate.2.2.0.3.zip')
			New-Item -ItemType Directory -Force -Path 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate\2.2.0.3' -ErrorAction Stop
			Expand-Archive -LiteralPath '$ITFolder\pswindowsupdate.2.2.0.3.zip' -DestinationPath 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PSWindowsUpdate\2.2.0.3' -ErrorAction Stop
			Import-Module PSWindowsUpdate -ErrorAction Stop
			RegMU
		}
	}

	If (((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Major -ge "2") -and ((Get-Command Get-WUInstall -ErrorAction SilentlyContinue).Version.Minor -ge "1")) {
		Write-Host "PSWindowsUpdate is installed! Attempting Updates"
		If ($NoDrivers -ne $True) {
			Write-Host "Checking for DRIVER Updates..."
			Get-WUInstall -MicrosoftUpdate -AcceptAll -Install -UpdateType Driver -IgnoreReboot -ErrorAction SilentlyContinue -Verbose
		}
		If ($NoSoftware -ne $True) {
			Write-Host "Checking for SOFTWARE Updates..."
			Get-WUInstall -MicrosoftUpdate -AcceptAll -Install -UpdateType Software -IgnoreReboot -ErrorAction SilentlyContinue -Verbose
		}
	} Else {
		Write-Host "PSWindowsUpdate is failing to install, please investigate"
	}
}
