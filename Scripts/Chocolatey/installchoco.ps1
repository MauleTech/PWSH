Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

#Custom
#Dowload config file index
$SiteConfigs = @()

$DetectedIP = (Invoke-WebRequest -uri "https://icanhazip.com" -UseBasicParsing).Content
$searchterm = '*' + $DetectedIP + '*'
$DetectedSite = $SiteConfigs.Where({ $PSItem.ExtIPs -like $searchterm })
If ($DetectedSite.Choco) {
	$DetectedIni = $DetectedSite.iniLoc
	$DetectedCode = $DetectedSite.Code
	$DetectedTitle = $DetectedSite.Site
	[string]$packageRepo = $DetectedSite.Choco

	if ($null -eq $packageRepo -or '' -eq $packageRepo) {
		Write-Host "Install Chocolatey Server"
		#$ChocoName = "ACG-Choco"
		#$packageRepo = 'https://choco.ambitionsgroup.com/nuget/chocolatey-group/'
	} else {
		Write-Host "Install local Chocolatey Server"
		$ChocoName = $DetectedCode + "-Choco"
		#Remove Ambitions source if it is no longer needed.
		If (Get-Command choco -errorAction SilentlyContinue) {
			$Sources = (choco source) ; If ($Sources -Like "*ambitionsgroup.com*") { choco source remove -n=ACG-Choco }
		}
		$SourceAdd = "choco source add -n=" + $ChocoName + " -s=" + $packageRepo + " --priority=1"
	}
} else {
	Write-Host "You're not at a specialized site."
	Write-Host "Install Chocolatey Server"
	#Remove stale ambitions source if it is no longer needed.
	If (Get-Command choco -errorAction SilentlyContinue) {
		$Sources = (choco source)
		If ($Sources -match "ACG-Choco - http://choco.ambitionsgroup.com:8081") { choco source remove -n=ACG-Choco }
		If ($Sources -match "ACG-Choco - https://choco.ambitionsgroup.com/nuget/chocolatey-group/") { choco source remove -n=ACG-Choco }
		If ($Sources -match "ACG-Choco - https://choco.ambitionsgroup.com/repository/chocolatey-group/") { choco source remove -n=ACG-Choco }
	}
	#$ChocoName = "ACG-Choco"
	#$packageRepo = 'https://choco.ambitionsgroup.com/nuget/chocolatey-group/'
	$SourceAdd = @()
	#$SourceAdd += "choco source add -n=" + $ChocoName + " -s=" + $packageRepo + " --priority=2"
	$SourceAdd += "choco source add -n=openmw -s=`"https://repo.openmw.org/repository/Chocolatey/`" --priority=10"
	$SourceAdd += "choco source add -n=chocolatey -s=`"https://chocolatey.org/api/v2`" --priority=100"
}

If (Get-Command choco.exe -ErrorAction SilentlyContinue) {
	#Custom
	$SourceAdd | ForEach-Object {Invoke-Expression -Command $_}
	#Update Chocolatey if Needed
	If (Get-Command choco -errorAction SilentlyContinue) {
		choco upgrade chocolatey -y
	}
	#EndCustom
} else {

	try {
		Write-Host "Attempting to use winget to install chocolatey."
		winget install --id chocolatey.chocolatey --source winget -h --accept-package-agreements --accept-source-agreements
		Get-Command choco.exe -ErrorAction Stop
	}
	catch {
		Write-Host "Attempting to use nuget to install chocolatey."
		if (-not (Get-PSRepository -Name ACGProGet -ErrorAction SilentlyContinue)) {
			Register-PSRepository -Name ACGProGet -SourceLocation https://choco.ambitionsgroup.com/nuget/chocolatey-group/ -PublishLocation https://choco.ambitionsgroup.com/nuget/chocolatey-group/ -PackageManagementProvider nuget -InstallationPolicy Trusted
		}
		Save-Package chocolatey -Source ACGProGet -Path "$ITFolder\Chocolatey" -Force
		& (Get-ChildItem -Path "$ITFolder\Chocolatey" -Recurse -Force | Where-Object { $_.Name -match "chocolateyinstall.ps1" }).PSPath
		Get-PSRepository -Name ACGProGet | Unregister-PSRepository
		Remove-Item -path "$ITFolder\Chocolatey" -Recurse -Force
		Get-Command choco.exe -ErrorAction Stop
	}
	finally {
		Write-Host "Attempting to use chocolatey's script to install chocolatey."
		Set-ExecutionPolicy Bypass -Scope Process -Force
		[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
		Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
		iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
	}

	#Custom
	Invoke-Expression $SourceAdd
	Choco Source Remove -n:chocolatey
	#Update Chocolatey if Needed
	If (Get-Command choco -errorAction SilentlyContinue) {
		choco upgrade chocolatey -y
	}
	#EndCustom
}