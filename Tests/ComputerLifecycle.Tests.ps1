<#
.SYNOPSIS
	Pester tests for the computer lifecycle functions in Functions\PS-Get.psm1.
.DESCRIPTION
	Run with: Invoke-Pester .\Tests\ComputerLifecycle.Tests.ps1

	Written to run on the Pester 3.4 that ships with Windows as well as on
	Pester 5, on Windows PowerShell 5.1 and PowerShell 7. The Should syntax
	differs between those Pester versions, so assertions throw instead, and all
	test data is passed in through -TestCases.
#>

Import-Module (Join-Path $PSScriptRoot '..\Functions\PS-Get.psm1') -Force -DisableNameChecking

$script:CheckNames = @('Age', 'Windows11', 'Memory', 'BootDrive', 'OSDrive', 'Health', 'RepeatTickets', 'Warranty')

function New-TestCheckSet {
	# All eight checks passing, except the ones named in -Status.
	param([hashtable]$Status = @{}, [string[]]$Omit = @())
	foreach ($name in $script:CheckNames) {
		if ($Omit -contains $name) { continue }
		$state = 'Pass'
		if ($Status.ContainsKey($name)) { $state = $Status[$name] }
		[pscustomobject]@{ Name = $name; Status = $state; Value = $null; Detail = "$name is $state" }
	}
}

function New-TestFacts {
	# Facts for a healthy two year old computer, except the ones named in -Override.
	param([hashtable]$Override = @{})
	$inv = [System.Globalization.CultureInfo]::InvariantCulture
	$facts = [ordered]@{
		ComputerName             = 'TESTPC'
		CollectedAt              = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss', $inv)
		Manufacturer             = 'Contoso'
		Model                    = 'TestBook 14'
		SerialNumber             = 'ABC1234'
		BaseBoardManufacturer    = 'Contoso'
		BaseBoardProduct         = '0X8DXD'
		BiosReleaseDate         = (Get-Date).AddYears(-2).ToString('yyyy-MM-dd', $inv)
		OSInstallDate            = (Get-Date).AddYears(-1).ToString('yyyy-MM-dd', $inv)
		EarliestOSInstallDate    = (Get-Date).AddYears(-2).ToString('yyyy-MM-dd', $inv)
		PurchaseDate             = (Get-Date).AddYears(-2).ToString('yyyy-MM-dd', $inv)
		ShipDate                 = $null
		WarrantyEndDate          = (Get-Date).AddYears(1).ToString('yyyy-MM-dd', $inv)
		RepeatTicketCount        = 0
		CpuName                  = 'Intel(R) Core(TM) i5-1235U'
		TpmPresent               = $true
		TpmSpecVersion           = '2.0, 0, 1.59'
		FirmwareType             = 'UEFI'
		SecureBootEnabled        = $true
		MemoryInstalledGB        = 16
		MemoryVisibleGB          = 15.7
		OSDrive                  = 'C:'
		OSDriveSizeGB            = 237.5
		OSDriveFreeGB            = 120.2
		BootDiskModel            = 'Contoso NVMe 256GB'
		BootDiskMediaType        = 'SSD'
		BootDiskBusType          = 'NVMe'
		PhysicalDiskName         = @('Contoso NVMe 256GB')
		PhysicalDiskBusType      = @('NVMe')
		PhysicalDiskHealthStatus = @('Healthy')
		SmartPredictFailure      = $false
		CollectionErrors         = @()
	}
	foreach ($key in $Override.Keys) { $facts[$key] = $Override[$key] }
	[pscustomobject]$facts
}

$script:AsOf = New-Object System.DateTime 2026, 1, 1
$script:Years = { param([double]$Count) (Get-Date).AddDays(-365.25 * $Count).ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture) }

Describe 'Get-ComputerLifecycleOutcome' {
	$allFail = @{}
	foreach ($name in $script:CheckNames) { $allFail[$name] = 'Fail' }
	$cases = @(
		@{ Case = 'every check passes'; Checks = @(New-TestCheckSet); Expected = 'Keep' },
		@{ Case = 'one hard check fails'; Checks = @(New-TestCheckSet -Status @{ Memory = 'Fail' }); Expected = 'Replace now' },
		@{ Case = 'a fail sits beside warn and unknown results'; Checks = @(New-TestCheckSet -Status @{ BootDrive = 'Fail'; Age = 'Warn'; Health = 'Unknown' }); Expected = 'Replace now' },
		@{ Case = 'every check fails'; Checks = @(New-TestCheckSet -Status $allFail); Expected = 'Replace now' },
		@{ Case = 'a hard check is unknown and nothing fails'; Checks = @(New-TestCheckSet -Status @{ Windows11 = 'Unknown' }); Expected = 'Needs review' },
		@{ Case = 'a hard check is unknown and another warns'; Checks = @(New-TestCheckSet -Status @{ Health = 'Unknown'; Age = 'Warn' }); Expected = 'Needs review' },
		@{ Case = 'age warns'; Checks = @(New-TestCheckSet -Status @{ Age = 'Warn' }); Expected = 'Plan to replace' },
		@{ Case = 'warranty warns'; Checks = @(New-TestCheckSet -Status @{ Warranty = 'Warn' }); Expected = 'Plan to replace' },
		@{ Case = 'age warns and the soft warranty check is unknown'; Checks = @(New-TestCheckSet -Status @{ Age = 'Warn'; Warranty = 'Unknown' }); Expected = 'Plan to replace' },
		@{ Case = 'only the soft warranty check is unknown'; Checks = @(New-TestCheckSet -Status @{ Warranty = 'Unknown' }); Expected = 'Needs review' },
		@{ Case = 'a required check is missing'; Checks = @(New-TestCheckSet -Omit 'OSDrive'); Expected = 'Needs review' },
		@{ Case = 'a status is not recognized'; Checks = @(New-TestCheckSet -Status @{ Memory = 'Maybe' }); Expected = 'Needs review' },
		@{ Case = 'a status is blank'; Checks = @(New-TestCheckSet -Status @{ Memory = '' }); Expected = 'Needs review' },
		@{ Case = 'a fail status is lower case'; Checks = @(New-TestCheckSet -Status @{ Memory = 'fail' }); Expected = 'Replace now' }
	)

	It 'returns "<Expected>" when <Case>' -TestCases $cases {
		param($Case, $Checks, $Expected)
		$outcome = Get-ComputerLifecycleOutcome -CheckResult $Checks
		if ($outcome.SuggestedOutcome -ne $Expected) { throw "Expected '$Expected' but got '$($outcome.SuggestedOutcome)'." }
		if (@($outcome.Reasons).Count -lt 1) { throw 'Expected at least one reason.' }
	}

	It 'returns "Needs review" when <Case>' -TestCases @(
		@{ Case = 'no results are supplied'; Checks = @() },
		@{ Case = 'the results are null'; Checks = $null }
	) {
		param($Case, $Checks)
		$outcome = Get-ComputerLifecycleOutcome -CheckResult $Checks
		if ($outcome.SuggestedOutcome -ne 'Needs review') { throw "Expected 'Needs review' but got '$($outcome.SuggestedOutcome)'." }
		if (@($outcome.UnassessedChecks).Count -ne 8) { throw "Expected 8 unassessed checks but got $(@($outcome.UnassessedChecks).Count)." }
	}

	It 'collects every failure instead of stopping at the first' -TestCases @(@{ Checks = @(New-TestCheckSet -Status $allFail) }) {
		param($Checks)
		$outcome = Get-ComputerLifecycleOutcome -CheckResult $Checks
		if (@($outcome.Reasons).Count -ne 8) { throw "Expected 8 reasons but got $(@($outcome.Reasons).Count)." }
	}

	It 'lists the unassessed checks and keeps warn reasons for Needs review' -TestCases @(@{ Checks = @(New-TestCheckSet -Status @{ Health = 'Unknown'; Warranty = 'Unknown'; Age = 'Warn' }) }) {
		param($Checks)
		$outcome = Get-ComputerLifecycleOutcome -CheckResult $Checks
		$unassessed = @($outcome.UnassessedChecks) -join ','
		if ($unassessed -ne 'Health,Warranty') { throw "Expected 'Health,Warranty' but got '$unassessed'." }
		$reasons = @($outcome.Reasons) -join ' | '
		if ($reasons -notmatch 'Not assessed - Health') { throw "Reasons do not name Health: $reasons" }
		if ($reasons -notmatch 'Age: Age is Warn') { throw "Reasons do not keep the Age warning: $reasons" }
	}

	It 'only lists the failures as reasons for Replace now' -TestCases @(@{ Checks = @(New-TestCheckSet -Status @{ Memory = 'Fail'; Age = 'Warn'; Health = 'Unknown' }) }) {
		param($Checks)
		$outcome = Get-ComputerLifecycleOutcome -CheckResult $Checks
		$reasons = @($outcome.Reasons) -join ' | '
		if ($reasons -ne 'Memory: Memory is Fail') { throw "Unexpected reasons: $reasons" }
	}

	It 'accepts check results from the pipeline' -TestCases @(@{ Checks = @(New-TestCheckSet -Status @{ Age = 'Warn' }) }) {
		param($Checks)
		$outcome = $Checks | Get-ComputerLifecycleOutcome
		if ($outcome.SuggestedOutcome -ne 'Plan to replace') { throw "Expected 'Plan to replace' but got '$($outcome.SuggestedOutcome)'." }
	}

	It 'honors a custom -RequiredCheck and -SoftCheck list' -TestCases @(@{ Checks = @(New-TestCheckSet -Status @{ Memory = 'Unknown' } -Omit 'Windows11', 'BootDrive', 'OSDrive', 'Health', 'RepeatTickets', 'Warranty') }) {
		param($Checks)
		$strict = Get-ComputerLifecycleOutcome -CheckResult $Checks -RequiredCheck Age, Memory
		if ($strict.SuggestedOutcome -ne 'Needs review') { throw "Expected 'Needs review' but got '$($strict.SuggestedOutcome)'." }
		$passing = @($Checks | Where-Object { $_.Name -eq 'Age' })
		$keep = Get-ComputerLifecycleOutcome -CheckResult $passing -RequiredCheck Age
		if ($keep.SuggestedOutcome -ne 'Keep') { throw "Expected 'Keep' but got '$($keep.SuggestedOutcome)'." }
		$warned = @([pscustomobject]@{ Name = 'Age'; Status = 'Warn'; Detail = 'old' }) + @($Checks | Where-Object { $_.Name -eq 'Memory' })
		$soft = Get-ComputerLifecycleOutcome -CheckResult $warned -RequiredCheck Age, Memory -SoftCheck Memory
		if ($soft.SuggestedOutcome -ne 'Plan to replace') { throw "Expected 'Plan to replace' but got '$($soft.SuggestedOutcome)'." }
	}
}

Describe 'Get-ComputerLifecycleAgeBasis' {
	It 'uses <Expected> when <Case>' -TestCases @(
		@{ Case = 'a purchase date is supplied'; Data = [pscustomobject]@{ PurchaseDate = '2022-05-01'; ShipDate = '2022-04-01'; BiosReleaseDate = '2021-01-01' }; Expected = 'PurchaseDate'; Date = '2022-05-01'; Estimate = $false },
		@{ Case = 'only a ship date is exact'; Data = [pscustomobject]@{ ShipDate = '2022-04-01'; BiosReleaseDate = '2021-01-01' }; Expected = 'ShipDate'; Date = '2022-04-01'; Estimate = $false },
		@{ Case = 'the BIOS date is the earliest estimate'; Data = [pscustomobject]@{ BiosReleaseDate = '2019-03-02'; EarliestOSInstallDate = '2020-06-01'; OSInstallDate = '2023-01-01' }; Expected = 'BiosReleaseDate'; Date = '2019-03-02'; Estimate = $true },
		@{ Case = 'an OS install predates an updated BIOS'; Data = [pscustomobject]@{ BiosReleaseDate = '2024-08-01'; EarliestOSInstallDate = '2020-06-01'; OSInstallDate = '2023-01-01' }; Expected = 'OSInstallDate'; Date = '2020-06-01'; Estimate = $true },
		@{ Case = 'the date is a DateTime value'; Data = [pscustomobject]@{ PurchaseDate = (New-Object System.DateTime 2021, 7, 4) }; Expected = 'PurchaseDate'; Date = '2021-07-04'; Estimate = $false },
		@{ Case = 'the purchase date is in the future'; Data = [pscustomobject]@{ PurchaseDate = '2031-01-01'; BiosReleaseDate = '2022-02-02' }; Expected = 'BiosReleaseDate'; Date = '2022-02-02'; Estimate = $true },
		@{ Case = 'the dates are not usable'; Data = [pscustomobject]@{ PurchaseDate = 'not a date'; BiosReleaseDate = '1980-01-01' }; Expected = 'Unknown'; Date = ''; Estimate = $false },
		@{ Case = 'no data is supplied'; Data = $null; Expected = 'Unknown'; Date = ''; Estimate = $false }
	) {
		param($Case, $Data, $Expected, $Date, $Estimate)
		$basis = Get-ComputerLifecycleAgeBasis -Data $Data -AsOf (New-Object System.DateTime 2026, 1, 1)
		if ($basis.Basis -ne $Expected) { throw "Expected basis '$Expected' but got '$($basis.Basis)'." }
		$actual = ''
		if ($null -ne $basis.Date) { $actual = $basis.Date.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture) }
		if ($actual -ne $Date) { throw "Expected date '$Date' but got '$actual'." }
		if ($basis.IsEstimate -ne $Estimate) { throw "Expected IsEstimate $Estimate but got $($basis.IsEstimate)." }
	}
}

Describe 'Get-ComputerLifecycleIdentity' {
	It 'looks up by <Source> when <Case>' -TestCases @(
		@{ Case = 'the motherboard is reported'; Data = [pscustomobject]@{ Manufacturer = 'Dell Inc.'; Model = 'Latitude 5420'; SerialNumber = '1234ABC'; BaseBoardManufacturer = 'Dell Inc.'; BaseBoardProduct = '0X8DXD' }; Source = 'Motherboard'; Lookup = 'Dell Inc. 0X8DXD'; Model = 'Dell Inc. Latitude 5420'; Serial = '1234ABC' },
		@{ Case = 'the motherboard is a placeholder'; Data = [pscustomobject]@{ Manufacturer = 'LENOVO'; Model = '20XW0026US'; SerialNumber = 'PF12345'; BaseBoardManufacturer = 'Default string'; BaseBoardProduct = 'Default string' }; Source = 'ComputerModel'; Lookup = 'LENOVO 20XW0026US'; Model = 'LENOVO 20XW0026US'; Serial = 'PF12345' },
		@{ Case = 'the motherboard is missing and the model names the maker'; Data = [pscustomobject]@{ Manufacturer = 'HP'; Model = 'HP EliteBook 840 G8'; SerialNumber = 'To be filled by O.E.M.' }; Source = 'ComputerModel'; Lookup = 'HP EliteBook 840 G8'; Model = 'HP EliteBook 840 G8'; Serial = '' },
		@{ Case = 'only a board maker is reported'; Data = [pscustomobject]@{ Manufacturer = 'System manufacturer'; Model = 'System Product Name'; SerialNumber = 'System Serial Number'; BaseBoardManufacturer = 'ASUSTeK COMPUTER INC.'; BaseBoardProduct = '' }; Source = 'Unknown'; Lookup = ''; Model = ''; Serial = '' },
		@{ Case = 'no data is supplied'; Data = $null; Source = 'Unknown'; Lookup = ''; Model = ''; Serial = '' }
	) {
		param($Case, $Data, $Source, $Lookup, $Model, $Serial)
		$identity = Get-ComputerLifecycleIdentity -Data $Data
		if ($identity.LookupSource -ne $Source) { throw "Expected source '$Source' but got '$($identity.LookupSource)'." }
		if ($identity.LookupModel -ne $Lookup) { throw "Expected lookup model '$Lookup' but got '$($identity.LookupModel)'." }
		if ($identity.ComputerModel -ne $Model) { throw "Expected computer model '$Model' but got '$($identity.ComputerModel)'." }
		if ($identity.SerialNumber -ne $Serial) { throw "Expected serial '$Serial' but got '$($identity.SerialNumber)'." }
	}
}

Describe 'Lifecycle check helpers' {
	It 'Age detail <Expected> when <Case>' -TestCases @(
		@{ Case = 'the age is an estimate'; Data = [pscustomobject]@{ BiosReleaseDate = '2021-06-01'; SerialNumber = 'ABC1234' }; Pattern = 'an estimate; look up serial number ABC1234 for the purchase date$'; Expected = 'gives the serial number' },
		@{ Case = 'the age is an estimate and the serial is a placeholder'; Data = [pscustomobject]@{ BiosReleaseDate = '2021-06-01'; SerialNumber = 'Default string' }; Pattern = 'an estimate$'; Expected = 'omits the serial number' },
		@{ Case = 'the purchase date is known'; Data = [pscustomobject]@{ PurchaseDate = '2021-06-01'; SerialNumber = 'ABC1234' }; Pattern = 'based on PurchaseDate 2021-06-01$'; Expected = 'omits the serial number' }
	) {
		param($Case, $Data, $Pattern, $Expected)
		$check = Get-ComputerLifecycleCheckAge -Data $Data -AsOf (New-Object System.DateTime 2026, 1, 1)
		if ($check.Detail -notmatch $Pattern) { throw "Unexpected detail: $($check.Detail)" }
	}

	It 'Windows11 detail leaves out the model to research when <Case>' -TestCases @(
		@{ Case = 'the check passes'; Data = (New-TestFacts) },
		@{ Case = 'the CPU fails'; Data = (New-TestFacts -Override @{ CpuName = 'Intel(R) Core(TM) i5-6500 CPU @ 3.20GHz'; SecureBootEnabled = $false }) },
		@{ Case = 'only the CPU is unrecognized'; Data = (New-TestFacts -Override @{ CpuName = 'Intel(R) Celeron(R) N4020 CPU @ 1.10GHz' }) }
	) {
		param($Case, $Data)
		$check = Get-ComputerLifecycleCheckWindows11 -Data $Data
		if ($check.Detail -match 'Research firmware settings') { throw "Did not expect a research hint: $($check.Detail)" }
	}

	It 'Age is <Expected> when <Case>' -TestCases @(
		@{ Case = 'bought 5.6 years ago'; Data = [pscustomobject]@{ PurchaseDate = '2020-06-01' }; Expected = 'Fail' },
		@{ Case = 'bought exactly 5 years ago'; Data = [pscustomobject]@{ PurchaseDate = '2021-01-01' }; Expected = 'Warn' },
		@{ Case = 'bought 4.6 years ago'; Data = [pscustomobject]@{ PurchaseDate = '2021-06-01' }; Expected = 'Warn' },
		@{ Case = 'bought exactly 4 years ago'; Data = [pscustomobject]@{ PurchaseDate = '2022-01-01' }; Expected = 'Warn' },
		@{ Case = 'bought 3 years ago'; Data = [pscustomobject]@{ PurchaseDate = '2023-01-01' }; Expected = 'Pass' },
		@{ Case = 'only an old BIOS date is known'; Data = [pscustomobject]@{ BiosReleaseDate = '2018-01-01' }; Expected = 'Fail' },
		@{ Case = 'no date is known'; Data = [pscustomobject]@{ PurchaseDate = $null }; Expected = 'Unknown' },
		@{ Case = 'no data is supplied'; Data = $null; Expected = 'Unknown' }
	) {
		param($Case, $Data, $Expected)
		$check = Get-ComputerLifecycleCheckAge -Data $Data -AsOf (New-Object System.DateTime 2026, 1, 1)
		if ($check.Name -ne 'Age') { throw "Unexpected name '$($check.Name)'." }
		if ($check.Status -ne $Expected) { throw "Expected '$Expected' but got '$($check.Status)' ($($check.Detail))." }
	}

	It 'Cpu is <Expected> for <Cpu>' -TestCases @(
		@{ Cpu = 'Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz'; Expected = 'Pass' },
		@{ Cpu = 'Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz'; Expected = 'Pass' },
		@{ Cpu = 'Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz'; Expected = 'Pass' },
		@{ Cpu = 'Intel(R) Core(TM) i7-1065G7 CPU @ 1.30GHz'; Expected = 'Pass' },
		@{ Cpu = '11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz'; Expected = 'Pass' },
		@{ Cpu = '12th Gen Intel(R) Core(TM) i5-1235U'; Expected = 'Pass' },
		@{ Cpu = '13th Gen Intel(R) Core(TM) i9-13900K'; Expected = 'Pass' },
		@{ Cpu = 'Intel(R) Core(TM) m3-8100Y CPU @ 1.10GHz'; Expected = 'Pass' },
		@{ Cpu = 'Intel(R) Core(TM) Ultra 7 155H'; Expected = 'Pass' },
		@{ Cpu = 'Intel(R) Core(TM) 5 120U'; Expected = 'Pass' },
		@{ Cpu = 'Intel(R) Core(TM) i3-N305'; Expected = 'Pass' },
		@{ Cpu = 'Intel(R) N100'; Expected = 'Pass' },
		@{ Cpu = 'Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz'; Expected = 'Fail' },
		@{ Cpu = 'Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz'; Expected = 'Fail' },
		@{ Cpu = 'Intel(R) Core(TM) i5-6500 CPU @ 3.20GHz'; Expected = 'Fail' },
		@{ Cpu = 'Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz'; Expected = 'Fail' },
		@{ Cpu = 'Intel(R) Core(TM) i5-2400 CPU @ 3.10GHz'; Expected = 'Fail' },
		@{ Cpu = 'Intel(R) Core(TM) i7 CPU 920 @ 2.67GHz'; Expected = 'Fail' },
		@{ Cpu = 'Intel(R) Core(TM) m3-7Y30 CPU @ 1.00GHz'; Expected = 'Fail' },
		@{ Cpu = 'Intel(R) Core(TM) i5-7Y54 CPU @ 1.20GHz'; Expected = 'Fail' },
		@{ Cpu = 'Intel(R) Core(TM)2 Duo CPU E8400 @ 3.00GHz'; Expected = 'Fail' },
		@{ Cpu = 'Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz'; Expected = 'Fail' },
		@{ Cpu = 'AMD Ryzen 5 2600 Six-Core Processor'; Expected = 'Pass' },
		@{ Cpu = 'AMD Ryzen 5 3500U with Radeon Vega Mobile Gfx'; Expected = 'Pass' },
		@{ Cpu = 'AMD Ryzen 7 PRO 5850U with Radeon Graphics'; Expected = 'Pass' },
		@{ Cpu = 'AMD Ryzen 7 5700X3D 8-Core Processor'; Expected = 'Pass' },
		@{ Cpu = 'AMD Ryzen Threadripper PRO 3955WX 16-Cores'; Expected = 'Pass' },
		@{ Cpu = 'AMD Ryzen 5 220 w/ Radeon 740M Graphics'; Expected = 'Pass' },
		@{ Cpu = 'AMD Ryzen AI 9 HX 370 w/ Radeon 890M'; Expected = 'Pass' },
		@{ Cpu = 'AMD Ryzen 7 1700 Eight-Core Processor'; Expected = 'Fail' },
		@{ Cpu = 'AMD Ryzen 3 PRO 1300 Quad-Core Processor'; Expected = 'Fail' },
		@{ Cpu = 'AMD Ryzen Threadripper 1950X 16-Core Processor'; Expected = 'Fail' },
		@{ Cpu = 'AMD FX(tm)-8350 Eight-Core Processor'; Expected = 'Fail' },
		@{ Cpu = 'AMD A10-9700 RADEON R7, 10 COMPUTE CORES 4C+6G'; Expected = 'Fail' },
		@{ Cpu = 'Snapdragon(R) X Elite - X1E80100 - Qualcomm(R) Oryon(TM) CPU'; Expected = 'Pass' },
		@{ Cpu = 'Intel(R) Celeron(R) N4020 CPU @ 1.10GHz'; Expected = 'Unknown' },
		@{ Cpu = 'Intel(R) Xeon(R) W-2245 CPU @ 3.90GHz'; Expected = 'Unknown' },
		@{ Cpu = 'AMD Athlon Silver 3050U with Radeon Graphics'; Expected = 'Unknown' },
		@{ Cpu = 'QEMU Virtual CPU version 2.5+'; Expected = 'Unknown' },
		@{ Cpu = ''; Expected = 'Unknown' }
	) {
		param($Cpu, $Expected)
		$check = Get-ComputerLifecycleCheckCpu -Data ([pscustomobject]@{ CpuName = $Cpu })
		if ($check.Status -ne $Expected) { throw "Expected '$Expected' but got '$($check.Status)' ($($check.Detail))." }
	}

	It 'Windows11 is <Expected> when <Case>' -TestCases @(
		@{ Case = 'CPU, TPM 2.0 and Secure Boot are all good'; Data = (New-TestFacts); Expected = 'Pass' },
		@{ Case = 'the CPU is too old'; Data = (New-TestFacts -Override @{ CpuName = 'Intel(R) Core(TM) i5-6500 CPU @ 3.20GHz' }); Expected = 'Fail' },
		@{ Case = 'the TPM is version 1.2'; Data = (New-TestFacts -Override @{ TpmSpecVersion = '1.2, 2, 3' }); Expected = 'Fail' },
		@{ Case = 'the CPU is too old and no TPM is detected'; Data = (New-TestFacts -Override @{ CpuName = 'Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz'; TpmPresent = $false; TpmSpecVersion = $null }); Expected = 'Fail' },
		@{ Case = 'no TPM is detected on a supported CPU'; Data = (New-TestFacts -Override @{ TpmPresent = $false; TpmSpecVersion = $null }); Expected = 'Unknown' },
		@{ Case = 'the TPM state was not collected'; Data = (New-TestFacts -Override @{ TpmPresent = $null; TpmSpecVersion = $null; CollectionErrors = @('Tpm: Access denied') }); Expected = 'Unknown' },
		@{ Case = 'a TPM is present without a version'; Data = (New-TestFacts -Override @{ TpmSpecVersion = '' }); Expected = 'Unknown' },
		@{ Case = 'Secure Boot is off'; Data = (New-TestFacts -Override @{ SecureBootEnabled = $false }); Expected = 'Unknown' },
		@{ Case = 'Secure Boot was not collected'; Data = (New-TestFacts -Override @{ SecureBootEnabled = $null }); Expected = 'Unknown' },
		@{ Case = 'the machine boots in legacy BIOS mode'; Data = (New-TestFacts -Override @{ FirmwareType = 'BIOS'; SecureBootEnabled = $false }); Expected = 'Unknown' },
		@{ Case = 'the firmware type was not collected'; Data = (New-TestFacts -Override @{ FirmwareType = $null; SecureBootEnabled = $null }); Expected = 'Unknown' },
		@{ Case = 'the CPU is not recognized'; Data = (New-TestFacts -Override @{ CpuName = 'Intel(R) Celeron(R) N4020 CPU @ 1.10GHz' }); Expected = 'Unknown' },
		@{ Case = 'no data is supplied'; Data = $null; Expected = 'Unknown' }
	) {
		param($Case, $Data, $Expected)
		$check = Get-ComputerLifecycleCheckWindows11 -Data $Data
		if ($check.Name -ne 'Windows11') { throw "Unexpected name '$($check.Name)'." }
		if ($check.Status -ne $Expected) { throw "Expected '$Expected' but got '$($check.Status)' ($($check.Detail))." }
	}

	It 'Memory is <Expected> when <Case>' -TestCases @(
		@{ Case = '8 GB is installed'; Data = [pscustomobject]@{ MemoryInstalledGB = 8 }; Expected = 'Fail' },
		@{ Case = '12 GB is installed'; Data = [pscustomobject]@{ MemoryInstalledGB = 12 }; Expected = 'Fail' },
		@{ Case = '16 GB is installed'; Data = [pscustomobject]@{ MemoryInstalledGB = 16; MemoryVisibleGB = 13.9 }; Expected = 'Pass' },
		@{ Case = '32 GB is installed'; Data = [pscustomobject]@{ MemoryInstalledGB = 32 }; Expected = 'Pass' },
		@{ Case = 'the value is a string'; Data = [pscustomobject]@{ MemoryInstalledGB = '16' }; Expected = 'Pass' },
		@{ Case = 'only 15.8 GB usable is known'; Data = [pscustomobject]@{ MemoryInstalledGB = $null; MemoryVisibleGB = 15.8 }; Expected = 'Pass' },
		@{ Case = 'only 7.9 GB usable is known'; Data = [pscustomobject]@{ MemoryInstalledGB = $null; MemoryVisibleGB = 7.9 }; Expected = 'Fail' },
		@{ Case = 'nothing was collected'; Data = [pscustomobject]@{ MemoryInstalledGB = $null }; Expected = 'Unknown' },
		@{ Case = 'no data is supplied'; Data = $null; Expected = 'Unknown' }
	) {
		param($Case, $Data, $Expected)
		$check = Get-ComputerLifecycleCheckMemory -Data $Data
		if ($check.Status -ne $Expected) { throw "Expected '$Expected' but got '$($check.Status)' ($($check.Detail))." }
	}

	It 'BootDrive is <Expected> when <Case>' -TestCases @(
		@{ Case = 'the boot disk is an HDD'; Data = [pscustomobject]@{ BootDiskMediaType = 'HDD'; BootDiskBusType = 'SATA' }; Expected = 'Fail' },
		@{ Case = 'the boot disk is a SATA SSD'; Data = [pscustomobject]@{ BootDiskMediaType = 'SSD'; BootDiskBusType = 'SATA' }; Expected = 'Pass' },
		@{ Case = 'the media type is unspecified on NVMe'; Data = [pscustomobject]@{ BootDiskMediaType = 'Unspecified'; BootDiskBusType = 'NVMe' }; Expected = 'Pass' },
		@{ Case = 'the media type is unspecified behind RAID'; Data = [pscustomobject]@{ BootDiskMediaType = 'Unspecified'; BootDiskBusType = 'RAID' }; Expected = 'Unknown' },
		@{ Case = 'nothing was collected'; Data = [pscustomobject]@{ BootDiskMediaType = $null; CollectionErrors = @('Disks: Access denied') }; Expected = 'Unknown' },
		@{ Case = 'no data is supplied'; Data = $null; Expected = 'Unknown' }
	) {
		param($Case, $Data, $Expected)
		$check = Get-ComputerLifecycleCheckBootDrive -Data $Data
		if ($check.Status -ne $Expected) { throw "Expected '$Expected' but got '$($check.Status)' ($($check.Detail))." }
	}

	It 'OSDrive is <Expected> when <Case>' -TestCases @(
		@{ Case = 'it is 237 GB with 42% free'; Data = [pscustomobject]@{ OSDriveSizeGB = 237; OSDriveFreeGB = 100 }; Expected = 'Pass' },
		@{ Case = 'it is exactly 200 GB with exactly 20% free'; Data = [pscustomobject]@{ OSDriveSizeGB = 200; OSDriveFreeGB = 40 }; Expected = 'Pass' },
		@{ Case = 'it is only 119 GB'; Data = [pscustomobject]@{ OSDriveSizeGB = 119; OSDriveFreeGB = 80 }; Expected = 'Fail' },
		@{ Case = 'it has only 11% free'; Data = [pscustomobject]@{ OSDriveSizeGB = 465; OSDriveFreeGB = 50 }; Expected = 'Fail' },
		@{ Case = 'it is small and nearly full'; Data = [pscustomobject]@{ OSDriveSizeGB = 119; OSDriveFreeGB = 5 }; Expected = 'Fail' },
		@{ Case = 'it is small and free space is unknown'; Data = [pscustomobject]@{ OSDriveSizeGB = 119; OSDriveFreeGB = $null }; Expected = 'Fail' },
		@{ Case = 'it is large and free space is unknown'; Data = [pscustomobject]@{ OSDriveSizeGB = 465; OSDriveFreeGB = $null }; Expected = 'Unknown' },
		@{ Case = 'nothing was collected'; Data = [pscustomobject]@{ OSDriveSizeGB = $null }; Expected = 'Unknown' },
		@{ Case = 'no data is supplied'; Data = $null; Expected = 'Unknown' }
	) {
		param($Case, $Data, $Expected)
		$check = Get-ComputerLifecycleCheckOSDrive -Data $Data
		if ($check.Status -ne $Expected) { throw "Expected '$Expected' but got '$($check.Status)' ($($check.Detail))." }
	}

	It 'Health is <Expected> when <Case>' -TestCases @(
		@{ Case = 'every disk is healthy'; Data = [pscustomobject]@{ PhysicalDiskName = @('A', 'B'); PhysicalDiskBusType = @('NVMe', 'SATA'); PhysicalDiskHealthStatus = @('Healthy', 'Healthy'); SmartPredictFailure = $false }; Expected = 'Pass' },
		@{ Case = 'a disk reports Warning'; Data = [pscustomobject]@{ PhysicalDiskName = @('A', 'B'); PhysicalDiskBusType = @('NVMe', 'SATA'); PhysicalDiskHealthStatus = @('Healthy', 'Warning') }; Expected = 'Fail' },
		@{ Case = 'a disk reports Unhealthy'; Data = [pscustomobject]@{ PhysicalDiskName = @('A'); PhysicalDiskBusType = @('SATA'); PhysicalDiskHealthStatus = @('Unhealthy') }; Expected = 'Fail' },
		@{ Case = 'SMART predicts a failure'; Data = [pscustomobject]@{ PhysicalDiskName = @('A'); PhysicalDiskBusType = @('SATA'); PhysicalDiskHealthStatus = @('Healthy'); SmartPredictFailure = $true }; Expected = 'Fail' },
		@{ Case = 'only a USB disk is unhealthy'; Data = [pscustomobject]@{ PhysicalDiskName = @('A', 'Stick'); PhysicalDiskBusType = @('NVMe', 'USB'); PhysicalDiskHealthStatus = @('Healthy', 'Unhealthy') }; Expected = 'Pass' },
		@{ Case = 'a single disk is healthy (scalar values)'; Data = [pscustomobject]@{ PhysicalDiskName = 'A'; PhysicalDiskBusType = 'NVMe'; PhysicalDiskHealthStatus = 'Healthy' }; Expected = 'Pass' },
		@{ Case = 'only SMART reported, with no failure'; Data = [pscustomobject]@{ PhysicalDiskHealthStatus = @(); SmartPredictFailure = $false }; Expected = 'Pass' },
		@{ Case = 'a disk does not report its health'; Data = [pscustomobject]@{ PhysicalDiskName = @('A'); PhysicalDiskBusType = @('RAID'); PhysicalDiskHealthStatus = @('Unknown') }; Expected = 'Unknown' },
		@{ Case = 'nothing was collected'; Data = [pscustomobject]@{ PhysicalDiskHealthStatus = @(); SmartPredictFailure = $null; CollectionErrors = @('Disks: Access denied') }; Expected = 'Unknown' },
		@{ Case = 'no data is supplied'; Data = $null; Expected = 'Unknown' }
	) {
		param($Case, $Data, $Expected)
		$check = Get-ComputerLifecycleCheckHealth -Data $Data
		if ($check.Status -ne $Expected) { throw "Expected '$Expected' but got '$($check.Status)' ($($check.Detail))." }
	}

	It 'RepeatTickets is <Expected> when <Case>' -TestCases @(
		@{ Case = 'no count is supplied'; Data = [pscustomobject]@{ RepeatTicketCount = $null }; Threshold = 3; Expected = 'Unknown' },
		@{ Case = 'the count is not a number'; Data = [pscustomobject]@{ RepeatTicketCount = 'several' }; Threshold = 3; Expected = 'Unknown' },
		@{ Case = 'there are no tickets'; Data = [pscustomobject]@{ RepeatTicketCount = 0 }; Threshold = 3; Expected = 'Pass' },
		@{ Case = 'there are 2 tickets'; Data = [pscustomobject]@{ RepeatTicketCount = 2 }; Threshold = 3; Expected = 'Pass' },
		@{ Case = 'there are 3 tickets'; Data = [pscustomobject]@{ RepeatTicketCount = 3 }; Threshold = 3; Expected = 'Fail' },
		@{ Case = 'there are 2 tickets and the threshold is 2'; Data = [pscustomobject]@{ RepeatTicketCount = 2 }; Threshold = 2; Expected = 'Fail' },
		@{ Case = 'no data is supplied'; Data = $null; Threshold = 3; Expected = 'Unknown' }
	) {
		param($Case, $Data, $Threshold, $Expected)
		$check = Get-ComputerLifecycleCheckRepeatTickets -Data $Data -Threshold $Threshold
		if ($check.Status -ne $Expected) { throw "Expected '$Expected' but got '$($check.Status)' ($($check.Detail))." }
	}

	It 'Warranty is <Expected> when <Case>' -TestCases @(
		@{ Case = 'the warranty has ended'; Data = [pscustomobject]@{ WarrantyEndDate = '2025-06-30' }; Expected = 'Warn' },
		@{ Case = 'the warranty is still running'; Data = [pscustomobject]@{ WarrantyEndDate = '2027-06-30' }; Expected = 'Pass' },
		@{ Case = 'the warranty ends today'; Data = [pscustomobject]@{ WarrantyEndDate = '2026-01-01' }; Expected = 'Pass' },
		@{ Case = 'the end date is a DateTime value'; Data = [pscustomobject]@{ WarrantyEndDate = (New-Object System.DateTime 2024, 2, 29) }; Expected = 'Warn' },
		@{ Case = 'the end date is unknown'; Data = [pscustomobject]@{ WarrantyEndDate = $null; WarrantyLookupNote = 'No lookup.' }; Expected = 'Unknown' },
		@{ Case = 'the end date is not a date'; Data = [pscustomobject]@{ WarrantyEndDate = 'soon' }; Expected = 'Unknown' },
		@{ Case = 'no data is supplied'; Data = $null; Expected = 'Unknown' }
	) {
		param($Case, $Data, $Expected)
		$check = Get-ComputerLifecycleCheckWarranty -Data $Data -AsOf (New-Object System.DateTime 2026, 1, 1)
		if ($check.Status -ne $Expected) { throw "Expected '$Expected' but got '$($check.Status)' ($($check.Detail))." }
	}

	It 'WarrantyInfo returns a note and no dates when <Case>' -TestCases @(
		@{ Case = 'the manufacturer has no lookup'; Manufacturer = 'LENOVO'; Serial = 'PF12345' },
		@{ Case = 'the Dell service tag is malformed'; Manufacturer = 'Dell Inc.'; Serial = 'AB&x=1' },
		@{ Case = 'nothing is supplied'; Manufacturer = ''; Serial = '' }
	) {
		param($Case, $Manufacturer, $Serial)
		$info = Get-ComputerLifecycleWarrantyInfo -Manufacturer $Manufacturer -SerialNumber $Serial
		if ($info.WarrantyEndDate) { throw "Did not expect a warranty end date: $($info.WarrantyEndDate)" }
		if (-not $info.Note) { throw 'Expected a note explaining why there is no warranty data.' }
	}
}

Describe 'Get-ComputerLifecycleAssessment' {
	It 'suggests "<Expected>" when <Case>' -TestCases @(
		@{ Case = 'a healthy two year old computer is in warranty'; Data = (New-TestFacts); Expected = 'Keep' },
		@{ Case = 'ticket history is missing'; Data = (New-TestFacts -Override @{ RepeatTicketCount = $null }); Expected = 'Needs review' },
		@{ Case = 'warranty is unknown on a young computer'; Data = (New-TestFacts -Override @{ WarrantyEndDate = $null }); Expected = 'Needs review' },
		@{ Case = 'it has 8 GB of RAM'; Data = (New-TestFacts -Override @{ MemoryInstalledGB = 8 }); Expected = 'Replace now' },
		@{ Case = 'it boots from a hard disk'; Data = (New-TestFacts -Override @{ BootDiskMediaType = 'HDD'; BootDiskBusType = 'SATA' }); Expected = 'Replace now' },
		@{ Case = 'it is six years old'; Data = (New-TestFacts -Override @{ PurchaseDate = (& $script:Years 6) }); Expected = 'Replace now' },
		@{ Case = 'it has four repeat tickets'; Data = (New-TestFacts -Override @{ RepeatTicketCount = 4 }); Expected = 'Replace now' },
		@{ Case = 'it is four and a half years old'; Data = (New-TestFacts -Override @{ PurchaseDate = (& $script:Years 4.5) }); Expected = 'Plan to replace' },
		@{ Case = 'it is out of warranty'; Data = (New-TestFacts -Override @{ WarrantyEndDate = (& $script:Years 0.5) }); Expected = 'Plan to replace' },
		@{ Case = 'it is four and a half years old with unknown warranty'; Data = (New-TestFacts -Override @{ PurchaseDate = (& $script:Years 4.5); WarrantyEndDate = $null }); Expected = 'Plan to replace' },
		@{ Case = 'Secure Boot is off'; Data = (New-TestFacts -Override @{ SecureBootEnabled = $false }); Expected = 'Needs review' },
		@{ Case = 'the facts arrive as a hashtable'; Data = @{ CpuName = 'Intel(R) Core(TM) i5-6500 CPU @ 3.20GHz'; ComputerName = 'HASHPC' }; Expected = 'Replace now' },
		@{ Case = 'the input is not lifecycle data'; Data = [pscustomobject]@{ Foo = 'Bar' }; Expected = 'Needs review' },
		@{ Case = 'the input is a number'; Data = 42; Expected = 'Needs review' }
	) {
		param($Case, $Data, $Expected)
		$row = @(Get-ComputerLifecycleAssessment -InputObject $Data -SkipWarrantyLookup)
		if ($row.Count -ne 1) { throw "Expected 1 row but got $($row.Count)." }
		if ($row[0].SuggestedOutcome -ne $Expected) { throw "Expected '$Expected' but got '$($row[0].SuggestedOutcome)' ($($row[0].Reasons))." }
		if (-not $row[0].Reasons) { throw 'Expected the Reasons column to be filled in.' }
	}

	It 'returns the documented columns' -TestCases @(@{ Data = (New-TestFacts) }) {
		param($Data)
		$row = $Data | Get-ComputerLifecycleAssessment -SkipWarrantyLookup
		$columns = @($row.PSObject.Properties | ForEach-Object { $_.Name })
		$expected = @('ComputerName', 'Manufacturer', 'Model', 'Motherboard', 'SerialNumber', 'SuggestedOutcome', 'Reasons', 'AgeBasis')
		foreach ($name in @('Age', 'Windows11', 'Memory', 'BootDrive', 'OSDrive', 'Health', 'RepeatTickets', 'Warranty')) { $expected += "${name}Value"; $expected += "${name}Status" }
		$expected += 'CollectedAt'
		if (($columns -join ',') -ne ($expected -join ',')) { throw "Unexpected columns: $($columns -join ',')" }
		if ($row.ComputerName -ne 'TESTPC') { throw "Unexpected ComputerName '$($row.ComputerName)'." }
		if ($row.AgeBasis -ne 'PurchaseDate') { throw "Unexpected AgeBasis '$($row.AgeBasis)'." }
		if ($row.Motherboard -ne 'Contoso 0X8DXD') { throw "Unexpected Motherboard '$($row.Motherboard)'." }
		if ($row.SerialNumber -ne 'ABC1234') { throw "Unexpected SerialNumber '$($row.SerialNumber)'." }
		if ($row.MemoryValue -ne 16 -or $row.MemoryStatus -ne 'Pass') { throw "Unexpected memory columns: $($row.MemoryValue) $($row.MemoryStatus)" }
	}

	It 'marks an estimated age in AgeBasis' -TestCases @(@{ Data = (New-TestFacts -Override @{ PurchaseDate = $null }) }) {
		param($Data)
		$row = $Data | Get-ComputerLifecycleAssessment -SkipWarrantyLookup
		if ($row.AgeBasis -notmatch '\(estimate\)$') { throw "Unexpected AgeBasis '$($row.AgeBasis)'." }
	}

	It 'names <Expected> in Reasons when <Case>' -TestCases @(
		@{ Case = 'Secure Boot is off'; Data = (New-TestFacts -Override @{ SecureBootEnabled = $false }); Expected = 'motherboard Contoso 0X8DXD \(computer model Contoso TestBook 14\)' },
		@{ Case = 'no TPM is detected'; Data = (New-TestFacts -Override @{ TpmPresent = $false; TpmSpecVersion = $null }); Expected = 'motherboard Contoso 0X8DXD' },
		@{ Case = 'the machine boots in legacy BIOS mode'; Data = (New-TestFacts -Override @{ FirmwareType = 'BIOS'; SecureBootEnabled = $false }); Expected = 'motherboard Contoso 0X8DXD' },
		@{ Case = 'Secure Boot is off and the motherboard is a placeholder'; Data = (New-TestFacts -Override @{ SecureBootEnabled = $false; BaseBoardManufacturer = 'Default string'; BaseBoardProduct = 'To be filled by O.E.M.' }); Expected = 'computer model Contoso TestBook 14 \(motherboard model not reported\)' },
		@{ Case = 'Secure Boot is off and no model is reported'; Data = (New-TestFacts -Override @{ SecureBootEnabled = $false; BaseBoardProduct = $null; Model = 'System Product Name' }); Expected = 'Motherboard and computer model were not reported' }
	) {
		param($Case, $Data, $Expected)
		$row = $Data | Get-ComputerLifecycleAssessment -SkipWarrantyLookup
		if ($row.SuggestedOutcome -ne 'Needs review') { throw "Expected 'Needs review' but got '$($row.SuggestedOutcome)'." }
		if ($row.Reasons -notmatch $Expected) { throw "Reasons do not name the model to research: $($row.Reasons)" }
	}

	It 'gives the serial number in Reasons when an estimated age triggers the outcome' -TestCases @(@{ Data = (New-TestFacts -Override @{ PurchaseDate = $null; BiosReleaseDate = (& $script:Years 4.5); EarliestOSInstallDate = (& $script:Years 4.4) }) }) {
		param($Data)
		$row = $Data | Get-ComputerLifecycleAssessment -SkipWarrantyLookup
		if ($row.SuggestedOutcome -ne 'Plan to replace') { throw "Expected 'Plan to replace' but got '$($row.SuggestedOutcome)' ($($row.Reasons))." }
		if ($row.Reasons -notmatch 'look up serial number ABC1234') { throw "Reasons do not give the serial number: $($row.Reasons)" }
		if ($row.SerialNumber -ne 'ABC1234') { throw "Unexpected SerialNumber '$($row.SerialNumber)'." }
	}

	It 'lets parameters supply the facts that are not on the machine' -TestCases @(@{ Data = (New-TestFacts -Override @{ RepeatTicketCount = $null; WarrantyEndDate = $null; PurchaseDate = $null }) }) {
		param($Data)
		$row = $Data | Get-ComputerLifecycleAssessment -SkipWarrantyLookup -RepeatTicketCount 0 -WarrantyEndDate (Get-Date).AddYears(1) -PurchaseDate (Get-Date).AddYears(-1)
		if ($row.SuggestedOutcome -ne 'Keep') { throw "Expected 'Keep' but got '$($row.SuggestedOutcome)' ($($row.Reasons))." }
		if ($row.AgeBasis -ne 'PurchaseDate') { throw "Unexpected AgeBasis '$($row.AgeBasis)'." }
		$strict = $Data | Get-ComputerLifecycleAssessment -SkipWarrantyLookup -RepeatTicketCount 2 -RepeatTicketThreshold 2 -WarrantyEndDate (Get-Date).AddYears(1)
		if ($strict.SuggestedOutcome -ne 'Replace now') { throw "Expected 'Replace now' but got '$($strict.SuggestedOutcome)'." }
	}

	It 'accepts JSON text, whole or line by line' -TestCases @(@{ Data = @((New-TestFacts), (New-TestFacts -Override @{ ComputerName = 'TESTPC2'; MemoryInstalledGB = 8 })) }) {
		param($Data)
		$single = ($Data[0] | ConvertTo-Json -Compress) | Get-ComputerLifecycleAssessment -SkipWarrantyLookup
		if (@($single).Count -ne 1 -or $single.SuggestedOutcome -ne 'Keep') { throw "Single object JSON gave '$($single.SuggestedOutcome)' ($($single.Reasons))." }
		$rows = @((ConvertTo-Json -InputObject $Data) -split "`r?`n" | Get-ComputerLifecycleAssessment -SkipWarrantyLookup)
		if ($rows.Count -ne 2) { throw "Expected 2 rows but got $($rows.Count)." }
		if ($rows[0].SuggestedOutcome -ne 'Keep' -or $rows[1].SuggestedOutcome -ne 'Replace now') { throw "Unexpected outcomes: $($rows[0].SuggestedOutcome), $($rows[1].SuggestedOutcome)" }
		if ($rows[1].ComputerName -ne 'TESTPC2') { throw "Unexpected ComputerName '$($rows[1].ComputerName)'." }
	}

	It 'returns "Needs review" instead of throwing when <Case>' -TestCases @(
		@{ Case = 'the text is not JSON'; Data = 'this is not json {' },
		@{ Case = 'the input is null'; Data = $null },
		@{ Case = 'the input is an empty string'; Data = '' }
	) {
		param($Case, $Data)
		$row = @($Data | Get-ComputerLifecycleAssessment -SkipWarrantyLookup)
		if ($row.Count -ne 1) { throw "Expected 1 row but got $($row.Count)." }
		if ($row[0].SuggestedOutcome -ne 'Needs review') { throw "Expected 'Needs review' but got '$($row[0].SuggestedOutcome)'." }
		if ($row[0].Reasons -notmatch '^Data collection failed') { throw "Unexpected reasons: $($row[0].Reasons)" }
	}

	It 'returns "Needs review" for a computer that cannot be reached' {
		$row = @(Get-ComputerLifecycleAssessment -ComputerName 'no-such-host.invalid' -SkipWarrantyLookup -WarningAction SilentlyContinue)
		if ($row.Count -ne 1) { throw "Expected 1 row but got $($row.Count)." }
		if ($row[0].ComputerName -ne 'no-such-host.invalid') { throw "Unexpected ComputerName '$($row[0].ComputerName)'." }
		if ($row[0].SuggestedOutcome -ne 'Needs review') { throw "Expected 'Needs review' but got '$($row[0].SuggestedOutcome)'." }
	}
}

Describe 'Get-ComputerLifecycleData' {
	It 'collects facts from this computer without throwing' {
		$data = Get-ComputerLifecycleData
		if ($data.ComputerName -ne $env:COMPUTERNAME) { throw "Unexpected ComputerName '$($data.ComputerName)'." }
		foreach ($name in @('Manufacturer', 'SerialNumber', 'BaseBoardManufacturer', 'BaseBoardProduct', 'CpuName', 'TpmPresent', 'FirmwareType', 'SecureBootEnabled', 'MemoryInstalledGB', 'OSDriveSizeGB', 'BootDiskMediaType', 'PhysicalDiskHealthStatus', 'RepeatTicketCount', 'CollectionErrors')) {
			if (-not $data.PSObject.Properties[$name]) { throw "Missing property '$name'." }
		}
	}

	It 'round trips through JSON into an assessment of this computer' {
		$json = Get-ComputerLifecycleData | ConvertTo-Json -Compress
		$row = @($json | Get-ComputerLifecycleAssessment -SkipWarrantyLookup)
		if ($row.Count -ne 1) { throw "Expected 1 row but got $($row.Count)." }
		if (@('Replace now', 'Plan to replace', 'Keep', 'Needs review') -notcontains $row[0].SuggestedOutcome) { throw "Unexpected outcome '$($row[0].SuggestedOutcome)'." }
		if ($row[0].ComputerName -ne $env:COMPUTERNAME) { throw "Unexpected ComputerName '$($row[0].ComputerName)'." }
		$direct = Get-ComputerLifecycleAssessment -SkipWarrantyLookup
		if ($direct.SuggestedOutcome -ne $row[0].SuggestedOutcome) { throw "Local and JSON outcomes differ: '$($direct.SuggestedOutcome)' and '$($row[0].SuggestedOutcome)'." }
	}
}
