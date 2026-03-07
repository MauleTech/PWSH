Function Invoke-Win10Decrap {
	Write-Host "Windows 10 Decrapifier"
	$progressPreference = 'silentlyContinue'
	Set-ExecutionPolicy Bypass -Scope Process -Force
	Enable-SSL
	Invoke-WebRequest https://raw.githubusercontent.com/MauleTech/PWSH/master/Scripts/Win-10-DeCrapifier/Windows10Decrapifier.txt -UseBasicParsing | Invoke-Expression
}

Function Invoke-IPv4NetworkScan {
	###############################################################################################################
	# Language     :  PowerShell 4.0
	# Filename     :  IPv4NetworkScan.ps1 
	# Autor        :  BornToBeRoot (https://github.com/BornToBeRoot)
	# Description  :  Powerful asynchronus IPv4 Network Scanner
	# Repository   :  https://github.com/BornToBeRoot/PowerShell_IPv4NetworkScanner
	###############################################################################################################

	<#
		.SYNOPSIS
		Powerful asynchronus IPv4 Network Scanner

		.DESCRIPTION
		This powerful asynchronus IPv4 Network Scanner allows you to scan every IPv4-Range you want (172.16.1.47 to 172.16.2.5 would work). But there is also the possibility to scan an entire subnet based on an IPv4-Address withing the subnet and a the subnetmask/CIDR.

		The default result will contain the the IPv4-Address, Status (Up or Down) and the Hostname. Other values can be displayed via parameter.

		.EXAMPLE
		.\IPv4NetworkScan.ps1 -StartIPv4Address 192.168.178.0 -EndIPv4Address 192.168.178.20

		IPv4Address   Status Hostname
		-----------   ------ --------
		192.168.178.1 Up     fritz.box

		.EXAMPLE
		.\IPv4NetworkScan.ps1 -IPv4Address 192.168.178.0 -Mask 255.255.255.0 -DisableDNSResolving

		IPv4Address    Status
		-----------    ------
		192.168.178.1  Up
		192.168.178.22 Up

		.EXAMPLE
		.\IPv4NetworkScan.ps1 -IPv4Address 192.168.178.0 -CIDR 25 -EnableMACResolving

		IPv4Address    Status Hostname           MAC               Vendor
		-----------    ------ --------           ---               ------
		192.168.178.1  Up     fritz.box          XX-XX-XX-XX-XX-XX AVM Audiovisuelles Marketing und Computersysteme GmbH
		192.168.178.22 Up     XXXXX-PC.fritz.box XX-XX-XX-XX-XX-XX ASRock Incorporation

		.LINK
		https://github.com/BornToBeRoot/PowerShell_IPv4NetworkScanner/blob/master/README.md
	#>

	[CmdletBinding(DefaultParameterSetName = 'CIDR')]
	Param(
		[Parameter(
			ParameterSetName = 'Range',
			Position = 0,
			Mandatory = $true,
			HelpMessage = 'Start IPv4-Address like 192.168.1.10')]
		[IPAddress]$StartIPv4Address,

		[Parameter(
			ParameterSetName = 'Range',
			Position = 1,
			Mandatory = $true,
			HelpMessage = 'End IPv4-Address like 192.168.1.100')]
		[IPAddress]$EndIPv4Address,
		
		[Parameter(
			ParameterSetName = 'CIDR',
			Position = 0,
			Mandatory = $true,
			HelpMessage = 'IPv4-Address which is in the subnet')]
		[Parameter(
			ParameterSetName = 'Mask',
			Position = 0,
			Mandatory = $true,
			HelpMessage = 'IPv4-Address which is in the subnet')]
		[IPAddress]$IPv4Address,

		[Parameter(
			ParameterSetName = 'CIDR',        
			Position = 1,
			Mandatory = $true,
			HelpMessage = 'CIDR like /24 without "/"')]
		[ValidateRange(0, 31)]
		[Int32]$CIDR,
	
		[Parameter(
			ParameterSetName = 'Mask',
			Position = 1,
			Mandatory = $true,
			Helpmessage = 'Subnetmask like 255.255.255.0')]
		[ValidateScript({
				if ($_ -match "^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(254|252|248|240|224|192|128|0)$") {
					return $true
				}
				else {
					throw "Enter a valid subnetmask (like 255.255.255.0)!"    
				}
			})]
		[String]$Mask,

		[Parameter(
			Position = 2,
			HelpMessage = 'Maxmium number of ICMP checks for each IPv4-Address (Default=2)')]
		[Int32]$Tries = 2,

		[Parameter(
			Position = 3,
			HelpMessage = 'Maximum number of threads at the same time (Default=256)')]
		[Int32]$Threads = 256,
		
		[Parameter(
			Position = 4,
			HelpMessage = 'Resolve DNS for each IP (Default=Enabled)')]
		[Switch]$DisableDNSResolving,

		[Parameter(
			Position = 5,
			HelpMessage = 'Resolve MAC-Address for each IP (Default=Disabled)')]
		[Switch]$EnableMACResolving,

		[Parameter(
			Position = 6,
			HelpMessage = 'Get extendend informations like BufferSize, ResponseTime and TTL (Default=Disabled)')]
		[Switch]$ExtendedInformations,

		[Parameter(
			Position = 7,
			HelpMessage = 'Include inactive devices in result')]
		[Switch]$IncludeInactive
	)

	Begin {
		Write-Verbose -Message "Script started at $(Get-Date)"
		
		$OUIListPath = "$ITFolder\oui.txt"

		function Convert-Subnetmask {
			[CmdLetBinding(DefaultParameterSetName = 'CIDR')]
			param( 
				[Parameter( 
					ParameterSetName = 'CIDR',       
					Position = 0,
					Mandatory = $true,
					HelpMessage = 'CIDR like /24 without "/"')]
				[ValidateRange(0, 32)]
				[Int32]$CIDR,

				[Parameter(
					ParameterSetName = 'Mask',
					Position = 0,
					Mandatory = $true,
					HelpMessage = 'Subnetmask like 255.255.255.0')]
				[ValidateScript({
						if ($_ -match "^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(255|254|252|248|240|224|192|128|0)$") {
							return $true
						}
						else {
							throw "Enter a valid subnetmask (like 255.255.255.0)!"    
						}
					})]
				[String]$Mask
			)

			Begin {

			}

			Process {
				switch ($PSCmdlet.ParameterSetName) {
					"CIDR" {                          
						# Make a string of bits (24 to 11111111111111111111111100000000)
						$CIDR_Bits = ('1' * $CIDR).PadRight(32, "0")
						
						# Split into groups of 8 bits, convert to Ints, join up into a string
						$Octets = $CIDR_Bits -split '(.{8})' -ne ''
						$Mask = ($Octets | ForEach-Object -Process { [Convert]::ToInt32($_, 2) }) -join '.'
					}

					"Mask" {
						# Convert the numbers into 8 bit blocks, join them all together, count the 1
						$Octets = $Mask.ToString().Split(".") | ForEach-Object -Process { [Convert]::ToString($_, 2) }
						$CIDR_Bits = ($Octets -join "").TrimEnd("0")

						# Count the "1" (111111111111111111111111 --> /24)                     
						$CIDR = $CIDR_Bits.Length             
					}               
				}

				[pscustomobject] @{
					Mask = $Mask
					CIDR = $CIDR
				}
			}

			End {
				
			}
		}

		# Helper function to convert an IPv4-Address to Int64 and vise versa
		function Convert-IPv4Address {
			[CmdletBinding(DefaultParameterSetName = 'IPv4Address')]
			param(
				[Parameter(
					ParameterSetName = 'IPv4Address',
					Position = 0,
					Mandatory = $true,
					HelpMessage = 'IPv4-Address as string like "192.168.1.1"')]
				[IPaddress]$IPv4Address,

				[Parameter(
					ParameterSetName = 'Int64',
					Position = 0,
					Mandatory = $true,
					HelpMessage = 'IPv4-Address as Int64 like 2886755428')]
				[long]$Int64
			) 

			Begin {

			}

			Process {
				switch ($PSCmdlet.ParameterSetName) {
					# Convert IPv4-Address as string into Int64
					"IPv4Address" {
						$Octets = $IPv4Address.ToString().Split(".") 
						$Int64 = [long]([long]$Octets[0] * 16777216 + [long]$Octets[1] * 65536 + [long]$Octets[2] * 256 + [long]$Octets[3]) 
					}
			
					# Convert IPv4-Address as Int64 into string 
					"Int64" {            
						$IPv4Address = (([System.Math]::Truncate($Int64 / 16777216)).ToString() + "." + ([System.Math]::Truncate(($Int64 % 16777216) / 65536)).ToString() + "." + ([System.Math]::Truncate(($Int64 % 65536) / 256)).ToString() + "." + ([System.Math]::Truncate($Int64 % 256)).ToString())
					}      
				}

				[pscustomobject] @{   
					IPv4Address = $IPv4Address
					Int64       = $Int64
				}
			}

			End {

			}
		}

		# Helper function to create a new Subnet
		function Get-IPv4Subnet {
			[CmdletBinding(DefaultParameterSetName = 'CIDR')]
			param(
				[Parameter(
					Position = 0,
					Mandatory = $true,
					HelpMessage = 'IPv4-Address which is in the subnet')]
				[IPAddress]$IPv4Address,

				[Parameter(
					ParameterSetName = 'CIDR',
					Position = 1,
					Mandatory = $true,
					HelpMessage = 'CIDR like /24 without "/"')]
				[ValidateRange(0, 31)]
				[Int32]$CIDR,

				[Parameter(
					ParameterSetName = 'Mask',
					Position = 1,
					Mandatory = $true,
					Helpmessage = 'Subnetmask like 255.255.255.0')]
				[ValidateScript({
						if ($_ -match "^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(254|252|248|240|224|192|128|0)$") {
							return $true
						}
						else {
							throw "Enter a valid subnetmask (like 255.255.255.0)!"    
						}
					})]
				[String]$Mask
			)

			Begin {
			
			}

			Process {
				# Convert Mask or CIDR - because we need both in the code below
				switch ($PSCmdlet.ParameterSetName) {
					"CIDR" {                          
						$Mask = (Convert-Subnetmask -CIDR $CIDR).Mask            
					}
					"Mask" {
						$CIDR = (Convert-Subnetmask -Mask $Mask).CIDR          
					}                  
				}
				
				# Get CIDR Address by parsing it into an IP-Address
				$CIDRAddress = [System.Net.IPAddress]::Parse([System.Convert]::ToUInt64(("1" * $CIDR).PadRight(32, "0"), 2))
			
				# Binary AND ... this is how subnets work.
				$NetworkID_bAND = $IPv4Address.Address -band $CIDRAddress.Address

				# Return an array of bytes. Then join them.
				$NetworkID = [System.Net.IPAddress]::Parse([System.BitConverter]::GetBytes([UInt32]$NetworkID_bAND) -join ("."))
				
				# Get HostBits based on SubnetBits (CIDR) // Hostbits (32 - /24 = 8 -> 00000000000000000000000011111111)
				$HostBits = ('1' * (32 - $CIDR)).PadLeft(32, "0")
				
				# Convert Bits to Int64
				$AvailableIPs = [Convert]::ToInt64($HostBits, 2)

				# Convert Network Address to Int64
				$NetworkID_Int64 = (Convert-IPv4Address -IPv4Address $NetworkID.ToString()).Int64

				# Convert add available IPs and parse into IPAddress
				$Broadcast = [System.Net.IPAddress]::Parse((Convert-IPv4Address -Int64 ($NetworkID_Int64 + $AvailableIPs)).IPv4Address)
				
				# Change useroutput ==> (/27 = 0..31 IPs -> AvailableIPs 32)
				$AvailableIPs += 1

				# Hosts = AvailableIPs - Network Address + Broadcast Address
				$Hosts = ($AvailableIPs - 2)
					
				# Build custom PSObject
				[pscustomobject] @{
					NetworkID = $NetworkID
					Broadcast = $Broadcast
					IPs       = $AvailableIPs
					Hosts     = $Hosts
				}
			}

			End {

			}
		}     
	}

	Process {
		# Calculate Subnet (Start and End IPv4-Address)
		if ($PSCmdlet.ParameterSetName -eq 'CIDR' -or $PSCmdlet.ParameterSetName -eq 'Mask') {
			# Convert Subnetmask
			if ($PSCmdlet.ParameterSetName -eq 'Mask') {
				$CIDR = (Convert-Subnetmask -Mask $Mask).CIDR     
			}

			# Create new subnet
			$Subnet = Get-IPv4Subnet -IPv4Address $IPv4Address -CIDR $CIDR

			# Assign Start and End IPv4-Address
			$StartIPv4Address = $Subnet.NetworkID
			$EndIPv4Address = $Subnet.Broadcast
		}

		# Convert Start and End IPv4-Address to Int64
		$StartIPv4Address_Int64 = (Convert-IPv4Address -IPv4Address $StartIPv4Address.ToString()).Int64
		$EndIPv4Address_Int64 = (Convert-IPv4Address -IPv4Address $EndIPv4Address.ToString()).Int64

		# Check if range is valid
		if ($StartIPv4Address_Int64 -gt $EndIPv4Address_Int64) {
			Write-Error -Message "Invalid IP-Range... Check your input!" -Category InvalidArgument -ErrorAction Stop
		}

		# Calculate IPs to scan (range)
		$IPsToScan = ($EndIPv4Address_Int64 - $StartIPv4Address_Int64)
		
		Write-Verbose -Message "Scanning range from $StartIPv4Address to $EndIPv4Address ($($IPsToScan + 1) IPs)"
		Write-Verbose -Message "Running with max $Threads threads"
		Write-Verbose -Message "ICMP checks per IP: $Tries"

		# Properties which are displayed in the output
		$PropertiesToDisplay = @()
		$PropertiesToDisplay += "IPv4Address", "Status"

		if ($DisableDNSResolving -eq $false) {
			$PropertiesToDisplay += "Hostname"
		}

		if ($EnableMACResolving) {
			$PropertiesToDisplay += "MAC"
		}

		# Check if it is possible to assign vendor to MAC --> import CSV-File 
		if ($EnableMACResolving) {
			$LatestOUIs = (Invoke-WebRequest -Uri "https://standards-oui.ieee.org/oui/oui.txt" -UseBasicParsing).Content
			$Output = ""

			foreach($Line in $LatestOUIs -split '[\r\n]')
			{
				if($Line -match "^[A-F0-9]{6}")
				{        
					# Line looks like: 2405F5     (base 16)		Integrated Device Technology (Malaysia) Sdn. Bhd.
					$Output += ($Line -replace '\s+', ' ').Replace(' (base 16) ', '|').Trim() + "`n"
				}
			}

			Out-File -InputObject $Output -FilePath "$ITFolder\oui.txt"
			if (Test-Path -Path $OUIListPath -PathType Leaf) {
				$OUIHashTable = @{ }

				Write-Verbose -Message "Read oui.txt and fill hash table..."

				foreach ($Line in Get-Content -Path $OUIListPath) {
					if (-not([String]::IsNullOrEmpty($Line))) {
						try {
							$HashTableData = $Line.Split('|')
							$OUIHashTable.Add($HashTableData[0], $HashTableData[1])
						}
						catch [System.ArgumentException] { } # Catch if mac is already added to hash table
					}
				}

				$AssignVendorToMAC = $true

				$PropertiesToDisplay += "Vendor"
			}
			else {
				$AssignVendorToMAC = $false

				Write-Warning -Message "No OUI-File to assign vendor with MAC-Address found! Execute the script ""Create-OUIListFromWeb.ps1"" to download the latest version. This warning does not affect the scanning procedure."
			}
		}  
		
		if ($ExtendedInformations) {
			$PropertiesToDisplay += "BufferSize", "ResponseTime", "TTL"
		}

		# Scriptblock --> will run in runspaces (threads)...
		[System.Management.Automation.ScriptBlock]$ScriptBlock = {
			Param(
				$IPv4Address,
				$Tries,
				$DisableDNSResolving,
				$EnableMACResolving,
				$ExtendedInformations,
				$IncludeInactive
			)
	
			# +++ Send ICMP requests +++
			$Status = [String]::Empty

			for ($i = 0; $i -lt $Tries; i++) {
				try {
					$PingObj = New-Object System.Net.NetworkInformation.Ping
					
					$Timeout = 1000
					$Buffer = New-Object Byte[] 32
					
					$PingResult = $PingObj.Send($IPv4Address, $Timeout, $Buffer)

					if ($PingResult.Status -eq "Success") {
						$Status = "Up"
						break # Exit loop, if host is reachable
					}
					else {
						$Status = "Down"
					}
				}
				catch {
					$Status = "Down"
					break # Exit loop, if there is an error
				}
			}
				
			# +++ Resolve DNS +++
			$Hostname = [String]::Empty     

			if ((-not($DisableDNSResolving)) -and ($Status -eq "Up" -or $IncludeInactive)) {   	
				try { 
					$Hostname = ([System.Net.Dns]::GetHostEntry($IPv4Address).HostName)
				} 
				catch { } # No DNS      
			}
		
			# +++ Get MAC-Address +++
			$MAC = [String]::Empty 

			if (($EnableMACResolving) -and (($Status -eq "Up") -or ($IncludeInactive))) {
				$Arp_Result = (arp -a).ToUpper().Trim()

				foreach ($Line in $Arp_Result) {                
					if ($Line.Split(" ")[0] -eq $IPv4Address) {                    
						$MAC = [Regex]::Matches($Line, "([0-9A-F][0-9A-F]-){5}([0-9A-F][0-9A-F])").Value
					}
				}
			}

			# +++ Get extended informations +++
			$BufferSize = [String]::Empty 
			$ResponseTime = [String]::Empty 
			$TTL = $null

			if ($ExtendedInformations -and ($Status -eq "Up")) {
				try {
					$BufferSize = $PingResult.Buffer.Length
					$ResponseTime = $PingResult.RoundtripTime
					$TTL = $PingResult.Options.Ttl
				}
				catch { } # Failed to get extended informations
			}	
		
			# +++ Result +++        
			if (($Status -eq "Up") -or ($IncludeInactive)) {
				[pscustomobject] @{
					IPv4Address  = $IPv4Address
					Status       = $Status
					Hostname     = $Hostname
					MAC          = $MAC   
					BufferSize   = $BufferSize
					ResponseTime = $ResponseTime
					TTL          = $TTL
				}
			}
			else {
				$null
			}
		} 

		Write-Verbose -Message "Setting up RunspacePool..."

		# Create RunspacePool and Jobs
		$RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Threads, $Host)
		$RunspacePool.Open()
		[System.Collections.ArrayList]$Jobs = @()

		Write-Verbose -Message "Setting up jobs..."

		# Set up jobs for each IP...
		for ($i = $StartIPv4Address_Int64; $i -le $EndIPv4Address_Int64; $i++) { 
			# Convert IP back from Int64
			$IPv4Address = (Convert-IPv4Address -Int64 $i).IPv4Address                

			# Create hashtable to pass parameters
			$ScriptParams = @{
				IPv4Address          = $IPv4Address
				Tries                = $Tries
				DisableDNSResolving  = $DisableDNSResolving
				EnableMACResolving   = $EnableMACResolving
				ExtendedInformations = $ExtendedInformations
				IncludeInactive      = $IncludeInactive
			}       

			# Catch when trying to divide through zero
			try {
				$Progress_Percent = (($i - $StartIPv4Address_Int64) / $IPsToScan) * 100 
			} 
			catch { 
				$Progress_Percent = 100 
			}

			Write-Progress -Activity "Setting up jobs..." -Id 1 -Status "Current IP-Address: $IPv4Address" -PercentComplete $Progress_Percent
							
			# Create new job
			$Job = [System.Management.Automation.PowerShell]::Create().AddScript($ScriptBlock).AddParameters($ScriptParams)
			$Job.RunspacePool = $RunspacePool
			
			$JobObj = [pscustomobject] @{
				RunNum = $i - $StartIPv4Address_Int64
				Pipe   = $Job
				Result = $Job.BeginInvoke()
			}

			# Add job to collection
			[void]$Jobs.Add($JobObj)
		}

		Write-Verbose -Message "Waiting for jobs to complete & starting to process results..."

		# Total jobs to calculate percent complete, because jobs are removed after they are processed
		$Jobs_Total = $Jobs.Count

		# Process results, while waiting for other jobs
		Do {
			# Get all jobs, which are completed
			$Jobs_ToProcess = $Jobs | Where-Object -FilterScript { $_.Result.IsCompleted }
	
			# If no jobs finished yet, wait 500 ms and try again
			if ($null -eq $Jobs_ToProcess) {
				Write-Verbose -Message "No jobs completed, wait 250ms..."

				Start-Sleep -Milliseconds 250
				continue
			}
			
			# Get jobs, which are not complete yet
			$Jobs_Remaining = ($Jobs | Where-Object -FilterScript { $_.Result.IsCompleted -eq $false }).Count

			# Catch when trying to divide through zero
			try {            
				$Progress_Percent = 100 - (($Jobs_Remaining / $Jobs_Total) * 100) 
			}
			catch {
				$Progress_Percent = 100
			}

			Write-Progress -Activity "Waiting for jobs to complete... ($($Threads - $($RunspacePool.GetAvailableRunspaces())) of $Threads threads running)" -Id 1 -PercentComplete $Progress_Percent -Status "$Jobs_Remaining remaining..."
		
			Write-Verbose -Message "Processing $(if($null -eq $Jobs_ToProcess.Count){"1"}else{$Jobs_ToProcess.Count}) job(s)..."

			# Processing completed jobs
			foreach ($Job in $Jobs_ToProcess) {       
				# Get the result...     
				$Job_Result = $Job.Pipe.EndInvoke($Job.Result)
				$Job.Pipe.Dispose()

				# Remove job from collection
				$Jobs.Remove($Job)
			
				# Check if result contains status
				if ($Job_Result.Status) {        
					if ($AssignVendorToMAC) {           
						$Vendor = [String]::Empty

						# Check if MAC is null or empty
						if (-not([String]::IsNullOrEmpty($Job_Result.MAC))) {
							# Split it, so we can search the vendor (XX-XX-XX-XX-XX-XX to XXXXXX)
							$MAC_VendorSearch = $Job_Result.MAC.Replace("-", "").Substring(0, 6)
									
							$Vendor = $OUIHashTable.Get_Item($MAC_VendorSearch)
						}

						[pscustomobject] @{
							IPv4Address  = $Job_Result.IPv4Address
							Status       = $Job_Result.Status
							Hostname     = $Job_Result.Hostname
							MAC          = $Job_Result.MAC
							Vendor       = $Vendor  
							BufferSize   = $Job_Result.BufferSize
							ResponseTime = $Job_Result.ResponseTime
							TTL          = $ResuJob_Resultlt.TTL
						} | Select-Object -Property $PropertiesToDisplay
					}
					else {
						$Job_Result | Select-Object -Property $PropertiesToDisplay
					}                            
				}
			} 

		} While ($Jobs.Count -gt 0)

		Write-Verbose -Message "Closing RunspacePool and free resources..."

		# Close the RunspacePool and free resources
		$RunspacePool.Close()
		$RunspacePool.Dispose()

		Write-Verbose -Message "Script finished at $(Get-Date)"
	}

	End {
	}
}

Function Invoke-NDDCScan {
	# Webhook URL loaded from local config file: $ITFolder\Config\webhooks.json
	# Example config: { "TeamsWebhookUri": "https://your-webhook-url-here" }
	Function Send-To-Teams{
		$date = Get-Date -Format g
		$webhookConfig = "$ITFolder\Config\webhooks.json"
		if (-not (Test-Path $webhookConfig)) {
			Write-Warning "Teams webhook config not found at $webhookConfig - notifications disabled."
			return
		}
		$config = Get-Content $webhookConfig -Raw | ConvertFrom-Json
		$uri = $config.TeamsWebhookUri
		if (-not $uri) {
			Write-Warning "TeamsWebhookUri not set in $webhookConfig - notifications disabled."
			return
		}

		$body = ConvertTo-Json -Depth 4 @{
			themeColor = $color
			title = $title
			text = "$env:computername at $env:userdomain says"
			sections = @(
				@{
					facts = @(
						@{
						name = 'Date'
						value = $date
						},
						@{
						name = 'Server'
						value = $server
						},
						@{
						name = 'Message'
						value = $message
						}
					)
				}
			)
		}
		Invoke-RestMethod -uri $uri -Method Post -body $body -ContentType 'application/json'
	}
	#Sets default title and color for notifications
	$title = $env:userdomain + ': Automated NDDC Upload Notification'
	$color = '808080'

Write-Host "Checking for NDDC Utility"
	[version]$ModVer = (Get-Module -ListAvailable -Name Posh-SSH).Version
	[version]$AvailableModVer = (Find-Module Posh-SSH -Repository PSGallery).Version
	If ($ModVer -ne $AvailableModVer) {
		Write-host "Posh-SSH has an update from $ModVer to $AvailableModVer.`nInstalling the update."
		Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
		Install-PackageProvider -Name NuGet -Force
		Remove-Module -Name Posh-SSH -Force -ErrorAction SilentlyContinue
		Uninstall-Module -Name Posh-SSH -AllVersions -Force -ErrorAction SilentlyContinue
		If (Get-Module -Name Posh-SSH -ListAvailable) {
			$ModPath = (Get-Module -Name Posh-SSH -ListAvailable).ModuleBase
			$ArgumentList = '/C "taskkill /IM powershell.exe /F & rd /s /q "' + $ModPath + '" & start powershell -NoExit -ExecutionPolicy Bypass -Command "irm raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt | iex ; Invoke-NDDCScan"'
			Remove-PathForcefully -Path $ModPath
			If (Get-Item -Path $ModPath -ErrorAction SilentlyContinue) {
				Start-Process "cmd.exe" -ArgumentList $ArgumentList
			}
		}
		Install-Module -Name Posh-SSH -AllowClobber -Force
	}	Else {
		Write-host "Posh-SSH is already up to date at version $AvailableModVer."
	}

Write-Host "Downloading the NDDC Utility"
	$NddcURL = "https://s3.amazonaws.com/networkdetective/download/NetworkDetectiveDataCollector.exe"
	$NddcFolder = $ITFolder + '\NddcAuto'
	$null = (New-Item -ItemType Directory -Force -Path $NddcFolder)
	$NddcDownloadPath = $NddcFolder + '\NetworkDetectiveDataCollector.zip'
	$Nddcexe = $NddcFolder + '\nddc.exe'
	Remove-Item $NddcDownloadPath -ea SilentlyContinue
	Invoke-ValidatedDownload -Uri $NddcURL -OutFile $NddcDownloadPath
	Expand-Archive -Path $NddcDownloadPath -DestinationPath $NddcFolder -Force

Write-Host "Optimizing Run Settings based on previous manual run."
	$PCInfo = Get-ComputerInfo
	$RunNdp = Get-Content "$ITFolder\nddc\run.ndp"

	$OutbaseLine = $($RunNdp | Select-String -Pattern '-outbase').LineNumber
	$nddcountbase = "nddc_" + $($PCInfo.CsDomain) + "_" + $($PCInfo.CsName) + "_" + $(Get-date -Format yyyy-MM-dd)
	$RunNdp[$OutbaseLine] = $nddcountbase

	$outdirLine = $($RunNdp | Select-String -Pattern '-outdir').LineNumber
	$outputfolder = $NddcFolder + '\' + $nddcountbase
	$null = (New-Item -ItemType Directory -Force -Path $outputfolder)
	$nddcoutdir = $outputfolder
	$RunNdp[$outdirLine] = $nddcoutdir

	If (Test-Path "$ITFolder\scripts\Server_Reboot_Cred.txt") {
		$CredUserLine = $($RunNdp | Select-String -Pattern '-credsuser').LineNumber
		$RunNdp[$CredUserLine] = gc $ITFolder\scripts\server_reboot_user.txt

		$credsepwd2Line = $($RunNdp | Select-String -Pattern '-credsepwd2').LineNumber
		$RunNdp[$($credsepwd2Line -1)] = '-credsepwd'
		$RunNdp[$credsepwd2Line] = (pwsh -command "Get-Content '$ITFolder\Scripts\Server_Reboot_Cred.txt' | ConvertTo-SecureString | ConvertFrom-SecureString -asplaintext")
	}

	$RunNdpFile = $NddcFolder + '\run.ndp'
	$RunNdp | Set-Content -Path $RunNdpFile -Force


Write-Host "Running NDDC"
	& $Nddcexe -file $RunNdpFile
	Clear-Content -Path $RunNdpFile -Force
	$ExportedFile = $($outputfolder + "\" + $nddcountbase + ".ndf")

# Check for credentials
	$SshKeyPath = $ITFolder + '\.ssh\nddc.id_rsa'
	If (-not (Test-Path $SshKeyPath)) {
		Write-Error "ERROR: .SSH Key not found at $ITFolder\.ssh\nddc.id_rsa. - - Check documentation for remedy."
		Write-Host "Send to Teams"
		$Message = "ERROR: .SSH Key not found at $ITFolder\.ssh\nddc.id_rsa. - - Check documentation for remedy."
		$server = "$env:computername"
		$color = 'ff0000'
		Send-To-Teams

	Write-Host "Logging the attempt"
		$date = Get-Date
		$date = $date.ToShortDateString()
		Add-Content "$ITFolder\NDDC Auto Scan Log.txt" "$date | .SSH Key not found at $ITFolder\.ssh\nddc.id_rsa. - - Check documentation for remedy."
	} Else {
	
	# Set local file path, SFTP path, and the backup location path which I assume is an SMB path
		$UploadID = $($PCInfo.CsDomain) + "_" + $($PCInfo.CsName)
		$SftpPath = "/home/dh_wu6qvp/<nddc.upload.server>/Uploads/" + $UploadID
		$SftpLink = "sftp://ftp.<nddc.upload.server>/Uploads/" + $UploadID

	# Set the IP of the SFTP server
		$SftpIp = 'ftp.<nddc.upload.server>'
		# Set the credentials
		$User = 'dh_wu6qvp'
		$Password = New-Object System.Security.SecureString
		$Credential = New-Object System.Management.Automation.PSCredential ('dh_wu6qvp', $Password)

	Write-Host "Establishing the SFTP connection"
		Get-SSHTrustedHost -HostName "ftp.<nddc.upload.server>" | Remove-SSHTrustedHost #Clears previously stored keys. They change over time with Dreamhost.
		$ThisSession = New-SFTPSession -KeyFile $SshKeyPath -ComputerName $SftpIp -Credential $Credential -AcceptKey

	Write-Host "Uploading the file to the SFTP path"
		New-SFTPItem -SessionId ($ThisSession).SessionId -Path $SftpPath -ItemType Directory -ErrorAction SilentlyContinue
		Set-SFTPItem -SessionId ($ThisSession).SessionId -Path $ExportedFile -Destination $SftpPath -Force

	Write-Host "Disconnecting all SFTP connections"
		Get-SFTPSession | Remove-SFTPSession -ErrorAction SilentlyContinue

	Write-Host "Send to Teams"
		$Message = "NDDC has scanned and uploaded to $SftpLink Check documentation for access credentials."
		If (Select-String -Path $ExportedFile -SimpleMatch "Invalid Active Directory username") {
			$Message = $Message + " The stored username and password appear to be incorrect. Please run NDDC manually at least once in $ITFolder\nddc and get to the point where the scan begins. You can cancel it after that."
			$Color = 'ff0000'
		}
		$server = "$env:computername"
		Send-To-Teams

	Write-Host "Logging the attempt"
		$date = Get-Date
		$date = $date.ToShortDateString()
		Add-Content "$ITFolder\NDDC Auto Scan Log.txt" "$date | NDDC has scanned and uploaded to $SftpLink Check documentation for access credentials."
		If (Select-String -Path $ExportedFile -SimpleMatch "Invalid Active Directory username") {
			Add-Content "$ITFolder\NDDC Auto Scan Log.txt" "$date | ERROR: The stored username and password appear to be incorrect. Please run NDDC manually at least once in $ITFolder\nddc and get to the point where the scan begins. You can cancel it after that."
		}

	Write-Host "Cleaning up"
		Remove-Item -Recurse -Force $outputfolder
	}
}

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAOSu5T8c/tsZpN
# lhU5psBqIWoHFvRCBDoNdrmX4NQugKCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IO2I2rwaxdzIFH2EuJZhDF00tRgDUDSwPwmSMhqKkl4LMA0GCSqGSIb3DQEBAQUA
# BIICAGP6g1W+hd9P35+089Gki1K1mC9YNHfRL4JdF/T7aXeJV33LTUDkibRT4Fcw
# tpGTDR0NDS1MEKXV14Vq19GaAm7AnTt5PLshQy5V2Vi7s9a4uRbKOO4UxTi9J9Dc
# kndKljYpMvBMpB7uXJ2sqVygRO7WVYYNrWBsdviicBcWDlkuwY7Rb55A40CUc6N/
# lRXU/KcBZVvlxVyaP6q4KwISNRZDL+nSPVzEwnxlcTd+jtkBWa8htmq8xR/KI5iM
# S8+stdXHvMCMurtLukalYc1IUdsyGEiUfTLstbyWIFlxdNQrc5LjEHr+8wCNuceo
# Hu4fzWQDXuQZoDxuJiCGOYx6yatbwTtrrDeICzhfY0QuvJQ3+NGnHNTyvk7bvSJW
# 6fDVqpn4kB5BZpYl6XaqkZZ7AIc/cUl76Z+FzdB6CJzWkwxI3vWipyqzCd1YW9Cs
# Zd7Ur3Vz2/05n7FCYH2AjPcqwn466kbbf83MayuSbiXKXueZ82q4QON0714dDvN7
# LAf8rgpOVIF/cLIMjapFYTk2ngGUp4R7Bx26hGprlpggJ3+2v++tBICCz3NddF3R
# loZkDgwn6UGbVUvQiNC+dzIV8oLuZ72Uv8l43MiJaMEuaYQ6eU9D7x+LOjIeDbAx
# 7TY53qmXyAyQ6nGunhakyqLYRzATr/sP2iyPyKYXdFfbY3e9oYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDMwNzE5NDYwNFowLwYJKoZIhvcNAQkEMSIEII7WvUWP
# XzcAO7GGPqXeRoSho0GWgHFNTZ3DiVqWs7INMA0GCSqGSIb3DQEBAQUABIICAMxC
# 5oz4A7eEvT2XvUrKxMlmnd8ohJYuhg4ludqaApd3v8YPRZDZMyu/2Gpf2vS+XdBH
# lKYXbp35OxSO0FPSWRSBrs/Rqjb9ODA8CvFx+jTVo2FFYVA5TG22Kna7h0/AZQSQ
# GWzR/aj7L9ZZ9egU139fW/kVGKGcO8gfkPsXvBoQaDu4xDvfTw+uo6vq4hfx2XXF
# ep4CedBGWi6Gv5CGYYqioa1peoWs5MzhL3+1UG/pz3fAOe6GJA3YcS/x6D0mjnQO
# +U9Miu+RKh7uzZF1Fs7qO8ymn2gT2yRy4vXHbcAkvX4dN6QkWtT9hy4SdWTsVSJX
# KbeHSFMJ+5Tlx7Xc8OLouwR0wnpR938jcl+14ft0vcUrUuWLFgokVLUp2Z0ESAdw
# 87aBeXy171Yx0SgZDWA/hnuOzqiSishD//v+pSCy9TFdbGp/ZR7terW9CNsW+EMq
# idBF45KtejKYqaVO9A14u5DxNXKPlTfiuYkScI8v7dJThga8pt3jXPXw11Ap6s9R
# RlXLo+gbAN0lc56xUrOIwBBs17cVLHBTlRlO6/uAhUOqJRAZvPcJH2xFyjRp7wpT
# 3Ij1NM6v+o5sRD//tYMID+AwTqfbz85Nl8Ei+6GLS7LISf3+1oNHsiBAruYL5q21
# 8gwzgGqh06xPO4oSXbacKAbCiwJQrdK7k9odZMjn
# SIG # End signature block
