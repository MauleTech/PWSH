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
	Function Send-To-Teams{
		$date = Get-Date -Format g
		$uri = $([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("aHR0cHM6Ly9hbWJpdGlvbnNncm91cC53ZWJob29rLm9mZmljZS5jb20vd2ViaG9va2IyLzg5N2QyYjRjLTUwYzYtNDljYi1hNjk0LTUwZTNjNzI2NWJkY0BjZjRiZGQwNi1iMDNkLTRiYWYtODU2NS0xMjY1NDY5YTg3NGYvSW5jb21pbmdXZWJob29rLzc2YjE1NmJiNmNjMTQxZmY5MmFmNTg0NzdiOGQxMTVjLzA0ZDMzMjQ3LWVlNzItNDFhZi1hNWFlLTFjNDI4MTI2MjQ0MS9WMlhHbDdZR0pwR0ItUHdpeE1lTEthNnpWUTlKYzlnbl96VDRnOTM2TlcxclUx")))

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
	(New-Object System.Net.WebClient).DownloadFile($NddcURL, $NddcDownloadPath)
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
		Write-Error "ERROR: .SSH Key not found at $ITFolder\.ssh\nddc.id_rsa. - - Check https://ambitions.itglue.com/806129/docs/9939741 for remedy."
		Write-Host "Send to Teams"
		$Message = "ERROR: .SSH Key not found at $ITFolder\.ssh\nddc.id_rsa. - - Check https://ambitions.itglue.com/806129/docs/9939741 for remedy."
		$server = "$env:computername"
		$color = 'ff0000'
		Send-To-Teams

	Write-Host "Logging the attempt"
		$date = Get-Date
		$date = $date.ToShortDateString()
		Add-Content "$ITFolder\NDDC Auto Scan Log.txt" "$date | .SSH Key not found at $ITFolder\.ssh\nddc.id_rsa. - - Check https://ambitions.itglue.com/806129/docs/9939741 for remedy."
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
		$Message = "NDDC has scanned and uploaded to $SftpLink Check https://ambitions.itglue.com/806129/passwords/17437892 for access."
		If (Select-String -Path $ExportedFile -SimpleMatch "Invalid Active Directory username") {
			$Message = $Message + " The stored username and password appear to be incorrect. Please run NDDC manually at least once in $ITFolder\nddc and get to the point where the scan begins. You can cancel it after that."
			$Color = 'ff0000'
		}
		$server = "$env:computername"
		Send-To-Teams

	Write-Host "Logging the attempt"
		$date = Get-Date
		$date = $date.ToShortDateString()
		Add-Content "$ITFolder\NDDC Auto Scan Log.txt" "$date | NDDC has scanned and uploaded to $SftpLink Check https://ambitions.itglue.com/806129/passwords/17437892 for access."
		If (Select-String -Path $ExportedFile -SimpleMatch "Invalid Active Directory username") {
			Add-Content "$ITFolder\NDDC Auto Scan Log.txt" "$date | ERROR: The stored username and password appear to be incorrect. Please run NDDC manually at least once in $ITFolder\nddc and get to the point where the scan begins. You can cancel it after that."
		}

	Write-Host "Cleaning up"
		Remove-Item -Recurse -Force $outputfolder
	}
}

# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU3QL1/LDTeH0oykkGt68+wATx
# WRugggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
# AQsFADA7MQswCQYDVQQGEwJVUzEYMBYGA1UECgwPVGVjaG5vbG9neUdyb3VwMRIw
# EAYDVQQDDAlBbWJpdGlvbnMwHhcNMjQwNTE3MjEzNjE0WhcNMjUwNTE3MjE0NjE0
# WjA7MQswCQYDVQQGEwJVUzEYMBYGA1UECgwPVGVjaG5vbG9neUdyb3VwMRIwEAYD
# VQQDDAlBbWJpdGlvbnMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCc
# sesiq3h/qYB2H80J5kTzMdmjIWe/BHmnUDv2JHBGdxp+ZOT+J9RpPtHNQDXB3Lca
# aL4YjAWC4H+UqJDJJpFj8OXBns9zfpR5coV5+eR6YjRvos9TILNwdErlLrp5CcxN
# vtNR99GyXGsfzrvxc4uWwRc4/fjCPgYHs1BmFyxzSneTlr4CZ56wPJZ1yGRHKn0y
# H5O26/af7stiGZ2GLmXF8VMpEqGE/xWs31aM8xzYBN5FAQjAwoJTGZvm13kukR1t
# 6Uq3huPX5lUpTasPJ3qLXnePKYtIr+390aNzj2+sDt3lcH51vP46nFMQrpzD/Xaz
# K/7UP+9I4J8goswNTrZRAgMBAAGjRjBEMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUE
# DDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUuS0+jvyX95p7+tTFuzZ+ulXo7jQwDQYJ
# KoZIhvcNAQELBQADggEBAF4DPkvlELNjrIUYtWMsFjn+VU6vXENJ3lktFShfL8IS
# 1GDlNZFu+vuJJ2nzLuSNERzdfWa6Pd5qIP05eeinJJtN/sqCPVoLjmA1Td4K6Rau
# Cg8WlxgemTDr3IwqejUlGq8h5AYIw1ike7Q70m9UWyIWT8XNILcXXK0UKUylHRl/
# f+fPinhW56qDDmL+7ctECrTBtm8d1aZOtLEijEbZTg72N2SwaKF7mUVmycT5MuN7
# 46w+V1w/i46wPcf0hkTazvISgUevjXj7dM04U+htX+mDwpvjP/QvQjo37ozOYdQR
# pIjjnNPZIFXprVXI2PRvM/YqP6KTiyKPqOuI+TA9RmkxggHwMIIB7AIBATBPMDsx
# CzAJBgNVBAYTAlVTMRgwFgYDVQQKDA9UZWNobm9sb2d5R3JvdXAxEjAQBgNVBAMM
# CUFtYml0aW9ucwIQFhG2sMJplopOBSMb0j7zpDAJBgUrDgMCGgUAoHgwGAYKKwYB
# BAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAc
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUNc1C
# j3NRFKK/FHTeH/JF5AqLzIowDQYJKoZIhvcNAQEBBQAEggEAj5n3g8te0Z1RGcnz
# fRiY+RCD8ByKp0xE2t7mVysb+PwKMVWXTt/VtnB5VJtrdQP84h16Bf3TrcttBxBN
# 77+iFIGwN5RWAfm/KzjdJUHFrEDb9Ak5emUtUo6wQDOWOYAty330CKGhlvpwLlLA
# y0uCABB8c9J3g9SoI1erSRPC39xy9DOrpNlu38nkE1eDkfoYH4jNid/TV7q+RJRt
# u/UfyuwR6aclJ3MyfPfPyVJFjR9RxnUP8rJY/y78gtYapqD2SyN296TNY/m0WJ1c
# K8/7ZUzuQQm/daE6ZQQ/iawIqJDDGgn5nrN4FiH7+g0iY3nxQtTkPAhTe3uMG5a5
# RXIEkQ==
# SIG # End signature block