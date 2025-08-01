Function Install-Action1 {
	<#
	.Synopsis
		Installs the Action1 Patch Management Software
	.Description
		Installs Action1 Patch Management Software
	.Notes
		For a list of site codes, go to:
		https://github.com/MauleTech/PWSH/blob/master/Scripts/Action1.csv
	#>

	###Require -RunAsAdministrator
	[cmdletbinding()]
	param(
		[string]$Code
	)

	If (-not (Get-Service -Name "A1Agent" -ErrorAction SilentlyContinue)) {
		Write-Host "Installing Action1 patch management."
		$SiteConfigs = @()
		$SiteConfigs = (Invoke-WebRequest -uri "https://raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/Scripts/Action1.csv" -Headers @{"Cache-Control"="no-cache"} -UseBasicParsing).Content | ConvertFrom-Csv -Delimiter ','

		# If a global variable 'SiteCode' exists, use it
		If (Get-Variable -Name SiteCode -ErrorAction SilentlyContinue) {
			$Code = $SiteCode
			$Silent = $True
		}

		if ([String]::IsNullOrEmpty(($SiteConfigs | Where-Object { $_.Code -eq $Code }).GUID)) {
			# Always display the available site codes before prompting
			Write-Host "`nAvailable Site Codes:" -ForegroundColor Cyan
			$SiteConfigs | Where-Object -Property GUID -ne "" | Select-Object Code, Site | Format-Table -AutoSize

			# Ensure $Code is provided and valid
			while ($null -eq $Code -or -not ($SiteConfigs | Where-Object { $_.Code -eq $Code })) {
				if ($null -ne $Code) {
					Write-Host "Invalid site code: $Code. Please enter a valid site code." -ForegroundColor Red
				}
				$Code = Read-Host "Enter Site Code"
			}
		}

		# Proceed with installation after validation
		$MSIUrl = 'https://app.action1.com/agent/'
		$GUID = ($SiteConfigs | Where-Object { $_.Code -eq $Code }).GUID
		$InstallURL = $MSIUrl + $GUID + "/Windows/Action1agent($Code).msi"
		$Action1Installer = Get-FileDownload -URL $InstallURL -SaveToFolder $ITFolder\Action1Patches
		$msiPath = $Action1Installer[1]
		$arguments = "/i `"$msiPath`" /quiet /norestart"
		$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru

		if ($process.ExitCode -eq 0) {
			Write-Output "Installation of $msiPath completed successfully."
		} else {
			Write-Output "Installation failed with exit code: $($process.ExitCode)"
		}
	} Else {
		Write-Output "A1Agent service is already installed."
	}
}

Function Install-AppDefaults {
	Write-Host "Downloading App Defaults"
	New-Item -ItemType Directory -Force -Path $ITFolder\ITS247Agent
	(New-Object System.Net.WebClient).DownloadFile('https://download.ambitionsgroup.com/AppDefaults.xml', '$ITFolder\AppDefaults.xml')
	Write-Host "Deploying App Defaults"
	Dism.exe /online /import-defaultappassociations:'$ITFolder\AppDefaults.xml'
}

Function Install-Choco {
	Write-Host "Installing Chocolatey"
	$progressPreference = 'silentlyContinue'
	Set-ExecutionPolicy Bypass -Scope Process -Force
	Enable-SSL
	Invoke-WebRequest https://raw.githubusercontent.com/MauleTech/PWSH/master/Scripts/Chocolatey/installchoco.txt -UseBasicParsing | Invoke-Expression
	Invoke-WebRequest https://raw.githubusercontent.com/MauleTech/PWSH/master/Scripts/Chocolatey/installchoco.txt -UseBasicParsing | Invoke-Expression
}

Function Install-ITS247Agent {
	If ($SiteCode -and !$IAmJOB) {
		Start-Job -Name "InstallAgent" -InitializationScript {
			$progressPreference = 'silentlyContinue'
			irm raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt | iex
		} -ScriptBlock {
			$global:SiteCode = $using:SiteCode
			$global:IAmJOB = $True
			irm raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt | iex
			Install-ITS247Agent
		} | Receive-Job -Wait #-AutoRemoveJob
	} ElseIf (($SiteCode -and $IAmJOB) -or (!$SiteCode -and !$IAmJOB)) {
		Write-Host "I'm running as a job!"
		$progressPreference = 'silentlyContinue'
		Set-ExecutionPolicy Bypass -Scope Process -Force
		irm raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt | iex
		Invoke-WebRequest https://raw.githubusercontent.com/MauleTech/PWSH/master/Scripts/ITS247Agent/Install_ITS247_Agent_MSI.txt -UseBasicParsing | Invoke-Expression
	} ElseIf (!$SiteCode -and $IAmJOB) {Write-Warning "You can't run the installer as job without specifying the SiteCode Variable. You can't interact with a job."}

}

Function Install-NetExtender {
	$App = Get-WmiObject -Class Win32_Product | Where-Object -Property "Name" -Like "*NetExtender*"

	If ($App) {
		$Name = $App.Name
		Write-Host "$Name is already installed. Please uninstall and reboot before attempting a fresh install."
	} Else {
		Write-Host "Downloading & Installing NetExtender"
		If (Get-Command winget -ErrorAction SilentlyContinue) {
			winget source update
			winget install --id SonicWall.NetExtender -e -h --accept-package-agreements --accept-source-agreements
		} Else {
			If (!(Get-Command choco -ErrorAction SilentlyContinue)) {Install-Choco}
			Choco upgrade sonicwall-sslvpn-netextender -y
		}
	}
}

Function Install-NiniteApps {
	If (-not (Test-Path '$ITFolder\NinitePro.exe')) {Install-NinitePro}
	Write-Host "Install Ninite Apps, waiting for install to complete and logging the results."
		$NiniteCache = "\\adsaltoxl\data\Software\Ninite\NiniteDownloads"
		If(test-path $NiniteCache){
			& $ITFolder\NinitePro.exe /select 7-Zip Air Chrome 'Firefox ESR' Zoom Greenshot 'Notepad++' 'Paint.NET' Reader VLC /cachepath $NiniteCache /allusers /silent '$ITFolder\NiniteReport.txt' | Wait-Process
		} ELSE {
			& $ITFolder\NinitePro.exe /select 7-Zip Air Chrome 'Firefox ESR' Zoom Greenshot 'Notepad++' 'Paint.NET' Reader VLC /nocache /allusers /silent '$ITFolder\NiniteReport.txt' | Wait-Process
		}
	Get-Content '$ITFolder\NiniteReport.txt'
	Write-Host "End of Install Ninite Apps"
}

Function Install-NinitePro {
	Write-Host "Downloading Ninite Installer"
	New-Item -ItemType Directory -Force -Path $ITFolder
	(New-Object System.Net.WebClient).DownloadFile('https://download.ambitionsgroup.com/Software/NinitePro.exe', '$ITFolder\NinitePro.exe')
	Write-Host "Schedule Ninite Updates"
	$Trigger = New-ScheduledTaskTrigger -AtStartup
	$User = "NT AUTHORITY\SYSTEM"
	$Action = New-ScheduledTaskAction -Execute "$ITFolder\NinitePro.exe" -Argument "/updateonly /nocache /silent $ITFolder\NiniteUpdates.log"
	Register-ScheduledTask -TaskName "Update Apps" -Trigger $Trigger -User $User -Action $Action -RunLevel Highest -Force
	Write-Host "End of Schedule Ninite Updates"
}

Function Install-O2016STD([String] $MSPURL){
	Write-Host "Downloading MS Office"
		Enable-SSL
		New-Item -ItemType Directory -Force -Path '$ITFolder\O2016STD'
		(New-Object System.Net.WebClient).DownloadFile('http://download.ambitionsgroup.com/Software/O2016_STD_X64.exe', '$ITFolder\O2016STD\O2016_STD_X64.exe')

	Write-Host "Downloading MS Office config files"
		$MSPfilename = $MSPURL.Substring($MSPURL.LastIndexOf("/") + 1)
		$MSPfilepath = '$ITFolder\O2016STD\' + $MSPfilename
		(New-Object System.Net.WebClient).DownloadFile($MSPURL, $MSPfilepath)

	Write-Host "Installing Office"
		& '$ITFolder\O2016STD\O2016_STD_X64.exe' -pth!nSong70 -o$ITFolder\O2016STD -y | Wait-Process
		& '$ITFolder\O2016STD\setup.exe' /adminfile $MSPfilepath | Wait-Process

	Write-Host "Placing Shortcuts"
		$TargetFile = 'C:\Program Files\Microsoft Office\Office16\OUTLOOK.EXE'
		$ShortcutFile = "$env:Public\Desktop\Outlook.lnk"
		$WScriptShell = New-Object -ComObject WScript.Shell
		$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
		$Shortcut.TargetPath = $TargetFile
		$Shortcut.Save()

		$TargetFile = 'C:\Program Files\Microsoft Office\Office16\EXCEL.EXE'
		$ShortcutFile = "$env:Public\Desktop\Excel.lnk"
		$WScriptShell = New-Object -ComObject WScript.Shell
		$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
		$Shortcut.TargetPath = $TargetFile
		$Shortcut.Save()

		$TargetFile = 'C:\Program Files\Microsoft Office\Office16\WINWORD.EXE'
		$ShortcutFile = "$env:Public\Desktop\Word.lnk"
		$WScriptShell = New-Object -ComObject WScript.Shell
		$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
		$Shortcut.TargetPath = $TargetFile
		$Shortcut.Save()
}

Function Install-O365([String] $SiteCode = "Generic"){
	Write-Host "Downloading MS Office"
		Enable-SSL
		New-Item -ItemType Directory -Force -Path "$ITFolder\O365"
		(New-Object System.Net.WebClient).DownloadFile('https://download.ambitionsgroup.com/O365/setup.exe', '$ITFolder\O365\setup.exe')
	Write-Host "Downloading MS Office config files"
		$O365ConfigSource = "https://download.ambitionsgroup.com/Sites/" + $SiteCode + "/" + $SiteCode + "_O365_Config.xml"
		$O365ConfigDest = "$ITFolder\O365\" + $SiteCode + "_O365_Config.xml"
		(New-Object System.Net.WebClient).DownloadFile($O365ConfigSource, $O365ConfigDest)
	Write-Host "Installing Office"
		& $ITFolder\O365\setup.exe /configure $O365ConfigDest | Wait-Process
	Write-Host "Placing Shortcuts"
		If (Test-Path "C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"){
			$TargetFile = "C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
		} ELSEIF (Test-Path "C:\Program Files (x86)\Microsoft Office\root\Office16\OUTLOOK.EXE"){
			$TargetFile = "C:\Program Files (x86)\Microsoft Office\root\Office16\OUTLOOK.EXE"
		}
		$ShortcutFile = "$env:Public\Desktop\Outlook.lnk"
		$WScriptShell = New-Object -ComObject WScript.Shell
		$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
		$Shortcut.TargetPath = $TargetFile
		$Shortcut.Save()

		If (Test-Path "C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"){
			$TargetFile = "C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"
		} ELSEIF (Test-Path "C:\Program Files (x86)\Microsoft Office\root\Office16\EXCEL.EXE"){
			$TargetFile = "C:\Program Files (x86)\Microsoft Office\root\Office16\EXCEL.EXE"
		}
		$ShortcutFile = "$env:Public\Desktop\Excel.lnk"
		$WScriptShell = New-Object -ComObject WScript.Shell
		$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
		$Shortcut.TargetPath = $TargetFile
		$Shortcut.Save()

		If (Test-Path "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"){
			$TargetFile = "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
		} ELSEIF (Test-Path "C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE"){
			$TargetFile = "C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE"
		}
		$ShortcutFile = "$env:Public\Desktop\Word.lnk"
		$WScriptShell = New-Object -ComObject WScript.Shell
		$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
		$Shortcut.TargetPath = $TargetFile
		$Shortcut.Save()
}

Function Install-O365ProofPointConnectors {
<#
	.SYNOPSIS
		Installs the proofpoint inbound and outbound connectors in exchange online, as well as spam bypass for emails coming from exchange.
#>
	If (Get-Command Get-Mailbox -ErrorAction SilentlyContinue){
		Function Install-ProofPointInbound {
			New-InboundConnector -Name “Inbound from ProofPoint” -Comment “Only accept email from ProofPoint transport addresses” -Enabled $True  -SenderDomains * -RestrictDomainsToIPAddresses $true -RequireTls $true -SenderIPAddresses 148.163.159.0/24, 148.163.158.0/24, 148.163.157.0/24, 148.163.156.0/24, 148.163.155.0/24, 148.163.154.0/24, 148.163.153.0/24, 148.163.151.0/24, 148.163.150.0/24, 148.163.149.0/24, 148.163.148.0/24, 148.163.147.0/24, 148.163.146.0/24, 148.163.145.0/24, 148.163.143.0/24, 148.163.142.0/24, 148.163.141.0/24, 148.163.140.0/24, 148.163.139.0/24, 148.163.138.0/24, 148.163.137.0/24, 148.163.135.0/24, 148.163.134.0/24, 148.163.133.0/24, 148.163.132.0/24, 148.163.131.0/24, 148.163.130.0/24, 148.163.129.0/24, 52.54.85.198, 52.55.243.18, 34.192.199.2, 67.231.156.0/24, 67.231.155.0/24, 67.231.154.0/24, 67.231.153.0/24, 67.231.152.0/24, 67.231.148.0/24, 67.231.147.0/24, 67.231.146.0/24, 67.231.145.0/24, 67.231.144.0/24, 148.163.152.0/24, 148.163.144.0/24, 148.163.136.0/24, 148.163.128.0/24, 67.231.149.0/24
		}

		Function Install-ProofPointOutbound {
			New-OutboundConnector -Name “Outbound to ProofPoint” -Comment “Send all external outbound email through ProofPoint SmartHost” -Enabled $true -RecipientDomains * -SmartHosts outbound-us1.ppe-hosted.com -TlsSettings EncryptionOnly -UseMXRecord $false
		}

		If (Get-InboundConnector) {
			$Readhost = Read-Host "Warning, an inbound connector already exists.`nAre you sure you want to install the ProofPoint connector which may conflict?`n( y / n ) "
			Switch ($ReadHost)
			{
				Y { Write-Host "Installing the Proofpoint Inbound Connector.";Install-ProofPointInbound }
				N { break }
				Default { "You didn't enter the a correct response" }
			}
		} else {
			Write-Host "Installing the Proofpoint Inbound Connector."
			Install-ProofPointInbound
		}

		If (Get-OutboundConnector) {
			$Readhost = Read-Host "Warning, an outbound connector already exists.`nAre you sure you want to install the ProofPoint connector which may conflict? ( y / n ) "
			Switch ($ReadHost)
			{
				Y { Write-Host "Installing the Proofpoint Outbound Connector.";Install-ProofPointOutbound }
				N { break }
				Default { "You didn't enter the a correct response" }
			}
		} Else {
			Write-Host "Installing the Proofpoint Outbound Connector."
			Install-ProofPointOutbound
		}

		Set-HostedConnectionFilterPolicy “Default” -IPAllowList 148.163.147.0/24, 148.163.146.0/24, 148.163.145.0/24, 148.163.143.0/24, 148.163.142.0/24, 148.163.141.0/24, 148.163.140.0/24, 148.163.139.0/24, 148.163.138.0/24, 148.163.137.0/24, 148.163.135.0/24, 148.163.134.0/24, 148.163.133.0/24, 148.163.132.0/24, 148.163.131.0/24, 148.163.130.0/24, 148.163.129.0/24, 52.54.85.198, 52.55.243.18, 34.192.199.2, 67.231.156.0/24, 67.231.155.0/24, 67.231.154.0/24, 67.231.153.0/24, 67.231.152.0/24, 67.231.148.0/24, 67.231.147.0/24, 67.231.146.0/24, 67.231.145.0/24, 67.231.144.0/24, 148.163.152.0/24, 148.163.144.0/24, 148.163.136.0/24, 148.163.128.0/24, 67.231.149.0/24 -EnableSafeList $True -AdminDisplayName "Proofpoint Bypass 365 Spam filter"
		Set-HostedContentFilterPolicy -Identity "Default" -AddXHeaderValue "Office 365 Notice: Possible Spam" -AdminDisplayName "Disabled 365 Filtering, inbound handled by Proofpoint." -BulkSpamAction "NoAction" -BulkThreshold 9 -DownloadLink $False -EnableEndUserSpamNotifications $False -EnableLanguageBlockList $False -EnableRegionBlockList $False -HighConfidencePhishAction Quarantine -HighConfidenceSpamAction AddXHeader -IncreaseScoreWithBizOrInfoUrls Off -IncreaseScoreWithImageLinks Off -IncreaseScoreWithNumericIps Off -IncreaseScoreWithRedirectToOtherPort Off -InlineSafetyTipsEnabled $False -MakeDefault -MarkAsSpamBulkMail Off -MarkAsSpamEmbedTagsInHtml Off -MarkAsSpamEmptyMessages Off -MarkAsSpamFormTagsInHtml Off -MarkAsSpamFramesInHtml Off -MarkAsSpamFromAddressAuthFail Off -MarkAsSpamJavaScriptInHtml Off -MarkAsSpamNdrBackscatter Off -MarkAsSpamObjectTagsInHtml Off -MarkAsSpamSensitiveWordList Off -MarkAsSpamSpfRecordHardFail Off -MarkAsSpamWebBugsInHtml Off -PhishSpamAction AddXHeader -PhishZapEnabled $False -QuarantineRetentionPeriod 30 -RedirectToRecipients $Null -RegionBlockList $Null -SpamAction AddXHeader -SpamZapEnabled $False -TestModeAction None -TestModeBccToRecipients $Null
		$DisableMailoxJunkFilters = Get-ExoMailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited; $All | foreach {Set-MailboxJunkEmailConfiguration $_.Name -Enabled $false}
	} Else {
		Write-Host "You are not connected to an exchange server. Try the command 'Connect-O365Exchange'."
	}
}

Function Install-SophosDnsCert {
	Write-Host "Checking Root Certificate"
	$RootCertPath = "Cert:\LocalMachine\Root\F415AEF803CE13AF11AD14FE5D38F9CF2D91C6CD" #Thumbprint of the Cert set to expire in 2036
	If (!(Test-Path $RootCertPath -ea SilentlyContinue)) {
		$certFilePath = "$Env:SystemDrive\IT\GitHub\PWSH\OneOffs\Sophos_certificate.pem"
		If (!(Test-Path $certFilePath -ea SilentlyContinue)) {
			Write-Host "Downloading the Umbrella Root Cert"
			irm 'https://raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt' | iex
			Update-ITFunctions
		}
		Write-Host "Installing the Umbrella Root Cert"
		Import-Certificate -FilePath $certFilePath -CertStoreLocation Cert:\LocalMachine\Root\
		If(Test-Path "C:\Program Files\Mozilla Firefox\defaults\pref\") {
			Write-Host "Configuring Firefox to use the Cert"
			Set-Content "C:\Program Files\Mozilla Firefox\defaults\pref\firefox-windows-truststore.js" "pref('security.enterprise_roots.enabled', true);"
		}
	} Else {
		Write-Host -ForegroundColor Green "The Umbrella Root Cert is already installed."
	}
}

Function Install-UmbrellaDns {
    [cmdletbinding()]
    param(
        [string]$Code #Shortcode of the site you want to install
    )
    
    # Set variables if SiteCode exists in current scope
    If (Get-Variable -Name SiteCode -ErrorAction SilentlyContinue) { 
        $Code = $SiteCode 
        $Silent = $True 
    }
    
    # Start job with a unique name for better tracking
    $jobName = "UmbrellaDNSInstall-$(Get-Random)"
    $job = Start-Job -Name $jobName -ArgumentList $SiteCode, $Code, $Silent -ScriptBlock {
        param($SiteCode, $Code, $Silent)
        
        try {
            # Download and import IT scripts
            irm raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt | iex
            
            # Run appropriate installation command
            If (Get-Variable -Name Code -ErrorAction SilentlyContinue) {
                Write-Host "Running Install-UmbrellaDNSasJob -Code $Code"
                Install-UmbrellaDNSasJob -Code $Code
            } Else {
                Write-Host "Running Install-UmbrellaDNSasJob"
                Install-UmbrellaDNSasJob
            }
            
            # Return success status
            return @{ Status = "Success"; Message = "Installation completed successfully" }
        }
        catch {
            # Capture and return any errors
            return @{ Status = "Error"; Message = $_.Exception.Message; ErrorDetails = $_ }
        }
    }
    
    Write-Host "Installation job started with ID: $($job.Id) and Name: $jobName"
    
    # Wait for the job with a timeout and properly handle it
    try {
        $completedJob = Wait-Job -Id $job.Id -Timeout 600 # 10-minute timeout
        
        if ($completedJob.State -eq "Completed") {
            $jobResults = Receive-Job -Id $job.Id
            Write-Host "Installation job completed successfully"
            
            # Output detailed results if available
            if ($jobResults -is [hashtable] -and $jobResults.ContainsKey("Status")) {
                Write-Host "Status: $($jobResults.Status)"
                Write-Host "Message: $($jobResults.Message)"
            } else {
                # Display raw results if not in expected format
                $jobResults
            }
        }
        elseif ($completedJob.State -eq "Failed") {
            Write-Error "Installation job failed. See error details below:"
            Receive-Job -Id $job.Id
        }
        else {
            Write-Warning "Job timed out or is in an unexpected state: $($completedJob.State)"
            Write-Warning "You can check job status later with: Get-Job -Id $($job.Id)"
        }
    }
    catch {
        Write-Error "Error monitoring installation job: $_"
    }
    finally {
        # Always clean up the job
        Remove-Job -Id $job.Id -Force -ErrorAction SilentlyContinue
    }
}

Function Install-UmbrellaDNSasJob {
	<#
	.Synopsis
		Installs the Umbrella Dns Client
	.Description
		Determines the site code from IP or manually, then downloads and installs the appropriate config file for the site.
	.Exampleget-
		Install-UmbrellaDNS -Code XMPL
		Installs the agent for the site Example Org. Will prompt for silent install confirmation.
	.Notes
		For a list of site codes, go to:
		https://github.com/MauleTech/PWSH/blob/49d3876af3f2548ca106fb731cb0bf4def21a007/Scripts/Umbrella/UDNS-Client-Mapping.csv
	#>

		###Require -RunAsAdministrator
	[cmdletbinding()]
	param(
		[string]$Code #Shortcode of the site you want to install, list available at https://github.com/MauleTech/PWSH/blob/master/Scripts/ITS247Agent/SiteAgentURLs.csv
	)
	$SiteConfigs = @()
	$SiteConfigs = (Invoke-WebRequest -uri "https://raw.githubusercontent.com/MauleTech/PWSH/master/Scripts/Umbrella/UDNS-Client-Mapping.csv" -Headers @{"Cache-Control"="no-cache"} -UseBasicParsing).Content | convertfrom-csv -Delimiter ','
	$MSIUrl = 'https://download.ambitionsgroup.com/Software/cisco-secure-client-win-5.1.9.113-predeploy-k9.zip'
	
	Write-Host "Checking Status Indicator"
	$IndicKey = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator | Select-Object -ExpandProperty UseGlobalDNS -ea SilentlyContinue
	If ($IndicKey -ne 1) {
		Write-Host "Setting Connectivity Indicator Reg Key"
		New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -force -ea SilentlyContinue
		New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator' -Name 'UseGlobalDNS' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;
	} Else {
		Write-Host -ForegroundColor Green "The Status Indicator is already set."
	}

	Write-Host "Checking Root Certificate"
	$RootCertPath = "Cert:\LocalMachine\Root\C5091132E9ADF8AD3E33932AE60A5C8FA939E824" #Thumbprint of the Cert set to expire in 2036
	If (!(Test-Path $RootCertPath -ea SilentlyContinue)) {
		Write-Host "Downloading the Umbrella Root Cert"
		$url = 'https://download.ambitionsgroup.com/Software/Cisco_Umbrella_Root_CA.cer'
		$certFolder = $ITFolder + '\UmbrellaClient\'
		$certFilePath = $certFolder + 'Cisco_Umbrella_Root_CA.cer'
		Remove-Item $certFilePath -ea SilentlyContinue
		$null = (New-Item -ItemType Directory -Force -Path $certFolder)
		(New-Object System.Net.WebClient).DownloadFile($url, $certFilePath)
		Write-Host "Installing the Umbrella Root Cert"
		#& certutil -addstore -enterprise -f "Root" $certFilePath
		Import-Certificate -FilePath $certFilePath -CertStoreLocation Cert:\LocalMachine\Root\
		If(Test-Path "C:\Program Files\Mozilla Firefox\defaults\pref\") {Write-Host "Configuring Firefox to use the Cert";Set-Content "C:\Program Files\Mozilla Firefox\defaults\pref\firefox-windows-truststore.js" "pref('security.enterprise_roots.enabled', true);"}
	} Else {
		Write-Host -ForegroundColor Green "The Umbrella Root Cert is already installed."
	}

	Write-Host "Checking Umbrella DNS client."
	$OldIsInstalled = Get-Service -Name Umbrella_RC -ErrorAction SilentlyContinue
	$NewIsInstalled = Get-Service -Name csc_umbrellaagent -ErrorAction SilentlyContinue
	$UpdateAvailable = $False
	
	If ($NewIsInstalled) {
		Write-Host -ForegroundColor Green "Cisco Secure Client Umbrella DNS agent is already installed. Exiting."
		[Version]$InstalledVersion = ((Get-Item "C:\Program Files (x86)\Cisco\Cisco Secure Client\acumbrellaagent.exe").VersionInfo).ProductVersion
		[Version]$AvailableVersion = ([regex]::Match($MSIUrl, 'win-(\d+\.\d+\.\d+\.\d+)-predeploy')).Groups[1].Value
		If ($AvailableVersion -gt $InstalledVersion) {
			Write-Host "Hooray! Available version ($AvailableVersion) is greater than installed version ($InstalledVersion)."
			$UpdateAvailable = $True
		} else {
			Write-Host "Available version ($AvailableVersion) is not greater than installed version ($InstalledVersion)."
		}
	}

	If ($NewIsInstalled -and $UpdateAvailable -eq $False) {
		Write-Host -ForegroundColor Green "Cisco Secure Client Umbrella DNS agent is already installed and up to date. Exiting."
	} Else {
		If ($OldIsInstalled) {
			Write-Host "The old Umbrella Client has been detected. Updating to the new Cisco Secure Client Umbrella DNS agent"
			$OldOrgData = (Get-Content -Path $Env:ProgramData\OpenDNS\ERC\OrgInfo.json | ConvertFrom-Json).organizationId
			$DetectedSite = $SiteConfigs | Where-Object {$_.Command -match $OldOrgData}
			If ($DetectedSite) {
				Write-Host "$($DetectedSite.Site) has been detected."
				$Code = $DetectedSite.Code
			}
		}
		If ($UpdateAvailable) {
			Write-Host "The old Umbrella Client has been detected. Updating to the new Cisco Secure Client Umbrella DNS agent"
			$OldOrgData = (Get-Content -Path "$env:ProgramData\Cisco\Cisco Secure Client\Umbrella\OrgInfo.json" | ConvertFrom-Json).organizationId
			$DetectedSite = $SiteConfigs | Where-Object {$_.Command -match $OldOrgData}
			If ($DetectedSite) {
				Write-Host "$($DetectedSite.Site) has been detected."
				$Code = $DetectedSite.Code
			}
		}
		If (!$Code) {
			$Hostname = (Get-ComputerInfo -Property CsName).CsName
			$prefix = $hostname.Split('-')[0]
			If ($prefix){
				$DetectedSite = $SiteConfigs | Where-Object {$_ -match $prefix}
			}
			If ($DetectedSite) {
				Write-Host "$($DetectedSite.Site) has been detected."
				$Code = $DetectedSite.Code
			}
		}
		Write-Host "Installing Umbrella DNS client."
		$PreDNS = (Get-NetIPConfiguration | Where {$_.Netprofile.Ipv4Connectivity -Like "*Internet*"}).DnsServer.ServerAddresses
		#Write-Host "DNS Servers: $PreDNS"
		#nslookup -q=txt debug.opendns.com
		Start-Sleep -Seconds 10
		#Dowload config file index

		Function InstallAgent {
			Write-Host
			Write-Host ================ Umbrella DNS Agent Installation ================
			Write-Host "$SelectedSite"
			# Check if the site code matches "SFSW"
			If ($SelectedSite.Site -Match "Santa Fe Solid Waste Management") {
				Write-Host "Installing Santa Fe City VPN first"
				# Define URLs for downloading the Cisco AnyConnect VPN installer and configuration files
				$CityVpnExeURL = "https://download.ambitionsgroup.com/Sites/SFSW/anyconnect-win-4.6.01103-core-vpn-webdeploy-k9.exe"
				$CityVpnConfigURL = "https://download.ambitionsgroup.com/Sites/SFSW/VPN.exe"
				
				# Download the VPN installer and configuration files to the Ambitions folder on the system drive
				# Get-FileDownload is a custom function that downloads files and returns an array with status and file path
				$CityVpnExeDownload = Get-FileDownload -URL $CityVpnExeURL -SaveToFolder $ITFolder\
				$CityVpnConfigDownload = Get-FileDownload -URL $CityVpnConfigURL -SaveToFolder $ITFolder\
				
				# Remove any existing Umbrella DNS installation that might conflict with the VPN client
				Uninstall-UmbrellaDNS
				
				# Install the Cisco AnyConnect VPN client with quiet installation parameters
				# /quiet /qn - Runs the installer silently without user interaction
				$CityVPNExe = $CityVpnExeDownload[-1]
				Write-Host "Start-Process -FilePath $CityVPNExe -ArgumentList '/quiet /qb' -Wait -PassThru"
				Start-Process -FilePath $CityVPNExe -ArgumentList '/quiet /qb' -Wait -PassThru
				# Apply the VPN configuration file to the installed Cisco Secure Client
				# -y: Automatically answer yes to all prompts
				# -o: Specify the output directory for the configuration
				$ConfigSFX = $CityVpnConfigDownload[-1]
				Write-Host "& $ConfigSFX -y -o'C:\ProgramData\Cisco\Cisco Secure Client'"
				& $ConfigSFX -y -o'C:\ProgramData\Cisco\Cisco Secure Client'
			} Else {$SelectedSite.Site}
			Write-Host Downloading the agent for $SelectedSite.Site
			$msiFolder = $ITFolder + '\UmbrellaClient\'
			#$Command = "msiexec /i " + $msiFilePath + " /qn " + $SelectedSite.Command

			$null = (New-Item -ItemType Directory -Force -Path $msiFolder)
			#If (Test-Path $msiFilePath) { Remove-Item $msiFilePath}
			$DownloadFileInfo = Get-FileDownload -URL $MSIUrl -SaveToFolder $msiFolder
			$DownloadFilePath = $DownloadFileInfo[-1]
			Get-Item $DownloadFilePath | Unblock-File

			Expand-Archive -Path $DownloadFilePath -DestinationPath $msiFolder
			Set-Location -Path $msiFolder

			#Write-Host Disabling Windows Defender Real Time Scanning
			#Set-MpPreference -DisableRealtimeMonitoring $True -ErrorAction SilentlyContinue
			Write-Host "Installing the agent for $($SelectedSite.Site)"
			Set-Location -Path $msiFolder
			Write-Host "Installing Cisco Secure Client CORE"
			$CoreMsi = $(Get-ChildItem -Path $msiFolder -Filter "*core*").FullName
			Start-Process 'msiexec.exe' -ArgumentList "/package $CoreMsi /norestart /passive PRE_DEPLOY_DISABLE_VPN=0" -Wait
			Write-Host "Installing Umbrella Module"
			$UmbrellaMsi = $(Get-ChildItem -Path $msiFolder -Filter "*umbrella-predeploy*").FullName
			Start-Process 'msiexec.exe' -ArgumentList "/package $UmbrellaMsi /norestart /passive" -Wait
			Write-Host "Installing Diagnostics and Repair Tool"
			$DartMsi = $(Get-ChildItem -Path $msiFolder -Filter "*dart-predeploy*").FullName
			Start-Process 'msiexec.exe' -ArgumentList "/package $DartMsi /norestart /passive" -Wait
			#$Command | Invoke-Expression | Wait-Process
			Write-Host "Creating Org File"
				# Define the input string
				$inputString = $SelectedSite.Command
				# Split the string into key-value pairs
				$pairs = $inputString -split ' '
				# Create a hashtable to store the required key-value pairs
				$data = @{}
				# Map the old keys to the new keys
				$keyMapping = @{
					'ORG_ID' = 'organizationId'
					'ORG_FINGERPRINT' = 'fingerprint'
					'USER_ID' = 'userId'
				}
				# Iterate over each pair and add the required key-value pairs to the hashtable
				foreach ($pair in $pairs) {
					$key, $value = $pair -split '='
					if ($keyMapping.ContainsKey($key)) {
						$data[$keyMapping[$key]] = $value
					}
				}
				# Create an ordered dictionary
				$orderedData = [ordered]@{}
				# Add the key-value pairs in the desired order
				$orderedData['organizationId'] = $data['organizationId']
				$orderedData['fingerprint'] = $data['fingerprint']
				$orderedData['userId'] = $data['userId']
				$orderedData
				$orderedData | ConvertTo-Json | Out-File -FilePath "$env:ProgramData\Cisco\Cisco Secure Client\Umbrella\OrgInfo.json"

				Write-Host "Restarting Services"
				Restart-Service -Name csc_umbrellaagent -ErrorAction SilentlyContinue

				#Cleanup
				Set-Location ..
				#Remove-Item -Path $msiFolder -Recurse -Force -ErrorAction SilentlyContinue

			#nslookup -q=txt debug.opendns.com
			#Start-Sleep -Seconds 30
			#$PostDNS = (Get-NetIPConfiguration | Where {$_.Netprofile.Ipv4Connectivity -Like "*Internet*"}).DnsServer.ServerAddresses
			#Write-Host "DNS Servers: $PostDNS"
			Get-Service -Name csc_umbrellaagent
			#BREAK
		} #End of InstallAgent

		Function Show-Menu {
			param (
				[string]$Title = 'Site Selection'
			)
			#Clear-Host
			Write-Host "Umbrella DNS Agent Installer"
			Write-Host
			Write-Host "================ $Title ================"
			Foreach ($Site in $SiteConfigs) {
				Write-Host "Enter "$Site.Code"`t for "$Site.Site
			}
			Write-Host "Enter 'Q' to quit"
			Write-Host
		} #End of Show-Menu

		Function Create-Menu {
			$selection = $null
			#Do {
				Show-Menu -Title 'Site Selection'
				If (!($selection)) { $selection = Read-Host "Please make a selection" }
				$SelectedSite = $SiteConfigs.Where( { $PSItem.Code -like $selection })
				If ($selection -eq 'q') { Break }
				If ($SelectedSite) {
					Write-Host
					Write-Host Selection Confirmed: $SelectedSite.Site
					InstallAgent
				} Else {
					$selection = Read-Host "Invalid code. Please make a valid selection"
				}
			#} Until ($selection -eq 'q')
		} #End of Create-Menu

		# Check for preassigned site code, offer choices If not
		If (Get-Variable -Name SiteCode -ErrorAction SilentlyContinue) { $Code = $SiteCode ; $Silent = $True }
		If ($Code) {
			$SelectedSite = $SiteConfigs.Where( { $PSItem.Code -like $Code })
			If ($SelectedSite) {
				InstallAgent
			} Else {
				Do {
					Show-Menu -Title 'Site Selection'
					$selection = Read-Host "Invalid code. Please make a valid selection"
				}
				Until ($selection -eq 'q')
			}
		} Else {
			Write-Host "Attempting to determine location"
			$DetectedIP = irm https://icanhazip.com
			$searchterm = '*' + $DetectedIP + '*'
			$DetectedSite = $SiteConfigs.Where( { $PSItem.ExtIPs -like $searchterm })
			If ($DetectedSite) {
				$DetectedCode = $DetectedSite.Code
				$DetectedTitle = $DetectedSite.Site

				If ($Auto) {
					#Silently install automatically
					Write-Host Automatic mode, hold on!
					$SelectedSite = $DetectedSite
					$Silent = $True
					InstallAgent
				} Else {
					#Prompt for auto install
					$message = "Based on your external IP address of $DetectedIP, you are at $DetectedTitle"
					$question = 'Do you want to proceed installing the agent for this site?'
					$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
					$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
					$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
					$decision = $Host.UI.PromptForChoice($message, $question, $choices, 0)
					If ($decision -eq 0) {
						Write-Host "Selection Confirmed: $DetectedTitle"
						$SelectedSite = $DetectedSite
						InstallAgent
						BREAK
					} Else {
						Write-Host Generating a site selection menu
						Create-Menu
					}
					#Pause
				}
			} Else {
				Write-Host No site detected based on your external IP address
				Create-Menu
			}
		}
	}
}

Function Install-UmbrellaDnsCert {
	Write-Host "Checking Root Certificate"
	$RootCertPath = "Cert:\LocalMachine\Root\C5091132E9ADF8AD3E33932AE60A5C8FA939E824" #Thumbprint of the Cert set to expire in 2036
	If (!(Test-Path $RootCertPath -ea SilentlyContinue)) {
		Write-Host "Downloading the Umbrella Root Cert"
		$url = 'https://download.ambitionsgroup.com/Software/Cisco_Umbrella_Root_CA.cer'
		$certFolder = $ITFolder + '\UmbrellaClient\'
		$certFilePath = $certFolder + 'Cisco_Umbrella_Root_CA.cer'
		Remove-Item $certFilePath -ea SilentlyContinue
		$null = (New-Item -ItemType Directory -Force -Path $certFolder)
		(New-Object System.Net.WebClient).DownloadFile($url, $certFilePath)
		Write-Host "Installing the Umbrella Root Cert"
		#& certutil -addstore -enterprise -f "Root" $certFilePath
		Import-Certificate -FilePath $certFilePath -CertStoreLocation Cert:\LocalMachine\Root\
		If(Test-Path "C:\Program Files\Mozilla Firefox\defaults\pref\") {Write-Host "Configuring Firefox to use the Cert";Set-Content "C:\Program Files\Mozilla Firefox\defaults\pref\firefox-windows-truststore.js" "pref('security.enterprise_roots.enabled', true);"}
	} Else {
		Write-Host -ForegroundColor Green "The Umbrella Root Cert is already installed."
	}
}

Function Install-WinGet {
	<#
		.SYNOPSIS
			Installs winget, Microsoft's answer to apt-get and choco.
		.LINK
			https://github.com/microsoft/winget-cli
		.LINK
			https://docs.microsoft.com/en-us/windows/package-manager/winget/
	#>
	
		$GetWinGet = {
			$url = 'https://github.com/microsoft/winget-cli/releases/latest'
			$request = [System.Net.WebRequest]::Create($url)
			$response = $request.GetResponse()
			$realTagUrl = $response.ResponseUri.OriginalString
			$version = $realTagUrl.split('/')[-1].Trim('v')
			#$version
			$fileName = "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
			$realDownloadUrl = $realTagUrl.Replace('tag', 'download') + '/' + $fileName
			Write-Host "Installing the latest version of winget from:`n $realDownloadUrl"
			$DownloadLocation = $($env:temp)
			Write-Host "Downloading Desktop App Installer"
			If (-not (Get-Command -Name "Get-FileDownload" -ErrorAction SilentlyContinue)) {irm raw.githubusercontent.com/MauleTech/PWSH/refs/heads/main/LoadFunctions.txt | iex}
			$DownloadFileInfo = Get-FileDownload -URL $realDownloadUrl -SaveToFolder $($env:temp)
			$DownloadFilePath = $DownloadFileInfo[-1]
			Add-AppxPackage -Path $DownloadFilePath -ForceApplicationShutdown -InstallAllResources -Verbose
			#& $($Env:LOCALAPPDATA + "\Microsoft\WindowsApps\winget.exe") source reset w
			#& $($Env:LOCALAPPDATA + "\Microsoft\WindowsApps\winget.exe") source add --name winget --arg https://winget.azureedge.net/cache --type Microsoft.PreIndexed.Package
			Remove-Item -Path $DownloadFilePath -Force -ErrorAction SilentlyContinue
		}
	
		$GetWinGetDependancies = {
			Write-Host "Checking Dependancies"
			## C++ Runtime framework packages for Desktop Bridge - https://docs.microsoft.com/en-us/troubleshoot/cpp/c-runtime-packages-desktop-bridge#how-to-install-and-update-desktop-framework-packages
			## x86 version
			$Installed_X86_VCLibs = Get-AppxPackage | Where-Object {$_.Name -Match "Microsoft.VCLibs.140.00.UWPDesktop" -and $_.Architecture -Match "X86"}
			If (-not ($Installed_X86_VCLibs)) {
				$DownloadURL = 'https://aka.ms/Microsoft.VCLibs.x86.14.00.Desktop.appx'
				$DownloadLocation = "$env:TEMP\"
				$LocalFilePath = Join-Path -Path $DownloadLocation -ChildPath "Microsoft.VCLibs.x86.14.00.Desktop.appx"
				If (Test-Path $LocalFilePath) {Remove-Item -Path $LocalFilePath -Force -ErrorAction SilentlyContinue}
				Write-Host "Downloading $DownloadURL"
				$progressPreference = 'silentlyContinue'
				Invoke-WebRequest -Uri $DownloadURL -OutFile $LocalFilePath
				If ($PSVersionTable.PSEdition -eq "Core") {Import-module "Appx" -UseWindowsPowerShell}
				Write-Host "Installing $LocalFilePath"
				Add-AppxPackage -Path $LocalFilePath -ForceApplicationShutdown -InstallAllResources -Verbose
				Remove-Item -Path $LocalFilePath -Force -ErrorAction SilentlyContinue
			}
			## x64 version
			If ([Environment]::Is64BitOperatingSystem){
				$Installed_X64_VCLibs = Get-AppxPackage | Where-Object {$_.Name -Match "Microsoft.VCLibs.140.00.UWPDesktop" -and $_.Architecture -Match "X64"}
				If (-not ($Installed_X64_VCLibs)) {
					$DownloadURL = 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx'
					$DownloadLocation = "$env:TEMP\"
					$LocalFilePath = Join-Path -Path $DownloadLocation -ChildPath "Microsoft.VCLibs.x64.14.00.Desktop.appx"
					If (Test-Path $LocalFilePath) {Remove-Item -Path $LocalFilePath -Force -ErrorAction SilentlyContinue}
					Write-Host "Downloading $DownloadURL"
					$progressPreference = 'silentlyContinue'
					Invoke-WebRequest -Uri $DownloadURL -OutFile $LocalFilePath
					If ($PSVersionTable.PSEdition -eq "Core") {Import-module "Appx" -UseWindowsPowerShell}
					Write-Host "Installing $LocalFilePath"
					Add-AppxPackage -Path $LocalFilePath -ForceApplicationShutdown -InstallAllResources -Verbose
					Remove-Item -Path $LocalFilePath -Force -ErrorAction SilentlyContinue
				}
			}
			#Microsoft.UI.Xaml
			$Providers = (Get-PackageProvider).Name
			If ($Providers -NotContains "Nuget") {
				Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force -ErrorAction SilentlyContinue
			}
						# Check if running in the desktop version of PowerShell
			if ($PSVersionTable.PSEdition -eq "Desktop" -and (Get-Command -Name "Register-PackageSource" -ErrorAction SilentlyContinue)) {
				Register-PackageSource -Name nuget.org -Location https://www.nuget.org/api/v2 -ProviderName NuGet -Trusted -Force
				Write-Host "Registered nuget.org package source for desktop PowerShell."
			} elseif ($PSVersionTable.PSEdition -eq "Core" -and (Get-Command -Name "Register-PackageSource" -ErrorAction SilentlyContinue)) {
				Register-PackageSource -Name nuget.org -Location https://api.nuget.org/v3/index.json -ProviderName NuGet -Trusted -Force
				Write-Host "Registered nuget.org package source for PowerShell Core."
			} else {
				Write-Host "Register-PackageSource cmdlet not found. Ensure you are running this script in a compatible PowerShell environment."
			}

			Install-Package -Name 'Microsoft.UI.Xaml' -ProviderName Nuget -Force
		}
	
		If ($(whoami) -eq "nt authority\system") {
			Write-Error "Due to the AppX nature of Winget, you cannot run this as the system user"
		} ElseIf (!(Get-process -Name Explorer -IncludeUserName | Where-Object -Property UserName -EQ $(whoami))){
			Write-Error "Due to the AppX nature of Winget, you cannot install WinGet when running the command as a user that is not logged in"
		} Else {
	# Install WinGet
		If (Get-Command winget -ErrorAction SilentlyContinue) {
			Write-Host "WinGet is already installed."
			$WGVersion = winget -v
			
			$url = 'https://github.com/microsoft/winget-cli/releases/latest'
			$request = [System.Net.WebRequest]::Create($url)
			$response = $request.GetResponse()
			$realTagUrl = $response.ResponseUri.OriginalString
			$WGLatestLink = $realTagUrl.split('/')[-1].Trim('v')
			
			If ($WGVersion -match $WGLatestLink) {
				Write-Host "The installed version $WGVersion is up to date."winget source update
			} Else {
				Write-Host "The installed version $WGVersion is out of date."
				If ($PSVersionTable.PSEdition -eq "Core") {Powershell.exe -NonInteractive -Command '$GetWinGetDependancies;$GetWinGet'} Else {$GetWinGetDependancies | IEX ; $GetWinGet | IEX}
				$WGVersion2 = winget -v
				If ($WGVersion -notmatch $WGVersion2) {
					Write-Host "Winget $WGVersion2 installed successfully"
				} Else {
					Write-Error "Winget did not install successfully"
				}
			}
		} Else {
			Write-Host "WinGet is not installed."
			If ($PSVersionTable.PSEdition -eq "Core") {Powershell.exe -NonInteractive -Command $GetWinGetDependancies} Else {$GetWinGetDependancies | IEX}
			If ($PSVersionTable.PSEdition -eq "Core") {Powershell.exe -NonInteractive -Command $GetWinGet} Else {$GetWinGet | IEX}
			If (Get-Command winget -ErrorAction SilentlyContinue) {
				$WGVersion = winget -v
				Write-Host "Winget $WGVersion installed successfully"
			} Else {
				Write-Error "Winget did not install successfully"
			}
		}
	}
}

Function Install-WinGetApps {
	If (-not (Get-Command -Name "winget" -ErrorAction SilentlyContinue)) {Install-Winget}
	winget source update
	Winget install -e --id 7zip.7zip -h --accept-package-agreements --accept-source-agreements
	Winget install -e --id Google.Chrome -h --accept-package-agreements --accept-source-agreements
	Winget install -e --id Mozilla.FirefoxESR -h --accept-package-agreements --accept-source-agreements
	Winget install -e --id Zoom.Zoom -h --accept-package-agreements --accept-source-agreements
	Winget install -e --id Notepad++.Notepad++ -h --accept-package-agreements --accept-source-agreements
	Winget install -e --id Adobe.AdobeAcrobatReaderDC -h --accept-package-agreements --accept-source-agreements
	Winget install -e --id VideoLAN.VLC -h --accept-package-agreements --accept-source-agreements
	Winget install -e --id Microsoft.PowerShell -h --accept-package-agreements --accept-source-agreements
}

Function Install-WinRepairToolbox {
	Write-Host "Downloading Windows Repair Toolbox"
		$URL = 'https://windows-repair-toolbox.com/files/Windows_Repair_Toolbox.zip'
		$DLFolder = $ITFolder + '\Windows_Repair_Toolbox'
		$DLFilePath = $DLFolder + '\Windows_Repair_Toolbox.zip'
		$null = (New-Item -ItemType Directory -Force -Path $DLFolder)
		(New-Object System.Net.WebClient).DownloadFile($url, $DLFilePath)
	Write-Host "Expanding Windows Repair Toolbox"
		Expand-Archive -Path $DLFilePath -DestinationPath $DLFolder -Force
	Write-Host "Downloading Windows Repair Toolbox Customizations"
		$URL = 'https://download.ambitionsgroup.com/Software/Windows_Repair_Toolbox_Custom.zip'
		$CustomizationFilePath = $DLFolder + '\Windows_Repair_Toolbox_Custom.zip'
		$null = (New-Item -ItemType Directory -Force -Path $DLFolder)
		(New-Object System.Net.WebClient).DownloadFile($url, $CustomizationFilePath)
	Write-Host "Customizing Windows Repair Toolbox"
		Expand-Archive -Path $CustomizationFilePath -DestinationPath $DLFolder -Force
	Write-Host "Cleaning up downloaded files"
	Remove-Item -Path $DLFilePath -Force
	Remove-Item -Path $CustomizationFilePath -Force
	"& $($DLFolder + '\Windows_Repair_Toolbox.exe')" | Clip
	Write-Host "The command to launch Windows Repair Toolbox has been put in your clipboard."
}


# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUUx1ZLLoh7/Vjzi0epjx9iXmo
# z+mgggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUSt/G
# vQE58VjZvSmVcNNM931G3X0wDQYJKoZIhvcNAQEBBQAEggEAAQgzf2VhiugaYauC
# JOtTST19tGeTqFgv3QSHffF+ROjRA9kb3fcLXko3kCAGM6LUaqqBSkDHeg9nmBr6
# bcXgOq5hBTcnyidDqfp7dCTAOt69rF37GmJvBEUhejvRoIVNREqIEQ2r64Cjq0hC
# 2wGFJOmoyvyHkAFX34pMMN1ykYzfTdPwnZnAlIRSw7Ms7xDo1qSkdiIfWFQV15Kq
# Qmj1Vz/76Kj3Ayt+JW668VIaA8wbUV0pGfnV7IIVLrdGfZGVWUCbTXWcmg4+j99t
# 6VFj+EOYSkCl8uCZhNJotAOFD0BwRuXfh9MUuzciL5/laUy8QwV45bUjh3X9XpA7
# FA4ENQ==
# SIG # End signature block
