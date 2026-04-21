Function Import-PPESenderLists {
	Function Export-PPEListsViaAPI {
		<#
		.REQUIREMENTS
			* API v1 from Proofpoint Essentials
			[Documentation: https://us1.proofpointessentials.com/api/v1/docs/specification.php]

			* Administrator Account for Proofpoint Essentials
				--Organization Admin
				--Channel Admin

		.DESCRIPTION
			This script is intended to use the API (v1) for Proofpoint Essentials to capture and export
			user and organization level Sender Lists in 4 separate CSV files.

		.INPUTS
			* Proofpoint Essentials Console Credentials
			* Domain that you are going to get Safe Sender information from
			* The Data Stack that the domain resides on. This is the beginning portion of your login site:
				(I.E. https://us2.proofpointessentials.com -- us2 would be the stack.)

		.OUTPUTS
			* This will output 4 files in the System Drive of your computer. These files will be located 
			in the following folder:
				** (SystemDrive, C for example) C:\Temp\SenderListExport\domain.com\

			* Files Generated from this script
				** UserSafeSenderList.csv
				** UserBlockedSenderList.csv
				** OrgSafeSender.csv
				** OrgBlockedSender.csv

		.NOTES
			Version:         1.0
			Creation Date:   4/8/2021

		.DISCLAIMER
			This script works in it's current form. Any alterations or adjustments made to this script
			will not be supported or eligible for troubleshooting support. This script is used for
			data gathering only. Proofpoint Essentials Support does not currently offer services
			to troubleshoot scripting solutions or script configurations. This is a working example of
			how the API can be utilized to get management information together for securing your 
			customers and enabling partners with new tools for information. 

		#>

		#Establish global parameters that will be used throughout the script.
		$Global:params = @{
			Domain      = ""
			Stack       = ""
			StackList   = ('us1','us2','us3','us4','us5','eu1')
			Headers     = ""
			Method      = 'GET'
			Body        = ""
			SMTP        = ""
			ContentType = 'application/json'
			FolderName  = ""
		}

		# This funciton will capture and prepare your credentials for the Proofpoint Essentials API.
		function Snag-Creds {
			#$domain = $Global:params.Domain
			$Creds = Get-Credential -Message "Enter your Credentials for Proofpoint Essentials."


			$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
			$headers.Add("X-User",($Creds).UserName)
			$headers.Add("X-Password",($Creds.GetNetworkCredential()).Password)

			$Global:params.Headers = $headers

		}

		# This function will take the parameters collected in the main script and use them to cycle through
		# the sender lists for the organization and each user within the provided domain.
		function Check-SafeSenderLists ($Pdomain) {
			$targetStack = $Global:params.Stack
			$targetDomain = $Pdomain
			$targetCompanyUsers = "https://$targetStack.proofpointessentials.com/api/v1/orgs/$targetDomain/users"
			$targetCompanyOrg = "https://$targetStack.proofpointessentials.com/api/v1/orgs/$targetDomain/"
			#$AllDomainCheck = '*@'


			$UserResponse = Invoke-RestMethod -Headers $Global:params.Headers -Uri $targetCompanyUsers -Method Get
			$OrgResponse = Invoke-RestMethod -Headers $Global:params.Headers -Uri $targetCompanyOrg -Method Get

			## Export User Safe Sender
			$Global:ExportFolder = "$ENV:SystemDrive\Temp\SenderListExport\$Pdomain"
			$UserSafeSenderList = "$Global:ExportFolder\UserSafeSenderList.csv"
			$UserBlockedSenderList = "$Global:ExportFolder\UserBlockedSenderList.csv"
			$UserSafeSender = @()
			$UserBlockedSender = @()
			IF (!(Test-Path $Global:ExportFolder)) {New-Item $Global:ExportFolder -ItemType Directory -Force}
			Write-Output "`nProcessing your request now..."
		## Exporting MULTI HashTable
			
			#Safe Sender Expansion for Users
			foreach ($item in $UserResponse.users) {
				$primary = $item.primary_email
				
				foreach ($WL in $item.white_list_senders) {
					$SafetyTest = $null
					IF ($WL -eq $primary) {$SafetyTest = "match"}
					IF ($WL -match '\*\@' -and $null -eq $SafetyTest) {$SafetyTest = "domain"}

					switch ($SafetyTest) {
						"match" {$UserSafeSender += @([pscustomobject]@{PrimaryEmail=$primary;Entry="$WL"});break}
						"domain" {$UserSafeSender += @([pscustomobject]@{PrimaryEmail=$primary;Entry="$WL"});break}
						default {$UserSafeSender += @([pscustomobject]@{PrimaryEmail=$primary;Entry="$WL"});break}
					}
				}
			
			foreach ($BL in $item.black_list_senders) {
			
					$SafetyTest = $null
					IF ($BL -eq $primary) {$SafetyTest = "match"}     
					IF ($BL -match '\*\@' -and $null -eq $SafetyTest) {$SafetyTest = "domain"}

					switch ($SafetyTest) {
						"match" {$UserBlockedSender += @([pscustomobject]@{PrimaryEmail=$primary;Entry="$BL"});break}
						"domain" {$UserBlockedSender += @([pscustomobject]@{PrimaryEmail=$primary;Entry="$BL"});break}
						default {$UserBlockedSender += @([pscustomobject]@{PrimaryEmail=$primary;Entry="$BL"});break}
					}
				}
			
			## Export ORG Safe Sender List
			$OrgSafeListLog = "$Global:ExportFolder\OrgSafeSender.csv"
			$OrgBlockedListLog = "$Global:ExportFolder\OrgBlockedSender.csv"
			$OrgSafeSender = @()
			$OrgBlockedSender = @()


		## Exporting MULTI HashTable
			#Safe Sender Expansion for Users
			$MainDomain = $OrgResponse.primary_domain
			foreach ($OWL in $OrgResponse.white_list_senders) {
				$OrgSafetyTest = $null
				IF ($OWL -match '\*\@') {$OrgSafetyTest = "domain"}

				switch ($OrgSafetyTest) {
					"domain" {$OrgSafeSender += @([pscustomobject]@{PrimaryDomain=$MainDomain;Entry="$OWL -- WARNING: ALL Domain Email listed as Safe Sender"});break}
					default {$OrgSafeSender += @([pscustomobject]@{PrimaryDomain=$MainDomain;Entry="$OWL"});break}
				}
			}

			foreach ($OBL in $OrgResponse.black_list_senders) {
				$OrgSafetyTest = $null
				IF ($OBL -match '\*\@') {$OrgSafetyTest = "domain"}

				switch ($OrgSafetyTest) {
					"domain" {$OrgBlockedSender += @([pscustomobject]@{PrimaryDomain=$MainDomain;Entry="$OBL -- WARNING: ALL Domain Email listed as Blocked Sender"});break}
					default {$OrgBlockedSender += @([pscustomobject]@{PrimaryDomain=$MainDomain;Entry="$OBL"});break}
				}
			}
			
			}

			$UserSafeSender | Export-Csv -Path $UserSafeSenderList -NoTypeInformation -Force
			$UserBlockedSender | Export-Csv -Path $UserBlockedSenderList -NoTypeInformation -Force
			$OrgSafeSender | Export-Csv -Path $OrgSafeListLog -NoTypeInformation -Force
			$OrgBlockedSender | Export-Csv -Path $OrgBlockedListLog -NoTypeInformation -Force
			
			#Open Explorer Window with new files inside.
			Invoke-Item $Global:ExportFolder
		}

		# This script will begin with a clean Powershell Window and walk through the credentials capture.
		Clear-Host
		Write-Output "Enter your credentials for Proofpoint.`n"
		Snag-Creds

		# This will enable you to select the domain that you wish to get information from.
		$TargetDomain = Read-Host -Prompt "Which domain are you going to pull sender lists from"

		# This is a security check which will only accept appropriate data stacks that we currently use.
		$Global:params.Stack = $null
		do {
			$Global:params.Stack = "us1" #(Read-Host "Which data stack are you accessing? (us1,us2,us3,us4,us5,eu1)").ToLower()
			} while ($Global:params.Stack -notin $Global:params.StackList)

		# This will execute the main program and generate the files within the selected directory. 
		Check-SafeSenderLists -Pdomain $TargetDomain
	}


	Function Test-User {
		Write-Host "Checking for a valid user"
		$Global:Mailbox = ($AllUserMailboxes | Where-Object -Property EmailAddresses -match $Global:User)
		If ($Mailbox) {
			$Global:User = $Mailbox.Alias
			$Global:Name = $Mailbox.DisplayName
			Write-Host "Mailbox for $Name was successfully found."
		} Else {
			<#$Mailbox = Get-ExoMailbox | Where-Object {($_.EmailAddresses -match $Global:User) -or ($_.PrimarySmtpAddress -match $Global:User)}#>
			If (-not $Mailbox) {
				Write-Host "Mailbox not found."
				#Break
			} ElseIf ($Mailbox.Count -gt 1) {
				Write-Host "Multiple mailboxes found. Please refine your search."
				#Break
			} ElseIf ($Mailbox) {
				$Global:User = $Mailbox.Alias
				$Global:Name = $Mailbox.DisplayName
				Write-Host "Mailbox for $Name was successfully found by secondary email address."
			}
		}
	}
	
	Function Test-Entries {
		Write-Host "Scanning for invalid entries"
		If ($Global:blocked) {
			$PreBlockedCount = $Global:blocked.count
			$Global:DomainList | ForEach-Object {$Global:blocked = $Global:blocked | Where-Object {$_ -notlike $('*@' + $_)}}
			$Global:blocked = $Global:blocked.Replace('*@','')
			$PostBlockedCount = $Global:blocked.count
		}
		
		If ($Global:trusted) {
			$PreTrustedCount = $Global:trusted.count
			$Global:DomainList | ForEach-Object {$Global:trusted = $Global:trusted | Where-Object {$_ -notlike $('*@' + $_)}}
			$Global:trusted = $Global:trusted.Replace('*@','')
			$PostTrustedCount = $Global:trusted.count
		}
		$TotalRemovedCount = $($PreBlockedCount - $PostBlockedCount) + $($PreTrustedCount - $PostTrustedCount)
		Write-Host "Removed $TotalRemovedCount invalid entries."
	}

	Function Import-Entries {
		#Check for empty lists
		#$Global:blocked | FT
		#$Global:trusted | FT
		If ([string]::IsNullOrWhiteSpace($Global:blocked)) {Clear-Variable blocked}
		If ([string]::IsNullOrWhiteSpace($Global:trusted)) {Clear-Variable trusted}
		$BadBlocked = @()
		$BadTrusted = @()
		Try {
			Write-Host "Attempting to configure all addresses at once."
			If ($Global:blocked -and $Global:trusted) {
				Write-Host "Blocked and Trusted Lists found, importing both."
				Set-MailboxJunkEmailConfiguration $Global:User -BlockedSendersAndDomains @{Add=$Global:blocked} -TrustedSendersAndDomains @{Add=$Global:trusted} -ContactsTrusted $false -ErrorAction Stop
			} elseif ($Global:blocked -and !($Global:trusted)) {
				Write-Host "Only Blocked list found, importing it."
				Set-MailboxJunkEmailConfiguration $Global:User -BlockedSendersAndDomains @{Add=$Global:blocked} -ErrorAction Stop
			} elseif (!($Global:blocked) -and $Global:trusted) {
				Write-Host "Only Trusted list found, importing it."
				Set-MailboxJunkEmailConfiguration $Global:User -TrustedSendersAndDomains @{Add=$Global:trusted} -ContactsTrusted $false -ErrorAction Stop
			} elseif (!($Global:blocked) -and !($Global:trusted)) {
				Write-Host "Neither a blocked list nor a trusted list found. Is there anything to import?"
			}
			Write-Host "It worked!"
			Get-MailboxJunkEmailConfiguration -Identity $Global:User | Format-Table Identity, TrustedSendersAndDomains, BlockedSendersAndDomains -AutoSize
		} Catch {
			Write-Host "That didn't work, trying one at a time."
			$CurrentSettings = Get-MailboxJunkEmailConfiguration -Identity $Global:User
			If ($Global:blocked) {
				$Global:blocked | ForEach-Object {
					Write-Host "Blocking: $_"
					$CurrentEmail = $_
					If ($CurrentSettings.BlockedSendersAndDomains -Contains $_){
						Write-Host -ForegroundColor Green "Already Blocked: $_"
					} Else {
						Try {
							Set-MailboxJunkEmailConfiguration $Global:User -BlockedSendersAndDomains @{Add=$_} -ErrorAction Stop
						} Catch {
							Write-Host -ForegroundColor Red "Failed to block: $_"
							$BadBlocked += $CurrentEmail
							Clear-Variable CurrentEmail
						}
					}
				}
			}
			If ($Global:trusted) {
				$Global:trusted | ForEach-Object {
					Write-Host "Trusting $_"
					$CurrentEmail = $_
					If ($CurrentSettings.TrustedSendersAndDomains -Contains $_){
						Write-Host -ForegroundColor Green "Already trusted: $_"
					} Else {
						Try {
							Set-MailboxJunkEmailConfiguration $Global:User -TrustedSendersAndDomains @{Add=$_} -ErrorAction Stop
						} Catch {
							Write-Host -ForegroundColor Red "Failed to trust: $_"
							$BadTrusted += $CurrentEmail
							Clear-Variable CurrentEmail
						}
					}
				}
			}
			Set-MailboxJunkEmailConfiguration $Global:User -ContactsTrusted $false
			$BadBlocked
			$BadTrusted
			Get-MailboxJunkEmailConfiguration -Identity $Global:User | Format-Table Identity, TrustedSendersAndDomains, BlockedSendersAndDomains -AutoSize
		}
	}
	Write-Host -NoNewLine "Create a new temporary organization admin account in the client`s account.`nNext, ensure you've connected to Exchange Online.`nWhen done, press any key to continue..."
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
	Export-PPEListsViaAPI
	$Directory = $Global:ExportFolder #Read-Host "Enter directory of exported files"
	Clear-Variable user,email,domain,blocked,trusted -Force -Scope Global -ea SilentlyContinue
	$Global:RawUserBlockedSenderList = Import-Csv -Path $($Directory + "\UserBlockedSenderList.csv")
	$Global:RawUserSafeSenderList = Import-Csv -Path $($Directory + "\UserSafeSenderList.csv")
	#Organization Wide List conversion and import
	$OrgSafeSenderFile = $($Directory + '\OrgSafeSender.csv')
	(Get-Content $OrgSafeSenderFile).replace('*@', '') | Set-Content $OrgSafeSenderFile
	(Get-Content $OrgSafeSenderFile).replace(' -- WARNING: ALL Domain Email listed as Safe Sender', '') | Set-Content $OrgSafeSenderFile
	$OrgBlockedSenderFile = $($Directory + '\OrgBlockedSender.csv')
	(Get-Content $OrgBlockedSenderFile).replace('*@', '') | Set-Content $OrgBlockedSenderFile
	(Get-Content $OrgBlockedSenderFile).replace(' -- WARNING: ALL Domain Email listed as Blocked Sender', '') | Set-Content $OrgBlockedSenderFile
	$Global:RawOrgBlockedSenderList = Import-Csv -Path $OrgBlockedSenderFile
	$Global:RawOrgSafeSenderList = Import-Csv -Path $OrgSafeSenderFile
	$OrgBlockedIndividualSenders = $($RawOrgBlockedSenderList | Where-Object -Property Entry -Match '@').Entry
	$OrgBlockedDomainSenders = $($RawOrgBlockedSenderList | Where-Object -Property Entry -NotMatch '@').Entry
	$OrgSafeIndividualSenders = $($RawOrgSafeSenderList | Where-Object -Property Entry -Match '@').Entry
	$OrgSafeDomainSenders = $($RawOrgSafeSenderList | Where-Object -Property Entry -NotMatch '@').Entry

	$Global:DomainList = (Get-AcceptedDomain).DomainName
	$Global:UserBlockedSenderList = $Global:RawUserBlockedSenderList
	$Global:UserSafeSenderList = $Global:RawUserSafeSenderList
	ForEach ($Domain in $Global:DomainList){$Global:UserBlockedSenderList = $Global:UserBlockedSenderList | Where-Object {$_.Entry -notlike $('*@' + $Domain)}}
	ForEach ($Domain in $Global:DomainList){$Global:UserSafeSenderList = $Global:UserSafeSenderList | Where-Object {$_.Entry -notlike $('*@' + $Domain)}}


	$Global:Users = ($Global:UserBlockedSenderList.PrimaryEmail + $Global:UserSafeSenderList.PrimaryEmail) | Sort-Object -Unique
	$Global:AllUserMailboxes = Get-Mailbox
	$Global:Users | ForEach-Object {
		$Global:Email = $_
		$Global:User = $Global:Email.Split("@")[0]
		#$Global:domain = $Global:Email.Split("@")[1]
		Write-Host "Processing: User= $Global:User"
		Test-User
		#$Global:blocked = @()
		#$Global:trusted = @()
		$Global:blocked = ($Global:UserBlockedSenderList | Where-Object {$_.PrimaryEmail -eq $Global:Email}).Entry
		$Global:trusted = ($Global:UserSafeSenderList | Where-Object {$_.PrimaryEmail -eq $Global:Email}).Entry
		Write-Host "There are $($Global:blocked.count) blocked entries and $($Global:trusted.count) trusted entries for $Global:User"
		#Test-Entries
		If ($Global:Mailbox){Import-Entries}
		Clear-Variable user,name,email,mailbox,domain,blocked,trusted -Force -Scope Global -ea SilentlyContinue
		Write-Host "`n`n"
	}

	Write-Host "Setting Organization Level sender lists."
	$ContentFilterPolicies = Get-HostedContentFilterPolicy
	If ($OrgBlockedIndividualSenders) {$ContentFilterPolicies | Set-HostedContentFilterPolicy -BlockedSenders $OrgBlockedIndividualSenders}
	If ($OrgBlockedDomainSenders) {$ContentFilterPolicies | Set-HostedContentFilterPolicy -BlockedSenderDomains $OrgBlockedDomainSenders}
	If ($OrgSafeIndividualSenders) {$ContentFilterPolicies | Set-HostedContentFilterPolicy -AllowedSenders $OrgSafeIndividualSenders}
	If ($OrgSafeDomainSenders) {$ContentFilterPolicies | Set-HostedContentFilterPolicy -AllowedSenderDomains $OrgSafeDomainSenders}

	$UserCount = $Global:Users.Count
	$TrustedCount = $Global:UserSafeSenderList.Count + $RawOrgSafeSenderList.Count
	$BlockedCount = $Global:UserBlockedSenderList.Count + $RawOrgBlockedSenderList.Count
	Write-Host "Processed $UserCount users, trusted $TrustedCount entries, and blocked $BlockedCount entries."
}

Function Import-PPESingleUserSenderLists {
	$Global:blocked = @()
	$Global:trusted = @()
	Function Read-InputBoxDialog([string]$Message, [string]$WindowTitle, [string]$DefaultText)
	{
		Add-Type -AssemblyName Microsoft.VisualBasic
		return [Microsoft.VisualBasic.Interaction]::InputBox($Message, $WindowTitle, $DefaultText)
	}
	Function Read-MultiLineInputBoxDialog() {
		param(
			[string]$Message,
			[string]$WindowTitle,
			[string]$DefaultText
		)

		Add-Type -AssemblyName System.Drawing
		Add-Type -AssemblyName System.Windows.Forms

		# Create the Label.
		$label = New-Object System.Windows.Forms.Label
		$label.Location = New-Object System.Drawing.Size(10,10)
		$label.Size = New-Object System.Drawing.Size(280,20)
		$label.AutoSize = $true
		$label.Text = $Message

		# Create the TextBox used to capture the user's text.
		$textBox = New-Object System.Windows.Forms.TextBox
		$textBox.Location = New-Object System.Drawing.Size(10,40)
		$textBox.Size = New-Object System.Drawing.Size(575,200)
		$textBox.AcceptsReturn = $true
		$textBox.AcceptsTab = $false
		$textBox.Multiline = $true
		$textBox.ScrollBars = 'Both'
		$textBox.Text = $DefaultText

		# Create the OK button.
		$okButton = New-Object System.Windows.Forms.Button
		$okButton.Location = New-Object System.Drawing.Size(415,250)
		$okButton.Size = New-Object System.Drawing.Size(75,25)
		$okButton.Text = "OK"
		$okButton.Add_Click({ $form.Tag = $textBox.Text; $form.Close() })

		# Create the Cancel button.
		$cancelButton = New-Object System.Windows.Forms.Button
		$cancelButton.Location = New-Object System.Drawing.Size(510,250)
		$cancelButton.Size = New-Object System.Drawing.Size(75,25)
		$cancelButton.Text = "Cancel"
		$cancelButton.Add_Click({ $form.Tag = $null; $form.Close() })

		# Create the form.
		$form = New-Object System.Windows.Forms.Form
		$form.Text = $WindowTitle
		$form.Size = New-Object System.Drawing.Size(610,320)
		$form.FormBorderStyle = 'FixedSingle'
		$form.StartPosition = "CenterScreen"
		$form.AutoSizeMode = 'GrowAndShrink'
		$form.Topmost = $True
		$form.AcceptButton = $okButton
		$form.CancelButton = $cancelButton
		$form.ShowInTaskbar = $true

		# Add all of the controls to the form.
		$form.Controls.Add($label)
		$form.Controls.Add($textBox)
		$form.Controls.Add($okButton)
		$form.Controls.Add($cancelButton)

		# Initialize and show the form.
		$form.Add_Shown({$form.Activate()})
		$form.ShowDialog() > $null   # Trash the text of the button that was clicked.

		# Return the text that the user entered.
		return $form.Tag
	}


	Function Test-Entries {
		Write-Host "Scanning for invalid entries"
		#$Global:domain = '*@' + $Global:domain
		$PreBlockedCount = $Global:blocked.count
		$Global:blocked = $Global:blocked | Where-Object {$_ -notlike $('*@' + $Global:domain)}
		$Global:blocked = $Global:blocked.Replace('*@','')
		$PostBlockedCount = $Global:blocked.count

		$PreTrustedCount = $Global:trusted.count
		$Global:trusted = $Global:trusted | Where-Object {$_ -notlike ('*@' + $Global:domain)}
		$Global:trusted = $Global:trusted.Replace('*@','')
		$PostTrustedCount = $Global:trusted.count
		$TotalRemovedCount = $($PreBlockedCount - $PostBlockedCount) + $($PreTrustedCount - $PostTrustedCount)
		Write-Host "Removed $TotalRemovedCount invalid entries."
	}


	Function Test-User {
		Write-Host "Checking for a valid user"
		$Mailbox = Get-Mailbox -Identity $User -ErrorAction SilentlyContinue
		If ($Mailbox) {
			$Global:Name = $Mailbox.DisplayName
			Write-Host "Mailbox for $Name was successfully found."
		} Else {
			$Mailbox = Get-ExoMailbox | Where-Object {($_.EmailAddresses -match $User) -or ($_.PrimarySmtpAddress -match $User)}
			If (-not $Mailbox) {
				Write-Host "Mailbox not found."
				#Break
			} ElseIf ($Mailbox.Count -gt 1) {
				Write-Host "Multiple mailboxes found. Please refine your search."
				#Break
			} ElseIf ($Mailbox) {
				$Global:User = $Mailbox.Alias
				$Global:Name = $Mailbox.DisplayName
				Write-Host "Mailbox for $Name was successfully found by secondary email address."
			}
		}
	}

	Function Import-Entries {
		#Check for empty lists
		If ([string]::IsNullOrWhiteSpace($blocked)) {Clear-Variable blocked}
		If ([string]::IsNullOrWhiteSpace($trusted)) {Clear-Variable trusted}
		$BadBlocked = @()
		$BadTrusted = @()
		Try {
			Write-Host "Attempting to configure all addresses at once."
			If ($blocked -and $trusted) {
				Write-Host "Blocked and Trusted Lists found, importing both."
				Set-MailboxJunkEmailConfiguration $User -BlockedSendersAndDomains @{Add=$blocked} -TrustedSendersAndDomains @{Add=$trusted} -ContactsTrusted $true -ErrorAction Stop
			} elseif ($blocked -and !($trusted)) {
				Write-Host "Only Blocked list found, importing it."
				Set-MailboxJunkEmailConfiguration $User -BlockedSendersAndDomains @{Add=$blocked} -ErrorAction Stop
			} elseif (!($blocked) -and $trusted) {
				Write-Host "Only Trusted list found, importing it."
				Set-MailboxJunkEmailConfiguration $User -TrustedSendersAndDomains @{Add=$trusted} -ContactsTrusted $true -ErrorAction Stop
			} elseif (!($blocked) -and !($trusted)) {
				Write-Host "Neither a blocked list nor a trusted list found. Is there anything to import?"
			}
			Write-Host "It worked!"
			Get-MailboxJunkEmailConfiguration -Identity $User | Format-Table Identity, TrustedSendersAndDomains, BlockedSendersAndDomains -AutoSize
		} Catch {
			Write-Host "That didn't work, trying one at a time."
			$CurrentSettings = Get-MailboxJunkEmailConfiguration -Identity $User
			$blocked | ForEach-Object {
				Write-Host "Blocking: $_"
				$CurrentEmail = $_
				If ($CurrentSettings.BlockedSendersAndDomains -Contains $_){
					Write-Host -ForegroundColor Green "Already Blocked: $_"
				} Else {
					Try {
						Set-MailboxJunkEmailConfiguration $User -BlockedSendersAndDomains @{Add=$_} -ErrorAction Stop
					} Catch {
						Write-Host -ForegroundColor Red "Failed to block: $_"
						$BadBlocked += $CurrentEmail
						Clear-Variable CurrentEmail
					}
				}
			}
			$trusted | ForEach-Object {
				Write-Host "Trusting $_"
				$CurrentEmail = $_
				If ($CurrentSettings.TrustedSendersAndDomains -Contains $_){
					Write-Host -ForegroundColor Green "Already trusted: $_"
				} Else {
					Try {
						Set-MailboxJunkEmailConfiguration $User -TrustedSendersAndDomains @{Add=$_} -ErrorAction Stop
					} Catch {
						Write-Host -ForegroundColor Red "Failed to trust: $_"
						$BadTrusted += $CurrentEmail
						Clear-Variable CurrentEmail
					}
				}
			}
			Set-MailboxJunkEmailConfiguration $User -ContactsTrusted $true
			$BadBlocked
			$BadTrusted
			Get-MailboxJunkEmailConfiguration -Identity $User | Format-Table Identity, TrustedSendersAndDomains, BlockedSendersAndDomains -AutoSize
		}
	}
	$Global:Email = Read-InputBoxDialog -Message "Please enter the user's email address:" -WindowTitle "Email Address"
	$Global:User = $Email.Split("@")[0]
	$Global:domain = $Email.Split("@")[1]
	$User
	$Global:domain
	Test-User
	$Global:blocked = (Read-MultiLineInputBoxDialog -Message "Please paste in the blocked senders for $Global:Name from Proofpoint" -WindowTitle "ProofPoint Blocked Senders") -split [System.Environment]::NewLine
	$Global:trusted = (Read-MultiLineInputBoxDialog -Message "Please paste in the Safe Sender List for $Global:Name from Proofpoint" -WindowTitle "ProofPoint Safe Senders") -split [System.Environment]::NewLine

	Test-Entries
	Import-Entries
	Clear-Variable user,email,domain,blocked,trusted -ea SilentlyContinue
}

Function Import-WindowsInstallerDrivers {
	param
	(
		[Parameter(Mandatory=$False)]
		$WorkingDirectory = $($Env:SystemDrive) + "\WinInstaller",

		[Parameter(Mandatory=$True)]
		[String]$USBDriveLetter
	)

	<#-----------------------------Folder Prep-----------------------------------#>

	#$WorkingDirectory = $($Env:SystemDrive) + "\WinInstaller"
	#[String]$USBDriveLetter = "P"
	$DriversDir = $($WorkingDirectory + "\Drivers")
	$UpdatesDir = $($WorkingDirectory + "\Updates")
	$MountDir = $($WorkingDirectory + "\Mount")
	$WIMBootDir = $($WorkingDirectory + "\WIM-Boot")
	$WimInstallDir = $($WorkingDirectory + "\WIM-Install")

	$NeededFolders = @(
		$WorkingDirectory
		$DriversDir
		$UpdatesDir
		$MountDir
		$WIMBootDir
		$WimInstallDir
	)

	If (Test-Path -Path $WorkingDirectory) {
		Write-Host "Cleaning up previous working directory if needed."
		If (Test-Path -Path $MountDir\* -ErrorAction SilentlyContinue) {
			Dismount-WindowsImage -Path $MountDir -Discard -Verbose -ErrorAction SilentlyContinue
		}
		Remove-PathForcefully -Path $WorkingDirectory -ErrorAction SilentlyContinue
	}

	Write-Host "Creating needed folders"
	$NeededFolders | ForEach-Object {
		If (!(Test-Path $_)) {
			$null = (New-Item -ItemType Directory -Force -Path $_)
		}
	}

	<#-----------------------------Driver Downloads-----------------------------------#>
	#Get Drivers
	#Write-Host "Downloading drivers from Intel"
	$DownloadedFiles = @()
	$URLs = @(
		#"https://www.intel.com/content/www/us/en/download/19512/intel-rapid-storage-technology-driver-installation-software-with-intel-optane-memory-10th-and-11th-gen-platforms.html"
		#"https://www.intel.com/content/www/us/en/download/720755/intel-rapid-storage-technology-driver-installation-software-with-intel-optane-memory-11th-and-12th-gen-platforms.html"
	)
	
	If (-not (Test-Path "${env:ProgramFiles}\7-Zip\7z.exe" -ErrorAction SilentlyContinue)) {
		Install-Choco
		Choco install 7zip -y
	}
	
	ForEach ($URL in $URLs) {
		Write-Host $URL
		$SourcePage = (Invoke-WebRequest -Uri $URL -UseBasicParsing).Content -split '\n'
		$PageLinkLines = ($SourcePage | Select-String -SimpleMatch ".exe"| Select-String -SimpleMatch "Licenses" -NotMatch).Line
		New-Variable -Name URLStrings -Value @() -Force
		$PageLinkLines | ForEach-Object {
			$URLStrings += ((Select-String '(http[s]?)(:\/\/)([^\s,]+)(?=")' -Input $($_.Replace(' ','%20'))).Matches.Value)
		}
		$URLStrings = $URLStrings | Where-Object {$_ -ne $Null}

		$URLStrings = $URLStrings | Where-Object {$_ -notmatch "html"}
		$URLStrings = $URLStrings | Sort-Object | Get-Unique
		ForEach ($URLString in $URLStrings){
			#$OutFile = $($DriversDir + "\" + $(Split-Path $URLString.Replace('%20','') -Leaf))
			$GUIFolder = $($DriversDir + "\Intel_" + (New-Guid).Guid)
			$DownloadFileInfo = Get-FileDownload -URL $URLString -SaveToFolder $GUIFolder
			$DownloadFileInfo
			$DownloadedFiles += $DownloadFileInfo[-1]
			#Extract .exe using 7zip
			& "${env:ProgramFiles}\7-Zip\7z.exe" x $DownloadFileInfo[-1] "-o$($GUIFolder)" -r -y
			Sleep 50
			#Extract content located in .text file, after renaming it to include not just an extension.
			Rename-Item -LiteralPath $((Get-ChildItem -Path $GUIFolder -Filter *.text).FullName) -NewName Content.text
			& "${env:ProgramFiles}\7-Zip\7z.exe" x "-o$GUIFolder" $((Get-ChildItem -Path $GUIFolder -Filter *.text).FullName) -y
			Clear-Variable OutFile -Force -ErrorAction SilentlyContinue
			Clear-Variable DownloadFileInfo -Force -ErrorAction SilentlyContinue
		}
		Clear-Variable URLStrings -Force -ErrorAction SilentlyContinue
	}

									
															 
  

	#Write-Host "Downloading drivers from Dell"
	$DellUrls = @(
	#"https://dl.dell.com/FOLDER08107340M/4/Intel-Rapid-Storage-Technology-Driver-and-Application_0F5G4_WIN64_19.2.0.1003_A01_03.EXE"
	#"https://dl.dell.com/FOLDER09445327M/3/Intel-Rapid-Storage-Technology-Driver-and-Application_88DXV_WIN64_18.7.6.1010_A05.EXE"
	)

	$DellUrls | ForEach-Object {
		#Add a '\' to the end of the folder only if needed.
		If ($DriversDir -notmatch '\\$'){	$DriversDir += '\'}
		$DownloadFileInfo = Get-FileDownload -URL $_ -SaveToFolder $DriversDir
		$FilePath = $DownloadFileInfo[-1]
		$ExtractPath = '"' + $DriversDir + $([System.IO.Path]::GetFileNameWithoutExtension($DownloadFileInfo[0])) + '"'
		Write-Host "& $FilePath /s /e=$ExtractPath"
		& $FilePath /s /e=$ExtractPath
		Clear-Variable DownloadFileInfo -Force -ErrorAction SilentlyContinue
	}

	<#-----------------------------Update Downloads-----------------------------------#>
	#Write-Host "Downloading updates from Windows"
	#$DownloadedFiles = @()
	$UpdateURLs = @(
		#"https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/d73b698e-6d66-4f6d-942e-6a980db92d07/public/windows11.0-kb5023778-x64_204c2f5ab1eb71d80eb470b5af079dd8e56c20e7.msu"
	)
	Write-Host -ForegroundColor Yellow "DOWNLOADS NEEDED`n - Make sure you're aware of which version of Windows you're working with, i.e. ""Windows 11 24H2 x64"".`n - Head to https://www.catalog.update.microsoft.com/Search.aspx `n - Do a search for that version + ""Cumulative x64"" i.e. Windows 11 24H2 Cumulative x64.`n - Identify the latest and download it."
	$UpdateURLs | ForEach-Object {
		Get-FileDownload -URL $_ -SaveToFolder $UpdatesDir
	}

	Write-Host -NoNewLine "Please add any manual drivers to $DriversDir`nPlease add the latest Windows cumulative update to $UpdatesDir`nPress any key to continue...";
	$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');

	#Get USB drive BOOT WIM
	$Global:BootWimPath = $($USBDriveLetter + ":\sources\boot.wim")
	If (-Not (Test-Path -Path $BootWimPath -ErrorAction SilentlyContinue)) {
		Do {
			Write-host "$BootWimPath is not valid. Please select a drive letter that has a Windows Installer on it"
			Get-Volume | Where-Object -Property DriveType -eq Removable | Select-Object DriveLetter,FileSystemLabel | Out-Host
			$USBDriveLetter = Read-Host "Drive Letter of Windows USB Installer:"
			$BootWimPath = $($USBDriveLetter + ":\sources\boot.wim")
		} Until (Test-Path -Path $BootWimPath -ErrorAction SilentlyContinue)
	}

	
	#Move Boot File from USB to local Computer
	Write-Host "`n`nCopying Boot.wim to local computer for processing"
	$WIMBootWorkingFile = $WIMBootDir + "\boot.wim"
	Write-Host "Copy-Item -Path $BootWimPath -Destination $WIMBootWorkingFile -Force"
	Copy-Item -Path $BootWimPath -Destination $WIMBootWorkingFile -Force

<#-----------------------------Process drivers for boot.wim (windows installer)-----------------------------------#>
	$Index = (Get-WindowsImage -ImagePath $WIMBootWorkingFile)
	$Index | ForEach-Object {
		Write-Host "Mounting Boot Image Index $($_.ImageIndex) - $($_.ImageName)"
		Mount-WindowsImage -Path $MountDir -ImagePath $WIMBootWorkingFile -Index $($_.ImageIndex)
		Write-Host "Adding Drivers"
		Add-WindowsDriver -Path $MountDir -Driver $DriversDir -Recurse -ForceUnsigned -Verbose
		#Write-Host "Adding Updates"
		#Add-WindowsPackage -Path $MountDir -PackagePath $UpdatesDir -Verbose
		Write-Host "Dismounting Boot Image Index $($_.ImageIndex) - $($_.ImageName)"
		Dismount-WindowsImage -Path $MountDir -Save
		Start-Sleep 1
	}
	Write-Host "Copying completed Boot.wim back to USB drive"
	Write-Host "Copy-Item -Path $WIMBootWorkingFile -Destination $BootWimPath -Force"
	Copy-Item -Path $WIMBootWorkingFile -Destination $BootWimPath -Force


<#-----------------------------Process drivers and updates for install.wim (windows image)-----------------------------------#>
	#Move Install.wim File from USB to local Computer
	$Global:InstallEsdPath = $($USBDriveLetter + ":\sources\install.esd")
	$Global:InstallWimPath = $($USBDriveLetter + ":\sources\install.wim")
	Write-Host "Copying install.(esd/wim) to local computer for processing"
	$EsdInstallWorkingFile = $WimInstallDir + "\install.esd"
	$WIMInstallWorkingFile = $WimInstallDir + "\install.wim"

	#Test for different file types
	If (Test-Path -Path $InstallWimPath -ErrorAction SilentlyContinue) {
		Write-Host "Copy-Item -Path $InstallWimPath -Destination $WIMInstallWorkingFile -Force"
		Copy-Item -Path $InstallWimPath -Destination $WIMInstallWorkingFile -Force
	} Else {
		$ConverToEsd = $True
		Write-Host "Copy-Item -Path $InstallEsdPath -Destination $EsdInstallWorkingFile -Force"
		Copy-Item -Path $InstallEsdPath -Destination $EsdInstallWorkingFile -Force
		$Image = (Get-WindowsImage -ImagePath $EsdInstallWorkingFile | Where-Object -Property ImageName -notmatch " N" | Where-Object -Property ImageName -notmatch "Education" | Where-Object -Property ImageName -notmatch "Single Language")[-1]
		Write-Host "Converting ESD file to WIM file"
		$Image | ForEach-Object {
			Write-Host "Exporting Image $($_.ImageIndex) of $($Image.count)Dism"
			<#Try { #Dont use the Powershell equivalent of "dism /export-image" as it'll cause errors when importing drivers.
				Export-WindowsImage -SourceImagePath $EsdInstallWorkingFile -SourceIndex $($_.ImageIndex) -DestinationImagePath $WIMInstallWorkingFile -CheckIntegrity
			} Catch { #>
				dism /export-image /SourceImageFile:$EsdInstallWorkingFile /SourceIndex:$($_.ImageIndex) /DestinationImageFile:$WIMInstallWorkingFile /Compress:max /CheckIntegrity
			#}
		}
	}

	$Image = (Get-WindowsImage -ImagePath $WIMInstallWorkingFile | Where-Object -Property ImageName -notmatch " N" | Where-Object -Property ImageName -notmatch "Education" | Where-Object -Property ImageName -notmatch "Single Language")
	$Image | ForEach-Object {
		Write-Host "Mounting Install Image Index $($_.ImageIndex) - $($_.ImageName)"
		Mount-WindowsImage -Path $MountDir -ImagePath $WIMInstallWorkingFile -Index $($_.ImageIndex)
		Write-Host "Adding Drivers"
		Add-WindowsDriver -Path $MountDir -Driver $DriversDir -Recurse -ForceUnsigned -Verbose
		Write-Host "Adding Updates"
		Add-WindowsPackage -Path $MountDir -PackagePath $UpdatesDir -Verbose
		Write-Host "Dismounting Install Image Index $($_.ImageIndex) - $($_.ImageName)"
		Dismount-WindowsImage -Path $MountDir -Save
		Start-Sleep 1
	}

	If ($ConverToEsd) {
		Remove-Item -Path $ESDInstallWorkingFile -Force
		$Image = (Get-WindowsImage -ImagePath $WIMInstallWorkingFile)
		Write-Host "Converting WIM file back to ESD file"
		$Image | ForEach-Object {
			Write-Host "Exporting Image $($_.ImageIndex) of $($Image.count)Dism"
			<#Try { #Dont use the Powershell equivalent of "dism /export-image" as it'll cause errors when importing drivers.
				Export-WindowsImage -SourceImagePath $EsdInstallWorkingFile -SourceIndex $($_.ImageIndex) -DestinationImagePath $WIMInstallWorkingFile -CheckIntegrity
			} Catch { #>
				dism /export-image /SourceImageFile:$WIMInstallWorkingFile /SourceIndex:$($_.ImageIndex) /DestinationImageFile:$ESDInstallWorkingFile /Compress:recovery /CheckIntegrity
			#}
		}
		Write-Host "Copying completed Install.esd back to USB drive"
		Copy-Item -Path $ESDInstallWorkingFile -Destination $InstallEsdPath -Force
	} Else {
		Write-Host "Copying completed Install.wim back to USB drive"
		Copy-Item -Path $WIMInstallWorkingFile -Destination $InstallWimPath -Force
	}

	Write-Host "Copying completed Boot.wim back to USB drive"
	Copy-Item -Path $WIMBootWorkingFile -Destination $BootWimPath -Force
}

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAmeXM1c/4pWgxA
# n6NmayI/mwQZYyPGuk2SOgqg9mn1EaCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IAZriaSWXCWovrch1W0NsM1Dl3RKDIYj5XyaPqlGNyb1MA0GCSqGSIb3DQEBAQUA
# BIICAIbPClZ+xEwofyZs50weC4nd6S8ZLHo0se0FbqHQspJ/wjL4TthsEYC92XYu
# YTtJy54lEaeQiNjqszgq5sqhvR1Jnq0dLXetj+lCm+7eP5iLcyXCFWDKpvdO0nEK
# X0/WFd24hxtd36gvoeADUqJz3qsHcJwtdQjdkLbI0Xd/CvkD9s7l84xV+gk14Xw3
# IWm58Fwm72eAfpT6OUZfgVcEf+UFq1AhBIhsrprInjjpAfUsIeXPwZftq2oYcHQw
# mcL+399nasf4tyDb4ymhQlpInn00fhYjDiaMhthjj/1dH7ATRTUQNpEcgR6bS7Fx
# uEEB2wZ/Pk6dSPO08tSXDASjQJC10+rcqcsZZf+s04dbBhRFEW8F7AWqONSEzpks
# 0MeekGFF0+jedB0dSRltJeYGNZqmtxY+YyqF5RXxpE6SKsoUkromRYXklEgfRHGy
# s+K6DGvh4upnICRcMwg5WPH6Q6hX/syjqDc7eJJQBHqCjj1O9e5sVmnDjDO4Zw9o
# N54IxAU/dlH3xsaf1ynNiuzj4emgeJEuPCts7vssj6fBnvtLhjZHkRiHsM8jK1Mb
# avmRsopWlq7mboVxTpvpgukpCH0JBUCMJHEkjkli64PjOkk+m1RWe4HVSocn8wO6
# GVlKYm/UXgF6hhc6qheyZKMjqKZYguqykj3+RTIJ1sahXpfvoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDQyMTE4MDMzNlowLwYJKoZIhvcNAQkEMSIEIMrAWt/6
# V1xbinc0a7sWmiU1IJNQihs4C7wDyZS32nd0MA0GCSqGSIb3DQEBAQUABIICAEid
# dWKIBqXJKGa45L9Y11LNH9zR/wY4R+W5/aqSJLuPx+xg240hsl2m++sJHVcRGJMu
# bOF1n8YJfWGaCnEpOmZahU9ebn3LN4XXF+S8XbZxWoXDfT15UkvUIrn5YTCjqWN6
# Q26wWz6WPABGTn4/ijBBvWC+NlwIyK+T06Yg5UXYqFFVVJzPpT/Co5DZE5hGbBo1
# Km++4IFkQ2ctW7s+FJemp8ZOShI3ctIPbXg5An69M9Tbs9njoUqjzCDbs8i1WAHh
# RJtpQL8pUHLu9HVGE+wQ9u2Zdj9pFOCaoDbJ7jj/sELnn7JRdsYZX67mr21r/94e
# M+YbiBYgEDsF4n3XpgIu5O4zqVzDzGknTaEckLGuQZK6gKSQKCKdBDwnyydABtdG
# c8ysgY/+VAaDBnyjXPxd+UBvNRm+9IvmIGrAvXPuoxtM692K1s2l3pmE5EYyP/tt
# o/Cl0n3f+8De3Iw9s58lMceHZ3Zg3L/sA8ey/oJErNy9PFP2oQRwhnlKKu9TIB8w
# DXOSa0mL94a0Cp2yQUPFstxOI4NR0ljQyvciu9fFyGuS1vymIdm9aGZW08ivom7U
# sll1eMG3y+01PBzrt4+Wn9sXB00IneA6k29CinrdET38qRPDFSd9fe+JOpfdfD9k
# 43GGu4Zl2JYKKUt6nR79pAKvAERT2K5/Hb+i1XZZ
# SIG # End signature block
