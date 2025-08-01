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
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUtIXu0cFmQAFU+b+kRlCuVfu1
# DY+gggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU6idW
# nc768kBjJBmAZfePgthOWrQwDQYJKoZIhvcNAQEBBQAEggEAS7PzKdT8x2ULWLaZ
# sf2DXDH63wTWNFEwQRtwUPNqH8I+/ly+R47DgTaeIvKlM7O12ovC2lz0DSWzM2UQ
# qxEVRstmnxPC2mbMvldjr+C5GlVMV8NQfMoJo/rH1wXA7E3KOEATxBVivi7sf8KZ
# GMPB/YLQtZM+1FS82s6W2yR9srWGwSVLX5QQPr+DmWfwgSVb+v12r4nLQZ42JE2l
# WWJgZcQcICozw3UpajZhTY73Ksh6z/GYa8JYlD2UUu5GdOp7pBJ/nAXbGfIBDPhC
# /4nBRdKbfoSnNd1hevUYp4C8Kt8LfUx7fl1FJTh47uRlpfyrsnvdSwEGg7DobEBC
# ax63wQ==
# SIG # End signature block
