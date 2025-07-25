# Partner Center Manual Download - https://github.com/microsoft/Partner-Center-PowerShell/archive/refs/heads/master.zip
Write-Host "Checking Module Status: MS PartnerCenter"
If (!(Get-Module PartnerCenter)) {
	# Check if the Azure AD PowerShell module is installed.
	If ( Get-Module -ListAvailable -Name PartnerCenter ) {
		Write-Host -ForegroundColor Green "Loading the Azure AD PowerShell module..."
		Import-Module PartnerCenter
		Start-Sleep 2
	} Else {
		Install-Module PartnerCenter
		Start-Sleep 2
	}
	If (!(Get-Module PartnerCenter)){
		Write-Host "Module MS PartnerCenter appears to be failing to install"
		Write-Host "Try updating PowerShellGet with the command: Install-Module -Name PowerShellGet -Force -AllowClobber"
	} Else {
		Write-Host "MS PartnerCenter Module Loaded"
	}
} Else {
	Write-Host "MS PartnerCenter Module Loaded"
}

# Check if the Azure AD PowerShell module has already been loaded.
Write-Host "Checking Module Status: Azure AD"
If (!(Get-Module AzureAD)) {
	# Check if the Azure AD PowerShell module is installed.
	If ( Get-Module -ListAvailable -Name AzureAD ) {
		Write-Host -ForegroundColor Green "Loading the Azure AD PowerShell module..."
		Import-Module AzureAD
		Start-Sleep 2
	} Else {
		Install-Module AzureAD
		Start-Sleep 2
	}
	If (!(Get-Module AzureAD)){
		Write-Host "Module AzureAD appears to be failing to install"
		Write-Host "Try updating PowerShellGet with the command: Install-Module -Name PowerShellGet -Force -AllowClobber"
	} Else {
		Write-Host "Azure AD PowerShell Module Loaded"
	}
} Else {
	Write-Host "Azure AD PowerShell Module Loaded"
}

Write-Host "Checking Module Status: MSolService"
If (!(Get-Module MSOnline)) {
	# Check if the Azure AD PowerShell module is installed.
	If ( Get-Module -ListAvailable -Name MSOnline ) {
		Write-Host -ForegroundColor Green "Loading the MSolService module..."
		Import-Module MSOnline
		Start-Sleep 2
	} Else {
		Install-Module MSOnline
		Start-Sleep 2
	}
	If (!(Get-Module MSOnline)){
		Write-Host "Module MSOnline appears to be failing to install"
		Write-Host "Try updating PowerShellGet with the command: Install-Module -Name PowerShellGet -Force -AllowClobber"
	} Else {
		Write-Host "MSOnline Module Loaded"
	}
} Else {
	Write-Host "MSOnline Module Loaded"
}

#Modern Auth and Unattended Scripts in Exchange Online PowerShell V2
#https://techcommunity.microsoft.com/t5/exchange-team-blog/modern-auth-and-unattended-scripts-in-exchange-online-powershell/ba-p/1497387

<#Write-Host "Checking Module Status: AdminToolbox.Office365"
If (!(Get-Module AdminToolbox.Office365)) {
	# Check if the Azure AD PowerShell module is installed.
	If ( Get-Module -ListAvailable -Name AdminToolbox.Office365 ) {
		Write-Host -ForegroundColor Green "Loading the AdminToolbox.Office365 module..."
		Import-Module AdminToolbox.Office365
		Start-Sleep 2
	} Else {
		Install-Module AdminToolbox.Office365
		Start-Sleep 2
	}
	If (!(Get-Module AdminToolbox.Office365)){
		Write-Host "Module AdminToolbox.Office365 appears to be failing to install"
		Write-Host "Try updating PowerShellGet with the command: Install-Module -Name PowerShellGet -Force -AllowClobber"
	} Else {
		Write-Host "AdminToolbox.Office365 Module Loaded"
	}
} Else {
	Write-Host "AdminToolbox.Office365 Module Loaded"
}#>

Write-Host "Importing Function Get-MFAStatus"
	#iwr https://raw.githubusercontent.com/ruudmens/LazyAdmin/master/Office365/MFAStatus.ps1 -useb | iex
	#Current version as of SEP2021 gives error, below link calls previous version.
	iwr https://raw.githubusercontent.com/ruudmens/LazyAdmin/feb452cdccf575f6e129c0a162591f29f57dc4b5/Office365/MFAStatus.ps1 -useb | iex


Function Connect-MsolServiceIfNeeded {
	If(-Not (Get-MsolDomain -ErrorAction SilentlyContinue))
	{
		Connect-MsolService
		Get-MsolDomain
	}
}
Function O365Audit {
<#
	O365 Environment Scripting T20200915.0046 - O365 Environment Scripting | Research Project
	Family of Commands
	Audit what is set/not set
	On Demand Audits
	Audit to Reports/Dashboard
	Script Location – Knowledgebase
	IT Glue Document
	Git Hub script locations
	Settings we want to set O365
	Standards
+	Enable Audit Logs – set 365 days - https://o365reports.com/2020/01/21/enable-mailbox-auditing-in-office-365-powershell/#Enable-Mailbox-Auditing-by-Default
	MFA Confirmation
	Block Basic Auth
	Deleted Items Retention to max (30 day)
	Disables all shared mailbox sign-in?
	Alerting and Reporting
	Periodic confirmation that standards stay set
	Logins – Foreign Country, Excessive Failure
	Forward to External Addresses
	Deleted item deletion
	Auto-move/delete rules
	Sharepoint Site Creation
	Upload of .aspx, other formats?
	Quality of Life
	Junk Email Filter disable
	Spam Filter ProofPoint replacement
	Spam Filter
	Email Encryption
	Data protection policy (PII, HIPAA)
	URL Protection
#>
$OrgConfig = Get-OrganizationConfig
$OrgName = $OrgConfig.DisplayName

Function O365-AuditSettings {
	Write-Host "Enable Audit Logs – set 365 days"
	Write-Host "Checking Mailbox Audit Settings"
	$OrgAuditDisabled = $OrgConfig.AuditDisabled
	$MailboxesAuditBypassed = Get-MailboxAuditBypassAssociation -ResultSize Unlimited | Select Identity,WhenCreated,AuditBypassEnabled | Where {$_.AuditBypassEnabled -eq $True}
	$PerMailboxAuditSettings = Get-MailBox * | Select Identity,AuditEnabled,AuditLogAgeLimit

	If ($OrgAuditDisabled) {
		Write-Host "[BAD] $OrgName does not have organization wide auditing enabled."
		Do {
			$Answer = Read-Host -Prompt 'Do you want to enable organization wide auditing? (y/n)'
			If (!($Answer -match 'y' -or $Answer -match 'n')) {Write-Host 'Please answer "y" for Yes or "n" for No.'}
		}
		Until ($Answer -match 'y' -or $Answer -match 'n')
		If ($Answer -match 'y') {
			Write-Host "Enabling organization wide auditing with the command: Set-OrganizationConfig -AuditDisabled $False -Verbose"
			Set-OrganizationConfig -AuditDisabled $False -Verbose
			Get-OrganizationConfig | Select AuditDisabled
		}
	} Else {
		Write-Host "[GOOD] $OrgName does have organization wide auditing enabled."
		If ($MailboxesAuditBypassed) {
			Write-Host "[BAD] However, the following user(s) have a bypass on the audit:`n $MailboxesAuditBypassed"
			Do {
				$Answer = Read-Host -Prompt 'Do you want to enable auditing on all of these accounts? (y/n)'
				If (!($Answer -match 'y' -or $Answer -match 'n')) {Write-Host 'Please answer "y" for Yes or "n" for No.'}
			}
			Until ($Answer -match 'y' -or $Answer -match 'n')
			If ($Answer -match 'y') {
				Write-Host "[GOOD] Enabling auditing on all of these accounts with the command: Set-MailboxAuditBypassAssociation –Identity <Identity> -AuditBypassEnabled $false"
				$MailboxesAuditBypassed | ForEach-Object {Set-MailboxAuditBypassAssociation –Identity $_.Identity -AuditBypassEnabled $false}
			} Else {
				Write-Host "[INFORM] If you wish to enable auditing on any of these accounts, use the command:`n`tSet-MailboxAuditBypassAssociation –Identity <Identity> -AuditBypassEnabled $false"
			}
		} Else {
			Write-Host "[GOOD] No users have a bypass enabled."
		}
	}

	$EnabledAuditMailBoxes = $PerMailboxAuditSettings | Where-Object {$_.AuditEnabled -eq $True}
	$ShortAuditAgeMailboxes = $EnabledAuditMailBoxes | Where-Object {[int]($_.AuditLogAgeLimit).Split(".")[0] -lt 365}
	Write-Host "There are $(($EnabledAuditMailBoxes).Count) mailboxes with Audit enabled"
	If ($ShortAuditAgeMailboxes) {
		Write-Host "[BAD] There are $(($ShortAuditAgeMailboxes).Count) mailboxes with an audit age limit less then 1 year"
		Do {
			$Answer = Read-Host -Prompt 'Do you want to extend the audit age limit on all of these accounts? (y/n)'
			If (!($Answer -match 'y' -or $Answer -match 'n')) {Write-Host 'Please answer "y" for Yes or "n" for No.'}
		}
		Until ($Answer -match 'y' -or $Answer -match 'n')
		If ($Answer -match 'y') {
			Write-Host "[GOOD] Extending the audit age limit to 365 days on all of these accounts with the command:`n`tSet-Mailbox –Identity <Identity> –AuditLogAgeLimit 365"
			$ShortAuditAgeMailboxes | ForEach-Object {Set-Mailbox –Identity $_.Identity –AuditLogAgeLimit 365}#;$newMailbox = Get-Mailbox -Identity "$_.Identity" | Select Identity,AuditEnabled,AuditLogAgeLimit; Write-Host "$($newMailbox.Identity) has now been set to an age limit of $(($newMailbox.AuditLogAgeLimit).Split(".")[0]) days"; $newMailbox = $Null}
		} Else {
			Write-Host "[INFORM] If you wish to Extend the audit age limit to 365 days on any of these accounts with the command:`n`tSet-Mailbox –Identity <Identity> –AuditLogAgeLimit 365"
		}
	} ELSE {
		Write-Host "[GOOD] There are no mailboxes with an audit age limit less then 1 year"
	}
}


Function O365-MFA {
	If ((Get-MsolDomain).Authentication -Match "Federated")) {
		Write-Host [Info] A domain is Federated, which may mean that it is protected by DUO MFA.
	}
	#https://lazyadmin.nl/powershell/list-office365-mfa-status-powershell/
	If ((Get-OrganizationConfig).OAuth2ClientProfileEnabled -eq $True) {
		Write-Host "[GOOD] MFA is enabled for the Organization."
	} Else {
		Write-Host "[BAD] MFA is not enabled for the Organization."
	}

	Write-Host "Checking MFA status of Admins."
	$MFAAdminsList = Get-MFAStatus -adminsOnly
	$MFAAdminsListCount = ($MFAAdminsList).Count
	$MFAAdminsListDisabled = $MFAAdminsList | Where-Object -Property MFAEnabled -eq $False
	$MFAAdminsListDisabledCount = ($MFAAdminsListDisabled).Count
	If ($MFAAdminsListDisabled) {
		Write-Host "[BAD] There are $MFAAdminsListCount admins and $MFAAdminsListDisabledCount of them do not have MFA enabled."
	} Else {
		Write-Host "[GOOD] All admins have MFA enabled."
	}

	Write-Host "Checking MFA status of licensed users."
	$MFAUsersList = Get-MFAStatus -IsLicensed
	$MFAUsersListDisabled = $MFAUsersList | Where-Object -Property MFAEnabled -eq $False
}

#https://www.itpromentor.com/block-basic-auth/
#https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online#modify-authentication-policies
#https://docs.microsoft.com/en-us/powershell/module/exchange/set-authenticationpolicy?view=exchange-ps
Function O365-BasicAuth {
	#Connect-O365Exchange if needed.
	If (!(Get-AuthenticationPolicy)) {
		Write-Host "[BAD] An org wide Authentication policy does not exist."
		Do {
			$Answer = Read-Host -Prompt 'Do you want to create an org wide Authentication policy? (y/n)'
			If (!($Answer -match 'y' -or $Answer -match 'n')) {Write-Host 'Please answer "y" for Yes or "n" for No.'}
		}
		Until ($Answer -match 'y' -or $Answer -match 'n')
		If ($Answer -match 'y') {
			Write-Host "[GOOD] Creating an org wide Authentication policy."
			New-AuthenticationPolicy -Name "Block Basic Auth"
			Set-AuthenticationPolicy -Identity "Block Basic Auth" -AllowBasicAuthPop:$false -AllowBasicAuthImap:$false -AllowBasicAuthMapi:$false -AllowBasicAuthOfflineAddressBook:$false -AllowBasicAuthOutlookService:$false -AllowBasicAuthPowershell:$false -AllowBasicAuthReportingWebServices:$false -AllowBasicAuthRpc:$false -AllowBasicAuthSmtp:$false -AllowBasicAuthWebServices:$false
			Set-OrganizationConfig -DefaultAuthenticationPolicy “Block Basic Auth”
			Write-Host "[INFORM] If you need to create an exception policy for some accounts: https://www.itpromentor.com/block-basic-auth/"
		} Else {
			Write-Host "[INFORM] If you wish to set up an org wide Authentication policy manually, check out these links:"
			Write-Host '          https://www.itpromentor.com/block-basic-auth/'
			Write-Host '          https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online#modify-authentication-policies'
			Write-Host '          https://docs.microsoft.com/en-us/powershell/module/exchange/set-authenticationpolicy?view=exchange-ps'
		}
	}
}

#Deleted Items Retention to max (30 day)
Function O365-ItemRetention {
	Write-Host "[INFO] Checking retention settings for each mailbox."
	$Retention = Get-Mailbox -ResultSize unlimited | Select-Object Name,Alias,RetainDeletedItemsFor | Where {$_.Alias -notlike "*DiscoverySearchMailbox*"}
	$RetentionNotMax = $Retention | Where-Object -Property "RetainDeletedItemsFor" -lt 30
	If ($RetentionNotMax){
		Write-Host "[BAD] $($RetentionNotMax.Count) mailboxes were found with less then 30 days retention."
		Do {
			$Answer = Read-Host -Prompt 'Do you want to expand the retention on these mailboxes? (y/n)'
			If (!($Answer -match 'y' -or $Answer -match 'n')) {Write-Host 'Please answer "y" for Yes or "n" for No.'}
		}
		Until ($Answer -match 'y' -or $Answer -match 'n')
		If ($Answer -match 'y') {
			Write-Host "[GOOD] Extending the mailbox retention time to 30 days for all mailboxes."
			$RetentionNotMax.Alias | Set-Mailbox -RetainDeletedItemsFor 30
		} Else {
			Write-Host "[INFORM] If you wish to manually adjust the retention time, check out this link:"
			Write-Host '          https://docs.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-user-mailboxes/change-deleted-item-retention'
		}
	} Else {
		Write-Host "[GOOD] All mailboxes are set to 30 days (the max)."
	}
}

#Disables all shared mailbox sign-in?
Function O365-DisableSharedMailboxSignin {
	#Needs ExchangeOnline and MSOLService
	$SharedMailboxes = Get-EXOMailbox -Filter {recipienttypedetails -eq "SharedMailbox"} | get-MsolUser | Select-Object UserPrincipalName,blockcredential
	$SignInEnabledSharedMailboxes = $SharedMailboxes | Where {$_.BlockCredential -eq $False}
	If ($SignInEnabledSharedMailboxes) {
		Write-Host "[BAD] $($SignInEnabledSharedMailboxes.Count) shared mailboxes were found with signin enabled."
		Do {
			$Answer = Read-Host -Prompt 'Do you want to disable signin for all shared mailboxes? (y/n)'
			If (!($Answer -match 'y' -or $Answer -match 'n')) {Write-Host 'Please answer "y" for Yes or "n" for No.'}
		}
		Until ($Answer -match 'y' -or $Answer -match 'n')
		If ($Answer -match 'y') {
			Write-Host "[GOOD] Disabling signin for all shared mailboxes."
			$SignInEnabledSharedMailboxes.UserPrincipalName | ForEach-Object { Set-MsolUser -UserPrincipalName $_ -BlockCredential $true}
		} Else {
			Write-Host "[INFORM] If you wish to manually disable signin for shared mailboxes, check out this link:"
			Write-Host '          https://techcommunity.microsoft.com/t5/exchange/list-shared-mailboxes-with-signin-enabled-and-then-block-signin/m-p/1405264'
		}
	} Else {
		Write-Host "[GOOD] No shared mailboxes were found with signin enabled."
	}
}
