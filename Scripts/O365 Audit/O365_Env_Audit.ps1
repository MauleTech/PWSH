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
	#Forked to MauleTech to control upstream changes
	iwr https://raw.githubusercontent.com/MauleTech/LazyAdmin/feb452cdccf575f6e129c0a162591f29f57dc4b5/Office365/MFAStatus.ps1 -useb | iex


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

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBMExZmY609rIhA
# +CSykca8+9GDHpB+9M4c/aBcmOwYmaCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IMa0Z+Va4dhIQCIcCCEmJ2GfB06pC4X+A3Im9THNtvUMMA0GCSqGSIb3DQEBAQUA
# BIICAA5IfS5LjIfXhHQBa19mvrX2zrbK1YwwL0GuaY/BY6xfwdsQpJ3SoQajxXWG
# /y8JirRskBXTc1ebD6ZqjrB3JfFTy7pZnPxQMRAFb414sU7dX7/15m4U4PqjtXQ8
# rRkwWzIuhbLFtlDImeW20FZye2rb0U0QW2Np3ramwefYc6Ql+oCAXXdZxCrrNaL7
# luMzlGr3lcjZy8GY3zMHWulL1OhySKHKoUX/27v3CuX68c1SJ12Hqrb2lCchvvWM
# 7oG3a7WQtuWNBOmpLTuXpoc1hwsZAB6RV1opx+sry+Sa/VIIh/Pwg94axE+SlXp7
# g7NQ0xc1ZoE3ZBc/NGauSNrEgzPoDkaf0RCxRB+PROPLmA72hJweYlZmJEZj/yAE
# RwIkxhnyyE9JhheHEPFxIqLlSVcnXpCQiOq6+lKVYo6jgoiBzcaK0JjTER1va7y3
# FGFIpPLSUNiBrRWXZOAXW1DWobw5OKSc6c+NyT1b583OZhxcVSh2L3iCqKLCWG7+
# V82iC7wdwHgf6ldnRd/v5MqYjUcG2zykSMdk/tAk4i/fNLH8TdeZbpKSFRGyNGEm
# QGkCQasrbZDgxGd3shU2IslWO609uZeo7u6nHD6W233OuZEPGjRCPqQ+FN8q6hB4
# T/Sp7V041WczJARtqhKWBznBeHI3POkubV7PhZWhHyNmg4ywoYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDMxMTE5MTk1NFowLwYJKoZIhvcNAQkEMSIEIPDw3AEk
# ISwLGTajzzGKKRyZdVuixZ6fSBvBzLNpXTgdMA0GCSqGSIb3DQEBAQUABIICABkl
# dLjT6ArayGa5ElXTpvOSQEEevlvoCmaqYVIr9jYwpthyhDZPKXSlv6fM51klGK0P
# O5KthE5WqP3k3MVYeJkB0NlnC7wswHx7c7A8ttR7jw+FcjR0wDIluFIw/7ewjlUs
# FLE6ClN5I7NwA4mXINem0xPV/wbUnyYZ7AakFqm4R4QUj1wwyHXlBqUXOqz19hYh
# RErwnh5hmLBVCnT68V13B1XBCjQmzSOBpQdR3iJ+LIVm0T+c5vJ/DgckwYZFufO+
# px55kTXG7r6BFezYwptla8U3AMPmcFveOo02SoJbiqkixbwrehINMzSK1EkkS1Bj
# JzJXNRCHyRQ2/d8E5tWoNc9v/XK1pTZHpl/GRBeTXSunWMc2atxL7oEcpT9JecE+
# wkW+WyYhmZw5vU2XbFHzMq37DBBmk/tp260G4bg1R6cmC+6f7suY8BZ9CXQCc+p1
# OynA1q1RJfirRAeOOltBbLofr8yc7nwxXmTnJ+bOSikvgrybUbcaKU+jkKD+inwv
# XNvGOoGdcXCRaEcyQKlTX9ImveZX7+o8u1i5DGEpxo/99qPhDNrRu5MbIQwe9Kl3
# ZRyoFghYEQW5TENeqszxQaW9gkL816BBjXxA/RUDHpLHD3X0q1H3DTYkEmFxiUDk
# 7ww/lIUbMRUlBcy8rkDyU+PkD5QFtS+KJ0F+VCKq
# SIG # End signature block
