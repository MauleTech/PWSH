Function Disable-LocalPasswordExpiration {
	param(
		[Parameter(Mandatory=$true)]
		[string]$UserName
	)
	Write-Host "Set local $UserName account to never expire"
	Set-LocalUser -Name $UserName -PasswordNeverExpires $True
}

Function Disable-DailyReboot {
	<#
	.SYNOPSIS
		Permanently deletes the scheduled task named "Daily Restart"
#>
	$DailyRebootTask = Get-ScheduledTask -TaskName "Daily Restart" -ErrorAction SilentlyContinue
	If ($DailyRebootTask) {
		$DailyRebootTask | Unregister-ScheduledTask -Confirm:$false
	}
	If (!(Get-ScheduledTask -TaskName "Daily Restart" -ErrorAction SilentlyContinue)) {
		Write-Host "The task 'Daily Restart' has been successfully removed."
	}
 Else {
		Write-Host "The task 'Daily Restart' has NOT been successfully removed. Please investigate!"
	}
}

function Disable-EdgeOOBE {
    <#
    .SYNOPSIS
        Disables Microsoft Edge OOBE (Out of Box Experience) and startup prompts.
    
    .DESCRIPTION
        Configures registry policies to disable Edge's first run experience,
        startup prompts, and various telemetry/recommendations. Says "no" to everything.
    
    .PARAMETER Scope
        Specify 'Machine' for HKLM (all users) or 'User' for HKCU (current user only).
        Default is 'Machine'.
    
    .EXAMPLE
        Disable-EdgeOOBE
        Disables Edge OOBE for all users on the machine.
    
    .EXAMPLE
        Disable-EdgeOOBE -Scope User
        Disables Edge OOBE for the current user only.
    
    .NOTES
        Requires administrative privileges when using -Scope Machine.
        Author: Maule Technologies
    #>
    
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('Machine', 'User')]
        [string]$Scope = 'Machine'
    )
    
    begin {
        # Determine registry path based on scope
        $regPath = switch ($Scope) {
            'Machine' { 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' }
            'User'    { 'HKCU:\SOFTWARE\Policies\Microsoft\Edge' }
        }
        
        # Check for admin rights if Machine scope
        if ($Scope -eq 'Machine') {
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            if (-not $isAdmin) {
                throw "Administrator privileges required for Machine scope. Run PowerShell as Administrator or use -Scope User."
            }
        }
        
        # Registry settings to disable OOBE and prompts
        $settings = @{
            # Core OOBE settings
            'HideFirstRunExperience'                = 1
            'StartupBoostEnabled'                   = 0
            'HardwareAccelerationModeEnabled'       = 0
            'BackgroundModeEnabled'                 = 0
            
            # Download and browser behavior
            'PromptForDownloadLocation'             = 0
            'DefaultBrowserSettingEnabled'          = 0
            'ShowRecommendationsEnabled'            = 0
            
            # Data collection and telemetry
            'UserFeedbackAllowed'                   = 0
            'MetricsReportingEnabled'               = 0
            'DiagnosticData'                        = 0
            'PersonalizationReportingEnabled'       = 0
            
            # Shopping and services
            'EdgeShoppingAssistantEnabled'          = 0
            'EdgeCollectionsEnabled'                = 0
            'ShowMicrosoftRewards'                  = 0
            'EdgeWalletCheckoutEnabled'             = 0
            
            # Misc prompts and features
            'WalletDonationEnabled'                 = 0
            'ConfigureDoNotTrack'                   = 1
            'AlternateErrorPagesEnabled'            = 0
            'AutofillAddressEnabled'                = 0
            'AutofillCreditCardEnabled'             = 0
            'PasswordManagerEnabled'                = 0
        }
    }
    
    process {
        try {
            # Create registry path if it doesn't exist
            if (-not (Test-Path $regPath)) {
                if ($PSCmdlet.ShouldProcess($regPath, "Create registry path")) {
                    New-Item -Path $regPath -Force | Out-Null
                    Write-Verbose "Created registry path: $regPath"
                }
            }
            
            # Apply each setting
            foreach ($setting in $settings.GetEnumerator()) {
                if ($PSCmdlet.ShouldProcess("$regPath\$($setting.Key)", "Set value to $($setting.Value)")) {
                    Set-ItemProperty -Path $regPath -Name $setting.Key -Value $setting.Value -Type DWord -Force
                    Write-Verbose "Set $($setting.Key) = $($setting.Value)"
                }
            }
            
            Write-Host "Successfully disabled Edge OOBE and startup prompts for scope: $Scope" -ForegroundColor Green
            Write-Host "Changes will take effect the next time Edge is launched." -ForegroundColor Yellow
            
        } catch {
            Write-Error "Failed to disable Edge OOBE: $_"
            throw
        }
    }
}

Function Disable-FastStartup {
	Write-Host "Disable Windows Fast Startup"
	REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d "0" /f
	powercfg -h off
}

Function Disable-Sleep {
	<#
.Synopsis
	Function to suspend your current Power Plan settings when running a PowerShell script.
.SYNOPSIS
	Function to suspend your current Power Plan settings when running a PowerShell script.
	Scenario: When downloading files using Robocopy from PowerShell you don't want your
	laptop to go into sleep mode.
.EXAMPLE
	Disable-Sleep
	Run mylongrunningscript with Display idle timeout prevented and verbose messages
#>

	If (!(Test-Path "C:\ProgramData\chocolatey\lib\dontsleep.portable\tools\DontSleep_x64_p.exe")) {
		If (!(Get-Command choco -ErrorAction SilentlyContinue)) { Install-Choco }
		choco install dontsleep.portable -y
	}
	& C:\ProgramData\chocolatey\lib\dontsleep.portable\tools\DontSleep_x64_p.exe -bg please_sleep_mode=0 enable=1
}

Function Disable-SleepOnAC {
	<#
.SYNOPSIS
	Configures Windows power plan settings for both battery and AC power modes.

.DESCRIPTION
	Sets display timeout, sleep timeout, and button/lid behavior for both battery (DC) 
	and AC power modes. Designed to prevent unwanted sleep when plugged in while 
	maintaining reasonable battery-saving settings.

.EXAMPLE
	Set-PowerPlanSettings
	Configures the active power plan with predefined battery and AC settings.
#>

	# Battery (DC) Settings
	powercfg /change monitor-timeout-dc 15      # Display off after 15 minutes
	powercfg /change standby-timeout-dc 45      # Sleep after 45 minutes
	powercfg /change hibernate-timeout-dc 0     # Disable hibernate on battery

	# Plugged In (AC) Settings
	powercfg /change monitor-timeout-ac 30      # Display off after 30 minutes
	powercfg /change standby-timeout-ac 0       # Never sleep when plugged in
	powercfg /change hibernate-timeout-ac 0     # Never hibernate when plugged in

	# Button/Lid Actions when Plugged In (AC)
	# Values: 0=Do Nothing, 1=Sleep, 2=Hibernate, 3=Shut Down
	powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS PBUTTONACTION 0  # Power button: Do nothing
	powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0  # Sleep button: Do nothing
	powercfg /setacvalueindex SCHEME_CURRENT SUB_BUTTONS LIDACTION 0      # Lid close: Do nothing

	# Apply the changes to the current power scheme
	powercfg /setactive SCHEME_CURRENT

	Write-Host "Power plan settings configured successfully." -ForegroundColor Green
}


# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU0QZbpxaAhAqiexISstu4tegZ
# v1mgggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUPgT6
# m72G6yT9puNkm45NT0Su910wDQYJKoZIhvcNAQEBBQAEggEAOBDA2okyalQINmsR
# JW07agX3ESz0+96jLVG3djDhwGw/LAUcHNjG094Ks9uqtF2tkvn9o3T6JB00Yzz/
# iE5jNVTtJSFAbwe+SxQrR9aVs+8e4gE9An5cBYTwYaatxKnw1bxjjv1kxKuKU6v1
# gETjAPoLfjeev1bFXXKhsPS3LKo8WYxOBdgTnwaETZyphf1Q9ZVSVuZK+eoA+5GV
# zDe5H9zT+rsx44SeCa//NR0E3GEx7Nc6MLCjTYtr9bSgiqwnyewvTpTWK5LWqblr
# LB58Xw79OSAXgfFN7vzwOiSH04CariVC5ocQpB1bYXXo+WvWdmqjLaQlXauMJiLm
# GeFwKA==
# SIG # End signature block