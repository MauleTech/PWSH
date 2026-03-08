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

Function Disable-LocalPasswordExpiration {
	param(
		[Parameter(Mandatory=$true)]
		[string]$UserName
	)
	Write-Host "Set local $UserName account to never expire"
	Set-LocalUser -Name $UserName -PasswordNeverExpires $True
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
