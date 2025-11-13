Function Restart-ComputerSafely {
<#
    .SYNOPSIS
        Restarts the computer immediately with BitLocker protection.
        Suspends BitLocker if enabled to prevent recovery prompts, then resumes after reboot.
    
    .PARAMETER Force
        Forces applications to close without warning.
    
    .PARAMETER Delay
        Seconds to wait before restarting. Defaults to 10 seconds.
    
    .EXAMPLE
        Restart-ComputerSafely
        Restarts the computer after 10 seconds, handling BitLocker automatically.
    
    .EXAMPLE
        Restart-ComputerSafely -Force -Delay 0
        Immediately restarts the computer without delay, forcing apps to close.
#>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Force,
        
        [Parameter()]
        [int]$Delay = 10
    )
    
    Write-Host "Preparing safe restart with BitLocker handling..."
    
    # Check if BitLocker is enabled
    $Volume = Get-BitLockerVolume -MountPoint C:
    
    if ($Volume.ProtectionStatus -eq 'On') {
        Write-Host "BitLocker is enabled. Suspending for 5 reboots..."
        
        # Suspend BitLocker
        Suspend-BitLocker -MountPoint C: -RebootCount 5
        
        # Log the suspension
        New-Item -Path 'HKLM:\SOFTWARE\MauleTech' -Force | Out-Null
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\MauleTech' -Name 'BitLockerSuspendedDate' -Value (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') -Force
        
        # Create the resume BitLocker script
        $ResumeScript = @'
Start-Sleep -Seconds 30
$Volume = Get-BitLockerVolume -MountPoint C:
if ($Volume.ProtectionStatus -eq 'Off') {
    Resume-BitLocker -MountPoint C:
    New-Item -Path 'HKLM:\SOFTWARE\MauleTech' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\MauleTech' -Name 'BitLockerResumedDate' -Value (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') -Force
}
'@
        
        # Save the resume script
        $ScriptPath = "$env:ProgramData\MauleTech\ResumeBitLocker.ps1"
        New-Item -Path "$env:ProgramData\MauleTech" -ItemType Directory -Force | Out-Null
        $ResumeScript | Out-File -FilePath $ScriptPath -Encoding ASCII -Force
        
        # Set RunOnce to resume BitLocker after reboot
        Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' -Name 'ResumeBitLocker' -Value "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $ScriptPath" -Force
        
        Write-Host "BitLocker suspended. Will resume automatically after reboot."
    } else {
        Write-Host "BitLocker is not enabled or already suspended."
    }
    
    # Send notification to users if there's a delay
    if ($Delay -gt 0) {
        $Message = "SYSTEM RESTART: This computer will restart in $Delay seconds. Please save your work immediately."
        try {
            msg * $Message
            Write-Host "User notification sent."
        } catch {
            Write-Host "Could not send user notification: $_"
        }
        
        Write-Host "Restarting in $Delay seconds..."
        Start-Sleep -Seconds $Delay
    }
    
    if ($Force) {
        Restart-Computer -Force
    } else {
        Restart-Computer
    }
}

Function Restart-VSSWriter {
	[CmdletBinding()]

	Param (
		[Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Mandatory = $True)]
		[String[]]
		$Name
	) #Param

	BEGIN { Write-Verbose "BEGIN: Restart-KPVSSWriter"} #BEGIN

	PROCESS {

		Write-Verbose "Working on VSS Writer: $Name"

		Switch ($Name) {
			'ASR Writer' { $Service = 'VSS' }
			'BITS Writer' { $Service = 'BITS' }
			'Certificate Authority' { $Service = 'EventSystem' }
			'COM+ REGDB Writer' { $Service = 'VSS' }
			'DFS Replication service writer' { $Service = 'DFSR' }
			'DHCP Jet Writer' { $Service = 'DHCPServer' }
			'FRS Writer' { $Service = 'NtFrs' }
			'FSRM writer' { $Service = 'srmsvc' }
			'IIS Config Writer' { $Service = 'AppHostSvc' }
			'IIS Metabase Writer' { $Service = 'IISADMIN' }
			'Microsoft Exchange Replica Writer' { $Service = 'MSExchangeRepl' }
			'Microsoft Exchange Writer' { $Service = 'MSExchangeIS' }
			'Microsoft Hyper-V VSS Writer' { $Service = 'vmms' }
			'MSMQ Writer (MSMQ)' { $Service = 'MSMQ' }
			'MSSearch Service Writer' { $Service = 'WSearch' }
			'NPS VSS Writer' { $Service = 'EventSystem' }
			'NTDS' { $Service = 'NTDS' }
			'OSearch VSS Writer' { $Service = 'OSearch' }
			'OSearch14 VSS Writer' { $Service = 'OSearch14' }
			'Registry Writer' { $Service = 'VSS' }
			'Shadow Copy Optimization Writer' { $Service = 'VSS' }
			'SMS Writer' { $Service = 'SMS_SITE_VSS_WRITER' }
			'SPSearch VSS Writer' { $Service = 'SPSearch' }
			'SPSearch4 VSS Writer' { $Service = 'SPSearch4' }
			'SqlServerWriter' { $Service = 'SQLWriter' }
			'System Writer' { $Service = 'CryptSvc' }
			'TermServLicensing' { $Service = 'TermServLicensing' }
			'WDS VSS Writer' { $Service = 'WDSServer' }
			'WIDWriter' { $Service = 'WIDWriter' }
			'WINS Jet Writer' { $Service = 'WINS' }
			'WMI Writer' { $Service = 'Winmgmt' }
			default {$Null = $Service}
		} #Switch

		IF ($Service) {
			Write-Verbose "Found matching service"
			$S = Get-Service -Name $Service
			Write-Host "Restarting service $(($S).DisplayName)"
			$S | Restart-Service -Force
		}
		ELSE {
			Write-Warning "No service associated with VSS Writer: $Name"
		}
	} #PROCESS
	END { } #END
}

# SIG # Begin signature block
# MIIF0AYJKoZIhvcNAQcCoIIFwTCCBb0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUQzlxiSNDzB6J0fb5nboaYMb3
# mDSgggNKMIIDRjCCAi6gAwIBAgIQFhG2sMJplopOBSMb0j7zpDANBgkqhkiG9w0B
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
# BgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUDhPU
# xl1XTTR4rQNyfXfA37MikY0wDQYJKoZIhvcNAQEBBQAEggEAFAJu/xjytBvVIote
# WP8pBKIKRzpXaqaMH2rt1oQqnfzRl2VjUDecBsQgzW95TfhnnR8q64KJ8hdb3sb3
# uMCUBKEU1BCgU5W6+TeVG0p3DZFnMV4ud2d7dmkuia3lxVANK4IO7Ky1+MmoxF9+
# uiUyL1M8coQrsaqGYRyrQ5FHmdbetlFYQRzMaVey/rCSigz9Axmhi91XpmVEZ7Xe
# dNy3bnUgSyYV7TmVrc6xbSPr3SWdL8Fzmrq/BTRtYpISwhn1gUlW5mI62XYIlSm4
# riCac18KDGEPoQidv/aCzxBJbuuSCcrJXlGrjGe/Z1ETpniIqM23JadzYqZwT75o
# G6Z5PQ==

# SIG # End signature block
