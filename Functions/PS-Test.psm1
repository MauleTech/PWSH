Function Test-SmtpRelay {
	<#
	.SYNOPSIS
		Tests whether an SMTP relay accepts a message, and reports why when it does not.
	.DESCRIPTION
		A diagnostic for SMTP relay paths. It proves whether a relay host accepts a message
		from this machine and, when it does not, reports the SMTP status code and the
		underlying reason instead of a generic "Failure sending mail." string. The common
		case is an anonymous submission from a scanner or MFP through an Exchange Online
		Protection connector, where the question is whether the connector accepts the mail
		at all.

		This is not a general replacement for Send-MailMessage. There is no attachment, Cc,
		Bcc, HTML body, or priority support; it is deliberately narrow.

		On the underlying API, stated plainly so the trade-off is not hidden:
		Send-MailMessage is documented as obsolete because it "doesn't guarantee secure
		connections to SMTP servers" (Platform Compatibility note DE0005), and
		System.Net.Mail.SmtpClient, which this function calls, carries the same caveat -
		Microsoft documents it as "not recommended for new development" and points to
		MailKit, or Send-MgUserMail for Exchange Online. Calling SmtpClient directly does
		not fix that, and this function does not claim to. SmtpClient is used on purpose,
		because the point of the test is to exercise the same plain SMTP submission a
		legacy device performs, without taking a module dependency (MailKit) or requiring a
		tenant mailbox and Graph consent (Send-MgUserMail). For sending real mail from
		automation, prefer one of those instead.

		Failure is reported through the returned object, not the error stream: the function
		does not throw when a relay rejects the message, so test the .Success or .Result
		property rather than $? or -ErrorAction Stop.
	.PARAMETER From
		Sender email address.
	.PARAMETER To
		One or more recipient email addresses.
	.PARAMETER SmtpServer
		SMTP server or relay hostname, e.g. contoso-com.mail.protection.outlook.com
	.PARAMETER Subject
		Email subject line.
	.PARAMETER Body
		Email body text. Defaults to an empty string.
	.PARAMETER Port
		SMTP port. Defaults to 25.
	.PARAMETER Credential
		Optional PSCredential for authenticated relay. Omit for anonymous relay
		(scanner/MFP style).
	.PARAMETER UseTls
		Whether to negotiate STARTTLS (explicit TLS on port 25/587). Defaults to $true.
		This is a [bool], not a [switch], so the colon form is required to turn it off:
		-UseTls:$false. A bare -UseTls is not valid syntax.

		With TLS on, STARTTLS is mandatory rather than preferred: if the relay does not
		advertise STARTTLS, System.Net.Mail fails the attempt instead of falling back to
		plaintext, so the test reports a TLS failure before the relay's accept/reject
		behavior is ever exercised. Re-run with -UseTls:$false to test the relay itself.

		Pass -UseTls:$false only to test plaintext relay behavior, for example reproducing
		a misconfigured scanner. Note: System.Net.Mail supports only explicit TLS
		(STARTTLS), not implicit TLS/SMTPS on port 465.
	.PARAMETER TimeoutSeconds
		How long to wait for the send to complete before giving up. Defaults to 30 seconds.
		The SmtpClient default is 100 seconds, which is a long time to sit and watch when
		port 25 is silently filtered.
	.OUTPUTS
		PSCustomObject with these properties, emitted on both the success and failure paths:
		Result (Sent, PartiallySent, or Failed), Success (true only when every recipient was
		accepted), From, To, AcceptedRecipients, FailedRecipients, SmtpServer, Port,
		TlsRequested, Authenticated, SecurityProtocol, StatusCode, and Error.

		Nothing is emitted when -WhatIf is used, matching the standard ShouldProcess
		contract.
	.NOTES
		Success means the relay accepted the message for delivery. It does not mean the
		message was delivered, or that it survived spam filtering or transport rules at the
		far end. Confirm delivery in the recipient mailbox or in message trace.

		Only test relays you administer or are authorized to test. This function can submit
		mail with an arbitrary From address, which is the behavior being diagnosed.
	.EXAMPLE
		Test-SmtpRelay -From "scanner@contoso.com" -To "user@contoso.com" -SmtpServer "contoso-com.mail.protection.outlook.com" -Subject "Relay test" -Body "Test" -Verbose
		Anonymous submission on port 25 through an Exchange Online Protection connector.
		This is the scanner/MFP case; -Verbose shows the TLS and connection detail.
	.EXAMPLE
		Test-SmtpRelay -From "alerts@contoso.com" -To "user@contoso.com" -SmtpServer "smtp.contoso.com" -Subject "Authenticated relay test" -Port 587 -Credential (Get-Credential)
		Authenticated submission on port 587. The credential is prompted for interactively.
	.EXAMPLE
		Test-SmtpRelay -From "scanner@contoso.com" -To "user@contoso.com" -SmtpServer "contoso-com.mail.protection.outlook.com" -Subject "Plaintext relay test" -UseTls:$false
		Reproduces a misconfigured device that submits without TLS. Warns before sending,
		because the session crosses the network unencrypted.
	.EXAMPLE
		$result = Test-SmtpRelay -From "scanner@contoso.com" -To "user1@contoso.com","user2@fabrikam.com" -SmtpServer "contoso-com.mail.protection.outlook.com" -Subject "Recipient scope test" -TimeoutSeconds 10
		$result.FailedRecipients
		Tests two recipients at once with a short timeout. When a relay accepts one domain
		and rejects the other, Result is PartiallySent and FailedRecipients names which
		address was refused.
	#>
	[CmdletBinding(SupportsShouldProcess)]
	param(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$From,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string[]]$To,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$SmtpServer,

		[Parameter(Mandatory)]
		[string]$Subject,

		[string]$Body = "",

		[ValidateRange(1, 65535)]
		[int]$Port = 25,

		[PSCredential]$Credential,

		[bool]$UseTls = $true,

		[ValidateRange(1, 600)]
		[int]$TimeoutSeconds = 30
	)

	If (-not $UseTls) {
		Write-Warning "TLS is disabled. The SMTP session, including the message content, will cross the network unencrypted."
		If ($Credential) {
			Write-Warning "-Credential was supplied with -UseTls:`$false. SMTP AUTH will transmit the user name and password base64 encoded in cleartext. Use this only against a relay you administer, on a network you trust, with a disposable account."
		}
	}

	# Both handles start null so the finally block can be null-safe. Without that guard a
	# failure during setup makes the finally throw on $null.Dispose(), which masks the real
	# error - the opposite of what a diagnostic tool should do.
	$mailMessage = $null
	$smtpClient = $null
	$previousSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
	$effectiveSecurityProtocol = $previousSecurityProtocol
	$securityProtocolChanged = $false

	try {
		# System.Net.Mail takes its TLS version from the process-global SecurityProtocol.
		# On Windows PowerShell 5.1 (a .NET Framework host) that value can predate TLS 1.2,
		# which Exchange Online Protection now refuses, so a relay that is actually healthy
		# would fail the handshake. Add TLS 1.2 for the duration of this call only, and
		# restore the previous value in the finally block. Zero means SystemDefault and is
		# left untouched so the OS can still negotiate TLS 1.3.
		If ($UseTls -and [int]$previousSecurityProtocol -ne 0 -and -not ($previousSecurityProtocol -band [Net.SecurityProtocolType]::Tls12)) {
			Write-Verbose "SecurityProtocol lacks Tls12 (currently $previousSecurityProtocol). Adding Tls12 for this call only."
			[Net.ServicePointManager]::SecurityProtocol = $previousSecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
			$securityProtocolChanged = $true
		}
		$effectiveSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol

		Write-Verbose "Building message from $From to $($To -join ', ')"
		$mailMessage = [System.Net.Mail.MailMessage]::new()
		# Construct the addresses explicitly rather than relying on PowerShell's implicit
		# string-to-MailAddress coercion. A malformed address then raises here, inside the
		# try, and is reported through the result object naming the offending address.
		$mailMessage.From = [System.Net.Mail.MailAddress]::new($From)
		ForEach ($recipient in $To) {
			$mailMessage.To.Add([System.Net.Mail.MailAddress]::new($recipient))
		}
		$mailMessage.Subject = $Subject
		$mailMessage.Body = $Body

		$smtpClient = [System.Net.Mail.SmtpClient]::new($SmtpServer, $Port)
		$smtpClient.EnableSsl = $UseTls
		$smtpClient.Timeout = $TimeoutSeconds * 1000
		# On .NET Framework, machine.config can supply a default delivery method and default
		# credentials for every SmtpClient. Pin the delivery method so the test always
		# exercises the network rather than silently writing an .eml to a pickup directory
		# and reporting success.
		$smtpClient.DeliveryMethod = [System.Net.Mail.SmtpDeliveryMethod]::Network
		Write-Verbose "TLS requested (STARTTLS): $UseTls. SecurityProtocol: $effectiveSecurityProtocol. Timeout: $TimeoutSeconds s."

		If ($Credential) {
			Write-Verbose "Using authenticated relay as $($Credential.UserName)"
			$smtpClient.Credentials = [System.Net.NetworkCredential]::new($Credential.UserName, $Credential.Password)
		} Else {
			Write-Verbose "Using anonymous relay (no credentials)"
			$smtpClient.UseDefaultCredentials = $false
			# UseDefaultCredentials = $false only reselects the client's own Credentials,
			# which machine.config may already have populated. Clear it so anonymous means
			# anonymous.
			$smtpClient.Credentials = $null
		}

		# ShouldProcess is inside the try so that a declined -WhatIf still unwinds through
		# the finally and cleans up.
		If ($PSCmdlet.ShouldProcess("$SmtpServer`:$Port", "Send test email to $($To -join ', ')")) {
			Write-Verbose "Connecting to $SmtpServer on port $Port..."
			$smtpClient.Send($mailMessage)
			Write-Host "Message accepted by $SmtpServer for $($To -join ', ')" -ForegroundColor Green
			[PSCustomObject]@{
				Result             = 'Sent'
				Success            = $true
				From               = $From
				To                 = $To
				AcceptedRecipients = $To
				FailedRecipients   = @()
				SmtpServer         = $SmtpServer
				Port               = $Port
				TlsRequested       = $UseTls
				Authenticated      = [bool]$Credential
				SecurityProtocol   = $effectiveSecurityProtocol
				StatusCode         = $null
				Error              = $null
			}
		}
	} catch {
		# PowerShell wraps the .NET exception in a MethodInvocationException, and
		# System.Net.Mail reports connection, DNS, and TLS handshake failures as a generic
		# SmtpException "Failure sending mail." with the real cause in InnerException. Walk
		# the whole chain so the technician gets "Connection refused" rather than "Failure
		# sending mail.", and pull out the SMTP status code and per-recipient rejections.
		$chain = @()
		$rootCause = $_.Exception.Message
		$statusCode = $null
		$failedRecipients = @()
		$exception = $_.Exception

		While ($exception) {
			$chain += "[$($exception.GetType().Name)] $($exception.Message)"
			$rootCause = $exception.Message

			# Check the plural type first; it derives from the singular, which derives from
			# SmtpException.
			If ($exception -is [System.Net.Mail.SmtpFailedRecipientsException]) {
				ForEach ($recipientError in $exception.InnerExceptions) {
					$failedRecipients += $recipientError.FailedRecipient
					$chain += "  $($recipientError.FailedRecipient): $([int]$recipientError.StatusCode) $($recipientError.StatusCode) - $($recipientError.Message)"
					If ($null -eq $statusCode) { $statusCode = $recipientError.StatusCode }
				}
				# InnerExceptions already covers everything below this node.
				Break
			}
			If ($exception -is [System.Net.Mail.SmtpFailedRecipientException]) {
				$failedRecipients += $exception.FailedRecipient
			}
			If ($exception -is [System.Net.Mail.SmtpException] -and $null -eq $statusCode) {
				$statusCode = $exception.StatusCode
			}

			$exception = $exception.InnerException
		}

		# FailedRecipient comes back wrapped in angle brackets ("<user@contoso.com>"), so it
		# has to be normalized before it is compared against $To. Without this the accepted
		# list silently keeps every rejected address and a total rejection is misreported as
		# a partial success. -notcontains is case-insensitive, which is what we want here.
		$failedRecipients = @($failedRecipients |
			Where-Object { $_ } |
			ForEach-Object { $_.Trim() -replace '^<|>$', '' } |
			Select-Object -Unique)
		$acceptedRecipients = @($To | Where-Object { $failedRecipients -notcontains $_ })

		# A relay that accepts some recipients and rejects others has already delivered to
		# the accepted ones. Reporting that as a flat failure would be wrong, and it is the
		# signature of an accepted-domain problem rather than a connector problem.
		If ($failedRecipients.Count -gt 0 -and $acceptedRecipients.Count -gt 0) {
			$resultState = 'PartiallySent'
			Write-Host "Relay accepted $($acceptedRecipients.Count) of $($To.Count) recipients. Rejected: $($failedRecipients -join ', ')" -ForegroundColor Yellow
		} Else {
			$resultState = 'Failed'
			Write-Host "Failed to send message: $rootCause" -ForegroundColor Red
		}
		# GeneralFailure (-1) is .NET's "no SMTP status was returned" placeholder, which
		# happens on connection, DNS, and TLS failures. Printing "-1" tells a technician
		# nothing, so only surface a real SMTP code. The raw value stays on the object.
		If ($statusCode -and $statusCode -ne [System.Net.Mail.SmtpStatusCode]::GeneralFailure) {
			Write-Host "SMTP status: $([int]$statusCode) $statusCode" -ForegroundColor Red
		}
		Write-Verbose ("Exception chain:`r`n" + ($chain -join "`r`n"))

		[PSCustomObject]@{
			Result             = $resultState
			Success            = $false
			From               = $From
			To                 = $To
			AcceptedRecipients = $acceptedRecipients
			FailedRecipients   = $failedRecipients
			SmtpServer         = $SmtpServer
			Port               = $Port
			TlsRequested       = $UseTls
			Authenticated      = [bool]$Credential
			SecurityProtocol   = $effectiveSecurityProtocol
			StatusCode         = $statusCode
			Error              = $rootCause
		}
	} finally {
		If ($securityProtocolChanged) {
			[Net.ServicePointManager]::SecurityProtocol = $previousSecurityProtocol
		}
		# Release the client first: its Dispose sends QUIT and tears down the connection
		# that still references the message.
		If ($smtpClient) { $smtpClient.Dispose() }
		If ($mailMessage) { $mailMessage.Dispose() }
	}
}

Function Test-PendingReboot {
	<#
	.SYNOPSIS
		Reports whether Windows is waiting on a reboot, and which subsystem is asking for it.
	.DESCRIPTION
		Answers the question that comes up before every patch window, install, or handoff:
		is this machine already waiting on a reboot, and why? A pending reboot is the usual
		cause of an installer refusing to run, a Windows Update cycle that never finishes,
		or a rename that appears to have been ignored.

		Six independent signals are checked, because no single one covers every case:

		- Component Based Servicing (servicing stack has staged work)
		- Windows Update, Auto Update branch (the classic RebootRequired flag)
		- Windows Update, Orchestrator branch (used by newer update paths)
		- Pending file rename operations (files queued to move or delete at boot)
		- Pending computer rename (the active name no longer matches the configured name)
		- Pending domain join (Netlogon has a join staged)

		If a Configuration Manager client is present, its own reboot state is queried as a
		seventh signal, since ConfigMgr tracks deployments the registry flags do not.

		Registry reads go through an explicit 64-bit view rather than the HKLM: PSDrive.
		RMM tools, ScreenConnect included, often launch the 32-bit powershell.exe on a
		64-bit OS, and WOW64 then redirects HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
		to Wow6432Node, where the servicing and Windows Update keys do not exist. A naive
		check run from a 32-bit host reports a clean machine that is in fact waiting on a
		reboot. This function does not have that blind spot.

		Nothing is changed, started, or stopped. The function only reads state.
	.PARAMETER Quiet
		Return a single [bool] and print nothing, for use in a condition:
		If (Test-PendingReboot -Quiet) { ... }. Cannot be combined with -PassThru.
	.PARAMETER PassThru
		Return the full result object instead of printing the report, for logging or for
		feeding into a report. Cannot be combined with -Quiet.
	.PARAMETER SkipFileRenameCheck
		Ignore the pending file rename signal. This is the weakest of the signals: antivirus
		products, Windows Defender definition updates, and some installers leave entries in
		PendingFileRenameOperations during normal operation, on machines that do not need a
		reboot. Use this switch when that noise makes the overall verdict useless.
	.PARAMETER SkipConfigMgrCheck
		Skip the Configuration Manager client query. The query is already skipped silently
		on machines with no client installed; this switch is for machines where WMI is
		damaged and the call is slow or hangs.
	.OUTPUTS
		[bool] with -Quiet.

		[PSCustomObject] with -PassThru, carrying ComputerName, PendingReboot, Reasons,
		ComponentBasedServicing, WindowsUpdate, WindowsUpdateOrchestrator,
		PendingFileRename, PendingFileRenameEntries, PendingComputerRename,
		PendingDomainJoin, ConfigMgrRebootPending, and ConfigMgrHardRebootPending.

		ConfigMgrRebootPending and ConfigMgrHardRebootPending are $null, not $false, when no
		Configuration Manager client answered. Test them with -eq $true so an unanswered
		check is not read as a clean result.

		Nothing is returned in the default console mode; the report is written to the host.
	.NOTES
		A pending reboot is a state, not a fault. Plenty of healthy machines carry one
		between a patch install and the next maintenance window.

		Reading these keys does not require elevation. The Configuration Manager query
		generally does, so on an unelevated session that check may report nothing on a
		machine that does have a client.

		The pending file rename list is shown truncated in the console report. Use
		-PassThru to see every entry.

		Deliberately not checked, because each produces more noise than signal on the
		machines this toolbox runs against: the Component Based Servicing PackagesPending
		key, which is populated during normal servicing without implying a reboot; the
		legacy HKLM\SOFTWARE\Microsoft\Updates UpdateExeVolatile value, which applies to
		Windows XP and Server 2003 era hotfix installers; and App-V 5.x pending tasks.
	.EXAMPLE
		Test-PendingReboot
		Prints the colored report. This is the form to run from a remote session when you
		just want to look at the machine.
	.EXAMPLE
		If (Test-PendingReboot -Quiet) { Write-Host "Reboot first." }
		Boolean form, for gating an install or a maintenance script.
	.EXAMPLE
		Test-PendingReboot -PassThru | Format-List
		Full detail, including the reason list and the queued file rename entries.
	.EXAMPLE
		Test-PendingReboot -SkipFileRenameCheck
		Ignores the file rename signal on a machine whose antivirus keeps that key
		populated, so the remaining signals decide the verdict.
	.EXAMPLE
		Invoke-Command -ComputerName SERVER01, SERVER02 -ScriptBlock ${function:Test-PendingReboot}
		Runs the check on remote machines without loading the whole toolbox on each one, by
		shipping the function itself. The function is deliberately local-only; remoting is
		how it reaches other machines. Note that -ArgumentList cannot supply named switches
		to a script block, so use a wrapper when a remote -PassThru is needed:
		Invoke-Command -ComputerName SERVER01 -ScriptBlock { param($Fn) & ([scriptblock]::Create($Fn)) -PassThru } -ArgumentList (Get-Command Test-PendingReboot).Definition
	#>
	[CmdletBinding(DefaultParameterSetName = 'Console')]
	[OutputType([bool], ParameterSetName = 'Quiet')]
	[OutputType([PSCustomObject], ParameterSetName = 'Object')]
	param(
		[Parameter(ParameterSetName = 'Quiet')]
		[switch]$Quiet,

		[Parameter(ParameterSetName = 'Object')]
		[switch]$PassThru,

		[switch]$SkipFileRenameCheck,

		[switch]$SkipConfigMgrCheck
	)

	# Platform is absent on Windows PowerShell 5.1 and 'Win32NT' on PowerShell 7 for Windows,
	# so this catches PowerShell 7 on Linux or macOS without touching the $IsWindows
	# automatic variable, which does not exist under 5.1 and would trip Set-StrictMode.
	If ($PSVersionTable.PSVersion.Major -ge 6 -and $PSVersionTable.Platform -ne 'Win32NT') {
		Throw 'Test-PendingReboot reads the Windows registry and requires Windows.'
	}

	Function Test-RegKeyPresent {
		Param([Microsoft.Win32.RegistryKey]$BaseKey, [string]$Path)
		$SubKey = $null
		Try {
			$SubKey = $BaseKey.OpenSubKey($Path)
			Return ($null -ne $SubKey)
		} Catch {
			# A key this function cannot open is reported as absent rather than fatal: an
			# ACL on one hive branch should not sink the other five checks.
			Write-Verbose "Could not open HKLM\$Path - $($_.Exception.Message)"
			Return $false
		} Finally {
			If ($SubKey) { $SubKey.Close() }
		}
	}

	Function Get-RegValueData {
		Param([Microsoft.Win32.RegistryKey]$BaseKey, [string]$Path, [string]$Name)
		$SubKey = $null
		Try {
			$SubKey = $BaseKey.OpenSubKey($Path)
			If ($null -eq $SubKey) { Return $null }
			Return $SubKey.GetValue($Name, $null)
		} Catch {
			Write-Verbose "Could not read HKLM\$Path\$Name - $($_.Exception.Message)"
			Return $null
		} Finally {
			If ($SubKey) { $SubKey.Close() }
		}
	}

	Function Write-CheckLine {
		Param([string]$Label, $State, [string]$SkippedNote = 'Not checked')
		If ($null -eq $State) {
			Write-Host ("  {0,-30} {1}" -f $Label, $SkippedNote) -ForegroundColor DarkGray
		} ElseIf ($State) {
			Write-Host ("  {0,-30} {1}" -f $Label, 'YES') -ForegroundColor Red
		} Else {
			Write-Host ("  {0,-30} {1}" -f $Label, 'No') -ForegroundColor Green
		}
	}

	$Reasons = New-Object System.Collections.Generic.List[string]
	$Cbs = $false
	$WindowsUpdate = $false
	$Orchestrator = $false
	$PendingFileRename = $null
	$FileRenameEntries = @()
	$PendingComputerRename = $false
	$PendingDomainJoin = $false
	$ConfiguredName = $null
	$CcmRebootPending = $null
	$CcmHardRebootPending = $null

	$BaseKey = $null
	Try {
		$View = If ([Environment]::Is64BitOperatingSystem) {
			[Microsoft.Win32.RegistryView]::Registry64
		} Else {
			[Microsoft.Win32.RegistryView]::Registry32
		}
		Write-Verbose "Reading HKLM through the $View view (host process is $(If ([Environment]::Is64BitProcess) { '64-bit' } Else { '32-bit' }))."
		$BaseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $View)

		$Cbs = Test-RegKeyPresent -BaseKey $BaseKey -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
		If ($Cbs) { $Reasons.Add('Component Based Servicing') }

		$WindowsUpdate = Test-RegKeyPresent -BaseKey $BaseKey -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
		If ($WindowsUpdate) { $Reasons.Add('Windows Update') }

		$Orchestrator = Test-RegKeyPresent -BaseKey $BaseKey -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\RebootRequired'
		If ($Orchestrator) { $Reasons.Add('Windows Update Orchestrator') }

		If (-not $SkipFileRenameCheck) {
			$SessionManager = 'SYSTEM\CurrentControlSet\Control\Session Manager'
			$RawEntries = @()
			ForEach ($ValueName in @('PendingFileRenameOperations', 'PendingFileRenameOperations2')) {
				$Data = Get-RegValueData -BaseKey $BaseKey -Path $SessionManager -Name $ValueName
				If ($Data) { $RawEntries += @($Data) }
			}
			# REG_MULTI_SZ holds source and destination in alternating slots, and an empty
			# destination means "delete at boot". The blanks are structure, not entries, so
			# they are dropped before the list is counted or shown.
			$FileRenameEntries = @($RawEntries | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
			$PendingFileRename = $FileRenameEntries.Count -gt 0
			If ($PendingFileRename) { $Reasons.Add('Pending file rename') }
		}

		# A rename is applied to the configured name immediately and to the active name only
		# at boot, so a mismatch is exactly the window between the two.
		$ActiveName = Get-RegValueData -BaseKey $BaseKey -Path 'SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name 'ComputerName'
		$ConfiguredName = Get-RegValueData -BaseKey $BaseKey -Path 'SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name 'ComputerName'
		If ($ActiveName -and $ConfiguredName -and $ActiveName -ne $ConfiguredName) {
			$PendingComputerRename = $true
			$Reasons.Add("Pending rename from $ActiveName to $ConfiguredName")
		}

		$Netlogon = 'SYSTEM\CurrentControlSet\Services\Netlogon'
		If ((Test-RegKeyPresent -BaseKey $BaseKey -Path "$Netlogon\JoinDomain") -or
			(Test-RegKeyPresent -BaseKey $BaseKey -Path "$Netlogon\AvoidSpnSet")) {
			$PendingDomainJoin = $true
			$Reasons.Add('Pending domain join')
		}
	} Finally {
		If ($BaseKey) { $BaseKey.Close() }
	}

	If (-not $SkipConfigMgrCheck) {
		Try {
			# The timeout matters more than it looks: on a machine with a damaged WMI
			# repository this call is the one step here that can sit indefinitely, and a
			# toolbox item that never returns is worse than one that reports less.
			$Ccm = Invoke-CimMethod -Namespace 'root\ccm\ClientSDK' -ClassName 'CCM_ClientUtilities' -MethodName 'DetermineIfRebootPending' -OperationTimeoutSec 30 -ErrorAction Stop
			If ($null -ne $Ccm -and $Ccm.ReturnValue -eq 0) {
				$CcmRebootPending = [bool]$Ccm.RebootPending
				$CcmHardRebootPending = [bool]$Ccm.IsHardRebootPending
				If ($CcmHardRebootPending) {
					$Reasons.Add('Configuration Manager client (hard reboot, no grace period)')
				} ElseIf ($CcmRebootPending) {
					$Reasons.Add('Configuration Manager client')
				}
			} Else {
				# A client that answers with a non-zero ReturnValue has told us nothing, so the
				# flags stay $null rather than being recorded as a clean result.
				Write-Verbose "Configuration Manager client returned $($Ccm.ReturnValue); treating its reboot state as unknown."
			}
		} Catch {
			# Absent on any machine without a ConfigMgr client, which is the common case.
			Write-Verbose "No Configuration Manager client answered - $($_.Exception.Message)"
		}
	}

	$IsPending = $Reasons.Count -gt 0

	If ($Quiet) { Return $IsPending }

	$Result = [PSCustomObject]@{
		ComputerName               = $env:COMPUTERNAME
		PendingReboot              = $IsPending
		Reasons                    = $Reasons.ToArray()
		ComponentBasedServicing    = $Cbs
		WindowsUpdate              = $WindowsUpdate
		WindowsUpdateOrchestrator  = $Orchestrator
		PendingFileRename          = $PendingFileRename
		PendingFileRenameEntries   = $FileRenameEntries
		PendingComputerRename      = $PendingComputerRename
		PendingDomainJoin          = $PendingDomainJoin
		ConfigMgrRebootPending     = $CcmRebootPending
		ConfigMgrHardRebootPending = $CcmHardRebootPending
	}

	If ($PassThru) { Return $Result }

	Write-Host ''
	Write-Host '=== Pending Reboot Check ===' -ForegroundColor Cyan
	Write-Host ("Computer: {0}    Checked: {1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
	Write-Host ''

	Write-CheckLine -Label 'Component Based Servicing' -State $Cbs
	Write-CheckLine -Label 'Windows Update' -State $WindowsUpdate
	Write-CheckLine -Label 'Windows Update Orchestrator' -State $Orchestrator
	Write-CheckLine -Label 'Pending file rename' -State $PendingFileRename -SkippedNote 'Skipped'
	Write-CheckLine -Label 'Pending computer rename' -State $PendingComputerRename
	If ($PendingComputerRename) {
		Write-Host ("    New name at next boot: {0}" -f $ConfiguredName) -ForegroundColor Yellow
	}
	Write-CheckLine -Label 'Pending domain join' -State $PendingDomainJoin
	If ($SkipConfigMgrCheck) {
		Write-CheckLine -Label 'ConfigMgr client' -State $null -SkippedNote 'Skipped'
	} Else {
		# A hard reboot is reported through IsHardRebootPending rather than RebootPending, so
		# showing only the latter would print "No" on a line the verdict counts as pending.
		# Stay $null when neither answered, so "No client" is not shown as a clean result.
		$CcmDisplay = If ($null -eq $CcmRebootPending -and $null -eq $CcmHardRebootPending) {
			$null
		} Else {
			($CcmRebootPending -eq $true) -or ($CcmHardRebootPending -eq $true)
		}
		Write-CheckLine -Label 'ConfigMgr client' -State $CcmDisplay -SkippedNote 'No client'
		If ($CcmHardRebootPending -eq $true) {
			Write-Host '    Hard reboot: the client will not offer a grace period.' -ForegroundColor Yellow
		}
	}

	If ($FileRenameEntries.Count -gt 0) {
		Write-Host ''
		Write-Host ("Queued file operations ({0}):" -f $FileRenameEntries.Count) -ForegroundColor Yellow
		ForEach ($Entry in ($FileRenameEntries | Select-Object -First 10)) {
			Write-Host "    $Entry" -ForegroundColor Gray
		}
		If ($FileRenameEntries.Count -gt 10) {
			Write-Host ("    ... and {0} more. Use -PassThru for the full list." -f ($FileRenameEntries.Count - 10)) -ForegroundColor Gray
		}
	}

	Write-Host ''
	If ($IsPending) {
		Write-Host '>>> REBOOT IS PENDING <<<' -ForegroundColor Red
		Write-Host ("Reason(s): {0}" -f ($Reasons -join '; ')) -ForegroundColor Red
	} Else {
		Write-Host '>>> NO REBOOT DETECTED <<<' -ForegroundColor Green
	}
	Write-Host ''
}

# SIG # Begin signature block
# MIIoCgYJKoZIhvcNAQcCoIIn+zCCJ/cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDw10MadudNuN+M
# QQinTAFQuc2sUE4AX4NC+9/ODZJLkqCCIRYwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# IFSRv1I1I+E18rHsYxtRn0Lnhc98j4TJU5opyVxCU++MMA0GCSqGSIb3DQEBAQUA
# BIICAJa+IfFiWGFwPjfYQfqxBqh/g905NDcr1az0nHMV67UK1jULf1EZcN4/RO3e
# hyZAdu10fyD2xaka7KwvISWERVbmcAralc9vJu4rlYLjbXVKrhshJXltI1bIcrrj
# iMEHX7SJ4o75v71Co18lRVadDeIHuRqnLw3mW2BAojpVgA5xSiJf2/ONr5pncisU
# y4rHGKqYStcPftm476wdr7E6AxCvB868dHq+89Az9xYAdeNhxHCYsKEW1dhqxlgM
# QYEMrecRm0zQuztFitxbpq3OW72ntEPY7qyicHgHd0AHIx0r60jOFs4p0J+NHWWQ
# Kj3pLnzTqEY7akWekejwIp7dRstL6TGZKgDy7XcMPQRWRncUDzszC4bvlCS1voC/
# HQJlVkT//lvenX9scw+/SDCXlfINYeh9dqO0iQkf/aXmCjt5zyNTRdH8nHZeXa0a
# kRVPibeUSIBWQjP+nmlRX3Klb70HIOQLxw9jAPS2aXzcsC3eSntTrxpibR9kxHB1
# Oasd2ZiQy7zySnLS596cV5vrRU/YYHD/a5abPIY0Ie4aN4kyoOxsYu5Vg1rqn4hp
# GN6/Jldq+rzJ6b5lJOc1q+4UwYx/ClcfPfJd74zDnuf7aP+MBa7wRwTWLu4xPmZM
# gUz/er7fVmiK+ZnWsWTWSTSziqVZWDFyzqNcN0zMQKwS7EQ3oYIDJjCCAyIGCSqG
# SIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0
# aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MDgxNzE3NTY1NVowLwYJKoZIhvcNAQkEMSIEICC2gjIy
# C26hn/qKX1B/s91qNaRew1gTDf5Acn2n70qPMA0GCSqGSIb3DQEBAQUABIICAIQO
# u5ODJnyuY6KKHZhCct9UN2BillAaI/9WY68V5NlYy3bTPxmXbhU8e+ev7VenJ8gy
# 6NJm47nrWiIthP8qa5rvMSceL6FK/7o299ef1ctfvxmHgieBEz6LJ5UI0rP9UraC
# LpZDtMl5hHIoqjL4GPgXlvaV64FOmQ1jkI3xiW3SpMGkkg31PMYg+SXylTEWrOrs
# aCo2mkr1kU8zrDkt3RSpxb/FHoSI3UV3o++e7e4J5gqkHpS735ADMOxvIYQbaz8c
# ujfQhX18wbRJndCrDmp72rSjndxgIXrjkixs7ws5ldnw5RVr9IDSc3JEQKTHHvHa
# zbjTWBI22MbpYu41ybMHY3/VBNWnsussLI6S0aTy26xOrsZ02c8zb8xO0ILxCRs/
# kCCAB5/1NC4J7oye5obYCPXZ46kwJEUsASWoGybKJqaeFOhHME6JaKpNAJMIP7AH
# gHATWluqLsaR4ZqNbHMcZMxgYRZuxxdUlwr5nAQFmszdsT0i0nB+beSRzadXVBT9
# yPCyAc4tmSmbJTstLBhGGh6MNZZA3IxyICPUfxZ4ftScKgUu+azaLFRY+6KVZ9MZ
# tirInblm2RlInCYnf4xO9h0ZtCBxnyZgeiu1xcxb1jAF2YwkzJ2mBdrTRSVZOhQG
# P3Odxpq3xJWf52WBASnI0JZTCa5GKoLUoNiS3CWt
# SIG # End signature block
