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
