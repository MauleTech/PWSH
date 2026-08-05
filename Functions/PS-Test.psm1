Function Test-SmtpRelay {
	<#
	.SYNOPSIS
		Sends a test email through an SMTP relay. Replacement for the obsolete Send-MailMessage cmdlet.
	.DESCRIPTION
		Send-MailMessage is obsolete because its underlying SmtpClient class cannot reliably
		negotiate modern TLS. This function wraps System.Net.Mail directly, which is the same
		approach Microsoft's own migration guidance points to when Send-MgUserMail (Graph, needs
		a mailbox/tenant) or MailKit (needs a module) do not fit the scenario - such as testing
		anonymous SMTP relay from a scanner/MFP through an Exchange Online Protection connector.
	.PARAMETER From
		Sender email address.
	.PARAMETER To
		One or more recipient email addresses.
	.PARAMETER SmtpServer
		SMTP server or relay hostname, e.g. contoso-com.mail.protection.outlook.com
	.PARAMETER Subject
		Email subject line.
	.PARAMETER Body
		Email body text. Defaults to empty string.
	.PARAMETER Port
		SMTP port. Defaults to 25.
	.PARAMETER Credential
		Optional PSCredential for authenticated relay. Omit for anonymous relay (scanner/MFP style).
	.PARAMETER UseTls
		Whether to negotiate STARTTLS (explicit TLS on port 25/587). Defaults to $true.
		Pass -UseTls:$false only to test plaintext/anonymous relay behavior, e.g. reproducing
		a misconfigured scanner. Note: System.Net.Mail only supports explicit TLS (STARTTLS),
		not implicit TLS/SMTPS on port 465.
	.EXAMPLE
		Test-SmtpRelay -From "scanner@contoso.com" -To "user@contoso.com" -SmtpServer "contoso-com.mail.protection.outlook.com" -Subject "On-Prem email test" -Body "Test" -Port 25 -Verbose
	.EXAMPLE
		Test-SmtpRelay -From "scanner@contoso.com" -To "user@contoso.com" -SmtpServer "contoso-com.mail.protection.outlook.com" -Subject "Plaintext relay test" -UseTls:$false -Verbose
	#>
	[CmdletBinding(SupportsShouldProcess)]
	param(
		[Parameter(Mandatory)]
		[string]$From,

		[Parameter(Mandatory)]
		[string[]]$To,

		[Parameter(Mandatory)]
		[string]$SmtpServer,

		[Parameter(Mandatory)]
		[string]$Subject,

		[string]$Body = "",

		[int]$Port = 25,

		[PSCredential]$Credential,

		[bool]$UseTls = $true
	)

	Write-Verbose "Building message from $From to $($To -join ', ')"
	$mailMessage = [System.Net.Mail.MailMessage]::new()
	$mailMessage.From = $From
	foreach ($recipient in $To) { $mailMessage.To.Add($recipient) }
	$mailMessage.Subject = $Subject
	$mailMessage.Body = $Body

	$smtpClient = [System.Net.Mail.SmtpClient]::new($SmtpServer, $Port)
	$smtpClient.EnableSsl = $UseTls
	Write-Verbose "TLS (STARTTLS): $UseTls"

	if ($Credential) {
		Write-Verbose "Using authenticated relay as $($Credential.UserName)"
		$smtpClient.Credentials = [System.Net.NetworkCredential]::new($Credential.UserName, $Credential.Password)
	} else {
		Write-Verbose "Using anonymous relay (no credentials)"
		$smtpClient.UseDefaultCredentials = $false
	}

	if ($PSCmdlet.ShouldProcess("$SmtpServer`:$Port", "Send test email to $($To -join ', ')")) {
		try {
			Write-Verbose "Connecting to $SmtpServer on port $Port..."
			$smtpClient.Send($mailMessage)
			Write-Host "Message sent successfully to $($To -join ', ')" -ForegroundColor Green
			[PSCustomObject]@{
				Success    = $true
				From       = $From
				To         = $To -join ', '
				SmtpServer = $SmtpServer
				Port       = $Port
				UseTls     = $UseTls
				Error      = $null
			}
		} catch {
			Write-Host "Failed to send message: $($_.Exception.Message)" -ForegroundColor Red
			[PSCustomObject]@{
				Success    = $false
				From       = $From
				To         = $To -join ', '
				SmtpServer = $SmtpServer
				Port       = $Port
				UseTls     = $UseTls
				Error      = $_.Exception.Message
			}
		} finally {
			$mailMessage.Dispose()
			$smtpClient.Dispose()
		}
	}
}
