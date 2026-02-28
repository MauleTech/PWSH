#Requires -Version 5.1

Function Protect-ConfigFile {
	<#
	.Synopsis
	Encrypts a configuration file for secure storage
	.Description
	Takes a plaintext configuration file and encrypts it using AES-256-CBC with
	HMAC-SHA256 integrity verification (Encrypt-then-MAC). The key is derived via
	PBKDF2-SHA256 with 600000 iterations. The encrypted file can be safely
	committed to a public or private repository.

	File format: Base64( salt[16] + iv[16] + hmac[32] + ciphertext )
	.Parameter Path
	Path to the plaintext configuration file (e.g. Sophos.csv, Action1.csv)
	.Parameter Password
	Password used for encryption. Must match the password used for decryption.
	.Parameter OutputPath
	Path for the encrypted output file. Defaults to the same directory with .enc extension
	.Example
	Protect-ConfigFile -Path .\Sophos.csv -Password "MySecurePassword"
	.Example
	Protect-ConfigFile -Path .\Action1.csv -Password "MySecurePassword" -OutputPath .\Action1.enc
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$Path,
		[Parameter(Mandatory = $true)]
		[string]$Password,
		[string]$OutputPath
	)

	if (-not (Test-Path $Path)) {
		throw "File not found: $Path"
	}

	if (-not $OutputPath) {
		$OutputPath = [System.IO.Path]::ChangeExtension($Path, '.enc')
	}

	$plainBytes = [System.IO.File]::ReadAllBytes((Resolve-Path $Path).Path)

	# Generate random salt and IV
	$salt = New-Object byte[] 16
	$iv = New-Object byte[] 16
	$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
	$rng.GetBytes($salt)
	$rng.GetBytes($iv)

	$keyDerivation = $null
	$aes = $null
	$encryptor = $null
	$hmac = $null
	$encKey = $null
	$hmacKey = $null

	try {
		# Derive 64 bytes: 32 for AES-256, 32 for HMAC-SHA256
		$keyDerivation = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
			$Password, $salt, 600000, [System.Security.Cryptography.HashAlgorithmName]::SHA256
		)
		$encKey = $keyDerivation.GetBytes(32)
		$hmacKey = $keyDerivation.GetBytes(32)

		# Encrypt with AES-256-CBC
		$aes = [System.Security.Cryptography.Aes]::Create()
		$aes.Key = $encKey
		$aes.IV = $iv
		$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
		$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

		$encryptor = $aes.CreateEncryptor()
		$ciphertext = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)

		# Compute HMAC-SHA256 over salt + iv + ciphertext (Encrypt-then-MAC)
		$dataToAuth = New-Object byte[] ($salt.Length + $iv.Length + $ciphertext.Length)
		[System.Buffer]::BlockCopy($salt, 0, $dataToAuth, 0, 16)
		[System.Buffer]::BlockCopy($iv, 0, $dataToAuth, 16, 16)
		[System.Buffer]::BlockCopy($ciphertext, 0, $dataToAuth, 32, $ciphertext.Length)

		$hmac = New-Object System.Security.Cryptography.HMACSHA256
		$hmac.Key = $hmacKey
		$tag = $hmac.ComputeHash($dataToAuth)

		# Combine: salt(16) + iv(16) + hmac(32) + ciphertext
		$combined = New-Object byte[] (16 + 16 + 32 + $ciphertext.Length)
		[System.Buffer]::BlockCopy($salt, 0, $combined, 0, 16)
		[System.Buffer]::BlockCopy($iv, 0, $combined, 16, 16)
		[System.Buffer]::BlockCopy($tag, 0, $combined, 32, 32)
		[System.Buffer]::BlockCopy($ciphertext, 0, $combined, 64, $ciphertext.Length)

		# Write as Base64
		$outputFullPath = if ([System.IO.Path]::IsPathRooted($OutputPath)) {
			$OutputPath
		} else {
			Join-Path (Get-Location) $OutputPath
		}
		[System.IO.File]::WriteAllText($outputFullPath, [System.Convert]::ToBase64String($combined))

		Write-Host "Encrypted file saved to: $outputFullPath" -ForegroundColor Green
	} finally {
		if ($encKey) { [System.Array]::Clear($encKey, 0, $encKey.Length) }
		if ($hmacKey) { [System.Array]::Clear($hmacKey, 0, $hmacKey.Length) }
		if ($hmac) { $hmac.Dispose() }
		if ($encryptor) { $encryptor.Dispose() }
		if ($aes) { $aes.Dispose() }
		if ($keyDerivation) { $keyDerivation.Dispose() }
		$rng.Dispose()
	}
}

Function Unprotect-ConfigFile {
	<#
	.Synopsis
	Decrypts an encrypted configuration file string
	.Description
	Decrypts Base64-encoded AES-256-CBC encrypted content with HMAC-SHA256
	integrity verification (Encrypt-then-MAC). The key is derived via
	PBKDF2-SHA256 with 600000 iterations. Returns the plaintext content as a string.
	Note: assumes the original file was UTF-8 encoded.

	Expected format: Base64( salt[16] + iv[16] + hmac[32] + ciphertext )
	.Parameter EncryptedContent
	The Base64-encoded encrypted content (as downloaded from BinCache)
	.Parameter Password
	The password that was used to encrypt the file via Protect-ConfigFile
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$EncryptedContent,
		[Parameter(Mandatory = $true)]
		[string]$Password
	)

	try {
		$combined = [System.Convert]::FromBase64String($EncryptedContent)
	} catch {
		throw "Invalid encrypted file format. The file does not appear to be properly encrypted."
	}

	# Minimum: salt(16) + iv(16) + hmac(32) + at least one AES block(16) = 80
	if ($combined.Length -lt 80) {
		throw "Invalid encrypted file: content too short."
	}

	# Extract salt(16) + iv(16) + hmac(32) + ciphertext
	$salt = New-Object byte[] 16
	$iv = New-Object byte[] 16
	$storedTag = New-Object byte[] 32
	$ciphertextLength = $combined.Length - 64
	$ciphertext = New-Object byte[] $ciphertextLength

	[System.Buffer]::BlockCopy($combined, 0, $salt, 0, 16)
	[System.Buffer]::BlockCopy($combined, 16, $iv, 0, 16)
	[System.Buffer]::BlockCopy($combined, 32, $storedTag, 0, 32)
	[System.Buffer]::BlockCopy($combined, 64, $ciphertext, 0, $ciphertextLength)

	$keyDerivation = $null
	$hmac = $null
	$aes = $null
	$decryptor = $null
	$encKey = $null
	$hmacKey = $null

	try {
		# Derive 64 bytes: 32 for AES-256, 32 for HMAC-SHA256
		$keyDerivation = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
			$Password, $salt, 600000, [System.Security.Cryptography.HashAlgorithmName]::SHA256
		)
		$encKey = $keyDerivation.GetBytes(32)
		$hmacKey = $keyDerivation.GetBytes(32)

		# Verify HMAC before decrypting (Encrypt-then-MAC)
		$dataToAuth = New-Object byte[] ($salt.Length + $iv.Length + $ciphertextLength)
		[System.Buffer]::BlockCopy($salt, 0, $dataToAuth, 0, 16)
		[System.Buffer]::BlockCopy($iv, 0, $dataToAuth, 16, 16)
		[System.Buffer]::BlockCopy($ciphertext, 0, $dataToAuth, 32, $ciphertextLength)

		$hmac = New-Object System.Security.Cryptography.HMACSHA256
		$hmac.Key = $hmacKey
		$computedTag = $hmac.ComputeHash($dataToAuth)

		# Constant-time comparison to prevent timing attacks
		$diff = 0
		for ($i = 0; $i -lt $computedTag.Length; $i++) {
			$diff = $diff -bor ($computedTag[$i] -bxor $storedTag[$i])
		}
		if ($diff -ne 0) {
			throw "Integrity check failed. The password is incorrect or the file has been tampered with."
		}

		# Decrypt with AES-256-CBC
		$aes = [System.Security.Cryptography.Aes]::Create()
		$aes.Key = $encKey
		$aes.IV = $iv
		$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
		$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

		$decryptor = $aes.CreateDecryptor()
		$plainBytes = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
	} finally {
		if ($encKey) { [System.Array]::Clear($encKey, 0, $encKey.Length) }
		if ($hmacKey) { [System.Array]::Clear($hmacKey, 0, $hmacKey.Length) }
		if ($hmac) { $hmac.Dispose() }
		if ($decryptor) { $decryptor.Dispose() }
		if ($aes) { $aes.Dispose() }
		if ($keyDerivation) { $keyDerivation.Dispose() }
	}

	# Assumes original file was UTF-8 encoded
	return [System.Text.Encoding]::UTF8.GetString($plainBytes)
}

Function Get-DecryptedConfig {
	<#
	.Synopsis
	Downloads and decrypts an encrypted configuration file from a URL
	.Description
	Fetches an encrypted .enc file via HTTPS and decrypts it using Unprotect-ConfigFile.
	Returns the plaintext content as a string.
	.Parameter Url
	The URL of the encrypted .enc file
	.Parameter Password
	The password to decrypt the file
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$Url,
		[Parameter(Mandatory = $true)]
		[string]$Password
	)

	$content = (Invoke-WebRequest -Uri $Url -Headers @{"Cache-Control"="no-cache"} -UseBasicParsing).Content
	return Unprotect-ConfigFile -EncryptedContent $content -Password $Password
}
