Function Protect-ConfigFile {
	<#
	.Synopsis
	Encrypts a configuration file for secure storage
	.Description
	Takes a plaintext configuration file and encrypts it using AES-256-CBC with a
	password-derived key (PBKDF2-SHA256, 100000 iterations). The encrypted file
	can be safely committed to a public or private repository.
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

	# Derive AES-256 key from password using PBKDF2-SHA256
	$keyDerivation = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
		$Password, $salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256
	)
	$key = $keyDerivation.GetBytes(32)

	# Encrypt with AES-256-CBC
	$aes = [System.Security.Cryptography.Aes]::Create()
	$aes.Key = $key
	$aes.IV = $iv
	$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
	$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

	$encryptor = $aes.CreateEncryptor()
	$ciphertext = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)

	# Combine: salt(16) + iv(16) + ciphertext
	$combined = New-Object byte[] ($salt.Length + $iv.Length + $ciphertext.Length)
	[System.Buffer]::BlockCopy($salt, 0, $combined, 0, 16)
	[System.Buffer]::BlockCopy($iv, 0, $combined, 16, 16)
	[System.Buffer]::BlockCopy($ciphertext, 0, $combined, 32, $ciphertext.Length)

	# Write as Base64
	$outputFullPath = if ([System.IO.Path]::IsPathRooted($OutputPath)) {
		$OutputPath
	} else {
		Join-Path (Get-Location) $OutputPath
	}
	[System.IO.File]::WriteAllText($outputFullPath, [System.Convert]::ToBase64String($combined))

	# Cleanup
	$encryptor.Dispose()
	$aes.Dispose()
	$keyDerivation.Dispose()
	$rng.Dispose()

	Write-Host "Encrypted file saved to: $outputFullPath" -ForegroundColor Green
}

Function Unprotect-ConfigFile {
	<#
	.Synopsis
	Decrypts an encrypted configuration file string
	.Description
	Decrypts Base64-encoded AES-256-CBC encrypted content using a password-derived
	key (PBKDF2-SHA256, 100000 iterations). Returns the plaintext content as a string.
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

	if ($combined.Length -lt 33) {
		throw "Invalid encrypted file: content too short."
	}

	# Extract salt(16) + iv(16) + ciphertext
	$salt = New-Object byte[] 16
	$iv = New-Object byte[] 16
	$ciphertextLength = $combined.Length - 32
	$ciphertext = New-Object byte[] $ciphertextLength

	[System.Buffer]::BlockCopy($combined, 0, $salt, 0, 16)
	[System.Buffer]::BlockCopy($combined, 16, $iv, 0, 16)
	[System.Buffer]::BlockCopy($combined, 32, $ciphertext, 0, $ciphertextLength)

	# Derive key from password using PBKDF2-SHA256
	$keyDerivation = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
		$Password, $salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256
	)
	$key = $keyDerivation.GetBytes(32)

	# Decrypt with AES-256-CBC
	$aes = [System.Security.Cryptography.Aes]::Create()
	$aes.Key = $key
	$aes.IV = $iv
	$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
	$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

	try {
		$decryptor = $aes.CreateDecryptor()
		$plainBytes = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
		$decryptor.Dispose()
	} catch [System.Security.Cryptography.CryptographicException] {
		$aes.Dispose()
		$keyDerivation.Dispose()
		throw "Decryption failed. The password is incorrect or the file is corrupted."
	}

	$aes.Dispose()
	$keyDerivation.Dispose()

	return [System.Text.Encoding]::UTF8.GetString($plainBytes)
}
