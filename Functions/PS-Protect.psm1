Function Get-StoredPassword {
	<#
	.Synopsis
	Retrieves a plaintext password from Windows Credential Manager
	.Description
	Uses the advapi32 CredRead API to look up a Generic credential by target name
	and return the stored password. Returns $null if the credential is not found.
	.Parameter Target
	The target name of the stored credential (e.g. "Powershell Client Install Password")
	.Example
	$pw = Get-StoredPassword -Target "Powershell Client Install Password"
	#>
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true)]
		[string]$Target
	)

	if (-not ([System.Management.Automation.PSTypeName]'CredManager').Type) {
		Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class CredManager {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credential);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern void CredFree(IntPtr credential);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    public static string GetPassword(string target) {
        IntPtr credPtr;
        if (!CredRead(target, 1, 0, out credPtr)) {
            return null;
        }
        try {
            CREDENTIAL cred = (CREDENTIAL)Marshal.PtrToStructure(credPtr, typeof(CREDENTIAL));
            if (cred.CredentialBlob != IntPtr.Zero && cred.CredentialBlobSize > 0) {
                return Marshal.PtrToStringUni(cred.CredentialBlob, cred.CredentialBlobSize / 2);
            }
            return null;
        } finally {
            CredFree(credPtr);
        }
    }
}
"@
	}

	return [CredManager]::GetPassword($Target)
}

Function Protect-ConfigFile {
	<#
	.Synopsis
	Encrypts a configuration file for secure storage
	.Description
	Takes a plaintext configuration file and encrypts it using AES-256-CBC with a
	password-derived key (PBKDF2-SHA256, 600000 iterations). The encrypted file
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

	$keyDerivation = $null
	$aes = $null
	$encryptor = $null

	try {
		# Derive AES-256 key from password using PBKDF2-SHA256 (600k iterations per NIST SP 800-63B)
		$keyDerivation = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
			$Password, $salt, 600000, [System.Security.Cryptography.HashAlgorithmName]::SHA256
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

		Write-Host "Encrypted file saved to: $outputFullPath" -ForegroundColor Green
	} finally {
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
	Decrypts Base64-encoded AES-256-CBC encrypted content using a password-derived
	key (PBKDF2-SHA256, 600000 iterations). Returns the plaintext content as a string.
	Note: assumes the original file was UTF-8 encoded.
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

	$keyDerivation = $null
	$aes = $null
	$decryptor = $null

	try {
		# Derive key from password using PBKDF2-SHA256 (600k iterations per NIST SP 800-63B)
		$keyDerivation = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
			$Password, $salt, 600000, [System.Security.Cryptography.HashAlgorithmName]::SHA256
		)
		$key = $keyDerivation.GetBytes(32)

		# Decrypt with AES-256-CBC
		$aes = [System.Security.Cryptography.Aes]::Create()
		$aes.Key = $key
		$aes.IV = $iv
		$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
		$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

		$decryptor = $aes.CreateDecryptor()
		$plainBytes = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
	} catch [System.Security.Cryptography.CryptographicException] {
		throw "Decryption failed. The password is incorrect or the file is corrupted."
	} finally {
		if ($decryptor) { $decryptor.Dispose() }
		if ($aes) { $aes.Dispose() }
		if ($keyDerivation) { $keyDerivation.Dispose() }
	}

	# Assumes original file was UTF-8 encoded
	return [System.Text.Encoding]::UTF8.GetString($plainBytes)
}
