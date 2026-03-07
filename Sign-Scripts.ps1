<#
.SYNOPSIS
    Signs all PowerShell scripts in the repository using an Azure Key Vault certificate.

.DESCRIPTION
    Authenticates to Azure via Service Principal (App Registration), retrieves a code
    signing certificate from Azure Key Vault, and applies Authenticode signatures to
    all .ps1, .psm1, and PowerShell .txt files in the repository.

    Requires the certificate's private key to be exportable in Key Vault.
    The App Registration needs Key Vault Secret "Get" permission (secrets, not certificates,
    because the PFX with private key is accessed via the Secrets API).

.PARAMETER VaultName
    The name of the Azure Key Vault containing the code signing certificate.

.PARAMETER CertName
    The name of the certificate in Azure Key Vault.

.PARAMETER TenantId
    The Azure AD tenant ID for the App Registration.

.PARAMETER ClientId
    The Application (client) ID of the App Registration.

.PARAMETER ClientSecret
    The client secret for the App Registration, as a SecureString.

.PARAMETER TimestampServer
    The RFC 3161 timestamp server URL. Defaults to DigiCert's timestamp server.
    Timestamping ensures signatures remain valid after the certificate expires.

.PARAMETER RepoRoot
    The root directory of the repository. Defaults to the directory containing this script.

.EXAMPLE
    $secret = ConvertTo-SecureString -String "xxxxx" -AsPlainText -Force
    .\Sign-Scripts.ps1 -VaultName "my-vault" -CertName "code-signing" `
        -TenantId "xxxxx" -ClientId "xxxxx" -ClientSecret $secret
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VaultName,

    [Parameter(Mandatory = $true)]
    [string]$CertName,

    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [Parameter(Mandatory = $true)]
    [SecureString]$ClientSecret,

    [Parameter(Mandatory = $false)]
    [string]$TimestampServer = "http://timestamp.digicert.com",

    [Parameter(Mandatory = $false)]
    [string]$RepoRoot = $PSScriptRoot
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Code Signing - Azure Key Vault" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# -------------------------------------------------------------------
# 1. Install / Import required modules
# -------------------------------------------------------------------
Write-Host "[1/5] Checking required PowerShell modules..." -ForegroundColor Yellow

$requiredModules = @("Az.Accounts", "Az.KeyVault")
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "  Installing $mod..."
        Install-Module -Name $mod -Force -Scope CurrentUser -AllowClobber
    }
    Import-Module $mod
}
Write-Host "  Modules ready." -ForegroundColor Green

# -------------------------------------------------------------------
# 2. Authenticate to Azure with Service Principal
# -------------------------------------------------------------------
Write-Host "[2/5] Authenticating to Azure..." -ForegroundColor Yellow

$credential = New-Object System.Management.Automation.PSCredential($ClientId, $ClientSecret)
Connect-AzAccount -ServicePrincipal -Credential $credential -Tenant $TenantId | Out-Null

Write-Host "  Authenticated as Service Principal ($ClientId)." -ForegroundColor Green

# -------------------------------------------------------------------
# 3. Retrieve code signing certificate from Key Vault
# -------------------------------------------------------------------
Write-Host "[3/5] Retrieving certificate '$CertName' from vault '$VaultName'..." -ForegroundColor Yellow

# The certificate's private key is accessed via the Secrets API (PFX format).
# This requires the App Registration to have "Get" permission on Key Vault Secrets.
$secret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $CertName

# Validate content type — we need PFX (PKCS#12), not PEM
$contentType = $secret.ContentType
Write-Host "  Content type: $contentType" -ForegroundColor Gray
if ($contentType -eq 'application/x-pem-file') {
    throw "Certificate '$CertName' uses PEM content type in Key Vault. Re-import it as PFX (PKCS#12) format so the private key can be loaded by this script."
}
if ($contentType -and $contentType -ne 'application/x-pkcs12') {
    Write-Warning "Unexpected content type '$contentType'; expected 'application/x-pkcs12' (PFX). Proceeding anyway."
}

# Extract the base64-encoded PFX from the SecureString value.
# Using Marshal rather than -AsPlainText to avoid potential encoding issues.
$ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret.SecretValue)
try {
    $base64Value = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
}
finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
}

$pfxBytes = [Convert]::FromBase64String($base64Value)
$base64Value = $null
Write-Host "  PFX data size: $($pfxBytes.Length) bytes" -ForegroundColor Gray

# Write PFX to temp file for import
$tempPfx = Join-Path ([System.IO.Path]::GetTempPath()) "sign-$([Guid]::NewGuid().ToString('N')).pfx"
[System.IO.File]::WriteAllBytes($tempPfx, $pfxBytes)
[System.Array]::Clear($pfxBytes, 0, $pfxBytes.Length)

$cert = $null
try {
    # Import-PfxCertificate is the most reliable import method on Windows.
    # Azure Key Vault Secrets API returns PFX with an empty password.
    # Note: ConvertTo-SecureString rejects empty strings, so use the constructor.
    $emptyPw = New-Object System.Security.SecureString
    $cert = Import-PfxCertificate -FilePath $tempPfx -CertStoreLocation Cert:\CurrentUser\My `
        -Password $emptyPw -Exportable
    Write-Host "  Certificate imported: $($cert.Subject)" -ForegroundColor Gray
    Write-Host "  HasPrivateKey: $($cert.HasPrivateKey)" -ForegroundColor Gray
}
catch {
    $primaryError = $_.Exception.Message
    Write-Host "  Import-PfxCertificate failed: $primaryError" -ForegroundColor Yellow
    # Fallback: load via .NET constructor (no cert store needed)
    try {
        $pfxBytes2 = [System.IO.File]::ReadAllBytes($tempPfx)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $pfxBytes2,
            [string]::Empty,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet -bor
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        )
        [System.Array]::Clear($pfxBytes2, 0, $pfxBytes2.Length)
        Write-Host "  Fallback import succeeded: $($cert.Subject)" -ForegroundColor Gray
        Write-Host "  HasPrivateKey: $($cert.HasPrivateKey)" -ForegroundColor Gray
    }
    catch {
        throw "Failed to load PFX certificate from Key Vault. Primary error: $primaryError. Fallback error: $($_.Exception.Message)"
    }
}
finally {
    Remove-Item $tempPfx -Force -ErrorAction SilentlyContinue
}

if (-not $cert.HasPrivateKey) {
    $msg = @"
Certificate '$CertName' does not have a private key.
The PFX from Key Vault's Secrets API does not contain the private key.

Common causes:
  1. The certificate's key policy has 'Exportable Private Key' set to NO.
  2. The policy was recently changed to exportable but a NEW VERSION of the
     certificate was not created. Policy changes only take effect on new versions.

To fix in Azure Portal:
  Key Vault > Certificates > $CertName > Certificate Policy
    > Advanced Policy Configuration > Set 'Exportable Private Key' to YES
  Then click 'Create a new version' (or delete and re-import the certificate).
"@
    throw $msg
}

# Verify the certificate has the Code Signing EKU
$codeSigningOid = "1.3.6.1.5.5.7.3.3"
$hasCodeSigningEku = ($cert.Extensions |
    Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } |
    ForEach-Object { $_.EnhancedKeyUsages } |
    Where-Object { $_.Value -eq $codeSigningOid } |
    Measure-Object).Count -gt 0

if (-not $hasCodeSigningEku) {
    Write-Warning "Certificate '$CertName' does not have the Code Signing enhanced key usage (EKU). Signing may fail."
}

if ($cert.NotAfter -lt (Get-Date)) {
    throw "Certificate '$CertName' expired on $($cert.NotAfter.ToString('yyyy-MM-dd')). Renew it in Key Vault before signing."
}

$daysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days
if ($daysUntilExpiry -le 30) {
    Write-Warning "Certificate '$CertName' expires in $daysUntilExpiry day(s) on $($cert.NotAfter.ToString('yyyy-MM-dd')). Renew it soon."
}

Write-Host "  Certificate retrieved successfully." -ForegroundColor Green
Write-Host "  Subject:  $($cert.Subject)" -ForegroundColor Gray
Write-Host "  Issuer:   $($cert.Issuer)" -ForegroundColor Gray
Write-Host "  Expires:  $($cert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Gray
Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray

# -------------------------------------------------------------------
# 4. Discover all scripts to sign
# -------------------------------------------------------------------
Write-Host "[4/5] Discovering scripts to sign..." -ForegroundColor Yellow

# Files that should never be signed
$excludeFiles = @(
    "URL-List.csv",
    "Sophos_certificate.pem"
)

$filesToSign = @()

# All .ps1 and .psm1 files anywhere in the repo
$filesToSign += Get-ChildItem -Path (Join-Path $RepoRoot '*') -Include "*.ps1", "*.psm1" -Recurse -File |
    Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' }

# Note: .txt files are excluded — Windows does not recognize them as a signable format,
# so Set-AuthenticodeSignature will fail with "UnknownError" on .txt files.

# Deduplicate
$filesToSign = $filesToSign | Sort-Object FullName -Unique

# Exclude the signing script itself
$selfPath = $MyInvocation.MyCommand.Path
$filesToSign = $filesToSign | Where-Object { $_.FullName -ne $selfPath }

Write-Host "  Found $($filesToSign.Count) files to sign." -ForegroundColor Green

# -------------------------------------------------------------------
# 5. Sign all scripts
# -------------------------------------------------------------------
Write-Host "[5/5] Signing scripts..." -ForegroundColor Yellow

$signed = 0
$failed = 0

try {
    foreach ($file in $filesToSign) {
        $relativePath = $file.FullName.Replace($RepoRoot, "").TrimStart("\", "/")

        try {
            $result = Set-AuthenticodeSignature -FilePath $file.FullName -Certificate $cert `
                -TimestampServer $TimestampServer -HashAlgorithm SHA256

            if ($result.Status -eq "Valid") {
                Write-Host "  [SIGNED] $relativePath" -ForegroundColor Green
                $signed++
            }
            else {
                Write-Host "  [FAILED] $relativePath - Status: $($result.Status) - $($result.StatusMessage)" -ForegroundColor Red
                $failed++
            }
        }
        catch {
            Write-Host "  [ERROR]  $relativePath - $($_.Exception.Message)" -ForegroundColor Red
            $failed++
        }
    }
}
finally {
    # Always clean up: remove the imported certificate from the store and release from memory
    if ($cert) {
        $certThumbprint = $cert.Thumbprint
        $cert.Dispose()
        Get-ChildItem "Cert:\CurrentUser\My\$certThumbprint" -ErrorAction SilentlyContinue | Remove-Item -Force
    }
    if ($emptyPw) {
        $emptyPw.Dispose()
    }
}

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Signing Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Signed:  $signed" -ForegroundColor Green
Write-Host "  Failed:  $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })
Write-Host "  Total:   $($filesToSign.Count)" -ForegroundColor Cyan

if ($failed -gt 0) {
    Write-Host "$failed file(s) failed to sign." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "All scripts signed successfully." -ForegroundColor Green
exit 0
