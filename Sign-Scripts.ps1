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

# Write PFX to temp file for import and diagnostics
$tempPfx = Join-Path ([System.IO.Path]::GetTempPath()) "sign-$([Guid]::NewGuid().ToString('N')).pfx"
[System.IO.File]::WriteAllBytes($tempPfx, $pfxBytes)
[System.Array]::Clear($pfxBytes, 0, $pfxBytes.Length)

# Dump PFX structure via certutil so we can see whether a private key is present
Write-Host "  Inspecting PFX structure with certutil..." -ForegroundColor Gray
$certutilOutput = & certutil -dump -p '""' $tempPfx 2>&1 | Out-String
# Show key-related lines (avoid leaking full cert details)
$certutilOutput -split "`n" | Where-Object {
    $_ -match 'Key Container|Private Key|CERT_KEY_PROV_INFO|Provider|KeySpec|Bag Attribute|friendlyName|Microsoft'
} | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }

# Try multiple import strategies
$cert = $null

# Strategy 1: Import-PfxCertificate (native PowerShell cmdlet)
Write-Host "  Import strategy: Import-PfxCertificate..." -ForegroundColor Gray
try {
    $emptyPw = ConvertTo-SecureString -String '' -AsPlainText -Force
    $cert = Import-PfxCertificate -FilePath $tempPfx -CertStoreLocation Cert:\CurrentUser\My `
        -Password $emptyPw -Exportable
    Write-Host "    HasPrivateKey: $($cert.HasPrivateKey)" -ForegroundColor Gray
}
catch {
    Write-Host "    Failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Strategy 2: certutil -importpfx (Windows CryptoAPI, bypasses .NET entirely)
if (-not $cert -or -not $cert.HasPrivateKey) {
    Write-Host "  Import strategy: certutil -importpfx..." -ForegroundColor Gray
    $importOutput = & certutil -f -user -p '""' -importpfx My $tempPfx 2>&1 | Out-String
    Write-Host "    certutil output:" -ForegroundColor Gray
    $importOutput -split "`n" | ForEach-Object { Write-Host "      $_" -ForegroundColor Gray }

    # Retrieve the cert from the store by finding the most recently added cert
    # that matches what was just imported
    $pfxForSubject = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($tempPfx)
    $expectedThumbprint = $pfxForSubject.Thumbprint
    $pfxForSubject.Dispose()
    $cert = Get-ChildItem "Cert:\CurrentUser\My\$expectedThumbprint" -ErrorAction SilentlyContinue
    if ($cert) {
        Write-Host "    Found cert in store - HasPrivateKey: $($cert.HasPrivateKey)" -ForegroundColor Gray
    }
    else {
        Write-Host "    Certificate not found in store after certutil import" -ForegroundColor Yellow
    }
}

# Strategy 3: X509Certificate2Collection with PersistKeySet + MachineKeySet
if (-not $cert -or -not $cert.HasPrivateKey) {
    Write-Host "  Import strategy: X509Certificate2Collection..." -ForegroundColor Gray
    try {
        $collection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $collection.Import(
            $tempPfx,
            [string]::Empty,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        )
        Write-Host "    Certificates in collection: $($collection.Count)" -ForegroundColor Gray
        foreach ($c in $collection) {
            Write-Host "    Subject: $($c.Subject) | HasPrivateKey: $($c.HasPrivateKey) | KeyAlg: $($c.PublicKey.Oid.FriendlyName)" -ForegroundColor Gray
        }
        $cert = $collection | Where-Object { $_.HasPrivateKey } | Select-Object -First 1
        if (-not $cert) { $cert = $collection[0] }
    }
    catch {
        Write-Host "    Failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Remove-Item $tempPfx -Force -ErrorAction SilentlyContinue

if (-not $cert -or -not $cert.HasPrivateKey) {
    Write-Host ""
    Write-Host "  === DIAGNOSTIC SUMMARY ===" -ForegroundColor Red
    Write-Host "  All import strategies failed to find a private key." -ForegroundColor Red
    Write-Host "  This typically means the Key Vault certificate's key policy" -ForegroundColor Red
    Write-Host "  has 'Exportable Private Key' set to NO." -ForegroundColor Red
    Write-Host ""
    Write-Host "  To fix: In Azure Portal > Key Vault > Certificates > $CertName" -ForegroundColor Yellow
    Write-Host "    > Certificate Policy > Advanced Policy Configuration" -ForegroundColor Yellow
    Write-Host "    > Set 'Exportable Private Key' to YES" -ForegroundColor Yellow
    Write-Host "    > Then create a new version of the certificate." -ForegroundColor Yellow
    throw "Certificate '$CertName' does not have a private key. The Key Vault certificate likely has a non-exportable key policy. See diagnostic output above."
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

# Files that should never be signed (not PowerShell)
$excludeFiles = @(
    "URL-List.csv",
    "urls.txt",
    "Sophos_certificate.pem"
)

$filesToSign = @()

# All .ps1 and .psm1 files anywhere in the repo
$filesToSign += Get-ChildItem -Path (Join-Path $RepoRoot '*') -Include "*.ps1", "*.psm1" -Recurse -File |
    Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' }

# .txt files in Functions/, OneOffs/, and Scripts/ (these are PowerShell per .gitattributes)
$txtDirs = @("Functions", "OneOffs", "Scripts")
foreach ($dir in $txtDirs) {
    $dirPath = Join-Path $RepoRoot $dir
    if (Test-Path $dirPath) {
        $filesToSign += Get-ChildItem -Path $dirPath -Filter "*.txt" -Recurse -File |
            Where-Object { $_.Name -notin $excludeFiles }
    }
}

# Also include LoadFunctions.txt at the repo root
$loadFunctions = Join-Path $RepoRoot "LoadFunctions.txt"
if (Test-Path $loadFunctions) {
    $filesToSign += Get-Item $loadFunctions
}

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

# Remove the imported certificate from the store and release from memory
$certThumbprint = $cert.Thumbprint
$cert.Dispose()
Get-ChildItem "Cert:\CurrentUser\My\$certThumbprint" -ErrorAction SilentlyContinue | Remove-Item -Force

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
