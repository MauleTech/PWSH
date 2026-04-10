Set-ExecutionPolicy Bypass -Scope Process -Force

$bootTimer = [System.Diagnostics.Stopwatch]::StartNew()

if (-not $ITFolder) {
    $Global:ITFolder = "$Env:SystemDrive\IT"
}

# Loaded modules may make web requests; ensure TLS 1.2 is available
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

$Global:PWSHFolder      = "$ITFolder\GitHub\PWSH"
$Global:FunctionsFolder = "$PWSHFolder\Functions"

# Locate a cached git executable -- MinGit paths first, then system installs, then PATH.
# Sets $Global:GitCommand which some modules reference.
$Global:GitExePath = $null
foreach ($candidate in @(
    "$ITFolder\GitHub\MinGit\cmd\git.exe",
    "$ITFolder\GitHub\MinGit\mingw64\bin\git.exe",
    "$ITFolder\GitHub\MinGit\bin\git.exe",
    "C:\Program Files\Git\bin\git.exe",
    "C:\Program Files (x86)\Git\bin\git.exe"
)) {
    if (Test-Path $candidate) { $Global:GitExePath = $candidate; break }
}
if (-not $Global:GitExePath) {
    $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    if ($gitCmd) { $Global:GitExePath = $gitCmd.Source }
}

if ($Global:GitExePath) {
    $Global:GitCommand = $Global:GitExePath
    $gitBinPath = Split-Path -Parent $Global:GitExePath
    if (($env:PATH -split ';') -notcontains $gitBinPath) {
        $env:PATH += ";$gitBinPath"
    }
}
else {
    Write-Warning "No local git installation found. Functions that require git will not work."
}

# --- Global functions that loaded modules depend on ---

function Global:Import-ITModules {
    $files = Get-ChildItem -Path $Global:FunctionsFolder -Filter "*.psm1" -File -ErrorAction SilentlyContinue
    if ($files) {
        $files | ForEach-Object {
            Import-Module $_.FullName -Global -Force -Verbose:$false -WarningAction SilentlyContinue
        }
    }
}

# Modules call Update-ITFunctions expecting a refresh; offline, that means reimporting from disk
function Global:Update-ITFunctions {
    Write-Host "Reloading modules from local cache..." -ForegroundColor Yellow
    Import-ITModules
    Write-Host "Cached functions reloaded." -ForegroundColor Green
    Write-Host "For online updates run: irm ps.mauletech.com | iex" -ForegroundColor Cyan
}

function Global:Update-ITPS {
    try { Import-ITModules }
    catch { Write-Warning "Update-ITPS: $_" }
}

# --- Load cached modules ---

# Single enumeration: used for the emptiness check and passed into Import-Module
$moduleFiles = @(Get-ChildItem -Path $Global:FunctionsFolder -Filter "*.psm1" -File -ErrorAction SilentlyContinue)
if ($moduleFiles.Count -eq 0) {
    Write-Host "No cached modules found in $Global:FunctionsFolder" -ForegroundColor Red
    Write-Host "Run the full loader first: irm ps.mauletech.com | iex" -ForegroundColor Yellow
    return
}

Write-Host "Loading PowerShell Functions from cache..." -ForegroundColor Yellow
$moduleFiles | ForEach-Object {
    Import-Module $_.FullName -Global -Force -Verbose:$false -WarningAction SilentlyContinue
}

$LoadedModules = @(Get-Module | Where-Object { $_.Path -like "$Global:FunctionsFolder*" })
if ($LoadedModules) {
    $bootTimer.Stop()
    $elapsed   = "{0:N1}s" -f $bootTimer.Elapsed.TotalSeconds
    # Use ExportedCommands from already-loaded module objects instead of the expensive Get-Command call
    $funcCount = ($LoadedModules | Where-Object { $_.Name -like "PS-*" } |
                  ForEach-Object { $_.ExportedCommands.Count } | Measure-Object -Sum).Sum
    Write-Host " $funcCount Functions loaded from cache in $elapsed" -ForegroundColor Green
    Write-Host " - Get-ITFunctions to see commands. Update-ITFunctions to reload from cache."
    Write-Host ""
}
else {
    Write-Host "Modules were not loaded successfully. Check the files in $Global:FunctionsFolder" -ForegroundColor Red
}

Set-Location $ITFolder
