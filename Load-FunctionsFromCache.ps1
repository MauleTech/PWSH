Set-ExecutionPolicy Bypass -Scope Process -Force

$bootTimer = [System.Diagnostics.Stopwatch]::StartNew()

# Set default IT folder path if not already defined
if (-not $ITFolder) {
    $Global:ITFolder = "$Env:SystemDrive\IT"
}

# Global paths expected by the function modules
$Global:PWSHFolder      = "$ITFolder\GitHub\PWSH"
$Global:FunctionsFolder = "$PWSHFolder\Functions"

# --- Locate a cached git executable (no downloads, no internet) ---

# MinGit binary path has shifted across versions: cmd\ (2.47.0+), mingw64\bin\ (intermediate), bin\ (legacy)
function Resolve-MinGitExe {
    param([string]$MinGitFolder = "$ITFolder\GitHub\MinGit")
    @(
        "$MinGitFolder\cmd\git.exe",
        "$MinGitFolder\mingw64\bin\git.exe",
        "$MinGitFolder\bin\git.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
}

$Global:GitExePath = Resolve-MinGitExe "$ITFolder\GitHub\MinGit"

if ($Global:GitExePath) {
    $Global:GitCommand = $Global:GitExePath
    $gitBinPath = Split-Path -Parent $Global:GitExePath
    if (($env:PATH -split ';') -notcontains $gitBinPath) {
        $env:PATH += ";$gitBinPath"
    }
}
else {
    # Fall back to well-known system install paths, then PATH
    $systemGit = @(
        "C:\Program Files\Git\bin\git.exe",
        "C:\Program Files (x86)\Git\bin\git.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $systemGit) {
        $gitCmd = Get-Command git -ErrorAction SilentlyContinue
        if ($gitCmd) { $systemGit = $gitCmd.Source }
    }

    if ($systemGit) {
        $Global:GitCommand = $systemGit
    }
    else {
        Write-Warning "No local git installation found. Functions that require git will not work."
    }
}

# --- Global utility functions expected by the loaded modules ---

# Run git commands using the .NET Process API (same implementation as LoadFunctions.txt)
function Global:Invoke-Git {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$GitPath,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Arguments,

        [Parameter(Mandatory=$false)]
        [string]$WorkingDirectory,

        [switch]$ShowOutput
    )

    if (-not $WorkingDirectory) {
        $WorkingDirectory = $PWD.Path
    }

    if (-not [System.IO.Path]::IsPathRooted($WorkingDirectory)) {
        throw "WorkingDirectory must be an absolute path: $WorkingDirectory"
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName  = $GitPath
    $psi.Arguments = ($Arguments | ForEach-Object {
        $escaped = $_ -replace '"', '\"'
        if ($_ -match '[\s"]') { "`"$escaped`"" } else { $_ }
    }) -join ' '
    $psi.WorkingDirectory       = $WorkingDirectory
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow         = $true

    $psi.EnvironmentVariables["GIT_TERMINAL_PROMPT"] = "0"

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi

    try {
        [void]$process.Start()

        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()

        if (-not $process.WaitForExit(60000)) {
            $process.Kill()
            [void][System.Threading.Tasks.Task]::WaitAll(@($stdoutTask, $stderrTask), 3000)
            throw "Git command timed out after 60 seconds: git $($Arguments -join ' ')"
        }

        $stdout = $stdoutTask.GetAwaiter().GetResult().TrimEnd([char]"`r", [char]"`n")
        $stderr = $stderrTask.GetAwaiter().GetResult().TrimEnd([char]"`r", [char]"`n")
        $output = if ($stdout) { $stdout -split "`r?`n" } else { @() }

        if ($process.ExitCode -ne 0) {
            $cmdString = "git $($Arguments -join ' ')"
            $errorMsg  = if ($stderr) { $stderr } elseif ($stdout) { $stdout } else { "Exit code $($process.ExitCode)" }
            throw "Git command '$cmdString' failed: $errorMsg"
        }

        if ($ShowOutput -and $output) { $output | Write-Output }

        return $output
    }
    finally {
        $process.Dispose()
    }
}

# Detect current branch; falls back to remote HEAD ref, then 'main'
function Global:Get-CurrentBranch {
    param([string]$Git, [string]$WorkDir)
    try {
        $branch = ((Invoke-Git -GitPath $Git -Arguments @("branch", "--show-current") -WorkingDirectory $WorkDir) -join "").Trim()
    }
    catch {
        Write-Warning "Failed to detect current branch: $($_.Exception.Message)"
        $branch = ""
    }

    if ([string]::IsNullOrWhiteSpace($branch)) {
        try {
            $headRef = ((Invoke-Git -GitPath $Git -Arguments @("symbolic-ref", "refs/remotes/origin/HEAD") -WorkingDirectory $WorkDir) -join "").Trim()
            $branch  = $headRef -replace '^refs/remotes/origin/', ''
        }
        catch { $branch = "" }

        if ([string]::IsNullOrWhiteSpace($branch)) {
            $branch = "main"
        }
    }
    return $branch
}

# Import all .psm1 modules from the Functions folder
function Global:Import-ITModules {
    $files = Get-ChildItem -Path $Global:FunctionsFolder -Filter "*.psm1" -File -ErrorAction SilentlyContinue
    if ($files) {
        $files | ForEach-Object {
            Import-Module $_.FullName -Global -Force -Verbose:$false -WarningAction SilentlyContinue
        }
    }
}

# Update-ITFunctions is called by some modules -- provide an offline-aware version
function Global:Update-ITFunctions {
    Write-Host "Checking for internet connectivity..." -ForegroundColor Yellow
    $online = $false
    try {
        $request = [System.Net.WebRequest]::Create("https://github.com")
        $request.Timeout = 5000
        $request.Method = "HEAD"
        $response = $request.GetResponse()
        $response.Close()
        $online = $true
    }
    catch {}

    if ($online -and (Test-Path $Global:PWSHFolder) -and $Global:GitCommand) {
        Write-Host "Internet available -- pulling latest changes..." -ForegroundColor Yellow
        try {
            # Inline sync: fetch + reset to remote branch
            $branch = Get-CurrentBranch -Git $Global:GitCommand -WorkDir $Global:PWSHFolder
            Invoke-Git -GitPath $Global:GitCommand -Arguments @("fetch", "origin") -WorkingDirectory $Global:PWSHFolder | Out-Null
            $remoteRef = "origin/$branch"
            Invoke-Git -GitPath $Global:GitCommand -Arguments @("checkout", "-B", $branch, $remoteRef) -WorkingDirectory $Global:PWSHFolder | Out-Null
            Invoke-Git -GitPath $Global:GitCommand -Arguments @("reset", "--hard", $remoteRef) -WorkingDirectory $Global:PWSHFolder | Out-Null
            Import-ITModules
            Write-Host "IT Functions updated and reloaded successfully!" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to update: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Reloading from cache instead..." -ForegroundColor Yellow
            Import-ITModules
        }
    }
    else {
        Write-Host "No internet connection -- reloading modules from local cache." -ForegroundColor Yellow
        Import-ITModules
        Write-Host "Cached functions reloaded." -ForegroundColor Green
    }
}

# Silent update variant used by background jobs
function Global:Update-ITPS {
    try {
        Import-ITModules
    }
    catch {
        Write-Warning "Update-ITPS: $_"
    }
}

# --- Load cached modules ---

if (-not (Test-Path $Global:FunctionsFolder)) {
    Write-Host "Functions folder not found: $Global:FunctionsFolder" -ForegroundColor Red
    Write-Host "Run the full loader (irm ps.mauletech.com | iex) on a machine with internet first." -ForegroundColor Yellow
    return
}

$moduleFiles = @(Get-ChildItem -Path $Global:FunctionsFolder -Filter "*.psm1" -File)
if ($moduleFiles.Count -eq 0) {
    Write-Host "No .psm1 files found in $Global:FunctionsFolder" -ForegroundColor Yellow
    return
}

Write-Host "Loading PowerShell Functions from cache..." -ForegroundColor Yellow
Import-ITModules

$LoadedModules = @(Get-Module | Where-Object { $_.Path -like "$Global:FunctionsFolder*" })
if ($LoadedModules) {
    $bootTimer.Stop()
    $elapsed   = "{0:N1}s" -f $bootTimer.Elapsed.TotalSeconds
    $funcCount = (Get-Command -Module ($LoadedModules.Name) -ErrorAction SilentlyContinue |
                  Where-Object { $_.Source -like "PS-*" }).Count
    Write-Host " $funcCount Functions loaded from cache in $elapsed" -ForegroundColor Green
    Write-Host " - Get-ITFunctions to see commands. Update-ITFunctions to check for updates."
    Write-Host ""
}
else {
    Write-Host "Modules were not loaded successfully. Check the files in $Global:FunctionsFolder" -ForegroundColor Red
}

Set-Location $ITFolder
