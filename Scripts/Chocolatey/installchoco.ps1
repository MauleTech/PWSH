Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

Write-Host "Install Chocolatey Server"

Function Update-ChocoPath {
    Write-Host 'Ensuring Chocolatey commands are on the path'
    $chocoInstallVariableName = "ChocolateyInstall"
    $chocoPath = [Environment]::GetEnvironmentVariable($chocoInstallVariableName)

    if (-not $chocoPath) {
        $chocoPath = "$env:ALLUSERSPROFILE\Chocolatey"
    }

    if (-not (Test-Path ($chocoPath))) {
        $chocoPath = "$env:PROGRAMDATA\chocolatey"
    }

    $chocoExePath = Join-Path $chocoPath -ChildPath 'bin'

    # Update current process PATH environment variable if it needs updating.
    if ($env:Path -notlike "*$chocoExePath*") {
        $env:Path = [Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine);
    }
}

If ((Get-Command "$env:PROGRAMDATA\chocolatey\choco.exe" -ErrorAction SilentlyContinue) -and !(Get-Command "choco.exe" -ErrorAction SilentlyContinue)) {
    Update-ChocoPath
}

If (Get-Command choco.exe -ErrorAction SilentlyContinue) {
    Set-ChocolateySources
    If (Get-Command choco -errorAction SilentlyContinue) {
        choco upgrade chocolatey -y
    }
} else {
    $installed = $false
    
    # Method 1: Try winget
    if (-not $installed) {
        try {
            Write-Host "Attempting to use winget to install chocolatey."
            winget install --id chocolatey.chocolatey --source winget -h --accept-package-agreements --accept-source-agreements
            Update-ChocoPath
            Get-Command 'choco.exe' -ErrorAction Stop
            $installed = $true
        }
        catch {
            Write-Host "Winget installation failed. Trying next method."
        }
    }
    
    # Method 2: Try NuGet
    if (-not $installed) {
        try {
            Write-Host "Attempting to use nuget to install chocolatey."
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force
            if (-not (Get-PSRepository -Name 'MauleCache' -ErrorAction SilentlyContinue)) {
                Register-PSRepository -Name 'MauleCache' -SourceLocation 'https://cache.mauletech.com/nuget/choco/' -PublishLocation 'https://cache.mauletech.com/nuget/choco/' -PackageManagementProvider nuget -InstallationPolicy Trusted
            }
            Save-Package chocolatey -Source 'MauleCache' -Path "$ITFolder\Chocolatey" -Force
            & (Get-ChildItem -Path "$ITFolder\Chocolatey" -Recurse -Force | Where-Object { $_.Name -match "chocolateyinstall.ps1" }).PSPath
            Update-ChocoPath
            Get-Command 'choco.exe' -ErrorAction Stop
            $installed = $true
        }
        catch {
            Write-Host "NuGet installation failed. Trying next method."
        }
        finally {
            # Cleanup NuGet artifacts
            if (Get-PSRepository -Name 'MauleCache' -ErrorAction SilentlyContinue) {
                Get-PSRepository -Name 'MauleCache' | Unregister-PSRepository
            }
            if (Test-Path "$ITFolder\Chocolatey") {
                Remove-Item -path "$ITFolder\Chocolatey" -Recurse -Force
            }
        }
    }
    
    # Method 3: Official install script
    if (-not $installed) {
        try {
            Write-Host "Attempting to use chocolatey's script to install chocolatey."
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208 -Force
            Invoke-ValidatedDownload -Uri 'https://community.chocolatey.org/install.ps1' | Invoke-Expression
            $installed = $true
        }
        catch {
            Write-Host "All installation methods failed."
            throw
        }
    }

    Set-ChocolateySources
}