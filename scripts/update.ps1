# GuardianWAF Update Script for Windows
# Usage: powershell -ExecutionPolicy Bypass -File update.ps1

param(
    [string]$Version = "",
    [ValidateSet("binary", "docker")]
    [string]$UpdateType = "binary",
    [switch]$Check
)

$ErrorActionPreference = "Stop"

$Repo = "guardianwaf/guardianwaf"
$BinaryName = "guardianwaf.exe"
$InstallDir = "C:\Program Files\GuardianWAF"

function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

function Get-CurrentVersion {
    $binaryPath = Join-Path $InstallDir $BinaryName
    if (Test-Path $binaryPath) {
        try {
            $output = & $binaryPath version 2>&1
            if ($output -is [array]) {
                return ($output[0] -replace 'v', '')
            }
            return ($output -replace 'v', '')
        } catch {
            return "unknown"
        }
    }

    # Try from PATH
    if (Get-Command $BinaryName -ErrorAction SilentlyContinue) {
        try {
            $output = & $BinaryName version 2>&1
            if ($output -is [array]) {
                return ($output[0] -replace 'v', '')
            }
            return ($output -replace 'v', '')
        } catch {
            return "unknown"
        }
    }

    return "not installed"
}

function Get-LatestVersion {
    try {
        $response = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
        return $response.tag_name -replace 'v', ''
    } catch {
        Write-Warn "Could not fetch latest version, using default: 1.1.0"
        return "1.1.0"
    }
}

function Get-Architecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default { return "amd64" }
    }
}

function Update-Binary {
    param($ver)

    $os = "windows"
    $arch = Get-Architecture
    $ext = ".zip"
    $filename = "guardianwaf_${ver}_${os}_${arch}${ext}"
    $downloadUrl = "https://github.com/$Repo/releases/download/v${ver}/$filename"
    $tempFile = "$env:TEMP\$filename"

    Write-Info "Stopping GuardianWAF service (if running)..."

    # Stop Docker container if running
    $container = docker ps -q --filter "name=guardianwaf" 2>$null
    if ($container) {
        Write-Info "Stopping GuardianWAF Docker container..."
        docker stop guardianwaf 2>$null
    }

    # Try to stop Windows service
    $service = Get-Service -Name "GuardianWAF" -ErrorAction SilentlyContinue
    if ($service) {
        Write-Info "Stopping GuardianWAF service..."
        Stop-Service -Name "GuardianWAF" -Force -ErrorAction SilentlyContinue
    }

    Write-Info "Downloading GuardianWAF v$ver for $os/$arch..."
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -UseBasicParsing
    } catch {
        Write-Err "Download failed: $_"
        exit 1
    }

    # Backup current
    $binaryPath = Join-Path $InstallDir $BinaryName
    if (Test-Path $binaryPath) {
        $backupPath = "$binaryPath.backup-$(Get-Date -Format 'yyyyMMdd')"
        Write-Info "Backing up current binary to $backupPath"
        Copy-Item $binaryPath $backupPath -Force
    }

    Write-Info "Installing new version to $InstallDir..."

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    Expand-Archive -Path $tempFile -DestinationPath $InstallDir -Force
    Remove-Item $tempFile -Force

    Write-Info "GuardianWAF v$ver installed successfully!"

    # Try to restart Windows service
    if ($service) {
        Write-Info "Starting GuardianWAF service..."
        Start-Service -Name "GuardianWAF" -ErrorAction SilentlyContinue
    }

    # Restart Docker container if it was running
    if ($container) {
        Write-Info "Restarting GuardianWAF Docker container..."
        docker start guardianwaf 2>$null
    }
}

function Update-Docker {
    Write-Info "Updating GuardianWAF Docker image..."

    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Err "Docker is not installed."
        exit 1
    }

    docker pull "ghcr.io/$Repo:latest"

    $container = docker ps -q --filter "name=guardianwaf" 2>$null
    if ($container) {
        Write-Info "Restarting GuardianWAF container..."
        docker restart guardianwaf
    } else {
        Write-Warn "Container not running. Start with: docker run -d --name guardianwaf -p 8088:8088 -p 9443:9443 ghcr.io/$Repo:latest"
    }
}

# Main
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  GuardianWAF Update Script" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$currentVersion = Get-CurrentVersion
$latestVersion = if ($Version) { $Version } else { Get-LatestVersion }

Write-Info "Current version: $currentVersion"
Write-Info "Latest version:   $latestVersion"
Write-Host ""

if ($Check) {
    if ($currentVersion -eq "not installed") {
        Write-Info "GuardianWAF is not installed"
        exit 1
    } elseif ($currentVersion -eq $latestVersion) {
        Write-Info "You have the latest version: v$currentVersion"
        exit 0
    } else {
        Write-Info "Update available: v$currentVersion -> v$latestVersion"
        exit 1
    }
}

if (-not $Version) {
    if ($currentVersion -eq $latestVersion) {
        Write-Info "You already have the latest version: v$currentVersion"
        exit 0
    }
    $Version = $latestVersion
}

switch ($UpdateType) {
    "docker" { Update-Docker }
    "binary" { Update-Binary -ver $Version }
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Update Complete!" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$newVersion = Get-CurrentVersion
Write-Info "Now running: v$newVersion"
Write-Host ""
