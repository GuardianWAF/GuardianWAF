# GuardianWAF Installation Script for Windows
# Usage: powershell -ExecutionPolicy Bypass -File install.ps1

param(
    [string]$Version = "",
    [ValidateSet("binary", "docker")]
    [string]$InstallType = "binary",
    [string]$InstallDir = "C:\Program Files\GuardianWAF",
    [string]$ConfigDir = "$env:ProgramData\GuardianWAF"
)

$ErrorActionPreference = "Stop"

$Repo = "guardianwaf/guardianwaf"
$BinaryName = "guardianwaf.exe"

function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

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

function Install-Binary {
    param($ver, $os, $arch)

    $ext = ".zip"
    $filename = "guardianwaf_${ver}_${os}_${arch}${ext}"
    $downloadUrl = "https://github.com/$Repo/releases/download/v${ver}/$filename"
    $tempFile = "$env:TEMP\$filename"

    Write-Info "Downloading GuardianWAF v$ver for $os/$arch..."
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempFile -UseBasicParsing
    } catch {
        Write-Err "Download failed: $_"
        exit 1
    }

    Write-Info "Installing to $InstallDir..."

    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    Expand-Archive -Path $tempFile -DestinationPath $InstallDir -Force
    Remove-Item $tempFile -Force

    # Add to PATH if not already
    $pathEntry = $InstallDir
    if ($env:PATH -notlike "*$pathEntry*") {
        Write-Info "Adding $InstallDir to PATH..."
        [Environment]::SetEnvironmentVariable(
            "PATH",
            "$env:PATH;$pathEntry",
            "User"
        )
        $env:PATH = "$env:PATH;$pathEntry"
    }

    Write-Info "GuardianWAF v$ver installed successfully!"
}

function New-DefaultConfig {
    Write-Info "Creating default configuration..."

    if (-not (Test-Path $ConfigDir)) {
        New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    }

    $configPath = Join-Path $ConfigDir "guardianwaf.yaml"

    if (-not (Test-Path $configPath)) {
        @"
# GuardianWAF Configuration
version: "1.0"

server:
  listen: ":8088"
  mode: enforce

tls:
  enabled: false
  listen: ":8443"

upstreams:
  - name: default
    targets:
      - url: "http://localhost:3000"

routes:
  - host: "*"
    upstream: default

logging:
  level: info
  format: json

waf:
  detection:
    enabled: true
  bot_detection:
    enabled: true
"@ | Out-File -FilePath $configPath -Encoding UTF8

        Write-Info "Default config created at $configPath"
    } else {
        Write-Warn "Config already exists at $configPath"
    }
}

function Install-Docker {
    Write-Info "Installing GuardianWAF via Docker..."

    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Err "Docker is not installed. Please install Docker Desktop first."
        exit 1
    }

    docker pull "ghcr.io/$Repo:latest"
    Write-Info "GuardianWAF Docker image installed!"
    Write-Info "Run with: docker run -d -p 8088:8088 -p 9443:9443 ghcr.io/$Repo:latest"
}

# Main
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  GuardianWAF Installation Script" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

if (-not $Version) {
    $Version = Get-LatestVersion
}

$os = "windows"
$arch = Get-Architecture

Write-Info "Version: $Version"
Write-Info "OS/Arch: $os/$arch"
Write-Info "Install type: $InstallType"
Write-Host ""

switch ($InstallType) {
    "docker" { Install-Docker }
    "binary" {
        Install-Binary -ver $Version -os $os -arch $arch
        New-DefaultConfig
    }
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Installation Complete!" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Quick start:"
Write-Host "  Binary: guardianwaf.exe serve -c `"$ConfigDir\guardianwaf.yaml`""
Write-Host "  Docker: docker run -d -p 8088:8088 -p 9443:9443 ghcr.io/$Repo:latest"
Write-Host ""
