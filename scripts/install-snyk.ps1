<#
.SYNOPSIS
    Download a pinned, checksum-verified Snyk CLI standalone binary for Windows dev machines.

.DESCRIPTION
    One source of truth for the version: scripts/snyk-version.txt. Same pattern as
    install-gitleaks.ps1, adapted to snyk/cli's release layout: one binary per platform plus
    a matching per-file "<asset>.sha256" companion (no single combined checksums file).

.EXAMPLE
    ./scripts/install-snyk.ps1
    ./scripts/install-snyk.ps1 -InstallDir "C:\tools\snyk"
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'snyk')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo      = 'snyk/cli'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$version   = (Get-Content (Join-Path $scriptDir 'snyk-version.txt') -Raw).Trim()  # v1.1305.2

$asset = 'snyk-win.exe'
$base  = "https://github.com/$repo/releases/download/$version"
$tmp   = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([System.Guid]::NewGuid().ToString()))

try {
    Write-Host "snyk $version - $asset"
    Write-Host "Downloading $asset ..."
    Invoke-WebRequest -Uri "$base/$asset"          -OutFile (Join-Path $tmp $asset)
    Invoke-WebRequest -Uri "$base/$asset.sha256"   -OutFile (Join-Path $tmp "$asset.sha256")

    Write-Host "Verifying sha256 ..."
    $expected = ((Get-Content (Join-Path $tmp "$asset.sha256") -Raw) -split '\s+')[0].ToLower()
    $actual   = (Get-FileHash (Join-Path $tmp $asset) -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) {
        throw "Checksum mismatch for $asset`n  expected: $expected`n  actual:   $actual"
    }
    Write-Host "Checksum OK."

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $dest = Join-Path $InstallDir 'snyk.exe'
    Copy-Item (Join-Path $tmp $asset) -Destination $dest -Force

    Write-Host "Installed: $dest"
    Write-Host "Add to PATH, or set this line in your .env:"
    Write-Host "  SNYK_BINARY=$dest"
}
finally {
    Remove-Item -Recurse -Force $tmp
}
