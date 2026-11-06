<#
.SYNOPSIS
    Download a pinned, checksum-verified gitleaks.exe for Windows dev machines.

.DESCRIPTION
    One source of truth for the version: scripts/gitleaks-version.txt.
    Verifies the SHA-256 against the release checksums file.

.EXAMPLE
    ./scripts/install-gitleaks.ps1
    ./scripts/install-gitleaks.ps1 -InstallDir "C:\tools\gitleaks"
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'gitleaks')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo       = 'gitleaks/gitleaks'
$scriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$version    = (Get-Content (Join-Path $scriptDir 'gitleaks-version.txt') -Raw).Trim()  # v8.30.1
$versionNoV = $version.TrimStart('v')                                                  # 8.30.1

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'x64'   }
    'ARM64' { 'arm64' }
    'x86'   { 'x32'   }
    default { throw "Unsupported arch: $env:PROCESSOR_ARCHITECTURE" }
}

$asset     = "gitleaks_${versionNoV}_windows_$arch.zip"
$checksums = "gitleaks_${versionNoV}_checksums.txt"
$base      = "https://github.com/$repo/releases/download/$version"
$tmp       = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([System.Guid]::NewGuid().ToString()))

try {
    Write-Host "gitleaks $version - windows/$arch"
    Write-Host "Downloading $asset ..."
    Invoke-WebRequest -Uri "$base/$asset"     -OutFile (Join-Path $tmp $asset)
    Invoke-WebRequest -Uri "$base/$checksums" -OutFile (Join-Path $tmp $checksums)

    Write-Host "Verifying sha256 ..."
    $line = Select-String -Path (Join-Path $tmp $checksums) -Pattern ([regex]::Escape($asset)) |
            Select-Object -First 1
    if (-not $line) { throw "No checksum for $asset in $checksums" }
    $expected = (($line.Line -split '\s+') | Where-Object { $_ })[0].ToLower()
    $actual   = (Get-FileHash (Join-Path $tmp $asset) -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) {
        throw "Checksum mismatch for $asset`n  expected: $expected`n  actual:   $actual"
    }
    Write-Host "Checksum OK."

    Write-Host "Extracting ..."
    $extracted = Join-Path $tmp 'extracted'
    Expand-Archive -Path (Join-Path $tmp $asset) -DestinationPath $extracted -Force
    $src = Get-ChildItem -Path $extracted -Recurse -Filter 'gitleaks.exe' | Select-Object -First 1
    if (-not $src) { throw 'gitleaks.exe not found in archive' }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $dest = Join-Path $InstallDir 'gitleaks.exe'
    Copy-Item $src.FullName -Destination $dest -Force

    Write-Host "Installed: $dest"
    Write-Host "Add to PATH, or set this line in your .env:"
    Write-Host "  GITLEAKS_BINARY=$dest"
}
finally {
    Remove-Item -Recurse -Force $tmp
}
