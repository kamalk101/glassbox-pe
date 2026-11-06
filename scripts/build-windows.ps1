# Build a portable GlassBox PE executable on Windows.
#
# Run from PowerShell in an empty scratch directory or inside a copied repo:
#   pwsh -ExecutionPolicy Bypass -File scripts\build-windows.ps1
#
# The output is dist\GlassBoxPE.exe. It is produced on Windows because
# PyInstaller cannot cross-compile a PE binary from Linux.

param(
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

if (-not (Test-Path ".venv")) {
    python -m venv .venv
}

& .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev,emu]" pyinstaller

if (-not $SkipTests) {
    python -m pytest
}

New-Item -ItemType Directory -Force -Path dist | Out-Null
& .\.venv\Scripts\pyinstaller.exe `
    --clean `
    --onefile `
    --console `
    --name GlassBoxPE `
    scripts\windows_entry.py

Copy-Item -Force dist\GlassBoxPE.exe GlassBoxPE.exe
Write-Host "Built GlassBoxPE.exe in $ProjectRoot"
