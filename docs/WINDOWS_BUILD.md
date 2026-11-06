# Build GlassBox PE for Windows

PyInstaller does not cross-compile from this Linux host to Windows. A Windows
binary must be built on Windows (or in a Windows VM). This document explains
how to create `GlassBoxPE.exe`.

## Prerequisites

- Windows 10 or 11
- Python 3.12 or later
- Git or a copy of this repository
- A terminal such as PowerShell

## One-command build

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev,emu]" pyinstaller
python -m pytest
python scripts\windows_entry.py --version
.\.venv\Scripts\pyinstaller.exe --clean --onefile --console --name GlassBoxPE scripts\windows_entry.py
```

Or use the helper:

```powershell
pwsh -ExecutionPolicy Bypass -File scripts\build-windows.ps1
```

The helper builds:

```text
GlassBoxPE.exe            # CLI
GlassBoxPE-Workbench.exe  # desktop UI
```

PyInstaller also writes an equivalent file under `dist\GlassBoxPE.exe`.

## Smoke test on Windows

After building, run:

```powershell
.\GlassBoxPE.exe --version
.\GlassBoxPE-Workbench.exe
.\GlassBoxPE.exe scan C:\Windows\System32\notepad.exe --json
```

The output is a normal PE verdict; it does not execute the sample.

## What the executable does

The executable is the ordinary GlassBox PE CLI. It can:

- static-scan PE files;
- run Speakeasy emulation if the emulation support is installed;
- generate reports and dashboards;
- run corpus evaluation.

It does **not** make a Windows sample safe to run. Never double-click a
suspicious sample on Windows.

## Distribution

Before distributing:

1. Decide whether to ship `GlassBoxPE.exe` or the source archive.
2. Exclude `.venv`, corpus data, case data, reports, and tools.
3. Verify the executable on a clean Windows VM.
4. Record the Python and dependency versions in the release notes.
5. Do not claim it detects malware in general; use the labelled benchmark
   reports in `docs/EVALUATION.md` as the only supported claim.
