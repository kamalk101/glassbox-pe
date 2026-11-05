"""Speakeasy emulation backend.

Runs the emulator in a subprocess so a malformed sample cannot crash the CLI, then
returns the JSON report and any files the sample dropped.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..static.pe import parse_pe
from ..utils import hash_file


@dataclass
class DroppedFile:
    path: str
    size: int
    sha256: str


@dataclass
class EmulationOutcome:
    ran: bool
    report: dict | None = None
    report_path: str | None = None
    dropped_files: list[DroppedFile] = field(default_factory=list)
    workdir: str | None = None
    error: str | None = None
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None


def speakeasy_available() -> bool:
    return importlib.util.find_spec("speakeasy") is not None


def run_emulation(path: str | Path, timeout: int = 60, workdir: str | Path | None = None) -> EmulationOutcome:
    target = Path(path).expanduser().resolve()
    if not speakeasy_available():
        return EmulationOutcome(
            ran=False,
            error=(
                "Speakeasy is not installed. Install the emulation extra:\n"
                '  pip install "glassbox-pe[emu]"\n'
                'or: pip install speakeasy-emulator "setuptools<81"'
            ),
        )

    try:
        info = parse_pe(target.read_bytes())
    except OSError as exc:
        return EmulationOutcome(ran=False, error=f"could not read sample: {exc}")
    if info.is_pe and info.machine_name not in {"x86", "x86-64"}:
        return EmulationOutcome(
            ran=False,
            error=(
                f"Speakeasy backend does not support {info.machine_name} samples; "
                "use an x86 or x86-64 build"
            ),
        )

    root = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="glassbox-emu-"))
    root.mkdir(parents=True, exist_ok=True)
    report_path = root / "speakeasy-report.json"
    dropped_dir = root / "dropped"
    if report_path.exists():
        report_path.unlink()
    if dropped_dir.exists():
        for child in sorted(dropped_dir.rglob("*"), reverse=True):
            if child.is_file():
                child.unlink()
            elif child.is_dir():
                child.rmdir()
    dropped_dir.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        "-m",
        "speakeasy",
        "-t",
        str(target),
        "-o",
        str(report_path),
        "-q",
        str(max(1, timeout)),
        "-z",
        str(dropped_dir),
        "--no-mp",
    ]

    env = dict(os.environ)
    env.setdefault("PYTHONWARNINGS", "ignore")

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(30, timeout + 60),
            env=env,
        )
        stdout, stderr, returncode = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        return EmulationOutcome(
            ran=False,
            workdir=str(root),
            error=f"emulation timed out after {timeout}s",
            stdout=stdout,
            stderr=stderr,
        )
    except OSError as exc:
        return EmulationOutcome(ran=False, workdir=str(root), error=f"could not start emulator: {exc}")

    report: dict | None = None
    error: str | None = None
    if report_path.is_file():
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            error = f"could not read emulation report: {exc}"
    else:
        error = f"emulator produced no report (exit {returncode})"

    if error is None and returncode not in (0, None):
        error = f"emulator exited with code {returncode}"

    dropped: list[DroppedFile] = []
    for child in sorted(dropped_dir.rglob("*")):
        if not child.is_file():
            continue
        try:
            hashes = hash_file(child)
        except OSError:
            continue
        dropped.append(DroppedFile(path=str(child), size=child.stat().st_size, sha256=hashes["sha256"]))

    return EmulationOutcome(
        ran=report is not None,
        report=report,
        report_path=str(report_path) if report_path.is_file() else None,
        dropped_files=dropped,
        workdir=str(root),
        error=error,
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
    )
