"""UPX discovery and invocation."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class UpxResult:
    success: bool
    output_path: str | None
    tool: str | None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None


def find_upx() -> str | None:
    """Locate a UPX executable.

    Precedence: GLASSBOX_UPX > PATH > <project>/tools/upx > ./tools/upx.
    """
    candidates: list[str] = []
    env = os.environ.get("GLASSBOX_UPX")
    if env:
        candidates.append(env)

    on_path = shutil.which("upx") or shutil.which("upx.exe")
    if on_path:
        candidates.append(on_path)

    project_root = Path(__file__).resolve().parents[2]
    candidates.extend(
        [
            str(project_root / "tools" / "upx"),
            str(project_root / "tools" / "upx.exe"),
            str(Path.cwd() / "tools" / "upx"),
        ]
    )

    for candidate in candidates:
        path = Path(candidate).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


def unpack_upx(input_path: str | Path, output_path: str | Path, timeout: int = 120) -> UpxResult:
    tool = find_upx()
    output = Path(output_path)
    if tool is None:
        return UpxResult(
            success=False,
            output_path=None,
            tool=None,
            error=(
                "UPX detected but the upx binary was not found. Set GLASSBOX_UPX, "
                "put upx in tools/, or install it on PATH."
            ),
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()

    try:
        completed = subprocess.run(
            [tool, "-q", "-d", "-o", str(output), str(input_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return UpxResult(success=False, output_path=None, tool=tool, error=f"UPX failed: {exc}")

    if not output.is_file() or output.stat().st_size == 0:
        return UpxResult(
            success=False,
            output_path=None,
            tool=tool,
            stdout=completed.stdout,
            stderr=completed.stderr,
            error=f"UPX did not produce an output file (exit {completed.returncode}).",
        )

    return UpxResult(
        success=True,
        output_path=str(output),
        tool=tool,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
