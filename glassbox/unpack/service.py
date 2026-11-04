"""Unpacking service: detect a packer and choose a supported unpacker."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..static.packer import PackerInfo, detect
from ..static.pe import parse_pe
from ..utils import is_probably_pe
from .upx import find_upx, unpack_upx


@dataclass
class UnpackResult:
    status: str  # unpacked / not_pe / not_packed / unsupported / tool_missing / failed
    success: bool
    packer: PackerInfo
    method: str | None = None
    output_path: str | None = None
    tool: str | None = None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "success": self.success,
            "packer": self.packer.to_dict(),
            "method": self.method,
            "output_path": self.output_path,
            "tool": self.tool,
            "error": self.error,
        }


def unpack_sample(
    path: str | Path,
    output_path: str | Path,
    packer: PackerInfo | None = None,
) -> UnpackResult:
    target = Path(path).expanduser().resolve()
    output = Path(output_path).expanduser().resolve()
    if output == target:
        return UnpackResult(
            status="failed",
            success=False,
            packer=packer or PackerInfo(),
            error="output path must differ from the input path",
        )
    if output.is_dir():
        return UnpackResult(
            status="failed",
            success=False,
            packer=packer or PackerInfo(),
            error=f"output path is a directory: {output}",
        )

    try:
        data = target.read_bytes()
    except OSError as exc:
        return UnpackResult(
            status="failed",
            success=False,
            packer=packer or PackerInfo(),
            error=f"could not read input: {exc}",
        )

    if not is_probably_pe(data):
        return UnpackResult(
            status="not_pe",
            success=False,
            packer=packer or PackerInfo(),
            error="input is not a valid PE file",
        )

    info = parse_pe(data)
    detected = packer or detect(data, info)

    if not detected.name:
        return UnpackResult(
            status="not_packed",
            success=False,
            packer=detected,
            error="no known packer detected",
        )

    if not detected.upx:
        return UnpackResult(
            status="unsupported",
            success=False,
            packer=detected,
            error=f"detected {detected.name}; only UPX unpacking is supported in Phase 3",
        )

    if find_upx() is None:
        return UnpackResult(
            status="tool_missing",
            success=False,
            packer=detected,
            error=(
                "UPX detected but the upx binary was not found. Set GLASSBOX_UPX, "
                "put upx in tools/, or install it on PATH."
            ),
        )

    result = unpack_upx(target, output)
    if not result.success:
        return UnpackResult(
            status="failed",
            success=False,
            packer=detected,
            method="upx",
            tool=result.tool,
            stdout=result.stdout,
            stderr=result.stderr,
            error=result.error,
        )

    output = Path(result.output_path or output_path)
    try:
        output_data = output.read_bytes()
    except OSError as exc:
        return UnpackResult(
            status="failed",
            success=False,
            packer=detected,
            method="upx",
            tool=result.tool,
            error=f"could not read unpacked output: {exc}",
        )

    if not is_probably_pe(output_data):
        return UnpackResult(
            status="failed",
            success=False,
            packer=detected,
            method="upx",
            tool=result.tool,
            output_path=str(output),
            error="unpacker produced a file that is not a valid PE",
        )

    return UnpackResult(
        status="unpacked",
        success=True,
        packer=detected,
        method="upx",
        output_path=str(output),
        tool=result.tool,
        stdout=result.stdout,
        stderr=result.stderr,
    )
