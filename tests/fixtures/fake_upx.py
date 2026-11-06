"""Cross-platform fake UPX executable used by unpack tests."""

from __future__ import annotations

import os
from pathlib import Path


def make_fake_upx(tmp_path: Path) -> Path:
    if os.name == "nt":
        script = tmp_path / "fake-upx.cmd"
        script.write_text(
            """@echo off
set "out="
:parse
if "%~1"=="" goto done
if /i "%~1"=="-o" (
  set "out=%~2"
  shift
  shift
  goto parse
)
shift
goto parse
:done
copy /Y "%FAKE_UNPACKED%" "%out%" >nul
""",
            encoding="utf-8",
        )
    else:
        script = tmp_path / "fake-upx.sh"
        script.write_text(
            """#!/bin/sh
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
cp "$FAKE_UNPACKED" "$out"
""",
            encoding="utf-8",
        )
        script.chmod(0o755)
    return script
