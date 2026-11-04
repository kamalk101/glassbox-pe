"""Configuration resolution."""

from __future__ import annotations

import os
from pathlib import Path


def resolve_cases_dir(explicit: str | None = None) -> Path:
    """Where case evidence is stored.

    Precedence: --cases-dir > GLASSBOX_CASES > ./cases
    """
    if explicit:
        return Path(explicit).expanduser().resolve()
    env = os.environ.get("GLASSBOX_CASES")
    if env:
        return Path(env).expanduser().resolve()
    return (Path.cwd() / "cases").resolve()
