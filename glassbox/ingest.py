"""Case identity and file intake."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .utils import hash_file, is_probably_pe


@dataclass
class Intake:
    path: Path
    size: int
    hashes: dict[str, str]
    file_type: str
    case_id: str


def detect_file_type(data: bytes, path: Path) -> str:
    if is_probably_pe(data):
        return "pe"
    if data[:2] == b"MZ":
        return "mz-unparsed"
    suffix = path.suffix.lower().lstrip(".")
    return suffix or "unknown"


def ingest(path: str | Path) -> Intake:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"not a file: {resolved}")

    size = resolved.stat().st_size
    if size == 0:
        raise ValueError(f"empty file: {resolved}")

    with open(resolved, "rb") as fh:
        head = fh.read(4096)

    hashes = hash_file(resolved)
    file_type = detect_file_type(head, resolved)
    return Intake(
        path=resolved,
        size=size,
        hashes=hashes,
        file_type=file_type,
        case_id=hashes["sha256"],
    )
