"""Small shared helpers."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def hash_file(path: str | Path, chunk_size: int = 1024 * 1024) -> dict[str, str]:
    """Return md5/sha1/sha256 plus size-friendly hex digests."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(chunk_size):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def human_size(num: int) -> str:
    value = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{num} B"


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def is_probably_pe(data: bytes) -> bool:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    try:
        offset = int.from_bytes(data[0x3C:0x40], "little")
    except Exception:
        return False
    return 0 <= offset < len(data) - 4 and data[offset : offset + 4] == b"PE\0\0"
