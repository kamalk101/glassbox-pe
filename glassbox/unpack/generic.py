"""Generic PE payload extraction.

This is deliberately conservative and static-only: it extracts a second PE that is
embedded in or appended to the analysed file, then validates it before treating
the extracted bytes as an unpacked child. It does not emulate or execute the
sample, and it is not a universal unpacker for ASPack, Themida, VMProtect, or
similar packers.
"""

from __future__ import annotations

import pefile
from pathlib import Path

from ..static.pe import parse_pe
from ..utils import is_probably_pe

MIN_PE_SIZE = 1024
MAX_PE_SIZE = 128 * 1024 * 1024


def _candidate_size(data: bytes, offset: int) -> int | None:
    try:
        pe = pefile.PE(data=data[offset:], fast_load=True)
    except Exception:
        return None
    try:
        raw_span = max(
            section.PointerToRawData + section.SizeOfRawData
            for section in getattr(pe, "sections", [])
        )
    except (ValueError, AttributeError):
        return None
    if not (MIN_PE_SIZE <= raw_span <= MAX_PE_SIZE):
        return None
    if raw_span > len(data) - offset:
        return None
    return raw_span


def find_embedded_pe(data: bytes, start: int = 0x100) -> tuple[int, bytes] | None:
    """Return the offset and bytes of the first valid embedded PE after ``start``."""
    if start < 0:
        start = 0
    position = data.find(b"MZ", start)
    while position >= 0:
        if position > 0 and position < len(data):
            size = _candidate_size(data, position)
            if size is not None:
                candidate = data[position:]
                parsed = parse_pe(candidate)
                if parsed.is_pe and not parsed.parse_error and parsed.num_sections > 0:
                    return position, candidate
        position = data.find(b"MZ", position + 2)
    return None


def unpack_generic(data: bytes, output_path: str | Path) -> tuple[bool, str | None, str]:
    found = find_embedded_pe(data)
    if found is None:
        return False, None, "no embedded or appended PE payload was found"

    offset, payload = found
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    if not is_probably_pe(payload):
        try:
            output.unlink(missing_ok=True)
        except OSError:
            pass
        return False, None, "extracted payload did not pass PE validation"
    return True, str(output), f"extracted embedded PE payload at offset 0x{offset:x}"