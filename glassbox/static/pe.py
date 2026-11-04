"""PE structure parsing.

This module only describes the file. It does not decide whether it is malicious.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pefile

MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x86-64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
    0x0200: "IA64",
}

SUBSYSTEM_NAMES = {
    1: "native",
    2: "GUI",
    3: "console",
    5: "OS/2",
    7: "POSIX",
    9: "Windows CE",
    10: "EFI application",
    11: "EFI boot service",
    12: "EFI runtime",
    14: "Xbox",
    16: "Windows boot",
}

PACKER_SECTION_NAMES = {
    "upx0",
    "upx1",
    "upx2",
    "upx!",
    ".aspack",
    ".adata",
    ".mpress1",
    ".mpress2",
    ".themida",
    ".vmp0",
    ".vmp1",
    ".vmp2",
    ".packed",
    "petite",
    ".petite",
    ".nsp0",
    ".nsp1",
    ".enigma1",
    ".enigma2",
}

INSTALLER_MARKERS = {
    "Nullsoft": "NSIS",
    "Inno Setup": "Inno Setup",
    "This installation was built with Inno Setup": "Inno Setup",
    "InstallShield": "InstallShield",
    "WixBundle": "WiX/MSI",
    "Windows Installer": "MSI",
}

EXECUTABLE = 0x20000000
READABLE = 0x40000000
WRITABLE = 0x80000000


@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_pointer: int
    entropy: float
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & EXECUTABLE)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & WRITABLE)

    @property
    def readable(self) -> bool:
        return bool(self.characteristics & READABLE)

    @property
    def wx(self) -> bool:
        return self.executable and self.writable


@dataclass
class PEInfo:
    is_pe: bool = False
    parse_error: str | None = None
    machine: int = 0
    machine_name: str = "unknown"
    timestamp: int = 0
    timestamp_iso: str | None = None
    timestamp_anomaly: str | None = None
    subsystem: int = 0
    subsystem_name: str = "unknown"
    characteristics: int = 0
    entry_point: int = 0
    image_base: int = 0
    num_sections: int = 0
    sections: list[SectionInfo] = field(default_factory=list)
    imports: dict[str, list[str]] = field(default_factory=dict)
    ordinal_imports: dict[str, list[int]] = field(default_factory=dict)
    exports: list[str] = field(default_factory=list)
    dlls: list[str] = field(default_factory=list)
    overlay_offset: int | None = None
    overlay_size: int = 0
    checksum: int = 0
    computed_checksum: int = 0
    checksum_mismatch: bool = False
    signature_present: bool = False
    signature_size: int = 0
    is_dotnet: bool = False
    tls_callbacks: int = 0
    tls_callback_address: int = 0
    rich_header_present: bool = False
    pdb_path: str | None = None
    version_info: dict[str, str] = field(default_factory=dict)
    resource_count: int = 0
    embedded_pe: list[str] = field(default_factory=list)
    installer_hint: str | None = None
    entry_section: str | None = None
    entry_in_executable_section: bool = True
    packer_hint: str | None = None
    imports_count: int = 0

    def all_import_functions(self) -> set[str]:
        functions: set[str] = set()
        for names in self.imports.values():
            functions.update(names)
        return functions

    def summary(self) -> dict:
        return {
            "machine": self.machine_name,
            "subsystem": self.subsystem_name,
            "entry_point": hex(self.entry_point),
            "image_base": hex(self.image_base),
            "sections": len(self.sections),
            "imports": self.imports_count,
            "import_dlls": len(self.imports),
            "exports": len(self.exports),
            "overlay_size": self.overlay_size,
            "signed": self.signature_present,
            "dotnet": self.is_dotnet,
            "tls_callbacks": self.tls_callbacks,
            "pdb": self.pdb_path,
            "packer": self.packer_hint,
            "installer": self.installer_hint,
            "timestamp": self.timestamp_iso,
        }


def _decode(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.rstrip(b"\x00").decode("utf-8", "replace")
    return str(value)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def _flatten_resources(entries) -> list[dict]:
    found: list[dict] = []

    def walk(items):
        for item in items:
            directory = getattr(item, "directory", None)
            if directory is not None:
                walk(directory.entries)
                continue
            data = getattr(item, "data", None)
            if data is not None:
                found.append(
                    {
                        "rva": int(getattr(data.struct, "OffsetToData", 0)),
                        "size": int(getattr(data.struct, "Size", 0)),
                    }
                )

    try:
        walk(entries)
    except Exception:
        return found
    return found


def _version_info(pe: pefile.PE) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for file_info in getattr(pe, "FileInfo", []) or []:
            for entry in file_info:
                for table in getattr(entry, "StringTable", []) or []:
                    for key, value in table.entries.items():
                        key_str = _decode(key)
                        if key_str and key_str not in values:
                            values[key_str] = _decode(value)
    except Exception:
        pass
    return values


def _pdb_path(pe: pefile.PE) -> str | None:
    try:
        for debug in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
            entry = getattr(debug, "entry", None)
            candidate = getattr(entry, "PdbFileName", None) if entry else None
            if candidate:
                return _decode(candidate)
    except Exception:
        pass
    return None


def _tls_callbacks(pe: pefile.PE) -> tuple[int, int]:
    try:
        tls = pe.DIRECTORY_ENTRY_TLS
        address = int(tls.struct.AddressOfCallBacks)
        count = 0
        if address:
            image_base = pe.OPTIONAL_HEADER.ImageBase
            rva = address - image_base
            try:
                raw = pe.get_data(rva, 8 * 8)
                for i in range(0, len(raw), 8):
                    ptr = int.from_bytes(raw[i : i + 8], "little")
                    if ptr == 0:
                        break
                    count += 1
            except Exception:
                pass
        return count, address
    except Exception:
        return 0, 0


def parse_pe(data: bytes) -> PEInfo:
    info = PEInfo()
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as exc:  # pefile raises many types
        info.parse_error = f"{type(exc).__name__}: {exc}"
        return info

    info.is_pe = True
    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER

    info.machine = int(fh.Machine)
    info.machine_name = MACHINE_NAMES.get(info.machine, f"0x{info.machine:04x}")
    info.timestamp = int(fh.TimeDateStamp)
    if info.timestamp:
        try:
            dt = datetime.fromtimestamp(info.timestamp, tz=timezone.utc)
            info.timestamp_iso = dt.isoformat()
            if dt.timestamp() > datetime.now(timezone.utc).timestamp() + 86400:
                info.timestamp_anomaly = "timestamp is in the future"
        except (OverflowError, OSError, ValueError):
            info.timestamp_anomaly = "timestamp is invalid"
    else:
        info.timestamp_anomaly = "timestamp is zero"

    info.subsystem = int(oh.Subsystem)
    info.subsystem_name = SUBSYSTEM_NAMES.get(info.subsystem, f"0x{info.subsystem:x}")
    info.characteristics = int(fh.Characteristics)
    info.entry_point = int(oh.AddressOfEntryPoint)
    info.image_base = int(oh.ImageBase)
    info.num_sections = int(fh.NumberOfSections)

    for section in pe.sections:
        name = _decode(section.Name)
        info.sections.append(
            SectionInfo(
                name=name,
                virtual_address=int(section.VirtualAddress),
                virtual_size=int(section.Misc_VirtualSize),
                raw_size=int(section.SizeOfRawData),
                raw_pointer=int(section.PointerToRawData),
                entropy=round(float(section.get_entropy()), 3),
                characteristics=int(section.Characteristics),
            )
        )

    imports: dict[str, list[str]] = {}
    ordinals: dict[str, list[int]] = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = _decode(entry.dll)
        names: list[str] = []
        ords: list[int] = []
        for imp in entry.imports:
            if imp.name:
                names.append(_decode(imp.name))
            elif imp.ordinal is not None:
                ords.append(int(imp.ordinal))
        imports[dll] = names
        if ords:
            ordinals[dll] = ords
    info.imports = imports
    info.ordinal_imports = ordinals
    info.dlls = sorted(imports)
    info.imports_count = sum(len(v) for v in imports.values())

    try:
        info.exports = [
            _decode(symbol.name) or f"ordinal:{symbol.ordinal}"
            for symbol in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) or []
        ]
    except Exception:
        info.exports = []

    overlay = pe.get_overlay() or b""
    info.overlay_size = len(overlay)
    if info.overlay_size:
        try:
            info.overlay_offset = pe.get_overlay_data_start_offset()
        except Exception:
            info.overlay_offset = None

    info.checksum = int(oh.CheckSum)
    try:
        info.computed_checksum = int(pe.generate_checksum())
    except Exception:
        info.computed_checksum = 0
    info.checksum_mismatch = bool(info.checksum and info.computed_checksum and info.checksum != info.computed_checksum)

    try:
        security = oh.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        info.signature_size = int(security.Size)
        info.signature_present = info.signature_size > 0
    except Exception:
        pass

    info.is_dotnet = hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR")

    info.tls_callbacks, info.tls_callback_address = _tls_callbacks(pe)

    try:
        pe.parse_rich_header()
        info.rich_header_present = bool(getattr(pe, "RICH_HEADER", None))
    except Exception:
        info.rich_header_present = False

    info.pdb_path = _pdb_path(pe)
    info.version_info = _version_info(pe)

    resources = _flatten_resources(getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), "entries", []) or [])
    info.resource_count = len(resources)
    for resource in resources:
        size = resource["size"]
        if 0 < size <= 32 * 1024 * 1024:
            try:
                blob = pe.get_data(resource["rva"], size)
                if blob[:2] == b"MZ":
                    info.embedded_pe.append(f"resource@{hex(resource['rva'])} ({size} bytes)")
            except Exception:
                continue

    # Entry point section
    for section in info.sections:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= info.entry_point < section.virtual_address + span:
            info.entry_section = section.name
            info.entry_in_executable_section = section.executable
            break
    if info.entry_section is None:
        info.entry_in_executable_section = False

    # Packer heuristics
    names = {s.name.lower() for s in info.sections}
    matched = sorted(names & PACKER_SECTION_NAMES)
    if matched:
        info.packer_hint = matched[0]
    elif any(s.entropy > 7.2 for s in info.sections) and info.imports_count < 10:
        info.packer_hint = "high-entropy / low-imports"

    # Installer markers (cheap scan of raw bytes)
    for marker, label in INSTALLER_MARKERS.items():
        if marker.encode("utf-8", "ignore") in data:
            info.installer_hint = label
            break

    try:
        pe.close()
    except Exception:
        pass
    return info
