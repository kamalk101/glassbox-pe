"""Build a small synthetic PE32+ file for tests.

It is a valid PE for parsing purposes, not a runnable Windows program. It exists
so the test suite never needs real malware.
"""

from __future__ import annotations

import struct

FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
IMAGE_BASE = 0x140000000

DEFAULT_IMPORTS = [
    "OpenProcess",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "CreateProcessA",
    "WinExec",
    "InternetOpenA",
    "InternetOpenUrlA",
    "HttpSendRequestA",
    "RegSetValueExA",
    "RegCreateKeyExA",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "Sleep",
    "CreateFileA",
    "WriteFile",
    "LoadLibraryA",
    "GetProcAddress",
]

DEFAULT_STRINGS = [
    "http://bad.example/gate.php",
    "203.0.113.9",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "C:\\Users\\Public\\svchost.exe",
    "cmd.exe /c powershell -enc AAAA",
    "Mozilla/5.0",
]


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _hint_name(name: str) -> bytes:
    raw = struct.pack("<H", 0) + name.encode("ascii") + b"\x00"
    if len(raw) % 2:
        raw += b"\x00"
    return raw


def _build_rdata(imports: list[str], strings: list[str], dll_name: str = "KERNEL32.dll") -> bytes:
    base = SECTION_ALIGN * 2  # .rdata RVA
    count = len(imports)
    descriptor_size = 40  # one descriptor + null terminator
    ilt_offset = descriptor_size
    iat_offset = ilt_offset + (count + 1) * 8
    cursor = iat_offset + (count + 1) * 8

    hint_offsets: list[int] = []
    hint_blob = bytearray()
    for name in imports:
        hint_offsets.append(cursor + len(hint_blob))
        hint_blob += _hint_name(name)

    dll_offset = cursor + len(hint_blob)
    dll_blob = dll_name.encode("ascii") + b"\x00"

    strings_offset = dll_offset + len(dll_blob)
    string_blob = bytearray()
    for value in strings:
        string_blob += value.encode("ascii") + b"\x00"
    string_blob += b"\x00"

    rdata = bytearray(cursor + len(hint_blob) + len(dll_blob) + len(string_blob))

    # Import descriptor
    struct.pack_into(
        "<IIIII",
        rdata,
        0,
        base + ilt_offset,            # OriginalFirstThunk RVA
        0,                            # TimeDateStamp
        0,                            # ForwarderChain
        base + dll_offset,            # Name RVA
        base + iat_offset,            # FirstThunk RVA
    )

    # ILT and IAT
    for index, hint_offset in enumerate(hint_offsets):
        value = base + hint_offset
        struct.pack_into("<Q", rdata, ilt_offset + index * 8, value)
        struct.pack_into("<Q", rdata, iat_offset + index * 8, value)
    struct.pack_into("<Q", rdata, ilt_offset + count * 8, 0)
    struct.pack_into("<Q", rdata, iat_offset + count * 8, 0)

    rdata[cursor : cursor + len(hint_blob)] = hint_blob
    rdata[dll_offset : dll_offset + len(dll_blob)] = dll_blob
    rdata[strings_offset : strings_offset + len(string_blob)] = string_blob
    return bytes(rdata)


def build_pe(
    imports: list[str] | None = None,
    strings: list[str] | None = None,
    packed: bool = False,
) -> bytes:
    imports = imports if imports is not None else DEFAULT_IMPORTS
    strings = strings if strings is not None else DEFAULT_STRINGS

    text_raw = (b"\x48\x31\xc0\xc3" + b"\x00" * (FILE_ALIGN - 4))
    rdata = _build_rdata(imports, strings)
    rdata_raw_size = _align(len(rdata), FILE_ALIGN)
    rdata_raw = rdata + b"\x00" * (rdata_raw_size - len(rdata))

    text_va = SECTION_ALIGN
    rdata_va = SECTION_ALIGN * 2

    headers = bytearray(FILE_ALIGN)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)
    headers[0x80:0x84] = b"PE\x00\x00"

    coff = struct.pack(
        "<HHIIIHH",
        0x8664,       # Machine: x86-64
        2,            # NumberOfSections
        0x60000000,   # TimeDateStamp
        0,            # PointerToSymbolTable
        0,            # NumberOfSymbols
        240,          # SizeOfOptionalHeader
        0x0022,       # Characteristics
    )

    data_directories = bytearray(16 * 8)
    struct.pack_into("<II", data_directories, 1 * 8, rdata_va, 40)  # import table

    optional = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,          # Magic: PE32+
        14, 0,          # linker version
        FILE_ALIGN,     # SizeOfCode
        rdata_raw_size, # SizeOfInitializedData
        0,              # SizeOfUninitializedData
        text_va,        # AddressOfEntryPoint
        text_va,        # BaseOfCode
        IMAGE_BASE,     # ImageBase
        SECTION_ALIGN,  # SectionAlignment
        FILE_ALIGN,     # FileAlignment
        6, 0,           # OS version
        0, 0,           # Image version
        6, 0,           # Subsystem version
        0,              # Win32VersionValue
        SECTION_ALIGN * 3,  # SizeOfImage
        FILE_ALIGN,     # SizeOfHeaders
        0,              # CheckSum
        3,              # Subsystem: console
        0x8160,         # DllCharacteristics
        0x100000,       # SizeOfStackReserve
        0x1000,         # SizeOfStackCommit
        0x100000,       # SizeOfHeapReserve
        0x1000,         # SizeOfHeapCommit
        0,              # LoaderFlags
        16,             # NumberOfRvaAndSizes
    ) + bytes(data_directories)

    assert len(optional) == 240, f"optional header is {len(optional)} bytes"

    text_header = struct.pack(
        "<8sIIIIIIHHI",
        b".text",
        FILE_ALIGN,
        text_va,
        FILE_ALIGN,
        FILE_ALIGN,
        0, 0, 0, 0,
        0x60000020,
    )
    rdata_name = b"UPX0" if packed else b".rdata"
    rdata_header = struct.pack(
        "<8sIIIIIIHHI",
        rdata_name,
        len(rdata),
        rdata_va,
        rdata_raw_size,
        FILE_ALIGN * 2,
        0, 0, 0, 0,
        0x40000040,
    )

    headers[0x80 + 4 : 0x80 + 4 + len(coff)] = coff
    optional_offset = 0x80 + 4 + len(coff)
    headers[optional_offset : optional_offset + len(optional)] = optional
    section_offset = optional_offset + len(optional)
    headers[section_offset : section_offset + 40] = text_header
    headers[section_offset + 40 : section_offset + 80] = rdata_header

    return bytes(headers) + text_raw + rdata_raw


if __name__ == "__main__":
    import sys

    output = sys.argv[1] if len(sys.argv) > 1 else "sample.exe"
    with open(output, "wb") as fh:
        fh.write(build_pe(packed="--packed" in sys.argv))
    print(f"wrote {output}")
