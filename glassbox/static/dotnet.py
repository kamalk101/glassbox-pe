"""Best-effort metadata analysis for .NET assemblies.

This is intentionally table-light: it scans the CLR ``#Strings`` and ``#US``
heaps for suspicious identifiers and string literals instead of building a full
managed-code model. It does not decompile IL. Identifiers are grouped into
evidence markers that rules can turn into findings.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..schema import Category

logging.getLogger("dnfile").setLevel(logging.CRITICAL)
logging.getLogger("dnfile").propagate = False

try:
    from dnfile import dnPE
    from dnfile.stream import StringsHeap, UserStringHeap
except ImportError:  # pragma: no cover - dependency is declared, but keep parsing defensive
    dnPE = None
    StringsHeap = None
    UserStringHeap = None

# marker -> human label
DOWNLOAD_MARKERS = (
    "DownloadString",
    "DownloadFile",
    "DownloadData",
    "DownloadDataAsync",
)
REFLECTION_MARKERS = (
    "Reflection.Assembly",
    "Reflection.Emit",
    "Assembly.Load",
    "AssemblyLoad",
    "ILGenerator",
    "DynamicAssembly",
)
PROCESS_MARKERS = (
    "ProcessStartInfo",
    "Process.Start",
)
REGISTRY_MARKERS = (
    "RegistryKey",
    "Registry.CurrentUser",
    "SetValue",
    "OpenSubKey",
)
OBFUSCATOR_MARKERS = (
    "Eazfuscator",
    "Confuser",
    "Dotfuscator",
    "Costura",
)
FRAMEWORK_NAMES = (
    "mscorlib",
    "netstandard",
    "System.Net.Http",
    "System.Data",
    "System.Xml",
    "System.Linq",
    "System.Runtime.Serialization",
    "System.Core",
    "Microsoft.Build",
)


@dataclass
class DotNetAnalysis:
    is_dotnet: bool = False
    parsed: bool = False
    error: str | None = None
    string_bytes_scanned: int = 0
    referenced_frameworks: list[str] = field(default_factory=list)
    download_markers: list[str] = field(default_factory=list)
    reflection_markers: list[str] = field(default_factory=list)
    process_markers: list[str] = field(default_factory=list)
    registry_markers: list[str] = field(default_factory=list)
    obfuscator_markers: list[str] = field(default_factory=list)

    @property
    def indicators(self) -> list[str]:
        return (
            self.download_markers
            + self.reflection_markers
            + self.process_markers
            + self.registry_markers
            + self.obfuscator_markers
        )

    def to_dict(self) -> dict:
        return {
            "is_dotnet": self.is_dotnet,
            "parsed": self.parsed,
            "error": self.error,
            "string_bytes_scanned": self.string_bytes_scanned,
            "referenced_frameworks": self.referenced_frameworks,
            "download_markers": self.download_markers,
            "reflection_markers": self.reflection_markers,
            "process_markers": self.process_markers,
            "registry_markers": self.registry_markers,
            "obfuscator_markers": self.obfuscator_markers,
        }


def _markers(raw: bytes, markers: tuple[str, ...]) -> list[str]:
    lowered = raw.lower()
    return [marker for marker in markers if marker.lower().encode("utf-8") in lowered]


def analyze(data: bytes, is_dotnet: bool = True) -> DotNetAnalysis:
    if not is_dotnet:
        return DotNetAnalysis(is_dotnet=False)
    if dnPE is None:
        return DotNetAnalysis(is_dotnet=True, error="dnfile is not installed")

    try:
        with dnPE(data=data, clr_lazy_load=True) as pe:
            if getattr(pe, "net", None) is None:
                return DotNetAnalysis(is_dotnet=True, error="CLR directory could not be parsed")
            raw = b"".join(
                getattr(stream, "__data__", b"") or b""
                for stream in (getattr(pe.net.metadata, "streams_list", []) or [])
                if isinstance(stream, (StringsHeap, UserStringHeap))
            )
    except Exception as exc:
        return DotNetAnalysis(is_dotnet=True, error=f"could not parse .NET metadata: {exc}")

    frameworks = _markers(raw, FRAMEWORK_NAMES)
    return DotNetAnalysis(
        is_dotnet=True,
        parsed=True,
        string_bytes_scanned=len(raw),
        referenced_frameworks=frameworks,
        download_markers=_markers(raw, DOWNLOAD_MARKERS),
        reflection_markers=_markers(raw, REFLECTION_MARKERS),
        process_markers=_markers(raw, PROCESS_MARKERS),
        registry_markers=_markers(raw, REGISTRY_MARKERS),
        obfuscator_markers=_markers(raw, OBFUSCATOR_MARKERS),
    )
