"""Static detection rules.

Each rule returns a FindingDraft. Evidence references Event IDs so the report can
link every conclusion back to a concrete artifact.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..schema import Category, Severity
from .imports import (
    BEHAVIOR_LABELS,
    BEHAVIOR_TECHNIQUE,
    ImportAnalysis,
    is_strong_anti_analysis,
    is_weak_anti_analysis,
)
from .pe import PEInfo
from .strings import StringsResult

STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".bss", ".rsrc", ".reloc", ".tls", ".idata",
    ".edata", ".debug", ".pdata", ".xdata", ".didat", ".didata", ".sdata",
    ".gfids", ".00cfg", ".CRT", ".rodata", ".fptable",
}

STRONG_COMMANDS = {
    "powershell", "pwsh", "rundll32", "regsvr32", "mshta", "wscript",
    "cscript", "certutil", "bitsadmin", "schtasks", "wmic", "psexec",
    "msbuild", "installutil",
}

INJECTION_WRITE_OR_EXECUTE = {
    "writeprocessmemory", "createremotethread", "ntcreatethreadex",
    "queueuserapc", "setthreadcontext", "rtlcreateuserthread",
}


@dataclass
class FindingDraft:
    rule_id: str
    title: str
    severity: Severity
    description: str
    category: Category
    evidence: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    confidence: float = 0.6
    data: dict = field(default_factory=dict)


@dataclass
class RuleContext:
    info: PEInfo
    strings: StringsResult
    imports: ImportAnalysis
    event_index: dict[str, str]
    file_size: int

    def ev(self, *keys: str) -> list[str]:
        found: list[str] = []
        for key in keys:
            event_id = self.event_index.get(key)
            if event_id and event_id not in found:
                found.append(event_id)
        return found


def _is_autorun_key(key: str) -> bool:
    lowered = key.lower().replace("/", "\\")
    return (
        "\\currentversion\\run" in lowered
        or "\\currentversion\\runonce" in lowered
        or lowered.endswith("\\run")
        or lowered.endswith("\\runonce")
    )


def _looks_like_dropped_executable(path: str) -> bool:
    lowered = path.lower().replace("/", "\\")
    extension = lowered.rsplit(".", 1)[-1] if "." in lowered else ""
    if extension not in {"exe", "dll", "scr", "sys", "cpl"}:
        return False
    hot_dirs = ("\\temp\\", "\\appdata\\", "\\public\\", "\\programdata\\", "\\users\\")
    return any(directory in lowered for directory in hot_dirs)


def evaluate(ctx: RuleContext) -> list[FindingDraft]:
    info = ctx.info
    strings = ctx.strings
    imports = ctx.imports
    findings: list[FindingDraft] = []

    # ---------------------------------------------------------------- PE shape
    if info.packer_hint:
        findings.append(
            FindingDraft(
                rule_id="GB-PE-002",
                title="Packed or heavily obfuscated image",
                severity=Severity.MEDIUM,
                description=(
                    f"Packer indicators found ({info.packer_hint}). Static analysis may be "
                    "looking at a stub rather than the real code."
                ),
                category=Category.PE,
                evidence=ctx.ev("pe", *[f"section:{s.name}" for s in info.sections if s.entropy > 7.2]),
                techniques=["T1027.002"],
                confidence=0.7,
                data={"hint": info.packer_hint, "imports": info.imports_count},
            )
        )

    wx = [s for s in info.sections if s.wx]
    if wx:
        findings.append(
            FindingDraft(
                rule_id="GB-PE-003",
                title="Writable and executable section",
                severity=Severity.MEDIUM,
                description=(
                    "One or more sections are both writable and executable (W+X). This is "
                    "uncommon in normal builds and is used for self-modifying or injected code."
                ),
                category=Category.PE,
                evidence=ctx.ev(*[f"section:{s.name}" for s in wx]),
                techniques=["T1027"],
                confidence=0.7,
                data={"sections": [s.name for s in wx]},
            )
        )

    if not info.entry_in_executable_section:
        findings.append(
            FindingDraft(
                rule_id="GB-PE-004",
                title="Entry point outside an executable section",
                severity=Severity.HIGH,
                description=(
                    "The PE entry point does not fall inside an executable section. This is a "
                    "classic sign of a modified or packed image."
                ),
                category=Category.PE,
                evidence=ctx.ev("pe"),
                techniques=["T1027"],
                confidence=0.75,
                data={"entry_point": hex(info.entry_point), "entry_section": info.entry_section},
            )
        )

    if info.overlay_size > max(1024 * 1024, int(ctx.file_size * 0.20)):
        findings.append(
            FindingDraft(
                rule_id="GB-PE-005",
                title="Large appended overlay",
                severity=Severity.LOW,
                description=(
                    f"{info.overlay_size} bytes of data are appended after the last section. "
                    "Overlays can hide a second payload or installer data."
                ),
                category=Category.PE,
                evidence=ctx.ev("overlay"),
                techniques=["T1027"],
                confidence=0.6,
                data={"overlay_size": info.overlay_size, "file_size": ctx.file_size},
            )
        )

    if info.timestamp_anomaly:
        findings.append(
            FindingDraft(
                rule_id="GB-PE-006",
                title="Anomalous compile timestamp",
                severity=Severity.LOW,
                description=f"The PE timestamp is suspicious: {info.timestamp_anomaly}.",
                category=Category.PE,
                evidence=ctx.ev("pe"),
                confidence=0.55,
                data={"timestamp": info.timestamp, "iso": info.timestamp_iso},
            )
        )

    if info.checksum_mismatch:
        findings.append(
            FindingDraft(
                rule_id="GB-PE-007",
                title="PE checksum mismatch",
                severity=Severity.LOW,
                description=(
                    "The stored PE checksum does not match the computed checksum. The file was "
                    "modified after it was built, or the checksum was never set."
                ),
                category=Category.PE,
                evidence=ctx.ev("pe"),
                confidence=0.5,
                data={"stored": info.checksum, "computed": info.computed_checksum},
            )
        )

    if not info.signature_present:
        findings.append(
            FindingDraft(
                rule_id="GB-PE-008",
                title="No Authenticode signature",
                severity=Severity.INFO,
                description="The file is not Authenticode-signed. Unsigned files are common, but unsigned malware is even more common.",
                category=Category.SIGNATURE,
                evidence=ctx.ev("signature"),
                confidence=0.5,
            )
        )

    if info.is_dotnet:
        findings.append(
            FindingDraft(
                rule_id="GB-PE-009",
                title=".NET managed assembly",
                severity=Severity.INFO,
                description="The sample is a .NET assembly. IL-level analysis is needed for deeper coverage.",
                category=Category.PE,
                evidence=ctx.ev("dotnet"),
                confidence=0.6,
            )
        )

    if info.installer_hint:
        findings.append(
            FindingDraft(
                rule_id="GB-PE-010",
                title=f"Installer detected ({info.installer_hint})",
                severity=Severity.INFO,
                description=(
                    "This looks like an installer. Package contents should be extracted and "
                    "analysed separately to avoid false positives."
                ),
                category=Category.PE,
                evidence=ctx.ev("pe"),
                confidence=0.6,
                data={"installer": info.installer_hint},
            )
        )

    if info.imports_count == 0 and not info.is_dotnet:
        findings.append(
            FindingDraft(
                rule_id="GB-PE-011",
                title="No imported functions",
                severity=Severity.HIGH,
                description=(
                    "The import table is empty. Normal native executables import from system DLLs; "
                    "this usually means packing or manual API resolution."
                ),
                category=Category.PE,
                evidence=ctx.ev("pe"),
                techniques=["T1027", "T1129"],
                confidence=0.75,
            )
        )

    if info.embedded_pe:
        findings.append(
            FindingDraft(
                rule_id="GB-PE-012",
                title="Embedded PE payload in resources",
                severity=Severity.HIGH,
                description=(
                    "A resource contains an MZ/PE header. This is a common way to hide a dropper "
                    "or second-stage executable inside the file."
                ),
                category=Category.PE,
                evidence=ctx.ev("embedded_pe", "resource"),
                techniques=["T1027"],
                confidence=0.8,
                data={"payloads": info.embedded_pe},
            )
        )

    if info.tls_callbacks:
        findings.append(
            FindingDraft(
                rule_id="GB-PE-013",
                title="TLS callbacks present",
                severity=Severity.LOW,
                description=(
                    "TLS callbacks run before the normal entry point. Legitimate software uses "
                    "them, but malware also uses them to run code earlier."
                ),
                category=Category.PE,
                evidence=ctx.ev("tls"),
                confidence=0.55,
                data={"count": info.tls_callbacks, "address": hex(info.tls_callback_address)},
            )
        )

    if imports.ordinal_count:
        findings.append(
            FindingDraft(
                rule_id="GB-PE-014",
                title="Ordinal-only imports",
                severity=Severity.LOW,
                description=(
                    "Some imports are referenced by ordinal instead of by name. This is legal, "
                    "but it hides which API is used and is common in malware."
                ),
                category=Category.PE,
                evidence=ctx.ev("pe"),
                techniques=["T1027"],
                confidence=0.55,
                data={"ordinals": imports.ordinal_imports},
            )
        )

    unusual_sections = [
        s.name for s in info.sections if s.name and s.name not in STANDARD_SECTIONS and not s.name.startswith(".debug")
    ]
    if unusual_sections:
        findings.append(
            FindingDraft(
                rule_id="GB-PE-015",
                title="Non-standard section names",
                severity=Severity.LOW,
                description=(
                    "The file contains section names that are not typical for a normal compiler "
                    "output. This can indicate packing or a custom loader."
                ),
                category=Category.PE,
                evidence=ctx.ev(*[f"section:{name}" for name in unusual_sections]),
                techniques=["T1027"],
                confidence=0.5,
                data={"sections": unusual_sections},
            )
        )

    # ------------------------------------------------------------- Process rules
    injection = imports.groups.get("process_injection", [])
    injection_strong = [
        function for function in injection
        if function.lower() in INJECTION_WRITE_OR_EXECUTE
    ]
    # OpenProcess by itself is normal in debuggers, task managers, and service
    # managers. Require a write/execute primitive before claiming injection.
    if injection_strong:
        severity = Severity.CRITICAL if len(injection_strong) >= 2 else Severity.HIGH
        findings.append(
            FindingDraft(
                rule_id="GB-PROC-001",
                title="Process injection capability",
                severity=severity,
                description=(
                    "The import table contains the API pattern used to write code into another "
                    "process and start it: " + ", ".join(injection) + "."
                ),
                category=Category.PROCESS,
                evidence=ctx.ev("imports:process_injection"),
                techniques=["T1055"],
                confidence=0.85 if len(injection_strong) >= 2 else 0.7,
                data={"functions": injection, "primitives": injection_strong},
            )
        )

    memory_reads = imports.groups.get("process_memory", [])
    if memory_reads:
        findings.append(
            FindingDraft(
                rule_id="GB-PROC-007",
                title="Process memory read capability",
                severity=Severity.MEDIUM if info.signature_present else Severity.HIGH,
                description=(
                    "The import table can read or dump another process's memory: "
                    + ", ".join(memory_reads) + ". Signed debuggers and monitoring tools "
                    "use the same APIs."
                ),
                category=Category.PROCESS,
                evidence=ctx.ev("imports:process_memory"),
                techniques=["T1003.001"],
                confidence=0.65 if info.signature_present else 0.75,
                data={"functions": memory_reads, "signed": info.signature_present},
            )
        )

    commands = strings.commands
    risky_commands = [command for command in commands if command in STRONG_COMMANDS]
    encoded_powershell = any(
        token in value.lower()
        for value in strings.all_strings
        for token in ("-encodedcommand", "-enc ", "frombase64string")
    )
    if risky_commands:
        findings.append(
            FindingDraft(
                rule_id="GB-PROC-002",
                title="Command interpreter / LOLBin strings",
                severity=Severity.HIGH if encoded_powershell else Severity.MEDIUM,
                description=(
                    "Strings reference command interpreters or living-off-the-land binaries: "
                    + ", ".join(risky_commands) + "."
                    + (" Encoded PowerShell content is present." if encoded_powershell else "")
                ),
                category=Category.PROCESS,
                evidence=ctx.ev("ioc:commands"),
                techniques=["T1059", "T1059.001", "T1027"] if encoded_powershell else ["T1059"],
                confidence=0.75 if encoded_powershell else 0.65,
                data={"commands": commands, "risky": risky_commands, "encoded": encoded_powershell},
            )
        )

    dynamic = imports.groups.get("dynamic_loading", [])
    if dynamic:
        findings.append(
            FindingDraft(
                rule_id="GB-PROC-003",
                title="Runtime code loading capability",
                severity=Severity.LOW,
                description=(
                    "The sample can resolve APIs and load code at runtime ("
                    + ", ".join(dynamic) + "). This is common in loaders and packers."
                ),
                category=Category.PROCESS,
                evidence=ctx.ev("imports:dynamic_loading"),
                techniques=["T1129"],
                confidence=0.55,
                data={"functions": dynamic},
            )
        )

    keylogging = imports.groups.get("keylogging", [])
    if keylogging:
        findings.append(
            FindingDraft(
                rule_id="GB-PROC-004",
                title="Keystroke capture capability",
                severity=Severity.HIGH,
                description="The import table contains keyboard hook or key-state APIs: " + ", ".join(keylogging) + ".",
                category=Category.PROCESS,
                evidence=ctx.ev("imports:keylogging"),
                techniques=["T1056.001"],
                confidence=0.8,
                data={"functions": keylogging},
            )
        )

    screen = imports.groups.get("screen_capture", [])
    network = imports.groups.get("network", [])
    if screen and network:
        findings.append(
            FindingDraft(
                rule_id="GB-PROC-005",
                title="Screen capture plus network capability",
                severity=Severity.MEDIUM,
                description=(
                    "The sample can capture the screen and communicate over the network, a "
                    "combination often used for remote surveillance."
                ),
                category=Category.PROCESS,
                evidence=ctx.ev("imports:screen_capture", "imports:network"),
                techniques=["T1113", "T1071.001"],
                confidence=0.7,
                data={"screen": screen, "network": network},
            )
        )

    privilege = imports.groups.get("privilege", [])
    if privilege:
        findings.append(
            FindingDraft(
                rule_id="GB-PROC-006",
                title="Token / privilege manipulation capability",
                severity=Severity.LOW,
                description="The sample can open process tokens or adjust privileges: " + ", ".join(privilege) + ".",
                category=Category.PROCESS,
                evidence=ctx.ev("imports:privilege"),
                techniques=["T1134"],
                confidence=0.55,
                data={"functions": privilege},
            )
        )

    # ------------------------------------------------------------ Registry rules
    persistence = imports.groups.get("persistence", [])
    autorun_keys = [key for key in strings.iocs.get("registry_keys", []) if _is_autorun_key(key)]
    if persistence and autorun_keys:
        findings.append(
            FindingDraft(
                rule_id="GB-REG-001",
                title="Persistence via autorun registry key",
                severity=Severity.HIGH,
                description=(
                    "The sample has registry-write APIs and contains an autorun key. This is a "
                    "direct persistence capability."
                ),
                category=Category.REGISTRY,
                evidence=ctx.ev("imports:persistence", "ioc:registry_keys"),
                techniques=["T1547.001"],
                confidence=0.85,
                data={"functions": persistence, "keys": autorun_keys[:5]},
            )
        )
    elif persistence:
        findings.append(
            FindingDraft(
                rule_id="GB-REG-002",
                title="Registry write capability",
                severity=Severity.LOW,
                description=(
                    "The sample imports registry write APIs. Alone this is weak evidence; "
                    "installers and system tools do the same."
                ),
                category=Category.REGISTRY,
                evidence=ctx.ev("imports:persistence"),
                techniques=["T1112"],
                confidence=0.5,
                data={"functions": persistence},
            )
        )

    if autorun_keys and not persistence:
        findings.append(
            FindingDraft(
                rule_id="GB-REG-003",
                title="Hardcoded autorun registry key",
                severity=Severity.HIGH,
                description="A hardcoded autorun registry key is present: " + ", ".join(autorun_keys[:3]) + ".",
                category=Category.REGISTRY,
                evidence=ctx.ev("ioc:registry_keys"),
                techniques=["T1547.001"],
                confidence=0.7,
                data={"keys": autorun_keys[:5]},
            )
        )

    # ------------------------------------------------------------- Network rules
    urls = strings.iocs.get("urls", [])
    ips = strings.iocs.get("ips", [])
    domains = strings.iocs.get("domains", [])
    # A lone four-part IP-looking string is frequently a version number in a
    # real binary. Require actual network APIs or a URL before claiming network
    # capability; keep raw IPs as supporting evidence when they accompany it.
    if len(network) >= 2 or urls:
        findings.append(
            FindingDraft(
                rule_id="GB-NET-001",
                title="Network communication capability",
                severity=Severity.MEDIUM if len(network) >= 2 else Severity.LOW,
                description=(
                    "The sample imports network APIs and/or contains network indicators. "
                    f"{len(network)} network functions, {len(urls)} URLs, {len(ips)} IPs."
                ),
                category=Category.NETWORK,
                evidence=ctx.ev("imports:network", "ioc:urls", "ioc:ips"),
                techniques=["T1071.001"],
                confidence=0.65,
                data={"functions": network, "urls": urls[:5], "ips": ips[:5]},
            )
        )

    execution = imports.groups.get("execution", [])
    if network and execution and (urls or ips):
        findings.append(
            FindingDraft(
                rule_id="GB-NET-002",
                title="Download-and-execute capability",
                severity=Severity.HIGH,
                description=(
                    "The sample combines network access, network indicators, and process "
                    "execution. This is the classic dropper pattern."
                ),
                category=Category.NETWORK,
                evidence=ctx.ev("imports:network", "imports:execution", "ioc:urls", "ioc:ips"),
                techniques=["T1105", "T1106"],
                confidence=0.75,
                data={"network": network, "execution": execution, "dynamic": dynamic},
            )
        )

    if urls and ips:
        findings.append(
            FindingDraft(
                rule_id="GB-NET-003",
                title="Hardcoded URL and raw IP indicators",
                severity=Severity.LOW,
                description=(
                    "The sample contains both URLs and raw IP addresses. Hardcoded infrastructure "
                    "is common in malware and uncommon in normal applications."
                ),
                category=Category.NETWORK,
                evidence=ctx.ev("ioc:urls", "ioc:ips"),
                techniques=["T1071.001"],
                confidence=0.6,
                data={"urls": urls[:5], "ips": ips[:5]},
            )
        )

    joined_strings = "\n".join(strings.all_strings).lower()
    mining_hits = [
        marker
        for marker in ("stratum+tcp://", "stratum+ssl://", "xmrig", "cryptonight", "minerd")
        if marker in joined_strings
    ]
    if mining_hits:
        findings.append(
            FindingDraft(
                rule_id="GB-NET-004",
                title="Cryptocurrency mining indicators",
                severity=Severity.HIGH,
                description=(
                    "The sample contains mining-pool or miner identifiers: "
                    + ", ".join(mining_hits) + "."
                ),
                category=Category.NETWORK,
                evidence=ctx.ev("mining"),
                techniques=["T1496"],
                confidence=0.85,
                data={"markers": mining_hits},
            )
        )

    # ---------------------------------------------------------------- File rules
    paths = strings.iocs.get("windows_paths", [])
    dropped = [path for path in paths if _looks_like_dropped_executable(path)]
    if dropped:
        findings.append(
            FindingDraft(
                rule_id="GB-FILE-001",
                title="Hardcoded executable path in a writable location",
                severity=Severity.MEDIUM,
                description=(
                    "The sample references an executable path under Temp, AppData, Public, or "
                    "ProgramData: " + ", ".join(dropped[:3]) + "."
                ),
                category=Category.FILE,
                evidence=ctx.ev("ioc:windows_paths"),
                techniques=["T1105"],
                confidence=0.65,
                data={"paths": dropped[:10]},
            )
        )

    # ------------------------------------------------------- Anti-analysis rules
    anti = imports.groups.get("anti_analysis", [])
    strong_anti = [function for function in anti if is_strong_anti_analysis(function)]
    weak_anti = [function for function in anti if is_weak_anti_analysis(function)]
    # Sleep/GetTickCount/QueryPerformanceCounter are ubiquitous. Only report
    # anti-analysis when strong checks exist, or when one strong check is paired
    # with another malicious capability.
    if len(strong_anti) >= 2 or (
        len(strong_anti) == 1
        and (injection_strong or (persistence and autorun_keys))
    ):
        severity = Severity.CRITICAL if len(strong_anti) >= 3 else Severity.HIGH
        findings.append(
            FindingDraft(
                rule_id="GB-PE-016",
                title="Anti-analysis checks",
                severity=severity,
                description=(
                    "The sample imports debugger or environment checks: "
                    + ", ".join(strong_anti)
                    + ". These are used to detect analysts and sandboxes."
                ),
                category=Category.PE,
                evidence=ctx.ev("imports:anti_analysis"),
                techniques=["T1497.001"],
                confidence=0.7 if len(strong_anti) >= 2 else 0.6,
                data={"functions": strong_anti, "timing_only": weak_anti},
            )
        )

    if info.pdb_path:
        findings.append(
            FindingDraft(
                rule_id="GB-PE-017",
                title="Debug PDB path present",
                severity=Severity.INFO,
                description="The binary retains a debug PDB path, which may leak build details.",
                category=Category.PE,
                evidence=ctx.ev("pdb"),
                confidence=0.5,
                data={"pdb": info.pdb_path},
            )
        )

    return findings


RULE_CATALOG = [
    ("GB-PE-002", "Packed or heavily obfuscated image"),
    ("GB-PE-003", "Writable and executable section"),
    ("GB-PE-004", "Entry point outside an executable section"),
    ("GB-PE-005", "Large appended overlay"),
    ("GB-PE-006", "Anomalous compile timestamp"),
    ("GB-PE-007", "PE checksum mismatch"),
    ("GB-PE-008", "No Authenticode signature"),
    ("GB-PE-009", ".NET managed assembly"),
    ("GB-PE-010", "Installer detected"),
    ("GB-PE-011", "No imported functions"),
    ("GB-PE-012", "Embedded PE payload in resources"),
    ("GB-PE-013", "TLS callbacks present"),
    ("GB-PE-014", "Ordinal-only imports"),
    ("GB-PE-015", "Non-standard section names"),
    ("GB-PE-016", "Anti-analysis checks"),
    ("GB-PE-017", "Debug PDB path present"),
    ("GB-PROC-001", "Process injection capability"),
    ("GB-PROC-002", "Command interpreter / LOLBin strings"),
    ("GB-PROC-003", "Runtime code loading capability"),
    ("GB-PROC-004", "Keystroke capture capability"),
    ("GB-PROC-005", "Screen capture plus network capability"),
    ("GB-PROC-006", "Token / privilege manipulation capability"),
    ("GB-PROC-007", "Process memory read capability"),
    ("GB-REG-001", "Persistence via autorun registry key"),
    ("GB-REG-002", "Registry write capability"),
    ("GB-REG-003", "Hardcoded autorun registry key"),
    ("GB-NET-001", "Network communication capability"),
    ("GB-NET-002", "Download-and-execute capability"),
    ("GB-NET-003", "Hardcoded URL and raw IP indicators"),
    ("GB-NET-004", "Cryptocurrency mining indicators"),
    ("GB-FILE-001", "Hardcoded executable path in a writable location"),
]


def behavior_label(behaviour: str) -> str:
    return BEHAVIOR_LABELS.get(behaviour, behaviour.replace("_", " "))


def behavior_technique(behaviour: str) -> str | None:
    return BEHAVIOR_TECHNIQUE.get(behaviour)
