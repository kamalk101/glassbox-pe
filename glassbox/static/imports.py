"""Group imported Windows APIs into behaviours."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..schema import Category

BEHAVIORS: dict[str, set[str]] = {
    "process_injection": {
        "openprocess", "virtualallocex", "writeprocessmemory", "createremotethread",
        "ntcreatethreadex", "queueuserapc", "setthreadcontext", "ntunmapviewofsection",
        "rtlcreateuserthread", "virtualprotectex",
    },
    "process_memory": {
        "readprocessmemory", "ntreadvirtualmemory", "minidumpwritedump",
        "psscapturesnapshot",
    },
    "execution": {
        "createprocessa", "createprocessw", "winexec", "shellexecutea",
        "shellexecutew", "shellexecuteexa", "shellexecuteexw",
        "createprocessasusera", "createprocessasuserw", "createprocesswithlogonw",
    },
    "dynamic_loading": {
        "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
        "getprocaddress", "ldrloaddll", "ntmapviewofsection",
    },
    "persistence": {
        "regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw",
        "createservicea", "createservicew", "startservicea", "startservicew",
        "changeserviceconfiga", "changeserviceconfigw",
    },
    "network": {
        "internetopena", "internetopenw", "internetopenurla", "internetopenurlw",
        "internetreadfile", "httpsendrequesta", "httpsendrequestw",
        "winhttpopen", "winhttpconnect", "winhttpsendrequest",
        "urldownloadtofilea", "urldownloadtofilew", "connect", "send", "recv",
        "gethostbyname", "wsastartup", "dnsquery_a", "dnsquery_w",
    },
    "file": {
        "createfilea", "createfilew", "writefile", "deletefilea", "deletefilew",
        "movefilea", "movefilew", "findfirstfilea", "findfirstfilew",
        "copyfilea", "copyfilew", "setfileattributesa", "setfileattributesw",
    },
    "anti_analysis": {
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
        "gettickcount", "gettickcount64", "queryperformancecounter", "sleep",
        "outputdebugstringa", "outputdebugstringw",
    },
    "crypto": {
        "cryptencrypt", "cryptdecrypt", "bcryptencrypt", "bcryptdecrypt",
        "cryptacquirecontexta", "cryptacquirecontextw",
    },
    "privilege": {
        "adjusttokenprivileges", "openprocesstoken", "lookupprivilegevaluea",
        "lookupprivilegevaluew",
    },
    "keylogging": {
        "setwindowshookexa", "setwindowshookexw", "getasynckeystate",
        "getkeystate", "getkeyboardstate",
    },
    "screen_capture": {
        "getdc", "bitblt", "createcompatibledc", "createcompatiblebitmap",
    },
}

BEHAVIOR_CATEGORY: dict[str, Category] = {
    "process_injection": Category.PROCESS,
    "process_memory": Category.PROCESS,
    "execution": Category.PROCESS,
    "dynamic_loading": Category.PROCESS,
    "persistence": Category.REGISTRY,
    "network": Category.NETWORK,
    "file": Category.FILE,
    "anti_analysis": Category.PE,
    "crypto": Category.FILE,
    "privilege": Category.PROCESS,
    "keylogging": Category.PROCESS,
    "screen_capture": Category.PROCESS,
}

BEHAVIOR_TECHNIQUE: dict[str, str] = {
    "process_injection": "T1055",
    "process_memory": "T1003.001",
    "execution": "T1106",
    "dynamic_loading": "T1129",
    "persistence": "T1547.001",
    "network": "T1071.001",
    "anti_analysis": "T1497.001",
    "privilege": "T1134",
    "keylogging": "T1056.001",
    "screen_capture": "T1113",
}

# Timing and sleep APIs are normal in almost every Windows program. They only
# become meaningful anti-analysis evidence when paired with debugger or
# process-inspection checks. Keeping the two sets separate prevents the most
# common static false positive on real benign binaries.
STRONG_ANTI_ANALYSIS = {
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "outputdebugstringa",
    "outputdebugstringw",
}
WEAK_ANTI_ANALYSIS = {
    "gettickcount",
    "gettickcount64",
    "queryperformancecounter",
    "sleep",
}

BEHAVIOR_LABELS: dict[str, str] = {
    "process_injection": "process injection",
    "process_memory": "process memory access",
    "execution": "process execution",
    "dynamic_loading": "runtime code loading",
    "persistence": "persistence / registry autorun",
    "network": "network communication",
    "file": "file access",
    "anti_analysis": "anti-analysis checks",
    "crypto": "cryptography",
    "privilege": "token / privilege manipulation",
    "keylogging": "keystroke capture",
    "screen_capture": "screen capture",
}


@dataclass
class ImportAnalysis:
    all_functions: list[str] = field(default_factory=list)
    groups: dict[str, list[str]] = field(default_factory=dict)
    dlls: list[str] = field(default_factory=list)
    ordinal_imports: dict[str, list[int]] = field(default_factory=dict)

    @property
    def ordinal_count(self) -> int:
        return sum(len(v) for v in self.ordinal_imports.values())


def _normalise(function: str) -> str:
    name = function.strip().lower()
    if "." in name:
        name = name.rsplit(".", 1)[-1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.lstrip("_")


API_LOOKUP: dict[str, list[str]] = {}
for _behaviour, _functions in BEHAVIORS.items():
    for _function in _functions:
        API_LOOKUP.setdefault(_function, []).append(_behaviour)


def classify_api(function: str) -> list[str]:
    """Return the behaviours associated with an API name.

    Accepts either a bare name (`CreateFileA`) or a Speakeasy-style name
    (`KERNEL32.CreateFileA`).
    """
    return API_LOOKUP.get(_normalise(function), [])


def is_strong_anti_analysis(function: str) -> bool:
    return _normalise(function) in STRONG_ANTI_ANALYSIS


def is_weak_anti_analysis(function: str) -> bool:
    return _normalise(function) in WEAK_ANTI_ANALYSIS


def analyze(imports: dict[str, list[str]], ordinal_imports: dict[str, list[int]]) -> ImportAnalysis:
    groups: dict[str, list[str]] = {behaviour: [] for behaviour in BEHAVIORS}
    all_functions: list[str] = []
    seen: set[str] = set()

    for dll, names in imports.items():
        for function in names:
            if function not in seen:
                seen.add(function)
                all_functions.append(function)
            for behaviour in classify_api(function):
                if function not in groups[behaviour]:
                    groups[behaviour].append(function)

    groups = {k: sorted(v, key=str.lower) for k, v in groups.items() if v}
    return ImportAnalysis(
        all_functions=sorted(all_functions, key=str.lower),
        groups=groups,
        dlls=sorted(imports),
        ordinal_imports=ordinal_imports,
    )
