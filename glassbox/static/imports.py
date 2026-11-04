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
    "execution": "T1106",
    "dynamic_loading": "T1129",
    "persistence": "T1547.001",
    "network": "T1071.001",
    "anti_analysis": "T1497.001",
    "privilege": "T1134",
    "keylogging": "T1056.001",
    "screen_capture": "T1113",
}

BEHAVIOR_LABELS: dict[str, str] = {
    "process_injection": "process injection",
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
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.lstrip("_")


def analyze(imports: dict[str, list[str]], ordinal_imports: dict[str, list[int]]) -> ImportAnalysis:
    lookup: dict[str, list[str]] = {}
    for behaviour, functions in BEHAVIORS.items():
        for function in functions:
            lookup.setdefault(function, []).append(behaviour)

    groups: dict[str, list[str]] = {behaviour: [] for behaviour in BEHAVIORS}
    all_functions: list[str] = []
    seen: set[str] = set()

    for dll, names in imports.items():
        for function in names:
            if function not in seen:
                seen.add(function)
                all_functions.append(function)
            normalised = _normalise(function)
            for behaviour in lookup.get(normalised, []):
                if function not in groups[behaviour]:
                    groups[behaviour].append(function)

    groups = {k: sorted(v, key=str.lower) for k, v in groups.items() if v}
    return ImportAnalysis(
        all_functions=sorted(all_functions, key=str.lower),
        groups=groups,
        dlls=sorted(imports),
        ordinal_imports=ordinal_imports,
    )
