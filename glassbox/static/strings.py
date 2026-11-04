"""String and indicator extraction from raw bytes.

No execution, no dependencies beyond the standard library.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

URL_RE = re.compile(r"https?://[^\s\"'<>\\)\]}]+", re.IGNORECASE)
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)
REGISTRY_RE = re.compile(
    r"(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)[\\/][^\s\"'<>|]{3,200}",
    re.IGNORECASE,
)
WINPATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"'<>|]{2,260}")
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

FILE_EXTENSIONS = {
    "dll", "exe", "sys", "ocx", "cpl", "drv", "mui", "manifest", "config",
    "pdb", "lib", "obj", "res", "xml", "txt", "log", "dat", "bin", "tmp",
    "jpg", "jpeg", "png", "gif", "ico", "bmp", "wav", "mp3", "mp4", "avi",
    "zip", "rar", "7z", "cab", "msi", "msp", "mst", "inf", "cat", "cer",
    "crt", "pem", "pfx", "p12", "js", "vbs", "ps1", "bat", "cmd", "scr",
    "lnk", "url", "html", "htm", "css", "json", "yml", "yaml", "toml",
}

COMMAND_TOKENS = (
    "cmd.exe", "powershell", "pwsh", "rundll32", "regsvr32", "mshta",
    "wscript", "cscript", "certutil", "bitsadmin", "schtasks", "sc.exe",
    "net.exe", "net1.exe", "wmic", "curl", "reg.exe", "attrib", "vssadmin",
    "bcdedit", "wevtutil", "taskkill", "psexec", "msbuild", "installutil",
)


@dataclass
class StringsResult:
    all_strings: list[str] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    base64_like: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    truncated: bool = False

    def count(self, kind: str) -> int:
        return len(self.iocs.get(kind, []))


def _clean(value: str) -> str:
    return value.strip().rstrip(".,);]}\"'")


def _dedupe(values: list[str], limit: int) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
        if len(result) >= limit:
            break
    return result


def _looks_like_filename(candidate: str) -> bool:
    if "." not in candidate:
        return False
    extension = candidate.rsplit(".", 1)[-1].lower()
    return extension in FILE_EXTENSIONS


def extract_strings(data: bytes, min_len: int = 4, limit: int = 30000) -> tuple[list[str], bool]:
    strings: list[str] = []
    truncated = False
    for match in ASCII_RE.finditer(data):
        if len(strings) >= limit:
            truncated = True
            break
        strings.append(match.group().decode("ascii", "ignore")[:4096])
    for match in UTF16_RE.finditer(data):
        if len(strings) >= limit:
            truncated = True
            break
        strings.append(match.group().decode("utf-16-le", "ignore")[:4096])
    return _dedupe(strings, limit), truncated


def extract_iocs(strings: list[str]) -> dict[str, list[str]]:
    urls: list[str] = []
    ips: list[str] = []
    domains: list[str] = []
    registry: list[str] = []
    paths: list[str] = []
    base64_like: list[str] = []

    for value in strings:
        for match in URL_RE.findall(value):
            urls.append(_clean(match))
        for match in IPV4_RE.findall(value):
            ips.append(match)
        for match in DOMAIN_RE.findall(value):
            candidate = _clean(match).lower()
            if _looks_like_filename(candidate):
                continue
            domains.append(candidate)
        for match in REGISTRY_RE.findall(value):
            registry.append(_clean(match))
        for match in WINPATH_RE.findall(value):
            paths.append(_clean(match))
        for match in BASE64_RE.findall(value):
            base64_like.append(match)

    return {
        "urls": _dedupe(urls, 300),
        "ips": _dedupe(ips, 300),
        "domains": _dedupe(domains, 300),
        "registry_keys": _dedupe(registry, 200),
        "windows_paths": _dedupe(paths, 300),
        "base64": _dedupe(base64_like, 25),
    }


def find_commands(strings: list[str]) -> list[str]:
    lowered = "\n".join(strings).lower()
    return [token for token in COMMAND_TOKENS if token in lowered]


def extract(data: bytes) -> StringsResult:
    strings, truncated = extract_strings(data)
    iocs = extract_iocs(strings)
    return StringsResult(
        all_strings=strings,
        iocs=iocs,
        base64_like=iocs.get("base64", []),
        commands=find_commands(strings),
        truncated=truncated,
    )
