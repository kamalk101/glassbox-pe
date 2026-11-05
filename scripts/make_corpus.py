#!/usr/bin/env python3
"""Build a small labelled synthetic corpus for `glassbox eval`.

The samples are valid PE files for parsing, not runnable programs. They exist
to demonstrate the evaluation workflow and to catch rule regressions; they are
not a substitute for a real malware corpus.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.fixtures.make_pe import DEFAULT_IMPORTS, DEFAULT_STRINGS, build_pe

SAMPLES = [
    {
        "path": "benign-fileops.exe",
        "label": "clean",
        "family": "benign",
        "notes": "ordinary file helper",
        "techniques": [],
        "pe": {
            "imports": ["CreateFileA", "ReadFile", "WriteFile", "CloseHandle", "GetFileSize"],
            "strings": ["C:\\Program Files\\GlassBox Demo\\data.txt", "hello from a benign helper"],
        },
    },
    {
        "path": "benign-console.exe",
        "label": "clean",
        "family": "benign",
        "notes": "console utility",
        "techniques": [],
        "pe": {
            "imports": ["GetStdHandle", "WriteConsoleA", "ExitProcess", "GetCommandLineA"],
            "strings": ["GlassBox PE demo utility", "usage: demo [options]"],
        },
    },
    {
        "path": "suspicious-injection.exe",
        "label": "suspicious",
        "family": "injector",
        "notes": "process-injection capability without a full chain",
        "techniques": ["T1055"],
        "pe": {
            "imports": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
            "strings": ["target process", "injection stage"],
        },
    },
    {
        "path": "suspicious-anti-vm.exe",
        "label": "suspicious",
        "family": "anti-analysis",
        "notes": "debugger and timing checks",
        "techniques": ["T1497.001"],
        "pe": {
            "imports": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "Sleep"],
            "strings": ["debugger detected", "waiting before execution"],
        },
    },
    {
        "path": "malicious-default.exe",
        "label": "malicious",
        "family": "synthetic-chain",
        "notes": "multi-stage synthetic sample",
        "techniques": [
            "T1055",
            "T1059",
            "T1071.001",
            "T1105",
            "T1106",
            "T1129",
            "T1497.001",
            "T1547.001",
        ],
        "pe": {"imports": DEFAULT_IMPORTS, "strings": DEFAULT_STRINGS},
    },
    {
        "path": "malicious-packed.exe",
        "label": "malicious",
        "family": "synthetic-chain-packed",
        "notes": "same chain with UPX-like section markers",
        "techniques": [
            "T1027",
            "T1027.002",
            "T1055",
            "T1059",
            "T1071.001",
            "T1105",
            "T1106",
            "T1129",
            "T1497.001",
            "T1547.001",
        ],
        "pe": {"imports": DEFAULT_IMPORTS, "strings": DEFAULT_STRINGS, "packed": True},
    },
    {
        "path": "malicious-credential-theft.exe",
        "label": "malicious",
        "family": "credential-theft",
        "notes": "YARA-visible credential-dumping strings",
        "techniques": ["T1003.001"],
        "pe": {
            "imports": ["OpenProcess", "ReadProcessMemory", "CreateFileA"],
            "strings": ["sekurlsa::logonpasswords", "lsadump::sam", "debug output"],
        },
    },
    {
        "path": "malicious-encoded-powershell.exe",
        "label": "malicious",
        "family": "encoded-powershell",
        "notes": "encoded and dynamically downloaded PowerShell",
        "techniques": ["T1059.001", "T1027"],
        "pe": {
            "imports": ["CreateProcessA", "WinExec", "InternetOpenA"],
            "strings": [
                "powershell -encodedcommand AAAA",
                "FromBase64String",
                "DownloadString",
            ],
        },
    },
    {
        "path": "malicious-coinminer.exe",
        "label": "malicious",
        "family": "coinminer",
        "notes": "mining-pool strings",
        "techniques": ["T1496"],
        "pe": {
            "imports": ["InternetOpenA", "Connect", "Send", "Recv"],
            "strings": ["stratum+tcp://pool.example:3333", "xmrig", "monero"],
        },
    },
    {
        "path": "evasive-timing-only.exe",
        "label": "suspicious",
        "family": "evasion-probe",
        "notes": "designed to evade static: timing-only anti-analysis APIs, no strings",
        "techniques": ["T1497.001"],
        "pe": {
            "imports": ["GetTickCount", "QueryPerformanceCounter", "Sleep"],
            "strings": ["ordinary timing loop"],
        },
    },
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output",
        nargs="?",
        default=str(ROOT / "corpus" / "demo"),
        help="output directory (default: corpus/demo)",
    )
    args = parser.parse_args()

    output = Path(args.output).expanduser()
    output.mkdir(parents=True, exist_ok=True)
    manifest_samples = []
    for sample in SAMPLES:
        target = output / sample["path"]
        target.write_bytes(build_pe(**sample["pe"]))
        manifest_samples.append(
            {
                "path": sample["path"],
                "label": sample["label"],
                "family": sample["family"],
                "notes": sample["notes"],
                "techniques": sample["techniques"],
            }
        )

    manifest = {
        "version": 1,
        "description": "Synthetic GlassBox PE evaluation corpus. Not real malware.",
        "samples": manifest_samples,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"wrote {len(manifest_samples)} samples to {output}")
    print(f"manifest: {output / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
