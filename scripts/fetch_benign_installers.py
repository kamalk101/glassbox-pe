#!/usr/bin/env python3
"""Download a small, fixed set of benign installer binaries for evaluation.

These are official public distributions, never unpacked or executed. The files
are stored under the gitignored ``corpus/benign-installers`` directory together
with a manifest labelled ``clean`` for GlassBox's false-positive study.

Sources and versions are pinned where the project publishes them. ``nuget.exe``
uses the official stable endpoint because its filename is not versioned there.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from glassbox.static.pe import parse_pe

SOURCES = [
    {
        "name": "7-Zip-26.05-x64.exe",
        "url": "https://github.com/ip7z/7zip/releases/download/26.05/7z2605-x64.exe",
        "family": "7-zip",
        "version": "26.05",
        "notes": "official 7-Zip installer",
    },
    {
        "name": "innosetup-7.1.1-x64.exe",
        "url": "https://github.com/jrsoftware/issrc/releases/download/is-7_1_1/innosetup-7.1.1-x64.exe",
        "family": "inno-setup",
        "version": "7.1.1",
        "notes": "official Inno Setup installer",
    },
    {
        "name": "python-3.14.10-amd64.exe",
        "url": "https://www.python.org/ftp/python/3.14.10/python-3.14.10-amd64.exe",
        "family": "python-runtime",
        "version": "3.14.10",
        "notes": "official Python Windows installer",
    },
    {
        "name": "npp.8.9.8.1.Installer.x64.exe",
        "url": "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.8.1/npp.8.9.8.1.Installer.x64.exe",
        "family": "notepad++",
        "version": "8.9.8.1",
        "notes": "official Notepad++ installer",
        "sha256": "26f3bcced788fadbac4e7e577b430ea2ce6060cf3bcad993ef4612ecd7d743da",
    },
    {
        "name": "nuget.exe",
        "url": "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe",
        "family": "nuget-cli",
        "version": "latest",
        "notes": "official NuGet command-line tool (.NET PE)",
    },
]
MAX_BYTES = 100 * 1024 * 1024


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "glassbox-pe-corpus-fetch/1.0"})
    total = 0
    with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as output:
        while True:
            chunk = response.read(256 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_BYTES:
                raise ValueError(f"download exceeded {MAX_BYTES} bytes")
            output.write(chunk)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=str(ROOT / "corpus" / "benign-installers"),
        help="output directory (default: corpus/benign-installers)",
    )
    parser.add_argument("--clean", action="store_true", help="remove the output directory first")
    args = parser.parse_args()

    output = Path(args.output).expanduser().resolve()
    if args.clean and output.exists():
        import shutil
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    samples = []
    temp_root = Path(tempfile.mkdtemp(prefix=".benign-installers-", dir=output.parent))
    try:
        for source in SOURCES:
            name = source["name"]
            target = output / name
            temp_file = temp_root / name
            print(f"downloading {source['url']}")
            _download(source["url"], temp_file)
            sha256 = _hash_file(temp_file)
            expected = source.get("sha256")
            if expected and sha256 != expected:
                raise ValueError(f"SHA-256 mismatch for {name}: expected {expected}, got {sha256}")
            info = parse_pe(temp_file.read_bytes())
            if not info.is_pe or info.parse_error:
                raise ValueError(f"downloaded file is not a parseable PE: {name}")
            os.replace(temp_file, target)
            samples.append(
                {
                    "path": name,
                    "label": "clean",
                    "family": source.get("family"),
                    "notes": source.get("notes"),
                    "version": source.get("version"),
                    "sha256": sha256,
                    "source_url": source["url"],
                    "is_dotnet": bool(info.is_dotnet),
                    "installer_hint": info.installer_hint,
                    "signed": bool(info.signature_present),
                }
            )
            print(f"  {sha256}  dotnet={bool(info.is_dotnet)} installer={info.installer_hint} signed={bool(info.signature_present)}")

        manifest = {
            "version": 1,
            "description": (
                "Official public benign installer binaries downloaded for static "
                "false-positive measurement. Do not execute during evaluation."
            ),
            "samples": samples,
        }
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"wrote {len(samples)} installer(s) and manifest to {output}")
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        import shutil
        shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
