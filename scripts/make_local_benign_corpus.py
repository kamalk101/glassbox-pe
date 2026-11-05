#!/usr/bin/env python3
"""Build a real benign PE corpus from trusted local software installs.

This does not download or execute anything. It walks known application and
Python-package locations, keeps files that parse as PE, deduplicates by SHA-256,
copies them into an ignored corpus directory, and writes a manifest labelled
``clean``.

The corpus is a false-positive check, not a representative benign benchmark.
Keep the source paths in the manifest so the provenance is auditable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import sysconfig
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from glassbox.static.pe import parse_pe

DEFAULT_ROOTS = [
    "/usr/share/code",
    "/opt",
    "/usr/lib",
    str(Path.home() / ".local" / "lib"),
]

MAX_BYTES = 25 * 1024 * 1024


def _site_packages_roots() -> list[Path]:
    roots: list[Path] = []
    for key in ("purelib", "platlib"):
        value = sysconfig.get_paths().get(key)
        if value:
            roots.append(Path(value))
    return roots


def _candidate_roots(extra: list[str]) -> list[Path]:
    roots = [Path(value).expanduser() for value in DEFAULT_ROOTS] + _site_packages_roots()
    roots += [Path(value).expanduser() for value in extra]
    seen: set[Path] = set()
    unique: list[Path] = []
    for root in roots:
        try:
            resolved = root.resolve()
        except OSError:
            continue
        if resolved in seen or not resolved.is_dir():
            continue
        seen.add(resolved)
        unique.append(resolved)
    return unique


def _iter_pe_files(roots: list[Path], include_dll: bool, output: Path):
    suffixes = {".exe"} if not include_dll else {".exe", ".dll"}
    for root in roots:
        try:
            entries = root.rglob("*")
        except OSError:
            continue
        for path in entries:
            try:
                if not path.is_file() or path.suffix.lower() not in suffixes:
                    continue
                if output in path.resolve().parents:
                    continue
                if path.stat().st_size > MAX_BYTES:
                    continue
            except OSError:
                continue
            yield path


def _digest(path: Path) -> tuple[str, bytes] | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return hashlib.sha256(data).hexdigest(), data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "output",
        nargs="?",
        default=str(ROOT / "corpus" / "local-benign"),
        help="output directory (default: corpus/local-benign)",
    )
    parser.add_argument(
        "--root",
        action="append",
        default=[],
        help="extra directory to scan for .exe files (repeatable)",
    )
    parser.add_argument("--max-samples", type=int, default=30)
    parser.add_argument("--include-dll", action="store_true", help="also collect .dll files")
    parser.add_argument("--clean", action="store_true", help="remove the output directory first")
    args = parser.parse_args()

    output = Path(args.output).expanduser().resolve()
    if args.clean and output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    roots = _candidate_roots(args.root)
    samples = []
    seen: set[str] = set()
    skipped_non_pe = 0
    skipped_duplicate = 0

    for path in _iter_pe_files(roots, args.include_dll, output):
        if len(samples) >= args.max_samples:
            break
        digested = _digest(path)
        if digested is None:
            continue
        sha256, data = digested
        if sha256 in seen:
            skipped_duplicate += 1
            continue
        info = parse_pe(data)
        if not info.is_pe or info.parse_error:
            skipped_non_pe += 1
            continue
        seen.add(sha256)
        target_name = f"{sha256[:12]}-{path.name}"
        target = output / target_name
        target.write_bytes(data)
        samples.append(
            {
                "path": target_name,
                "label": "clean",
                "family": "local-benign",
                "notes": f"trusted local install: {path}",
                "sha256": sha256,
            }
        )

    manifest = {
        "version": 1,
        "description": (
            "Real benign PE corpus collected from trusted local application and "
            "Python-package installs. Not a representative benign benchmark."
        ),
        "source_roots": [str(root) for root in roots],
        "samples": samples,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"wrote {len(samples)} real benign sample(s) to {output}")
    print(f"skipped {skipped_duplicate} duplicate(s), {skipped_non_pe} non-PE file(s)")
    print(f"manifest: {output / 'manifest.json'}")
    return 0 if samples else 1


if __name__ == "__main__":
    raise SystemExit(main())
