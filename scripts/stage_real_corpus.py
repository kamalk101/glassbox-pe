#!/usr/bin/env python3
"""Stage user-provided PE samples into a private, non-executing corpus.

This script is for a trusted operator who already has lawful access to samples
and wants to preserve them safely for offline static analysis. It copies files,
hashes them, validates that they parse as PE, deduplicates by SHA-256, and
writes a manifest. It never executes a sample.

It does not extract archives. Unpack samples with your own lab tooling first,
and only in an isolated environment. It will refuse to overwrite a non-empty
output directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from glassbox.static.pe import parse_pe

TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
VALID_LABELS = {"clean", "suspicious", "malicious"}
LAYOUT_DIRS = ("clean", "suspicious", "malicious")
MAX_SAMPLE_BYTES = 512 * 1024 * 1024


def _is_lower_hex(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _technique_ids(values: list[str]) -> list[str]:
    techniques = []
    for raw in values:
        for item in raw.replace(",", " ").split():
            value = item.strip().upper()
            if not value:
                continue
            if not TECHNIQUE_RE.match(value):
                raise ValueError(f"invalid ATT&CK technique ID: {value!r}")
            techniques.append(value)
    return sorted(set(techniques))


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _label_for(input_dir: Path, path: Path, layout: str, default_label: str | None) -> str:
    if layout == "flat":
        if default_label is None:
            raise ValueError("a flat input layout requires --label")
        return default_label

    relative = path.relative_to(input_dir)
    top = relative.parts[0].lower() if relative.parts else ""
    if top in LAYOUT_DIRS:
        return top
    if len(relative.parts) > 1:
        second = relative.parts[1].lower() if len(relative.parts) > 1 else ""
        if second in LAYOUT_DIRS:
            return second
    if default_label is not None:
        return default_label
    raise ValueError(f"could not infer label for {path}; use clean/, suspicious/, or malicious/ directories")


def _iter_pe_candidates(source: Path) -> list[Path]:
    if source.is_file():
        return [source]
    if source.is_dir():
        return sorted(path for path in source.rglob("*") if path.is_file())
    raise FileNotFoundError(source)


def _prepare_output(output: Path) -> tuple[Path, Path]:
    output_parent = output.parent.resolve()
    output_parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {output}")
    temp = Path(tempfile.mkdtemp(prefix=f".{output.name}-", dir=output_parent))
    temp.chmod(0o700)
    return temp, output


def _safe_copy(source: Path, destination: Path) -> None:
    shutil.copyfile(source, destination)
    destination.chmod(0o600)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="file or directory containing PE samples")
    parser.add_argument(
        "--output",
        default=str(ROOT / "corpus" / "real-malware"),
        help="output directory (default: corpus/real-malware, gitignored)",
    )
    parser.add_argument(
        "--layout",
        choices=["auto", "flat"],
        default="auto",
        help="auto derives labels from clean/, suspicious/, or malicious/ parent directories",
    )
    parser.add_argument("--label", choices=sorted(VALID_LABELS), default=None)
    parser.add_argument("--technique", action="append", default=[], help="ATT&CK ID for all samples")
    parser.add_argument("--family", default="operator-provided")
    parser.add_argument("--notes", default="staged by an operator; source path preserved in provenance")
    parser.add_argument("--max-sample-mb", type=int, default=64)
    parser.add_argument(
        "--confirm-malware",
        action="store_true",
        help="acknowledge that these may be malicious binaries; required for non-clean labels",
    )
    args = parser.parse_args()

    default_label = args.label
    max_bytes = args.max_sample_mb * 1024 * 1024
    source = Path(args.source).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()

    if default_label in {"malicious", "suspicious"} and not args.confirm_malware:
        print("refusing to stage labelled malware without --confirm-malware", file=sys.stderr)
        return 2

    candidates = _iter_pe_candidates(source)
    techniques = _technique_ids(args.technique)
    temp, final = None, None
    try:
        temp, final = _prepare_output(output)
        samples = []
        seen: set[str] = set()
        skipped = []

        for candidate in candidates:
            if candidate.suffix.lower() != ".exe":
                skipped.append((str(candidate), "not an .exe"))
                continue
            try:
                size = candidate.stat().st_size
            except OSError:
                skipped.append((str(candidate), "unreadable"))
                continue
            if size > max_bytes or size > MAX_SAMPLE_BYTES:
                skipped.append((str(candidate), f"larger than {args.max_sample_mb} MiB"))
                continue
            # Hash first so we never copy more than necessary.
            sha256 = _digest_file(candidate)
            if _is_lower_hex(sha256) is False or sha256 in seen:
                skipped.append((str(candidate), "duplicate or unreadable"))
                continue
            try:
                info = parse_pe(candidate.read_bytes())
            except OSError:
                skipped.append((str(candidate), "unreadable"))
                continue
            if not info.is_pe or info.parse_error:
                skipped.append((str(candidate), "not a parseable PE"))
                continue

            label = _label_for(source if source.is_dir() else source.parent, candidate, args.layout, default_label)
            if label in {"malicious", "suspicious"} and not args.confirm_malware:
                print("refusing to stage a non-clean sample without --confirm-malware", file=sys.stderr)
                return 2

            destination = temp / f"{sha256}.exe"
            _safe_copy(candidate, destination)
            seen.add(sha256)
            samples.append(
                {
                    "path": destination.name,
                    "label": label,
                    "family": args.family,
                    "notes": args.notes,
                    "techniques": techniques,
                    "sha256": sha256,
                    "provenance": str(candidate),
                }
            )

        manifest = {
            "version": 1,
            "description": "Operator-provided real samples for isolated static evaluation.",
            "samples": samples,
            "skipped": [{"path": path, "reason": reason} for path, reason in skipped],
        }
        (temp / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        os.replace(temp, final)
        final.chmod(0o700)
        print(f"staged {len(samples)} sample(s) into {final}")
        print(f"skipped {len(skipped)} file(s); manifest: {final / 'manifest.json'}")
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        if temp is not None and temp.exists():
            shutil.rmtree(temp, ignore_errors=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
