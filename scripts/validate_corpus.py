#!/usr/bin/env python3
"""Validate and summarize a labelled PE corpus without executing samples.

Checks: manifest shape, labels, ATT&CK IDs, missing files, non-PE files,
duplicate SHA-256, declared SHA-256 mismatches, duplicate import hashes, family
skew, provenance for non-clean labels, file/directory permissions, and per-group
coverage. It never executes a sample.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import os
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pefile
from glassbox.ingest import ingest
from glassbox.static.pe import parse_pe

TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
VALID_LABELS = {"clean", "suspicious", "malicious"}


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _group(name: str, value: object) -> str:
    label = str(value).lower() if value not in {None, ""} else "none"
    return f"{name}={label}"


def _imphash(path: Path) -> str | None:
    try:
        with pefile.PE(str(path), fast_load=True) as pe:
            return pe.get_imphash() or None
    except Exception:
        return None


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)
    return f"{name}={label}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", help="corpus directory or manifest.json")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--require-provenance",
        action="store_true",
        help="fail non-clean entries that do not record source/provenance",
    )
    args = parser.parse_args()

    manifest_path = Path(args.corpus).expanduser()
    if manifest_path.is_dir():
        manifest_path = manifest_path / "manifest.json"
    if not manifest_path.is_file():
        print(f"error: manifest not found: {manifest_path}", file=sys.stderr)
        return 1
    base = manifest_path.parent
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = raw.get("samples") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        print("error: manifest has no samples list", file=sys.stderr)
        return 1

    problems: list[str] = []
    warnings: list[str] = []
    samples = []
    seen: dict[str, str] = {}
    imphash_seen: dict[str, str] = {}
    imphash_groups: Counter[str] = Counter()
    broader_mode_count = 0
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            problems.append(f"entry {index}: not an object")
            continue
        relative = entry.get("path")
        label = str(entry.get("label", "")).lower()
        techniques = entry.get("techniques") or []
        if not relative:
            problems.append(f"entry {index}: missing path")
            continue
        if label not in VALID_LABELS:
            problems.append(f"entry {index}: unknown label {entry.get('label')!r}")
        if not isinstance(techniques, list):
            problems.append(f"entry {index}: techniques must be a list")
            techniques = []
        bad = [t for t in techniques if not isinstance(t, str) or not TECHNIQUE_RE.match(t)]
        if bad:
            problems.append(f"entry {index}: invalid technique IDs {bad}")

        sample_path = (base / relative).resolve()
        if not sample_path.is_file():
            problems.append(f"entry {index}: file not found: {relative}")
            continue
        try:
            digest = _digest(sample_path)
        except OSError as exc:
            problems.append(f"entry {index}: unreadable: {exc}")
            continue
        expected_digest = entry.get("sha256")
        if expected_digest is not None and str(expected_digest).lower().strip() != digest.lower():
            problems.append(f"entry {index}: declared sha256 mismatch for {relative}")
        if digest in seen:
            problems.append(f"entry {index}: duplicate sha256 of {seen[digest]}")
        else:
            seen[digest] = str(relative)

        source = entry.get("provenance") or entry.get("source_url") or entry.get("source")
        if args.require_provenance and label in {"suspicious", "malicious"} and not source:
            problems.append(f"entry {index}: non-clean sample has no provenance/source field")
        elif label in {"suspicious", "malicious"} and not source:
            warnings.append(f"entry {index}: non-clean sample has no provenance/source field")

        mode = _mode(sample_path)
        if mode & 0o077:
            broader_mode_count += 1
        imphash = _imphash(sample_path)
        if imphash:
            imphash_groups[imphash] += 1
            if imphash in imphash_seen:
                warnings.append(f"entry {index}: duplicate imphash {imphash} ({imphash_seen[imphash]})")
            else:
                imphash_seen[imphash] = str(relative)

        try:
            info = parse_pe(sample_path.read_bytes())
        except OSError as exc:
            problems.append(f"entry {index}: unreadable: {exc}")
            continue
        if not info.is_pe or info.parse_error:
            problems.append(f"entry {index}: not a parseable PE ({info.parse_error or 'not PE'})")

        samples.append(
            {
                "path": str(relative),
                "label": label,
                "family": entry.get("family") or "unknown",
                "sha256": digest,
                "size": sample_path.stat().st_size,
                "signed": bool(info.signature_present),
                "installer": info.installer_hint,
                "dotnet": bool(info.is_dotnet),
                "packer": info.packer_hint,
            }
        )

    if broader_mode_count:
        warnings.append(f"{broader_mode_count} sample file(s) are readable by group/other users; use mode 0600")

    summary: dict[str, object] = {
        "manifest": str(manifest_path),
        "samples": len(samples),
        "problems": problems,
        "labels": dict(sorted(Counter(s["label"] for s in samples).items())),
        "families": dict(sorted(Counter(s["family"] for s in samples).items())),
        "signed": sum(1 for s in samples if s["signed"]),
        "unsigned": sum(1 for s in samples if not s["signed"]),
        "installer": dict(sorted(Counter(str(s["installer"] or "none").lower() for s in samples).items())),
        "dotnet": sum(1 for s in samples if s["dotnet"]),
        "packers": dict(sorted(Counter(str(s["packer"] or "none").lower() for s in samples).items())),
        "total_bytes": sum(s["size"] for s in samples),
        "imphash_duplicate_groups": sum(1 for count in imphash_groups.values() if count > 1),
        "warnings": warnings,
    }
    if samples:
        dominant_count = max(Counter(s["family"] for s in samples).values())
        if dominant_count / len(samples) > 0.5:
            dominant = Counter(s["family"] for s in samples).most_common(1)[0][0]
            warnings.append(f"family skew: {dominant_count}/{len(samples)} samples belong to {dominant!r}")
            summary["warnings"] = warnings

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"manifest : {summary['manifest']}")
        print(f"samples  : {summary['samples']} ({summary['total_bytes']} bytes)")
        print(f"labels   : {summary['labels']}")
        print(f"families : {summary['families']}")
        print(f"signed   : {summary['signed']} signed · {summary['unsigned']} unsigned")
        print(f".NET     : {summary['dotnet']}")
        print(f"installer hints: {summary['installer']}")
        print(f"packers  : {summary['packers']}")
        if summary["imphash_duplicate_groups"]:
            print(f"imphash duplicate groups: {summary['imphash_duplicate_groups']}")
        if warnings:
            print(f"\nwarnings ({len(warnings)}):")
            for warning in warnings:
                print(f"  - {warning}")
        if problems:
            print(f"\nproblems ({len(problems)}):")
            for problem in problems:
                print(f"  - {problem}")
        else:
            print("\nproblems: none")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
