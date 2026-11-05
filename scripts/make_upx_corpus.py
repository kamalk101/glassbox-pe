#!/usr/bin/env python3
"""Create a small UPX-packed benign corpus for the unpack ablation.

Example:
    python scripts/make_upx_corpus.py --source /path/to/7zr.exe

The source must be a benign, unpacked x86/x86-64 PE. The output is ignored by
git. This script never executes the sample; it only invokes UPX.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from glassbox.unpack.upx import find_upx


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="benign unpacked PE to pack")
    parser.add_argument(
        "--output",
        default=str(ROOT / "corpus" / "upx-benign"),
        help="output directory (default: corpus/upx-benign)",
    )
    parser.add_argument("--name", default=None, help="name for the packed sample")
    parser.add_argument("--clean", action="store_true")
    args = parser.parse_args()

    source = Path(args.source).expanduser().resolve()
    if not source.is_file():
        print(f"error: source not found: {source}", file=sys.stderr)
        return 1
    upx = find_upx()
    if upx is None:
        print("error: UPX not found; run scripts/fetch_upx.sh or set GLASSBOX_UPX", file=sys.stderr)
        return 1

    output = Path(args.output).expanduser().resolve()
    if args.clean and output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    name = args.name or f"{source.stem}-packed.exe"
    target = output / name
    if target.exists():
        target.unlink()
    completed = subprocess.run(
        [upx, "-q", "-9", "-o", str(target), str(source)],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0 or not target.is_file():
        print(f"error: UPX failed: {completed.stderr.strip()}", file=sys.stderr)
        return 1

    manifest = {
        "version": 1,
        "description": "Benign UPX-packed sample for unpack-ablation testing.",
        "samples": [
            {
                "path": name,
                "label": "clean",
                "family": "upx-benign",
                "notes": f"packed from trusted source: {source}",
                "techniques": [],
            }
        ],
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"wrote {target}")
    print(f"manifest: {output / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
