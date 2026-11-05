#!/usr/bin/env python3
"""Combine a real benign corpus with the synthetic malicious corpus.

The resulting manifest references files in place, so it is cheap and does not
duplicate samples. This is the closest local approximation to the planned
mixed evaluation set: real benign binaries plus synthetic malicious fixtures.
It is not a real-malware benchmark.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(directory: Path) -> list[dict]:
    manifest = directory / "manifest.json"
    if not manifest.is_file():
        raise FileNotFoundError(f"manifest not found: {manifest}")
    return json.loads(manifest.read_text(encoding="utf-8"))["samples"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benign", default=str(ROOT / "corpus" / "local-benign"))
    parser.add_argument("--malicious", default=str(ROOT / "corpus" / "demo"))
    parser.add_argument("--output", default=str(ROOT / "corpus" / "mixed"))
    args = parser.parse_args()

    benign_dir = Path(args.benign).expanduser().resolve()
    malicious_dir = Path(args.malicious).expanduser().resolve()
    output = Path(args.output).expanduser().resolve()

    samples: list[dict] = []
    for sample in _load(benign_dir):
        samples.append(
            {
                **sample,
                "_source": (benign_dir / sample["path"]).resolve(),
            }
        )
    for sample in _load(malicious_dir):
        if sample.get("label") not in {"suspicious", "malicious"}:
            continue
        samples.append(
            {
                **sample,
                "_source": (malicious_dir / sample["path"]).resolve(),
            }
        )

    output.mkdir(parents=True, exist_ok=True)

    def rel(path: Path) -> str:
        return Path(os.path.relpath(path.resolve(), output)).as_posix()

    for sample in samples:
        source = Path(sample.pop("_source"))
        sample["path"] = rel(source)
    manifest = {
        "version": 1,
        "description": (
            "Real local benign PEs plus synthetic malicious fixtures. "
            "Not a real-malware benchmark."
        ),
        "samples": samples,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"wrote {len(samples)} samples to {output / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
