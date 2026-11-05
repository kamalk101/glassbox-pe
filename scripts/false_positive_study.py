#!/usr/bin/env python3
"""Slice a labelled corpus to expose false-positive and false-negative groups.

This runs the static path only and does not execute samples. It is intended for
measurable false-positive studies on corpora that contain benign installers,
signed binaries, .NET assemblies, and packers.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from glassbox.analyzer import analyze_static
from glassbox.evaluation import POSITIVE_LABELS, load_manifest
from glassbox.ingest import ingest


def _is_positive(label: str) -> bool:
    return label in POSITIVE_LABELS


def _groups(case, label: str, family: str) -> dict[str, str]:
    artifacts = case.artifacts or {}
    pe = artifacts.get("pe") or {}
    packer = artifacts.get("packer") or {}
    return {
        "label": label,
        "family": str(family or "unknown").lower(),
        "signed": "signed" if pe.get("signed") else "unsigned",
        "installer": str(pe.get("installer") or "none").lower(),
        "dotnet": "dotnet" if pe.get("dotnet") else "native",
        "packer": str(packer.get("name") or pe.get("packer") or "none").lower(),
    }


def _rate(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "n/a"
    return f"{numerator}/{denominator} ({numerator / denominator:.0%})"


def _summarize(samples: list[dict], key: str) -> dict:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for sample in samples:
        grouped[sample["groups"][key]].append(sample)
    rows = []
    for value in sorted(grouped):
        group = grouped[value]
        clean = [sample for sample in group if sample["actual"] == "clean"]
        positives = [sample for sample in group if _is_positive(sample["actual"])]
        false_positives = [sample for sample in clean if sample["predicted"] != "clean"]
        detected = [sample for sample in positives if sample["predicted"] != "clean"]
        rows.append(
            {
                "value": value,
                "samples": len(group),
                "false_positives": len(false_positives),
                "clean_samples": len(clean),
                "detected": len(detected),
                "positive_samples": len(positives),
                "false_positive_samples": [sample["path"] for sample in false_positives],
                "missed_positives": [
                    sample["path"] for sample in positives if sample["predicted"] == "clean"
                ],
            }
        )
    return {"key": key, "rows": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", help="corpus directory or manifest.json")
    parser.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    args = parser.parse_args()

    base, manifest, entries = load_manifest(args.corpus)
    samples = []
    errors = []
    for entry in entries:
        path = Path(entry["path"])
        if not path.is_absolute():
            path = base / path
        try:
            case = analyze_static(ingest(path))
        except Exception as exc:
            errors.append({"path": str(path), "error": str(exc)})
            continue
        verdict = case.verdict
        predicted = verdict.label.value if verdict else "inconclusive"
        samples.append(
            {
                "path": str(Path(entry["path"])),
                "actual": entry["label"],
                "predicted": predicted,
                "score": verdict.score if verdict else 0,
                "findings": [finding.rule_id for finding in case.findings],
                "groups": _groups(case, entry["label"], entry.get("family")),
            }
        )

    report = {
        "manifest": str(manifest),
        "samples": len(samples),
        "errors": errors,
        "slices": [_summarize(samples, key) for key in ("signed", "installer", "dotnet", "packer", "family")],
    }

    if args.format == "json":
        print(json.dumps(report, indent=2))
        return 0

    lines = [
        f"corpus: {report['manifest']}",
        f"samples analyzed: {report['samples']}",
        "",
    ]
    markdown = args.format == "markdown"
    if markdown:
        lines.extend([
            "# False-positive study",
            "",
            "Static analysis only; no samples were executed.",
            "",
        ])
    for slice_result in report["slices"]:
        title = slice_result["key"]
        if markdown:
            lines.extend([f"## {title}", "", "| value | samples | clean FP | positive detected |", "|---|---:|---:|---:|"])
        else:
            lines.append(title)
        for row in slice_result["rows"]:
            fp = _rate(row["false_positives"], row["clean_samples"])
            detected = _rate(row["detected"], row["positive_samples"])
            if markdown:
                lines.append(f"| {row['value']} | {row['samples']} | {fp} | {detected} |")
            else:
                lines.append(
                    f"  {row['value']:24} n={row['samples']:3}  clean FP {fp:14}  positive detected {detected}"
                )
            if row["false_positive_samples"]:
                lines.append("    false positives: " + ", ".join(row["false_positive_samples"]))
            if row["missed_positives"]:
                lines.append("    missed positives: " + ", ".join(row["missed_positives"]))
        if markdown:
            lines.append("")
        else:
            lines.append("")
    if errors:
        lines.append(f"errors: {len(errors)}")
        for error in errors:
            lines.append(f"  - {error['path']}: {error['error']}")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
