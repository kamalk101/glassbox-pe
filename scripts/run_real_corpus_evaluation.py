#!/usr/bin/env python3
"""Run the complete real-corpus measurement workflow offline.

This script never executes a sample. It reads PE files, validates a manifest,
runs static / UPX-unpack / optionally emulated evaluation, and writes a report
directory under the chosen output path. It fails when validation finds a real
problem (missing files, hashes, duplicate samples, or provenance requirements).

Intended invocation inside an isolated lab:

    python scripts/run_real_corpus_evaluation.py /path/to/corpus \\
        --output-dir /path/to/measurement-report \\
        --require-provenance --emulation --timeout 60
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from glassbox.evaluation import evaluate_corpus


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    path.chmod(0o600)


def _markdown(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


def _validate(corpus: Path, output_dir: Path, require_provenance: bool) -> dict:
    command = [sys.executable, str(ROOT / "scripts" / "validate_corpus.py"), str(corpus), "--json"]
    if require_provenance:
        command.append("--require-provenance")
    completed = subprocess.run(command, text=True, capture_output=True)
    try:
        validation = json.loads(completed.stdout)
    except json.JSONDecodeError:
        validation = {
            "manifest": str(corpus / "manifest.json") if corpus.is_dir() else str(corpus),
            "samples": 0,
            "problems": [f"validator output was not JSON: {completed.stderr or completed.stdout}"],
            "warnings": [],
        }
    validation["validator_return_code"] = completed.returncode
    _write_json(output_dir / "validation.json", validation)
    return validation


def _metric_summary(evaluate_result: dict) -> list[str]:
    metrics = evaluate_result["metrics"]
    binary = metrics["binary"]
    calibration = metrics.get("calibration") or {}
    lines = [
        f"- samples evaluated: {metrics['samples']}",
        f"- accuracy (3-class): {metrics['accuracy']}",
        f"- binary precision/recall/F1: {binary['precision']}/{binary['recall']}/{binary['f1']}",
        f"- PR-AUC: {binary['pr_auc']}",
        f"- recall at FPR <= 1%: {binary.get('recall_at_fpr_1pct')}",
        f"- Brier/ECE: {calibration.get('brier')}/{calibration.get('ece')}",
        f"- false positives: {binary['fp']}, false negatives: {binary['fn']}",
        f"- technique recall: {metrics['techniques']['recall']} ({metrics['techniques']['matched']}/{metrics['techniques']['expected']})",
    ]
    return lines


def _mispredictions(result: dict) -> list[dict]:
    return [sample for sample in result.get("samples", []) if not sample.get("correct")]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", help="corpus directory or manifest.json")
    parser.add_argument("--output-dir", default="", help="report directory (default: reports/real-corpus-<ts>)")
    parser.add_argument("--timeout", type=int, default=60, help="emulation timeout per sample")
    parser.add_argument("--emulation", action="store_true", help="also run Speakeasy emulation")
    parser.add_argument("--allow-missing-provenance", action="store_true")
    parser.add_argument("--limit", type=int, default=None, help="evaluate only first N samples (smoke test)")
    args = parser.parse_args()

    corpus = Path(args.corpus).expanduser().resolve()
    if corpus.is_dir():
        manifest = corpus / "manifest.json"
    else:
        manifest = corpus
    if not manifest.is_file():
        print(f"error: manifest not found: {manifest}", file=sys.stderr)
        return 2
    corpus_root = manifest.parent

    output = Path(args.output_dir).expanduser().resolve() if args.output_dir else (
        ROOT / "reports" / f"real-corpus-{dt.datetime.now().astimezone().strftime('%Y%m%d-%H%M%S')}"
    )
    if output.exists() and any(output.iterdir()):
        print(f"error: output directory exists and is not empty: {output}", file=sys.stderr)
        return 2
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o700)

    validation = _validate(corpus_root, output, not args.allow_missing_provenance)
    if validation.get("problems"):
        print("validation failed; evaluation was not run", file=sys.stderr)
        print(json.dumps(validation["problems"], indent=2), file=sys.stderr)
        return 1

    started = dt.datetime.now().astimezone()
    outputs = {}
    for mode in ("static", "unpack"):
        print(f"running {mode} evaluation...", flush=True)
        result = evaluate_corpus(corpus_root, mode=mode, timeout=args.timeout, limit=args.limit)
        outputs[mode] = result
        _write_json(output / f"evaluation-{mode}.json", result)

    if args.emulation:
        print("running emulation evaluation...", flush=True)
        outputs["emulation"] = evaluate_corpus(
            corpus_root,
            mode="emulation",
            timeout=args.timeout,
            limit=args.limit,
        )
        _write_json(output / "evaluation-emulation.json", outputs["emulation"])

    static = outputs["static"]
    unpack = outputs["unpack"]
    mispredictions = _mispredictions(static)
    calibration = static["metrics"].get("calibration") or {}
    report_lines = [
        "# Real-corpus measurement report",
        "",
        f"- generated: {started.isoformat(timespec='seconds')}",
        f"- manifest: `{manifest}`",
        f"- output: `{output}`",
        f"- samples: {static['metrics']['samples']}",
        f"- validation errors/warnings: {len(validation.get('problems', []))}/{len(validation.get('warnings', []))}",
        f"- emulation: {'enabled' if args.emulation else 'not run'}",
        "",
        "## Static metrics",
        "",
        * _metric_summary(static),
        "",
        "## Unpack ablation",
        "",
        * _metric_summary(unpack),
        "",
        f"- unpack summary: {unpack.get('unpack')}",
    ]
    if args.emulation:
        emulation = outputs["emulation"]
        report_lines.extend(
            [
                "",
                "## Emulation ablation",
                "",
                * _metric_summary(emulation),
                f"- emulation summary: {emulation.get('emulation')}",
            ]
        )
    report_lines.extend(
        [
            "",
            "## Static mispredictions",
            "",
        ]
    )
    if mispredictions:
        report_lines.append(f"- count: {len(mispredictions)}")
        for sample in mispredictions:
            findings = ", ".join(sample.get("findings") or [])
            report_lines.append(
                f"- `{sample['path']}` actual={sample['actual']} predicted={sample['predicted']} "
                f"score={sample['score']}; findings={findings}"
            )
    else:
        report_lines.append("- none")
    report_lines.extend(
        [
            "",
            "## Calibration caveat",
            "",
            f"Brier {calibration.get('brier')} and ECE {calibration.get('ece')} are engineering",
            "diagnostics. The confidence score is not a validated probability estimate.",
            "",
            "## Safety",
            "",
            "No sample was executed natively. UPX unpacking does not execute the sample.",
            "Emulation is explicit and uses Speakeasy; treat it as unsafe unless the host is an isolated lab.",
            "",
        ]
    )
    _markdown(output / "MEASUREMENT.md", "\n".join(report_lines) + "\n")
    print(f"\nreport: {output / 'MEASUREMENT.md'}")
    print("files written:", ", ".join(p.name for p in sorted(output.iterdir())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
