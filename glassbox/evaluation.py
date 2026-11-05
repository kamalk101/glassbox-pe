"""Labelled-corpus evaluation for the static triage path.

This is deliberately small and dependency-free. The corpus manifest is a JSON
list of samples with an expected label and optional ATT&CK techniques. The
metrics are useful for comparing rule changes, not for claiming real-world
malware-detection performance.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analyzer import analyze_static
from .ingest import ingest

ACTUAL_LABELS = ("clean", "suspicious", "malicious")
POSITIVE_LABELS = {"suspicious", "malicious"}
ALL_LABELS = ACTUAL_LABELS + ("inconclusive",)


def load_manifest(corpus: str | Path) -> tuple[Path, Path, list[dict[str, Any]]]:
    path = Path(corpus).expanduser()
    if path.is_dir():
        manifest_path = path / "manifest.json"
        base = path
    else:
        manifest_path = path
        base = path.parent

    if not manifest_path.is_file():
        raise FileNotFoundError(f"corpus manifest not found: {manifest_path}")

    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid corpus manifest: {exc}") from exc

    entries = raw.get("samples") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ValueError("corpus manifest must be a list or an object with a 'samples' list")

    samples: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"manifest entry {index} is not an object")
        relative = entry.get("path")
        if not relative:
            raise ValueError(f"manifest entry {index} is missing 'path'")
        label = str(entry.get("label", entry.get("expected_label", ""))).lower()
        if label not in ACTUAL_LABELS:
            raise ValueError(
                f"manifest entry {index} has label {label!r}; expected one of {', '.join(ACTUAL_LABELS)}"
            )
        techniques = entry.get("techniques") or []
        samples.append(
            {
                "path": str(relative),
                "label": label,
                "techniques": sorted({str(technique).upper() for technique in techniques}),
                "family": entry.get("family"),
                "notes": entry.get("notes"),
            }
        )
    return base, manifest_path, samples


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _prf(tp: int, fp: int, fn: int) -> dict[str, float]:
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    return {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}


def _average_precision(actual: list[bool], scores: list[float]) -> float | None:
    positives = sum(1 for value in actual if value)
    negatives = len(actual) - positives
    if not positives or not negatives:
        return None

    ranked = sorted(zip(scores, actual), key=lambda pair: pair[0], reverse=True)
    true_positive = 0
    false_positive = 0
    previous_recall = 0.0
    average_precision = 0.0
    for _score, is_positive in ranked:
        if is_positive:
            true_positive += 1
        else:
            false_positive += 1
        recall = true_positive / positives
        precision = true_positive / (true_positive + false_positive)
        average_precision += (recall - previous_recall) * precision
        previous_recall = recall
    return round(average_precision, 4)


def _metrics(samples: list[dict[str, Any]]) -> dict[str, Any]:
    evaluated = len(samples)
    correct = sum(1 for sample in samples if sample["predicted"] == sample["actual"])
    confusion = {
        actual: {predicted: 0 for predicted in ALL_LABELS}
        for actual in ACTUAL_LABELS
    }
    for sample in samples:
        actual = sample["actual"]
        predicted = sample["predicted"]
        if actual in confusion and predicted in ALL_LABELS:
            confusion[actual][predicted] += 1

    per_class: dict[str, dict[str, Any]] = {}
    f1_values: list[float] = []
    for label in ACTUAL_LABELS:
        tp = sum(1 for sample in samples if sample["actual"] == label and sample["predicted"] == label)
        fp = sum(1 for sample in samples if sample["actual"] != label and sample["predicted"] == label)
        fn = sum(1 for sample in samples if sample["actual"] == label and sample["predicted"] != label)
        metrics = _prf(tp, fp, fn)
        metrics["support"] = sum(1 for sample in samples if sample["actual"] == label)
        per_class[label] = metrics
        f1_values.append(metrics["f1"])

    binary_tp = sum(
        1
        for sample in samples
        if sample["actual"] in POSITIVE_LABELS and sample["predicted"] in POSITIVE_LABELS
    )
    binary_fp = sum(
        1
        for sample in samples
        if sample["actual"] not in POSITIVE_LABELS and sample["predicted"] in POSITIVE_LABELS
    )
    binary_tn = sum(
        1
        for sample in samples
        if sample["actual"] not in POSITIVE_LABELS and sample["predicted"] not in POSITIVE_LABELS
    )
    binary_fn = sum(
        1
        for sample in samples
        if sample["actual"] in POSITIVE_LABELS and sample["predicted"] not in POSITIVE_LABELS
    )
    binary = _prf(binary_tp, binary_fp, binary_fn)
    binary.update(
        {
            "tp": binary_tp,
            "fp": binary_fp,
            "tn": binary_tn,
            "fn": binary_fn,
            "accuracy": round(_safe_div(binary_tp + binary_tn, evaluated), 4),
            "pr_auc": _average_precision(
                [sample["actual"] in POSITIVE_LABELS for sample in samples],
                [float(sample["score"]) / 100.0 for sample in samples],
            ),
        }
    )

    expected_total = 0
    matched_total = 0
    technique_stats: dict[str, dict[str, Any]] = {}
    for sample in samples:
        for technique in sample["expected_techniques"]:
            expected_total += 1
            row = technique_stats.setdefault(technique, {"expected": 0, "detected": 0, "recall": 0.0})
            row["expected"] += 1
            if technique in sample["matched_techniques"]:
                matched_total += 1
                row["detected"] += 1
    for row in technique_stats.values():
        row["recall"] = round(_safe_div(row["detected"], row["expected"]), 4)

    return {
        "samples": evaluated,
        "accuracy": round(_safe_div(correct, evaluated), 4),
        "binary": binary,
        "confusion": confusion,
        "per_class": per_class,
        "macro_f1": round(sum(f1_values) / len(f1_values), 4) if f1_values else 0.0,
        "techniques": {
            "expected": expected_total,
            "matched": matched_total,
            "recall": round(_safe_div(matched_total, expected_total), 4),
            "per_technique": dict(sorted(technique_stats.items())),
        },
    }


def evaluate_corpus(corpus: str | Path) -> dict[str, Any]:
    base, manifest_path, entries = load_manifest(corpus)
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    for entry in entries:
        sample_path = Path(entry["path"])
        if not sample_path.is_absolute():
            sample_path = base / sample_path
        sample_path = sample_path.expanduser().resolve()

        if not sample_path.is_file():
            errors.append({"path": str(sample_path), "error": "file not found"})
            continue

        try:
            case = analyze_static(ingest(sample_path))
        except Exception as exc:  # pragma: no cover - defensive around third-party parsing
            errors.append({"path": str(sample_path), "error": str(exc)})
            continue

        verdict = case.verdict
        predicted = verdict.label.value if verdict else "inconclusive"
        detected = set(case.techniques())
        expected = set(entry["techniques"])
        matched = sorted(expected & detected)
        results.append(
            {
                "path": entry["path"],
                "family": entry.get("family"),
                "notes": entry.get("notes"),
                "actual": entry["label"],
                "predicted": predicted,
                "correct": predicted == entry["label"],
                "score": verdict.score if verdict else 0,
                "confidence": verdict.confidence if verdict else 0.0,
                "sneakiness": verdict.sneakiness if verdict else 0,
                "expected_techniques": sorted(expected),
                "detected_techniques": sorted(detected),
                "matched_techniques": matched,
                "missing_techniques": sorted(expected - detected),
                "unexpected_techniques": sorted(detected - expected),
                "findings": [finding.rule_id for finding in case.findings],
            }
        )

    return {
        "corpus": str(base),
        "manifest": str(manifest_path),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "metrics": _metrics(results),
        "samples": results,
        "errors": errors,
    }
