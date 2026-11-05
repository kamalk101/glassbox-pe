"""Labelled-corpus evaluation for the static triage path.

This is deliberately small and dependency-free. The corpus manifest is a JSON
list of samples with an expected label and optional ATT&CK techniques. The
metrics are useful for comparing rule changes, not for claiming real-world
malware-detection performance.
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal, Sequence

from . import score
from .analyzer import analyze_static
from .emu import EmulationOutcome, apply_emulation, run_emulation
from .ingest import ingest
from .schema import Source
from .static.packer import PackerInfo
from .unpack import UnpackResult, unpack_sample

ACTUAL_LABELS = ("clean", "suspicious", "malicious")
POSITIVE_LABELS = {"suspicious", "malicious"}
ALL_LABELS = ACTUAL_LABELS + ("inconclusive",)
MODES = ("static", "unpack", "emulation")
EvalMode = Literal["static", "unpack", "emulation"]


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


def _recall_at_fpr(
    actual: list[bool],
    scores: list[float],
    max_fpr: float = 0.01,
) -> dict[str, Any] | None:
    """Highest recall whose false-positive rate is at most ``max_fpr``.

    Thresholds are the observed scores. A threshold above every score is also
    considered so benign-only or zero-recall corpora get a defined answer.
    """
    positives = sum(1 for value in actual if value)
    negatives = len(actual) - positives
    if not positives or not negatives:
        return None

    candidates = sorted(set(scores), reverse=True)
    candidates.insert(0, max(scores) + 1e-9)
    best: dict[str, Any] | None = None
    for threshold in candidates:
        tp = sum(1 for score_value, positive in zip(scores, actual) if positive and score_value >= threshold)
        fp = sum(1 for score_value, positive in zip(scores, actual) if not positive and score_value >= threshold)
        fpr = fp / negatives
        if fpr > max_fpr:
            continue
        recall = tp / positives
        candidate = {
            "threshold": round(threshold, 4),
            "recall": round(recall, 4),
            "false_positive_rate": round(fpr, 4),
        }
        if best is None or candidate["recall"] > best["recall"]:
            best = candidate
    return best


def _calibration(actual: list[bool], confidences: list[float], bins: int = 5) -> dict[str, Any]:
    if not actual:
        return {"brier": None, "ece": None, "bins": []}
    brier = sum((confidence - float(positive)) ** 2 for confidence, positive in zip(confidences, actual)) / len(actual)

    grouped: list[dict[str, Any]] = []
    ece = 0.0
    for index in range(bins):
        low = index / bins
        high = (index + 1) / bins
        members = [
            (confidence, positive)
            for confidence, positive in zip(confidences, actual)
            if low <= confidence < high or (index == bins - 1 and confidence == 1.0)
        ]
        if not members:
            grouped.append(
                {
                    "range": f"{low:.1f}-{high:.1f}",
                    "count": 0,
                    "mean_confidence": None,
                    "positive_rate": None,
                }
            )
            continue
        mean_confidence = sum(confidence for confidence, _ in members) / len(members)
        positive_rate = sum(1 for _, positive in members if positive) / len(members)
        ece += (len(members) / len(actual)) * abs(mean_confidence - positive_rate)
        grouped.append(
            {
                "range": f"{low:.1f}-{high:.1f}",
                "count": len(members),
                "mean_confidence": round(mean_confidence, 4),
                "positive_rate": round(positive_rate, 4),
            }
        )
    return {"brier": round(brier, 4), "ece": round(ece, 4), "bins": grouped}


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
    binary_actual = [sample["actual"] in POSITIVE_LABELS for sample in samples]
    binary_scores = [float(sample["score"]) / 100.0 for sample in samples]
    confidences = [float(sample.get("confidence", 0.0)) for sample in samples]

    binary = _prf(binary_tp, binary_fp, binary_fn)
    binary.update(
        {
            "tp": binary_tp,
            "fp": binary_fp,
            "tn": binary_tn,
            "fn": binary_fn,
            "accuracy": round(_safe_div(binary_tp + binary_tn, evaluated), 4),
            "pr_auc": _average_precision(binary_actual, binary_scores),
            "recall_at_fpr_1pct": _recall_at_fpr(binary_actual, binary_scores, max_fpr=0.01),
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
        "calibration": _calibration(binary_actual, confidences),
    }


def evaluate_corpus(
    corpus: str | Path,
    *,
    mode: EvalMode = "static",
    timeout: int = 30,
    limit: int | None = None,
    yara_rules: Sequence[str | Path] | None = None,
    emulation_runner: Callable[..., EmulationOutcome] | None = None,
    unpack_runner: Callable[..., UnpackResult] | None = None,
) -> dict[str, Any]:
    if mode not in MODES:
        raise ValueError(f"unknown evaluation mode {mode!r}; expected one of {', '.join(MODES)}")

    base, manifest_path, entries = load_manifest(corpus)
    if limit is not None:
        entries = entries[: max(0, limit)]
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    yara_summary = {"available": False, "rules": 0, "samples_with_matches": 0, "matches": 0}
    unpack_summary: dict[str, Any] = {"attempted": 0, "unpacked": 0, "unsupported": 0, "failed": 0, "improved": 0}
    emulation_summary: dict[str, Any] = {
        "ran": 0,
        "failed": 0,
        "api_calls": 0,
        "samples_with_api_events": 0,
        "categories": {},
    }

    for entry in entries:
        sample_path = Path(entry["path"])
        if not sample_path.is_absolute():
            sample_path = base / sample_path
        sample_path = sample_path.expanduser().resolve()

        if not sample_path.is_file():
            errors.append({"path": str(sample_path), "error": "file not found"})
            continue

        try:
            case = analyze_static(ingest(sample_path), yara_rules=yara_rules)
        except Exception as exc:  # pragma: no cover - defensive around third-party parsing
            errors.append({"path": str(sample_path), "error": str(exc)})
            continue

        case_yara = case.artifacts.get("yara") or {}
        if case_yara.get("available"):
            yara_summary["available"] = True
            yara_summary["rules"] = max(yara_summary["rules"], int(case_yara.get("rules") or 0))
        matches = case_yara.get("matches") or []
        if matches:
            yara_summary["samples_with_matches"] += 1
            yara_summary["matches"] += len(matches)

        emulation_info: dict[str, Any] | None = None
        unpack_info: dict[str, Any] | None = None
        detected = set(case.techniques())
        findings = [finding.rule_id for finding in case.findings]
        static_score = case.verdict.score if case.verdict else 0
        final_score = static_score

        if mode == "emulation":
            runner = emulation_runner or run_emulation
            with tempfile.TemporaryDirectory(prefix="glassbox-eval-emu-") as temp_dir:
                workdir = Path(temp_dir) / case.case_id
                try:
                    outcome = runner(sample_path, timeout=timeout, workdir=workdir)
                except Exception as exc:  # pragma: no cover - subprocess/environment failure
                    outcome = EmulationOutcome(ran=False, error=str(exc))
                apply_emulation(case, outcome)
                emu_artifacts = case.artifacts.get("emulation") or {}
                categories = sorted(
                    {event.category.value for event in case.events if event.source is Source.EMULATION}
                )
                emulation_info = {
                    "ran": bool(outcome.ran),
                    "api_calls": int(emu_artifacts.get("api_calls") or 0),
                    "behaviours": emu_artifacts.get("behaviours") or {},
                    "categories": categories,
                    "dropped_files": len(outcome.dropped_files),
                    "dynamic_segments": int(emu_artifacts.get("dynamic_segments") or 0),
                    "error": outcome.error,
                }
                if outcome.ran:
                    emulation_summary["ran"] += 1
                    emulation_summary["api_calls"] += emulation_info["api_calls"]
                    if emulation_info["api_calls"]:
                        emulation_summary["samples_with_api_events"] += 1
                    for category in categories:
                        emulation_summary["categories"][category] = (
                            emulation_summary["categories"].get(category, 0) + 1
                        )
                else:
                    emulation_summary["failed"] += 1
                    if outcome.error:
                        errors.append({"path": entry["path"], "error": f"emulation: {outcome.error}"})
                detected = set(case.techniques())
                findings = [finding.rule_id for finding in case.findings]
                final_score = case.verdict.score if case.verdict else final_score

        elif mode == "unpack":
            runner = unpack_runner or unpack_sample
            with tempfile.TemporaryDirectory(prefix="glassbox-eval-unpack-") as temp_dir:
                output = Path(temp_dir) / f"{sample_path.stem}.unpacked.exe"
                try:
                    unpack_result = runner(sample_path, output)
                except Exception as exc:  # pragma: no cover - tool/environment failure
                    unpack_result = UnpackResult(
                        status="failed",
                        success=False,
                        packer=PackerInfo(),
                        error=str(exc),
                    )
                unpack_info = {
                    "status": unpack_result.status,
                    "method": unpack_result.method,
                    "packer": unpack_result.packer.name if unpack_result.packer else None,
                    "error": unpack_result.error,
                    "child_score": None,
                    "child_findings": [],
                }
                if unpack_result.status != "not_packed":
                    unpack_summary["attempted"] += 1
                if unpack_result.success and unpack_result.output_path:
                    unpack_summary["unpacked"] += 1
                    try:
                        child = analyze_static(ingest(Path(unpack_result.output_path)), yara_rules=yara_rules)
                    except Exception as exc:  # pragma: no cover - defensive
                        unpack_info["error"] = f"child analysis failed: {exc}"
                    else:
                        child_score = child.verdict.score if child.verdict else 0
                        unpack_info["child_score"] = child_score
                        unpack_info["child_findings"] = [finding.rule_id for finding in child.findings]
                        detected |= set(child.techniques())
                        findings.extend(f"child:{finding.rule_id}" for finding in child.findings)
                        # The unpacked image is the more faithful view. A packed
                        # stub's byte-level suspicion should not override a clean
                        # child, and hidden child capabilities should surface.
                        if child_score != final_score:
                            unpack_summary["improved"] += 1
                        final_score = child_score
                elif unpack_result.status == "unsupported":
                    unpack_summary["unsupported"] += 1
                elif unpack_result.status not in {"not_packed", "not_pe"}:
                    unpack_summary["failed"] += 1

        if case.verdict and case.verdict.label.value == "inconclusive":
            predicted = "inconclusive"
        else:
            predicted = score.label_for_score(final_score).value
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
                "score": final_score,
                "static_score": static_score,
                "confidence": case.verdict.confidence if case.verdict else 0.0,
                "sneakiness": case.verdict.sneakiness if case.verdict else 0,
                "expected_techniques": sorted(expected),
                "detected_techniques": sorted(detected),
                "matched_techniques": matched,
                "missing_techniques": sorted(expected - detected),
                "unexpected_techniques": sorted(detected - expected),
                "findings": findings,
                "yara_matches": [match.get("rule") for match in matches],
                "emulation": emulation_info,
                "unpack": unpack_info,
            }
        )

    payload = {
        "corpus": str(base),
        "manifest": str(manifest_path),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "mode": mode,
        "limit": limit,
        "yara": yara_summary,
        "metrics": _metrics(results),
        "samples": results,
        "errors": errors,
    }
    if mode == "emulation":
        payload["emulation"] = emulation_summary
    if mode == "unpack":
        payload["unpack"] = unpack_summary
    return payload
