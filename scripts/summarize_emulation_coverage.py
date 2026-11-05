#!/usr/bin/env python3
"""Summarise a GlassBox emulation evaluation JSON report.

Does not emulate anything; it only reads the output of ``glassbox eval --json``.
It reports sample coverage, category/event counts, behaviour counts, and a
per-sample table so missing network/registry coverage is visible rather than
hidden by aggregate scores.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

COVERAGE_COLUMNS = ("process", "file", "network", "registry", "pe", "other")


def _events(report: dict, name: str) -> Counter:
    return Counter(report.get("emulation", {}).get(name, {}))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", help="evaluation JSON written by glassbox eval --json")
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args()

    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    if report.get("mode") != "emulation":
        print("error: this report is not an emulation-mode evaluation")
        return 2

    summary = report.get("emulation") or {}
    samples = report.get("samples") or []

    category_events = _events(report, "category_events")
    categories = _events(report, "categories")
    behaviours = _events(report, "behaviours")

    rows = []
    for sample in samples:
        emulation = sample.get("emulation") or {}
        categories_list = ", ".join(emulation.get("categories") or []) or "-"
        behaviours_list = ", ".join(
            f"{key}:{value}" for key, value in sorted((emulation.get("behaviours") or {}).items())
        ) or "-"
        rows.append(
            {
                "file": sample.get("path", "?"),
                "ran": "yes" if emulation.get("ran") else "no",
                "apis": str(emulation.get("api_calls", 0)),
                "categories": categories_list,
                "behaviours": behaviours_list,
            }
        )

    if args.markdown:
        print("# Emulation coverage summary")
        print()
        print(f"- corpus: `{report.get('corpus')}`")
        print(f"- samples: {len(samples)}; ran: {summary.get('ran', 0)}; failed: {summary.get('failed', 0)}")
        print(f"- API calls: {summary.get('api_calls', 0)}")
        print(f"- samples with API events: {summary.get('samples_with_api_events', 0)}")
        print()
        print("## Samples with at least one event per category")
        print()
        print("| category | samples |")
        print("|---|---:|")
        for category in COVERAGE_COLUMNS:
            print(f"| {category} | {categories.get(category, 0)} |")
        print()
        print("## Event counts")
        print()
        print("| category | events |")
        print("|---|---:|")
        for category in COVERAGE_COLUMNS:
            print(f"| {category} | {category_events.get(category, 0)} |")
        print()
        print("## Attempted behaviour counts")
        print()
        if behaviours:
            for behaviour, count in sorted(behaviours.items()):
                print(f"- `{behaviour}`: {count}")
        else:
            print("- none")
        print()
        print("## Per-sample")
        print()
        print("| sample | ran | APIs | categories | behaviours |")
        print("|---|---|---:|---|---|")
        for row in rows:
            print(f"| `{row['file']}` | {row['ran']} | {row['apis']} | {row['categories']} | {row['behaviours']} |")
    else:
        print(f"corpus                 : {report.get('corpus')}")
        print(f"samples               : {len(samples)}")
        print(f"ran / failed          : {summary.get('ran', 0)} / {summary.get('failed', 0)}")
        print(f"API calls             : {summary.get('api_calls', 0)}")
        print(f"samples with API events: {summary.get('samples_with_api_events', 0)}")
        print("categories             :", ", ".join(f"{k}:{categories[k]}" for k in sorted(categories)) or "-")
        print("event counts           :", ", ".join(f"{k}:{category_events[k]}" for k in sorted(category_events)) or "-")
        print("behaviour counts      :", ", ".join(f"{k}:{v}" for k, v in sorted(behaviours.items())) or "-")
        print()
        for row in rows:
            print(f"{row['ran']:3} {row['apis']:4} {row['file']}: {row['categories']} | {row['behaviours']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
