"""Offline case dashboard rendering."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .html_report import render_html

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
LABELS = ("clean", "suspicious", "malicious", "inconclusive")


def _day(row: dict[str, Any]) -> str:
    created = str(row.get("created_at") or "")
    return created[:10] if len(created) >= 10 else "unknown"


def build_dashboard_view(rows: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(rows, key=lambda row: row.get("created_at", ""), reverse=True)
    counts = {label: 0 for label in LABELS}
    for row in ordered:
        label = row.get("label", "inconclusive")
        counts[label if label in counts else "inconclusive"] += 1
    total = len(ordered)
    distribution = [
        {
            "label": label,
            "count": counts[label],
            "percent": (counts[label] / total * 100) if total else 0.0,
        }
        for label in LABELS
    ]
    average_score = sum(int(row.get("score") or 0) for row in ordered) / total if total else 0.0
    average_sneakiness = sum(int(row.get("sneakiness") or 0) for row in ordered) / total if total else 0.0
    report_count = sum(1 for row in ordered if row.get("has_report"))
    emulation_count = sum(1 for row in ordered if row.get("emulation_ran"))

    by_day: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        by_day[_day(row)][(row.get("label") or "inconclusive")] += 1
    activity_by_day = [
        {
            "day": day,
            "clean": by_day[day]["clean"],
            "suspicious": by_day[day]["suspicious"],
            "malicious": by_day[day]["malicious"],
            "inconclusive": by_day[day]["inconclusive"],
        }
        for day in sorted(by_day)
    ]
    unpack_counts = Counter(str(row.get("unpack_status") or "none") for row in rows)
    timeline = [
        {
            "case_id": row.get("case_id", ""),
            "file_name": row.get("file_name", "?"),
            "label": row.get("label", "inconclusive"),
            "score": row.get("score", 0),
            "created_at": row.get("created_at", ""),
            "report": f"{row.get('case_id', '')}/report.html" if row.get("has_report") else "",
        }
        for row in sorted(rows, key=lambda item: item.get("created_at", ""))
    ]
    return {
        "total": total,
        "counts": counts,
        "distribution": distribution,
        "average_score": round(average_score, 1),
        "average_sneakiness": round(average_sneakiness, 1),
        "suspicious_or_malicious": counts["suspicious"] + counts["malicious"],
        "report_coverage": round(report_count / total * 100, 1) if total else 0.0,
        "emulation_coverage": round(emulation_count / total * 100, 1) if total else 0.0,
        "unpack_counts": dict(sorted(unpack_counts.items())),
        "activity_by_day": activity_by_day,
        "timeline": timeline,
        "cases": ordered,
    }


def render_dashboard(rows: list[dict[str, Any]], generated_at: str | None = None) -> str:
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(
            enabled_extensions=("html", "xml", "j2"),
            default_for_string=True,
            default=True,
        ),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = environment.get_template("dashboard.html.j2")
    return template.render(
        view=build_dashboard_view(rows),
        generated_at=generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )


def write_case_reports(store, rows: list[dict[str, Any]]) -> list[Path]:
    written: list[Path] = []
    for row in rows:
        case = store.load(row["case_id"])
        target = store.case_dir(case.case_id) / "report.html"
        target.write_text(render_html(case), encoding="utf-8")
        written.append(target)
    return written
