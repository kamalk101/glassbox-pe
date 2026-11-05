"""Offline case dashboard rendering."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .html_report import render_html

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
LABELS = ("clean", "suspicious", "malicious", "inconclusive")


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
    return {
        "total": total,
        "counts": counts,
        "distribution": distribution,
        "average_score": round(average_score, 1),
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
