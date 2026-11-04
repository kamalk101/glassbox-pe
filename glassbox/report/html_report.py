"""Standalone HTML report rendering."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..correlate import correlate
from ..schema import Case, VerdictLabel
from ..utils import human_size

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

VERDICT_DISPLAY = {
    VerdictLabel.CLEAN: "CLEAN",
    VerdictLabel.SUSPICIOUS: "SUSPICIOUS",
    VerdictLabel.MALICIOUS: "LIKELY MALICIOUS",
    VerdictLabel.INCONCLUSIVE: "INCONCLUSIVE",
}


def _json_preview(value: Any, limit: int = 4000) -> str:
    try:
        text = json.dumps(value, indent=2, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        text = repr(value)
    if len(text) > limit:
        text = text[:limit] + "\n... truncated ..."
    return text


def _event_view(event) -> dict[str, Any]:
    return {
        "id": event.id,
        "category": event.category.value,
        "action": event.action,
        "target": event.target,
        "source": event.source.value,
        "strength": event.strength.value,
        "technique": event.technique or "",
        "parent": event.parent or "",
        "timestamp": event.timestamp or "",
        "data_json": _json_preview(event.data),
    }


def _finding_view(finding, events_by_id: dict[str, Any]) -> dict[str, Any]:
    evidence = []
    missing = []
    for event_id in finding.evidence:
        event = events_by_id.get(event_id)
        if event is None:
            missing.append(event_id)
            continue
        evidence.append(
            {
                "id": event.id,
                "action": event.action,
                "target": event.target,
                "strength": event.strength.value,
            }
        )
    return {
        "id": finding.id,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "description": finding.description,
        "category": finding.category.value,
        "source": finding.source.value,
        "confidence": f"{finding.confidence:.2f}",
        "techniques": finding.techniques,
        "evidence": evidence,
        "missing_evidence": missing,
        "data_json": _json_preview(finding.data) if finding.data else "",
    }


def _unpack_view(unpack: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(unpack, dict):
        return None
    diff = unpack.get("diff") or {}
    return {
        "status": unpack.get("status", "?"),
        "packer": unpack.get("packer") or {},
        "method": unpack.get("method") or "-",
        "output_path": unpack.get("output_path") or "-",
        "tool": unpack.get("tool") or "-",
        "error": unpack.get("error") or "",
        "child_case_id": unpack.get("child_case_id") or diff.get("child_case_id") or "",
        "diff": diff,
        "new_imports": diff.get("new_imports") or [],
        "removed_imports": diff.get("removed_imports") or [],
        "new_sections": diff.get("new_sections") or [],
        "removed_sections": diff.get("removed_sections") or [],
        "new_findings": diff.get("new_findings") or [],
        "resolved_findings": diff.get("resolved_findings") or [],
        "diff_json": _json_preview(diff) if diff else "",
    }


def _verdict_view(case: Case) -> dict[str, Any] | None:
    verdict = case.verdict
    if verdict is None:
        return None
    return {
        "label": verdict.label.value,
        "display": VERDICT_DISPLAY.get(verdict.label, verdict.label.value.upper()),
        "score": verdict.score,
        "confidence": f"{verdict.confidence:.2f}",
        "sneakiness": verdict.sneakiness,
        "sneakiness_reasons": verdict.sneakiness_reasons,
        "summary": verdict.summary,
        "techniques": verdict.techniques,
        "next_steps": verdict.next_steps,
        "counterfactuals": verdict.counterfactuals,
        "static_only": verdict.static_only,
    }


def build_html_view(case: Case) -> dict[str, Any]:
    events_by_id = {event.id: event for event in case.events}
    static = case.artifacts.get("pe") or {}
    packer = case.artifacts.get("packer") or {}
    sections = case.artifacts.get("sections_detail") or []

    return {
        "size_human": human_size(case.size),
        "verdict": _verdict_view(case),
        "correlation": correlate(case),
        "findings": [_finding_view(finding, events_by_id) for finding in case.findings],
        "events": [_event_view(event) for event in case.events],
        "pe": static,
        "packer": packer,
        "sections": sections,
        "import_groups": case.artifacts.get("imports") or {},
        "imports_count": len(case.artifacts.get("imports_all") or []),
        "unpack": _unpack_view(case.artifacts.get("unpack")),
        "emulation": case.artifacts.get("emulation") or {},
        "errors": case.errors,
    }


def render_html(case: Case, generated_at: str | None = None) -> str:
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
    template = environment.get_template("case.html.j2")
    view = build_html_view(case)
    return template.render(
        case=case,
        view=view,
        generated_at=generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
