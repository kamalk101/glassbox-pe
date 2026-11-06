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


def _wrap_lines(value: Any, width: int = 34, max_lines: int = 2) -> list[str]:
    text = " ".join(str(value or "").split())
    if not text:
        return ["-"]
    lines = []
    current = ""
    for word in text.split(" "):
        if not current:
            current = word
            continue
        if len(current) + 1 + len(word) <= width:
            current += " " + word
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = lines[-1][: max(0, width - 1)] + "…"
    return lines


def _graph_node(id_: str, kind: str, label: str, sublabel: str, col: int, row: int, source: str = "", severity: str = "") -> dict[str, Any]:
    return {
        "id": id_,
        "kind": kind,
        "label": label,
        "sublabel": sublabel,
        "x": col,
        "y": row,
        "source": source or kind,
        "severity": severity,
        "search": f"{id_} {label} {sublabel} {source} {severity}".lower(),
        "label_lines": _wrap_lines(label, 32, 2),
        "sublabel_lines": _wrap_lines(sublabel, 42, 1),
    }


def _build_event_graph(case: Case) -> dict[str, Any]:
    event_to_finding: dict[str, list[str]] = {}
    for finding in case.findings:
        for event_id in finding.evidence:
            event_to_finding.setdefault(event_id, []).append(finding.id)

    parent_events = sorted(
        [event for event in case.events if any(other.parent == event.id for other in case.events)],
        key=lambda event: event.id,
    )
    child_events = [event for event in case.events if event not in parent_events]
    findings = case.findings

    # Node columns: findings / evidence events / parent events.
    row_height = 64
    node_width = 340
    finding_x = 40
    event_x = 500
    parent_x = 1040
    max_rows = max(len(findings), len(child_events), len(parent_events), 1)
    height = max_rows * row_height + 120
    nodes = []

    for index, finding in enumerate(findings):
        nodes.append(
            _graph_node(
                finding.id,
                "finding",
                f"{finding.rule_id} · {finding.title}",
                f"{finding.severity.value} · {finding.confidence:.2f} · {finding.source.value}",
                finding_x,
                60 + index * row_height,
                source=finding.source.value,
                severity=finding.severity.value,
            )
        )

    for index, event in enumerate(child_events):
        nodes.append(
            _graph_node(
                event.id,
                "event",
                event.action,
                f"{event.category.value} · {event.strength.value} · {event.source.value}",
                event_x,
                60 + index * row_height,
                source=event.source.value,
                severity="",
            )
        )

    for index, event in enumerate(parent_events):
        nodes.append(
            _graph_node(
                event.id,
                "parent",
                event.action,
                f"{event.category.value} · {event.source.value}",
                parent_x,
                60 + index * row_height,
                source=event.source.value,
                severity="",
            )
        )

    edges = []
    for finding in findings:
        for event_id in finding.evidence:
            if event_id:
                edges.append({"source": finding.id, "target": event_id, "kind": "evidence-support"})
    for event in case.events:
        if event.parent:
            edges.append({"source": event.parent, "target": event.id, "kind": "child"})

    events_by_id = {event.id: event for event in case.events}
    finding_locations = {finding.id: nodes[idx] for idx, finding in enumerate(findings)}
    child_locations = {event.id: nodes[len(findings) + idx] for idx, event in enumerate(child_events)}
    parent_locations = {event.id: nodes[len(findings) + len(child_events) + idx] for idx, event in enumerate(parent_events)}

    def edge_view(edge: dict[str, str]) -> dict[str, Any] | None:
        start = finding_locations.get(edge["source"]) or child_locations.get(edge["source"]) or parent_locations.get(edge["source"])
        target = child_locations.get(edge["target"]) or parent_locations.get(edge["target"]) or finding_locations.get(edge["target"])
        if start is None or target is None:
            return None
        if start is target:
            return None
        return {
            **edge,
            "x1": start["x"] + node_width,
            "y1": start["y"] + 22,
            "x2": target["x"],
            "y2": target["y"] + 22,
        }

    linked_edges = [view for edge in edges if (view := edge_view(edge))]
    return {
        "nodes": nodes,
        "edges": linked_edges,
        "width": parent_x + node_width + 80,
        "height": height,
        "node_width": node_width,
        "finding_count": len(findings),
        "event_count": len(case.events),
        "node_count": len(nodes),
    }


def _unpack_view(unpack: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(unpack, dict):
        return None
    diff = unpack.get("diff") or {}
    new_imports = diff.get("new_imports") or []
    removed_imports = diff.get("removed_imports") or []
    new_sections = diff.get("new_sections") or []
    removed_sections = diff.get("removed_sections") or []
    new_findings = diff.get("new_findings") or []
    resolved_findings = diff.get("resolved_findings") or []
    parent_score = diff.get("parent_score")
    child_score = diff.get("child_score")
    parent_confidence = diff.get("parent_confidence")
    child_confidence = diff.get("child_confidence")

    comparison = [
        {
            "label": "verdict",
            "before": diff.get("parent_verdict") or "?",
            "after": diff.get("child_verdict") or "?",
            "delta": "changed" if diff.get("parent_verdict") != diff.get("child_verdict") else "same",
            "status": "changed" if diff.get("parent_verdict") != diff.get("child_verdict") else "same",
        },
        {
            "label": "risk score",
            "before": parent_score if parent_score is not None else "?",
            "after": child_score if child_score is not None else "?",
            "delta": "" if parent_score is None or child_score is None else f"{child_score - parent_score:+d}",
            "status": "changed" if parent_score != child_score else "same",
        },
        {
            "label": "confidence",
            "before": parent_confidence if parent_confidence is not None else "?",
            "after": child_confidence if child_confidence is not None else "?",
            "delta": "" if parent_confidence is None or child_confidence is None else f"{child_confidence - parent_confidence:+.2f}",
            "status": "changed" if parent_confidence != child_confidence else "same",
        },
        {
            "label": "size",
            "before": unpack.get("parent_size", "?"),
            "after": unpack.get("child_size", "?"),
            "delta": f"{diff.get('size_delta', 0):+d} bytes",
            "status": "changed" if diff.get("size_delta", 0) else "same",
        },
        {
            "label": "imports",
            "before": f"{len(new_imports)} new / {len(removed_imports)} removed",
            "after": "after unpack",
            "delta": f"{len(new_imports) - len(removed_imports):+d}",
            "status": "changed" if new_imports or removed_imports else "same",
        },
        {
            "label": "sections",
            "before": f"{len(new_sections)} new / {len(removed_sections)} removed",
            "after": "after unpack",
            "delta": f"{len(new_sections) - len(removed_sections):+d}",
            "status": "changed" if new_sections or removed_sections else "same",
        },
        {
            "label": "findings",
            "before": f"{len(new_findings)} new / {len(resolved_findings)} resolved",
            "after": "after unpack",
            "delta": f"{len(new_findings) - len(resolved_findings):+d}",
            "status": "changed" if new_findings or resolved_findings else "same",
        },
    ]
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
        "comparison": comparison,
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

    events = events_view = [
        {**_event_view(event), "seq": index + 1}
        for index, event in enumerate(case.events)
    ]

    return {
        "size_human": human_size(case.size),
        "verdict": _verdict_view(case),
        "correlation": correlate(case),
        "findings": [_finding_view(finding, events_by_id) for finding in case.findings],
        "events": events,
        "event_graph": _build_event_graph(case),
        "pe": static,
        "packer": packer,
        "sections": sections,
        "import_groups": case.artifacts.get("imports") or {},
        "imports_count": len(case.artifacts.get("imports_all") or []),
        "unpack": _unpack_view(case.artifacts.get("unpack")),
        "emulation": case.artifacts.get("emulation") or {},
        "observed": case.artifacts.get("observed") or {},
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
