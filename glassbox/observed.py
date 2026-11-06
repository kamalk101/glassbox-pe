"""Attach observed VM events to a case.

This module reads JSON reports produced by a Windows guest collector. It does
not execute anything and is not used to run samples.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .schema import Case, Category, Severity, Source, Strength

VALID_CATEGORIES = {category.value for category in Category}

ACTION_CATEGORY = {
    "process_create": Category.PROCESS,
    "process_exit": Category.PROCESS,
    "process_start": Category.PROCESS,
    "image_load": Category.PE,
    "file_create": Category.FILE,
    "file_write": Category.FILE,
    "file_delete": Category.FILE,
    "file_rename": Category.FILE,
    "file_move": Category.FILE,
    "file_access": Category.FILE,
    "registry_create": Category.REGISTRY,
    "registry_set": Category.REGISTRY,
    "registry_delete": Category.REGISTRY,
    "registry_open": Category.REGISTRY,
    "registry_access": Category.REGISTRY,
    "network_connect": Category.NETWORK,
    "network_send": Category.NETWORK,
    "network_recv": Category.NETWORK,
    "dns_query": Category.NETWORK,
    "socket_create": Category.NETWORK,
}

ACTION_TECHNIQUE = {
    "process_create": "T1059",
    "process_start": "T1059",
    "file_create": "T1105",
    "file_write": "T1105",
    "registry_create": "T1547.001",
    "registry_set": "T1547.001",
    "registry_delete": "T1112",
    "network_connect": "T1071.001",
    "network_send": "T1071.001",
    "dns_query": "T1071.001",
}


@dataclass
class ObservedReport:
    sample_sha256: str
    environment: dict[str, Any]
    started_at: str | None
    ended_at: str | None
    events: list[dict[str, Any]]
    dropped_files: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_sha256": self.sample_sha256,
            "environment": self.environment,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "events": self.events,
            "dropped_files": self.dropped_files,
        }


def load_report(path: str | Path) -> ObservedReport:
    target = Path(path).expanduser()
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read observed report: {exc}") from exc

    sample = raw.get("sample") or {}
    events = raw.get("events") or []
    dropped_files = raw.get("dropped_files") or []
    environment = raw.get("environment") or {}
    if not sample.get("sha256"):
        raise ValueError("observed report is missing sample.sha256")
    if not isinstance(events, list) or not isinstance(dropped_files, list):
        raise ValueError("observed report must contain events and dropped_files lists")
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"observed event {index} is not an object")
    return ObservedReport(
        sample_sha256=str(sample["sha256"]).lower(),
        environment=dict(environment) if isinstance(environment, dict) else {},
        started_at=raw.get("started_at"),
        ended_at=raw.get("ended_at"),
        events=events,
        dropped_files=dropped_files,
    )


def _action_mapping(event: dict[str, Any]) -> tuple[Category, str]:
    action = str(event.get("action") or "").lower()
    category = ACTION_CATEGORY.get(action)
    if category is None:
        raw = str(event.get("category") or "other").lower()
        category = Category(raw) if raw in VALID_CATEGORIES else Category.OTHER
    return category, action or "observed_event"


def _target(event: dict[str, Any]) -> str:
    value = event.get("target") or event.get("path") or event.get("name") or ""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value[:5])
    return str(value)[:240]


def attach_observed(case: Case, report: ObservedReport) -> None:
    case.events = [event for event in case.events if event.source is not Source.VM]
    case.findings = [finding for finding in case.findings if finding.source is not Source.VM]

    index = case.add_event(
        Category.PE,
        "observed_run",
        target="observed VM run",
        data={
            "environment": report.environment,
            "started_at": report.started_at,
            "ended_at": report.ended_at,
            "events": len(report.events),
            "dropped_files": len(report.dropped_files),
        },
        source=Source.VM,
        strength=Strength.OBSERVED,
    )

    for raw in report.events:
        category, action = _action_mapping(raw)
        target = _target(raw)
        technique = str(raw.get("technique") or ACTION_TECHNIQUE.get(action, ""))
        lower_target = target.lower()
        if category is Category.REGISTRY and any(
            marker in lower_target
            for marker in (r"currentversion\run", r"currentversion\runonce", "policies\\explorer\\run")
        ):
            technique = "T1547.001"
        elif category is Category.REGISTRY and action in {"registry_create", "registry_set", "registry_delete"}:
            technique = "T1112"
        elif category is Category.NETWORK and action == "network_connect":
            technique = "T1071.001"

        case.add_event(
            category,
            action,
            target=target,
            data={k: v for k, v in raw.items() if k not in {"category", "action", "target", "technique"}},
            source=Source.VM,
            strength=Strength.OBSERVED,
            technique=technique or None,
            parent=index.id,
        )

    for dropped in report.dropped_files:
        case.add_event(
            Category.FILE,
            "dropped_file",
            target=str(dropped.get("path") or "?")[:240],
            data={
                "size": dropped.get("size"),
                "sha256": dropped.get("sha256"),
            },
            source=Source.VM,
            strength=Strength.OBSERVED,
            technique="T1105",
            parent=index.id,
        )

    observed_events = [event for event in case.events if event.source is Source.VM]
    if observed_events:
        case.add_finding(
            rule_id="GB-OBS-001",
            title="Observed runtime behavior",
            severity=Severity.MEDIUM,
            description=(
                "An isolated Windows run observed behavior. This should be correlated with "
                "static evidence; it is not automatically malicious."
            ),
            category=Category.PROCESS if any(event.category is Category.PROCESS for event in observed_events) else Category.OTHER,
            evidence=[event.id for event in observed_events[:25]],
            techniques=sorted({event.technique for event in observed_events if event.technique}),
            source=Source.VM,
            confidence=0.8,
        )

    case.artifacts["observed"] = {
        **report.to_dict(),
        "events": len(report.events),
        "dropped_files": len(report.dropped_files),
        "report_file": None,
    }
