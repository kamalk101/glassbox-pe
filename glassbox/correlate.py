"""Cross-source correlation for findings, evidence, and ATT&CK techniques."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .schema import Case, Source, Strength


def correlate(case: Case) -> dict[str, Any]:
    """Summarise how findings, events, and techniques support each other.

    A technique is "corroborated" when it appears in both static findings and
    attempted/observed evidence. This is a report-level summary, not a new
    finding, so it never changes the verdict score by itself.
    """

    events_by_id = {event.id: event for event in case.events}
    techniques: dict[str, dict[str, Any]] = {}
    findings_without_evidence: list[str] = []
    linked_event_ids: set[str] = set()

    for finding in case.findings:
        linked = [events_by_id[event_id] for event_id in finding.evidence if event_id in events_by_id]
        if not linked:
            findings_without_evidence.append(finding.id)
        linked_event_ids.update(event.id for event in linked)

        for technique in finding.techniques:
            entry = techniques.setdefault(
                technique,
                {
                    "technique": technique,
                    "findings": [],
                    "event_ids": set(),
                    "strengths": set(),
                    "static": False,
                    "attempted": False,
                    "observed": False,
                },
            )
            entry["findings"].append(finding.id)
            entry["event_ids"].update(event.id for event in linked)
            entry["strengths"].update(event.strength for event in linked)
            if finding.source is Source.STATIC:
                entry["static"] = True
            elif finding.source is Source.EMULATION:
                entry["attempted"] = True
            elif finding.source is Source.VM:
                entry["observed"] = True

    technique_rows: list[dict[str, Any]] = []
    for technique, entry in techniques.items():
        if Strength.STATIC in entry["strengths"]:
            entry["static"] = True
        if Strength.ATTEMPTED in entry["strengths"]:
            entry["attempted"] = True
        if Strength.OBSERVED in entry["strengths"]:
            entry["observed"] = True

        if entry["observed"]:
            status = "observed"
        elif entry["static"] and entry["attempted"]:
            status = "corroborated"
        elif entry["attempted"]:
            status = "attempted only"
        elif entry["static"]:
            status = "static only"
        else:
            status = "unlinked"

        technique_rows.append(
            {
                "technique": technique,
                "status": status,
                "findings": sorted(set(entry["findings"])),
                "event_ids": sorted(entry["event_ids"]),
                "strengths": sorted(strength.value for strength in entry["strengths"]),
            }
        )

    technique_rows.sort(key=lambda row: (row["technique"]))
    by_strength = Counter(event.strength.value for event in case.events)
    by_category = Counter(event.category.value for event in case.events)
    by_source = Counter(finding.source.value for finding in case.findings)

    return {
        "findings": len(case.findings),
        "findings_with_evidence": len(case.findings) - len(findings_without_evidence),
        "findings_without_evidence": findings_without_evidence,
        "events": len(case.events),
        "linked_events": len(linked_event_ids),
        "coverage": (
            (len(case.findings) - len(findings_without_evidence)) / len(case.findings)
            if case.findings
            else 1.0
        ),
        "by_strength": dict(sorted(by_strength.items())),
        "by_category": dict(sorted(by_category.items())),
        "by_source": dict(sorted(by_source.items())),
        "techniques": technique_rows,
        "corroborated_techniques": [
            row["technique"] for row in technique_rows if row["status"] == "corroborated"
        ],
        "static_only_techniques": [
            row["technique"] for row in technique_rows if row["status"] == "static only"
        ],
        "attempted_only_techniques": [
            row["technique"] for row in technique_rows if row["status"] == "attempted only"
        ],
        "observed_techniques": [
            row["technique"] for row in technique_rows if row["status"] == "observed"
        ],
    }
