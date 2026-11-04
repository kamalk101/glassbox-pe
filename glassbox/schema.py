"""Core data contract for GlassBox PE.

Everything the backends produce is an Event. Everything the analyst sees is a
Finding backed by evidence Event IDs. The verdict is derived from findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

SCHEMA_VERSION = "0.1"
TOOL_VERSION = "0.1.0"


class Strength(str, Enum):
    STATIC = "static"
    ATTEMPTED = "attempted"
    OBSERVED = "observed"


class Source(str, Enum):
    STATIC = "static"
    EMULATION = "emulation"
    VM = "vm"


class Category(str, Enum):
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    REGISTRY = "registry"
    PE = "pe"
    SIGNATURE = "signature"
    OTHER = "other"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerdictLabel(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    INCONCLUSIVE = "inconclusive"


@dataclass
class Event:
    """One observed or inferred fact, with provenance."""

    id: str
    category: Category
    action: str
    target: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    source: Source = Source.STATIC
    strength: Strength = Strength.STATIC
    technique: str | None = None
    parent: str | None = None
    timestamp: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category.value,
            "action": self.action,
            "target": self.target,
            "data": self.data,
            "source": self.source.value,
            "strength": self.strength.value,
            "technique": self.technique,
            "parent": self.parent,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Event":
        return cls(
            id=raw["id"],
            category=Category(raw.get("category", "other")),
            action=raw.get("action", ""),
            target=raw.get("target", ""),
            data=raw.get("data") or {},
            source=Source(raw.get("source", "static")),
            strength=Strength(raw.get("strength", "static")),
            technique=raw.get("technique"),
            parent=raw.get("parent"),
            timestamp=raw.get("timestamp"),
        )


@dataclass
class Finding:
    """A conclusion backed by one or more evidence events."""

    id: str
    rule_id: str
    title: str
    severity: Severity
    description: str
    category: Category
    evidence: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    source: Source = Source.STATIC
    confidence: float = 0.6
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "category": self.category.value,
            "evidence": self.evidence,
            "techniques": self.techniques,
            "source": self.source.value,
            "confidence": round(self.confidence, 3),
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Finding":
        return cls(
            id=raw["id"],
            rule_id=raw.get("rule_id", ""),
            title=raw.get("title", ""),
            severity=Severity(raw.get("severity", "info")),
            description=raw.get("description", ""),
            category=Category(raw.get("category", "other")),
            evidence=raw.get("evidence") or [],
            techniques=raw.get("techniques") or [],
            source=Source(raw.get("source", "static")),
            confidence=float(raw.get("confidence", 0.6)),
            data=raw.get("data") or {},
        )


@dataclass
class Verdict:
    label: VerdictLabel
    score: int
    confidence: float
    sneakiness: int
    summary: str
    techniques: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    counterfactuals: list[dict[str, Any]] = field(default_factory=list)
    static_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label.value,
            "score": self.score,
            "confidence": round(self.confidence, 3),
            "sneakiness": self.sneakiness,
            "summary": self.summary,
            "techniques": self.techniques,
            "next_steps": self.next_steps,
            "counterfactuals": self.counterfactuals,
            "static_only": self.static_only,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Verdict":
        return cls(
            label=VerdictLabel(raw.get("label", "inconclusive")),
            score=int(raw.get("score", 0)),
            confidence=float(raw.get("confidence", 0.0)),
            sneakiness=int(raw.get("sneakiness", 0)),
            summary=raw.get("summary", ""),
            techniques=raw.get("techniques") or [],
            next_steps=raw.get("next_steps") or [],
            counterfactuals=raw.get("counterfactuals") or [],
            static_only=bool(raw.get("static_only", True)),
        )


@dataclass
class Case:
    """A single analysed sample and its full evidence trail."""

    case_id: str
    file_name: str
    file_path: str
    size: int
    hashes: dict[str, str]
    file_type: str
    created_at: str
    tool_version: str = TOOL_VERSION
    schema_version: str = SCHEMA_VERSION
    events: list[Event] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    verdict: Verdict | None = None
    artifacts: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    _event_counter: int = 0
    _finding_counter: int = 0

    def add_event(
        self,
        category: Category,
        action: str,
        target: str = "",
        data: dict[str, Any] | None = None,
        source: Source = Source.STATIC,
        strength: Strength = Strength.STATIC,
        technique: str | None = None,
        parent: str | None = None,
    ) -> Event:
        self._event_counter += 1
        event = Event(
            id=f"evt-{self._event_counter:04d}",
            category=category,
            action=action,
            target=target,
            data=data or {},
            source=source,
            strength=strength,
            technique=technique,
            parent=parent,
        )
        self.events.append(event)
        return event

    def add_finding(
        self,
        rule_id: str,
        title: str,
        severity: Severity,
        description: str,
        category: Category,
        evidence: list[str] | None = None,
        techniques: list[str] | None = None,
        source: Source = Source.STATIC,
        confidence: float = 0.6,
        data: dict[str, Any] | None = None,
    ) -> Finding:
        self._finding_counter += 1
        finding = Finding(
            id=f"fnd-{self._finding_counter:03d}",
            rule_id=rule_id,
            title=title,
            severity=severity,
            description=description,
            category=category,
            evidence=evidence or [],
            techniques=techniques or [],
            source=source,
            confidence=confidence,
            data=data or {},
        )
        self.findings.append(finding)
        return finding

    def techniques(self) -> list[str]:
        found: set[str] = set()
        for finding in self.findings:
            found.update(finding.techniques)
        return sorted(found)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool_version": self.tool_version,
            "case_id": self.case_id,
            "file_name": self.file_name,
            "file_path": self.file_path,
            "size": self.size,
            "hashes": self.hashes,
            "file_type": self.file_type,
            "created_at": self.created_at,
            "events": [e.to_dict() for e in self.events],
            "findings": [f.to_dict() for f in self.findings],
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "artifacts": self.artifacts,
            "errors": self.errors,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Case":
        case = cls(
            case_id=raw["case_id"],
            file_name=raw.get("file_name", ""),
            file_path=raw.get("file_path", ""),
            size=int(raw.get("size", 0)),
            hashes=raw.get("hashes") or {},
            file_type=raw.get("file_type", "unknown"),
            created_at=raw.get("created_at", ""),
            tool_version=raw.get("tool_version", TOOL_VERSION),
            schema_version=raw.get("schema_version", SCHEMA_VERSION),
            events=[Event.from_dict(e) for e in raw.get("events") or []],
            findings=[Finding.from_dict(f) for f in raw.get("findings") or []],
            verdict=Verdict.from_dict(raw["verdict"]) if raw.get("verdict") else None,
            artifacts=raw.get("artifacts") or {},
            errors=raw.get("errors") or [],
        )
        case._event_counter = len(case.events)
        case._finding_counter = len(case.findings)
        return case
