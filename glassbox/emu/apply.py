"""Turn a Speakeasy report into evidence events and findings."""

from __future__ import annotations

from collections import defaultdict

from .. import score
from ..schema import Case, Category, Source, Strength
from ..static.imports import (
    BEHAVIOR_CATEGORY,
    BEHAVIOR_LABELS,
    BEHAVIOR_TECHNIQUE,
    classify_api,
    is_strong_anti_analysis,
)
from .speakeasy_backend import EmulationOutcome

MAX_API_EVENTS = 400

WRITE_APIS = {
    "writefile",
    "deletefilea",
    "deletefilew",
    "movefilea",
    "movefilew",
    "copyfilea",
    "copyfilew",
    "setfileattributesa",
    "setfileattributesw",
}

BEHAVIOUR_FINDINGS = {
    "process_injection": ("GB-EMU-001", "Attempted process injection", "high", "T1055"),
    "persistence": ("GB-EMU-002", "Attempted persistence", "high", "T1547.001"),
    "network": ("GB-EMU-003", "Attempted network communication", "medium", "T1071.001"),
    "execution": ("GB-EMU-004", "Attempted process execution", "low", "T1106"),
    "dynamic_loading": ("GB-EMU-005", "Attempted runtime code loading", "low", "T1129"),
    "file_write": ("GB-EMU-006", "Attempted file modification", "low", None),
    "anti_analysis": ("GB-EMU-007", "Attempted anti-analysis checks", "low", "T1497.001"),
    "keylogging": ("GB-EMU-008", "Attempted keystroke capture", "high", "T1056.001"),
    "screen_capture": ("GB-EMU-009", "Attempted screen capture", "medium", "T1113"),
}

SEVERITY_BY_NAME = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def _clear_emulation(case: Case) -> None:
    case.events = [event for event in case.events if event.source is not Source.EMULATION]
    case.findings = [finding for finding in case.findings if finding.source is not Source.EMULATION]
    case.artifacts.pop("emulation", None)


def _function_name(api_name: str) -> str:
    return api_name.rsplit(".", 1)[-1] if "." in api_name else api_name


def _dll_name(api_name: str) -> str:
    return api_name.rsplit(".", 1)[0] if "." in api_name else ""


def _iter_calls(report: dict):
    for entry_point in report.get("entry_points") or []:
        for call in entry_point.get("apis") or []:
            yield entry_point, call


def apply_emulation(case: Case, outcome: EmulationOutcome) -> Case:
    _clear_emulation(case)

    if not outcome.ran or not outcome.report:
        if outcome.error:
            case.errors.append(f"emulation: {outcome.error}")
        return case

    report = outcome.report
    meta = case.add_event(
        Category.PE,
        "emulation",
        target="speakeasy",
        data={
            "version": report.get("emu_version"),
            "runtime": report.get("emulation_total_runtime"),
            "arch": report.get("arch"),
            "os": report.get("os_run"),
            "report": outcome.report_path,
        },
        source=Source.EMULATION,
        strength=Strength.ATTEMPTED,
    )

    behaviour_events: dict[str, list[str]] = defaultdict(list)
    behaviour_functions: dict[str, list[str]] = defaultdict(list)
    api_count = 0

    for _entry, call in _iter_calls(report):
        api_name = str(call.get("api_name") or "")
        if not api_name:
            continue
        function = _function_name(api_name)
        behaviours = classify_api(function)
        behaviour = behaviours[0] if behaviours else None
        if behaviour == "anti_analysis" and not is_strong_anti_analysis(function):
            behaviour = None
        category = BEHAVIOR_CATEGORY.get(behaviour, Category.OTHER) if behaviour else Category.OTHER
        args = call.get("args") or []
        target = str(args[0]) if args else ""
        event = case.add_event(
            category,
            function,
            target=target[:200],
            data={
                "args": args,
                "ret": call.get("ret_val"),
                "pc": call.get("pc"),
                "dll": _dll_name(api_name),
                "behaviour": behaviour,
            },
            source=Source.EMULATION,
            strength=Strength.ATTEMPTED,
            technique=BEHAVIOR_TECHNIQUE.get(behaviour) if behaviour else None,
            parent=meta.id,
        )
        api_count += 1
        if behaviour:
            behaviour_events[behaviour].append(event.id)
            behaviour_functions[behaviour].append(function)
        if api_count >= MAX_API_EVENTS:
            case.add_event(
                Category.OTHER,
                "emulation_truncated",
                target=f"more than {MAX_API_EVENTS} API calls",
                source=Source.EMULATION,
                strength=Strength.ATTEMPTED,
                parent=meta.id,
            )
            break

    dynamic_events: list[str] = []
    for entry_point in report.get("entry_points") or []:
        for index, segment in enumerate(entry_point.get("dynamic_code_segments") or []):
            dynamic_events.append(
                case.add_event(
                    Category.PROCESS,
                    "dynamic_code",
                    target=str(segment.get("addr", segment.get("address", f"segment-{index}")))[:200],
                    data={"segment": segment},
                    source=Source.EMULATION,
                    strength=Strength.ATTEMPTED,
                    technique="T1027",
                    parent=meta.id,
                ).id
            )

    memory_strings = (report.get("strings") or {}).get("in_memory") or {}
    if isinstance(memory_strings, dict):
        for encoding in ("ansi", "unicode"):
            values = memory_strings.get(encoding) or []
            if values:
                case.add_event(
                    Category.PE,
                    "memory_strings",
                    target=f"{len(values)} {encoding} strings",
                    data={"encoding": encoding, "items": values[:100], "count": len(values)},
                    source=Source.EMULATION,
                    strength=Strength.ATTEMPTED,
                    parent=meta.id,
                )

    dropped_events: list[str] = []
    for dropped in outcome.dropped_files:
        dropped_events.append(
            case.add_event(
                Category.FILE,
                "dropped_file",
                target=dropped.path,
                data={"size": dropped.size, "sha256": dropped.sha256},
                source=Source.EMULATION,
                strength=Strength.ATTEMPTED,
                technique="T1105",
                parent=meta.id,
            ).id
        )

    # File writes are more interesting than reads; split them out for the verdict.
    file_writes = [
        function
        for function in behaviour_functions.get("file", [])
        if function.lower() in WRITE_APIS
    ]
    if file_writes:
        behaviour_events["file_write"] = behaviour_events.get("file", [])
        behaviour_functions["file_write"] = file_writes

    static_techniques = {
        technique
        for finding in case.findings
        if finding.source is Source.STATIC
        for technique in finding.techniques
    }

    for behaviour, (rule_id, title, severity_name, technique) in BEHAVIOUR_FINDINGS.items():
        events = behaviour_events.get(behaviour) or []
        functions = behaviour_functions.get(behaviour) or []
        if not events:
            continue
        # Do not double-count a low-value capability that static analysis has
        # already established. Higher-severity emulation findings still add the
        # attempted-behaviour layer.
        if severity_name == "low" and technique and technique in static_techniques:
            continue
        case.add_finding(
            rule_id=rule_id,
            title=f"{title} (emulation)",
            severity=score.Severity[severity_name.upper()],
            description=(
                f"During emulation the sample called {len(events)} API(s) associated with "
                f"{BEHAVIOR_LABELS.get(behaviour, behaviour)}: "
                + ", ".join(sorted(set(functions))[:8])
                + "."
            ),
            category=BEHAVIOR_CATEGORY.get(behaviour, Category.OTHER),
            evidence=events[:25],
            techniques=[technique] if technique else [],
            source=Source.EMULATION,
            confidence=0.8,
            data={"count": len(events), "functions": sorted(set(functions))},
        )

    if dropped_events:
        case.add_finding(
            rule_id="GB-EMU-010",
            title="Dropped file during emulation",
            severity=score.Severity.MEDIUM,
            description="The sample wrote one or more files during emulation. These are queued as child artefacts.",
            category=Category.FILE,
            evidence=dropped_events[:25],
            techniques=["T1105"],
            source=Source.EMULATION,
            confidence=0.85,
            data={"files": [drop.__dict__ for drop in outcome.dropped_files]},
        )

    if dynamic_events:
        case.add_finding(
            rule_id="GB-EMU-011",
            title="Runtime code generated during emulation",
            severity=score.Severity.MEDIUM,
            description="The emulator observed dynamically generated code segments. This is common in unpackers and loaders.",
            category=Category.PROCESS,
            evidence=dynamic_events[:25],
            techniques=["T1027"],
            source=Source.EMULATION,
            confidence=0.75,
            data={"segments": len(dynamic_events)},
        )

    if api_count == 0:
        case.add_finding(
            rule_id="GB-EMU-000",
            title="Emulation produced no API events",
            severity=score.Severity.INFO,
            description=(
                "The sample did not reach any supported API during emulation. It may be packed, "
                "anti-emulation aware, or need a different execution path."
            ),
            category=Category.PE,
            evidence=[meta.id],
            source=Source.EMULATION,
            confidence=0.5,
        )

    case.artifacts["emulation"] = {
        "ran": True,
        "version": report.get("emu_version"),
        "runtime": report.get("emulation_total_runtime"),
        "arch": report.get("arch"),
        "api_calls": api_count,
        "behaviours": {key: len(value) for key, value in behaviour_events.items()},
        "dropped_files": [drop.__dict__ for drop in outcome.dropped_files],
        "dynamic_segments": len(dynamic_events),
        "report_path": outcome.report_path,
        "error": outcome.error,
    }

    if case.verdict and case.verdict.label.value != "inconclusive":
        case.verdict = score.build_verdict(
            case.findings,
            static_only=False,
            sneakiness=case.verdict.sneakiness,
            sneakiness_reasons=case.verdict.sneakiness_reasons,
            signed=bool((case.artifacts.get("pe") or {}).get("signed")),
        )
        case.verdict.techniques = case.techniques()

    return case
