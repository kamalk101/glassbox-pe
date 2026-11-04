"""Static analysis pipeline: bytes in, Case out."""

from __future__ import annotations

from . import score
from .ingest import Intake
from .schema import Case, Category, Source, Strength
from .static import imports as imports_mod
from .static import packer as packer_mod
from .static import pe as pe_mod
from .static import rules as rules_mod
from .static import strings as strings_mod
from .utils import utc_now_iso


def _import_event_category(behaviour: str) -> Category:
    return imports_mod.BEHAVIOR_CATEGORY.get(behaviour, Category.PE)


def analyze_static(intake: Intake) -> Case:
    case = Case(
        case_id=intake.case_id,
        file_name=intake.path.name,
        file_path=str(intake.path),
        size=intake.size,
        hashes=intake.hashes,
        file_type=intake.file_type,
        created_at=utc_now_iso(),
    )

    try:
        data = intake.path.read_bytes()
    except OSError as exc:
        case.errors.append(f"read error: {exc}")
        case.verdict = score.build_verdict([], pe_mod.PEInfo(), strings_mod.StringsResult(), imports_mod.ImportAnalysis(), parse_error=str(exc))
        return case

    info = pe_mod.parse_pe(data)
    strings = strings_mod.extract(data)
    import_analysis = imports_mod.analyze(info.imports, info.ordinal_imports)
    packer = packer_mod.detect(data, info)

    event_index: dict[str, str] = {}

    # Core PE event
    event_index["pe"] = case.add_event(
        Category.PE,
        "parsed",
        target=case.file_name,
        data=info.summary(),
    ).id

    for section in info.sections:
        event = case.add_event(
            Category.PE,
            "section",
            target=section.name,
            data={
                "virtual_address": hex(section.virtual_address),
                "virtual_size": section.virtual_size,
                "raw_size": section.raw_size,
                "entropy": section.entropy,
                "executable": section.executable,
                "writable": section.writable,
                "wx": section.wx,
            },
        )
        event_index.setdefault(f"section:{section.name}", event.id)

    event_index["overlay"] = case.add_event(
        Category.PE,
        "overlay",
        target=f"{info.overlay_size} bytes",
        data={"size": info.overlay_size, "offset": info.overlay_offset},
    ).id

    event_index["signature"] = case.add_event(
        Category.SIGNATURE,
        "authenticode",
        target="present" if info.signature_present else "absent",
        data={"size": info.signature_size},
    ).id

    if info.is_dotnet:
        event_index["dotnet"] = case.add_event(
            Category.PE,
            "dotnet",
            target="managed assembly",
        ).id

    if info.tls_callbacks:
        event_index["tls"] = case.add_event(
            Category.PE,
            "tls_callbacks",
            target=f"{info.tls_callbacks} callback(s)",
            data={"address": hex(info.tls_callback_address)},
        ).id

    if info.pdb_path:
        event_index["pdb"] = case.add_event(
            Category.PE,
            "pdb_path",
            target=info.pdb_path,
        ).id

    if info.resource_count:
        event_index["resource"] = case.add_event(
            Category.PE,
            "resources",
            target=f"{info.resource_count} entries",
        ).id

    if info.embedded_pe:
        event_index["embedded_pe"] = case.add_event(
            Category.PE,
            "embedded_pe",
            target=", ".join(info.embedded_pe[:3]),
            data={"payloads": info.embedded_pe},
        ).id

    event_index["imports:all"] = case.add_event(
        Category.PE,
        "imports",
        target=f"{info.imports_count} functions from {len(info.imports)} DLL(s)",
        data={"dlls": info.dlls, "ordinal_count": import_analysis.ordinal_count},
    ).id

    for behaviour, functions in import_analysis.groups.items():
        event_index[f"imports:{behaviour}"] = case.add_event(
            _import_event_category(behaviour),
            "capability",
            target=rules_mod.behavior_label(behaviour),
            data={"functions": functions},
            technique=rules_mod.behavior_technique(behaviour),
        ).id

    # Indicator events (one per kind, with the values attached)
    ioc_specs = [
        ("ioc:urls", Category.NETWORK, "url", "urls"),
        ("ioc:ips", Category.NETWORK, "ip", "ips"),
        ("ioc:domains", Category.NETWORK, "domain", "domains"),
        ("ioc:registry_keys", Category.REGISTRY, "registry_key", "registry_keys"),
        ("ioc:windows_paths", Category.FILE, "path", "windows_paths"),
        ("ioc:base64", Category.PE, "encoded_string", "base64"),
    ]
    for key, category, action, ioc_key in ioc_specs:
        values = strings.iocs.get(ioc_key, [])
        if not values:
            continue
        event_index[key] = case.add_event(
            category,
            action,
            target=values[0][:200],
            data={"count": len(values), "items": values[:50]},
        ).id

    if strings.commands:
        event_index["ioc:commands"] = case.add_event(
            Category.PROCESS,
            "command_tokens",
            target=", ".join(strings.commands[:5]),
            data={"commands": strings.commands},
        ).id

    # Rules -> findings
    context = rules_mod.RuleContext(
        info=info,
        strings=strings,
        imports=import_analysis,
        event_index=event_index,
        file_size=intake.size,
    )
    drafts = rules_mod.evaluate(context)
    for draft in drafts:
        case.add_finding(
            rule_id=draft.rule_id,
            title=draft.title,
            severity=draft.severity,
            description=draft.description,
            category=draft.category,
            evidence=draft.evidence,
            techniques=draft.techniques,
            source=Source.STATIC,
            confidence=draft.confidence,
            data=draft.data,
        )

    verdict = score.build_verdict(
        case.findings,
        info,
        strings,
        import_analysis,
        parse_error=info.parse_error,
    )
    verdict.techniques = case.techniques()
    case.verdict = verdict

    if info.parse_error:
        case.errors.append(f"pe parse: {info.parse_error}")

    case.artifacts = {
        "pe": info.summary(),
        "strings": {
            "count": len(strings.all_strings),
            "truncated": strings.truncated,
            "commands": strings.commands,
        },
        "iocs": {key: len(value) for key, value in strings.iocs.items()},
        "imports": import_analysis.groups,
        "imports_all": sorted(info.all_import_functions()),
        "sections": [section.name for section in info.sections],
        "packer": packer.to_dict(),
        "events": len(case.events),
        "findings": len(case.findings),
    }

    # Keep the case file small but useful for later phases/UI.
    case.artifacts["strings_preview"] = strings.all_strings[:200]

    return case
