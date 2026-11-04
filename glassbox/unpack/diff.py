"""Compare a packed case with its unpacked child case."""

from __future__ import annotations

from ..schema import Case


def _artifact_set(case: Case, key: str) -> set[str]:
    value = case.artifacts.get(key) or []
    return set(value) if isinstance(value, list) else set()


def diff_cases(parent: Case, child: Case) -> dict:
    parent_findings = {f.rule_id for f in parent.findings if f.source.value == "static"}
    child_findings = {f.rule_id for f in child.findings if f.source.value == "static"}

    parent_imports = _artifact_set(parent, "imports_all")
    child_imports = _artifact_set(child, "imports_all")
    parent_sections = _artifact_set(parent, "sections")
    child_sections = _artifact_set(child, "sections")

    return {
        "child_case_id": child.case_id,
        "size_delta": child.size - parent.size,
        "new_imports": sorted(child_imports - parent_imports),
        "removed_imports": sorted(parent_imports - child_imports),
        "new_sections": sorted(child_sections - parent_sections),
        "removed_sections": sorted(parent_sections - child_sections),
        "new_findings": sorted(child_findings - parent_findings),
        "resolved_findings": sorted(parent_findings - child_findings),
        "parent_verdict": parent.verdict.label.value if parent.verdict else None,
        "child_verdict": child.verdict.label.value if child.verdict else None,
        "parent_score": parent.verdict.score if parent.verdict else None,
        "child_score": child.verdict.score if child.verdict else None,
        "parent_confidence": parent.verdict.confidence if parent.verdict else None,
        "child_confidence": child.verdict.confidence if child.verdict else None,
    }
