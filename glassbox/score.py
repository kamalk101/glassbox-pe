"""Sneakiness and evidence-weighted verdict scoring.

This is deliberately rule-based and explainable. There is no ML in Phase 1.
"""

from __future__ import annotations

from .schema import Finding, Severity, Verdict, VerdictLabel
from .static.imports import ImportAnalysis
from .static.pe import PEInfo
from .static.strings import StringsResult

SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 4,
    Severity.MEDIUM: 12,
    Severity.HIGH: 25,
    Severity.CRITICAL: 40,
}

SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _weighted_sum(findings: list[Finding]) -> float:
    weights = sorted((SEVERITY_WEIGHT[f.severity] for f in findings), reverse=True)
    total = 0.0
    for index, weight in enumerate(weights):
        total += weight * (0.85**index)
    return total


def compute_sneakiness(info: PEInfo, strings: StringsResult, imports: ImportAnalysis) -> tuple[int, list[str]]:
    points = 0
    reasons: list[str] = []

    if info.packer_hint:
        points += 25
        reasons.append(f"packed ({info.packer_hint})")

    high_entropy = [s for s in info.sections if s.entropy > 7.2]
    if high_entropy:
        bonus = min(24, 8 * len(high_entropy))
        points += bonus
        reasons.append(f"{len(high_entropy)} high-entropy section(s)")

    anti = imports.groups.get("anti_analysis", [])
    if anti:
        points += 15
        reasons.append("anti-analysis APIs")

    if info.overlay_size > 1024 * 1024:
        points += 10
        reasons.append("large overlay")

    if strings.base64_like:
        points += 10
        reasons.append("encoded/obfuscated strings")

    if any(s.wx for s in info.sections):
        points += 10
        reasons.append("W+X section")

    if info.tls_callbacks:
        points += 5
        reasons.append("TLS callbacks")

    if info.embedded_pe:
        points += 15
        reasons.append("embedded PE resource")

    if imports.ordinal_count:
        points += 5
        reasons.append("ordinal-only imports")

    return min(100, points), reasons


def label_for_score(score: int) -> VerdictLabel:
    if score >= 60:
        return VerdictLabel.MALICIOUS
    if score >= 25:
        return VerdictLabel.SUSPICIOUS
    return VerdictLabel.CLEAN


def _label(score: int) -> VerdictLabel:
    return label_for_score(score)


def _confidence(findings: list[Finding], static_only: bool = True) -> float:
    weight = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    high = sum(1 for f in findings if SEVERITY_RANK[f.severity] >= 3)
    value = 0.45 + min(0.30, weight / 200.0) + min(0.10, high * 0.03)
    if not static_only:
        value += 0.08
    ceiling = 0.80 if static_only else 0.90
    return round(min(ceiling, value), 2)


def counterfactuals(findings: list[Finding], limit: int = 3) -> list[dict]:
    """How much does each finding contribute to the raw risk total?

    We deliberately use the uncapped weighted sum here: with a 100-point cap,
    removing one finding usually leaves the score pinned at 100 and hides the
    contribution. The verdict score stays capped; the counterfactual shows the
    underlying risk points.
    """
    base = int(round(_weighted_sum(findings)))
    ranked = sorted(findings, key=lambda f: SEVERITY_WEIGHT[f.severity], reverse=True)
    results: list[dict] = []
    for finding in ranked:
        if SEVERITY_WEIGHT[finding.severity] == 0:
            continue
        remaining = [f for f in findings if f.id != finding.id]
        without = int(round(_weighted_sum(remaining)))
        delta = base - without
        if delta <= 0:
            continue
        results.append(
            {
                "finding_id": finding.id,
                "title": finding.title,
                "base_risk": base,
                "risk_without": without,
                "delta": delta,
            }
        )
        if len(results) >= limit:
            break
    return results


def build_verdict(
    findings: list[Finding],
    info: PEInfo | None = None,
    strings: StringsResult | None = None,
    imports: ImportAnalysis | None = None,
    *,
    parse_error: str | None = None,
    static_only: bool = True,
    sneakiness: int | None = None,
    sneakiness_reasons: list[str] | None = None,
    signed: bool = False,
) -> Verdict:
    if sneakiness is None:
        if info is not None and strings is not None and imports is not None:
            sneakiness, reasons = compute_sneakiness(info, strings, imports)
        else:
            sneakiness, reasons = 0, []
    else:
        reasons = list(sneakiness_reasons or [])

    if parse_error or (info is not None and not info.is_pe):
        return Verdict(
            label=VerdictLabel.INCONCLUSIVE,
            score=0,
            confidence=0.0,
            sneakiness=sneakiness,
            summary=f"Could not parse the file as a PE: {parse_error or 'unknown error'}.",
            next_steps=["Verify the file is a valid Windows executable.", "Try a known-good PE for comparison."],
            counterfactuals=[],
            sneakiness_reasons=reasons,
            mitigations=[],
            static_only=static_only,
        )

    score = min(100, int(round(_weighted_sum(findings))))
    mitigations: list[str] = []
    signature_present = signed or bool(info is not None and info.signature_present)
    if signature_present and score > 0:
        discount = min(20, score)
        score = max(0, score - discount)
        mitigations.append(
            f"Authenticode signature present: -{discount} risk point(s) "
            "(presence is not a validity or trust check)"
        )

    label = _label(score)
    confidence = _confidence(findings, static_only=static_only)

    high = [f for f in findings if SEVERITY_RANK[f.severity] >= 3]
    mode = "Static" if static_only else "Static and emulated"
    if label is VerdictLabel.MALICIOUS:
        summary = (
            f"{mode} evidence is consistent with malware: {len(high)} high/critical findings "
            f"across {len({f.category for f in findings})} evidence categories."
        )
    elif label is VerdictLabel.SUSPICIOUS:
        summary = (
            f"{mode} evidence shows suspicious capabilities ({len(high)} high/critical findings). "
            + ("Behavioral confirmation is needed." if static_only else "Review the attempted behavior.")
        )
    else:
        summary = f"{mode} evidence shows no strong indicators. This is not a guarantee of safety."
    if mitigations:
        summary += " " + "; ".join(mitigations) + "."

    steps: list[str] = []
    if info is not None:
        if info.packer_hint:
            steps.append("Unpack the sample and re-run static analysis (Phase 3).")
        if info.installer_hint:
            steps.append("Extract the installer payloads and analyze them separately.")
        if info.is_dotnet:
            steps.append("Add IL-level analysis for this .NET assembly.")
        if info.embedded_pe:
            steps.append("Extract the embedded PE resource and queue it as a child case.")
    if static_only:
        steps.append("Run emulation to turn static capabilities into attempted behavior.")
    else:
        steps.append("Correlate attempted behavior with static findings and review the evidence IDs.")
    if label in (VerdictLabel.SUSPICIOUS, VerdictLabel.MALICIOUS) and not static_only:
        steps.append("Confirm in an isolated VM if available (observed evidence).")
    if not steps:
        steps.append("No immediate action; keep the case for comparison.")

    return Verdict(
        label=label,
        score=score,
        confidence=confidence,
        sneakiness=sneakiness,
        summary=summary,
        techniques=[],
        next_steps=steps,
        counterfactuals=counterfactuals(findings),
        sneakiness_reasons=reasons,
        mitigations=mitigations,
        static_only=static_only,
    )
