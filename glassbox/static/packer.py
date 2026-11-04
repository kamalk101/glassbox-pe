"""Packer detection (UPX, ASPack, MPRESS, VMProtect, and heuristics)."""

from __future__ import annotations

from dataclasses import dataclass, field

from .pe import PEInfo

# label -> (section names, raw markers, is_upx)
KNOWN_PACKERS = {
    "UPX": ({"upx0", "upx1", "upx2", "upx!"}, {"UPX!", "UPX0", "UPX1"}, True),
    "ASPack": ({".aspack", ".adata"}, {"ASPack"}, False),
    "MPRESS": ({".mpress1", ".mpress2"}, {"MPRESS"}, False),
    "Themida": ({".themida"}, {"Themida"}, False),
    "VMProtect": ({".vmp0", ".vmp1", ".vmp2"}, {"VMProtect"}, False),
    "Enigma": ({".enigma1", ".enigma2"}, {"Enigma"}, False),
    "Petite": ({"petite", ".petite"}, {"Petite"}, False),
    "NsPack": ({".nsp0", ".nsp1"}, {"NsPack"}, False),
}


@dataclass
class PackerInfo:
    name: str | None = None
    confidence: str = "none"  # none / low / medium / high
    upx: bool = False
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "confidence": self.confidence,
            "upx": self.upx,
            "evidence": self.evidence,
        }


def detect(data: bytes, info: PEInfo) -> PackerInfo:
    if not info.is_pe:
        return PackerInfo()

    names = {section.name.strip().lower() for section in info.sections}
    evidence: list[str] = []

    for label, (section_names, markers, is_upx) in KNOWN_PACKERS.items():
        hits = sorted(names & section_names)
        marker_hits = [marker for marker in markers if marker.encode("ascii", "ignore") in data]
        if hits or marker_hits:
            if hits:
                evidence.append(f"section names: {', '.join(hits)}")
            if marker_hits:
                evidence.append(f"markers: {', '.join(sorted(marker_hits))}")
            return PackerInfo(name=label, confidence="high", upx=is_upx, evidence=evidence)

    high_entropy = [section for section in info.sections if section.entropy > 7.2]
    if high_entropy and info.imports_count < 10:
        evidence.append(
            "high-entropy section(s): "
            + ", ".join(f"{s.name}={s.entropy}" for s in high_entropy[:3])
        )
        evidence.append(f"only {info.imports_count} imported function(s)")
        return PackerInfo(
            name="Unknown packer (high entropy, low imports)",
            confidence="medium",
            upx=False,
            evidence=evidence,
        )

    return PackerInfo()
