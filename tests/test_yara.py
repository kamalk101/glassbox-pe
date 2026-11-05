from pathlib import Path

import pytest

from glassbox.analyzer import analyze_static
from glassbox.ingest import ingest
from glassbox.static import yara as yara_mod
from tests.fixtures.make_pe import build_pe

pytest.importorskip("yara")


def _analyze(tmp_path, data: bytes, rules=None):
    path = tmp_path / "sample.exe"
    path.write_bytes(data)
    return analyze_static(ingest(path), yara_rules=rules)


def test_builtin_yara_rule_matches_and_links_evidence(tmp_path):
    case = _analyze(
        tmp_path,
        build_pe(strings=["sekurlsa::logonpasswords", "ordinary code"]),
    )

    assert case.artifacts["yara"]["available"] is True
    assert case.artifacts["yara"]["matches"]
    match = case.artifacts["yara"]["matches"][0]
    assert match["rule"] == "GB_YARA_CREDENTIAL_THEFT"
    assert match["strings"][0]["offset"] > 0

    finding = next(finding for finding in case.findings if finding.rule_id == "GB-YARA-001")
    assert finding.severity.value == "critical"
    assert finding.techniques == ["T1003.001"]
    event = next(event for event in case.events if event.id == finding.evidence[0])
    assert event.action == "yara_match"
    assert event.target == "GB_YARA_CREDENTIAL_THEFT"


def test_clean_sample_has_no_yara_match(tmp_path):
    case = _analyze(
        tmp_path,
        build_pe(imports=["CreateFileA", "ReadFile"], strings=["ordinary helper"]),
    )

    assert case.artifacts["yara"]["available"] is True
    assert case.artifacts["yara"]["matches"] == []
    assert not any(finding.rule_id.startswith("GB-YARA-") for finding in case.findings)


def test_custom_yara_rule_path(tmp_path):
    rule_file = tmp_path / "custom.yar"
    rule_file.write_text(
        """
rule CUSTOM_MARKER
{
    meta:
        gb_rule_id = "GB-YARA-999"
        title = "Custom marker"
        severity = "low"
        category = "other"
        technique = "T9999"
    strings:
        $a = "GLASSBOX-CUSTOM-MARKER" ascii
    condition:
        $a
}
""",
        encoding="utf-8",
    )
    case = _analyze(tmp_path, build_pe(strings=["GLASSBOX-CUSTOM-MARKER"]), rules=[rule_file])

    assert any(match["rule"] == "CUSTOM_MARKER" for match in case.artifacts["yara"]["matches"])
    assert any(finding.rule_id == "GB-YARA-999" for finding in case.findings)


def test_yara_scan_reports_missing_rule_directory(tmp_path):
    result = yara_mod.scan_bytes(b"not a pe", rule_paths=[tmp_path / "missing"])

    assert result.available is False
    assert "no YARA rule files" in (result.error or "")
