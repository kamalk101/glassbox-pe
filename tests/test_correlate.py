from glassbox.analyzer import analyze_static
from glassbox.correlate import correlate
from glassbox.ingest import ingest
from glassbox.schema import Category, Severity, Source, Strength
from tests.fixtures.make_pe import build_pe


def _analyzed(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe())
    return analyze_static(ingest(sample))


def test_correlation_marks_technique_corroborated(tmp_path):
    case = _analyzed(tmp_path)
    attempted = case.add_event(
        Category.PROCESS,
        "CreateRemoteThread",
        target="notepad.exe",
        source=Source.EMULATION,
        strength=Strength.ATTEMPTED,
        technique="T1055",
    )
    case.add_finding(
        rule_id="GB-EMU-001",
        title="Attempted process injection (emulation)",
        severity=Severity.HIGH,
        description="test",
        category=Category.PROCESS,
        evidence=[attempted.id],
        techniques=["T1055"],
        source=Source.EMULATION,
    )

    result = correlate(case)

    assert "T1055" in result["corroborated_techniques"]
    row = next(item for item in result["techniques"] if item["technique"] == "T1055")
    assert row["status"] == "corroborated"
    assert row["strengths"] == ["attempted", "static"]
    assert attempted.id in row["event_ids"]
    assert result["by_strength"]["attempted"] == 1
    assert result["by_strength"]["static"] >= 1
    assert result["coverage"] == 1.0
    assert result["findings_without_evidence"] == []


def test_correlation_reports_unlinked_findings(tmp_path):
    case = _analyzed(tmp_path)
    finding = case.add_finding(
        rule_id="GB-TEST-001",
        title="No evidence",
        severity=Severity.LOW,
        description="test",
        category=Category.OTHER,
        evidence=["evt-9999"],
        techniques=["T9999"],
    )

    result = correlate(case)

    assert finding.id in result["findings_without_evidence"]
    assert "T9999" in result["static_only_techniques"]
    assert result["coverage"] < 1.0
