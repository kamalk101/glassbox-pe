from glassbox.schema import (
    Case,
    Category,
    Event,
    Finding,
    Severity,
    Source,
    Strength,
    Verdict,
    VerdictLabel,
)


def test_case_roundtrip():
    case = Case(
        case_id="abc123",
        file_name="sample.exe",
        file_path="/tmp/sample.exe",
        size=1024,
        hashes={"sha256": "abc123"},
        file_type="pe",
        created_at="2026-01-01T00:00:00+00:00",
    )
    event = case.add_event(Category.PROCESS, "CreateProcess", target="cmd.exe")
    finding = case.add_finding(
        "GB-TEST-001",
        "Test finding",
        Severity.HIGH,
        "description",
        Category.PROCESS,
        evidence=[event.id],
        techniques=["T1059"],
    )
    case.verdict = Verdict(
        label=VerdictLabel.SUSPICIOUS,
        score=42,
        confidence=0.7,
        sneakiness=55,
        summary="test",
        techniques=["T1059"],
        next_steps=["run emulation"],
        counterfactuals=[{"finding_id": finding.id, "title": "x", "score_without": 10, "delta": 32}],
        static_only=True,
    )

    raw = case.to_dict()
    restored = Case.from_dict(raw)

    assert restored.case_id == case.case_id
    assert restored.events[0].category is Category.PROCESS
    assert restored.findings[0].severity is Severity.HIGH
    assert restored.verdict.label is VerdictLabel.SUSPICIOUS
    assert restored.verdict.counterfactuals[0]["delta"] == 32
    assert restored.events[0].source is Source.STATIC
    assert restored.events[0].strength is Strength.STATIC


def test_event_roundtrip():
    event = Event(
        id="evt-0001",
        category=Category.NETWORK,
        action="http_post",
        target="https://example.test",
        data={"bytes": 1},
        source=Source.EMULATION,
        strength=Strength.ATTEMPTED,
        technique="T1071.001",
    )
    assert Event.from_dict(event.to_dict()).to_dict() == event.to_dict()


def test_finding_roundtrip():
    finding = Finding(
        id="fnd-001",
        rule_id="GB-TEST",
        title="t",
        severity=Severity.CRITICAL,
        description="d",
        category=Category.PE,
        evidence=["evt-0001"],
        techniques=["T1055"],
        confidence=0.9,
    )
    assert Finding.from_dict(finding.to_dict()).to_dict() == finding.to_dict()
