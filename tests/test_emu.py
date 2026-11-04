from glassbox.analyzer import analyze_static
from glassbox.emu import DroppedFile, EmulationOutcome, apply_emulation
from glassbox.ingest import ingest
from glassbox.schema import Source, Strength
from glassbox.static.imports import classify_api
from tests.fixtures.make_pe import build_pe


def _static_case(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe())
    return analyze_static(ingest(sample))


def _report():
    return {
        "emu_version": "test",
        "arch": "x64",
        "os_run": "windows.6_1",
        "emulation_total_runtime": 1.25,
        "entry_points": [
            {
                "apis": [
                    {"api_name": "KERNEL32.CreateRemoteThread", "args": ["0x1"], "ret_val": "0x0", "pc": "0x1000"},
                    {"api_name": "KERNEL32.WriteProcessMemory", "args": ["0x2"], "ret_val": "0x1", "pc": "0x1010"},
                    {"api_name": "KERNEL32.CreateFileA", "args": ["0x2000"], "ret_val": "0x3", "pc": "0x1020"},
                    {"api_name": "KERNEL32.WriteFile", "args": ["0x3", "0x2000"], "ret_val": "0x1", "pc": "0x1030"},
                    {"api_name": "KERNEL32.InternetOpenA", "args": ["0x3000"], "ret_val": "0x4", "pc": "0x1040"},
                    {"api_name": "ADVAPI32.RegSetValueExA", "args": ["0x5"], "ret_val": "0x0", "pc": "0x1050"},
                ],
                "dynamic_code_segments": [{"addr": "0x3000", "size": 128}],
            }
        ],
    }


def test_classify_speakeasy_api_name():
    assert "file" in classify_api("KERNEL32.CreateFileA")
    assert "process_injection" in classify_api("KERNEL32.CreateRemoteThread")
    assert classify_api("MSVCRT._initterm") == []


def test_apply_emulation_adds_attempted_evidence(tmp_path):
    case = _static_case(tmp_path)
    dropped = tmp_path / "dropped.exe"
    dropped.write_bytes(b"MZ" + b"\x00" * 32)
    outcome = EmulationOutcome(
        ran=True,
        report=_report(),
        report_path=str(tmp_path / "report.json"),
        dropped_files=[DroppedFile(path=str(dropped), size=dropped.stat().st_size, sha256="0" * 64)],
    )

    apply_emulation(case, outcome)

    emu_events = [e for e in case.events if e.source is Source.EMULATION]
    assert emu_events
    assert all(e.strength is Strength.ATTEMPTED for e in emu_events)
    assert any(e.action == "CreateRemoteThread" for e in emu_events)
    assert any(e.action == "dropped_file" for e in emu_events)

    rule_ids = {f.rule_id for f in case.findings}
    assert "GB-EMU-001" in rule_ids  # process injection
    assert "GB-EMU-002" in rule_ids  # persistence
    assert "GB-EMU-003" in rule_ids  # network
    assert "GB-EMU-006" in rule_ids  # file write
    assert "GB-EMU-010" in rule_ids  # dropped file
    assert "GB-EMU-011" in rule_ids  # dynamic code

    assert case.verdict is not None
    assert case.verdict.static_only is False
    assert case.verdict.confidence <= 0.90
    assert case.artifacts["emulation"]["api_calls"] == 6
    assert case.artifacts["emulation"]["dropped_files"]


def test_apply_emulation_is_idempotent(tmp_path):
    case = _static_case(tmp_path)
    outcome = EmulationOutcome(ran=True, report=_report(), report_path=str(tmp_path / "report.json"))

    apply_emulation(case, outcome)
    event_count = len(case.events)
    finding_count = len(case.findings)
    emu_event_count = len([e for e in case.events if e.source is Source.EMULATION])

    apply_emulation(case, outcome)

    assert len(case.events) == event_count
    assert len(case.findings) == finding_count
    assert len([e for e in case.events if e.source is Source.EMULATION]) == emu_event_count


def test_apply_emulation_without_report_keeps_static_case(tmp_path):
    case = _static_case(tmp_path)
    before = case.verdict.to_dict()
    apply_emulation(case, EmulationOutcome(ran=False, error="not installed"))
    assert case.verdict.to_dict() == before
    assert any("emulation" in error for error in case.errors)
