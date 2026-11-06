from glassbox.analyzer import analyze_static
from glassbox.emu import DroppedFile, EmulationOutcome, apply_emulation
from glassbox.emu.apply import _pointer_target
from glassbox.ingest import ingest
from glassbox.schema import Source, Strength
from glassbox.static.imports import classify_api
from glassbox.static.pe import parse_pe
from tests.fixtures.make_pe import build_pe
from tests.fixtures.speakeasy_reports import network_registry_report


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


def _image_pointer(data: bytes, info, needle: bytes) -> int:
    offset = data.index(needle)
    for section in info.sections:
        if section.raw_pointer <= offset < section.raw_pointer + section.raw_size:
            return info.image_base + section.virtual_address + offset - section.raw_pointer
    raise AssertionError(f"{needle!r} was not found in a section")


def test_pointer_target_resolves_ascii_strings_in_image():
    data = build_pe()
    info = parse_pe(data)
    pointer = _image_pointer(data, info, b"http://bad.example/gate.php")

    target, resolved = _pointer_target([hex(pointer)], data, info)

    assert target == "http://bad.example/gate.php"
    assert resolved == ["http://bad.example/gate.php"]


def test_apply_emulation_uses_resolved_pointer_as_event_target(tmp_path):
    data = build_pe()
    sample = tmp_path / "sample.exe"
    sample.write_bytes(data)
    info = parse_pe(data)
    pointer = _image_pointer(data, info, b"http://bad.example/gate.php")

    case = analyze_static(ingest(sample))
    report = _report()
    for call in report["entry_points"][0]["apis"]:
        if call["api_name"] == "KERNEL32.InternetOpenA":
            call["args"] = [hex(pointer)]
            break
    outcome = EmulationOutcome(ran=True, report=report, report_path=str(tmp_path / "report.json"))

    apply_emulation(case, outcome)

    event = next(e for e in case.events if e.action == "InternetOpenA")
    assert event.target == "http://bad.example/gate.php"
    assert event.data["resolved_args"] == ["http://bad.example/gate.php"]
    assert event.data["args"] == [hex(pointer)]


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


def test_apply_emulation_summarizes_resolved_resources(tmp_path):
    data = build_pe()
    sample = tmp_path / "sample.exe"
    sample.write_bytes(data)
    info = parse_pe(data)
    registry = b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    drop_path = b"C:\\Users\\Public\\svchost.exe"

    case = analyze_static(ingest(sample))
    report = _report()
    for call in report["entry_points"][0]["apis"]:
        if call["api_name"] == "ADVAPI32.RegSetValueExA":
            call["args"] = [hex(_image_pointer(data, info, registry))]
        elif call["api_name"] == "KERNEL32.CreateFileA":
            call["args"] = [hex(_image_pointer(data, info, drop_path))]
    outcome = EmulationOutcome(ran=True, report=report, report_path=str(tmp_path / "report.json"))

    apply_emulation(case, outcome)

    assert case.artifacts["emulation"]["resources"]["registry"] == [
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    ]
    assert case.artifacts["emulation"]["resources"]["file"] == [
        "C:\\Users\\Public\\svchost.exe"
    ]


def test_apply_emulation_covers_all_behavior_categories(tmp_path):
    data = build_pe()
    sample = tmp_path / "sample.exe"
    sample.write_bytes(data)
    info = parse_pe(data)
    case = analyze_static(ingest(sample))

    url = b"http://bad.example/gate.php"
    file_path = b"C:\\Users\\Public\\svchost.exe"
    registry_key = b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

    report = _report()
    calls = report["entry_points"][0]["apis"]
    for call in calls:
        if call["api_name"] == "KERNEL32.CreateRemoteThread":
            call["args"] = [hex(_image_pointer(data, info, url))]
        elif call["api_name"] == "KERNEL32.CreateFileA":
            call["args"] = [hex(_image_pointer(data, info, file_path))]
        elif call["api_name"] == "KERNEL32.WriteFile":
            call["args"] = ["0x3", hex(_image_pointer(data, info, file_path))]
        elif call["api_name"] == "KERNEL32.InternetOpenA":
            call["args"] = [hex(_image_pointer(data, info, url))]
        elif call["api_name"] == "ADVAPI32.RegSetValueExA":
            call["args"] = [hex(_image_pointer(data, info, registry_key))]

    # Add read-only registry access to exercise the new registry-read category.
    calls.append(
        {
            "api_name": "ADVAPI32.RegOpenKeyExA",
            "args": [hex(_image_pointer(data, info, registry_key))],
            "ret_val": "0x0",
            "pc": "0x1060",
        }
    )

    dropped = tmp_path / "dropped.exe"
    dropped.write_bytes(b"MZ" + b"\x00" * 32)
    outcome = EmulationOutcome(
        ran=True,
        report=report,
        report_path=str(tmp_path / "report.json"),
        dropped_files=[DroppedFile(path=str(dropped), size=dropped.stat().st_size, sha256="0" * 64)],
    )

    apply_emulation(case, outcome)

    categories = {e.category.value for e in case.events if e.source is Source.EMULATION}
    assert {"process", "file", "network", "registry", "pe"} <= categories
    resources = case.artifacts["emulation"]["resources"]
    assert "C:\\Users\\Public\\svchost.exe" in resources["file"]
    assert "http://bad.example/gate.php" in resources["network"]
    assert "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" in resources["registry"]

    rule_ids = {f.rule_id for f in case.findings}
    assert "GB-EMU-001" in rule_ids
    assert "GB-EMU-002" in rule_ids
    assert "GB-EMU-003" in rule_ids
    assert "GB-EMU-006" in rule_ids
    assert "GB-EMU-010" in rule_ids
    assert "GB-EMU-011" in rule_ids
    assert "GB-EMU-012" in rule_ids


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


def test_network_registry_report_exercises_all_categories(tmp_path):
    case = _static_case(tmp_path)
    dropped = tmp_path / "dropped.exe"
    dropped.write_bytes(b"MZ" + b"\x00" * 32)
    report = network_registry_report()
    outcome = EmulationOutcome(
        ran=True,
        report=report,
        report_path=str(tmp_path / "report.json"),
        dropped_files=[DroppedFile(path=str(dropped), size=dropped.stat().st_size, sha256="0" * 64)],
    )

    apply_emulation(case, outcome)

    categories = {e.category.value for e in case.events if e.source is Source.EMULATION}
    assert {"process", "file", "network", "registry", "pe", "other"} <= categories

    resources = case.artifacts["emulation"]["resources"]
    assert "C:\\Users\\Public\\svchost.exe" in resources["file"]
    assert "http://bad.example/gate.php" in resources["network"]
    assert "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" in resources["registry"]

    rule_ids = {f.rule_id for f in case.findings}
    # Low-level attempted findings are suppressed when static analysis already
    # established the same capability (for example execution, dynamic loading,
    # or anti-analysis). High- and medium-confidence attempted behaviour and
    # file/registry-query signals are still recorded.
    assert {
        "GB-EMU-001",
        "GB-EMU-002",
        "GB-EMU-003",
        "GB-EMU-006",
        "GB-EMU-008",
        "GB-EMU-009",
        "GB-EMU-010",
        "GB-EMU-011",
        "GB-EMU-012",
    } <= rule_ids

    assert case.artifacts["emulation"]["api_calls"] == 15
    assert case.artifacts["emulation"]["dropped_files"]
