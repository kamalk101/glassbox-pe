from glassbox.analyzer import analyze_static
from glassbox.ingest import ingest
from glassbox.static import imports as imports_mod
from glassbox.static import pe as pe_mod
from glassbox.static import strings as strings_mod
from tests.fixtures.make_pe import build_pe


def _analyze(tmp_path, data: bytes):
    path = tmp_path / "sample.exe"
    path.write_bytes(data)
    return analyze_static(ingest(path))


def test_parse_pe_structure():
    info = pe_mod.parse_pe(build_pe())

    assert info.is_pe
    assert info.parse_error is None
    assert info.machine_name == "x86-64"
    assert info.subsystem_name == "console"
    assert len(info.sections) == 2
    assert info.entry_section == ".text"
    assert info.entry_in_executable_section
    assert "KERNEL32.dll" in info.imports
    assert "VirtualAllocEx" in info.all_import_functions()
    assert not info.signature_present
    assert info.packer_hint is None


def test_parse_pe_rejects_garbage():
    info = pe_mod.parse_pe(b"this is not a pe file")
    assert not info.is_pe
    assert info.parse_error


def test_strings_and_iocs():
    result = strings_mod.extract(build_pe())

    assert any("bad.example" in url for url in result.iocs["urls"])
    assert "203.0.113.9" in result.iocs["ips"]
    assert any("currentversion\\run" in key.lower() for key in result.iocs["registry_keys"])
    assert "cmd.exe" in result.commands
    assert "powershell" in result.commands


def test_import_grouping():
    info = pe_mod.parse_pe(build_pe())
    analysis = imports_mod.analyze(info.imports, info.ordinal_imports)

    assert "OpenProcess" in analysis.groups["process_injection"]
    assert "RegSetValueExA" in analysis.groups["persistence"]
    assert "InternetOpenA" in analysis.groups["network"]
    assert "IsDebuggerPresent" in analysis.groups["anti_analysis"]


def test_static_analysis_correlates_findings(tmp_path):
    case = _analyze(tmp_path, build_pe())

    assert case.verdict is not None
    assert case.verdict.label.value in {"suspicious", "malicious"}
    assert case.verdict.score > 0
    assert case.verdict.confidence <= 0.8
    assert len(case.events) > 10

    rule_ids = {finding.rule_id for finding in case.findings}
    assert "GB-PROC-001" in rule_ids  # injection
    assert "GB-REG-001" in rule_ids   # persistence
    assert "GB-NET-002" in rule_ids   # download + execute
    assert "GB-PE-016" in rule_ids    # anti-analysis
    assert "GB-FILE-001" in rule_ids  # dropped executable path

    event_ids = {event.id for event in case.events}
    for finding in case.findings:
        assert set(finding.evidence) <= event_ids

    assert case.techniques()
    assert case.verdict.counterfactuals


def test_packed_detection(tmp_path):
    case = _analyze(tmp_path, build_pe(packed=True))

    assert case.artifacts["pe"]["packer"] == "upx0"
    assert any(finding.rule_id == "GB-PE-002" for finding in case.findings)
    assert case.verdict.sneakiness >= 25


def test_minimal_clean_sample(tmp_path):
    data = build_pe(imports=["CreateFileA", "WriteFile"], strings=["hello world"])
    case = _analyze(tmp_path, data)

    assert case.verdict is not None
    assert case.verdict.label.value == "clean"
    assert not any(f.rule_id == "GB-PROC-001" for f in case.findings)
