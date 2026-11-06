import json
from pathlib import Path

from click.testing import CliRunner

from glassbox.cli import cli
from tests.fixtures.make_pe import DEFAULT_IMPORTS, build_pe


def test_cli_scan_json(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe())
    cases = tmp_path / "cases"

    result = CliRunner().invoke(
        cli,
        ["scan", str(sample), "--json", "--cases-dir", str(cases)],
    )

    assert result.exit_code in (1, 2), result.output
    payload = json.loads(result.output)
    assert payload["file_name"] == "sample.exe"
    assert payload["verdict"]["label"] in {"suspicious", "malicious"}
    assert (cases / payload["case_id"] / "case.json").is_file()


def test_cli_scan_is_cached(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe())
    cases = tmp_path / "cases"
    runner = CliRunner()

    first = runner.invoke(cli, ["scan", str(sample), "--json", "--cases-dir", str(cases)])
    second = runner.invoke(cli, ["scan", str(sample), "--json", "--cases-dir", str(cases)])

    assert first.exit_code == second.exit_code
    assert json.loads(first.output)["case_id"] == json.loads(second.output)["case_id"]


def test_cli_cases_list_and_show(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe())
    cases = tmp_path / "cases"
    runner = CliRunner()

    scan = runner.invoke(cli, ["scan", str(sample), "--json", "--cases-dir", str(cases)])
    case_id = json.loads(scan.output)["case_id"]

    listed = runner.invoke(cli, ["cases", "list", "--cases-dir", str(cases)])
    assert listed.exit_code == 0
    assert case_id[:12] in listed.output

    shown = runner.invoke(
        cli, ["cases", "show", case_id[:12], "--json", "--cases-dir", str(cases)]
    )
    assert shown.exit_code == 0
    assert json.loads(shown.output)["case_id"] == case_id


def test_cli_rules_list():
    result = CliRunner().invoke(cli, ["rules", "list"])
    assert result.exit_code == 0
    assert "GB-PROC-001" in result.output


def test_cli_report_html(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe())
    cases = tmp_path / "cases"
    runner = CliRunner()

    scan = runner.invoke(cli, ["scan", str(sample), "--json", "--cases-dir", str(cases)])
    case_id = json.loads(scan.output)["case_id"]

    report = runner.invoke(
        cli,
        ["report", case_id, "--html", "--cases-dir", str(cases)],
    )

    assert report.exit_code == 0, report.output
    target = Path(report.output.strip())
    assert target.is_file()
    content = target.read_text(encoding="utf-8")
    assert content.startswith("<!doctype html>")
    assert case_id in content
    assert "Evidence events" in content

    both = runner.invoke(
        cli,
        ["report", case_id, "--html", "--json", "--cases-dir", str(cases)],
    )
    assert both.exit_code == 3


def test_cli_dashboard_and_case_reports(tmp_path):
    clean = tmp_path / "clean.exe"
    clean.write_bytes(
        build_pe(
            imports=["CreateFileA", "ReadFile", "CloseHandle"],
            strings=["ordinary helper"],
        )
    )
    suspicious = tmp_path / "suspicious.exe"
    suspicious.write_bytes(build_pe())
    cases = tmp_path / "cases"
    runner = CliRunner()

    for sample in (clean, suspicious):
        runner.invoke(cli, ["scan", str(sample), "--json", "--cases-dir", str(cases)])

    result = runner.invoke(cli, ["dashboard", "--cases-dir", str(cases), "--reports"])

    assert result.exit_code == 0, result.output
    target = Path(result.output.splitlines()[0])
    assert target.name == "index.html"
    assert target.is_file()
    content = target.read_text(encoding="utf-8")
    assert "Case index" in content
    assert "clean.exe" in content
    assert "suspicious.exe" in content
    assert "label-clean" in content
    assert "label-malicious" in content
    assert 'id="search"' in content
    assert "Activity timeline" in content
    assert "Verdicts by day" in content
    assert "Unpack status" in content
    assert "average sneakiness" in content
    assert "reports generated" in content
    assert "timeline-item" in content
    assert "wrote 2 case report(s)" in result.output

    report_files = list(cases.glob("*/report.html"))
    assert len(report_files) == 2


def test_cli_unpack_not_packed(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe())
    runner = CliRunner()

    result = runner.invoke(cli, ["unpack", str(sample)])

    assert result.exit_code == 0
    assert "no known packer" in (result.output + getattr(result, "stderr", ""))


def test_cli_unpack_upx_with_fake_tool(tmp_path):
    packed = tmp_path / "packed.exe"
    packed.write_bytes(build_pe(packed=True))
    unpacked_source = tmp_path / "unpacked-source.exe"
    unpacked_source.write_bytes(
        build_pe(
            imports=DEFAULT_IMPORTS + ["SetWindowsHookExA"],
            strings=["hello from the unpacked payload"],
        )
    )

    import sys

    from tests.fixtures.fake_upx import make_fake_upx

    fake = make_fake_upx(tmp_path)

    cases = tmp_path / "cases"
    runner = CliRunner()
    env = {"GLASSBOX_UPX": str(fake), "FAKE_UNPACKED": str(unpacked_source)}

    result = runner.invoke(
        cli,
        ["unpack", str(packed), "--json", "--cases-dir", str(cases)],
        env=env,
    )

    assert result.exit_code in (1, 2), result.output
    payload = json.loads(result.output)
    unpack = payload["artifacts"]["unpack"]
    assert unpack["status"] == "unpacked"
    assert unpack["method"] == "upx"
    assert "SetWindowsHookExA" in unpack["diff"]["new_imports"]
    assert "GB-UNP-001" in {finding["rule_id"] for finding in payload["findings"]}
    assert (cases / unpack["diff"]["child_case_id"] / "case.json").is_file()
    assert (cases / payload["case_id"] / "unpacked").is_dir()

    # Re-running the same unpack must replace, not duplicate, its event/finding.
    again = runner.invoke(
        cli,
        ["unpack", str(packed), "--json", "--cases-dir", str(cases)],
        env=env,
    )
    assert again.exit_code in (1, 2), again.output
    repeated = json.loads(again.output)
    assert [f["rule_id"] for f in repeated["findings"]].count("GB-UNP-001") == 1
    assert [e["action"] for e in repeated["events"]].count("unpacked") == 1


def test_cli_emu_and_analyze(tmp_path):
    import pytest

    pytest.importorskip("speakeasy")

    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe())
    cases = tmp_path / "cases"
    runner = CliRunner()

    for command in ("emu", "analyze"):
        result = runner.invoke(
            cli,
            [command, str(sample), "--json", "--timeout", "2", "--cases-dir", str(cases)],
        )
        assert result.exit_code in (1, 2), result.output
        payload = json.loads(result.output)
        assert payload["artifacts"]["emulation"]["ran"] is True
        assert payload["verdict"]["static_only"] is False
