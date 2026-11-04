import json

from click.testing import CliRunner

from glassbox.cli import cli
from tests.fixtures.make_pe import build_pe


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


def test_cli_stub_commands(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe())
    runner = CliRunner()

    result = runner.invoke(cli, ["unpack", str(sample)])
    assert result.exit_code == 3


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
