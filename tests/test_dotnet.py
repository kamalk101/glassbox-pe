from pathlib import Path

import pytest

from glassbox.analyzer import analyze_static
from glassbox.ingest import ingest
from glassbox.static import dotnet
from glassbox.static.dotnet import DotNetAnalysis, analyze
from tests.fixtures.make_pe import build_pe


def test_non_dotnet_analysis_is_disabled():
    result = analyze(b"not a pe", is_dotnet=False)

    assert result.is_dotnet is False
    assert result.parsed is False
    assert result.indicators == []


def test_native_pe_reports_dotnet_parse_failure(tmp_path):
    result = analyze(build_pe(imports=["CreateFileA"]), is_dotnet=True)

    assert result.is_dotnet is True
    assert result.parsed is False
    assert result.error


def test_optional_public_nuget_corpus(tmp_path):
    sample = Path("corpus/benign-installers/nuget.exe")
    if not sample.is_file():
        pytest.skip("optional public installer corpus is not downloaded")

    result = analyze(sample.read_bytes(), is_dotnet=True)

    assert result.parsed is True
    assert "mscorlib" in result.referenced_frameworks
    assert "ProcessStartInfo" in result.process_markers


def test_optional_public_nuget_scan_stays_clean(tmp_path):
    sample = Path("corpus/benign-installers/nuget.exe")
    if not sample.is_file():
        pytest.skip("optional public installer corpus is not downloaded")
    target = tmp_path / "nuget.exe"
    target.write_bytes(sample.read_bytes())

    case = analyze_static(ingest(target))

    assert case.artifacts["dotnet"]["parsed"] is True
    assert any(finding.rule_id == "GB-DN-002" for finding in case.findings)
    assert case.verdict is not None
    assert case.verdict.label.value == "clean"
