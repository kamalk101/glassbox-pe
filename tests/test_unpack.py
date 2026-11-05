from pathlib import Path

from glassbox.analyzer import analyze_static
from glassbox.ingest import ingest
from glassbox.static.packer import PackerInfo
from glassbox.unpack import diff_cases, unpack_sample
from glassbox.unpack.service import UnpackResult
from tests.fixtures.make_pe import DEFAULT_IMPORTS, build_pe


def _fake_upx(tmp_path: Path) -> Path:
    script = tmp_path / "fake-upx"
    script.write_text(
        """#!/bin/sh
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; else shift; fi
done
cp "$FAKE_UNPACKED" "$out"
""",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _write_sample(path: Path, **kwargs) -> Path:
    path.write_bytes(build_pe(**kwargs))
    return path


def test_unpack_upx_with_fake_tool(tmp_path, monkeypatch):
    packed = _write_sample(tmp_path / "packed.exe", packed=True)
    unpacked = _write_sample(
        tmp_path / "unpacked-source.exe",
        imports=DEFAULT_IMPORTS + ["SetWindowsHookExA"],
        strings=["hello from the unpacked payload"],
    )
    fake = _fake_upx(tmp_path)
    monkeypatch.setenv("GLASSBOX_UPX", str(fake))
    monkeypatch.setenv("FAKE_UNPACKED", str(unpacked))

    output = tmp_path / "out" / "unpacked.exe"
    result = unpack_sample(packed, output)

    assert isinstance(result, UnpackResult)
    assert result.status == "unpacked"
    assert result.success is True
    assert result.method == "upx"
    assert result.packer.name == "UPX"
    assert result.output_path == str(output)
    assert output.is_file()
    assert output.read_bytes()[:2] == b"MZ"


def test_unpack_rejects_output_equal_to_input(tmp_path):
    packed = _write_sample(tmp_path / "packed.exe", packed=True)

    result = unpack_sample(packed, packed)

    assert result.status == "failed"
    assert "differ" in (result.error or "")
    assert packed.is_file()


def test_unpack_reports_not_packed(tmp_path):
    sample = _write_sample(tmp_path / "plain.exe")

    result = unpack_sample(sample, tmp_path / "out.exe")

    assert result.status == "not_packed"
    assert result.success is False


def test_unpack_reports_unsupported_packer(tmp_path):
    sample = _write_sample(tmp_path / "plain.exe")
    packer = PackerInfo(name="Themida", confidence="high", upx=False)

    result = unpack_sample(sample, tmp_path / "out.exe", packer=packer)

    assert result.status == "unsupported"
    assert "Themida" in (result.error or "")
    assert result.packer.name == "Themida"


def test_unpack_reports_missing_tool(tmp_path, monkeypatch):
    packed = _write_sample(tmp_path / "packed.exe", packed=True)
    monkeypatch.setattr("glassbox.unpack.service.find_upx", lambda: None)

    result = unpack_sample(packed, tmp_path / "out.exe")

    assert result.status == "tool_missing"
    assert "upx binary was not found" in (result.error or "")


def test_unpack_generic_extracts_embedded_pe(tmp_path):
    packed = tmp_path / "embedded.exe"
    packed.write_bytes(build_pe() + b"\x00" * 256 + build_pe(imports=DEFAULT_IMPORTS + ["SetWindowsHookExA"]))
    output = tmp_path / "out" / "embedded-unpacked.exe"
    result = unpack_sample(packed, output)

    assert result.status == "unpacked"
    assert result.success is True
    assert result.method == "generic-embedded-pe"
    assert result.packer.name is None
    assert result.output_path == str(output)
    assert output.read_bytes()[:2] == b"MZ"


def test_unpack_generic_extracts_known_packer_payload(tmp_path):
    payload = build_pe(imports=DEFAULT_IMPORTS + ["SetWindowsHookExA"])
    packed = tmp_path / "packed.exe"
    packed.write_bytes(build_pe(packed=True) + b"\x00" * 256 + payload)
    output = tmp_path / "out" / "generic.exe"
    packer = PackerInfo(name="Themida", confidence="high", upx=False)

    result = unpack_sample(packed, output, packer=packer)

    assert result.status == "unpacked"
    assert result.method == "generic-embedded-pe"
    assert result.packer.name == "Themida"


def test_unpack_generic_reports_no_payload(tmp_path):
    sample = _write_sample(tmp_path / "plain.exe")

    result = unpack_sample(sample, tmp_path / "out.exe")

    assert result.status == "not_packed"
    assert result.success is False
    parent = _write_sample(tmp_path / "parent.exe")
    child = _write_sample(
        tmp_path / "child.exe",
        imports=DEFAULT_IMPORTS + ["SetWindowsHookExA"],
        strings=["hello from the unpacked payload"],
    )

    parent_case = analyze_static(ingest(parent))
    child_case = analyze_static(ingest(child))

    diff = diff_cases(parent_case, child_case)

    assert diff["child_case_id"] == child_case.case_id
    assert "SetWindowsHookExA" in diff["new_imports"]
    assert "GB-PROC-004" in diff["new_findings"]
    assert diff["size_delta"] == child.stat().st_size - parent.stat().st_size
