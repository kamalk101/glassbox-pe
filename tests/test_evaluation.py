import json

from click.testing import CliRunner

from glassbox.cli import cli
from glassbox.emu import EmulationOutcome
from glassbox.evaluation import _calibration, _recall_at_fpr, evaluate_corpus, load_manifest
from glassbox.static.packer import PackerInfo
from glassbox.unpack import UnpackResult
from tests.fixtures.make_pe import build_pe


def _write_sample(path, **kwargs):
    path.write_bytes(build_pe(**kwargs))
    return path


def test_evaluate_corpus_metrics(tmp_path):
    _write_sample(
        tmp_path / "clean.exe",
        imports=["CreateFileA", "ReadFile", "CloseHandle"],
        strings=["ordinary file helper"],
    )
    _write_sample(
        tmp_path / "suspicious.exe",
        imports=["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        strings=["injection stage"],
    )
    _write_sample(tmp_path / "malicious.exe")
    manifest = {
        "samples": [
            {"path": "clean.exe", "label": "clean", "techniques": []},
            {"path": "suspicious.exe", "label": "suspicious", "techniques": ["T1055"]},
            {"path": "malicious.exe", "label": "malicious", "techniques": ["T1055", "T1059"]},
        ]
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    result = evaluate_corpus(tmp_path)

    metrics = result["metrics"]
    assert metrics["samples"] == 3
    assert metrics["accuracy"] == 1.0
    assert metrics["binary"]["tp"] == 2
    assert metrics["binary"]["tn"] == 1
    assert metrics["binary"]["pr_auc"] == 1.0
    assert metrics["macro_f1"] == 1.0
    assert metrics["techniques"]["recall"] == 1.0
    assert [sample["predicted"] for sample in result["samples"]] == [
        "clean",
        "suspicious",
        "malicious",
    ]
    assert result["errors"] == []


def test_evaluate_corpus_reports_missing_files(tmp_path):
    manifest = [{"path": "missing.exe", "label": "clean"}]
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    result = evaluate_corpus(tmp_path)

    assert result["metrics"]["samples"] == 0
    assert result["metrics"]["binary"]["pr_auc"] is None
    assert result["errors"][0]["error"] == "file not found"


def test_manifest_rejects_unknown_labels(tmp_path):
    (tmp_path / "sample.exe").write_bytes(build_pe())
    (tmp_path / "manifest.json").write_text(
        json.dumps([{"path": "sample.exe", "label": "probably-bad"}]),
        encoding="utf-8",
    )

    try:
        load_manifest(tmp_path)
    except ValueError as exc:
        assert "expected one of" in str(exc)
    else:
        raise AssertionError("unknown label was accepted")


def test_cli_eval_json_and_output(tmp_path):
    _write_sample(tmp_path / "clean.exe", imports=["CreateFileA", "ReadFile"], strings=["ok"])
    (tmp_path / "manifest.json").write_text(
        json.dumps([{"path": "clean.exe", "label": "clean"}]),
        encoding="utf-8",
    )
    output = tmp_path / "eval-result.json"

    result = CliRunner().invoke(
        cli,
        ["eval", str(tmp_path), "--json", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["metrics"]["samples"] == 1
    assert output.is_file()
    assert json.loads(output.read_text(encoding="utf-8"))["metrics"]["samples"] == 1


def test_recall_at_fpr_and_calibration():
    actual = [True, True, False, False]
    scores = [0.9, 0.4, 0.2, 0.1]
    recall = _recall_at_fpr(actual, scores, max_fpr=0.0)
    assert recall is not None
    assert recall["recall"] == 1.0
    assert recall["false_positive_rate"] == 0.0

    calibration = _calibration(actual, [0.9, 0.8, 0.2, 0.1])
    assert calibration["brier"] == 0.025
    assert calibration["ece"] is not None


def test_evaluate_corpus_emulation_mode(tmp_path):
    _write_sample(
        tmp_path / "clean.exe",
        imports=["CreateFileA", "ReadFile"],
        strings=["ordinary helper"],
    )
    (tmp_path / "manifest.json").write_text(
        json.dumps([{"path": "clean.exe", "label": "clean", "techniques": []}]),
        encoding="utf-8",
    )

    def fake_runner(path, timeout=30, workdir=None):
        return EmulationOutcome(
            ran=True,
            report={
                "emu_version": "test",
                "entry_points": [
                    {
                        "apis": [
                            {
                                "api_name": "KERNEL32.CreateRemoteThread",
                                "args": ["0x1"],
                                "ret_val": "0x0",
                            }
                        ]
                    }
                ],
            },
        )

    result = evaluate_corpus(tmp_path, mode="emulation", emulation_runner=fake_runner)

    assert result["mode"] == "emulation"
    assert result["emulation"]["ran"] == 1
    assert result["emulation"]["api_calls"] == 1
    assert "process" in result["samples"][0]["emulation"]["categories"]
    assert result["samples"][0]["predicted"] in {"suspicious", "malicious"}
    assert result["samples"][0]["static_score"] < result["samples"][0]["score"]


def test_evaluate_corpus_unpack_mode(tmp_path):
    _write_sample(
        tmp_path / "packed.exe",
        imports=["CreateFileA", "ReadFile"],
        strings=["ordinary helper"],
        packed=True,
    )
    (tmp_path / "manifest.json").write_text(
        json.dumps([{"path": "packed.exe", "label": "malicious", "techniques": ["T1055"]}]),
        encoding="utf-8",
    )

    def fake_unpack(path, output):
        output.write_bytes(build_pe(imports=["OpenProcess", "VirtualAllocEx", "WriteProcessMemory"]))
        return UnpackResult(
            status="unpacked",
            success=True,
            packer=PackerInfo(name="UPX", confidence="high", upx=True),
            method="upx",
            output_path=str(output),
        )

    result = evaluate_corpus(tmp_path, mode="unpack", unpack_runner=fake_unpack)

    assert result["mode"] == "unpack"
    assert result["unpack"]["unpacked"] == 1
    assert result["unpack"]["improved"] == 1
    assert result["samples"][0]["predicted"] == "malicious"
    assert result["samples"][0]["unpack"]["child_score"] > result["samples"][0]["static_score"]


def test_cli_eval_mode_and_yara_summary(tmp_path):
    _write_sample(tmp_path / "sample.exe", strings=["sekurlsa::logonpasswords"])
    (tmp_path / "manifest.json").write_text(
        json.dumps([{"path": "sample.exe", "label": "malicious", "techniques": ["T1003.001"]}]),
        encoding="utf-8",
    )

    result = CliRunner().invoke(cli, ["eval", str(tmp_path), "--json", "--mode", "static"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["mode"] == "static"
    assert payload["yara"]["samples_with_matches"] == 1
