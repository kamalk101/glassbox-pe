import json

from click.testing import CliRunner

from glassbox.cli import cli
from glassbox.evaluation import evaluate_corpus, load_manifest
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
