import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from tests.fixtures.make_pe import build_pe

ROOT = Path(__file__).resolve().parents[1]


def test_real_corpus_runner_generates_report(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "clean.exe").write_bytes(build_pe(imports=["CreateFileA", "ReadFile"], strings=["ordinary helper"]))
    (corpus / "manifest.json").write_text(
        json.dumps([{"path": "clean.exe", "label": "clean", "techniques": []}]),
        encoding="utf-8",
    )
    output = tmp_path / "measurement"

    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "run_real_corpus_evaluation.py"),
            str(corpus),
            "--output-dir",
            str(output),
            "--limit",
            "1",
            "--allow-missing-provenance",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = (output / "MEASUREMENT.md").read_text(encoding="utf-8")
    validation = json.loads((output / "validation.json").read_text(encoding="utf-8"))
    assert "## Static metrics" in report
    assert validation["samples"] == 1
    assert validation["problems"] == []
    assert validation["validator_return_code"] == 0
    if os.name == "nt":
        assert output.is_dir()
    else:
        assert os.stat(output).st_mode & 0o077 == 0
