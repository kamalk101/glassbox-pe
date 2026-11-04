import hashlib

import pytest

from glassbox.ingest import ingest
from glassbox.utils import human_size, is_probably_pe
from tests.fixtures.make_pe import build_pe


def test_ingest_hashes(tmp_path):
    payload = b"not a real executable" * 100
    path = tmp_path / "sample.bin"
    path.write_bytes(payload)

    intake = ingest(path)

    assert intake.size == len(payload)
    assert intake.hashes["sha256"] == hashlib.sha256(payload).hexdigest()
    assert intake.case_id == intake.hashes["sha256"]
    assert intake.file_type == "bin"


def test_ingest_pe_type(tmp_path):
    path = tmp_path / "sample.exe"
    path.write_bytes(build_pe())

    intake = ingest(path)

    assert intake.file_type == "pe"
    assert is_probably_pe(build_pe())


def test_ingest_rejects_missing(tmp_path):
    with pytest.raises(FileNotFoundError):
        ingest(tmp_path / "missing.exe")


def test_human_size():
    assert human_size(999) == "999 B"
    assert human_size(2048) == "2.0 KB"
