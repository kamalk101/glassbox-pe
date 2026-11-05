"""Filesystem-backed case store.

Layout: <cases_dir>/<sha256>/case.json
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from .schema import Case


class CaseStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    def case_dir(self, case_id: str) -> Path:
        return self.root / case_id

    def case_path(self, case_id: str) -> Path:
        return self.case_dir(case_id) / "case.json"

    def exists(self, case_id: str) -> bool:
        return self.case_path(case_id).is_file()

    def save(self, case: Case) -> Path:
        directory = self.case_dir(case.case_id)
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / "case.json"
        tmp = directory / "case.json.tmp"
        tmp.write_text(json.dumps(case.to_dict(), indent=2), encoding="utf-8")
        tmp.replace(target)
        return target

    def load(self, case_id: str) -> Case:
        path = self.case_path(case_id)
        if not path.is_file():
            raise FileNotFoundError(f"case not found: {case_id}")
        return Case.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def list(self) -> list[dict]:
        if not self.root.is_dir():
            return []
        rows: list[dict] = []
        for entry in sorted(self.root.iterdir()):
            path = entry / "case.json"
            if not path.is_file():
                continue
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            verdict = raw.get("verdict") or {}
            artifacts = raw.get("artifacts") or {}
            unpack = artifacts.get("unpack") or {}
            emulation = artifacts.get("emulation") or {}
            rows.append(
                {
                    "case_id": raw.get("case_id", entry.name),
                    "file_name": raw.get("file_name", "?"),
                    "size": raw.get("size", 0),
                    "created_at": raw.get("created_at", ""),
                    "label": verdict.get("label", "inconclusive"),
                    "score": verdict.get("score", 0),
                    "confidence": verdict.get("confidence", 0.0),
                    "sneakiness": verdict.get("sneakiness", 0),
                    "unpack_status": unpack.get("status"),
                    "emulation_ran": bool(emulation.get("ran")),
                    "has_report": (entry / "report.html").is_file(),
                }
            )
        return rows

    def delete(self, case_id: str) -> None:
        directory = self.case_dir(case_id)
        if not directory.is_dir():
            raise FileNotFoundError(f"case not found: {case_id}")
        shutil.rmtree(directory)
