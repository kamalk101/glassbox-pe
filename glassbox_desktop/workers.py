"""Background workers for the GlassBox PE desktop UI."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, QThread, Signal

from glassbox.analyzer import analyze_static
from glassbox.ingest import ingest
from glassbox.schema import Case


class ScanWorker(QThread):
    """Scan a file without blocking the UI thread."""

    finished_case = Signal(object)
    failed = Signal(str)

    def __init__(self, path: Path, parent=None):
        super().__init__(parent)
        self._path = Path(path)

    def run(self) -> None:  # noqa: D401 - Qt entry point
        try:
            case = analyze_static(ingest(self._path))
        except Exception as exc:  # pragma: no cover - defensive around UI runtime
            self.failed.emit(str(exc))
            return
        self.finished_case.emit(case)
