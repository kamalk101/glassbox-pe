"""Qt models for the GlassBox PE workbench."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt

COLUMNS = [
    ("case_id", "ID"),
    ("file_name", "File"),
    ("label", "Verdict"),
    ("score", "Score"),
    ("confidence", "Confidence"),
    ("sneakiness", "Sneakiness"),
    ("unpack_status", "Unpack"),
    ("created_at", "Created"),
]


class CasesTableModel(QAbstractTableModel):
    """Simple table model backed by a list of case dictionaries."""

    def __init__(self, rows: list[dict[str, Any]] | None = None, parent=None):
        super().__init__(parent)
        self._rows = list(rows or [])

    def set_rows(self, rows: list[dict[str, Any]]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def row_at(self, row: int) -> dict[str, Any] | None:
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802 - Qt API
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802 - Qt API
        return 0 if parent.isValid() else len(COLUMNS)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None
        item = self._rows[index.row()]
        key = COLUMNS[index.column()][0]
        value = item.get(key, "")
        if role == Qt.DisplayRole:
            if key == "case_id":
                return str(value)[:12]
            if isinstance(value, float):
                return f"{value:.2f}"
            return value if value is not None else "-"
        if role == Qt.TextAlignmentRole and key in {"score", "confidence", "sneakiness"}:
            return Qt.AlignRight | Qt.AlignVCenter
        if role == Qt.UserRole:
            return item
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):  # noqa: N802
        if role != Qt.DisplayRole or orientation != Qt.Horizontal:
            return None
        return COLUMNS[section][1]
