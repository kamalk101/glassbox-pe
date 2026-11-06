"""Main desktop window for GlassBox PE."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QSortFilterProxyModel, Qt
from PySide6.QtGui import QAction, QColor, QBrush
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QSplitter,
    QTabWidget,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from glassbox.cases import CaseStore
from glassbox.config import resolve_cases_dir
from glassbox.ingest import ingest

from .graph import EvidenceGraphView
from .models import COLUMNS, CasesTableModel
from .workers import ScanWorker

VERDICT_COLORS = {
    "clean": "#61e294",
    "suspicious": "#ffd166",
    "malicious": "#ff6b7a",
    "inconclusive": "#d38bff",
}


class CaseFilterProxy(QSortFilterProxyModel):
    """Case-insensitive text and verdict filter."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._text = ""
        self._verdict = "all"

    def set_filter(self, text: str, verdict: str) -> None:
        self._text = text.strip().lower()
        self._verdict = verdict
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent) -> bool:  # noqa: N802
        model = self.sourceModel()
        row = [model.itemData(model.index(source_row, column)).get(Qt.DisplayRole) for column in range(model.columnCount())]
        lowered = " ".join(str(value or "").lower() for value in row)
        if self._text and self._text not in lowered:
            return False
        if self._verdict != "all" and row[2] != self._verdict:
            return False
        return True


class MainWindow(QMainWindow):
    """Single-window desktop workbench for GlassBox PE."""

    def __init__(self, cases_dir: str | Path | None = None):
        super().__init__()
        self.setWindowTitle("GlassBox PE Workbench")
        self.resize(1420, 900)
        self.store = CaseStore(resolve_cases_dir(cases_dir))
        self._current_case = None
        self._build_menu()
        self._build_layout()
        self.statusBar().showMessage("Ready")
        self.refresh_cases()

    def _build_menu(self) -> None:
        file_menu = self.menuBar().addMenu("&File")
        open_action = QAction("Open PE…", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)
        file_menu.addSeparator()
        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        view_menu = self.menuBar().addMenu("&View")
        refresh_action = QAction("Refresh cases", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(self.refresh_cases)
        view_menu.addAction(refresh_action)

        help_menu = self.menuBar().addMenu("&Help")
        about = QAction("About", self)
        about.triggered.connect(self.about_dialog)
        help_menu.addAction(about)

    def _build_layout(self) -> None:
        toolbar = QToolBar("Actions")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        scan_action = QAction("Scan PE", self)
        scan_action.triggered.connect(self.open_file)
        toolbar.addAction(scan_action)
        self.refresh_action = QAction("Refresh", self)
        self.refresh_action.triggered.connect(self.refresh_cases)
        toolbar.addAction(self.refresh_action)
        toolbar.addSeparator()
        self.status_label = QLabel("No case loaded")
        toolbar.addWidget(self.status_label)

        splitter = QSplitter()
        self.setCentralWidget(splitter)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(8, 8, 8, 8)

        controls = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search cases…")
        self.search_edit.textChanged.connect(self._apply_filter)
        controls.addWidget(self.search_edit, stretch=1)
        self.verdict_filter = QComboBox()
        self.verdict_filter.addItems(["all", "clean", "suspicious", "malicious", "inconclusive"])
        self.verdict_filter.currentTextChanged.connect(self._apply_filter)
        controls.addWidget(self.verdict_filter)
        left_layout.addLayout(controls)

        self.table_model = CasesTableModel(parent=self)
        self.proxy_model = CaseFilterProxy(self)
        self.proxy_model.setSourceModel(self.table_model)
        self.table = QTableView()
        self.table.setModel(self.proxy_model)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setMinimumWidth(520)
        self.table.selectionModel().selectionChanged.connect(self._selection_changed)
        left_layout.addWidget(self.table, stretch=1)
        splitter.addWidget(left)

        self.tabs = QTabWidget()
        self.summary_tab = QWidget()
        self.summary_layout = QFormLayout(self.summary_tab)
        self._summary_labels = {}
        for key in ["File", "SHA256", "Verdict", "Score", "Confidence", "Sneakiness", "Signature", "Imports", "Observed"]:
            label = QLabel("-")
            label.setWordWrap(True)
            self.summary_layout.addRow(QLabel(key), label)
            self._summary_labels[key] = label
        self.tabs.addTab(self.summary_tab, "Overview")
        self.sections_tab = self._make_table()
        self.tabs.addTab(self.sections_tab, "Sections")
        self.imports_tab = self._make_table()
        self.tabs.addTab(self.imports_tab, "Imports")
        self.findings_tab = self._make_table()
        self.tabs.addTab(self.findings_tab, "Findings")
        self.events_tab = self._make_table()
        self.tabs.addTab(self.events_tab, "Evidence events")
        self.graph_view = EvidenceGraphView()
        self.tabs.addTab(self.graph_view, "Evidence graph")
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        self.log_output = QPlainTextEdit()
        self.log_output.setMaximumHeight(150)
        self.log_output.setReadOnly(True)
        self.log_output.setPlaceholderText("Analysis output will appear here")
        self.setStatusBar(self.statusBar())
        self.statusBar().addPermanentWidget(self.log_output, 1)

    def _make_table(self):
        table = QTableWidget()
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.horizontalHeader().setStretchLastSection(True)
        return table

    def _apply_filter(self):
        self.proxy_model.set_filter(self.search_edit.text(), self.verdict_filter.currentText())

    def refresh_cases(self):
        rows = self.store.list()
        self.table_model.set_rows(rows)
        self.table.resizeColumnsToContents()
        self.statusBar().showMessage(f"Loaded {len(rows)} case(s)", 3000)

    def open_file(self, *_args):
        file_name, _ = QFileDialog.getOpenFileName(self, "Open PE file", "", "PE files (*.exe *.dll *.sys *.drv);;All files (*)")
        if not file_name:
            return
        self.scan_file(Path(file_name))

    def scan_file(self, path: Path):
        self.statusBar().showMessage(f"Scanning {path.name}…")
        self.log_output.appendPlainText(f"Scanning {path}…")
        self.setEnabled(False)
        self.worker = ScanWorker(path, self)
        self.worker.finished_case.connect(self._scan_finished)
        self.worker.failed.connect(self._scan_failed)
        self.worker.finished.connect(lambda: self.setEnabled(True))
        self.worker.start()

    def _scan_failed(self, message: str):
        self.setEnabled(True)
        self.statusBar().showMessage(f"Scan failed: {message}", 10000)
        self.log_output.appendPlainText(f"ERROR: {message}")

    def _scan_finished(self, case):
        self.setEnabled(True)
        self.store.save(case)
        self.current_case_id = case.case_id
        self.refresh_cases()
        self.select_case_by_id(case.case_id)
        self.statusBar().showMessage(f"Scanned {case.file_name}: {case.verdict.label.value if case.verdict else 'inconclusive'}", 10000)

    def _selection_changed(self, selected, deselected):
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return
        proxy_index = indexes[0]
        source_index = self.proxy_model.mapToSource(proxy_index)
        row = self.table_model.row_at(source_index.row())
        if row:
            self.load_case(row["case_id"])

    def select_case_by_id(self, case_id: str):
        rows = [self.table_model.row_at(i) for i in range(self.table_model.rowCount())]
        for i, row in enumerate(rows):
            if row and row.get("case_id") == case_id:
                self.table.selectRow(i)
                return

    def load_case(self, case_id: str):
        try:
            case = self.store.load(case_id)
        except FileNotFoundError:
            self.statusBar().showMessage("Case no longer exists", 5000)
            return
        self._current_case = case
        self._populate_summary(case)
        self._populate_sections(case)
        self._populate_imports(case)
        self._populate_findings(case)
        self._populate_events(case)
        self.graph_view.show_case(case)

    def _populate_summary(self, case):
        verdict = case.verdict
        colors = {
            "clean": QColor("#61e294"),
            "suspicious": QColor("#ffd166"),
            "malicious": QColor("#ff6b7a"),
            "inconclusive": QColor("#d38bff"),
        }
        label = verdict.label.value if verdict else "inconclusive"
        self._summary_labels["File"].setText(case.file_name)
        self._summary_labels["SHA256"].setText(case.hashes.get("sha256", "?"))
        self._summary_labels["Verdict"].setText(label.upper())
        self._summary_labels["Verdict"].setStyleSheet(f"color: {colors.get(label, '#ffffff').name()}; font-weight: bold")
        self._summary_labels["Score"].setText(f"{verdict.score if verdict else 0}/100" if verdict else "-")
        self._summary_labels["Confidence"].setText(f"{verdict.confidence:.2f}" if verdict else "-")
        self._summary_labels["Sneakiness"].setText(str(verdict.sneakiness) if verdict else "-")
        observed = case.artifacts.get("observed") or {}
        self._summary_labels["Observed"].setText(str(bool(observed.get("events") or observed.get("dropped_files"))))
        self._summary_labels["Signature"].setText(str(case.artifacts.get("pe", {}).get("signed", False)))
        self._summary_labels["Imports"].setText(str(case.artifacts.get("pe", {}).get("imports", 0)))
        self.status_label.setText(f"{case.file_name}: {label.upper()}" if verdict else f"{case.file_name}")

    def _populate_sections(self, case):
        sections = case.artifacts.get("sections_detail") or []
        rows = [[s.get("name"), s.get("entropy"), s.get("raw_size"), s.get("virtual_size"), "X" if s.get("executable") else "", "W" if s.get("writable") else "", "W+X" if s.get("wx") else "", ""] for s in sections]
        self._set_table_rows(self.sections_tab, ["Name", "Entropy", "Raw", "Virtual", "Exec", "Write", "W+X", ""], rows)

    def _populate_imports(self, case):
        groups = case.artifacts.get("imports") or {}
        rows = [[key, len(value), ", ".join(value[:8])] for key, value in sorted(groups.items())]
        self._set_table_rows(self.imports_tab, ["Behavior", "Count", "Functions"], rows)

    def _populate_findings(self, case):
        rows = [[f.rule_id, f.severity.value, f.title, ", ".join(f.techniques) or "-", f.source.value] for f in case.findings]
        self._set_table_rows(self.findings_tab, ["Rule", "Severity", "Finding", "Techniques", "Source"], rows)

    def _populate_events(self, case):
        rows = [[event.id, event.source.value, event.category.value, event.action, event.strength.value, event.technique or "-", event.target] for event in case.events[:500]]
        self._set_table_rows(self.events_tab, ["Id", "Source", "Category", "Action", "Strength", "Technique", "Target"], rows)

    def _set_table_rows(self, table, headers, rows):
        table.clearContents()
        table.setRowCount(len(rows))
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        for row_i, row in enumerate(rows):
            for column_i, value in enumerate(row):
                table.setItem(row_i, column_i, QTableWidgetItem(str(value)))
        table.resizeColumnsToContents()
        table.horizontalHeader().setStretchLastSection(True)

    def about_dialog(self):
        QMessageBox.about(self, "About GlassBox PE", "GlassBox PE Workbench\nOffline, evidence-first triage for Windows executables.")
