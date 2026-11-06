import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6", reason="desktop extra not installed")

from PySide6.QtWidgets import QApplication

from glassbox.analyzer import analyze_static
from glassbox.ingest import ingest
from glassbox.cases import CaseStore
from glassbox_desktop.app import main
from glassbox_desktop.main_window import MainWindow
from tests.fixtures.make_pe import build_pe


@pytest.fixture(scope="session")
def qt_app():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


def test_workbench_window_builds(qt_app, tmp_path):
    cases_dir = tmp_path / "cases"
    window = MainWindow(cases_dir=cases_dir)
    assert window.table.model().rowCount() == 0
    assert window.tabs.count() >= 6
    assert window.windowTitle() == "GlassBox PE Workbench"
    window.close()


def test_workbench_loads_existing_case(qt_app, tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(build_pe())
    case = analyze_static(ingest(sample))
    cases_dir = tmp_path / "cases"
    store = CaseStore(cases_dir)
    store.save(case)

    window = MainWindow(cases_dir=cases_dir)
    assert window.table.model().rowCount() == 1
    window.select_case_by_id(case.case_id)
    assert window._summary_labels["File"].text() == "sample.exe"
    assert window.table.model().data(window.table.model().index(0, 2)) == case.verdict.label.value
    window.close()


def test_cli_help_contains_app_name(capsys):
    import sys
    from glassbox_desktop.app import main

    old_argv = sys.argv[:]
    sys.argv = ["glassbox-gui", "--help"]
    try:
        with pytest.raises(SystemExit) as exc_info:
            main()
    finally:
        sys.argv = old_argv
    assert exc_info.value.code == 0
    out = capsys.readouterr().out
    assert "GlassBox PE Workbench" in out
