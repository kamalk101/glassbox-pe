"""Application shell for the GlassBox PE desktop workbench."""

from __future__ import annotations

from argparse import Namespace, ArgumentParser
from pathlib import Path

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from .main_window import MainWindow
from .resources import APP_NAME


def main() -> int:
    parser = ArgumentParser(description="GlassBox PE Workbench")
    parser.add_argument(
        "--cases-dir",
        default=None,
        help="directory for stored cases (default: configured cases directory)",
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")
    args = parser.parse_args()

    if args.version:
        from . import __version__

        print(f"{APP_NAME} {__version__}")
        return 0

    app = QApplication([])
    app.setApplicationName(APP_NAME)
    window = MainWindow(cases_dir=args.cases_dir)
    window.show()
    return app.exec()
