"""Điểm khởi chạy ứng dụng đồ hoạ (GUI Entry Point) - DumpAnalyzer.

Được gọi từ file run_gui.bat:
    python -m dumpanalyzer.gui.app
"""

import sys
import os
import logging
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from dumpanalyzer.core.logging_setup import setup_logging
from dumpanalyzer.gui.main_window import MainWindow


def main() -> int:
    """Khởi động ứng dụng PySide6 với cấu hình High DPI và phông chữ sắc nét."""
    setup_logging()
    logger = logging.getLogger("dumpanalyzer.gui")
    logger.info("Khởi động giao diện người dùng DumpAnalyzer...")

    # Cấu hình thuộc tính High DPI cho Qt
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("DumpAnalyzer")
    app.setOrganizationName("DumpAnalyzer")

    # Tạo và hiển thị cửa sổ chính
    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
