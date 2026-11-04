"""Cấu hình pytest dùng chung và fixtures cho toàn bộ bộ kiểm thử."""

import os
import sys
import pytest

os.environ["QT_QPA_PLATFORM"] = "offscreen"


@pytest.fixture(scope="session")
def qapp():
    """Khởi tạo QApplication dùng chung cho toàn bộ phiên kiểm thử GUI."""
    try:
        from PySide6.QtWidgets import QApplication
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
        yield app
    except ImportError:
        yield None


@pytest.fixture
def mock_msgbox(monkeypatch):
    """Giả lập QMessageBox để không gây chặn tiến trình kiểm thử tự động."""
    try:
        from PySide6.QtWidgets import QMessageBox
        monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: QMessageBox.Ok)
        monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: QMessageBox.Ok)
        monkeypatch.setattr(QMessageBox, "critical", lambda *args, **kwargs: QMessageBox.Ok)
        monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)
        monkeypatch.setattr(QMessageBox, "exec_", lambda self: QMessageBox.Ok)
        monkeypatch.setattr(QMessageBox, "exec", lambda self: QMessageBox.Ok)
    except ImportError:
        pass
