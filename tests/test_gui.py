"""Bộ kiểm thử cho Giao diện người dùng PySide6 (GUI) của DumpAnalyzer.

Chạy hoàn toàn trong môi trường tự động không đầu (headless / offscreen),
kiểm tra các Tab Tổng quan, Chi tiết crash, Kết luận, Cài đặt và luồng xử lý nền.
"""

import os
import sys
import pytest

# Thiết lập nền tảng offscreen để chạy kiểm thử Qt không cần màn hình đồ họa
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QLabel, QMessageBox

from dumpanalyzer.core.models import Crash, Evidence, Finding, MachineInfo
from dumpanalyzer.gui.main_window import MainWindow
from dumpanalyzer.gui.tab_detail import DetailTab
from dumpanalyzer.gui.tab_overview import OverviewTab
from dumpanalyzer.gui.tab_settings import SettingsTab
from dumpanalyzer.gui.tab_verdict import VerdictTab
from dumpanalyzer.gui.worker import AnalysisWorker


@pytest.fixture(scope="session")
def qapp():
    """Khởi tạo QApplication dùng chung cho toàn bộ phiên kiểm thử."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app


@pytest.fixture
def mock_msgbox(monkeypatch):
    """Giả lập QMessageBox để không gây chặn tiến trình kiểm thử tự động."""
    monkeypatch.setattr(QMessageBox, "information", lambda *args, **kwargs: QMessageBox.Ok)
    monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: QMessageBox.Ok)
    monkeypatch.setattr(QMessageBox, "critical", lambda *args, **kwargs: QMessageBox.Ok)
    monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)


@pytest.fixture
def sample_gui_data():
    """Tạo dữ liệu thử nghiệm cho giao diện."""
    c1 = Crash(
        id=1,
        dump_path="C:/dumps/test1.dmp",
        dump_sha256="hash123",
        bugcheck_code="0x124",
        bugcheck_name="WHEA_UNCORRECTABLE_ERROR",
        image_name="AuthenticAMD.sys",
        module_name="AuthenticAMD",
        process_name="System",
        failure_bucket_id="0x124_AuthenticAMD",
        p1="0x0",
        p2="0xffff8000",
        p3="0x0",
        p4="0x0",
        uptime_seconds=7200,
        cdb_raw_output="STACK_TEXT:\nfffff800`01000000 fffff800`02000000 nt!KeBugCheckEx\nfffff800`01000010 AuthenticAMD+0x1000\n",
        analyzed_by="cdb",
        crash_time_utc="2026-10-20T10:00:00Z",
    )
    c2 = Crash(
        id=2,
        dump_path="",
        dump_sha256="hash_log_41",
        bugcheck_code="0x0",
        bugcheck_name="UNKNOWN_BUGCHECK",
        image_name="",
        module_name="",
        process_name="",
        failure_bucket_id="",
        p1="",
        p2="",
        p3="",
        p4="",
        uptime_seconds=0,
        cdb_raw_output="",
        analyzed_by="log_only",
        crash_time_utc="2026-10-21T15:30:00Z",
    )

    machine = MachineInfo(
        hostname="DESKTOP-TEST",
        model="MSI B550 GAMING PLUS",
        bios="v1.4",
        cpu="AMD Ryzen 7 5800X 8-Core",
        os_build="22631",
    )

    finding = Finding(
        suspect="cpu",
        score=68.5,
        confidence="trung bình",
        rationale="Lỗi WHEA lặp lại nhiều lần, nghi vấn phần cứng CPU.",
        next_steps=[
            "Kiểm tra nhiệt độ CPU khi chịu tải",
            "Cập nhật driver chipset",
            "Chạy MemTest86 kiểm tra RAM",
            "Cập nhật BIOS bo mạch chủ",
        ],
    )
    setattr(finding, "suspect_ranking", [
        {"label": "Bộ xử lý CPU", "percentage": 68.5},
        {"label": "Bộ nguồn (PSU)", "percentage": 31.5},
    ])

    ev = Evidence(
        id=1,
        crash_id=1,
        kind="dump",
        source="cdb",
        event_id=None,
        time_utc="2026-10-20T10:00:00Z",
        summary="WHEA MCA Error",
        detail="MACHINE_CHECK_EXCEPTION",
    )

    return {
        "crashes": [c1, c2],
        "machine_info": machine,
        "finding": finding,
        "evidences": [ev],
        "suspect_ranking": getattr(finding, "suspect_ranking"),
        "conflict_detected": True,
    }


def test_main_window_structure(qapp, mock_msgbox):
    """Kiểm tra cấu trúc khung cửa sổ chính, thanh tiêu đề và 4 Tab."""
    win = MainWindow()
    win.show()

    assert win.windowTitle() == "DumpAnalyzer – Phân tích màn hình xanh & khởi động lại"
    assert win.tabs.count() == 5
    assert win.tabs.tabText(0) == "Tổng quan"
    assert win.tabs.tabText(1) == "Chi tiết crash"
    assert win.tabs.tabText(2) == "Kết luận"
    assert win.tabs.tabText(3) == "Kiểm tra phần cứng"
    assert win.tabs.tabText(4) == "Cài đặt"


def test_overview_tab_kpi_and_badges(qapp, mock_msgbox, sample_gui_data):
    """Kiểm tra Tab Tổng quan: thẻ KPI, danh sách crash và nhãn 'Không có dump'."""
    tab = OverviewTab()
    tab.set_data(
        crashes=sample_gui_data["crashes"],
        finding=sample_gui_data["finding"],
        suspect_ranking=sample_gui_data["suspect_ranking"],
    )

    # 1. Kiểm tra 4 thẻ KPI
    assert tab.card_total.lbl_value.text() == "2 sự cố"
    assert "1 có dump" in tab.card_dumps.lbl_value.text()
    assert "Bộ xử lý CPU" in tab.card_top_suspect.lbl_value.text()
    assert tab.card_confidence.lbl_value.text() == "TRUNG BÌNH"

    # 2. Kiểm tra các dòng trong bảng
    assert tab.table.rowCount() == 2

    # Dòng 0: có dump bằng cdb
    item_code0 = tab.table.item(0, 1).text()
    assert item_code0 == "0x124"
    lbl_method0 = tab.table.cellWidget(0, 5).findChild(QLabel).text()
    assert lbl_method0 == "WinDbg cdb"

    # Dòng 1: log_only bắt buộc phải có nhãn "Không có dump"
    item_code1 = tab.table.item(1, 1).text()
    assert item_code1 == "0x0"
    lbl_method1 = tab.table.cellWidget(1, 5).findChild(QLabel).text()
    assert lbl_method1 == "Không có dump"

    # 3. Kiểm tra tính năng lọc tìm kiếm
    tab.txt_search.setText("WHEA")
    assert tab.table.rowCount() == 1
    tab.txt_search.clear()
    assert tab.table.rowCount() == 2


def test_detail_tab_display(qapp, mock_msgbox, sample_gui_data):
    """Kiểm tra Tab Chi tiết crash: hiển thị thông số, 4 tham số, Call Stack và sự kiện."""
    tab = DetailTab()
    tab.set_data(
        crashes=sample_gui_data["crashes"],
        evidences=sample_gui_data["evidences"],
    )

    assert tab.combo_crashes.count() == 2

    # Kiểm tra hiển thị crash 1 (WHEA 0x124)
    tab.select_crash(sample_gui_data["crashes"][0])
    assert tab.meta_labels["lbl_bugcheck_code"].text() == "0x124"
    assert tab.meta_labels["lbl_bugcheck_name"].text() == "WHEA_UNCORRECTABLE_ERROR"
    assert tab.meta_labels["lbl_image_name"].text() == "AuthenticAMD.sys"
    assert "0xffff8000" in tab.lbl_p2.text()
    assert "STACK_TEXT" in tab.txt_stack.toPlainText()
    assert tab.table_events.rowCount() == 1

    # Kiểm tra hiển thị crash 2 (log_only mã 0x0)
    tab.select_crash(sample_gui_data["crashes"][1])
    assert tab.meta_labels["lbl_bugcheck_code"].text() == "0x0"
    assert "Không có dump" in tab.lbl_method_badge.text()


def test_verdict_tab_display_and_conflict(qapp, mock_msgbox, sample_gui_data):
    """Kiểm tra Tab Kết luận: xếp hạng xác suất, rationale, các bước theo tầng và cảnh báo mâu thuẫn."""
    tab = VerdictTab()
    tab.show()
    tab.set_data(
        crashes=sample_gui_data["crashes"],
        finding=sample_gui_data["finding"],
        machine_info=sample_gui_data["machine_info"],
        evidences=sample_gui_data["evidences"],
        suspect_ranking=sample_gui_data["suspect_ranking"],
        conflict_detected=True,
    )

    # 1. Kết luận chính & Độ tin cậy
    assert "Bộ xử lý CPU (68.5%)" in tab.lbl_top_suspect.text()
    assert "TRUNG BÌNH" in tab.lbl_confidence_badge.text()
    assert "Lỗi WHEA lặp lại nhiều lần" in tab.lbl_rationale.text()

    # 2. Cờ cảnh báo mâu thuẫn (Conflict Warning)
    assert not tab.conflict_banner.isHidden()

    # 3. Xếp hạng nghi vấn
    assert tab.ranking_container.count() == 2

    # 4. Các bước khuyến nghị kiểm tra
    assert tab.steps_container.count() == 4


def test_settings_tab_dump_readiness_and_rules_validation(qapp, mock_msgbox):
    """Kiểm tra Tab Cài đặt: bảng khả năng ghi dump và nút kiểm tra quy tắc."""
    tab = SettingsTab()
    assert tab.table_config.rowCount() >= 4

    # Kiểm tra gọi kiểm tra quy tắc không phát sinh ngoại lệ
    tab._on_validate_rules_clicked()


def test_worker_cancellation(qapp):
    """Kiểm tra luồng AnalysisWorker hỗ trợ cờ huỷ an toàn."""
    worker = AnalysisWorker(source_type="folder", folder_path="/nonexistent")
    assert worker._is_cancelled is False
    worker.cancel()
    assert worker._is_cancelled is True
