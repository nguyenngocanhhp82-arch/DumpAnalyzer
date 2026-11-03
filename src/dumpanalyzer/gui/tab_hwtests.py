"""Tab 5: Kiểm tra phần cứng (Hardware Diagnostic Tests Tab) trong PySide6 DumpAnalyzer.

Tích hợp khung plugin kiểm tra phần cứng an toàn (Phần 4):
1. storage_health (chkdsk /scan chỉ đọc & SMART)
2. windows_memory_diagnostic (mdsched.exe & đọc Event Log sau reboot)
3. external_test_import (nhập kết quả MemTest86, OCCT, Prime95)
Kèm bảng lịch sử chạy và xuất phiếu hướng dẫn test RAM chuẩn mực.
"""

import sys
from typing import Optional
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from dumpanalyzer.core.models import MachineInfo
from dumpanalyzer.core.timeutil import utc_to_local_str
from dumpanalyzer.gui.theme import (
    COLOR_BORDER,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
)
from dumpanalyzer.hwtests.storage_health import StorageHealthTest
from dumpanalyzer.hwtests.windows_memory_diagnostic import WindowsMemoryDiagnosticTest
from dumpanalyzer.hwtests.external_test_import import ExternalTestImport, generate_ram_test_guide
from dumpanalyzer.storage.db import Database


class HardwareTestsTab(QWidget):
    """Tab Điều khiển & Thu thập kết quả kiểm tra phần cứng."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._machine_info: Optional[MachineInfo] = None
        self._db: Optional[Database] = None

        self._storage_test = StorageHealthTest()
        self._wmd_test = WindowsMemoryDiagnosticTest()
        self._external_test = ExternalTestImport()

        self._init_ui()

    def _get_db(self) -> Database:
        if self._db is None:
            self._db = Database()
        return self._db

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(14)

        # Header giới thiệu
        header_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        lbl_title = QLabel("KHUNG KIỂM TRA PHẦN CỨNG AN TOÀN (HARDWARE DIAGNOSTICS)")
        lbl_title.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {COLOR_TEXT_PRIMARY};")
        title_box.addWidget(lbl_title)

        lbl_desc = QLabel(
            "Chỉ sử dụng công cụ chuẩn mực của hệ thống hoặc nhập kết quả kiểm tra ngoài. "
            "Chế độ chỉ quét đọc (read-only scan), tuyệt đối không gây hư hại đĩa hay xung đột bộ nhớ."
        )
        lbl_desc.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px;")
        title_box.addWidget(lbl_desc)
        header_layout.addLayout(title_box, 1)

        # Kiểm tra quyền Admin
        is_admin = False
        if sys.platform == "win32":
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                pass
        self.lbl_admin_badge = QLabel("QUYỀN ADMIN: " + ("ĐÃ CÓ" if is_admin else "CHƯA CÓ"))
        badge_bg = "#15803d" if is_admin else "#b45309"
        self.lbl_admin_badge.setStyleSheet(
            f"background-color: {badge_bg}; color: #ffffff; font-weight: bold; font-size: 11px; padding: 4px 10px; border-radius: 4px;"
        )
        header_layout.addWidget(self.lbl_admin_badge, alignment=Qt.AlignRight)
        main_layout.addLayout(header_layout)

        # Splitter chia đôi: Trái (Các plugin kiểm tra), Phải (Lịch sử kết quả)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(8)

        # ==================== CỘT TRÁI: CÁC PLUGIN KIỂM TRA ====================
        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setFrameShape(QFrame.NoFrame)

        left_content = QWidget()
        left_layout = QVBoxLayout(left_content)
        left_layout.setContentsMargins(0, 0, 10, 0)
        left_layout.setSpacing(14)

        # 1. Card 1: Storage Health (Ổ đĩa & chkdsk /scan)
        storage_card = QFrame()
        storage_card.setObjectName("CardFrame")
        storage_card.setStyleSheet("background-color: #0b1120; border: 1px solid #1e293b; border-radius: 8px; padding: 12px;")
        st_layout = QVBoxLayout(storage_card)
        st_layout.setSpacing(8)

        st_header = QHBoxLayout()
        lbl_st_name = QLabel("1. Kiểm tra Ổ đĩa (SMART & chkdsk /scan)")
        lbl_st_name.setStyleSheet("font-size: 13px; font-weight: bold; color: #38bdf8;")
        st_header.addWidget(lbl_st_name)

        lbl_st_badge = QLabel("Không reboot | Cần Admin | ~3 phút")
        lbl_st_badge.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px;")
        st_header.addWidget(lbl_st_badge, alignment=Qt.AlignRight)
        st_layout.addLayout(st_header)

        lbl_st_desc = QLabel("Đọc bộ đếm lỗi SMART/I/O và quét nhanh tính toàn vẹn hệ thống tệp ở chế độ CHỈ ĐỌC (không sửa /f /r).")
        lbl_st_desc.setStyleSheet("color: #94a3b8; font-size: 12px;")
        lbl_st_desc.setWordWrap(True)
        st_layout.addWidget(lbl_st_desc)

        st_action_layout = QHBoxLayout()
        lbl_drive = QLabel("Ổ đĩa:")
        lbl_drive.setStyleSheet(f"color: {COLOR_TEXT_PRIMARY}; font-weight: 500;")
        st_action_layout.addWidget(lbl_drive)

        self.combo_drive = QComboBox()
        self.combo_drive.addItems(["C:", "D:", "E:", "F:"])
        self.combo_drive.setFixedWidth(70)
        st_action_layout.addWidget(self.combo_drive)

        self.btn_run_storage = QPushButton("Quét ổ đĩa (chkdsk /scan)")
        self.btn_run_storage.setStyleSheet("background-color: #0284c7; color: #ffffff; font-weight: bold; padding: 6px 14px; border-radius: 4px;")
        self.btn_run_storage.clicked.connect(self._on_run_storage_test)
        st_action_layout.addWidget(self.btn_run_storage)
        st_action_layout.addStretch()
        st_layout.addLayout(st_action_layout)

        self.lbl_storage_status = QLabel("Trạng thái: Chưa thực hiện")
        self.lbl_storage_status.setStyleSheet("color: #cbd5e1; font-size: 12px; font-style: italic;")
        st_layout.addWidget(self.lbl_storage_status)
        left_layout.addWidget(storage_card)

        # 2. Card 2: Windows Memory Diagnostic (RAM)
        wmd_card = QFrame()
        wmd_card.setObjectName("CardFrame")
        wmd_card.setStyleSheet("background-color: #0b1120; border: 1px solid #1e293b; border-radius: 8px; padding: 12px;")
        wmd_layout = QVBoxLayout(wmd_card)
        wmd_layout.setSpacing(8)

        wmd_header = QHBoxLayout()
        lbl_wmd_name = QLabel("2. Windows Memory Diagnostic (mdsched.exe)")
        lbl_wmd_name.setStyleSheet("font-size: 13px; font-weight: bold; color: #38bdf8;")
        wmd_header.addWidget(lbl_wmd_name)

        lbl_wmd_badge = QLabel("Cần Reboot | Cần Admin | ~15 phút")
        lbl_wmd_badge.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px;")
        wmd_header.addWidget(lbl_wmd_badge, alignment=Qt.AlignRight)
        wmd_layout.addLayout(wmd_header)

        lbl_wmd_desc = QLabel(
            "Khởi chạy mdsched.exe để hẹn giờ quét RAM khi máy khởi động lại. "
            "Sau khi máy khởi động lại xong, bấm 'Đọc kết quả sự kiện' để tự động nạp kết quả vào hệ thống."
        )
        lbl_wmd_desc.setStyleSheet("color: #94a3b8; font-size: 12px;")
        lbl_wmd_desc.setWordWrap(True)
        wmd_layout.addWidget(lbl_wmd_desc)

        wmd_action_layout = QHBoxLayout()
        self.btn_open_mdsched = QPushButton("Mở mdsched.exe hẹn giờ")
        self.btn_open_mdsched.setStyleSheet("background-color: #4338ca; color: #ffffff; font-weight: bold; padding: 6px 14px; border-radius: 4px;")
        self.btn_open_mdsched.clicked.connect(self._on_open_mdsched)
        wmd_action_layout.addWidget(self.btn_open_mdsched)

        self.btn_collect_wmd = QPushButton("Đọc kết quả (Event Log)")
        self.btn_collect_wmd.setStyleSheet("background-color: #0d9488; color: #ffffff; font-weight: bold; padding: 6px 14px; border-radius: 4px;")
        self.btn_collect_wmd.clicked.connect(self._on_collect_wmd_results)
        wmd_action_layout.addWidget(self.btn_collect_wmd)
        wmd_action_layout.addStretch()
        wmd_layout.addLayout(wmd_action_layout)

        self.lbl_wmd_status = QLabel("Trạng thái: Chưa thực hiện")
        self.lbl_wmd_status.setStyleSheet("color: #cbd5e1; font-size: 12px; font-style: italic;")
        wmd_layout.addWidget(self.lbl_wmd_status)
        left_layout.addWidget(wmd_card)

        # 3. Card 3: External Test Import (MemTest86, OCCT, Prime95)
        ext_card = QFrame()
        ext_card.setObjectName("CardFrame")
        ext_card.setStyleSheet("background-color: #0b1120; border: 1px solid #1e293b; border-radius: 8px; padding: 12px;")
        ext_layout = QVBoxLayout(ext_card)
        ext_layout.setSpacing(8)

        ext_header = QHBoxLayout()
        lbl_ext_name = QLabel("3. Nhập kết quả chuyên sâu ngoài (MemTest86 / OCCT)")
        lbl_ext_name.setStyleSheet("font-size: 13px; font-weight: bold; color: #38bdf8;")
        ext_header.addWidget(lbl_ext_name)

        self.btn_guide_ram = QPushButton("📄 Hướng dẫn test RAM USB")
        self.btn_guide_ram.setStyleSheet("background-color: #1e293b; color: #38bdf8; font-weight: bold; font-size: 11px; padding: 3px 8px; border: 1px solid #38bdf8; border-radius: 4px;")
        self.btn_guide_ram.clicked.connect(self._on_show_ram_guide)
        ext_header.addWidget(self.btn_guide_ram, alignment=Qt.AlignRight)
        ext_layout.addLayout(ext_header)

        grid_ext = QGridLayout()
        grid_ext.setSpacing(8)

        grid_ext.addWidget(QLabel("Công cụ:"), 0, 0)
        self.combo_tool_name = QComboBox()
        self.combo_tool_name.addItems(["MemTest86", "Memtest86+", "OCCT", "Prime95", "CrystalDiskInfo", "Khác"])
        grid_ext.addWidget(self.combo_tool_name, 0, 1)

        grid_ext.addWidget(QLabel("Nhóm kiểm tra:"), 0, 2)
        self.combo_ext_group = QComboBox()
        self.combo_ext_group.addItems(["ram", "cpu", "storage", "gpu"])
        grid_ext.addWidget(self.combo_ext_group, 0, 3)

        grid_ext.addWidget(QLabel("Số lượt hoàn thành (Passes):"), 1, 0)
        self.spin_passes = QSpinBox()
        self.spin_passes.setRange(0, 100)
        self.spin_passes.setValue(4)
        grid_ext.addWidget(self.spin_passes, 1, 1)

        grid_ext.addWidget(QLabel("Số lỗi ghi nhận (Errors):"), 1, 2)
        self.spin_errors = QSpinBox()
        self.spin_errors.setRange(0, 99999)
        self.spin_errors.setValue(0)
        grid_ext.addWidget(self.spin_errors, 1, 3)

        grid_ext.addWidget(QLabel("Thời lượng (phút):"), 2, 0)
        self.spin_duration = QSpinBox()
        self.spin_duration.setRange(0, 10000)
        self.spin_duration.setValue(60)
        grid_ext.addWidget(self.spin_duration, 2, 1)

        grid_ext.addWidget(QLabel("Ghi chú:"), 2, 2)
        self.txt_ext_notes = QLineEdit()
        self.txt_ext_notes.setPlaceholderText("Ghi chú thêm về kết quả...")
        grid_ext.addWidget(self.txt_ext_notes, 2, 3)

        grid_ext.addWidget(QLabel("File báo cáo/ảnh:"), 3, 0)
        file_box = QHBoxLayout()
        self.txt_report_path = QLineEdit()
        self.txt_report_path.setPlaceholderText("Đường dẫn file ảnh/log kết quả...")
        file_box.addWidget(self.txt_report_path, 1)
        btn_browse_report = QPushButton("...")
        btn_browse_report.setFixedWidth(36)
        btn_browse_report.clicked.connect(self._on_browse_report_file)
        file_box.addWidget(btn_browse_report)
        grid_ext.addLayout(file_box, 3, 1, 1, 3)

        ext_layout.addLayout(grid_ext)

        ext_btn_row = QHBoxLayout()
        self.btn_save_ext = QPushButton("Đánh giá & Lưu kết quả ngoài")
        self.btn_save_ext.setStyleSheet("background-color: #16a34a; color: #ffffff; font-weight: bold; padding: 7px 16px; border-radius: 4px;")
        self.btn_save_ext.clicked.connect(self._on_save_external_test)
        ext_btn_row.addWidget(self.btn_save_ext)
        ext_btn_row.addStretch()
        ext_layout.addLayout(ext_btn_row)

        left_layout.addWidget(ext_card)

        left_scroll.setWidget(left_content)
        splitter.addWidget(left_scroll)

        # ==================== CỘT PHẢI: LỊCH SỬ CHẠY KIỂM TRA ====================
        right_container = QFrame()
        right_container.setObjectName("CardFrame")
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(14, 14, 14, 14)
        right_layout.setSpacing(10)

        history_header = QHBoxLayout()
        lbl_hist_title = QLabel("LỊCH SỬ KIỂM TRA PHẦN CỨNG CỦA MÁY")
        lbl_hist_title.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {COLOR_TEXT_PRIMARY}; border-bottom: 2px solid {COLOR_BORDER}; padding-bottom: 6px;")
        history_header.addWidget(lbl_hist_title)

        btn_refresh_hist = QPushButton("Tải lại")
        btn_refresh_hist.setStyleSheet("padding: 4px 10px; font-size: 11px;")
        btn_refresh_hist.clicked.connect(self.refresh_history)
        history_header.addWidget(btn_refresh_hist, alignment=Qt.AlignRight)
        right_layout.addLayout(history_header)

        self.table_history = QTableWidget()
        self.table_history.setColumnCount(5)
        self.table_history.setHorizontalHeaderLabels([
            "Thời điểm",
            "Công cụ",
            "Trạng thái",
            "Thời lượng",
            "Chi tiết kết quả",
        ])
        self.table_history.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_history.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_history.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_history.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_history.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table_history.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_history.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table_history.verticalHeader().setVisible(False)
        right_layout.addWidget(self.table_history, 1)

        # Card giải thích quy đổi
        rule_info_card = QFrame()
        rule_info_card.setStyleSheet("background-color: #0b1120; border: 1px dashed #334155; border-radius: 6px; padding: 10px;")
        rule_layout = QVBoxLayout(rule_info_card)
        rule_layout.setSpacing(4)

        lbl_r_title = QLabel("Quy đổi kết quả sang Bằng chứng (Evidence):")
        lbl_r_title.setStyleSheet("color: #38bdf8; font-weight: bold; font-size: 12px;")
        rule_layout.addWidget(lbl_r_title)

        lbl_r_failed = QLabel("• FAILED (Phát hiện lỗi): sinh Bằng chứng MẠNH ỦNG HỘ (Strong Support), xác nhận hỏng hóc.")
        lbl_r_failed.setStyleSheet("color: #f87171; font-size: 11px;")
        rule_layout.addWidget(lbl_r_failed)

        lbl_r_passed = QLabel("• PASSED (Đạt yêu cầu): sinh Bằng chứng PHẢN BÁC (Refute), hạ điểm nghi ngờ (với RAM là Weak Refute).")
        lbl_r_passed.setStyleSheet("color: #4ade80; font-size: 11px;")
        rule_layout.addWidget(lbl_r_passed)

        right_layout.addWidget(rule_info_card)

        splitter.addWidget(right_container)
        splitter.setSizes([550, 450])

        main_layout.addWidget(splitter)

    def set_machine_info(self, machine_info: Optional[MachineInfo]) -> None:
        """Cập nhật thông tin máy tính đang xem."""
        self._machine_info = machine_info
        self.refresh_history()

    def refresh_history(self) -> None:
        """Tải lại danh sách lịch sử chạy từ SQLite."""
        m_id = getattr(self._machine_info, "id", None) or 1
        db = self._get_db()
        runs = db.get_test_runs_by_machine(m_id)

        self.table_history.setRowCount(len(runs))
        for row_idx, r in enumerate(runs):
            st_time = utc_to_local_str(r.get("started_at")) if r.get("started_at") else "-"
            test_id = r.get("test_id", "-")
            status = r.get("status", "-").upper()
            details = r.get("details", "")

            # Format status color
            item_st = QTableWidgetItem(status)
            if status == "PASSED":
                item_st.setForeground(Qt.green)
            elif status == "FAILED":
                item_st.setForeground(Qt.red)
            elif status == "PENDING":
                item_st.setForeground(Qt.yellow)
            else:
                item_st.setForeground(Qt.gray)

            self.table_history.setItem(row_idx, 0, QTableWidgetItem(st_time))
            self.table_history.setItem(row_idx, 1, QTableWidgetItem(test_id))
            self.table_history.setItem(row_idx, 2, item_st)
            self.table_history.setItem(row_idx, 3, QTableWidgetItem("-"))
            self.table_history.setItem(row_idx, 4, QTableWidgetItem(details))

    def _on_run_storage_test(self) -> None:
        """Thực thi kiểm tra chkdsk /scan chỉ đọc."""
        drive = self.combo_drive.currentText()
        reply = QMessageBox.question(
            self,
            "Xác nhận quét ổ đĩa",
            f"Bạn có chắc muốn chạy lệnh kiểm tra chỉ đọc 'chkdsk {drive} /scan'?\n\n"
            "Chế độ này an toàn, chỉ quét phân tích cấu trúc đĩa và không sửa hay ghi đè dữ liệu.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.Yes,
        )
        if reply != QMessageBox.Yes:
            return

        self.lbl_storage_status.setText(f"Đang thực thi chkdsk {drive} /scan...")
        try:
            m_id = getattr(self._machine_info, "id", None) or 1
            res = self._storage_test.start(machine_id=m_id, drive=drive)
            db = self._get_db()
            db.insert_test_run(
                machine_id=m_id,
                test_id=self._storage_test.id,
                status=res.status,
                details=res.details,
                started_at=res.started_at,
                finished_at=res.finished_at,
                raw_output=res.raw,
            )
            self.lbl_storage_status.setText(f"Hoàn thành: {res.status.upper()} - {res.details[:60]}...")
            self.refresh_history()
            QMessageBox.information(self, "Kết quả kiểm tra ổ đĩa", res.details)
        except Exception as e:
            self.lbl_storage_status.setText(f"Lỗi: {e}")
            QMessageBox.critical(self, "Lỗi kiểm tra", str(e))

    def _on_open_mdsched(self) -> None:
        """Mở công cụ mdsched.exe và ghi nhận trạng thái pending."""
        m_id = getattr(self._machine_info, "id", None) or 1
        res = self._wmd_test.start(machine_id=m_id)
        db = self._get_db()
        db.insert_test_run(
            machine_id=m_id,
            test_id=self._wmd_test.id,
            status=res.status,
            details=res.details,
            started_at=res.started_at,
            finished_at=res.finished_at,
            raw_output=res.raw,
        )
        self.lbl_wmd_status.setText("Trạng thái: PENDING (Đang chờ khởi động lại máy)")
        self.refresh_history()
        QMessageBox.information(self, "Windows Memory Diagnostic", res.details)

    def _on_collect_wmd_results(self) -> None:
        """Đọc kết quả sự kiện Event Log của Windows Memory Diagnostic sau reboot."""
        m_id = getattr(self._machine_info, "id", None) or 1
        res = self._wmd_test.collect_result(machine_id=m_id)
        db = self._get_db()
        db.insert_test_run(
            machine_id=m_id,
            test_id=self._wmd_test.id,
            status=res.status,
            details=res.details,
            started_at=res.started_at,
            finished_at=res.finished_at,
            raw_output=res.raw,
        )
        self.lbl_wmd_status.setText(f"Kết quả: {res.status.upper()} - {res.details}")
        self.refresh_history()
        QMessageBox.information(self, "Kết quả chẩn đoán RAM", res.details)

    def _on_browse_report_file(self) -> None:
        f_path, _ = QFileDialog.getOpenFileName(self, "Chọn file báo cáo hoặc ảnh chụp kết quả", "", "All Files (*.*)")
        if f_path:
            self.txt_report_path.setText(f_path)

    def _on_save_external_test(self) -> None:
        """Đánh giá và lưu kết quả từ công cụ ngoài."""
        tool = self.combo_tool_name.currentText()
        grp = self.combo_ext_group.currentText()
        passes = self.spin_passes.value()
        errs = self.spin_errors.value()
        dur = self.spin_duration.value()
        notes = self.txt_ext_notes.text().strip()
        report = self.txt_report_path.text().strip()

        res = self._external_test.evaluate_external_result(
            tool_name=tool,
            group=grp,
            passes=passes,
            errors=errs,
            duration_minutes=dur,
            notes=notes,
            report_path=report,
        )

        m_id = getattr(self._machine_info, "id", None) or 1
        db = self._get_db()
        db.insert_test_run(
            machine_id=m_id,
            test_id=self._external_test.id,
            status=res.status,
            details=res.details,
            started_at=res.started_at,
            finished_at=res.finished_at,
            raw_output=res.raw,
        )
        self.refresh_history()
        QMessageBox.information(self, "Đã lưu kết quả kiểm tra ngoài", res.details)

    def _on_show_ram_guide(self) -> None:
        """Hiển thị tài liệu hướng dẫn test RAM bằng USB MemTest86."""
        guide_text = generate_ram_test_guide()
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Phiếu hướng dẫn kiểm tra RAM bằng MemTest86")
        msg_box.setText("Hướng dẫn chi tiết quy trình kiểm tra bộ nhớ RAM ngoài hệ điều hành:")
        msg_box.setDetailedText(guide_text)
        btn_export = msg_box.addButton("Lưu ra file TXT", QMessageBox.ActionRole)
        msg_box.addButton(QMessageBox.Close)
        msg_box.exec()

        if msg_box.clickedButton() == btn_export:
            f_path, _ = QFileDialog.getSaveFileName(self, "Lưu hướng dẫn test RAM", "Huong_Dan_Test_RAM_MemTest86.txt", "Text Files (*.txt)")
            if f_path:
                Path(f_path).write_text(guide_text, encoding="utf-8")
                QMessageBox.information(self, "Thành công", f"Đã lưu tài liệu hướng dẫn ra:\n{f_path}")
