"""Tab 4: Cài đặt & Khả năng ghi dump (Settings Tab) trong PySide6 DumpAnalyzer.

Bao gồm:
1. Mục 'Khả năng ghi dump': Bảng kiểm tra registry CrashControl, pagefile, dung lượng ổ C:,
   sự kiện volmgr và nút bật tự động ghi dump an toàn (có hộp thoại xác nhận).
2. Mục 'Cấu hình phân tích': Đường dẫn cdb.exe, symbols Microsoft, thư mục làm việc,
   bộ đọc Minidump Triage nội bộ, cửa sổ thời gian tương quan và số luồng xử lý song song.
3. Mục 'Quản lý quy tắc chẩn đoán': Nút kiểm tra tính hợp lệ toàn diện (Validate Rules)
   và nút mở nhanh thư mục cấu hình rules YAML.
4. Mục 'Thông tin phần mềm': Bản quyền tác giả phát triển Lilbow, phiên bản và mục đích ứng dụng.
"""

import os
import subprocess
import sys
from typing import Any, Dict, Optional
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
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
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from dumpanalyzer.collectors.dump_config import (
    CRASH_DUMP_MODES,
    apply_automatic_dump,
    check_disk_space_and_ram,
    check_pagefile_status,
    check_volmgr_events,
    evaluate_readiness,
    read_registry_crash_control,
)
from dumpanalyzer.core.config import get_rules_dir, get_settings_path, load_settings, save_settings
from dumpanalyzer.engine.rule_loader import validate_rules_and_settings
from dumpanalyzer.gui.theme import (
    COLOR_ACCENT,
    COLOR_BORDER,
    COLOR_DANGER,
    COLOR_SUCCESS,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_WARNING,
)


class SettingsTab(QWidget):
    """Tab Cài đặt và Kiểm tra Khả năng ghi dump của hệ thống."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._settings_path = get_settings_path()
        self._settings: Dict[str, Any] = load_settings(self._settings_path)
        self._init_ui()
        self.refresh_dump_config()

    def _init_ui(self) -> None:
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)

        container_widget = QWidget()
        main_layout = QVBoxLayout(container_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)

        # =====================================================================
        # MỤC 1: KHẢ NĂNG GHI DUMP (DUMP CONFIG & READINESS)
        # =====================================================================
        readiness_card = QFrame()
        readiness_card.setObjectName("CardFrame")
        readiness_layout = QVBoxLayout(readiness_card)
        readiness_layout.setContentsMargins(20, 16, 20, 16)
        readiness_layout.setSpacing(14)

        header_r = QHBoxLayout()
        lbl_r_title = QLabel("1. KHẢ NĂNG GHI DUMP KHI SẬP MÁY (DUMP READINESS)")
        lbl_r_title.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {COLOR_TEXT_PRIMARY};")
        header_r.addWidget(lbl_r_title)

        self.lbl_readiness_badge = QLabel("CHƯA KIỂM TRA")
        self.lbl_readiness_badge.setStyleSheet(
            "background-color: #334155; color: #cbd5e1; font-weight: bold; padding: 4px 12px; border-radius: 6px;"
        )
        header_r.addWidget(self.lbl_readiness_badge, alignment=Qt.AlignRight)
        readiness_layout.addLayout(header_r)

        # Bảng thông số CrashControl & Ổ đĩa (Chiều cao linh hoạt, thoáng mắt)
        self.table_config = QTableWidget()
        self.table_config.setColumnCount(3)
        self.table_config.setHorizontalHeaderLabels(["Thành phần kiểm tra", "Giá trị hiện tại", "Đánh giá & Khuyến nghị"])
        self.table_config.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_config.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_config.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table_config.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_config.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table_config.verticalHeader().setVisible(False)
        self.table_config.verticalHeader().setDefaultSectionSize(34)
        self.table_config.setMinimumHeight(190)
        readiness_layout.addWidget(self.table_config)

        # Hàng nút thao tác khả năng ghi dump
        actions_r = QHBoxLayout()
        actions_r.setSpacing(12)

        self.btn_refresh_dump_cfg = QPushButton("🔄 Kiểm tra lại cấu hình ghi dump")
        self.btn_refresh_dump_cfg.setStyleSheet("padding: 7px 16px; font-weight: 600;")
        self.btn_refresh_dump_cfg.clicked.connect(self.refresh_dump_config)
        actions_r.addWidget(self.btn_refresh_dump_cfg)

        self.btn_enable_dump = QPushButton("⚡ Bật tự động ghi dump (Automatic Dump)")
        self.btn_enable_dump.setStyleSheet(
            f"background-color: {COLOR_ACCENT}; color: #ffffff; font-weight: bold; padding: 7px 18px; border-radius: 6px;"
        )
        self.btn_enable_dump.clicked.connect(self._on_enable_dump_clicked)
        actions_r.addWidget(self.btn_enable_dump)

        actions_r.addStretch()
        readiness_layout.addLayout(actions_r)

        main_layout.addWidget(readiness_card)

        # =====================================================================
        # MỤC 2: CẤU HÌNH PHÂN TÍCH & ĐƯỜNG DẪN HỆ THỐNG
        # =====================================================================
        cfg_card = QFrame()
        cfg_card.setObjectName("CardFrame")
        cfg_layout = QVBoxLayout(cfg_card)
        cfg_layout.setContentsMargins(20, 16, 20, 16)
        cfg_layout.setSpacing(16)

        lbl_cfg_title = QLabel("2. CẤU HÌNH PHÂN TÍCH & ĐƯỜNG DẪN HỆ THỐNG")
        lbl_cfg_title.setStyleSheet(
            f"font-size: 13px; font-weight: bold; color: {COLOR_TEXT_PRIMARY}; border-bottom: 2px solid {COLOR_BORDER}; padding-bottom: 6px;"
        )
        cfg_layout.addWidget(lbl_cfg_title)

        grid_cfg = QGridLayout()
        grid_cfg.setVerticalSpacing(14)
        grid_cfg.setHorizontalSpacing(14)
        grid_cfg.setColumnMinimumWidth(0, 180)

        # 1. CDB Path
        lbl_cdb = QLabel("Đường dẫn WinDbg (cdb.exe):")
        lbl_cdb.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-weight: 500;")
        self.txt_cdb = QLineEdit(self._settings.get("cdb_path", "") or "")
        self.txt_cdb.setPlaceholderText("Ví dụ: C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe")
        btn_browse_cdb = QPushButton("📁 Duyệt...")
        btn_browse_cdb.setFixedWidth(90)
        btn_browse_cdb.clicked.connect(self._browse_cdb)
        grid_cfg.addWidget(lbl_cdb, 0, 0)
        grid_cfg.addWidget(self.txt_cdb, 0, 1)
        grid_cfg.addWidget(btn_browse_cdb, 0, 2)

        # 2. Symbol Path
        lbl_sym = QLabel("Máy chủ Symbol Microsoft:")
        lbl_sym.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-weight: 500;")
        self.txt_sym = QLineEdit(self._settings.get("symbol_path", "") or "")
        self.txt_sym.setPlaceholderText("srv*https://msdl.microsoft.com/download/symbols...")
        grid_cfg.addWidget(lbl_sym, 1, 0)
        grid_cfg.addWidget(self.txt_sym, 1, 1, 1, 2)

        # 3. Workspace Directory
        lbl_ws = QLabel("Thư mục làm việc (Workspace):")
        lbl_ws.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-weight: 500;")
        self.txt_ws = QLineEdit(self._settings.get("workspace_dir", "workspace"))
        self.txt_ws.setPlaceholderText("Thư mục lưu CSDL tạm và mẫu dump...")
        btn_browse_ws = QPushButton("📁 Duyệt...")
        btn_browse_ws.setFixedWidth(90)
        btn_browse_ws.clicked.connect(self._browse_workspace)
        grid_cfg.addWidget(lbl_ws, 2, 0)
        grid_cfg.addWidget(self.txt_ws, 2, 1)
        grid_cfg.addWidget(btn_browse_ws, 2, 2)

        # 4. Triage Reader Settings
        triage_cfg = self._settings.get("triage_reader", {}) or {}
        lbl_triage = QLabel("Bộ đọc Minidump Triage:")
        lbl_triage.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-weight: 500;")
        triage_row = QHBoxLayout()
        triage_row.setSpacing(10)
        self.chk_triage_enabled = QCheckBox("Kích hoạt bộ đọc Triage nội bộ thuần Python (Không cần WinDbg/cdb)")
        self.chk_triage_enabled.setChecked(bool(triage_cfg.get("enabled", True)))
        self.chk_triage_enabled.setStyleSheet("color: #cbd5e1; font-weight: 500;")
        triage_row.addWidget(self.chk_triage_enabled)
        triage_row.addStretch()
        grid_cfg.addWidget(lbl_triage, 3, 0)
        grid_cfg.addLayout(triage_row, 3, 1, 1, 2)

        # 5. Cửa sổ thời gian tìm kiếm sự kiện
        lbl_win = QLabel("Cửa sổ sự kiện trước sập:")
        lbl_win.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-weight: 500;")
        row_win = QVBoxLayout()
        row_win.setSpacing(4)

        spin_h = QHBoxLayout()
        spin_h.setSpacing(8)
        self.spin_window = QSpinBox()
        self.spin_window.setRange(1, 120)
        self.spin_window.setValue(int(self._settings.get("time_window_minutes", 10)))
        self.spin_window.setSuffix(" phút")
        self.spin_window.setFixedWidth(120)
        spin_h.addWidget(self.spin_window)
        spin_h.addStretch()
        row_win.addLayout(spin_h)

        lbl_win_hint = QLabel("Khoảng thời gian quét Windows Event Log trước mỗi lần sập máy (mặc định 10 phút).")
        lbl_win_hint.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px;")
        lbl_win_hint.setWordWrap(True)
        row_win.addWidget(lbl_win_hint)

        grid_cfg.addWidget(lbl_win, 4, 0, Qt.AlignTop)
        grid_cfg.addLayout(row_win, 4, 1, 1, 2)

        # 6. Số tiến trình phân tích song song
        lbl_conc = QLabel("Tiến trình song song:")
        lbl_conc.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-weight: 500;")
        row_conc = QVBoxLayout()
        row_conc.setSpacing(4)

        spin_c_h = QHBoxLayout()
        spin_c_h.setSpacing(8)
        self.spin_conc = QSpinBox()
        self.spin_conc.setRange(1, 16)
        self.spin_conc.setValue(int(self._settings.get("concurrency", 2)))
        self.spin_conc.setSuffix(" luồng")
        self.spin_conc.setFixedWidth(120)
        spin_c_h.addWidget(self.spin_conc)
        spin_c_h.addStretch()
        row_conc.addLayout(spin_c_h)

        lbl_conc_hint = QLabel("Số luồng CPU tối đa dùng để phân tích file dump đồng thời (khuyến nghị 2-4 luồng).")
        lbl_conc_hint.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px;")
        lbl_conc_hint.setWordWrap(True)
        row_conc.addWidget(lbl_conc_hint)

        grid_cfg.addWidget(lbl_conc, 5, 0, Qt.AlignTop)
        grid_cfg.addLayout(row_conc, 5, 1, 1, 2)

        grid_cfg.setColumnStretch(1, 1)
        cfg_layout.addLayout(grid_cfg)

        # Nút lưu cấu hình
        actions_cfg = QHBoxLayout()
        self.btn_save_settings = QPushButton("💾 Lưu cấu hình hệ thống")
        self.btn_save_settings.setStyleSheet(
            f"background-color: {COLOR_ACCENT}; color: #ffffff; font-weight: bold; padding: 8px 22px; border-radius: 6px;"
        )
        self.btn_save_settings.clicked.connect(self._on_save_settings_clicked)
        actions_cfg.addWidget(self.btn_save_settings)
        actions_cfg.addStretch()
        cfg_layout.addLayout(actions_cfg)

        main_layout.addWidget(cfg_card)

        # =====================================================================
        # MỤC 3: QUẢN LÝ BỘ QUY TẮC CHẨN ĐOÁN (RULES MANAGEMENT)
        # =====================================================================
        rules_card = QFrame()
        rules_card.setObjectName("CardFrame")
        rules_layout = QVBoxLayout(rules_card)
        rules_layout.setContentsMargins(20, 16, 20, 16)
        rules_layout.setSpacing(12)

        lbl_rules_title = QLabel("3. QUẢN LÝ BỘ QUY TẮC CHẨN ĐOÁN (YAML RULES)")
        lbl_rules_title.setStyleSheet(
            f"font-size: 13px; font-weight: bold; color: {COLOR_TEXT_PRIMARY}; border-bottom: 2px solid {COLOR_BORDER}; padding-bottom: 6px;"
        )
        rules_layout.addWidget(lbl_rules_title)

        lbl_rules_desc = QLabel(
            "Tất cả quy tắc mã lỗi Bug Check, phân loại module Microsoft/USB, luật bằng chứng Minidump Triage, "
            "ánh xạ driver bên thứ ba và mẫu hình đa crash đều được lưu trong các file YAML dễ đọc, có thể cập nhật không cần biên dịch lại."
        )
        lbl_rules_desc.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px; line-height: 1.4;")
        lbl_rules_desc.setWordWrap(True)
        rules_layout.addWidget(lbl_rules_desc)

        actions_rules = QHBoxLayout()
        actions_rules.setSpacing(12)

        self.btn_validate_rules = QPushButton("🔍 Kiểm tra tính hợp lệ bộ quy tắc (Validate Rules)")
        self.btn_validate_rules.setStyleSheet("font-weight: bold; padding: 7px 18px;")
        self.btn_validate_rules.clicked.connect(self._on_validate_rules_clicked)
        actions_rules.addWidget(self.btn_validate_rules)

        self.btn_open_rules_folder = QPushButton("📂 Mở thư mục chứa file quy tắc (config/rules)")
        self.btn_open_rules_folder.setStyleSheet("font-weight: 500; padding: 7px 16px;")
        self.btn_open_rules_folder.clicked.connect(self._on_open_rules_folder_clicked)
        actions_rules.addWidget(self.btn_open_rules_folder)

        actions_rules.addStretch()
        rules_layout.addLayout(actions_rules)

        main_layout.addWidget(rules_card)

        # =====================================================================
        # MỤC 4: THÔNG TIN PHẦN MỀM & BẢN QUYỀN (ABOUT & CREDITS)
        # =====================================================================
        about_card = QFrame()
        about_card.setObjectName("CardFrame")
        about_layout = QVBoxLayout(about_card)
        about_layout.setContentsMargins(20, 16, 20, 16)
        about_layout.setSpacing(12)

        lbl_about_title = QLabel("4. THÔNG TIN PHẦN MỀM & BẢN QUYỀN")
        lbl_about_title.setStyleSheet(
            f"font-size: 13px; font-weight: bold; color: {COLOR_TEXT_PRIMARY}; border-bottom: 2px solid {COLOR_BORDER}; padding-bottom: 6px;"
        )
        about_layout.addWidget(lbl_about_title)

        grid_about = QGridLayout()
        grid_about.setVerticalSpacing(10)
        grid_about.setHorizontalSpacing(16)
        grid_about.setColumnMinimumWidth(0, 160)

        lbl_app_name = QLabel("Tên phần mềm:")
        lbl_app_name.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-weight: 500;")
        lbl_app_val = QLabel("DumpAnalyzer")
        lbl_app_val.setStyleSheet("font-weight: bold; color: #38bdf8; font-size: 13px;")
        grid_about.addWidget(lbl_app_name, 0, 0)
        grid_about.addWidget(lbl_app_val, 0, 1)

        lbl_app_ver = QLabel("Phiên bản:")
        lbl_app_ver.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-weight: 500;")
        from dumpanalyzer import __version__
        lbl_ver_val = QLabel(f"v{__version__}")
        lbl_ver_val.setStyleSheet("font-weight: bold; color: #4ade80; font-size: 13px;")
        grid_about.addWidget(lbl_app_ver, 1, 0)
        grid_about.addWidget(lbl_ver_val, 1, 1)

        lbl_author = QLabel("Tác giả phát triển:")
        lbl_author.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-weight: 500;")
        lbl_author_val = QLabel("Lilbow")
        lbl_author_val.setStyleSheet("font-weight: 800; color: #f59e0b; font-size: 14px;")
        grid_about.addWidget(lbl_author, 2, 0)
        grid_about.addWidget(lbl_author_val, 2, 1)

        lbl_purpose = QLabel("Mục đích ứng dụng:")
        lbl_purpose.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-weight: 500;")
        lbl_purpose_val = QLabel(
            "Chẩn đoán và phân tích nguyên nhân sự cố BSOD (màn hình xanh), tự động tương quan "
            "với Windows Event Log trước thời điểm sập máy nhằm hỗ trợ kỹ thuật viên IT xử lý nhanh chóng, chính xác."
        )
        lbl_purpose_val.setWordWrap(True)
        lbl_purpose_val.setStyleSheet("color: #cbd5e1; font-size: 12px; line-height: 1.4;")
        grid_about.addWidget(lbl_purpose, 3, 0, Qt.AlignTop)
        grid_about.addWidget(lbl_purpose_val, 3, 1, Qt.AlignTop)

        grid_about.setColumnStretch(1, 1)
        about_layout.addLayout(grid_about)
        main_layout.addWidget(about_card)

        main_layout.addStretch()

        scroll_area.setWidget(container_widget)
        root_layout.addWidget(scroll_area)

    def refresh_dump_config(self) -> None:
        """Đọc lại cấu hình registry và cập nhật bảng kiểm tra khả năng ghi dump."""
        reg_data = read_registry_crash_control()
        pf_data = check_pagefile_status()
        disk_data = check_disk_space_and_ram()
        volmgr_data = check_volmgr_events()
        readiness = evaluate_readiness(reg_data, pf_data, disk_data, volmgr_data)
        status = readiness.get("status", "KHÔNG GHI ĐƯỢC DUMP")

        if status == "SẴN SÀNG":
            self.lbl_readiness_badge.setText("SẴN SÀNG GHI DUMP")
            self.lbl_readiness_badge.setStyleSheet(
                f"background-color: #14532d; color: #86efac; border: 1px solid {COLOR_SUCCESS}; font-weight: bold; padding: 4px 12px; border-radius: 6px;"
            )
        elif status == "CẦN CHÚ Ý":
            self.lbl_readiness_badge.setText("CẦN CHÚ Ý")
            self.lbl_readiness_badge.setStyleSheet(
                f"background-color: #78350f; color: #fde68a; border: 1px solid {COLOR_WARNING}; font-weight: bold; padding: 4px 12px; border-radius: 6px;"
            )
        else:
            self.lbl_readiness_badge.setText("KHÔNG GHI ĐƯỢC DUMP")
            self.lbl_readiness_badge.setStyleSheet(
                f"background-color: #7f1d1d; color: #fca5a5; border: 1px solid {COLOR_DANGER}; font-weight: bold; padding: 4px 12px; border-radius: 6px;"
            )

        dump_code = reg_data.get("CrashDumpEnabled")
        mode_desc = CRASH_DUMP_MODES.get(dump_code, f"Mã không xác định ({dump_code})")
        volmgr_summary = "Không có lỗi ghi dump"
        if volmgr_data.get("has_failure_161"):
            volmgr_summary = f"Cảnh báo: Phát hiện {volmgr_data.get('event_161_count', 1)} lỗi Event 161 (ghi dump thất bại)"
        elif volmgr_data.get("has_success_162"):
            volmgr_summary = f"Hoạt động tốt: {volmgr_data.get('event_162_count', 1)} lần ghi dump Event 162 thành công"

        rows = [
            ("Loại dump thiết lập (CrashDumpEnabled)", f"{dump_code} ({mode_desc})", "Khuyến nghị: 7 (Automatic memory dump)"),
            ("Bộ nhớ RAM vật lý", f"{disk_data.get('ram_gb', 0):.1f} GB", "Yêu cầu tối thiểu để lưu kernel dump"),
            ("Dung lượng trống ổ hệ thống (C:)", f"{disk_data.get('free_disk_gb', 0):.1f} GB", f"Khuyến nghị an toàn: >= {disk_data.get('recommended_free_gb', 10):.1f} GB"),
            ("Tình trạng Pagefile ổ C:", "Có cấu hình" if pf_data.get("has_system_drive_pagefile") else "Thiếu hoặc quá nhỏ", "Bắt buộc có Pagefile trên C: để ghi dump"),
            ("Nhật ký dịch vụ ghi dump (volmgr)", volmgr_summary, "Event 161 (thất bại) / Event 162 (thành công)"),
        ]

        self.table_config.setRowCount(len(rows))
        for r_idx, (col0, col1, col2) in enumerate(rows):
            self.table_config.setItem(r_idx, 0, QTableWidgetItem(col0))
            item1 = QTableWidgetItem(col1)
            item1.setTextAlignment(Qt.AlignCenter)
            self.table_config.setItem(r_idx, 1, item1)
            self.table_config.setItem(r_idx, 2, QTableWidgetItem(col2))

    def _on_enable_dump_clicked(self) -> None:
        """Xử lý bật tự động ghi dump có hộp thoại xác nhận."""
        reply = QMessageBox.question(
            self,
            "Xác nhận thay đổi cấu hình hệ thống",
            "Bạn có chắc chắn muốn bật tính năng tự động ghi dump (Automatic Memory Dump)?\n\n"
            "Hệ thống sẽ:\n"
            "1. Tự động xuất file sao lưu registry hiện tại (.reg) vào thư mục backup/.\n"
            "2. Thiết lập giá trị CrashDumpEnabled = 7 trong khóa CrashControl.\n"
            "3. Không can thiệp vào Pagefile hay các khóa registry khác.\n\n"
            "Lưu ý: Có thể cần khởi động lại máy để Windows nhận cấu hình mới.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if reply != QMessageBox.Yes:
            return

        result = apply_automatic_dump(confirmed=True)
        if result.get("success"):
            msg = result.get("message", "")
            QMessageBox.information(self, "Cấu hình thành công", f"Đã áp dụng cấu hình ghi dump thành công!\n\n{msg}")
            self.refresh_dump_config()
        else:
            msg = result.get("message", "")
            QMessageBox.critical(self, "Không thể áp dụng", f"Áp dụng cấu hình thất bại:\n\n{msg}")

    def _browse_cdb(self) -> None:
        """Chọn file cdb.exe."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Chọn file cdb.exe", "", "Thực thi WinDbg (cdb.exe);;Tất cả tệp (*.*)")
        if file_path:
            self.txt_cdb.setText(file_path)

    def _browse_workspace(self) -> None:
        """Chọn thư mục workspace."""
        dir_path = QFileDialog.getExistingDirectory(self, "Chọn thư mục làm việc (Workspace)")
        if dir_path:
            self.txt_ws.setText(dir_path)

    def _on_save_settings_clicked(self) -> None:
        """Lưu lại các thiết lập vào settings.yaml."""
        try:
            self._settings["cdb_path"] = self.txt_cdb.text().strip()
            self._settings["symbol_path"] = self.txt_sym.text().strip()
            self._settings["workspace_dir"] = self.txt_ws.text().strip() or "workspace"
            self._settings["time_window_minutes"] = self.spin_window.value()
            self._settings["concurrency"] = self.spin_conc.value()

            if "triage_reader" not in self._settings:
                self._settings["triage_reader"] = {}
            self._settings["triage_reader"]["enabled"] = self.chk_triage_enabled.isChecked()

            save_settings(self._settings_path, self._settings)
            QMessageBox.information(self, "Lưu thành công", "Đã lưu cài đặt hệ thống vào config/settings.yaml thành công!")
        except Exception as e:
            QMessageBox.critical(self, "Lỗi lưu cấu hình", f"Không thể lưu cấu hình:\n{str(e)}")

    def _on_validate_rules_clicked(self) -> None:
        """Chạy kiểm tra tính hợp lệ của các file quy tắc YAML."""
        is_ok, errors, _ = validate_rules_and_settings()
        if is_ok:
            QMessageBox.information(
                self,
                "Bộ quy tắc Hợp lệ",
                "Tuyệt vời! Toàn bộ các file quy tắc YAML và cài đặt đều hợp lệ và sẵn sàng sử dụng!\n\n"
                "- settings.yaml: Hợp lệ\n"
                "- bugcheck_rules.yaml: Đạt chuẩn\n"
                "- driver_map.yaml: Đạt chuẩn\n"
                "- event_rules.yaml: Đạt chuẩn\n"
                "- patterns.yaml: Đạt chuẩn\n"
                "- module_classes.yaml: Đạt chuẩn\n"
                "- triage_rules.yaml: Đạt chuẩn",
            )
        else:
            err_msg = "\n".join(f"• {e}" for e in errors)
            QMessageBox.critical(
                self,
                "Phát hiện lỗi trong bộ quy tắc",
                f"Đã phát hiện các lỗi cú pháp hoặc ngữ nghĩa cần sửa:\n\n{err_msg}",
            )

    def _on_open_rules_folder_clicked(self) -> None:
        """Mở thư mục config/rules trong File Explorer."""
        rules_dir = get_rules_dir()
        rules_dir.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(str(rules_dir))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(rules_dir)])
            else:
                subprocess.Popen(["xdg-open", str(rules_dir)])
        except Exception:
            QMessageBox.information(self, "Đường dẫn thư mục", f"Đường dẫn thư mục quy tắc:\n{rules_dir}")
