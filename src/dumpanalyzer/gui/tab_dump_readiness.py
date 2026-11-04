"""Tab Sẵn sàng ghi dump (Dump Readiness Tab) trong PySide6 DumpAnalyzer (Đợt 04).

Bao gồm:
- Khu vực 1: Máy cục bộ (Local Machine Readiness) với huy hiệu trạng thái, proof level,
  4 thẻ con chi tiết (Registry, Pagefile, Ổ đĩa/RAM, Volmgr & Dump Gap), hộp lý do và khuyến nghị,
  các nút thao tác an toàn (Kiểm tra lại, Bật ghi dump, Hoàn tác, Xuất gói, Mở thư mục).
- Khu vực 2: Đội máy (Fleet Overview) tải báo cáo từ thư mục chia sẻ, bộ lọc, tìm kiếm,
  bảng danh sách máy trạm và xuất báo cáo Excel 3 sheet.
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
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
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from dumpanalyzer.collectors.dump_config import (
    CRASH_DUMP_MODES,
    STATUS_ATTENTION,
    STATUS_BLOCKED,
    STATUS_READY,
    STATUS_READY_PENDING_REBOOT,
    STATUS_UNKNOWN,
    collect_dump_readiness,
    enable_crash_dump,
    rollback_crash_dump,
)
from dumpanalyzer.core.config import get_settings_path, load_settings
from dumpanalyzer.engine.deployment_package import (
    aggregate_fleet_reports,
    export_fleet_readiness_excel,
    generate_deployment_package,
)
from dumpanalyzer.gui.theme import (
    COLOR_ACCENT,
    COLOR_BG_INPUT,
    COLOR_BORDER,
    COLOR_DANGER,
    COLOR_SUCCESS,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_WARNING,
)
from dumpanalyzer.storage.db import Database


class ReadinessWorker(QThread):
    """Luồng ngầm để quét hoặc áp dụng cấu hình dump readiness không làm treo giao diện."""

    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, action: str = "collect", target_mode: int = 7, backup_path: Optional[str] = None):
        super().__init__()
        self.action = action
        self.target_mode = target_mode
        self.backup_path = backup_path

    def run(self) -> None:
        try:
            db = Database()
            if self.action == "collect":
                res = collect_dump_readiness(target_mode=self.target_mode, db=db)
                self.finished.emit(res)
            elif self.action == "enable":
                res = enable_crash_dump(
                    target_mode=self.target_mode,
                    confirmed=True,
                    actor="gui_admin",
                    db=db,
                )
                self.finished.emit(res)
            elif self.action == "rollback" and self.backup_path:
                res = rollback_crash_dump(
                    backup_path=self.backup_path,
                    confirmed=True,
                    actor="gui_admin",
                    db=db,
                )
                self.finished.emit(res)
            db.close()
        except Exception as e:
            self.error.emit(str(e))


class DumpReadinessTab(QWidget):
    """Tab Giao diện chuyên trách về Sẵn sàng ghi dump (Đợt 04)."""

    readiness_changed = Signal(dict)  # Phát ra khi trạng thái cục bộ thay đổi

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._current_report: Dict[str, Any] = {}
        self._fleet_data: Dict[str, Any] = {}
        self._worker: Optional[ReadinessWorker] = None
        self._init_ui()
        self.refresh_local()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(18, 16, 18, 16)
        main_layout.setSpacing(14)

        # Tab widget phân chia Máy cục bộ và Đội máy
        self.sub_tabs = QTabWidget()

        # Sub-tab 1: Máy cục bộ
        local_widget = self._build_local_tab()
        self.sub_tabs.addTab(local_widget, "Máy cục bộ")

        # Sub-tab 2: Đội máy
        fleet_widget = self._build_fleet_tab()
        self.sub_tabs.addTab(fleet_widget, "Tổng hợp Đội máy (Fleet)")

        main_layout.addWidget(self.sub_tabs)

    # ==================== KHU VỰC 1: MÁY CỤC BỘ ====================

    def _build_local_tab(self) -> QWidget:
        container = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(16, 16, 16, 16)
        inner_layout.setSpacing(18)

        # 1. Huy hiệu trạng thái lớn ở trên cùng (Badge)
        self.badge_frame = QFrame()
        self.badge_frame.setObjectName("CardFrame")
        badge_layout = QVBoxLayout(self.badge_frame)
        badge_layout.setContentsMargins(20, 18, 20, 18)
        badge_layout.setSpacing(12)

        top_row = QHBoxLayout()
        self.lbl_status_badge = QLabel("ĐANG KIỂM TRA...")
        self.lbl_status_badge.setAlignment(Qt.AlignCenter)
        self.lbl_status_badge.setStyleSheet(
            f"background-color: {COLOR_BG_INPUT}; color: {COLOR_TEXT_PRIMARY}; font-weight: bold; padding: 10px 24px; border-radius: 8px; font-size: 15px; min-height: 24px;"
        )
        top_row.addWidget(self.lbl_status_badge)

        self.lbl_proof_badge = QLabel("Mức chứng minh: Chưa rõ")
        self.lbl_proof_badge.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 12px; font-weight: 600; padding: 6px 10px;"
        )
        top_row.addWidget(self.lbl_proof_badge, alignment=Qt.AlignRight)
        badge_layout.addLayout(top_row)

        self.lbl_status_summary = QLabel("Đang tải dữ liệu kiểm tra khả năng ghi dump...")
        self.lbl_status_summary.setStyleSheet(f"font-size: 13px; color: {COLOR_TEXT_PRIMARY}; line-height: 1.4;")
        self.lbl_status_summary.setWordWrap(True)
        badge_layout.addWidget(self.lbl_status_summary)

        inner_layout.addWidget(self.badge_frame)

        # 2. Lưới 4 Thẻ con chi tiết (2x2 Grid)
        grid_cards = QGridLayout()
        grid_cards.setHorizontalSpacing(16)
        grid_cards.setVerticalSpacing(16)

        # Card 1: Registry CrashControl
        self.card_registry = self._create_card("1. Cấu hình Registry (CrashControl)")
        self.lbl_reg_cde = QLabel("CrashDumpEnabled: ...")
        self.lbl_reg_autoreboot = QLabel("AutoReboot: ...")
        self.lbl_reg_minidumpdir = QLabel("MinidumpDir: ...")
        self.lbl_reg_readok = QLabel("Đọc Registry: ...")
        self.card_registry.layout().addWidget(self.lbl_reg_cde)
        self.card_registry.layout().addWidget(self.lbl_reg_autoreboot)
        self.card_registry.layout().addWidget(self.lbl_reg_minidumpdir)
        self.card_registry.layout().addWidget(self.lbl_reg_readok)
        grid_cards.addWidget(self.card_registry, 0, 0)

        # Card 2: Bộ nhớ ảo (Pagefile)
        self.card_pagefile = self._create_card("2. Bộ nhớ ảo (Pagefile)")
        self.lbl_pf_state = QLabel("Trạng thái: ...")
        self.lbl_pf_size = QLabel("Dung lượng ổ C: ...")
        self.lbl_pf_auto = QLabel("Tự động quản lý: ...")
        self.lbl_pf_dedicated = QLabel("Dedicated dump file: ...")
        self.card_pagefile.layout().addWidget(self.lbl_pf_state)
        self.card_pagefile.layout().addWidget(self.lbl_pf_size)
        self.card_pagefile.layout().addWidget(self.lbl_pf_auto)
        self.card_pagefile.layout().addWidget(self.lbl_pf_dedicated)
        grid_cards.addWidget(self.card_pagefile, 0, 1)

        # Card 3: Ổ đĩa & RAM
        self.card_disk = self._create_card("3. Ổ đĩa hệ thống & RAM")
        self.lbl_disk_free = QLabel("Ổ C trống: ...")
        self.lbl_ram_size = QLabel("RAM vật lý: ...")
        self.lbl_disk_ratio = QLabel("Tỷ lệ trống C / RAM: ...")
        self.lbl_disk_verdict = QLabel("Đánh giá đĩa: ...")
        self.card_disk.layout().addWidget(self.lbl_disk_free)
        self.card_disk.layout().addWidget(self.lbl_ram_size)
        self.card_disk.layout().addWidget(self.lbl_disk_ratio)
        self.card_disk.layout().addWidget(self.lbl_disk_verdict)
        grid_cards.addWidget(self.card_disk, 1, 0)

        # Card 4: Volmgr & Dump Gap
        self.card_volmgr = self._create_card("4. Lịch sử ghi dump (volmgr) & Dump Gap")
        self.lbl_vm_success = QLabel("Ghi thành công gần nhất: Không có")
        self.lbl_vm_failure = QLabel("Lỗi gần nhất: Không có")
        self.lbl_gap_info = QLabel("Dump Gap: Chưa đối chiếu")
        self.lbl_last_boot = QLabel("Khởi động lại gần nhất: ...")
        self.card_volmgr.layout().addWidget(self.lbl_vm_success)
        self.card_volmgr.layout().addWidget(self.lbl_vm_failure)
        self.card_volmgr.layout().addWidget(self.lbl_gap_info)
        self.card_volmgr.layout().addWidget(self.lbl_last_boot)
        grid_cards.addWidget(self.card_volmgr, 1, 1)

        inner_layout.addLayout(grid_cards)

        # 3. Hộp Lý do và Khuyến nghị
        reasons_card = self._create_card("Lý do chi tiết & Khuyến nghị hành động")
        self.txt_reasons = QLabel("Không có cảnh báo.")
        self.txt_reasons.setStyleSheet(f"color: {COLOR_TEXT_PRIMARY}; font-size: 13px; line-height: 1.5; padding: 4px 0;")
        self.txt_reasons.setWordWrap(True)
        reasons_card.layout().addWidget(self.txt_reasons)
        inner_layout.addWidget(reasons_card)

        # 4. Cụm nút hành động
        actions_frame = QFrame()
        actions_layout = QHBoxLayout(actions_frame)
        actions_layout.setContentsMargins(0, 0, 0, 0)
        actions_layout.setSpacing(12)

        self.btn_refresh = QPushButton("🔄 Kiểm tra lại (F5)")
        self.btn_refresh.setStyleSheet("font-weight: bold; padding: 8px 16px;")
        self.btn_refresh.setMinimumHeight(34)
        self.btn_refresh.clicked.connect(self.refresh_local)
        actions_layout.addWidget(self.btn_refresh)

        self.btn_enable = QPushButton("⚡ Bật ghi dump an toàn")
        self.btn_enable.setStyleSheet(
            f"background-color: {COLOR_SUCCESS}; color: #ffffff; font-weight: bold; padding: 8px 18px; border-radius: 6px;"
        )
        self.btn_enable.setMinimumHeight(34)
        self.btn_enable.clicked.connect(self._on_enable_clicked)
        actions_layout.addWidget(self.btn_enable)

        self.btn_rollback = QPushButton("↩ Hoàn tác thay đổi")
        self.btn_rollback.setStyleSheet("font-weight: bold; padding: 8px 16px;")
        self.btn_rollback.setMinimumHeight(34)
        self.btn_rollback.clicked.connect(self._on_rollback_clicked)
        actions_layout.addWidget(self.btn_rollback)

        self.btn_package = QPushButton("📦 Xuất gói triển khai (.ps1)")
        self.btn_package.setStyleSheet("font-weight: bold; padding: 8px 16px;")
        self.btn_package.setMinimumHeight(34)
        self.btn_package.clicked.connect(self._on_package_clicked)
        actions_layout.addWidget(self.btn_package)

        self.btn_open_dir = QPushButton("📁 Mở thư mục sao lưu")
        self.btn_open_dir.setStyleSheet("font-weight: bold; padding: 8px 16px;")
        self.btn_open_dir.setMinimumHeight(34)
        self.btn_open_dir.clicked.connect(self._on_open_backup_dir)
        actions_layout.addWidget(self.btn_open_dir)

        actions_layout.addStretch()
        inner_layout.addWidget(actions_frame)

        scroll.setWidget(inner)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(scroll)
        return container

    def _create_card(self, title: str) -> QFrame:
        card = QFrame()
        card.setObjectName("CardFrame")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(18, 16, 18, 16)
        card_layout.setSpacing(10)
        lbl_t = QLabel(title)
        lbl_t.setStyleSheet(
            f"font-size: 13px; font-weight: bold; color: {COLOR_TEXT_PRIMARY}; border-bottom: 1px solid {COLOR_BORDER}; padding-bottom: 8px; margin-bottom: 4px;"
        )
        card_layout.addWidget(lbl_t)
        return card

    # ==================== KHU VỰC 2: ĐỘI MÁY (FLEET) ====================

    def _build_fleet_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # Toolbar trên cùng
        tb = QHBoxLayout()
        tb.setSpacing(12)

        lbl_dir = QLabel("Thư mục chia sẻ báo cáo:")
        lbl_dir.setStyleSheet(f"font-weight: 600; color: {COLOR_TEXT_MUTED};")
        tb.addWidget(lbl_dir)

        self.txt_fleet_dir = QLineEdit()
        self.txt_fleet_dir.setPlaceholderText("Đường dẫn UNC (\\\\server\\share) hoặc thư mục local...")
        self.txt_fleet_dir.setMinimumHeight(34)
        tb.addWidget(self.txt_fleet_dir, 1)

        btn_browse_fleet = QPushButton("Duyệt...")
        btn_browse_fleet.setMinimumHeight(34)
        btn_browse_fleet.clicked.connect(self._on_browse_fleet_dir)
        tb.addWidget(btn_browse_fleet)

        self.btn_load_fleet = QPushButton("📥 Nạp báo cáo đội máy")
        self.btn_load_fleet.setStyleSheet(
            f"background-color: {COLOR_ACCENT}; color: #ffffff; font-weight: bold; padding: 7px 16px; border-radius: 6px;"
        )
        self.btn_load_fleet.setMinimumHeight(34)
        self.btn_load_fleet.clicked.connect(self._on_load_fleet_clicked)
        tb.addWidget(self.btn_load_fleet)

        self.btn_export_fleet_excel = QPushButton("📊 Xuất báo cáo Excel (.xlsx)")
        self.btn_export_fleet_excel.setStyleSheet(
            f"background-color: {COLOR_SUCCESS}; color: #ffffff; font-weight: bold; padding: 7px 16px; border-radius: 6px;"
        )
        self.btn_export_fleet_excel.setMinimumHeight(34)
        self.btn_export_fleet_excel.clicked.connect(self._on_export_fleet_excel_clicked)
        tb.addWidget(self.btn_export_fleet_excel)

        layout.addLayout(tb)

        # Bảng KPI Tóm tắt
        kpi_frame = QFrame()
        kpi_frame.setObjectName("CardFrame")
        kpi_layout = QHBoxLayout(kpi_frame)
        kpi_layout.setContentsMargins(18, 16, 18, 16)
        kpi_layout.setSpacing(24)

        self.lbl_kpi_total = QLabel("Tổng số máy: 0")
        self.lbl_kpi_total.setStyleSheet("font-weight: bold; font-size: 13px;")
        kpi_layout.addWidget(self.lbl_kpi_total)

        self.lbl_kpi_ready_rate = QLabel("Tỷ lệ READY: 0.0%")
        self.lbl_kpi_ready_rate.setStyleSheet(f"font-weight: bold; font-size: 13px; color: {COLOR_SUCCESS};")
        kpi_layout.addWidget(self.lbl_kpi_ready_rate)

        self.lbl_kpi_reboot = QLabel("Chờ reboot: 0")
        self.lbl_kpi_reboot.setStyleSheet(f"font-weight: bold; font-size: 13px; color: {COLOR_WARNING};")
        kpi_layout.addWidget(self.lbl_kpi_reboot)

        self.lbl_kpi_blocked = QLabel("Bị chặn: 0")
        self.lbl_kpi_blocked.setStyleSheet(f"font-weight: bold; font-size: 13px; color: {COLOR_DANGER};")
        kpi_layout.addWidget(self.lbl_kpi_blocked)

        self.lbl_kpi_stale = QLabel("Quá hạn: 0")
        self.lbl_kpi_stale.setStyleSheet(f"font-weight: bold; font-size: 13px; color: {COLOR_TEXT_MUTED};")
        kpi_layout.addWidget(self.lbl_kpi_stale)

        kpi_layout.addStretch()
        layout.addWidget(kpi_frame)

        # Thanh tìm kiếm & lọc
        filter_row = QHBoxLayout()
        filter_row.setSpacing(12)

        lbl_filter = QLabel("Lọc trạng thái:")
        lbl_filter.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px; font-weight: 500;")
        filter_row.addWidget(lbl_filter)

        self.combo_fleet_filter = QComboBox()
        self.combo_fleet_filter.addItems(["Tất cả", "READY", "READY_PENDING_REBOOT", "ATTENTION", "BLOCKED", "UNKNOWN", "Quá hạn (>14 ngày)"])
        self.combo_fleet_filter.setMinimumHeight(34)
        self.combo_fleet_filter.setMinimumWidth(180)
        self.combo_fleet_filter.currentTextChanged.connect(self._apply_fleet_filter)
        filter_row.addWidget(self.combo_fleet_filter)

        lbl_search = QLabel("Tìm tên máy:")
        lbl_search.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px; font-weight: 500;")
        filter_row.addWidget(lbl_search)

        self.txt_fleet_search = QLineEdit()
        self.txt_fleet_search.setPlaceholderText("Nhập hostname...")
        self.txt_fleet_search.setMinimumHeight(34)
        self.txt_fleet_search.textChanged.connect(self._apply_fleet_filter)
        filter_row.addWidget(self.txt_fleet_search, 1)

        layout.addLayout(filter_row)

        # Bảng danh sách máy trạm
        self.table_fleet = QTableWidget(0, 9)
        self.table_fleet.setHorizontalHeaderLabels([
            "Hostname", "IP Address", "Hệ điều hành", "Trạng thái", "CrashControl", "RAM (GB)", "Ổ C: Trống (GB)", "Cập nhật lúc", "Lý do / Ghi chú"
        ])
        self.table_fleet.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table_fleet.horizontalHeader().setStretchLastSection(True)
        self.table_fleet.verticalHeader().setDefaultSectionSize(36)
        self.table_fleet.setAlternatingRowColors(True)
        layout.addWidget(self.table_fleet, 1)

        return container

    # ==================== LOGIC XỬ LÝ SỰ KIỆN MÁY CỤC BỘ ====================

    def refresh_local(self) -> None:
        """Thu thập lại trạng thái sẵn sàng của máy cục bộ."""
        self.lbl_status_badge.setText("ĐANG QUÉT...")
        self.lbl_status_summary.setText("Đang đọc Registry CrashControl, Pagefile và System Event Log...")
        self.btn_refresh.setEnabled(False)

        self._worker = ReadinessWorker(action="collect")
        self._worker.finished.connect(self._on_local_collected)
        self._worker.error.connect(self._on_local_error)
        self._worker.start()

    def _on_local_collected(self, report: dict) -> None:
        self.btn_refresh.setEnabled(True)
        self._current_report = report
        self.readiness_changed.emit(report)

        res = report.get("result", {})
        status = res.get("status", STATUS_UNKNOWN)
        proof = res.get("proof_level", "none")
        proof_str = "Đã có bằng chứng thực tế (volmgr 1001)" if proof == "evidence_of_success" else "Chưa có bằng chứng thực tế"

        # Cập nhật Badge
        if status == STATUS_READY:
            badge_style = f"background-color: {COLOR_SUCCESS}; color: #ffffff; font-weight: bold; padding: 8px 16px; border-radius: 8px; font-size: 15px;"
            badge_text = "✓ SẴN SÀNG GHI DUMP (READY)"
        elif status == STATUS_READY_PENDING_REBOOT:
            badge_style = "background-color: #78350f; color: #fef08a; border: 2px solid #f59e0b; font-weight: bold; padding: 8px 16px; border-radius: 8px; font-size: 15px;"
            badge_text = "⏳ ĐÃ BẬT GHI DUMP (Chờ khởi động lại máy để áp dụng)"
        elif status == STATUS_ATTENTION:
            badge_style = "background-color: #854d0e; color: #fef9c3; border: 1px solid #eab308; font-weight: bold; padding: 8px 16px; border-radius: 8px; font-size: 15px;"
            badge_text = "⚠ CẦN CHÚ Ý (ATTENTION)"
        elif status == STATUS_BLOCKED:
            badge_style = f"background-color: {COLOR_DANGER}; color: #ffffff; font-weight: bold; padding: 8px 16px; border-radius: 8px; font-size: 15px;"
            badge_text = "⛔ BỊ CHẶN (BLOCKED)"
        else:
            badge_style = f"background-color: {COLOR_BG_INPUT}; color: {COLOR_TEXT_PRIMARY}; font-weight: bold; padding: 8px 16px; border-radius: 8px; font-size: 15px;"
            badge_text = "❓ KHÔNG XÁC ĐỊNH (UNKNOWN)"

        self.lbl_status_badge.setStyleSheet(badge_style)
        self.lbl_status_badge.setText(badge_text)
        self.lbl_proof_badge.setText(f"Mức chứng minh: {proof_str}")
        self.lbl_status_summary.setText(f"Tóm tắt: {res.get('summary', '')}")

        # Card 1: Registry
        reg = report.get("registry", {})
        cde = reg.get("crash_dump_enabled")
        mode_desc = CRASH_DUMP_MODES.get(cde, "Không rõ") if cde is not None else "Không tồn tại"
        self.lbl_reg_cde.setText(f"CrashDumpEnabled: {cde} ({mode_desc})")
        self.lbl_reg_autoreboot.setText(f"AutoReboot: {'Bật (1)' if reg.get('auto_reboot') == 1 else 'Tắt (0)'}")
        self.lbl_reg_minidumpdir.setText(f"MinidumpDir: {reg.get('minidump_dir', 'Mặc định')}")
        self.lbl_reg_readok.setText(f"Đọc Registry: {'Thành công' if reg.get('read_ok') else 'Thất bại/Lỗi quyền'}")

        # Card 2: Pagefile
        pf = report.get("pagefile", {})
        self.lbl_pf_state.setText(f"Trạng thái: {pf.get('state', 'unknown').upper()}")
        self.lbl_pf_size.setText(f"Dung lượng ổ C: {pf.get('system_drive_size_mb', 0)} MB")
        self.lbl_pf_auto.setText(f"Tự động quản lý: {'Có' if pf.get('automatic_managed') else 'Không'}")
        ded = pf.get("dedicated_dump_file")
        self.lbl_pf_dedicated.setText(f"Dedicated dump file: {ded.get('path')} ({ded.get('size_mb', 0)} MB)" if ded else "Dedicated dump file: Không cấu hình")

        # Card 3: Ổ đĩa & RAM
        disk = report.get("disk", {})
        free_gb = disk.get("free_gb", 0)
        ram_gb = report.get("ram_gb", 0)
        self.lbl_disk_free.setText(f"Ổ {disk.get('system_drive', 'C:')} trống: {free_gb} GB")
        self.lbl_ram_size.setText(f"RAM vật lý: {ram_gb} GB")
        ratio = (free_gb / ram_gb * 100) if ram_gb > 0 else 0
        self.lbl_disk_ratio.setText(f"Tỷ lệ trống C / RAM: {ratio:.1f}%")
        self.lbl_disk_verdict.setText("Đánh giá đĩa: Đủ dung lượng" if free_gb >= 10 else "Đánh giá đĩa: Rất ít dung lượng (< 10GB)")

        # Card 4: Volmgr & Gap
        vm = report.get("volmgr", {})
        self.lbl_vm_success.setText(f"Ghi thành công gần nhất: {vm.get('last_success_utc') or 'Chưa ghi nhận'}")
        self.lbl_vm_failure.setText(f"Lỗi gần nhất: {vm.get('last_failure_utc') or 'Không có lỗi'}")
        gap = report.get("dump_gap")
        if gap and gap.get("missing", 0) > 0:
            self.lbl_gap_info.setText(f"Dump Gap: THIẾU {gap.get('missing')} DUMP (Có {gap.get('expected_bsod')} BSOD Event 41)")
            self.lbl_gap_info.setStyleSheet(f"color: {COLOR_WARNING}; font-weight: bold;")
        else:
            self.lbl_gap_info.setText("Dump Gap: 0 (Đầy đủ file dump)")
            self.lbl_gap_info.setStyleSheet(f"color: {COLOR_TEXT_PRIMARY};")
        self.lbl_last_boot.setText(f"Khởi động lại gần nhất: {report.get('last_boot_time_utc') or 'Không rõ'}")

        # Hộp lý do & Khuyến nghị
        reason_lines = []
        for rc in res.get("reason_codes", []):
            lvl = rc.get("level", "").upper()
            reason_lines.append(f"• [{lvl}] {rc.get('detail')}")
        rec_lines = [f"1. {r}" for r in res.get("recommendations", [])]

        full_txt = ""
        if reason_lines:
            full_txt += "CÁC LÝ DO VÀ CẢNH BÁO:\n" + "\n".join(reason_lines) + "\n\n"
        if rec_lines:
            full_txt += "KHUYẾN NGHỊ HÀNH ĐỘNG:\n" + "\n".join(rec_lines)
        if not full_txt:
            full_txt = "✓ Máy tính đáp ứng đầy đủ điều kiện ghi dump hệ thống. Không có cảnh báo."
        self.txt_reasons.setText(full_txt)

        # Cập nhật trạng thái nút Bật
        act = report.get("enable_action", {})
        if act.get("allowed", False):
            self.btn_enable.setEnabled(True)
            self.btn_enable.setToolTip("Bật cấu hình Automatic Dump (7)")
        else:
            self.btn_enable.setEnabled(False)
            reasons = ", ".join(act.get("blocked_by", ["Không được phép"]))
            self.btn_enable.setToolTip(f"Không thể bật vì: {reasons}")

    def _on_local_error(self, err_msg: str) -> None:
        self.btn_refresh.setEnabled(True)
        self.lbl_status_badge.setText("LỖI")
        self.lbl_status_summary.setText(f"Lỗi kiểm tra: {err_msg}")
        QMessageBox.critical(self, "Lỗi kiểm tra dump readiness", err_msg)

    def _on_enable_clicked(self) -> None:
        """Hộp thoại xác nhận trước khi bật ghi dump."""
        cur_cde = self._current_report.get("registry", {}).get("crash_dump_enabled")
        cur_desc = CRASH_DUMP_MODES.get(cur_cde, "Chưa bật") if cur_cde is not None else "Chưa có cấu hình"

        dlg = QDialog(self)
        dlg.setWindowTitle("Xác nhận Bật Ghi Dump An Toàn")
        dlg.setFixedWidth(520)
        dlg_layout = QVBoxLayout(dlg)
        dlg_layout.setSpacing(12)

        lbl_hdr = QLabel("BẬT GHI DUMP HỆ THỐNG (CRASH CONTROL)")
        lbl_hdr.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {COLOR_TEXT_PRIMARY};")
        dlg_layout.addWidget(lbl_hdr)

        msg_body = (
            f"<b>Cấu hình hiện tại:</b> CrashDumpEnabled = {cur_cde} ({cur_desc})<br>"
            f"<b>Cấu hình mục tiêu:</b> CrashDumpEnabled = 7 (Automatic dump)<br><br>"
            f"<b>Các bước tự động:</b><br>"
            f"• Tự động tạo bản sao lưu đầy đủ <code>.json</code> và <code>.reg</code> vào thư mục <code>workspace/backups/</code>.<br>"
            f"• Ghi nhật ký kiểm toán (Audit log) chi tiết.<br>"
            f"• Kiểm tra tự phục hồi (Read-after-write rollback) nếu ghi thất bại.<br><br>"
            f"<b style='color: #f59e0b;'>LƯU Ý QUAN TRỌNG:</b><br>"
            f"Cần <b>KHỞI ĐỘNG LẠI MÁY</b> sau khi bật để Windows áp dụng cấu hình mới.<br>"
            f"<i>Phần mềm TUYỆT ĐỐI KHÔNG tự khởi động lại máy của bạn.</i>"
        )
        lbl_content = QLabel(msg_body)
        lbl_content.setWordWrap(True)
        dlg_layout.addWidget(lbl_content)

        bbox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bbox.button(QDialogButtonBox.Ok).setText("Xác nhận bật")
        bbox.button(QDialogButtonBox.Cancel).setText("Huỷ bỏ")
        bbox.accepted.connect(dlg.accept)
        bbox.rejected.connect(dlg.reject)
        dlg_layout.addWidget(bbox)

        if dlg.exec() != QDialog.Accepted:
            return

        # Thực thi bật trong luồng ngầm
        self.btn_enable.setEnabled(False)
        self.lbl_status_summary.setText("Đang sao lưu và cập nhật Registry hệ thống...")

        self._worker = ReadinessWorker(action="enable", target_mode=7)
        self._worker.finished.connect(self._on_enable_finished)
        self._worker.error.connect(self._on_enable_error)
        self._worker.start()

    def _on_enable_finished(self, res: dict) -> None:
        self.btn_enable.setEnabled(True)
        if res.get("success"):
            QMessageBox.information(
                self,
                "Bật ghi dump thành công",
                f"{res.get('message')}\n\n"
                f"File sao lưu: {res.get('backup_file')}\n\n"
                f"Vui lòng khởi động lại máy tính khi thuận tiện để Windows áp dụng cấu hình.",
            )
            self.refresh_local()
        else:
            QMessageBox.critical(self, "Lỗi bật ghi dump", res.get("message", "Thao tác thất bại."))
            self.refresh_local()

    def _on_enable_error(self, err_msg: str) -> None:
        self.btn_enable.setEnabled(True)
        QMessageBox.critical(self, "Lỗi thực thi", err_msg)
        self.refresh_local()

    def _on_rollback_clicked(self) -> None:
        """Chọn file sao lưu JSON và hoàn tác cấu hình."""
        settings = load_settings(get_settings_path())
        ws_dir = Path(settings.get("working_dir", "./workspace")) / "backups"
        ws_dir.mkdir(parents=True, exist_ok=True)

        backup_file, _ = QFileDialog.getOpenFileName(
            self,
            "Chọn file sao lưu JSON để hoàn tác",
            str(ws_dir),
            "JSON Backup Files (*.json);;All Files (*)",
        )
        if not backup_file:
            return

        ans = QMessageBox.question(
            self,
            "Xác nhận hoàn tác cấu hình CrashControl",
            f"Bạn có chắc chắn muốn hoàn tác Registry về trạng thái trong file:\n{backup_file}?\n\n"
            f"Lưu ý: Cần khởi động lại máy sau khi hoàn tác để có hiệu lực.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if ans != QMessageBox.Yes:
            return

        self._worker = ReadinessWorker(action="rollback", backup_path=backup_file)
        self._worker.finished.connect(self._on_rollback_finished)
        self._worker.error.connect(self._on_rollback_error)
        self._worker.start()

    def _on_rollback_finished(self, res: dict) -> None:
        if res.get("success"):
            QMessageBox.information(self, "Hoàn tác thành công", res.get("message"))
            self.refresh_local()
        else:
            QMessageBox.critical(self, "Lỗi hoàn tác", res.get("message", "Hoàn tác thất bại."))

    def _on_rollback_error(self, err_msg: str) -> None:
        QMessageBox.critical(self, "Lỗi thực thi hoàn tác", err_msg)

    def _on_package_clicked(self) -> None:
        """Xuất gói triển khai PowerShell."""
        out_dir = QFileDialog.getExistingDirectory(self, "Chọn thư mục xuất gói triển khai")
        if not out_dir:
            return
        try:
            pkg_path = generate_deployment_package(out_dir)
            QMessageBox.information(
                self,
                "Xuất gói triển khai thành công",
                f"Đã tạo các file triển khai tại:\n{pkg_path}\n\n"
                f"Bao gồm: Enable-CrashDump.ps1, Rollback-CrashDump.ps1, README_TRIEN_KHAI.txt.",
            )
        except Exception as e:
            QMessageBox.critical(self, "Lỗi xuất gói triển khai", str(e))

    def _on_open_backup_dir(self) -> None:
        """Mở thư mục sao lưu trong File Explorer."""
        settings = load_settings(get_settings_path())
        ws_dir = Path(settings.get("working_dir", "./workspace")) / "backups"
        ws_dir.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(str(ws_dir))  # type: ignore
            else:
                subprocess.Popen(["xdg-open", str(ws_dir)])
        except Exception as e:
            QMessageBox.information(self, "Thư mục sao lưu", f"Đường dẫn: {ws_dir}\n({e})")

    # ==================== LOGIC XỬ LÝ SỰ KIỆN ĐỘI MÁY ====================

    def _on_browse_fleet_dir(self) -> None:
        dir_path = QFileDialog.getExistingDirectory(self, "Chọn thư mục chứa báo cáo JSON đội máy")
        if dir_path:
            self.txt_fleet_dir.setText(dir_path)

    def _on_load_fleet_clicked(self) -> None:
        dir_path = self.txt_fleet_dir.text().strip()
        if not dir_path:
            QMessageBox.warning(self, "Chưa chọn thư mục", "Vui lòng nhập hoặc chọn thư mục chứa file JSON báo cáo đội máy.")
            return

        db = Database()
        try:
            self._fleet_data = aggregate_fleet_reports(share_dir=dir_path, db=db)
        except Exception as e:
            QMessageBox.critical(self, "Lỗi nạp báo cáo đội máy", str(e))
            db.close()
            return
        db.close()

        summary = self._fleet_data.get("summary", {})
        total = summary.get("total_machines", 0)
        ready_pct = summary.get("ready_rate", 0.0)
        reboot_cnt = summary.get("ready_pending_reboot_count", 0)
        blocked_cnt = summary.get("blocked_count", 0)
        stale_cnt = summary.get("stale_count", 0)

        self.lbl_kpi_total.setText(f"Tổng số máy: {total}")
        self.lbl_kpi_ready_rate.setText(f"Tỷ lệ READY: {ready_pct:.1f}%")
        self.lbl_kpi_reboot.setText(f"Chờ reboot: {reboot_cnt}")
        self.lbl_kpi_blocked.setText(f"Bị chặn: {blocked_cnt}")
        self.lbl_kpi_stale.setText(f"Quá hạn (>14 ngày): {stale_cnt}")

        self._populate_fleet_table()

    def _populate_fleet_table(self) -> None:
        machines = self._fleet_data.get("machines", [])
        filter_status = self.combo_fleet_filter.currentText()
        search_query = self.txt_fleet_search.text().strip().lower()

        filtered: List[Dict[str, Any]] = []
        for m in machines:
            st = m.get("status", STATUS_UNKNOWN)
            is_stale = m.get("is_stale", False)
            hname = m.get("hostname", "").lower()

            if search_query and search_query not in hname:
                continue

            if filter_status == "Tất cả":
                filtered.append(m)
            elif filter_status == "Quá hạn (>14 ngày)":
                if is_stale:
                    filtered.append(m)
            elif filter_status == st:
                filtered.append(m)

        self.table_fleet.setRowCount(len(filtered))
        for row, m in enumerate(filtered):
            st = m.get("status", STATUS_UNKNOWN)
            cde = m.get("crash_dump_enabled")
            cde_str = f"{cde} ({CRASH_DUMP_MODES.get(cde, 'Không rõ')})" if cde is not None else "Chưa có"

            self.table_fleet.setItem(row, 0, QTableWidgetItem(m.get("hostname", "")))
            self.table_fleet.setItem(row, 1, QTableWidgetItem(m.get("ip_address", "")))
            self.table_fleet.setItem(row, 2, QTableWidgetItem(m.get("os_caption", "")))

            # Cột trạng thái có tô màu
            st_item = QTableWidgetItem(st)
            if st == STATUS_READY:
                st_item.setForeground(Qt.green)
            elif st == STATUS_READY_PENDING_REBOOT:
                st_item.setForeground(Qt.yellow)
            elif st == STATUS_BLOCKED:
                st_item.setForeground(Qt.red)
            self.table_fleet.setItem(row, 3, st_item)

            self.table_fleet.setItem(row, 4, QTableWidgetItem(cde_str))
            self.table_fleet.setItem(row, 5, QTableWidgetItem(str(m.get("ram_gb", 0))))
            self.table_fleet.setItem(row, 6, QTableWidgetItem(str(m.get("free_gb", 0))))
            self.table_fleet.setItem(row, 7, QTableWidgetItem(m.get("collected_at_utc", "")[:19]))

            reasons = ", ".join(m.get("reason_codes", []))
            self.table_fleet.setItem(row, 8, QTableWidgetItem(reasons or m.get("summary", "")))

    def _apply_fleet_filter(self) -> None:
        if self._fleet_data:
            self._populate_fleet_table()

    def _on_export_fleet_excel_clicked(self) -> None:
        """Xuất file Excel báo cáo tổng hợp đội máy."""
        if not self._fleet_data or not self._fleet_data.get("machines"):
            QMessageBox.warning(self, "Chưa có dữ liệu", "Vui lòng nạp báo cáo đội máy trước khi xuất Excel.")
            return

        out_path, _ = QFileDialog.getSaveFileName(
            self,
            "Lưu báo cáo Excel đội máy",
            "Bao_cao_san_sang_doi_may.xlsx",
            "Excel Files (*.xlsx);;All Files (*)",
        )
        if not out_path:
            return

        try:
            saved_file = export_fleet_readiness_excel(self._fleet_data, out_path)
            QMessageBox.information(
                self,
                "Xuất Excel thành công",
                f"Đã xuất báo cáo Excel 3 sheet tổng hợp ra:\n{saved_file}",
            )
        except Exception as e:
            QMessageBox.critical(self, "Lỗi xuất Excel", str(e))
