"""
Tab Nhật ký Windows Event Log (tab_eventlog.py) trong giao diện PySide6 DumpAnalyzer.

Cung cấp:
1. Thu thập log trực tiếp từ máy (System + Application + log chọn lọc theo cấp độ Critical/Error/Warning/Info).
2. Nhập file .evtx hoặc thư mục chứa file .evtx ngoại vi (từ máy khác, khách hàng gửi, bản sao lưu).
3. 5 Thẻ KPI thống kê trực quan (Tổng số, Critical, Error, Warning, Đột biến Spikes).
4. Bộ lọc đa chiều: tìm kiếm từ khóa, lọc theo cấp độ, danh mục, provider, khoảng thời gian.
5. Xem đầy đủ nội dung chi tiết: Message, EventData parsed, XML thô.
6. Khối phân tích ngữ cảnh trước sập nguồn (Pre-Crash Context) cho Event 41 / 6008.
7. Chế độ che thông tin nhạy cảm (Privacy Redaction).
8. Nút xuất báo cáo Excel đa bảng tính (.xlsx).
"""

from datetime import datetime
import json
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from dumpanalyzer.analyzer.eventlog_analyzer import (
    EventLogAnalysisResult,
    EventLogItem,
    export_eventlog_to_excel,
    harvest_evtx_eventlog,
    harvest_live_eventlog,
    redact_event_item,
)
from dumpanalyzer.core.timeutil import utc_to_local_str
from dumpanalyzer.gui.theme import (
    COLOR_ACCENT,
    COLOR_ACCENT_HOVER,
    COLOR_BG_SURFACE,
    COLOR_BORDER_LIGHT,
    COLOR_DANGER,
    COLOR_SUCCESS,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_WARNING,
)


class EventLogHarvestWorker(QThread):
    """Luồng chạy ngầm thu thập và phân tích Event Log tránh đơ giao diện."""
    finished = Signal(object)
    error = Signal(str)

    def __init__(
        self,
        mode: str = "live",
        evtx_path: Optional[str] = None,
        max_events: int = 2000,
        parent: Optional[QWidget] = None,
    ):
        super().__init__(parent)
        self.mode = mode
        self.evtx_path = evtx_path
        self.max_events = max_events

    def run(self) -> None:
        try:
            if self.mode == "evtx" and self.evtx_path:
                res = harvest_evtx_eventlog(self.evtx_path, max_events=self.max_events)
            else:
                res = harvest_live_eventlog(max_events=self.max_events)
            self.finished.emit(res)
        except Exception as e:
            self.error.emit(str(e))


class EventKPICard(QFrame):
    """Thẻ hiển thị chỉ số KPI sự kiện."""

    def __init__(self, title: str, initial_value: str = "0", color: str = COLOR_TEXT_PRIMARY, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("CardFrame")
        self.setFrameShape(QFrame.StyledPanel)
        self.setMinimumHeight(84)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        self.lbl_title = QLabel(title)
        self.lbl_title.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px; font-weight: 700; text-transform: uppercase;")
        layout.addWidget(self.lbl_title)

        self.lbl_val = QLabel(initial_value)
        self.lbl_val.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: bold;")
        layout.addWidget(self.lbl_val)

    def set_value(self, val: str, color: Optional[str] = None) -> None:
        self.lbl_val.setText(val)
        if color:
            self.lbl_val.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: bold;")


class EventLogTab(QWidget):
    """Tab Nhật ký Event Log chuyên sâu."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._analysis_result: Optional[EventLogAnalysisResult] = None
        self._filtered_events: List[EventLogItem] = []
        self._worker: Optional[EventLogHarvestWorker] = None
        self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(18, 16, 18, 16)
        main_layout.setSpacing(14)

        # 1. Hàng Công cụ trên cùng (Toolbar)
        toolbar = QHBoxLayout()
        toolbar.setSpacing(12)

        self.btn_scan_live = QPushButton("🔄 Quét log máy trực tiếp")
        self.btn_scan_live.setStyleSheet(
            f"QPushButton {{ background-color: {COLOR_ACCENT}; color: #ffffff; font-weight: 600; padding: 7px 16px; border-radius: 6px; }}"
            f"QPushButton:hover {{ background-color: {COLOR_ACCENT_HOVER}; }}"
        )
        self.btn_scan_live.clicked.connect(self._on_scan_live)
        toolbar.addWidget(self.btn_scan_live)

        self.btn_import_evtx = QPushButton("📂 Nhập file .evtx")
        self.btn_import_evtx.setStyleSheet(
            f"QPushButton {{ background-color: {COLOR_BG_SURFACE}; color: {COLOR_TEXT_PRIMARY}; border: 1px solid {COLOR_BORDER_LIGHT}; font-weight: 600; padding: 7px 14px; border-radius: 6px; }}"
            f"QPushButton:hover {{ background-color: #334155; }}"
        )
        self.btn_import_evtx.clicked.connect(self._on_import_evtx)
        toolbar.addWidget(self.btn_import_evtx)

        self.btn_import_evtx_dir = QPushButton("📁 Nhập thư mục .evtx")
        self.btn_import_evtx_dir.setStyleSheet(
            f"QPushButton {{ background-color: {COLOR_BG_SURFACE}; color: {COLOR_TEXT_PRIMARY}; border: 1px solid {COLOR_BORDER_LIGHT}; font-weight: 600; padding: 7px 14px; border-radius: 6px; }}"
            f"QPushButton:hover {{ background-color: #334155; }}"
        )
        self.btn_import_evtx_dir.clicked.connect(self._on_import_evtx_dir)
        toolbar.addWidget(self.btn_import_evtx_dir)

        self.btn_export_excel = QPushButton("📊 Xuất báo cáo Excel (.xlsx)")
        self.btn_export_excel.setStyleSheet(
            f"QPushButton {{ background-color: {COLOR_BG_SURFACE}; color: {COLOR_TEXT_PRIMARY}; border: 1px solid {COLOR_BORDER_LIGHT}; font-weight: 600; padding: 7px 16px; border-radius: 6px; }}"
            f"QPushButton:hover {{ background-color: #334155; }}"
        )
        self.btn_export_excel.clicked.connect(self._on_export_excel)
        toolbar.addWidget(self.btn_export_excel)

        self.chk_redact = QCheckBox("Che thông tin cá nhân / IP (Privacy Redaction)")
        self.chk_redact.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px; margin-left: 8px;")
        self.chk_redact.toggled.connect(self._apply_filters)
        toolbar.addWidget(self.chk_redact)

        toolbar.addStretch()

        self.lbl_status = QLabel("Chưa nạp sự kiện")
        self.lbl_status.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px;")
        toolbar.addWidget(self.lbl_status)

        main_layout.addLayout(toolbar)

        # Thanh tiến trình ẩn
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        # 2. Hàng Thẻ KPI tóm tắt
        kpi_layout = QHBoxLayout()
        kpi_layout.setSpacing(12)

        self.card_total = EventKPICard("Tổng số sự kiện", "0 lần", COLOR_TEXT_PRIMARY)
        self.card_critical = EventKPICard("Nghiêm trọng (Critical)", "0", COLOR_DANGER)
        self.card_error = EventKPICard("Lỗi (Error)", "0", "#f97316")
        self.card_warning = EventKPICard("Cảnh báo (Warning)", "0", COLOR_WARNING)
        self.card_spikes = EventKPICard("Đột biến phát hiện", "0 đợt", COLOR_SUCCESS)

        kpi_layout.addWidget(self.card_total)
        kpi_layout.addWidget(self.card_critical)
        kpi_layout.addWidget(self.card_error)
        kpi_layout.addWidget(self.card_warning)
        kpi_layout.addWidget(self.card_spikes)

        main_layout.addLayout(kpi_layout)

        # 3. Thanh Bộ lọc Đa chiều
        filter_layout = QHBoxLayout()
        filter_layout.setSpacing(10)

        lbl_search = QLabel("Tìm kiếm:")
        lbl_search.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px; font-weight: 600;")
        filter_layout.addWidget(lbl_search)

        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Tìm theo nội dung, Provider, Event ID...")
        self.txt_search.textChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.txt_search, 2)

        lbl_level = QLabel("Mức độ:")
        lbl_level.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px; font-weight: 600;")
        filter_layout.addWidget(lbl_level)

        self.combo_level = QComboBox()
        self.combo_level.addItems(["Tất cả cấp độ", "Critical (Nghiêm trọng)", "Error (Lỗi)", "Warning (Cảnh báo)", "Information (Thông tin)"])
        self.combo_level.currentIndexChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.combo_level, 1)

        lbl_cat = QLabel("Danh mục:")
        lbl_cat.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px; font-weight: 600;")
        filter_layout.addWidget(lbl_cat)

        self.combo_category = QComboBox()
        category_options = [
            ("Tất cả danh mục", "all"),
            ("Sập & Khởi động bất thường", "crash_reboot"),
            ("Phần cứng (WHEA)", "hardware"),
            ("Lưu trữ & Hệ thống tệp", "storage"),
            ("USB & Thiết bị ngoại vi", "usb_device"),
            ("Màn hình & Card đồ họa (GPU)", "display_gpu"),
            ("Cập nhật & Cài đặt", "updates_install"),
            ("Dịch vụ & Ứng dụng", "app_service"),
            ("Nguồn & Nhiệt độ", "power_thermal"),
            ("Khác (Chưa phân loại)", "other"),
        ]
        for label, key in category_options:
            self.combo_category.addItem(label, key)
        self.combo_category.currentIndexChanged.connect(self._apply_filters)
        filter_layout.addWidget(self.combo_category, 1)

        main_layout.addLayout(filter_layout)

        # 4. Khu vực Splitter: Bảng sự kiện (trên) và Chi tiết sự kiện (dưới)
        splitter = QSplitter(Qt.Vertical)

        # Bảng sự kiện
        self.table_events = QTableWidget(0, 6)
        self.table_events.setHorizontalHeaderLabels([
            "Thời gian (Local)", "Mức độ", "Danh mục", "Nguồn (Provider)", "ID", "Nội dung tóm tắt"
        ])
        self.table_events.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_events.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_events.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_events.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_events.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table_events.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.table_events.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_events.setSelectionMode(QTableWidget.SingleSelection)
        self.table_events.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table_events.itemSelectionChanged.connect(self._on_event_selected)

        splitter.addWidget(self.table_events)

        # Khối Chi tiết Sự kiện & Ngữ cảnh
        detail_container = QFrame()
        detail_container.setObjectName("CardFrame")
        detail_container.setFrameShape(QFrame.StyledPanel)
        det_layout = QVBoxLayout(detail_container)
        det_layout.setContentsMargins(14, 12, 14, 12)
        det_layout.setSpacing(8)

        self.lbl_detail_title = QLabel("Chi tiết sự kiện được chọn:")
        self.lbl_detail_title.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {COLOR_TEXT_PRIMARY};")
        det_layout.addWidget(self.lbl_detail_title)

        self.txt_detail = QTextEdit()
        self.txt_detail.setReadOnly(True)
        self.txt_detail.setPlaceholderText("Nhấp chọn một dòng sự kiện trong bảng trên để xem chi tiết đầy đủ...")
        det_layout.addWidget(self.txt_detail)

        splitter.addWidget(detail_container)
        splitter.setSizes([380, 200])

        main_layout.addWidget(splitter, 1)

    def _set_loading(self, loading: bool, message: str = "") -> None:
        self.progress_bar.setVisible(loading)
        self.btn_scan_live.setEnabled(not loading)
        self.btn_import_evtx.setEnabled(not loading)
        self.btn_import_evtx_dir.setEnabled(not loading)
        self.btn_export_excel.setEnabled(not loading)
        self.lbl_status.setText(message)

    def _on_scan_live(self) -> None:
        """Kích hoạt quét log trực tiếp của máy trong luồng ngầm."""
        self._set_loading(True, "Đang quét Windows Event Log trực tiếp...")
        self._worker = EventLogHarvestWorker(mode="live", parent=self)
        self._worker.finished.connect(self._on_harvest_finished)
        self._worker.error.connect(self._on_harvest_error)
        self._worker.start()

    def _on_import_evtx(self) -> None:
        """Chọn một file .evtx để phân tích."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Chọn file Windows Event Log (.evtx)",
            "",
            "Windows Event Log (*.evtx);;Tất cả tệp (*.*)",
        )
        if not file_path:
            return

        self._set_loading(True, f"Đang đọc tệp {Path(file_path).name}...")
        self._worker = EventLogHarvestWorker(mode="evtx", evtx_path=file_path, parent=self)
        self._worker.finished.connect(self._on_harvest_finished)
        self._worker.error.connect(self._on_harvest_error)
        self._worker.start()

    def _on_import_evtx_dir(self) -> None:
        """Chọn một thư mục chứa nhiều file .evtx để tổng hợp phân tích."""
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Chọn thư mục chứa các file Windows Event Log (.evtx)",
            "",
        )
        if not dir_path:
            return

        self._set_loading(True, f"Đang đọc thư mục .evtx: {Path(dir_path).name}...")
        self._worker = EventLogHarvestWorker(mode="evtx", evtx_path=dir_path, parent=self)
        self._worker.finished.connect(self._on_harvest_finished)
        self._worker.error.connect(self._on_harvest_error)
        self._worker.start()

    def _on_harvest_finished(self, result: EventLogAnalysisResult) -> None:
        self._set_loading(False, f"Đã nạp {result.total_events} sự kiện từ {result.source_description}")
        self.set_analysis_result(result)
        if result.warnings:
            QMessageBox.warning(self, "Thông báo Event Log", "\n".join(result.warnings))

    def _on_harvest_error(self, err_msg: str) -> None:
        self._set_loading(False, f"Lỗi: {err_msg}")
        QMessageBox.critical(self, "Lỗi đọc Event Log", f"Không thể thu thập log: {err_msg}")

    def set_analysis_result(self, result: EventLogAnalysisResult) -> None:
        """Cập nhật dữ liệu phân tích và làm mới toàn bộ giao diện."""
        self._analysis_result = result
        self.card_total.set_value(f"{result.total_events} lần")
        self.card_critical.set_value(str(result.level_counts.get("Critical", 0)))
        self.card_error.set_value(str(result.level_counts.get("Error", 0)))
        self.card_warning.set_value(str(result.level_counts.get("Warning", 0)))

        spike_cnt = len(result.spikes)
        self.card_spikes.set_value(f"{spike_cnt} đợt", COLOR_DANGER if spike_cnt > 0 else COLOR_SUCCESS)

        self._apply_filters()

    def _apply_filters(self) -> None:
        """Lọc và hiển thị danh sách sự kiện lên bảng."""
        if not self._analysis_result:
            self.table_events.setRowCount(0)
            return

        query = self.txt_search.text().strip().lower()
        level_sel = self.combo_level.currentText()
        cat_key = self.combo_category.currentData()
        cat_sel = self.combo_category.currentText()
        is_redact = self.chk_redact.isChecked()

        filtered: List[EventLogItem] = []
        for ev in self._analysis_result.events:
            # 1. Lọc theo Level
            if "Critical" in level_sel and ev.level != 1:
                continue
            if "Error" in level_sel and ev.level != 2:
                continue
            if "Warning" in level_sel and ev.level != 3:
                continue
            if "Information" in level_sel and ev.level not in (4, 0):
                continue

            # 2. Lọc theo Danh mục (ưu tiên mã danh mục chính xác)
            if cat_key and cat_key != "all":
                if ev.category != cat_key:
                    continue
            elif cat_sel != "Tất cả danh mục":
                if cat_sel.lower() not in ev.category_name.lower():
                    continue

            # 3. Lọc theo từ khóa tìm kiếm
            if query:
                content = f"{ev.provider} {ev.event_id} {ev.raw_message or ''} {json.dumps(ev.event_data)}".lower()
                if query not in content:
                    continue

            filtered.append(ev)

        self._filtered_events = filtered
        self._render_table(filtered, redact=is_redact)

    def _render_table(self, events: List[EventLogItem], redact: bool = False) -> None:
        """Vẽ lại bảng dữ liệu."""
        self.table_events.setRowCount(0)
        self.table_events.setRowCount(len(events))

        for r_idx, ev in enumerate(events):
            disp_ev = redact_event_item(ev) if redact else ev

            # Cột 0: Thời gian
            item_time = QTableWidgetItem(utc_to_local_str(disp_ev.time_created_utc))
            self.table_events.setItem(r_idx, 0, item_time)

            # Cột 1: Mức độ (Badge)
            item_lvl = QTableWidgetItem(disp_ev.level_label_vi)
            if disp_ev.level == 1:
                item_lvl.setForeground(Qt.red)
            elif disp_ev.level == 2:
                item_lvl.setForeground(Qt.yellow)
            elif disp_ev.level == 3:
                item_lvl.setForeground(Qt.cyan)
            self.table_events.setItem(r_idx, 1, item_lvl)

            # Cột 2: Danh mục
            item_cat = QTableWidgetItem(disp_ev.category_name)
            self.table_events.setItem(r_idx, 2, item_cat)

            # Cột 3: Provider
            item_prov = QTableWidgetItem(disp_ev.provider)
            self.table_events.setItem(r_idx, 3, item_prov)

            # Cột 4: Event ID
            item_id = QTableWidgetItem(str(disp_ev.event_id))
            item_id.setTextAlignment(Qt.AlignCenter)
            self.table_events.setItem(r_idx, 4, item_id)

            # Cột 5: Tóm tắt nội dung
            msg = (disp_ev.raw_message or "").replace("\r", " ").replace("\n", " ").strip()
            item_msg = QTableWidgetItem(msg[:180] + ("..." if len(msg) > 180 else ""))
            self.table_events.setItem(r_idx, 5, item_msg)

    def _on_event_selected(self) -> None:
        """Hiển thị chi tiết đầy đủ khi người dùng chọn một dòng."""
        sel_rows = self.table_events.selectedItems()
        if not sel_rows:
            return
        row = sel_rows[0].row()
        if row >= len(self._filtered_events):
            return

        raw_ev = self._filtered_events[row]
        ev = redact_event_item(raw_ev) if self.chk_redact.isChecked() else raw_ev

        lines = [
            f"=== THÔNG TIN SỰ KIỆN: {ev.provider} (ID: {ev.event_id}) ===",
            f"• Thời gian (Local): {utc_to_local_str(ev.time_created_utc)}  |  UTC: {ev.time_created_utc}",
            f"• Mức độ nghiêm trọng: {ev.level_label_vi} (Level {ev.level})",
            f"• Kênh nhật ký (Channel): {ev.channel}",
            f"• Danh mục nghiệp vụ: {ev.category_name} ({ev.category})",
            "",
            "--- NỘI DUNG THÔNG BÁO (MESSAGE) ---",
            ev.raw_message or "(Không có nội dung mô tả)",
            "",
        ]

        if ev.event_data:
            lines.append("--- DỮ LIỆU BÓC TÁCH (EVENT DATA) ---")
            for k, v in ev.event_data.items():
                lines.append(f"• {k}: {v}")
            lines.append("")

        # Nếu là sự kiện sập nguồn, kiểm tra xem có ngữ cảnh trước sập không
        if self._analysis_result and ev.event_id in (41, 6008):
            for ctx in self._analysis_result.pre_crash_contexts:
                if ctx.crash_event_id == ev.event_id and ctx.crash_time_utc == ev.time_created_utc:
                    lines.append("--- NGỮ CẢNH TRƯỚC LẦN SẬP NÀY (PRE-CRASH CONTEXT) ---")
                    lines.append(ctx.summary)
                    lines.append(f"Danh sách {len(ctx.preceding_events)} cảnh báo/lỗi xảy ra trong {ctx.window_minutes} phút trước sập:")
                    for idx, pe in enumerate(ctx.preceding_events, start=1):
                        pe_disp = redact_event_item(pe) if self.chk_redact.isChecked() else pe
                        p_msg = (pe_disp.raw_message or "").replace('\n', ' ')[:90]
                        lines.append(f"  [{idx}] {utc_to_local_str(pe_disp.time_created_utc)} | {pe_disp.level_name} | {pe_disp.provider} ({pe_disp.event_id}): {p_msg}")
                    lines.append("")
                    break

        self.txt_detail.setPlainText("\n".join(lines))

    def _on_export_excel(self) -> None:
        """Xuất toàn bộ kết quả ra file Excel."""
        if not self._analysis_result or not self._analysis_result.events:
            QMessageBox.information(self, "Chưa có dữ liệu", "Vui lòng quét hoặc nạp sự kiện trước khi xuất báo cáo.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Lưu báo cáo Event Log sang Excel",
            f"BaoCao_EventLog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
            "Microsoft Excel (*.xlsx)",
        )
        if not file_path:
            return

        try:
            is_redact = self.chk_redact.isChecked()
            out_file = export_eventlog_to_excel(self._analysis_result, file_path, redact=is_redact)
            QMessageBox.information(
                self,
                "Xuất Excel thành công",
                f"Đã xuất báo cáo Event Log thành công tại:\n{out_file}",
            )
        except Exception as e:
            QMessageBox.critical(self, "Lỗi xuất Excel", f"Không thể xuất file: {e}")
