"""Tab 2: Chi tiết Crash (Crash Detail Tab) trong PySide6 DumpAnalyzer.

Hiển thị toàn bộ thông số kỹ thuật chuyên sâu của một lần sập được chọn:
- Metadata dump, mã Bug Check, 4 tham số (P1..P4), thủ phạm / nạn nhân.
- Khung Call Stack (STACK_TEXT) với font monospaced dễ đọc.
- Khung Bằng chứng Minidump Triage nội bộ (Ngoại lệ, module call stack, unloaded drivers).
- Bảng sự kiện Event Log xảy ra trong cửa sổ 10 phút trước khi sập.
- Dòng thời gian sự cố của máy tính (Crash Timeline).
"""

import json
from typing import Dict, List, Optional
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from dumpanalyzer.core.models import Crash, Evidence
from dumpanalyzer.core.timeutil import utc_to_local_str
from dumpanalyzer.gui.theme import (
    COLOR_BORDER,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    get_method_badge_style,
)


class DetailTab(QWidget):
    """Tab xem chi tiết chuyên sâu từng phiên sập máy."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._crashes: List[Crash] = []
        self._evidences_by_crash: Dict[int, List[Evidence]] = {}
        self._current_crash: Optional[Crash] = None
        self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(14)

        # 1. Hàng trên cùng: Selector chọn crash + Badge phương thức phân tích
        top_bar = QHBoxLayout()
        top_bar.setSpacing(14)

        lbl_select = QLabel("Chọn lần sập cần xem:")
        lbl_select.setStyleSheet(f"font-weight: bold; color: {COLOR_TEXT_PRIMARY}; font-size: 13px;")
        top_bar.addWidget(lbl_select)

        self.combo_crashes = QComboBox()
        self.combo_crashes.setMinimumHeight(36)
        self.combo_crashes.currentIndexChanged.connect(self._on_crash_combo_changed)
        top_bar.addWidget(self.combo_crashes, 1)

        self.lbl_method_badge = QLabel("Chưa chọn")
        self.lbl_method_badge.setStyleSheet(get_method_badge_style("none"))
        top_bar.addWidget(self.lbl_method_badge)

        main_layout.addLayout(top_bar)

        # 2. Vùng nội dung chính: QSplitter chia 2 cột trái - phải
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(8)

        # ==================== CỘT TRÁI: CÁC THẺ CARD GỌN GÀNG ====================
        scroll_left = QScrollArea()
        scroll_left.setWidgetResizable(True)
        scroll_left.setFrameShape(QFrame.NoFrame)

        left_container = QWidget()
        left_layout = QVBoxLayout(left_container)
        left_layout.setContentsMargins(0, 0, 8, 0)
        left_layout.setSpacing(14)

        # CARD 1: TỔNG QUAN BUGCHECK
        card_overview = QFrame()
        card_overview.setObjectName("CardFrame")
        layout_overview = QVBoxLayout(card_overview)
        layout_overview.setContentsMargins(16, 14, 16, 14)
        layout_overview.setSpacing(10)

        header_ov = QHBoxLayout()
        self.lbl_bugcheck_code = QLabel("0x00000000")
        self.lbl_bugcheck_code.setStyleSheet(
            "font-size: 20px; font-weight: 800; color: #38bdf8; font-family: monospace;"
        )
        header_ov.addWidget(self.lbl_bugcheck_code)

        self.lbl_bugcheck_name = QLabel("CHƯA CÓ LỖI")
        self.lbl_bugcheck_name.setStyleSheet(
            "background-color: #1e3a8a; color: #93c5fd; font-weight: bold; padding: 4px 10px; border-radius: 6px; font-size: 12px;"
        )
        header_ov.addWidget(self.lbl_bugcheck_name, alignment=Qt.AlignRight)
        layout_overview.addLayout(header_ov)

        # Grid thông tin thời điểm & uptime
        grid_ov = QGridLayout()
        grid_ov.setHorizontalSpacing(12)
        grid_ov.setVerticalSpacing(6)

        lbl_t_title = QLabel("Thời điểm:")
        lbl_t_title.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px;")
        self.lbl_time = QLabel("-")
        self.lbl_time.setStyleSheet(f"color: {COLOR_TEXT_PRIMARY}; font-weight: 600; font-size: 12px;")
        grid_ov.addWidget(lbl_t_title, 0, 0)
        grid_ov.addWidget(self.lbl_time, 0, 1)

        lbl_src_title = QLabel("Nguồn thời gian:")
        lbl_src_title.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px;")
        self.lbl_time_source = QLabel("-")
        self.lbl_time_source.setStyleSheet("color: #cbd5e1; font-size: 12px;")
        grid_ov.addWidget(lbl_src_title, 1, 0)
        grid_ov.addWidget(self.lbl_time_source, 1, 1)

        lbl_up_title = QLabel("Thời gian chạy:")
        lbl_up_title.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px;")
        self.lbl_uptime = QLabel("-")
        self.lbl_uptime.setStyleSheet("color: #cbd5e1; font-size: 12px;")
        grid_ov.addWidget(lbl_up_title, 2, 0)
        grid_ov.addWidget(self.lbl_uptime, 2, 1)

        layout_overview.addLayout(grid_ov)
        left_layout.addWidget(card_overview)

        # CARD 2: 4 THAM SỐ BUGCHECK PARAMETERS (P1 - P4)
        card_params = QFrame()
        card_params.setObjectName("CardFrame")
        layout_params = QVBoxLayout(card_params)
        layout_params.setContentsMargins(16, 12, 16, 12)
        layout_params.setSpacing(10)

        lbl_p_hdr = QLabel("4 THAM SỐ BUGCHECK (PARAMETERS)")
        lbl_p_hdr.setStyleSheet(
            f"font-size: 11px; font-weight: 700; color: {COLOR_TEXT_MUTED}; letter-spacing: 0.5px;"
        )
        layout_params.addWidget(lbl_p_hdr)

        grid_p = QGridLayout()
        grid_p.setHorizontalSpacing(10)
        grid_p.setVerticalSpacing(8)

        def _make_param_box(label_text: str):
            box = QFrame()
            box.setStyleSheet(
                "background-color: #0b1120; border: 1px solid #1e293b; border-radius: 6px; padding: 4px;"
            )
            v = QVBoxLayout(box)
            v.setContentsMargins(8, 4, 8, 4)
            v.setSpacing(2)
            lbl_tag = QLabel(label_text)
            lbl_tag.setStyleSheet("color: #64748b; font-size: 10px; font-weight: 700;")
            lbl_val = QLabel("-")
            lbl_val.setStyleSheet(
                "color: #38bdf8; font-family: monospace; font-size: 12px; font-weight: 600;"
            )
            lbl_val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            v.addWidget(lbl_tag)
            v.addWidget(lbl_val)
            return box, lbl_val

        box_p1, self.val_p1 = _make_param_box("THAM SỐ 1 (P1)")
        box_p2, self.val_p2 = _make_param_box("THAM SỐ 2 (P2)")
        box_p3, self.val_p3 = _make_param_box("THAM SỐ 3 (P3)")
        box_p4, self.val_p4 = _make_param_box("THAM SỐ 4 (P4)")

        grid_p.addWidget(box_p1, 0, 0)
        grid_p.addWidget(box_p2, 0, 1)
        grid_p.addWidget(box_p3, 1, 0)
        grid_p.addWidget(box_p4, 1, 1)
        layout_params.addLayout(grid_p)

        # Alias tương thích ngược
        self.lbl_p1 = self.val_p1
        self.lbl_p2 = self.val_p2
        self.lbl_p3 = self.val_p3
        self.lbl_p4 = self.val_p4

        left_layout.addWidget(card_params)

        # CARD 3: BẰNG CHỨNG MINIDUMP TRIAGE (Ngoại lệ & Call Stack Modules)
        self.card_triage = QFrame()
        self.card_triage.setObjectName("CardFrame")
        layout_triage = QVBoxLayout(self.card_triage)
        layout_triage.setContentsMargins(16, 12, 16, 12)
        layout_triage.setSpacing(8)

        lbl_triage_hdr = QLabel("BẰNG CHỨNG TỪ MINIDUMP TRIAGE (BỘ ĐỌC NỘI BỘ)")
        lbl_triage_hdr.setStyleSheet(
            "font-size: 11px; font-weight: 700; color: #a855f7; letter-spacing: 0.5px;"
        )
        layout_triage.addWidget(lbl_triage_hdr)

        grid_tr = QGridLayout()
        grid_tr.setHorizontalSpacing(10)
        grid_tr.setVerticalSpacing(6)

        lbl_exc_tag = QLabel("Ngoại lệ (Exception):")
        lbl_exc_tag.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px;")
        self.lbl_triage_exception = QLabel("-")
        self.lbl_triage_exception.setStyleSheet("color: #fca5a5; font-weight: 600; font-size: 12px; font-family: monospace;")
        self.lbl_triage_exception.setTextInteractionFlags(Qt.TextSelectableByMouse)
        grid_tr.addWidget(lbl_exc_tag, 0, 0)
        grid_tr.addWidget(self.lbl_triage_exception, 0, 1)

        lbl_mean_tag = QLabel("Ý nghĩa ngoại lệ:")
        lbl_mean_tag.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px;")
        self.lbl_triage_meaning = QLabel("-")
        self.lbl_triage_meaning.setStyleSheet("color: #fcd34d; font-size: 12px;")
        self.lbl_triage_meaning.setWordWrap(True)
        grid_tr.addWidget(lbl_mean_tag, 1, 0)
        grid_tr.addWidget(self.lbl_triage_meaning, 1, 1)

        lbl_stk_tag = QLabel("Chuỗi Module Stack:")
        lbl_stk_tag.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px;")
        self.lbl_triage_stack_modules = QLabel("-")
        self.lbl_triage_stack_modules.setStyleSheet("color: #93c5fd; font-weight: 600; font-size: 12px;")
        self.lbl_triage_stack_modules.setWordWrap(True)
        grid_tr.addWidget(lbl_stk_tag, 2, 0)
        grid_tr.addWidget(self.lbl_triage_stack_modules, 2, 1)

        lbl_unl_tag = QLabel("Driver đã gỡ gần sập:")
        lbl_unl_tag.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px;")
        self.lbl_triage_unloaded = QLabel("-")
        self.lbl_triage_unloaded.setStyleSheet("color: #cbd5e1; font-size: 12px;")
        self.lbl_triage_unloaded.setWordWrap(True)
        grid_tr.addWidget(lbl_unl_tag, 3, 0)
        grid_tr.addWidget(self.lbl_triage_unloaded, 3, 1)

        layout_triage.addLayout(grid_tr)
        left_layout.addWidget(self.card_triage)

        # CARD 4: THÔNG TIN KỸ THUẬT & FILE DUMP
        card_tech = QFrame()
        card_tech.setObjectName("CardFrame")
        layout_tech = QVBoxLayout(card_tech)
        layout_tech.setContentsMargins(16, 12, 16, 12)
        layout_tech.setSpacing(8)

        lbl_tech_hdr = QLabel("CHI TIẾT KỸ THUẬT & TỆP DUMP")
        lbl_tech_hdr.setStyleSheet(
            f"font-size: 11px; font-weight: 700; color: {COLOR_TEXT_MUTED}; letter-spacing: 0.5px;"
        )
        layout_tech.addWidget(lbl_tech_hdr)

        grid_tech = QGridLayout()
        grid_tech.setHorizontalSpacing(10)
        grid_tech.setVerticalSpacing(6)

        tech_fields = [
            ("Driver thủ phạm:", "lbl_image_name"),
            ("Module gây lỗi:", "lbl_module_name"),
            ("Tiến trình (Process):", "lbl_process_name"),
            ("Failure Bucket ID:", "lbl_bucket_id"),
            ("Đường dẫn dump:", "lbl_dump_path"),
            ("Mã băm SHA256:", "lbl_dump_sha256"),
        ]

        self.tech_labels: Dict[str, QLabel] = {}
        for r_i, (f_title, f_key) in enumerate(tech_fields):
            lbl_title = QLabel(f_title)
            lbl_title.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px;")
            lbl_v = QLabel("-")
            lbl_v.setStyleSheet(f"color: {COLOR_TEXT_PRIMARY}; font-size: 12px;")
            lbl_v.setWordWrap(True)
            lbl_v.setTextInteractionFlags(Qt.TextSelectableByMouse)
            grid_tech.addWidget(lbl_title, r_i, 0, Qt.AlignTop | Qt.AlignLeft)
            grid_tech.addWidget(lbl_v, r_i, 1, Qt.AlignTop | Qt.AlignLeft)
            self.tech_labels[f_key] = lbl_v

        grid_tech.setColumnMinimumWidth(0, 130)
        grid_tech.setColumnStretch(1, 1)
        layout_tech.addLayout(grid_tech)
        left_layout.addWidget(card_tech)

        left_layout.addStretch()
        scroll_left.setWidget(left_container)
        splitter.addWidget(scroll_left)

        # ==================== CỘT PHẢI: STACK & SỰ KIỆN 10 PHÚT ====================
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(14)

        # 1. Khung Call Stack (STACK_TEXT)
        stack_card = QFrame()
        stack_card.setObjectName("CardFrame")
        stack_layout = QVBoxLayout(stack_card)
        stack_layout.setContentsMargins(16, 12, 16, 12)
        stack_layout.setSpacing(8)

        lbl_stack_title = QLabel("CALL STACK TRACE (!analyze -v hoặc Minidump Triage)")
        lbl_stack_title.setStyleSheet(
            f"font-size: 12px; font-weight: bold; color: {COLOR_TEXT_PRIMARY}; border-bottom: 1px solid {COLOR_BORDER}; padding-bottom: 4px;"
        )
        stack_layout.addWidget(lbl_stack_title)

        self.txt_stack = QPlainTextEdit()
        self.txt_stack.setReadOnly(True)
        self.txt_stack.setPlaceholderText("Không có dữ liệu Call Stack (chế độ header_only hoặc không có dump).")
        self.txt_stack.setMinimumHeight(150)
        stack_layout.addWidget(self.txt_stack)

        right_layout.addWidget(stack_card, 1)

        # 2. Khung Bảng sự kiện 10 phút trước crash
        events_card = QFrame()
        events_card.setObjectName("CardFrame")
        events_layout = QVBoxLayout(events_card)
        events_layout.setContentsMargins(16, 12, 16, 12)
        events_layout.setSpacing(8)

        lbl_events_title = QLabel("SỰ KIỆN WINDOWS EVENT LOG TRONG CỬA SỔ 10 PHÚT TRƯỚC SẬP")
        lbl_events_title.setStyleSheet(
            f"font-size: 12px; font-weight: bold; color: {COLOR_TEXT_PRIMARY}; border-bottom: 1px solid {COLOR_BORDER}; padding-bottom: 4px;"
        )
        events_layout.addWidget(lbl_events_title)

        self.table_events = QTableWidget()
        self.table_events.setColumnCount(4)
        self.table_events.setHorizontalHeaderLabels([
            "Thời điểm",
            "Nguồn (Provider)",
            "Event ID",
            "Mô tả sự kiện",
        ])
        self.table_events.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_events.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_events.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_events.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table_events.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_events.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table_events.verticalHeader().setVisible(False)
        self.table_events.verticalHeader().setDefaultSectionSize(32)
        events_layout.addWidget(self.table_events)

        right_layout.addWidget(events_card, 1)

        splitter.addWidget(right_container)
        splitter.setSizes([430, 570])

        main_layout.addWidget(splitter, 1)

        # 3. Khung Dòng thời gian Crash của máy (Crash Timeline)
        timeline_card = QFrame()
        timeline_card.setObjectName("CardFrame")
        timeline_card.setFixedHeight(170)
        tl_layout = QVBoxLayout(timeline_card)
        tl_layout.setContentsMargins(16, 12, 16, 12)
        tl_layout.setSpacing(6)

        lbl_tl_title = QLabel("DÒNG THỜI GIAN SỰ CỐ CỦA MÁY (CRASH TIMELINE)")
        lbl_tl_title.setStyleSheet(f"font-size: 12px; font-weight: bold; color: {COLOR_TEXT_PRIMARY};")
        tl_layout.addWidget(lbl_tl_title)

        self.table_timeline = QTableWidget()
        self.table_timeline.setColumnCount(5)
        self.table_timeline.setHorizontalHeaderLabels([
            "STT",
            "Thời điểm (Giờ địa phương)",
            "Mã BugCheck",
            "Tên sự cố",
            "Module / Driver",
        ])
        self.table_timeline.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_timeline.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_timeline.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_timeline.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_timeline.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table_timeline.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_timeline.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table_timeline.verticalHeader().setVisible(False)
        self.table_timeline.verticalHeader().setDefaultSectionSize(30)
        self.table_timeline.cellClicked.connect(self._on_timeline_row_clicked)
        tl_layout.addWidget(self.table_timeline)

        main_layout.addWidget(timeline_card)

    def _on_timeline_row_clicked(self, row: int, _col: int) -> None:
        """Chuyển chi tiết hiển thị khi click một dòng trên timeline."""
        if 0 <= row < len(self._crashes):
            self.select_crash(self._crashes[row])

    def set_data(self, crashes: List[Crash], evidences: Optional[List[Evidence]] = None) -> None:
        """Cập nhật dữ liệu cho tab Chi tiết."""
        self._crashes = list(crashes)
        self._evidences_by_crash = {}

        if evidences:
            for ev in evidences:
                c_id = getattr(ev, "crash_id", None)
                if c_id is not None:
                    self._evidences_by_crash.setdefault(c_id, []).append(ev)

        self.combo_crashes.blockSignals(True)
        self.combo_crashes.clear()

        self.table_timeline.setRowCount(len(self._crashes))

        for idx, c in enumerate(self._crashes, start=1):
            t_val = getattr(c, "crash_time_utc", getattr(c, "crash_time", None))
            t_str = utc_to_local_str(t_val) if t_val else "Chưa rõ thời điểm"
            bc_code = getattr(c, "bugcheck_code", "N/A") or "N/A"
            bc_name = getattr(c, "bugcheck_name", "Chưa rõ") or "Chưa rõ"
            item_text = f"Sự cố #{idx}: {t_str} — {bc_code} ({bc_name})"
            self.combo_crashes.addItem(item_text, userData=c)

            mod = getattr(c, "image_name", getattr(c, "module_name", "-")) or "-"
            self.table_timeline.setItem(idx - 1, 0, QTableWidgetItem(str(idx)))
            self.table_timeline.setItem(idx - 1, 1, QTableWidgetItem(t_str))
            self.table_timeline.setItem(idx - 1, 2, QTableWidgetItem(bc_code))
            self.table_timeline.setItem(idx - 1, 3, QTableWidgetItem(bc_name))
            self.table_timeline.setItem(idx - 1, 4, QTableWidgetItem(mod))

        self.combo_crashes.blockSignals(False)

        if self._crashes:
            self.select_crash(self._crashes[0])
        else:
            self._clear_display()

    def select_crash(self, crash: Crash) -> None:
        """Chọn và hiển thị một Crash cụ thể (được gọi từ Tab 1 khi double click)."""
        for i in range(self.combo_crashes.count()):
            c_data = self.combo_crashes.itemData(i)
            if c_data and (c_data is crash or getattr(c_data, "id", None) == getattr(crash, "id", None)):
                self.combo_crashes.setCurrentIndex(i)
                self._display_crash(c_data)
                return

        self._display_crash(crash)

    @property
    def meta_labels(self) -> Dict[str, QLabel]:
        """Thuộc tính tương thích ngược cho các bài kiểm tra và module bên ngoài."""
        d = dict(self.tech_labels)
        d["lbl_bugcheck_code"] = self.lbl_bugcheck_code
        d["lbl_bugcheck_name"] = self.lbl_bugcheck_name
        d["lbl_time"] = self.lbl_time
        d["lbl_time_source"] = self.lbl_time_source
        d["lbl_uptime"] = self.lbl_uptime
        return d

    def _on_crash_combo_changed(self, index: int) -> None:
        """Xử lý khi người dùng đổi lựa chọn trên dropdown."""
        if index < 0 or index >= len(self._crashes):
            return
        crash = self._crashes[index]
        self._display_crash(crash)

    def _display_crash(self, c: Crash) -> None:
        """Hiển thị chi tiết đối tượng Crash lên giao diện."""
        self._current_crash = c
        t_val = getattr(c, "crash_time_utc", getattr(c, "crash_time", None))
        t_str = utc_to_local_str(t_val) if t_val else "Không xác định"
        analyzed = getattr(c, "analyzed_by", "none") or "none"

        # Cập nhật Badge phân tích
        if analyzed == "log_only":
            self.lbl_method_badge.setText("Không có dump (log_only)")
        elif analyzed == "header_only":
            self.lbl_method_badge.setText("Chỉ đọc Header (header_only)")
        elif analyzed in ("triage_native", "triage"):
            self.lbl_method_badge.setText("Triage Native (Bộ đọc nội bộ)")
        else:
            self.lbl_method_badge.setText("WinDbg cdb")
        self.lbl_method_badge.setStyleSheet(get_method_badge_style(analyzed))

        # CARD 1: Tổng quan
        self.lbl_bugcheck_code.setText(getattr(c, "bugcheck_code", "N/A") or "N/A")
        self.lbl_bugcheck_name.setText(getattr(c, "bugcheck_name", "CHƯA RÕ LỖI") or "CHƯA RÕ LỖI")
        self.lbl_time.setText(t_str)

        time_src = getattr(c, "crash_time_source", "unknown") or "unknown"
        src_labels = {
            "header": "Header file dump (chính xác)",
            "cdb": "WinDbg cdb (chính xác)",
            "mtime": "Giờ sửa file mtime (ước tính)",
            "eventlog_6008": "EventLog 6008 (tắt bất thường)",
            "estimated": "Ước tính từ chuỗi sự kiện",
            "kp41": "Kernel-Power Event 41",
        }
        self.lbl_time_source.setText(src_labels.get(time_src, time_src))

        uptime_sec = getattr(c, "uptime_seconds", 0) or 0
        if uptime_sec > 0:
            uptime_str = f"{uptime_sec} giây (~{uptime_sec // 60} phút)"
        else:
            uptime_str = "Không rõ (hoặc dump triage)"
        self.lbl_uptime.setText(uptime_str)

        # CARD 2: 4 Tham số
        self.val_p1.setText(getattr(c, "p1", "-") or "-")
        self.val_p2.setText(getattr(c, "p2", "-") or "-")
        self.val_p3.setText(getattr(c, "p3", "-") or "-")
        self.val_p4.setText(getattr(c, "p4", "-") or "-")

        # CARD 3: Triage Native Data
        triage_json_raw = getattr(c, "triage_json", None)
        exc_code = getattr(c, "exception_code", None)
        exc_addr = getattr(c, "exception_address", None)
        exc_mod = getattr(c, "exception_module", None)

        t_data = {}
        if triage_json_raw:
            try:
                t_data = json.loads(triage_json_raw)
            except Exception:
                t_data = {}

        t_exc = t_data.get("exception", {}) or {}
        final_code = exc_code or t_exc.get("code", "")
        final_addr = exc_addr or t_exc.get("address", "")
        final_mod = exc_mod or t_exc.get("module", "")
        final_mean = t_exc.get("meaning", "")
        stack_mods = t_data.get("stack_modules_in_order", [])
        unloaded_list = t_data.get("unloaded", [])

        if final_code or stack_mods or analyzed == "triage_native":
            self.card_triage.setVisible(True)
            self.lbl_triage_exception.setText(
                f"{final_code or 'N/A'} tại {final_addr or 'N/A'} ({final_mod or 'N/A'})"
            )
            self.lbl_triage_meaning.setText(final_mean or "(Không có mô tả ngoại lệ)")
            if stack_mods:
                self.lbl_triage_stack_modules.setText(" ➔ ".join(stack_mods))
            else:
                self.lbl_triage_stack_modules.setText("Không trích xuất được stack module")

            if unloaded_list:
                self.lbl_triage_unloaded.setText(", ".join(unloaded_list[:12]))
            else:
                self.lbl_triage_unloaded.setText("Không có driver nào bị gỡ trước crash")
        else:
            self.card_triage.setVisible(False)

        # CARD 4: Chi tiết Kỹ thuật
        self.tech_labels["lbl_image_name"].setText(getattr(c, "image_name", "-") or "-")
        self.tech_labels["lbl_module_name"].setText(getattr(c, "module_name", "-") or "-")
        self.tech_labels["lbl_process_name"].setText(getattr(c, "process_name", "-") or "-")
        self.tech_labels["lbl_bucket_id"].setText(getattr(c, "failure_bucket_id", "-") or "-")

        dump_path = getattr(c, "dump_path", "")
        self.tech_labels["lbl_dump_path"].setText(dump_path if dump_path else "[Không có file dump]")
        self.tech_labels["lbl_dump_sha256"].setText(getattr(c, "dump_sha256", "-") or "-")

        # Cột Phải: Call Stack
        stack_text = getattr(c, "cdb_raw_output", "")
        if stack_text and "STACK_TEXT:" in stack_text:
            parts = stack_text.split("STACK_TEXT:")
            if len(parts) > 1:
                stack_lines = parts[1].split("\n\n")[0]
                self.txt_stack.setPlainText(f"STACK_TEXT:\n{stack_lines.strip()}")
            else:
                self.txt_stack.setPlainText(stack_text.strip())
        elif stack_text:
            self.txt_stack.setPlainText(stack_text.strip())
        elif stack_mods:
            lines = ["CALL STACK TỪ MINIDUMP TRIAGE (TRÍCH XUẤT NỘI BỘ):", "=" * 50]
            for i, m in enumerate(stack_mods):
                lines.append(f"  #{i:02d}  {m}")
            if final_code:
                lines.append("-" * 50)
                lines.append(f"  Ngoại lệ: {final_code} tại {final_addr} ({final_mod})")
            self.txt_stack.setPlainText("\n".join(lines))
        else:
            self.txt_stack.setPlainText("Không có dữ liệu Call Stack (phân tích bằng header_only hoặc log_only).")

        # Cột Phải: Bảng sự kiện liên quan
        c_id = getattr(c, "id", None)
        ev_list = self._evidences_by_crash.get(c_id, []) if c_id else []
        self.table_events.setRowCount(len(ev_list))

        for row, ev in enumerate(ev_list):
            t_ev = getattr(ev, "time_utc", getattr(ev, "timestamp", ""))
            time_ev_str = utc_to_local_str(t_ev) if t_ev else "-"
            source = getattr(ev, "source", "")
            ev_id_str = str(getattr(ev, "event_id", "-")) if getattr(ev, "event_id", None) else "-"
            desc = getattr(ev, "detail", getattr(ev, "details", getattr(ev, "summary", "-")))

            self.table_events.setItem(row, 0, QTableWidgetItem(time_ev_str))
            self.table_events.setItem(row, 1, QTableWidgetItem(source))
            self.table_events.setItem(row, 2, QTableWidgetItem(ev_id_str))
            self.table_events.setItem(row, 3, QTableWidgetItem(desc))

    def _clear_display(self) -> None:
        """Xoá sạch màn hình khi không có dữ liệu."""
        self.lbl_method_badge.setText("Chưa có dữ liệu")
        self.lbl_method_badge.setStyleSheet(get_method_badge_style("none"))
        self.lbl_bugcheck_code.setText("0x00000000")
        self.lbl_bugcheck_name.setText("CHƯA CÓ LỖI")
        self.lbl_time.setText("-")
        self.lbl_time_source.setText("-")
        self.lbl_uptime.setText("-")

        self.val_p1.setText("-")
        self.val_p2.setText("-")
        self.val_p3.setText("-")
        self.val_p4.setText("-")

        self.card_triage.setVisible(False)
        for lbl in self.tech_labels.values():
            lbl.setText("-")
        self.txt_stack.setPlainText("")
        self.table_events.setRowCount(0)
