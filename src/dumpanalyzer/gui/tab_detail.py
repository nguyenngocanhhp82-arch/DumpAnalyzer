"""Tab 2: Chi tiết Crash (Crash Detail Tab) trong PySide6 DumpAnalyzer.

Hiển thị toàn bộ thông số kỹ thuật chuyên sâu của một lần sập được chọn:
- Metadata dump, mã Bug Check, 4 tham số (P1..P4), thủ phạm / nạn nhân.
- Khung Call Stack (STACK_TEXT) với font monospaced dễ đọc.
- Bảng sự kiện Event Log xảy ra trong cửa sổ 10 phút trước khi sập.
"""

from typing import Any, Dict, List, Optional
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from dumpanalyzer.core.models import Crash, Evidence
from dumpanalyzer.core.timeutil import utc_to_local_str
from dumpanalyzer.gui.theme import (
    COLOR_BG_INPUT,
    COLOR_BG_SURFACE,
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
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(14)

        # 1. Hàng trên cùng: Selector chọn crash + Badge trạng thái
        top_bar = QHBoxLayout()
        top_bar.setSpacing(12)

        lbl_select = QLabel("Chọn lần sập cần xem:")
        lbl_select.setStyleSheet(f"font-weight: bold; color: {COLOR_TEXT_PRIMARY};")
        top_bar.addWidget(lbl_select)

        self.combo_crashes = QComboBox()
        self.combo_crashes.currentIndexChanged.connect(self._on_crash_combo_changed)
        top_bar.addWidget(self.combo_crashes, 1)

        self.lbl_method_badge = QLabel("Chưa chọn")
        self.lbl_method_badge.setStyleSheet(get_method_badge_style("none"))
        top_bar.addWidget(self.lbl_method_badge)

        main_layout.addLayout(top_bar)

        # 2. Vùng nội dung chính: QSplitter chia 2 cột trái - phải
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(8)

        # ==================== CỘT TRÁI: THÔNG SỐ VÀ THAM SỐ ====================
        left_card = QFrame()
        left_card.setObjectName("CardFrame")
        left_layout = QVBoxLayout(left_card)
        left_layout.setContentsMargins(14, 14, 14, 14)
        left_layout.setSpacing(12)

        lbl_meta_title = QLabel("THÔNG TIN DUMP & THAM SỐ LỖI")
        lbl_meta_title.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {COLOR_TEXT_PRIMARY}; border-bottom: 2px solid {COLOR_BORDER}; padding-bottom: 6px;")
        left_layout.addWidget(lbl_meta_title)

        grid = QGridLayout()
        grid.setVerticalSpacing(8)
        grid.setHorizontalSpacing(10)

        # Định nghĩa các trường thông tin
        fields = [
            ("Thời điểm:", "lbl_time"),
            ("Nguồn thời điểm:", "lbl_time_source"),
            ("Mã lỗi BugCheck:", "lbl_bugcheck_code"),
            ("Tên lỗi chuẩn:", "lbl_bugcheck_name"),
            ("Driver thủ phạm:", "lbl_image_name"),
            ("Module gây lỗi:", "lbl_module_name"),
            ("Tiến trình (Process):", "lbl_process_name"),
            ("Failure Bucket ID:", "lbl_bucket_id"),
            ("Thời gian chạy (Uptime):", "lbl_uptime"),
            ("Đường dẫn dump:", "lbl_dump_path"),
            ("Mã băm SHA256:", "lbl_dump_sha256"),
        ]

        self.meta_labels: Dict[str, QLabel] = {}
        for row_idx, (title, attr) in enumerate(fields):
            lbl_title = QLabel(title)
            lbl_title.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px; font-weight: 500;")
            lbl_val = QLabel("-")
            lbl_val.setStyleSheet(f"color: {COLOR_TEXT_PRIMARY}; font-size: 12px; font-weight: 600;")
            lbl_val.setWordWrap(True)
            grid.addWidget(lbl_title, row_idx, 0, Qt.AlignTop | Qt.AlignLeft)
            grid.addWidget(lbl_val, row_idx, 1, Qt.AlignTop | Qt.AlignLeft)
            self.meta_labels[attr] = lbl_val

        grid.setColumnStretch(1, 1)
        left_layout.addLayout(grid)

        # Khung 4 tham số BugCheck Parameters (P1..P4)
        lbl_params_title = QLabel("4 THAM SỐ BUGCHECK PARAMETERS (P1 - P4)")
        lbl_params_title.setStyleSheet(f"font-size: 12px; font-weight: bold; color: {COLOR_TEXT_MUTED}; border-bottom: 1px dashed {COLOR_BORDER}; padding-bottom: 4px; margin-top: 10px;")
        left_layout.addWidget(lbl_params_title)

        grid_p = QGridLayout()
        grid_p.setSpacing(6)
        self.lbl_p1 = QLabel("P1: -")
        self.lbl_p2 = QLabel("P2: -")
        self.lbl_p3 = QLabel("P3: -")
        self.lbl_p4 = QLabel("P4: -")

        for p_lbl in (self.lbl_p1, self.lbl_p2, self.lbl_p3, self.lbl_p4):
            p_lbl.setStyleSheet("background-color: #0b1120; color: #38bdf8; font-family: monospace; font-size: 11px; padding: 6px; border-radius: 4px; border: 1px solid #1e293b;")

        grid_p.addWidget(self.lbl_p1, 0, 0)
        grid_p.addWidget(self.lbl_p2, 0, 1)
        grid_p.addWidget(self.lbl_p3, 1, 0)
        grid_p.addWidget(self.lbl_p4, 1, 1)
        left_layout.addLayout(grid_p)

        left_layout.addStretch()
        splitter.addWidget(left_card)

        # ==================== CỘT PHẢI: STACK & SỰ KIỆN 10 PHÚT ====================
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(14)

        # 1. Khung Call Stack (STACK_TEXT)
        stack_card = QFrame()
        stack_card.setObjectName("CardFrame")
        stack_layout = QVBoxLayout(stack_card)
        stack_layout.setContentsMargins(14, 14, 14, 14)
        stack_layout.setSpacing(8)

        lbl_stack_title = QLabel("CALL STACK TRACE (!analyze -v STACK_TEXT)")
        lbl_stack_title.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {COLOR_TEXT_PRIMARY}; border-bottom: 2px solid {COLOR_BORDER}; padding-bottom: 6px;")
        stack_layout.addWidget(lbl_stack_title)

        self.txt_stack = QPlainTextEdit()
        self.txt_stack.setReadOnly(True)
        self.txt_stack.setPlaceholderText("Không có dữ liệu Call Stack (chế độ header_only hoặc không có dump).")
        stack_layout.addWidget(self.txt_stack)

        right_layout.addWidget(stack_card, 1)

        # 2. Khung Bảng sự kiện 10 phút trước crash
        events_card = QFrame()
        events_card.setObjectName("CardFrame")
        events_layout = QVBoxLayout(events_card)
        events_layout.setContentsMargins(14, 14, 14, 14)
        events_layout.setSpacing(8)

        lbl_events_title = QLabel("SỰ KIỆN WINDOWS EVENT LOG TRONG CỬA SỔ 10 PHÚT TRƯỚC SẬP")
        lbl_events_title.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {COLOR_TEXT_PRIMARY}; border-bottom: 2px solid {COLOR_BORDER}; padding-bottom: 6px;")
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
        events_layout.addWidget(self.table_events)

        right_layout.addWidget(events_card, 1)

        splitter.addWidget(right_container)
        splitter.setSizes([380, 620])

        main_layout.addWidget(splitter)

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

        for idx, c in enumerate(self._crashes, start=1):
            t_val = getattr(c, "crash_time_utc", getattr(c, "crash_time", None))
            t_str = utc_to_local_str(t_val) if t_val else "Chưa rõ thời điểm"
            bc_code = getattr(c, "bugcheck_code", "N/A") or "N/A"
            bc_name = getattr(c, "bugcheck_name", "Chưa rõ") or "Chưa rõ"
            item_text = f"Sự cố #{idx}: {t_str} — {bc_code} ({bc_name})"
            self.combo_crashes.addItem(item_text, userData=c)

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

        # Nếu không có trong combo, tự hiển thị
        self._display_crash(crash)

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
        analyzed = getattr(c, "analyzed_by", "none")

        # Cập nhật Badge
        if analyzed == "log_only":
            self.lbl_method_badge.setText("Không có dump (log_only)")
        elif analyzed == "header_only":
            self.lbl_method_badge.setText("Header-only")
        else:
            self.lbl_method_badge.setText("WinDbg cdb")
        self.lbl_method_badge.setStyleSheet(get_method_badge_style(analyzed))

        # Cập nhật thông tin cột trái
        self.meta_labels["lbl_time"].setText(t_str)
        time_src = getattr(c, "crash_time_source", "unknown") or "unknown"
        src_labels = {
            "header": "Header file dump (chính xác)",
            "cdb": "WinDbg cdb (chính xác)",
            "mtime": "Giờ sửa file mtime (ước tính)",
            "eventlog_6008": "EventLog 6008 (tắt bất thường)",
            "estimated": "Ước tính từ chuỗi sự kiện",
            "kp41": "Kernel-Power Event 41",
        }
        self.meta_labels["lbl_time_source"].setText(src_labels.get(time_src, time_src))
        self.meta_labels["lbl_bugcheck_code"].setText(getattr(c, "bugcheck_code", "N/A") or "N/A")
        self.meta_labels["lbl_bugcheck_name"].setText(getattr(c, "bugcheck_name", "Chưa rõ") or "Chưa rõ")
        self.meta_labels["lbl_image_name"].setText(getattr(c, "image_name", "-") or "-")
        self.meta_labels["lbl_module_name"].setText(getattr(c, "module_name", "-") or "-")
        self.meta_labels["lbl_process_name"].setText(getattr(c, "process_name", "-") or "-")
        self.meta_labels["lbl_bucket_id"].setText(getattr(c, "failure_bucket_id", "-") or "-")

        uptime_sec = getattr(c, "uptime_seconds", 0) or 0
        if uptime_sec > 0:
            uptime_str = f"{uptime_sec} giây (~{uptime_sec // 60} phút)"
        else:
            uptime_str = "Không rõ"
        self.meta_labels["lbl_uptime"].setText(uptime_str)

        dump_path = getattr(c, "dump_path", "")
        self.meta_labels["lbl_dump_path"].setText(dump_path if dump_path else "[Không có file dump]")
        self.meta_labels["lbl_dump_sha256"].setText(getattr(c, "dump_sha256", "-") or "-")

        # Cập nhật 4 tham số
        self.lbl_p1.setText(f"P1: {getattr(c, 'p1', '-') or '-'}")
        self.lbl_p2.setText(f"P2: {getattr(c, 'p2', '-') or '-'}")
        self.lbl_p3.setText(f"P3: {getattr(c, 'p3', '-') or '-'}")
        self.lbl_p4.setText(f"P4: {getattr(c, 'p4', '-') or '-'}")

        # Cập nhật Call Stack
        stack_text = getattr(c, "cdb_raw_output", "")
        if stack_text and "STACK_TEXT:" in stack_text:
            # Trích xuất đoạn STACK_TEXT nếu có
            parts = stack_text.split("STACK_TEXT:")
            if len(parts) > 1:
                stack_lines = parts[1].split("\n\n")[0]
                self.txt_stack.setPlainText(f"STACK_TEXT:\n{stack_lines.strip()}")
            else:
                self.txt_stack.setPlainText(stack_text.strip())
        elif stack_text:
            self.txt_stack.setPlainText(stack_text.strip())
        else:
            self.txt_stack.setPlainText("Không có dữ liệu Call Stack (phân tích bằng header_only hoặc log_only).")

        # Cập nhật bảng sự kiện liên quan
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
        for lbl in self.meta_labels.values():
            lbl.setText("-")
        self.lbl_p1.setText("P1: -")
        self.lbl_p2.setText("P2: -")
        self.lbl_p3.setText("P3: -")
        self.lbl_p4.setText("P4: -")
        self.txt_stack.setPlainText("")
        self.table_events.setRowCount(0)
