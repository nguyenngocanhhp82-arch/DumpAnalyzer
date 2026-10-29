"""Tab 1: Tổng quan (Overview Tab) trong giao diện PySide6 DumpAnalyzer.

Hiển thị 4 thẻ KPI thống kê chính, thanh tìm kiếm lọc theo mã lỗi/module,
và bảng danh sách tất cả các lần sập máy với nhãn chữ kèm màu sắc chuyên nghiệp.
Đặc biệt: dòng nào là crash log_only có gắn nhãn rõ ràng 'Không có dump'.
"""

from typing import Any, Dict, List, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from dumpanalyzer.core.models import Crash, Finding
from dumpanalyzer.core.timeutil import utc_to_local_str
from dumpanalyzer.gui.theme import (
    COLOR_BG_INPUT,
    COLOR_BG_SURFACE,
    COLOR_BORDER,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    get_method_badge_style,
    get_suspect_badge_color,
)


class KPICard(QFrame):
    """Thẻ thông số KPI trực quan với tiêu đề và giá trị nổi bật."""

    def __init__(self, title: str, initial_value: str = "-", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("CardFrame")
        self.setFrameShape(QFrame.StyledPanel)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        self.lbl_title = QLabel(title)
        self.lbl_title.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px; font-weight: 600; text-transform: uppercase;")
        layout.addWidget(self.lbl_title)

        self.lbl_value = QLabel(initial_value)
        self.lbl_value.setStyleSheet(f"color: {COLOR_TEXT_PRIMARY}; font-size: 20px; font-weight: bold;")
        layout.addWidget(self.lbl_value)

    def set_value(self, val: str, color_override: Optional[str] = None) -> None:
        """Cập nhật giá trị hiển thị trên thẻ."""
        self.lbl_value.setText(val)
        if color_override:
            self.lbl_value.setStyleSheet(f"color: {color_override}; font-size: 20px; font-weight: bold;")
        else:
            self.lbl_value.setStyleSheet(f"color: {COLOR_TEXT_PRIMARY}; font-size: 20px; font-weight: bold;")


class OverviewTab(QWidget):
    """Tab Tổng quan danh sách sự cố và các thẻ thống kê tổng quan."""

    crash_selected = Signal(object)  # Phát ra đối tượng Crash khi người dùng chọn một dòng

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._crashes: List[Crash] = []
        self._filtered_crashes: List[Crash] = []
        self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        # 1. Hàng 4 thẻ KPI thống kê
        kpi_layout = QHBoxLayout()
        kpi_layout.setSpacing(16)

        self.card_total = KPICard("Tổng số sự cố", "0 lần")
        self.card_dumps = KPICard("Dump đã phân tích", "0 / 0")
        self.card_top_suspect = KPICard("Nghi ngờ chính", "-")
        self.card_confidence = KPICard("Độ tin cậy", "-")

        kpi_layout.addWidget(self.card_total)
        kpi_layout.addWidget(self.card_dumps)
        kpi_layout.addWidget(self.card_top_suspect)
        kpi_layout.addWidget(self.card_confidence)
        main_layout.addLayout(kpi_layout)

        # 2. Thanh tìm kiếm và bộ lọc nhanh
        filter_layout = QHBoxLayout()
        filter_layout.setSpacing(12)

        lbl_filter = QLabel("Lọc dữ liệu:")
        lbl_filter.setStyleSheet(f"font-weight: 600; color: {COLOR_TEXT_MUTED};")
        filter_layout.addWidget(lbl_filter)

        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Tìm kiếm theo mã lỗi (0x124...), tên lỗi hoặc module/driver...")
        self.txt_search.textChanged.connect(self._apply_filter)
        filter_layout.addWidget(self.txt_search, 1)

        self.combo_type_filter = QComboBox()
        self.combo_type_filter.addItems(["Tất cả sự cố", "Chỉ có file dump", "Không có dump (log_only)"])
        self.combo_type_filter.currentIndexChanged.connect(self._apply_filter)
        filter_layout.addWidget(self.combo_type_filter)

        main_layout.addLayout(filter_layout)

        # 3. Bảng danh sách các lần sập
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Thời điểm (Giờ địa phương)",
            "Mã lỗi",
            "Tên lỗi BugCheck",
            "Module / Driver",
            "Nhóm nghi ngờ",
            "Phương thức",
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)

        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.itemDoubleClicked.connect(self._on_item_double_clicked)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)

        main_layout.addWidget(self.table)

    def set_data(
        self,
        crashes: List[Crash],
        finding: Optional[Finding] = None,
        suspect_ranking: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """Cập nhật dữ liệu sập máy và các thẻ KPI thống kê."""
        self._crashes = list(crashes)
        total_crashes = len(crashes)
        dump_crashes = sum(1 for c in crashes if getattr(c, "analyzed_by", "") != "log_only")

        self.card_total.set_value(f"{total_crashes} sự cố")
        self.card_dumps.set_value(f"{dump_crashes} có dump / {total_crashes - dump_crashes} log")

        if finding:
            conf_str = finding.confidence.upper()
            self.card_confidence.set_value(conf_str)

            top_name = "-"
            if suspect_ranking:
                s0 = suspect_ranking[0]
                label = s0.get("label", s0.get("suspect", "Khác"))
                pct = float(s0.get("percentage", s0.get("score", 0.0)))
                top_name = f"{label} ({pct:.1f}%)"
            elif hasattr(finding, "suspect"):
                top_name = f"{finding.suspect} ({finding.score:.1f}%)"
            self.card_top_suspect.set_value(top_name)
        else:
            self.card_top_suspect.set_value("-")
            self.card_confidence.set_value("-")

        self._apply_filter()

    def _apply_filter(self) -> None:
        """Lọc danh sách crash theo ô tìm kiếm và dropdown loại dump."""
        search_kw = self.txt_search.text().strip().lower()
        type_idx = self.combo_type_filter.currentIndex()

        self._filtered_crashes = []
        for c in self._crashes:
            # Lọc theo loại
            is_log_only = getattr(c, "analyzed_by", "") == "log_only"
            if type_idx == 1 and is_log_only:
                continue
            if type_idx == 2 and not is_log_only:
                continue

            # Lọc theo từ khóa
            bc_code = (getattr(c, "bugcheck_code", "") or "").lower()
            bc_name = (getattr(c, "bugcheck_name", "") or "").lower()
            mod = (getattr(c, "image_name", "") or getattr(c, "module_name", "") or "").lower()
            suspect = (getattr(c, "suspect_hardware", "") or "").lower()

            if search_kw:
                if not (search_kw in bc_code or search_kw in bc_name or search_kw in mod or search_kw in suspect):
                    continue

            self._filtered_crashes.append(c)

        self._populate_table()

    def _populate_table(self) -> None:
        """Điền dữ liệu vào bảng sau khi đã lọc."""
        self.table.setRowCount(len(self._filtered_crashes))

        for row, c in enumerate(self._filtered_crashes):
            t_val = getattr(c, "crash_time_utc", getattr(c, "crash_time", None))
            time_str = utc_to_local_str(t_val) if t_val else "Không xác định"
            bc_code = getattr(c, "bugcheck_code", "N/A") or "N/A"
            bc_name = getattr(c, "bugcheck_name", "Chưa rõ") or "Chưa rõ"
            mod = getattr(c, "image_name", getattr(c, "module_name", "-")) or "-"
            suspect = getattr(c, "suspect_hardware", "Chưa rõ") or "Chưa rõ"
            analyzed = getattr(c, "analyzed_by", "none")

            # 1. Cột Thời điểm
            item_time = QTableWidgetItem(time_str)
            item_time.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            self.table.setItem(row, 0, item_time)

            # 2. Cột Mã lỗi
            item_code = QTableWidgetItem(bc_code)
            item_code.setTextAlignment(Qt.AlignCenter)
            item_code.setForeground(Qt.white)
            self.table.setItem(row, 1, item_code)

            # 3. Cột Tên lỗi
            item_name = QTableWidgetItem(bc_name)
            item_name.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            self.table.setItem(row, 2, item_name)

            # 4. Cột Module
            item_mod = QTableWidgetItem(mod)
            item_mod.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            self.table.setItem(row, 3, item_mod)

            # 5. Cột Nhóm nghi ngờ (Widget thẻ màu có nhãn chữ)
            bg_col, fg_col = get_suspect_badge_color(suspect)
            lbl_suspect = QLabel(f" {suspect} ")
            lbl_suspect.setAlignment(Qt.AlignCenter)
            lbl_suspect.setStyleSheet(
                f"background-color: {bg_col}; color: {fg_col}; font-weight: bold; border-radius: 4px; padding: 2px 6px;"
            )
            cell_suspect = QWidget()
            layout_s = QHBoxLayout(cell_suspect)
            layout_s.setContentsMargins(4, 4, 4, 4)
            layout_s.addWidget(lbl_suspect)
            self.table.setCellWidget(row, 4, cell_suspect)

            # 6. Cột Phương thức phân tích (Gắn nhãn 'Không có dump' nếu là log_only)
            badge_text = "WinDbg cdb"
            if analyzed == "log_only":
                badge_text = "Không có dump"
            elif analyzed == "header_only":
                badge_text = "Header-only"

            lbl_method = QLabel(badge_text)
            lbl_method.setAlignment(Qt.AlignCenter)
            lbl_method.setStyleSheet(get_method_badge_style(analyzed))
            cell_method = QWidget()
            layout_m = QHBoxLayout(cell_method)
            layout_m.setContentsMargins(4, 4, 4, 4)
            layout_m.addWidget(lbl_method)
            self.table.setCellWidget(row, 5, cell_method)

    def _on_selection_changed(self) -> None:
        """Xử lý khi người dùng chọn dòng trong bảng."""
        selected_rows = self.table.selectedIndexes()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        if 0 <= row < len(self._filtered_crashes):
            selected_crash = self._filtered_crashes[row]
            self.crash_selected.emit(selected_crash)

    def _on_item_double_clicked(self, item: QTableWidgetItem) -> None:
        """Nhấp đúp chuột vào một dòng để chuyển sang tab Chi tiết."""
        row = item.row()
        if 0 <= row < len(self._filtered_crashes):
            selected_crash = self._filtered_crashes[row]
            self.crash_selected.emit(selected_crash)
