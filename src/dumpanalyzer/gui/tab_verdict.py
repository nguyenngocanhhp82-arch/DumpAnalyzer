"""Tab 3: Kết luận chẩn đoán (Verdict Tab) trong PySide6 DumpAnalyzer.

Hiển thị xếp hạng nghi ngờ với thanh phần trăm trực quan, phân tích mức độ tin cậy,
danh sách bằng chứng có gắn nhãn phân loại, giải thích nguyên nhân bằng tiếng Việt
và danh sách các bước kiểm tra khuyến nghị được sắp xếp từ Dễ đến Khó.
"""

from typing import Any, Dict, List, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from dumpanalyzer.core.models import Crash, Evidence, Finding, MachineInfo
from dumpanalyzer.gui.theme import (
    COLOR_ACCENT,
    COLOR_BORDER,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_WARNING,
    get_confidence_badge_style,
)
from dumpanalyzer.report.exporter import export_excel_report, export_html_report


class SuspectBarWidget(QWidget):
    """Widget hiển thị một dòng nghi vấn với thanh phần trăm và số điểm."""

    def __init__(self, label: str, percentage: float, parent: Optional[QWidget] = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(4)

        header_layout = QHBoxLayout()
        lbl_name = QLabel(label)
        lbl_name.setStyleSheet(f"color: {COLOR_TEXT_PRIMARY}; font-weight: 600; font-size: 13px;")
        header_layout.addWidget(lbl_name)

        lbl_pct = QLabel(f"{percentage:.1f}%")
        lbl_pct.setStyleSheet(f"color: {COLOR_ACCENT}; font-weight: bold; font-size: 13px;")
        header_layout.addWidget(lbl_pct, alignment=Qt.AlignRight)
        layout.addLayout(header_layout)

        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(int(percentage))
        bar.setTextVisible(False)
        bar.setFixedHeight(8)
        layout.addWidget(bar)


class VerdictTab(QWidget):
    """Tab Kết luận & Khuyến nghị hành động tiếp theo."""

    export_requested = Signal(str)  # Phát ra khi yêu cầu xuất ('html' hoặc 'excel')

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._crashes: List[Crash] = []
        self._finding: Optional[Finding] = None
        self._machine_info: Optional[MachineInfo] = None
        self._evidences: List[Evidence] = []
        self._suspect_ranking: List[Dict[str, Any]] = []
        self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        # QSplitter chia 2 cột: Cột trái (Xếp hạng & Bằng chứng), Cột phải (Rationale & Các bước kiểm tra)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(8)

        # ==================== CỘT TRÁI: XẾP HẠNG & BẰNG CHỨNG ====================
        left_container = QWidget()
        left_layout = QVBoxLayout(left_container)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(14)

        # 1. Thẻ Kết luận đứng đầu & Độ tin cậy
        top_card = QFrame()
        top_card.setObjectName("CardFrame")
        top_layout = QVBoxLayout(top_card)
        top_layout.setContentsMargins(14, 14, 14, 14)
        top_layout.setSpacing(10)

        header_row = QHBoxLayout()
        lbl_top_title = QLabel("KẾT LUẬN NGUYÊN NHÂN CHÍNH")
        lbl_top_title.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {COLOR_TEXT_MUTED}; text-transform: uppercase;")
        header_row.addWidget(lbl_top_title)

        self.lbl_confidence_badge = QLabel("ĐỘ TIN CẬY: CHƯA RÕ")
        self.lbl_confidence_badge.setStyleSheet(get_confidence_badge_style("none"))
        header_row.addWidget(self.lbl_confidence_badge, alignment=Qt.AlignRight)
        top_layout.addLayout(header_row)

        self.lbl_top_suspect = QLabel("Chưa có kết luận chẩn đoán")
        self.lbl_top_suspect.setStyleSheet("font-size: 22px; font-weight: bold; color: #38bdf8; margin: 4px 0;")
        top_layout.addWidget(self.lbl_top_suspect)

        # Cảnh báo mâu thuẫn (Conflict Warning) nếu dump vs log không thống nhất
        self.conflict_banner = QFrame()
        self.conflict_banner.setStyleSheet(
            f"background-color: #451a03; border: 1px solid {COLOR_WARNING}; border-radius: 6px; padding: 8px;"
        )
        conf_layout = QHBoxLayout(self.conflict_banner)
        conf_layout.setContentsMargins(8, 6, 8, 6)
        lbl_conf_icon = QLabel("⚠️")
        lbl_conf_icon.setStyleSheet("font-size: 16px;")
        conf_layout.addWidget(lbl_conf_icon)

        self.lbl_conflict_text = QLabel("Cảnh báo: Dữ liệu dump và sự kiện log mâu thuẫn (chưa thống nhất hướng nghi ngờ).")
        self.lbl_conflict_text.setStyleSheet("color: #fde68a; font-size: 12px; font-weight: 500;")
        self.lbl_conflict_text.setWordWrap(True)
        conf_layout.addWidget(self.lbl_conflict_text, 1)

        self.conflict_banner.setVisible(False)
        top_layout.addWidget(self.conflict_banner)

        left_layout.addWidget(top_card)

        # 2. Thẻ Xếp hạng xác suất nghi ngờ
        ranking_card = QFrame()
        ranking_card.setObjectName("CardFrame")
        ranking_layout = QVBoxLayout(ranking_card)
        ranking_layout.setContentsMargins(14, 14, 14, 14)
        ranking_layout.setSpacing(10)

        lbl_rank_title = QLabel("XẾP HẠNG XÁC SUẤT NGI VẤN")
        lbl_rank_title.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {COLOR_TEXT_PRIMARY}; border-bottom: 2px solid {COLOR_BORDER}; padding-bottom: 6px;")
        ranking_layout.addWidget(lbl_rank_title)

        self.ranking_container = QVBoxLayout()
        self.ranking_container.setSpacing(8)
        ranking_layout.addLayout(self.ranking_container)

        left_layout.addWidget(ranking_card)

        # 3. Thẻ Bằng chứng thu thập
        evidence_card = QFrame()
        evidence_card.setObjectName("CardFrame")
        ev_layout = QVBoxLayout(evidence_card)
        ev_layout.setContentsMargins(14, 14, 14, 14)
        ev_layout.setSpacing(8)

        lbl_ev_title = QLabel("BẰNG CHỨNG ĐỐI CHIẾU THU THẬP ĐƯỢC")
        lbl_ev_title.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {COLOR_TEXT_PRIMARY}; border-bottom: 2px solid {COLOR_BORDER}; padding-bottom: 6px;")
        ev_layout.addWidget(lbl_ev_title)

        scroll_ev = QScrollArea()
        scroll_ev.setWidgetResizable(True)
        scroll_ev.setFrameShape(QFrame.NoFrame)
        self.ev_widget = QWidget()
        self.ev_container = QVBoxLayout(self.ev_widget)
        self.ev_container.setContentsMargins(0, 0, 0, 0)
        self.ev_container.setSpacing(6)
        scroll_ev.setWidget(self.ev_widget)
        ev_layout.addWidget(scroll_ev, 1)

        left_layout.addWidget(evidence_card, 1)
        splitter.addWidget(left_container)

        # ==================== CỘT PHẢI: RATIONALE & KHUYẾN NGHỊ ====================
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(14)

        # 1. Thẻ Giải thích nguyên nhân (Rationale)
        rat_card = QFrame()
        rat_card.setObjectName("CardFrame")
        rat_layout = QVBoxLayout(rat_card)
        rat_layout.setContentsMargins(14, 14, 14, 14)
        rat_layout.setSpacing(8)

        lbl_rat_title = QLabel("GIẢI THÍCH NGUYÊN NHÂN (RATIONALE)")
        lbl_rat_title.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {COLOR_TEXT_PRIMARY}; border-bottom: 2px solid {COLOR_BORDER}; padding-bottom: 6px;")
        rat_layout.addWidget(lbl_rat_title)

        self.lbl_rationale = QLabel("Chưa có dữ liệu phân tích.")
        self.lbl_rationale.setStyleSheet("color: #e2e8f0; font-size: 13px; line-height: 1.5; padding: 8px 0;")
        self.lbl_rationale.setWordWrap(True)
        rat_layout.addWidget(self.lbl_rationale)

        right_layout.addWidget(rat_card)

        # 2. Thẻ Các bước kiểm tra theo thứ tự từ Dễ đến Khó
        steps_card = QFrame()
        steps_card.setObjectName("CardFrame")
        steps_layout = QVBoxLayout(steps_card)
        steps_layout.setContentsMargins(14, 14, 14, 14)
        steps_layout.setSpacing(10)

        lbl_steps_title = QLabel("VIỆC CẦN KIỂM TRA (SẮP XẾP TỪ DỄ ĐẾN KHÓ)")
        lbl_steps_title.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {COLOR_TEXT_PRIMARY}; border-bottom: 2px solid {COLOR_BORDER}; padding-bottom: 6px;")
        steps_layout.addWidget(lbl_steps_title)

        scroll_steps = QScrollArea()
        scroll_steps.setWidgetResizable(True)
        scroll_steps.setFrameShape(QFrame.NoFrame)
        self.steps_widget = QWidget()
        self.steps_container = QVBoxLayout(self.steps_widget)
        self.steps_container.setContentsMargins(0, 0, 0, 0)
        self.steps_container.setSpacing(8)
        scroll_steps.setWidget(self.steps_widget)
        steps_layout.addWidget(scroll_steps, 1)

        right_layout.addWidget(steps_card, 1)

        # 3. Hàng nút xuất báo cáo & Lưu ý kỹ thuật
        bottom_actions = QHBoxLayout()
        bottom_actions.setSpacing(12)

        self.btn_export_html = QPushButton("Xuất báo cáo HTML")
        self.btn_export_html.setStyleSheet("background-color: #2563eb; color: #ffffff; font-weight: bold; padding: 9px 18px; border-radius: 6px;")
        self.btn_export_html.clicked.connect(self._on_export_html_clicked)
        bottom_actions.addWidget(self.btn_export_html)

        self.btn_export_excel = QPushButton("Xuất báo cáo Excel (.xlsx)")
        self.btn_export_excel.setStyleSheet("background-color: #15803d; color: #ffffff; font-weight: bold; padding: 9px 18px; border-radius: 6px;")
        self.btn_export_excel.clicked.connect(self._on_export_excel_clicked)
        bottom_actions.addWidget(self.btn_export_excel)

        bottom_actions.addStretch()
        right_layout.addLayout(bottom_actions)

        lbl_disclaimer = QLabel("Lưu ý: Kết luận là khoanh vùng xác suất theo quy tắc, không phải khẳng định tuyệt đối.")
        lbl_disclaimer.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px; font-style: italic;")
        right_layout.addWidget(lbl_disclaimer)

        splitter.addWidget(right_container)
        splitter.setSizes([450, 550])

        main_layout.addWidget(splitter)

    def set_data(
        self,
        crashes: List[Crash],
        finding: Optional[Finding] = None,
        machine_info: Optional[MachineInfo] = None,
        evidences: Optional[List[Evidence]] = None,
        suspect_ranking: Optional[List[Dict[str, Any]]] = None,
        conflict_detected: bool = False,
    ) -> None:
        """Cập nhật dữ liệu chẩn đoán và khuyến nghị lên giao diện."""
        self._crashes = list(crashes)
        self._finding = finding
        self._machine_info = machine_info
        self._evidences = list(evidences or [])
        self._suspect_ranking = list(suspect_ranking or [])

        # 1. Cập nhật Thẻ kết luận chính & Độ tin cậy
        if finding:
            conf_str = finding.confidence.upper()
            self.lbl_confidence_badge.setText(f"ĐỘ TIN CẬY: {conf_str}")
            self.lbl_confidence_badge.setStyleSheet(get_confidence_badge_style(finding.confidence))

            top_text = "Chưa rõ"
            if self._suspect_ranking:
                s0 = self._suspect_ranking[0]
                label = s0.get("label", s0.get("suspect", "Khác"))
                pct = float(s0.get("percentage", s0.get("score", 0.0)))
                top_text = f"{label} ({pct:.1f}%)"
            elif hasattr(finding, "suspect"):
                top_text = f"{finding.suspect} ({finding.score:.1f}%)"
            self.lbl_top_suspect.setText(top_text)

            self.lbl_rationale.setText(finding.rationale or "Không có diễn giải bổ sung.")
        else:
            self.lbl_confidence_badge.setText("ĐỘ TIN CẬY: CHƯA RÕ")
            self.lbl_confidence_badge.setStyleSheet(get_confidence_badge_style("none"))
            self.lbl_top_suspect.setText("Chưa có kết luận chẩn đoán")
            self.lbl_rationale.setText("Chưa có dữ liệu phân tích.")

        # Cờ xung đột
        self.conflict_banner.setVisible(conflict_detected)

        # 2. Xây dựng danh sách thanh xếp hạng
        self._clear_layout(self.ranking_container)
        if self._suspect_ranking:
            for s in self._suspect_ranking:
                label = s.get("label", s.get("suspect", "Khác"))
                pct = float(s.get("percentage", s.get("score", 0.0)))
                bar_item = SuspectBarWidget(label, pct)
                self.ranking_container.addWidget(bar_item)
        else:
            lbl_empty = QLabel("Chưa có thông tin xếp hạng.")
            lbl_empty.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-style: italic;")
            self.ranking_container.addWidget(lbl_empty)

        # 3. Xây dựng danh sách bằng chứng
        self._clear_layout(self.ev_container)
        if self._evidences:
            for ev in self._evidences[:20]:  # Giới hạn 20 bằng chứng nổi bật nhất
                ev_card = QFrame()
                ev_card.setStyleSheet("background-color: #0b1120; border: 1px solid #1e293b; border-radius: 6px; padding: 6px;")
                card_l = QVBoxLayout(ev_card)
                card_l.setContentsMargins(6, 4, 6, 4)
                card_l.setSpacing(2)

                top_l = QHBoxLayout()
                ev_type = getattr(ev, "kind", getattr(ev, "evidence_type", "eventlog"))
                source = getattr(ev, "source", "")
                lbl_badge = QLabel(f"[{ev_type.upper()}] {source}")
                lbl_badge.setStyleSheet("color: #38bdf8; font-weight: bold; font-size: 11px;")
                top_l.addWidget(lbl_badge)

                weight = getattr(ev, "weight", 10)
                lbl_w = QLabel(f"+{weight}")
                lbl_w.setStyleSheet("color: #4ade80; font-weight: bold; font-size: 11px;")
                top_l.addWidget(lbl_w, alignment=Qt.AlignRight)
                card_l.addLayout(top_l)

                detail = getattr(ev, "detail", getattr(ev, "details", getattr(ev, "summary", "-")))
                lbl_d = QLabel(detail)
                lbl_d.setStyleSheet("color: #cbd5e1; font-size: 11px;")
                lbl_d.setWordWrap(True)
                card_l.addWidget(lbl_d)

                self.ev_container.addWidget(ev_card)
        else:
            lbl_no_ev = QLabel("Chưa thu thập được bằng chứng cụ thể.")
            lbl_no_ev.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-style: italic;")
            self.ev_container.addWidget(lbl_no_ev)

        # 4. Xây dựng danh sách các bước kiểm tra (Từ Dễ đến Khó)
        self._clear_layout(self.steps_container)
        next_steps = finding.next_steps if finding else []
        if next_steps:
            for idx, step in enumerate(next_steps, start=1):
                step_item = self._create_step_widget(idx, step)
                self.steps_container.addWidget(step_item)
        else:
            lbl_no_step = QLabel("Không có hành động khuyến nghị nào.")
            lbl_no_step.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-style: italic;")
            self.steps_container.addWidget(lbl_no_step)

    def _create_step_widget(self, index: int, step_text: str) -> QWidget:
        """Tạo widget cho một bước kiểm tra kèm huy hiệu phân loại độ khó."""
        w = QFrame()
        w.setStyleSheet("background-color: #0b1120; border: 1px solid #1e293b; border-radius: 6px; padding: 8px;")
        l = QHBoxLayout(w)
        l.setContentsMargins(8, 6, 8, 6)
        l.setSpacing(10)

        # Huy hiệu độ khó
        badge_style, badge_text = self._get_tier_badge_info(step_text)
        lbl_tier = QLabel(badge_text)
        lbl_tier.setStyleSheet(badge_style)
        l.addWidget(lbl_tier, alignment=Qt.AlignTop)

        lbl_desc = QLabel(f"<strong>{index}.</strong> {step_text}")
        lbl_desc.setStyleSheet("color: #f1f5f9; font-size: 13px; line-height: 1.4;")
        lbl_desc.setWordWrap(True)
        l.addWidget(lbl_desc, 1)

        return w

    def _get_tier_badge_info(self, step_text: str) -> tuple[str, str]:
        """Xác định phong cách CSS và tên huy hiệu tầng độ khó."""
        s = step_text.lower()
        if any(k in s for k in ["nhiệt độ", "nóng", "quạt", "driver verifier", "khởi động sạch", "cấu hình dump", "tắt verifier"]):
            return "background-color: #1e3a8a; color: #bfdbfe; font-size: 10px; font-weight: bold; padding: 2px 6px; border-radius: 4px;", "TẦNG 1: DỄ"
        elif any(k in s for k in ["ddu", "cập nhật driver", "cài lại driver", "sfc", "chkdsk", "sửa lỗi tệp", "diệt virus", "antivirus"]):
            return "background-color: #78350f; color: #fde68a; font-size: 10px; font-weight: bold; padding: 2px 6px; border-radius: 4px;", "TẦNG 2: TRUNG BÌNH"
        elif any(k in s for k in ["memtest", "kiểm tra ram", "smart", "cáp", "tháo", "ổ cứng", "ssd", "nvme"]):
            return "background-color: #7c2d12; color: #fed7aa; font-size: 10px; font-weight: bold; padding: 2px 6px; border-radius: 4px;", "TẦNG 3: NÂNG CAO"
        elif any(k in s for k in ["cập nhật bios", "bios", "nguồn", "psu", "thay", "bo mạch chủ", "mainboard"]):
            return "background-color: #7f1d1d; color: #fecaca; font-size: 10px; font-weight: bold; padding: 2px 6px; border-radius: 4px;", "TẦNG 4: PHỨC TẠP"
        return "background-color: #334155; color: #cbd5e1; font-size: 10px; font-weight: bold; padding: 2px 6px; border-radius: 4px;", "KHUYẾN NGHỊ"

    def _clear_layout(self, layout: QVBoxLayout) -> None:
        """Xoá toàn bộ widget con trong layout."""
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def _on_export_html_clicked(self) -> None:
        """Xử lý xuất báo cáo HTML."""
        if not self._crashes and not self._finding:
            QMessageBox.warning(self, "Chưa có dữ liệu", "Chưa có dữ liệu phân tích nào để xuất báo cáo.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Lưu báo cáo chẩn đoán HTML",
            "Bao_cao_DumpAnalyzer.html",
            "Tệp HTML (*.html);;Tất cả tệp (*.*)",
        )
        if file_path:
            try:
                export_html_report(
                    output_path=file_path,
                    crashes=self._crashes,
                    finding=self._finding,
                    machine_info=self._machine_info,
                    evidences=self._evidences,
                    suspect_ranking=self._suspect_ranking,
                )
                QMessageBox.information(self, "Xuất thành công", f"Đã xuất báo cáo HTML thành công tại:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Lỗi xuất báo cáo", f"Không thể xuất báo cáo HTML:\n{str(e)}")

    def _on_export_excel_clicked(self) -> None:
        """Xử lý xuất báo cáo Excel."""
        if not self._crashes and not self._finding:
            QMessageBox.warning(self, "Chưa có dữ liệu", "Chưa có dữ liệu phân tích nào để xuất báo cáo.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Lưu báo cáo chẩn đoán Excel",
            "Bao_cao_DumpAnalyzer.xlsx",
            "Bảng tính Excel (*.xlsx);;Tất cả tệp (*.*)",
        )
        if file_path:
            try:
                export_excel_report(
                    output_path=file_path,
                    crashes=self._crashes,
                    finding=self._finding,
                    machine_info=self._machine_info,
                    evidences=self._evidences,
                    suspect_ranking=self._suspect_ranking,
                )
                QMessageBox.information(self, "Xuất thành công", f"Đã xuất báo cáo Excel thành công tại:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Lỗi xuất báo cáo", f"Không thể xuất báo cáo Excel:\n{str(e)}")
