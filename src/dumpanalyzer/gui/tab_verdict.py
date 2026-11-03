"""Tab 3: Kết luận chẩn đoán (Verdict Tab) trong PySide6 DumpAnalyzer.

Hiển thị xếp hạng nghi ngờ với thanh phần trăm trực quan, phân tích mức độ tin cậy,
danh sách bằng chứng có gắn nhãn phân loại (Ủng hộ / Phản bác), giải thích nguyên nhân bằng tiếng Việt,
các bước kiểm tra khuyến nghị và khung phản hồi độ chính xác (Feedback).
"""

from typing import Any, Dict, List, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
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
from dumpanalyzer.storage.db import Database


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
    open_readiness_tab_requested = Signal()  # Phát ra khi người dùng bấm xem chi tiết sẵn sàng ghi dump

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._crashes: List[Crash] = []
        self._finding: Optional[Finding] = None
        self._machine_info: Optional[MachineInfo] = None
        self._evidences: List[Evidence] = []
        self._suspect_ranking: List[Dict[str, Any]] = []
        self._db: Optional[Database] = None
        self._init_ui()

    def _get_db(self) -> Database:
        if self._db is None:
            self._db = Database()
        return self._db

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        # 0. Khung cảnh báo Sẵn sàng ghi dump (Warning Callout Box - Phần 6.3)
        self.readiness_warning_frame = QFrame()
        self.readiness_warning_frame.setStyleSheet(
            "background-color: #450a0a; border: 1px solid #ef4444; border-radius: 8px; padding: 10px 14px;"
        )
        warn_layout = QHBoxLayout(self.readiness_warning_frame)
        warn_layout.setContentsMargins(0, 0, 0, 0)
        warn_layout.setSpacing(10)

        lbl_warn_icon = QLabel("⚠️")
        lbl_warn_icon.setStyleSheet("font-size: 20px;")
        warn_layout.addWidget(lbl_warn_icon)

        self.lbl_readiness_warning = QLabel("")
        self.lbl_readiness_warning.setStyleSheet("color: #fca5a5; font-size: 13px; font-weight: 500;")
        self.lbl_readiness_warning.setWordWrap(True)
        warn_layout.addWidget(self.lbl_readiness_warning, 1)

        btn_go_readiness = QPushButton("Kiểm tra tab Sẵn sàng ghi dump ➜")
        btn_go_readiness.setStyleSheet(
            "background-color: #7f1d1d; color: #ffffff; font-weight: bold; padding: 6px 12px; border-radius: 4px; border: 1px solid #ef4444;"
        )
        btn_go_readiness.clicked.connect(self.open_readiness_tab_requested.emit)
        warn_layout.addWidget(btn_go_readiness)

        self.readiness_warning_frame.setVisible(False)
        main_layout.addWidget(self.readiness_warning_frame)

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

        # Giải thích căn cứ độ tin cậy
        self.lbl_conf_rationale = QLabel("")
        self.lbl_conf_rationale.setStyleSheet("color: #94a3b8; font-size: 12px; font-style: italic;")
        self.lbl_conf_rationale.setWordWrap(True)
        top_layout.addWidget(self.lbl_conf_rationale)

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

        lbl_rank_title = QLabel("XẾP HẠNG XÁC SUẤT NGHI VẤN")
        lbl_rank_title.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {COLOR_TEXT_PRIMARY}; border-bottom: 2px solid {COLOR_BORDER}; padding-bottom: 6px;")
        ranking_layout.addWidget(lbl_rank_title)

        self.ranking_container = QVBoxLayout()
        self.ranking_container.setSpacing(8)
        ranking_layout.addLayout(self.ranking_container)

        left_layout.addWidget(ranking_card)

        # 3. Thẻ Bằng chứng thu thập (Ủng hộ & Phản bác)
        evidence_card = QFrame()
        evidence_card.setObjectName("CardFrame")
        ev_layout = QVBoxLayout(evidence_card)
        ev_layout.setContentsMargins(14, 14, 14, 14)
        ev_layout.setSpacing(8)

        lbl_ev_title = QLabel("BẰNG CHỨNG THU THẬP ĐƯỢC (ỦNG HỘ & PHẢN BÁC)")
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

        # ==================== CỘT PHẢI: RATIONALE, KHUYẾN NGHỊ & FEEDBACK ====================
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

        # 3. Thẻ Phản hồi của Kỹ thuật viên IT (Feedback - Phần 2.1)
        feedback_card = QFrame()
        feedback_card.setObjectName("CardFrame")
        feedback_card.setStyleSheet("background-color: #0b1120; border: 1px solid #1e293b; border-radius: 8px; padding: 12px;")
        fb_layout = QVBoxLayout(feedback_card)
        fb_layout.setSpacing(8)

        lbl_fb_title = QLabel("ĐÁNH GIÁ ĐỘ CHÍNH XÁC KẾT LUẬN (FEEDBACK)")
        lbl_fb_title.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {COLOR_TEXT_PRIMARY}; border-bottom: 2px solid {COLOR_BORDER}; padding-bottom: 4px;")
        fb_layout.addWidget(lbl_fb_title)

        fb_btn_row = QHBoxLayout()
        fb_btn_row.setSpacing(8)

        self.btn_group_verdict = QButtonGroup(self)
        self.btn_fb_dung = QPushButton("✓ Đúng")
        self.btn_fb_dung.setStyleSheet("background-color: #1e293b; color: #4ade80; font-weight: bold; padding: 5px 12px; border: 1px solid #4ade80; border-radius: 4px;")
        self.btn_fb_dung.setCheckable(True)

        self.btn_fb_sai = QPushButton("✗ Sai")
        self.btn_fb_sai.setStyleSheet("background-color: #1e293b; color: #f87171; font-weight: bold; padding: 5px 12px; border: 1px solid #f87171; border-radius: 4px;")
        self.btn_fb_sai.setCheckable(True)

        self.btn_fb_chua_ro = QPushButton("? Chưa rõ")
        self.btn_fb_chua_ro.setStyleSheet("background-color: #1e293b; color: #facc15; font-weight: bold; padding: 5px 12px; border: 1px solid #facc15; border-radius: 4px;")
        self.btn_fb_chua_ro.setCheckable(True)
        self.btn_fb_chua_ro.setChecked(True)

        self.btn_group_verdict.addButton(self.btn_fb_dung)
        self.btn_group_verdict.addButton(self.btn_fb_sai)
        self.btn_group_verdict.addButton(self.btn_fb_chua_ro)

        fb_btn_row.addWidget(self.btn_fb_dung)
        fb_btn_row.addWidget(self.btn_fb_sai)
        fb_btn_row.addWidget(self.btn_fb_chua_ro)
        fb_btn_row.addStretch()
        fb_layout.addLayout(fb_btn_row)

        fb_form_row = QHBoxLayout()
        lbl_cause = QLabel("Nguyên nhân thực tế:")
        lbl_cause.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px;")
        fb_form_row.addWidget(lbl_cause)

        self.combo_actual_cause = QComboBox()
        self.combo_actual_cause.addItems(["ram", "storage", "driver", "gpu", "psu", "cpu", "thermal", "software", "Khác"])
        fb_form_row.addWidget(self.combo_actual_cause)

        lbl_fb_note = QLabel("Ghi chú:")
        lbl_fb_note.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px;")
        fb_form_row.addWidget(lbl_fb_note)

        self.txt_feedback_note = QLineEdit()
        self.txt_feedback_note.setPlaceholderText("Ghi chú kinh nghiệm xử lý thực tế...")
        fb_form_row.addWidget(self.txt_feedback_note, 1)

        self.btn_save_feedback = QPushButton("Lưu phản hồi")
        self.btn_save_feedback.setStyleSheet("background-color: #0284c7; color: #ffffff; font-weight: bold; padding: 5px 14px; border-radius: 4px;")
        self.btn_save_feedback.clicked.connect(self._on_save_feedback)
        fb_form_row.addWidget(self.btn_save_feedback)

        fb_layout.addLayout(fb_form_row)

        self.lbl_feedback_msg = QLabel("")
        self.lbl_feedback_msg.setStyleSheet("color: #4ade80; font-size: 11px;")
        fb_layout.addWidget(self.lbl_feedback_msg)

        right_layout.addWidget(feedback_card)

        # 4. Hàng nút xuất báo cáo & Lưu ý kỹ thuật
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
        dump_readiness: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Cập nhật dữ liệu chẩn đoán và khuyến nghị lên giao diện."""
        self._crashes = list(crashes)
        self._finding = finding
        self._machine_info = machine_info
        self._evidences = list(evidences or [])
        self._suspect_ranking = list(suspect_ranking or [])

        # Kiểm tra và hiển thị Cảnh báo Sẵn sàng ghi dump (Phần 6.3)
        readiness_report = dump_readiness
        if readiness_report is None:
            try:
                db = self._get_db()
                row = db.get_latest_dump_readiness()
                if row:
                    import json
                    readiness_report = json.loads(row["report_json"])
            except Exception:
                pass

        if readiness_report:
            st = readiness_report.get("result", {}).get("status", "UNKNOWN")
            if st != "READY":
                summary_txt = readiness_report.get("result", {}).get("summary", "")
                gap_info = readiness_report.get("dump_gap") or {}
                missing_cnt = gap_info.get("missing", 0)
                gap_str = f" (Dump Gap = {missing_cnt} dump bị thiếu)" if missing_cnt > 0 else ""
                self.lbl_readiness_warning.setText(
                    f"CẢNH BÁO KHẢ NĂNG GHI DUMP: Máy tính này hiện có trạng thái [{st}] ({summary_txt})."
                    f"{gap_str}\nCác lần sập gần đây có thể không ghi được dump đầy đủ. "
                    f"Vui lòng mở tab 'Sẵn sàng ghi dump' để kiểm tra và khắc phục."
                )
                self.readiness_warning_frame.setVisible(True)
            else:
                self.readiness_warning_frame.setVisible(False)
        else:
            self.readiness_warning_frame.setVisible(False)

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

            conf_rat = getattr(finding, "confidence_rationale", "")
            if conf_rat:
                self.lbl_conf_rationale.setText(f"Căn cứ độ tin cậy: {conf_rat}")
                self.lbl_conf_rationale.setVisible(True)
            else:
                self.lbl_conf_rationale.setVisible(False)

            self.lbl_rationale.setText(finding.rationale or "Không có diễn giải bổ sung.")
        else:
            self.lbl_confidence_badge.setText("ĐỘ TIN CẬY: CHƯA RÕ")
            self.lbl_confidence_badge.setStyleSheet(get_confidence_badge_style("none"))
            self.lbl_top_suspect.setText("Chưa có kết luận chẩn đoán")
            self.lbl_conf_rationale.setVisible(False)
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

        # 3. Xây dựng danh sách bằng chứng (Ủng hộ vs Phản bác)
        self._clear_layout(self.ev_container)
        if self._evidences:
            support_ev = [e for e in self._evidences if getattr(e, "polarity", "support") != "refute"]
            refute_ev = [e for e in self._evidences if getattr(e, "polarity", "support") == "refute"]

            if support_ev:
                lbl_sup = QLabel(f"BẰNG CHỨNG ỦNG HỘ ({len(support_ev)}):")
                lbl_sup.setStyleSheet("color: #4ade80; font-weight: bold; font-size: 11px; margin-top: 4px;")
                self.ev_container.addWidget(lbl_sup)
                for ev in support_ev[:15]:
                    self.ev_container.addWidget(self._create_evidence_card(ev, is_refute=False))

            if refute_ev:
                lbl_ref = QLabel(f"BẰNG CHỨNG PHẢN BÁC / HẠ ĐIỂM ({len(refute_ev)}):")
                lbl_ref.setStyleSheet("color: #f87171; font-weight: bold; font-size: 11px; margin-top: 8px;")
                self.ev_container.addWidget(lbl_ref)
                for ev in refute_ev[:10]:
                    self.ev_container.addWidget(self._create_evidence_card(ev, is_refute=True))
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

    def _create_evidence_card(self, ev: Evidence, is_refute: bool = False) -> QWidget:
        """Tạo thẻ hiển thị bằng chứng kèm độ mạnh (strength) và chiều hướng (polarity)."""
        ev_card = QFrame()
        bg_col = "#1c1917" if is_refute else "#0b1120"
        border_col = "#78350f" if is_refute else "#1e293b"
        ev_card.setStyleSheet(f"background-color: {bg_col}; border: 1px solid {border_col}; border-radius: 6px; padding: 6px;")
        card_l = QVBoxLayout(ev_card)
        card_l.setContentsMargins(6, 4, 6, 4)
        card_l.setSpacing(2)

        top_l = QHBoxLayout()
        ev_type = getattr(ev, "kind", getattr(ev, "evidence_type", "eventlog"))
        source = getattr(ev, "source", "")
        strength = getattr(ev, "strength", "weak").upper()

        if is_refute:
            badge_text = f"[PHẢN BÁC - {strength}] [{ev_type.upper()}] {source}"
            badge_color = "#f87171"
        else:
            badge_text = f"[{strength}] [{ev_type.upper()}] {source}"
            badge_color = "#38bdf8"

        lbl_badge = QLabel(badge_text)
        lbl_badge.setStyleSheet(f"color: {badge_color}; font-weight: bold; font-size: 11px;")
        top_l.addWidget(lbl_badge)

        weight = getattr(ev, "weight", 10)
        sign = "-" if is_refute else "+"
        w_color = "#fb923c" if is_refute else "#4ade80"
        lbl_w = QLabel(f"{sign}{weight}")
        lbl_w.setStyleSheet(f"color: {w_color}; font-weight: bold; font-size: 11px;")
        top_l.addWidget(lbl_w, alignment=Qt.AlignRight)
        card_l.addLayout(top_l)

        detail = getattr(ev, "detail", getattr(ev, "details", getattr(ev, "summary", "-")))
        lbl_d = QLabel(detail)
        lbl_d.setStyleSheet("color: #cbd5e1; font-size: 11px;")
        lbl_d.setWordWrap(True)
        card_l.addWidget(lbl_d)
        return ev_card

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
        lbl_tier.setFixedHeight(20)
        l.addWidget(lbl_tier)

        # Nội dung bước
        lbl_text = QLabel(f"<b>{index}.</b> {step_text}")
        lbl_text.setStyleSheet("color: #e2e8f0; font-size: 12px;")
        lbl_text.setWordWrap(True)
        l.addWidget(lbl_text, 1)

        return w

    def _get_tier_badge_info(self, step: str) -> tuple[str, str]:
        """Xác định màu và nhãn tầng độ khó dựa trên nội dung bước kiểm tra."""
        s = step.lower()
        if any(k in s for k in ["nhiệt độ", "nóng", "quạt", "driver verifier", "khởi động sạch", "cấu hình dump", "tắt verifier"]):
            return (
                "background-color: #064e3b; color: #34d399; font-weight: bold; font-size: 10px; padding: 2px 6px; border-radius: 4px;",
                "TẦNG 1: DỄ",
            )
        elif any(k in s for k in ["ddu", "cập nhật driver", "cài lại driver", "sfc", "chkdsk", "sửa lỗi tệp", "diệt virus", "antivirus"]):
            return (
                "background-color: #1e3a8a; color: #60a5fa; font-weight: bold; font-size: 10px; padding: 2px 6px; border-radius: 4px;",
                "TẦNG 2: VỪA",
            )
        elif any(k in s for k in ["memtest", "kiểm tra ram", "smart", "cáp", "tháo", "ổ cứng", "ssd", "nvme"]):
            return (
                "background-color: #78350f; color: #fbbf24; font-weight: bold; font-size: 10px; padding: 2px 6px; border-radius: 4px;",
                "TẦNG 3: NÂNG CAO",
            )
        elif any(k in s for k in ["cập nhật bios", "bios", "nguồn", "psu", "thay", "bo mạch chủ", "mainboard"]):
            return (
                "background-color: #7f1d1d; color: #f87171; font-weight: bold; font-size: 10px; padding: 2px 6px; border-radius: 4px;",
                "TẦNG 4: PHỨC TẠP",
            )
        return (
            "background-color: #1e293b; color: #94a3b8; font-weight: bold; font-size: 10px; padding: 2px 6px; border-radius: 4px;",
            "KHUYẾN NGHỊ",
        )

    def _on_save_feedback(self) -> None:
        """Lưu đánh giá độ chính xác kết luận từ KTV."""
        if self.btn_fb_dung.isChecked():
            verdict = "dung"
        elif self.btn_fb_sai.isChecked():
            verdict = "sai"
        else:
            verdict = "chua_ro"

        actual_cause = self.combo_actual_cause.currentText()
        note = self.txt_feedback_note.text().strip()

        pred_grp = "unknown"
        if self._suspect_ranking:
            pred_grp = self._suspect_ranking[0].get("suspect", "unknown")
        elif self._finding and hasattr(self._finding, "suspect"):
            pred_grp = self._finding.suspect

        pred_conf = self._finding.confidence if self._finding else "unknown"
        m_id = getattr(self._machine_info, "id", None) or 1
        an_ref = f"finding_{getattr(self._finding, 'id', 'latest')}"

        db = self._get_db()
        db.add_feedback(
            machine_id=m_id,
            analysis_ref=an_ref,
            predicted_group=pred_grp,
            predicted_confidence=pred_conf,
            verdict=verdict,
            actual_cause=actual_cause,
            note=note,
        )

        self.lbl_feedback_msg.setText("✓ Đã ghi nhận phản hồi vào cơ sở dữ liệu thành công!")
        QMessageBox.information(
            self,
            "Ghi nhận phản hồi",
            f"Đã lưu đánh giá của bạn ({verdict.upper()}) cho máy này.\n"
            f"Nguyên nhân thực tế: {actual_cause}\n"
            f"Dữ liệu này sẽ được dùng để thống kê độ chính xác của hệ thống.",
        )

    def _on_export_html_clicked(self) -> None:
        """Xử lý sự kiện nhấn nút Xuất báo cáo HTML."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Lưu báo cáo chẩn đoán HTML",
            "BaoCao_ChanDoan_DumpAnalyzer.html",
            "HTML Files (*.html)",
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
                QMessageBox.information(
                    self,
                    "Xuất báo cáo thành công",
                    f"Báo cáo chẩn đoán dạng HTML đã được lưu thành công tại:\n{file_path}",
                )
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Lỗi xuất báo cáo",
                    f"Không thể xuất file báo cáo HTML: {e}",
                )

    def _on_export_excel_clicked(self) -> None:
        """Xử lý sự kiện nhấn nút Xuất báo cáo Excel."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Lưu báo cáo chẩn đoán Excel",
            "BaoCao_ChanDoan_DumpAnalyzer.xlsx",
            "Excel Files (*.xlsx)",
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
                QMessageBox.information(
                    self,
                    "Xuất báo cáo thành công",
                    f"Báo cáo chẩn đoán dạng Excel (.xlsx) đã được lưu thành công tại:\n{file_path}",
                )
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Lỗi xuất báo cáo",
                    f"Không thể xuất file báo cáo Excel: {e}",
                )

    def _clear_layout(self, layout: QVBoxLayout) -> None:
        """Dọn sạch các widget con trong layout."""
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
            elif item.layout() is not None:
                self._clear_layout(item.layout())
