"""Cửa sổ chính (Main Window) của DumpAnalyzer PySide6.

Tích hợp thanh công cụ điều khiển (Nguồn dữ liệu, Khoảng thời gian, Nút Phân tích, Nút Huỷ, Nút Xuất báo cáo),
thanh tiến trình động, và 4 Tab chức năng: Tổng quan | Chi tiết crash | Kết luận | Cài đặt.
"""

from typing import Any, Dict, List, Optional
from PySide6.QtCore import QDate
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDateEdit,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from dumpanalyzer.core.config import get_project_root
from dumpanalyzer.core.models import Crash, Evidence, Finding, MachineInfo
from dumpanalyzer.gui.tab_detail import DetailTab
from dumpanalyzer.gui.tab_dump_readiness import DumpReadinessTab
from dumpanalyzer.gui.tab_hwtests import HardwareTestsTab
from dumpanalyzer.gui.tab_overview import OverviewTab
from dumpanalyzer.gui.tab_settings import SettingsTab
from dumpanalyzer.gui.tab_verdict import VerdictTab
from dumpanalyzer.gui.theme import (
    COLOR_BG_SURFACE,
    COLOR_BORDER,
    COLOR_TEXT_MUTED,
    MAIN_STYLESHEET,
)
from dumpanalyzer.gui.worker import AnalysisWorker


class MainWindow(QMainWindow):
    """Cửa sổ ứng dụng chính DumpAnalyzer."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("DumpAnalyzer – Phân tích màn hình xanh & khởi động lại")
        self.resize(1200, 800)
        self.setMinimumSize(960, 640)
        self.setStyleSheet(MAIN_STYLESHEET)

        self._worker: Optional[AnalysisWorker] = None
        self._crashes: List[Crash] = []
        self._finding: Optional[Finding] = None
        self._machine_info: Optional[MachineInfo] = None
        self._evidences: List[Evidence] = []
        self._suspect_ranking: List[Dict[str, Any]] = []

        self._init_ui()

    def _init_ui(self) -> None:
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 1. Header Bar trên cùng
        header_frame = QFrame()
        header_frame.setObjectName("HeaderBar")
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(20, 12, 20, 12)

        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)
        lbl_title = QLabel("DumpAnalyzer – Phân tích màn hình xanh & khởi động lại")
        lbl_title.setObjectName("HeaderTitle")
        title_layout.addWidget(lbl_title)

        lbl_subtitle = QLabel("Chẩn đoán nguyên nhân sự cố BSOD & Windows Event Log dành cho Kỹ thuật viên IT • Tác giả phát triển: Lilbow")
        lbl_subtitle.setObjectName("HeaderSubtitle")
        title_layout.addWidget(lbl_subtitle)
        header_layout.addLayout(title_layout, 1)

        main_layout.addWidget(header_frame)

        # 2. Hàng công cụ điều khiển (Toolbar)
        toolbar_frame = QFrame()
        toolbar_frame.setStyleSheet(
            f"background-color: {COLOR_BG_SURFACE}; border-bottom: 1px solid {COLOR_BORDER}; padding: 10px 20px;"
        )
        toolbar_layout = QHBoxLayout(toolbar_frame)
        toolbar_layout.setContentsMargins(0, 0, 0, 0)
        toolbar_layout.setSpacing(12)

        # Nguồn dữ liệu
        lbl_src = QLabel("Nguồn dữ liệu:")
        lbl_src.setStyleSheet(f"font-weight: 600; color: {COLOR_TEXT_MUTED};")
        toolbar_layout.addWidget(lbl_src)

        self.combo_source = QComboBox()
        self.combo_source.addItem("Máy cục bộ này (Quét tự động)", userData="local")
        self.combo_source.addItem("Thư mục dump đã thu về", userData="folder")
        self.combo_source.currentIndexChanged.connect(self._on_source_changed)
        toolbar_layout.addWidget(self.combo_source)

        # Container chọn thư mục (chỉ hiện khi chọn 'folder')
        self.folder_container = QWidget()
        folder_layout = QHBoxLayout(self.folder_container)
        folder_layout.setContentsMargins(0, 0, 0, 0)
        folder_layout.setSpacing(8)

        lbl_folder = QLabel("Thư mục:")
        lbl_folder.setStyleSheet(f"font-weight: 600; color: {COLOR_TEXT_MUTED};")
        folder_layout.addWidget(lbl_folder)

        self.txt_folder = QLineEdit()
        self.txt_folder.setPlaceholderText("Đường dẫn thư mục chứa file dump...")
        self.txt_folder.setEnabled(False)
        folder_layout.addWidget(self.txt_folder, 1)

        self.btn_browse_folder = QPushButton("📁 Duyệt thư mục...")
        self.btn_browse_folder.setEnabled(False)
        self.btn_browse_folder.clicked.connect(self._on_browse_folder)
        folder_layout.addWidget(self.btn_browse_folder)

        toolbar_layout.addWidget(self.folder_container, 1)

        # Nhãn thông báo khi chọn quét máy cục bộ
        self.lbl_local_info = QLabel("⚡ Tự động quét các vị trí mặc định của Windows (%SystemRoot%\\Minidump và MEMORY.DMP)")
        self.lbl_local_info.setStyleSheet("color: #38bdf8; font-size: 12px; font-weight: 500;")
        toolbar_layout.addWidget(self.lbl_local_info, 1)

        # Mặc định ban đầu: ẩn folder_container, hiện thông báo quét cục bộ
        self.folder_container.setVisible(False)
        self.lbl_local_info.setVisible(True)

        # Khoảng ngày (Từ - Đến)
        lbl_from = QLabel("Từ:")
        lbl_from.setStyleSheet(f"font-weight: 600; color: {COLOR_TEXT_MUTED};")
        toolbar_layout.addWidget(lbl_from)

        self.date_from = QDateEdit()
        self.date_from.setCalendarPopup(True)
        self.date_from.setDate(QDate.currentDate().addDays(-30))
        toolbar_layout.addWidget(self.date_from)

        lbl_to = QLabel("Đến:")
        lbl_to.setStyleSheet(f"font-weight: 600; color: {COLOR_TEXT_MUTED};")
        toolbar_layout.addWidget(lbl_to)

        self.date_to = QDateEdit()
        self.date_to.setCalendarPopup(True)
        self.date_to.setDate(QDate.currentDate())
        toolbar_layout.addWidget(self.date_to)

        # Nút Phân tích (Primary)
        self.btn_analyze = QPushButton("Phân tích")
        self.btn_analyze.setObjectName("PrimaryButton")
        self.btn_analyze.clicked.connect(self._on_start_analysis)
        toolbar_layout.addWidget(self.btn_analyze)

        # Nút Huỷ (ẩn khi không chạy)
        self.btn_cancel = QPushButton("Huỷ")
        self.btn_cancel.setObjectName("DangerButton")
        self.btn_cancel.setVisible(False)
        self.btn_cancel.clicked.connect(self._on_cancel_analysis)
        toolbar_layout.addWidget(self.btn_cancel)

        # Nút Xuất báo cáo
        self.btn_export = QPushButton("Xuất báo cáo ▾")
        self.btn_export.setStyleSheet("font-weight: bold; padding: 8px 14px;")
        self.btn_export.clicked.connect(self._on_export_menu_clicked)
        toolbar_layout.addWidget(self.btn_export)

        main_layout.addWidget(toolbar_frame)

        # 3. Thanh tiến trình phân tích (Ẩn khi nhàn rỗi)
        self.progress_frame = QFrame()
        self.progress_frame.setStyleSheet(
            f"background-color: #0b1120; border-bottom: 1px solid {COLOR_BORDER}; padding: 8px 20px;"
        )
        self.progress_frame.setVisible(False)
        prog_layout = QHBoxLayout(self.progress_frame)
        prog_layout.setContentsMargins(0, 0, 0, 0)
        prog_layout.setSpacing(12)

        self.lbl_progress_status = QLabel("Đang chuẩn bị...")
        self.lbl_progress_status.setStyleSheet("color: #38bdf8; font-weight: 600; font-size: 12px;")
        prog_layout.addWidget(self.lbl_progress_status, 1)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedWidth(260)
        prog_layout.addWidget(self.progress_bar)

        main_layout.addWidget(self.progress_frame)

        # 4. QTabWidget trung tâm
        self.tabs = QTabWidget()
        self.tab_overview = OverviewTab()
        self.tab_detail = DetailTab()
        self.tab_verdict = VerdictTab()
        self.tab_hwtests = HardwareTestsTab()
        self.tab_readiness = DumpReadinessTab()
        self.tab_settings = SettingsTab()

        self.tabs.addTab(self.tab_overview, "Tổng quan")
        self.tabs.addTab(self.tab_detail, "Chi tiết crash")
        self.tabs.addTab(self.tab_verdict, "Kết luận")
        self.tabs.addTab(self.tab_readiness, "Sẵn sàng ghi dump")
        self.tabs.addTab(self.tab_hwtests, "Kiểm tra phần cứng")
        self.tabs.addTab(self.tab_settings, "Cài đặt")

        # Kết nối tín hiệu chuyển tab khi double click dòng ở Tab Tổng quan
        self.tab_overview.crash_selected.connect(self._on_crash_selected_from_overview)

        # Kết nối tín hiệu chuyển sang tab Sẵn sàng ghi dump từ cảnh báo ở tab Kết luận
        self.tab_verdict.open_readiness_tab_requested.connect(
            lambda: self.tabs.setCurrentWidget(self.tab_readiness)
        )

        main_layout.addWidget(self.tabs, 1)

    def _on_source_changed(self, index: int) -> None:
        """Kích hoạt hoặc ẩn hiện chọn thư mục tuỳ theo nguồn dữ liệu."""
        is_folder = self.combo_source.currentData() == "folder"
        self.folder_container.setVisible(is_folder)
        self.lbl_local_info.setVisible(not is_folder)
        self.txt_folder.setEnabled(is_folder)
        self.btn_browse_folder.setEnabled(is_folder)

    def _on_browse_folder(self) -> None:
        """Duyệt chọn thư mục chứa file dump."""
        dir_path = QFileDialog.getExistingDirectory(self, "Chọn thư mục chứa các file dump (.dmp)")
        if dir_path:
            self.txt_folder.setText(dir_path)

    def _on_start_analysis(self) -> None:
        """Khởi động luồng phân tích ngầm trong QThread."""
        source_type = self.combo_source.currentData()
        folder_path = self.txt_folder.text().strip() if source_type == "folder" else None

        if source_type == "folder" and not folder_path:
            QMessageBox.warning(self, "Chưa chọn thư mục", "Vui lòng chọn thư mục chứa file dump trước khi phân tích.")
            return

        from_str = self.date_from.date().toString("yyyy-MM-dd")
        to_str = self.date_to.date().toString("yyyy-MM-dd")

        # Cập nhật trạng thái giao diện khi chạy
        self.btn_analyze.setEnabled(False)
        self.btn_cancel.setVisible(True)
        self.progress_frame.setVisible(True)
        self.progress_bar.setValue(0)
        self.lbl_progress_status.setText("Bắt đầu khởi tạo luồng phân tích...")

        # Khởi tạo và kết nối Worker QThread
        self._worker = AnalysisWorker(
            source_type=source_type,
            folder_path=folder_path,
            from_date=from_str,
            to_date=to_str,
        )
        self._worker.progress.connect(self._on_worker_progress)
        self._worker.status_message.connect(self._on_worker_status)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.error.connect(self._on_worker_error)
        self._worker.start()

    def _on_cancel_analysis(self) -> None:
        """Người dùng bấm nút Huỷ phân tích."""
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self.lbl_progress_status.setText("Đang huỷ phân tích theo yêu cầu...")
            self.btn_cancel.setEnabled(False)

    def _on_worker_progress(self, pct: int, msg: str) -> None:
        """Cập nhật thanh tiến trình."""
        self.progress_bar.setValue(pct)
        self.lbl_progress_status.setText(msg)

    def _on_worker_status(self, msg: str) -> None:
        """Cập nhật thông báo trạng thái phụ."""
        self.lbl_progress_status.setText(msg)

    def _on_worker_finished(self, data: dict) -> None:
        """Xử lý khi luồng phân tích hoàn tất thành công."""
        self.btn_analyze.setEnabled(True)
        self.btn_cancel.setVisible(False)
        self.btn_cancel.setEnabled(True)
        self.progress_frame.setVisible(False)

        self._crashes = data.get("crashes", [])
        self._finding = data.get("finding")
        self._machine_info = data.get("machine_info")
        self._evidences = data.get("evidences", [])
        self._suspect_ranking = data.get("suspect_ranking", [])
        conflict_detected = data.get("conflict_detected", False)

        # Cập nhật dữ liệu cho các Tab
        self.tab_overview.set_data(self._crashes, self._finding, self._suspect_ranking)
        self.tab_detail.set_data(self._crashes, self._evidences)
        self.tab_verdict.set_data(
            crashes=self._crashes,
            finding=self._finding,
            machine_info=self._machine_info,
            evidences=self._evidences,
            suspect_ranking=self._suspect_ranking,
            conflict_detected=conflict_detected,
        )
        self.tab_hwtests.set_machine_info(self._machine_info)

        # Tự động chuyển người dùng sang tab Kết luận nếu có sập máy
        if self._crashes:
            self.tabs.setCurrentIndex(2)  # Tab Kết luận
            QMessageBox.information(
                self,
                "Hoàn tất phân tích",
                f"Đã phân tích thành công {len(self._crashes)} sự cố hệ thống!\n"
                f"Kết luận đã được tính toán tại tab 'Kết luận'.",
            )
        else:
            QMessageBox.information(
                self,
                "Không tìm thấy sự cố",
                "Không phát hiện file dump hoặc sự cố nào trong khoảng thời gian đã chọn.",
            )

    def _on_worker_error(self, err_msg: str, details: str = "") -> None:
        """Xử lý khi luồng phân tích gặp lỗi nghiêm trọng."""
        self.btn_analyze.setEnabled(True)
        self.btn_cancel.setVisible(False)
        self.progress_frame.setVisible(False)

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Critical)
        box.setWindowTitle("Lỗi phân tích")
        box.setText(err_msg)

        log_path = get_project_root() / "logs" / "dumpanalyzer.log"
        detailed_text = f"Tệp nhật ký log: {log_path}\n\n"
        if details:
            detailed_text += f"Chi tiết kỹ thuật (Traceback):\n{details}\n"
        box.setDetailedText(detailed_text)

        btn_copy = box.addButton("Sao chép chi tiết", QMessageBox.ActionRole)
        box.addButton(QMessageBox.Ok)

        box.exec_()
        if box.clickedButton() == btn_copy:
            clipboard = QApplication.clipboard()
            if clipboard:
                clipboard.setText(f"{err_msg}\n\n{detailed_text}")

    def _on_crash_selected_from_overview(self, crash: Crash) -> None:
        """Xử lý khi người dùng chọn/nhấp đúp một dòng ở tab Tổng quan -> chuyển sang tab Chi tiết."""
        self.tab_detail.select_crash(crash)
        self.tabs.setCurrentIndex(1)  # Tab Chi tiết crash

    def _on_export_menu_clicked(self) -> None:
        """Mở menu popup chọn định dạng xuất báo cáo (HTML hoặc Excel)."""
        if not self._crashes and not self._finding:
            QMessageBox.warning(self, "Chưa có dữ liệu", "Vui lòng chạy phân tích trước khi xuất báo cáo.")
            return

        menu = QMenu(self)
        action_html = menu.addAction("Xuất báo cáo HTML")
        action_excel = menu.addAction("Xuất báo cáo Excel (.xlsx)")

        chosen = menu.exec_(self.btn_export.mapToGlobal(self.btn_export.rect().bottomLeft()))
        if chosen == action_html:
            self.tab_verdict._on_export_html_clicked()
        elif chosen == action_excel:
            self.tab_verdict._on_export_excel_clicked()
