"""Luồng xử lý nền (Background Worker) cho PySide6 GUI.

Đảm bảo toàn bộ quá trình quét dump, chạy cdb, truy vấn Event Log và chấm điểm
diễn ra trong QThread riêng biệt, không bao giờ làm treo hoặc đơ giao diện người dùng.
Hỗ trợ thanh tiến trình (progress bar), cập nhật thông báo và nút Huỷ an toàn.
Sử dụng chung pipeline phân tích tập trung từ dumpanalyzer.engine.pipeline.
"""

import logging
import traceback
from typing import Any, Optional
from PySide6.QtCore import QThread, Signal

from dumpanalyzer.engine.pipeline import run_analysis

logger = logging.getLogger(__name__)


class AnalysisWorker(QThread):
    """QThread thực hiện quy trình phân tích toàn diện trong nền thông qua pipeline."""

    # Tín hiệu phát ra cho giao diện
    progress = Signal(int, str)           # (Phần trăm 0-100, Thông điệp hiển thị)
    status_message = Signal(str)          # Thông báo chi tiết
    finished = Signal(dict)               # Trả về kết quả phân tích
    error = Signal(str, str)              # (Thông báo tóm tắt có loại lỗi, Traceback chi tiết)

    def __init__(
        self,
        source_type: str = "local",       # 'local' hoặc 'folder'
        folder_path: Optional[str] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        db_path: Optional[str] = None,
        parent: Optional[Any] = None,
    ):
        super().__init__(parent)
        self.source_type = source_type
        self.folder_path = folder_path
        self.from_date = from_date
        self.to_date = to_date
        self.db_path = db_path
        self._is_cancelled = False

    def cancel(self) -> None:
        """Kích hoạt cờ huỷ để luồng dừng an toàn."""
        self._is_cancelled = True
        logger.info("Yêu cầu huỷ quá trình phân tích từ người dùng.")

    def run(self) -> None:
        """Hàm thực thi chính trong luồng riêng biệt."""
        if self._is_cancelled:
            self.progress.emit(0, "Đã huỷ phân tích.")
            return

        try:
            payload = run_analysis(
                source_type=self.source_type,
                folder_path=self.folder_path,
                from_date=self.from_date,
                to_date=self.to_date,
                db_path=self.db_path,
                progress_cb=self._on_progress,
                status_cb=self._on_status,
                is_cancelled=lambda: self._is_cancelled,
            )

            if self._is_cancelled or payload is None:
                self.progress.emit(0, "Đã huỷ phân tích.")
                return

            self.finished.emit(payload)

        except Exception as e:
            logger.exception("Lỗi trong quá trình phân tích nền:")
            err_type = type(e).__name__
            err_summary = f"Đã xảy ra lỗi khi phân tích ({err_type}): {str(e)}"
            detailed_tb = traceback.format_exc()
            self.error.emit(err_summary, detailed_tb)

    def _on_progress(self, pct: int, msg: str) -> None:
        """Chuyển tiếp tiến trình về giao diện qua Signal."""
        self.progress.emit(pct, msg)

    def _on_status(self, msg: str) -> None:
        """Chuyển tiếp trạng thái chi tiết về giao diện qua Signal."""
        self.status_message.emit(msg)
