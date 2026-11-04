"""Bộ kiểm thử cho AnalysisWorker (PySide6 GUI) của DumpAnalyzer.

Kiểm tra luồng thực thi nền AnalysisWorker.run(), phát tín hiệu tiến trình,
hoàn tất và báo lỗi có cấu trúc (loại lỗi + chi tiết kỹ thuật traceback).
"""

from pathlib import Path
from unittest.mock import patch
import pytest

from dumpanalyzer.gui.worker import AnalysisWorker


@pytest.fixture
def fixtures_dir():
    return Path(__file__).resolve().parent / "fixtures"


def test_worker_synchronous_success(qapp, tmp_path, fixtures_dir):
    """Kiểm tra AnalysisWorker.run() chạy thành công đồng bộ, phát finished với đầy đủ trường."""
    test_db = tmp_path / "worker_success.db"

    worker = AnalysisWorker(
        source_type="folder",
        folder_path=str(fixtures_dir),
        db_path=str(test_db),
    )

    received_progress = []
    received_status = []
    received_finished = []
    received_error = []

    worker.progress.connect(lambda pct, msg: received_progress.append((pct, msg)))
    worker.status_message.connect(lambda msg: received_status.append(msg))
    worker.finished.connect(lambda payload: received_finished.append(payload))
    worker.error.connect(lambda msg, details="": received_error.append((msg, details)))

    worker.run()

    # Xác nhận KHÔNG phát sinh lỗi
    assert len(received_error) == 0

    # Xác nhận nhận được payload hoàn tất với đầy đủ các khóa GUI cần
    assert len(received_finished) == 1
    payload = received_finished[0]
    required_keys = [
        "machine_info",
        "crashes",
        "finding",
        "evidences",
        "suspect_ranking",
        "conflict_detected",
        "patterns_matched",
    ]
    for k in required_keys:
        assert k in payload, f"Thiếu trường '{k}' trong payload finished"

    assert len(payload["crashes"]) >= 4
    assert len(payload["suspect_ranking"]) > 0

    # Xác nhận tiến trình được phát đều đặn
    assert len(received_progress) > 0
    assert received_progress[-1][0] == 100


def test_worker_error_emits_structured_details(qapp, tmp_path):
    """Kiểm tra khi xảy ra sự cố, AnalysisWorker phát tín hiệu error gồm tên loại lỗi và traceback."""
    test_db = tmp_path / "worker_err.db"

    worker = AnalysisWorker(
        source_type="folder",
        folder_path="/nonexistent_path_test",
        db_path=str(test_db),
    )

    received_error = []
    worker.error.connect(lambda msg, details="": received_error.append((msg, details)))

    # Giả lập lỗi PermissionError trong run_analysis
    with patch("dumpanalyzer.gui.worker.run_analysis", side_effect=PermissionError("Thư mục bị từ chối truy cập")):
        worker.run()

    assert len(received_error) == 1
    err_summary, detailed_tb = received_error[0]

    # Kiểm tra định dạng thông báo có nêu loại lỗi
    assert "PermissionError" in err_summary
    assert "Thư mục bị từ chối truy cập" in err_summary
    assert "Traceback" in detailed_tb
    assert "PermissionError" in detailed_tb


def test_worker_cancellation(qapp, tmp_path, fixtures_dir):
    """Kiểm tra cờ huỷ worker.cancel() khiến worker dừng lại mà không phát finished."""
    test_db = tmp_path / "worker_cancel.db"

    worker = AnalysisWorker(
        source_type="folder",
        folder_path=str(fixtures_dir),
        db_path=str(test_db),
    )

    received_finished = []
    received_error = []
    worker.finished.connect(lambda payload: received_finished.append(payload))
    worker.error.connect(lambda msg, details="": received_error.append((msg, details)))

    # Huỷ trước khi chạy
    worker.cancel()
    assert worker._is_cancelled is True

    worker.run()

    # Không phát finished hay error
    assert len(received_finished) == 0
    assert len(received_error) == 0
