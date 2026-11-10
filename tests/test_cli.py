"""
Kiểm thử giao diện dòng lệnh CLI của DumpAnalyzer.
"""

import pytest
from dumpanalyzer.cli import main
from dumpanalyzer import __version__


def test_cli_version(capsys):
    """Kiểm tra gọi tham số --version."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert f"DumpAnalyzer v{__version__}" in captured.out or f"DumpAnalyzer v{__version__}" in captured.err


def test_cli_check_env(capsys):
    """Kiểm tra lệnh check-env thực thi thành công trả về code 0."""
    ret = main(["check-env"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "ĐANG KIỂM TRA MÔI TRƯỜNG HỆ THỐNG" in captured.out
    assert "Cơ sở dữ liệu mã Bug Check:" in captured.out


def test_cli_batch(tmp_path, capsys):
    """Kiểm tra lệnh batch trên thư mục rỗng trả về code 0."""
    folder = tmp_path / "batch_folder"
    folder.mkdir()
    ret = main(["batch", "--dir", str(folder)])
    assert ret == 0
    captured = capsys.readouterr()
    assert "PHÂN TÍCH THEO LÔ ĐA MÁY TÍNH" in captured.out
    assert "Tổng số máy tính nhận diện: 0" in captured.out


def test_cli_clean_workspace(tmp_path, capsys):
    """Kiểm tra lệnh clean-workspace thực thi thành công trả về code 0."""
    ws = tmp_path / "test_ws"
    ws.mkdir()
    d = ws / "test.dmp"
    d.write_bytes(b"DUMP")

    ret = main(["clean-workspace", "--dir", str(ws)])
    assert ret == 0
    captured = capsys.readouterr()
    assert "DỌN DẸP AN TOÀN THƯ MỤC LÀM VIỆC" in captured.out
    assert "Đã xoá an toàn 1 file dump tạm" in captured.out
    assert not d.exists()


def test_cli_events_options(tmp_path, capsys, monkeypatch):
    """Kiểm tra lệnh events với các cờ mới: --spikes, --pre-crash, --redact, --export-excel."""
    from dumpanalyzer.analyzer.eventlog_analyzer import EventLogAnalysisResult, EventLogItem

    mock_res = EventLogAnalysisResult(
        events=[
            EventLogItem(
                event_id=41,
                provider="Microsoft-Windows-Kernel-Power",
                time_created_utc="2026-11-10T10:00:00Z",
                raw_message="Hệ thống khởi động lại cho user C:\\Users\\AdminIT\\file.",
                level=1,
                level_name="Critical",
                level_label_vi="Nghiêm trọng (Critical)",
                category="crash_reboot",
                category_name="Sập & Khởi động",
            ),
            EventLogItem(
                event_id=7,
                provider="Disk",
                time_created_utc="2026-11-10T09:50:00Z",
                raw_message="Lỗi Disk sector tại IP 192.168.1.50.",
                level=2,
                level_name="Error",
                level_label_vi="Lỗi (Error)",
                category="storage",
                category_name="Lưu trữ",
            ),
        ],
        total_events=2,
        level_counts={"Critical": 1, "Error": 1, "Warning": 0, "Information": 0},
        source_description="Test CLI Stream",
    )

    monkeypatch.setattr(
        "dumpanalyzer.analyzer.eventlog_analyzer.harvest_live_eventlog",
        lambda *args, **kwargs: mock_res,
    )

    # 1. Chạy events với cờ --redact
    ret = main(["events", "--redact"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "che thông tin nhạy cảm" in captured.out
    assert "[ANONYMIZED_USER]" in captured.out

    # 2. Chạy events với cờ --export-excel
    excel_out = tmp_path / "cli_event_report.xlsx"
    ret = main(["events", "--export-excel", str(excel_out)])
    assert ret == 0
    assert excel_out.exists()

    # 3. Chạy events với cờ --spikes
    ret = main(["events", "--spikes"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "CÁC ĐỢT BÙNG PHÁT LỖI ĐỘT BIẾN" in captured.out


