"""
Kiểm thử lệnh CLI scan và cơ chế cache theo SHA256 trong SQLite.
"""

from pathlib import Path
from dumpanalyzer.cli import main
from dumpanalyzer.storage.db import Database

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_cli_scan_and_caching(capsys):
    """
    Kiểm tra luồng quét dump:
    - Lần 1: Quét file mới, phân tích và lưu SQLite ([MỚI]).
    - Lần 2: Quét lại cùng thư mục, dùng cache SQLite ([CACHE]), không trùng lặp bản ghi.
    """
    db = Database()
    # Xoá các bản ghi cũ để test sạch
    with db._get_connection() as conn:
        conn.execute("DELETE FROM crash")

    # 1. Chạy scan lần 1
    ret1 = main(["scan", "--path", str(FIXTURES_DIR)])
    assert ret1 == 0

    out1 = capsys.readouterr().out
    assert "Tìm thấy" in out1
    assert "kernel_sample_124.dmp" in out1
    assert "[MỚI]" in out1

    crashes_after_run1 = db.list_crashes()
    count_run1 = len(crashes_after_run1)
    assert count_run1 >= 3  # Ít nhất 3 file dump hợp lệ

    # 2. Chạy scan lần 2 (kiểm tra cache)
    ret2 = main(["scan", "--path", str(FIXTURES_DIR)])
    assert ret2 == 0

    out2 = capsys.readouterr().out
    assert "[CACHE]" in out2

    crashes_after_run2 = db.list_crashes()
    assert len(crashes_after_run2) == count_run1, "Số bản ghi không được tăng lên khi chạy lại (cache SHA256)"

    db.close()
