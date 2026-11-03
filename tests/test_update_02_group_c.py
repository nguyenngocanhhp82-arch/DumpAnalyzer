"""Tests hồi quy cho Nhóm C theo ĐỢT CẬP NHẬT 02.
Kiểm tra:
1. build_eventlog_script: Cú pháp FilterHashtable, ForEach-Object, UTF8 output, không có foreach pipe.
2. Phân biệt 3 trạng thái khi gọi PowerShell:
   (a) Không có sự kiện khớp (returncode=0, stdout='[]') -> trả về [], không lỗi.
   (b) PowerShell lỗi (returncode!=0, stderr='Access denied') -> ghi log warning kèm stderr.
   (c) Timeout -> ghi log warning timeout.
3. Cờ --debug-ps trên lệnh CLI events.
"""

import subprocess
from unittest.mock import patch, MagicMock
import pytest
from dumpanalyzer.collectors.eventlog import build_eventlog_script, read_system_events


def test_c1_build_eventlog_script_syntax():
    """Kiểm tra cú pháp script PowerShell do build_eventlog_script tạo ra."""
    script = build_eventlog_script(from_date="2026-10-20T00:00:00Z", to_date="2026-10-29T00:00:00Z")

    # Bắt buộc có OutputEncoding UTF8
    assert "OutputEncoding" in script and "UTF8" in script
    # Bắt buộc lọc bằng -FilterHashtable
    assert "-FilterHashtable" in script
    assert "StartTime" in script
    assert "EndTime" in script
    # Bắt buộc dùng ForEach-Object
    assert "ForEach-Object" in script
    # TUYỆT ĐỐI không có cú pháp lỗi 'foreach (...) { ... } |'
    import re
    assert not re.search(r"foreach\s*\([^\)]+\)\s*\{[^}]*\}\s*\|", script, re.DOTALL)


def test_c2_read_system_events_states(caplog):
    """Kiểm tra xử lý 3 trạng thái: (a) rỗng hợp lệ, (b) lỗi PS, (c) timeout."""
    import logging

    # Trạng thái (a): Thành công nhưng không có sự kiện (returncode=0, stdout='[]')
    mock_res_a = MagicMock(returncode=0, stdout="[]", stderr="")
    with patch("sys.platform", "win32"), patch("subprocess.run", return_value=mock_res_a):
        with caplog.at_level(logging.WARNING):
            events = read_system_events()
            assert events == []
            assert not any("Lỗi khi thực thi PowerShell" in r.message for r in caplog.records)

    caplog.clear()

    # Trạng thái (b): Lỗi thực thi PowerShell (returncode=1, stderr='Access is denied')
    mock_res_b = MagicMock(returncode=1, stdout="", stderr="Access is denied")
    with patch("sys.platform", "win32"), patch("subprocess.run", return_value=mock_res_b):
        with caplog.at_level(logging.WARNING):
            events = read_system_events()
            assert events == []
            assert any("Access is denied" in r.message for r in caplog.records)

    caplog.clear()

    # Trạng thái (c): Timeout
    with patch("sys.platform", "win32"), patch("subprocess.run", side_effect=subprocess.TimeoutExpired("powershell.exe", 120)):
        with caplog.at_level(logging.WARNING):
            events = read_system_events()
            assert events == []
            assert any("quá thời gian" in r.message for r in caplog.records)


def test_c3_debug_ps_output(capsys):
    """Kiểm tra cờ debug_ps in thông tin debug script và output."""
    mock_res = MagicMock(returncode=0, stdout="[]", stderr="")
    with patch("sys.platform", "win32"), patch("subprocess.run", return_value=mock_res):
        read_system_events(debug_ps=True)
        captured = capsys.readouterr().out
        assert "DEBUG POWERSHELL" in captured
        assert "Get-WinEvent" in captured
