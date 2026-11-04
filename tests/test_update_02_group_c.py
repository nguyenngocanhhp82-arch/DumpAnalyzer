"""Tests hồi quy cho Nhóm C theo ĐỢT CẬP NHẬT 02.
Kiểm tra:
1. build_eventlog_script: Cú pháp FilterHashtable, ForEach-Object, UTF8 output, không có foreach pipe.
2. Phân biệt 3 trạng thái khi gọi PowerShell:
   (a) Không có sự kiện khớp (returncode=0, stdout='[]') -> trả về [], không lỗi.
   (b) PowerShell lỗi (returncode!=0, stderr='Access denied') -> ghi log warning kèm stderr.
   (c) Timeout -> ghi log warning timeout.
3. Cờ --debug-ps trên lệnh CLI events.
"""

import shutil
import subprocess
from unittest.mock import patch, MagicMock
import pytest
from dumpanalyzer.collectors.eventlog import (
    build_eventlog_script,
    get_last_eventlog_warning,
    read_system_events,
)


def test_c1_build_eventlog_script_syntax():
    """Kiểm tra cú pháp script PowerShell do build_eventlog_script tạo ra."""
    script = build_eventlog_script(from_date="2026-10-20T00:00:00Z", to_date="2026-10-29T00:00:00Z")

    # Bắt buộc có OutputEncoding UTF8
    assert "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8" in script
    # Bắt buộc lọc bằng -FilterHashtable với ProviderName và Id
    assert "-FilterHashtable" in script
    assert "ProviderName" in script
    assert "Id" in script
    assert "StartTime" in script
    assert "EndTime" in script
    # Bắt buộc dùng ForEach-Object
    assert "ForEach-Object" in script
    assert "ConvertTo-Json -Depth 4 -Compress" in script
    # TUYỆT ĐỐI không có cú pháp lỗi 'foreach (...) { ... } |'
    import re
    assert not re.search(r"foreach\s*\([^\)]+\)\s*\{[^}]*\}\s*\|", script, re.DOTALL)


def test_c2_read_system_events_states(caplog):
    """Kiểm tra xử lý 3 trạng thái:
    (a) rỗng hợp lệ (returncode=0, stdout='[]', stderr='').
    (b1) lỗi PS returncode != 0 (stderr='Access is denied').
    (b2) lỗi PS stderr có nội dung dù returncode == 0.
    (c) timeout (subprocess.TimeoutExpired).
    Hai trạng thái lỗi (b) và (c) phải ghi log WARNING kèm stderr và trả cảnh báo cho GUI/CLI, không được im lặng.
    """
    import logging

    # Trạng thái (a): Thành công nhưng không có sự kiện (returncode=0, stdout='[]')
    mock_res_a = MagicMock(returncode=0, stdout="[]", stderr="")
    with patch("sys.platform", "win32"), patch("subprocess.run", return_value=mock_res_a):
        with caplog.at_level(logging.WARNING):
            warn_list_a = []
            events = read_system_events(warnings=warn_list_a)
            assert events == []
            assert not any("Lỗi khi thực thi PowerShell" in r.message for r in caplog.records)
            assert get_last_eventlog_warning() is None
            assert len(warn_list_a) == 0

    caplog.clear()

    # Trạng thái (b1): Lỗi thực thi PowerShell (returncode=1, stderr='Access is denied')
    mock_res_b1 = MagicMock(returncode=1, stdout="", stderr="Access is denied")
    with patch("sys.platform", "win32"), patch("subprocess.run", return_value=mock_res_b1):
        with caplog.at_level(logging.WARNING):
            warn_list_b1 = []
            events = read_system_events(warnings=warn_list_b1)
            assert events == []
            assert any("Access is denied" in r.message for r in caplog.records)
            last_warn = get_last_eventlog_warning()
            assert last_warn is not None
            assert "Access is denied" in last_warn
            assert len(warn_list_b1) == 1
            assert "Access is denied" in warn_list_b1[0]

    caplog.clear()

    # Trạng thái (b2): returncode=0 nhưng stderr có nội dung (ví dụ ParserError)
    mock_res_b2 = MagicMock(returncode=0, stdout="[]", stderr="ParserError: An empty pipe element is not allowed")
    with patch("sys.platform", "win32"), patch("subprocess.run", return_value=mock_res_b2):
        with caplog.at_level(logging.WARNING):
            warn_list_b2 = []
            events = read_system_events(warnings=warn_list_b2)
            assert events == []
            assert any("ParserError" in r.message for r in caplog.records)
            last_warn = get_last_eventlog_warning()
            assert last_warn is not None
            assert "ParserError" in last_warn
            assert len(warn_list_b2) == 1
            assert "ParserError" in warn_list_b2[0]

    caplog.clear()

    # Trạng thái (c): Timeout
    with patch("sys.platform", "win32"), patch("subprocess.run", side_effect=subprocess.TimeoutExpired("powershell.exe", 120)):
        with caplog.at_level(logging.WARNING):
            warn_list_c = []
            events = read_system_events(warnings=warn_list_c)
            assert events == []
            assert any("quá thời gian" in r.message for r in caplog.records)
            last_warn = get_last_eventlog_warning()
            assert last_warn is not None
            assert "quá thời gian" in last_warn.lower()
            assert len(warn_list_c) == 1
            assert "quá thời gian" in warn_list_c[0].lower()


def test_c3_debug_ps_output(capsys):
    """Kiểm tra cờ debug_ps in thông tin debug script và output."""
    mock_res = MagicMock(returncode=0, stdout="[]", stderr="")
    with patch("sys.platform", "win32"), patch("subprocess.run", return_value=mock_res):
        read_system_events(debug_ps=True)
        captured = capsys.readouterr().out
        assert "DEBUG POWERSHELL" in captured
        assert "Get-WinEvent" in captured


def test_c4_pwsh_parser_syntax_validation():
    """Kiểm tra cú pháp PowerShell của script sinh ra bằng pwsh AST parser (nếu môi trường có pwsh)."""
    pwsh_bin = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh_bin:
        pytest.skip("Không tìm thấy pwsh/powershell trên môi trường hiện tại")

    script = build_eventlog_script(from_date="2026-10-20T00:00:00Z", to_date="2026-10-29T00:00:00Z")

    # Sử dụng bộ phân tích cú pháp tĩnh AST của PowerShell
    ps_parse_cmd = """
    $script = [Console]::In.ReadToEnd()
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($script, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        $errMsgs = ($errors | ForEach-Object { $_.Message }) -join "; "
        [Console]::Error.WriteLine("ParserError: $errMsgs")
        exit 1
    }
    exit 0
    """
    proc = subprocess.run(
        [pwsh_bin, "-NoProfile", "-Command", ps_parse_cmd],
        input=script,
        text=True,
        capture_output=True,
    )
    assert proc.returncode == 0, f"Script có lỗi cú pháp PowerShell: {proc.stderr}"


def test_c5_pwsh_parser_catches_empty_pipe_element_syntax_error():
    """Xác nhận lỗi ParserError 'An empty pipe element is not allowed' trên cú pháp cũ foreach (...) {} |."""
    pwsh_bin = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh_bin:
        pytest.skip("Không tìm thấy pwsh/powershell trên môi trường hiện tại")

    broken_script = """
    $events = Get-WinEvent -FilterHashtable @{LogName='System'}
    foreach ($e in $events) {
        [PSCustomObject]@{ Xml = $e.ToXml(); Message = $e.Message }
    } | ConvertTo-Json -Depth 4
    """
    ps_parse_cmd = """
    $script = [Console]::In.ReadToEnd()
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($script, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        $errMsgs = ($errors | ForEach-Object { $_.Message }) -join "; "
        [Console]::Error.WriteLine("ParserError: $errMsgs")
        exit 1
    }
    exit 0
    """
    proc = subprocess.run(
        [pwsh_bin, "-NoProfile", "-Command", ps_parse_cmd],
        input=broken_script,
        text=True,
        capture_output=True,
    )
    assert proc.returncode != 0
    assert "An empty pipe element is not allowed" in proc.stderr
