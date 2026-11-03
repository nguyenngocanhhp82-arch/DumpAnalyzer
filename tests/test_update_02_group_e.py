"""Tests hồi quy cho Nhóm E theo ĐỢT CẬP NHẬT 02.
Kiểm tra:
1. Đọc Event 1001 từ EventData (param1, param2) không phụ thuộc ngôn ngữ Windows.
2. Fallback sang regex message khi EventData rỗng.
3. Lọc Provider cho Event 1001 (chỉ nhận WER-SystemErrorReporting hoặc BugCheck).
"""

import pytest
from dumpanalyzer.collectors.eventlog import parse_bugcheck_1001_message


def test_e1_event_1001_from_event_data_language_independent():
    """Event có raw_message rỗng và đọc từ event_data param1/param2."""
    raw_message = ""
    event_data = {
        "param1": "0x0000009f (0x3, 0xffffe0, 0xffffd0, 0xffffc0)",
        "param2": "C:\\Windows\\MEMORY.DMP",
    }

    res = parse_bugcheck_1001_message(message=raw_message, event_data=event_data)
    assert res["bugcheck_code"] == "0x9F"
    assert res["p1"] == "0x3"
    assert res["p2"] == "0xffffe0"
    assert res["p3"] == "0xffffd0"
    assert res["p4"] == "0xffffc0"
    assert res["dump_file"] == "C:\\Windows\\MEMORY.DMP"


def test_e2_event_1001_fallback_to_english_message():
    """Event không có param trong event_data thì fallback sang message tiếng Anh."""
    msg = (
        "The computer has rebooted from a bugcheck. "
        "The bugcheck was: 0x0000001a (0x1, 0x2, 0x3, 0x4). "
        "A dump was saved in: C:\\Windows\\MEMORY.DMP."
    )
    res = parse_bugcheck_1001_message(message=msg, event_data={})
    assert res["bugcheck_code"] == "0x1A"
    assert res["p1"] == "0x1"
    assert res["p2"] == "0x2"
    assert res["p3"] == "0x3"
    assert res["p4"] == "0x4"
    assert res["dump_file"] == "C:\\Windows\\MEMORY.DMP"


def test_e3_filter_event_1001_by_provider():
    """Chỉ bóc tách wer1001_info khi provider là WER-SystemErrorReporting hoặc BugCheck."""
    from dumpanalyzer.collectors.eventlog import is_kernel_bugcheck_1001_provider

    assert is_kernel_bugcheck_1001_provider("Microsoft-Windows-WER-SystemErrorReporting") is True
    assert is_kernel_bugcheck_1001_provider("BugCheck") is True
    assert is_kernel_bugcheck_1001_provider("WER-SystemErrorReporting") is True
    assert is_kernel_bugcheck_1001_provider("Windows Error Reporting") is False
    assert is_kernel_bugcheck_1001_provider("Application Error") is False

