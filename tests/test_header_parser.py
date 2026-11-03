"""
Kiểm thử bộ phân tích header nhị phân header_parser.
"""

from pathlib import Path
from dumpanalyzer.analyzer.header_parser import (
    parse_dump_header,
    lookup_bugcheck_name,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_lookup_bugcheck_name():
    """Kiểm tra tra cứu tên chuẩn của mã Bug Check."""
    assert lookup_bugcheck_name("0x124") == "WHEA_UNCORRECTABLE_ERROR"
    assert lookup_bugcheck_name("0x1A") == "MEMORY_MANAGEMENT"
    assert lookup_bugcheck_name("0x00000133") == "DPC_WATCHDOG_VIOLATION"
    assert lookup_bugcheck_name("0x999999") == "UNKNOWN_BUGCHECK"


def test_parse_kernel_dump_124():
    """Kiểm tra đọc header dump PAGEDU64 mã 0x124."""
    dump_file = FIXTURES_DIR / "kernel_sample_124.dmp"
    info = parse_dump_header(dump_file)

    assert info.valid is True
    assert info.signature == "PAGEDU64"
    assert info.dump_type == "kernel"
    assert info.bugcheck_code == "0x124"
    assert info.bugcheck_name == "WHEA_UNCORRECTABLE_ERROR"
    assert info.p1 == "0x0"
    assert info.p2 == "0xFFFF800012345678"
    assert info.p3 == "0xB200000000000000"
    assert info.p4 == "0x175"
    assert info.crash_time_utc is not None
    assert info.crash_time_utc.endswith("Z")
    assert info.crash_time_source == "header"
    assert info.uptime_seconds == 188130


def test_parse_kernel_dump_1a():
    """Kiểm tra đọc header dump PAGEDU64 mã 0x1A."""
    dump_file = FIXTURES_DIR / "kernel_sample_1a.dmp"
    info = parse_dump_header(dump_file)

    assert info.valid is True
    assert info.dump_type == "kernel"
    assert info.bugcheck_code == "0x1A"
    assert info.bugcheck_name == "MEMORY_MANAGEMENT"
    assert info.p1 == "0x41792"
    assert info.crash_time_source == "header"
    assert info.uptime_seconds == 3600


def test_parse_minidump():
    """Kiểm tra đọc header Minidump MDMP."""
    dump_file = FIXTURES_DIR / "minidump_sample.dmp"
    info = parse_dump_header(dump_file)

    assert info.valid is True
    assert info.signature == "MDMP"
    assert info.dump_type == "mini"
    assert info.crash_time_utc is not None
    assert info.crash_time_source == "header"


def test_parse_corrupted_dump():
    """Kiểm tra xử lý mềm khi file dump bị hỏng header."""
    dump_file = FIXTURES_DIR / "corrupted.dmp"
    info = parse_dump_header(dump_file)

    assert info.valid is False
    assert "Định dạng dump chưa hỗ trợ" in info.error_message


def test_parse_nonexistent_file():
    """Kiểm tra không gây crash khi file không tồn tại."""
    info = parse_dump_header("/path/to/nonexistent/dump.dmp")
    assert info.valid is False
    assert "File không tồn tại" in info.error_message
