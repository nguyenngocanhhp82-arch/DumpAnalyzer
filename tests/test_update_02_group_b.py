"""Tests hồi quy cho Nhóm B theo ĐỢT CẬP NHẬT 02.
Kiểm tra:
1. Đọc SystemTime tại offset 0xFA8 cho header PAGEDU64.
2. Đọc DumpType tại offset 0xF98 (1=full, 2=kernel, 4=mini, 5=bitmap/kernel).
3. Đọc SystemUpTime tại offset 0xFF8 (nếu có).
4. Ghi nhận crash_time_source ('header' vs 'mtime').
5. Cột crash_time_source trong SQLite db.py.
"""

import struct
from pathlib import Path
import pytest
from dumpanalyzer.analyzer.header_parser import parse_dump_header, DumpHeaderInfo
from dumpanalyzer.core.models import Crash
from dumpanalyzer.storage.db import Database


def test_b1_pagedu64_header_offsets(tmp_path):
    """Kiểm tra đọc chính xác SystemTime (0xFA8), DumpType (0xF98) và SystemUpTime (0xFF8)."""
    dump_file = tmp_path / "test_pagedu64.dmp"
    # Header PAGEDU64 kích thước tối thiểu 0x1000 (4096 bytes)
    buf = bytearray(8192)

    # Signature
    buf[0:4] = b"PAGE"
    buf[4:8] = b"DU64"

    # BugcheckCode và params
    struct.pack_into("<I", buf, 0x38, 0x124)  # 0x124
    struct.pack_into("<Q", buf, 0x40, 0x0)
    struct.pack_into("<Q", buf, 0x48, 0xFFFF800012345678)
    struct.pack_into("<Q", buf, 0x50, 0xB200000000000000)
    struct.pack_into("<Q", buf, 0x58, 0x175)

    # DumpType tại 0xF98: 1 = Full dump
    struct.pack_into("<I", buf, 0xF98, 1)

    # SystemTime tại 0xFA8: FILETIME 134369640000000000 (tương đương 2026-10-29 10:00:00 UTC)
    target_ft = 134369640000000000
    struct.pack_into("<Q", buf, 0xFA8, target_ft)

    # SystemUpTime tại 0xFF8: 3600 giây (3600 * 10_000_000 ticks)
    struct.pack_into("<Q", buf, 0xFF8, 3600 * 10_000_000)

    dump_file.write_bytes(buf)

    info = parse_dump_header(dump_file)
    assert info.valid is True
    assert info.signature == "PAGEDU64"
    assert info.bugcheck_code == "0x124"
    assert info.dump_type == "full"
    assert info.crash_time_source == "header"
    assert info.crash_time_utc == "2026-10-20T10:00:00Z"
    assert info.uptime_seconds == 3600


def test_b2_fallback_to_mtime_when_header_systemtime_zero(tmp_path):
    """Khi SystemTime tại 0xFA8 = 0, crash_time_source phải là 'mtime'."""
    dump_file = tmp_path / "test_zero_time.dmp"
    buf = bytearray(8192)
    buf[0:4] = b"PAGE"
    buf[4:8] = b"DU64"
    struct.pack_into("<I", buf, 0x38, 0x3B)
    struct.pack_into("<I", buf, 0xF98, 2)  # Kernel dump
    struct.pack_into("<Q", buf, 0xFA8, 0)  # SystemTime = 0

    dump_file.write_bytes(buf)

    info = parse_dump_header(dump_file)
    assert info.valid is True
    assert info.dump_type == "kernel"
    assert info.crash_time_source == "mtime"
    assert info.crash_time_utc is not None


def test_b3_db_crash_time_source(tmp_path):
    """Kiểm tra lưu và lấy crash_time_source trong SQLite db."""
    db_file = tmp_path / "test_db.db"
    db = Database(db_file)

    crash = Crash(
        dump_path="C:\\test.dmp",
        dump_sha256="abc123456",
        dump_type="full",
        crash_time_utc="2026-10-29T10:00:00Z",
        crash_time_source="header",
        bugcheck_code="0x124",
        analyzed_by="cdb",
    )
    c_id = db.insert_crash(crash)
    assert c_id > 0

    crashes = db.list_crashes()
    assert len(crashes) == 1
    assert crashes[0]["crash_time_source"] == "header"
