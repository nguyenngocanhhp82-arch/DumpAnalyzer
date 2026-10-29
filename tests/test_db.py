"""
Kiểm thử tầng lưu trữ SQLite và thao tác trên bảng crash.
"""

from dumpanalyzer.storage.db import Database
from dumpanalyzer.core.models import Crash


def test_db_init_and_crud(tmp_path):
    """Kiểm tra tạo bảng tự động và chèn/truy vấn crash theo sha256."""
    db_file = tmp_path / "test_dump.db"
    db = Database(db_file)

    # Ban đầu chưa có dữ liệu
    assert db.get_crash_by_sha256("fake_sha256_hash") is None

    # Tạo bản ghi Crash mẫu
    test_crash = Crash(
        dump_path="C:\\workspace\\test.dmp",
        dump_sha256="abc123def456789",
        dump_type="mini",
        crash_time_utc="2026-10-29T08:00:00Z",
        bugcheck_code="0x124",
        bugcheck_name="WHEA_UNCORRECTABLE_ERROR",
        p1="0x0",
        p2="0xffff8000",
        p3="0x0",
        p4="0x0",
        image_name="AuthenticAMD.sys",
        module_name="AuthenticAMD",
        process_name="System",
        failure_bucket_id="0x124_AuthenticAMD",
        uptime_seconds=3600,
        cdb_raw_output="SAMPLE CDB RAW OUTPUT",
        analyzed_by="cdb",
    )

    crash_id = db.insert_crash(test_crash)
    assert crash_id is not None
    assert crash_id > 0

    # Kiểm tra tra cứu cache qua SHA256
    cached = db.get_crash_by_sha256("abc123def456789")
    assert cached is not None
    assert cached["id"] == crash_id
    assert cached["bugcheck_code"] == "0x124"
    assert cached["bugcheck_name"] == "WHEA_UNCORRECTABLE_ERROR"
    assert cached["cdb_raw_output"] == "SAMPLE CDB RAW OUTPUT"

    # Kiểm tra danh sách crashes
    all_crashes = db.list_crashes()
    assert len(all_crashes) == 1

    db.close()
