"""
Kiểm thử module dump_finder: tìm kiếm, tính SHA256 và copy an toàn.
"""

from pathlib import Path
from dumpanalyzer.collectors.dump_finder import (
    calculate_sha256,
    find_dumps,
    copy_dump_safely,
)


def test_calculate_sha256(tmp_path):
    """Kiểm tra tính toán mã băm SHA256 chính xác."""
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("Hello DumpAnalyzer Test", encoding="utf-8")

    import hashlib
    expected_hash = hashlib.sha256("Hello DumpAnalyzer Test".encode("utf-8")).hexdigest().lower()

    calc_hash = calculate_sha256(sample_file)
    assert calc_hash == expected_hash


def test_find_dumps_fixtures():
    """Kiểm tra tìm kiếm các file dump trong thư mục tests/fixtures."""
    fixtures_dir = Path(__file__).resolve().parent / "fixtures"
    dumps = find_dumps([str(fixtures_dir)])

    filenames = [d["filename"] for d in dumps]
    assert "kernel_sample_124.dmp" in filenames
    assert "kernel_sample_1a.dmp" in filenames
    assert "minidump_sample.dmp" in filenames
    assert "corrupted.dmp" in filenames


def test_copy_dump_safely(tmp_path):
    """Kiểm tra copy an toàn dump vào thư mục làm việc, không ảnh hưởng file gốc."""
    src_file = tmp_path / "original.dmp"
    src_file.write_bytes(b"ORIGINAL_DUMP_DATA_BYTES")

    workspace = tmp_path / "workspace"
    copied = copy_dump_safely(src_file, workspace)

    assert copied.exists()
    assert copied.parent == workspace
    assert copied.read_bytes() == b"ORIGINAL_DUMP_DATA_BYTES"

    # Kiểm tra file gốc không bị xoá hay sửa
    assert src_file.exists()
    assert src_file.read_bytes() == b"ORIGINAL_DUMP_DATA_BYTES"


def test_cleanup_workspace(tmp_path):
    """Kiểm tra dọn dẹp workspace xoá file copy tạm nhưng không chạm tới file gốc."""
    from dumpanalyzer.collectors.dump_finder import cleanup_workspace

    original = tmp_path / "original.dmp"
    original.write_bytes(b"ORIGINAL")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    temp1 = workspace / "temp1.dmp"
    temp1.write_bytes(b"TEMP1")
    temp2 = workspace / "temp2.tmp"
    temp2.write_bytes(b"TEMP2")
    keep_file = workspace / "results.json"
    keep_file.write_bytes(b"KEEP")

    deleted = cleanup_workspace(workspace)
    assert deleted == 2
    assert not temp1.exists()
    assert not temp2.exists()
    assert keep_file.exists()
    assert original.exists()

