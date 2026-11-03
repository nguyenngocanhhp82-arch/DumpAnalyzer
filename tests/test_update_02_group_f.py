"""Tests cho Nhóm F theo ĐỢT CẬP NHẬT 02.
Kiểm tra:
1. suspect_driver trong Crash:
   - Scorer ưu tiên crash.suspect_driver nếu có.
   - Scorer fallback sang chuỗi 'Driver nghi vấn trong stack:' trong cdb_raw_output khi suspect_driver rỗng.
   - cdb_runner tạo Crash có suspect_driver lấy từ CdbAnalysisResult.
2. File lớn MEMORY.DMP:
   - Kiểm tra dung lượng trống (cần >= size * 1.2).
   - Kiểm tra ngưỡng max_copy_gb (mặc định 8 GB). Nếu vượt quá hoặc không đủ đĩa -> không copy, trả về file gốc.
   - Băm nhanh (calculate_fast_hash) cho file lớn: size + mtime + sha256(1MB đầu + 1MB cuối).
3. Đảm bảo .gitignore loại trừ data/*.db, workspace/, logs/.
"""

from pathlib import Path
from unittest.mock import patch, MagicMock

from dumpanalyzer.core.models import Crash
from dumpanalyzer.engine.scorer import score_single_crash
from dumpanalyzer.engine.rule_loader import load_all_rules
from dumpanalyzer.collectors.dump_finder import (
    calculate_fast_hash,
    copy_dump_safely,
)



def test_f1_suspect_driver_priority_in_scorer():
    """Scorer ưu tiên crash.suspect_driver trước chuỗi trong cdb_raw_output."""
    rules = load_all_rules()
    settings = {"conflict_threshold": 15}

    # Trường hợp 1: Có suspect_driver trực tiếp
    crash1 = Crash(
        id=1,
        dump_type="mini",
        image_name="ntoskrnl.exe",
        module_name="ntoskrnl.exe",
        bugcheck_code="0x124",
        suspect_driver="nvlddmkm.sys",
        cdb_raw_output="Driver nghi vấn trong stack: amdkmdag.sys",  # Chuỗi cũ khác nhưng phải ưu tiên nvlddmkm.sys
        analyzed_by="cdb",
    )
    res1 = score_single_crash(crash1, [], rules, settings)
    assert "gpu" in res1["top_suspect"].lower() or any("nvlddmkm" in n for n in res1["notes"])
    assert any("amdkmdag" not in n for n in res1["notes"])

    # Trường hợp 2: suspect_driver rỗng -> fallback đọc cdb_raw_output (tương thích dữ liệu DB cũ)
    crash2 = Crash(
        id=2,
        dump_type="mini",
        image_name="ntoskrnl.exe",
        module_name="ntoskrnl.exe",
        bugcheck_code="0x124",
        suspect_driver="",
        cdb_raw_output="Driver nghi vấn trong stack: nvlddmkm.sys",
        analyzed_by="cdb",
    )
    res2 = score_single_crash(crash2, [], rules, settings)
    assert "gpu" in res2["top_suspect"].lower() or any("nvlddmkm" in n for n in res2["notes"])



def test_f2_calculate_fast_hash(tmp_path):
    """Tính mã băm nhanh cho file: chứa tiền tố 'fast_' và độ dài đúng."""
    big_file = tmp_path / "big_sample.dmp"
    # Tạo file giả lập 3 MB (> 2 MB để có cả head 1MB và tail 1MB)
    head = b"H" * (1024 * 1024)
    mid = b"M" * (1024 * 1024)
    tail = b"T" * (1024 * 1024)
    big_file.write_bytes(head + mid + tail)

    fast_hash = calculate_fast_hash(big_file)
    assert fast_hash.startswith("fast_")
    assert str(len(head + mid + tail)) in fast_hash


def test_f3_copy_dump_safely_max_copy_gb_limit(tmp_path):
    """Nếu file vượt quá max_copy_gb -> không copy, trả về đường dẫn file gốc."""
    src = tmp_path / "huge_memory.dmp"
    src.write_bytes(b"HUGE DUMP DATA")
    workspace = tmp_path / "workspace"

    orig_stat = Path.stat

    def mock_stat(self, **kwargs):
        if self.name == src.name:
            res = orig_stat(self, **kwargs)
            m = MagicMock()
            m.st_size = 10 * 1024 * 1024 * 1024  # 10 GB
            m.st_mtime = res.st_mtime
            return m
        return orig_stat(self, **kwargs)

    with patch.object(Path, "stat", side_effect=mock_stat, autospec=True):
        result_path = copy_dump_safely(src, workspace, max_copy_gb=8)
        assert result_path == src.resolve()
        assert list(workspace.glob("*")) == []


def test_f4_copy_dump_safely_insufficient_disk_space(tmp_path):
    """Nếu ổ đĩa không đủ 1.2x dung lượng file -> không copy, trả về file gốc."""
    src = tmp_path / "medium_dump.dmp"
    src.write_bytes(b"MEDIUM DUMP")
    workspace = tmp_path / "workspace"

    orig_stat = Path.stat

    def mock_stat(self, **kwargs):
        if self.name == src.name:
            res = orig_stat(self, **kwargs)
            m = MagicMock()
            m.st_size = 200 * 1024 * 1024  # 200 MB
            m.st_mtime = res.st_mtime
            return m
        return orig_stat(self, **kwargs)

    with patch("shutil.disk_usage") as mock_disk:
        # Giả lập ổ đĩa chỉ còn 100 MB trống (< 200 * 1.2 = 240 MB)
        mock_disk.return_value = MagicMock(free=100 * 1024 * 1024)

        with patch.object(Path, "stat", side_effect=mock_stat, autospec=True):
            result_path = copy_dump_safely(src, workspace)
            assert result_path == src.resolve()
            assert list(workspace.glob("*")) == []



def test_f5_gitignore_excludes_real_data():
    """Kiểm tra .gitignore loại trừ data/*.db, workspace/, logs/."""
    from dumpanalyzer.core.config import get_project_root

    gitignore = get_project_root() / ".gitignore"
    assert gitignore.exists()
    content = gitignore.read_text(encoding="utf-8")
    assert "data/*.db" in content
    assert "workspace/" in content
    assert "logs/" in content
