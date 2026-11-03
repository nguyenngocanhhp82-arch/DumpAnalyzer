"""
Kiểm thử module cấu hình và các file dữ liệu quy tắc.
"""

import json
import yaml
from dumpanalyzer.core.config import (
    load_settings,
    get_project_root,
    check_environment_summary,
)


def test_load_settings():
    """Kiểm tra việc nạp settings.yaml thành công và có đủ các khoá cấu hình bắt buộc."""
    settings = load_settings()
    assert isinstance(settings, dict)
    assert "cdb_timeout_seconds" in settings
    assert settings["cdb_timeout_seconds"] >= 60
    assert "confidence_thresholds" in settings
    assert settings["confidence_thresholds"]["high"] >= 70
    assert "working_dir" in settings


def test_bugcheck_codes_json():
    """Kiểm tra cơ sở dữ liệu mã Bug Check có chứa ít nhất 379 mã chuẩn Microsoft."""
    json_path = get_project_root() / "config" / "data" / "bugcheck_codes.json"
    assert json_path.exists(), f"Không tìm thấy file {json_path}"

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert len(data) >= 379
    # Kiểm tra một số mã lỗi kinh điển
    assert "0x124" in data
    assert data["0x124"]["name"] == "WHEA_UNCORRECTABLE_ERROR"
    assert "0x133" in data
    assert data["0x133"]["name"] == "DPC_WATCHDOG_VIOLATION"
    assert "0x1A" in data
    assert data["0x1A"]["name"] == "MEMORY_MANAGEMENT"
    assert "0xDEADDEAD" in data


def test_yaml_rules_syntax():
    """Kiểm tra cú pháp của tất cả các file cấu hình quy tắc YAML khởi đầu."""
    rules_dir = get_project_root() / "config" / "rules"
    rule_files = [
        "bugcheck_rules.yaml",
        "driver_map.yaml",
        "event_rules.yaml",
        "patterns.yaml",
    ]

    for rf in rule_files:
        file_path = rules_dir / rf
        assert file_path.exists(), f"File luật {rf} không tồn tại"
        with open(file_path, "r", encoding="utf-8") as f:
            content = yaml.safe_load(f)
            assert content is not None, f"File {rf} rỗng hoặc không parse được"


def test_environment_summary():
    """Kiểm tra hàm tổng hợp môi trường trả về đủ các trường thông tin."""
    summary = check_environment_summary()
    assert "cdb_found" in summary
    assert "is_admin" in summary
    assert "os_platform" in summary
    assert "dump_paths" in summary


def test_find_cdb_executable(tmp_path):
    """Kiểm tra logic tìm kiếm cdb.exe: ưu tiên đường dẫn chỉ định tay, không fallback bừa bãi."""
    from dumpanalyzer.core.config import find_cdb_executable

    # 1. Đường dẫn chỉ định tay không tồn tại -> bắt buộc trả về None
    assert find_cdb_executable("/nonexistent/path/to/cdb.exe") is None

    # 2. Đường dẫn chỉ định tay tồn tại -> trả về đúng đường dẫn đó
    fake_cdb = tmp_path / "cdb.exe"
    fake_cdb.write_text("mock binary", encoding="utf-8")
    assert find_cdb_executable(str(fake_cdb)) == str(fake_cdb)

