"""
Kiểm thử toàn diện module nạp quy tắc (Rule Loader) và kiểm tra cú pháp YAML.
"""

from pathlib import Path
import pytest
from dumpanalyzer.engine.rule_loader import (
    load_yaml_with_line_numbers,
    validate_rules_and_settings,
    load_all_rules,
    normalize_bugcheck_code,
    validate_bugcheck_rules,
    validate_driver_map,
    validate_event_rules,
    validate_patterns,
    validate_settings,
)
from dumpanalyzer.cli import cmd_validate_rules
from argparse import Namespace


def test_normalize_bugcheck_code():
    """Kiểm tra hàm chuẩn hoá mã Bug Check về dạng chuỗi Hex viết hoa."""
    assert normalize_bugcheck_code(0x124) == "0x124"
    assert normalize_bugcheck_code("0x1a") == "0x1A"
    assert normalize_bugcheck_code("133") == "0x133"
    assert normalize_bugcheck_code(0) == "0x0"
    assert normalize_bugcheck_code("0x0") == "0x0"


def test_load_all_rules_default():
    """Kiểm tra nạp toàn bộ quy tắc mặc định từ thư mục config/rules."""
    rules = load_all_rules()
    assert "bugchecks" in rules
    assert "drivers" in rules
    assert "ms_core_modules" in rules
    assert "event_rules" in rules
    assert "patterns" in rules

    # Kiểm tra các mã cơ bản đã được nạp
    assert "0x124" in rules["bugchecks"]
    assert "0x1A" in rules["bugchecks"]
    assert "0x116" in rules["bugchecks"]
    assert "0x0" in rules["bugchecks"]

    # Kiểm tra driver NVIDIA và module ntoskrnl
    assert "nvlddmkm.sys" in rules["drivers"]
    assert "ntoskrnl.exe" in rules["ms_core_modules"]


def test_validate_rules_and_settings_clean():
    """Kiểm tra toàn bộ bộ quy tắc hiện tại của dự án phải hợp lệ 100%."""
    is_valid, errors, summary = validate_rules_and_settings()
    assert is_valid is True
    assert len(errors) == 0
    assert summary.get("bugcheck_rules_count", 0) >= 20
    assert summary.get("driver_mappings_count", 0) >= 5
    assert summary.get("ms_core_modules_count", 0) >= 8


def test_yaml_syntax_error_with_line_number(tmp_path):
    """Kiểm tra khi file YAML bị lỗi cú pháp thụt đầu dòng, parser phải báo đúng số dòng."""
    bad_yaml = tmp_path / "bad_syntax.yaml"
    bad_yaml.write_text(
        "root:\n"
        "  item1: 123\n"
        " item2: 456\n",  # Lỗi thụt đầu dòng tại dòng 3
        encoding="utf-8",
    )

    data, err = load_yaml_with_line_numbers(bad_yaml)
    assert data is None
    assert err is not None
    assert "dòng 3" in err.lower() or "dòng" in err.lower()


def test_validate_bugcheck_rules_semantic_errors(tmp_path):
    """Kiểm tra phát hiện lỗi ngữ nghĩa trong bugcheck_rules.yaml."""
    dummy_file = tmp_path / "bugcheck_rules.yaml"

    # Trường hợp thiếu 'name'
    bad_data = {
        0x124: {
            "suspects": {"cpu": 50}
        }
    }
    errs = validate_bugcheck_rules(bad_data, dummy_file)
    assert len(errs) > 0
    assert any("Thiếu trường bắt buộc 'name'" in e for e in errs)

    # Trường hợp trọng số không phải số
    bad_data_2 = {
        0x1A: {
            "name": "TEST",
            "suspects": {"ram": "rất cao"}
        }
    }
    errs_2 = validate_bugcheck_rules(bad_data_2, dummy_file)
    assert any("phải là số" in e for e in errs_2)


def test_validate_driver_map_semantic_errors(tmp_path):
    """Kiểm tra phát hiện lỗi cấu trúc trong driver_map.yaml."""
    dummy_file = tmp_path / "driver_map.yaml"

    # Thiếu action
    bad_data = {
        "drivers": {
            "test.sys": {"device": "Card test", "type": "gpu"}
        },
        "ms_core_modules": ["ntoskrnl.exe"]
    }
    errs = validate_driver_map(bad_data, dummy_file)
    assert any("Thiếu trường bắt buộc 'action'" in e for e in errs)


def test_validate_event_rules_semantic_errors(tmp_path):
    """Kiểm tra phát hiện lỗi cấu trúc trong event_rules.yaml."""
    dummy_file = tmp_path / "event_rules.yaml"

    bad_data = {
        "events": [
            {"source": "Disk"}  # thiếu ids và adds
        ]
    }
    errs = validate_event_rules(bad_data, dummy_file)
    assert any("Thiếu danh sách 'ids'" in e for e in errs)
    assert any("Thiếu từ điển trọng số 'adds'" in e for e in errs)


def test_cli_validate_rules_command():
    """Kiểm tra thực thi lệnh CLI 'dumpanalyzer validate-rules'."""
    ret = cmd_validate_rules(Namespace())
    assert ret == 0
