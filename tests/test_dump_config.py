"""
Kiểm thử module dump_config (Phase 1B): kiểm tra khả năng ghi dump,
đánh giá trạng thái readiness, format backup registry và lệnh CLI check-dump-config.
"""

from pathlib import Path
from dumpanalyzer.collectors.dump_config import (
    read_registry_crash_control,
    evaluate_readiness,
    backup_registry_crash_control,
    apply_automatic_dump,
)
from dumpanalyzer.cli import main


def test_read_registry_crash_control():
    """Kiểm tra hàm đọc registry trả về cấu trúc dữ liệu hợp lệ."""
    data = read_registry_crash_control()
    assert isinstance(data, dict)
    assert "CrashDumpEnabled" in data
    assert "AutoReboot" in data
    assert "Overwrite" in data


def test_evaluate_readiness_blocked_cases():
    """Kiểm tra các trường hợp dẫn đến trạng thái KHÔNG GHI ĐƯỢC DUMP."""
    # Case 1: Tắt dump (CrashDumpEnabled = 0)
    res1 = evaluate_readiness(
        reg_data={"CrashDumpEnabled": 0},
        pf_data={"has_system_drive_pagefile": True},
        disk_data={"sufficient_space": True},
        volmgr_data={"has_failure_161": False},
    )
    assert res1["status"] == "KHÔNG GHI ĐƯỢC DUMP"
    assert any("TẮT" in r for r in res1["reasons"])

    # Case 2: Không có pagefile trên ổ hệ thống
    res2 = evaluate_readiness(
        reg_data={"CrashDumpEnabled": 7},
        pf_data={"has_system_drive_pagefile": False},
        disk_data={"sufficient_space": True},
        volmgr_data={"has_failure_161": False},
    )
    assert res2["status"] == "KHÔNG GHI ĐƯỢC DUMP"
    assert any("Pagefile" in r for r in res2["reasons"])


def test_evaluate_readiness_attention_and_ready_cases():
    """Kiểm tra trường hợp CẦN CHÚ Ý và SẴN SÀNG."""
    # Case 1: Thiếu dung lượng trống hoặc có lỗi volmgr 161 -> CẦN CHÚ Ý
    res_att = evaluate_readiness(
        reg_data={"CrashDumpEnabled": 7},
        pf_data={"has_system_drive_pagefile": True},
        disk_data={"sufficient_space": False, "free_disk_gb": 4.0, "recommended_free_gb": 21.0},
        volmgr_data={"has_failure_161": True, "last_failure_time": "2026-10-25"},
    )
    assert res_att["status"] == "CẦN CHÚ Ý"
    assert len(res_att["reasons"]) >= 2

    # Case 2: Mọi yếu tố hoàn hảo -> SẴN SÀNG
    res_ready = evaluate_readiness(
        reg_data={"CrashDumpEnabled": 7},
        pf_data={"has_system_drive_pagefile": True},
        disk_data={"sufficient_space": True},
        volmgr_data={"has_failure_161": False},
    )
    assert res_ready["status"] == "SẴN SÀNG"
    assert len(res_ready["reasons"]) == 0


def test_backup_registry_format(tmp_path):
    """Kiểm tra việc xuất file sao lưu registry .reg đúng định dạng Windows."""
    backup_file = backup_registry_crash_control(target_dir=tmp_path)
    assert backup_file.exists()
    assert backup_file.suffix == ".reg"

    content = backup_file.read_text(encoding="utf-8")
    assert "Windows Registry Editor Version 5.00" in content
    assert r"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl]" in content
    assert '"CrashDumpEnabled"=dword:' in content


def test_apply_automatic_dump_unconfirmed():
    """Kiểm tra huỷ bỏ an toàn khi người dùng chưa xác nhận."""
    res = apply_automatic_dump(confirmed=False)
    assert res["success"] is False
    assert "chưa được người dùng xác nhận" in res["message"]


def test_cli_check_dump_config(capsys):
    """Kiểm tra lệnh dòng lệnh check-dump-config chạy không lỗi."""
    ret = main(["check-dump-config"])
    assert ret == 0

    captured = capsys.readouterr().out
    assert "KIỂM TRA KHẢ NĂNG GHI DUMP HỆ THỐNG" in captured
    assert "Cấu hình Registry (CrashControl):" in captured
    assert "Tình trạng Bộ nhớ ảo (Pagefile):" in captured
    assert "TRẠNG THÁI:" in captured
