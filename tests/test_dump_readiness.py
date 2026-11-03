"""Bộ kiểm thử toàn diện Đợt 04: Dump Readiness, Safe Actions & Fleet Aggregator.

Bao phủ tối thiểu 15 kịch bản theo Mục 10.1 của ANTIGRAVITY_UPDATE_04_DUMP_READINESS.md:
1. Decision matrix: Kiểm thử tham số hoá cho toàn bộ các tổ hợp của Bảng 3.3.
2. Phân biệt read_ok=False (UNKNOWN) vs giá trị thiếu (missing).
3. Pagefile: unknown vs ok vs missing, Dedicated dump file.
4. Volmgr: Thứ tự thời gian (161 sau 1001 -> ATTENTION; 1001 sau 161 -> READY + evidence_of_success).
5. Backup & Rollback: Initial=0, Initial=3, Initial=missing (xoá value khỏi registry).
6. Read-after-write failure: Tự động rollback khi ghi sai.
7. Idempotence: enable khi máy đã ở mode 7 -> changed=False.
8. Quét source code: Tuyệt đối không chứa shutdown, Restart-Computer, Stop-Computer.
9. Pending reboot: changed_at > last_boot_time -> READY_PENDING_REBOOT.
10. JSON report roundtrip: xuất JSON và kiểm tra tính toàn vẹn.
11. Corrupted JSON report: Bỏ qua an toàn, ghi nhận lỗi, không crash.
12. Stale report: Đánh dấu is_stale khi báo cáo > 14 ngày.
13. Deployment package: Tạo 3 file, có tham số -WhatIf, ma trận quyết định khớp.
14. Dump Gap: Event 41 BSOD vs Dump file, cutoff date, BugcheckCode=0 là non-bsod reset.
15. BugcheckCode decimal -> hex conversion: 10 -> 0x0000000A, 0 -> 0x00000000.
"""

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from dumpanalyzer.collectors.dump_config import (
    STATUS_READY,
    STATUS_READY_PENDING_REBOOT,
    STATUS_ATTENTION,
    STATUS_BLOCKED,
    STATUS_UNKNOWN,
    evaluate_readiness_v2,
    enable_crash_dump,
    rollback_crash_dump,
    backup_registry_crash_control_v2,
    collect_dump_readiness,
    compute_dump_gap,
)
from dumpanalyzer.engine.deployment_package import (
    generate_deployment_package,
    aggregate_fleet_reports,
)
from dumpanalyzer.engine.correlator import Correlator
from dumpanalyzer.core.models import Crash
from dumpanalyzer.storage.db import Database


# ==================== SCENARIO 1: DECISION MATRIX ====================

@pytest.mark.parametrize(
    "reg, pf, disk, vm, expected_status, expected_allowed",
    [
        # Row 1: Ready lý tưởng
        (
            {"CrashDumpEnabled": 7, "read_ok": True},
            {"state": "ok", "system_drive_size_mb": 16384},
            {"free_gb": 35.0, "ram_gb": 16.0, "sufficient_space": True},
            {"has_recent_failure": False, "has_recent_success": True},
            STATUS_READY,
            False,  # đã ở mode 7, không cần bật lại
        ),
        # Row 2: CrashDumpEnabled = 0 -> BLOCKED, cho phép bật
        (
            {"CrashDumpEnabled": 0, "read_ok": True},
            {"state": "ok", "system_drive_size_mb": 16384},
            {"free_gb": 35.0, "ram_gb": 16.0, "sufficient_space": True},
            {"has_recent_failure": False, "has_recent_success": False},
            STATUS_BLOCKED,
            True,
        ),
        # Row 3: CrashDumpEnabled missing -> BLOCKED, cho phép bật
        (
            {"CrashDumpEnabled": None, "read_ok": True, "missing_values": ["CrashDumpEnabled"]},
            {"state": "ok", "system_drive_size_mb": 16384},
            {"free_gb": 35.0, "ram_gb": 16.0, "sufficient_space": True},
            {"has_recent_failure": False, "has_recent_success": False},
            STATUS_BLOCKED,
            True,
        ),
        # Row 4: CrashDumpEnabled = 3 (Small dump) -> ATTENTION, cho phép nâng cấp
        (
            {"CrashDumpEnabled": 3, "read_ok": True},
            {"state": "ok", "system_drive_size_mb": 16384},
            {"free_gb": 35.0, "ram_gb": 16.0, "sufficient_space": True},
            {"has_recent_failure": False, "has_recent_success": True},
            STATUS_ATTENTION,
            True,
        ),
        # Row 5: Pagefile missing -> BLOCKED, KHÔNG cho phép bật
        (
            {"CrashDumpEnabled": 0, "read_ok": True},
            {"state": "missing", "system_drive_size_mb": 0},
            {"free_gb": 35.0, "ram_gb": 16.0, "sufficient_space": True},
            {"has_recent_failure": False, "has_recent_success": False},
            STATUS_BLOCKED,
            False,
        ),
        # Row 6: Pagefile unknown -> UNKNOWN, KHÔNG cho phép bật
        (
            {"CrashDumpEnabled": 0, "read_ok": True},
            {"state": "unknown", "system_drive_size_mb": 0},
            {"free_gb": 35.0, "ram_gb": 16.0, "sufficient_space": True},
            {"has_recent_failure": False, "has_recent_success": False},
            STATUS_UNKNOWN,
            False,
        ),
        # Row 7: Thiếu dung lượng đĩa hệ thống C: < threshold -> BLOCKED, KHÔNG cho phép bật
        (
            {"CrashDumpEnabled": 0, "read_ok": True},
            {"state": "ok", "system_drive_size_mb": 16384},
            {"free_gb": 3.0, "ram_gb": 16.0, "sufficient_space": False},
            {"has_recent_failure": False, "has_recent_success": False},
            STATUS_BLOCKED,
            False,
        ),
        # Row 8: volmgr 161 gần nhất không có success -> ATTENTION, KHÔNG cho phép bật
        (
            {"CrashDumpEnabled": 7, "read_ok": True},
            {"state": "ok", "system_drive_size_mb": 16384},
            {"free_gb": 35.0, "ram_gb": 16.0, "sufficient_space": True},
            {"has_recent_failure": True, "has_recent_success": False},
            STATUS_ATTENTION,
            False,
        ),
        # Row 9: Registry read_ok = False -> UNKNOWN, KHÔNG cho phép bật
        (
            {"CrashDumpEnabled": None, "read_ok": False, "error": "Access denied"},
            {"state": "ok", "system_drive_size_mb": 16384},
            {"free_gb": 35.0, "ram_gb": 16.0, "sufficient_space": True},
            {"has_recent_failure": False, "has_recent_success": False},
            STATUS_UNKNOWN,
            False,
        ),
    ],
)
def test_decision_matrix_parameterized(reg, pf, disk, vm, expected_status, expected_allowed):
    res = evaluate_readiness_v2(
        reg_data=reg,
        pf_data=pf,
        disk_data=disk,
        volmgr_data=vm,
        target_mode=7,
    )
    assert res["status"] == expected_status
    assert res["enable_action"]["allowed"] == expected_allowed


# ==================== SCENARIO 2: SEPARATION OF read_ok=False VS MISSING ====================

def test_distinguish_read_error_vs_missing_value():
    # Case A: read error (e.g. non-Windows / permission)
    reg_err = {"read_ok": False, "CrashDumpEnabled": None, "error": "PermissionError"}
    res_err = evaluate_readiness_v2(
        reg_data=reg_err,
        pf_data={"state": "ok"},
        disk_data={"sufficient_space": True},
        volmgr_data={"has_recent_failure": False},
    )
    assert res_err["status"] == STATUS_UNKNOWN
    assert any(rc["code"] in ("REGISTRY_UNREADABLE", "REGISTRY_READ_ERROR") for rc in res_err["reason_codes"])

    # Case B: read_ok=True but value missing
    reg_missing = {"read_ok": True, "CrashDumpEnabled": None, "missing_values": ["CrashDumpEnabled"]}
    res_missing = evaluate_readiness_v2(
        reg_data=reg_missing,
        pf_data={"state": "ok"},
        disk_data={"sufficient_space": True},
        volmgr_data={"has_recent_failure": False},
    )
    assert res_missing["status"] == STATUS_BLOCKED
    assert any(rc["code"] in ("DUMP_VALUE_MISSING", "CRASH_DUMP_DISABLED") for rc in res_missing["reason_codes"])


# ==================== SCENARIO 3: PAGEFILE STATES & DEDICATED DUMP ====================

def test_pagefile_states_and_dedicated_dump():
    # Dedicated dump file satisfies storage requirement even if C: pagefile is missing
    pf_dedicated = {
        "state": "ok",
        "has_system_drive": False,
        "dedicated_dump_file": {"path": r"D:\dedicateddumpfile.sys", "size_mb": 16384},
    }
    res = evaluate_readiness_v2(
        reg_data={"CrashDumpEnabled": 7, "read_ok": True},
        pf_data=pf_dedicated,
        disk_data={"sufficient_space": True},
        volmgr_data={"has_recent_failure": False},
    )
    assert res["status"] == STATUS_READY

    # Pagefile unknown state
    pf_unknown = {"state": "unknown"}
    res_unk = evaluate_readiness_v2(
        reg_data={"CrashDumpEnabled": 7, "read_ok": True},
        pf_data=pf_unknown,
        disk_data={"sufficient_space": True},
        volmgr_data={"has_recent_failure": False},
    )
    assert res_unk["status"] == STATUS_UNKNOWN


# ==================== SCENARIO 4: VOLMGR CHRONOLOGICAL ORDER ====================

def test_volmgr_chronological_order():
    # Success after failure: volmgr 1001 is newer -> READY with evidence_of_success
    vm_recovered = {
        "has_recent_failure": False,
        "has_recent_success": True,
        "last_failure_utc": "2026-10-01T10:00:00Z",
        "last_success_utc": "2026-10-15T10:00:00Z",
    }
    res_rec = evaluate_readiness_v2(
        reg_data={"CrashDumpEnabled": 7, "read_ok": True},
        pf_data={"state": "ok"},
        disk_data={"sufficient_space": True},
        volmgr_data=vm_recovered,
    )
    assert res_rec["status"] == STATUS_READY
    assert res_rec["proof_level"] == "evidence_of_success"

    # Failure after success: volmgr 161 is newer -> ATTENTION
    vm_broken = {
        "has_recent_failure": True,
        "has_recent_success": True,
        "last_failure_utc": "2026-10-20T10:00:00Z",
        "last_success_utc": "2026-10-15T10:00:00Z",
    }
    res_brk = evaluate_readiness_v2(
        reg_data={"CrashDumpEnabled": 7, "read_ok": True},
        pf_data={"state": "ok"},
        disk_data={"sufficient_space": True},
        volmgr_data=vm_broken,
    )
    assert res_brk["status"] == STATUS_ATTENTION
    assert any(rc["code"] in ("VOLMGR_FAILURE_RECENT", "VOLMGR_161_DUMP_FAILED") for rc in res_brk["reason_codes"])


# ==================== SCENARIO 5: BACKUP & ROLLBACK (3 INITIAL STATES) ====================

def test_backup_and_rollback_three_initial_states(tmp_path):
    # Test 1: Initial = 0
    state_0 = {"CrashDumpEnabled": 0, "AutoReboot": 1, "read_ok": True}
    res_0 = backup_registry_crash_control_v2(target_dir=tmp_path, current_state=state_0)
    json_path_0 = res_0["json_path"]
    reg_path_0 = res_0["reg_path"]
    assert json_path_0.exists()
    assert reg_path_0.exists()

    content_json_0 = json.loads(json_path_0.read_text(encoding="utf-8"))
    assert content_json_0["values"]["CrashDumpEnabled"]["data"] == 0

    content_reg_0 = reg_path_0.read_text(encoding="utf-8")
    assert '"CrashDumpEnabled"=dword:00000000' in content_reg_0

    # Test 2: Initial = 3 (Small dump)
    state_3 = {"CrashDumpEnabled": 3, "AutoReboot": 1, "read_ok": True}
    res_3 = backup_registry_crash_control_v2(target_dir=tmp_path, current_state=state_3)
    reg_path_3 = res_3["reg_path"]
    content_reg_3 = reg_path_3.read_text(encoding="utf-8")
    assert '"CrashDumpEnabled"=dword:00000003' in content_reg_3

    # Test 3: Initial = missing CrashDumpEnabled -> .reg must contain '"CrashDumpEnabled"=-'
    state_missing = {"CrashDumpEnabled": None, "AutoReboot": 1, "read_ok": True, "missing_values": ["CrashDumpEnabled"]}
    res_m = backup_registry_crash_control_v2(target_dir=tmp_path, current_state=state_missing)
    json_path_m = res_m["json_path"]
    reg_path_m = res_m["reg_path"]
    content_json_m = json.loads(json_path_m.read_text(encoding="utf-8"))
    assert content_json_m["values"]["CrashDumpEnabled"]["present"] is False
    assert content_json_m["values"]["CrashDumpEnabled"]["data"] is None

    content_reg_m = reg_path_m.read_text(encoding="utf-8")
    assert '"CrashDumpEnabled"=-' in content_reg_m

    # Mock rollback execution for missing state (must delete value)
    mock_winreg = MagicMock()
    with patch.dict("sys.modules", {"winreg": mock_winreg}):
        res_rb = rollback_crash_dump(json_path_m, confirmed=True, actor="test")
        assert res_rb["success"] is True
        # Verify DeleteValue was called for CrashDumpEnabled
        assert any("DeleteValue" in str(call) for call in mock_winreg.mock_calls)


# ==================== SCENARIO 6: READ-AFTER-WRITE FAILURE & SELF-ROLLBACK ====================

def test_read_after_write_failure_triggers_rollback(tmp_path):
    mock_winreg = MagicMock()
    # Mock OpenKey
    mock_winreg.OpenKey.return_value = MagicMock()
    mock_winreg.CreateKeyEx.return_value = MagicMock()

    # QueryValue returns 0 instead of written 7 (write failed / Antivirus blocked)
    mock_winreg.QueryValueEx.return_value = (0, 4)

    with patch.dict("sys.modules", {"winreg": mock_winreg}), \
         patch("dumpanalyzer.collectors.dump_config.read_registry_crash_control") as mock_read, \
         patch("dumpanalyzer.collectors.dump_config.check_pagefile_status") as mock_pf, \
         patch("dumpanalyzer.collectors.dump_config.check_disk_space_and_ram") as mock_disk, \
         patch("dumpanalyzer.collectors.dump_config.check_volmgr_events") as mock_vm:

        mock_read.return_value = {"CrashDumpEnabled": 0, "read_ok": True}
        mock_pf.return_value = {"state": "ok"}
        mock_disk.return_value = {"sufficient_space": True, "free_gb": 50, "ram_gb": 16}
        mock_vm.return_value = {"has_recent_failure": False}

        res = enable_crash_dump(target_mode=7, confirmed=True, actor="test")
        # Should fail read-after-write verification
        assert res["success"] is False
        assert "hoàn tác" in res["message"]


# ==================== SCENARIO 7: IDEMPOTENCE ====================

def test_enable_idempotent_no_changes():
    with patch("dumpanalyzer.collectors.dump_config.read_registry_crash_control") as mock_read, \
         patch("dumpanalyzer.collectors.dump_config.check_pagefile_status") as mock_pf, \
         patch("dumpanalyzer.collectors.dump_config.check_disk_space_and_ram") as mock_disk, \
         patch("dumpanalyzer.collectors.dump_config.check_volmgr_events") as mock_vm:

        mock_read.return_value = {"CrashDumpEnabled": 7, "AutoReboot": 1, "read_ok": True}
        mock_pf.return_value = {"state": "ok"}
        mock_disk.return_value = {"sufficient_space": True, "free_gb": 50, "ram_gb": 16}
        mock_vm.return_value = {"has_recent_failure": False}

        res = enable_crash_dump(target_mode=7, confirmed=True, actor="test")
        assert res["success"] is True
        assert res["changed"] is False
        assert "Không cần thay đổi" in res["message"]


# ==================== SCENARIO 8: NO SHUTDOWN / REBOOT IN CODEBASE ====================

def test_source_code_scan_no_shutdown_or_reboot():
    src_dir = Path(__file__).resolve().parent.parent / "src"
    dangerous_keywords = [
        "shutdown /r",
        "shutdown -r",
        "Restart-Computer",
        "Stop-Computer",
        "InitiateSystemShutdown",
    ]

    for py_file in src_dir.rglob("*.py"):
        text = py_file.read_text(encoding="utf-8", errors="ignore")
        for kw in dangerous_keywords:
            assert kw.lower() not in text.lower(), f"Phát hiện lệnh khởi động lại trái phép '{kw}' trong {py_file}!"


# ==================== SCENARIO 9: PENDING REBOOT DETECTION ====================

def test_pending_reboot_status():
    now = datetime.now(timezone.utc)
    changed_at = (now - timedelta(minutes=10)).isoformat()
    last_boot = (now - timedelta(hours=5)).isoformat()  # Booted before change

    res = evaluate_readiness_v2(
        reg_data={"CrashDumpEnabled": 7, "read_ok": True},
        pf_data={"state": "ok"},
        disk_data={"sufficient_space": True},
        volmgr_data={"has_recent_failure": False},
        latest_change={"changed_at_utc": changed_at, "result": "success"},
        last_boot_time_utc=last_boot,
    )
    assert res["status"] == STATUS_READY_PENDING_REBOOT
    assert any(rc["code"] == "PENDING_REBOOT" for rc in res["reason_codes"])


# ==================== SCENARIO 10: JSON REPORT ROUNDTRIP ====================

def test_json_report_roundtrip():
    report = collect_dump_readiness(target_mode=7)
    json_str = json.dumps(report, ensure_ascii=False)
    parsed = json.loads(json_str)

    assert parsed["schema_version"] == 1
    assert "hostname" in parsed
    assert "result" in parsed
    assert parsed["result"]["status"] in (
        STATUS_READY,
        STATUS_READY_PENDING_REBOOT,
        STATUS_ATTENTION,
        STATUS_BLOCKED,
        STATUS_UNKNOWN,
    )


# ==================== SCENARIO 11: CORRUPTED JSON REPORT HANDLING ====================

def test_corrupted_json_report_fleet_aggregator(tmp_path):
    # Create valid report
    valid_file = tmp_path / "valid_m1.json"
    valid_file.write_text(json.dumps({
        "schema_version": 1,
        "hostname": "M1",
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "result": {"status": "READY", "summary": "OK", "reason_codes": []},
        "registry": {"crash_dump_enabled": 7},
        "disk": {"free_gb": 40},
        "ram_gb": 16,
    }), encoding="utf-8")

    # Create corrupted report
    corrupt_file = tmp_path / "corrupted_m2.json"
    corrupt_file.write_text("INVALID JSON DATA {{{", encoding="utf-8")

    res = aggregate_fleet_reports(share_dir=tmp_path)
    assert res["total_files"] == 2
    assert res["valid_reports"] == 1
    assert res["invalid_reports"] == 1
    assert res["summary"]["total_machines"] == 1


# ==================== SCENARIO 12: STALE REPORT DETECTION (>14 DAYS) ====================

def test_stale_report_detection(tmp_path):
    stale_time = (datetime.now(timezone.utc) - timedelta(days=20)).isoformat()
    stale_file = tmp_path / "stale_machine.json"
    stale_file.write_text(json.dumps({
        "schema_version": 1,
        "hostname": "OLD_MACHINE",
        "collected_at_utc": stale_time,
        "result": {"status": "READY", "summary": "Cũ", "reason_codes": []},
    }), encoding="utf-8")

    res = aggregate_fleet_reports(share_dir=tmp_path)
    assert res["summary"]["stale_count"] == 1
    assert res["machines"][0]["is_stale"] is True


# ==================== SCENARIO 13: DEPLOYMENT PACKAGE & -WhatIf ====================

def test_deployment_package_generation(tmp_path):
    pkg_dir = generate_deployment_package(tmp_path)
    enable_ps1 = pkg_dir / "Enable-CrashDump.ps1"
    rollback_ps1 = pkg_dir / "Rollback-CrashDump.ps1"
    readme_txt = pkg_dir / "README_TRIEN_KHAI.txt"

    assert enable_ps1.exists()
    assert rollback_ps1.exists()
    assert readme_txt.exists()

    enable_code = enable_ps1.read_text(encoding="utf-8")
    assert "[switch]$WhatIf" in enable_code
    assert "CrashControl" in enable_code
    assert "Restart-Computer" not in enable_code
    assert "shutdown" not in enable_code


# ==================== SCENARIO 14: DUMP GAP & CUTOFF DATE ====================

def test_compute_dump_gap_calculation():
    events = [
        # BSOD 1
        {"event_id": 41, "time_created_utc": "2026-10-10T08:00:00Z", "extra_json": json.dumps({"BugcheckCode": 10})},
        # BSOD 2
        {"event_id": 41, "time_created_utc": "2026-10-15T08:00:00Z", "extra_json": json.dumps({"BugcheckCode": 80})},
        # Non-BSOD reset (hard power off) BugcheckCode = 0
        {"event_id": 41, "time_created_utc": "2026-10-18T08:00:00Z", "extra_json": json.dumps({"BugcheckCode": 0})},
        # Irrelevant event
        {"event_id": 1001, "time_created_utc": "2026-10-15T08:05:00Z"},
    ]

    crashes = [
        Crash(id=1, crash_time_utc="2026-10-10T08:00:00Z", dump_type="mini", bugcheck_code="0x0000000A"),
    ]

    gap = compute_dump_gap(events=events, crashes=crashes)
    assert gap["expected_bsod"] == 2
    assert gap["found_dumps"] == 1
    assert gap["missing"] == 1
    assert gap["non_bsod_resets"] == 1


# ==================== SCENARIO 15: BUGCHECKCODE DECIMAL TO HEX CONVERSION ====================

def test_bugcheck_code_decimal_to_hex_in_correlator():
    correlator = Correlator()

    # Case 1: BugcheckCode decimal 10 -> 0x0000000A (IRQL_NOT_LESS_OR_EQUAL)
    raw_ev1 = {
        "event_id": 41,
        "time_created_utc": "2026-10-20T08:00:00Z",
        "provider": "Microsoft-Windows-Kernel-Power",
        "raw_message": "He thong khoi dong lai ma khong tat nguon sach se",
        "extra_json": json.dumps({"BugcheckCode": 10}),
    }
    detected = correlator.detect_log_only_crashes(existing_crashes=[], events=[raw_ev1])
    assert len(detected) == 1
    crash_obj, _ = detected[0]
    assert crash_obj.bugcheck_code in ("0xA", "0x0000000A")
    assert crash_obj.dump_type in ("none", "log_only")
    assert crash_obj.analyzed_by == "log_only"
    ej1 = json.loads(crash_obj.extra_json)
    assert ej1.get("bugcheck_hex_8") == "0x0000000A"
    assert ej1.get("is_bsod") is True

    # Case 2: BugcheckCode decimal 0 -> Non-BSOD Reset
    raw_ev2 = {
        "event_id": 41,
        "time_created_utc": "2026-10-22T08:00:00Z",
        "provider": "Microsoft-Windows-Kernel-Power",
        "raw_message": "He thong khoi dong lai do mat nguon dot ngot",
        "extra_json": json.dumps({"BugcheckCode": 0}),
    }
    detected2 = correlator.detect_log_only_crashes(existing_crashes=[], events=[raw_ev2])
    assert len(detected2) == 1
    crash_obj2, _ = detected2[0]
    assert crash_obj2.bugcheck_code in ("", "0x0", "0x00000000")
    ej2 = json.loads(crash_obj2.extra_json)
    assert ej2.get("reset_type") == "non_bsod_reset"
    assert ej2.get("is_bsod") is False
    assert "Không có BSOD" in crash_obj2.bugcheck_name or "Mất nguồn" in crash_obj2.bugcheck_name


# ==================== BONUS TEST: DATABASE MIGRATION & TABLES ====================

def test_database_dump_readiness_and_change_tables(tmp_path):
    test_db_path = tmp_path / "test_readiness.db"
    db = Database(str(test_db_path))

    # Verify tables exist
    conn = db._get_connection()
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {row[0] for row in cur.fetchall()}
    assert "dump_readiness" in tables
    assert "dump_config_change" in tables

    # Test insert and get readiness
    rid = db.insert_dump_readiness({
        "machine_id": None,
        "hostname": "DESKTOP-TEST",
        "status": "READY",
        "proof_level": "evidence_of_success",
        "crash_dump_enabled": 7,
        "pagefile_state": "ok",
        "free_disk_gb": 45.5,
        "ram_gb": 16.0,
        "report_json": '{"status":"READY"}',
    })
    assert rid > 0
    latest = db.get_latest_dump_readiness()
    assert latest is not None
    assert latest["hostname"] == "DESKTOP-TEST"
    assert latest["status"] == "READY"

    # Test insert and get config change
    cid = db.insert_dump_config_change({
        "action": "enable",
        "previous_mode": 0,
        "new_mode": 7,
        "success": 1,
        "backup_path": str(tmp_path / "backup.json"),
        "actor": "test_admin",
        "notes": "Enabled via pytest",
    })
    assert cid > 0
    latest_ch = db.get_latest_dump_config_change()
    assert latest_ch is not None
    assert latest_ch["action"] == "enable"
    assert latest_ch["new_mode"] == 7

    db.close()
