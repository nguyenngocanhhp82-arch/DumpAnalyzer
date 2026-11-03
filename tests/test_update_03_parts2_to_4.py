"""
Bộ kiểm thử toàn diện cho Đợt Cập Nhật 03 (v1.1.0) - Phần 2, 3 và 4.
Kiểm tra vòng phản hồi, lịch sử máy, phân tích đội máy, tách độ tin cậy,
gợi ý bước tiếp theo và khung plugin kiểm tra phần cứng.
"""

import pytest
from datetime import datetime, timezone, timedelta
from dumpanalyzer.core.models import Crash, Evidence
from dumpanalyzer.storage.db import Database
from dumpanalyzer.engine.fleet import analyze_fleet_crashes, generate_fleet_evidences_for_crash
from dumpanalyzer.engine.scorer import (
    evaluate_confidence,
    compute_event_points,
    score_single_crash,
)
from dumpanalyzer.engine.rule_loader import load_all_rules
from dumpanalyzer.core.config import load_settings
from dumpanalyzer.engine.verdict import generate_crash_finding
from dumpanalyzer.hwtests.base import (
    TestResult as HwTestResult,
    test_result_to_evidence as convert_test_result_to_evidence,
)
from dumpanalyzer.hwtests.storage_health import build_chkdsk_command
from dumpanalyzer.hwtests.windows_memory_diagnostic import WindowsMemoryDiagnosticTest
from dumpanalyzer.hwtests.external_test_import import (
    ExternalTestImport,
    generate_ram_test_guide,
)


# ==============================================================================
# PHẦN 2: FEEDBACK, LỊCH SỬ MÁY & ĐỘI MÁY
# ==============================================================================

def test_feedback_crud_and_stats(tmp_path):
    """Kiểm tra ghi/đọc feedback và tính toán tỷ lệ chính xác (ngưỡng 10 ca)."""
    db_file = tmp_path / "test_feedback.db"
    db = Database(db_file)
    from dumpanalyzer.core.models import MachineInfo
    m_id = db.insert_machine(MachineInfo(hostname="PC-FEEDBACK"))

    # 1. Ban đầu 0 ca
    stats0 = db.get_feedback_stats()
    assert stats0["total_count"] == 0
    assert stats0["sufficient_data"] is False
    assert stats0["accuracy_rate"] is None
    assert "chưa đủ dữ liệu" in stats0["message"]

    # 2. Thêm 5 ca (chưa đủ 10 ca)
    for i in range(5):
        verdict = "dung" if i < 4 else "sai"
        db.add_feedback(
            machine_id=m_id,
            analysis_ref=f"ref_{i}",
            predicted_group="ram",
            predicted_confidence="cao",
            verdict=verdict,
            actual_cause="ram" if verdict == "dung" else "psu",
            note="Test note",
        )

    stats5 = db.get_feedback_stats()
    assert stats5["total_count"] == 5
    assert stats5["sufficient_data"] is False
    assert stats5["accuracy_rate"] is None
    assert "chưa đủ dữ liệu" in stats5["message"]

    # 3. Thêm tiếp 7 ca -> tổng cộng 12 ca (>= 10 ca)
    for i in range(5, 12):
        verdict = "dung" if i < 10 else "sai"
        db.add_feedback(
            machine_id=m_id,
            analysis_ref=f"ref_{i}",
            predicted_group="ram",
            predicted_confidence="cao",
            verdict=verdict,
            actual_cause="ram" if verdict == "dung" else "gpu",
            note="Test note",
        )

    stats12 = db.get_feedback_stats()
    assert stats12["total_count"] == 12
    assert stats12["sufficient_data"] is True
    assert stats12["accuracy_rate"] is not None
    # 4 + 5 = 9 dung; 1 + 2 = 3 sai -> 9/12 = 75.0%
    assert stats12["accuracy_rate"] == 75.0
    assert stats12["verdict_counts"]["dung"] == 9
    assert stats12["verdict_counts"]["sai"] == 3
    assert stats12["by_predicted_group"]["ram"]["total"] == 12


def test_fleet_aggregation_and_evidence_generation(tmp_path):
    """Kiểm tra gom crash đội máy theo bucket_id & suspect_driver, cộng điểm đúng nhóm."""
    db_file = tmp_path / "test_fleet.db"
    db = Database(db_file)
    from dumpanalyzer.core.models import MachineInfo
    now = datetime.now(timezone.utc)

    # Tạo 4 máy
    m_ids = []
    for h in ["PC-ALPHA", "PC-BETA", "PC-GAMMA", "PC-DELTA"]:
        m_ids.append(db.insert_machine(MachineInfo(hostname=h, os_build="22631")))

    # Thêm crash cho 3 máy với cùng 1 suspect_driver 'bad_driver.sys' và cùng bucket 'AV_bad_driver'
    for idx, m_id in enumerate(m_ids[:3]):
        c = Crash(
            machine_id=m_id,
            crash_time_utc=(now - timedelta(days=idx + 1)).isoformat(),
            bugcheck_code="0x3B",
            dump_sha256=f"hash_fleet_{idx}",
            suspect_driver="bad_driver.sys",
            failure_bucket_id="AV_bad_driver!vuln_func",
        )
        db.insert_crash(c)

    # Thêm crash cho máy 4 với driver khác
    c4 = Crash(
        machine_id=m_ids[3],
        crash_time_utc=(now - timedelta(days=2)).isoformat(),
        bugcheck_code="0x124",
        dump_sha256="hash_fleet_other",
        suspect_driver="other_drv.sys",
        failure_bucket_id="WHEA_UNCORRECTABLE",
    )
    db.insert_crash(c4)

    # Phân tích đội máy (ngưỡng min_machines=3)
    fleet_res = analyze_fleet_crashes(db, settings={"fleet_min_machines": 3, "fleet_window_days": 30})
    assert len(fleet_res["fleet_drivers"]) == 1
    assert fleet_res["fleet_drivers"][0]["driver"] == "bad_driver.sys"
    assert fleet_res["fleet_drivers"][0]["machine_count"] == 3

    assert len(fleet_res["fleet_buckets"]) == 1
    assert fleet_res["fleet_buckets"][0]["bucket_id"] == "AV_bad_driver!vuln_func"
    assert fleet_res["fleet_buckets"][0]["machine_count"] == 3

    # Sinh bằng chứng đội máy cho 1 crash
    evs = generate_fleet_evidences_for_crash(
        crash_id=1,
        suspect_driver="bad_driver.sys",
        failure_bucket_id="AV_bad_driver!vuln_func",
        fleet_summary=fleet_res,
    )
    assert len(evs) == 2
    for ev in evs:
        assert ev.kind == "fleet"
        assert ev.strength == "medium"
        assert ev.polarity == "support"
        assert ev.group_id == "fleet_cross_machine"


# ==============================================================================
# PHẦN 3: TÁCH ĐỘ TIN CẬY & GỢI Ý BƯỚC TIẾP THEO
# ==============================================================================

def test_confidence_bugcheck_only_evaluates_to_thap():
    """Chỉ có mã BugCheck đơn lẻ mà không có bằng chứng strong -> độ tin cậy thấp."""
    # BugCheck 0x1A thường chỉ vào RAM với điểm cao
    c = Crash(
        id=1,
        bugcheck_code="0x1A",
        bugcheck_name="MEMORY_MANAGEMENT",
        analyzed_by="header_only",
    )
    evidences = [
        Evidence(
            crash_id=1,
            kind="bugcheck",
            source="0x1A",
            summary="BugCheck 0x1A MEMORY_MANAGEMENT",
            strength="weak",
            polarity="support",
            group_id="bugcheck",
        )
    ]
    scored = score_single_crash(c, evidences, rules=load_all_rules(), settings=load_settings())
    top_group = scored["top_suspect"]
    conf, rationale = evaluate_confidence(top_group, scored["top_score"], evidences)

    assert conf in ("thấp", "thap")
    assert "chưa đủ" in rationale.lower() and "mạnh" in rationale.lower()


def test_confidence_two_strong_different_group_ids_reach_cao():
    """>= 2 bằng chứng strong từ 2 group_id độc lập -> độ tin cậy CAO."""
    evidences = [
        Evidence(
            crash_id=1,
            kind="eventlog",
            source="WHEA Event 18",
            summary="Phần cứng WHEA báo lỗi vi kiến trúc CPU",
            strength="strong",
            polarity="support",
            group_id="whea_event",
        ),
        Evidence(
            crash_id=1,
            kind="cdb",
            source="WinDbg !errrec",
            summary="Thành phần WHEA chỉ điểm Core Cache CPU",
            strength="strong",
            polarity="support",
            group_id="cdb_whea_errrec",
        ),
    ]
    conf, rationale = evaluate_confidence("cpu", 85.0, evidences)
    assert conf == "cao"
    assert "bằng chứng mạnh" in rationale.lower()


def test_confidence_two_strong_same_group_id_caps_at_trung_binh():
    """2 bằng chứng strong nhưng cùng group_id -> chỉ đạt TRUNG BÌNH."""
    evidences = [
        Evidence(
            crash_id=1,
            kind="eventlog",
            source="Disk 7 error 1",
            summary="Khối I/O ổ đĩa bị lỗi",
            strength="strong",
            polarity="support",
            group_id="disk_io_error",
        ),
        Evidence(
            crash_id=1,
            kind="eventlog",
            source="Disk 7 error 2",
            summary="Khối I/O ổ đĩa bị lỗi lặp lại",
            strength="strong",
            polarity="support",
            group_id="disk_io_error",
        ),
    ]
    conf, rationale = evaluate_confidence("storage", 90.0, evidences)
    assert conf == "trung bình"


def test_refute_evidence_reduces_points_and_floors_at_zero():
    """Bằng chứng phản bác (polarity='refute') giảm điểm và không làm điểm bị âm."""
    # Bằng chứng HWTest passed phản bác ram
    evidences = [
        Evidence(
            crash_id=1,
            kind="hwtest",
            source="HWTest: storage_health",
            summary="Kiểm tra ổ đĩa ĐẠT",
            strength="medium",
            polarity="refute",
            group_id="hwtest_storage_health",
        )
    ]
    points, _ = compute_event_points(evidences, rules={})
    # Nhóm storage không bị âm điểm dù bị trừ
    assert points.get("storage", 0.0) == 0.0


def test_next_steps_hints_for_missing_data():
    """Kiểm tra sinh gợi ý hành động tiếp theo theo từng trường hợp thiếu dữ liệu."""
    c = Crash(
        id=1,
        bugcheck_code="0x3B",
        analyzed_by="header_only",  # Thiếu cdb
    )
    rules = load_all_rules()
    scored_res = {"top_suspect": "driver", "top_score": 75.0, "confidence": "thấp"}
    finding = generate_crash_finding(c, scored_res, rules)
    assert finding.next_steps is not None
    steps_text = " ".join(finding.next_steps)
    # Phải có gợi ý cài đặt WinDbg/cdb vì đang chạy header_only
    assert "WinDbg" in steps_text or "cdb" in steps_text
    # Phải có cảnh báo verifier /reset nếu nhắc đến Driver Verifier
    if "Driver Verifier" in steps_text:
        assert "verifier /reset" in steps_text


# ==============================================================================
# PHẦN 4: KHUNG PLUGIN KIỂM TRA PHẦN CỨNG (HWTESTS)
# ==============================================================================

def test_storage_health_command_strictly_rejects_dangerous_flags():
    """Kiểm tra lệnh chkdsk /scan chỉ đọc, chặn tuyệt đối /f, /r, /spotfix."""
    cmd = build_chkdsk_command("C:")
    assert cmd == ["chkdsk", "C:", "/scan"]
    assert "/f" not in cmd
    assert "/r" not in cmd
    assert "/spotfix" not in cmd
    assert "bcdedit" not in cmd

    # Kiểm tra chặn cờ cấm nếu người dùng vô tình truyền vào
    with pytest.raises(ValueError, match="Vi phạm an toàn hệ thống"):
        build_chkdsk_command("C: /f")


def test_windows_memory_diagnostic_event_mapping():
    """Kiểm tra plugin Windows Memory Diagnostic: ID chưa biết -> inconclusive."""
    wmd = WindowsMemoryDiagnosticTest()

    # ID 1101 chuẩn -> passed
    res_passed = wmd.collect_result(
        mock_events=[{"event_id": 1101, "message": "The computer memory was tested and no errors found."}]
    )
    assert res_passed.status == "passed"

    # ID 1102 chuẩn -> failed
    res_failed = wmd.collect_result(
        mock_events=[{"event_id": 1102, "message": "Hardware problems were detected."}]
    )
    assert res_failed.status == "failed"

    # ID 9999 lạ không nằm trong ánh xạ -> inconclusive
    res_unknown = wmd.collect_result(
        mock_events=[{"event_id": 9999, "message": "Unknown memory diagnostic result."}]
    )
    assert res_unknown.status == "inconclusive"
    assert "CHƯA KIỂM CHỨNG" in res_unknown.details or "chưa có trong ánh xạ" in res_unknown.details


def test_external_test_import_rules_and_guide():
    """Kiểm tra đánh giá công cụ ngoài (passes < 4 -> inconclusive) và hướng dẫn MemTest86."""
    ext = ExternalTestImport()

    # 1. Có lỗi -> failed
    res_err = ext.evaluate_external_result(
        tool_name="MemTest86", group="ram", passes=4, errors=2, duration_minutes=120
    )
    assert res_err.status == "failed"
    assert "LỖI" in res_err.details

    # 2. 0 lỗi nhưng chỉ chạy 2 passes (< 4) -> inconclusive
    res_inconcl = ext.evaluate_external_result(
        tool_name="MemTest86", group="ram", passes=2, errors=0, duration_minutes=45
    )
    assert res_inconcl.status == "inconclusive"
    assert "CHƯA ĐỦ ĐỂ KẾT LUẬN" in res_inconcl.details

    # 3. 0 lỗi và chạy >= 4 passes -> passed
    res_pass = ext.evaluate_external_result(
        tool_name="MemTest86", group="ram", passes=4, errors=0, duration_minutes=180
    )
    assert res_pass.status == "passed"

    # 4. Hướng dẫn test RAM
    guide = generate_ram_test_guide()
    assert "MEMTEST86" in guide.upper()
    assert "4 PASSES" in guide.upper()
    assert "USB" in guide.upper()


def test_hwtest_to_evidence_conversion():
    """Kiểm tra quy đổi kết quả test thành Evidence đúng độ mạnh và chiều hướng."""
    # Failed -> strong, support
    res_failed = HwTestResult(status="failed", details="Phát hiện lỗi bad sector")
    ev_failed = convert_test_result_to_evidence("storage_health", "storage", res_failed)
    assert ev_failed is not None
    assert ev_failed.strength == "strong"
    assert ev_failed.polarity == "support"
    assert ev_failed.group_id == "hwtest_storage_health"

    # Passed RAM -> weak, refute (lỗi RAM chập chờn)
    res_ram_pass = HwTestResult(status="passed", details="Không phát hiện lỗi")
    ev_ram = convert_test_result_to_evidence("windows_memory_diagnostic", "ram", res_ram_pass)
    assert ev_ram is not None
    assert ev_ram.strength == "weak"
    assert ev_ram.polarity == "refute"

    # Inconclusive / Pending / Not Run -> Không sinh evidence
    for st in ("inconclusive", "pending", "not_run"):
        assert convert_test_result_to_evidence("storage_health", "storage", HwTestResult(status=st)) is None
