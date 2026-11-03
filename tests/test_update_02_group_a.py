"""Tests tái hiện các lỗi Nhóm A theo ĐỢT CẬP NHẬT 02 (A1, A2, A3, A4).
Các test này PHẢI FAIL trên code cũ và PASS sau khi sửa.
"""

import pytest
from dumpanalyzer.core.models import Crash, Evidence
from dumpanalyzer.engine.correlator import Correlator
from dumpanalyzer.engine.scorer import score_single_crash, score_machine_crashes
from dumpanalyzer.engine.rule_loader import load_all_rules, validate_event_rules
from dumpanalyzer.core.config import load_settings
from pathlib import Path


def test_a1_whea_event_kind_and_scoring():
    """A1: Sự kiện WHEA phải có kind='eventlog' và tăng điểm CPU cho crash 0x124."""
    correlator = Correlator(window_minutes=10)
    crash_time = "2026-10-29T10:00:00Z"
    crash = Crash(
        id=1,
        dump_type="kernel",
        crash_time_utc=crash_time,
        bugcheck_code="0x124",
        bugcheck_name="WHEA_UNCORRECTABLE_ERROR",
        p1="0x0",
        p2="0xFFFF800012345678",
        p3="0x0",
        p4="0x0",
        analyzed_by="cdb",
    )

    raw_events = [
        {
            "provider": "Microsoft-Windows-WHEA-Logger",
            "event_id": 18,
            "time_created_utc": "2026-10-29T09:55:00Z",
            "raw_message": "A fatal hardware error has occurred. Component: Processor Core",
            "event_data": {"RawData": "1234"},
        }
    ]

    evidences = correlator.correlate_events_to_crash(crash, raw_events)
    assert len(evidences) == 1
    # Bắt buộc kind='eventlog', không phải 'hardware'
    assert evidences[0].kind == "eventlog"

    rules = load_all_rules()
    settings = load_settings()

    # Chấm điểm không có evidence
    score_no_ev = score_single_crash(crash, [], rules, settings)
    cpu_no_ev = dict(score_no_ev["suspect_scores"]).get("cpu", 0.0)

    # Chấm điểm có evidence WHEA ID 18
    score_with_ev = score_single_crash(crash, evidences, rules, settings)
    cpu_with_ev = dict(score_with_ev["suspect_scores"]).get("cpu", 0.0)

    # Điểm cpu khi có WHEA ID 18 PHẢI cao hơn khi không có
    assert cpu_with_ev > cpu_no_ev


def test_a2_cap_in_event_rules():
    """A2: Giá trị cap trong event_rules.yaml phải giới hạn điểm cộng dồn từ cùng một luật."""
    rules = load_all_rules()
    settings = load_settings()

    crash = Crash(
        id=1,
        dump_type="kernel",
        crash_time_utc="2026-10-29T10:00:00Z",
        bugcheck_code="0x1A",
        bugcheck_name="MEMORY_MANAGEMENT",
        analyzed_by="cdb",
    )

    # Tạo 1 sự kiện Disk ID 7
    ev_1 = [
        Evidence(
            id=1,
            crash_id=1,
            kind="eventlog",
            source="Disk",
            event_id=7,
            time_utc="2026-10-29T09:55:00Z",
            summary="Bad block",
        )
    ]

    # Tạo 2 sự kiện Disk ID 7 (25 + 25 = 50 -> cap 40)
    ev_2 = ev_1 + [
        Evidence(
            id=2,
            crash_id=1,
            kind="eventlog",
            source="Disk",
            event_id=7,
            time_utc="2026-10-29T09:56:00Z",
            summary="Bad block",
        )
    ]

    # Tạo 20 sự kiện Disk ID 7 (20 * 25 = 500 -> cap 40)
    ev_20 = [
        Evidence(
            id=i,
            crash_id=1,
            kind="eventlog",
            source="Disk",
            event_id=7,
            time_utc=f"2026-10-29T09:5{i%10}:00Z",
            summary="Bad block",
        )
        for i in range(1, 21)
    ]

    res_1 = score_single_crash(crash, ev_1, rules, settings)
    res_2 = score_single_crash(crash, ev_2, rules, settings)
    res_20 = score_single_crash(crash, ev_20, rules, settings)

    storage_1 = dict(res_1["suspect_scores"]).get("storage", 0.0)
    storage_2 = dict(res_2["suspect_scores"]).get("storage", 0.0)
    storage_20 = dict(res_20["suspect_scores"]).get("storage", 0.0)

    # 2 sự kiện và 20 sự kiện PHẢI cho cùng điểm storage vì đã chạm cap
    assert storage_2 == pytest.approx(storage_20, abs=0.1)
    # 1 sự kiện phải thấp hơn hoặc bằng 2 sự kiện
    assert storage_1 <= storage_2


def test_a2_validate_event_rules_cap():
    """A2: Kiểm tra validate_event_rules kiểm tra trường cap."""
    fake_file = Path("event_rules.yaml")

    # cap <= 0
    bad_data_1 = {
        "events": [
            {"source": "Disk", "ids": [7], "adds": {"storage": 25}, "cap": 0}
        ]
    }
    errs_1 = validate_event_rules(bad_data_1, fake_file)
    assert any("cap" in e.lower() for e in errs_1)

    # cap nhỏ hơn 1 lần cộng của adds
    bad_data_2 = {
        "events": [
            {"source": "Disk", "ids": [7], "adds": {"storage": 25}, "cap": 10}
        ]
    }
    errs_2 = validate_event_rules(bad_data_2, fake_file)
    assert any("cap" in e.lower() for e in errs_2)


def test_a3_correlator_json_import():
    """A3: Kiểm tra sự kiện raw_message rỗng nhưng có event_data không ném NameError."""
    correlator = Correlator(window_minutes=10)
    crash = Crash(
        id=1,
        dump_type="kernel",
        crash_time_utc="2026-10-29T10:00:00Z",
        bugcheck_code="0x124",
    )
    raw_events = [
        {
            "provider": "Disk",
            "event_id": 7,
            "time_created_utc": "2026-10-29T09:55:00Z",
            "raw_message": "",
            "event_data": {"Device": "\\Device\\Harddisk0\\DR0", "Status": "0xC000009C"},
        }
    ]
    evidences = correlator.correlate_events_to_crash(crash, raw_events)
    assert len(evidences) == 1
    assert "Harddisk0" in evidences[0].detail


def test_a4_patterns_conditions():
    """A4: Kiểm tra điều kiện kích hoạt patterns.yaml chính xác."""
    rules = load_all_rules()
    settings = load_settings()

    # Case 1: 3 crash header_only khác mã bug check -> Pattern 1 KHÔNG được kích hoạt
    c1 = Crash(id=1, dump_type="kernel", bugcheck_code="0x1A", analyzed_by="header_only", image_name="")
    c2 = Crash(id=2, dump_type="kernel", bugcheck_code="0x50", analyzed_by="header_only", image_name="")
    c3 = Crash(id=3, dump_type="kernel", bugcheck_code="0x3B", analyzed_by="header_only", image_name="")
    scored_header = score_machine_crashes([(c1, []), (c2, []), (c3, [])], rules, settings)
    assert "Module lỗi thay đổi liên tục, toàn module Microsoft" not in scored_header["patterns_matched"]

    # Case 2: 3 crash cdb với 3 module Microsoft khác nhau -> Pattern 1 PHẢI kích hoạt
    c1_ms = Crash(id=1, dump_type="mini", bugcheck_code="0x1A", analyzed_by="cdb", image_name="ntoskrnl.exe")
    c2_ms = Crash(id=2, dump_type="mini", bugcheck_code="0x50", analyzed_by="cdb", image_name="win32kbase.sys")
    c3_ms = Crash(id=3, dump_type="mini", bugcheck_code="0x3B", analyzed_by="cdb", image_name="fltmgr.sys")
    scored_ms = score_machine_crashes([(c1_ms, []), (c2_ms, []), (c3_ms, [])], rules, settings)
    assert "Module lỗi thay đổi liên tục, toàn module Microsoft" in scored_ms["patterns_matched"]

    # Case 3: Update 10 ngày trước crash đầu tiên (N=7) -> Pattern 3 KHÔNG được kích hoạt
    crash_t = "2026-10-29T10:00:00Z"
    old_update = Evidence(
        id=1,
        crash_id=1,
        kind="update",
        source="WindowsUpdate",
        time_utc="2026-10-15T10:00:00Z",  # 14 ngày trước
        summary="Cập nhật KB5001234",
    )
    c_up = Crash(id=1, dump_type="mini", crash_time_utc=crash_t, bugcheck_code="0x3B", analyzed_by="cdb", image_name="test.sys")
    scored_up_old = score_machine_crashes([(c_up, [old_update])], rules, settings)
    assert "Sự cố bắt đầu xuất hiện sau khi cài bản cập nhật hoặc phần mềm mới" not in scored_up_old["patterns_matched"]

    # Case 4: Mất nguồn có file dump -> Pattern 4 KHÔNG kích hoạt
    c_kp41_dump = Crash(
        id=1,
        dump_type="mini",
        crash_time_utc=crash_t,
        bugcheck_code="0x0",
        analyzed_by="cdb",
        dump_path="C:\\Windows\\Minidump\\01.dmp"
    )
    scored_kp41_dump = score_machine_crashes([(c_kp41_dump, [])], rules, settings)
    assert "Mất nguồn đột ngột không kịp tạo dump (Kernel-Power 41 với BugcheckCode = 0)" not in scored_kp41_dump["patterns_matched"]

    # Case 5: driver_of_module trong driver_map (nvlddmkm.sys) -> cộng điểm cho gpu, không phải 'driver'
    c1_gpu = Crash(id=1, dump_type="mini", bugcheck_code="0x116", analyzed_by="cdb", image_name="nvlddmkm.sys")
    c2_gpu = Crash(id=2, dump_type="mini", bugcheck_code="0x116", analyzed_by="cdb", image_name="nvlddmkm.sys")
    c3_gpu = Crash(id=3, dump_type="mini", bugcheck_code="0x116", analyzed_by="cdb", image_name="nvlddmkm.sys")
    scored_gpu = score_machine_crashes([(c1_gpu, []), (c2_gpu, []), (c3_gpu)], rules, settings)
    assert "Cùng một driver bên thứ ba lặp lại nhiều lần" in scored_gpu["patterns_matched"]
    scores_dict = dict(scored_gpu["suspect_scores"])
    assert scores_dict.get("gpu", 0.0) > scores_dict.get("driver", 0.0)
