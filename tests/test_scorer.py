"""
Kiểm thử toàn diện thuật toán chấm điểm (Scorer) cho cả crash đơn lẻ và tổng thể máy.
Kiểm tra các trần độ tin cậy, quy tắc đồng thuận 1.5x, phân biệt nạn nhân vs thủ phạm,
mẫu hình patterns.yaml, phát hiện mâu thuẫn và trọng số log_only.
"""

import pytest
from dumpanalyzer.core.models import Crash, Evidence
from dumpanalyzer.engine.rule_loader import load_all_rules
from dumpanalyzer.core.config import load_settings
from dumpanalyzer.engine.scorer import score_single_crash, score_machine_crashes


@pytest.fixture
def rules():
    return load_all_rules()


@pytest.fixture
def settings():
    return load_settings()


def test_single_crash_confidence_cap_medium(rules, settings):
    """
    Quy tắc handoff: Trường hợp chỉ có 1 crash, dù điểm số rất cao (>= 70),
    độ tin cậy tối đa chỉ được xếp loại là 'trung bình'.
    """
    crash = Crash(
        id=1,
        dump_type="mini",
        bugcheck_code="0x116",
        bugcheck_name="VIDEO_TDR_FAILURE",
        image_name="nvlddmkm.sys",
        analyzed_by="cdb",
    )
    res = score_single_crash(crash, [], rules, settings)
    assert res["top_suspect"] == "gpu"
    assert res["top_score"] >= 70.0
    # Điểm cao (>=70) nhưng độ tin cậy bị trần ở mức 'trung bình' vì chỉ có 1 crash
    assert res["confidence"] == "trung bình"
    assert "Trần 1 crash" in res["applied_caps"]



def test_header_only_confidence_cap_medium(rules, settings):
    """Quy tắc UPDATE_01: header_only có độ tin cậy tối đa 'trung bình'."""
    crash = Crash(
        id=2,
        dump_type="mini",
        bugcheck_code="0x116",
        bugcheck_name="VIDEO_TDR_FAILURE",
        analyzed_by="header_only",
    )
    res = score_single_crash(crash, [], rules, settings)
    assert res["top_suspect"] == "gpu"
    assert res["confidence"] == "trung bình"


def test_log_only_confidence_caps(rules, settings):
    """
    Kiểm tra các trần độ tin cậy cho crash log_only theo UPDATE_01 mục D:
    1. BugcheckCode khác 0 CÓ event hỗ trợ -> tối đa 'trung bình'
    2. BugcheckCode khác 0 KHÔNG CÓ event hỗ trợ -> tối đa 'thấp'
    3. BugcheckCode = 0 (mất nguồn/treo cứng) -> tối đa 'thấp'
    """
    # 1. Có event hỗ trợ: Event Display 4101 hỗ trợ GPU 0x116
    crash_with_ev = Crash(
        id=3,
        dump_type="none",
        bugcheck_code="0x116",
        analyzed_by="log_only",
    )
    ev_disp = Evidence(
        id=101,
        crash_id=3,
        kind="eventlog",
        source="Display",
        event_id=4101,
        summary="Driver card đồ hoạ bị treo",
    )
    res1 = score_single_crash(crash_with_ev, [ev_disp], rules, settings)
    assert res1["confidence"] == "trung bình"
    assert res1["top_suspect"] == "gpu"

    # 2. Không có event hỗ trợ
    crash_no_ev = Crash(
        id=4,
        dump_type="none",
        bugcheck_code="0x116",
        analyzed_by="log_only",
    )
    res2 = score_single_crash(crash_no_ev, [], rules, settings)
    assert res2["confidence"] == "thấp"
    assert "không có event hỗ trợ" in res2["applied_caps"]

    # 3. BugcheckCode = 0 (mất nguồn / treo cứng)
    crash_kp41_zero = Crash(
        id=5,
        dump_type="none",
        bugcheck_code="0x0",
        analyzed_by="log_only",
    )
    res3 = score_single_crash(crash_kp41_zero, [], rules, settings)
    assert res3["confidence"] == "thấp"
    assert res3["top_suspect"] in ("psu", "thermal")
    assert "BugcheckCode=0" in res3["applied_caps"]


def test_log_only_no_specific_driver_blamed(rules, settings):
    """
    Quy tắc UPDATE_01 mục A.3: Không bao giờ kết luận một driver cụ thể là thủ phạm
    khi chỉ có log. Chỉ được nêu nhóm thiết bị.
    """
    crash_log = Crash(
        id=6,
        dump_type="none",
        bugcheck_code="0xD1",
        image_name="some_random_driver.sys",  # có thể có chuỗi rác
        analyzed_by="log_only",
    )
    res = score_single_crash(crash_log, [], rules, settings)
    # Không được chứa tiền tố driver:some_random_driver.sys
    assert not any(s.startswith("driver:") for s, _ in res["suspect_scores"])
    assert res["top_suspect"] in ("driver", "network", "ram")


def test_consensus_factor_1_5(rules, settings):
    """
    Quy tắc handoff mục 6.4: Event cùng nhóm với giả thuyết từ dump được nhân hệ số 1.5 (đồng thuận).
    """
    crash = Crash(
        id=7,
        dump_type="mini",
        bugcheck_code="0x124",
        analyzed_by="cdb",
    )
    # Event WHEA cộng điểm CPU (weight trong yaml là 25)
    ev_whea = Evidence(
        id=201,
        crash_id=7,
        kind="eventlog",
        source="Microsoft-Windows-WHEA-Logger",
        event_id=18,
    )
    # Chạy không có event
    res_no_ev = score_single_crash(crash, [], rules, settings)
    # Chạy có event WHEA (cùng nhóm CPU)
    res_ev = score_single_crash(crash, [ev_whea], rules, settings)

    cpu_score_no_ev = dict(res_no_ev["suspect_scores"]).get("cpu", 0)
    cpu_score_ev = dict(res_ev["suspect_scores"]).get("cpu", 0)
    assert cpu_score_ev > cpu_score_no_ev
    assert 201 in res_ev["used_evidence_ids"]


def test_ms_core_module_not_blamed_and_third_party_found(rules, settings):
    """
    Quy tắc kỹ thuật: Module Microsoft (ntoskrnl.exe) KHÔNG phải thủ phạm.
    Nếu có driver bên thứ ba trong stack (klif.sys), driver đó phải được quy trách nhiệm.
    """
    crash = Crash(
        id=8,
        dump_type="mini",
        bugcheck_code="0x1A",
        image_name="ntoskrnl.exe",
        module_name="ntoskrnl.exe",
        cdb_raw_output="STACK_TEXT:\nfffff000`00000000 nt!KeBugCheckEx\nfffff000`00000010 klif+0x1234\nDriver nghi vấn trong stack: klif.sys\n",
        analyzed_by="cdb",
    )
    res = score_single_crash(crash, [], rules, settings)
    # Phải có điểm cho driver:klif.sys hoặc driver
    assert any("klif.sys" in s for s, _ in res["suspect_scores"])
    assert not any("ntoskrnl.exe" in s for s, _ in res["suspect_scores"])


def test_multiple_dumps_same_driver_can_reach_high_confidence(rules, settings):
    """
    Nhiều crash (>= 3) cùng lặp lại driver bên thứ ba (nvlddmkm.sys):
    Thưởng lặp lại kích hoạt, độ tin cậy có thể đạt 'cao'.
    """
    crashes = []
    for i in range(1, 4):
        c = Crash(
            id=i,
            dump_type="mini",
            bugcheck_code="0x116",
            image_name="nvlddmkm.sys",
            analyzed_by="cdb",
        )
        crashes.append((c, []))

    res = score_machine_crashes(crashes, rules, settings)
    assert res["top_suspect"] == "gpu"
    assert res["top_score"] >= 70.0
    assert res["confidence"] == "cao"
    assert "Cùng một driver bên thứ ba lặp lại nhiều lần" in res["patterns_matched"]


def test_multiple_dumps_different_ms_modules_hardware_pattern(rules, settings):
    """
    Mẫu hình patterns.yaml: Module khác nhau mỗi lần, toàn module Microsoft
    -> Nhận diện dấu hiệu phần cứng RAM/PSU/thermal.
    """
    c1 = Crash(id=1, dump_type="mini", bugcheck_code="0x1A", image_name="ntoskrnl.exe", analyzed_by="cdb")
    c2 = Crash(id=2, dump_type="mini", bugcheck_code="0x50", image_name="win32kbase.sys", analyzed_by="cdb")
    c3 = Crash(id=3, dump_type="mini", bugcheck_code="0x3B", image_name="fltmgr.sys", analyzed_by="cdb")

    crashes = [(c1, []), (c2, []), (c3, [])]
    res = score_machine_crashes(crashes, rules, settings)
    assert "Module lỗi thay đổi liên tục, toàn module Microsoft" in res["patterns_matched"]
    assert res["top_suspect"] in ("ram", "psu", "thermal")


def test_conflict_detection(rules, settings):
    """
    Phát hiện mâu thuẫn: Dump chỉ một hướng (GPU), Event log chỉ hướng khác (Storage),
    chênh lệch điểm < 15 -> Gắn cờ is_conflicted = True.
    """
    # Crash 1 và Crash 2: Dump chỉ rõ RAM do MEMORY_MANAGEMENT (0x1A), nhưng có Event Disk 11 (Storage)
    c1 = Crash(id=1, dump_type="mini", bugcheck_code="0x1A", analyzed_by="cdb")
    c2 = Crash(id=2, dump_type="mini", bugcheck_code="0x1A", analyzed_by="cdb")
    ev_disk = Evidence(
        id=301,
        crash_id=1,
        kind="eventlog",
        source="Disk",
        event_id=11,
    )

    crashes = [(c1, [ev_disk]), (c2, [ev_disk])]
    res = score_machine_crashes(crashes, rules, settings)
    # Kiểm tra cờ mâu thuẫn được bật
    assert res["is_conflicted"] is True
    assert "chưa thống nhất" in res["conflict_note"].lower()
