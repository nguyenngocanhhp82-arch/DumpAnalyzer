"""
Kiểm thử bộ tương quan thời gian correlator.
Kiểm tra cửa sổ 10 phút, gộp Event 41 và 1001, xử lý crash log_only và gắn bản cập nhật 7 ngày.
"""

import json
from pathlib import Path
from dumpanalyzer.core.models import Crash
from dumpanalyzer.engine.correlator import Correlator

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def load_fixture_events():
    with open(FIXTURES_DIR / "sample_events.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_correlate_events_within_10_minute_window():
    """Kiểm tra chỉ các sự kiện trong cửa sổ 10 phút trước crash mới được gắn vào evidence."""
    events = load_fixture_events()
    correlator = Correlator(window_minutes=10)

    # Crash tại thời điểm 2026-10-20 10:00:00 UTC
    crash = Crash(
        id=1,
        crash_time_utc="2026-10-20T10:00:00Z",
        bugcheck_code="0x116",
        bugcheck_name="VIDEO_TDR_FAILURE",
    )

    evidences = correlator.correlate_events_to_crash(crash, events)

    # Các sự kiện hợp lệ trong [09:50:00, 10:02:00]:
    # 1. nvlddmkm (09:55:00)
    # 2. Display 4101 (09:58:30)
    # 3. Kernel-Power 41 (10:00:00)
    # 4. WER 1001 (10:01:30)
    # 5. WHEA 18 (09:52:00)
    # Sự kiện Disk 153 (ngày 18/10) PHẢI bị loại trừ khỏi cửa sổ 10 phút của crash này!
    sources = [e.source for e in evidences]
    assert "nvlddmkm" in sources
    assert "Display" in sources
    assert "Microsoft-Windows-WHEA-Logger" in sources
    assert "Disk" not in sources, "Disk event diễn ra 2 ngày trước không được rơi vào cửa sổ 10 phút"


def test_detect_log_only_crashes_and_merge_41_1001():
    """
    Kiểm tra:
    1. Phát hiện sập không có dump (log_only).
    2. Gộp Event 41 và 1001 cùng vụ sập thành 1 Crash duy nhất.
    3. Event 41 mã 0 tạo crash không BSOD (mất nguồn).
    """
    events = load_fixture_events()
    correlator = Correlator(window_minutes=10)

    # Giả sử trong DB chưa có crash dump nào
    existing_crashes = []

    detected = correlator.detect_log_only_crashes(existing_crashes, events)

    # Trong sample_events.json có 2 vụ sập:
    # Vụ 1: 2026-10-20 10:00:00 (Event 41 mã 278 -> 0x116 và Event 1001)
    # Vụ 2: 2026-10-22 14:30:00 (Event 41 mã 0)
    assert len(detected) == 2

    crash1, events1 = detected[0]
    assert crash1.analyzed_by == "log_only"
    assert crash1.dump_type == "none"
    assert crash1.bugcheck_code == "0x116"
    assert crash1.bugcheck_name == "VIDEO_TDR_FAILURE"
    # Đã gộp cả Event 41 và 1001
    e_ids1 = [e["event_id"] for e in events1]
    assert 41 in e_ids1
    assert 1001 in e_ids1

    crash2, events2 = detected[1]
    assert crash2.analyzed_by == "log_only"
    assert crash2.bugcheck_code == ""
    assert "Không có BSOD" in crash2.bugcheck_name


def test_correlate_recent_updates_7_days():
    """Kiểm tra gắn bản cập nhật Windows diễn ra trong vòng 7 ngày trước crash đầu tiên."""
    correlator = Correlator(update_days=7)

    crashes = [
        Crash(id=10, crash_time_utc="2026-10-20T10:00:00Z"),
        Crash(id=11, crash_time_utc="2026-10-22T14:30:00Z"),
    ]

    updates = [
        {
            "hotfix_id": "KB5012345",
            "description": "Security Update",
            "installed_time_utc": "2026-10-15T08:00:00Z",  # 5 ngày trước crash đầu tiên (Hợp lệ)
        },
        {
            "hotfix_id": "KB5099999",
            "description": "Old Update",
            "installed_time_utc": "2026-10-01T08:00:00Z",  # 19 ngày trước crash đầu tiên (Bị loại trừ)
        },
    ]

    evidences = correlator.correlate_recent_updates(crashes, updates)
    assert len(evidences) == 1
    assert evidences[0].crash_id == 10
    assert "KB5012345" in evidences[0].summary
    assert evidences[0].kind == "update"
