"""Tests hồi quy cho Nhóm D theo ĐỢT CẬP NHẬT 02.
Kiểm tra:
1. Ước tính giờ sập cho crash log_only:
   - Dữ liệu mock: WHEA lúc 03:00:00Z, sự kiện cuối trước khi sập lúc 03:01:00Z,
     Event 6005 lúc 03:12:00Z, Event 41 lúc 03:12:00Z.
   - crash_time_source phải là 'estimated'.
   - crash_time_utc phải là 03:01:00Z.
   - Bằng chứng (evidences) của crash PHẢI chứa sự kiện WHEA lúc 03:00:00Z.
2. Event 6008 cung cấp thời gian sập -> crash_time_source = 'eventlog_6008'.
3. Khi không có sự kiện trước sập -> crash_time_source = 'kp41'.
"""

from dumpanalyzer.engine.correlator import Correlator


def test_d1_estimate_crash_time_and_correlate_whea():
    """WHEA lúc 03:00, sự kiện cuối 03:01, Event 41 lúc 03:12 -> WHEA phải được gom vào Evidence."""
    correlator = Correlator(window_minutes=10)

    events = [
        {
            "provider": "Microsoft-Windows-WHEA-Logger",
            "event_id": 18,
            "time_created_utc": "2026-10-29T03:00:00Z",
            "raw_message": "Fatal hardware error",
            "event_data": {},
        },
        {
            "provider": "Disk",
            "event_id": 7,
            "time_created_utc": "2026-10-29T03:01:00Z",
            "raw_message": "The device has a bad block",
            "event_data": {},
        },
        {
            "provider": "EventLog",
            "event_id": 6005,
            "time_created_utc": "2026-10-29T03:12:00Z",
            "raw_message": "The Event log service was started.",
            "event_data": {},
        },
        {
            "provider": "Microsoft-Windows-Kernel-Power",
            "event_id": 41,
            "time_created_utc": "2026-10-29T03:12:00Z",
            "raw_message": "The system has rebooted without cleanly shutting down first.",
            "kp41_info": {"bugcheck_code": "0x0"},
        },
    ]

    detected = correlator.detect_log_only_crashes(existing_crashes=[], all_events=events)
    assert len(detected) == 1
    crash, matched_events = detected[0]

    # Kiểm tra nguồn thời gian và thời điểm sập ước lượng
    assert crash.crash_time_source == "estimated"
    assert crash.crash_time_utc == "2026-10-29T03:01:00Z"

    # Correlate events: WHEA lúc 03:00 (11 phút trước Event 41 nhưng chỉ 1 phút trước giờ sập thật)
    evidences = correlator.correlate_events_to_crash(crash, events)
    whea_evs = [ev for ev in evidences if ev.source == "Microsoft-Windows-WHEA-Logger"]
    assert len(whea_evs) >= 1
    assert whea_evs[0].event_id == 18


def test_d2_event_6008_crash_time():
    """Event 6008 có timestamp shutdown -> crash_time_source = 'eventlog_6008'."""
    correlator = Correlator(window_minutes=10)

    events = [
        {
            "provider": "EventLog",
            "event_id": 6008,
            "time_created_utc": "2026-10-29T03:12:00Z",
            "raw_message": "The previous system shutdown at 03:02:00Z was unexpected.",
            "event_data": {"ShutdownTime": "2026-10-29T03:02:00Z"},
        },
        {
            "provider": "Microsoft-Windows-Kernel-Power",
            "event_id": 41,
            "time_created_utc": "2026-10-29T03:12:00Z",
            "raw_message": "Reboot without clean shutdown",
            "kp41_info": {"bugcheck_code": "0x0"},
        },
    ]

    detected = correlator.detect_log_only_crashes(existing_crashes=[], all_events=events)
    assert len(detected) == 1
    crash, _ = detected[0]
    assert crash.crash_time_source == "eventlog_6008"
    assert crash.crash_time_utc == "2026-10-29T03:02:00Z"


def test_d3_fallback_kp41():
    """Khi không có Event 6008 và không có sự kiện nào trước sập -> fallback kp41."""
    correlator = Correlator(window_minutes=10)

    events = [
        {
            "provider": "Microsoft-Windows-Kernel-Power",
            "event_id": 41,
            "time_created_utc": "2026-10-29T03:12:00Z",
            "raw_message": "Reboot without clean shutdown",
            "kp41_info": {"bugcheck_code": "0x0"},
        },
    ]

    detected = correlator.detect_log_only_crashes(existing_crashes=[], all_events=events)
    assert len(detected) == 1
    crash, _ = detected[0]
    assert crash.crash_time_source == "kp41"
    assert crash.crash_time_utc == "2026-10-29T03:12:00Z"

