"""
Kiểm thử bộ phân tích chuyên sâu Windows Event Log (test_eventlog_analyzer.py).
Bao phủ:
- Phân loại danh mục theo event_categories.yaml
- Che chắn thông tin nhạy cảm (Privacy Redaction)
- Phát hiện đột biến lỗi (Spike Detection)
- Trích xuất ngữ cảnh sự kiện trước sập nguồn (Pre-Crash Context)
- Xây dựng lệnh PowerShell thu thập log theo cấp độ và tệp .evtx
- Xuất báo cáo Excel đa bảng tính (.xlsx)
"""

import openpyxl

from dumpanalyzer.analyzer.eventlog_analyzer import (
    categorize_event,
    redact_sensitive_text,
    detect_event_spikes,
    analyze_pre_crash_contexts,
    build_harvest_script,
    analyze_event_stream,
    export_eventlog_to_excel,
    EventLogItem,
)


def test_categorize_event():
    """Kiểm tra phân loại sự kiện vào đúng danh mục nghiệp vụ."""
    # 1. Sập và khởi động
    cat_id, cat_name = categorize_event("Microsoft-Windows-Kernel-Power", 41)
    assert cat_id == "crash_reboot"
    assert "Sập & Khởi động" in cat_name

    cat_id, _ = categorize_event("EventLog", 6008)
    assert cat_id == "crash_reboot"

    cat_id, _ = categorize_event("Microsoft-Windows-WER-SystemErrorReporting", 1001)
    assert cat_id == "crash_reboot"

    # 2. Phần cứng WHEA
    cat_id, cat_name = categorize_event("Microsoft-Windows-WHEA-Logger", 18)
    assert cat_id == "hardware"
    assert "WHEA" in cat_name

    # 3. Lưu trữ
    cat_id, cat_name = categorize_event("Disk", 7)
    assert cat_id == "storage"
    assert "Lưu trữ" in cat_name

    cat_id, _ = categorize_event("stornvme", 129)
    assert cat_id == "storage"

    # 4. USB & Thiết bị
    cat_id, _ = categorize_event("Microsoft-Windows-Kernel-PnP", 219)
    assert cat_id == "usb_device"

    # 5. Màn hình / GPU
    cat_id, _ = categorize_event("Display", 4101)
    assert cat_id == "display_gpu"

    cat_id, _ = categorize_event("nvlddmkm", 13)
    assert cat_id == "display_gpu"

    # 6. Cập nhật & Cài đặt
    cat_id, _ = categorize_event("Microsoft-Windows-WindowsUpdateClient", 19)
    assert cat_id == "updates_install"

    # 7. Dịch vụ & Ứng dụng
    cat_id, _ = categorize_event("Application Error", 1000)
    assert cat_id == "app_service"

    # 8. Nguồn & Nhiệt độ
    cat_id, _ = categorize_event("Microsoft-Windows-Kernel-Processor-Power", 37)
    assert cat_id == "power_thermal"

    # 9. Nguồn lạ chưa phân loại
    cat_id, cat_name = categorize_event("UnknownCustomAppService", 9999)
    assert cat_id == "other"
    assert "Khác" in cat_name


def test_redact_sensitive_text():
    """Kiểm tra chức năng che thông tin nhạy cảm (User Path, IP, Domain User)."""
    text1 = "Lỗi xảy ra tại file C:\\Users\\NguyenVanA\\Documents\\data.txt khi nạp mô-đun."
    redacted1 = redact_sensitive_text(text1)
    assert "NguyenVanA" not in redacted1
    assert "C:\\Users\\[ANONYMIZED_USER]\\Documents\\data.txt" in redacted1

    text2 = "Kết nối máy chủ cơ sở dữ liệu tại IP 192.168.1.125 bị từ chối truy cập."
    redacted2 = redact_sensitive_text(text2)
    assert "192.168.1.125" not in redacted2
    assert "[IP_REDACTED]" in redacted2

    text3 = "Người dùng CORP_HQ\\it_admin_01 thực hiện yêu cầu khởi động lại máy."
    redacted3 = redact_sensitive_text(text3)
    assert "it_admin_01" not in redacted3
    assert "[DOMAIN]\\[USER_REDACTED]" in redacted3

    # Giữ nguyên các tài khoản hệ thống chuẩn
    text_sys = "Dịch vụ chạy dưới quyền NT AUTHORITY\\SYSTEM đã dừng."
    assert redact_sensitive_text(text_sys) == text_sys


def test_detect_event_spikes():
    """Kiểm tra phát hiện đợt bùng phát lỗi Disk đột biến trong thời gian ngắn."""
    events = [
        EventLogItem(event_id=7, provider="Disk", level=2, time_created_utc="2026-11-10T08:00:10Z"),
        EventLogItem(event_id=7, provider="Disk", level=2, time_created_utc="2026-11-10T08:00:40Z"),
        EventLogItem(event_id=7, provider="Disk", level=2, time_created_utc="2026-11-10T08:01:10Z"),
        EventLogItem(event_id=7, provider="Disk", level=2, time_created_utc="2026-11-10T08:01:50Z"),
        EventLogItem(event_id=7, provider="Disk", level=2, time_created_utc="2026-11-10T08:02:30Z"),
        EventLogItem(event_id=7, provider="Disk", level=2, time_created_utc="2026-11-10T08:03:00Z"),
    ]
    spikes = detect_event_spikes(events, window_minutes=5, threshold=5)
    assert len(spikes) == 1
    assert spikes[0].provider == "Disk"
    assert spikes[0].count == 6
    assert "Bùng phát 6 sự kiện" in spikes[0].description

    # Trường hợp ít hơn ngưỡng threshold -> không có cảnh báo
    few_events = events[:3]
    assert len(detect_event_spikes(few_events, window_minutes=5, threshold=5)) == 0


def test_analyze_pre_crash_contexts():
    """Kiểm tra trích xuất chính xác các lỗi xảy ra trong 15 phút trước lần sập máy."""
    events = [
        # 3 lỗi Disk trước khi sập
        EventLogItem(event_id=7, provider="Disk", category_name="Lưu trữ & Hệ thống tệp", level=2, time_created_utc="2026-11-10T08:10:00Z"),
        EventLogItem(event_id=11, provider="Disk", category_name="Lưu trữ & Hệ thống tệp", level=2, time_created_utc="2026-11-10T08:12:00Z"),
        EventLogItem(event_id=51, provider="Disk", category_name="Lưu trữ & Hệ thống tệp", level=3, time_created_utc="2026-11-10T08:14:00Z"),
        # Sự kiện sập nguồn Kernel-Power 41 lúc 08:15:00
        EventLogItem(
            event_id=41,
            provider="Microsoft-Windows-Kernel-Power",
            level=1,
            time_created_utc="2026-11-10T08:15:00Z",
            extra_info={"kp41": {"bugcheck_code": "0x124"}},
        ),
        # Một lỗi sau khi máy đã sập (không được tính vào tiền sự kiện)
        EventLogItem(event_id=7, provider="Disk", level=2, time_created_utc="2026-11-10T08:25:00Z"),
    ]

    contexts = analyze_pre_crash_contexts(events, window_minutes=15)
    assert len(contexts) == 1
    ctx = contexts[0]
    assert ctx.crash_event_id == 41
    assert "BSOD (0x124)" in ctx.crash_type
    assert len(ctx.preceding_events) == 3
    assert ctx.dominant_category_name == "Lưu trữ & Hệ thống tệp"
    assert "ghi nhận 3 cảnh báo/lỗi" in ctx.summary


def test_build_harvest_script():
    """Kiểm tra xây dựng script PowerShell hợp lệ cho cả log trực tiếp và file .evtx."""
    # 1. Script Live System + Application
    ps_live = build_harvest_script(channels=["System", "Application"], levels=[1, 2, 3], max_events=1000)
    assert "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8" in ps_live
    assert "Get-WinEvent -FilterHashtable $filters -MaxEvents 1000" in ps_live
    assert "LogName = @('System', 'Application')" in ps_live
    assert "Level = @(1, 2, 3)" in ps_live
    assert "ForEach-Object" in ps_live
    assert "ConvertTo-Json -Depth 4 -Compress" in ps_live

    # 2. Script EVTX
    ps_evtx = build_harvest_script(evtx_path="C:\\Dumps\\System.evtx", levels=[1, 2], max_events=500)
    assert "Path = $filePath" in ps_evtx
    assert "Level = @(1, 2)" in ps_evtx
    assert "System.evtx" in ps_evtx


def test_export_eventlog_to_excel(tmp_path):
    """Kiểm tra xuất toàn bộ kết quả phân tích sang file Excel (.xlsx) đa sheet."""
    mock_events = [
        EventLogItem(
            event_id=41,
            provider="Microsoft-Windows-Kernel-Power",
            channel="System",
            level=1,
            level_name="Critical",
            level_label_vi="Nghiêm trọng (Critical)",
            time_created_utc="2026-11-10T10:00:00Z",
            raw_message="Hệ thống đã sập nguồn lúc 10:00:00 cho user C:\\Users\\AdminIT\\AppData.",
            category="crash_reboot",
            category_name="Sập & Khởi động bất thường",
            event_data={"BugcheckCode": "292", "BugcheckParameter1": "0x1"},
            extra_info={"kp41": {"bugcheck_code": "0x124"}},
        ),
        EventLogItem(
            event_id=7,
            provider="Disk",
            channel="System",
            level=2,
            level_name="Error",
            level_label_vi="Lỗi (Error)",
            time_created_utc="2026-11-10T09:55:00Z",
            raw_message="Khối hỏng trên thiết bị \\Device\\Harddisk0\\DR0 tại IP 10.0.0.5.",
            category="storage",
            category_name="Lưu trữ & Hệ thống tệp",
            event_data={"Device": "\\Device\\Harddisk0\\DR0"},
        ),
    ]

    res = analyze_event_stream(
        [e.to_dict() for e in mock_events],
        source_description="Test Mock Stream",
    )
    assert res.total_events == 2
    assert res.level_counts["Critical"] == 1
    assert res.level_counts["Error"] == 1

    out_file = tmp_path / "eventlog_report.xlsx"
    exported_path = export_eventlog_to_excel(res, out_file, redact=True)

    assert exported_path.exists()
    wb = openpyxl.load_workbook(exported_path)
    assert "Tổng quan & Thống kê" in wb.sheetnames
    assert "Danh sách Sự kiện" in wb.sheetnames

    # Kiểm tra tính năng che thông tin nhạy cảm trong sheet chi tiết
    ws_det = wb["Danh sách Sự kiện"]
    found_redacted_user = False
    found_redacted_ip = False
    for row in ws_det.iter_rows(values_only=True):
        msg = str(row[8]) if len(row) > 8 else ""
        if "[ANONYMIZED_USER]" in msg:
            found_redacted_user = True
        if "[IP_REDACTED]" in msg:
            found_redacted_ip = True

    assert found_redacted_user is True
    assert found_redacted_ip is True
