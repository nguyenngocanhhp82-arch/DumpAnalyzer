"""
Kiểm thử bộ thu thập và phân tích sự kiện eventlog.
Đặc biệt kiểm tra quy tắc đổi BugcheckCode của Event 41 từ thập phân sang hex (278 -> 0x116),
và nhận diện mã 0 là không có BSOD.
"""

from dumpanalyzer.collectors.eventlog import (
    parse_event_xml,
    parse_kernel_power_41,
    parse_bugcheck_1001_message,
)


def test_parse_event_xml():
    """Kiểm tra phân tích XML Event bóc tách đúng thuộc tính và EventData theo tên."""
    sample_xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-Kernel-Power" />
            <EventID>41</EventID>
            <Level>1</Level>
            <TimeCreated SystemTime="2026-10-20T10:00:00.0000000Z" />
        </System>
        <EventData>
            <Data Name="BugcheckCode">278</Data>
            <Data Name="BugcheckParameter1">0xffff800011111111</Data>
            <Data Name="BugcheckParameter2">0xffff800022222222</Data>
            <Data Name="BugcheckParameter3">0x0</Data>
            <Data Name="BugcheckParameter4">0x2</Data>
            <Data Name="SleepInProgress">0</Data>
            <Data Name="PowerButtonTimestamp">0</Data>
        </EventData>
    </Event>
    """
    res = parse_event_xml(sample_xml)
    assert res["event_id"] == 41
    assert res["provider"] == "Microsoft-Windows-Kernel-Power"
    assert res["time_created_utc"] == "2026-10-20T10:00:00Z"
    assert res["event_data"]["BugcheckCode"] == "278"
    assert res["event_data"]["BugcheckParameter1"] == "0xffff800011111111"


def test_parse_kernel_power_41_decimal_conversion():
    """
    QUY TẮC BẮT BUỘC (UPDATE_01 mục C.1):
    Event 41 BugcheckCode thường là số thập phân (ví dụ 278).
    PHẢI đổi sang hex (0x116) trước khi tra luật.
    """
    data_bsod = {
        "BugcheckCode": "278",
        "BugcheckParameter1": "0xffff800011111111",
        "BugcheckParameter2": "0x2",
        "BugcheckParameter3": "0",
        "BugcheckParameter4": "1",
    }
    kp_info = parse_kernel_power_41(data_bsod)
    assert kp_info["is_bsod"] is True
    assert kp_info["bugcheck_code"] == "0x116"
    assert kp_info["p1"] == "0xFFFF800011111111"
    assert kp_info["p2"] == "0x2"


def test_parse_kernel_power_41_code_zero():
    """
    QUY TẮC BẮT BUỘC (UPDATE_01 mục C.2):
    BugcheckCode = 0 nghĩa là KHÔNG CÓ BSOD (nghi mất nguồn, treo cứng, quá nhiệt).
    """
    data_no_bsod = {
        "BugcheckCode": "0",
        "BugcheckParameter1": "0",
        "BugcheckParameter2": "0",
        "BugcheckParameter3": "0",
        "BugcheckParameter4": "0",
    }
    kp_info = parse_kernel_power_41(data_no_bsod)
    assert kp_info["is_bsod"] is False
    assert kp_info["bugcheck_code"] == "0x0"


def test_parse_bugcheck_1001_message():
    """Kiểm tra trích xuất mã lỗi và đường dẫn dump từ nội dung Event 1001."""
    msg = (
        "The computer has rebooted from a bugcheck. "
        "The bugcheck was: 0x0000001a (0x0000000000041792, 0xfffff00000000000, 0x0000000000000001, 0x0000000000000000). "
        "A dump was saved in: C:\\Windows\\MEMORY.DMP."
    )
    res = parse_bugcheck_1001_message(msg)
    assert res["bugcheck_code"] == "0x1A"
    assert res["p1"] == "0x0000000000041792"
    assert res["dump_file"] == "C:\\Windows\\MEMORY.DMP"
