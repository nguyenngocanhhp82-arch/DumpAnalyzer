"""
Kiểm thử CdbParser với 10 fixtures output !analyze -v thực tế (không cần cdb.exe).
Kiểm tra khả năng phân tách module bên thứ ba và không coi ntoskrnl là thủ phạm mặc định.
"""

from pathlib import Path
from dumpanalyzer.analyzer.cdb_parser import CdbParser

CDB_OUT_DIR = Path(__file__).resolve().parent / "fixtures" / "cdb_outputs"


def test_parse_whea_0x124():
    """Kiểm tra parse lỗi phần cứng WHEA 0x124 từ cdb."""
    raw = (CDB_OUT_DIR / "whea_0x124.txt").read_text(encoding="utf-8")
    parser = CdbParser()
    res = parser.parse(raw)

    assert res.bugcheck_code == "0x124"
    assert res.bugcheck_name == "WHEA_UNCORRECTABLE_ERROR"
    assert res.p1 == "0x0"
    assert res.p2 == "0xFFFF800012345678"
    assert res.p3 == "0xB200000000000000"
    assert res.p4 == "0x175"
    assert res.image_name == "AuthenticAMD.sys"
    assert res.module_name == "AuthenticAMD"
    assert "0x124_AuthenticAMD" in res.failure_bucket_id
    assert res.process_name == "System"
    assert res.uptime_seconds == 2 * 86400 + 4 * 3600 + 15 * 60 + 30


def test_parse_gpu_nvidia_0xd1():
    """Kiểm tra parse lỗi Driver IRQL 0xD1 với driver card đồ hoạ NVIDIA nvlddmkm.sys."""
    raw = (CDB_OUT_DIR / "gpu_nvidia_0xd1.txt").read_text(encoding="utf-8")
    parser = CdbParser()
    res = parser.parse(raw)

    assert res.bugcheck_code == "0xD1"
    assert res.bugcheck_name == "DRIVER_IRQL_NOT_LESS_OR_EQUAL"
    assert res.image_name == "nvlddmkm.sys"
    assert res.suspect_driver == "nvlddmkm.sys"
    assert res.is_ms_culprit is False
    assert "nvlddmkm" in [m.lower() for m in res.third_party_stack_modules]


def test_parse_network_realtek_0xd1():
    """Kiểm tra parse lỗi Driver IRQL 0xD1 với card mạng Realtek rt640x64.sys."""
    raw = (CDB_OUT_DIR / "network_realtek_0xd1.txt").read_text(encoding="utf-8")
    parser = CdbParser()
    res = parser.parse(raw)

    assert res.bugcheck_code == "0xD1"
    assert res.image_name == "rt640x64.sys"
    assert res.suspect_driver == "rt640x64.sys"


def test_parse_mem_management_ms_ntoskrnl_with_antivirus():
    """
    QUY TẮC QUAN TRỌNG:
    IMAGE_NAME là ntoskrnl.exe (nạn nhân), stack chứa driver bên thứ ba klif.sys (Kaspersky).
    Parser KHÔNG ĐƯỢC kết luận ntoskrnl là thủ phạm mà phải tìm ra klif.sys!
    """
    raw = (CDB_OUT_DIR / "mem_management_ms_ntoskrnl_with_antivirus.txt").read_text(encoding="utf-8")
    parser = CdbParser()
    res = parser.parse(raw)

    assert res.bugcheck_code == "0x1A"
    assert res.image_name == "ntoskrnl.exe"
    assert res.is_ms_culprit is True
    # Phải bắt được klif.sys trong stack
    assert any("klif" in m.lower() for m in res.third_party_stack_modules)
    assert "klif" in res.suspect_driver.lower()


def test_parse_dpc_watchdog_ssd_0x133():
    """Kiểm tra parse lỗi DPC Watchdog 0x133 với SSD NVMe stornvme.sys."""
    raw = (CDB_OUT_DIR / "dpc_watchdog_ssd_0x133.txt").read_text(encoding="utf-8")
    parser = CdbParser()
    res = parser.parse(raw)

    assert res.bugcheck_code == "0x133"
    assert res.image_name == "stornvme.sys"
    assert res.p1 == "0x1"
    assert res.p2 == "0x1E00"


def test_parse_pagefault_pure_hardware_0x50():
    """Kiểm tra lỗi Page Fault 0x50 thuần tuý phần cứng, stack chỉ toàn module Microsoft."""
    raw = (CDB_OUT_DIR / "pagefault_pure_hardware_0x50.txt").read_text(encoding="utf-8")
    parser = CdbParser()
    res = parser.parse(raw)

    assert res.bugcheck_code == "0x50"
    assert res.image_name == "ntoskrnl.exe"
    assert res.is_ms_culprit is True
    assert len(res.third_party_stack_modules) == 0


def test_parse_missing_fields_no_symbols():
    """Kiểm tra parse output cdb khi thiếu symbol và thiếu trường."""
    raw = (CDB_OUT_DIR / "missing_fields_no_symbols.txt").read_text(encoding="utf-8")
    parser = CdbParser()
    res = parser.parse(raw)

    assert res.symbol_error is True
    assert res.bugcheck_code == "0x3B"
    assert res.image_name == "unknown_image"


def test_parse_kernel_security_audio_0x139():
    """Kiểm tra parse lỗi Kernel Security Check 0x139 với driver âm thanh rtkvhd64.sys."""
    raw = (CDB_OUT_DIR / "kernel_security_audio_0x139.txt").read_text(encoding="utf-8")
    parser = CdbParser()
    res = parser.parse(raw)

    assert res.bugcheck_code == "0x139"
    assert res.image_name == "rtkvhd64.sys"
    assert res.suspect_driver == "rtkvhd64.sys"


def test_parse_complete_output_with_vertarget_time_lm():
    """Kiểm tra parse output đầy đủ phiên bản Windows, thời gian và bảng module lm."""
    raw = (CDB_OUT_DIR / "complete_output_with_vertarget_time_lm.txt").read_text(encoding="utf-8")
    parser = CdbParser()
    res = parser.parse(raw)

    assert res.bugcheck_code == "0x9F"
    assert "Windows 10" in res.windows_version
    assert res.crash_time_utc is not None
    assert "nt" in res.loaded_modules
    assert "pci" in res.loaded_modules


def test_parse_partial_timeout_output():
    """Kiểm tra xử lý mềm khi cdb bị ngắt ngang do timeout."""
    raw = (CDB_OUT_DIR / "partial_timeout_output.txt").read_text(encoding="utf-8")
    parser = CdbParser()
    res = parser.parse(raw)

    assert res.bugcheck_code == "0x133"
    assert res.p1 == "0x1"
    assert res.process_name == "System"
