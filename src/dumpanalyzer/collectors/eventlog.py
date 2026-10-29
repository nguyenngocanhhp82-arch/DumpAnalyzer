"""
Module thu thập và phân tích sự kiện từ Windows Event Log (System Log).
Đảm bảo:
- Đọc EventData theo tên trường qua cấu trúc XML, không cắt chuỗi vị trí.
- Xử lý Event 41: BugcheckCode thập phân sang Hex (278 -> 0x116); mã 0 = không có BSOD.
- Xử lý Event 1001: Trích xuất mã lỗi và đường dẫn dump từ nội dung WER.
- Hỗ trợ nạp mock/fixture JSON trên môi trường Linux để kiểm thử không cần Windows thật.
"""

import sys
import json
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from dumpanalyzer.core.timeutil import parse_to_utc, to_utc_iso
from dumpanalyzer.core.logging_setup import get_logger

logger = get_logger("eventlog")

# Danh sách Provider và ID sự kiện trọng yếu cần thu thập
CURATED_EVENT_PROVIDERS = {
    "Microsoft-Windows-Kernel-Power": [41],
    "EventLog": [6008],
    "Microsoft-Windows-WER-SystemErrorReporting": [1001],
    "WER-SystemErrorReporting": [1001],
    "BugCheck": [1001],
    "Microsoft-Windows-WHEA-Logger": [1, 17, 18, 19, 20, 47],
    "Disk": [7, 11, 51, 153],
    "stornvme": [129],
    "storahci": [129],
    "Display": [4101],
    "nvlddmkm": [13, 14],
    "Ntfs": [55],
    "volmgr": [161, 162],
    "Microsoft-Windows-WindowsUpdateClient": [19, 20],
    "WindowsUpdateClient": [19, 20],
    "MsiInstaller": [11707, 1033],
    "User32": [1074],
}


def parse_event_xml(xml_string: str) -> Dict[str, Any]:
    """
    Phân tích một chuỗi XML của Windows Event thành dictionary có cấu trúc.
    Bóc tách System properties và EventData key-value pairs theo tên trường.
    """
    result: Dict[str, Any] = {
        "event_id": 0,
        "provider": "",
        "time_created_utc": None,
        "level": 0,
        "event_data": {},
        "raw_message": "",
    }

    if not xml_string or not xml_string.strip():
        return result

    try:
        # Xoá namespace để dễ dàng bóc tách
        clean_xml = re.sub(r'xmlns="[^"]+"', '', xml_string)
        root = ET.fromstring(clean_xml)

        system = root.find("System")
        if system is not None:
            # EventID
            e_id_elem = system.find("EventID")
            if e_id_elem is not None and e_id_elem.text:
                result["event_id"] = int(e_id_elem.text)

            # Provider
            prov_elem = system.find("Provider")
            if prov_elem is not None:
                result["provider"] = prov_elem.attrib.get("Name", "")

            # TimeCreated
            time_elem = system.find("TimeCreated")
            if time_elem is not None:
                raw_time = time_elem.attrib.get("SystemTime", "")
                result["time_created_utc"] = to_utc_iso(raw_time)

            # Level
            lvl_elem = system.find("Level")
            if lvl_elem is not None and lvl_elem.text:
                result["level"] = int(lvl_elem.text)

        # EventData
        event_data_elem = root.find("EventData")
        if event_data_elem is not None:
            for data_elem in event_data_elem.findall("Data"):
                name = data_elem.attrib.get("Name")
                val = data_elem.text or ""
                if name:
                    result["event_data"][name] = val
                else:
                    # Trường không có thuộc tính Name
                    result["event_data"].setdefault("_unnamed", []).append(val)

    except Exception as e:
        logger.debug(f"Lỗi khi parse Event XML: {e}")

    return result


def parse_kernel_power_41(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Xử lý đặc biệt cho Event 41 (Kernel-Power):
    Trường BugcheckCode thường là số thập phân (ví dụ 278) -> PHẢI đổi sang hex (0x116).
    BugcheckCode = 0 nghĩa là KHÔNG CÓ BSOD (mất nguồn, quá nhiệt hoặc treo cứng).
    """
    raw_code = str(event_data.get("BugcheckCode", "0")).strip()
    try:
        dec_val = int(raw_code)
        if dec_val == 0:
            hex_code = "0x0"
            is_bsod = False
        else:
            hex_code = f"0x{dec_val:X}"
            is_bsod = True
    except ValueError:
        hex_code = raw_code
        is_bsod = hex_code not in ("0", "0x0")

    def _format_param(param_name):
        val = str(event_data.get(param_name, "0")).strip()
        try:
            p_int = int(val, 16) if val.startswith("0x") else int(val)
            return f"0x{p_int:X}"
        except ValueError:
            return val

    return {
        "is_bsod": is_bsod,
        "bugcheck_code": hex_code,
        "p1": _format_param("BugcheckParameter1"),
        "p2": _format_param("BugcheckParameter2"),
        "p3": _format_param("BugcheckParameter3"),
        "p4": _format_param("BugcheckParameter4"),
        "power_button_timestamp": event_data.get("PowerButtonTimestamp", "0"),
        "sleep_in_progress": event_data.get("SleepInProgress", "0"),
    }


def parse_bugcheck_1001_message(message: str) -> Dict[str, Any]:
    """
    Trích xuất mã lỗi và đường dẫn dump từ nội dung mô tả của Event 1001 (WER/BugCheck).
    Ví dụ: 'The computer has rebooted from a bugcheck. The bugcheck was: 0x0000001a... A dump was saved in: C:\\Windows\\MEMORY.DMP'
    """
    res = {
        "bugcheck_code": "",
        "p1": "0x0",
        "p2": "0x0",
        "p3": "0x0",
        "p4": "0x0",
        "dump_file": "",
    }

    if not message:
        return res

    # 1. Tìm mã Bug Check
    m_code = re.search(r"bugcheck was:\s*(0x[0-9a-fA-F]+)", message, re.IGNORECASE)
    if m_code:
        try:
            val = int(m_code.group(1), 16)
            res["bugcheck_code"] = f"0x{val:X}"
        except ValueError:
            res["bugcheck_code"] = m_code.group(1)

    # 2. Tìm tham số (ví dụ: (0x0000000000041792, 0xfffff00000000000...))
    m_params = re.search(r"\((0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+)\)", message)
    if m_params:
        for idx in range(1, 5):
            res[f"p{idx}"] = m_params.group(idx)

    # 3. Tìm đường dẫn file dump
    m_dump = re.search(r"dump was saved in:\s*([^\r\n,]+)", message, re.IGNORECASE)
    if m_dump:
        res["dump_file"] = m_dump.group(1).strip().rstrip(".,")

    return res


def read_system_events(
    from_date: Optional[Union[str, datetime]] = None,
    to_date: Optional[Union[str, datetime]] = None,
    mock_events: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """
    Thu thập các sự kiện trọng yếu từ Windows System Log trong khoảng thời gian chỉ định.
    Nếu có mock_events (dùng trong unit test / Linux), trả về trực tiếp dữ liệu mock đã xử lý.
    """
    if mock_events is not None:
        return mock_events

    if sys.platform != "win32":
        logger.info("Môi trường non-Windows: Không thể gọi trực tiếp Windows Event Log.")
        return []

    from_dt = parse_to_utc(from_date) if from_date else None
    to_dt = parse_to_utc(to_date) if to_date else None

    # Xây dựng lệnh PowerShell truy vấn Get-WinEvent xuất XML
    ps_filter = "@{LogName='System';"
    if from_dt:
        ps_filter += f" StartTime=[datetime]'{from_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}';"
    if to_dt:
        ps_filter += f" EndTime=[datetime]'{to_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}';"
    ps_filter += "}"

    ps_script = f"""
    $events = Get-WinEvent -FilterHashtable {ps_filter} -ErrorAction SilentlyContinue |
        Where-Object {{
            $id = $_.Id
            $prov = $_.ProviderName
            ($id -eq 41 -and $prov -match 'Kernel-Power') -or
            ($id -eq 6008) -or
            ($id -eq 1001) -or
            ($prov -match 'WHEA-Logger') -or
            ($prov -eq 'Disk') -or
            ($prov -eq 'stornvme' -or $prov -eq 'storahci') -or
            ($prov -eq 'Display' -or $prov -eq 'nvlddmkm') -or
            ($prov -eq 'Ntfs') -or
            ($prov -eq 'volmgr') -or
            ($prov -match 'WindowsUpdateClient') -or
            ($prov -eq 'MsiInstaller') -or
            ($id -eq 1074)
        }}
    
    foreach ($e in $events) {{
        [PSCustomObject]@{{
            Xml = $e.ToXml()
            Message = $e.Message
        }}
    }} | ConvertTo-Json -Depth 4
    """

    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            logger.debug(f"PowerShell Get-WinEvent kết thúc với mã {proc.returncode}")
            return []

        raw_json = proc.stdout.strip()
        data_list = json.loads(raw_json) if raw_json.startswith("[") or raw_json.startswith("{") else []
        if isinstance(data_list, dict):
            data_list = [data_list]

        parsed_events = []
        for item in data_list:
            xml_str = item.get("Xml", "")
            ev = parse_event_xml(xml_str)
            ev["raw_message"] = item.get("Message", "")

            # Xử lý đặc biệt nếu là Event 41
            if ev["event_id"] == 41 and "Kernel-Power" in ev["provider"]:
                ev["kp41_info"] = parse_kernel_power_41(ev["event_data"])

            # Xử lý đặc biệt nếu là Event 1001
            elif ev["event_id"] == 1001:
                ev["wer1001_info"] = parse_bugcheck_1001_message(ev["raw_message"])

            parsed_events.append(ev)

        # Sắp xếp sự kiện tăng dần theo thời gian (chuỗi UTC ISO)
        parsed_events.sort(key=lambda x: x["time_created_utc"] or "")
        return parsed_events

    except Exception as e:
        logger.error(f"Lỗi khi đọc Windows Event Log: {e}")
        return []
