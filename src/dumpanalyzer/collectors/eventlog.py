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
from datetime import datetime
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
    "Microsoft-Windows-Kernel-PnP": [219],
    "Kernel-PnP": [219],
    "Microsoft-Windows-CodeIntegrity": [3033, 3063],
    "CodeIntegrity": [3033, 3063],
    "Microsoft-Windows-Kernel-Processor-Power": [37],
    "Kernel-Processor-Power": [37],
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


def is_kernel_bugcheck_1001_provider(provider: str) -> bool:
    """Kiểm tra xem provider của Event 1001 có phải là từ Kernel WER / BugCheck hay không."""
    if not provider:
        return False
    norm = provider.strip().lower()
    valid_exact = {
        "microsoft-windows-wer-systemerrorreporting",
        "wer-systemerrorreporting",
        "bugcheck",
    }
    if norm in valid_exact:
        return True
    if "wer-systemerrorreporting" in norm or "bugcheck" in norm:
        return True
    return False


def parse_bugcheck_1001_message(
    message: str = "",
    event_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Trích xuất mã lỗi và đường dẫn dump từ Event 1001:
    - Đọc từ EventData (param1, param2...) không phụ thuộc ngôn ngữ Windows.
    - Dự phòng bằng regex trên nội dung raw_message tiếng Anh.
    """
    res = {
        "bugcheck_code": "",
        "p1": "0x0",
        "p2": "0x0",
        "p3": "0x0",
        "p4": "0x0",
        "dump_file": "",
    }

    # 1. Thử bóc tách từ event_data trước (độc lập ngôn ngữ)
    if event_data and isinstance(event_data, dict):
        param1 = str(event_data.get("param1", "")).strip()
        if param1:
            # Dạng param1: '0x0000009f (0x3, 0xffffe0, 0xffffd0, 0xffffc0)'
            m_full = re.search(r"(0x[0-9a-fA-F]+)\s*\(([^)]+)\)", param1)
            if m_full:
                raw_code = m_full.group(1)
                try:
                    res["bugcheck_code"] = f"0x{int(raw_code, 16):X}"
                except ValueError:
                    res["bugcheck_code"] = raw_code

                params = [p.strip() for p in m_full.group(2).split(",")]
                if len(params) >= 1:
                    res["p1"] = params[0]
                if len(params) >= 2:
                    res["p2"] = params[1]
                if len(params) >= 3:
                    res["p3"] = params[2]
                if len(params) >= 4:
                    res["p4"] = params[3]
            else:
                m_hex = re.search(r"^(0x[0-9a-fA-F]+)$", param1)
                if m_hex:
                    try:
                        res["bugcheck_code"] = f"0x{int(m_hex.group(1), 16):X}"
                    except ValueError:
                        res["bugcheck_code"] = m_hex.group(1)

        param2 = str(event_data.get("param2", "")).strip()
        if param2 and (".dmp" in param2.lower() or "\\" in param2):
            res["dump_file"] = param2
        else:
            for val in event_data.values():
                val_str = str(val).strip()
                if val_str.lower().endswith(".dmp"):
                    res["dump_file"] = val_str
                    break

    # Nếu đã lấy được bugcheck_code và dump_file từ event_data thì trả về ngay
    if res["bugcheck_code"]:
        return res

    # 2. Phương án dự phòng: Regex trên raw_message (tiếng Anh)
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



from dumpanalyzer.core.config import load_settings


def build_eventlog_script(
    from_date: Optional[Union[str, datetime]] = None,
    to_date: Optional[Union[str, datetime]] = None,
    providers: Optional[List[str]] = None,
    ids: Optional[List[int]] = None,
) -> str:
    """
    Xây dựng câu lệnh PowerShell sử dụng Get-WinEvent -FilterHashtable và ForEach-Object.
    - Đặt [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    - Lọc trực tiếp ProviderName và Id bằng FilterHashtable
    - Sử dụng try/catch để bắt trường hợp không có sự kiện và trả về mảng rỗng []
    """
    from_dt = parse_to_utc(from_date) if from_date else None
    to_dt = parse_to_utc(to_date) if to_date else None

    # Lấy danh sách provider và ID mặc định nếu không truyền
    if providers is None:
        prov_list = list(CURATED_EVENT_PROVIDERS.keys())
    else:
        prov_list = providers

    if ids is None:
        all_ids = set()
        for p_ids in CURATED_EVENT_PROVIDERS.values():
            all_ids.update(p_ids)
        id_list = sorted(all_ids)
    else:
        id_list = ids

    prov_str = ", ".join(f"'{p}'" for p in prov_list)
    id_str = ", ".join(str(i) for i in id_list)

    filter_lines = [
        "    LogName = 'System'",
        f"    ProviderName = @({prov_str})",
        f"    Id = @({id_str})",
    ]
    if from_dt:
        filter_lines.append(f"    StartTime = [datetime]'{from_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}'")
    if to_dt:
        filter_lines.append(f"    EndTime = [datetime]'{to_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}'")

    filter_body = "\n".join(filter_lines)

    ps_script = f"""[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$filter = @{{
{filter_body}
}}

try {{
    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
    $events | ForEach-Object {{
        [PSCustomObject]@{{
            Xml = $_.ToXml()
            Message = $_.Message
        }}
    }} | ConvertTo-Json -Depth 4 -Compress
}} catch {{
    if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound' -or $_.Exception.Message -match 'No events were found') {{
        Write-Output '[]'
        exit 0
    }} else {{
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 1
    }}
}}
"""
    return ps_script


def read_system_events(
    from_date: Optional[Union[str, datetime]] = None,
    to_date: Optional[Union[str, datetime]] = None,
    mock_events: Optional[List[Dict[str, Any]]] = None,
    debug_ps: bool = False,
) -> List[Dict[str, Any]]:
    """
    Thu thập các sự kiện trọng yếu từ Windows System Log trong khoảng thời gian chỉ định.
    Nếu có mock_events (dùng trong unit test / Linux), trả về trực tiếp dữ liệu mock đã xử lý.
    """
    if mock_events is not None:
        return mock_events

    ps_script = build_eventlog_script(from_date=from_date, to_date=to_date)

    if sys.platform != "win32":
        if debug_ps:
            print("\n=== DEBUG POWERSHELL ===")
            print(f"Script:\n{ps_script.strip()}")
            print("Môi trường: non-Windows (chỉ hiển thị script, không thực thi).")
            print("========================\n")
        logger.info("Môi trường non-Windows: Không thể gọi trực tiếp Windows Event Log.")
        return []

    settings = load_settings()
    timeout = int(settings.get("eventlog_timeout_seconds", 120))

    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )

        if debug_ps:
            print("\n=== DEBUG POWERSHELL ===")
            print(f"Script:\n{ps_script.strip()}")
            print(f"ReturnCode: {proc.returncode}")
            print(f"Stderr: {proc.stderr.strip()}")
            print(f"Output (500 chars):\n{proc.stdout[:500]}")
            print("========================\n")

        if proc.returncode != 0:
            err_msg = proc.stderr.strip() or f"Mã lỗi {proc.returncode}"
            logger.warning(f"Lỗi khi thực thi PowerShell đọc Event Log: {err_msg}")
            return []

        raw_json = proc.stdout.strip()
        if not raw_json or raw_json == "[]":
            return []

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
                prov = ev.get("provider", "")
                if is_kernel_bugcheck_1001_provider(prov):
                    ev["wer1001_info"] = parse_bugcheck_1001_message(ev.get("raw_message", ""), ev.get("event_data"))
                else:
                    # Bỏ qua Event 1001 từ Application WER
                    continue


            parsed_events.append(ev)

        # Sắp xếp sự kiện tăng dần theo thời gian (chuỗi UTC ISO)
        parsed_events.sort(key=lambda x: x["time_created_utc"] or "")
        return parsed_events

    except subprocess.TimeoutExpired:
        logger.warning(f"Lệnh PowerShell đọc Event Log bị quá thời gian ({timeout}s).")
        if debug_ps:
            print("\n=== DEBUG POWERSHELL ===")
            print(f"Script:\n{ps_script.strip()}")
            print(f"Lỗi: Quá thời gian chờ ({timeout} giây)")
            print("========================\n")
        return []
    except Exception as e:
        logger.error(f"Lỗi khi đọc Windows Event Log: {e}")
        return []


def read_application_crashes(
    from_date: Optional[Union[str, datetime]] = None,
    to_date: Optional[Union[str, datetime]] = None,
    mock_events: Optional[List[Dict[str, Any]]] = None,
    debug_ps: bool = False,
) -> List[Dict[str, Any]]:
    """
    Thu thập các sự kiện Application Error ID 1000 từ Application log (Phần 1.2).
    Dùng để phát hiện các ứng dụng sập ngẫu nhiên (chỉ báo lỗi bộ nhớ/RAM).
    """
    if mock_events is not None:
        return mock_events

    from_dt = parse_to_utc(from_date) if from_date else None
    to_dt = parse_to_utc(to_date) if to_date else None

    filter_lines = [
        "    LogName = 'Application'",
        "    ProviderName = 'Application Error'",
        "    Id = 1000",
    ]
    if from_dt:
        filter_lines.append(f"    StartTime = [datetime]'{from_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}'")
    if to_dt:
        filter_lines.append(f"    EndTime = [datetime]'{to_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}'")

    filter_body = "\n".join(filter_lines)
    ps_script = f"""[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$filter = @{{
{filter_body}
}}

try {{
    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
    $events | ForEach-Object {{
        [PSCustomObject]@{{
            Xml = $_.ToXml()
            Message = $_.Message
        }}
    }} | ConvertTo-Json -Depth 4 -Compress
}} catch {{
    if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound' -or $_.Exception.Message -match 'No events were found') {{
        Write-Output '[]'
        exit 0
    }} else {{
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 1
    }}
}}
"""
    if sys.platform != "win32":
        if debug_ps:
            print("\n=== DEBUG POWERSHELL APPLICATION LOG ===")
            print(f"Script:\n{ps_script.strip()}")
            print("========================================\n")
        return []

    settings = load_settings()
    timeout = int(settings.get("eventlog_timeout_seconds", 120))

    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        raw_json = proc.stdout.strip()
        if not raw_json or raw_json == "[]":
            return []

        data_list = json.loads(raw_json) if raw_json.startswith("[") or raw_json.startswith("{") else []
        if isinstance(data_list, dict):
            data_list = [data_list]

        parsed = []
        for item in data_list:
            ev = parse_event_xml(item.get("Xml", ""))
            ev["raw_message"] = item.get("Message", "")
            # Trích xuất tên ứng dụng gây lỗi từ EventData (AppName hoặc param1)
            ed = ev.get("event_data", {})
            app_name = ed.get("AppName") or ed.get("param1") or ""
            fault_mod = ed.get("FaultModuleName") or ed.get("param4") or ""
            exc_code = ed.get("ExceptionCode") or ed.get("param7") or ""
            ev["app_crash_info"] = {
                "app_name": str(app_name).strip(),
                "fault_module": str(fault_mod).strip(),
                "exception_code": str(exc_code).strip(),
            }
            parsed.append(ev)

        parsed.sort(key=lambda x: x["time_created_utc"] or "")
        return parsed
    except Exception as e:
        logger.warning(f"Lỗi khi đọc Application Error log: {e}")
        return []


def summarize_app_crashes(app_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Thống kê các vụ sập ứng dụng: đếm số ứng dụng khác nhau bị sập.
    Nếu >= 3 ứng dụng khác nhau bị sập -> gợi ý RAM lỗi (Phần 1.2).
    """
    unique_apps = set()
    crash_records = []
    for ev in app_events:
        info = ev.get("app_crash_info") or {}
        app_name = info.get("app_name", "").strip().lower()
        if not app_name:
            ed = ev.get("event_data", {})
            app_name = str(ed.get("AppName") or ed.get("param1") or "").strip().lower()
        if app_name:
            unique_apps.add(app_name)
            crash_records.append({
                "app": app_name,
                "time_utc": ev.get("time_created_utc"),
                "module": info.get("fault_module", ""),
            })

    return {
        "unique_app_count": len(unique_apps),
        "unique_apps": sorted(unique_apps),
        "total_crashes": len(app_events),
        "is_random_multiapp": len(unique_apps) >= 3,
    }

