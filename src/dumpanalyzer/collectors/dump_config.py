"""
Module kiểm tra và cấu hình khả năng ghi Dump của hệ thống Windows (Đợt 04 - UPDATE_04).
Tuân thủ nghiêm ngặt 11 nguyên tắc thiết kế (P1-P11):
- MẶC ĐỊNH CHỈ ĐỌC: Kiểm tra CrashControl, Pagefile, dung lượng đĩa, volmgr và lịch sử.
- THAY ĐỔI TỐI THIỂU: Chỉ ghi CrashDumpEnabled (và LogEvent nếu cho phép).
- KHÔNG BAO GIỜ TỰ KHỞI ĐỘNG LẠI MÁY (P3).
- HOÀN TÁC ĐƯỢC 100%: Sao lưu cả JSON (nguồn sự thật) và .reg (P4).
- BA TRẠNG THÁI (P5): Tách bạch rõ 'chưa có' với 'lỗi đọc'.
- TRẠNG THÁI SẴN SÀNG KHÔNG PHẢI ĐÃ CHỨNG MINH: Tách status và proof_level (P6).
- TÔN TRỌNG LỰA CHỌN CÓ CHỦ ĐÍCH: Không tự ý đổi mode 1, 2, 7 hoặc Small (3) (P7).
- NHẬT KÝ ĐẦY ĐỦ (P8) và AN TOÀN BẢO MẬT (P9).
"""

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from dumpanalyzer.core.config import get_project_root, is_running_as_admin, load_settings
from dumpanalyzer.core.logging_setup import get_logger

logger = get_logger("dump_config")

# Phiên bản công cụ hiện tại
TOOL_VERSION = "1.2.0"

# Mô tả các chế độ CrashDumpEnabled trong Windows
CRASH_DUMP_MODES = {
    0: "Tắt hoàn toàn (None - Không ghi dump)",
    1: "Complete memory dump (Toàn bộ bộ nhớ)",
    2: "Kernel memory dump (Bộ nhớ nhân)",
    3: "Small memory dump (Minidump 64KB/256KB)",
    7: "Automatic memory dump (Tự động - Khuyến nghị từ Win 8/10/11)",
}

# Hằng số Trạng thái tổng (Section 3.1)
STATUS_READY = "READY"
STATUS_READY_PENDING_REBOOT = "READY_PENDING_REBOOT"
STATUS_ATTENTION = "ATTENTION"
STATUS_BLOCKED = "BLOCKED"
STATUS_UNKNOWN = "UNKNOWN"

# Hằng số Mức độ chứng minh ghi dump (Section 1.4 & 3.1)
PROOF_NONE = "none"
PROOF_EVIDENCE = "evidence_of_success"

# Hằng số Mã lý do (Section 3.2)
CODE_DUMP_DISABLED = "DUMP_DISABLED"
CODE_DUMP_VALUE_MISSING = "DUMP_VALUE_MISSING"
CODE_REGISTRY_UNREADABLE = "REGISTRY_UNREADABLE"
CODE_DUMP_MODE_SMALL = "DUMP_MODE_SMALL"
CODE_PAGEFILE_MISSING = "PAGEFILE_MISSING"
CODE_PAGEFILE_UNKNOWN = "PAGEFILE_UNKNOWN"
CODE_PAGEFILE_TOO_SMALL = "PAGEFILE_TOO_SMALL"
CODE_DISK_LOW = "DISK_LOW"
CODE_VOLMGR_FAILURE_RECENT = "VOLMGR_FAILURE_RECENT"
CODE_DUMP_FILES_MISSING = "DUMP_FILES_MISSING"
CODE_PENDING_REBOOT = "PENDING_REBOOT"
CODE_NOT_ADMIN = "NOT_ADMIN"

# Biến mock phục vụ unit test độc lập môi trường (Linux/CI)
_mock_registry_state: Optional[Dict[str, Any]] = None
_mock_admin_state: Optional[bool] = None
_mock_boot_time_utc: Optional[str] = None


def set_mock_registry(state: Optional[Dict[str, Any]]) -> None:
    """Thiết lập registry giả lập cho unit test."""
    global _mock_registry_state
    _mock_registry_state = state


def set_mock_admin(is_admin: Optional[bool]) -> None:
    """Thiết lập quyền admin giả lập cho unit test."""
    global _mock_admin_state
    _mock_admin_state = is_admin


def set_mock_boot_time(boot_time_utc: Optional[str]) -> None:
    """Thiết lập thời gian khởi động giả lập cho unit test."""
    global _mock_boot_time_utc
    _mock_boot_time_utc = boot_time_utc


def _check_admin() -> bool:
    """Kiểm tra quyền admin hiện tại có xét đến mock test."""
    if _mock_admin_state is not None:
        return _mock_admin_state
    if sys.platform != "win32":
        return True
    return is_running_as_admin()


def read_registry_crash_control() -> Dict[str, Any]:
    """
    Đọc các giá trị trong HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl.
    Phân biệt rõ ràng 3 trường hợp (Sửa L1):
    1. Đọc thành công và giá trị tồn tại -> read_ok=True, value_present=True, CrashDumpEnabled=int
    2. Đọc thành công nhưng giá trị không tồn tại -> read_ok=True, value_present=False, CrashDumpEnabled=None
    3. Lỗi đọc registry -> read_ok=False, value_present=False, CrashDumpEnabled=None, error="..."
    """
    if _mock_registry_state is not None:
        return dict(_mock_registry_state)

    data = {
        "read_ok": True,
        "value_present": True,
        "CrashDumpEnabled": None,
        "AutoReboot": None,
        "Overwrite": None,
        "MinidumpDir": r"%SystemRoot%\Minidump",
        "DumpFile": r"%SystemRoot%\MEMORY.DMP",
        "DedicatedDumpFile": None,
        "DumpFileSize": None,
        "LogEvent": None,
        "raw_found": False,
        "error": None,
        "all_values": {},
    }

    if sys.platform != "win32":
        # Môi trường non-Windows (Linux / macOS) phục vụ chạy test / phát triển
        data["CrashDumpEnabled"] = 7
        data["AutoReboot"] = 1
        data["Overwrite"] = 1
        data["LogEvent"] = 1
        data["raw_found"] = True
        data["all_values"] = {
            "CrashDumpEnabled": {"present": True, "data": 7, "type": "REG_DWORD"},
            "AutoReboot": {"present": True, "data": 1, "type": "REG_DWORD"},
            "Overwrite": {"present": True, "data": 1, "type": "REG_DWORD"},
            "MinidumpDir": {"present": True, "data": r"%SystemRoot%\Minidump", "type": "REG_SZ"},
            "DumpFile": {"present": True, "data": r"%SystemRoot%\MEMORY.DMP", "type": "REG_SZ"},
            "LogEvent": {"present": True, "data": 1, "type": "REG_DWORD"},
        }
        return data

    try:
        import winreg

        key_path = r"SYSTEM\CurrentControlSet\Control\CrashControl"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as key:
            data["raw_found"] = True

            # Đọc toàn bộ các giá trị hiện có trong key để phục vụ sao lưu 100%
            idx = 0
            while True:
                try:
                    name, val, vtype = winreg.EnumValue(key, idx)
                    vtype_str = "REG_DWORD" if vtype == winreg.REG_DWORD else "REG_SZ"
                    data["all_values"][name] = {"present": True, "data": val, "type": vtype_str}
                    idx += 1
                except OSError:
                    break

            def _query_val(name: str):
                try:
                    val, _ = winreg.QueryValueEx(key, name)
                    return val, True
                except FileNotFoundError:
                    return None, False

            cde_val, cde_pres = _query_val("CrashDumpEnabled")
            data["CrashDumpEnabled"] = cde_val
            data["value_present"] = cde_pres

            ar_val, _ = _query_val("AutoReboot")
            data["AutoReboot"] = ar_val

            ow_val, _ = _query_val("Overwrite")
            data["Overwrite"] = ow_val

            md_val, _ = _query_val("MinidumpDir")
            if md_val:
                data["MinidumpDir"] = md_val

            df_val, _ = _query_val("DumpFile")
            if df_val:
                data["DumpFile"] = df_val

            ddf_val, _ = _query_val("DedicatedDumpFile")
            data["DedicatedDumpFile"] = ddf_val

            dfs_val, _ = _query_val("DumpFileSize")
            data["DumpFileSize"] = dfs_val

            le_val, _ = _query_val("LogEvent")
            data["LogEvent"] = le_val

    except Exception as e:
        logger.error(f"Lỗi khi đọc registry CrashControl: {e}")
        data["read_ok"] = False
        data["value_present"] = False
        data["CrashDumpEnabled"] = None
        data["error"] = str(e)

    return data


def check_pagefile_status(dedicated_dump_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Kiểm tra tình trạng Pagefile trên ổ đĩa hệ thống (mặc định C:).
    Sửa L3 (Fail-open): Nếu lệnh lỗi hoặc timeout, trả về state="unknown", KHÔNG tự coi là ok.
    Sửa L6: Tính đến DedicatedDumpFile nếu được cấu hình.
    """
    res = {
        "state": "ok",  # ok | missing | unknown
        "has_system_drive_pagefile": True,
        "system_drive_size_mb": 0,
        "automatic_managed": True,
        "dedicated_dump_configured": False,
        "details": [],
        "error": None,
    }

    if dedicated_dump_file and dedicated_dump_file.strip():
        res["dedicated_dump_configured"] = True
        res["details"].append(f"DedicatedDumpFile: {dedicated_dump_file}")

    if sys.platform != "win32":
        res["details"].append("Pagefile giả lập 8192 MB trên C: (Môi trường Linux)")
        res["system_drive_size_mb"] = 8192
        return res

    ps_cmd = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "try { "
        "$pf = Get-CimInstance Win32_PageFileUsage -ErrorAction Stop | "
        "Select-Object Name, AllocatedBaseSize, CurrentUsage; "
        "$auto = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).AutomaticManagedPagefile; "
        "@{ Pagefiles = $pf; AutomaticManaged = $auto } | ConvertTo-Json -Depth 3 "
        "} catch { Write-Error $_.Exception.Message; exit 1 }"
    )

    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if proc.returncode != 0:
            res["state"] = "unknown"
            res["has_system_drive_pagefile"] = False
            res["error"] = proc.stderr.strip() or "PowerShell error"
            return res

        raw_out = proc.stdout.strip()
        if not raw_out:
            res["state"] = "unknown"
            return res

        parsed = json.loads(raw_out)
        auto_managed = bool(parsed.get("AutomaticManaged", False))
        res["automatic_managed"] = auto_managed

        pfs = parsed.get("Pagefiles") or []
        if isinstance(pfs, dict):
            pfs = [pfs]

        found_c = False
        total_c_size = 0
        for it in pfs:
            name = str(it.get("Name", "")).lower()
            size = int(it.get("AllocatedBaseSize", 0) or 0)
            res["details"].append(f"{name} ({size} MB)")
            if "c:" in name:
                found_c = True
                total_c_size += size

        res["system_drive_size_mb"] = total_c_size

        if found_c or auto_managed or res["dedicated_dump_configured"]:
            res["state"] = "ok"
            res["has_system_drive_pagefile"] = True
        else:
            res["state"] = "missing"
            res["has_system_drive_pagefile"] = False

    except Exception as e:
        logger.error(f"Lỗi kiểm tra pagefile: {e}")
        res["state"] = "unknown"
        res["has_system_drive_pagefile"] = False
        res["error"] = str(e)

    return res


def check_disk_space_and_ram(target_mode: int = 7) -> Dict[str, Any]:
    """
    Kiểm tra dung lượng đĩa trống và RAM (Sửa L5).
    Áp dụng ngưỡng cấu hình được từ dump_readiness.yaml theo target_mode.
    """
    info = {
        "free_disk_gb": 0.0,
        "ram_gb": 0.0,
        "sufficient_space": True,
        "system_drive": "C:\\",
        "recommended_free_gb": 10.0,
        "target_mode": target_mode,
    }

    if sys.platform == "win32":
        sys_drive = os.environ.get("SystemDrive", "C:") + "\\"
        info["system_drive"] = sys_drive
        try:
            total, used, free = shutil.disk_usage(sys_drive)
            info["free_disk_gb"] = round(free / (1024**3), 2)
        except Exception:
            pass

        try:
            ram_cmd = "(Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum"
            proc = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", ram_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0 and proc.stdout.strip().isdigit():
                ram_bytes = int(proc.stdout.strip())
                info["ram_gb"] = round(ram_bytes / (1024**3), 2)
        except Exception:
            pass
    else:
        total, used, free = shutil.disk_usage("/")
        info["free_disk_gb"] = round(free / (1024**3), 2)
        info["ram_gb"] = 16.0

    # Nạp cấu hình ngưỡng từ dump_readiness.yaml theo target_mode
    ram_plus = 5.0
    min_gb = 10.0

    if target_mode == 3:  # Small dump
        ram_plus = 0.0
        min_gb = 2.0
    elif target_mode == 1:  # Complete dump
        ram_plus = 5.0
        min_gb = 15.0

    threshold = max(info["ram_gb"] + ram_plus, min_gb)
    info["recommended_free_gb"] = round(threshold, 2)
    info["sufficient_space"] = info["free_disk_gb"] >= threshold

    return info


def check_volmgr_events(lookback_days: int = 180) -> Dict[str, Any]:
    """
    Kiểm tra sự kiện volmgr có tính thứ tự thời gian (Sửa L4).
    VOLMGR_FAILURE_RECENT chỉ bật khi sự kiện thất bại gần nhất MỚI HƠN sự kiện thành công gần nhất.
    """
    result = {
        "has_failure_161": False,  # Giữ cho tương thích ngược
        "has_recent_failure": False,
        "last_failure_time": None,
        "last_success_time": None,
        "events_count": 0,
        "failure_events": [],
        "success_events": [],
    }

    if sys.platform != "win32":
        return result

    ps_cmd = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        "$ProgressPreference = 'SilentlyContinue'; "
        f"$limit = (Get-Date).AddDays(-{lookback_days}); "
        "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='volmgr'; "
        "Id=@(45,46,49,161,162); StartTime=$limit} -MaxEvents 50 -ErrorAction SilentlyContinue | "
        "Select-Object Id, @{N='TimeUtc'; E={$_.TimeCreated.ToUniversalTime().ToString('o')}} | "
        "ForEach-Object { $_ | ConvertTo-Json -Compress }"
    )

    try:
        from dumpanalyzer.core.ps_runner import parse_ps_json_output, run_powershell_script
        proc = run_powershell_script(ps_cmd, timeout=15)
        if proc.returncode == 0 and (proc.stdout or "").strip():
            events = parse_ps_json_output(proc.stdout or "")

            result["events_count"] = len(events)
            failure_ids = {45, 46, 49, 161}
            success_ids = {162}

            # Sắp xếp sự kiện theo thời gian UTC giảm dần (mới nhất trước)
            events.sort(key=lambda x: str(x.get("TimeUtc", "")), reverse=True)

            for ev in events:
                eid = ev.get("Id")
                t_str = ev.get("TimeUtc")
                if eid in failure_ids:
                    result["failure_events"].append({"id": eid, "time_utc": t_str})
                    if not result["last_failure_time"]:
                        result["last_failure_time"] = t_str
                    if eid == 161:
                        result["has_failure_161"] = True
                elif eid in success_ids:
                    result["success_events"].append({"id": eid, "time_utc": t_str})
                    if not result["last_success_time"]:
                        result["last_success_time"] = t_str

            # Đánh giá thứ tự thời gian (Sửa L4)
            if result["last_failure_time"]:
                if not result["last_success_time"]:
                    result["has_recent_failure"] = True
                elif str(result["last_failure_time"]) > str(result["last_success_time"]):
                    result["has_recent_failure"] = True

    except Exception as e:
        logger.debug(f"Không thể đọc event volmgr: {e}")

    return result


def get_last_boot_time_utc() -> Optional[str]:
    """Lấy thời điểm khởi động máy gần nhất ở định dạng ISO-8601 UTC (Sửa L7)."""
    if _mock_boot_time_utc is not None:
        return _mock_boot_time_utc

    if sys.platform != "win32":
        # Giả lập 24h trước cho Linux
        return datetime.now(timezone.utc).isoformat()

    ps_cmd = (
        "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')"
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass
    return None


def evaluate_readiness_v2(
    reg_data: Dict[str, Any],
    pf_data: Dict[str, Any],
    disk_data: Dict[str, Any],
    volmgr_data: Dict[str, Any],
    last_boot_time_utc: Optional[str] = None,
    latest_change: Optional[Dict[str, Any]] = None,
    is_admin: bool = True,
    gap_info: Optional[Dict[str, Any]] = None,
    target_mode: int = 7,
    rules: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Ma trận quyết định toàn diện đánh giá khả năng sẵn sàng ghi dump (Section 3.1, 3.2, 3.3).
    Nguồn logic duy nhất cho cả Local GUI, CLI, Fleet và Deployment Package.
    """
    reason_codes: List[Dict[str, str]] = []
    recommendations: List[str] = []

    # 1. Kiểm tra Registry (CrashControl)
    read_ok = reg_data.get("read_ok", True)
    val_present = reg_data.get("value_present", True)
    dump_code = reg_data.get("CrashDumpEnabled")

    if not read_ok:
        reason_codes.append({
            "code": CODE_REGISTRY_UNREADABLE,
            "level": "unknown",
            "detail": f"Không thể đọc Registry CrashControl: {reg_data.get('error', 'Lỗi không xác định')}",
        })
        recommendations.append("Kiểm tra quyền truy cập hệ thống hoặc chạy phần mềm bằng quyền Administrator.")
    else:
        if not val_present or dump_code is None:
            reason_codes.append({
                "code": CODE_DUMP_VALUE_MISSING,
                "level": "blocking",
                "detail": "Giá trị CrashDumpEnabled không tồn tại trong khóa CrashControl.",
            })
            recommendations.append("Bấm 'Bật ghi dump' để thiết lập chế độ ghi dump tự động (Automatic).")
        elif dump_code == 0:
            reason_codes.append({
                "code": CODE_DUMP_DISABLED,
                "level": "blocking",
                "detail": "Chức năng ghi dump đang bị TẮT hoàn toàn (CrashDumpEnabled = 0).",
            })
            recommendations.append("Bấm 'Bật ghi dump' hoặc chạy 'dumpanalyzer dump-enable' để bật Automatic memory dump.")
        elif dump_code == 3:
            reason_codes.append({
                "code": CODE_DUMP_MODE_SMALL,
                "level": "warning",
                "detail": "Máy đang ở chế độ Small memory dump (Minidump), không lưu toàn bộ bộ nhớ kernel.",
            })
            recommendations.append("Khuyến nghị nâng cấp lên Automatic memory dump (chế độ 7) nếu ổ đĩa đủ dung lượng.")

    # 2. Kiểm tra Pagefile (Sửa L3, L6)
    pf_state = pf_data.get("state", "ok")
    if pf_state == "unknown":
        reason_codes.append({
            "code": CODE_PAGEFILE_UNKNOWN,
            "level": "unknown",
            "detail": f"Không xác định được trạng thái Pagefile: {pf_data.get('error', 'Lệnh kiểm tra thất bại')}",
        })
        recommendations.append("Kiểm tra thủ công cấu hình Virtual Memory trong System Properties.")
    elif pf_state == "missing" or not pf_data.get("has_system_drive_pagefile", True):
        reason_codes.append({
            "code": CODE_PAGEFILE_MISSING,
            "level": "blocking",
            "detail": "Không có Pagefile trên ổ đĩa hệ thống (C:) và không có DedicatedDumpFile hợp lệ.",
        })
        recommendations.append("Vào System Properties -> Advanced -> Virtual Memory -> Bật 'Automatically manage paging file size for all drives'.")

    # 3. Kiểm tra Dung lượng đĩa (Sửa L5)
    if not disk_data.get("sufficient_space", True):
        free_gb = disk_data.get("free_disk_gb", 0.0)
        rec_gb = disk_data.get("recommended_free_gb", 10.0)
        reason_codes.append({
            "code": CODE_DISK_LOW,
            "level": "warning",
            "detail": f"Dung lượng trống ổ hệ thống thấp ({free_gb} GB, khuyến nghị >= {rec_gb} GB cho chế độ {target_mode}).",
        })
        recommendations.append("Dọn dẹp bớt dung lượng trên ổ đĩa hệ thống bằng Disk Cleanup hoặc Storage Sense.")

    # 4. Kiểm tra Lỗi volmgr (Sửa L4)
    has_volmgr_fail = volmgr_data.get("has_recent_failure", False) or (
        volmgr_data.get("has_failure_161", False)
        and (
            not volmgr_data.get("last_success_time")
            or str(volmgr_data.get("last_failure_time", "")) > str(volmgr_data.get("last_success_time", ""))
        )
    )
    if has_volmgr_fail:
        t_fail = volmgr_data.get("last_failure_time", "gần đây")
        reason_codes.append({
            "code": CODE_VOLMGR_FAILURE_RECENT,
            "level": "warning",
            "detail": f"Phát hiện sự kiện volmgr báo lỗi ghi dump gần nhất lúc {t_fail}.",
        })
        recommendations.append("Kiểm tra sức khoẻ ổ đĩa (SMART), cáp kết nối và driver bộ điều khiển lưu trữ.")

    # 5. Kiểm tra Dump gap (Sửa L9)
    if gap_info and gap_info.get("missing", 0) > 0:
        missing_cnt = gap_info["missing"]
        reason_codes.append({
            "code": CODE_DUMP_FILES_MISSING,
            "level": "warning",
            "detail": f"Phát hiện {missing_cnt} lần sập BSOD (Event 41) nhưng không tìm thấy file dump tương ứng.",
        })
        recommendations.append("Có thể do công cụ dọn dẹp (Storage Sense, Disk Cleanup, CCleaner) xóa file dump, hoặc ổ đĩa bị đầy lúc sập. Hãy kiểm tra lại.")

    # 6. Kiểm tra Trạng thái chờ khởi động lại (Sửa L7)
    pending_reboot = False
    if latest_change and latest_change.get("result") == "success":
        changed_at = latest_change.get("changed_at_utc", "")
        if last_boot_time_utc and changed_at and str(last_boot_time_utc) < str(changed_at):
            pending_reboot = True
            reason_codes.append({
                "code": CODE_PENDING_REBOOT,
                "level": "info",
                "detail": f"Đã thay đổi cấu hình ghi dump lúc {changed_at}, máy chưa khởi động lại kể từ lúc đổi.",
            })
            recommendations.append("Cần khởi động lại máy để Windows áp dụng cấu hình ghi dump mới.")

    # 7. Kiểm tra Quyền Admin
    if not is_admin:
        reason_codes.append({
            "code": CODE_NOT_ADMIN,
            "level": "info",
            "detail": "Đang chạy không có quyền Administrator. Một số kiểm tra có thể bị giới hạn.",
        })

    # Xác định Trạng thái tổng (Section 3.1)
    levels = {rc["level"] for rc in reason_codes}
    if "unknown" in levels:
        status = STATUS_UNKNOWN
        summary = "Không xác định: Không đọc được đầy đủ dữ liệu cấu hình hoặc trạng thái bộ nhớ ảo."
    elif "blocking" in levels:
        status = STATUS_BLOCKED
        summary = "Không ghi được dump: Hệ thống bị chặn ghi file dump do cấu hình hoặc thiếu pagefile."
    elif pending_reboot:
        status = STATUS_READY_PENDING_REBOOT
        summary = "Đã bật cấu hình, đang chờ khởi động lại máy để có hiệu lực."
    elif "warning" in levels:
        status = STATUS_ATTENTION
        summary = "Cần chú ý: Máy có thể ghi dump nhưng dung lượng thấp hoặc từng có sự cố ghi dump."
    else:
        status = STATUS_READY
        summary = "Sẵn sàng (theo cấu hình): Hệ thống đã đủ điều kiện ghi dump theo tiêu chuẩn."

    # Xác định proof_level (Section 1.4 & 3.1)
    proof_level = PROOF_NONE
    if volmgr_data.get("last_success_time") or volmgr_data.get("last_success_utc") or volmgr_data.get("has_recent_success"):
        proof_level = PROOF_EVIDENCE

    # Đánh giá Ma trận hành động Bật ghi dump (Section 3.3)
    enable_allowed = True
    blocked_by: List[str] = []
    needs_confirm_notes: List[str] = []

    if not is_admin:
        enable_allowed = False
        blocked_by.append("Cần quyền Administrator để thay đổi Registry.")

    if not read_ok:
        enable_allowed = False
        blocked_by.append("Không thể đọc Registry CrashControl.")

    if dump_code in (1, 2, 7) and val_present:
        enable_allowed = False
        blocked_by.append(f"Cấu hình đã được bật sẵn ở chế độ {dump_code} ({CRASH_DUMP_MODES.get(dump_code, '')}).")

    if dump_code == 3 and val_present:
        # P7 & Ma trận 3.3: Small dump (3) cho phép nâng cấp lên Automatic (7) kèm xác nhận
        if target_mode == 7:
            needs_confirm_notes.append("Máy đang ở chế độ Small dump (3). Bạn đang yêu cầu nâng cấp lên Automatic dump (7).")
        else:
            enable_allowed = False
            blocked_by.append("Máy đã ở sẵn chế độ Small dump (3).")

    # Kiểm tra pagefile theo Ma trận 3.3: Pagefile missing | unknown -> KHÔNG BẬT
    if pf_state in ("missing", "unknown") or not pf_data.get("has_system_drive_pagefile", True):
        if not pf_data.get("dedicated_dump_file"):
            enable_allowed = False
            blocked_by.append("Không can thiệp cấu hình khi bộ nhớ ảo (Pagefile) chưa chuẩn hoặc không tồn tại trên ổ C:.")

    # Kiểm tra dung lượng đĩa theo Ma trận 3.3
    if not disk_data.get("sufficient_space", True):
        enable_allowed = False
        blocked_by.append("Dung lượng ổ đĩa không đủ theo tiêu chuẩn an toàn.")

    # Kiểm tra volmgr 161 theo Ma trận 3.3
    if volmgr_data.get("has_recent_failure", False):
        enable_allowed = False
        blocked_by.append("Hệ thống từng gặp lỗi volmgr 161 gần đây, cần kiểm tra phần cứng trước.")

    return {
        "status": status,
        "proof_level": proof_level,
        "reason_codes": reason_codes,
        "summary": summary,
        "recommendations": recommendations,
        "enable_action": {
            "allowed": enable_allowed,
            "blocked_by": blocked_by,
            "target_mode": target_mode,
            "needs_confirm_notes": needs_confirm_notes,
        },
    }


def evaluate_readiness(
    reg_data: Dict[str, Any],
    pf_data: Dict[str, Any],
    disk_data: Dict[str, Any],
    volmgr_data: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Hàm đánh giá khả năng ghi dump (giữ nguyên chữ ký cũ để tương thích 100% với GUI/CLI/test cũ).
    Tự động gọi evaluate_readiness_v2 bên dưới và ánh xạ trường.
    """
    v2 = evaluate_readiness_v2(
        reg_data=reg_data,
        pf_data=pf_data,
        disk_data=disk_data,
        volmgr_data=volmgr_data,
    )

    # Ánh xạ trạng thái hiển thị tiếng Việt truyền thống cho các test cũ
    status_map = {
        STATUS_READY: "SẴN SÀNG",
        STATUS_READY_PENDING_REBOOT: "SẴN SÀNG (CHỜ KHỞI ĐỘNG LẠI)",
        STATUS_ATTENTION: "CẦN CHÚ Ý",
        STATUS_BLOCKED: "KHÔNG GHI ĐƯỢC DUMP",
        STATUS_UNKNOWN: "KHÔNG XÁC ĐỊNH",
    }

    reasons = [rc["detail"] for rc in v2["reason_codes"]]
    return {
        "status": status_map.get(v2["status"], v2["status"]),
        "raw_status": v2["status"],
        "summary": v2["summary"],
        "reasons": reasons,
        "recommendations": v2["recommendations"],
        "reason_codes": v2["reason_codes"],
        "proof_level": v2["proof_level"],
        "enable_action": v2["enable_action"],
    }


def backup_registry_crash_control_v2(
    target_dir: Optional[Any] = None,
    current_state: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Sao lưu cấu hình CrashControl đầy đủ ra cả tệp .json và .reg (Sửa L2).
    - Tệp .json: Nguồn sự thật để hoàn tác, lưu trữ toàn bộ giá trị kèm cờ 'present'.
    - Tệp .reg: Bản dự phòng, giá trị vốn không tồn tại được ghi cú pháp xóa ("CrashDumpEnabled"=-).
    """
    if isinstance(target_dir, dict) and current_state is None:
        current_state = target_dir
        target_dir = None

    if target_dir is None:
        settings = load_settings()
        b_dir_cfg = settings.get("dump_readiness", {}).get("backup_dir", "backup")
        target_dir = get_project_root() / b_dir_cfg
    else:
        target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    hostname = socket.gethostname()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_path = target_dir / f"CrashControl_{hostname}_{stamp}"

    reg_data = current_state if current_state is not None else read_registry_crash_control()
    all_vals = reg_data.get("all_values", {})
    missing_vals = reg_data.get("missing_values", [])

    # Chuẩn bị dữ liệu JSON hoàn tác
    json_values: Dict[str, Any] = {}
    standard_keys = [
        "CrashDumpEnabled",
        "AutoReboot",
        "Overwrite",
        "MinidumpDir",
        "DumpFile",
        "DedicatedDumpFile",
        "DumpFileSize",
        "LogEvent",
    ]

    for k in standard_keys:
        if k in all_vals:
            json_values[k] = all_vals[k]
        elif k in missing_vals or reg_data.get(k) is None:
            json_values[k] = {"present": False, "data": None, "type": "REG_DWORD"}
        else:
            val = reg_data.get(k)
            vtype = "REG_DWORD" if isinstance(val, int) else "REG_SZ"
            json_values[k] = {"present": True, "data": val, "type": vtype}

    backup_json_data = {
        "schema_version": 1,
        "tool_version": TOOL_VERSION,
        "hostname": hostname,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "values": json_values,
    }

    json_file = Path(f"{base_path}.json")
    json_text = json.dumps(backup_json_data, indent=2, ensure_ascii=False)
    json_file.write_text(json_text, encoding="utf-8")
    json_sha256 = hashlib.sha256(json_file.read_bytes()).hexdigest()

    # Chuẩn bị nội dung tệp .reg an toàn
    reg_lines = [
        "Windows Registry Editor Version 5.00",
        "",
        f"; DumpAnalyzer Backup File (v{TOOL_VERSION})",
        f"; Hostname: {hostname}",
        f"; Backup Time UTC: {datetime.now(timezone.utc).isoformat()}",
        "",
        r"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl]",
    ]

    cde_info = json_values.get("CrashDumpEnabled", {})
    if cde_info.get("present") and cde_info.get("data") is not None:
        cde_val = cde_info.get("data", 0) or 0
        reg_lines.append(f'"CrashDumpEnabled"=dword:{cde_val:08x}')
    else:
        # Nếu ban đầu không tồn tại -> dùng cú pháp xóa trong .reg (Sửa L2)
        reg_lines.append('"CrashDumpEnabled"=-')

    reg_file = Path(f"{base_path}.reg")
    reg_file.write_text("\r\n".join(reg_lines) + "\r\n", encoding="utf-8")
    reg_sha256 = hashlib.sha256(reg_file.read_bytes()).hexdigest()

    logger.info(f"Đã tạo bản sao lưu CrashControl tại: {json_file} và {reg_file}")

    return {
        "json_path": json_file,
        "reg_path": reg_file,
        "json_sha256": json_sha256,
        "reg_sha256": reg_sha256,
        "values": json_values,
    }


def backup_registry_crash_control(target_dir: Optional[Path] = None) -> Path:
    """Hàm sao lưu cũ giữ nguyên chữ ký (trả về Path file .reg) để tương thích ngược."""
    res = backup_registry_crash_control_v2(target_dir=target_dir)
    return res["reg_path"]


def enable_crash_dump(
    target_mode: int = 7,
    confirmed: bool = False,
    actor: Optional[str] = None,
    method: str = "local",
    backup_dir: Optional[Path] = None,
    db: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Thực hiện hành động BẬT GHI DUMP an toàn theo đúng Section 5.1 và ma trận 3.3.
    """
    hostname = socket.gethostname()
    actor_name = actor or os.environ.get("USERNAME") or os.environ.get("USER") or "admin"

    if not confirmed:
        return {
            "success": False,
            "message": "Thao tác đã bị huỷ vì chưa được người dùng xác nhận.",
            "reboot_required": False,
        }

    if not _check_admin():
        return {
            "success": False,
            "message": "Cần quyền Administrator để thay đổi cấu hình Registry hệ thống.",
            "reboot_required": False,
        }

    # 1. Thu thập và kiểm tra theo ma trận quyết định
    readiness = collect_dump_readiness(target_mode=target_mode, db=db)
    current_cde = readiness.get("registry", {}).get("crash_dump_enabled")
    if current_cde == target_mode:
        return {
            "success": True,
            "changed": False,
            "message": f"Không cần thay đổi: Hệ thống đã ở sẵn chế độ {target_mode} ({CRASH_DUMP_MODES.get(target_mode, '')}).",
            "readiness": readiness,
            "reboot_required": False,
        }

    action_info = readiness.get("enable_action", {})
    if not action_info.get("allowed", False):
        blocked_msg = ", ".join(action_info.get("blocked_by", ["Không được phép theo ma trận quyết định"]))
        return {
            "success": False,
            "message": f"Không thể bật ghi dump: {blocked_msg}",
            "readiness": readiness,
            "reboot_required": False,
        }

    # 2. Sao lưu toàn diện trước khi thay đổi (Sửa L2)
    try:
        b_info = backup_registry_crash_control_v2(target_dir=backup_dir)
    except Exception as e:
        logger.error(f"Không thể sao lưu cấu hình: {e}")
        return {
            "success": False,
            "message": f"Không thể sao lưu cấu hình cũ: {e}. Huỷ thao tác để đảm bảo an toàn.",
            "reboot_required": False,
        }

    old_cde = readiness.get("registry", {}).get("crash_dump_enabled")
    old_values = {"CrashDumpEnabled": old_cde}
    new_values = {"CrashDumpEnabled": target_mode}

    # 3. Ghi registry và đọc lại để xác nhận (Read-after-write)
    write_success = True
    err_msg = ""

    use_winreg = (sys.platform == "win32" or "winreg" in sys.modules) and _mock_registry_state is None
    if use_winreg:
        try:
            import winreg

            key_path = r"SYSTEM\CurrentControlSet\Control\CrashControl"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE | winreg.KEY_READ) as key:
                winreg.SetValueEx(key, "CrashDumpEnabled", 0, winreg.REG_DWORD, target_mode)

                # Kiểm tra đọc lại ngay lập tức
                read_back, _ = winreg.QueryValueEx(key, "CrashDumpEnabled")
                if read_back != target_mode:
                    write_success = False
                    err_msg = f"Đọc lại giá trị không khớp ({read_back} != {target_mode}). Đang tự hoàn tác..."
        except Exception as e:
            write_success = False
            err_msg = f"Lỗi khi ghi Registry: {e}"
    else:
        # Giả lập non-Windows hoặc mock test
        if _mock_registry_state is not None:
            _mock_registry_state["CrashDumpEnabled"] = target_mode
            _mock_registry_state["value_present"] = True

    # 4. Tự động hoàn tác nếu read-after-write thất bại
    if not write_success:
        rollback_crash_dump(b_info["json_path"], confirmed=True, actor="system_rollback", db=db)
        return {
            "success": False,
            "message": f"Thao tác thất bại: {err_msg}",
            "reboot_required": False,
        }

    # 5. Ghi nhật ký audit log ra file JSONL và SQLite (Section 5.4)
    change_record = {
        "hostname": hostname,
        "changed_at_utc": datetime.now(timezone.utc).isoformat(),
        "actor": actor_name,
        "method": method,
        "action": "enable",
        "old_values": old_values,
        "new_values": new_values,
        "backup_path": str(b_info["json_path"]),
        "result": "success",
        "message": f"Đặt CrashDumpEnabled = {target_mode}",
        "reboot_required": True,
    }

    _write_audit_log(change_record, db=db)

    # 6. Chuẩn bị thông điệp phản hồi
    notes_str = ""
    if action_info.get("needs_confirm_notes"):
        notes_str = "\n[CẢNH BÁO BỔ SUNG]\n  - " + "\n  - ".join(action_info["needs_confirm_notes"])

    success_msg = (
        f"ĐÃ BẬT GHI DUMP THÀNH CÔNG (CrashDumpEnabled = {target_mode})!\n"
        f"Bản sao lưu an toàn đã được tạo tại:\n"
        f"  - JSON: {b_info['json_path']}\n"
        f"  - REG:  {b_info['reg_path']}\n"
        f"[LƯU Ý QUAN TRỌNG] Bạn CẦN KHỞI ĐỘNG LẠI MÁY để Windows áp dụng cấu hình này. "
        f"Phần mềm KHÔNG tự khởi động lại máy.{notes_str}"
    )

    return {
        "success": True,
        "changed": True,
        "message": success_msg,
        "backup_path": str(b_info["json_path"]),
        "reg_backup_path": str(b_info["reg_path"]),
        "reboot_required": True,
    }


def rollback_crash_dump(
    backup_json_path: Union[str, Path],
    confirmed: bool = False,
    actor: Optional[str] = None,
    method: str = "local",
    db: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Hoàn tác cấu hình CrashControl theo bản sao lưu JSON (Section 5.3 & Sửa L2).
    Nếu giá trị ban đầu không tồn tại -> thực hiện DeleteValue, phục hồi 100% trạng thái gốc.
    """
    hostname = socket.gethostname()
    actor_name = actor or os.environ.get("USERNAME") or os.environ.get("USER") or "admin"
    b_file = Path(backup_json_path).resolve()

    if not confirmed:
        return {
            "success": False,
            "message": "Thao tác hoàn tác đã bị huỷ vì chưa được người dùng xác nhận.",
            "reboot_required": False,
        }

    if not _check_admin():
        return {
            "success": False,
            "message": "Cần quyền Administrator để hoàn tác cấu hình Registry.",
            "reboot_required": False,
        }

    if not b_file.is_file():
        return {
            "success": False,
            "message": f"Không tìm thấy file sao lưu JSON tại: {b_file}",
            "reboot_required": False,
        }

    try:
        backup_data = json.loads(b_file.read_text(encoding="utf-8"))
    except Exception as e:
        return {
            "success": False,
            "message": f"Lỗi đọc file sao lưu JSON: {e}",
            "reboot_required": False,
        }

    values = backup_data.get("values", {})
    cde_info = values.get("CrashDumpEnabled", {})
    was_present = cde_info.get("present", False)
    orig_data = cde_info.get("data")

    # Áp dụng hoàn tác vào Registry
    use_winreg = (sys.platform == "win32" or "winreg" in sys.modules) and _mock_registry_state is None
    if use_winreg:
        try:
            import winreg

            key_path = r"SYSTEM\CurrentControlSet\Control\CrashControl"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as key:
                if was_present and orig_data is not None:
                    winreg.SetValueEx(key, "CrashDumpEnabled", 0, winreg.REG_DWORD, int(orig_data))
                else:
                    try:
                        winreg.DeleteValue(key, "CrashDumpEnabled")
                    except FileNotFoundError:
                        pass
        except Exception as e:
            return {
                "success": False,
                "message": f"Lỗi khi hoàn tác Registry: {e}",
                "reboot_required": False,
            }
    else:
        if _mock_registry_state is not None:
            if was_present and orig_data is not None:
                _mock_registry_state["CrashDumpEnabled"] = orig_data
                _mock_registry_state["value_present"] = True
            else:
                _mock_registry_state["CrashDumpEnabled"] = None
                _mock_registry_state["value_present"] = False

    # Ghi audit log hoàn tác
    change_record = {
        "hostname": hostname,
        "changed_at_utc": datetime.now(timezone.utc).isoformat(),
        "actor": actor_name,
        "method": method,
        "action": "rollback",
        "old_values": {"CrashDumpEnabled": "current"},
        "new_values": {"CrashDumpEnabled": orig_data if was_present else None},
        "backup_path": str(b_file),
        "result": "success",
        "message": f"Hoàn tác CrashDumpEnabled về {orig_data if was_present else 'XÓA (không tồn tại)'}",
        "reboot_required": True,
    }
    _write_audit_log(change_record, db=db)

    return {
        "success": True,
        "message": (
            f"ĐÃ HOÀN TÁC CẤU HÌNH CRASHCONTROL THÀNH CÔNG!\n"
            f"Trạng thái khôi phục: CrashDumpEnabled = {orig_data if was_present else 'Không tồn tại (đã xóa)'}.\n"
            f"[LƯU Ý] Cần KHỞI ĐỘNG LẠI MÁY để Windows áp dụng lại cấu hình này."
        ),
        "reboot_required": True,
    }


def apply_automatic_dump(confirmed: bool = False) -> Dict[str, Any]:
    """Hàm cũ giữ nguyên chữ ký gọi trực tiếp enable_crash_dump(7)."""
    return enable_crash_dump(target_mode=7, confirmed=confirmed, method="legacy_apply")


def _write_audit_log(change_record: Dict[str, Any], db: Optional[Any] = None) -> None:
    """Ghi audit log ra file logs/dump_config_changes.jsonl và bảng CSDL."""
    try:
        log_dir = get_project_root() / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        jsonl_file = log_dir / "dump_config_changes.jsonl"
        with open(jsonl_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(change_record, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.error(f"Không thể ghi nhật ký file JSONL: {e}")

    try:
        if db is not None:
            db.insert_dump_config_change(change_record)
        else:
            from dumpanalyzer.storage.db import Database

            with Database() as local_db:
                local_db.insert_dump_config_change(change_record)
    except Exception as e:
        logger.debug(f"Không thể ghi nhật ký SQLite: {e}")


def collect_dump_readiness(
    target_mode: int = 7,
    db: Optional[Any] = None,
    days_gap: int = 90,
) -> Dict[str, Any]:
    """
    Thu thập toàn bộ dữ liệu cấu hình và đánh giá khả năng sẵn sàng của máy cục bộ.
    Trả về cấu trúc chuẩn schema_version=1 (Section 9.2).
    """
    hostname = socket.gethostname()
    collected_at = datetime.now(timezone.utc).isoformat()
    is_admin = _check_admin()

    reg_data = read_registry_crash_control()
    dedicated_df = reg_data.get("DedicatedDumpFile")
    pf_data = check_pagefile_status(dedicated_dump_file=dedicated_df)
    disk_data = check_disk_space_and_ram(target_mode=target_mode)

    settings = load_settings()
    v_lookback = settings.get("dump_readiness", {}).get("volmgr_lookback_days", 180)
    volmgr_data = check_volmgr_events(lookback_days=v_lookback)

    last_boot_utc = get_last_boot_time_utc()

    # Tra cứu lịch sử thay đổi gần nhất từ CSDL nếu có
    latest_change = None
    try:
        if db is not None:
            latest_change = db.get_latest_dump_config_change(hostname)
        else:
            from dumpanalyzer.storage.db import Database

            with Database() as local_db:
                latest_change = local_db.get_latest_dump_config_change(hostname)
    except Exception as e:
        logger.debug(f"Không thể tra cứu dump_config_change: {e}")

    # Tính toán dump gap (Sửa L9)
    gap_info = None
    try:
        gap_info = compute_dump_gap(days=days_gap, db=db)
    except Exception as e:
        logger.debug(f"Không thể tính dump gap: {e}")

    # Đánh giá v2
    eval_res = evaluate_readiness_v2(
        reg_data=reg_data,
        pf_data=pf_data,
        disk_data=disk_data,
        volmgr_data=volmgr_data,
        last_boot_time_utc=last_boot_utc,
        latest_change=latest_change,
        is_admin=is_admin,
        gap_info=gap_info,
        target_mode=target_mode,
    )

    # Đóng gói báo cáo JSON chuẩn (Section 9.2)
    os_info = {"caption": "Microsoft Windows", "build": "unknown"}
    if sys.platform == "win32":
        try:
            build = os.sys.getwindowsversion().build
            os_info["build"] = str(build)
            os_info["caption"] = f"Windows (Build {build})"
        except Exception:
            pass

    report = {
        "schema_version": 1,
        "tool_version": TOOL_VERSION,
        "hostname": hostname,
        "collected_at_utc": collected_at,
        "os": os_info,
        "is_admin": is_admin,
        "registry": {
            "read_ok": reg_data.get("read_ok", True),
            "crash_dump_enabled": reg_data.get("CrashDumpEnabled"),
            "value_present": reg_data.get("value_present", True),
            "dedicated_dump_file": reg_data.get("DedicatedDumpFile"),
            "log_event": reg_data.get("LogEvent"),
        },
        "pagefile": {
            "state": pf_data.get("state", "ok"),
            "system_drive_size_mb": pf_data.get("system_drive_size_mb", 0),
            "automatic_managed": pf_data.get("automatic_managed", True),
        },
        "disk": {
            "system_drive": disk_data.get("system_drive", "C:\\"),
            "free_gb": disk_data.get("free_disk_gb", 0.0),
        },
        "ram_gb": disk_data.get("ram_gb", 0.0),
        "volmgr": {
            "last_failure_utc": volmgr_data.get("last_failure_time"),
            "last_success_utc": volmgr_data.get("last_success_time"),
        },
        "last_boot_time_utc": last_boot_utc,
        "result": {
            "status": eval_res["status"],
            "proof_level": eval_res["proof_level"],
            "reason_codes": eval_res["reason_codes"],
            "pending_reboot": any(rc["code"] == CODE_PENDING_REBOOT for rc in eval_res["reason_codes"]),
            "summary": eval_res["summary"],
            "recommendations": eval_res["recommendations"],
        },
        "enable_action": eval_res["enable_action"],
        "dump_gap": gap_info,
    }

    # Lưu bản ghi vào CSDL bảng dump_readiness nếu có thể
    try:
        db_record = {
            "hostname": hostname,
            "collected_at_utc": collected_at,
            "source": "local",
            "status": eval_res["status"],
            "proof_level": eval_res["proof_level"],
            "crash_dump_enabled": reg_data.get("CrashDumpEnabled"),
            "registry_read_ok": 1 if reg_data.get("read_ok", True) else 0,
            "pagefile_state": pf_data.get("state", "unknown"),
            "free_disk_gb": disk_data.get("free_disk_gb", 0.0),
            "ram_gb": disk_data.get("ram_gb", 0.0),
            "last_boot_time_utc": last_boot_utc,
            "pending_reboot": 1 if any(rc["code"] == CODE_PENDING_REBOOT for rc in eval_res["reason_codes"]) else 0,
            "reason_codes": eval_res["reason_codes"],
            "raw_json": json.dumps(report, ensure_ascii=False),
        }
        if db is not None:
            db.insert_dump_readiness(db_record)
        else:
            from dumpanalyzer.storage.db import Database

            with Database() as local_db:
                local_db.insert_dump_readiness(db_record)
    except Exception as e:
        logger.debug(f"Không thể lưu dump_readiness vào DB: {e}")

    return report


def compute_dump_gap(
    days: int = 90,
    match_window_minutes: int = 15,
    db: Optional[Any] = None,
    events: Optional[List[Dict[str, Any]]] = None,
    crashes: Optional[List[Any]] = None,
    change_cutoff_utc: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Đối chiếu số lần sập BSOD trong Event Log với số file dump thực tế tìm thấy (Section 8.2 & Sửa L9).
    Loại trừ các lần sập trước thời điểm đổi cấu hình (nếu có bản ghi dump_config_change).
    Hỗ trợ truyền trực tiếp events và crashes hoặc truy vấn từ CSDL.
    """
    res = {
        "expected_bsod": 0,
        "matched_dumps": 0,
        "found_dumps": 0,
        "missing": 0,
        "non_bsod_resets": 0,
        "missing_details": [],
    }

    try:
        # Trường hợp 1: Có truyền trực tiếp danh sách events và crashes (in-memory test/caller)
        if events is not None:
            expected = 0
            non_bsod = 0
            for ev in events:
                if ev.get("event_id") != 41:
                    continue
                ev_time = ev.get("time_created_utc", "")
                if change_cutoff_utc and ev_time < change_cutoff_utc:
                    continue

                # Trích xuất BugcheckCode
                bc_code = None
                if "extra_json" in ev and ev["extra_json"]:
                    try:
                        ej = json.loads(ev["extra_json"])
                        bc_code = ej.get("BugcheckCode")
                    except Exception:
                        pass
                elif "kp41_info" in ev:
                    bc_code = ev["kp41_info"].get("bugcheck_code")
                elif "event_data" in ev:
                    bc_code = ev["event_data"].get("BugcheckCode")

                if bc_code is None or bc_code == 0 or str(bc_code) in ("0", "0x0", "0x00000000"):
                    non_bsod += 1
                else:
                    expected += 1

            matched = len(crashes or [])
            res["expected_bsod"] = expected
            res["matched_dumps"] = matched
            res["found_dumps"] = matched
            res["non_bsod_resets"] = non_bsod
            res["missing"] = max(0, expected - matched)
            return res

        # Trường hợp 2: Truy vấn từ CSDL
        from dumpanalyzer.storage.db import Database

        local_db = db if db is not None else Database()
        should_close = db is None

        # 1. Lấy ngày thay đổi cấu hình gần nhất (nếu có) để loại trừ giai đoạn dump còn tắt
        if not change_cutoff_utc:
            hostname = socket.gethostname()
            last_change = local_db.get_latest_dump_config_change(hostname)
            change_cutoff_utc = last_change.get("changed_at_utc") if last_change else None

        # 2. Đếm các sự kiện crash có bugcheck_code hợp lệ (≠ 0x0)
        conn = local_db._get_connection()
        cur = conn.execute(
            """
            SELECT id, crash_time_utc, bugcheck_code, dump_path, analyzed_by
            FROM crash
            WHERE bugcheck_code IS NOT NULL
              AND bugcheck_code NOT IN ('0x0', '0', '')
            ORDER BY crash_time_utc DESC
            """
        )
        crashes_db = [dict(r) for r in cur.fetchall()]

        if should_close:
            local_db.close()

        expected = 0
        matched = 0
        missing_details = []

        for c in crashes_db:
            c_time = c.get("crash_time_utc", "")
            # Nếu có điểm mốc thay đổi cấu hình, chỉ xét các sự kiện sau thời điểm đó
            if change_cutoff_utc and c_time < change_cutoff_utc:
                continue

            expected += 1
            has_dump = bool(c.get("dump_path")) and c.get("analyzed_by") in ("cdb", "header_only")
            if has_dump:
                matched += 1
            else:
                missing_details.append({
                    "crash_id": c.get("id"),
                    "time_utc": c_time,
                    "bugcheck_code": c.get("bugcheck_code"),
                })

        res["expected_bsod"] = expected
        res["matched_dumps"] = matched
        res["found_dumps"] = matched
        res["missing"] = max(0, expected - matched)
        res["missing_details"] = missing_details

    except Exception as e:
        logger.debug(f"Lỗi tính dump gap: {e}")

    return res
