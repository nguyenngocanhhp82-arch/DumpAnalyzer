"""
Module kiểm tra và cấu hình khả năng ghi Dump của hệ thống Windows (Phase 1B).
Đảm bảo tuân thủ nghiêm ngặt các quy tắc an toàn:
- MẶC ĐỊNH CHỈ ĐỌC: Kiểm tra CrashControl, Pagefile, dung lượng đĩa và volmgr.
- CHỈ SỬA KHI CÓ --apply VÀ NGƯỜI DÙNG XÁC NHẬN BẰNG TAY.
- Luôn sao lưu giá trị registry cũ ra file .reg trước khi can thiệp.
- Chỉ sửa duy nhất CrashDumpEnabled = 7, không đụng các khoá khác hay pagefile.
- Không bao giờ tự khởi động lại máy tính.
"""

import sys
import os
import shutil
import socket
import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from dumpanalyzer.core.config import get_project_root, is_running_as_admin
from dumpanalyzer.core.logging_setup import get_logger

logger = get_logger("dump_config")

# Mô tả các chế độ CrashDumpEnabled trong Windows
CRASH_DUMP_MODES = {
    0: "Tắt hoàn toàn (None - Không ghi dump)",
    1: "Complete memory dump (Toàn bộ bộ nhớ)",
    2: "Kernel memory dump (Bộ nhớ nhân)",
    3: "Small memory dump (Minidump 64KB/256KB)",
    7: "Automatic memory dump (Tự động - Khuyến nghị từ Win 8/10/11)",
}


def read_registry_crash_control() -> Dict[str, Any]:
    """
    Đọc các giá trị trong HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl.
    Trên Windows dùng module winreg; trên non-Windows trả về mock an toàn.
    """
    data = {
        "CrashDumpEnabled": None,
        "AutoReboot": None,
        "Overwrite": None,
        "MinidumpDir": "",
        "DumpFile": "",
        "raw_found": False,
        "error": None,
    }

    if sys.platform != "win32":
        # Môi trường non-Windows (Linux / macOS) phục vụ chạy test / phát triển
        data["CrashDumpEnabled"] = 7
        data["AutoReboot"] = 1
        data["Overwrite"] = 1
        data["MinidumpDir"] = r"%SystemRoot%\Minidump"
        data["DumpFile"] = r"%SystemRoot%\MEMORY.DMP"
        data["raw_found"] = True
        return data

    try:
        import winreg
        key_path = r"SYSTEM\CurrentControlSet\Control\CrashControl"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as key:
            data["raw_found"] = True

            def _query_val(name):
                try:
                    val, _ = winreg.QueryValueEx(key, name)
                    return val
                except FileNotFoundError:
                    return None

            data["CrashDumpEnabled"] = _query_val("CrashDumpEnabled")
            data["AutoReboot"] = _query_val("AutoReboot")
            data["Overwrite"] = _query_val("Overwrite")
            data["MinidumpDir"] = _query_val("MinidumpDir") or r"%SystemRoot%\Minidump"
            data["DumpFile"] = _query_val("DumpFile") or r"%SystemRoot%\MEMORY.DMP"
    except Exception as e:
        logger.error(f"Lỗi khi đọc registry CrashControl: {e}")
        data["error"] = str(e)

    return data


def check_pagefile_status() -> Dict[str, Any]:
    """
    Kiểm tra tình trạng Pagefile trên ổ đĩa chứa Windows (mặc định C:).
    Nếu không có Pagefile trên ổ C:, Windows KHÔNG THỂ ghi kernel/minidump khi BSOD.
    """
    res = {
        "has_system_drive_pagefile": True,
        "details": [],
        "managed_automatically": True,
        "error": None,
    }

    if sys.platform != "win32":
        res["details"] = ["Pagefile giả lập 8192 MB trên C: (Môi trường Linux)"]
        return res

    ps_cmd = (
        "Get-CimInstance Win32_PageFileUsage | "
        "Select-Object Name, AllocatedBaseSize, CurrentUsage | ConvertTo-Json"
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            raw_out = proc.stdout.strip()
            items = json.loads(raw_out) if raw_out.startswith("[") or raw_out.startswith("{") else []
            if isinstance(items, dict):
                items = [items]

            found_c = False
            for it in items:
                name = str(it.get("Name", "")).lower()
                size = it.get("AllocatedBaseSize", 0)
                res["details"].append(f"{name} ({size} MB)")
                if "c:" in name:
                    found_c = True

            res["has_system_drive_pagefile"] = found_c
        else:
            # Kiểm tra xem có AutomaticManagedPagefile không
            auto_cmd = "(Get-CimInstance Win32_ComputerSystem).AutomaticManagedPagefile"
            auto_proc = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", auto_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            is_auto = "true" in auto_proc.stdout.lower()
            res["managed_automatically"] = is_auto
            res["has_system_drive_pagefile"] = is_auto
    except Exception as e:
        res["error"] = str(e)

    return res


def check_disk_space_and_ram() -> Dict[str, Any]:
    """
    Kiểm tra dung lượng trống của ổ chứa Windows so với dung lượng RAM vật lý.
    Khuyến nghị dung lượng trống >= RAM + 5GB để đảm bảo ghi được Automatic/Kernel dump.
    """
    info = {
        "free_disk_gb": 0.0,
        "ram_gb": 0.0,
        "sufficient_space": True,
        "system_drive": "C:\\",
    }

    if sys.platform == "win32":
        sys_drive = os.environ.get("SystemDrive", "C:") + "\\"
        info["system_drive"] = sys_drive
        try:
            total, used, free = shutil.disk_usage(sys_drive)
            info["free_disk_gb"] = round(free / (1024 ** 3), 2)
        except Exception:
            pass

        # Lấy RAM qua PowerShell
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
                info["ram_gb"] = round(ram_bytes / (1024 ** 3), 2)
        except Exception:
            pass
    else:
        # Giả lập cho Linux
        total, used, free = shutil.disk_usage("/")
        info["free_disk_gb"] = round(free / (1024 ** 3), 2)
        info["ram_gb"] = 16.0

    # Tiêu chí: dung lượng trống phải lớn hơn RAM + 5GB (hoặc tối thiểu 10GB nếu RAM nhỏ)
    threshold = max(info["ram_gb"] + 5.0, 10.0)
    info["sufficient_space"] = info["free_disk_gb"] >= threshold
    info["recommended_free_gb"] = threshold

    return info


def check_volmgr_events() -> Dict[str, Any]:
    """
    Kiểm tra lịch sử ghi dump trong Event Log từ Provider 'volmgr':
    - Event 161: Tạo file dump thất bại.
    - Event 162: Tạo file dump thành công.
    """
    result = {
        "has_failure_161": False,
        "last_failure_time": None,
        "last_success_time": None,
        "events_count": 0,
    }

    if sys.platform != "win32":
        return result

    ps_cmd = (
        "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='volmgr'; Id=@(161,162)} "
        "-MaxEvents 10 -ErrorAction SilentlyContinue | "
        "Select-Object Id, TimeCreated | ConvertTo-Json"
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            raw_out = proc.stdout.strip()
            events = json.loads(raw_out) if raw_out.startswith("[") or raw_out.startswith("{") else []
            if isinstance(events, dict):
                events = [events]

            result["events_count"] = len(events)
            for ev in events:
                eid = ev.get("Id")
                etime = ev.get("TimeCreated")
                if eid == 161 and not result["has_failure_161"]:
                    result["has_failure_161"] = True
                    result["last_failure_time"] = etime
                elif eid == 162 and not result["last_success_time"]:
                    result["last_success_time"] = etime
    except Exception as e:
        logger.debug(f"Không thể đọc event volmgr: {e}")

    return result


def evaluate_readiness(
    reg_data: Dict[str, Any],
    pf_data: Dict[str, Any],
    disk_data: Dict[str, Any],
    volmgr_data: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Đánh giá tổng thể khả năng ghi dump của hệ thống theo 3 mức:
    - SẴN SÀNG (Màu xanh)
    - CẦN CHÚ Ý (Màu vàng)
    - KHÔNG GHI ĐƯỢC DUMP (Màu đỏ)
    """
    reasons = []
    recommendations = []
    is_blocked = False
    needs_attention = False

    dump_code = reg_data.get("CrashDumpEnabled")
    if dump_code == 0 or dump_code is None:
        is_blocked = True
        reasons.append("Chức năng ghi dump đang bị TẮT hoàn toàn trong Registry (CrashDumpEnabled = 0).")
        recommendations.append("Chạy lệnh 'dumpanalyzer check-dump-config --apply' để bật Automatic memory dump.")
    elif dump_code == 3:
        needs_attention = True
        reasons.append("Máy đang chỉ ghi Small memory dump (Minidump). Sẽ không lưu được toàn bộ bộ nhớ kernel.")

    if not pf_data.get("has_system_drive_pagefile", True):
        is_blocked = True
        reasons.append("Không phát hiện Pagefile trên ổ đĩa hệ thống (C:). Windows không thể ghi crash dump nếu không có pagefile.")
        recommendations.append("Vào System Properties -> Advanced -> Performance Settings -> Advanced -> Virtual Memory -> Bật 'Automatically manage paging file size for all drives'.")

    if not disk_data.get("sufficient_space", True):
        needs_attention = True
        free_gb = disk_data.get("free_disk_gb", 0)
        rec_gb = disk_data.get("recommended_free_gb", 10)
        reasons.append(f"Dung lượng trống ổ hệ thống thấp ({free_gb} GB, khuyến nghị >= {rec_gb} GB).")
        recommendations.append("Dọn dẹp bớt dung lượng trên ổ đĩa hệ thống (dùng Disk Cleanup hoặc Storage Sense).")

    if volmgr_data.get("has_failure_161", False):
        needs_attention = True
        reasons.append("Phát hiện sự kiện volmgr Event 161 (ghi file dump từng thất bại trong quá khứ).")
        recommendations.append("Kiểm tra sức khoẻ ổ đĩa (SMART), cáp kết nối và driver bộ điều khiển lưu trữ.")

    if is_blocked:
        status = "KHÔNG GHI ĐƯỢC DUMP"
        summary = "Máy tính hiện KHÔNG THỂ ghi nhận file dump khi xảy ra màn hình xanh BSOD."
    elif needs_attention:
        status = "CẦN CHÚ Ý"
        summary = "Máy tính có thể ghi dump nhưng cấu hình chưa tối ưu hoặc có nguy cơ ghi dump thất bại."
    else:
        status = "SẴN SÀNG"
        summary = "Cấu hình hoàn hảo: Hệ thống đã sẵn sàng ghi lại file dump khi có sự cố màn hình xanh."

    return {
        "status": status,
        "summary": summary,
        "reasons": reasons,
        "recommendations": recommendations,
    }


def backup_registry_crash_control(target_dir: Optional[Path] = None) -> Path:
    """
    Sao lưu cấu hình hiện tại của CrashControl ra file .reg trước khi thay đổi.
    Đường dẫn: backup/CrashControl_<hostname>_<YYYYMMDD_HHMMSS>.reg
    """
    if target_dir is None:
        target_dir = get_project_root() / "backup"
    target_dir.mkdir(parents=True, exist_ok=True)

    hostname = socket.gethostname()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = target_dir / f"CrashControl_{hostname}_{timestamp}.reg"

    reg_data = read_registry_crash_control()

    dump_code = reg_data.get("CrashDumpEnabled")
    val_hex = f"{dump_code:08x}" if dump_code is not None else "00000000"

    reg_content = f"""Windows Registry Editor Version 5.00

; DumpAnalyzer Backup File
; Hostname: {hostname}
; Backup Time: {datetime.now(timezone.utc).isoformat()}

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\CrashControl]
"CrashDumpEnabled"=dword:{val_hex}
"""

    with open(backup_file, "w", encoding="utf-8") as f:
        f.write(reg_content)

    logger.info(f"Đã sao lưu cấu hình CrashControl ra: {backup_file}")
    return backup_file


def apply_automatic_dump(confirmed: bool = False) -> Dict[str, Any]:
    """
    Áp dụng cấu hình ghi dump tự động (CrashDumpEnabled = 7).
    Chỉ thực thi khi:
    1. Đang chạy với quyền Administrator.
    2. Tham số confirmed = True (người dùng đã bấm xác nhận 'y').
    3. Đã sao lưu thành công file .reg cũ.
    """
    if not confirmed:
        return {
            "success": False,
            "message": "Thao tác đã bị huỷ vì chưa được người dùng xác nhận.",
        }

    if not is_running_as_admin():
        return {
            "success": False,
            "message": "Cần quyền Administrator để thay đổi cấu hình Registry hệ thống. Hãy mở Terminal bằng 'Run as administrator'.",
        }

    # 1. Sao lưu cấu hình cũ
    try:
        backup_path = backup_registry_crash_control()
    except Exception as e:
        return {
            "success": False,
            "message": f"Không thể sao lưu cấu hình cũ: {e}. Huỷ thao tác để đảm bảo an toàn.",
        }

    # 2. Áp dụng giá trị mới
    if sys.platform == "win32":
        try:
            import winreg
            key_path = r"SYSTEM\CurrentControlSet\Control\CrashControl"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "CrashDumpEnabled", 0, winreg.REG_DWORD, 7)

            logger.info("Đã đặt CrashDumpEnabled = 7 thành công.")
            return {
                "success": True,
                "message": (
                    f"ĐÃ BẬT GHI DUMP TỰ ĐỘNG THÀNH CÔNG (CrashDumpEnabled = 7)!\n"
                    f"Bản sao lưu cũ đã được lưu an toàn tại: {backup_path}\n"
                    f"[LƯU Ý] Bạn có thể cần KHỞI ĐỘNG LẠI MÁY để Windows áp dụng cấu hình này."
                ),
            }
        except Exception as e:
            logger.error(f"Lỗi khi ghi Registry: {e}")
            return {
                "success": False,
                "message": f"Lỗi khi cập nhật Registry: {e}",
            }
    else:
        # Mock thành công trên non-Windows
        return {
            "success": True,
            "message": f"Đã mô phỏng đặt CrashDumpEnabled = 7 (Backup: {backup_path}).",
        }
