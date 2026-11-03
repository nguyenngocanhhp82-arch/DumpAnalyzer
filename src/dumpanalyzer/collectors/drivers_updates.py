"""
Module thu thập thông tin driver thiết bị và các bản cập nhật/phần mềm mới cài đặt.
Giúp xác định driver quá hạn hoặc cập nhật Windows gây xung đột trong vòng 30 ngày.
"""

import sys
import subprocess
import json
from typing import List, Dict, Any
from dumpanalyzer.core.timeutil import parse_to_utc, to_utc_iso
from dumpanalyzer.core.logging_setup import get_logger

logger = get_logger("drivers_updates")


def collect_third_party_drivers() -> List[Dict[str, Any]]:
    """
    Thu thập danh sách các driver thiết bị bên thứ ba (không phải do Microsoft phát hành)
    qua Win32_PnPSignedDriver.
    """
    if sys.platform != "win32":
        return []

    ps_script = """
    Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
        Where-Object { $_.DriverProviderName -and $_.DriverProviderName -notmatch 'Microsoft' } |
        Select-Object DeviceName, DriverProviderName, DriverVersion, DriverDate, IsSigned |
        ConvertTo-Json
    """
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=25,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            raw = proc.stdout.strip()
            items = json.loads(raw) if raw.startswith("[") or raw.startswith("{") else []
            if isinstance(items, dict):
                items = [items]
            return items
    except Exception as e:
        logger.warning(f"Lỗi khi thu thập danh sách driver: {e}")

    return []


def collect_recent_windows_updates(days: int = 30) -> List[Dict[str, Any]]:
    """
    Thu thập các bản cập nhật Windows (HotFix) được cài đặt trong N ngày gần nhất.
    """
    if sys.platform != "win32":
        return []

    ps_script = f"""
    $threshold = (Get-Date).AddDays(-{days})
    Get-HotFix -ErrorAction SilentlyContinue |
        Where-Object {{ $_.InstalledOn -ge $threshold }} |
        Select-Object HotFixID, Description, InstalledOn |
        ConvertTo-Json
    """
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            raw = proc.stdout.strip()
            items = json.loads(raw) if raw.startswith("[") or raw.startswith("{") else []
            if isinstance(items, dict):
                items = [items]

            results = []
            for it in items:
                installed_time = parse_to_utc(it.get("InstalledOn"))
                results.append({
                    "hotfix_id": it.get("HotFixID"),
                    "description": it.get("Description"),
                    "installed_time_utc": to_utc_iso(installed_time),
                })
            return results
    except Exception as e:
        logger.warning(f"Lỗi khi lấy thông tin bản cập nhật Windows: {e}")

    return []
