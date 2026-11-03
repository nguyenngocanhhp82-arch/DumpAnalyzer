"""
Module thu thập thông tin phần cứng và cấu hình hệ thống (sysinfo.py).
Bao gồm:
- RAM: Win32_PhysicalMemory (Dung lượng, Tốc độ, Cờ gợi ý ép xung XMP)
- Ổ đĩa: Get-PhysicalDisk + Get-StorageReliabilityCounter (HealthStatus, Wear, Nhiệt độ, Lỗi đọc/ghi)
- BIOS, CPU, GPU: Win32_BIOS, Win32_Processor, Win32_VideoController (Tuổi BIOS, tuổi driver GPU)
- Chịu lỗi độc lập giữa các nguồn: lỗi một nguồn không làm hỏng nguồn khác.
- An toàn: Chỉ thực thi lệnh PowerShell ở chế độ đọc (Get-CimInstance/Get-PhysicalDisk).
"""

import sys
import json
import subprocess
import datetime
from typing import Dict, Any, Optional, List
from dumpanalyzer.core.timeutil import parse_to_utc
from dumpanalyzer.core.logging_setup import get_logger

from dumpanalyzer.storage.db import Database

logger = get_logger("sysinfo")


def _run_ps_json(script: str, timeout_sec: int = 30) -> Optional[Any]:
    """Chạy script PowerShell chỉ đọc và giải mã kết quả JSON."""
    if sys.platform != "win32":
        return None

    full_cmd = f"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n{script}"
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", full_cmd],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        raw = proc.stdout.strip()
        if raw.startswith("[") or raw.startswith("{"):
            return json.loads(raw)
        return None
    except Exception as e:
        logger.debug(f"Lỗi khi thực thi PowerShell sysinfo: {e}")
        return None


def collect_ram_info(mock_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Thu thập thông tin thanh RAM qua Win32_PhysicalMemory."""
    if mock_data is not None:
        return mock_data

    ps_script = """
try {
    $mems = Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop
    $mems | ForEach-Object {
        [PSCustomObject]@{
            Capacity = $_.Capacity
            Speed = $_.Speed
            ConfiguredClockSpeed = $_.ConfiguredClockSpeed
            Manufacturer = $_.Manufacturer
            PartNumber = $_.PartNumber
            DeviceLocator = $_.DeviceLocator
        }
    } | ConvertTo-Json -Compress
} catch {
    Write-Output '[]'
}
"""
    raw_list = _run_ps_json(ps_script) or []
    if isinstance(raw_list, dict):
        raw_list = [raw_list]

    modules: List[Dict[str, Any]] = []
    total_bytes = 0
    overclock_hint = False

    for item in raw_list:
        cap = int(item.get("Capacity") or 0)
        speed = int(item.get("Speed") or 0)
        cfg_speed = int(item.get("ConfiguredClockSpeed") or 0)
        total_bytes += cap

        if cfg_speed > speed and speed > 0:
            overclock_hint = True

        modules.append({
            "locator": item.get("DeviceLocator", ""),
            "capacity_gb": round(cap / (1024**3), 2),
            "speed_mhz": speed,
            "configured_speed_mhz": cfg_speed,
            "manufacturer": (item.get("Manufacturer") or "").strip(),
            "part_number": (item.get("PartNumber") or "").strip(),
        })

    return {
        "total_gb": round(total_bytes / (1024**3), 2),
        "module_count": len(modules),
        "modules": modules,
        "overclock_hint": overclock_hint,
    }


def collect_storage_info(mock_data: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Thu thập tình trạng sức khỏe ổ đĩa qua Get-PhysicalDisk & Get-StorageReliabilityCounter."""
    if mock_data is not None:
        return mock_data

    ps_script = """
try {
    $disks = Get-PhysicalDisk -ErrorAction Stop
    $result = @()
    foreach ($d in $disks) {
        $rel = $null
        try {
            $rel = Get-StorageReliabilityCounter -PhysicalDisk $d -ErrorAction SilentlyContinue
        } catch {}

        $result += [PSCustomObject]@{
            DeviceId = $d.DeviceId
            FriendlyName = $d.FriendlyName
            MediaType = $d.MediaType
            OperationalStatus = ($d.OperationalStatus -join ', ')
            HealthStatus = $d.HealthStatus
            Size = $d.Size
            ReadErrorsTotal = if ($rel) { $rel.ReadErrorsTotal } else { 0 }
            WriteErrorsTotal = if ($rel) { $rel.WriteErrorsTotal } else { 0 }
            Temperature = if ($rel) { $rel.Temperature } else { $null }
            Wear = if ($rel) { $rel.Wear } else { $null }
            PowerOnHours = if ($rel) { $rel.PowerOnHours } else { $null }
        }
    }
    $result | ConvertTo-Json -Compress
} catch {
    Write-Output '[]'
}
"""
    raw_list = _run_ps_json(ps_script) or []
    if isinstance(raw_list, dict):
        raw_list = [raw_list]

    disks = []
    for item in raw_list:
        size_b = int(item.get("Size") or 0)
        disks.append({
            "device_id": str(item.get("DeviceId", "")),
            "friendly_name": item.get("FriendlyName", "Unknown Disk"),
            "media_type": item.get("MediaType", "Unspecified"),
            "operational_status": item.get("OperationalStatus", "Unknown"),
            "health_status": item.get("HealthStatus", "Unknown"),
            "size_gb": round(size_b / (1024**3), 1),
            "read_errors": int(item.get("ReadErrorsTotal") or 0),
            "write_errors": int(item.get("WriteErrorsTotal") or 0),
            "temperature_c": item.get("Temperature"),
            "wear_pct": item.get("Wear"),
            "power_on_hours": item.get("PowerOnHours"),
        })
    return disks


def collect_bios_cpu_gpu_info(mock_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Thu thập thông tin phiên bản BIOS, CPU và Driver GPU."""
    if mock_data is not None:
        return mock_data

    ps_script = """
$res = [PSCustomObject]@{
    Bios = (Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue | Select-Object SMBIOSBIOSVersion, ReleaseDate, Manufacturer)
    Cpu = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed)
    Gpu = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Select-Object Name, DriverVersion, DriverDate)
}
$res | ConvertTo-Json -Depth 3 -Compress
"""
    raw_obj = _run_ps_json(ps_script) or {}
    bios_raw = raw_obj.get("Bios") or {}
    cpu_raw = raw_obj.get("Cpu") or {}
    gpu_raw = raw_obj.get("Gpu") or []
    if isinstance(gpu_raw, dict):
        gpu_raw = [gpu_raw]

    # Tính tuổi BIOS
    bios_date_str = str(bios_raw.get("ReleaseDate") or "")
    bios_age_years = None
    if bios_date_str:
        try:
            dt = parse_to_utc(bios_date_str)
            if dt:
                now = datetime.datetime.now(datetime.timezone.utc)
                bios_age_years = round((now - dt).days / 365.25, 1)
        except Exception:
            pass

    # Xử lý GPU
    gpus = []
    now = datetime.datetime.now(datetime.timezone.utc)
    for g in gpu_raw:
        g_name = g.get("Name", "")
        d_ver = g.get("DriverVersion", "")
        d_date_str = str(g.get("DriverDate") or "")
        age_months = None
        if d_date_str:
            try:
                g_dt = parse_to_utc(d_date_str)
                if g_dt:
                    age_months = max(0, (now.year - g_dt.year) * 12 + (now.month - g_dt.month))
            except Exception:
                pass

        gpus.append({
            "name": g_name,
            "driver_version": d_ver,
            "driver_date": d_date_str,
            "driver_age_months": age_months,
        })

    return {
        "bios": {
            "version": bios_raw.get("SMBIOSBIOSVersion", ""),
            "release_date": bios_date_str,
            "age_years": bios_age_years,
            "manufacturer": bios_raw.get("Manufacturer", ""),
        },
        "cpu": {
            "name": cpu_raw.get("Name", ""),
            "cores": cpu_raw.get("NumberOfCores", 0),
            "threads": cpu_raw.get("NumberOfLogicalProcessors", 0),
            "max_clock_mhz": cpu_raw.get("MaxClockSpeed", 0),
        },
        "gpu": gpus,
    }


def collect_all_system_info(
    mock_ram: Optional[Dict[str, Any]] = None,
    mock_disks: Optional[List[Dict[str, Any]]] = None,
    mock_platform: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Thu thập toàn bộ thông tin hệ thống từ RAM, Ổ đĩa, BIOS, CPU, GPU."""
    ram = collect_ram_info(mock_ram)
    disks = collect_storage_info(mock_disks)
    platform = collect_bios_cpu_gpu_info(mock_platform)

    return {
        "ram": ram,
        "disks": disks,
        "bios": platform.get("bios", {}),
        "cpu": platform.get("cpu", {}),
        "gpu": platform.get("gpu", []),
    }


def save_system_info_to_db(db: Database, machine_id: int, sys_info: Dict[str, Any]) -> None:
    """Lưu toàn bộ thông tin hệ thống đã thu thập vào bảng system_info."""
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # 1. RAM
    ram = sys_info.get("ram", {})
    if ram:
        db.insert_system_info(
            machine_id=machine_id,
            category="ram",
            key="config",
            value=f"{ram.get('total_gb', 0)} GB ({ram.get('module_count', 0)} thanh)",
            raw_json=json.dumps(ram, ensure_ascii=False),
            collected_at=now_iso,
        )

    # 2. Ổ đĩa
    disks = sys_info.get("disks", [])
    for d in disks:
        d_name = d.get("friendly_name", "Disk")
        db.insert_system_info(
            machine_id=machine_id,
            category="disk",
            key=d.get("device_id", "0"),
            value=f"{d_name} - Sức khỏe: {d.get('health_status')} | Độ mòn: {d.get('wear_pct')}%",
            raw_json=json.dumps(d, ensure_ascii=False),
            collected_at=now_iso,
        )

    # 3. BIOS
    bios = sys_info.get("bios", {})
    if bios:
        db.insert_system_info(
            machine_id=machine_id,
            category="bios",
            key="version",
            value=f"{bios.get('version')} (Ngày: {bios.get('release_date')})",
            raw_json=json.dumps(bios, ensure_ascii=False),
            collected_at=now_iso,
        )

    # 4. CPU
    cpu = sys_info.get("cpu", {})
    if cpu:
        db.insert_system_info(
            machine_id=machine_id,
            category="cpu",
            key="model",
            value=cpu.get("name", ""),
            raw_json=json.dumps(cpu, ensure_ascii=False),
            collected_at=now_iso,
        )

    # 5. GPU
    for g in sys_info.get("gpu", []):
        db.insert_system_info(
            machine_id=machine_id,
            category="gpu",
            key=g.get("name", "GPU"),
            value=f"Driver: {g.get('driver_version')} ({g.get('driver_date')})",
            raw_json=json.dumps(g, ensure_ascii=False),
            collected_at=now_iso,
        )
