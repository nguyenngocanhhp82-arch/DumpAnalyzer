"""
Module thu thập thông tin phần cứng hệ thống và trạng thái sức khoẻ ổ đĩa (SMART).
Bao gồm:
- Thông tin máy tính (Model, BIOS, CPU, RAM, OS Build).
- Trạng thái SMART của ổ đĩa thông qua Get-PhysicalDisk và Get-StorageReliabilityCounter.
"""

import sys
import socket
import platform
import subprocess
import json
from typing import Dict, Any, List
from dumpanalyzer.core.models import MachineInfo
from dumpanalyzer.core.logging_setup import get_logger

logger = get_logger("hardware")


def collect_machine_info() -> MachineInfo:
    """
    Thu thập thông tin tổng quan về phần cứng và hệ điều hành của máy tính.
    Lưu vào bảng 'machine' trong CSDL SQLite.
    """
    hostname = socket.gethostname()
    model = ""
    bios = ""
    cpu = platform.processor() or ""
    os_build = platform.version() or ""

    if sys.platform == "win32":
        ps_script = """
        $cs = Get-CimInstance Win32_ComputerSystem
        $b = Get-CimInstance Win32_BIOS
        $p = Get-CimInstance Win32_Processor | Select-Object -First 1
        $os = Get-CimInstance Win32_OperatingSystem
        [PSCustomObject]@{
            Model = $cs.Model
            Manufacturer = $cs.Manufacturer
            BIOS = "$($b.Manufacturer) $($b.SMBIOSBIOSVersion)"
            CPU = $p.Name
            Build = "$($os.Caption) ($($os.BuildNumber))"
        } | ConvertTo-Json
        """
        try:
            proc = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                data = json.loads(proc.stdout.strip())
                model = f"{data.get('Manufacturer', '')} {data.get('Model', '')}".strip()
                bios = data.get("BIOS", "")
                cpu = data.get("CPU", cpu)
                os_build = data.get("Build", os_build)
        except Exception as e:
            logger.debug(f"Không thể lấy thông tin chi tiết máy qua WMI: {e}")
    else:
        model = "Linux System / Development Container"
        bios = "Standard Linux Kernel"

    return MachineInfo(
        hostname=hostname,
        model=model,
        bios=bios,
        cpu=cpu,
        os_build=os_build,
    )


def collect_smart_status() -> List[Dict[str, Any]]:
    """
    Kiểm tra tình trạng sức khoẻ ổ đĩa (SMART, lỗi đọc/ghi, nhiệt độ)
    thông qua Get-PhysicalDisk và Get-StorageReliabilityCounter trong Windows.
    """
    if sys.platform != "win32":
        return []

    ps_script = """
    $disks = Get-PhysicalDisk -ErrorAction SilentlyContinue | Select-Object DeviceId, FriendlyName, MediaType, HealthStatus, OperationalStatus
    $counters = Get-StorageReliabilityCounter -ErrorAction SilentlyContinue | Select-Object DeviceId, ReadErrorsTotal, WriteErrorsTotal, Temperature, Wear
    $results = @()
    foreach ($d in $disks) {
        $c = $counters | Where-Object { $_.DeviceId -eq $d.DeviceId }
        $results += [PSCustomObject]@{
            DeviceId = $d.DeviceId
            FriendlyName = $d.FriendlyName
            MediaType = $d.MediaType
            HealthStatus = $d.HealthStatus
            OperationalStatus = $d.OperationalStatus
            ReadErrors = if ($c) { $c.ReadErrorsTotal } else { 0 }
            WriteErrors = if ($c) { $c.WriteErrorsTotal } else { 0 }
            Temperature = if ($c) { $c.Temperature } else { $null }
            Wear = if ($c) { $c.Wear } else { $null }
        }
    }
    $results | ConvertTo-Json
    """
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            raw = proc.stdout.strip()
            items = json.loads(raw) if raw.startswith("[") or raw.startswith("{") else []
            if isinstance(items, dict):
                items = [items]
            return items
    except Exception as e:
        logger.warning(f"Lỗi khi đọc SMART ổ đĩa: {e}")

    return []
