"""
Module phân tích cú pháp đầu ra text từ lệnh cdb.exe (!analyze -v).
Bóc tách:
- BugCheckCode và 4 tham số.
- IMAGE_NAME, MODULE_NAME, PROCESS_NAME, FAILURE_BUCKET_ID.
- STACK_TEXT và danh sách module bên thứ ba trong stack.
- Phân biệt rõ: Nạn nhân (module lõi Microsoft) vs Thủ phạm thực sự (driver bên thứ ba).
- Thông tin hệ điều hành (vertarget), thời gian sập (.time), danh sách module nạp (lm t n).
"""

import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Set
import yaml
from dumpanalyzer.core.config import get_project_root
from dumpanalyzer.core.timeutil import parse_to_utc, to_utc_iso
from dumpanalyzer.core.logging_setup import get_logger
from dumpanalyzer.analyzer.header_parser import lookup_bugcheck_name

logger = get_logger("cdb_parser")

# Danh sách mặc định các module lõi Microsoft (nạn nhân mặc định)
DEFAULT_MS_CORE_MODULES: Set[str] = {
    "nt",
    "ntoskrnl.exe", "ntoskrnl",
    "ntkrnlmp.exe", "ntkrnlmp",
    "hal.dll", "hal",
    "win32k.sys", "win32k",
    "win32kfull.sys", "win32kfull",
    "win32kbase.sys", "win32kbase",
    "ntfs.sys", "ntfs",
    "fltmgr.sys", "fltmgr",
    "clfs.sys", "clfs",
    "ci.dll", "ci",
    "ksecdd.sys", "ksecdd",
    "werkernel.sys", "werkernel",
    "wdfilter.sys", "wdfilter",
    "tcpip.sys", "tcpip",
    "netio.sys", "netio",
}


def load_ms_core_modules() -> Set[str]:
    """Tải danh sách module lõi Microsoft từ driver_map.yaml."""
    rules_path = get_project_root() / "config" / "rules" / "driver_map.yaml"
    modules = set(DEFAULT_MS_CORE_MODULES)
    if rules_path.exists():
        try:
            with open(rules_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict) and "ms_core_modules" in data:
                    for m in data["ms_core_modules"]:
                        clean = m.strip().lower()
                        modules.add(clean)
                        if clean.endswith(".sys") or clean.endswith(".dll") or clean.endswith(".exe"):
                            modules.add(clean.rsplit(".", 1)[0])
        except Exception as e:
            logger.warning(f"Lỗi khi đọc ms_core_modules từ driver_map.yaml: {e}")
    return modules


@dataclass
class CdbAnalysisResult:
    """Kết quả phân tích có cấu trúc từ output text của cdb."""
    bugcheck_code: str = ""
    bugcheck_name: str = ""
    p1: str = "0x0"
    p2: str = "0x0"
    p3: str = "0x0"
    p4: str = "0x0"
    image_name: str = ""
    module_name: str = ""
    process_name: str = ""
    failure_bucket_id: str = ""
    stack_text: str = ""
    stack_modules: List[str] = field(default_factory=list)
    third_party_stack_modules: List[str] = field(default_factory=list)
    suspect_driver: str = ""          # Driver bên thứ ba bị nghi ngờ nhất trong stack
    is_ms_culprit: bool = False       # True nếu IMAGE_NAME là module Microsoft
    windows_version: str = ""
    crash_time_utc: Optional[str] = None
    uptime_seconds: int = 0
    loaded_modules: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    raw_output: str = ""
    symbol_error: bool = False


class CdbParser:
    """Lớp phân tích text output của cdb.exe !analyze -v."""

    def __init__(self, ms_core_modules: Optional[Set[str]] = None):
        self.ms_core_modules = ms_core_modules if ms_core_modules is not None else load_ms_core_modules()

    def parse(self, raw_text: str) -> CdbAnalysisResult:
        """Phân tích toàn bộ chuỗi text xuất ra từ cdb."""
        res = CdbAnalysisResult(raw_output=raw_text)

        if not raw_text or not raw_text.strip():
            return res

        # 1. Kiểm tra cảnh báo lỗi symbol
        if "*** ERROR: Symbol file could not be found" in raw_text or "Symbols could not be loaded" in raw_text:
            res.symbol_error = True

        # 2. Bóc tách BugCheckCode
        m_code = re.search(r"BUGCHECK_CODE:\s*([0-9a-fA-Fx]+)", raw_text, re.IGNORECASE)
        if m_code:
            raw_c = m_code.group(1).strip()
            try:
                val = int(raw_c, 16)
                res.bugcheck_code = f"0x{val:X}"
            except ValueError:
                res.bugcheck_code = raw_c
        else:
            # Dự phòng: đọc từ lệnh .bugcheck
            m_dot_bc = re.search(r"Bugcheck code\s+([0-9a-fA-Fx]+)", raw_text, re.IGNORECASE)
            if m_dot_bc:
                raw_c = m_dot_bc.group(1).strip()
                try:
                    val = int(raw_c, 16)
                    res.bugcheck_code = f"0x{val:X}"
                except ValueError:
                    res.bugcheck_code = raw_c

        # Tra cứu tên Bug Check
        if res.bugcheck_code:
            res.bugcheck_name = lookup_bugcheck_name(res.bugcheck_code)

        # 3. Bóc tách 4 tham số BUGCHECK_P1 .. P4
        for p_idx, attr in enumerate(["p1", "p2", "p3", "p4"], start=1):
            m_p = re.search(rf"BUGCHECK_P{p_idx}:\s*([0-9a-fA-Fx]+)", raw_text, re.IGNORECASE)
            if m_p:
                val_str = m_p.group(1).strip()
                try:
                    val = int(val_str, 16)
                    setattr(res, attr, f"0x{val:X}")
                except ValueError:
                    setattr(res, attr, val_str)

        # Dự phòng đọc tham số từ .bugcheck (Arguments: p1 p2 p3 p4)
        if res.p1 == "0x0" and res.p2 == "0x0":
            m_args = re.search(r"Arguments\s+([0-9a-fA-Fx]+)\s+([0-9a-fA-Fx]+)\s+([0-9a-fA-Fx]+)\s+([0-9a-fA-Fx]+)", raw_text, re.IGNORECASE)
            if m_args:
                res.p1 = f"0x{int(m_args.group(1), 16):X}"
                res.p2 = f"0x{int(m_args.group(2), 16):X}"
                res.p3 = f"0x{int(m_args.group(3), 16):X}"
                res.p4 = f"0x{int(m_args.group(4), 16):X}"

        # 4. Bóc tách IMAGE_NAME, MODULE_NAME, PROCESS_NAME, FAILURE_BUCKET_ID
        m_img = re.search(r"IMAGE_NAME:\s*([^\r\n]+)", raw_text)
        if m_img:
            res.image_name = m_img.group(1).strip()

        m_mod = re.search(r"MODULE_NAME:\s*([^\r\n]+)", raw_text)
        if m_mod:
            res.module_name = m_mod.group(1).strip()

        m_proc = re.search(r"PROCESS_NAME:\s*([^\r\n]+)", raw_text)
        if m_proc:
            res.process_name = m_proc.group(1).strip()

        m_bucket = re.search(r"FAILURE_BUCKET_ID:\s*([^\r\n]+)", raw_text)
        if m_bucket:
            res.failure_bucket_id = m_bucket.group(1).strip()

        # 5. Bóc tách STACK_TEXT
        # Mẫu: STACK_TEXT:\n... cho đến khi gặp dòng trống hoặc nhãn CHỮ_HOA:
        m_stack = re.search(r"STACK_TEXT:\s*[\r\n]+(.*?)(?=\r?\n\r?\n|\r?\n[A-Z_]{3,}:|\Z)", raw_text, re.DOTALL)
        if m_stack:
            res.stack_text = m_stack.group(1).strip()
            res.stack_modules = self._extract_modules_from_stack(res.stack_text)
            res.third_party_stack_modules = [
                m for m in res.stack_modules if not self._is_ms_module(m)
            ]

        # 6. Kiểm tra xem thủ phạm cdb chỉ định có phải là module Microsoft hay không
        img_lower = res.image_name.lower()
        mod_lower = res.module_name.lower()
        if self._is_ms_module(img_lower) or self._is_ms_module(mod_lower):
            res.is_ms_culprit = True
            # Nếu IMAGE_NAME là Microsoft lõi (nạn nhân), ưu tiên tìm driver bên thứ ba đầu tiên trong stack
            if res.third_party_stack_modules:
                res.suspect_driver = res.third_party_stack_modules[0]
            else:
                res.suspect_driver = res.image_name or res.module_name
        else:
            res.is_ms_culprit = False
            res.suspect_driver = res.image_name or res.module_name

        # 7. Bóc tách thông tin Windows version và thời gian
        # Từ vertarget: "Windows 10 Kernel Version 19041 MP (8 procs) Free x64"
        m_ver = re.search(r"Windows\s+([0-9]+(?:\.[0-9]+)?\s+Kernel[^\r\n]+)", raw_text, re.IGNORECASE)
        if m_ver:
            res.windows_version = m_ver.group(0).strip()

        # Từ .time hoặc Debug session time:
        # "Debug session time: Tue Oct 20 10:00:00.123 2026 (UTC + 7:00)"
        m_time = re.search(r"Debug session time:\s*([^\r\n]+)", raw_text, re.IGNORECASE)
        if m_time:
            time_str = m_time.group(1).strip()
            # Bỏ phần (UTC ...) nếu có để parse_to_utc xử lý
            clean_time = re.sub(r"\(UTC[^\)]*\)", "", time_str).strip()
            try:
                # Định dạng thường gặp: Tue Oct 20 10:00:00.123 2026
                dt = parse_to_utc(clean_time)
                if dt:
                    res.crash_time_utc = to_utc_iso(dt)
            except Exception:
                pass

        # 8. Bóc tách System Uptime: "System Uptime: 0 days 1:23:45.678"
        m_uptime = re.search(r"System Uptime:\s*([^\r\n]+)", raw_text, re.IGNORECASE)
        if m_uptime:
            res.uptime_seconds = self._parse_uptime(m_uptime.group(1).strip())

        # 9. Bóc tách danh sách module từ `lm t n`
        res.loaded_modules = self._extract_loaded_modules(raw_text)

        return res

    def _is_ms_module(self, name: str) -> bool:
        """Kiểm tra xem tên module có thuộc danh sách lõi Microsoft không."""
        clean = name.lower().strip()
        if clean in self.ms_core_modules:
            return True
        stem = clean.rsplit(".", 1)[0]
        return stem in self.ms_core_modules

    def _extract_modules_from_stack(self, stack_text: str) -> List[str]:
        """
        Trích xuất danh sách tên các module xuất hiện trong stack trace.
        Dòng stack thường có dạng:
        fffff800`12345678 fffff800`87654321 nvlddmkm+0x123456
        hoặc: ntoskrnl!KiPageFault+0x123
        """
        modules = []
        seen = set()

        for line in stack_text.splitlines():
            line = line.strip()
            if not line:
                continue

            # Tìm chuỗi trước dấu ! hoặc +
            # Ví dụ: nvlddmkm+0x123 -> nvlddmkm; ntoskrnl!KeBugCheckEx -> ntoskrnl
            m = re.search(r"([A-Za-z0-9_\-\.]+)(?:!|\+0x|\+)", line)
            if m:
                mod = m.group(1).strip()
                # Loại trừ các địa chỉ hex thuần túy
                if re.match(r"^[0-9a-fA-F`]+$", mod):
                    continue
                # Chuẩn hoá tên
                mod_lower = mod.lower()
                if mod_lower not in seen and len(mod_lower) > 1:
                    seen.add(mod_lower)
                    modules.append(mod)

        return modules

    def _parse_uptime(self, uptime_str: str) -> int:
        """Chuyển đổi chuỗi System Uptime (vd: '0 days 2:30:15.123') sang giây."""
        try:
            total_sec = 0
            m_days = re.search(r"(\d+)\s+days?", uptime_str, re.IGNORECASE)
            if m_days:
                total_sec += int(m_days.group(1)) * 86400

            m_time = re.search(r"(\d+):(\d+):(\d+)", uptime_str)
            if m_time:
                h, m, s = int(m_time.group(1)), int(m_time.group(2)), int(m_time.group(3))
                total_sec += h * 3600 + m * 60 + s
            return total_sec
        except Exception:
            return 0

    def _extract_loaded_modules(self, raw_text: str) -> Dict[str, Dict[str, Any]]:
        """
        Bóc tách bảng module từ lệnh lm t n:
        start    end        module name
        fffff800`10000000 fffff800`10100000   nvlddmkm   (pdb symbols)
        """
        modules = {}
        # Tìm phần bắt đầu của bảng lm
        m_start = re.search(r"start\s+end\s+module name", raw_text, re.IGNORECASE)
        if not m_start:
            return modules

        lm_section = raw_text[m_start.end():]
        for line in lm_section.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("0:") or line.startswith("quit:") or line.startswith("KEY_VALUES"):
                break

            parts = re.split(r"\s+", line)
            if len(parts) >= 3:
                start_addr, end_addr, mod_name = parts[0], parts[1], parts[2]
                if "`" in start_addr or len(start_addr) >= 8:
                    mod_clean = mod_name.strip()
                    modules[mod_clean.lower()] = {
                        "name": mod_clean,
                        "start": start_addr,
                        "end": end_addr,
                    }

        return modules
