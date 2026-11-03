"""
Module đọc và phân tích header nhị phân của file crash dump Windows (không cần cdb.exe).
Hỗ trợ:
- Windows 64-bit Kernel / Complete Dump (Chữ ký PAGEDU64).
- Windows Minidump (Chữ ký MDMP).
- Kiểm tra tính toàn vẹn và tra cứu mã Bug Check trong danh sách chuẩn.
"""

import struct
import json
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Union, Dict, Any
from dumpanalyzer.core.config import get_project_root
from dumpanalyzer.core.timeutil import to_utc_iso
from dumpanalyzer.core.logging_setup import get_logger

logger = get_logger("header_parser")

# Hằng số chuyển đổi Windows FILETIME sang Unix Epoch (1601-01-01 -> 1970-01-01)
WINDOWS_TICK = 10_000_000
SEC_TO_UNIX_EPOCH = 11_644_473_600


@dataclass
class DumpHeaderInfo:
    """Thông tin trích xuất trực tiếp từ header file dump."""
    dump_type: str = "unknown"         # 'kernel', 'full', 'mini', 'unknown'
    bugcheck_code: str = ""            # Mã hex chuẩn hoá (ví dụ: '0x124', '0x1A')
    bugcheck_name: str = ""            # Tên chuẩn tra cứu (ví dụ: 'WHEA_UNCORRECTABLE_ERROR')
    p1: str = "0x0"
    p2: str = "0x0"
    p3: str = "0x0"
    p4: str = "0x0"
    crash_time_utc: Optional[str] = None  # Chuỗi thời gian UTC ISO-8601
    crash_time_source: str = "unknown"    # 'header' hoặc 'mtime'
    uptime_seconds: int = 0               # Uptime tính bằng giây
    valid: bool = False
    signature: str = ""
    error_message: str = ""


_BUGCHECK_CACHE: Optional[Dict[str, Any]] = None


def _get_bugcheck_dict() -> Dict[str, Any]:
    """Tải và lưu đệm từ điển mã lỗi từ bugcheck_codes.json."""
    global _BUGCHECK_CACHE
    if _BUGCHECK_CACHE is None:
        json_path = get_project_root() / "config" / "data" / "bugcheck_codes.json"
        if json_path.exists():
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    _BUGCHECK_CACHE = json.load(f)
            except Exception as e:
                logger.warning(f"Lỗi đọc bugcheck_codes.json: {e}")
                _BUGCHECK_CACHE = {}
        else:
            _BUGCHECK_CACHE = {}
    return _BUGCHECK_CACHE


def lookup_bugcheck_name(code_hex: str) -> str:
    """Tra cứu tên chuẩn của mã Bug Check (hỗ trợ cả dạng '0x124' và '0x00000124')."""
    if not code_hex:
        return ""
    mapping = _get_bugcheck_dict()
    clean = code_hex.upper().strip()

    # Thử tra trực tiếp
    if clean in mapping:
        return mapping[clean].get("name", "")

    # Chuẩn hoá về int rồi format lại
    try:
        val = int(clean, 16)
        short_hex = f"0x{val:X}"
        if short_hex in mapping:
            return mapping[short_hex].get("name", "")
        long_hex = f"0x{val:08X}"
        if long_hex in mapping:
            return mapping[long_hex].get("name", "")
    except ValueError:
        pass

    return "UNKNOWN_BUGCHECK"


def filetime_to_utc_iso(filetime_val: int) -> Optional[str]:
    """Chuyển đổi Windows FILETIME (64-bit int) sang chuỗi ISO UTC."""
    if filetime_val <= 0:
        return None
    try:
        epoch_seconds = (filetime_val / WINDOWS_TICK) - SEC_TO_UNIX_EPOCH
        if 0 < epoch_seconds < 3_000_000_000:  # Giới hạn an toàn từ năm 1970 đến 2065
            dt = datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
            return to_utc_iso(dt)
    except Exception:
        pass
    return None


def parse_dump_header(file_path: Union[str, Path]) -> DumpHeaderInfo:
    """
    Đọc nhị phân header của file dump:
    - Nhận diện chữ ký PAGE DU64 (Kernel/Complete Dump 64-bit).
    - Nhận diện chữ ký MDMP (Minidump).
    - Trích xuất BugCheckCode và 4 tham số.
    """
    path_obj = Path(file_path)
    if not path_obj.exists() or not path_obj.is_file():
        return DumpHeaderInfo(error_message=f"File không tồn tại: {file_path}")

    file_size = path_obj.stat().st_size
    if file_size < 32:
        return DumpHeaderInfo(error_message="File quá nhỏ, không phải file dump hợp lệ")

    try:
        with open(path_obj, "rb") as f:
            header_bytes = f.read(min(file_size, 8192))
    except Exception as e:
        return DumpHeaderInfo(error_message=f"Lỗi đọc file: {e}")

    # =========================================================================
    # 1. TRƯỜNG HỢP: Windows 64-bit Kernel / Complete Dump (PAGEDU64)
    # =========================================================================
    sig1 = header_bytes[0:4]
    sig2 = header_bytes[4:8]

    if sig1 == b"PAGE" and sig2 == b"DU64":
        if len(header_bytes) < 0x60:
            return DumpHeaderInfo(
                signature="PAGEDU64",
                dump_type="kernel",
                error_message="Header PAGEDU64 bị cắt cụt (không đủ 96 bytes)",
            )

        # Offset theo struct _DUMP_HEADER64 của Microsoft (ntdddump.h / ReactOS / Volatility):
        # 0x38: BugCheckCode (uint32)
        # 0x40: BugCheckCodeParameter[0] (uint64)
        # 0x48: BugCheckCodeParameter[1] (uint64)
        # 0x50: BugCheckCodeParameter[2] (uint64)
        # 0x58: BugCheckCodeParameter[3] (uint64)
        # 0xF98: DumpType (uint32: 1=full, 2/3/5=kernel, 4=mini)
        # 0xFA8: SystemTime (uint64 FILETIME UTC)
        # 0xFF8: SystemUpTime (uint64 100ns ticks)
        try:
            bc_code = struct.unpack_from("<I", header_bytes, 0x38)[0]
            p1 = struct.unpack_from("<Q", header_bytes, 0x40)[0]
            p2 = struct.unpack_from("<Q", header_bytes, 0x48)[0]
            p3 = struct.unpack_from("<Q", header_bytes, 0x50)[0]
            p4 = struct.unpack_from("<Q", header_bytes, 0x58)[0]

            code_hex = f"0x{bc_code:X}"
            name = lookup_bugcheck_name(code_hex)

            # Đọc DumpType tại 0xF98
            dump_type = "kernel"
            if len(header_bytes) >= 0xF9C:
                dt_code = struct.unpack_from("<I", header_bytes, 0xF98)[0]
                if dt_code == 1:
                    dump_type = "full"
                elif dt_code == 4:
                    dump_type = "mini"
                elif dt_code in (2, 3, 5):
                    dump_type = "kernel"

            # Đọc SystemTime tại offset chuẩn 0xFA8
            crash_time_utc = None
            crash_time_source = "mtime"
            if len(header_bytes) >= 0xFB0:
                ft = struct.unpack_from("<Q", header_bytes, 0xFA8)[0]
                if ft > 0:
                    converted = filetime_to_utc_iso(ft)
                    if converted:
                        crash_time_utc = converted
                        crash_time_source = "header"

            # Fallback về 0xA0 nếu 0xFA8 chưa có (tương thích ngược fixture cũ)
            if not crash_time_utc and len(header_bytes) >= 0xB0:
                ft_old = struct.unpack_from("<Q", header_bytes, 0xA0)[0]
                if ft_old > 0:
                    converted = filetime_to_utc_iso(ft_old)
                    if converted:
                        crash_time_utc = converted
                        crash_time_source = "header"

            # Nếu không có SystemTime hợp lệ trong header, lấy mtime của file
            if not crash_time_utc:
                crash_time_utc = to_utc_iso(path_obj.stat().st_mtime)
                crash_time_source = "mtime"

            # Đọc SystemUpTime tại offset 0xFF8 (uint64, 100ns ticks)
            uptime_seconds = 0
            if len(header_bytes) >= 0x1000:
                uptime_ticks = struct.unpack_from("<Q", header_bytes, 0xFF8)[0]
                if uptime_ticks > 0:
                    uptime_seconds = int(uptime_ticks / 10_000_000)

            return DumpHeaderInfo(
                dump_type=dump_type,
                bugcheck_code=code_hex,
                bugcheck_name=name,
                p1=f"0x{p1:X}",
                p2=f"0x{p2:X}",
                p3=f"0x{p3:X}",
                p4=f"0x{p4:X}",
                crash_time_utc=crash_time_utc,
                crash_time_source=crash_time_source,
                uptime_seconds=uptime_seconds,
                valid=True,
                signature="PAGEDU64",
            )
        except Exception as e:
            return DumpHeaderInfo(
                signature="PAGEDU64",
                dump_type="kernel",
                error_message=f"Lỗi giải mã cấu trúc DMP_HEADER64: {e}",
            )

    # =========================================================================
    # 2. TRƯỜNG HỢP: Windows Minidump (MDMP)
    # =========================================================================
    if sig1 == b"MDMP":
        # Minidump Header:
        # 0x00: Signature b'MDMP'
        # 0x04: Version
        # 0x08: NumberOfStreams (uint32)
        # 0x0C: StreamDirectoryRva (uint32)
        # 0x14: TimeDateStamp (uint32 Unix timestamp)
        try:
            num_streams, stream_rva, checksum, time_date_stamp = struct.unpack_from("<IIII", header_bytes, 0x08)
            crash_time_utc = None
            crash_time_source = "mtime"
            if time_date_stamp > 0:
                try:
                    dt = datetime.fromtimestamp(time_date_stamp, tz=timezone.utc)
                    crash_time_utc = to_utc_iso(dt)
                    crash_time_source = "header"
                except Exception:
                    pass

            if not crash_time_utc:
                crash_time_utc = to_utc_iso(path_obj.stat().st_mtime)
                crash_time_source = "mtime"

            # Quét danh sách stream tìm ExceptionStream (StreamType = 6)
            bc_code_found = None
            p_params = [0, 0, 0, 0]

            with open(path_obj, "rb") as f:
                if stream_rva < file_size:
                    f.seek(stream_rva)
                    # Mỗi directory entry gồm: StreamType (uint32), DataSize (uint32), Rva (uint32)
                    dir_bytes = f.read(num_streams * 12)
                    for i in range(num_streams):
                        if (i + 1) * 12 > len(dir_bytes):
                            break
                        stype, dsize, rva = struct.unpack_from("<III", dir_bytes, i * 12)
                        if stype == 6 and rva < file_size:  # ExceptionStream
                            f.seek(rva)
                            # MINIDUMP_EXCEPTION_STREAM:
                            # ThreadId (4), __alignment (4), ExceptionRecord:
                            # ExceptionCode (4), ExceptionFlags (4), ExceptionRecord (8), ExceptionAddress (8), NumberParameters (4)
                            ex_bytes = f.read(min(dsize, 160))
                            if len(ex_bytes) >= 16:
                                ex_code = struct.unpack_from("<I", ex_bytes, 8)[0]
                                bc_code_found = f"0x{ex_code:X}"
                                # Đọc parameters nếu có
                                if len(ex_bytes) >= 32:
                                    num_p = struct.unpack_from("<I", ex_bytes, 28)[0]
                                    for p_idx in range(min(num_p, 4)):
                                        offset_p = 32 + (p_idx * 8)
                                        if offset_p + 8 <= len(ex_bytes):
                                            p_params[p_idx] = struct.unpack_from("<Q", ex_bytes, offset_p)[0]
                            break

            code_hex = bc_code_found if bc_code_found else "0x0"
            name = lookup_bugcheck_name(code_hex) if bc_code_found else "Cần cdb phân tích"

            return DumpHeaderInfo(
                dump_type="mini",
                bugcheck_code=code_hex,
                bugcheck_name=name,
                p1=f"0x{p_params[0]:X}",
                p2=f"0x{p_params[1]:X}",
                p3=f"0x{p_params[2]:X}",
                p4=f"0x{p_params[3]:X}",
                crash_time_utc=crash_time_utc,
                crash_time_source=crash_time_source,
                valid=True,
                signature="MDMP",
            )
        except Exception as e:
            return DumpHeaderInfo(
                signature="MDMP",
                dump_type="mini",
                error_message=f"Lỗi giải mã cấu trúc Minidump MDMP: {e}",
            )

    # =========================================================================
    # 3. Chữ ký không xác định hoặc không hỗ trợ
    # =========================================================================
    sig_repr = header_bytes[:8].decode("ascii", errors="replace")
    return DumpHeaderInfo(
        dump_type="unknown",
        signature=sig_repr,
        error_message=f"Định dạng dump chưa hỗ trợ hoặc file bị hỏng (chữ ký: '{sig_repr}')",
    )
