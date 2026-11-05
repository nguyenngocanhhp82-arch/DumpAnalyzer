"""
Bộ đọc minidump kiểu Triage (DumpType = 4) bằng Python thuần (Đợt 05).
Không cần cdb.exe, WinDbg hay Symbol server.

Tuân thủ nguyên tắc:
- N1: Không bao giờ ném ngoại lệ vì dữ liệu hỏng.
- N2: Kiểm tra giới hạn mọi offset/kích thước/số lượng.
- N3: Chỉ đọc phần cần thiết, không đọc/lưu bộ nhớ thô, tiến trình, luồng.
- N4: Phân biệt đã kiểm chứng (0x23, build 26100) và chưa kiểm chứng.
- N5: Quét ngăn xếp chỉ là ứng viên (heuristic), tối đa mức vừa.
"""

from dataclasses import dataclass, field
import datetime
from pathlib import Path
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

from dumpanalyzer.core.logging_setup import get_logger

logger = get_logger("triage_reader")

# ---- HẰNG SỐ CẤU TRÚC MINIDUMP TRIAGE (Offset tuyệt đối từ đầu file) ---------
HDR_SIGNATURE = 0x00          # b'PAGE'
HDR_VALIDDUMP = 0x04          # b'DU64'
HDR_MAJOR = 0x08              # u32
HDR_MINOR = 0x0C              # u32 (build number, ví dụ 26100)
HDR_MACHINE = 0x30            # u32 (0x8664 = x64)
HDR_NPROC = 0x34              # u32
HDR_BUGCHECK = 0x38           # u32
HDR_PARAMS = 0x40             # 4 x u64
HDR_DUMPTYPE = 0xF98          # u32 (1=full, 2=kernel, 3=header, 4=triage)
HDR_SYSTEMTIME = 0xFA8        # u64 FILETIME (UTC)
TRIAGE_BASE = 0x2000          # Cấu trúc TRIAGE_DUMP64 bắt đầu ngay sau DUMP_HEADER64
TRIAGE_FIELDS = [
    "ServicePackBuild", "SizeOfDump", "ValidOffset", "ContextOffset",
    "ExceptionOffset", "MmOffset", "UnloadedDriversOffset", "PrcbOffset",
    "ProcessOffset", "ThreadOffset", "CallStackOffset", "SizeOfCallStack",
    "DriverListOffset", "DriverCount", "StringPoolOffset", "StringPoolSize",
    "BrokenDriverOffset", "TriageOptions",
]                             # 18 x u32 bắt đầu tại 0x2000
TRIAGE_TOP_OF_STACK = TRIAGE_BASE + 72   # u64: địa chỉ ảo của byte đầu vùng call stack
VALID_MARKER = b"TRGD"        # 4 byte tại ValidOffset

DRIVER_ENTRY_STRIDE = 144     # 0x90 bytes mỗi entry driver
DRV_OFF_NAME_PTR = 0x00       # u64 offset tuyệt đối tới bản ghi tên trong string pool
DRV_OFF_DLLBASE = 0x38        # u64
DRV_OFF_SIZE = 0x48           # u32

UNLOADED_ENTRY_STRIDE = 56    # 0x38 bytes mỗi entry driver đã gỡ
UNLOADED_NAME_OFF = 0x10      # Tên UTF-16 tối đa 12 ký tự (24 bytes) tại offset +0x10

MAX_DRIVERS = 2000
MAX_STRING_POOL = 1 << 20     # 1 MB
MAX_UNLOADED = 256
DEFAULT_MAX_TRIAGE_BYTES = 16 << 20  # 16 MB
DEFAULT_MAX_STACK_CANDIDATES = 200

# Danh sách Bug Check đã kiểm chứng hỗ trợ đọc exception từ param 2 và 3
SUPPORTED_EXCEPTION_BUGCHECKS = {"0x23", "0x24"}


@dataclass
class TriageResult:
    """Kết quả phân tích minidump triage không cần cdb."""
    ok: bool = False
    warnings: List[str] = field(default_factory=list)
    file_size: int = 0
    header: Dict[str, Any] = field(default_factory=dict)
    exception: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    modules: List[Dict[str, Any]] = field(default_factory=list)
    unloaded: List[str] = field(default_factory=list)
    stack_candidates: List[Dict[str, Any]] = field(default_factory=list)
    stack_modules_in_order: List[str] = field(default_factory=list)
    stack_module_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Chuyển thành dictionary an toàn để lưu CSDL hoặc xuất JSON."""
        return {
            "ok": self.ok,
            "warnings": self.warnings,
            "file_size": self.file_size,
            "header": self.header,
            "exception": self.exception,
            "context": self.context,
            "modules_count": len(self.modules),
            "modules": self.modules[:300],  # Giới hạn an toàn kích thước
            "unloaded": self.unloaded[:256],
            "stack_candidates": self.stack_candidates[:200],
            "stack_modules_in_order": self.stack_modules_in_order,
            "stack_module_counts": self.stack_module_counts,
        }


def _filetime_to_iso(v: int) -> Optional[str]:
    """Chuyển Windows FILETIME sang chuỗi ISO UTC (kiểm tra năm 2000..2100)."""
    if v <= 0:
        return None
    try:
        epoch_seconds = (v / 10_000_000) - 11_644_473_600
        dt = datetime.datetime.fromtimestamp(epoch_seconds, tz=datetime.timezone.utc)
        if 2000 <= dt.year <= 2100:
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        pass
    return None


def _u32(b: Union[bytes, bytearray], o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def _u64(b: Union[bytes, bytearray], o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def read_triage(
    path: Union[str, Path],
    *,
    max_bytes: int = DEFAULT_MAX_TRIAGE_BYTES,
    max_stack_candidates: int = DEFAULT_MAX_STACK_CANDIDATES,
    exception_bugchecks: Optional[List[str]] = None,
) -> TriageResult:
    """
    Đọc và giải mã minidump triage PAGEDU64 từ tệp dump.
    Tuyệt đối không ném ngoại lệ ra ngoài (N1).
    """
    res = TriageResult()
    w = res.warnings
    allowed_exc_bcs = set(exception_bugchecks) if exception_bugchecks else SUPPORTED_EXCEPTION_BUGCHECKS

    path_obj = Path(path)
    if not path_obj.exists() or not path_obj.is_file():
        w.append(f"Tệp không tồn tại: {path}")
        return res

    try:
        res.file_size = path_obj.stat().st_size
        if res.file_size < TRIAGE_BASE + 0x80:
            w.append("File quá nhỏ cho một dump PAGEDU64.")
            return res

        # 1. Đọc phần đầu file (tối thiểu TRIAGE_BASE + 0x80 bytes để lấy header và triage table)
        read_initial = min(res.file_size, TRIAGE_BASE + 0x100)
        with open(path_obj, "rb") as f:
            head = f.read(read_initial)

            if len(head) < TRIAGE_BASE + 0x80:
                w.append("Header PAGEDU64 không đầy đủ.")
                return res

            if head[0:4] != b"PAGE" or head[4:8] != b"DU64":
                w.append("Signature dump không hợp lệ (không phải PAGEDU64 x64). Không hỗ trợ định dạng này.")
                return res

            # Parse header cơ bản
            hdr = res.header
            hdr["os_major"] = _u32(head, HDR_MAJOR)
            hdr["os_build"] = _u32(head, HDR_MINOR)
            hdr["machine"] = hex(_u32(head, HDR_MACHINE))
            hdr["processors"] = _u32(head, HDR_NPROC)
            bc_code_raw = _u32(head, HDR_BUGCHECK)
            hdr["bugcheck_code"] = f"0x{bc_code_raw:X}"
            hdr["params"] = [f"0x{_u64(head, HDR_PARAMS + 8 * i):X}" for i in range(4)]
            hdr["dump_type"] = _u32(head, HDR_DUMPTYPE)
            hdr["dump_type_name"] = {1: "full", 2: "kernel", 3: "header", 4: "triage"}.get(
                hdr["dump_type"], "unknown"
            )
            hdr["system_time_utc"] = _filetime_to_iso(_u64(head, HDR_SYSTEMTIME))
            if hdr["system_time_utc"] is None:
                w.append("SystemTime trong header không hợp lệ; nên dùng giờ sửa file và đánh dấu nguồn 'mtime'.")

            # Nếu không phải dump triage (DumpType != 4), dừng sớm, trả header
            if hdr["dump_type"] != 4:
                w.append("Không phải dump triage: chỉ đọc được header. Dùng cdb để phân tích sâu.")
                res.ok = True
                return res

            # Đọc cấu trúc triage tại 0x2000
            t_values = struct.unpack_from("<18I", head, TRIAGE_BASE)
            t: Dict[str, int] = dict(zip(TRIAGE_FIELDS, t_values))
            top_of_stack = _u64(head, TRIAGE_TOP_OF_STACK)

            end = t["SizeOfDump"]
            if not (TRIAGE_BASE < end <= max_bytes) or end > res.file_size:
                w.append(f"SizeOfDump bất thường ({end}).")
                return res

            # Đọc toàn bộ vùng triage hợp lệ
            f.seek(0)
            d = f.read(end)

        # 2. Kiểm tra dấu hiệu hợp lệ TRGD
        vo = t["ValidOffset"]
        if vo + 4 <= len(d):
            if d[vo:vo + 4] != VALID_MARKER:
                w.append("Dấu hiệu hợp lệ triage (TRGD) không khớp; dữ liệu có thể không đáng tin.")
        else:
            w.append("ValidOffset nằm ngoài phạm vi SizeOfDump.")

        # 3. Đọc danh sách Module và String Pool
        mods: List[Dict[str, Any]] = []
        cnt = t["DriverCount"]
        base = t["DriverListOffset"]
        sp_off, sp_size = t["StringPoolOffset"], t["StringPoolSize"]

        if 0 < cnt <= MAX_DRIVERS and base + cnt * DRIVER_ENTRY_STRIDE <= len(d) and sp_size <= MAX_STRING_POOL:
            for i in range(cnt):
                e = base + i * DRIVER_ENTRY_STRIDE
                noff = _u64(d, e + DRV_OFF_NAME_PTR)
                name = "?"
                if sp_off <= noff < sp_off + sp_size and noff + 4 <= len(d):
                    n_chars = _u32(d, noff)
                    if 0 < n_chars <= 128 and noff + 4 + 2 * n_chars <= len(d):
                        try:
                            name = d[noff + 4:noff + 4 + 2 * n_chars].decode("utf-16le", "replace")
                        except Exception:
                            name = "?"
                dllbase = _u64(d, e + DRV_OFF_DLLBASE)
                size = _u32(d, e + DRV_OFF_SIZE)
                if dllbase and size:
                    mods.append({"name": name, "base": dllbase, "size": size})
        else:
            w.append("Danh sách module không đọc được (DriverCount/offset bất thường).")

        res.modules = [{"name": m["name"], "base": f"0x{m['base']:X}", "size": m["size"]} for m in mods]

        def mod_of(addr: int) -> Optional[Tuple[str, int]]:
            """Tìm module chứa địa chỉ và tính offset tương đối."""
            for m in mods:
                if m["base"] <= addr < m["base"] + m["size"]:
                    return m["name"], addr - m["base"]
            return None

        # 4. Đọc danh sách Driver đã gỡ (Unloaded Drivers)
        uo = t["UnloadedDriversOffset"]
        if 0 < uo < base <= len(d):
            ucount = _u32(d, uo)
            first = uo + 8  # 4 bytes count + 4 bytes padding
            if ucount <= MAX_UNLOADED and first + ucount * UNLOADED_ENTRY_STRIDE <= len(d):
                for i in range(ucount):
                    eo = first + i * UNLOADED_ENTRY_STRIDE + UNLOADED_NAME_OFF
                    raw = d[eo:eo + 24]
                    try:
                        nm = raw.decode("utf-16le", "replace").split("\x00")[0]
                        if nm:
                            res.unloaded.append(nm)
                    except Exception:
                        pass
            else:
                w.append("Danh sách driver đã gỡ không đọc được.")

        # 5. Ánh xạ Call Stack
        cso, csz = t["CallStackOffset"], t["SizeOfCallStack"]

        def stack_off(va: int, length: int = 8) -> Optional[int]:
            o = va - top_of_stack
            if 0 <= o and o + length <= csz and cso + o + length <= len(d):
                return cso + o
            return None

        # 6. Exception Record & Context Record
        # Chỉ áp dụng diễn giải tham số 2/3 là ngoại lệ khi Bug Check thuộc danh sách đã kiểm chứng
        current_bc = hdr["bugcheck_code"].upper()
        norm_bc = f"0x{int(current_bc, 16):X}" if current_bc.startswith("0X") else current_bc

        hp = [int(x, 16) for x in hdr["params"]]
        rsp: Optional[int] = None

        if norm_bc in allowed_exc_bcs or current_bc in allowed_exc_bcs:
            if stack_off(hp[1], 0x20 + 8 * 4) is None:
                w.append(f"exception_from_p2: địa chỉ 0x{hp[1]:X} nằm ngoài vùng call stack của dump.")
            else:
                eo = stack_off(hp[1], 0x20 + 8 * 4)
                if eo is not None:
                    code, flags = struct.unpack_from("<II", d, eo)
                    addr = _u64(d, eo + 0x10)
                    npar = min(_u32(d, eo + 0x18), 15)
                    info = [_u64(d, eo + 0x20 + 8 * i) for i in range(min(npar, 4))]
                    m = mod_of(addr)
                    res.exception = {
                        "code": f"0x{code:08X}",
                        "flags": flags,
                        "address": f"0x{addr:X}",
                        "module": m[0] if m else None,
                        "module_offset": f"0x{m[1]:X}" if m else None,
                        "parameters": [f"0x{x:X}" for x in info],
                    }
                    if code == 0xC0000005 and len(info) >= 2:
                        acc_type = {0: "ĐỌC", 1: "GHI", 8: "THỰC THI"}.get(info[0], "truy cập")
                        null_note = " (con trỏ NULL + offset nhỏ)" if info[1] < 0x10000 else ""
                        res.exception["meaning"] = f"Access violation: {acc_type} địa chỉ 0x{info[1]:X}{null_note}"

            if stack_off(hp[2], 0x100) is None:
                w.append(f"context_from_p3: địa chỉ 0x{hp[2]:X} nằm ngoài vùng call stack của dump.")
            else:
                co = stack_off(hp[2], 0x100)
                if co is not None:
                    rsp = _u64(d, co + 0x98)
                    rip = _u64(d, co + 0xF8)
                    m = mod_of(rip)
                    res.context = {
                        "rip": f"0x{rip:X}",
                        "rsp": f"0x{rsp:X}",
                        "rip_module": m[0] if m else None,
                        "rip_module_offset": f"0x{m[1]:X}" if m else None,
                    }
        else:
            # Bug Check khác: chưa kiểm chứng quy ước p2/p3 là ngoại lệ
            logger.debug(f"Bug Check {current_bc} chưa kiểm chứng cấu trúc ngoại lệ p2/p3. Bỏ qua ExceptionRecord.")

        # 7. Quét Call Stack tìm ứng viên địa chỉ trả về (Heuristic - N5)
        start = (rsp - top_of_stack) if (rsp and top_of_stack <= rsp < top_of_stack + csz) else 0
        start -= start % 8

        cands: List[Dict[str, Any]] = []
        for i in range(start, csz - 7, 8):
            if len(cands) >= max_stack_candidates:
                break
            v = _u64(d, cso + i)
            m = mod_of(v)
            if m:
                rsp_off = hex(top_of_stack + i - (rsp or top_of_stack)) if rsp else hex(i)
                cands.append({
                    "rsp_offset": rsp_off,
                    "address": f"0x{v:X}",
                    "module": m[0],
                    "offset": f"0x{m[1]:X}",
                })

        res.stack_candidates = cands

        # Danh sách module theo thứ tự xuất hiện đầu tiên
        order: List[str] = []
        seen = set()
        for c in cands:
            mod_name = c["module"]
            if mod_name not in seen:
                seen.add(mod_name)
                order.append(mod_name)
        res.stack_modules_in_order = order

        # Số lần xuất hiện của mỗi module trong stack
        counts: Dict[str, int] = {}
        for c in cands:
            mod_name = c["module"]
            counts[mod_name] = counts.get(mod_name, 0) + 1
        res.stack_module_counts = counts

        res.ok = True

    except Exception as ex:
        # Chốt chặn cuối cùng theo N1: không bao giờ để crash chương trình
        w.append(f"Lỗi không mong đợi khi đọc dump: {type(ex).__name__}: {ex}")
        logger.warning(f"Lỗi triage_reader khi đọc {path}: {ex}", exc_info=True)

    return res
