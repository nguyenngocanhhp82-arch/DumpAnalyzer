#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MÃ THAM CHIẾU: đọc minidump kiểu "triage" của Windows (PAGEDU64, DumpType = 4)
bằng Python thuần, KHÔNG cần cdb/WinDbg/symbol.

Đã kiểm chứng trên MỘT file mẫu duy nhất: 092326-67062-01.dmp
(Windows 11 build 26100, x64, Bug Check 0x23). Các offset có thể khác ở dump
của phiên bản Windows khác -> mọi phần đều phải chịu lỗi và trả cảnh báo
thay vì ném ngoại lệ. Đây là MÃ THAM CHIẾU để Antigravity tích hợp vào dự án
(analyzer/triage_reader.py), không phải mã sản xuất.

Cách chạy thử:
    python triage_reader_reference.py <file.dmp> [--json]
"""
import datetime
import json
import os
import struct
import sys

# ---- Hằng số cấu trúc (offset TUYỆT ĐỐI tính từ đầu file) -------------------
HDR_SIGNATURE = 0x00          # b'PAGE'
HDR_VALIDDUMP = 0x04          # b'DU64'
HDR_MAJOR = 0x08              # u32
HDR_MINOR = 0x0C              # u32 (build number, vd 26100)
HDR_MACHINE = 0x30            # u32 (0x8664 = x64)
HDR_NPROC = 0x34              # u32
HDR_BUGCHECK = 0x38           # u32
HDR_PARAMS = 0x40             # 4 x u64
HDR_DUMPTYPE = 0xF98          # u32 (1=full, 2=kernel/summary, 3=header, 4=triage)
HDR_REQUIRED_SPACE = 0xFA0    # u64
HDR_SYSTEMTIME = 0xFA8        # u64 FILETIME (UTC)  <- ĐÃ KIỂM CHỨNG
TRIAGE_BASE = 0x2000          # cấu trúc TRIAGE_DUMP64 ngay sau DUMP_HEADER64
TRIAGE_FIELDS = [
    "ServicePackBuild", "SizeOfDump", "ValidOffset", "ContextOffset",
    "ExceptionOffset", "MmOffset", "UnloadedDriversOffset", "PrcbOffset",
    "ProcessOffset", "ThreadOffset", "CallStackOffset", "SizeOfCallStack",
    "DriverListOffset", "DriverCount", "StringPoolOffset", "StringPoolSize",
    "BrokenDriverOffset", "TriageOptions",
]                              # 18 x u32 bắt đầu tại 0x2000
TRIAGE_TOP_OF_STACK = TRIAGE_BASE + 72   # u64: địa chỉ ảo của byte đầu vùng call stack
VALID_MARKER = b"TRGD"         # 4 byte cuối vùng triage (tại ValidOffset)

DRIVER_ENTRY_STRIDE = 144      # 0x90
DRV_OFF_NAME_PTR = 0x00        # u64: offset (tuyệt đối) tới bản ghi tên trong string pool
DRV_OFF_DLLBASE = 0x38         # u64
DRV_OFF_SIZE = 0x48            # u32
UNLOADED_ENTRY_STRIDE = 0x38   # 56 byte; tên (tối đa 12 ký tự) nằm tại +0x10
UNLOADED_NAME_OFF = 0x10

MAX_DRIVERS = 2000
MAX_STRING_POOL = 1 << 20
MAX_TRIAGE_BYTES = 16 << 20    # không đọc quá 16 MB đầu file


def _filetime_to_iso(v):
    try:
        t = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=v / 10)
        if 2000 <= t.year <= 2100:
            return t.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        pass
    return None


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def read_triage(path):
    """Trả về dict kết quả; KHÔNG ném ngoại lệ vì dữ liệu hỏng (chỉ cảnh báo)."""
    res = {
        "ok": False, "warnings": [], "file_size": 0,
        "header": {}, "exception": {}, "context": {},
        "modules": [], "unloaded": [], "stack_candidates": [],
    }
    w = res["warnings"]
    try:
        res["file_size"] = os.path.getsize(path)
        with open(path, "rb") as f:
            head = f.read(TRIAGE_BASE + 0x80)
            if len(head) < TRIAGE_BASE + 0x80:
                w.append("File quá nhỏ cho một dump PAGEDU64.")
                return res
            if head[0:4] != b"PAGE" or head[4:8] != b"DU64":
                w.append("Không phải dump PAGEDU64 (x64). Không hỗ trợ định dạng này.")
                return res

            hdr = res["header"]
            hdr["os_major"] = _u32(head, HDR_MAJOR)
            hdr["os_build"] = _u32(head, HDR_MINOR)
            hdr["machine"] = hex(_u32(head, HDR_MACHINE))
            hdr["processors"] = _u32(head, HDR_NPROC)
            hdr["bugcheck_code"] = "0x%X" % _u32(head, HDR_BUGCHECK)
            hdr["params"] = ["0x%X" % _u64(head, HDR_PARAMS + 8 * i) for i in range(4)]
            hdr["dump_type"] = _u32(head, HDR_DUMPTYPE)
            hdr["dump_type_name"] = {1: "full", 2: "kernel", 3: "header", 4: "triage"}.get(
                hdr["dump_type"], "unknown")
            hdr["system_time_utc"] = _filetime_to_iso(_u64(head, HDR_SYSTEMTIME))
            if hdr["system_time_utc"] is None:
                w.append("SystemTime trong header không hợp lệ; nên dùng giờ sửa file và đánh dấu nguồn 'mtime'.")

            if hdr["dump_type"] != 4:
                w.append("Không phải dump triage: chỉ đọc được header. Dùng cdb để phân tích sâu.")
                res["ok"] = True
                return res

            t = dict(zip(TRIAGE_FIELDS, struct.unpack_from("<18I", head, TRIAGE_BASE)))
            top = _u64(head, TRIAGE_TOP_OF_STACK)
            res["triage"] = {k: v for k, v in t.items()}
            res["triage"]["TopOfStack"] = "0x%X" % top

            end = t["SizeOfDump"]
            if not (TRIAGE_BASE < end <= MAX_TRIAGE_BYTES) or end > res["file_size"]:
                w.append("SizeOfDump bất thường (%d)." % end)
                return res
            f.seek(0)
            d = f.read(end)

        # --- Dấu hiệu hợp lệ cuối vùng triage
        vo = t["ValidOffset"]
        if vo + 4 <= len(d) and d[vo:vo + 4] != VALID_MARKER:
            w.append("Dấu hiệu hợp lệ triage (TRGD) không khớp; dữ liệu có thể không đáng tin.")

        # --- Danh sách module + string pool
        mods = []
        cnt = t["DriverCount"]
        base = t["DriverListOffset"]
        sp_off, sp_size = t["StringPoolOffset"], t["StringPoolSize"]
        if 0 < cnt <= MAX_DRIVERS and base + cnt * DRIVER_ENTRY_STRIDE <= len(d) and sp_size <= MAX_STRING_POOL:
            for i in range(cnt):
                e = base + i * DRIVER_ENTRY_STRIDE
                noff = _u64(d, e + DRV_OFF_NAME_PTR)
                name = "?"
                if sp_off <= noff < sp_off + sp_size and noff + 4 <= len(d):
                    n = _u32(d, noff)
                    if 0 < n <= 128 and noff + 4 + 2 * n <= len(d):
                        name = d[noff + 4:noff + 4 + 2 * n].decode("utf-16le", "replace")
                dllbase = _u64(d, e + DRV_OFF_DLLBASE)
                size = _u32(d, e + DRV_OFF_SIZE)
                if dllbase and size:
                    mods.append({"name": name, "base": dllbase, "size": size})
        else:
            w.append("Danh sách module không đọc được (DriverCount/offset bất thường).")
        res["modules"] = [{"name": m["name"], "base": "0x%X" % m["base"], "size": m["size"]} for m in mods]

        def mod_of(a):
            for m in mods:
                if m["base"] <= a < m["base"] + m["size"]:
                    return m["name"], a - m["base"]
            return None

        # --- Driver đã gỡ (unloaded): vùng [UnloadedDriversOffset, DriverListOffset)
        uo = t["UnloadedDriversOffset"]
        if 0 < uo < base <= len(d):
            ucount = _u32(d, uo)
            first = uo + 8
            if ucount <= 256 and first + ucount * UNLOADED_ENTRY_STRIDE <= len(d):
                for i in range(ucount):
                    eo = first + i * UNLOADED_ENTRY_STRIDE + UNLOADED_NAME_OFF
                    raw = d[eo:eo + 24]
                    nm = raw.decode("utf-16le", "replace").split("\x00")[0]
                    if nm:
                        res["unloaded"].append(nm)
            else:
                w.append("Danh sách driver đã gỡ không đọc được.")

        # --- Ánh xạ địa chỉ ảo -> offset file trong vùng call stack
        cso, csz = t["CallStackOffset"], t["SizeOfCallStack"]

        def stack_off(va, length=8):
            o = va - top
            if 0 <= o and o + length <= csz and cso + o + length <= len(d):
                return cso + o
            return None

        hp = [int(x, 16) for x in hdr["params"]]
        # --- Exception record & context record (với Bug Check 0x23, p2/p3)
        for label, va in (("exception_from_p2", hp[1]), ("context_from_p3", hp[2])):
            if stack_off(va, 0x100) is None:
                w.append("%s: địa chỉ 0x%X nằm ngoài vùng call stack của dump." % (label, va))
        eo = stack_off(hp[1], 0x20 + 8 * 4)
        if eo is not None:
            code, flags = struct.unpack_from("<II", d, eo)
            addr = _u64(d, eo + 0x10)
            npar = min(_u32(d, eo + 0x18), 15)
            info = [_u64(d, eo + 0x20 + 8 * i) for i in range(min(npar, 4))]
            m = mod_of(addr)
            res["exception"] = {
                "code": "0x%08X" % code, "flags": flags, "address": "0x%X" % addr,
                "module": m[0] if m else None, "module_offset": ("0x%X" % m[1]) if m else None,
                "parameters": ["0x%X" % x for x in info],
            }
            if code == 0xC0000005 and len(info) >= 2:
                res["exception"]["meaning"] = "Access violation: %s địa chỉ 0x%X%s" % (
                    {0: "ĐỌC", 1: "GHI", 8: "THỰC THI"}.get(info[0], "truy cập"), info[1],
                    " (con trỏ NULL + offset nhỏ)" if info[1] < 0x10000 else "")
        co = stack_off(hp[2], 0x100)
        rsp = None
        if co is not None:
            rsp = _u64(d, co + 0x98)
            rip = _u64(d, co + 0xF8)
            m = mod_of(rip)
            res["context"] = {"rip": "0x%X" % rip, "rsp": "0x%X" % rsp,
                              "rip_module": m[0] if m else None,
                              "rip_module_offset": ("0x%X" % m[1]) if m else None}

        # --- Quét call stack tìm địa chỉ trả về nằm trong module (HEURISTIC)
        start = (rsp - top) if (rsp and top <= rsp < top + csz) else 0
        start -= start % 8
        cands = []
        for i in range(start, csz - 7, 8):
            v = _u64(d, cso + i)
            m = mod_of(v)
            if m:
                cands.append({"rsp_offset": hex(top + i - (rsp or top)) if rsp else hex(i),
                              "address": "0x%X" % v, "module": m[0], "offset": "0x%X" % m[1]})
        res["stack_candidates"] = cands
        order, seen = [], set()
        for c in cands:
            if c["module"] not in seen:
                seen.add(c["module"]); order.append(c["module"])
        res["stack_modules_in_order"] = order
        counts = {}
        for c in cands:
            counts[c["module"]] = counts.get(c["module"], 0) + 1
        res["stack_module_counts"] = counts
        res["ok"] = True
    except Exception as ex:  # chốt chặn cuối: không bao giờ làm sập chương trình
        w.append("Lỗi không mong đợi khi đọc dump: %s: %s" % (type(ex).__name__, ex))
    return res


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    out = read_triage(sys.argv[1])
    if "--json" in sys.argv:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        h, ex = out["header"], out["exception"]
        print("OK:", out["ok"], "| cảnh báo:", out["warnings"])
        print("OS build:", h.get("os_build"), "| loại dump:", h.get("dump_type_name"),
              "| giờ (UTC):", h.get("system_time_utc"))
        print("Bug Check:", h.get("bugcheck_code"), h.get("params"))
        print("Ngoại lệ:", ex)
        print("Module trong stack (theo thứ tự):", out.get("stack_modules_in_order"))
        print("Số module:", len(out["modules"]), "| driver đã gỡ:", len(out["unloaded"]))
