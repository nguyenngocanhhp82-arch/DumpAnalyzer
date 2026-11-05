"""
Bộ sinh file minidump triage tổng hợp (Synthetic Triage Minidump Generator)
Phục vụ CI, kiểm thử tự động và kiểm tra tính năng cục bộ (selftest) không cần file dump thật.
Tuân thủ đầy đủ đặc tả bố cục nhị phân PAGEDU64 / DumpType=4 (Đợt 05).
"""

import struct
from typing import Dict, List, Optional, Union


def build_synthetic_triage(
    modules: Optional[List[Dict[str, Union[str, int]]]] = None,
    unloaded: Optional[List[str]] = None,
    exception: Optional[Dict[str, Union[str, int, List[int]]]] = None,
    stack_modules: Optional[List[str]] = None,
    bugcheck_code: str = "0x23",
    params: Optional[List[Union[str, int]]] = None,
    os_build: int = 26100,
    system_time_filetime: int = 133715819700000000,  # ~2026-09-23T10:59:30Z
    corrupt_trgd: bool = False,
    corrupt_header_sig: bool = False,
    corrupt_dump_type: Optional[int] = None,
) -> bytes:
    """
    Dựng mảng byte của một minidump triage PAGEDU64 tổng hợp chuẩn mực.
    """
    if modules is None:
        modules = [
            {"name": "ntoskrnl.exe", "base": 0xFFFFF80585C00000, "size": 0x1450000},
            {"name": "fastfat.SYS", "base": 0xFFFFF80590000000, "size": 0x40000},
            {"name": "FLTMGR.SYS", "base": 0xFFFFF80517790000, "size": 0x95000},
            {"name": "bfs.sys", "base": 0xFFFFF80591000000, "size": 0x20000},
            {"name": "uaspstor.sys", "base": 0xFFFFF80592000000, "size": 0x30000},
        ]

    if unloaded is None:
        unloaded = ["USBSTOR.SYS", "hiber_stornv"]

    if exception is None:
        exception = {
            "code": 0xC0000005,
            "address": 0xFFFFF80585ED8334,
            "params": [0, 0x218],
        }

    if stack_modules is None:
        stack_modules = ["ntoskrnl.exe", "fastfat.SYS", "FLTMGR.SYS", "bfs.sys"]

    # 1. Khởi tạo buffer header (0x2100 bytes bao gồm DUMP_HEADER64 và TRIAGE_DUMP64 ban đầu)
    buf = bytearray(0x2100)

    # Chữ ký
    if corrupt_header_sig:
        buf[0:4] = b"XXXX"
        buf[4:8] = b"YYYY"
    else:
        buf[0:4] = b"PAGE"
        buf[4:8] = b"DU64"

    struct.pack_into("<I", buf, 0x08, 15)        # major
    struct.pack_into("<I", buf, 0x0C, os_build)  # build
    struct.pack_into("<I", buf, 0x30, 0x8664)    # machine x64
    struct.pack_into("<I", buf, 0x34, 8)         # processors

    # Bug check code
    bc_int = int(bugcheck_code, 16) if isinstance(bugcheck_code, str) else int(bugcheck_code)
    struct.pack_into("<I", buf, 0x38, bc_int)

    # TopOfStack ảo
    top_of_stack_va = 0xFFFFBB8A25D40000
    exception_va = top_of_stack_va + 0x200
    context_va = top_of_stack_va + 0x400
    rsp_va = top_of_stack_va + 0x600

    # 4 tham số mặc định
    if params is None:
        p1 = 0xE0121
        p2 = exception_va
        p3 = context_va
        p4 = int(exception.get("address", 0xFFFFF80585ED8334))
        p_list = [p1, p2, p3, p4]
    else:
        p_list = [int(x, 16) if isinstance(x, str) else int(x) for x in params]

    for i in range(4):
        struct.pack_into("<Q", buf, 0x40 + 8 * i, p_list[i])

    # DumpType (0xF98)
    dt_val = 4 if corrupt_dump_type is None else corrupt_dump_type
    struct.pack_into("<I", buf, 0xF98, dt_val)

    # SystemTime (0xFA8)
    struct.pack_into("<Q", buf, 0xFA8, system_time_filetime)

    # 2. Xây dựng các vùng sau TRIAGE_BASE (0x2000)
    # Vùng Unloaded drivers
    unloaded_offset = 0x2100
    unloaded_bytes = bytearray()
    unloaded_bytes.extend(struct.pack("<I", len(unloaded)))  # count
    unloaded_bytes.extend(b"\x00\x00\x00\x00")              # 4 byte padding
    for u_name in unloaded:
        u_entry = bytearray(56)  # 0x38 byte
        # Tên UTF-16LE tối đa 12 ký tự (24 bytes) tại offset +0x10
        raw_name = u_name[:12].encode("utf-16le")
        u_entry[0x10:0x10 + len(raw_name)] = raw_name
        unloaded_bytes.extend(u_entry)

    driver_list_offset = unloaded_offset + len(unloaded_bytes)

    # Vùng String Pool: lưu tên các module
    # Tạo danh sách driver entry (144 bytes mỗi entry) và string pool
    string_pool_offset_estimate = driver_list_offset + len(modules) * 144
    # Căn 4 bytes
    if string_pool_offset_estimate % 4 != 0:
        string_pool_offset_estimate += 4 - (string_pool_offset_estimate % 4)

    string_pool_bytes = bytearray()
    driver_entries_bytes = bytearray()

    for m in modules:
        m_name = str(m.get("name", "driver.sys"))
        m_base = int(m.get("base", 0xFFFFF80000000000))
        m_size = int(m.get("size", 0x10000))

        # Lưu tên vào string pool: [u32 char_count] + [utf-16le bytes] + [u16 0] + padding 4
        rel_sp_offset = len(string_pool_bytes)
        name_abs_offset = string_pool_offset_estimate + rel_sp_offset

        encoded_name = m_name.encode("utf-16le") + b"\x00\x00"
        char_count = len(m_name)
        sp_item = struct.pack("<I", char_count) + encoded_name
        if len(sp_item) % 4 != 0:
            sp_item += b"\x00" * (4 - (len(sp_item) % 4))
        string_pool_bytes.extend(sp_item)

        # 144 byte driver entry
        d_entry = bytearray(144)
        struct.pack_into("<Q", d_entry, 0x00, name_abs_offset)
        struct.pack_into("<Q", d_entry, 0x38, m_base)
        struct.pack_into("<I", d_entry, 0x48, m_size)
        driver_entries_bytes.extend(d_entry)

    string_pool_offset = driver_list_offset + len(driver_entries_bytes)
    string_pool_size = len(string_pool_bytes)

    # Vùng Call Stack
    call_stack_offset = string_pool_offset + string_pool_size
    if call_stack_offset % 16 != 0:
        call_stack_offset += 16 - (call_stack_offset % 16)
    size_of_call_stack = 0x4000  # 16 KB
    call_stack_bytes = bytearray(size_of_call_stack)

    # Đặt Exception Record vào call stack tại offset = exception_va - top_of_stack_va
    exc_rel = exception_va - top_of_stack_va
    if 0 <= exc_rel <= size_of_call_stack - 0x100:
        exc_code = int(exception.get("code", 0xC0000005))
        exc_addr = int(exception.get("address", 0xFFFFF80585ED8334))
        exc_params = exception.get("params", [0, 0x218])
        struct.pack_into("<II", call_stack_bytes, exc_rel, exc_code, 0)
        struct.pack_into("<Q", call_stack_bytes, exc_rel + 0x10, exc_addr)
        struct.pack_into("<I", call_stack_bytes, exc_rel + 0x18, len(exc_params))
        for p_idx, p_val in enumerate(exc_params[:4]):
            struct.pack_into("<Q", call_stack_bytes, exc_rel + 0x20 + 8 * p_idx, int(p_val))

    # Đặt Context Record vào call stack tại offset = context_va - top_of_stack_va
    ctx_rel = context_va - top_of_stack_va
    if 0 <= ctx_rel <= size_of_call_stack - 0x100:
        struct.pack_into("<Q", call_stack_bytes, ctx_rel + 0x98, rsp_va)
        rip_val = int(exception.get("address", 0xFFFFF80585ED8334))
        struct.pack_into("<Q", call_stack_bytes, ctx_rel + 0xF8, rip_val)

    # Đặt stack candidates từ rsp_va trở đi
    rsp_rel = rsp_va - top_of_stack_va
    mod_map = {m["name"]: int(m["base"]) for m in modules}
    curr_stack_off = rsp_rel
    for s_mod in stack_modules:
        if s_mod in mod_map and curr_stack_off + 8 <= size_of_call_stack:
            ret_addr = mod_map[s_mod] + 0x1234
            struct.pack_into("<Q", call_stack_bytes, curr_stack_off, ret_addr)
            curr_stack_off += 8

    # Vùng Valid Marker (TRGD)
    valid_offset = call_stack_offset + size_of_call_stack
    size_of_dump = valid_offset + 4

    # Ghi cấu trúc TRIAGE_BASE (0x2000..0x2048)
    triage_fields = [
        os_build,                    # ServicePackBuild
        size_of_dump,                # SizeOfDump
        valid_offset,                # ValidOffset
        0,                           # ContextOffset
        0,                           # ExceptionOffset
        0,                           # MmOffset
        unloaded_offset,             # UnloadedDriversOffset
        0,                           # PrcbOffset
        0,                           # ProcessOffset
        0,                           # ThreadOffset
        call_stack_offset,           # CallStackOffset
        size_of_call_stack,          # SizeOfCallStack
        driver_list_offset,          # DriverListOffset
        len(modules),                # DriverCount
        string_pool_offset,          # StringPoolOffset
        string_pool_size,            # StringPoolSize
        0,                           # BrokenDriverOffset
        0,                           # TriageOptions
    ]
    struct.pack_into("<18I", buf, 0x2000, *triage_fields)
    struct.pack_into("<Q", buf, 0x2048, top_of_stack_va)

    # Ghép toàn bộ các vùng lại thành file hoàn chỉnh
    full_dump = bytearray(size_of_dump)
    full_dump[0:len(buf)] = buf
    full_dump[unloaded_offset:unloaded_offset + len(unloaded_bytes)] = unloaded_bytes
    full_dump[driver_list_offset:driver_list_offset + len(driver_entries_bytes)] = driver_entries_bytes
    full_dump[string_pool_offset:string_pool_offset + len(string_pool_bytes)] = string_pool_bytes
    full_dump[call_stack_offset:call_stack_offset + len(call_stack_bytes)] = call_stack_bytes

    # Ghi marker TRGD
    marker = b"XXXX" if corrupt_trgd else b"TRGD"
    full_dump[valid_offset:valid_offset + 4] = marker

    return bytes(full_dump)
