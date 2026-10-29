"""
Giao diện dòng lệnh (CLI) của DumpAnalyzer.
Cung cấp các công cụ kiểm tra môi trường, quét dump và kích hoạt phân tích không cần GUI.
"""

import sys
import argparse
import json
from pathlib import Path
from dumpanalyzer import __version__
from dumpanalyzer.core.config import (
    check_environment_summary,
    get_project_root,
    load_settings,
)
from dumpanalyzer.core.logging_setup import setup_logging


from dumpanalyzer.collectors.dump_finder import find_dumps, copy_dump_safely, calculate_sha256
from dumpanalyzer.analyzer.header_parser import parse_dump_header
from dumpanalyzer.storage.db import Database
from dumpanalyzer.core.models import Crash
from dumpanalyzer.core.timeutil import utc_to_local_str
from dumpanalyzer.collectors.dump_config import (
    read_registry_crash_control,
    check_pagefile_status,
    check_disk_space_and_ram,
    check_volmgr_events,
    evaluate_readiness,
    apply_automatic_dump,
    CRASH_DUMP_MODES,
)
from dumpanalyzer.analyzer.cdb_runner import (
    analyze_dump_file,
    analyze_dumps_parallel,
    warmup_symbols,
)



def print_banner():
    banner = f"""
======================================================================
  DumpAnalyzer v{__version__} - Chẩn đoán Dump BSOD & Windows Event Log
  Dành cho Kỹ thuật viên & Quản trị hệ thống IT
======================================================================
"""
    print(banner.strip())


def cmd_scan(args):
    """Quét tìm file dump, đọc header mã lỗi, kiểm tra cache SHA256 và lưu vào SQLite."""
    print_banner()
    settings = load_settings()

    # Xác định đường dẫn quét
    if args.path:
        search_paths = [args.path]
    else:
        search_paths = settings.get("dump_search_paths", [])

    working_dir = Path(settings.get("working_dir", "./workspace"))
    working_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n[*] Đang quét tìm file dump tại: {', '.join(search_paths)}")
    if args.from_date or args.to_date:
        print(f"    Khoảng thời gian: Từ {args.from_date or 'đầu'} đến {args.to_date or 'nay'}")

    dumps = find_dumps(search_paths, from_date=args.from_date, to_date=args.to_date)

    if not dumps:
        print("\n[!] Không tìm thấy file dump nào trong phạm vi đã chọn.")
        return 0

    print(f"[OK] Tìm thấy {len(dumps)} file dump. Đang tiến hành đọc header...\n")

    db = Database()
    results = []

    for item in dumps:
        src_path = item["path"]
        try:
            sha256_hash = calculate_sha256(src_path)
        except Exception as e:
            print(f"[Cảnh báo] Không thể đọc mã hash file {src_path}: {e}")
            continue

        # 1. Kiểm tra cache trong DB
        cached_crash = db.get_crash_by_sha256(sha256_hash)
        if cached_crash and not args.force:
            results.append({
                "time_str": utc_to_local_str(cached_crash["crash_time_utc"]),
                "bugcheck_code": cached_crash["bugcheck_code"] or "N/A",
                "bugcheck_name": cached_crash["bugcheck_name"] or "Không rõ",
                "dump_type": cached_crash["dump_type"] or "mini",
                "status": "[CACHE]",
                "path": str(src_path),
            })
            continue

        # 2. Copy an toàn sang workspace
        try:
            copied_path = copy_dump_safely(src_path, working_dir, file_sha256=sha256_hash)
        except Exception as e:
            print(f"[Cảnh báo] Không thể sao chép {src_path.name}: {e}")
            copied_path = src_path

        # 3. Đọc header
        header_info = parse_dump_header(copied_path)

        # 4. Lưu vào SQLite
        crash_record = Crash(
            dump_path=str(copied_path),
            dump_sha256=sha256_hash,
            dump_type=header_info.dump_type,
            crash_time_utc=header_info.crash_time_utc,
            bugcheck_code=header_info.bugcheck_code,
            bugcheck_name=header_info.bugcheck_name,
            p1=header_info.p1,
            p2=header_info.p2,
            p3=header_info.p3,
            p4=header_info.p4,
            analyzed_by="header_only",
        )

        try:
            if not cached_crash:
                db.insert_crash(crash_record)
        except Exception as e:
            print(f"[Cảnh báo] Lỗi lưu vào CSDL: {e}")

        status_tag = "[MỚI]" if not cached_crash else "[CẬP NHẬT]"
        results.append({
            "time_str": utc_to_local_str(header_info.crash_time_utc),
            "bugcheck_code": header_info.bugcheck_code or "N/A",
            "bugcheck_name": header_info.bugcheck_name or "Chưa rõ",
            "dump_type": header_info.dump_type,
            "status": status_tag,
            "path": str(src_path),
        })

    db.close()

    # In bảng kết quả
    col_time = 20
    col_code = 12
    col_name = 32
    col_type = 8
    col_status = 9

    header_line = (
        f"{'Thời điểm (Giờ địa phương)':<{col_time}} | "
        f"{'Mã lỗi':<{col_code}} | "
        f"{'Tên lỗi BugCheck':<{col_name}} | "
        f"{'Loại':<{col_type}} | "
        f"{'Trạng thái':<{col_status}} | "
        f"Đường dẫn file"
    )
    separator = "-" * len(header_line) + "-" * 20

    print(separator)
    print(header_line)
    print(separator)

    for r in results:
        t_str = r["time_str"][:col_time]
        c_str = r["bugcheck_code"][:col_code]
        n_str = r["bugcheck_name"][:col_name]
        tp_str = r["dump_type"][:col_type]
        st_str = r["status"][:col_status]
        p_str = r["path"]
        print(f"{t_str:<{col_time}} | {c_str:<{col_code}} | {n_str:<{col_name}} | {tp_str:<{col_type}} | {st_str:<{col_status}} | {p_str}")

    print(separator)
    print(f"Tổng số: {len(results)} file dump được hiển thị.\n")
    return 0


def cmd_check_env(args):
    """Thực hiện kiểm tra toàn diện môi trường chạy của hệ thống."""
    print_banner()
    print("\n--- ĐANG KIỂM TRA MÔI TRƯỜNG HỆ THỐNG ---")

    env = check_environment_summary()

    # 1. Hệ điều hành & Python
    print(f"\n[1] Môi trường thực thi:")
    print(f"    - Nền tảng HĐH:     {env['os_platform']}")
    print(f"    - Phiên bản Python: {env['python_version']}")

    # 2. Quyền Administrator
    print(f"\n[2] Quyền thực thi:")
    if env["is_admin"]:
        print("    [OK] Đang chạy với quyền Administrator (hoặc root).")
    else:
        print("    [!] Chưa có quyền Administrator.")
        if env["os_platform"] == "win32":
            print("        -> LƯU Ý: Một số file tại 'C:\\Windows\\Minidump' và 'MEMORY.DMP'")
            print("           yêu cầu quyền Admin để đọc. Hãy mở Terminal bằng 'Run as administrator'.")

    # 3. Công cụ cdb.exe (Windows Debugging Tools)
    print(f"\n[3] Công cụ gỡ lỗi Windows (cdb.exe):")
    if env["cdb_found"]:
        print(f"    [OK] Đã phát hiện cdb.exe tại: {env['cdb_path']}")
    else:
        print("    [X] KHÔNG tìm thấy cdb.exe trên hệ thống!")
        print(env["cdb_guide"])

    # 4. Thư mục dump mặc định
    print(f"\n[4] Kiểm tra thư mục / file Dump hệ thống:")
    for path_str, exists in env["dump_paths"].items():
        status = "[TỒN TẠI]" if exists else "[KHÔNG THẤY]"
        print(f"    - {path_str:<35} : {status}")

    # 5. Kiểm tra cơ sở dữ liệu mã Bug Check
    json_path = get_project_root() / "config" / "data" / "bugcheck_codes.json"
    print(f"\n[5] Cơ sở dữ liệu mã Bug Check:")
    if json_path.exists():
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            print(f"    [OK] Đã nạp thành công {len(data)} mã Bug Check từ file cấu hình.")
        except Exception as e:
            print(f"    [X] Lỗi đọc file bugcheck_codes.json: {e}")
    else:
        print(f"    [X] Chưa tìm thấy file dữ liệu tại {json_path}")

    # 6. Thư mục làm việc
    print(f"\n[6] Thư mục làm việc tạm (workspace):")
    ws_path = Path(env["working_dir"])
    if not ws_path.is_absolute():
        ws_path = get_project_root() / ws_path
    ws_path.mkdir(parents=True, exist_ok=True)
    print(f"    - Đường dẫn: {ws_path} (Sẵn sàng)")

    print("\n======================================================================")
    print("Kiểm tra hoàn tất. Bạn có thể tiến hành các thao tác tiếp theo.")
    print("======================================================================\n")
    return 0


def cmd_check_dump_config(args):
    """Kiểm tra toàn diện khả năng sinh dump của hệ thống và tuỳ chọn bật CrashDumpEnabled = 7."""
    print_banner()
    print("\n--- KIỂM TRA KHẢ NĂNG GHI DUMP HỆ THỐNG (Crash Readiness) ---")

    reg_data = read_registry_crash_control()
    pf_data = check_pagefile_status()
    disk_data = check_disk_space_and_ram()
    volmgr_data = check_volmgr_events()

    eval_result = evaluate_readiness(reg_data, pf_data, disk_data, volmgr_data)

    # 1. Cấu hình Registry CrashControl
    print(f"\n[1] Cấu hình Registry (CrashControl):")
    dump_code = reg_data.get("CrashDumpEnabled")
    mode_desc = CRASH_DUMP_MODES.get(dump_code, f"Mã không xác định ({dump_code})")
    print(f"    - CrashDumpEnabled:  {dump_code} ({mode_desc})")
    print(f"    - AutoReboot:        {reg_data.get('AutoReboot')} (Tự khởi động lại sau BSOD)")
    print(f"    - Overwrite:         {reg_data.get('Overwrite')} (Ghi đè file dump cũ)")
    print(f"    - MinidumpDir:       {reg_data.get('MinidumpDir')}")
    print(f"    - DumpFile:          {reg_data.get('DumpFile')}")

    # 2. Tình trạng Pagefile
    print(f"\n[2] Tình trạng Bộ nhớ ảo (Pagefile):")
    if pf_data["has_system_drive_pagefile"]:
        print("    [OK] Đã phát hiện Pagefile trên ổ đĩa hệ thống.")
    else:
        print("    [!] CẢNH BÁO: Không có Pagefile trên ổ hệ thống (C:).")
    if pf_data.get("details"):
        for d in pf_data["details"]:
            print(f"         + {d}")

    # 3. Dung lượng trống ổ cứng và RAM
    print(f"\n[3] Dung lượng ổ đĩa & Bộ nhớ RAM:")
    print(f"    - Dung lượng RAM:    {disk_data['ram_gb']} GB")
    print(f"    - Dung lượng trống:  {disk_data['free_disk_gb']} GB trên ổ {disk_data['system_drive']}")
    print(f"    - Mức khuyến nghị:   >= {disk_data['recommended_free_gb']} GB (RAM + 5GB)")
    if disk_data["sufficient_space"]:
        print("    [OK] Đủ dung lượng trống để lưu Kernel / Automatic dump.")
    else:
        print("    [!] CẢNH BÁO: Dung lượng trống thấp hơn mức an toàn để ghi dump.")

    # 4. Lịch sử dịch vụ volmgr
    print(f"\n[4] Lịch sử dịch vụ ghi dump (volmgr):")
    if volmgr_data["has_failure_161"]:
        print(f"    [!] CẢNH BÁO: Đã từng có sự kiện tạo dump thất bại (Event 161 lúc {volmgr_data['last_failure_time']}).")
    else:
        print("    [OK] Không phát hiện lỗi tạo dump thất bại (Event 161) gần đây.")

    # 5. ĐÁNH GIÁ TỔNG THỂ
    status_tag = f"=== TRẠNG THÁI: [{eval_result['status']}] ==="
    print(f"\n{'=' * len(status_tag)}")
    print(status_tag)
    print(f"{'=' * len(status_tag)}")
    print(f">> {eval_result['summary']}")

    if eval_result["reasons"]:
        print("\nCác vấn đề phát hiện:")
        for r in eval_result["reasons"]:
            print(f"  * {r}")

    if eval_result["recommendations"]:
        print("\nKhuyến nghị hành động:")
        for rec in eval_result["recommendations"]:
            print(f"  -> {rec}")

    print("\n----------------------------------------------------------------------")

    # 6. Xử lý cờ --apply
    if args.apply:
        print("\n[!] BẠN ĐANG YÊU CẦU CẤU HÌNH BẬT GHI DUMP TỰ ĐỘNG (--apply)")
        print("    Chương trình sẽ:")
        print("    1. Sao lưu cấu hình Registry hiện tại ra file .reg trong thư mục 'backup/'.")
        print("    2. Đặt giá trị 'CrashDumpEnabled' thành 7 (Automatic memory dump).")
        print("    3. TUYỆT ĐỐI KHÔNG sửa pagefile và KHÔNG tự khởi động lại máy.\n")

        confirm = input("Bạn có chắc chắn muốn thực hiện thay đổi này? (gõ 'y' để xác nhận): ").strip().lower()
        if confirm == "y":
            res = apply_automatic_dump(confirmed=True)
            if res["success"]:
                print(f"\n[THÀNH CÔNG] {res['message']}\n")
                return 0
            else:
                print(f"\n[THẤT BÀI] {res['message']}\n")
                return 1
        else:
            print("\n[HUỶ BỎ] Người dùng đã huỷ thao tác sửa đổi registry.\n")
            return 0
    else:
        print("Ghi chú: Lệnh trên chỉ ĐỌC cấu hình. Để tự động bật ghi dump an toàn, hãy dùng:")
        print("         dumpanalyzer check-dump-config --apply\n")
        return 0


def build_parser() -> argparse.ArgumentParser:
    """Xây dựng bộ phân tích tham số dòng lệnh."""
    parser = argparse.ArgumentParser(
        prog="dumpanalyzer",
        description="DumpAnalyzer - Phân tích BSOD dump kết hợp Windows Event Log",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"DumpAnalyzer v{__version__}",
        help="Hiển thị phiên bản hiện tại của phần mềm",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="Lệnh khả dụng",
        description="Chọn lệnh cần thực thi",
        help="Nhập 'dumpanalyzer <lệnh> --help' để xem chi tiết từng lệnh",
    )

    # Subcommand: check-env
    parser_check = subparsers.add_parser(
        "check-env",
        help="Kiểm tra môi trường hệ thống (cdb.exe, quyền Admin, thư mục dump)",
    )
    parser_check.set_defaults(func=cmd_check_env)

    # Subcommand: scan
    parser_scan = subparsers.add_parser(
        "scan",
        help="Quét và đọc mã lỗi từ header file dump (không cần cdb.exe)",
    )
    parser_scan.add_argument(
        "--path",
        help="Đường dẫn thư mục hoặc file dump cần quét (ví dụ: 'C:\\Windows\\Minidump' hoặc file cụ thể)",
    )
    parser_scan.add_argument(
        "--from",
        dest="from_date",
        help="Chỉ quét các file dump từ ngày này (định dạng: YYYY-MM-DD)",
    )
    parser_scan.add_argument(
        "--to",
        dest="to_date",
        help="Chỉ quét các file dump đến ngày này (định dạng: YYYY-MM-DD)",
    )
    parser_scan.add_argument(
        "--force",
        action="store_true",
        help="Bỏ qua cache SHA256, bắt buộc đọc lại và cập nhật cơ sở dữ liệu",
    )
    parser_scan.set_defaults(func=cmd_scan)

def cmd_analyze(args):
    """Phân tích chuyên sâu file dump bằng cdb.exe (!analyze -v) và lưu output thô."""
    print_banner()
    settings = load_settings()
    db = Database()

    targets: List[Dict[str, Any]] = []

    if args.all:
        targets = db.get_unprocessed_crashes()
        print(f"\n[*] Đang tìm các file dump chưa phân tích cdb trong CSDL: Tìm thấy {len(targets)} bản ghi.")
    elif args.path:
        search_path = Path(args.path)
        if search_path.is_file():
            # Kiểm tra trong DB hoặc tạo mới
            sha256 = calculate_sha256(search_path)
            cached = db.get_crash_by_sha256(sha256)
            if cached:
                targets = [cached]
            else:
                h_info = parse_dump_header(search_path)
                c_id = db.insert_crash(Crash(
                    dump_path=str(search_path),
                    dump_sha256=sha256,
                    dump_type=h_info.dump_type,
                    crash_time_utc=h_info.crash_time_utc,
                    bugcheck_code=h_info.bugcheck_code,
                    bugcheck_name=h_info.bugcheck_name,
                    p1=h_info.p1, p2=h_info.p2, p3=h_info.p3, p4=h_info.p4,
                    analyzed_by="header_only",
                ))
                targets = [db.get_crash_by_sha256(sha256)]
        else:
            found = find_dumps([str(search_path)])
            for f in found:
                sha256 = calculate_sha256(f["path"])
                cached = db.get_crash_by_sha256(sha256)
                if cached:
                    targets.append(cached)
                else:
                    h_info = parse_dump_header(f["path"])
                    c_id = db.insert_crash(Crash(
                        dump_path=str(f["path"]),
                        dump_sha256=sha256,
                        dump_type=h_info.dump_type,
                        crash_time_utc=h_info.crash_time_utc,
                        bugcheck_code=h_info.bugcheck_code,
                        bugcheck_name=h_info.bugcheck_name,
                        p1=h_info.p1, p2=h_info.p2, p3=h_info.p3, p4=h_info.p4,
                        analyzed_by="header_only",
                    ))
                    targets.append(db.get_crash_by_sha256(sha256))
    else:
        print("\n[!] Hãy chỉ định '--all' để phân tích mọi dump chưa xử lý, hoặc '--path <đường_dẫn>'.")
        db.close()
        return 1

    if not targets:
        print("[OK] Không có file dump nào cần phân tích chuyên sâu.")
        db.close()
        return 0

    concurrency = args.concurrency or settings.get("max_parallel_cdb", 2)
    print(f"[*] Bắt đầu phân tích chuyên sâu {len(targets)} dump (Số luồng: {concurrency})...\n")

    results = []
    for item in targets:
        dump_path = item["dump_path"]
        res = analyze_dump_file(
            dump_path=dump_path,
            cdb_path=settings.get("cdb_path"),
            symbol_path=settings.get("symbol_path"),
            timeout_seconds=settings.get("cdb_timeout_seconds", 300),
        )

        cdb_res = res["cdb_result"]
        analyzed_by = res["analyzed_by"]

        # Cập nhật kết quả vào SQLite
        db.update_crash_cdb_results(
            crash_id=item["id"],
            image_name=cdb_res.image_name,
            module_name=cdb_res.module_name,
            process_name=cdb_res.process_name,
            failure_bucket_id=cdb_res.failure_bucket_id,
            uptime_seconds=cdb_res.uptime_seconds,
            cdb_raw_output=res["raw_output"],
            analyzed_by=analyzed_by,
        )

        results.append({
            "id": item["id"],
            "code": cdb_res.bugcheck_code or item.get("bugcheck_code", "N/A"),
            "name": cdb_res.bugcheck_name or item.get("bugcheck_name", "Không rõ"),
            "suspect": cdb_res.suspect_driver or cdb_res.image_name or "Chưa rõ",
            "process": cdb_res.process_name or "N/A",
            "bucket": cdb_res.failure_bucket_id or "N/A",
            "by": analyzed_by,
        })

    db.close()

    # In bảng tổng kết
    col_id = 4
    col_code = 10
    col_name = 30
    col_susp = 22
    col_proc = 14
    col_by = 12

    line_hdr = (
        f"{'ID':<{col_id}} | "
        f"{'Mã lỗi':<{col_code}} | "
        f"{'Tên lỗi':<{col_name}} | "
        f"{'Nghi vấn chính':<{col_susp}} | "
        f"{'Tiến trình':<{col_proc}} | "
        f"{'Phương thức':<{col_by}}"
    )
    sep = "-" * len(line_hdr) + "-" * 10
    print(sep)
    print(line_hdr)
    print(sep)
    for r in results:
        print(
            f"{r['id']:<{col_id}} | "
            f"{r['code']:<{col_code}} | "
            f"{r['name'][:col_name]:<{col_name}} | "
            f"{r['suspect'][:col_susp]:<{col_susp}} | "
            f"{r['process'][:col_proc]:<{col_proc}} | "
            f"{r['by']:<{col_by}}"
        )
    print(sep)
    print(f"Hoàn thành phân tích {len(results)} file dump.\n")
    return 0


def cmd_warmup_symbols(args):
    """Kiểm tra và tải trước Symbol Microsoft."""
    print_banner()
    print("\n--- TẢI TRƯỚC SYMBOLS MICROSOFT (Symbol Warmup) ---")
    settings = load_settings()
    res = warmup_symbols(
        cdb_path=settings.get("cdb_path"),
        symbol_path=settings.get("symbol_path"),
    )
    if res["success"]:
        print(f"[OK] {res['message']}\n")
        return 0
    else:
        print(f"[X] {res['message']}\n")
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Xây dựng bộ phân tích tham số dòng lệnh."""
    parser = argparse.ArgumentParser(
        prog="dumpanalyzer",
        description="DumpAnalyzer - Phân tích BSOD dump kết hợp Windows Event Log",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"DumpAnalyzer v{__version__}",
        help="Hiển thị phiên bản hiện tại của phần mềm",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="Lệnh khả dụng",
        description="Chọn lệnh cần thực thi",
        help="Nhập 'dumpanalyzer <lệnh> --help' để xem chi tiết từng lệnh",
    )

    # Subcommand: check-env
    parser_check = subparsers.add_parser(
        "check-env",
        help="Kiểm tra môi trường hệ thống (cdb.exe, quyền Admin, thư mục dump)",
    )
    parser_check.set_defaults(func=cmd_check_env)

    # Subcommand: scan
    parser_scan = subparsers.add_parser(
        "scan",
        help="Quét và đọc mã lỗi từ header file dump (không cần cdb.exe)",
    )
    parser_scan.add_argument(
        "--path",
        help="Đường dẫn thư mục hoặc file dump cần quét (ví dụ: 'C:\\Windows\\Minidump' hoặc file cụ thể)",
    )
    parser_scan.add_argument(
        "--from",
        dest="from_date",
        help="Chỉ quét các file dump từ ngày này (định dạng: YYYY-MM-DD)",
    )
    parser_scan.add_argument(
        "--to",
        dest="to_date",
        help="Chỉ quét các file dump đến ngày này (định dạng: YYYY-MM-DD)",
    )
    parser_scan.add_argument(
        "--force",
        action="store_true",
        help="Bỏ qua cache SHA256, bắt buộc đọc lại và cập nhật cơ sở dữ liệu",
    )
    parser_scan.set_defaults(func=cmd_scan)

    # Subcommand: check-dump-config (Phase 1B)
    parser_dump_cfg = subparsers.add_parser(
        "check-dump-config",
        help="Kiểm tra khả năng ghi dump của Windows (CrashControl, Pagefile, Dung lượng đĩa, volmgr)",
    )
    parser_dump_cfg.add_argument(
        "--apply",
        action="store_true",
        help="Bật ghi dump tự động (CrashDumpEnabled = 7) có sao lưu và xác nhận an toàn",
    )
    parser_dump_cfg.set_defaults(func=cmd_check_dump_config)

    # Subcommand: analyze (Phase 2)
    parser_analyze = subparsers.add_parser(
        "analyze",
        help="Phân tích chuyên sâu bằng cdb.exe (!analyze -v) lấy stack trace và driver bên thứ ba",
    )
    parser_analyze.add_argument(
        "--all",
        action="store_true",
        help="Phân tích toàn bộ các file dump chưa xử lý trong CSDL",
    )
    parser_analyze.add_argument(
        "--path",
        help="Đường dẫn thư mục hoặc file dump cần phân tích chuyên sâu",
    )
    parser_analyze.add_argument(
        "--concurrency",
        type=int,
        default=2,
        help="Số tiến trình phân tích song song tối đa (mặc định: 2)",
    )
    parser_analyze.set_defaults(func=cmd_analyze)

    # Subcommand: warmup-symbols (Phase 2)
    parser_warmup = subparsers.add_parser(
        "warmup-symbols",
        help="Tải trước Symbol Microsoft để tránh bị treo khi phân tích hàng loạt",
    )
    parser_warmup.set_defaults(func=cmd_warmup_symbols)

    return parser


def main(argv=None):
    """Điểm vào chính của ứng dụng dòng lệnh."""
    setup_logging()
    parser = build_parser()
    args = parser.parse_args(argv)

    if hasattr(args, "func"):
        return args.func(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())

