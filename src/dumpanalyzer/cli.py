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
