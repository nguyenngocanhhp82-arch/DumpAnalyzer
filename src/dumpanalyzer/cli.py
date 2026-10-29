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


def print_banner():
    banner = f"""
======================================================================
  DumpAnalyzer v{__version__} - Chẩn đoán Dump BSOD & Windows Event Log
  Dành cho Kỹ thuật viên & Quản trị hệ thống IT
======================================================================
"""
    print(banner.strip())


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
