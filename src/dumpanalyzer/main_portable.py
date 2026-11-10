"""
Điểm khởi chạy thống nhất cho bản đóng gói Portable 1 file duy nhất (main_portable.py).

Quy tắc:
1. Khi người dùng nhấp đúp chuột từ File Explorer (không có tham số dòng lệnh hoặc có --gui):
   Khởi động giao diện đồ hoạ PySide6 hoàn chỉnh, không bật cửa sổ console đen thừa thãi.
2. Khi người dùng gọi từ Command Prompt / PowerShell (có tham số lệnh như scan, analyze, verdict, check-env...):
   Gắn kết (AttachConsole) với cửa sổ lệnh hiện tại và thực thi CLI, in kết quả trực tiếp ra màn hình console.
"""

import sys


def main() -> int:
    # Nếu có tham số dòng lệnh và không phải là yêu cầu mở giao diện đồ hoạ
    if len(sys.argv) > 1 and sys.argv[1] not in ("--gui", "-g"):
        if sys.platform == "win32":
            import ctypes
            # Gắn vào console cha để hiển thị stdout/stderr trên Command Prompt / PowerShell
            try:
                ctypes.windll.kernel32.AttachConsole(-1)
            except Exception:
                pass
        from dumpanalyzer.cli import main as cli_main
        return cli_main(sys.argv[1:])
    else:
        from dumpanalyzer.gui.app import main as gui_main
        return gui_main()


if __name__ == "__main__":
    sys.exit(main())
