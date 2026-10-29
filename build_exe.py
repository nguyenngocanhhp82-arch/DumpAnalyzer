"""Script tự động build và đóng gói DumpAnalyzer bằng PyInstaller.

Quy trình:
1. Chạy PyInstaller theo cấu hình trong DumpAnalyzer.spec (--onedir, uac_admin).
2. Sao chép thư mục cấu hình config/ (settings.yaml, rules/, data/) vào cạnh file .exe.
3. Sao chép các file batch (run_gui.bat, run_cli.bat) để IT click chạy nhanh.
4. Tạo tài liệu hướng dẫn nhanh README_DIST.txt trong thư mục xuất bản.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path


def build():
    root = Path(__file__).resolve().parent
    dist_dir = root / "dist" / "DumpAnalyzer"
    config_src = root / "config"
    spec_file = root / "DumpAnalyzer.spec"

    print("=================================================================")
    print("      TIẾN HÀNH ĐÓNG GÓI DUMPANALYZER (PYINSTALLER)")
    print("=================================================================")
    print(f"[*] Thư mục gốc: {root}")
    print(f"[*] File cấu hình spec: {spec_file}")

    # 1. Chạy PyInstaller
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        str(spec_file),
    ]

    print(f"[*] Đang thực thi: {' '.join(cmd)}")
    ret = subprocess.run(cmd, cwd=str(root))
    if ret.returncode != 0:
        print(f"[X] Lỗi: PyInstaller kết thúc với mã lỗi {ret.returncode}")
        return ret.returncode

    # 2. Sao chép thư mục config/ vào cạnh file .exe
    config_dest = dist_dir / "config"
    print(f"[*] Đang sao chép thư mục cấu hình: {config_src} -> {config_dest}")
    if config_dest.exists():
        shutil.rmtree(config_dest)
    shutil.copytree(config_src, config_dest)

    # 3. Tạo file run_gui.bat và run_cli.bat
    run_gui_bat = dist_dir / "run_gui.bat"
    run_gui_bat.write_text(
        "@echo off\r\n"
        "title DumpAnalyzer - BSOD & Crash Triage Tool\r\n"
        "start \"\" \"%~dp0DumpAnalyzer.exe\"\r\n",
        encoding="utf-8",
    )

    run_cli_bat = dist_dir / "run_cli.bat"
    run_cli_bat.write_text(
        "@echo off\r\n"
        "title DumpAnalyzer CLI\r\n"
        "cd /d \"%~dp0\"\r\n"
        "echo ==================================================================\r\n"
        "echo           DUMPANALYZER - DÒNG LỆNH CHẨN ĐOÁN BSOD\r\n"
        "echo ==================================================================\r\n"
        "echo Vi du su dung:\r\n"
        "echo   DumpAnalyzer-cli.exe check-env\r\n"
        "echo   DumpAnalyzer-cli.exe scan\r\n"
        "echo   DumpAnalyzer-cli.exe check-dump-config\r\n"
        "echo   DumpAnalyzer-cli.exe analyze --all\r\n"
        "echo   DumpAnalyzer-cli.exe verdict --latest\r\n"
        "echo   DumpAnalyzer-cli.exe batch --dir .\\dump_fleet\r\n"
        "echo   DumpAnalyzer-cli.exe validate-rules\r\n"
        "echo ==================================================================\r\n"
        "cmd /k\r\n",
        encoding="utf-8",
    )

    # 4. Tạo tài liệu hướng dẫn nhanh
    readme_dist = dist_dir / "HD_SU_DUNG.txt"
    readme_dist.write_text(
        "==================================================================\n"
        "          DUMPANALYZER - CÔNG CỤ CHẨN ĐOÁN MÀN HÌNH XANH\n"
        "==================================================================\n\n"
        "1. KHỞI CHẠY NHANH:\n"
        "   - Nhấp đúp chuột vào 'run_gui.bat' hoặc 'DumpAnalyzer.exe' để mở giao diện đồ hoạ.\n"
        "   - Nhấp đúp chuột vào 'run_cli.bat' để mở cửa sổ lệnh chẩn đoán.\n\n"
        "2. YÊU CẦU QUYỀN ADMINISTRATOR:\n"
        "   - Windows sẽ tự động hiển thị hộp thoại UAC hỏi quyền Administrator.\n"
        "   - Quyền Admin là bắt buộc để đọc trực tiếp file C:\\Windows\\Minidump và MEMORY.DMP.\n\n"
        "3. CÔNG CỤ CDB.EXE (TÙY CHỌN):\n"
        "   - Nếu máy chưa cài cdb.exe, phần mềm sẽ đọc nhanh qua header dump.\n"
        "   - Để phân tích chi tiết call stack, cài đặt 'Debugging Tools for Windows' qua Windows SDK.\n\n"
        "4. TÙY BIẾN LUẬT:\n"
        "   - Mọi luật chẩn đoán nằm trong thư mục 'config/rules/'.\n"
        "   - Bạn có thể chỉnh sửa bằng Notepad mà không cần biên dịch lại phần mềm.\n\n"
        "Chúc bạn chẩn đoán và khắc phục sự cố thành công!\n",
        encoding="utf-8",
    )

    print("\n=================================================================")
    print(f"[+] ĐÓNG GÓI THÀNH CÔNG TẠI: {dist_dir}")
    print("=================================================================\n")
    return 0


if __name__ == "__main__":
    sys.exit(build())
