"""
Script tự động đóng gói ứng dụng DumpAnalyzer bằng PyInstaller.
Thực hiện:
1. Kiểm tra môi trường và cài đặt các thư viện cần thiết.
2. Chạy PyInstaller với DumpAnalyzer.spec (--onedir, --windowed, --uac-admin).
3. Tự động sao chép thư mục 'config/' đặt ngay cạnh file DumpAnalyzer.exe trong thư mục dist/DumpAnalyzer/.
4. Hướng dẫn kỹ thuật viên IT sử dụng và thiết lập ngoại lệ Antivirus.
"""

import sys
import shutil
import subprocess
from pathlib import Path


def main():
    project_root = Path(__file__).resolve().parent.parent
    dist_dir = project_root / "dist" / "DumpAnalyzer"
    spec_file = project_root / "DumpAnalyzer.spec"
    config_src = project_root / "config"

    print("=================================================================")
    print("      DUMPANALYZER — QUY TRÌNH ĐÓNG GÓI PYINSTALLER (PHASE 6)    ")
    print("=================================================================")
    print(f"[*] Thư mục dự án: {project_root}")
    print(f"[*] File cấu hình spec: {spec_file}")

    if not spec_file.exists():
        print(f"[X] Không tìm thấy file {spec_file}!")
        sys.exit(1)

    # 1. Chạy PyInstaller
    print("\n[1/3] Đang tiến hành đóng gói PyInstaller...")
    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", str(spec_file)]
    res = subprocess.run(cmd, cwd=project_root)
    if res.returncode != 0:
        print("[X] Quá trình PyInstaller gặp lỗi. Dừng đóng gói.")
        sys.exit(res.returncode)

    # 2. Sao chép thư mục config đặt cạnh file .exe
    print("\n[2/3] Đang sao chép thư mục 'config/' ra cạnh file thực thi...")
    target_config = dist_dir / "config"
    if target_config.exists():
        shutil.rmtree(target_config)
    shutil.copytree(config_src, target_config)
    print(f"[+] Đã sao chép cấu hình YAML thành công -> {target_config}")

    # Tạo thư mục logs sẵn sàng
    logs_dir = dist_dir / "logs"
    logs_dir.mkdir(exist_ok=True)

    print("\n[3/3] HOÀN TẤT ĐÓNG GÓI THÀNH CÔNG!")
    print(f"[+] Thư mục ứng dụng đã sẵn sàng tại:")
    print(f"    {dist_dir}")
    print("\nLƯU Ý QUAN TRỌNG KHI TRIỂN KHAI CHO IT:")
    print("1. File thực thi 'DumpAnalyzer.exe' tự động yêu cầu quyền Administrator.")
    print("2. Kỹ thuật viên IT có thể mở trực tiếp thư mục 'dist/DumpAnalyzer/config/rules/'")
    print("   để bổ sung mã Bug Check hoặc map driver mà không cần build lại mã nguồn.")
    print("3. Thêm thư mục ứng dụng vào danh sách loại trừ (Exclusion) của Windows Defender")
    print("   hoặc phần mềm diệt virus công ty để tránh hiện tượng nhận diện nhầm.")
    print("=================================================================\n")


if __name__ == "__main__":
    main()
