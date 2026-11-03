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

# Đảm bảo stdout/stderr luôn dùng UTF-8 trên mọi nền tảng (tránh UnicodeEncodeError cp1252 trên Windows runner)
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def main():
    project_root = Path(__file__).resolve().parent.parent
    dist_dir = project_root / "dist" / "DumpAnalyzer"
    spec_file = project_root / "DumpAnalyzer.spec"
    config_src = project_root / "config"

    print("=================================================================")
    print("      DUMPANALYZER -- QUY TRINH DONG GOI PYINSTALLER (PHASE 6)   ")
    print("=================================================================")
    print(f"[*] Thu muc du an: {project_root}")
    print(f"[*] File cau hinh spec: {spec_file}")

    if not spec_file.exists():
        print(f"[X] Khong tim thay file {spec_file}!")
        sys.exit(1)

    # 1. Chạy PyInstaller
    print("\n[1/3] Dang tien hanh dong goi PyInstaller...")
    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", str(spec_file)]
    res = subprocess.run(cmd, cwd=project_root)
    if res.returncode != 0:
        print("[X] Qua trinh PyInstaller gap loi. Dung dong goi.")
        sys.exit(res.returncode)

    # 2. Sao chép thư mục config đặt cạnh file .exe
    print("\n[2/3] Dang sao chep thu muc 'config/' ra canh file thuc thi...")
    target_config = dist_dir / "config"
    if target_config.exists():
        shutil.rmtree(target_config)
    shutil.copytree(config_src, target_config, ignore=shutil.ignore_patterns("*.db", "*.sqlite", "workspace*", "logs*"))
    print(f"[+] Da sao chep cau hinh YAML thanh cong -> {target_config}")

    # Tạo thư mục logs sẵn sàng
    logs_dir = dist_dir / "logs"
    logs_dir.mkdir(exist_ok=True)

    print("\n[3/3] HOAN TAT DONG GOI THANH CONG!")
    print(f"[+] Thu muc ung dung da san sang tai:")
    print(f"    {dist_dir}")
    print("\nLUU Y QUAN TRONG KHI TRIEN KHAI CHO IT:")
    print("1. File thuc thi 'DumpAnalyzer.exe' tu dong yeu cau quyen Administrator.")
    print("2. Ky thuat vien IT co the mo truc tiep thu muc 'dist/DumpAnalyzer/config/rules/'")
    print("   de bo sung ma Bug Check hoac map driver ma khong can build lai ma nguon.")
    print("3. Them thu muc ung dung vao danh sach loai tru (Exclusion) cua Windows Defender")
    print("   hoac phan mem diet virus cong ty de tranh hien tuong nhan dien nham.")
    print("=================================================================\n")



if __name__ == "__main__":
    main()
