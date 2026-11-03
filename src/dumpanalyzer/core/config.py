"""
Quản lý cấu hình hệ thống DumpAnalyzer và kiểm tra môi trường chạy.
Tự động phát hiện cdb.exe (Windows Debugging Tools), kiểm tra quyền Administrator và thư mục dump.
"""

import os
import sys
import shutil
import ctypes
from pathlib import Path
from typing import Dict, Any, List, Optional
import yaml


# Hướng dẫn chi tiết bằng tiếng Việt khi thiếu cdb.exe
CDB_INSTALL_GUIDE = """
[CẢNH BÁO] Không tìm thấy công cụ phân tích 'cdb.exe'!
Chương trình sẽ chỉ chạy ở chế độ cơ bản (đọc header dump) và không thể phân tích stack trace chuyên sâu.

HƯỚNG DẪN CÀI ĐẶT WINDOWS DEBUGGING TOOLS CHO NHÂN VIÊN IT:
1. Tải bộ cài 'Windows SDK' từ trang chủ Microsoft:
   https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
2. Khi chạy bộ cài, ở màn hình chọn tính năng (Features), BỎ CHỌN TẤT CẢ và CHỈ TÍCH CHỌN:
   [v] "Debugging Tools for Windows"
3. Nhấn Install để hoàn tất.
4. Mở lại DumpAnalyzer hoặc cấu hình đường dẫn cdb.exe trong file 'config/settings.yaml'.
Đường dẫn thông thường:
C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe
"""


DEFAULT_SETTINGS: Dict[str, Any] = {
    "cdb_path": "",
    "symbol_path": "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols",
    "cdb_timeout_seconds": 300,
    "max_parallel_cdb": 2,
    "working_dir": "./workspace",
    "dump_search_paths": [
        "C:\\Windows\\Minidump",
        "C:\\Windows\\MEMORY.DMP",
        "C:\\Windows\\LiveKernelReports",
    ],
    "auto_cleanup_copied_dumps": False,
    "max_copy_gb": 8,
    "event_window_minutes": 10,

    "eventlog_timeout_seconds": 120,
    "update_history_days": 7,
    "confidence_thresholds": {
        "high": 70,
        "medium": 40,
    },
    "min_verdict_score": 35,
    "conflict_threshold": 15,
    "repeat_multiplier": 1.25,
    "logging": {
        "level": "INFO",
        "log_file": "./logs/dumpanalyzer.log",
        "max_bytes": 10485760,
        "backup_count": 5,
    },
}


COMMON_CDB_LOCATIONS = [
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
    r"C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe",
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe",
    r"C:\Program Files\Windows Kits\10\Debuggers\x86\cdb.exe",
    r"C:\Program Files (x86)\Windows Kits\8.1\Debuggers\x64\cdb.exe",
    r"C:\Debuggers\cdb.exe",
]


def get_project_root() -> Path:
    """Trả về thư mục gốc của dự án DumpAnalyzer.
    Khi chạy ở dạng đóng gói PyInstaller (frozen), trả về thư mục chứa file .exe
    để nạp thư mục config/ đặt bên cạnh .exe theo yêu cầu UPDATE_01.
    """
    import sys
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent.parent.parent


def get_rules_dir() -> Path:
    """Trả về đường dẫn tới thư mục chứa các file rules (config/rules)."""
    return get_project_root() / "config" / "rules"


def get_settings_path() -> Path:
    """Trả về đường dẫn tới file cấu hình chính (config/settings.yaml)."""
    return get_project_root() / "config" / "settings.yaml"


def load_settings(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Nạp file settings.yaml, tự động kết hợp với giá trị mặc định an toàn."""
    settings = dict(DEFAULT_SETTINGS)

    if config_path:
        target = Path(config_path)
    else:
        target = get_project_root() / "config" / "settings.yaml"

    if target.exists():
        try:
            with open(target, "r", encoding="utf-8") as f:
                user_cfg = yaml.safe_load(f)
                if isinstance(user_cfg, dict):
                    settings.update(user_cfg)
        except Exception as e:
            print(f"[Cảnh báo] Lỗi đọc file cấu hình {target}: {e}. Đang dùng cấu hình mặc định.")

    return settings


def save_settings(config_path: str | Path, settings: Dict[str, Any]) -> None:
    """Lưu từ điển cấu hình ra file settings.yaml."""
    target = Path(config_path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as f:
        yaml.safe_dump(settings, f, default_flow_style=False, allow_unicode=True, sort_keys=False)


def find_cdb_executable(configured_path: Optional[str] = None) -> Optional[str]:
    """
    Tự động tìm kiếm đường dẫn cdb.exe:
    1. Kiểm tra cấu hình do người dùng chỉ định.
    2. Kiểm tra biến môi trường PATH.
    3. Quét các vị trí cài đặt Windows Kits phổ biến.
    """
    # 1. Kiểm tra cấu hình chỉ định tay
    if configured_path and configured_path.strip():
        p = Path(configured_path.strip())
        if p.exists() and p.is_file():
            return str(p)
        # Đường dẫn được cấu hình rõ ràng nhưng không tồn tại -> không tự ý dùng cdb khác
        return None

    # 2. Kiểm tra trong PATH
    in_path = shutil.which("cdb.exe") or shutil.which("cdb")
    if in_path:
        return str(Path(in_path).resolve())

    # 3. Kiểm tra các thư mục mặc định trên Windows
    for loc in COMMON_CDB_LOCATIONS:
        if Path(loc).exists():
            return loc

    return None


def is_running_as_admin() -> bool:
    """
    Kiểm tra xem chương trình có đang chạy dưới quyền Administrator (hoặc root) hay không.
    Quyền Admin là bắt buộc để truy cập thư mục C:\\Windows\\Minidump và đọc trực tiếp file MEMORY.DMP.
    """
    try:
        if sys.platform == "win32":
            return bool(ctypes.windll.shell32.IsUserAnAdmin() != 0)
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def check_dump_paths(paths: List[str]) -> Dict[str, bool]:
    """Kiểm tra sự tồn tại của các thư mục/file dump trên hệ thống."""
    results = {}
    for p in paths:
        path_obj = Path(p)
        results[p] = path_obj.exists()
    return results


def check_environment_summary() -> Dict[str, Any]:
    """
    Kiểm tra tổng quan môi trường và trả về dict thông tin chi tiết.
    Dùng cho lệnh CLI 'check-env' và thông báo trên GUI.
    """
    settings = load_settings()
    cdb_path = find_cdb_executable(settings.get("cdb_path"))
    is_admin = is_running_as_admin()
    configured_paths = settings.get("dump_search_paths", [])
    path_status = check_dump_paths(configured_paths)

    return {
        "cdb_found": bool(cdb_path),
        "cdb_path": cdb_path,
        "cdb_guide": CDB_INSTALL_GUIDE if not cdb_path else "",
        "is_admin": is_admin,
        "dump_paths": path_status,
        "os_platform": sys.platform,
        "python_version": sys.version.split()[0],
        "working_dir": settings.get("working_dir", "./workspace"),
    }
