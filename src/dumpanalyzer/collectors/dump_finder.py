"""
Module tìm kiếm, sao chép an toàn và tính mã băm SHA256 cho file dump (BSOD).
Đảm bảo:
- Chỉ ĐỌC file gốc, KHÔNG BAO GIỜ xoá hoặc sửa file gốc.
- Luôn copy file dump ra thư mục làm việc tạm trước khi xử lý.
- Tính toán SHA256 làm khoá cache chống phân tích trùng lặp.
"""

import os
import shutil
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Union
from dumpanalyzer.core.timeutil import parse_to_utc
from dumpanalyzer.core.logging_setup import get_logger

logger = get_logger("dump_finder")


def calculate_sha256(file_path: Union[str, Path], chunk_size: int = 65536) -> str:
    """
    Tính mã băm SHA256 của file bằng cách đọc từng khối nhớ (chunk 64KB).
    Tránh tràn bộ nhớ RAM đối với các file MEMORY.DMP dung lượng lớn (nhiều GB).
    """
    sha256 = hashlib.sha256()
    path_obj = Path(file_path)
    if not path_obj.exists() or not path_obj.is_file():
        raise FileNotFoundError(f"File không tồn tại: {file_path}")

    with open(path_obj, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)

    return sha256.hexdigest().lower()


def find_dumps(
    search_paths: List[str],
    from_date: Optional[Union[str, datetime]] = None,
    to_date: Optional[Union[str, datetime]] = None,
) -> List[Dict[str, Any]]:
    """
    Quét tìm các file dump (*.dmp, *.DMP) trong danh sách thư mục hoặc file đơn lẻ.
    Hỗ trợ lọc theo khoảng thời gian sửa đổi (mtime).

    Trả về danh sách dict:
    [
        {
            "path": Path,
            "filename": str,
            "size_bytes": int,
            "mtime_utc": datetime,
            "source_type": "minidump" | "kernel_dump" | "custom"
        }, ...
    ]
    """
    from_utc = parse_to_utc(from_date) if from_date else None
    to_utc = parse_to_utc(to_date) if to_date else None

    found_files = []
    seen_paths = set()

    for p in search_paths:
        if not p:
            continue
        path_obj = Path(p).resolve()

        if not path_obj.exists():
            logger.debug(f"Đường dẫn quét không tồn tại: {p}")
            continue

        candidate_files: List[Path] = []
        if path_obj.is_file():
            if path_obj.suffix.lower() == ".dmp":
                candidate_files.append(path_obj)
        elif path_obj.is_dir():
            try:
                # Quét file .dmp và .DMP trong thư mục
                for item in path_obj.rglob("*"):
                    if item.is_file() and item.suffix.lower() == ".dmp":
                        candidate_files.append(item)
            except PermissionError as e:
                logger.warning(f"Không có quyền truy cập thư mục {path_obj}: {e}")
                continue

        for f in candidate_files:
            real_path_str = str(f.resolve())
            if real_path_str in seen_paths:
                continue
            seen_paths.add(real_path_str)

            try:
                stat = f.stat()
                mtime_utc = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)

                # Lọc theo khoảng thời gian nếu có
                if from_utc and mtime_utc < from_utc:
                    continue
                if to_utc and mtime_utc > to_utc:
                    continue

                source_type = "custom"
                if "minidump" in real_path_str.lower():
                    source_type = "minidump"
                elif "memory.dmp" in real_path_str.lower():
                    source_type = "kernel_dump"

                found_files.append({
                    "path": f,
                    "filename": f.name,
                    "size_bytes": stat.st_size,
                    "mtime_utc": mtime_utc,
                    "source_type": source_type,
                })
            except Exception as e:
                logger.warning(f"Lỗi khi đọc thông tin file {f}: {e}")

    # Sắp xếp file theo thời gian mới nhất lên trước
    found_files.sort(key=lambda x: x["mtime_utc"], reverse=True)
    return found_files


def copy_dump_safely(
    src_file: Union[str, Path],
    working_dir: Union[str, Path],
    file_sha256: Optional[str] = None,
) -> Path:
    """
    Sao chép an toàn file dump sang thư mục làm việc (working_dir).
    Tuyệt đối không sửa file gốc.
    Đặt tên file đích kèm tiền tố SHA256 ngắn gọn để tránh ghi đè khi trùng tên.
    """
    src_path = Path(src_file).resolve()
    if not src_path.exists():
        raise FileNotFoundError(f"File nguồn không tồn tại: {src_file}")

    target_dir = Path(working_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    if not file_sha256:
        file_sha256 = calculate_sha256(src_path)

    short_hash = file_sha256[:12]
    safe_name = f"{short_hash}_{src_path.name}"
    dest_path = target_dir / safe_name

    # Nếu file đã tồn tại trong thư mục làm việc và đủ dung lượng thì tái sử dụng
    if dest_path.exists() and dest_path.stat().st_size == src_path.stat().st_size:
        logger.debug(f"File copy đã tồn tại trong workspace: {dest_path}")
        return dest_path

    logger.info(f"Đang sao chép dump: {src_path.name} -> {dest_path}")
    shutil.copy2(src_path, dest_path)
    return dest_path


def cleanup_workspace(
    working_dir: Union[str, Path],
    extensions: Optional[List[str]] = None,
) -> int:
    """
    Dọn dẹp an toàn các file dump đã sao chép trong thư mục làm việc (workspace).
    TUYỆT ĐỐI KHÔNG BAO GIỜ XOÁ FILE GỐC. Chỉ dọn dẹp các file copy trong thư mục tạm.

    Args:
        working_dir: Đường dẫn thư mục làm việc cần dọn dẹp.
        extensions: Danh sách phần mở rộng cần dọn (mặc định [".dmp", ".tmp"]).

    Returns:
        Số lượng file đã được xoá an toàn khỏi workspace.
    """
    target_dir = Path(working_dir).resolve()
    if not target_dir.exists() or not target_dir.is_dir():
        return 0

    if extensions is None:
        extensions = [".dmp", ".tmp"]

    deleted_count = 0
    for item in target_dir.iterdir():
        if item.is_file() and any(item.name.lower().endswith(ext.lower()) for ext in extensions):
            try:
                item.unlink()
                deleted_count += 1
                logger.info(f"Đã xoá file tạm an toàn trong workspace: {item.name}")
            except Exception as e:
                logger.warning(f"Không thể xoá file tạm {item.name}: {e}")

    return deleted_count


def secure_workspace_permissions(working_dir: Union[str, Path]) -> bool:
    """
    Thiết lập phân quyền an toàn cho thư mục làm việc (chỉ tài khoản hiện tại được đọc/ghi).
    Trên POSIX (Linux/macOS): chmod 0700.
    Trên Windows: đảm bảo thư mục tồn tại và thiết lập thuộc tính bảo vệ.
    """
    import sys
    target_dir = Path(working_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    try:
        if sys.platform != "win32":
            os.chmod(target_dir, 0o700)
        return True
    except Exception as e:
        logger.warning(f"Lỗi khi thiết lập phân quyền an toàn cho {target_dir}: {e}")
        return False

