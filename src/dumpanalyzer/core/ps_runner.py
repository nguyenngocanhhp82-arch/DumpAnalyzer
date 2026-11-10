"""
Tiện ích thực thi script PowerShell an toàn và giải mã kết quả JSON/NDJSON từ stdout.
Khắc phục triệt để các lỗi đặc thù trên Windows khi đóng gói GUI (console=False):
- Sử dụng -EncodedCommand (UTF-16LE Base64) để không bị lỗi escape dấu nháy, xuống dòng hoặc đường dẫn tiếng Việt.
- Truyền stdin=subprocess.DEVNULL và CREATE_NO_WINDOW để tránh lỗi WinError 6 (invalid handle) và chớp cửa sổ đen.
- Hỗ trợ đọc cả JSON Array tiêu chuẩn lẫn NDJSON (mỗi dòng 1 object) để vượt qua giới hạn MaxJsonLength 2MB của PowerShell 5.1.
- Tự động loại bỏ UTF-8 BOM (\\ufeff).
"""

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Dict, List


def find_powershell_exe() -> str:
    """Tìm đường dẫn đáng tin cậy tới powershell.exe trên Windows."""
    if os.name == "nt":
        ps_exe = shutil.which("powershell.exe") or shutil.which("powershell")
        if ps_exe:
            return ps_exe
        sys_root = os.environ.get("SystemRoot", r"C:\Windows")
        cand = Path(sys_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if cand.is_file():
            return str(cand)
    return "powershell.exe"


def run_powershell_script(ps_script: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """Thực thi script PowerShell qua -EncodedCommand (hoặc stdin nếu quá dài) an toàn trên Windows."""
    ps_exe = find_powershell_exe()
    encoded = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")

    kwargs: Dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": timeout,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

    if len(encoded) < 28000:
        cmd = [ps_exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded]
        kwargs["stdin"] = subprocess.DEVNULL
    else:
        cmd = [ps_exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"]
        kwargs["input"] = ps_script

    return subprocess.run(cmd, **kwargs)


def parse_ps_json_output(raw_stdout: str) -> List[Dict[str, Any]]:
    """
    Giải mã dữ liệu JSON hoặc NDJSON (mỗi dòng 1 JSON object) từ stdout của PowerShell.
    Tự động xử lý UTF-8 BOM (\\ufeff), output rỗng hoặc [] hoặc single dict.
    """
    if not raw_stdout:
        return []

    cleaned = raw_stdout.lstrip("\ufeff").strip()
    if not cleaned or cleaned in ("[]", "null"):
        return []

    # 1. Thử parse toàn bộ chuỗi nếu là 1 JSON array hoặc 1 JSON object duy nhất
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, list):
            return [x for x in parsed if isinstance(x, dict)]
        if isinstance(parsed, dict):
            return [parsed]
        return []
    except json.JSONDecodeError:
        pass

    # 2. Fallback: Parse từng dòng NDJSON (do ForEach-Object | ConvertTo-Json xuất từng object riêng biệt)
    items: List[Dict[str, Any]] = []
    for line in cleaned.splitlines():
        line_str = line.lstrip("\ufeff").strip()
        if not line_str or line_str in ("[]", "null"):
            continue
        try:
            obj = json.loads(line_str)
            if isinstance(obj, dict):
                items.append(obj)
            elif isinstance(obj, list):
                items.extend([x for x in obj if isinstance(x, dict)])
        except json.JSONDecodeError:
            continue

    return items
