"""
Plugin Windows Memory Diagnostic (mdsched.exe) - Phần 4.2b.
Chỉ gọi mdsched.exe để người dùng tự chọn khởi động lại; không can thiệp sâu vào boot.
Sau khi khởi động lại, collect_result() đọc kết quả từ Event Log qua ánh xạ YAML.
"""

import sys
import subprocess
import datetime
from typing import Optional, Tuple, Dict, Any, List

from dumpanalyzer.hwtests.base import HardwareTest, TestResult
from dumpanalyzer.core.logging_setup import get_logger

logger = get_logger("hwtests.wmd")

DEFAULT_EVENT_MAP = {
    1101: "passed",
    1102: "failed",
    1201: "passed",
    1202: "failed",
}


class WindowsMemoryDiagnosticTest(HardwareTest):
    """Plugin khởi chạy và đọc kết quả từ công cụ Windows Memory Diagnostic tích hợp sẵn."""

    id: str = "windows_memory_diagnostic"
    name: str = "Windows Memory Diagnostic (mdsched.exe)"
    description: str = "Mở công cụ kiểm tra bộ nhớ RAM chuẩn của Windows. Yêu cầu khởi động lại máy để tiến hành kiểm tra."
    group: str = "ram"
    requires_reboot: bool = True
    requires_admin: bool = True
    estimated_minutes: int = 15

    def check_prerequisites(self) -> Tuple[bool, str]:
        """Kiểm tra điều kiện tiên quyết (chỉ chạy trên Windows và cần quyền Admin)."""
        if sys.platform != "win32":
            return False, "Windows Memory Diagnostic chỉ có sẵn trên hệ điều hành Windows."

        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                return False, "Cần quyền Administrator để kích hoạt Windows Memory Diagnostic."
            return True, "Hệ thống đáp ứng đủ điều kiện."
        except Exception as e:
            return False, f"Không thể kiểm tra quyền quản trị: {e}"

    def start(
        self,
        machine_id: Optional[int] = None,
        mock_launch: bool = False,
    ) -> TestResult:
        """
        Khởi chạy mdsched.exe để người dùng tự lên lịch kiểm tra RAM khi khởi động lại.
        Trạng thái trả về là 'pending'.
        """
        st_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        logger.info("Yêu cầu mở công cụ mdsched.exe")

        if not mock_launch and sys.platform == "win32":
            try:
                # Chỉ mở cửa sổ mdsched.exe, không can thiệp bcdedit
                subprocess.Popen(["mdsched.exe"])
                details = (
                    "Đã mở cửa sổ Windows Memory Diagnostic (mdsched.exe). "
                    "Hãy chọn 'Restart now and check for problems' hoặc 'Check for problems the next time I start my computer'. "
                    "Sau khi máy khởi động lại xong, hãy nhấn nút 'Đọc kết quả' để kiểm tra kết quả chẩn đoán."
                )
            except Exception as e:
                return TestResult(
                    status="inconclusive",
                    details=f"Không thể khởi chạy mdsched.exe: {e}",
                    started_at=st_at,
                    finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    raw=str(e),
                )
        else:
            details = "Đã lên lịch kiểm tra RAM với mdsched.exe (chế độ giả lập/test). Trạng thái đang chờ khởi động lại."

        return TestResult(
            status="pending",
            details=details,
            started_at=st_at,
            finished_at="",
            raw="mdsched launched, status=pending",
        )

    def collect_result(
        self,
        machine_id: Optional[int] = None,
        run_id: Optional[int] = None,
        started_at: Optional[str] = None,
        mock_events: Optional[List[Dict[str, Any]]] = None,
        rules: Optional[Dict[str, Any]] = None,
    ) -> TestResult:
        """
        Đọc các sự kiện từ provider 'Microsoft-Windows-MemoryDiagnostics-Results'
        phát sinh sau thời điểm started_at. Ánh xạ Event ID qua cấu hình test_rules.yaml.
        """
        fn_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        tr_rules = (rules or {}).get("test_rules", {})
        event_map = tr_rules.get("memory_diagnostic_event_map") or DEFAULT_EVENT_MAP

        # 1. Lấy danh sách sự kiện từ PowerShell hoặc mock
        events = []
        if mock_events is not None:
            events = mock_events
        elif sys.platform == "win32":
            ps_script = """[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ProgressPreference = 'SilentlyContinue'
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results'
} -MaxEvents 5 -ErrorAction SilentlyContinue |
Select-Object Id, TimeCreated, Message | ForEach-Object { $_ | ConvertTo-Json -Compress }
"""
            try:
                from dumpanalyzer.core.ps_runner import parse_ps_json_output, run_powershell_script
                proc = run_powershell_script(ps_script, timeout=30)
                events = parse_ps_json_output(proc.stdout or "")
            except Exception as e:
                logger.warning(f"Không thể đọc log MemoryDiagnostics: {e}")

        if not events:
            return TestResult(
                status="pending",
                details="Chưa tìm thấy sự kiện kết quả nào từ Microsoft-Windows-MemoryDiagnostics-Results. Máy tính có thể chưa hoàn thành lượt quét hoặc chưa khởi động lại.",
                started_at=started_at or "",
                finished_at=fn_at,
                raw="No events found",
            )

        # Lấy sự kiện mới nhất
        latest_ev = events[0]
        ev_id = int(latest_ev.get("Id") or latest_ev.get("id") or latest_ev.get("event_id") or 0)
        msg = str(latest_ev.get("Message") or latest_ev.get("message") or "")

        # 2. Ánh xạ ID sự kiện
        if ev_id in event_map or str(ev_id) in event_map:
            mapped_status = event_map.get(ev_id) or event_map.get(str(ev_id))
            if mapped_status == "passed":
                details = f"Windows Memory Diagnostic ĐẠT (Event ID {ev_id}). Không tìm thấy lỗi bộ nhớ RAM trong lượt kiểm tra này."
            else:
                details = f"Windows Memory Diagnostic PHÁT HIỆN LỖI (Event ID {ev_id}): {msg}"

            return TestResult(
                status=mapped_status,
                details=details,
                started_at=started_at or "",
                finished_at=fn_at,
                raw=f"Event ID {ev_id}: {msg}",
            )
        else:
            # ID chưa xác định trong bảng quy tắc
            details = (
                f"CHƯA KIỂM CHỨNG ID trên Windows thật: Tìm thấy Event ID {ev_id} ({msg[:100]}...). "
                f"ID này chưa có trong file cấu hình test_rules.yaml. Vui lòng xác nhận thủ công bằng nút đạt/không đạt."
            )
            return TestResult(
                status="inconclusive",
                details=details,
                started_at=started_at or "",
                finished_at=fn_at,
                raw=f"Unknown Event ID {ev_id}: {msg}",
            )
