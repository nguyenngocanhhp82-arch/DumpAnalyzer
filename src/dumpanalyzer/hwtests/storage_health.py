"""
Plugin kiểm tra sức khỏe ổ đĩa và hệ thống tệp (storage_health).
Chế độ: CHỈ QUÉT ĐỌC (chkdsk /scan), TUYỆT ĐỐI KHÔNG DÙNG /f, /r, /spotfix.
"""

import sys
import subprocess
import datetime
from typing import Optional, Tuple, List

from dumpanalyzer.hwtests.base import HardwareTest, TestResult
from dumpanalyzer.collectors.sysinfo import collect_storage_info
from dumpanalyzer.core.logging_setup import get_logger

logger = get_logger("hwtests.storage_health")

FORBIDDEN_FLAGS = ["/f", "/r", "/spotfix", "-f", "-r"]


def build_chkdsk_command(drive: str = "C:") -> List[str]:
    """
    Sinh chuỗi lệnh chkdsk ở chế độ CHỈ QUÉT (read-only scan).
    Chặn triệt để mọi cờ ghi hoặc sửa đĩa phá hủy (/f, /r, /spotfix).
    """
    clean_drive = drive.strip().rstrip(":\\").upper() + ":"
    cmd = ["chkdsk", clean_drive, "/scan"]

    for arg in cmd:
        for f in FORBIDDEN_FLAGS:
            if f in arg.lower():
                raise ValueError(f"Vi phạm an toàn hệ thống: cờ '{f}' bị cấm!")
    return cmd


class StorageHealthTest(HardwareTest):
    """Plugin kiểm tra sức khỏe ổ cứng: SMART / StorageReliability và chkdsk /scan."""

    id: str = "storage_health"
    name: str = "Kiểm tra sức khỏe ổ đĩa (SMART & chkdsk /scan)"
    description: str = "Đọc trạng thái SMART, đếm lỗi I/O và chạy chkdsk ở chế độ chỉ quét (không sửa) để phát hiện lỗi phân vùng/bad sector."
    group: str = "storage"
    requires_reboot: bool = False
    requires_admin: bool = True
    estimated_minutes: int = 3

    def check_prerequisites(self) -> Tuple[bool, str]:
        """Kiểm tra điều kiện tiên quyết (quyền Administrator trên Windows)."""
        if sys.platform != "win32":
            return False, "Plugin này chỉ chạy trên hệ điều hành Windows."

        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                return False, "Cần quyền Administrator để thực thi lệnh chkdsk /scan."
            return True, "Hệ thống đáp ứng đủ điều kiện."
        except Exception as e:
            return False, f"Không thể kiểm tra quyền quản trị: {e}"

    def start(
        self,
        machine_id: Optional[int] = None,
        drive: str = "C:",
        mock_output: Optional[str] = None,
        mock_exit_code: int = 0,
        timeout_seconds: int = 180,
    ) -> TestResult:
        """
        Thực thi kiểm tra SMART và chạy lệnh chkdsk /scan chỉ đọc.
        """
        st_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        logger.info(f"Bắt đầu bài test storage_health trên ổ {drive}")

        # 1. Thu thập thông tin SMART từ Get-PhysicalDisk
        disks = collect_storage_info()
        smart_issues = []
        for d in disks:
            wear = d.get("wear_pct")
            r_err = d.get("read_errors", 0)
            h_stat = str(d.get("health_status", "")).lower()
            if wear is not None and wear >= 80:
                smart_issues.append(f"Ổ {d.get('friendly_name')}: Độ mòn SSD cao ({wear}%)")
            if r_err and r_err > 10:
                smart_issues.append(f"Ổ {d.get('friendly_name')}: Bộ đếm lỗi đọc cao ({r_err} lỗi)")
            if h_stat in ("warning", "unhealthy"):
                smart_issues.append(f"Ổ {d.get('friendly_name')}: HealthStatus báo bất thường ({h_stat})")

        # 2. Chạy chkdsk /scan chỉ đọc
        cmd = build_chkdsk_command(drive)
        # Kiểm tra an toàn lần cuối
        cmd_str = " ".join(cmd)
        if any(f in cmd_str.lower() for f in FORBIDDEN_FLAGS) or "bcdedit" in cmd_str.lower():
            raise ValueError("Lệnh chứa cờ bị cấm không an toàn!")

        raw_output = ""
        exit_code = 0

        if mock_output is not None:
            raw_output = mock_output
            exit_code = mock_exit_code
        else:
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                    shell=False,
                )
                raw_output = proc.stdout + "\n" + proc.stderr
                exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                fn_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
                return TestResult(
                    status="inconclusive",
                    details=f"Quá thời gian chờ ({timeout_seconds}s) khi chạy chkdsk trên ổ {drive}.",
                    started_at=st_at,
                    finished_at=fn_at,
                    raw="TimeoutExpired",
                )
            except Exception as e:
                fn_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
                return TestResult(
                    status="inconclusive",
                    details=f"Không thể chạy chkdsk: {e}",
                    started_at=st_at,
                    finished_at=fn_at,
                    raw=str(e),
                )

        fn_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Phân tích kết quả
        is_corrupted = (
            exit_code != 0
            or "found corruption" in raw_output.lower()
            or "errors found" in raw_output.lower()
            or "bad sectors" in raw_output.lower()
        )

        if is_corrupted or smart_issues:
            detail_lines = []
            if smart_issues:
                detail_lines.extend(smart_issues)
            if is_corrupted:
                detail_lines.append(f"chkdsk phát hiện lỗi cấu trúc file system / bad sector trên ổ {drive} (mã thoát: {exit_code}).")
            return TestResult(
                status="failed",
                details="; ".join(detail_lines),
                started_at=st_at,
                finished_at=fn_at,
                raw=raw_output,
            )
        else:
            return TestResult(
                status="passed",
                details=f"Ổ đĩa {drive} và hệ thống SMART đều ở trạng thái tốt. Không tìm thấy lỗi trong lượt quét này.",
                started_at=st_at,
                finished_at=fn_at,
                raw=raw_output,
            )

    def collect_result(self, machine_id: Optional[int] = None, run_id: Optional[int] = None) -> TestResult:
        """Thu thập kết quả lần chạy trước đó."""
        return TestResult(
            status="not_run",
            details="Chưa chạy bài kiểm tra.",
        )
