"""
Lớp cơ sở và mô hình kết quả kiểm tra phần cứng (HardwareTest base class & TestResult).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
from dumpanalyzer.core.models import Evidence


@dataclass
class TestResult:
    """Kết quả một lần thực thi kiểm tra phần cứng."""
    status: str = "not_run"  # 'passed', 'failed', 'inconclusive', 'pending', 'not_run'
    details: str = ""
    started_at: str = ""
    finished_at: str = ""
    raw: str = ""


class HardwareTest(ABC):
    """Lớp trừu tượng cho tất cả các plugin kiểm tra phần cứng."""

    id: str = ""
    name: str = ""
    description: str = ""
    group: str = "unknown"  # 'ram', 'storage', 'cpu', 'gpu', v.v.
    requires_reboot: bool = False
    requires_admin: bool = False
    estimated_minutes: int = 5

    @abstractmethod
    def check_prerequisites(self) -> Tuple[bool, str]:
        """Kiểm tra điều kiện tiên quyết (quyền admin, file thực thi, hệ điều hành)."""
        pass

    @abstractmethod
    def start(self, machine_id: Optional[int] = None) -> TestResult:
        """Bắt đầu chạy bài kiểm tra."""
        pass

    @abstractmethod
    def collect_result(self, machine_id: Optional[int] = None, run_id: Optional[int] = None) -> TestResult:
        """Thu thập kết quả sau khi bài kiểm tra hoàn thành (hoặc sau khi khởi động lại)."""
        pass


def test_result_to_evidence(
    test_id: str,
    group: str,
    result: TestResult,
    rules: Optional[Dict[str, Any]] = None,
    crash_id: Optional[int] = None,
) -> Optional[Evidence]:
    """
    Chuyển đổi kết quả kiểm tra phần cứng thành Bằng chứng (Evidence).
    Quy tắc:
    - failed: sinh bằng chứng STRONG, SUPPORT cho nhóm kiểm tra (khẳng định lỗi).
    - passed: sinh bằng chứng REFUTE (RAM là WEAK refute; ổ cứng/khác là MEDIUM refute).
    - inconclusive, pending, not_run: KHÔNG sinh bằng chứng.
    """
    if result.status not in ("failed", "passed"):
        return None

    tr_rules = (rules or {}).get("test_rules", {})
    conversion_map = tr_rules.get("evidence_conversion", {}).get(test_id, {})
    now_iso = datetime.now(timezone.utc).isoformat()

    if result.status == "failed":
        rule_conf = conversion_map.get("failed", {})
        strength = rule_conf.get("strength", "strong")
        polarity = "support"
        summary = rule_conf.get("summary", f"Kiểm tra {test_id} PHÁT HIỆN LỖI phần cứng ({group})")
        detail = result.details or f"Bài kiểm tra phần cứng {test_id} báo lỗi."
    else:  # passed
        rule_conf = conversion_map.get("passed", {})
        # RAM passed chỉ nên là weak refute vì lỗi RAM có thể chập chờn
        default_strength = "weak" if group == "ram" else "medium"
        strength = rule_conf.get("strength", default_strength)
        polarity = "refute"
        summary = rule_conf.get("summary", f"Kiểm tra {test_id} ĐẠT - Không phát hiện lỗi ({group})")
        detail = result.details or f"Bài kiểm tra phần cứng {test_id} đạt yêu cầu."

    return Evidence(
        crash_id=crash_id,
        kind="hwtest",
        source=f"HWTest: {test_id}",
        time_utc=now_iso,
        summary=summary,
        detail=detail,
        strength=strength,
        polarity=polarity,
        group_id=f"hwtest_{test_id}",
    )
