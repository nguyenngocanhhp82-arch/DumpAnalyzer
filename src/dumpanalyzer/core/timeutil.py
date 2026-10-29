"""
Xử lý chuẩn hoá múi giờ cho DumpAnalyzer.
Quy tắc:
- Mọi mốc thời gian lưu trong CSDL và tính toán tương quan PHẢI là chuẩn UTC (ISO 8601: YYYY-MM-DDTHH:MM:SSZ).
- Chỉ chuyển đổi sang giờ địa phương khi hiển thị trên giao diện hoặc xuất báo cáo.
"""

from datetime import datetime, timezone, tzinfo
from typing import Optional, Union
import re


def now_utc_iso() -> str:
    """Trả về thời gian hiện tại chuẩn ISO UTC (kết thúc bằng Z)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_to_utc(dt_val: Union[str, datetime, int, float, None]) -> Optional[datetime]:
    """
    Chuyển đổi một đối tượng thời gian bất kỳ (str, int timestamp, datetime) về datetime UTC.
    Nếu không có thông tin múi giờ, mặc định coi là thời gian địa phương của máy đang chạy.
    """
    if dt_val is None:
        return None

    if isinstance(dt_val, (int, float)):
        # Epoch timestamp tính bằng giây
        return datetime.fromtimestamp(dt_val, tz=timezone.utc)

    if isinstance(dt_val, datetime):
        if dt_val.tzinfo is None:
            # Gán giờ địa phương rồi chuyển về UTC
            local_dt = dt_val.astimezone()
            return local_dt.astimezone(timezone.utc)
        return dt_val.astimezone(timezone.utc)

    if isinstance(dt_val, str):
        raw = dt_val.strip()
        if not raw:
            return None

        # 1. Hỗ trợ định dạng PowerShell JSON /Date(1730000000000)/
        ps_match = re.search(r"/Date\((\d+)\)/", raw)
        if ps_match:
            epoch_ms = int(ps_match.group(1))
            return datetime.fromtimestamp(epoch_ms / 1000.0, tz=timezone.utc)

        # 2. Định dạng ISO UTC chuẩn kết thúc bằng Z
        if raw.endswith("Z"):
            clean = raw[:-1]
            try:
                dt = datetime.fromisoformat(clean)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        # 3. Định dạng ISO có timezone offset (+07:00, -05:00)
        try:
            dt = datetime.fromisoformat(raw)
            if dt.tzinfo is not None:
                return dt.astimezone(timezone.utc)
            # Không có tzinfo -> coi là local time
            return dt.astimezone().astimezone(timezone.utc)
        except ValueError:
            pass

        # 4. Các định dạng thông dụng: YYYY-MM-DD HH:MM:SS
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%d/%m/%Y %H:%M:%S",
            "%m/%d/%Y %I:%M:%S %p",
            "%Y/%m/%d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(raw, fmt)
                return dt.astimezone().astimezone(timezone.utc)
            except ValueError:
                continue

    return None


def to_utc_iso(dt_val: Union[str, datetime, int, float, None]) -> Optional[str]:
    """Chuyển đổi bất kỳ thời gian nào sang chuỗi chuẩn ISO UTC 'YYYY-MM-DDTHH:MM:SSZ'."""
    utc_dt = parse_to_utc(dt_val)
    if utc_dt is None:
        return None
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_to_local_str(utc_str: Optional[str], fmt: str = "%d/%m/%Y %H:%M:%S") -> str:
    """
    Chuyển đổi chuỗi thời gian UTC từ cơ sở dữ liệu sang chuỗi giờ địa phương dễ đọc cho IT.
    Ví dụ: '2026-10-29T09:00:00Z' -> '29/10/2026 16:00:00' (với múi giờ UTC+7).
    """
    if not utc_str:
        return "Không xác định"

    utc_dt = parse_to_utc(utc_str)
    if utc_dt is None:
        return utc_str

    local_dt = utc_dt.astimezone()  # Tự động lấy múi giờ máy tính hiện tại
    return local_dt.strftime(fmt)
