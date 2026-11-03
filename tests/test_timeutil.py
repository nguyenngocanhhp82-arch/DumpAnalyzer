"""
Kiểm thử chuẩn hoá múi giờ và thời gian UTC.
"""

from datetime import timezone
from dumpanalyzer.core.timeutil import (
    parse_to_utc,
    to_utc_iso,
    utc_to_local_str,
    now_utc_iso,
)


def test_now_utc_iso_format():
    """Kiểm tra thời gian hiện tại chuẩn UTC kết thúc bằng 'Z'."""
    now_str = now_utc_iso()
    assert now_str.endswith("Z")
    assert len(now_str) == 20  # YYYY-MM-DDTHH:MM:SSZ


def test_parse_iso_utc():
    """Kiểm tra parse chuỗi ISO UTC."""
    dt = parse_to_utc("2026-10-29T08:30:00Z")
    assert dt is not None
    assert dt.tzinfo == timezone.utc
    assert dt.hour == 8
    assert dt.minute == 30


def test_parse_powershell_date():
    """Kiểm tra parse chuỗi định dạng PowerShell JSON /Date(1730000000000)/."""
    # 1730000000 giây = 2024-10-27 03:33:20 UTC
    dt = parse_to_utc("/Date(1730000000000)/")
    assert dt is not None
    assert dt.tzinfo == timezone.utc
    assert dt.year == 2024


def test_parse_standard_string():
    """Kiểm tra parse chuỗi 'YYYY-MM-DD HH:MM:SS'."""
    iso = to_utc_iso("2026-10-29 10:15:00")
    assert iso is not None
    assert iso.endswith("Z")


def test_utc_to_local_str():
    """Kiểm tra chuyển đổi sang chuỗi hiển thị giờ địa phương."""
    res = utc_to_local_str("2026-10-29T12:00:00Z")
    assert "/" in res  # Chứa định dạng ngày tháng dd/mm/yyyy
    assert ":" in res  # Chứa giờ phút

    # Giá trị None hoặc rỗng
    assert utc_to_local_str(None) == "Không xác định"
    assert utc_to_local_str("") == "Không xác định"
