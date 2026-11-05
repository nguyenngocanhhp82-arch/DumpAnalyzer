"""Kiểm thử đối chiếu với file mẫu thực tế 092326-67062-01.

Sử dụng:
- tests/fixtures/expected_triage_092326-67062-01.json
- tests/private_fixtures/092326-67062-01.dmp (nếu có, nếu không có thì skip).
"""

import json
from pathlib import Path
import pytest
from dumpanalyzer.analyzer.triage_reader import read_triage


def test_expected_fixture_schema():
    """Kiểm tra cấu trúc và tính hợp lệ của file fixture expected JSON."""
    fixture_path = Path("tests/fixtures/expected_triage_092326-67062-01.json")
    assert fixture_path.exists(), f"Không tìm thấy file fixture: {fixture_path}"

    with open(fixture_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data.get("ok") is True
    header = data.get("header", {})
    assert header.get("bugcheck_code") in ("0x23", "0x00000023")
    assert header.get("os_build") == 26100
    assert header.get("dump_type_name") == "triage"

    exc = data.get("exception", {})
    assert exc.get("code") == "0xC0000005"
    assert exc.get("module") in ("fastfat.SYS", "ntoskrnl.exe")
    assert exc.get("address") in ("0xFFFFF8017B4F9732", "0xFFFFF80585ED8334")

    stack = data.get("stack_modules_in_order", [])
    assert len(stack) > 0


def test_real_dump_if_available():
    """Nếu có file dump thật trong tests/private_fixtures/, đọc và đối chiếu từng trường với expected."""
    real_dump = Path("tests/private_fixtures/092326-67062-01.dmp")
    if not real_dump.exists():
        # Kiểm tra xem có ở thư mục gốc hoặc docs không
        alt_dump = Path("092326-67062-01.dmp")
        if alt_dump.exists():
            real_dump = alt_dump
        else:
            pytest.skip("Không có file dump thực tế 092326-67062-01.dmp trong tests/private_fixtures/ (bỏ qua kiểm tra nhị phân thật)")

    res = read_triage(real_dump)
    assert res.ok is True
    assert res.header.get("bugcheck_code") in ("0x23", "0x00000023")
    assert res.header.get("os_build") == 26100
    assert res.header.get("dump_type_name") == "triage"

    assert res.exception is not None
    assert res.exception.get("code") == "0xC0000005"
    assert res.exception.get("module") in ("fastfat.SYS", "ntoskrnl.exe")

    assert "FLTMGR.SYS" in res.stack_modules_in_order
    assert "fastfat.SYS" in res.stack_modules_in_order
    assert "ntoskrnl.exe" in res.stack_modules_in_order
