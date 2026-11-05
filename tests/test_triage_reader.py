"""Kiểm thử bộ đọc Minidump Triage thuần Python (analyzer/triage_reader.py).

Tuân thủ các nguyên tắc:
- N1: Không bao giờ crash unhandled với bất kỳ file nào (rỗng, cắt ngắn, rác, sai signature).
- N2: Chịu lỗi triệt để, ghi cảnh báo vào warnings list.
- N4: Bảo mật bộ nhớ người dùng, không leak raw binary payload.
"""

from pathlib import Path
from dumpanalyzer.analyzer._selftest_fixture import build_synthetic_triage
from dumpanalyzer.analyzer.triage_reader import read_triage, TriageResult


def test_triage_reader_synthetic_success(tmp_path: Path):
    """Kiểm tra đọc file minidump triage tổng hợp chuẩn định dạng PAGEDU64."""
    data = build_synthetic_triage()
    dmp_file = tmp_path / "synthetic_triage.dmp"
    dmp_file.write_bytes(data)

    res = read_triage(dmp_file)
    assert isinstance(res, TriageResult)
    assert res.ok is True
    assert res.header.get("os_build") == 26100
    assert res.header.get("bugcheck_code") in ("0x23", "0x00000023")
    assert res.header.get("dump_type_name") == "triage"

    # Kiểm tra ngoại lệ trích xuất
    assert res.exception is not None
    assert res.exception.get("code") == "0xC0000005"
    assert "Access violation" in res.exception.get("meaning", "")
    assert res.exception.get("module") in ("ntoskrnl.exe", "fastfat.SYS")

    # Kiểm tra call stack
    assert len(res.stack_modules_in_order) >= 2
    assert "FLTMGR.SYS" in res.stack_modules_in_order
    assert "fastfat.SYS" in res.stack_modules_in_order

    # Kiểm tra unloaded drivers
    assert "USBSTOR.SYS" in res.unloaded


def test_triage_reader_empty_file(tmp_path: Path):
    """Kiểm tra file rỗng 0 bytes không gây crash unhandled (N1)."""
    empty_file = tmp_path / "empty.dmp"
    empty_file.write_bytes(b"")

    res = read_triage(empty_file)
    assert res.ok is False
    assert len(res.warnings) > 0
    assert "quá nhỏ" in res.warnings[0].lower() or "kích thước" in res.warnings[0].lower()


def test_triage_reader_truncated_header(tmp_path: Path):
    """Kiểm tra file bị cắt ngắn giữa chừng (ví dụ 500 bytes) không gây struct.error (N1)."""
    trunc_file = tmp_path / "truncated.dmp"
    trunc_file.write_bytes(b"PAGEDUMP" + b"\x00" * 400)

    res = read_triage(trunc_file)
    assert res.ok is False
    assert len(res.warnings) > 0


def test_triage_reader_invalid_signature(tmp_path: Path):
    """Kiểm tra file không phải dump (sai signature) trả về cảnh báo hợp lý."""
    bad_file = tmp_path / "bad_sig.dmp"
    bad_file.write_bytes(b"NOT_A_DUMP_FILE" + b"\x00" * 16384)

    res = read_triage(bad_file)
    assert res.ok is False
    assert any("signature" in w.lower() for w in res.warnings)


def test_triage_reader_nonexistent_file(tmp_path: Path):
    """Kiểm tra đường dẫn không tồn tại."""
    ghost_file = tmp_path / "ghost_file.dmp"
    res = read_triage(ghost_file)
    assert res.ok is False
    assert any("không tồn tại" in w.lower() for w in res.warnings)


def test_triage_reader_non_triage_dump(tmp_path: Path):
    """Kiểm tra dump không phải loại triage (DumpType != 4) được phát hiện đúng."""
    # Tạo dump với DumpType = 1 (Full dump)
    data = bytearray(build_synthetic_triage())
    # Sửa DumpType tại 0xF98 thành 1
    data[0xF98:0xF9C] = (1).to_bytes(4, "little")
    non_triage_file = tmp_path / "full_dump.dmp"
    non_triage_file.write_bytes(data)

    res = read_triage(non_triage_file)
    assert res.header.get("dump_type_name") == "full"
    # Vẫn đọc được header cơ bản nhưng cảnh báo không phải triage
    assert any("không phải dump triage" in w.lower() for w in res.warnings)


def test_triage_reader_to_dict_safety(tmp_path: Path):
    """Kiểm tra to_dict() tuần tự hóa JSON chuẩn và không chứa memory dump bytes (N4)."""
    data = build_synthetic_triage()
    dmp_file = tmp_path / "synthetic.dmp"
    dmp_file.write_bytes(data)

    res = read_triage(dmp_file)
    d = res.to_dict()
    assert isinstance(d, dict)
    assert d["ok"] is True
    assert "header" in d
    assert "modules" in d
    # Đảm bảo không chứa trường nhị phân thô
    import json
    json_str = json.dumps(d)
    assert isinstance(json_str, str)
