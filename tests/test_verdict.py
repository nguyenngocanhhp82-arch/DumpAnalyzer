"""
Kiểm thử toàn diện module kết luận chẩn đoán (Verdict Engine),
sắp xếp bước kiểm tra từ DỄ -> KHÓ, liên kết Evidence và lưu trữ CSDL.
"""

from argparse import Namespace
import pytest
from dumpanalyzer.core.models import Crash, Evidence, Finding, MachineInfo
from dumpanalyzer.engine.rule_loader import load_all_rules
from dumpanalyzer.core.config import load_settings
from dumpanalyzer.engine.scorer import score_single_crash, score_machine_crashes
from dumpanalyzer.engine.verdict import (
    sort_next_steps_easy_to_hard,
    generate_crash_finding,
    generate_machine_finding,
)
from dumpanalyzer.storage.db import Database
from dumpanalyzer.cli import cmd_verdict


@pytest.fixture
def rules():
    return load_all_rules()


@pytest.fixture
def settings():
    return load_settings()


def test_sort_next_steps_easy_to_hard():
    """Kiểm tra thuật toán sắp xếp các bước kiểm tra theo độ khó từ dễ đến khó."""
    unsorted_steps = [
        "Thay thế bộ nguồn (PSU) mới hoặc thử nguồn khác",  # Tier 4 (Rất khó / Tốn chi phí)
        "Kiểm tra nhiệt độ CPU trong Windows hoặc BIOS",      # Tier 1 (Cực dễ / Nhanh)
        "Chạy MemTest86 kiểm tra RAM (ít nhất 2 lượt)",       # Tier 3 (Kiểm tra phần cứng)
        "Gỡ sạch driver bằng DDU trong Safe Mode rồi cài lại", # Tier 2 (Sửa phần mềm / Driver)
        "Cập nhật BIOS bo mạch chủ lên phiên bản mới nhất",   # Tier 4 (Can thiệp sâu)
        "Bật tính năng ghi dump bộ nhớ trong DumpAnalyzer",   # Tier 1 (Phần mềm nhanh)
    ]

    sorted_steps = sort_next_steps_easy_to_hard(unsorted_steps)

    # Các bước Tier 1 phải đứng đầu
    assert "nhiệt độ" in sorted_steps[0].lower() or "bật tính năng ghi dump" in sorted_steps[0].lower()
    assert "bật tính năng ghi dump" in sorted_steps[1].lower() or "nhiệt độ" in sorted_steps[1].lower()

    # DDU (Tier 2) phải đứng trước MemTest86 (Tier 3)
    ddu_idx = next(i for i, s in enumerate(sorted_steps) if "ddu" in s.lower())
    mem_idx = next(i for i, s in enumerate(sorted_steps) if "memtest86" in s.lower())
    assert ddu_idx < mem_idx

    # Thay nguồn / BIOS (Tier 4) phải đứng ở cuối
    bios_idx = next(i for i, s in enumerate(sorted_steps) if "cập nhật bios" in s.lower())
    psu_idx = next(i for i, s in enumerate(sorted_steps) if "psu" in s.lower())
    assert bios_idx > mem_idx
    assert psu_idx > mem_idx


def test_generate_crash_finding_attributes(rules, settings):
    """Kiểm tra các thuộc tính của Finding sinh ra cho crash đơn lẻ."""
    crash = Crash(
        id=10,
        dump_type="mini",
        bugcheck_code="0x124",
        bugcheck_name="WHEA_UNCORRECTABLE_ERROR",
        analyzed_by="cdb",
    )
    ev = Evidence(id=55, crash_id=10, kind="eventlog", source="Microsoft-Windows-WHEA-Logger", event_id=18)

    scored = score_single_crash(crash, [ev], rules, settings)
    finding = generate_crash_finding(crash, scored, rules, machine_id=1)

    assert finding.scope == "crash"
    assert finding.crash_id == 10
    assert finding.suspect == "cpu"
    assert finding.confidence == "trung bình"
    assert 55 in finding.evidence_ids
    assert len(finding.next_steps) >= 3
    # Lời giải thích phải có tiếng Việt và nhắc tới mã lỗi hoặc CPU
    assert "0x124" in finding.rationale or "CPU" in finding.rationale


def test_generate_machine_finding_attributes(rules, settings):
    """Kiểm tra Finding tổng hợp theo máy."""
    scored_machine = {
        "suspect_scores": [("gpu", 85.0), ("driver", 10.0), ("ram", 5.0)],
        "top_suspect": "gpu",
        "top_score": 85.0,
        "confidence": "cao",
        "used_evidence_ids": [1, 2, 3],
        "is_conflicted": False,
        "conflict_note": "",
        "patterns_matched": ["Cùng một driver bên thứ ba lặp lại nhiều lần"],
        "crash_count": 3,
    }

    finding = generate_machine_finding(machine_id=2, scored_result=scored_machine, rules=rules)
    assert finding.scope == "machine"
    assert finding.machine_id == 2
    assert finding.suspect == "gpu"
    assert finding.confidence == "cao"
    assert [1, 2, 3] == finding.evidence_ids
    assert "Cùng một driver bên thứ ba lặp lại" in finding.rationale


def test_database_finding_crud(tmp_path):
    """Kiểm tra lưu trữ và truy vấn Finding trong SQLite DB."""
    db_file = tmp_path / "test_verdict.db"
    db = Database(db_path=db_file)

    crash = Crash(
        dump_path="dummy.dmp",
        dump_sha256="abc12345",
        dump_type="mini",
        crash_time_utc="2026-10-29T10:00:00Z",
        bugcheck_code="0x116",
        analyzed_by="cdb",
    )
    m_id = db.insert_machine(MachineInfo(hostname="TEST-PC"))
    c_id = db.insert_crash(crash)

    finding = Finding(
        scope="crash",
        crash_id=c_id,
        machine_id=m_id,
        suspect="gpu",
        score=82.5,
        confidence="cao",
        rationale="Card đồ họa NVIDIA gặp lỗi timeout TDR.",
        evidence_ids=[10, 11],
        next_steps=["Cài lại driver bằng DDU", "Kiểm tra nhiệt độ GPU"],
    )

    f_id = db.insert_finding(finding)
    assert f_id > 0

    # Đọc lại theo crash
    retrieved = db.get_findings_by_crash(c_id)
    assert len(retrieved) == 1
    item = retrieved[0]
    assert item["suspect"] == "gpu"
    assert item["score"] == 82.5
    assert item["confidence"] == "cao"
    assert item["evidence_ids"] == [10, 11]
    assert item["next_steps"] == ["Cài lại driver bằng DDU", "Kiểm tra nhiệt độ GPU"]

    db.close()


def test_cli_verdict_execution(tmp_path, monkeypatch):
    """Kiểm tra thực thi lệnh CLI 'dumpanalyzer verdict'."""
    db_file = tmp_path / "test_cli_verdict.db"

    # Chạy trên DB tạm
    monkeypatch.setattr("dumpanalyzer.cli.Database", lambda: Database(db_path=db_file))

    db = Database(db_path=db_file)
    c_id = db.insert_crash(Crash(
        dump_path="test.dmp",
        dump_sha256="sha_verdict_test",
        dump_type="mini",
        crash_time_utc="2026-10-29T12:00:00Z",
        bugcheck_code="0x124",
        bugcheck_name="WHEA_UNCORRECTABLE_ERROR",
        analyzed_by="cdb",
    ))
    db.close()

    # 1. Test verdict cho 1 crash
    ret_crash = cmd_verdict(Namespace(crash_id=c_id, machine=None, from_date=None, to_date=None))
    assert ret_crash == 0

    # 2. Test verdict cho toàn bộ máy
    ret_all = cmd_verdict(Namespace(crash_id=None, machine=None, from_date=None, to_date=None))
    assert ret_all == 0
