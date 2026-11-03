"""Unit tests cho module phân tích đa máy engine (batch_analyzer.py)."""

import pytest
from dumpanalyzer.engine.batch_analyzer import (
    discover_machines_and_dumps,
    analyze_fleet,
    export_fleet_html_report,
    export_fleet_excel_report,
)
from dumpanalyzer.core.models import Crash, MachineInfo, Finding


@pytest.fixture
def sample_fleet_dir(tmp_path):
    """Tạo cấu trúc thư mục giả lập gồm 2 máy tính và dump trực tiếp."""
    fleet = tmp_path / "fleet_data"
    fleet.mkdir()

    pc1 = fleet / "PC-KE-TOAN-01"
    pc1.mkdir()
    d1 = pc1 / "crash1.dmp"
    d1.write_bytes(b"PAGEDU64" + b"\x00" * 2000)

    pc2 = fleet / "PC-IT-02"
    pc2.mkdir()
    d2 = pc2 / "crash2.dmp"
    d2.write_bytes(b"PAGEDU64" + b"\x00" * 2000)

    direct = fleet / "direct.dmp"
    direct.write_bytes(b"PAGEDU64" + b"\x00" * 2000)

    return fleet


def test_discover_machines_and_dumps(sample_fleet_dir):
    """Kiểm tra nhận diện thư mục con và file dump lẻ."""
    discovered = discover_machines_and_dumps(sample_fleet_dir)
    assert "PC-KE-TOAN-01" in discovered
    assert "PC-IT-02" in discovered
    assert "Máy ngoại vi" in discovered

    assert len(discovered["PC-KE-TOAN-01"]) == 1
    assert len(discovered["PC-IT-02"]) == 1
    assert len(discovered["Máy ngoại vi"]) == 1


def test_analyze_fleet(sample_fleet_dir, tmp_path):
    """Kiểm tra quá trình phân tích fleet đa máy và tính năng phát hiện cảnh báo."""
    discovered = discover_machines_and_dumps(sample_fleet_dir)
    db_file = tmp_path / "test_fleet.db"
    settings = {
        "workspace_dir": str(tmp_path / "workspace"),
        "cdb_path": "",
        "confidence_thresholds": {"high": 70, "medium": 40},
        "min_verdict_score": 35,
    }

    fleet_data = analyze_fleet(discovered, settings=settings, db_path=str(db_file))

    assert "machines" in fleet_data
    assert "summary" in fleet_data
    assert fleet_data["summary"]["total_machines"] == 3
    assert fleet_data["summary"]["total_crashes"] == 3

    # Kiểm tra mỗi máy có kết quả phân tích và finding
    for m in fleet_data["machines"]:
        assert "machine_name" in m
        assert "finding" in m
        assert isinstance(m["finding"], Finding)
        assert "confidence" in m


def test_export_fleet_html_and_excel(tmp_path):
    """Kiểm tra xuất báo cáo HTML và Excel tổng hợp đa máy."""
    # Tạo dữ liệu giả lập cho fleet
    m_info = MachineInfo(hostname="PC-01", os_build="Windows 11")
    finding = Finding(
        scope="machine",
        machine_id=1,
        suspect="gpu",
        score=75.0,
        confidence="cao",
        rationale="Nghi ngờ card đồ hoạ",
        next_steps=["Cập nhật driver GPU", "Kiểm tra nhiệt độ"],
    )
    c1 = Crash(
        id=1,
        machine_id=1,
        bugcheck_code="0x116",
        bugcheck_name="VIDEO_TDR_FAILURE",
        module_name="nvlddmkm.sys",
        image_name="nvlddmkm.sys",
        analyzed_by="cdb",
    )

    fleet_data = {
        "summary": {
            "total_machines": 1,
            "total_crashes": 1,
            "suspect_distribution": {"gpu": 1},
            "top_drivers": [("nvlddmkm.sys", 1)],
            "top_bugchecks": [("0x116", 1)],
            "fleet_warnings": [
                "Driver 'nvlddmkm.sys' xuất hiện trong 1 vụ sập."
            ],
        },
        "machines": [
            {
                "machine_name": "PC-01",
                "machine_info": m_info,
                "crashes": [c1],
                "finding": finding,
                "suspect_ranking": [("gpu", 75.0), ("ram", 15.0)],
                "top_suspect": "gpu",
                "top_score": 75.0,
                "confidence": "cao",
            }
        ],
    }

    html_out = tmp_path / "fleet_report.html"
    res_html = export_fleet_html_report(html_out, fleet_data)
    assert res_html.exists()
    content = html_out.read_text(encoding="utf-8")
    assert "Báo cáo Phân tích Sự cố Đa máy" in content
    assert "PC-01" in content
    assert "nvlddmkm.sys" in content

    xlsx_out = tmp_path / "fleet_report.xlsx"
    res_xlsx = export_fleet_excel_report(xlsx_out, fleet_data)
    assert res_xlsx.exists()
    assert res_xlsx.stat().st_size > 1000
