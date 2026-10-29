"""
Unit tests cho module phân tích theo lô đa máy (FleetBatchAnalyzer).
"""

import shutil
from pathlib import Path
import pytest
from dumpanalyzer.analyzer.batch import FleetBatchAnalyzer


@pytest.fixture
def dummy_dump_fleet(tmp_path):
    """
    Tạo cấu trúc thư mục giả lập gồm 2 máy tính:
    - PC-SALES-01: 2 file dump
    - PC-DESIGN-02: 1 file dump
    - dump_root.dmp (ở thư mục gốc)
    """
    fleet_dir = tmp_path / "fleet_dumps"
    fleet_dir.mkdir()

    pc1 = fleet_dir / "PC-SALES-01"
    pc1.mkdir()
    d1 = pc1 / "crash1.dmp"
    d2 = pc1 / "crash2.dmp"

    # Dùng header giả lập PAGEDU64 cho d1 và d2
    # Viết nhị phân PAGEDU64 tối thiểu
    header_bytes = b"PAGEDU64" + b"\x00" * 4000
    d1.write_bytes(header_bytes)
    d2.write_bytes(header_bytes)

    pc2 = fleet_dir / "PC-DESIGN-02"
    pc2.mkdir()
    d3 = pc2 / "crash3.dmp"
    d3.write_bytes(header_bytes)

    # File ở root
    d_root = fleet_dir / "standalone.dmp"
    d_root.write_bytes(header_bytes)

    return fleet_dir


def test_discover_machines(dummy_dump_fleet):
    analyzer = FleetBatchAnalyzer()
    discovered = analyzer.discover_machines(dummy_dump_fleet)

    assert "PC-SALES-01" in discovered
    assert "PC-DESIGN-02" in discovered
    assert len(discovered["PC-SALES-01"]) == 2
    assert len(discovered["PC-DESIGN-02"]) == 1


def test_analyze_fleet(dummy_dump_fleet):
    analyzer = FleetBatchAnalyzer()
    meta = {
        "PC-SALES-01": {"model": "Dell OptiPlex 7090", "motherboard": "Dell 0M41G8"},
        "PC-DESIGN-02": {"model": "ASUS ProArt Station", "motherboard": "ASUS ProArt B760"},
    }
    fleet_result = analyzer.analyze_fleet(dummy_dump_fleet, machine_metadata=meta)

    assert fleet_result["total_machines"] >= 2
    assert fleet_result["total_crashes"] >= 3
    assert len(fleet_result["machines"]) >= 2

    # Kiểm tra metadata máy
    sales_res = next(m for m in fleet_result["machines"] if m["machine_name"] == "PC-SALES-01")
    assert sales_res["model"] == "Dell OptiPlex 7090"
    assert sales_res["dump_count"] == 2
    assert "verdict" in sales_res


def test_widespread_driver_detection(tmp_path):
    """
    Kiểm tra cơ chế phát hiện driver lỗi xuất hiện đồng loạt trên >= 2 máy khác nhau.
    """
    fleet_dir = tmp_path / "fleet_driver_test"
    fleet_dir.mkdir()

    pc1 = fleet_dir / "PC-A"
    pc1.mkdir()
    d1 = pc1 / "test1.dmp"
    d1.write_bytes(b"PAGEDU64" + b"\x00" * 2000)

    pc2 = fleet_dir / "PC-B"
    pc2.mkdir()
    d2 = pc2 / "test2.dmp"
    d2.write_bytes(b"PAGEDU64" + b"\x00" * 2000)

    analyzer = FleetBatchAnalyzer()

    # Mock lại analyze_dump_file để trả về cùng 1 driver nvlddmkm.sys
    orig_analyze_dump = analyzer.analyze_dump_file

    def mock_analyze_dump(path):
        res = orig_analyze_dump(path)
        res["faulting_module"] = "nvlddmkm.sys"
        res["bugcheck_code"] = "0x116"
        res["bugcheck_name"] = "VIDEO_TDR_FAILURE"
        return res

    analyzer.analyze_dump_file = mock_analyze_dump

    fleet_result = analyzer.analyze_fleet(fleet_dir)
    assert len(fleet_result["widespread_drivers"]) == 1
    w_drv = fleet_result["widespread_drivers"][0]
    assert w_drv["driver"] == "nvlddmkm.sys"
    assert w_drv["affected_machines_count"] == 2
    assert set(w_drv["affected_machines"]) == {"PC-A", "PC-B"}

    # Xuất báo cáo HTML & Excel
    report_path = tmp_path / "fleet_report.html"
    out_html = analyzer.export_fleet_html(fleet_result, report_path)
    assert Path(out_html).exists()
    content = Path(out_html).read_text(encoding="utf-8")
    assert "nvlddmkm.sys" in content
    assert "CẢNH BÁO LỖI DRIVER HÀNG LOẠT TRÊN NHIỀU MÁY" in content

    excel_path = tmp_path / "fleet_report.xlsx"
    out_excel = analyzer.export_fleet_excel(fleet_result, excel_path)
    assert Path(out_excel).exists()
    assert Path(out_excel).stat().st_size > 1000
