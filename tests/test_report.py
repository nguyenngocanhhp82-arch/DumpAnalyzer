"""Bộ kiểm thử cho module xuất báo cáo HTML và Excel (report/exporter.py)."""

import openpyxl
import pytest

from dumpanalyzer.core.models import Crash, Evidence, Finding, MachineInfo
from dumpanalyzer.report.exporter import export_excel_report, export_html_report


@pytest.fixture
def sample_report_data():
    """Tạo dữ liệu mẫu đa dạng cho bài kiểm thử xuất báo cáo."""
    c1 = Crash(
        id=1,
        dump_path="C:/dumps/kernel_124.dmp",
        dump_sha256="abc123sha256",
        dump_type="kernel",
        crash_time_utc="2026-10-20T10:00:00Z",
        bugcheck_code="0x124",
        bugcheck_name="WHEA_UNCORRECTABLE_ERROR",
        p1="0x0",
        p2="0xffff8000",
        p3="0x0",
        p4="0x0",
        image_name="AuthenticAMD.sys",
        module_name="AuthenticAMD",
        process_name="System",
        failure_bucket_id="0x124_AuthenticAMD_PROCESSOR_CACHE",
        uptime_seconds=3600,
        analyzed_by="cdb",
    )
    c2 = Crash(
        id=2,
        dump_path="",
        dump_sha256="sha_log_only_41",
        dump_type="none",
        crash_time_utc="2026-10-22T08:30:00Z",
        bugcheck_code="0x0",
        bugcheck_name="UNKNOWN_BUGCHECK",
        image_name="",
        module_name="",
        process_name="",
        failure_bucket_id="",
        uptime_seconds=0,
        analyzed_by="log_only",
    )

    machine = MachineInfo(
        hostname="PC-VANPHONG-01",
        model="Gigabyte B550M Aorus Elite",
        bios="F15",
        cpu="AMD Ryzen 5 5600X 6-Core Processor",
        os_build="22631.3007",
    )

    finding = Finding(
        scope="machine",
        suspect="cpu",
        score=72.5,
        confidence="cao",
        rationale="Hệ thống ghi nhận nhiều lần sập mã 0x124 với lỗi cache CPU AMD.",
        next_steps=[
            "Kiểm tra nhiệt độ CPU khi chịu tải",
            "Cập nhật driver chipset AMD",
            "Chạy MemTest86 kiểm tra RAM",
            "Cập nhật BIOS bo mạch chủ",
        ],
    )

    suspect_ranking = [
        {"label": "Bộ xử lý CPU", "percentage": 72.5},
        {"label": "Bộ nhớ RAM", "percentage": 18.0},
        {"label": "Bộ nguồn (PSU)", "percentage": 9.5},
    ]

    ev1 = Evidence(
        id=1,
        crash_id=1,
        kind="dump",
        source="cdb",
        event_id=None,
        time_utc="2026-10-20T10:00:00Z",
        summary="WHEA MCA error trên core 2",
        detail="MACHINE_CHECK_EXCEPTION cache hierarchy error",
    )
    ev2 = Evidence(
        id=2,
        crash_id=2,
        kind="eventlog",
        source="Microsoft-Windows-Kernel-Power",
        event_id=41,
        time_utc="2026-10-22T08:30:00Z",
        summary="Sự cố mất nguồn Kernel-Power 41 (BugcheckCode=0)",
        detail="The system has rebooted without cleanly shutting down first.",
    )

    return {
        "crashes": [c1, c2],
        "machine": machine,
        "finding": finding,
        "suspect_ranking": suspect_ranking,
        "evidences": [ev1, ev2],
    }


def test_export_html_report_success(tmp_path, sample_report_data):
    """Kiểm tra xuất file báo cáo HTML thành công với đầy đủ các thành phần trực quan."""
    out_file = tmp_path / "report.html"
    res_path = export_html_report(
        output_path=out_file,
        crashes=sample_report_data["crashes"],
        finding=sample_report_data["finding"],
        machine_info=sample_report_data["machine"],
        evidences=sample_report_data["evidences"],
        suspect_ranking=sample_report_data["suspect_ranking"],
    )

    assert res_path.exists()
    content = res_path.read_text(encoding="utf-8")

    # Kiểm tra các thông tin trọng yếu
    assert "<!DOCTYPE html>" in content
    assert "DumpAnalyzer" in content
    assert "PC-VANPHONG-01" in content
    assert "AMD Ryzen 5 5600X" in content
    assert "Độ tin cậy: cao" in content
    assert "Bộ xử lý CPU" in content
    assert "72.5%" in content
    assert "0x124" in content
    assert "WHEA_UNCORRECTABLE_ERROR" in content
    assert "Không có dump (log_only)" in content  # Nhãn dòng log_only
    assert "TẦNG 1: DỄ" in content                 # Phân loại độ khó
    assert "TẦNG 4: PHỨC TẠP" in content
    assert "Microsoft-Windows-Kernel-Power" in content


def test_export_excel_report_success(tmp_path, sample_report_data):
    """Kiểm tra xuất file báo cáo Excel (.xlsx) với 3 sheet trình bày chuẩn."""
    out_file = tmp_path / "report.xlsx"
    res_path = export_excel_report(
        output_path=out_file,
        crashes=sample_report_data["crashes"],
        finding=sample_report_data["finding"],
        machine_info=sample_report_data["machine"],
        evidences=sample_report_data["evidences"],
        suspect_ranking=sample_report_data["suspect_ranking"],
    )

    assert res_path.exists()
    wb = openpyxl.load_workbook(str(res_path))

    # Kiểm tra các sheet
    assert "Tổng quan & Kết luận" in wb.sheetnames
    assert "Danh sách Crash" in wb.sheetnames
    assert "Bằng chứng thu thập" in wb.sheetnames

    # Kiểm tra sheet 1
    ws1 = wb["Tổng quan & Kết luận"]
    ws1_values = [str(cell.value) for row in ws1.iter_rows() for cell in row if cell.value is not None]
    assert "CAO" in ws1_values
    assert any("Bộ xử lý CPU" in v for v in ws1_values)

    # Kiểm tra sheet 2 (Danh sách Crash)
    ws2 = wb["Danh sách Crash"]
    assert ws2.cell(row=2, column=3).value == "0x124"
    assert ws2.cell(row=3, column=3).value == "0x0"
    assert ws2.cell(row=3, column=7).value == "log_only"

    # Kiểm tra sheet 3 (Bằng chứng)
    ws3 = wb["Bằng chứng thu thập"]
    assert ws3.cell(row=2, column=4).value == "cdb"
    assert ws3.cell(row=3, column=4).value == "Microsoft-Windows-Kernel-Power"


def test_export_empty_data(tmp_path):
    """Kiểm tra xuất báo cáo an toàn khi dữ liệu rỗng."""
    html_out = tmp_path / "empty.html"
    xlsx_out = tmp_path / "empty.xlsx"

    p1 = export_html_report(html_out, crashes=[], finding=None, machine_info=None, evidences=[])
    p2 = export_excel_report(xlsx_out, crashes=[], finding=None, machine_info=None, evidences=[])

    assert p1.exists()
    assert p2.exists()
    assert "Không có dữ liệu sập máy" in p1.read_text(encoding="utf-8")
