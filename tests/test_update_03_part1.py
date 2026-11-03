"""
Bộ kiểm thử cho ĐỢT CẬP NHẬT 03 - PHẦN 1: THU THÊM DỮ LIỆU ĐỂ TĂNG BẰNG CHỨNG
Bao gồm:
- 1.1 Parser cdb (!errrec, !chkimg, lmvm, --save-cdb-samples)
- 1.2 Mở rộng Event Log (Kernel-PnP 219, Code Integrity, Application Error 1000, Processor 37)
- 1.3 Thu thập thông tin hệ thống sysinfo (RAM, Ổ đĩa, BIOS/CPU/GPU)
- 1.4 Nhập danh sách thiết bị CSV AppSheet (asset_info)
"""

from dumpanalyzer.analyzer.cdb_parser import CdbParser, CdbAnalysisResult
from dumpanalyzer.analyzer.cdb_runner import _save_raw_cdb_sample
from dumpanalyzer.collectors.eventlog import (
    summarize_app_crashes,
    CURATED_EVENT_PROVIDERS,
)
from dumpanalyzer.collectors.sysinfo import (
    collect_all_system_info,
    save_system_info_to_db,
)
from dumpanalyzer.collectors.asset_info import (
    import_asset_csv,
    evaluate_asset_evidence,
)
from dumpanalyzer.storage.db import Database
from dumpanalyzer.core.models import MachineInfo



def test_cdb_parser_errrec_synthetic():
    """Kiểm tra bóc tách !errrec từ output CPER WHEA mẫu (dữ liệu tổng hợp)."""
    synthetic_errrec = """
===============================================================================
Common Platform Error Record (CPER)
-------------------------------------------------------------------------------
Record Id     : 01d9f8e4e9b8f2c0
Severity      : Fatal (1)
Flags         : 0x00000000
Record Length : 288
Section Count : 1

Section 0     : Processor Generic
Section Type  : {9876beee-8f18-4838-88db-51060b12d195} (Processor Generic)
Error Type    : Micro-architectural Error
Processor APIC ID : 0x00000000
    """
    parser = CdbParser()
    res = parser.parse(synthetic_errrec)

    assert res.errrec_info is not None
    assert res.errrec_info["component"] == "cpu"
    assert "Processor Generic" in res.errrec_info["section_type"]
    assert "Micro-architectural Error" in res.errrec_info["error_type"]
    assert res.errrec_info["severity"] == "Fatal (1)"


def test_cdb_parser_errrec_memory_ecc():
    """Kiểm tra bóc tách !errrec trường hợp lỗi bộ nhớ Memory ECC (dữ liệu tổng hợp)."""
    synthetic_mem_errrec = """
Common Platform Error Record (CPER)
Severity      : Recoverable (2)
Section 0     : Memory
Section Type  : {9876beee-8f18-4838-88db-51060b12d197} (Memory Error)
Error Type    : Multi-bit ECC
    """
    parser = CdbParser()
    res = parser.parse(synthetic_mem_errrec)

    assert res.errrec_info is not None
    assert res.errrec_info["component"] == "ram"
    assert "Memory" in res.errrec_info["section_type"]
    assert "Multi-bit ECC" in res.errrec_info["error_type"]


def test_cdb_parser_chkimg_corrupted_and_clean():
    """Kiểm tra bóc tách !chkimg -d nt khi phát hiện lỗi sai khác và khi toàn vẹn."""
    parser = CdbParser()

    # Trường hợp 1: Có 16 lỗi sai khác
    synthetic_chkimg_err = """
!chkimg -d nt
16 errors : !nt (fffff800`04001000-fffff800`0400100f)
4610 patterns tested, 16 different bytes
    """
    res_err = parser.parse(synthetic_chkimg_err)
    assert res_err.chkimg_info is not None
    assert res_err.chkimg_info["is_corrupted"] is True
    assert res_err.chkimg_info["error_count"] == 16
    assert res_err.chkimg_info["patterns_tested"] == 4610

    # Trường hợp 2: Toàn vẹn (0 errors)
    synthetic_chkimg_clean = """
!chkimg -d nt
4610 patterns tested, 0 errors (including 0 checksum errors)
    """
    res_clean = parser.parse(synthetic_chkimg_clean)
    assert res_clean.chkimg_info is not None
    assert res_clean.chkimg_info["is_corrupted"] is False
    assert res_clean.chkimg_info["error_count"] == 0


def test_cdb_parser_lmvm_driver_age():
    """Kiểm tra bóc tách lmvm và tính tuổi driver (tháng) so với thời điểm crash."""
    synthetic_lmvm = """
Loaded symbol image file: nvlddmkm.sys
    Image name: nvlddmkm.sys
    Timestamp:        Thu Sep 21 04:32:10 2023 (650BD3CA)
    File version:     31.0.15.3742
    Product version:  31.0.15.3742
    """
    parser = CdbParser()
    res = parser.parse(synthetic_lmvm)
    assert res.driver_age_info is not None
    assert res.driver_age_info["image_name"] == "nvlddmkm.sys"

    info = parser._parse_lmvm(synthetic_lmvm, suspect_driver="nvlddmkm.sys", crash_time_utc="2024-09-21T10:00:00Z")
    assert info is not None
    assert info["image_name"] == "nvlddmkm.sys"
    assert info["file_version"] == "31.0.15.3742"
    assert info["age_months"] == 12  # Từ tháng 9/2023 đến tháng 9/2024 là đúng 12 tháng


def test_cdb_parser_fault_tolerance():
    """Kiểm tra tính chịu lỗi của parser: văn bản rác hoặc thiếu lệnh không làm văng exception."""
    parser = CdbParser()
    junk_output = "Some random text without symbols or error records\nquit:\n"
    res = parser.parse(junk_output)
    assert isinstance(res, CdbAnalysisResult)
    assert res.errrec_info is None
    assert res.chkimg_info is None
    assert res.driver_age_info is None


def test_save_raw_cdb_sample(tmp_path):
    """Kiểm tra chức năng lưu sample cdb vào workspace/cdb_samples."""
    sample_txt = "DUMP ANALYSIS TEST SAMPLE CONTENT"
    dump_fake = tmp_path / "test_mini.dmp"
    dump_fake.touch()

    saved_file = _save_raw_cdb_sample(dump_fake, sample_txt, target_dir=tmp_path / "cdb_samples")
    assert saved_file is not None
    assert saved_file.exists()
    assert saved_file.read_text(encoding="utf-8") == sample_txt


def test_eventlog_providers_and_app_crashes():
    """Kiểm tra danh sách CURATED_EVENT_PROVIDERS và hàm summarize_app_crashes."""
    # Kiểm tra các ID mới có trong danh sách
    assert 219 in CURATED_EVENT_PROVIDERS.get("Microsoft-Windows-Kernel-PnP", [])
    assert 3033 in CURATED_EVENT_PROVIDERS.get("Microsoft-Windows-CodeIntegrity", [])
    assert 37 in CURATED_EVENT_PROVIDERS.get("Microsoft-Windows-Kernel-Processor-Power", [])

    # Thử nghiệm thống kê App Crashes (Event 1000)
    mock_events = [
        {"app_crash_info": {"app_name": "chrome.exe", "fault_module": "ntdll.dll"}},
        {"app_crash_info": {"app_name": "discord.exe", "fault_module": "discord.dll"}},
        {"app_crash_info": {"app_name": "winword.exe", "fault_module": "mso.dll"}},
        {"app_crash_info": {"app_name": "chrome.exe", "fault_module": "chrome.dll"}},
    ]
    summary = summarize_app_crashes(mock_events)
    assert summary["unique_app_count"] == 3
    assert "chrome.exe" in summary["unique_apps"]
    assert "discord.exe" in summary["unique_apps"]
    assert "winword.exe" in summary["unique_apps"]
    assert summary["is_random_multiapp"] is True


def test_sysinfo_collector_and_db(tmp_path):
    """Kiểm tra thu thập sysinfo từ fixture tổng hợp và lưu vào bảng system_info."""
    db_path = tmp_path / "sysinfo_test.db"
    db = Database(db_path)
    mid = db.insert_machine(MachineInfo(hostname="PC-ACCOUNTING-01"))

    mock_ram = {
        "total_gb": 32.0,
        "module_count": 2,
        "modules": [{"locator": "DIMM 0", "speed_mhz": 3200, "configured_speed_mhz": 3600}],
        "overclock_hint": True,
    }
    mock_disks = [
        {
            "device_id": "0",
            "friendly_name": "Samsung NVMe 980",
            "media_type": "SSD",
            "health_status": "Warning",
            "operational_status": "Degraded",
            "size_gb": 1000.0,
            "wear_pct": 85,
            "read_errors": 12,
            "write_errors": 0,
            "temperature_c": 55,
            "power_on_hours": 12000,
        }
    ]
    mock_platform = {
        "bios": {"version": "F10", "release_date": "2019-01-01", "age_years": 5.2, "manufacturer": "Gigabyte"},
        "cpu": {"name": "AMD Ryzen 5 3600", "cores": 6, "threads": 12},
        "gpu": [{"name": "GTX 1660 Ti", "driver_version": "450.12", "driver_date": "2020-05-01", "driver_age_months": 48}],
    }

    all_sys = collect_all_system_info(mock_ram=mock_ram, mock_disks=mock_disks, mock_platform=mock_platform)
    assert all_sys["ram"]["overclock_hint"] is True
    assert all_sys["disks"][0]["wear_pct"] == 85

    # Lưu vào database
    save_system_info_to_db(db, machine_id=mid, sys_info=all_sys)

    # Đọc lại từ CSDL
    rows = db.get_system_info_by_machine(mid)
    assert len(rows) >= 5
    categories = {r["category"] for r in rows}
    assert "ram" in categories
    assert "disk" in categories
    assert "bios" in categories
    assert "cpu" in categories
    assert "gpu" in categories

    db.close()


def test_asset_info_csv_import_and_evidence(tmp_path):
    """Kiểm tra nhập file CSV danh sách thiết bị và sinh bằng chứng."""
    csv_file = tmp_path / "devices_export.csv"
    csv_content = """Tên máy;Ngày mua;Số lần sửa;RAM;Ghi chú
PC-ADMIN-01;2018-05-10;4;16GB;Từng thay nguồn 2 lần, máy nóng
PC-HR-02;2023-11-01;0;8GB;Máy mới cấp phát
"""
    csv_file.write_text(csv_content, encoding="utf-8")

    db_path = tmp_path / "asset_test.db"
    db = Database(db_path)

    res = import_asset_csv(csv_file, db)
    assert res["imported_count"] == 2
    assert res["errors"] == []

    # Tra cứu PC-ADMIN-01
    asset_01 = db.get_asset_info_by_hostname("pc-admin-01")
    assert asset_01 is not None
    assert asset_01["repair_count"] == 4
    assert asset_01["purchase_date"] == "2018-05-10"

    # Đánh giá bằng chứng từ tuổi máy và số lần sửa
    evs = evaluate_asset_evidence(asset_01)
    assert len(evs) == 2  # 1 tuổi máy > 4 năm, 1 số lần sửa >= 3
    summaries = [e.summary for e in evs]
    assert any("đã sử dụng" in s for s in summaries)
    assert any("từng sửa chữa 4 lần" in s for s in summaries)

    db.close()
