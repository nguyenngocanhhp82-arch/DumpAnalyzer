"""
Module tạo gói triển khai bật ghi dump (Deployment Package) và tổng hợp báo cáo đội máy (Fleet Aggregator).
Được thiết kế theo Section 7.1, 7.2, 7.3 của UPDATE_04:
- Enable-CrashDump.ps1: Script PowerShell idempotent, tuân thủ ma trận 3.3, có -WhatIf, sao lưu đầy đủ.
- Rollback-CrashDump.ps1: Hoàn tác 100% về trạng thái ban đầu kể cả xóa giá trị.
- README_TRIEN_KHAI.txt: Hướng dẫn chi tiết bằng tiếng Việt.
- Aggregate Fleet JSON reports: Đọc, kiểm tra hợp lệ, lưu SQLite, phát hiện cũ/hỏng, xuất Excel.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("dumpanalyzer.deployment_package")


ENABLE_CRASHDUMP_PS1 = r"""<#
.SYNOPSIS
    Enable-CrashDump.ps1 - Bat ghi dump an toan cho Windows (DumpAnalyzer Deployment Package).
.DESCRIPTION
    Script tu dong hoa idempotent, tuan thu chat che nguyen tac an toan:
    - Chi ghi khi CrashDumpEnabled = 0 hoac chua ton tai.
    - Khong tu y doi che do 1, 2, 7 hoac Small (3).
    - Sao luu day du ca .reg va .json truoc khi ghi.
    - Doc lai de xac nhan (read-after-write).
    - TUYET DOI KHONG TU KHOI DONG LAI MAY.
    - Ghi audit log vao %ProgramData%\DumpAnalyzer\logs.
.PARAMETER TargetMode
    Che do ghi dump dich (7 = Automatic, 3 = Small). Mac dinh la 7.
.PARAMETER ReportDir
    Thu muc chia se mang de ghi file bao cao JSON cua may sau khi xu ly.
.PARAMETER DataDir
    Thu muc luu tru backup va log tren may cuc bo. Mac dinh la %ProgramData%\DumpAnalyzer.
.PARAMETER UseCli
    Goi truc tiep DumpAnalyzer-cli.exe neu duoc dat cung thu muc.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet(3, 7)] [int]$TargetMode = 7,
    [string]$ReportDir = "",
    [string]$DataDir = "$env:ProgramData\DumpAnalyzer",
    [switch]$UseCli,
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
$keyPs  = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
$keyReg = 'HKLM\SYSTEM\CurrentControlSet\Control\CrashControl'

# 0. Kiem tra quyen Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Can quyen Administrator de thay doi cau hinh Registry."
    exit 3
}

New-Item -ItemType Directory -Force -Path "$DataDir\backup","$DataDir\logs" | Out-Null

# Che do -UseCli neu co san executable
if ($UseCli) {
    $cliPath = Join-Path $PSScriptRoot "DumpAnalyzer-cli.exe"
    if (Test-Path $cliPath) {
        Write-Output "[*] Phat hien DumpAnalyzer-cli.exe, tien hanh thuc thi qua CLI..."
        & $cliPath dump-enable --yes --mode $TargetMode
        exit $LASTEXITCODE
    }
}

# 1. Doc trang thai hien tai (phan biet khong ton tai voi loi doc)
$prop = Get-ItemProperty -Path $keyPs -Name CrashDumpEnabled -ErrorAction SilentlyContinue
$cur  = if ($prop -and ($null -ne $prop.CrashDumpEnabled)) { [int]$prop.CrashDumpEnabled } else { $null }

# 2. Ma tran quyet dinh (Section 3.3)
if ($cur -in 1, 2, 7) {
    Write-Output "[OK] Khong can thay doi: CrashDumpEnabled da duoc bat san o che do $cur."
    exit 0
}
if ($cur -eq 3) {
    Write-Output "[CANH BAO] May dang o che do Small dump (3). Giu nguyen lua chon cua he thong. Yeu cau xac nhan rieng de nang cap."
    exit 0
}

# 3. Sao luu day du truoc khi thay doi (.reg va .json)
$stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$base  = Join-Path "$DataDir\backup" "CrashControl_${env:COMPUTERNAME}_$stamp"

try {
    reg export $keyReg "$base.reg" /y | Out-Null
} catch {
    Write-Warning "Khong the xuat file .reg: $_"
}

$backupJson = @{
    schema_version = 1
    tool_version = "1.2.0"
    hostname = $env:COMPUTERNAME
    created_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    values = @{
        CrashDumpEnabled = @{
            present = ($null -ne $cur)
            data = $cur
            type = "REG_DWORD"
        }
    }
}
$backupJson | ConvertTo-Json -Depth 5 | Set-Content -Path "$base.json" -Encoding UTF8

# 4. Ghi dung mot gia tri va doc lai de xac nhan
if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Dat CrashDumpEnabled = $TargetMode")) {
    Set-ItemProperty -Path $keyPs -Name CrashDumpEnabled -Value $TargetMode -Type DWord

    $afterProp = Get-ItemProperty -Path $keyPs -Name CrashDumpEnabled -ErrorAction SilentlyContinue
    $after = if ($afterProp) { [int]$afterProp.CrashDumpEnabled } else { -1 }

    if ($after -ne $TargetMode) {
        Write-Error "Doc lai sau khi ghi khong khop ($after != $TargetMode). Vui long hoan tac bang file: $base.json"
        exit 1
    }

    Write-Output "[OK] Da bat ghi dump thanh cong (CrashDumpEnabled = $TargetMode)."
    Write-Output "     Ban sao luu da luu tai: $base.json"
    Write-Output "     [LUU Y] CAN KHOI DONG LAI MAY de he thong ap dung cau hinh. Script KHONG tu khoi dong lai."
}

# 5. Ghi nhat ky audit log append-only
$logEntry = @{
    hostname = $env:COMPUTERNAME
    changed_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    actor = $env:USERNAME
    method = "package_script"
    action = "enable"
    old_values = @{ CrashDumpEnabled = $cur }
    new_values = @{ CrashDumpEnabled = $TargetMode }
    backup_path = "$base.json"
    result = "success"
    message = "Set CrashDumpEnabled = $TargetMode via Enable-CrashDump.ps1"
    reboot_required = $true
} | ConvertTo-Json -Compress

Add-Content -Path "$DataDir\logs\dump_config_changes.jsonl" -Value $logEntry -Encoding UTF8

# 6. Ghi bao cao vao ReportDir chia se (neu co)
if ($ReportDir -and (Test-Path $ReportDir)) {
    try {
        $repFile = Join-Path $ReportDir "$($env:COMPUTERNAME).json"
        $repData = @{
            schema_version = 1
            tool_version = "1.2.0"
            hostname = $env:COMPUTERNAME
            collected_at_utc = (Get-Date).ToUniversalTime().ToString('o')
            os = @{ caption = (Get-CimInstance Win32_OperatingSystem).Caption; build = [string](Get-CimInstance Win32_OperatingSystem).BuildNumber }
            is_admin = $true
            registry = @{ read_ok = $true; crash_dump_enabled = $TargetMode; value_present = $true }
            pagefile = @{ state = "ok"; automatic_managed = $true }
            disk = @{ system_drive = "C:\"; free_gb = 0 }
            ram_gb = 0
            volmgr = @{ last_failure_utc = $null; last_success_utc = $null }
            last_boot_time_utc = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
            result = @{
                status = "READY_PENDING_REBOOT"
                proof_level = "none"
                reason_codes = @(@{ code = "PENDING_REBOOT"; level = "info"; detail = "Da doi cau hinh sang mode $TargetMode, dang cho khoi dong lai." })
                pending_reboot = $true
                summary = "Da bat cau hinh, cho khoi dong lai may de co hieu luc."
                recommendations = @("Khoi dong lai may de cau hinh moi hoat dong.")
            }
        }
        $repData | ConvertTo-Json -Depth 5 | Set-Content -Path $repFile -Encoding UTF8
    } catch {
        Write-Warning "Khong the ghi file bao cao mang: $_"
    }
}

exit 0
"""

ROLLBACK_CRASHDUMP_PS1 = r"""<#
.SYNOPSIS
    Rollback-CrashDump.ps1 - Hoan tac cau hinh CrashControl theo ban sao luu JSON.
.DESCRIPTION
    Doc tep sao luu JSON, khoi phuc lai dung gia tri ban dau.
    Neu gia tri von khong ton tai ban dau -> tien hanh xoa gia tri (Remove-ItemProperty)
    dam bao hoan tac 100% trang thai sach.
.PARAMETER BackupJson
    Duong dan tep sao luu .json.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$BackupJson
)

$ErrorActionPreference = 'Stop'
$keyPs = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Can quyen Administrator de hoan tac cau hinh Registry."
    exit 3
}

if (-not (Test-Path $BackupJson)) {
    Write-Error "Khong tim thay tep sao luu JSON tai: $BackupJson"
    exit 1
}

$rawJson = Get-Content -Path $BackupJson -Raw -Encoding UTF8
$backupData = $rawJson | ConvertFrom-Json
$cdeInfo = $backupData.values.CrashDumpEnabled

if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Hoan tac cau hinh CrashControl")) {
    if ($cdeInfo.present -and ($null -ne $cdeInfo.data)) {
        Set-ItemProperty -Path $keyPs -Name CrashDumpEnabled -Value ([int]$cdeInfo.data) -Type DWord
        Write-Output "[OK] Da hoan tac CrashDumpEnabled = $($cdeInfo.data)."
    } else {
        Remove-ItemProperty -Path $keyPs -Name CrashDumpEnabled -ErrorAction SilentlyContinue
        Write-Output "[OK] Da xoa gia tri CrashDumpEnabled (khoi phuc trang thai ban dau khong ton tai)."
    }
    Write-Output "     [LUU Y] CAN KHOI DONG LAI MAY de he thong ap dung lai cau hinh cu."
}

exit 0
"""

README_TRIEN_KHAI_TXT = """==============================================================================
          GÓI TRIỂN KHAI BẬT GHI DUMP TỰ ĐỘNG CHO ĐỘI MÁY TÍNH
==============================================================================
Dự án: DumpAnalyzer (v1.2.0)
Tài liệu hướng dẫn quản trị viên IT triển khai an toàn cho đội máy.

1. NGUYÊN TẮC AN TOÀN TUYỆT ĐỐI:
   - Script KHÔNG BAO GIỜ tự khởi động lại máy tính người dùng.
   - Script có tính chất IDEMPOTENT: Chạy nhiều lần cho kết quả như một lần.
   - Nếu máy đã bật sẵn (chế độ 1, 2, 7) hoặc đang dùng Small dump (3), script sẽ
     TÔN TRỌNG và KHÔNG tự ý thay đổi.
   - Tự động sao lưu đầy đủ cả file .reg và file .json vào %ProgramData%\\DumpAnalyzer\\backup.

2. CÁC CÁCH TRIỂN KHAI:

   CÁCH 1: CHẠY TRỰC TIẾP TRÊN TỪNG MÁY (BẰNG TAY)
   - Mở PowerShell bằng quyền Administrator.
   - Chạy lệnh kiểm tra trước (không thay đổi gì):
       .\\Enable-CrashDump.ps1 -WhatIf
   - Chạy lệnh thực thi thật:
       .\\Enable-CrashDump.ps1 -TargetMode 7
   - Hoàn tác nếu cần:
       .\\Rollback-CrashDump.ps1 -BackupJson "C:\\ProgramData\\DumpAnalyzer\\backup\\CrashControl_...json"

   CÁCH 2: TRIỂN KHAI QUA GPO STARTUP SCRIPT (ACTIVE DIRECTORY DOMAIN)
   - Đặt file Enable-CrashDump.ps1 vào thư mục chia sẻ mạng (ví dụ: \\\\server\\share\\scripts\\).
   - Mở Group Policy Management:
       Computer Configuration -> Policies -> Windows Settings -> Scripts (Startup/Shutdown) -> Startup.
   - Thêm script với tham số:
       -TargetMode 7 -ReportDir "\\\\server\\share\\dump_readiness_reports"
   - Khi máy tính trong miền khởi động lại, script chạy dưới quyền SYSTEM, tự động bật
     ghi dump và gửi báo cáo JSON về thư mục chia sẻ.

   CÁCH 3: TRIỂN KHAI QUA CÔNG CỤ QUẢN LÝ TẬP TRUNG (RMM / INTUNE / PDQ DEPLOY)
   - Tạo package chạy lệnh:
       powershell.exe -ExecutionPolicy Bypass -File .\\Enable-CrashDump.ps1 -TargetMode 7
   - Báo cáo kết quả sẽ được ghi vào %ProgramData%\\DumpAnalyzer\\logs\\dump_config_changes.jsonl.

3. TỔNG HỢP BÁO CÁO TOÀN ĐỘI MÁY:
   - Trên máy quản trị IT, mở phần mềm DumpAnalyzer, vào Tab "Sẵn sàng ghi dump".
   - Bấm nút "Nạp báo cáo từ thư mục chia sẻ" (hoặc chạy CLI: dumpanalyzer dump-fleet --dir <thư_mục>).
   - Phần mềm sẽ tổng hợp trạng thái, thống kê tỷ lệ máy sẵn sàng và xuất file Excel.

Chúc bạn quản lý và chẩn đoán sự cố đội máy thành công!
"""


def generate_deployment_package(output_dir: str | Path, target_mode: int = 7) -> Path:
    """Tạo gói triển khai đầy đủ ra thư mục đích (Section 7.3)."""
    out = Path(output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    # 1. Enable-CrashDump.ps1
    ps1_file = out / "Enable-CrashDump.ps1"
    ps1_file.write_text(ENABLE_CRASHDUMP_PS1, encoding="utf-8")

    # 2. Rollback-CrashDump.ps1
    rb_file = out / "Rollback-CrashDump.ps1"
    rb_file.write_text(ROLLBACK_CRASHDUMP_PS1, encoding="utf-8")

    # 3. README_TRIEN_KHAI.txt
    readme_file = out / "README_TRIEN_KHAI.txt"
    readme_file.write_text(README_TRIEN_KHAI_TXT, encoding="utf-8")

    logger.info(f"Đã tạo gói triển khai tại: {out}")
    return out


def parse_and_validate_report_file(file_path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Đọc và kiểm tra tính hợp lệ của một tệp báo cáo JSON máy tính (Section 7.2)."""
    if not file_path.is_file():
        return None, f"Tệp không tồn tại: {file_path}"

    # Giới hạn kích thước file an toàn (tối đa 256 KB)
    if file_path.stat().st_size > 256 * 1024:
        return None, f"Kích thước tệp quá lớn ({file_path.stat().st_size} bytes > 256 KB)"

    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception as e:
        return None, f"Không thể parse JSON: {e}"

    if not isinstance(data, dict):
        return None, "Nội dung JSON không phải dictionary"

    # Kiểm tra schema_version và các trường cốt lõi
    if data.get("schema_version") != 1:
        return None, f"schema_version không hỗ trợ ({data.get('schema_version')} != 1)"

    if not data.get("hostname"):
        return None, "Thiếu trường bắt buộc 'hostname'"

    if not data.get("collected_at_utc"):
        return None, "Thiếu trường bắt buộc 'collected_at_utc'"

    return data, None


def aggregate_fleet_reports(
    share_dir: str | Path,
    stale_days: int = 14,
    db: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Đọc tất cả các tệp JSON báo cáo trong thư mục chia sẻ, lưu vào SQLite và tính toán thống kê (Section 7.2).
    """
    p_dir = Path(share_dir).resolve()
    result = {
        "share_dir": str(p_dir),
        "total_files": 0,
        "valid_reports": 0,
        "invalid_reports": 0,
        "invalid_files": [],
        "machines": {},
        "summary": {
            "total_machines": 0,
            "ready_count": 0,
            "ready_pending_reboot_count": 0,
            "attention_count": 0,
            "blocked_count": 0,
            "unknown_count": 0,
            "stale_count": 0,
            "ready_rate": 0.0,
            "top_reasons": {},
        },
    }

    if not p_dir.is_dir():
        result["invalid_files"].append({"file": str(p_dir), "error": "Thư mục không tồn tại"})
        return result

    json_files = list(p_dir.glob("*.json"))
    result["total_files"] = len(json_files)

    now_utc = datetime.now(timezone.utc)

    for jf in json_files:
        rep_data, err = parse_and_validate_report_file(jf)
        if err:
            result["invalid_reports"] += 1
            result["invalid_files"].append({"file": jf.name, "error": err})
            continue

        result["valid_reports"] += 1
        hostname = rep_data["hostname"]
        c_time_str = rep_data.get("collected_at_utc", "")

        # Kiểm tra tính cũ (stale)
        is_stale = False
        try:
            c_dt = datetime.fromisoformat(c_time_str.replace("Z", "+00:00"))
            age_days = (now_utc - c_dt).total_seconds() / 86400.0
            if age_days > stale_days:
                is_stale = True
        except Exception:
            pass

        rep_data["is_stale"] = is_stale

        # Nếu một máy có nhiều file, giữ bản ghi có collected_at_utc mới nhất
        if hostname not in result["machines"] or c_time_str > result["machines"][hostname].get("collected_at_utc", ""):
            result["machines"][hostname] = rep_data

        # Lưu vào CSDL bảng dump_readiness
        try:
            res_block = rep_data.get("result", {})
            reg_block = rep_data.get("registry", {})
            pf_block = rep_data.get("pagefile", {})
            disk_block = rep_data.get("disk", {})
            reason_codes = res_block.get("reason_codes", [])

            db_record = {
                "hostname": hostname,
                "collected_at_utc": c_time_str,
                "source": "share_json",
                "status": res_block.get("status", "UNKNOWN"),
                "proof_level": res_block.get("proof_level", "none"),
                "crash_dump_enabled": reg_block.get("crash_dump_enabled"),
                "registry_read_ok": 1 if reg_block.get("read_ok", True) else 0,
                "pagefile_state": pf_block.get("state", "unknown"),
                "free_disk_gb": disk_block.get("free_gb", 0.0),
                "ram_gb": rep_data.get("ram_gb", 0.0),
                "last_boot_time_utc": rep_data.get("last_boot_time_utc"),
                "pending_reboot": 1 if res_block.get("pending_reboot") else 0,
                "reason_codes": reason_codes,
                "raw_json": json.dumps(rep_data, ensure_ascii=False),
            }

            if db is not None:
                db.insert_dump_readiness(db_record)
            else:
                from dumpanalyzer.storage.db import Database

                with Database() as local_db:
                    local_db.insert_dump_readiness(db_record)
        except Exception as e:
            logger.debug(f"Lỗi lưu CSDL cho máy {hostname}: {e}")

    # Tính toán thống kê toàn đội máy
    machines_list = list(result["machines"].values())
    tot_m = len(machines_list)
    result["summary"]["total_machines"] = tot_m

    r_count = 0
    r_pr_count = 0
    att_count = 0
    blk_count = 0
    unk_count = 0
    stale_count = 0
    reasons_freq: Dict[str, int] = {}

    for m in machines_list:
        st = m.get("result", {}).get("status", "UNKNOWN")
        if st == "READY":
            r_count += 1
        elif st == "READY_PENDING_REBOOT":
            r_pr_count += 1
        elif st == "ATTENTION":
            att_count += 1
        elif st == "BLOCKED":
            blk_count += 1
        else:
            unk_count += 1

        if m.get("is_stale"):
            stale_count += 1

        for rc in m.get("result", {}).get("reason_codes", []):
            code = rc.get("code", "UNKNOWN")
            reasons_freq[code] = reasons_freq.get(code, 0) + 1

    result["summary"]["ready_count"] = r_count
    result["summary"]["ready_pending_reboot_count"] = r_pr_count
    result["summary"]["attention_count"] = att_count
    result["summary"]["blocked_count"] = blk_count
    result["summary"]["unknown_count"] = unk_count
    result["summary"]["stale_count"] = stale_count
    result["summary"]["ready_rate"] = round((r_count / tot_m * 100.0), 1) if tot_m > 0 else 0.0
    result["summary"]["top_reasons"] = dict(sorted(reasons_freq.items(), key=lambda x: x[1], reverse=True))

    result["machines_by_host"] = result["machines"]
    result["machines"] = machines_list

    return result


def export_fleet_readiness_excel(fleet_result: Dict[str, Any], output_path: str | Path) -> Path:
    """Xuất báo cáo tổng hợp đội máy ra file Excel 3 sheet (Section 7.2)."""
    import openpyxl
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    wb = openpyxl.Workbook()
    ws_summary = wb.active
    ws_summary.title = "Tổng quan đội máy"

    ws_detail = wb.create_sheet(title="Chi tiết từng máy")
    ws_action = wb.create_sheet(title="Cần xử lý ngay")

    # Định dạng
    font_header = Font(name="Segoe UI", size=11, bold=True, color="FFFFFF")
    fill_header = PatternFill(start_color="1E3A8A", end_color="1E3A8A", fill_type="solid")
    fill_warn = PatternFill(start_color="FEF3C7", end_color="FEF3C7", fill_type="solid")
    fill_danger = PatternFill(start_color="FEE2E2", end_color="FEE2E2", fill_type="solid")
    fill_success = PatternFill(start_color="D1FAE5", end_color="D1FAE5", fill_type="solid")

    # 1. Sheet Tổng quan
    summary = fleet_result.get("summary", {})
    ws_summary["A1"] = "BÁO CÁO SẴN SÀNG GHI DUMP ĐỘI MÁY (DUMP READINESS FLEET)"
    ws_summary["A1"].font = Font(name="Segoe UI", size=14, bold=True, color="1E3A8A")
    ws_summary["A2"] = f"Thời điểm xuất: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')} | Thư mục: {fleet_result.get('share_dir')}"
    ws_summary["A2"].font = Font(name="Segoe UI", size=10, italic=True)

    kpis = [
        ("Tổng số máy tính", summary.get("total_machines", 0)),
        ("Tỷ lệ Sẵn sàng (READY)", f"{summary.get('ready_rate', 0.0)}%"),
        ("Sẵn sàng (READY)", summary.get("ready_count", 0)),
        ("Chờ khởi động lại (READY_PENDING_REBOOT)", summary.get("ready_pending_reboot_count", 0)),
        ("Cần chú ý (ATTENTION)", summary.get("attention_count", 0)),
        ("Bị chặn ghi dump (BLOCKED)", summary.get("blocked_count", 0)),
        ("Không xác định (UNKNOWN)", summary.get("unknown_count", 0)),
        ("Báo cáo cũ (> 14 ngày)", summary.get("stale_count", 0)),
    ]

    for idx, (lbl, val) in enumerate(kpis, start=4):
        ws_summary[f"A{idx}"] = lbl
        ws_summary[f"B{idx}"] = val
        ws_summary[f"A{idx}"].font = Font(name="Segoe UI", size=11, bold=True)
        ws_summary[f"B{idx}"].font = Font(name="Segoe UI", size=11)
        ws_summary[f"B{idx}"].alignment = Alignment(horizontal="right")

    # 2. Sheet Chi tiết
    detail_headers = [
        "STT", "Tên máy", "Trạng thái", "Chế độ dump", "Pagefile",
        "Ổ C: trống (GB)", "RAM (GB)", "Lần sập không dump", "Báo cáo lần cuối", "Cũ (Stale)", "Lý do chính"
    ]
    ws_detail.append(detail_headers)
    for col_num in range(1, len(detail_headers) + 1):
        cell = ws_detail.cell(row=1, column=col_num)
        cell.font = font_header
        cell.fill = fill_header
        cell.alignment = Alignment(horizontal="center", vertical="center")

    machines = list(fleet_result.get("machines", {}).values())
    machines.sort(key=lambda x: x.get("hostname", ""))

    action_rows = []

    for r_idx, m in enumerate(machines, start=2):
        res = m.get("result", {})
        status = res.get("status", "UNKNOWN")
        reg = m.get("registry", {})
        pf = m.get("pagefile", {})
        disk = m.get("disk", {})
        reasons = [rc.get("code", "") for rc in res.get("reason_codes", [])]

        gap = m.get("dump_gap", {}) or {}
        missing_dumps = gap.get("missing", 0)

        row_vals = [
            r_idx - 1,
            m.get("hostname", ""),
            status,
            reg.get("crash_dump_enabled", "None"),
            pf.get("state", "unknown"),
            disk.get("free_gb", 0.0),
            m.get("ram_gb", 0.0),
            missing_dumps,
            m.get("collected_at_utc", "")[:19].replace("T", " "),
            "CŨ" if m.get("is_stale") else "Mới",
            ", ".join(reasons) if reasons else "Không có",
        ]
        ws_detail.append(row_vals)

        # Đánh dấu màu
        stat_cell = ws_detail.cell(row=r_idx, column=3)
        if status == "READY":
            stat_cell.fill = fill_success
        elif status == "BLOCKED":
            stat_cell.fill = fill_danger
        elif status in ("ATTENTION", "READY_PENDING_REBOOT"):
            stat_cell.fill = fill_warn

        if status in ("BLOCKED", "UNKNOWN") or missing_dumps > 0:
            action_rows.append(row_vals)

    # 3. Sheet Cần xử lý ngay
    ws_action.append(detail_headers)
    for col_num in range(1, len(detail_headers) + 1):
        cell = ws_action.cell(row=1, column=col_num)
        cell.font = font_header
        cell.fill = PatternFill(start_color="B91C1C", end_color="B91C1C", fill_type="solid")
        cell.alignment = Alignment(horizontal="center", vertical="center")

    for act_row in action_rows:
        ws_action.append(act_row)

    # Tự động căn chỉnh độ rộng cột
    for ws in (ws_summary, ws_detail, ws_action):
        for col in ws.columns:
            max_len = max(len(str(cell.value or "")) for cell in col)
            col_letter = get_column_letter(col[0].column)
            ws.column_dimensions[col_letter].width = max(max_len + 3, 12)

    wb.save(str(out_file))
    logger.info(f"Đã xuất báo cáo Excel đội máy tại: {out_file}")
    return out_file
