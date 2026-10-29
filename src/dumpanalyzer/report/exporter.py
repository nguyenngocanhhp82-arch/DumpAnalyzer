"""Module xuất báo cáo chẩn đoán sự cố hệ thống định dạng HTML và Excel.

Hỗ trợ kỹ thuật viên IT xuất file báo cáo chuyên nghiệp để lưu trữ hoặc gửi khách hàng/cấp trên.
Bao gồm đầy đủ kết luận, xếp hạng nghi vấn, các bước xử lý từ dễ đến khó và bằng chứng liên đới.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import openpyxl
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from dumpanalyzer.core.models import Crash, Evidence, Finding, MachineInfo
from dumpanalyzer.core.timeutil import utc_to_local_str


def export_html_report(
    output_path: str | Path,
    crashes: List[Crash],
    finding: Optional[Finding] = None,
    machine_info: Optional[MachineInfo] = None,
    evidences: Optional[List[Evidence]] = None,
    suspect_ranking: Optional[List[Dict[str, Any]]] = None,
) -> Path:
    """Xuất báo cáo định dạng HTML độc lập (standalone), có CSS nhúng đẹp mắt.

    Args:
        output_path: Đường dẫn file HTML cần xuất.
        crashes: Danh sách các phiên crash đã phân tích.
        finding: Kết luận chẩn đoán tổng hợp hoặc đơn lẻ.
        machine_info: Thông tin máy tính (nếu có).
        evidences: Danh sách bằng chứng (nếu có).
        suspect_ranking: Danh sách xếp hạng nghi vấn (nếu có riêng).

    Returns:
        Path của file HTML đã ghi.
    """
    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    generated_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    hostname = machine_info.hostname if machine_info else "Máy cục bộ"
    os_info = f"Windows (Build {machine_info.os_build})" if machine_info and machine_info.os_build else getattr(machine_info, "os_name", "Windows")
    cpu_info = machine_info.cpu if machine_info and machine_info.cpu else "Chưa rõ"
    ram_info = f"{getattr(machine_info, 'ram_total_gb', 0):.1f} GB" if machine_info and hasattr(machine_info, "ram_total_gb") and getattr(machine_info, "ram_total_gb") else getattr(machine_info, "model", "Chưa rõ")
    bios_info = getattr(machine_info, "bios", getattr(machine_info, "bios_version", "Chưa rõ")) if machine_info else "Chưa rõ"

    # Xếp hạng nghi vấn
    suspect_ranks: List[Dict[str, Any]] = []
    top_suspect = "Chưa xác định"
    confidence = "Không đủ dữ kiện"
    rationale = "Chưa có đủ dữ liệu để đưa ra kết luận chẩn đoán."
    next_steps: List[str] = []

    if suspect_ranking:
        for s in suspect_ranking:
            label = s.get("label", s.get("suspect", "Khác"))
            pct = float(s.get("percentage", s.get("score", 0.0)))
            suspect_ranks.append({"label": label, "percentage": pct})
    elif finding and hasattr(finding, "suspect_ranking") and getattr(finding, "suspect_ranking"):
        for s in finding.suspect_ranking:
            label = s.get("label", s.get("suspect", "Khác"))
            pct = float(s.get("percentage", 0.0))
            suspect_ranks.append({"label": label, "percentage": pct})
    elif finding:
        suspect_ranks.append({"label": finding.suspect, "percentage": finding.score})

    if finding:
        confidence = finding.confidence
        rationale = finding.rationale
        next_steps = finding.next_steps or []

    if suspect_ranks:
        top_suspect = f"{suspect_ranks[0]['label']} ({suspect_ranks[0]['percentage']:.1f}%)"

    # Màu huy hiệu độ tin cậy
    conf_class = "badge-low"
    if confidence == "cao":
        conf_class = "badge-high"
    elif confidence == "trung bình":
        conf_class = "badge-med"

    # Phân loại độ khó cho các bước kiểm tra
    def get_tier_badge(step: str) -> str:
        s_lower = step.lower()
        if any(k in s_lower for k in ["nhiệt độ", "nóng", "quạt", "driver verifier", "khởi động sạch", "cấu hình dump", "tắt verifier"]):
            return '<span class="tier-tag tier-1">TẦNG 1: DỄ</span>'
        elif any(k in s_lower for k in ["ddu", "cập nhật driver", "cài lại driver", "sfc", "chkdsk", "sửa lỗi tệp", "diệt virus", "antivirus"]):
            return '<span class="tier-tag tier-2">TẦNG 2: TRUNG BÌNH</span>'
        elif any(k in s_lower for k in ["memtest", "kiểm tra ram", "smart", "cáp", "tháo", "ổ cứng", "ssd", "nvme"]):
            return '<span class="tier-tag tier-3">TẦNG 3: NÂNG CAO</span>'
        elif any(k in s_lower for k in ["cập nhật bios", "bios", "nguồn", "psu", "thay", "bo mạch chủ", "mainboard"]):
            return '<span class="tier-tag tier-4">TẦNG 4: PHỨC TẠP</span>'
        return '<span class="tier-tag tier-2">KHUYẾN NGHỊ</span>'

    # Xây dựng các hàng bảng crash
    crash_rows_html = []
    for idx, c in enumerate(crashes, start=1):
        t_val = getattr(c, "crash_time_utc", getattr(c, "crash_time", None))
        time_local = utc_to_local_str(t_val) if t_val else "Không xác định"
        code_hex = getattr(c, "bugcheck_code", "N/A") or "N/A"
        name = getattr(c, "bugcheck_name", "Chưa rõ") or "Chưa rõ"
        module = getattr(c, "image_name", getattr(c, "module_name", getattr(c, "culprit_module", "-"))) or "-"
        suspect = getattr(c, "suspect_hardware", "-") or "-"

        method_badge = ""
        analyzed = getattr(c, "analyzed_by", "none")
        if analyzed == "log_only":
            method_badge = '<span class="badge-tag tag-logonly">Không có dump (log_only)</span>'
        elif analyzed == "header_only":
            method_badge = '<span class="badge-tag tag-header">Header-only</span>'
        else:
            method_badge = '<span class="badge-tag tag-cdb">WinDbg CDB</span>'

        row = f"""
        <tr>
            <td style="text-align: center;">{idx}</td>
            <td><strong>{time_local}</strong></td>
            <td><code>{code_hex}</code></td>
            <td>{name}</td>
            <td><code>{module}</code></td>
            <td>{suspect}</td>
            <td style="text-align: center;">{method_badge}</td>
        </tr>
        """
        crash_rows_html.append(row)

    # Xây dựng các hàng bằng chứng
    evidence_rows_html = []
    if evidences:
        for idx, ev in enumerate(evidences, start=1):
            t_str = getattr(ev, "time_utc", getattr(ev, "timestamp", ""))
            ev_time = utc_to_local_str(t_str) if t_str else "-"
            ev_type = getattr(ev, "kind", getattr(ev, "evidence_type", "eventlog"))
            ev_source = getattr(ev, "source", "")
            ev_detail = getattr(ev, "detail", getattr(ev, "details", getattr(ev, "summary", "-")))
            ev_weight = getattr(ev, "weight", 10)
            ev_type_badge = f'<span class="badge-tag tag-header">{ev_type}</span>'
            row = f"""
            <tr>
                <td style="text-align: center;">{idx}</td>
                <td>{ev_time}</td>
                <td>{ev_type_badge}</td>
                <td><strong>{ev_source}</strong></td>
                <td>{ev_detail}</td>
                <td style="text-align: center;"><code>+{ev_weight}</code></td>
            </tr>
            """
            evidence_rows_html.append(row)

    html_content = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Báo cáo Phân tích Dump & Sự cố - {hostname}</title>
    <style>
        :root {{
            --bg: #f8fafc;
            --surface: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --primary: #2563eb;
            --primary-light: #eff6ff;
            --success: #16a34a;
            --warning: #d97706;
            --danger: #dc2626;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            margin: 0;
            padding: 30px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            color: #ffffff;
            padding: 32px;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            margin-bottom: 24px;
        }}
        .header h1 {{
            margin: 0 0 8px 0;
            font-size: 26px;
            letter-spacing: -0.5px;
        }}
        .header p {{
            margin: 0;
            color: #94a3b8;
            font-size: 14px;
        }}
        .grid-2 {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 24px;
        }}
        .card {{
            background: var(--surface);
            border-radius: 10px;
            border: 1px solid var(--border);
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .card h2 {{
            margin-top: 0;
            font-size: 18px;
            color: #1e293b;
            border-bottom: 2px solid var(--border);
            padding-bottom: 12px;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .meta-list {{
            list-style: none;
            padding: 0;
            margin: 0;
        }}
        .meta-list li {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px dashed var(--border);
            font-size: 14px;
        }}
        .meta-list li span.label {{
            color: var(--text-muted);
            font-weight: 500;
        }}
        .meta-list li span.val {{
            font-weight: 600;
        }}
        .badge-high {{
            background: #dcfce7;
            color: #15803d;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-med {{
            background: #fef3c7;
            color: #b45309;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-low {{
            background: #fee2e2;
            color: #b91c1c;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .progress-item {{
            margin-bottom: 14px;
        }}
        .progress-header {{
            display: flex;
            justify-content: space-between;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 4px;
        }}
        .progress-bar-bg {{
            background-color: #e2e8f0;
            height: 10px;
            border-radius: 5px;
            overflow: hidden;
        }}
        .progress-bar-fill {{
            background: linear-gradient(90deg, #3b82f6, #1d4ed8);
            height: 100%;
            border-radius: 5px;
        }}
        .rationale-box {{
            background: #f1f5f9;
            border-left: 4px solid var(--primary);
            padding: 16px;
            border-radius: 6px;
            font-size: 14px;
            line-height: 1.6;
            margin-bottom: 20px;
        }}
        .step-item {{
            display: flex;
            align-items: flex-start;
            margin-bottom: 12px;
            padding-bottom: 10px;
            border-bottom: 1px solid #f1f5f9;
            font-size: 14px;
        }}
        .tier-tag {{
            font-size: 10px;
            font-weight: 700;
            padding: 3px 6px;
            border-radius: 4px;
            margin-right: 12px;
            white-space: nowrap;
        }}
        .tier-1 {{ background: #dbeafe; color: #1e40af; }}
        .tier-2 {{ background: #fef3c7; color: #92400e; }}
        .tier-3 {{ background: #ffedd5; color: #9a3412; }}
        .tier-4 {{ background: #fee2e2; color: #991b1b; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-top: 10px;
        }}
        th, td {{
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
            text-align: left;
        }}
        th {{
            background-color: #f8fafc;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
        }}
        tr:hover td {{
            background-color: #f8fafc;
        }}
        .badge-tag {{
            font-size: 11px;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 600;
        }}
        .tag-logonly {{ background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }}
        .tag-header {{ background: #f0fdf4; color: #15803d; border: 1px solid #bbf7d0; }}
        .tag-cdb {{ background: #eff6ff; color: #1d4ed8; border: 1px solid #bfdbfe; }}
        .disclaimer {{
            font-size: 12px;
            color: var(--text-muted);
            text-align: center;
            margin-top: 32px;
            padding-top: 16px;
            border-top: 1px solid var(--border);
        }}
        @media print {{
            body {{ background: #ffffff; padding: 0; }}
            .card {{ box-shadow: none; border: 1px solid #cbd5e1; }}
            .header {{ background: #0f172a !important; -webkit-print-color-adjust: exact; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- HEADER -->
        <div class="header">
            <h1>DumpAnalyzer – Báo cáo Chẩn đoán Sự cố Hệ thống</h1>
            <p>Thời điểm xuất báo cáo: <strong>{generated_time}</strong> | Hệ thống: <strong>{hostname}</strong></p>
        </div>

        <!-- KPI GRID -->
        <div class="grid-2">
            <!-- CỘT 1: THÔNG TIN MÁY & KẾT LUẬN CHÍNH -->
            <div class="card">
                <h2>
                    <span>Tổng quan Thiết bị</span>
                    <span class="{conf_class}">Độ tin cậy: {confidence}</span>
                </h2>
                <ul class="meta-list">
                    <li><span class="label">Tên máy (Hostname):</span><span class="val">{hostname}</span></li>
                    <li><span class="label">Hệ điều hành:</span><span class="val">{os_info}</span></li>
                    <li><span class="label">Bộ xử lý (CPU):</span><span class="val">{cpu_info}</span></li>
                    <li><span class="label">Bộ nhớ RAM:</span><span class="val">{ram_info}</span></li>
                    <li><span class="label">Phiên bản BIOS:</span><span class="val">{bios_info}</span></li>
                    <li><span class="label">Tổng số lần sập:</span><span class="val">{len(crashes)} sự cố</span></li>
                    <li><span class="label">Nguyên nhân hàng đầu:</span><span class="val" style="color: var(--primary);">{top_suspect}</span></li>
                </ul>
            </div>

            <!-- CỘT 2: XẾP HẠNG NGUYÊN NHÂN -->
            <div class="card">
                <h2>Xếp hạng Xác suất Nghi vấn</h2>
                <div>
                    {"".join(f'''
                    <div class="progress-item">
                        <div class="progress-header">
                            <span>{s["label"]}</span>
                            <span>{s["percentage"]:.1f}%</span>
                        </div>
                        <div class="progress-bar-bg">
                            <div class="progress-bar-fill" style="width: {min(100.0, s["percentage"])}%;"></div>
                        </div>
                    </div>
                    ''' for s in suspect_ranks) if suspect_ranks else '<p style="color: var(--text-muted);">Chưa có xếp hạng nguyên nhân.</p>'}
                </div>
            </div>
        </div>

        <!-- KHUNG KẾT LUẬN & HÀNH ĐỘNG -->
        <div class="grid-2">
            <!-- RATIONALE -->
            <div class="card">
                <h2>Giải thích Nguyên nhân (Rationale)</h2>
                <div class="rationale-box">
                    {rationale}
                </div>
            </div>

            <!-- NEXT STEPS -->
            <div class="card">
                <h2>Khuyến nghị Xử lý (Từ Dễ đến Khó)</h2>
                <div>
                    {"".join(f'''
                    <div class="step-item">
                        {get_tier_badge(st)}
                        <div>{st}</div>
                    </div>
                    ''' for st in next_steps) if next_steps else '<p style="color: var(--text-muted);">Không có khuyến nghị nào.</p>'}
                </div>
            </div>
        </div>

        <!-- BẢNG DANH SÁCH CRASH -->
        <div class="card" style="margin-bottom: 24px;">
            <h2>Danh sách các Lần sập Máy (Crash Events)</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 40px; text-align: center;">STT</th>
                        <th>Thời điểm (Giờ địa phương)</th>
                        <th>Mã lỗi</th>
                        <th>Tên lỗi chuẩn Microsoft</th>
                        <th>Module/Driver</th>
                        <th>Nhóm nghi ngờ</th>
                        <th style="text-align: center;">Phương thức</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(crash_rows_html) if crash_rows_html else '<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">Không có dữ liệu sập máy.</td></tr>'}
                </tbody>
            </table>
        </div>

        <!-- BẢNG BẰNG CHỨNG (NẾU CÓ) -->
        {f'''
        <div class="card" style="margin-bottom: 24px;">
            <h2>Bằng chứng Đối chiếu Thu thập được ({len(evidences)} bằng chứng)</h2>
            <table>
                <thead>
                    <tr>
                        <th style="width: 40px; text-align: center;">STT</th>
                        <th>Thời điểm</th>
                        <th>Loại bằng chứng</th>
                        <th>Nguồn dữ liệu</th>
                        <th>Chi tiết bằng chứng</th>
                        <th style="text-align: center;">Trọng số</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(evidence_rows_html)}
                </tbody>
            </table>
        </div>
        ''' if evidences else ''}

        <!-- DISCLAIMER -->
        <div class="disclaimer">
            <p><strong>Lưu ý kỹ thuật:</strong> Báo cáo được tự động tạo bởi DumpAnalyzer dựa trên các thuật toán khoanh vùng xác suất và quy tắc chuyên gia. Kết luận mang tính định hướng điều tra, không phải là kết luận sửa chữa tuyệt đối. Luôn sao lưu dữ liệu quan trọng trước khi can thiệp phần cứng hoặc cài đặt lại hệ điều hành.</p>
        </div>
    </div>
</body>
</html>
"""
    out_file.write_text(html_content, encoding="utf-8")
    return out_file


def export_excel_report(
    output_path: str | Path,
    crashes: List[Crash],
    finding: Optional[Finding] = None,
    machine_info: Optional[MachineInfo] = None,
    evidences: Optional[List[Evidence]] = None,
    suspect_ranking: Optional[List[Dict[str, Any]]] = None,
) -> Path:
    """Xuất báo cáo định dạng Microsoft Excel (.xlsx) với nhiều sheet trình bày rõ ràng.

    Sheet 1: Tổng quan & Kết luận
    Sheet 2: Danh sách lần sập (Crashes)
    Sheet 3: Bằng chứng (Evidences)

    Args:
        output_path: Đường dẫn file .xlsx cần xuất.
        crashes: Danh sách crash.
        finding: Kết luận finding.
        machine_info: Thông tin máy tính.
        evidences: Danh sách bằng chứng.
        suspect_ranking: Danh sách xếp hạng xác suất nghi vấn.

    Returns:
        Path của file .xlsx đã ghi.
    """
    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    wb = openpyxl.Workbook()

    # Style dùng chung
    font_header = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    fill_header = PatternFill(start_color="1F497D", end_color="1F497D", fill_type="solid")
    font_title = Font(name="Calibri", size=14, bold=True, color="1F497D")
    font_bold = Font(name="Calibri", size=11, bold=True)
    font_regular = Font(name="Calibri", size=11)
    align_center = Alignment(horizontal="center", vertical="center")
    align_left = Alignment(horizontal="left", vertical="center")
    border_thin = Border(
        left=Side(style="thin", color="D9D9D9"),
        right=Side(style="thin", color="D9D9D9"),
        top=Side(style="thin", color="D9D9D9"),
        bottom=Side(style="thin", color="D9D9D9"),
    )

    # -------------------------------------------------------------
    # SHEET 1: Tổng quan & Kết luận
    # -------------------------------------------------------------
    ws1 = wb.active
    ws1.title = "Tổng quan & Kết luận"
    ws1.views.sheetView[0].showGridLines = True

    # Title
    ws1["A1"] = "BÁO CÁO PHÂN TÍCH SỰ CỐ HỆ THỐNG - DUMPANALYZER"
    ws1["A1"].font = font_title
    ws1["A2"] = f"Ngày xuất báo cáo: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"
    ws1["A2"].font = font_regular

    # Thông tin máy
    row = 4
    ws1.cell(row=row, column=1, value="THÔNG TIN THIẾT BỊ").font = font_bold
    row += 1
    meta = [
        ("Tên máy (Hostname)", machine_info.hostname if machine_info else "Máy cục bộ"),
        ("Hệ điều hành", f"Windows (Build {machine_info.os_build})" if machine_info and machine_info.os_build else getattr(machine_info, "os_name", "Windows")),
        ("Bộ xử lý (CPU)", machine_info.cpu if machine_info and machine_info.cpu else "Chưa rõ"),
        ("Bộ nhớ RAM", f"{getattr(machine_info, 'ram_total_gb', 0):.1f} GB" if machine_info and hasattr(machine_info, "ram_total_gb") and getattr(machine_info, "ram_total_gb") else getattr(machine_info, "model", "Chưa rõ")),
        ("Phiên bản BIOS", getattr(machine_info, "bios", getattr(machine_info, "bios_version", "Chưa rõ")) if machine_info else "Chưa rõ"),
        ("Tổng số lần sập phân tích", f"{len(crashes)} sự cố"),
    ]
    for label, val in meta:
        ws1.cell(row=row, column=1, value=label).font = font_regular
        ws1.cell(row=row, column=2, value=val).font = font_bold
        row += 1

    row += 1
    # Kết luận chính
    ws1.cell(row=row, column=1, value="KẾT LUẬN CHẨN ĐOÁN").font = font_bold
    row += 1

    ranks: List[Dict[str, Any]] = []
    if suspect_ranking:
        ranks = suspect_ranking
    elif finding and hasattr(finding, "suspect_ranking") and getattr(finding, "suspect_ranking"):
        ranks = getattr(finding, "suspect_ranking")
    elif finding:
        ranks = [{"label": finding.suspect, "percentage": finding.score}]

    if finding:
        ws1.cell(row=row, column=1, value="Mức độ tin cậy:").font = font_regular
        ws1.cell(row=row, column=2, value=finding.confidence.upper()).font = font_bold
        row += 1

        top_s = ranks[0] if ranks else {}
        top_name = top_s.get("label", top_s.get("suspect", "Chưa rõ"))
        top_pct = float(top_s.get("percentage", top_s.get("score", 0.0)))
        ws1.cell(row=row, column=1, value="Nguyên nhân hàng đầu:").font = font_regular
        ws1.cell(row=row, column=2, value=f"{top_name} ({top_pct:.1f}%)").font = font_bold
        row += 1

        ws1.cell(row=row, column=1, value="Giải thích (Rationale):").font = font_regular
        cell_rat = ws1.cell(row=row, column=2, value=finding.rationale)
        cell_rat.font = font_regular
        cell_rat.alignment = Alignment(wrap_text=True)
        row += 2

        # Bảng xếp hạng nghi vấn
        ws1.cell(row=row, column=1, value="XẾP HẠNG XÁC SUẤT NGHI VẤN").font = font_bold
        row += 1
        headers_rank = ["STT", "Nhóm nghi ngờ", "Tỷ lệ xác suất (%)"]
        for col_idx, h in enumerate(headers_rank, start=1):
            c = ws1.cell(row=row, column=col_idx, value=h)
            c.font = font_header
            c.fill = fill_header
            c.alignment = align_center
            c.border = border_thin
        row += 1
        for s_idx, s in enumerate(ranks, start=1):
            s_label = s.get("label", s.get("suspect", "Khác"))
            s_val = float(s.get("percentage", s.get("score", 0.0)))
            ws1.cell(row=row, column=1, value=s_idx).alignment = align_center
            ws1.cell(row=row, column=2, value=s_label)
            ws1.cell(row=row, column=3, value=round(s_val, 1)).alignment = align_center
            for c_idx in range(1, 4):
                ws1.cell(row=row, column=c_idx).border = border_thin
            row += 1

        row += 1
        # Các bước khuyến nghị
        ws1.cell(row=row, column=1, value="CÁC BƯỚC KHUYẾN NGHỊ KIỂM TRA (TỪ DỄ ĐẾN KHÓ)").font = font_bold
        row += 1
        for st_idx, st in enumerate(finding.next_steps or [], start=1):
            ws1.cell(row=row, column=1, value=f"{st_idx}.").alignment = align_center
            ws1.cell(row=row, column=2, value=st)
            row += 1

    # -------------------------------------------------------------
    # SHEET 2: Danh sách Crash
    # -------------------------------------------------------------
    ws2 = wb.create_sheet(title="Danh sách Crash")
    ws2.views.sheetView[0].showGridLines = True

    crash_headers = [
        "STT",
        "Thời điểm (Giờ địa phương)",
        "Mã lỗi",
        "Tên lỗi BugCheck",
        "Module/Driver",
        "Nhóm nghi ngờ",
        "Phương thức",
        "Đường dẫn file dump",
    ]
    for col_idx, h in enumerate(crash_headers, start=1):
        c = ws2.cell(row=1, column=col_idx, value=h)
        c.font = font_header
        c.fill = fill_header
        c.alignment = align_center
        c.border = border_thin

    for r_idx, c_obj in enumerate(crashes, start=2):
        t_val = getattr(c_obj, "crash_time_utc", getattr(c_obj, "crash_time", None))
        t_loc = utc_to_local_str(t_val) if t_val else "Không xác định"
        mod = getattr(c_obj, "image_name", getattr(c_obj, "module_name", getattr(c_obj, "culprit_module", "-"))) or "-"
        suspect = getattr(c_obj, "suspect_hardware", "-") or "-"
        ws2.cell(row=r_idx, column=1, value=r_idx - 1).alignment = align_center
        ws2.cell(row=r_idx, column=2, value=t_loc)
        ws2.cell(row=r_idx, column=3, value=getattr(c_obj, "bugcheck_code", "N/A") or "N/A").alignment = align_center
        ws2.cell(row=r_idx, column=4, value=getattr(c_obj, "bugcheck_name", "Chưa rõ") or "Chưa rõ")
        ws2.cell(row=r_idx, column=5, value=mod)
        ws2.cell(row=r_idx, column=6, value=suspect)
        ws2.cell(row=r_idx, column=7, value=getattr(c_obj, "analyzed_by", "none")).alignment = align_center
        ws2.cell(row=r_idx, column=8, value=c_obj.dump_path or "[Không có dump]")
        for c_col in range(1, 9):
            ws2.cell(row=r_idx, column=c_col).border = border_thin

    # -------------------------------------------------------------
    # SHEET 3: Bằng chứng (Evidences)
    # -------------------------------------------------------------
    if evidences:
        ws3 = wb.create_sheet(title="Bằng chứng thu thập")
        ws3.views.sheetView[0].showGridLines = True
        ev_headers = ["STT", "Thời điểm", "Loại bằng chứng", "Nguồn", "Chi tiết bằng chứng", "Trọng số"]
        for col_idx, h in enumerate(ev_headers, start=1):
            c = ws3.cell(row=1, column=col_idx, value=h)
            c.font = font_header
            c.fill = fill_header
            c.alignment = align_center
            c.border = border_thin

        for r_idx, ev in enumerate(evidences, start=2):
            t_str = getattr(ev, "time_utc", getattr(ev, "timestamp", ""))
            t_loc = utc_to_local_str(t_str) if t_str else "-"
            ev_type = getattr(ev, "kind", getattr(ev, "evidence_type", "eventlog"))
            ev_source = getattr(ev, "source", "")
            ev_detail = getattr(ev, "detail", getattr(ev, "details", getattr(ev, "summary", "-")))
            ev_weight = getattr(ev, "weight", 10)

            ws3.cell(row=r_idx, column=1, value=r_idx - 1).alignment = align_center
            ws3.cell(row=r_idx, column=2, value=t_loc)
            ws3.cell(row=r_idx, column=3, value=ev_type).alignment = align_center
            ws3.cell(row=r_idx, column=4, value=ev_source)
            ws3.cell(row=r_idx, column=5, value=ev_detail)
            ws3.cell(row=r_idx, column=6, value=ev_weight).alignment = align_center
            for c_col in range(1, 7):
                ws3.cell(row=r_idx, column=c_col).border = border_thin

    # Tự động căn chỉnh độ rộng cột cho đẹp mắt
    for sheet in wb.worksheets:
        for col in sheet.columns:
            max_len = max(len(str(cell.value or "")) for cell in col)
            col_letter = get_column_letter(col[0].column)
            sheet.column_dimensions[col_letter].width = min(50, max(max_len + 3, 12))

    wb.save(str(out_file))
    return out_file
