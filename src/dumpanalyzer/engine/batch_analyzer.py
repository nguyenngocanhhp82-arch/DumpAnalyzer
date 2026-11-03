"""Module phân tích đa máy và nhận diện sự cố diện rộng (Batch Multi-Machine Analyzer).

Cho phép kỹ thuật viên IT quét thư mục chứa dump của nhiều máy (mỗi máy một thư mục con),
tổng hợp chẩn đoán cho từng máy, và phát hiện các driver/model gây lỗi hàng loạt trên quy mô công ty.
"""

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import openpyxl
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from dumpanalyzer.analyzer.cdb_runner import build_crash_from_dump
from dumpanalyzer.collectors.dump_finder import calculate_sha256, copy_dump_safely, find_dumps
from dumpanalyzer.core.config import get_settings_path, load_settings
from dumpanalyzer.core.models import Crash, MachineInfo, Evidence
from dumpanalyzer.core.timeutil import utc_to_local_str
from dumpanalyzer.engine.rule_loader import load_all_rules
from dumpanalyzer.engine.scorer import score_machine_crashes
from dumpanalyzer.engine.verdict import generate_machine_finding
from dumpanalyzer.storage.db import Database


def discover_machines_and_dumps(
    root_dir: str | Path,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
) -> Dict[str, List[Path]]:
    """Phát hiện các máy tính và danh sách file dump tương ứng trong thư mục gốc.

    Cấu trúc hỗ trợ:
    1. Thư mục con: mỗi thư mục con là tên một máy tính (ví dụ: `PC-KE-TOAN-01/*.dmp`).
    2. File dump trực tiếp: nếu thư mục gốc chứa file .dmp trực tiếp, gom vào máy "Máy đơn lẻ".

    Args:
        root_dir: Đường dẫn thư mục gốc.
        from_date: Lọc từ ngày (YYYY-MM-DD).
        to_date: Lọc đến ngày (YYYY-MM-DD).

    Returns:
        Từ điển { "Tên máy": [Danh sách Path file dump] }
    """
    root_path = Path(root_dir).resolve()
    if not root_path.exists() or not root_path.is_dir():
        return {}

    result: Dict[str, List[Path]] = {}

    # 1. Quét các thư mục con (mỗi thư mục con là 1 máy)
    for sub in sorted(root_path.iterdir()):
        if sub.is_dir() and not sub.name.startswith("."):
            found = find_dumps([str(sub)], from_date=from_date, to_date=to_date)
            if found:
                result[sub.name] = [item["path"] for item in found]

    # 2. Nếu thư mục gốc có file .dmp nằm ngoài cùng
    direct_found = find_dumps([str(root_path)], from_date=from_date, to_date=to_date)
    sub_dumps_set = {d.resolve() for d_list in result.values() for d in d_list}
    loose_dumps = [item["path"] for item in direct_found if item["path"].resolve() not in sub_dumps_set]
    if loose_dumps:
        result["Máy ngoại vi"] = loose_dumps

    return result


def analyze_fleet(
    machines_dumps: Dict[str, List[Path]],
    settings: Optional[Dict[str, Any]] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Phân tích toàn diện tất cả các máy trong danh sách.

    Returns:
        Từ điển chứa:
        - 'machines': Danh sách kết quả chi tiết từng máy
        - 'summary': Thống kê tổng hợp diện rộng (tỷ lệ lỗi, driver lỗi hàng loạt)
    """
    if settings is None:
        settings = load_settings(get_settings_path())

    rules = load_all_rules()
    workspace_dir = Path(settings.get("workspace_dir", "workspace"))
    workspace_dir.mkdir(parents=True, exist_ok=True)
    db = Database(db_path)

    machines_results: List[Dict[str, Any]] = []
    fleet_suspects: Counter = Counter()
    fleet_drivers: Counter = Counter()
    fleet_bugchecks: Counter = Counter()
    total_crashes_count = 0

    for machine_name, dump_files in machines_dumps.items():
        m_info = MachineInfo(
            hostname=machine_name,
            model="Phân tích hàng loạt đa máy",
            cpu="Chưa rõ",
            bios="Chưa rõ",
            os_build="Windows",
        )
        m_id = db.insert_machine(m_info)
        m_crashes: List[Crash] = []

        for d_path in dump_files:
            try:
                sha = calculate_sha256(d_path)
                copied_path = copy_dump_safely(d_path, workspace_dir, file_sha256=sha)
            except Exception:
                continue

            if not copied_path or not sha:
                continue

            cached = db.get_crash_by_sha256(sha)
            if cached:
                crash_obj = Crash(**cached)
                crash_obj.machine_id = m_id
                m_crashes.append(crash_obj)
            else:
                crash_obj = build_crash_from_dump(copied_path, settings=settings, machine_id=m_id, sha256=sha)
                c_id = db.insert_crash(crash_obj)
                crash_obj.id = c_id
                m_crashes.append(crash_obj)

            # Thống kê mã Bug Check
            if crash_obj.bugcheck_code:
                fleet_bugchecks[crash_obj.bugcheck_code] += 1

            # Thống kê driver bên thứ ba
            drv = crash_obj.image_name or crash_obj.module_name
            if drv and not drv.lower().endswith(".exe") and "ntoskrnl" not in drv.lower():
                fleet_drivers[drv.lower()] += 1

        # Truy vấn lịch sử các vụ sập trước đây của máy trong history_lookback_days (Phần 2.2)
        lookback_days = int(settings.get("history_lookback_days", 180))
        from datetime import timezone, timedelta
        from_date_iso = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).isoformat()
        historical_crashes_raw = db.get_crashes_by_machine(m_id, from_date=from_date_iso)

        combined_crashes_map: Dict[str, Crash] = {}
        for c in m_crashes:
            key = c.dump_sha256 or str(c.id) or c.dump_path or ""
            combined_crashes_map[key] = c
        for hc_dict in historical_crashes_raw:
            hc_obj = Crash(**hc_dict)
            key = hc_obj.dump_sha256 or str(hc_obj.id) or hc_obj.dump_path or ""
            if key not in combined_crashes_map:
                combined_crashes_map[key] = hc_obj

        all_machine_crashes = list(combined_crashes_map.values())
        total_crashes_count += len(all_machine_crashes)

        # Chấm điểm cho từng máy với toàn bộ crash trong khoảng lookback
        crash_tuples = []
        for c in all_machine_crashes:
            evs_raw = db.get_evidences_by_crash(c.id) if c.id else []
            evs_obj = [Evidence(**e) for e in evs_raw]
            crash_tuples.append((c, evs_obj))

        scored_result = score_machine_crashes(crash_tuples, rules, settings)
        top_suspect = scored_result.get("top_suspect", "unknown")
        top_score = scored_result.get("top_score", 0.0)
        confidence = scored_result.get("confidence", "thấp")
        suspect_ranking = scored_result.get("suspect_scores", [])

        finding = generate_machine_finding(
            machine_id=m_id,
            scored_result=scored_result,
            rules=rules,
        )
        setattr(finding, "suspect_ranking", suspect_ranking)
        db.insert_finding(finding)

        # Đếm nhóm nghi vấn trên quy mô máy
        fleet_suspects[top_suspect] += 1

        # Dòng thời gian crash của máy (Phần 2.2)
        timeline = []
        for c in sorted(all_machine_crashes, key=lambda x: x.crash_time_utc or "", reverse=True):
            timeline.append({
                "crash_time_utc": c.crash_time_utc,
                "bugcheck_code": c.bugcheck_code,
                "module_name": c.image_name or c.module_name or "unknown",
            })

        machines_results.append({
            "machine_name": machine_name,
            "machine_info": m_info,
            "crashes": all_machine_crashes,
            "finding": finding,
            "suspect_ranking": suspect_ranking,
            "top_suspect": top_suspect,
            "top_score": top_score,
            "confidence": confidence,
            "timeline": timeline,
        })

    db.close()


    # Nhận diện cảnh báo lỗi diện rộng (Fleet-wide warnings)
    fleet_warnings: List[str] = []
    num_machines = len(machines_results)

    # 1. Phát hiện driver lặp lại trên >= 2 máy khác nhau
    for drv_name, count in fleet_drivers.most_common(5):
        if count >= 2:
            fleet_warnings.append(
                f"Driver nghi vấn '{drv_name}' xuất hiện lặp lại trong {count} vụ sập trên các máy tính khác nhau. "
                f"Khả năng cao do bản cập nhật driver bị lỗi diện rộng hoặc xung đột phần mềm tương thích."
            )

    # 2. Phát hiện mã lỗi Bug Check áp đảo
    for bc_code, count in fleet_bugchecks.most_common(3):
        if count >= 3 and count >= (total_crashes_count * 0.4):
            fleet_warnings.append(
                f"Mã Bug Check {bc_code} chiếm đa số ({count}/{total_crashes_count} vụ sập, {count*100/max(1, total_crashes_count):.1f}%). "
                f"Kiểm tra lại cấu hình phần cứng hoặc cập nhật hệ điều hành đồng loạt."
            )

    summary = {
        "total_machines": num_machines,
        "total_crashes": total_crashes_count,
        "suspect_distribution": dict(fleet_suspects),
        "top_drivers": fleet_drivers.most_common(5),
        "top_bugchecks": fleet_bugchecks.most_common(5),
        "fleet_warnings": fleet_warnings,
    }

    return {
        "machines": machines_results,
        "summary": summary,
    }


def export_fleet_html_report(
    output_path: str | Path,
    fleet_data: Dict[str, Any],
) -> Path:
    """Xuất báo cáo tổng hợp phân tích đa máy định dạng HTML độc lập, có nhúng CSS hiện đại."""
    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    summary = fleet_data.get("summary", {})
    machines = fleet_data.get("machines", [])
    generated_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    # Bảng phân bổ nghi vấn
    suspect_rows_html = "".join(
        f"""
        <div style="margin-bottom: 10px;">
            <div style="display:flex; justify-content:space-between; font-size:13px; font-weight:600; margin-bottom:4px;">
                <span>{suspect.upper()}</span>
                <span>{count} máy</span>
            </div>
            <div style="background:#e2e8f0; height:8px; border-radius:4px; overflow:hidden;">
                <div style="background:#2563eb; height:100%; width:{count*100/max(1, summary.get('total_machines', 1))}%;"></div>
            </div>
        </div>
        """
        for suspect, count in summary.get("suspect_distribution", {}).items()
    )

    # Hàng danh sách các máy
    machine_rows_html = []
    for idx, m in enumerate(machines, start=1):
        f = m.get("finding")
        top_name = m.get("top_suspect", "Chưa rõ")
        score = m.get("top_score", 0.0)
        conf = m.get("confidence", "thấp")
        badge_color = "#15803d" if conf == "cao" else ("#b45309" if conf == "trung bình" else "#b91c1c")
        badge_bg = "#dcfce7" if conf == "cao" else ("#fef3c7" if conf == "trung bình" else "#fee2e2")

        crashes_count = len(m.get("crashes", []))
        first_step = f.next_steps[0] if (f and f.next_steps) else "-"

        row = f"""
        <tr>
            <td style="text-align: center;">{idx}</td>
            <td><strong>{m['machine_name']}</strong></td>
            <td style="text-align: center;">{crashes_count}</td>
            <td><strong>{top_name}</strong> ({score:.1f}%)</td>
            <td style="text-align: center;">
                <span style="background:{badge_bg}; color:{badge_color}; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:11px;">
                    {conf.upper()}
                </span>
            </td>
            <td style="font-size: 12px;">{first_step}</td>
        </tr>
        """
        machine_rows_html.append(row)

    # Cảnh báo diện rộng
    warnings_html = "".join(
        f'<div style="background:#fef3c7; border-left:4px solid #f59e0b; padding:12px; margin-bottom:10px; border-radius:4px; font-size:13px; color:#92400e;"><strong>⚠️ Cảnh báo:</strong> {w}</div>'
        for w in summary.get("fleet_warnings", [])
    ) if summary.get("fleet_warnings") else '<p style="color:#64748b; font-style:italic;">Không phát hiện bất thường diện rộng nào.</p>'

    html_content = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Báo cáo Phân tích Sự cố Đa máy - DumpAnalyzer</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f8fafc;
            color: #0f172a;
            padding: 30px;
            margin: 0;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, #1e293b, #0f172a);
            color: #ffffff;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 24px;
        }}
        .grid-3 {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 24px; }}
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px; }}
        .card {{
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        .kpi-title {{ font-size: 12px; font-weight: bold; color: #64748b; text-transform: uppercase; }}
        .kpi-val {{ font-size: 26px; font-weight: bold; color: #0f172a; margin-top: 6px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }}
        th, td {{ padding: 12px 14px; border-bottom: 1px solid #e2e8f0; text-align: left; }}
        th {{ background: #f8fafc; color: #64748b; font-size: 11px; text-transform: uppercase; }}
        tr:hover td {{ background: #f8fafc; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 style="margin:0 0 6px 0; font-size:24px;">DumpAnalyzer – Báo cáo Tổng hợp Sự cố Đa máy (Fleet Report)</h1>
            <p style="margin:0; color:#94a3b8; font-size:13px;">Thời điểm xuất: {generated_time} | Phạm vi: Toàn bộ thư mục đa máy</p>
        </div>

        <div class="grid-3">
            <div class="card">
                <div class="kpi-title">Tổng số máy tính</div>
                <div class="kpi-val">{summary.get('total_machines', 0)} máy</div>
            </div>
            <div class="card">
                <div class="kpi-title">Tổng số lần sập phân tích</div>
                <div class="kpi-val">{summary.get('total_crashes', 0)} sự cố</div>
            </div>
            <div class="card">
                <div class="kpi-title">Cảnh báo diện rộng</div>
                <div class="kpi-val" style="color: {'#d97706' if summary.get('fleet_warnings') else '#16a34a'};">
                    {len(summary.get('fleet_warnings', []))} cảnh báo
                </div>
            </div>
        </div>

        <div class="grid-2">
            <div class="card">
                <h3 style="margin-top:0; border-bottom:2px solid #e2e8f0; padding-bottom:8px;">Phân bổ Nhóm Nguyên nhân theo Máy</h3>
                {suspect_rows_html if suspect_rows_html else '<p style="color:#64748b;">Không có dữ liệu.</p>'}
            </div>
            <div class="card">
                <h3 style="margin-top:0; border-bottom:2px solid #e2e8f0; padding-bottom:8px;">Nhận diện Bất thường & Cảnh báo Hàng loạt</h3>
                {warnings_html}
            </div>
        </div>

        <div class="card">
            <h3 style="margin-top:0; border-bottom:2px solid #e2e8f0; padding-bottom:8px;">Chi tiết Từng Máy tính Phân tích</h3>
            <table>
                <thead>
                    <tr>
                        <th style="width:40px; text-align:center;">STT</th>
                        <th>Tên máy (Hostname)</th>
                        <th style="text-align:center;">Số vụ sập</th>
                        <th>Nguyên nhân hàng đầu</th>
                        <th style="text-align:center;">Độ tin cậy</th>
                        <th>Khuyến nghị xử lý đầu tiên</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(machine_rows_html) if machine_rows_html else '<tr><td colspan="6" style="text-align:center;">Không có máy nào được phân tích.</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
    out_file.write_text(html_content, encoding="utf-8")
    return out_file


def export_fleet_excel_report(
    output_path: str | Path,
    fleet_data: Dict[str, Any],
) -> Path:
    """Xuất báo cáo tổng hợp phân tích đa máy định dạng Microsoft Excel (.xlsx).

    Sheet 1: Tổng quan toàn công ty & Cảnh báo diện rộng
    Sheet 2: Chi tiết theo từng máy
    Sheet 3: Toàn bộ danh sách các lần sập (Toàn công ty)
    """
    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)

    summary = fleet_data.get("summary", {})
    machines = fleet_data.get("machines", [])

    wb = openpyxl.Workbook()

    font_header = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    fill_header = PatternFill(start_color="1F497D", end_color="1F497D", fill_type="solid")
    font_title = Font(name="Calibri", size=14, bold=True, color="1F497D")
    font_bold = Font(name="Calibri", size=11, bold=True)
    font_regular = Font(name="Calibri", size=11)
    align_center = Alignment(horizontal="center", vertical="center")
    border_thin = Border(
        left=Side(style="thin", color="D9D9D9"),
        right=Side(style="thin", color="D9D9D9"),
        top=Side(style="thin", color="D9D9D9"),
        bottom=Side(style="thin", color="D9D9D9"),
    )

    # -------------------------------------------------------------
    # SHEET 1: Tổng quan diện rộng
    # -------------------------------------------------------------
    ws1 = wb.active
    ws1.title = "Tổng quan Đa máy"
    ws1.views.sheetView[0].showGridLines = True

    ws1["A1"] = "BÁO CÁO TỔNG HỢP SỰ CỐ ĐA MÁY - DUMPANALYZER"
    ws1["A1"].font = font_title
    ws1["A2"] = f"Thời điểm xuất: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}"
    ws1["A2"].font = font_regular

    row = 4
    ws1.cell(row=row, column=1, value="THỐNG KÊ TOÀN CÔNG TY").font = font_bold
    row += 1
    stats = [
        ("Tổng số máy tính kiểm tra", f"{summary.get('total_machines', 0)} máy"),
        ("Tổng số lần sập phân tích", f"{summary.get('total_crashes', 0)} vụ sập"),
        ("Số cảnh báo bất thường diện rộng", f"{len(summary.get('fleet_warnings', []))} cảnh báo"),
    ]
    for label, val in stats:
        ws1.cell(row=row, column=1, value=label).font = font_regular
        ws1.cell(row=row, column=2, value=val).font = font_bold
        row += 1

    row += 1
    ws1.cell(row=row, column=1, value="CẢNH BÁO BẤT THƯỜNG DIỆN RỘNG (FLEET WARNINGS)").font = font_bold
    row += 1
    warnings = summary.get("fleet_warnings", [])
    if warnings:
        for w_idx, w in enumerate(warnings, start=1):
            ws1.cell(row=row, column=1, value=f"[Cảnh báo #{w_idx}]").alignment = align_center
            c_w = ws1.cell(row=row, column=2, value=w)
            c_w.font = font_regular
            c_w.alignment = Alignment(wrap_text=True)
            row += 1
    else:
        ws1.cell(row=row, column=1, value="Không phát hiện bất thường diện rộng nào.").font = font_regular
        row += 1

    # -------------------------------------------------------------
    # SHEET 2: Chi tiết theo từng máy
    # -------------------------------------------------------------
    ws2 = wb.create_sheet(title="Chi tiết Từng máy")
    ws2.views.sheetView[0].showGridLines = True
    headers_m = [
        "STT",
        "Tên máy tính (Hostname)",
        "Số vụ sập",
        "Nguyên nhân hàng đầu",
        "Xác suất (%)",
        "Độ tin cậy",
        "Khuyến nghị xử lý hàng đầu",
    ]
    for col_idx, h in enumerate(headers_m, start=1):
        c = ws2.cell(row=1, column=col_idx, value=h)
        c.font = font_header
        c.fill = fill_header
        c.alignment = align_center
        c.border = border_thin

    for r_idx, m_res in enumerate(machines, start=2):
        f = m_res.get("finding")
        ws2.cell(row=r_idx, column=1, value=r_idx - 1).alignment = align_center
        ws2.cell(row=r_idx, column=2, value=m_res["machine_name"]).font = font_bold
        ws2.cell(row=r_idx, column=3, value=len(m_res.get("crashes", []))).alignment = align_center
        ws2.cell(row=r_idx, column=4, value=m_res.get("top_suspect", "Chưa rõ"))
        ws2.cell(row=r_idx, column=5, value=round(m_res.get("top_score", 0.0), 1)).alignment = align_center
        ws2.cell(row=r_idx, column=6, value=m_res.get("confidence", "thấp").upper()).alignment = align_center
        ws2.cell(row=r_idx, column=7, value=f.next_steps[0] if (f and f.next_steps) else "-")
        for col_i in range(1, 8):
            ws2.cell(row=r_idx, column=col_i).border = border_thin

    # -------------------------------------------------------------
    # SHEET 3: Toàn bộ danh sách crash
    # -------------------------------------------------------------
    ws3 = wb.create_sheet(title="Toàn bộ Danh sách Crash")
    ws3.views.sheetView[0].showGridLines = True
    headers_c = [
        "STT",
        "Máy tính",
        "Thời điểm (Giờ địa phương)",
        "Mã lỗi BugCheck",
        "Tên lỗi BugCheck",
        "Module/Driver",
        "Phương thức",
        "Đường dẫn file dump",
    ]
    for col_idx, h in enumerate(headers_c, start=1):
        c = ws3.cell(row=1, column=col_idx, value=h)
        c.font = font_header
        c.fill = fill_header
        c.alignment = align_center
        c.border = border_thin

    cur_row = 2
    for m_res in machines:
        m_name = m_res["machine_name"]
        for c_obj in m_res.get("crashes", []):
            t_val = getattr(c_obj, "crash_time_utc", getattr(c_obj, "crash_time", None))
            t_loc = utc_to_local_str(t_val) if t_val else "Không xác định"
            mod = getattr(c_obj, "image_name", getattr(c_obj, "module_name", "-")) or "-"
            ws3.cell(row=cur_row, column=1, value=cur_row - 1).alignment = align_center
            ws3.cell(row=cur_row, column=2, value=m_name).font = font_bold
            ws3.cell(row=cur_row, column=3, value=t_loc)
            ws3.cell(row=cur_row, column=4, value=getattr(c_obj, "bugcheck_code", "N/A") or "N/A").alignment = align_center
            ws3.cell(row=cur_row, column=5, value=getattr(c_obj, "bugcheck_name", "Chưa rõ") or "Chưa rõ")
            ws3.cell(row=cur_row, column=6, value=mod)
            ws3.cell(row=cur_row, column=7, value=getattr(c_obj, "analyzed_by", "none")).alignment = align_center
            ws3.cell(row=cur_row, column=8, value=getattr(c_obj, "dump_path", "") or "[Không có dump]")
            for col_i in range(1, 9):
                ws3.cell(row=cur_row, column=col_i).border = border_thin
            cur_row += 1

    # Căn chỉnh độ rộng cột
    for sheet in wb.worksheets:
        for col in sheet.columns:
            max_len = max(len(str(cell.value or "")) for cell in col)
            col_letter = get_column_letter(col[0].column)
            sheet.column_dimensions[col_letter].width = min(50, max(max_len + 3, 12))

    wb.save(str(out_file))
    return out_file
