"""
Module phân tích theo lô đa dump / đa máy tính (Batch & Fleet Analysis).
Hỗ trợ:
- Quét cây thư mục chứa dump của nhiều máy tính (mỗi thư mục con là một tên máy tính).
- Phân tích và chấm điểm cho từng máy riêng biệt.
- Tổng hợp thống kê liên máy (Cross-machine correlation):
  + Tỷ lệ lỗi theo dòng máy / bo mạch chủ.
  + Phát hiện driver lỗi xuất hiện đồng loạt trên nhiều máy khác nhau trong công ty.
  + Bảng xếp hạng mã lỗi phổ biến toàn công ty.
- Xuất báo cáo tổng hợp fleet dạng cấu trúc dữ liệu, HTML và Excel.
"""

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, Tuple

from dumpanalyzer.analyzer.header_parser import parse_dump_header, DumpHeaderInfo
from dumpanalyzer.collectors.dump_finder import find_dumps
from dumpanalyzer.core.logging_setup import get_logger
from dumpanalyzer.core.timeutil import utc_to_local_str
from dumpanalyzer.core.models import Crash, Evidence, Finding
from dumpanalyzer.engine.rule_loader import load_all_rules
from dumpanalyzer.core.config import load_settings
from dumpanalyzer.engine.scorer import score_machine_crashes, score_single_crash, get_suspect_label_vi
from dumpanalyzer.engine.verdict import generate_machine_finding, generate_crash_finding

logger = get_logger("batch_analyzer")


class FleetBatchAnalyzer:
    """
    Bộ phân tích theo lô cho nhiều máy tính / nhiều file dump.
    """

    def __init__(self, rules: Optional[Dict[str, Any]] = None, settings: Optional[Dict[str, Any]] = None):
        self.rules = rules or load_all_rules()
        self.settings = settings or load_settings()

    def discover_machines(self, root_dir: Union[str, Path]) -> Dict[str, List[Path]]:
        """
        Quét cấu trúc thư mục để phân loại dump theo máy tính:
        - Các thư mục con trực tiếp được coi là tên máy (hostname / PC Name).
        - Các file dump nằm trực tiếp tại root_dir được gán cho máy 'DEFAULT' hoặc tên thư mục gốc.
        """
        root = Path(root_dir).resolve()
        if not root.exists() or not root.is_dir():
            raise FileNotFoundError(f"Thư mục không tồn tại: {root_dir}")

        machine_dumps: Dict[str, List[Path]] = defaultdict(list)

        # 1. Tìm các file dump nằm ở thư mục con
        for item in root.iterdir():
            if item.is_dir():
                sub_dumps = find_dumps([str(item)])
                if sub_dumps:
                    machine_name = item.name
                    for d in sub_dumps:
                        machine_dumps[machine_name].append(d["path"])
            elif item.is_file() and item.suffix.lower() == ".dmp":
                # File nằm ngay thư mục gốc
                machine_dumps[root.name or "DEFAULT"].append(item)

        return dict(machine_dumps)

    def analyze_dump_file(self, dump_path: Path) -> Dict[str, Any]:
        """
        Phân tích nhanh thông tin dump qua header (hoặc fallback).
        """
        try:
            info = parse_dump_header(dump_path)
            # Trích xuất module từ dump_type hoặc fallback
            module_name = ""

            return {
                "file_path": str(dump_path),
                "filename": dump_path.name,
                "bugcheck_code": info.bugcheck_code,
                "bugcheck_name": info.bugcheck_name,
                "parameters": [info.p1, info.p2, info.p3, info.p4],
                "dump_type": info.dump_type,
                "timestamp_utc": info.crash_time_utc or datetime.fromtimestamp(dump_path.stat().st_mtime, tz=timezone.utc).isoformat(),
                "analyzed_by": "header_only",
                "faulting_module": module_name or "Unknown",
                "architecture": "x64",
                "build_number": 0,
            }
        except Exception as e:
            logger.warning(f"Lỗi khi đọc header file {dump_path.name}: {e}")
            return {
                "file_path": str(dump_path),
                "filename": dump_path.name,
                "bugcheck_code": "0x0",
                "bugcheck_name": "UNKNOWN_CRASH",
                "parameters": ["0x0", "0x0", "0x0", "0x0"],
                "dump_type": "unknown",
                "timestamp_utc": datetime.fromtimestamp(dump_path.stat().st_mtime, tz=timezone.utc),
                "analyzed_by": "header_only",
                "faulting_module": "Unknown",
                "architecture": "x64",
                "build_number": 0,
            }

    def analyze_machine(
        self,
        machine_name: str,
        dump_paths: List[Path],
        hardware_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Phân tích tất cả dump của một máy và trả về kết luận chẩn đoán.
        """
        crashes = [self.analyze_dump_file(p) for p in dump_paths]
        # Sắp xếp crash theo thời gian mới nhất lên đầu (chuẩn hoá string so sánh an toàn)
        crashes.sort(key=lambda x: str(x.get("timestamp_utc", "")), reverse=True)

        crash_tuples: List[Tuple[Crash, List[Evidence]]] = []
        for idx, c in enumerate(crashes):
            t_utc = c["timestamp_utc"]
            t_str = t_utc if isinstance(t_utc, str) else t_utc.isoformat()
            c_obj = Crash(
                id=idx + 1,
                dump_path=c["file_path"],
                dump_type=c["dump_type"],
                crash_time_utc=t_str,
                bugcheck_code=c["bugcheck_code"],
                bugcheck_name=c["bugcheck_name"],
                p1=c["parameters"][0],
                p2=c["parameters"][1],
                p3=c["parameters"][2],
                p4=c["parameters"][3],
                module_name=c.get("faulting_module", ""),
                image_name=c.get("faulting_module", ""),
                analyzed_by=c.get("analyzed_by", "header_only"),
            )
            crash_tuples.append((c_obj, []))

        scored = score_machine_crashes(crash_tuples, self.rules, self.settings)
        finding = generate_machine_finding(None, scored, self.rules)

        verdict = {
            "primary_culprit": get_suspect_label_vi(scored.get("top_suspect", "unknown")),
            "top_score": scored.get("top_score", 0.0),
            "confidence": scored.get("confidence", "thấp"),
            "rationale": finding.rationale,
            "next_steps": finding.next_steps,
            "suspect_scores": scored.get("suspect_scores", []),
        }

        return {
            "machine_name": machine_name,
            "dump_count": len(crashes),
            "crashes": crashes,
            "verdict": verdict,
            "model": (hardware_info or {}).get("model", "Chưa rõ Model"),
            "motherboard": (hardware_info or {}).get("motherboard", "Chưa rõ Bo mạch"),
        }

    def analyze_fleet(
        self,
        root_dir: Union[str, Path],
        machine_metadata: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Phân tích toàn bộ đội máy tính trong thư mục gốc.
        Tổng hợp thống kê và phát hiện bất thường liên máy (Cross-machine correlation).
        """
        machine_metadata = machine_metadata or {}
        discovered = self.discover_machines(root_dir)

        machine_results = []
        all_crashes: List[Dict[str, Any]] = []
        bugcheck_counter: Counter = Counter()
        driver_counter: Counter = Counter()
        driver_machines: Dict[str, set] = defaultdict(set)
        group_counter: Counter = Counter()
        model_crash_counter: Counter = Counter()

        for machine_name, dumps in discovered.items():
            meta = machine_metadata.get(machine_name, {})
            m_res = self.analyze_machine(machine_name, dumps, hardware_info=meta)
            machine_results.append(m_res)

            verdict = m_res["verdict"]
            top_group = verdict.get("primary_culprit", "Chưa rõ")
            group_counter[top_group] += 1

            model_name = m_res.get("model", "Chưa rõ")
            model_crash_counter[model_name] += len(m_res["crashes"])

            for c in m_res["crashes"]:
                all_crashes.append({**c, "machine_name": machine_name})
                bc = f"{c['bugcheck_code']} ({c['bugcheck_name']})"
                bugcheck_counter[bc] += 1
                drv = c.get("faulting_module", "Unknown")
                if drv and drv != "Unknown":
                    driver_counter[drv] += 1
                    driver_machines[drv].add(machine_name)

        # Phát hiện sự cố hàng loạt (Fleet-wide widespread issues)
        widespread_drivers = []
        for drv, m_set in driver_machines.items():
            if len(m_set) >= 2 or (len(discovered) == 1 and driver_counter[drv] >= 2):
                widespread_drivers.append({
                    "driver": drv,
                    "affected_machines_count": len(m_set),
                    "affected_machines": sorted(list(m_set)),
                    "total_crashes": driver_counter[drv],
                    "severity": "CAO" if len(m_set) >= 3 else "CẢNH BÁO",
                    "note": f"Driver '{drv}' xuất hiện trong {driver_counter[drv]} lần sập trên {len(m_set)} máy tính khác nhau.",
                })
        widespread_drivers.sort(key=lambda x: (x["affected_machines_count"], x["total_crashes"]), reverse=True)

        return {
            "timestamp_utc": datetime.now(timezone.utc),
            "root_dir": str(Path(root_dir).resolve()),
            "total_machines": len(machine_results),
            "total_crashes": len(all_crashes),
            "machines": machine_results,
            "widespread_drivers": widespread_drivers,
            "top_bugchecks": bugcheck_counter.most_common(10),
            "top_groups": group_counter.most_common(),
            "model_crashes": model_crash_counter.most_common(),
        }

    def export_fleet_html(self, fleet_data: Dict[str, Any], output_path: Union[str, Path]) -> str:
        """
        Xuất báo cáo tổng quan đội máy tính (Fleet Overview Report) ra file HTML độc lập.
        """
        out = Path(output_path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        widespread_html = ""
        if fleet_data["widespread_drivers"]:
            widespread_rows = ""
            for item in fleet_data["widespread_drivers"]:
                machines_str = ", ".join(item["affected_machines"])
                badge_cls = "badge-danger" if item["severity"] == "CAO" else "badge-warning"
                widespread_rows += f"""
                <tr>
                    <td><strong>{item['driver']}</strong></td>
                    <td><span class="badge {badge_cls}">{item['severity']}</span></td>
                    <td>{item['affected_machines_count']} máy ({machines_str})</td>
                    <td>{item['total_crashes']} lần</td>
                    <td>{item['note']}</td>
                </tr>
                """
            widespread_html = f"""
            <div class="card warning-card">
                <h3>⚠️ CẢNH BÁO LỖI DRIVER HÀNG LOẠT TRÊN NHIỀU MÁY</h3>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Driver</th>
                            <th>Mức độ</th>
                            <th>Máy bị ảnh hưởng</th>
                            <th>Tổng sập</th>
                            <th>Khuyến nghị IT</th>
                        </tr>
                    </thead>
                    <tbody>
                        {widespread_rows}
                    </tbody>
                </table>
            </div>
            """

        machine_rows = ""
        for m in fleet_data["machines"]:
            v = m["verdict"]
            conf = v.get("confidence", "Chưa rõ")
            badge_cls = "badge-success" if conf == "Cao" else ("badge-warning" if conf == "Trung bình" else "badge-secondary")
            culprit = v.get("primary_culprit", "Chưa rõ")
            score = v.get("top_score", 0)
            machine_rows += f"""
            <tr>
                <td><strong>{m['machine_name']}</strong></td>
                <td>{m.get('model', 'Chưa rõ')}</td>
                <td>{m['dump_count']} file</td>
                <td><span class="badge {badge_cls}">{conf}</span></td>
                <td><strong>{culprit}</strong> ({score}%)</td>
                <td>{v.get('rationale', '')[:80]}...</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Báo Cáo Tổng Hợp Đa Máy Tính - DumpAnalyzer</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; background: #f8fafc; color: #1e293b; margin: 0; padding: 24px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: #0f172a; color: #fff; padding: 24px; border-radius: 8px; margin-bottom: 24px; }}
        .header h1 {{ margin: 0 0 8px 0; font-size: 24px; }}
        .grid-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .stat-card {{ background: #fff; padding: 20px; border-radius: 8px; border: 1px solid #e2e8f0; }}
        .stat-card .val {{ font-size: 28px; font-weight: bold; color: #0284c7; margin-top: 8px; }}
        .card {{ background: #fff; padding: 24px; border-radius: 8px; border: 1px solid #e2e8f0; margin-bottom: 24px; }}
        .warning-card {{ border-left: 6px solid #e11d48; }}
        .data-table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        .data-table th, .data-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
        .data-table th {{ background: #f1f5f9; font-weight: 600; font-size: 13px; text-transform: uppercase; color: #475569; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: bold; }}
        .badge-danger {{ background: #ffe4e6; color: #e11d48; }}
        .badge-warning {{ background: #fef3c7; color: #d97706; }}
        .badge-success {{ background: #dcfce7; color: #16a34a; }}
        .badge-secondary {{ background: #f1f5f9; color: #475569; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>DumpAnalyzer — Báo Cáo Tổng Hợp Sự Cố Đa Máy Tính</h1>
            <p>Thời gian lập báo cáo: {utc_to_local_str(fleet_data['timestamp_utc'].isoformat())} | Thư mục: {fleet_data['root_dir']}</p>
        </div>

        <div class="grid-stats">
            <div class="stat-card">
                <div>Tổng số máy tính</div>
                <div class="val">{fleet_data['total_machines']}</div>
            </div>
            <div class="stat-card">
                <div>Tổng số lần sập (Dump)</div>
                <div class="val">{fleet_data['total_crashes']}</div>
            </div>
            <div class="stat-card">
                <div>Driver lỗi hàng loạt</div>
                <div class="val" style="color: {'#e11d48' if fleet_data['widespread_drivers'] else '#16a34a'};">
                    {len(fleet_data['widespread_drivers'])}
                </div>
            </div>
        </div>

        {widespread_html}

        <div class="card">
            <h3>Danh Sách Chi Tiết Theo Từng Máy Tính</h3>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Tên máy</th>
                        <th>Model</th>
                        <th>Số dump</th>
                        <th>Độ tin cậy</th>
                        <th>Nghi ngờ chính</th>
                        <th>Tóm tắt chẩn đoán</th>
                    </tr>
                </thead>
                <tbody>
                    {machine_rows}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
        with open(out, "w", encoding="utf-8") as f:
            f.write(html_content)

        return str(out)

    def export_fleet_excel(self, fleet_data: Dict[str, Any], output_path: Union[str, Path]) -> str:
        """
        Xuất báo cáo tổng hợp đội máy tính (Fleet Overview Report) ra file Excel đa bảng tính (.xlsx).
        - Sheet 1: Tổng quan Đội máy
        - Sheet 2: Danh sách Máy tính
        - Sheet 3: Driver Lỗi Hàng Loạt
        - Sheet 4: Danh sách Toàn bộ Crash
        """
        import openpyxl
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        from openpyxl.utils import get_column_letter

        out = Path(output_path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        wb = openpyxl.Workbook()

        # Styles
        header_fill = PatternFill(start_color="0F172A", end_color="0F172A", fill_type="solid")
        header_font = Font(name="Segoe UI", size=11, bold=True, color="FFFFFF")
        title_font = Font(name="Segoe UI", size=14, bold=True, color="0F172A")

        # Sheet 1: Tổng quan Đội máy
        ws_overview = wb.active
        ws_overview.title = "Tổng quan Đội máy"
        ws_overview.views.sheetView[0].showGridLines = True

        ws_overview.append(["BÁO CÁO TỔNG HỢP SỰ CỐ ĐA MÁY TÍNH — DUMPANALYZER"])
        ws_overview.cell(1, 1).font = title_font
        ws_overview.append([f"Thời gian lập: {utc_to_local_str(fleet_data['timestamp_utc'].isoformat())}"])
        ws_overview.append([f"Thư mục quét: {fleet_data['root_dir']}"])
        ws_overview.append([])

        ws_overview.append(["CHỈ SỐ TỔNG QUAN", "GIÁ TRỊ"])
        ws_overview.cell(5, 1).font = header_font
        ws_overview.cell(5, 1).fill = header_fill
        ws_overview.cell(5, 2).font = header_font
        ws_overview.cell(5, 2).fill = header_fill

        stats = [
            ("Tổng số máy tính quét được", fleet_data["total_machines"]),
            ("Tổng số lần sập / file dump", fleet_data["total_crashes"]),
            ("Số driver gặp lỗi diện rộng (>=2 máy)", len(fleet_data["widespread_drivers"])),
        ]
        for row in stats:
            ws_overview.append(list(row))
        ws_overview.append([])

        # Top Bug Checks
        ws_overview.append(["MÃ BUG CHECK PHỔ BIẾN TOÀN CÔNG TY", "SỐ LẦN XUẤT HIỆN"])
        ws_overview.cell(ws_overview.max_row, 1).font = header_font
        ws_overview.cell(ws_overview.max_row, 1).fill = header_fill
        ws_overview.cell(ws_overview.max_row, 2).font = header_font
        ws_overview.cell(ws_overview.max_row, 2).fill = header_fill
        for bc, count in fleet_data.get("top_bugchecks", []):
            ws_overview.append([bc, count])

        # Sheet 2: Danh sách máy tính
        ws_machines = wb.create_sheet(title="Danh sách Máy tính")
        ws_machines.views.sheetView[0].showGridLines = True
        m_headers = ["Tên Máy", "Model", "Bo Mạch", "Số Dump", "Độ Tin Cậy", "Nghi Ngờ Chính", "Xác Suất (%)", "Khuyến Nghị IT"]
        ws_machines.append(m_headers)
        for col_idx in range(1, len(m_headers) + 1):
            cell = ws_machines.cell(1, col_idx)
            cell.font = header_font
            cell.fill = header_fill

        for m in fleet_data["machines"]:
            v = m["verdict"]
            ws_machines.append([
                m["machine_name"],
                m.get("model", "Chưa rõ"),
                m.get("motherboard", "Chưa rõ"),
                m["dump_count"],
                v.get("confidence", "Chưa rõ"),
                v.get("primary_culprit", "Chưa rõ"),
                v.get("top_score", 0),
                v.get("rationale", ""),
            ])

        # Sheet 3: Driver Lỗi Hàng Loạt
        ws_drivers = wb.create_sheet(title="Driver Lỗi Hàng Loạt")
        ws_drivers.views.sheetView[0].showGridLines = True
        d_headers = ["Tên Driver", "Mức Độ", "Số Máy Bị Ảnh Hưởng", "Danh Sách Máy", "Tổng Số Lần Sập", "Ghi Chú Khuyến Nghị"]
        ws_drivers.append(d_headers)
        for col_idx in range(1, len(d_headers) + 1):
            cell = ws_drivers.cell(1, col_idx)
            cell.font = header_font
            cell.fill = header_fill

        for drv in fleet_data["widespread_drivers"]:
            ws_drivers.append([
                drv["driver"],
                drv["severity"],
                drv["affected_machines_count"],
                ", ".join(drv["affected_machines"]),
                drv["total_crashes"],
                drv["note"],
            ])

        # Sheet 4: Danh sách Toàn bộ Crash
        ws_crashes = wb.create_sheet(title="Toàn bộ Lần Sập")
        ws_crashes.views.sheetView[0].showGridLines = True
        c_headers = ["Tên Máy", "Tên File", "Thời Gian (Local)", "Mã Lỗi Hex", "Tên Mã Lỗi", "Module Lỗi", "Kiểu Dump"]
        ws_crashes.append(c_headers)
        for col_idx in range(1, len(c_headers) + 1):
            cell = ws_crashes.cell(1, col_idx)
            cell.font = header_font
            cell.fill = header_fill

        for m in fleet_data["machines"]:
            for c in m["crashes"]:
                t_str = c.get("timestamp_utc", "")
                loc_t = utc_to_local_str(t_str) if isinstance(t_str, str) else str(t_str)
                ws_crashes.append([
                    m["machine_name"],
                    c.get("filename", ""),
                    loc_t,
                    c.get("bugcheck_code", ""),
                    c.get("bugcheck_name", ""),
                    c.get("faulting_module", ""),
                    c.get("dump_type", ""),
                ])

        # Auto-adjust column width on all sheets
        for ws in wb.worksheets:
            for col in ws.columns:
                max_len = max(len(str(cell.value or "")) for cell in col)
                col_letter = get_column_letter(col[0].column)
                ws.column_dimensions[col_letter].width = min(max(max_len + 3, 12), 60)

        wb.save(out)
        return str(out)
