"""
Module nhập danh sách thiết bị và lịch sử sửa chữa từ file CSV (AppSheet/Google Sheets) (asset_info.py).
Không sử dụng Google API ngoài - chỉ đọc file CSV cục bộ.
Hỗ trợ ánh xạ tên cột linh hoạt từ settings.yaml.
"""

import csv
import re
import datetime

from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from dumpanalyzer.core.config import load_settings
from dumpanalyzer.core.logging_setup import get_logger
from dumpanalyzer.core.timeutil import parse_to_utc, to_utc_iso
from dumpanalyzer.core.models import Evidence
from dumpanalyzer.storage.db import Database

logger = get_logger("asset_info")

DEFAULT_CSV_MAPPING = {
    "hostname": ["tên máy", "device name", "hostname", "computer name", "máy", "ten may", "device_name"],
    "purchase_date": ["ngày mua", "purchase date", "ngày nhập", "date purchased", "ngay mua", "purchase_date"],
    "warranty_expiry": ["ngày hết hạn bảo hành", "hết bảo hành", "warranty expiry", "warranty end", "het bao hanh", "warranty"],
    "repair_count": ["số lần sửa", "lần sửa", "repair count", "repairs", "so lan sua", "repair_count"],
    "ram": ["ram", "bộ nhớ", "dung lượng ram", "memory", "dung luong ram"],
    "notes": ["ghi chú", "notes", "lịch sử sửa chữa", "tình trạng", "ghi chu", "note"],
}


def _find_matching_col(headers: List[str], candidate_names: List[str]) -> Optional[str]:
    """Tìm tên cột thực tế trong file CSV khớp với danh sách bí danh."""
    header_norm_map = {h.strip().lower(): h for h in headers if h}
    for cand in candidate_names:
        cand_clean = cand.strip().lower()
        if cand_clean in header_norm_map:
            return header_norm_map[cand_clean]
    return None


def read_csv_lines_safely(file_path: Union[str, Path]) -> List[str]:
    """Đọc file CSV với dự phòng nhiều bảng mã (UTF-8, UTF-8 BOM, cp1252)."""
    p = Path(file_path).resolve()
    if not p.exists():
        raise FileNotFoundError(f"Không tìm thấy file CSV tại: {file_path}")

    # Thử UTF-8-sig trước (xử lý BOM), rồi utf-8, cuối cùng cp1252
    for enc in ["utf-8-sig", "utf-8", "cp1252", "latin1"]:
        try:
            content = p.read_text(encoding=enc)
            return content.splitlines()
        except UnicodeDecodeError:
            continue
    # Dự phòng replace
    content = p.read_text(encoding="utf-8", errors="replace")
    return content.splitlines()


def import_asset_csv(
    csv_path: Union[str, Path],
    db: Database,
    mapping: Optional[Dict[str, List[str]]] = None,
) -> Dict[str, Any]:
    """
    Nhập danh sách thiết bị từ file CSV xuất từ AppSheet/Google Sheets.
    Lưu hoặc cập nhật vào bảng asset_info.
    """
    settings = load_settings()
    configured_mapping = mapping or settings.get("asset_csv_mapping") or DEFAULT_CSV_MAPPING

    lines = read_csv_lines_safely(csv_path)
    if not lines:
        return {"total_rows": 0, "imported_count": 0, "skipped_count": 0, "errors": ["File CSV rỗng"]}

    # Phát hiện dấu phân cách (dấu phẩy , hoặc chấm phẩy ;)
    first_line = lines[0]
    delimiter = ";" if first_line.count(";") > first_line.count(",") else ","

    reader = csv.DictReader(lines, delimiter=delimiter)
    headers = reader.fieldnames or []

    # Tìm ánh xạ cột
    col_host = _find_matching_col(headers, configured_mapping.get("hostname", []))
    col_purchase = _find_matching_col(headers, configured_mapping.get("purchase_date", []))
    col_warranty = _find_matching_col(headers, configured_mapping.get("warranty_expiry", []))
    col_repairs = _find_matching_col(headers, configured_mapping.get("repair_count", []))
    col_ram = _find_matching_col(headers, configured_mapping.get("ram", []))
    col_notes = _find_matching_col(headers, configured_mapping.get("notes", []))

    if not col_host:
        return {
            "total_rows": 0,
            "imported_count": 0,
            "skipped_count": 0,
            "errors": [f"Không tìm thấy cột định danh tên máy trong CSV (các cột hiện có: {', '.join(headers)})"],
        }

    imported_count = 0
    skipped_count = 0
    errors: List[str] = []
    row_num = 1

    for row in reader:
        row_num += 1
        raw_host = row.get(col_host, "").strip() if col_host else ""
        if not raw_host:
            skipped_count += 1
            continue

        purchase_date = str(row.get(col_purchase, "")).strip() if col_purchase else ""
        warranty_expiry = str(row.get(col_warranty, "")).strip() if col_warranty else ""
        raw_repairs = str(row.get(col_repairs, "0")).strip() if col_repairs else "0"
        ram_str = str(row.get(col_ram, "")).strip() if col_ram else ""
        notes_str = str(row.get(col_notes, "")).strip() if col_notes else ""

        # Parse số lần sửa
        try:
            m_num = re.search(r"\d+", raw_repairs)
            repair_count = int(m_num.group(0)) if m_num else 0
        except Exception:
            repair_count = 0

        # Lưu vào CSDL
        try:
            db.upsert_asset_info(
                hostname=raw_host,
                purchase_date=purchase_date,
                warranty_expiry=warranty_expiry,
                repair_count=repair_count,
                ram=ram_str,
                notes=notes_str,
                raw_json="",
            )
            imported_count += 1
        except Exception as e:
            errors.append(f"Dòng {row_num} ({raw_host}): {e}")

    return {
        "total_rows": row_num - 1,
        "imported_count": imported_count,
        "skipped_count": skipped_count,
        "errors": errors,
    }


def evaluate_asset_evidence(
    asset_data: Optional[Dict[str, Any]],
    rules: Optional[Dict[str, Any]] = None,
) -> List[Evidence]:
    """
    Sinh các bằng chứng từ thông tin thiết bị (tuổi máy, số lần sửa chữa).
    Bằng chứng mức yếu - vừa, hỗ trợ khoanh vùng phần cứng già cỗi.
    """
    evidences: List[Evidence] = []
    if not asset_data:
        return evidences

    asset_rules = (rules or {}).get("asset_rules", {})
    age_thresh = float(asset_rules.get("machine_age_years_threshold", 4.0))
    repair_thresh = int(asset_rules.get("repair_count_threshold", 3))

    purchase_date_str = asset_data.get("purchase_date", "")
    repair_count = int(asset_data.get("repair_count") or 0)
    hostname = asset_data.get("hostname", "")

    # 1. Tuổi máy
    if purchase_date_str:
        dt = parse_to_utc(purchase_date_str)
        if dt:
            now = datetime.datetime.now(datetime.timezone.utc)
            age_years = round((now - dt).days / 365.25, 1)
            if age_years >= age_thresh:
                evidences.append(
                    Evidence(
                        kind="asset",
                        source="AppSheet Asset",
                        time_utc=to_utc_iso(dt),
                        summary=f"Thiết bị đã sử dụng {age_years} năm (ngày mua: {purchase_date_str})",
                        detail=f"Máy tính '{hostname}' đã hoạt động vượt ngưỡng {age_thresh} năm, các linh kiện có thể bị suy giảm hiệu năng/độ bền.",
                        strength=asset_rules.get("machine_age_strength", "weak"),
                        polarity="support",
                        group_id=asset_rules.get("machine_age_group_id", "asset_machine_age"),
                    )
                )

    # 2. Lịch sử sửa chữa nhiều lần
    if repair_count >= repair_thresh:
        evidences.append(
            Evidence(
                kind="asset",
                source="AppSheet Asset",
                time_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                summary=f"Thiết bị từng sửa chữa {repair_count} lần trong quá khứ",
                detail=f"Lịch sử bảo trì ghi nhận máy '{hostname}' đã sửa chữa {repair_count} lần (ngưỡng cảnh báo: {repair_thresh}). Ghi chú: {asset_data.get('notes', '')}",
                strength=asset_rules.get("repair_count_strength", "medium"),
                polarity="support",
                group_id=asset_rules.get("repair_count_group_id", "asset_repair_count"),
            )
        )

    return evidences
