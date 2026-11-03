"""
Module tạo kết luận chẩn đoán (Verdict Engine).
Tổng hợp kết quả chấm điểm, sinh lời giải thích rõ ràng bằng tiếng Việt,
liên kết bằng chứng (evidence_ids) và sắp xếp các bước kiểm tra theo thứ tự DỄ -> KHÓ.
"""

import logging
from typing import Any, Dict, List, Optional
from dumpanalyzer.core.models import Crash, Finding
from dumpanalyzer.engine.scorer import get_suspect_label_vi
from dumpanalyzer.engine.rule_loader import normalize_bugcheck_code

logger = logging.getLogger("dumpanalyzer.engine.verdict")


def get_step_difficulty_weight(step: str) -> int:
    """
    Ước lượng độ khó / mức độ phức tạp của bước kiểm tra (điểm càng nhỏ càng dễ).
    Thang điểm:
      1: Thao tác phần mềm cực nhanh, không can thiệp sâu (bật dump, xem nhiệt độ, xem thông tin)
      2: Thao tác sửa lỗi phần mềm / gỡ cài đặt driver (DDU, sfc, chkdsk, gỡ update)
      3: Kiểm tra phần cứng không cần thay linh kiện (MemTest86, tháo lắp vệ sinh RAM, cáp)
      4: Can thiệp sâu phần cứng / Thay thế linh kiện / Nạp BIOS (thay nguồn, mua linh kiện mới, update BIOS)
    """
    s = step.lower()

    # Tier 1: Cực dễ / Nhanh / Không tốn chi phí
    if any(k in s for k in ("bật tính năng ghi dump", "khởi động lại", "nhiệt độ", "fast startup", "verifier /reset", "kiểm tra dây nguồn", "ổ cắm")):
        return 1

    # Tier 2: Sửa phần mềm / Driver
    if any(k in s for k in ("ddu", "cài lại driver", "cập nhật driver", "cập nhật firmware", "gỡ", "sfc /scannow", "chkdsk", "uninstall update", "whql")):
        return 2

    # Tier 3: Kiểm tra phần cứng
    if any(k in s for k in ("memtest86", "kiểm tra smart", "thử riêng từng thanh ram", "vệ sinh", "cáp sata", "khe cắm")):
        return 3

    # Tier 4: Can thiệp sâu / Mua sắm linh kiện
    if any(k in s for k in ("bios", "thử nguồn khác", "thay nguồn", "thay thế", "mua", "bảo hành", "thay keo tản nhiệt")):
        return 4

    return 2


def sort_next_steps_easy_to_hard(steps: List[str]) -> List[str]:
    """Sắp xếp danh sách các bước kiểm tra theo thứ tự từ DỄ đến KHÓ."""
    # Loại bỏ các bước trùng lặp nhưng giữ nguyên thứ tự xuất hiện ban đầu
    unique_steps: List[str] = []
    seen = set()
    for st in steps:
        clean = st.strip()
        if clean and clean not in seen:
            unique_steps.append(clean)
            seen.add(clean)

    return sorted(unique_steps, key=get_step_difficulty_weight)


def generate_crash_finding(
    crash: Crash,
    scored_result: Dict[str, Any],
    rules: Dict[str, Any],
    machine_id: Optional[int] = None,
) -> Finding:
    """
    Sinh kết luận chẩn đoán Finding cho một vụ sập (Crash) cụ thể.
    """
    top_suspect = scored_result.get("top_suspect", "unknown")
    top_score = float(scored_result.get("top_score", 0.0))
    confidence = scored_result.get("confidence", "thấp")
    evidence_ids = scored_result.get("used_evidence_ids", [])
    is_log_only = scored_result.get("is_log_only", False)
    applied_caps = scored_result.get("applied_caps", "")

    # 1. Thu thập các bước kiểm tra (next_steps) từ next_steps.yaml và các quy tắc
    raw_steps: List[str] = []
    ns_rules = rules.get("next_steps", {})
    suspect_steps_map = ns_rules.get("suspect_steps", {})
    missing_data_hints = ns_rules.get("missing_data_hints", {})

    # Lấy bước hành động từ suspect_steps trong next_steps.yaml
    clean_susp = top_suspect.split(":", 1)[0] if ":" in top_suspect else top_suspect
    if clean_susp in suspect_steps_map:
        raw_steps.extend(suspect_steps_map[clean_susp])

    # Lấy từ driver_map nếu có driver cụ thể
    driver_map = rules.get("drivers", {})
    img = (crash.image_name or "").strip().lower()
    if img in driver_map and "action" in driver_map[img]:
        raw_steps.insert(0, driver_map[img]["action"])

    # Lấy từ bugcheck_rules
    bc_code = normalize_bugcheck_code(crash.bugcheck_code) if crash.bugcheck_code else "0x0"
    bc_rules = rules.get("bugchecks", {})
    if bc_code in bc_rules:
        raw_steps.extend(bc_rules[bc_code].get("next_steps", []))

    # Phát hiện dữ liệu còn thiếu (Missing Data Hints)
    missing_hints: List[str] = []
    if is_log_only:
        raw_steps.insert(0, "Bật tính năng ghi dump bộ nhớ (Automatic Memory Dump) trong DumpAnalyzer để có dữ liệu chẩn đoán sâu hơn nếu máy bị sập lại.")
    elif crash.analyzed_by == "header_only" or not crash.cdb_raw_output:
        if "missing_cdb" in missing_data_hints:
            missing_hints.append(missing_data_hints["missing_cdb"].get("text", ""))
    if crash.dump_type in ("minidump", "triage", "mini"):
        if "mini_dump_only" in missing_data_hints:
            missing_hints.append(missing_data_hints["mini_dump_only"].get("text", ""))

    if missing_hints:
        raw_steps.extend(missing_hints)

    if not raw_steps:
        raw_steps = [
            "Kiểm tra nhiệt độ CPU và GPU trong Windows hoặc BIOS",
            "Cập nhật driver thiết bị lên phiên bản mới nhất",
            "Chạy công cụ kiểm tra bộ nhớ Windows Memory Diagnostic",
        ]

    ordered_steps = sort_next_steps_easy_to_hard(raw_steps)

    # 2. Xây dựng lời giải thích (rationale) bằng tiếng Việt
    suspect_label = get_suspect_label_vi(top_suspect)
    bc_name = crash.bugcheck_name or bc_code

    if confidence == "không đủ dữ kiện":
        rationale = (
            f"Vụ sập mã {bc_code} ({bc_name}) chưa đủ thông tin để khoanh vùng nguyên nhân chắc chắn "
            f"(điểm nghi ngờ cao nhất chỉ đạt {top_score:.1f}%). "
            f"Khuyến nghị chạy lại phân tích bằng cdb hoặc theo dõi thêm các lần sập sau."
        )
    elif is_log_only:
        if bc_code in ("0", "0x0", ""):
            rationale = (
                f"Hệ thống bị tắt hoặc khởi động lại đột ngột không qua màn hình xanh BSOD (Event 41, mã 0). "
                f"Nghi vấn cao nhất nghiêng về {suspect_label} ({top_score:.1f}%), có thể do mất điện, sụt áp hoặc rơ-le quá nhiệt ngắt khẩn cấp. "
                f"Lưu ý: Kết luận kém chắc chắn do không có file dump."
            )
        else:
            rationale = (
                f"Sự cố ghi nhận mã Bug Check {bc_code} ({bc_name}) từ Windows Event Log nhưng không tìm thấy file dump. "
                f"Khoanh vùng nhóm nghi ngờ chính: {suspect_label} ({top_score:.1f}%). "
                f"Lưu ý: Không có dump nên chỉ xác định được nhóm thiết bị, không thể khẳng định driver cụ thể."
            )
    else:
        # Có dump
        if top_suspect.startswith("driver:"):
            drv_name = top_suspect.split(":", 1)[1]
            rationale = (
                f"Phân tích dump {bc_code} ({bc_name}) xác định nghi vấn trọng tâm là driver '{drv_name}' ({top_score:.1f}%). "
                f"Driver này xuất hiện trực tiếp trong luồng gây crash hoặc đỉnh call stack."
            )
        elif top_suspect in ("ram", "cpu", "storage", "gpu"):
            rationale = (
                f"Mã Bug Check {bc_code} ({bc_name}) kết hợp bằng chứng phân tích stack trace cho thấy tỷ lệ cao do {suspect_label} ({top_score:.1f}%)."
            )
        else:
            rationale = (
                f"Vụ sập {bc_code} ({bc_name}) được khoanh vùng nghi ngờ chính tại {suspect_label} với điểm tin cậy {top_score:.1f}%."
            )

    if applied_caps:
        rationale += f" [{applied_caps}]"
    if missing_hints:
        rationale += f" [Dữ liệu còn thiếu: {'; '.join(missing_hints)}]"

    suspicion_share = float(scored_result.get("suspicion_share", top_score))
    confidence_rationale = scored_result.get("confidence_rationale", "")

    return Finding(
        scope="crash",
        crash_id=crash.id,
        machine_id=machine_id or crash.machine_id,
        suspect=top_suspect,
        score=top_score,
        confidence=confidence,
        rationale=rationale,
        evidence_ids=evidence_ids,
        next_steps=ordered_steps,
        suspicion_share=suspicion_share,
        confidence_rationale=confidence_rationale,
    )



def generate_machine_finding(
    machine_id: Optional[int] = None,
    scored_result: Optional[Dict[str, Any]] = None,
    rules: Optional[Dict[str, Any]] = None,
) -> Finding:
    """
    Sinh kết luận chẩn đoán tổng thể cho một máy tính (Scope: 'machine').
    """
    scored = scored_result or {}
    active_rules = rules or {}
    top_suspect = scored.get("top_suspect", "unknown")
    top_score = float(scored.get("top_score", 0.0))
    confidence = scored.get("confidence", "thấp")
    evidence_ids = scored.get("used_evidence_ids", [])
    is_conflicted = scored.get("is_conflicted", False)
    conflict_note = scored.get("conflict_note", "")
    patterns_matched = scored.get("patterns_matched", [])
    crash_count = scored.get("crash_count", 0)

    suspect_label = get_suspect_label_vi(top_suspect)

    # 1. Thu thập các bước kiểm tra phù hợp với nhóm nghi ngờ cao nhất của máy
    raw_steps: List[str] = []
    ns_rules = active_rules.get("next_steps", {})
    suspect_steps_map = ns_rules.get("suspect_steps", {})
    missing_data_hints = ns_rules.get("missing_data_hints", {})

    clean_susp = top_suspect.split(":", 1)[0] if ":" in top_suspect else top_suspect
    if clean_susp in suspect_steps_map:
        raw_steps.extend(suspect_steps_map[clean_susp])

    # Tra cứu các bước của top suspect từ các bugcheck rules liên quan
    bc_rules = active_rules.get("bugchecks", {})
    for bc_item in bc_rules.values():
        if top_suspect in bc_item.get("suspects", {}):
            raw_steps.extend(bc_item.get("next_steps", []))

    # Nếu có pattern matched: thêm bước kiểm tra từ pattern
    for pat in active_rules.get("patterns", []):
        if pat.get("name") in patterns_matched and "next_steps" in pat:
            raw_steps.extend(pat.get("next_steps", []))

    # Phát hiện dữ liệu còn thiếu cho máy
    missing_hints: List[str] = []
    if crash_count == 1 and "single_crash_only" in missing_data_hints:
        missing_hints.append(missing_data_hints["single_crash_only"].get("text", ""))
    if clean_susp == "ram" and "missing_hwtest_ram" in missing_data_hints:
        missing_hints.append(missing_data_hints["missing_hwtest_ram"].get("text", ""))
    elif clean_susp == "storage" and "missing_hwtest_storage" in missing_data_hints:
        missing_hints.append(missing_data_hints["missing_hwtest_storage"].get("text", ""))

    if missing_hints:
        raw_steps.extend(missing_hints)

    if not raw_steps:
        raw_steps = [
            "Khởi động lại máy và kiểm tra nhiệt độ linh kiện",
            "Cập nhật toàn bộ driver và Windows Update lên bản mới nhất",
            "Chạy MemTest86 kiểm tra RAM",
        ]

    ordered_steps = sort_next_steps_easy_to_hard(raw_steps)

    # 2. Xây dựng lời giải thích tổng hợp (rationale)
    if confidence == "không đủ dữ kiện":
        rationale = (
            f"Tổng hợp qua {crash_count} lần sập máy chưa đủ dữ kiện để khẳng định nguyên nhân gốc rễ "
            f"(điểm cao nhất chỉ đạt {top_score:.1f}%). Cần thu thập thêm file dump hoặc mở rộng khoảng thời gian quét."
        )
    else:
        rationale = (
            f"Qua tổng hợp và đối chiếu {crash_count} lần sập hệ thống, nguyên nhân nghi vấn hàng đầu là "
            f"{suspect_label} ({top_score:.1f}%), xếp hạng độ tin cậy: {confidence.upper()}."
        )

        if patterns_matched:
            p_text = "; ".join(patterns_matched)
            rationale += f" Phát hiện mẫu hình đặc trưng: {p_text}."

        if is_conflicted and conflict_note:
            rationale += f" {conflict_note}"

        if missing_hints:
            rationale += f" [Dữ liệu còn thiếu: {'; '.join(missing_hints)}]"

    suspicion_share = float(scored.get("suspicion_share", top_score))
    confidence_rationale = scored.get("confidence_rationale", "")

    return Finding(
        scope="machine",
        crash_id=None,
        machine_id=machine_id,
        suspect=top_suspect,
        score=top_score,
        confidence=confidence,
        rationale=rationale,
        evidence_ids=evidence_ids,
        next_steps=ordered_steps,
        suspicion_share=suspicion_share,
        confidence_rationale=confidence_rationale,
    )

