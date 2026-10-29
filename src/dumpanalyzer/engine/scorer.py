"""
Module chấm điểm và suy luận nguyên nhân (Rule Engine Scorer).
Hiện thực hóa thuật toán chấm điểm theo Mục 6 của Handoff và các quy tắc trần độ tin cậy trong UPDATE_01.
"""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from dumpanalyzer.core.models import Crash, Evidence
from dumpanalyzer.engine.rule_loader import normalize_bugcheck_code

logger = logging.getLogger("dumpanalyzer.engine.scorer")

# Danh sách tên hiển thị thân thiện bằng tiếng Việt cho các nhóm nguyên nhân
SUSPECT_LABELS_VI = {
    "gpu": "Card màn hình / Driver GPU",
    "ram": "Bộ nhớ RAM",
    "storage": "Ổ cứng / SSD / Bộ điều khiển lưu trữ",
    "driver": "Driver bên thứ ba",
    "cpu": "Bộ xử lý CPU / Ép xung",
    "psu": "Bộ nguồn máy tính (PSU) / Nguồn điện",
    "thermal": "Quá nhiệt (Nhiệt độ CPU/GPU)",
    "bios": "BIOS / Bo mạch chủ (Motherboard)",
    "network": "Card mạng LAN / Wi-Fi",
    "update": "Bản cập nhật Windows / Phần mềm mới cài",
    "unknown": "Chưa xác định",
}


def get_suspect_label_vi(suspect: str) -> str:
    """Trả về nhãn hiển thị tiếng Việt cho nhóm nghi ngờ."""
    if suspect.startswith("driver:"):
        drv_name = suspect.split(":", 1)[1]
        return f"Driver {drv_name}"
    return SUSPECT_LABELS_VI.get(suspect, suspect)


def score_single_crash(
    crash: Crash,
    evidences: List[Evidence],
    rules: Dict[str, Any],
    settings: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Chấm điểm nguyên nhân cho một vụ sập (Crash) đơn lẻ.
    Trả về dict chứa:
      - 'suspect_scores': danh sách (suspect, score_pct) đã sắp xếp giảm dần
      - 'top_suspect': nhóm nghi ngờ cao nhất
      - 'top_score': điểm % cao nhất (0 - 100)
      - 'confidence': 'thấp', 'trung bình', 'cao', hoặc 'không đủ dữ kiện'
      - 'used_evidence_ids': danh sách ID các bằng chứng được dùng
      - 'is_log_only': bool
      - 'applied_caps': mô tả trần độ tin cậy đã áp dụng
      - 'notes': ghi chú kỹ thuật
    """
    raw_scores: Dict[str, float] = {}
    used_evidence_ids: List[int] = []
    notes: List[str] = []

    is_log_only = (crash.analyzed_by == "log_only" or crash.dump_type == "none")
    is_header_only = (crash.analyzed_by == "header_only")

    # 1. Điểm khởi đầu từ bugcheck_rules.yaml
    bc_code = normalize_bugcheck_code(crash.bugcheck_code) if crash.bugcheck_code else "0x0"
    bc_rules = rules.get("bugchecks", {})

    rule_for_code = bc_rules.get(bc_code)
    if not rule_for_code and is_log_only and bc_code in ("0", "0x0", ""):
        rule_for_code = bc_rules.get("0x0")

    if rule_for_code:
        for suspect, pts in rule_for_code.get("suspects", {}).items():
            raw_scores[suspect] = raw_scores.get(suspect, 0.0) + float(pts)
    else:
        # Nếu mã lỗi chưa có trong YAML rules: cấp điểm cơ bản
        raw_scores["driver"] = 35.0
        raw_scores["ram"] = 25.0
        raw_scores["storage"] = 20.0
        raw_scores["cpu"] = 20.0

    # Xác định các giả thuyết ban đầu từ dump/mã lỗi để tính đồng thuận sau này
    initial_top_suspects: Set[str] = {
        k for k, v in sorted(raw_scores.items(), key=lambda item: item[1], reverse=True)[:2]
    }

    # 2. Phân tích Driver / Module gây lỗi
    driver_map = rules.get("drivers", {})
    ms_core_modules = rules.get("ms_core_modules", [])

    img = (crash.image_name or "").strip().lower()
    mod = (crash.module_name or "").strip().lower()
    active_module = img if img else mod

    # Trích xuất suspect driver nếu cdb parser đã phát hiện trong call stack
    suspect_driver_in_stack = ""
    if crash.cdb_raw_output and "Driver nghi vấn trong stack:" in crash.cdb_raw_output:
        for line in crash.cdb_raw_output.splitlines():
            if "Driver nghi vấn trong stack:" in line:
                suspect_driver_in_stack = line.split(":", 1)[1].strip().lower()
                break

    if is_log_only:
        # UPDATE_01: Crash không có dump TUYỆT ĐỐI không kết luận driver cụ thể
        # Chỉ nhóm thiết bị, trừ khi event log tự nêu rõ
        pass
    else:
        # Có dump: phân định Nạn nhân vs Thủ phạm
        is_ms_module = any(active_module.endswith(ms_mod) for ms_mod in ms_core_modules)

        if is_ms_module:
            # Module Microsoft: ĐÂY LÀ NẠN NHÂN, KHÔNG CỘNG ĐIỂM CHO DRIVER NÀY
            notes.append(f"Module sập là '{active_module}' (Microsoft OS Core) - đây là nạn nhân.")
            if suspect_driver_in_stack:
                notes.append(f"Phát hiện driver bên thứ ba trong stack: '{suspect_driver_in_stack}'.")
                drv_info = driver_map.get(suspect_driver_in_stack)
                if drv_info:
                    dev_type = drv_info.get("type", "driver")
                    raw_scores[dev_type] = raw_scores.get(dev_type, 0.0) + 50.0
                    initial_top_suspects.add(dev_type)
                else:
                    raw_scores[f"driver:{suspect_driver_in_stack}"] = (
                        raw_scores.get(f"driver:{suspect_driver_in_stack}", 0.0) + 40.0
                    )
                    initial_top_suspects.add(f"driver:{suspect_driver_in_stack}")
            else:
                # Không có driver bên thứ ba nào trong stack: cộng nhẹ cho phần cứng theo bug check
                if bc_code in ("0x1A", "0x50", "0x4E"):
                    raw_scores["ram"] = raw_scores.get("ram", 0.0) + 20.0
                elif bc_code in ("0x124", "0x101"):
                    raw_scores["cpu"] = raw_scores.get("cpu", 0.0) + 20.0
                elif bc_code in ("0x7B", "0x7A", "0x24"):
                    raw_scores["storage"] = raw_scores.get("storage", 0.0) + 20.0
        elif active_module:
            # Driver bên thứ ba trực tiếp
            drv_info = driver_map.get(active_module)
            if drv_info:
                dev_type = drv_info.get("type", "driver")
                raw_scores[dev_type] = raw_scores.get(dev_type, 0.0) + 60.0
                initial_top_suspects.add(dev_type)
            else:
                raw_scores[f"driver:{active_module}"] = raw_scores.get(f"driver:{active_module}", 0.0) + 50.0
                initial_top_suspects.add(f"driver:{active_module}")


    # 3. Cộng điểm từ Event Log theo event_rules.yaml
    event_rules = rules.get("event_rules", [])
    has_supporting_event = False

    for ev in evidences:
        ev_id_val = ev.id if ev.id is not None else 0
        if ev.kind == "eventlog":
            matched = False
            for rule in event_rules:
                if rule.get("source", "").lower() in ev.source.lower():
                    rule_ids = rule.get("ids", [])
                    if ev.event_id in rule_ids or not rule_ids:
                        matched = True
                        for susp, weight in rule.get("adds", {}).items():
                            # Nếu event đồng thuận với hướng nghi ngờ từ dump -> nhân hệ số 1.5
                            factor = 1.5 if susp in initial_top_suspects else 1.0
                            raw_scores[susp] = raw_scores.get(susp, 0.0) + (float(weight) * factor)
                            has_supporting_event = True
            if matched and ev_id_val:
                used_evidence_ids.append(ev_id_val)

        elif ev.kind == "smart":
            raw_scores["storage"] = raw_scores.get("storage", 0.0) + 30.0
            if ev_id_val:
                used_evidence_ids.append(ev_id_val)
            has_supporting_event = True

        elif ev.kind == "update":
            raw_scores["update"] = raw_scores.get("update", 0.0) + 25.0
            if ev_id_val:
                used_evidence_ids.append(ev_id_val)
            has_supporting_event = True

    # 4. Chuẩn hoá điểm về thang 0 - 100
    total_raw = sum(raw_scores.values())
    scored_list: List[Tuple[str, float]] = []

    if total_raw > 0:
        for susp, pts in raw_scores.items():
            pct = round((pts / total_raw) * 100.0, 1)
            scored_list.append((susp, pct))
    else:
        scored_list = [("unknown", 0.0)]

    scored_list.sort(key=lambda x: x[1], reverse=True)

    top_suspect, top_score = scored_list[0] if scored_list else ("unknown", 0.0)

    # 5. Xác định độ tin cậy và Áp dụng trần (Confidence Caps)
    conf_thresh = settings.get("confidence_thresholds", {"high": 70, "medium": 40})
    min_verdict_score = settings.get("min_verdict_score", 35)

    if top_score < min_verdict_score:
        confidence = "không đủ dữ kiện"
    elif top_score >= conf_thresh.get("high", 70):
        confidence = "cao"
    elif top_score >= conf_thresh.get("medium", 40):
        confidence = "trung bình"
    else:
        confidence = "thấp"

    applied_cap = ""
    # Quy tắc trần 1: 1 crash đơn lẻ -> tối đa "trung bình"
    if confidence == "cao":
        confidence = "trung bình"
        applied_cap = "Trần 1 crash: Độ tin cậy tối đa là 'trung bình'."

    # Quy tắc trần 2: header_only -> tối đa "trung bình"
    if is_header_only and confidence == "cao":
        confidence = "trung bình"
        applied_cap = "Trần header_only: Không có cdb phân tích stack trace."

    # Quy tắc trần 3: log_only (UPDATE_01 mục D)
    if is_log_only:
        if bc_code in ("0", "0x0", ""):
            # BugcheckCode = 0: tối đa "thấp"
            confidence = "thấp"
            applied_cap = "Trần log_only BugcheckCode=0 (mất nguồn/treo): Độ tin cậy 'thấp'."
        elif has_supporting_event:
            # Có mã Bug Check khác 0 VÀ có event hỗ trợ cùng hướng: tối đa "trung bình"
            if confidence == "cao":
                confidence = "trung bình"
                applied_cap = "Trần log_only có event hỗ trợ: Tối đa 'trung bình'."
        else:
            # Có mã Bug Check nhưng KHÔNG có event hỗ trợ: tối đa "thấp"
            confidence = "thấp"
            applied_cap = "Trần log_only không có event hỗ trợ: Tối đa 'thấp'."

    return {
        "suspect_scores": scored_list,
        "top_suspect": top_suspect,
        "top_score": top_score,
        "confidence": confidence,
        "used_evidence_ids": list(set(used_evidence_ids)),
        "is_log_only": is_log_only,
        "applied_caps": applied_cap,
        "notes": notes,
    }


def score_machine_crashes(
    crashes_with_evidences: List[Tuple[Crash, List[Evidence]]],
    rules: Dict[str, Any],
    settings: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Chấm điểm và phân tích xu hướng cho toàn bộ máy tính (nhiều vụ sập).
    Tổng hợp điểm các crash, áp dụng patterns.yaml, thưởng lặp lại và phát hiện mâu thuẫn.
    """
    if not crashes_with_evidences:
        return {
            "suspect_scores": [("unknown", 0.0)],
            "top_suspect": "unknown",
            "top_score": 0.0,
            "confidence": "không đủ dữ kiện",
            "used_evidence_ids": [],
            "is_conflicted": False,
            "conflict_note": "",
            "patterns_matched": [],
            "crash_count": 0,
        }

    # Nếu chỉ có 1 crash: kế thừa trực tiếp kết quả crash đơn lẻ
    if len(crashes_with_evidences) == 1:
        crash, evs = crashes_with_evidences[0]
        res = score_single_crash(crash, evs, rules, settings)
        res["is_conflicted"] = False
        res["conflict_note"] = ""
        res["patterns_matched"] = []
        res["crash_count"] = 1
        return res

    # Có từ 2 crash trở lên: Tổng hợp điểm
    aggregated_scores: Dict[str, float] = {}
    all_evidence_ids: Set[int] = set()
    top_suspect_per_crash: List[str] = []
    dump_hypotheses: List[str] = []
    log_hypotheses: List[str] = []

    log_only_weight = float(settings.get("log_only_weight", 0.5))
    repeat_multiplier = float(settings.get("repeat_multiplier", 1.25))
    conflict_threshold = float(settings.get("conflict_threshold", 15))

    ms_core_modules = rules.get("ms_core_modules", [])
    third_party_modules: List[str] = []
    all_microsoft_modules = True
    has_update_event = False
    has_kp41_zero = False

    for crash, evs in crashes_with_evidences:
        c_res = score_single_crash(crash, evs, rules, settings)
        c_weight = log_only_weight if c_res["is_log_only"] else 1.0

        for susp, pct in c_res["suspect_scores"]:
            aggregated_scores[susp] = aggregated_scores.get(susp, 0.0) + (pct * c_weight)

        all_evidence_ids.update(c_res["used_evidence_ids"])
        top_suspect_per_crash.append(c_res["top_suspect"])

        # Xác định giả thuyết nghiêng về Dump vs Event Log
        if not c_res["is_log_only"]:
            dump_hypotheses.append(c_res["top_suspect"])

        # Tìm giả thuyết từ các sự kiện Event Log của crash này
        event_rules = rules.get("event_rules", [])
        log_pts_crash: Dict[str, float] = {}
        for ev in evs:
            if ev.kind == "eventlog":
                for r in event_rules:
                    if r.get("source", "").lower() in ev.source.lower():
                        r_ids = r.get("ids", [])
                        if ev.event_id in r_ids or not r_ids:
                            for s, w in r.get("adds", {}).items():
                                log_pts_crash[s] = log_pts_crash.get(s, 0.0) + float(w)
            elif ev.kind == "smart":
                log_pts_crash["storage"] = log_pts_crash.get("storage", 0.0) + 30.0
            elif ev.kind == "update":
                log_pts_crash["update"] = log_pts_crash.get("update", 0.0) + 25.0

        if log_pts_crash:
            top_log_crash = max(log_pts_crash, key=log_pts_crash.get)
            log_hypotheses.append(top_log_crash)
        elif c_res["is_log_only"]:
            log_hypotheses.append(c_res["top_suspect"])

        if normalize_bugcheck_code(crash.bugcheck_code) in ("0", "0x0", ""):
            has_kp41_zero = True


        # Kiểm tra module
        img = (crash.image_name or "").strip().lower()
        if img:
            is_ms = any(img.endswith(m) for m in ms_core_modules)
            if is_ms:
                pass
            else:
                all_microsoft_modules = False
                third_party_modules.append(img)

        # Kiểm tra bằng chứng update
        for ev in evs:
            if ev.kind == "update":
                has_update_event = True

    # Áp dụng patterns.yaml
    patterns = rules.get("patterns", [])
    patterns_matched: List[str] = []
    total_crashes = len(crashes_with_evidences)

    for pat in patterns:
        cond = pat.get("when", {})
        pat_name = pat.get("name", "")
        matched = False

        # Pattern 1: Module khác nhau mỗi lần, toàn module Microsoft
        if cond.get("only_microsoft_modules") and total_crashes >= cond.get("min_dumps", 3):
            if all_microsoft_modules and len(set(c[0].bugcheck_code for c in crashes_with_evidences)) >= cond.get("distinct_modules_min", 2):
                matched = True

        # Pattern 2: Cùng một driver bên thứ ba lặp lại
        if cond.get("same_third_party_module_min") and len(third_party_modules) >= cond.get("min_dumps", 3):
            from collections import Counter
            counts = Counter(third_party_modules)
            if any(cnt >= cond.get("same_third_party_module_min", 3) for cnt in counts.values()):
                matched = True

        # Pattern 3: Sự cố liên quan cập nhật
        if cond.get("first_crash_within_days_after_update") and has_update_event:
            matched = True

        # Pattern 4: Mất nguồn đột ngột không dump (KP41 = 0)
        if cond.get("kernelpower41_bugcheck0") and has_kp41_zero:
            matched = True

        if matched:
            patterns_matched.append(pat_name)
            for s, add_pts in pat.get("add", {}).items():
                target_s = "driver" if s == "driver_of_module" else s
                aggregated_scores[target_s] = aggregated_scores.get(target_s, 0.0) + float(add_pts)

    # Thưởng lặp lại (Repeat Bonus): Cùng một giả thuyết đứng đầu ở >= 3 crash
    from collections import Counter
    suspect_counts = Counter(top_suspect_per_crash)
    for susp, cnt in suspect_counts.items():
        if cnt >= 3 and susp in aggregated_scores:
            aggregated_scores[susp] *= repeat_multiplier

    # Chuẩn hoá điểm tổng hợp về 0 - 100%
    total_agg = sum(aggregated_scores.values())
    final_scored: List[Tuple[str, float]] = []
    if total_agg > 0:
        for s, pts in aggregated_scores.items():
            pct = round((pts / total_agg) * 100.0, 1)
            final_scored.append((s, pct))
    else:
        final_scored = [("unknown", 0.0)]

    final_scored.sort(key=lambda x: x[1], reverse=True)
    top_suspect, top_score = final_scored[0] if final_scored else ("unknown", 0.0)

    # Phát hiện mâu thuẫn (Conflict Detection)
    is_conflicted = False
    conflict_note = ""
    if dump_hypotheses and log_hypotheses:
        top_dump_hypo = Counter(dump_hypotheses).most_common(1)[0][0]
        top_log_hypo = Counter(log_hypotheses).most_common(1)[0][0]

        if top_dump_hypo != top_log_hypo:
            # Lấy điểm của 2 giả thuyết này
            score_dict = dict(final_scored)
            diff = abs(score_dict.get(top_dump_hypo, 0.0) - score_dict.get(top_log_hypo, 0.0))
            if diff < conflict_threshold:
                is_conflicted = True
                conflict_note = (
                    f"Cảnh báo: Dữ liệu chưa thống nhất! "
                    f"Phân tích Dump nghiêng về '{get_suspect_label_vi(top_dump_hypo)}', "
                    f"trong khi Event Log nghiêng về '{get_suspect_label_vi(top_log_hypo)}' "
                    f"(chênh lệch {diff:.1f} điểm < {conflict_threshold} điểm)."
                )

    # Xác định độ tin cậy của máy
    conf_thresh = settings.get("confidence_thresholds", {"high": 70, "medium": 40})
    min_verdict_score = settings.get("min_verdict_score", 35)

    if top_score < min_verdict_score:
        confidence = "không đủ dữ kiện"
    elif top_score >= conf_thresh.get("high", 70):
        # Có ít nhất 2 crash đồng thuận và điểm cao -> đạt "cao"
        most_common_cnt = suspect_counts.get(top_suspect, 0)
        if most_common_cnt >= 2 and not is_conflicted:
            confidence = "cao"
        else:
            confidence = "trung bình"
    elif top_score >= conf_thresh.get("medium", 40):
        confidence = "trung bình"
    else:
        confidence = "thấp"

    return {
        "suspect_scores": final_scored,
        "top_suspect": top_suspect,
        "top_score": top_score,
        "confidence": confidence,
        "used_evidence_ids": list(all_evidence_ids),
        "is_conflicted": is_conflicted,
        "conflict_note": conflict_note,
        "patterns_matched": patterns_matched,
        "crash_count": total_crashes,
    }
